package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	// Note: time is used for timestamps (CreatedAt/UpdatedAt), not for RNG.
)

// ---------------------------------------------------------------------------
// Task — represents an async operation with lifecycle tracking.
// ---------------------------------------------------------------------------

// TaskStatus represents the current state of an async task.
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

// isTerminal reports whether the status is a terminal state (no further
// transitions possible).
func (s TaskStatus) isTerminal() bool {
	return s == TaskStatusCompleted || s == TaskStatusFailed || s == TaskStatusCancelled
}

// Task represents an async MCP tool invocation. Long-running tools (scan,
// assess, bypass, discover) create a Task when invoked, return the task_id
// immediately, and the client polls get_task_status for results.
//
// Task intentionally does NOT store raw arguments (Args) to avoid keeping
// potentially sensitive data (target URLs, payloads) in memory beyond the
// initial launch response.
type Task struct {
	mu sync.RWMutex

	// Immutable fields (set at creation, never change).
	ID        string    `json:"task_id"`
	Tool      string    `json:"tool"`
	CreatedAt time.Time `json:"created_at"`

	// Mutable fields (updated by the running goroutine).
	Status    TaskStatus `json:"status"`
	Progress  float64    `json:"progress"`    // 0–100
	Total     float64    `json:"total"`       // expected total work units
	Message   string     `json:"message"`     // human-readable progress message
	UpdatedAt time.Time  `json:"updated_at"`

	// Terminal fields (set once when complete/failed/cancelled).
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`

	// Cancellation support.
	cancel context.CancelFunc `json:"-"`

	// done is closed when the task reaches a terminal state.
	// Used by WaitFor for long-poll support.
	done chan struct{} `json:"-"`
}

// SetProgress updates the task's progress counters. Thread-safe.
func (t *Task) SetProgress(progress, total float64, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Status.isTerminal() {
		return // Prevent overwriting terminal state messages.
	}
	t.Progress = progress
	t.Total = total
	t.Message = message
	t.UpdatedAt = time.Now()
}

// Complete marks the task as completed with the given result and releases
// the task's context. Thread-safe. No-op if the task is already in a
// terminal state (prevents Cancel→Complete races).
func (t *Task) Complete(result json.RawMessage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Status.isTerminal() {
		return
	}
	t.Status = TaskStatusCompleted
	t.Progress = t.Total
	t.Result = result
	t.Message = "completed"
	t.UpdatedAt = time.Now()
	if t.cancel != nil {
		t.cancel()
	}
	closeDone(t.done)
	log.Printf("[mcp-task] COMPLETED  id=%s  tool=%s  result_bytes=%d", t.ID, t.Tool, len(result))
}

// Fail marks the task as failed with an error message and releases
// the task's context. Thread-safe. No-op if the task is already in a
// terminal state (prevents Cancel→Fail races where the workFn detects
// context cancellation and calls Fail after Cancel already set the status).
func (t *Task) Fail(errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Status.isTerminal() {
		return
	}
	t.Status = TaskStatusFailed
	t.Error = errMsg
	t.Message = "failed: " + errMsg
	t.UpdatedAt = time.Now()
	if t.cancel != nil {
		t.cancel()
	}
	closeDone(t.done)
	log.Printf("[mcp-task] FAILED  id=%s  tool=%s  err=%s", t.ID, t.Tool, errMsg)
}

// Cancel marks the task as cancelled and fires the context cancellation.
// Thread-safe.
func (t *Task) Cancel() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Status == TaskStatusRunning || t.Status == TaskStatusPending {
		t.Status = TaskStatusCancelled
		t.Message = "cancelled by user"
		t.UpdatedAt = time.Now()
		if t.cancel != nil {
			t.cancel()
		}
		closeDone(t.done)
		log.Printf("[mcp-task] CANCELLED  id=%s  tool=%s", t.ID, t.Tool)
	}
}

// closeDone safely closes a done channel. Must be called under t.mu.Lock().
func closeDone(ch chan struct{}) {
	select {
	case <-ch:
		// Already closed.
	default:
		close(ch)
	}
}

// WaitFor blocks until the task reaches a terminal state, the context is
// cancelled, or waitSeconds elapses — whichever comes first. Used by
// get_task_status for long-poll support to reduce polling frequency and
// eliminate timing-dependent "task not found" errors.
func (t *Task) WaitFor(ctx context.Context, waitSeconds int) {
	if waitSeconds <= 0 {
		return
	}
	timer := time.NewTimer(time.Duration(waitSeconds) * time.Second)
	defer timer.Stop()
	select {
	case <-t.done:
		// Task completed/failed/cancelled.
	case <-ctx.Done():
		// Client disconnected or context cancelled.
	case <-timer.C:
		// Timeout — return current status.
	}
}

// Snapshot returns a read-consistent copy of the task for JSON serialization.
// Thread-safe.
func (t *Task) Snapshot() TaskSnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	snap := TaskSnapshot{
		ID:        t.ID,
		Tool:      t.Tool,
		Status:    t.Status,
		Progress:  t.Progress,
		Total:     t.Total,
		Message:   t.Message,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
	if t.Status == TaskStatusCompleted {
		snap.Result = t.Result
	}
	if t.Status == TaskStatusFailed {
		snap.Error = t.Error
	}
	return snap
}

// TaskSnapshot is an immutable, JSON-serializable view of a Task.
type TaskSnapshot struct {
	ID        string          `json:"task_id"`
	Tool      string          `json:"tool"`
	Status    TaskStatus      `json:"status"`
	Progress  float64         `json:"progress"`
	Total     float64         `json:"total"`
	Message   string          `json:"message"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// TaskManager — concurrent-safe store for async tasks with auto-cleanup.
// ---------------------------------------------------------------------------

const (
	// taskTTL is how long completed/failed/cancelled tasks are kept.
	taskTTL = 30 * time.Minute

	// cleanupInterval is how often the cleanup goroutine runs.
	cleanupInterval = 5 * time.Minute

	// maxActiveTasks prevents unbounded memory growth.
	maxActiveTasks = 100

	// maxTaskDuration is the hard ceiling on how long any single task can
	// run before its context is automatically cancelled. Prevents runaway
	// tasks from consuming slots indefinitely.
	maxTaskDuration = 30 * time.Minute
)

// TaskManager manages the lifecycle of async MCP tasks.
type TaskManager struct {
	mu    sync.RWMutex
	tasks map[string]*Task
	wg    sync.WaitGroup // tracks running task goroutines for clean shutdown
	stop  chan struct{}
}

// NewTaskManager creates a new TaskManager and starts its cleanup goroutine.
func NewTaskManager() *TaskManager {
	tm := &TaskManager{
		tasks: make(map[string]*Task),
		stop:  make(chan struct{}),
	}
	go tm.cleanupLoop()
	return tm
}

// Stop cancels all running tasks, waits for goroutines to drain (with a
// 10-second timeout), and shuts down the cleanup goroutine. Safe to call
// multiple times.
func (tm *TaskManager) Stop() {
	select {
	case <-tm.stop:
		return // Already stopped.
	default:
	}

	tm.cancelAll()

	// Wait for goroutines to notice cancellation and exit.
	done := make(chan struct{})
	go func() {
		tm.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}

	close(tm.stop)
}

// Create creates a new task for the given tool and returns it. The caller is
// responsible for starting a goroutine that uses task.SetProgress/Complete/Fail.
// The returned context is derived from the provided parent and is cancelled
// when the task is cancelled, completed, failed, or the parent is done.
func (tm *TaskManager) Create(parent context.Context, tool string) (*Task, context.Context, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Count active (non-terminal) tasks. Because we hold tm.mu (write lock),
	// no new tasks can be created concurrently. We read t.Status under
	// t.mu.RLock to avoid data races.
	active := 0
	for _, t := range tm.tasks {
		t.mu.RLock()
		s := t.Status
		t.mu.RUnlock()
		if !s.isTerminal() {
			active++
		}
	}
	if active >= maxActiveTasks {
		return nil, nil, fmt.Errorf("too many active tasks (%d/%d) — wait for existing tasks to complete or cancel them", active, maxActiveTasks)
	}

	id, err := generateTaskID()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate task ID: %w", err)
	}
	// Wrap context with a hard timeout so no task can run indefinitely.
	timeoutCtx, timeoutCancel := context.WithTimeout(parent, maxTaskDuration)
	ctx, cancel := context.WithCancel(timeoutCtx)
	// Chain: when cancel() fires it also releases timeoutCtx resources,
	// but we must also ensure timeoutCancel is called to avoid leaking
	// the timer goroutine when the task finishes before the deadline.
	now := time.Now()

	task := &Task{
		ID:        id,
		Tool:      tool,
		Status:    TaskStatusRunning,
		Progress:  0,
		Total:     100,
		Message:   "starting",
		CreatedAt: now,
		UpdatedAt: now,
		cancel: func() {
			cancel()
			timeoutCancel()
		},
		done: make(chan struct{}),
	}

	tm.tasks[id] = task
	log.Printf("[mcp-task] CREATED  id=%s  tool=%s  active=%d", id, tool, active+1)
	return task, ctx, nil
}

// Get returns the task with the given ID, or nil if not found.
func (tm *TaskManager) Get(id string) *Task {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	t := tm.tasks[id]
	if t == nil {
		// Log every miss — this is the symptom clients report as "task not found".
		ids := make([]string, 0, len(tm.tasks))
		for k := range tm.tasks {
			ids = append(ids, k)
		}
		log.Printf("[mcp-task] GET MISS  id=%s  known_tasks=%d  ids=%v", id, len(tm.tasks), ids)
	}
	return t
}

// List returns snapshots of all tasks, optionally filtered by status.
func (tm *TaskManager) List(statusFilter ...TaskStatus) []TaskSnapshot {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	filterSet := make(map[TaskStatus]bool, len(statusFilter))
	for _, s := range statusFilter {
		filterSet[s] = true
	}

	snapshots := make([]TaskSnapshot, 0, len(tm.tasks))
	for _, t := range tm.tasks {
		snap := t.Snapshot()
		if len(filterSet) > 0 && !filterSet[snap.Status] {
			continue
		}
		snapshots = append(snapshots, snap)
	}
	return snapshots
}

// ActiveCount returns the number of running/pending tasks.
func (tm *TaskManager) ActiveCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	count := 0
	for _, t := range tm.tasks {
		t.mu.RLock()
		s := t.Status
		t.mu.RUnlock()
		if !s.isTerminal() {
			count++
		}
	}
	return count
}

// cleanupLoop periodically removes expired terminal tasks.
func (tm *TaskManager) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tm.stop:
			return
		case <-ticker.C:
			tm.cleanup()
		}
	}
}

// cleanup removes tasks that have been in a terminal state longer than taskTTL.
// Uses a two-phase approach: read under RLock, delete under Lock, to minimise
// the time the write lock is held.
func (tm *TaskManager) cleanup() {
	// Phase 1: collect expired IDs under read lock.
	tm.mu.RLock()
	cutoff := time.Now().Add(-taskTTL)
	var expired []string
	for id, t := range tm.tasks {
		t.mu.RLock()
		status := t.Status
		updated := t.UpdatedAt
		t.mu.RUnlock()

		if status.isTerminal() && updated.Before(cutoff) {
			expired = append(expired, id)
		}
	}
	tm.mu.RUnlock()

	if len(expired) == 0 {
		return
	}

	// Phase 2: delete under write lock.
	tm.mu.Lock()
	for _, id := range expired {
		delete(tm.tasks, id)
	}
	remaining := len(tm.tasks)
	tm.mu.Unlock()
	log.Printf("[mcp-task] CLEANUP  removed=%d  remaining=%d  ids=%v", len(expired), remaining, expired)
}

// cancelAll cancels every running/pending task. Called during server shutdown
// to prevent goroutine leaks.
func (tm *TaskManager) cancelAll() {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	for _, t := range tm.tasks {
		t.Cancel()
	}
}

// generateTaskID produces a short, unique, URL-safe task identifier.
// Format: "task_" + 16 hex chars (8 random bytes = 2^64 values).
// With 2^64 possibilities, birthday-paradox collision requires ~4 billion IDs.
func generateTaskID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return "task_" + hex.EncodeToString(b), nil
}
