package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestGenerateTaskID(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id, err := generateTaskID()
		if err != nil {
			t.Fatalf("generateTaskID() returned error: %v", err)
		}
		if !hasPrefix(id, "task_") {
			t.Fatalf("task ID %q missing 'task_' prefix", id)
		}
		if len(id) != 21 { // "task_" (5) + 16 hex chars
			t.Fatalf("task ID %q has unexpected length %d, want 21", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate task ID generated: %s", id)
		}
		seen[id] = true
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestTaskLifecycle(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	ctx := context.Background()

	task, taskCtx, err := tm.Create(ctx, "scan")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	// Verify initial state.
	snap := task.Snapshot()
	if snap.Status != TaskStatusRunning {
		t.Errorf("initial status = %q, want %q", snap.Status, TaskStatusRunning)
	}
	if snap.Progress != 0 {
		t.Errorf("initial progress = %v, want 0", snap.Progress)
	}
	if snap.Tool != "scan" {
		t.Errorf("tool = %q, want %q", snap.Tool, "scan")
	}

	// Context should not be done yet.
	select {
	case <-taskCtx.Done():
		t.Fatal("task context should not be done yet")
	default:
	}

	// Update progress.
	task.SetProgress(50, 100, "halfway")
	snap = task.Snapshot()
	if snap.Progress != 50 {
		t.Errorf("progress = %v, want 50", snap.Progress)
	}
	if snap.Message != "halfway" {
		t.Errorf("message = %q, want %q", snap.Message, "halfway")
	}

	// Complete.
	resultData := json.RawMessage(`{"bypasses":5}`)
	task.Complete(resultData)
	snap = task.Snapshot()
	if snap.Status != TaskStatusCompleted {
		t.Errorf("status = %q, want %q", snap.Status, TaskStatusCompleted)
	}
	if string(snap.Result) != `{"bypasses":5}` {
		t.Errorf("result = %s, want %s", snap.Result, resultData)
	}
	if snap.Progress != snap.Total {
		t.Errorf("progress = %v, want %v (total)", snap.Progress, snap.Total)
	}
}

func TestTaskFailure(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, err := tm.Create(context.Background(), "assess")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	task.Fail("connection refused")
	snap := task.Snapshot()
	if snap.Status != TaskStatusFailed {
		t.Errorf("status = %q, want %q", snap.Status, TaskStatusFailed)
	}
	if snap.Error != "connection refused" {
		t.Errorf("error = %q, want %q", snap.Error, "connection refused")
	}

	// Result should not be set on failure.
	if snap.Result != nil {
		t.Errorf("result should be nil on failure, got %s", snap.Result)
	}
}

func TestTaskCancellation(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, taskCtx, err := tm.Create(context.Background(), "bypass")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	// Cancel the task.
	task.Cancel()
	snap := task.Snapshot()
	if snap.Status != TaskStatusCancelled {
		t.Errorf("status = %q, want %q", snap.Status, TaskStatusCancelled)
	}

	// Context should be done.
	select {
	case <-taskCtx.Done():
		// Expected.
	case <-time.After(time.Second):
		t.Fatal("task context not cancelled after Cancel()")
	}

	// Double cancel should be safe (no panic).
	task.Cancel()
}

func TestTaskCancelCompletedNoop(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, err := tm.Create(context.Background(), "scan")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	task.Complete(json.RawMessage(`{}`))
	task.Cancel() // Should be a no-op.

	snap := task.Snapshot()
	if snap.Status != TaskStatusCompleted {
		t.Errorf("status = %q, want %q — cancel should not affect completed tasks", snap.Status, TaskStatusCompleted)
	}
}

func TestTaskManagerGet(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, err := tm.Create(context.Background(), "scan")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	got := tm.Get(task.ID)
	if got == nil {
		t.Fatal("Get returned nil for existing task")
	}
	if got.ID != task.ID {
		t.Errorf("task ID = %q, want %q", got.ID, task.ID)
	}

	// Non-existent task.
	if tm.Get("task_nonexistent") != nil {
		t.Error("Get returned non-nil for nonexistent task")
	}
}

func TestTaskManagerList(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	t1, _, _ := tm.Create(context.Background(), "scan")
	t2, _, _ := tm.Create(context.Background(), "assess")
	t1.Complete(json.RawMessage(`{}`))

	// List all.
	all := tm.List()
	if len(all) != 2 {
		t.Fatalf("List() returned %d tasks, want 2", len(all))
	}

	// List only running.
	running := tm.List(TaskStatusRunning)
	if len(running) != 1 {
		t.Fatalf("List(running) returned %d tasks, want 1", len(running))
	}
	if running[0].Tool != "assess" {
		t.Errorf("running task tool = %q, want %q", running[0].Tool, "assess")
	}

	// List only completed.
	completed := tm.List(TaskStatusCompleted)
	if len(completed) != 1 {
		t.Fatalf("List(completed) returned %d tasks, want 1", len(completed))
	}
	if completed[0].ID != t1.ID {
		t.Errorf("completed task ID = %q, want %q", completed[0].ID, t1.ID)
	}

	_ = t2 // avoid unused warning
}

func TestTaskManagerActiveCount(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	if tm.ActiveCount() != 0 {
		t.Fatalf("initial active count = %d, want 0", tm.ActiveCount())
	}

	t1, _, _ := tm.Create(context.Background(), "scan")
	t2, _, _ := tm.Create(context.Background(), "assess")

	if tm.ActiveCount() != 2 {
		t.Fatalf("active count = %d, want 2", tm.ActiveCount())
	}

	t1.Complete(json.RawMessage(`{}`))
	if tm.ActiveCount() != 1 {
		t.Fatalf("active count = %d after completing one, want 1", tm.ActiveCount())
	}

	t2.Fail("timeout")
	if tm.ActiveCount() != 0 {
		t.Fatalf("active count = %d after failing second, want 0", tm.ActiveCount())
	}
}

func TestTaskManagerMaxActiveTasks(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	// Fill to capacity.
	for i := 0; i < maxActiveTasks; i++ {
		_, _, err := tm.Create(context.Background(), "scan")
		if err != nil {
			t.Fatalf("creating task %d: %v", i, err)
		}
	}

	// Next one should fail.
	_, _, err := tm.Create(context.Background(), "scan")
	if err == nil {
		t.Fatal("expected error when exceeding maxActiveTasks")
	}
}

func TestTaskManagerCleanup(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, _ := tm.Create(context.Background(), "scan")
	task.Complete(json.RawMessage(`{}`))

	// Manually set UpdatedAt to be older than TTL.
	task.mu.Lock()
	task.UpdatedAt = time.Now().Add(-taskTTL - time.Minute)
	task.mu.Unlock()

	tm.cleanup()

	if tm.Get(task.ID) != nil {
		t.Error("expired task should have been cleaned up")
	}

	// Running tasks should NOT be cleaned up even if old.
	task2, _, _ := tm.Create(context.Background(), "assess")
	task2.mu.Lock()
	task2.UpdatedAt = time.Now().Add(-taskTTL - time.Minute)
	task2.mu.Unlock()

	tm.cleanup()
	if tm.Get(task2.ID) == nil {
		t.Error("running task should not be cleaned up regardless of age")
	}
}

func TestTaskConcurrentAccess(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, err := tm.Create(context.Background(), "scan")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	var wg sync.WaitGroup
	// Concurrent readers.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = task.Snapshot()
		}()
	}
	// Concurrent writers.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			task.SetProgress(float64(n), 100, fmt.Sprintf("step %d", n))
		}(i)
	}
	// Concurrent list/get.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tm.List()
			_ = tm.Get(task.ID)
			_ = tm.ActiveCount()
		}()
	}
	wg.Wait()
}

func TestTaskManagerStop(t *testing.T) {
	tm := NewTaskManager()

	// Double stop should not panic.
	tm.Stop()
	tm.Stop()
}

func TestTaskManagerCancelAll(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	t1, ctx1, _ := tm.Create(context.Background(), "scan")
	t2, ctx2, _ := tm.Create(context.Background(), "assess")
	t3, _, _ := tm.Create(context.Background(), "bypass")
	t3.Complete(nil) // Already completed — cancel should be no-op.

	tm.cancelAll()

	// Running tasks should be cancelled.
	snap1 := t1.Snapshot()
	if snap1.Status != TaskStatusCancelled {
		t.Errorf("t1 status = %q, want cancelled", snap1.Status)
	}
	snap2 := t2.Snapshot()
	if snap2.Status != TaskStatusCancelled {
		t.Errorf("t2 status = %q, want cancelled", snap2.Status)
	}

	// Contexts should be done.
	select {
	case <-ctx1.Done():
	default:
		t.Error("ctx1 should be done after cancelAll")
	}
	select {
	case <-ctx2.Done():
	default:
		t.Error("ctx2 should be done after cancelAll")
	}

	// Completed task should remain completed.
	snap3 := t3.Snapshot()
	if snap3.Status != TaskStatusCompleted {
		t.Errorf("t3 status = %q, want completed — cancelAll should not affect terminal tasks", snap3.Status)
	}
}

func TestCompleteReleasesContext(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, ctx, _ := tm.Create(context.Background(), "scan")
	task.Complete(nil)

	// Context should be cancelled after Complete.
	select {
	case <-ctx.Done():
		// Expected — context released.
	case <-time.After(time.Second):
		t.Fatal("context should be cancelled after Complete()")
	}
}

func TestFailReleasesContext(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, ctx, _ := tm.Create(context.Background(), "scan")
	task.Fail("some error")

	// Context should be cancelled after Fail.
	select {
	case <-ctx.Done():
		// Expected — context released.
	case <-time.After(time.Second):
		t.Fatal("context should be cancelled after Fail()")
	}
}

func TestTaskDoesNotStoreArgs(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, _ := tm.Create(context.Background(), "scan")

	// Task should not have an Args field — verify by marshalling the snapshot.
	snap := task.Snapshot()

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshaling snapshot: %v", err)
	}
	s := string(data)
	if contains(s, "args") {
		t.Error("task snapshot should not contain an 'args' field")
	}
}

func TestTerminalStateGuard_CancelThenFail(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, _ := tm.Create(context.Background(), "scan")

	// Simulate the Cancel→Fail race: Cancel sets "cancelled", then
	// the workFn goroutine detects context error and calls Fail.
	task.Cancel()
	task.Fail("scan cancelled") // Should be a no-op.

	snap := task.Snapshot()
	if snap.Status != TaskStatusCancelled {
		t.Errorf("status = %q, want %q — Fail should not overwrite cancelled status", snap.Status, TaskStatusCancelled)
	}
	if snap.Error != "" {
		t.Errorf("error = %q, want empty — Fail should not set error on cancelled task", snap.Error)
	}
}

func TestTerminalStateGuard_CompleteThenFail(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, _ := tm.Create(context.Background(), "scan")

	task.Complete(json.RawMessage(`{"ok":true}`))
	task.Fail("should not happen") // Should be a no-op.

	snap := task.Snapshot()
	if snap.Status != TaskStatusCompleted {
		t.Errorf("status = %q, want %q", snap.Status, TaskStatusCompleted)
	}
	if snap.Error != "" {
		t.Errorf("error = %q, want empty", snap.Error)
	}
	if string(snap.Result) != `{"ok":true}` {
		t.Errorf("result = %s, want {\"ok\":true}", snap.Result)
	}
}

func TestTerminalStateGuard_FailThenComplete(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, _ := tm.Create(context.Background(), "scan")

	task.Fail("some error")
	task.Complete(json.RawMessage(`{"should":"not appear"}`)) // Should be a no-op.

	snap := task.Snapshot()
	if snap.Status != TaskStatusFailed {
		t.Errorf("status = %q, want %q", snap.Status, TaskStatusFailed)
	}
	if snap.Result != nil {
		t.Errorf("result = %s, want nil — Complete should not set result on failed task", snap.Result)
	}
}

func TestKeepAliveWriterImplementsFlusher(t *testing.T) {
	// Verify keepAliveWriter satisfies http.Flusher at compile time.
	// If this test compiles, the interface is satisfied.
	var _ interface {
		Flush()
	} = &keepAliveWriter{}

	// Verify keepAliveWriter implements Unwrap() for Go 1.20+
	// http.ResponseController discovery.
	var _ interface {
		Unwrap() http.ResponseWriter
	} = &keepAliveWriter{}
}

func TestTaskContextHasDeadline(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	_, ctx, err := tm.Create(context.Background(), "scan")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("task context should have a deadline (maxTaskDuration)")
	}
	// Deadline should be roughly maxTaskDuration from now (allow 5s tolerance).
	expected := time.Now().Add(maxTaskDuration)
	diff := deadline.Sub(expected)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("deadline %v is not within 5s of expected %v", deadline, expected)
	}
}

func TestWaitGroupDrainsOnStop(t *testing.T) {
	tm := NewTaskManager()

	task, taskCtx, _ := tm.Create(context.Background(), "scan")

	// Simulate a goroutine tracked by the WaitGroup.
	tm.wg.Add(1)
	started := make(chan struct{})
	go func() {
		defer tm.wg.Done()
		close(started)
		// Block until context is cancelled (simulates real work).
		<-taskCtx.Done()
		task.Fail("cancelled")
	}()
	<-started

	// Stop should cancel tasks and wait for goroutines.
	// This call should return promptly, not hang.
	done := make(chan struct{})
	go func() {
		tm.cancelAll()
		tm.wg.Wait()
		tm.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Expected — goroutines drained.
	case <-time.After(5 * time.Second):
		t.Fatal("Stop should have drained goroutines within 5s")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GetLatest — cross-session task discovery
// ---------------------------------------------------------------------------

func TestGetLatest_EmptyManager(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	if got := tm.GetLatest(); got != nil {
		t.Errorf("GetLatest on empty manager should return nil, got task %s", got.ID)
	}
}

func TestGetLatest_SingleActiveTask(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, _ := tm.Create(context.Background(), "scan")
	got := tm.GetLatest()
	if got == nil {
		t.Fatal("GetLatest should return the active task")
	}
	if got.ID != task.ID {
		t.Errorf("GetLatest returned %s, want %s", got.ID, task.ID)
	}
}

func TestGetLatest_PrefersActiveOverTerminal(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	completed, _, _ := tm.Create(context.Background(), "scan")
	completed.Complete(json.RawMessage(`{}`))

	active, _, _ := tm.Create(context.Background(), "assess")

	got := tm.GetLatest()
	if got == nil {
		t.Fatal("GetLatest should return a task")
	}
	if got.ID != active.ID {
		t.Errorf("GetLatest should prefer active task %s, got %s", active.ID, got.ID)
	}
}

func TestGetLatest_FallsBackToTerminal(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, _ := tm.Create(context.Background(), "scan")
	task.Complete(json.RawMessage(`{"result":"done"}`))

	got := tm.GetLatest()
	if got == nil {
		t.Fatal("GetLatest should fall back to the completed task")
	}
	if got.ID != task.ID {
		t.Errorf("GetLatest returned %s, want %s", got.ID, task.ID)
	}
}

func TestGetLatest_MostRecentActive(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	_, _, _ = tm.Create(context.Background(), "scan")
	// Small sleep to ensure CreatedAt ordering is deterministic.
	time.Sleep(10 * time.Millisecond)
	newer, _, _ := tm.Create(context.Background(), "assess")

	got := tm.GetLatest()
	if got == nil {
		t.Fatal("GetLatest should return a task")
	}
	if got.ID != newer.ID {
		t.Errorf("GetLatest should return most recent active task %s, got %s", newer.ID, got.ID)
	}
}

func TestGetLatest_WithToolFilter(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	scanTask, _, _ := tm.Create(context.Background(), "scan")
	_, _, _ = tm.Create(context.Background(), "assess")

	got := tm.GetLatest("scan")
	if got == nil {
		t.Fatal("GetLatest with tool filter should return the scan task")
	}
	if got.ID != scanTask.ID {
		t.Errorf("GetLatest(\"scan\") returned %s, want %s", got.ID, scanTask.ID)
	}
}

func TestGetLatest_ToolFilterNoMatch(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	_, _, _ = tm.Create(context.Background(), "scan")

	got := tm.GetLatest("bypass")
	if got != nil {
		t.Errorf("GetLatest with non-matching filter should return nil, got %s", got.ID)
	}
}

// TestSnapshot_DeepCopiesResult verifies that Snapshot() deep-copies the
// Result field (json.RawMessage) instead of aliasing the internal buffer.
// Regression: Snapshot returned the same underlying byte slice as the task's
// Result, allowing callers to corrupt internal state by modifying the snapshot.
func TestSnapshot_DeepCopiesResult(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, err := tm.Create(context.Background(), "scan")
	if err != nil {
		t.Fatal(err)
	}

	resultData := []byte(`{"key":"original"}`)
	task.Complete(resultData)

	snap := task.Snapshot()
	if snap.Result == nil {
		t.Fatal("snapshot Result should not be nil after Complete")
	}

	// Mutate the snapshot's Result bytes
	for i := range snap.Result {
		snap.Result[i] = 'X'
	}

	// Internal Result must be unchanged
	snap2 := task.Snapshot()
	if string(snap2.Result) != `{"key":"original"}` {
		t.Errorf("internal Result was mutated via snapshot: got %s", string(snap2.Result))
	}
}
