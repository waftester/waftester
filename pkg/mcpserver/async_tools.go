package mcpserver

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// defaultWaitSeconds is used when the AI agent omits wait_seconds from
// get_task_status. The JSON schema declares "default": 30, but that's only
// a hint for the AI — Go unmarshaling leaves int fields at zero when absent.
// Using a pointer (*int) lets us distinguish "not provided" from "explicitly 0".
const defaultWaitSeconds = 30

// ---------------------------------------------------------------------------
// Async tool infrastructure — get_task_status, cancel_task, list_tasks
// ---------------------------------------------------------------------------

// registerAsyncTools adds the task management tools.
func (s *Server) registerAsyncTools() {
	s.addGetTaskStatusTool()
	s.addCancelTaskTool()
	s.addListTasksTool()
}

// ═══════════════════════════════════════════════════════════════════════════
// get_task_status — Poll for async task results
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addGetTaskStatusTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "get_task_status",
			Title: "Get Task Status",
			Description: `Poll for the status and results of an async task. Fast tools (detect_waf, list_payloads, mutate, probe, learn, generate_cicd) return results directly. Long-running tools (scan, assess, bypass, discover) return a task_id — use this tool to check progress and retrieve results.

USE THIS TOOL WHEN:
• You received a task_id from scan, assess, bypass, or discover
• You need to check if an async task has completed
• You want to see progress (percentage, current step) of a running task
• You lost the task_id (new session, reconnect) — omit task_id to auto-discover the latest task

POLLING PATTERN (YOU MUST FOLLOW THIS — DO NOT RETURN EARLY TO THE USER):
1. Call the long-running tool (e.g., scan) → receive {"task_id": "task_abc123", "status": "running"}
2. Call get_task_status with {"task_id": "task_abc123", "wait_seconds": 30}
3. If status is "running" → call get_task_status AGAIN with wait_seconds (KEEP POLLING)
4. If status is "completed" → the full result is in the "result" field — NOW return to user
5. If status is "failed" → check "error" field for what went wrong
6. NEVER tell the user to "check back later" — always poll until completion within the same execution

CROSS-SESSION RECOVERY: If you don't have a task_id (e.g., after reconnecting), simply call
get_task_status with NO task_id or with just {"wait_seconds": 30}. The server will automatically
find the most recent active task. You can also pass "tool_name" to filter by which tool started it.

CRITICAL: Use wait_seconds to avoid rapid polling. Setting wait_seconds=30 makes the server
wait up to 30 seconds for the task to complete before responding. This is more efficient than
polling every few seconds and prevents "task not found" errors from connection resets.

RETURNS:
• task_id, tool, status, progress (0-100), message — always present
• result — present when status is "completed" (contains the full tool output)
• error — present when status is "failed"

EXAMPLES:
  With task_id:   {"task_id": "task_a1b2c3d4e5f6g7h8", "wait_seconds": 30}
  Auto-discover:  {"wait_seconds": 30}
  Filter by tool: {"tool_name": "assess", "wait_seconds": 30}

TASK ID FORMAT: task_ prefix + exactly 16 hex characters (e.g., task_a1b2c3d4e5f6g7h8). NO dashes, NO UUIDs.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"task_id": map[string]any{
						"type":        "string",
						"description": "The task ID returned by a long-running tool (e.g., \"task_a1b2c3d4e5f6g7h8\"). If omitted, auto-discovers the most recent active task.",
					},
					"tool_name": map[string]any{
						"type":        "string",
						"description": "When task_id is omitted, filter auto-discovery by the tool that started the task (e.g., \"assess\", \"scan\", \"bypass\", \"discover\", \"scan_spec\").",
						"enum":        []string{"scan", "assess", "bypass", "discover", "scan_spec"},
					},
					"wait_seconds": map[string]any{
						"type":        "integer",
						"description": "Wait up to this many seconds for the task to complete before responding. Use 30 for most cases. Max 120.",
						"default":     30,
						"minimum":     0,
						"maximum":     120,
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Get Task Status",
			},
		},
		loggedTool("get_task_status", s.handleGetTaskStatus),
	)
}

func (s *Server) handleGetTaskStatus(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		TaskID      string `json:"task_id"`
		ToolName    string `json:"tool_name"`
		WaitSeconds *int   `json:"wait_seconds"` // pointer to distinguish absent from explicit 0
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	// ─── Auto-discovery: task_id omitted → find the most recent task ────
	if args.TaskID == "" {
		var task *Task
		if args.ToolName != "" {
			task = s.tasks.GetLatest(args.ToolName)
			log.Printf("[mcp] get_task_status: auto-discovery by tool_name=%q", args.ToolName)
		} else {
			task = s.tasks.GetLatest()
			log.Printf("[mcp] get_task_status: auto-discovery (no task_id, no tool_name)")
		}
		if task == nil {
			return enrichedError(
				"no tasks found — nothing to poll",
				[]string{
					"No async tasks exist. Start one first using scan, assess, bypass, or discover.",
					"If you recently started a task, it may have expired (tasks are kept for 30 minutes).",
					"Use 'list_tasks' to see all tasks with their correct task_id values.",
				},
			), nil
		}
		args.TaskID = task.ID
		log.Printf("[mcp] get_task_status: auto-discovered task %s (tool=%s)", task.ID, task.Tool)
	}

	// Validate task ID format before map lookup. Our IDs are "task_" + 16
	// hex chars (e.g., "task_a1b2c3d4e5f6g7h8"). AI agents sometimes
	// hallucinate UUIDs (dashes) or wrong-length IDs — catch that early
	// with a specific error message so the agent can self-correct.
	if reason := ValidateTaskID(args.TaskID); reason != "" {
		log.Printf("[mcp] get_task_status: invalid task_id format: %s (got %q)", reason, args.TaskID)
		return enrichedError(
			fmt.Sprintf("invalid task_id format: %s", reason),
			[]string{
				fmt.Sprintf("You provided: %q", args.TaskID),
				"Valid task IDs look like: task_a1b2c3d4e5f6g7h8 (task_ prefix + exactly 16 hex characters, NO dashes).",
				"Copy the exact task_id from the response of the tool that started the task (scan, assess, bypass, discover).",
				"Use 'list_tasks' to see all active tasks with their correct task_id values.",
			},
		), nil
	}

	// Resolve wait_seconds: use default 30 when omitted, respect explicit 0.
	waitSeconds := defaultWaitSeconds
	if args.WaitSeconds != nil {
		waitSeconds = *args.WaitSeconds
	}
	// Clamp to [0, 120].
	if waitSeconds < 0 {
		waitSeconds = 0
	}
	if waitSeconds > 120 {
		waitSeconds = 120
	}

	task := s.tasks.Get(args.TaskID)
	if task == nil {
		log.Printf("[mcp] get_task_status: task %s not found (active tasks: %d)", args.TaskID, s.tasks.ActiveCount())
		return enrichedError(
			fmt.Sprintf("task %q not found — it may have expired (tasks are kept for 30 minutes after completion)", args.TaskID),
			[]string{
				"Verify the task_id is correct (it should start with 'task_' followed by 16 hex characters).",
				"Completed tasks expire after 30 minutes — re-run the original tool if needed.",
				"Use 'list_tasks' to see all active and recent tasks.",
				"If running via stdio transport, tasks do not persist between sessions — the server runs tools synchronously instead.",
			},
		), nil
	}

	// Long-poll: if the task is still running and wait_seconds > 0,
	// wait for completion or timeout before responding.
	if waitSeconds > 0 {
		snap := task.Snapshot()
		if !snap.Status.isTerminal() {
			task.WaitFor(ctx, waitSeconds)
		}
	}

	snap := task.Snapshot()
	return jsonResult(snap)
}

// ValidateTaskID checks that a task ID matches our expected format:
// "task_" + exactly 16 lowercase hex characters (no dashes, no other chars).
// Returns an empty string if valid, or a human-readable reason if invalid.
func ValidateTaskID(id string) string {
	if !strings.HasPrefix(id, "task_") {
		return fmt.Sprintf("task_id must start with 'task_' (got %q)", id)
	}
	hexPart := id[5:] // strip "task_" prefix
	if len(hexPart) != 16 {
		return fmt.Sprintf("task_id must be exactly 21 characters (task_ + 16 hex chars), got %d characters", len(id))
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Sprintf("task_id contains non-hex characters after 'task_' prefix: %v", err)
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════════════════
// cancel_task — Cancel a running async task
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addCancelTaskTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "cancel_task",
			Title: "Cancel Task",
			Description: `Cancel a running async task. Use this to stop a long-running scan, assess, bypass, or discover operation that is no longer needed.

USE THIS TOOL WHEN:
• The user wants to stop a running task
• A task is taking too long and you want to abort it
• The user has changed their mind about what to test

Only running/pending tasks can be cancelled. Completed or failed tasks cannot be cancelled.

EXAMPLE: {"task_id": "task_a1b2c3d4e5f6g7h8"}`,

			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"task_id": map[string]any{
						"type":        "string",
						"description": "The task ID to cancel.",
					},
				},
				"required": []string{"task_id"},
			},
			Annotations: &mcp.ToolAnnotations{
				IdempotentHint: true,
				Title:          "Cancel Task",
			},
		},
		loggedTool("cancel_task", s.handleCancelTask),
	)
}

func (s *Server) handleCancelTask(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		TaskID string `json:"task_id"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.TaskID == "" {
		return errorResult("task_id is required. Example: {\"task_id\": \"task_a1b2c3d4e5f6g7h8\"}"), nil
	}

	if reason := ValidateTaskID(args.TaskID); reason != "" {
		return enrichedError(
			fmt.Sprintf("invalid task_id format: %s", reason),
			[]string{
				"Valid task IDs look like: task_a1b2c3d4e5f6g7h8 (task_ prefix + exactly 16 hex characters, NO dashes).",
				"Use 'list_tasks' to see all active tasks with their correct task_id values.",
			},
		), nil
	}

	task := s.tasks.Get(args.TaskID)
	if task == nil {
		return enrichedError(
			fmt.Sprintf("task %q not found", args.TaskID),
			[]string{
				"Verify the task_id is correct.",
				"Use 'list_tasks' to see all active tasks.",
			},
		), nil
	}

	snap := task.Snapshot()
	if snap.Status == TaskStatusCompleted || snap.Status == TaskStatusFailed || snap.Status == TaskStatusCancelled {
		return jsonResult(map[string]any{
			"task_id": args.TaskID,
			"status":  snap.Status,
			"message": fmt.Sprintf("task already in terminal state: %s", snap.Status),
		})
	}

	task.Cancel()

	return jsonResult(map[string]any{
		"task_id": args.TaskID,
		"status":  TaskStatusCancelled,
		"message": "task cancelled successfully",
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// list_tasks — List all async tasks
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addListTasksTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "list_tasks",
			Title: "List Tasks",
			Description: `List all async tasks with their status and progress. Use this to see what's running, completed, or failed.

USE THIS TOOL WHEN:
• You want to see all running tasks
• You lost track of a task_id (e.g., after reconnecting or session reset)
• You want to check if any tasks are still running before starting new ones
• You need to recover a task_id from a previous session

OPTIONAL FILTERS:
• status: filter by task status ("running", "completed", "failed", "cancelled")
• tool_name: filter by which tool started the task ("scan", "assess", "bypass", "discover", "scan_spec")
• If omitted, returns all tasks

EXAMPLES: {} or {"status": "running"} or {"tool_name": "assess"} or {"status": "running", "tool_name": "scan"}`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"status": map[string]any{
						"type":        "string",
						"description": "Filter by task status.",
						"enum":        []string{"pending", "running", "completed", "failed", "cancelled"},
					},
					"tool_name": map[string]any{
						"type":        "string",
						"description": "Filter by which tool started the task.",
						"enum":        []string{"scan", "assess", "bypass", "discover", "scan_spec"},
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "List Tasks",
			},
		},
		loggedTool("list_tasks", s.handleListTasks),
	)
}

func (s *Server) handleListTasks(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		Status   string `json:"status"`
		ToolName string `json:"tool_name"`
	}
	_ = parseArgs(req, &args) // Optional args — ignore parse errors.

	var snapshots []TaskSnapshot
	if args.Status != "" {
		snapshots = s.tasks.List(TaskStatus(args.Status))
	} else {
		snapshots = s.tasks.List()
	}

	// Apply tool_name filter client-side (List only supports status filtering).
	if args.ToolName != "" {
		filtered := make([]TaskSnapshot, 0, len(snapshots))
		for _, snap := range snapshots {
			if snap.Tool == args.ToolName {
				filtered = append(filtered, snap)
			}
		}
		snapshots = filtered
	}

	result := map[string]any{
		"tasks":        snapshots,
		"total":        len(snapshots),
		"active_count": s.tasks.ActiveCount(),
	}
	return jsonResult(result)
}

// ---------------------------------------------------------------------------
// Async task launcher — shared helper for long-running tools
// ---------------------------------------------------------------------------

// asyncTaskResponse is the immediate response returned by async tools.
type asyncTaskResponse struct {
	TaskID            string `json:"task_id"`
	Status            string `json:"status"`
	Tool              string `json:"tool"`
	Message           string `json:"message"`
	EstimatedDuration string `json:"estimated_duration"`
	NextStep          string `json:"next_step"`
}

// launchAsync creates a task and starts the work function in a goroutine.
// Returns the immediate acknowledgment response with task_id for the client.
// The workFn receives the task and a cancellable context — it should call
// task.SetProgress during execution and task.Complete or task.Fail when done.
//
// In sync mode (stdio transport), the work function runs inline and the
// complete result is returned directly — no polling required. This prevents
// "task not found" errors when each stdio invocation is a new process.
//
// Goroutine synchronization: all shared state is protected by the TaskManager's
// sync.RWMutex (tm.mu) and per-task sync.RWMutex (task.mu) in taskmanager.go.
// Map literals in this file are local-scope JSON schemas, not shared state.
func (s *Server) launchAsync(
	ctx context.Context,
	toolName string,
	estimatedDuration string,
	workFn func(ctx context.Context, task *Task),
) (*mcp.CallToolResult, error) {
	// Sync mode (stdio): run inline and return the complete result.
	// Stdio connections are per-process, so async state would be lost
	// between invocations. Blocking is safe because stdio has no HTTP
	// timeout and the client waits for the response.
	if s.syncMode.Load() {
		log.Printf("[mcp] sync mode: running %s inline (no async)", toolName)
		return s.runSync(ctx, toolName, workFn)
	}

	// Async mode (HTTP/SSE): create task and return task_id immediately.
	task, taskCtx, err := s.tasks.Create(context.Background(), toolName)
	if err != nil {
		return enrichedError(
			fmt.Sprintf("cannot start async task: %v", err),
			[]string{
				"Too many concurrent tasks are running.",
				"Use 'list_tasks' to see active tasks.",
				"Cancel unnecessary tasks with 'cancel_task' or wait for them to complete.",
			},
		), nil
	}

	log.Printf("[mcp] async: created task %s for %s", task.ID, toolName)

	// Fire and forget — the goroutine runs independently of the request.
	// Panic recovery ensures the task transitions to "failed" instead of
	// leaving it permanently stuck in "running" status.
	// WaitGroup tracking ensures Stop() can drain all goroutines.
	s.tasks.wg.Add(1)
	// If Stop() already ran, undo the Add and bail. The small window between
	// Create() returning and wg.Add(1) is covered by http.Server.Shutdown
	// draining in-flight handlers, but this makes the contract explicit.
	select {
	case <-s.tasks.stop:
		s.tasks.wg.Done()
		task.Fail("server is shutting down")
		return enrichedError("server is shutting down", nil), nil
	default:
	}
	go func() {
		defer s.tasks.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[mcp] task %s panicked: %v", task.ID, r)
				task.Fail(fmt.Sprintf("internal panic: %v", r))
			}
		}()
		workFn(taskCtx, task)
		// Defensive: if workFn returned without calling Complete/Fail,
		// force the task to a terminal state so it doesn't permanently
		// consume an active-task slot.
		snap := task.Snapshot()
		if !snap.Status.isTerminal() {
			task.Fail("tool returned without reporting completion or failure")
			snap = task.Snapshot()
		}
		log.Printf("[mcp] task %s finished: status=%s", task.ID, snap.Status)
	}()

	resp := asyncTaskResponse{
		TaskID:            task.ID,
		Status:            string(TaskStatusRunning),
		Tool:              toolName,
		Message:           fmt.Sprintf("%s started — use get_task_status to poll for results", toolName),
		EstimatedDuration: estimatedDuration,
		NextStep:          fmt.Sprintf("Call get_task_status with {\"task_id\": \"%s\"} to check progress and retrieve results when complete.", task.ID),
	}
	return jsonResult(resp)
}

// runSync executes a long-running tool inline and returns the complete result.
// Used in stdio mode where async state cannot persist between invocations.
func (s *Server) runSync(
	ctx context.Context,
	toolName string,
	workFn func(ctx context.Context, task *Task),
) (*mcp.CallToolResult, error) {
	// Create a task for lifecycle tracking (progress, completion, failure)
	// even in sync mode, so workFn can use the same Task API.
	task, taskCtx, err := s.tasks.Create(ctx, toolName)
	if err != nil {
		return enrichedError(
			fmt.Sprintf("cannot start task: %v", err),
			[]string{
				"Too many concurrent tasks are running.",
				"Cancel unnecessary tasks or wait for them to complete.",
			},
		), nil
	}

	// Run inline — blocks until complete.
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[mcp] sync task %s panicked: %v", task.ID, r)
				task.Fail(fmt.Sprintf("internal panic: %v", r))
			}
		}()
		workFn(taskCtx, task)
	}()

	snap := task.Snapshot()
	log.Printf("[mcp] sync task %s completed: status=%s", task.ID, snap.Status)

	switch snap.Status {
	case TaskStatusCompleted:
		// Return the raw result directly — no task_id wrapper.
		if len(snap.Result) > 0 {
			return textResult(string(snap.Result)), nil
		}
		return textResult(fmt.Sprintf("%s completed successfully", toolName)), nil
	case TaskStatusFailed:
		return enrichedError(
			fmt.Sprintf("%s failed: %s", toolName, snap.Error),
			[]string{"Check the error details and retry with adjusted parameters."},
		), nil
	case TaskStatusCancelled:
		return errorResult(fmt.Sprintf("%s was cancelled", toolName)), nil
	default:
		// Shouldn't happen — workFn should call Complete or Fail.
		return errorResult(fmt.Sprintf("%s ended in unexpected state: %s", toolName, snap.Status)), nil
	}
}
