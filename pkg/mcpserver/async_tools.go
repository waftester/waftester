package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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

POLLING PATTERN:
1. Call the long-running tool (e.g., scan) → receive {"task_id": "task_abc123", "status": "running"}
2. Wait 5-10 seconds
3. Call get_task_status with {"task_id": "task_abc123"}
4. If status is "running" → note the progress percentage, wait and poll again
5. If status is "completed" → the full result is in the "result" field
6. If status is "failed" → check "error" field for what went wrong
7. If status is "cancelled" → task was cancelled by user

RETURNS:
• task_id, tool, status, progress (0-100), message — always present
• result — present when status is "completed" (contains the full tool output)
• error — present when status is "failed"

EXAMPLE: {"task_id": "task_a1b2c3d4"}`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"task_id": map[string]any{
						"type":        "string",
						"description": "The task ID returned by a long-running tool (e.g., \"task_a1b2c3d4\").",
					},
				},
				"required": []string{"task_id"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Get Task Status",
			},
		},
		s.handleGetTaskStatus,
	)
}

func (s *Server) handleGetTaskStatus(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		TaskID string `json:"task_id"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.TaskID == "" {
		return errorResult("task_id is required. Example: {\"task_id\": \"task_a1b2c3d4\"}"), nil
	}

	task := s.tasks.Get(args.TaskID)
	if task == nil {
		return enrichedError(
			fmt.Sprintf("task %q not found — it may have expired (tasks are kept for 30 minutes after completion)", args.TaskID),
			[]string{
				"Verify the task_id is correct (it should start with 'task_').",
				"Completed tasks expire after 30 minutes — re-run the original tool if needed.",
				"Use 'list_tasks' to see all active and recent tasks.",
			},
		), nil
	}

	snap := task.Snapshot()
	return jsonResult(snap)
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

EXAMPLE: {"task_id": "task_a1b2c3d4"}`,
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
		s.handleCancelTask,
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
		return errorResult("task_id is required. Example: {\"task_id\": \"task_a1b2c3d4\"}"), nil
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
• You lost track of a task_id
• You want to check if any tasks are still running before starting new ones

OPTIONAL FILTERS:
• status: filter by task status ("running", "completed", "failed", "cancelled")
• If omitted, returns all tasks

EXAMPLE: {} or {"status": "running"}`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"status": map[string]any{
						"type":        "string",
						"description": "Filter by task status.",
						"enum":        []string{"pending", "running", "completed", "failed", "cancelled"},
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "List Tasks",
			},
		},
		s.handleListTasks,
	)
}

func (s *Server) handleListTasks(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		Status string `json:"status"`
	}
	_ = parseArgs(req, &args) // Optional args — ignore parse errors.

	var snapshots []TaskSnapshot
	if args.Status != "" {
		snapshots = s.tasks.List(TaskStatus(args.Status))
	} else {
		snapshots = s.tasks.List()
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
func (s *Server) launchAsync(
	ctx context.Context,
	toolName string,
	estimatedDuration string,
	workFn func(ctx context.Context, task *Task),
) (*mcp.CallToolResult, error) {
	// Use context.Background() as parent so the task outlives the HTTP request.
	// The tool's own cancellation context is managed by the TaskManager.
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

	// Fire and forget — the goroutine runs independently of the request.
	// Panic recovery ensures the task transitions to "failed" instead of
	// leaving it permanently stuck in "running" status.
	// WaitGroup tracking ensures Stop() can drain all goroutines.
	s.tasks.wg.Add(1)
	go func() {
		defer s.tasks.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				task.Fail(fmt.Sprintf("internal panic: %v", r))
			}
		}()
		workFn(taskCtx, task)
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
