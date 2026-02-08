package mcpserver_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/mcpserver"
)

// newTestSessionFrom creates a connected client↔server session using an
// existing mcpserver.Server. This lets tests pre-populate the TaskManager
// before exercising MCP tools.
func newTestSessionFrom(t *testing.T, srv *mcpserver.Server) *mcp.ClientSession {
	t.Helper()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "0.0.1",
	}, nil)

	ctx := context.Background()
	go func() {
		_ = srv.MCPServer().Run(ctx, serverTransport)
	}()

	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// ---------------------------------------------------------------------------
// get_task_status tests
// ---------------------------------------------------------------------------

func TestGetTaskStatus_MissingTaskID(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing task_id")
	}
	text := extractText(t, result)
	if !strings.Contains(strings.ToLower(text), "task_id") {
		t.Errorf("error should mention task_id, got: %s", text)
	}
}

func TestGetTaskStatus_NonexistentTask(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(`{"task_id": "task_nonexistent"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent task")
	}
	text := extractText(t, result)
	if !strings.Contains(strings.ToLower(text), "not found") {
		t.Errorf("error should mention 'not found', got: %s", text)
	}
}

// ---------------------------------------------------------------------------
// cancel_task tests
// ---------------------------------------------------------------------------

func TestCancelTask_MissingTaskID(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "cancel_task",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing task_id")
	}
}

func TestCancelTask_NonexistentTask(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "cancel_task",
		Arguments: json.RawMessage(`{"task_id": "task_nonexistent"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent task")
	}
}

// ---------------------------------------------------------------------------
// list_tasks tests
// ---------------------------------------------------------------------------

func TestListTasks_EmptyInitially(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_tasks",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatal("list_tasks should not return error for empty task list")
	}

	text := extractText(t, result)
	var parsed struct {
		Total       int `json:"total"`
		ActiveCount int `json:"active_count"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parsing list_tasks result: %v", err)
	}
	if parsed.Total != 0 {
		t.Errorf("total = %d, want 0 for fresh server", parsed.Total)
	}
	if parsed.ActiveCount != 0 {
		t.Errorf("active_count = %d, want 0 for fresh server", parsed.ActiveCount)
	}
}

// ---------------------------------------------------------------------------
// Async tool pattern — scan returns task_id
// ---------------------------------------------------------------------------

func TestScanReturnsTaskID(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Scan with valid target — should return task_id immediately, not block.
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "scan",
		Arguments: json.RawMessage(`{"target": "https://example.com", "categories": ["sqli"]}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("scan returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp struct {
		TaskID  string `json:"task_id"`
		Status  string `json:"status"`
		Tool    string `json:"tool"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parsing async response: %v", err)
	}
	if resp.TaskID == "" {
		t.Fatal("task_id should not be empty")
	}
	if !strings.HasPrefix(resp.TaskID, "task_") {
		t.Errorf("task_id should have 'task_' prefix, got: %s", resp.TaskID)
	}
	if resp.Status != "running" {
		t.Errorf("status = %q, want 'running'", resp.Status)
	}
	if resp.Tool != "scan" {
		t.Errorf("tool = %q, want 'scan'", resp.Tool)
	}
}

func TestAssessReturnsTaskID(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "assess",
		Arguments: json.RawMessage(`{"target": "https://example.com"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("assess returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parsing async response: %v", err)
	}
	if resp.TaskID == "" {
		t.Fatal("task_id should not be empty")
	}
	if resp.Tool != "assess" {
		t.Errorf("tool = %q, want 'assess'", resp.Tool)
	}
}

func TestBypassReturnsTaskID(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "bypass",
		Arguments: json.RawMessage(`{"target": "https://example.com", "payloads": ["' OR 1=1--"]}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("bypass returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parsing async response: %v", err)
	}
	if resp.TaskID == "" {
		t.Fatal("task_id should not be empty")
	}
	if resp.Tool != "bypass" {
		t.Errorf("tool = %q, want 'bypass'", resp.Tool)
	}
}

func TestDiscoverReturnsTaskID(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover",
		Arguments: json.RawMessage(`{"target": "https://example.com"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("discover returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parsing async response: %v", err)
	}
	if resp.TaskID == "" {
		t.Fatal("task_id should not be empty")
	}
	if resp.Tool != "discover" {
		t.Errorf("tool = %q, want 'discover'", resp.Tool)
	}
}

// ---------------------------------------------------------------------------
// Async validation — errors return synchronously, not as tasks
// ---------------------------------------------------------------------------

func TestAsyncToolValidatesArgsSynchronously(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tests := []struct {
		name string
		tool string
		args string
	}{
		{"scan_empty_target", "scan", `{"target": ""}`},
		{"scan_bad_scheme", "scan", `{"target": "ftp://example.com"}`},
		{"assess_empty_target", "assess", `{"target": ""}`},
		{"bypass_empty_target", "bypass", `{"target": ""}`},
		{"bypass_no_payloads", "bypass", `{"target": "https://example.com"}`},
		{"discover_empty_target", "discover", `{"target": ""}`},
		{"discover_bad_scheme", "discover", `{"target": "ftp://example.com"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tt.tool,
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected IsError for invalid args, got: %s", extractText(t, result))
			}
			// Should NOT contain task_id — validation errors are synchronous.
			text := extractText(t, result)
			if strings.Contains(text, "task_id") {
				t.Errorf("validation error should not return task_id, got: %s", text)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Task lifecycle via MCP: create → poll → get result
// ---------------------------------------------------------------------------

func TestAsyncTaskPolling(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	// Create a task directly via TaskManager.
	task, _, err := srv.Tasks().Create(context.Background(), "test_tool")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	// Complete it with a result.
	task.Complete(json.RawMessage(`{"result": "done"}`))

	// Now poll via MCP.
	cs := newTestSessionFrom(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(`{"task_id": "` + task.ID + `"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("get_task_status returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var snap struct {
		TaskID string          `json:"task_id"`
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(text), &snap); err != nil {
		t.Fatalf("parsing snapshot: %v", err)
	}
	if snap.Status != "completed" {
		t.Errorf("status = %q, want 'completed'", snap.Status)
	}

	// Verify the result field contains our data (compare as parsed JSON,
	// not raw string, because marshaling may add whitespace).
	var gotResult map[string]interface{}
	if err := json.Unmarshal(snap.Result, &gotResult); err != nil {
		t.Fatalf("parsing result field: %v", err)
	}
	if gotResult["result"] != "done" {
		t.Errorf("result = %v, want {\"result\": \"done\"}", gotResult)
	}
}

func TestAsyncTaskCancel(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	task, _, err := srv.Tasks().Create(context.Background(), "test_tool")
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	cs := newTestSessionFrom(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "cancel_task",
		Arguments: json.RawMessage(`{"task_id": "` + task.ID + `"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("cancel_task returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	if !strings.Contains(text, "cancelled") {
		t.Errorf("expected 'cancelled' in response, got: %s", text)
	}
}

func TestListTasks_AfterCreation(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	_, _, _ = srv.Tasks().Create(context.Background(), "scan")
	_, _, _ = srv.Tasks().Create(context.Background(), "assess")

	cs := newTestSessionFrom(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_tasks",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	text := extractText(t, result)
	var parsed struct {
		Total       int `json:"total"`
		ActiveCount int `json:"active_count"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if parsed.Total != 2 {
		t.Errorf("total = %d, want 2", parsed.Total)
	}
	if parsed.ActiveCount != 2 {
		t.Errorf("active_count = %d, want 2", parsed.ActiveCount)
	}
}

func TestListTasks_WithStatusFilter(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	t1, _, _ := srv.Tasks().Create(context.Background(), "scan")
	_, _, _ = srv.Tasks().Create(context.Background(), "assess")
	t1.Complete(json.RawMessage(`{}`))

	cs := newTestSessionFrom(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_tasks",
		Arguments: json.RawMessage(`{"status": "running"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	text := extractText(t, result)
	var parsed struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if parsed.Total != 1 {
		t.Errorf("total = %d, want 1 (only running task)", parsed.Total)
	}
}

// ---------------------------------------------------------------------------
// Estimated duration — covered via scan response containing a message field
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// WaitFor — long-poll support for get_task_status
// ---------------------------------------------------------------------------

func TestWaitForCompletesImmediatelyWhenDone(t *testing.T) {
	t.Parallel()
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	task, _, _ := srv.Tasks().Create(context.Background(), "scan")
	task.Complete(json.RawMessage(`{"result":"ok"}`))

	// WaitFor should return immediately since the task is already done.
	start := time.Now()
	task.WaitFor(context.Background(), 10)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("WaitFor blocked for %v, expected immediate return", elapsed)
	}
}

func TestWaitForTimesOut(t *testing.T) {
	t.Parallel()
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	task, _, _ := srv.Tasks().Create(context.Background(), "scan")

	start := time.Now()
	task.WaitFor(context.Background(), 1) // wait 1 second
	elapsed := time.Since(start)

	if elapsed < 900*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("WaitFor elapsed = %v, expected ~1s", elapsed)
	}
}

func TestWaitForUnblocksOnCompletion(t *testing.T) {
	t.Parallel()
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	task, _, _ := srv.Tasks().Create(context.Background(), "scan")

	// Complete the task after 200ms.
	go func() {
		time.Sleep(200 * time.Millisecond)
		task.Complete(json.RawMessage(`{"done":true}`))
	}()

	start := time.Now()
	task.WaitFor(context.Background(), 10) // wait up to 10s
	elapsed := time.Since(start)

	// Should unblock quickly after 200ms, not wait 10s.
	if elapsed > 2*time.Second {
		t.Errorf("WaitFor blocked for %v, expected ~200ms", elapsed)
	}
}

func TestWaitForUnblocksOnContextCancel(t *testing.T) {
	t.Parallel()
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	task, _, _ := srv.Tasks().Create(context.Background(), "scan")

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context after 200ms.
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	task.WaitFor(ctx, 10) // wait up to 10s
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("WaitFor blocked for %v, expected ~200ms", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Sync mode — stdio transport runs tools synchronously
// ---------------------------------------------------------------------------

func TestSyncModeDefault(t *testing.T) {
	t.Parallel()
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	if srv.IsSyncMode() {
		t.Error("new server should not be in sync mode by default")
	}
}

// TestGetTaskStatusWaitSeconds verifies the wait_seconds parameter.
func TestGetTaskStatusWaitSeconds(t *testing.T) {
	t.Parallel()
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	task, _, _ := srv.Tasks().Create(context.Background(), "scan")

	// Complete after 300ms.
	go func() {
		time.Sleep(300 * time.Millisecond)
		task.Complete(json.RawMessage(`{"bypasses":5}`))
	}()

	cs := newTestSessionFrom(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(`{"task_id":"` + task.ID + `","wait_seconds":10}`),
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	// Should return quickly after task completes (~300ms), not wait 10s.
	if elapsed > 3*time.Second {
		t.Errorf("get_task_status with wait_seconds blocked for %v, expected ~300ms", elapsed)
	}

	text := extractText(t, result)
	if !strings.Contains(text, "completed") {
		t.Errorf("expected completed status, got: %s", text)
	}
	if !strings.Contains(text, "bypasses") {
		t.Errorf("expected result to contain bypasses, got: %s", text)
	}
}
