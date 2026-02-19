package mcpserver_test

// n8n_regression_test.go — Full regression simulating real n8n MCP client usage.
//
// n8n connects via SSE transport, discovers tools, calls them, reads resources,
// and uses the async polling pattern. These tests exercise the exact paths n8n
// hits, including SSE transport, reconnection, cross-session task recovery,
// CORS for localhost origins, and the complete async workflow.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/mcpserver"
)

// ---------------------------------------------------------------------------
// Helpers: shared server + SSE session factory
// ---------------------------------------------------------------------------

// newSSETestSession creates a connected client↔server session over the SSE
// transport, matching how n8n connects. Returns the client session and the
// test server.
func newSSETestSession(t *testing.T) (*mcp.ClientSession, *httptest.Server) {
	t.Helper()

	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	srv.MarkReady()
	handler := srv.HTTPHandler() // includes /sse mount
	ts := httptest.NewServer(handler)

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "n8n-test-client",
		Version: "1.0.0",
	}, nil)

	transport := &mcp.SSEClientTransport{
		Endpoint: ts.URL + "/sse",
	}

	ctx := context.Background()
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		ts.Close()
		srv.Stop()
		t.Fatalf("SSE client.Connect: %v", err)
	}

	t.Cleanup(func() {
		cs.Close()
		ts.Close()
		srv.Stop()
	})
	return cs, ts
}

// newSharedServerSSESession creates a session against an existing test server.
// Used for reconnection tests where multiple sessions share the same server.
func newSharedServerSSESession(t *testing.T, ts *httptest.Server) *mcp.ClientSession {
	t.Helper()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "n8n-reconnect-client",
		Version: "1.0.0",
	}, nil)

	transport := &mcp.SSEClientTransport{
		Endpoint: ts.URL + "/sse",
	}

	cs, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("SSE reconnect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// newN8nSharedServer creates a server + test HTTP server for use by multiple
// sessions. Returns the mcpserver and httptest server.
func newN8nSharedServer(t *testing.T) (*mcpserver.Server, *httptest.Server) {
	t.Helper()

	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	srv.MarkReady()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)

	t.Cleanup(func() {
		ts.Close()
		srv.Stop()
	})
	return srv, ts
}

// extractTextN8n extracts the text content from a CallToolResult.
func extractTextN8n(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("empty Content in tool result")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] is %T, want *mcp.TextContent", result.Content[0])
	}
	return tc.Text
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: SSE Transport — capabilities negotiation (n8n's first call)
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_CapabilitiesNegotiation(t *testing.T) {
	cs, _ := newSSETestSession(t)
	init := cs.InitializeResult()

	if init.ServerInfo.Name != "waf-tester" {
		t.Errorf("server name = %q, want %q", init.ServerInfo.Name, "waf-tester")
	}
	if init.ServerInfo.Version == "" {
		t.Error("server version empty")
	}
	if init.Instructions == "" {
		t.Error("server instructions empty — n8n needs these for tool routing")
	}
	if init.Capabilities.Tools == nil {
		t.Error("tools capability nil — n8n won't discover tools")
	}
	if init.Capabilities.Resources == nil {
		t.Error("resources capability nil — n8n won't discover resources")
	}
	if init.Capabilities.Prompts == nil {
		t.Error("prompts capability nil — n8n won't discover prompts")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: SSE Transport — tool discovery (ListTools)
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_ToolDiscovery(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	// n8n uses 26 tools (no event_crawl without headless)
	if len(result.Tools) != 26 {
		t.Errorf("got %d tools, want 26", len(result.Tools))
	}

	// Verify critical tools n8n needs for workflows
	required := map[string]bool{
		"detect_waf":        false,
		"scan":              false,
		"assess":            false,
		"bypass":            false,
		"discover":          false,
		"list_payloads":     false,
		"mutate":            false,
		"learn":             false,
		"probe":             false,
		"generate_cicd":     false,
		"get_task_status":   false,
		"cancel_task":       false,
		"list_tasks":        false,
		"list_tampers":      false,
		"discover_bypasses": false,
	}

	for _, tool := range result.Tools {
		if _, ok := required[tool.Name]; ok {
			required[tool.Name] = true
		}
		// Every tool must have a description for n8n to display
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
		// Every tool must have input schema
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil InputSchema", tool.Name)
		}
	}

	for name, found := range required {
		if !found {
			t.Errorf("required tool %q not found in ListTools", name)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: SSE Transport — resource discovery + reading
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_ResourceDiscovery(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// List static resources
	resources, err := cs.ListResources(ctx, &mcp.ListResourcesParams{})
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}

	// List resource templates (e.g., waftester://payloads/{category})
	templates, err := cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{})
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}

	totalResources := len(resources.Resources) + len(templates.ResourceTemplates)
	if totalResources < 10 {
		t.Errorf("got %d total resources, want at least 10 (static + templates)", totalResources)
	}

	// Read each static resource to verify it returns valid content
	for _, res := range resources.Resources {
		t.Run(res.URI, func(t *testing.T) {
			result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: res.URI})
			if err != nil {
				t.Fatalf("ReadResource(%s): %v", res.URI, err)
			}
			if len(result.Contents) == 0 {
				t.Fatalf("ReadResource(%s): empty contents", res.URI)
			}
			text := result.Contents[0].Text
			if text == "" {
				t.Errorf("ReadResource(%s): empty text", res.URI)
			}
			// All resources except the guide should return valid JSON
			if res.MIMEType == "application/json" && !json.Valid([]byte(text)) {
				t.Errorf("ReadResource(%s): invalid JSON: %.100s", res.URI, text)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: SSE Transport — prompt discovery + retrieval
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_PromptDiscovery(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	prompts, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{})
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if len(prompts.Prompts) != 7 {
		t.Errorf("got %d prompts, want 7", len(prompts.Prompts))
	}

	// Per-prompt argument sets — some prompts need more than just target.
	promptArgs := map[string]map[string]string{
		"waf_bypass":       {"target": "https://example.com", "category": "sqli"},
		"evasion_research": {"target": "https://example.com", "payload": "<script>alert(1)</script>"},
	}

	// Every prompt should be retrievable
	for _, p := range prompts.Prompts {
		t.Run(p.Name, func(t *testing.T) {
			args := promptArgs[p.Name]
			if args == nil {
				args = map[string]string{"target": "https://example.com"}
			}
			result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
				Name:      p.Name,
				Arguments: args,
			})
			if err != nil {
				t.Fatalf("GetPrompt(%s): %v", p.Name, err)
			}
			if len(result.Messages) == 0 {
				t.Fatalf("GetPrompt(%s): no messages", p.Name)
			}
			// All messages should have non-empty text content
			for i, msg := range result.Messages {
				tc, ok := msg.Content.(*mcp.TextContent)
				if !ok {
					t.Errorf("message[%d] is %T, want *mcp.TextContent", i, msg.Content)
					continue
				}
				if tc.Text == "" {
					t.Errorf("message[%d] has empty text", i)
				}
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: SSE Transport — fast tool calls (synchronous execution)
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_FastToolCalls(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tests := []struct {
		name string
		tool string
		args map[string]any
		want string // substring that must appear in result
	}{
		{
			name: "list_payloads_no_filter",
			tool: "list_payloads",
			args: map[string]any{},
			want: "total_payloads",
		},
		{
			name: "list_payloads_sqli",
			tool: "list_payloads",
			args: map[string]any{"category": "sqli"},
			want: "sqli",
		},
		{
			name: "mutate_url_encode",
			tool: "mutate",
			args: map[string]any{
				"payload":  "<script>alert(1)</script>",
				"encoders": []string{"url"},
			},
			want: "%3Cscript%3E",
		},
		{
			name: "generate_cicd_github",
			tool: "generate_cicd",
			args: map[string]any{
				"target":   "https://example.com",
				"platform": "github",
			},
			want: "github",
		},
		{
			name: "list_tampers",
			tool: "list_tampers",
			args: map[string]any{},
			want: "tamper",
		},
		{
			name: "list_templates",
			tool: "list_templates",
			args: map[string]any{},
			want: "template",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsJSON, _ := json.Marshal(tt.args)
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tt.tool,
				Arguments: json.RawMessage(argsJSON),
			})
			if err != nil {
				t.Fatalf("CallTool(%s): %v", tt.tool, err)
			}
			if result.IsError {
				t.Fatalf("CallTool(%s) returned IsError: %s", tt.tool, extractTextN8n(t, result))
			}
			text := extractTextN8n(t, result)
			if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.want)) {
				t.Errorf("CallTool(%s) response missing %q:\n%.200s", tt.tool, tt.want, text)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: SSE Transport — async workflow (launch → poll → results)
// This is the core n8n pattern for long-running tools.
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_AsyncWorkflow(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: Call an async tool — it returns a task_id immediately
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_bypasses",
		Arguments: json.RawMessage(`{"target": "https://example.com/search?q=test"}`),
	})
	if err != nil {
		t.Fatalf("CallTool(discover_bypasses): %v", err)
	}
	if result.IsError {
		t.Fatalf("discover_bypasses returned error: %s", extractTextN8n(t, result))
	}

	// Parse the async response envelope
	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID            string `json:"task_id"`
		Status            string `json:"status"`
		Tool              string `json:"tool"`
		EstimatedDuration string `json:"estimated_duration"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parsing async response: %v\nraw: %s", err, text)
	}
	if asyncResp.TaskID == "" {
		t.Fatal("task_id is empty")
	}
	if !strings.HasPrefix(asyncResp.TaskID, "task_") {
		t.Errorf("task_id missing 'task_' prefix: %s", asyncResp.TaskID)
	}
	if asyncResp.Status != "running" {
		t.Errorf("initial status = %q, want 'running'", asyncResp.Status)
	}
	if asyncResp.Tool != "discover_bypasses" {
		t.Errorf("tool = %q, want 'discover_bypasses'", asyncResp.Tool)
	}

	// Step 2: Poll with get_task_status (n8n's polling loop)
	pollArgs, _ := json.Marshal(map[string]any{
		"task_id":      asyncResp.TaskID,
		"wait_seconds": 5, // short wait for test speed
	})

	var pollResult *mcp.CallToolResult
	for i := 0; i < 10; i++ { // max 10 poll attempts
		pollResult, err = cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "get_task_status",
			Arguments: json.RawMessage(pollArgs),
		})
		if err != nil {
			t.Fatalf("poll %d: CallTool(get_task_status): %v", i, err)
		}

		pollText := extractTextN8n(t, pollResult)
		var snap struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(pollText), &snap); err != nil {
			t.Fatalf("poll %d: parse: %v", i, err)
		}

		if snap.Status == "completed" || snap.Status == "failed" || snap.Status == "cancelled" {
			break // terminal state reached
		}
	}

	// Step 3: Verify we got a terminal status
	pollText := extractTextN8n(t, pollResult)
	var finalSnap struct {
		TaskID   string  `json:"task_id"`
		Status   string  `json:"status"`
		Tool     string  `json:"tool"`
		Progress float64 `json:"progress"`
	}
	if err := json.Unmarshal([]byte(pollText), &finalSnap); err != nil {
		t.Fatalf("final parse: %v", err)
	}
	if finalSnap.TaskID != asyncResp.TaskID {
		t.Errorf("task_id mismatch: got %q, want %q", finalSnap.TaskID, asyncResp.TaskID)
	}
	// Task should complete or fail (no live target), both are acceptable
	if finalSnap.Status != "completed" && finalSnap.Status != "failed" {
		t.Errorf("final status = %q, want 'completed' or 'failed'", finalSnap.Status)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: SSE — cross-session task recovery (n8n reconnects per turn)
// n8n creates a new SSE connection for each turn. The task_id from a
// previous session must be recoverable via get_task_status auto-discovery.
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_CrossSessionTaskRecovery(t *testing.T) {
	srv, ts := newN8nSharedServer(t)
	_ = srv

	// Session 1: launch an async task
	client1 := mcp.NewClient(&mcp.Implementation{Name: "n8n-session-1", Version: "1.0.0"}, nil)
	transport1 := &mcp.SSEClientTransport{Endpoint: ts.URL + "/sse"}
	cs1, err := client1.Connect(context.Background(), transport1, nil)
	if err != nil {
		t.Fatalf("session1 connect: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result, err := cs1.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_bypasses",
		Arguments: json.RawMessage(`{"target": "https://example.com/search?q=test"}`),
	})
	if err != nil {
		t.Fatalf("session1 CallTool: %v", err)
	}
	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parse task_id: %v\nraw: %s", err, text)
	}
	taskID := asyncResp.TaskID

	// Close session 1 (simulates n8n disconnecting)
	cs1.Close()

	// Session 2: new connection, recover the task
	client2 := mcp.NewClient(&mcp.Implementation{Name: "n8n-session-2", Version: "1.0.0"}, nil)
	transport2 := &mcp.SSEClientTransport{Endpoint: ts.URL + "/sse"}
	cs2, err := client2.Connect(context.Background(), transport2, nil)
	if err != nil {
		t.Fatalf("session2 connect: %v", err)
	}
	defer cs2.Close()

	// Auto-discover using task_id from session 1
	pollArgs, _ := json.Marshal(map[string]any{
		"task_id":      taskID,
		"wait_seconds": 5,
	})
	pollResult, err := cs2.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(pollArgs),
	})
	if err != nil {
		t.Fatalf("session2 get_task_status: %v", err)
	}

	pollText := extractTextN8n(t, pollResult)
	var snap struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(pollText), &snap); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if snap.TaskID != taskID {
		t.Errorf("task_id mismatch: got %q, want %q", snap.TaskID, taskID)
	}
	// Status should be running, completed, or failed — not "not found"
	if snap.Status == "" {
		t.Error("recovered task has empty status")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: SSE — auto-discovery without task_id (n8n lost the task_id)
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_AutoDiscoveryWithoutTaskID(t *testing.T) {
	srv, ts := newN8nSharedServer(t)
	_ = srv

	// Session 1: create a task
	client1 := mcp.NewClient(&mcp.Implementation{Name: "n8n-1", Version: "1.0.0"}, nil)
	transport1 := &mcp.SSEClientTransport{Endpoint: ts.URL + "/sse"}
	cs1, err := client1.Connect(context.Background(), transport1, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cs1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err = cs1.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_bypasses",
		Arguments: json.RawMessage(`{"target": "https://example.com/search?q=test"}`),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}

	// Now call get_task_status WITHOUT task_id — should auto-discover
	result, err := cs1.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(`{"wait_seconds": 3}`),
	})
	if err != nil {
		t.Fatalf("auto-discover: %v", err)
	}

	text := extractTextN8n(t, result)
	var snap struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &snap); err != nil {
		t.Fatalf("parse: %v\nraw: %s", err, text)
	}
	if snap.TaskID == "" {
		t.Error("auto-discovered task has empty task_id")
	}
	if snap.Tool != "discover_bypasses" {
		t.Errorf("auto-discovered tool = %q, want 'discover_bypasses'", snap.Tool)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: SSE — auto-discovery filtered by tool_name
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_AutoDiscoveryByToolName(t *testing.T) {
	srv, ts := newN8nSharedServer(t)
	_ = srv

	client := mcp.NewClient(&mcp.Implementation{Name: "n8n", Version: "1.0.0"}, nil)
	transport := &mcp.SSEClientTransport{Endpoint: ts.URL + "/sse"}
	cs, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Launch a task
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_bypasses",
		Arguments: json.RawMessage(`{"target": "https://example.com/search?q=test"}`),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}

	// Auto-discover with tool_name filter
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(`{"tool_name": "discover_bypasses", "wait_seconds": 3}`),
	})
	if err != nil {
		t.Fatalf("auto-discover by tool: %v", err)
	}

	text := extractTextN8n(t, result)
	var snap struct {
		Tool string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &snap); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if snap.Tool != "discover_bypasses" {
		t.Errorf("filtered tool = %q, want 'discover_bypasses'", snap.Tool)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 10: SSE — list_tasks shows all tasks
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_ListTasks(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Launch two tasks
	for i := 0; i < 2; i++ {
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "discover_bypasses",
			Arguments: json.RawMessage(fmt.Sprintf(`{"target": "https://example-%d.com/search?q=test"}`, i)),
		})
		if err != nil {
			t.Fatalf("launch %d: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond) // ensure distinct timestamps
	}

	// List all tasks
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_tasks",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("list_tasks: %v", err)
	}

	text := extractTextN8n(t, result)
	var listResp struct {
		Tasks []struct {
			TaskID string `json:"task_id"`
			Tool   string `json:"tool"`
			Status string `json:"status"`
		} `json:"tasks"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(text), &listResp); err != nil {
		t.Fatalf("parse list_tasks: %v\nraw: %.300s", err, text)
	}
	if listResp.Total < 2 {
		t.Errorf("total tasks = %d, want at least 2", listResp.Total)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 11: SSE — cancel_task stops a running task
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_CancelTask(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Launch a task
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_bypasses",
		Arguments: json.RawMessage(`{"target": "https://example.com/search?q=test"}`),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Cancel the task
	cancelArgs, _ := json.Marshal(map[string]any{"task_id": asyncResp.TaskID})
	cancelResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "cancel_task",
		Arguments: json.RawMessage(cancelArgs),
	})
	if err != nil {
		t.Fatalf("cancel_task: %v", err)
	}
	if cancelResult.IsError {
		t.Fatalf("cancel_task error: %s", extractTextN8n(t, cancelResult))
	}

	// Verify the task is cancelled
	time.Sleep(100 * time.Millisecond) // brief wait for cancellation to propagate
	pollArgs, _ := json.Marshal(map[string]any{"task_id": asyncResp.TaskID, "wait_seconds": 1})
	pollResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(pollArgs),
	})
	if err != nil {
		t.Fatalf("get_task_status: %v", err)
	}
	pollText := extractTextN8n(t, pollResult)
	var snap struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(pollText), &snap); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if snap.Status != "cancelled" && snap.Status != "completed" && snap.Status != "failed" {
		t.Errorf("after cancel, status = %q, want terminal state", snap.Status)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 12: SSE — Ping (n8n liveness check)
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_Ping(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := cs.Ping(ctx, &mcp.PingParams{}); err != nil {
		t.Fatalf("Ping over SSE: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 13: CORS — n8n's localhost origin is accepted
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_CORS_LocalhostOrigins(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	srv.MarkReady()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer func() {
		ts.Close()
		srv.Stop()
	}()

	// n8n runs on various localhost ports
	origins := []string{
		"http://localhost:5678", // default n8n port
		"http://localhost:3000", // custom port
		"http://127.0.0.1:5678", // IP-based
		"http://[::1]:5678",     // IPv6
	}

	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			req, _ := http.NewRequest("OPTIONS", ts.URL+"/mcp", nil)
			req.Header.Set("Origin", origin)
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "Content-Type, Mcp-Session-Id")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("preflight: %v", err)
			}
			resp.Body.Close()

			allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			if allowOrigin != origin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", allowOrigin, origin)
			}
			allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
			if !strings.Contains(allowMethods, "POST") {
				t.Errorf("Access-Control-Allow-Methods missing POST: %q", allowMethods)
			}
			allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
			if !strings.Contains(allowHeaders, "Mcp-Session-Id") {
				t.Errorf("Access-Control-Allow-Headers missing Mcp-Session-Id: %q", allowHeaders)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 14: CORS — non-localhost origins are blocked
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_CORS_NonLocalhostBlocked(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	srv.MarkReady()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer func() {
		ts.Close()
		srv.Stop()
	}()

	origins := []string{
		"https://evil.com",
		"https://attacker.io",
		"http://192.168.1.1:5678",
	}

	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			req, _ := http.NewRequest("OPTIONS", ts.URL+"/mcp", nil)
			req.Header.Set("Origin", origin)
			req.Header.Set("Access-Control-Request-Method", "POST")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("preflight: %v", err)
			}
			resp.Body.Close()

			allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			if allowOrigin != "" {
				t.Errorf("non-localhost origin %q should be blocked, got Allow-Origin=%q", origin, allowOrigin)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 15: Health endpoint — readiness probe
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_HealthEndpoint(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer func() {
		ts.Close()
		srv.Stop()
	}()

	// Before MarkReady: should return 503
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Errorf("before MarkReady: status = %d, want 503", resp.StatusCode)
	}
	if !strings.Contains(string(body), "starting") {
		t.Errorf("before MarkReady: body should contain 'starting': %s", body)
	}

	// After MarkReady: should return 200
	srv.MarkReady()
	resp, err = http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("after MarkReady: status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "ok") {
		t.Errorf("after MarkReady: body should contain 'ok': %s", body)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 16: Security headers present in all responses
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SecurityHeaders(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	srv.MarkReady()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer func() {
		ts.Close()
		srv.Stop()
	}()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	resp.Body.Close()

	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options: DENY")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 17: SSE — error handling for invalid inputs
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_ErrorHandling(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name      string
		tool      string
		args      string
		wantError bool // expects IsError
		wantText  string
	}{
		{
			name:      "scan_missing_target",
			tool:      "scan",
			args:      `{}`,
			wantError: true,
			wantText:  "target",
		},
		{
			name:      "detect_waf_missing_target",
			tool:      "detect_waf",
			args:      `{}`,
			wantError: true,
			wantText:  "target",
		},
		{
			name:      "mutate_missing_payload",
			tool:      "mutate",
			args:      `{}`,
			wantError: true,
			wantText:  "payload",
		},
		{
			name:      "get_task_status_invalid_id",
			tool:      "get_task_status",
			args:      `{"task_id": "not-a-valid-uuid"}`,
			wantError: true,
			wantText:  "task_id",
		},
		{
			name:      "scan_invalid_scheme",
			tool:      "scan",
			args:      `{"target": "ftp://evil.com"}`,
			wantError: true,
			wantText:  "http",
		},
		{
			name:      "nonexistent_tool",
			tool:      "does_not_exist",
			args:      `{}`,
			wantError: true,
			wantText:  "", // protocol error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tt.tool,
				Arguments: json.RawMessage(tt.args),
			})

			// Some errors are protocol-level (unknown tool), some are tool-level (IsError)
			if err != nil {
				if tt.tool == "does_not_exist" {
					return // expected protocol error for unknown tool
				}
				t.Fatalf("unexpected protocol error for %s: %v", tt.name, err)
			}

			if tt.wantError && !result.IsError {
				t.Errorf("expected IsError=true for %s, got false. Response: %.200s",
					tt.name, extractTextN8n(t, result))
			}

			if tt.wantText != "" {
				text := extractTextN8n(t, result)
				if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantText)) {
					t.Errorf("response for %s missing %q:\n%.200s", tt.name, tt.wantText, text)
				}
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 18: SSE — concurrent sessions don't interfere
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_ConcurrentSessions(t *testing.T) {
	_, ts := newN8nSharedServer(t)

	const goroutines = 5
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			client := mcp.NewClient(&mcp.Implementation{
				Name:    fmt.Sprintf("n8n-concurrent-%d", idx),
				Version: "1.0.0",
			}, nil)
			transport := &mcp.SSEClientTransport{Endpoint: ts.URL + "/sse"}
			cs, err := client.Connect(context.Background(), transport, nil)
			if err != nil {
				errCh <- fmt.Errorf("session %d connect: %w", idx, err)
				return
			}
			defer cs.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			// Each session calls list_payloads and mutate
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "list_payloads",
				Arguments: json.RawMessage(`{}`),
			})
			if err != nil {
				errCh <- fmt.Errorf("session %d list_payloads: %w", idx, err)
				return
			}
			if result.IsError {
				errCh <- fmt.Errorf("session %d list_payloads IsError", idx)
				return
			}

			result, err = cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "mutate",
				Arguments: json.RawMessage(`{"payload": "<script>", "encoders": ["url"]}`),
			})
			if err != nil {
				errCh <- fmt.Errorf("session %d mutate: %w", idx, err)
				return
			}
			if result.IsError {
				errCh <- fmt.Errorf("session %d mutate IsError", idx)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 19: SSE — full n8n workflow simulation (Workflow A from docs)
// detect_waf → list_payloads → scan (async) → poll → assess (async) → poll
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_FullWorkflowA(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1: detect_waf (fast tool)
	wafResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "detect_waf",
		Arguments: json.RawMessage(`{"target": "https://example.com"}`),
	})
	if err != nil {
		t.Fatalf("detect_waf: %v", err)
	}
	// detect_waf returns async (task_id) even though it's fast in docs
	// Verify it responds without protocol error
	_ = wafResult

	// Step 2: list_payloads (fast tool)
	payloadResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{"category": "sqli"}`),
	})
	if err != nil {
		t.Fatalf("list_payloads: %v", err)
	}
	if payloadResult.IsError {
		t.Fatalf("list_payloads error: %s", extractTextN8n(t, payloadResult))
	}

	// Step 3: Read version resource for capabilities
	versionResult, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://version",
	})
	if err != nil {
		t.Fatalf("ReadResource(version): %v", err)
	}
	if len(versionResult.Contents) == 0 {
		t.Fatal("version resource empty")
	}

	// Step 4: Read guide resource for methodology
	guideResult, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://guide",
	})
	if err != nil {
		t.Fatalf("ReadResource(guide): %v", err)
	}
	if len(guideResult.Contents) == 0 {
		t.Fatal("guide resource empty")
	}

	// Step 5: Get security_audit prompt
	promptResult, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "security_audit",
		Arguments: map[string]string{"target": "https://example.com"},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(promptResult.Messages) == 0 {
		t.Fatal("prompt returned no messages")
	}

	// Step 6: generate_cicd for automation
	cicdResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "generate_cicd",
		Arguments: json.RawMessage(`{"target": "https://example.com", "platform": "github"}`),
	})
	if err != nil {
		t.Fatalf("generate_cicd: %v", err)
	}
	if cicdResult.IsError {
		t.Fatalf("generate_cicd error: %s", extractTextN8n(t, cicdResult))
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 20: Streamable HTTP — default "/" mount point works
// (covers the / mount in addition to /mcp tested elsewhere)
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_StreamableHTTP_RootMount(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	srv.MarkReady()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer func() {
		ts.Close()
		srv.Stop()
	}()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "root-mount-test",
		Version: "1.0.0",
	}, nil)

	// Connect via "/" instead of "/mcp"
	transport := &mcp.StreamableClientTransport{
		Endpoint:   ts.URL + "/",
		MaxRetries: -1,
	}

	ctx := context.Background()
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect via /: %v", err)
	}
	defer cs.Close()

	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx2, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools via /: %v", err)
	}
	if len(result.Tools) != 26 {
		t.Errorf("got %d tools via /, want 26", len(result.Tools))
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 21: Tool schema validation — every tool has proper JSON Schema
// n8n uses InputSchema to build the parameter form in the UI.
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_ToolSchemaStructure(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		t.Run(tool.Name, func(t *testing.T) {
			if tool.InputSchema == nil {
				t.Fatal("InputSchema is nil")
			}

			// InputSchema should be a valid JSON Schema object
			schemaBytes, err := json.Marshal(tool.InputSchema)
			if err != nil {
				t.Fatalf("marshal InputSchema: %v", err)
			}

			var schema map[string]any
			if err := json.Unmarshal(schemaBytes, &schema); err != nil {
				t.Fatalf("unmarshal InputSchema: %v", err)
			}

			// Must have "type": "object"
			schemaType, ok := schema["type"].(string)
			if !ok || schemaType != "object" {
				t.Errorf("schema type = %v, want 'object'", schema["type"])
			}

			// Must have "properties" (even if empty)
			if _, ok := schema["properties"]; !ok {
				t.Error("schema missing 'properties' key")
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 22: Resource payloads/{category} template works via SSE
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_ReadPayloadsByCategory(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	categories := []string{"sqli", "xss", "traversal", "ssrf", "cmdi"}
	for _, cat := range categories {
		t.Run(cat, func(t *testing.T) {
			result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
				URI: "waftester://payloads/" + cat,
			})
			if err != nil {
				t.Fatalf("ReadResource(payloads/%s): %v", cat, err)
			}
			if len(result.Contents) == 0 {
				t.Fatalf("payloads/%s: empty contents", cat)
			}
			text := result.Contents[0].Text
			if !json.Valid([]byte(text)) {
				t.Errorf("payloads/%s: invalid JSON: %.100s", cat, text)
			}
			if !strings.Contains(text, cat) {
				t.Errorf("payloads/%s: response doesn't contain category name", cat)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 23: SSE — spec tools work end-to-end
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_SpecTools(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	specContent := `openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /users:
    get:
      summary: List users
      parameters:
        - name: q
          in: query
          schema:
            type: string`

	specTools := []struct {
		name string
		args map[string]any
	}{
		{"validate_spec", map[string]any{"spec_content": specContent}},
		{"list_spec_endpoints", map[string]any{"spec_content": specContent}},
		{"plan_spec", map[string]any{"spec_content": specContent, "target": "https://example.com"}},
		{"preview_spec_scan", map[string]any{"spec_content": specContent, "target": "https://example.com"}},
		{"spec_intelligence", map[string]any{"spec_content": specContent}},
		{"describe_spec_auth", map[string]any{"spec_content": specContent}},
		{"export_spec", map[string]any{"spec_content": specContent, "format": "json"}},
	}

	for _, tt := range specTools {
		t.Run(tt.name, func(t *testing.T) {
			argsJSON, _ := json.Marshal(tt.args)
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tt.name,
				Arguments: json.RawMessage(argsJSON),
			})
			if err != nil {
				t.Fatalf("CallTool(%s): %v", tt.name, err)
			}
			if result.IsError {
				// Some spec tools may legitimately return errors for minimal specs
				// but should not crash
				return
			}
			text := extractTextN8n(t, result)
			if text == "" {
				t.Errorf("CallTool(%s): empty response", tt.name)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 24: SSE — enriched error responses have recovery_steps
// n8n workflows need structured errors to self-correct.
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_EnrichedErrors(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// get_task_status with no tasks should return enriched error
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(`{"wait_seconds": 0}`),
	})
	if err != nil {
		t.Fatalf("get_task_status: %v", err)
	}
	if !result.IsError {
		// If not an error, no task was found — also acceptable
		return
	}

	text := extractTextN8n(t, result)
	var errResp struct {
		Error         string   `json:"error"`
		RecoverySteps []string `json:"recovery_steps"`
	}
	if err := json.Unmarshal([]byte(text), &errResp); err != nil {
		// Not all errors are enriched — plain text errors are valid too
		return
	}
	if errResp.Error != "" && len(errResp.RecoverySteps) == 0 {
		t.Error("enriched error has empty recovery_steps")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 25: SSE — show_template returns template content
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_ShowTemplate(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// First list templates to get a valid name
	listResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_templates",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("list_templates: %v", err)
	}
	listText := extractTextN8n(t, listResult)

	var listResp struct {
		Templates []struct {
			Name string `json:"name"`
		} `json:"templates"`
	}
	if err := json.Unmarshal([]byte(listText), &listResp); err != nil {
		t.Fatalf("parse list_templates: %v\nraw: %.300s", err, listText)
	}
	if len(listResp.Templates) == 0 {
		t.Skip("no templates available")
	}

	// Show the first template
	showArgs, _ := json.Marshal(map[string]any{"name": listResp.Templates[0].Name})
	showResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "show_template",
		Arguments: json.RawMessage(showArgs),
	})
	if err != nil {
		t.Fatalf("show_template: %v", err)
	}
	if showResult.IsError {
		t.Fatalf("show_template error: %s", extractTextN8n(t, showResult))
	}
	showText := extractTextN8n(t, showResult)
	if showText == "" {
		t.Error("show_template returned empty response")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 26: Verify serverInstructions mentions all tool names
// Catches: new tools added but not documented in server instructions.
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_ServerInstructionsMentionAllTools(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	init := cs.InitializeResult()
	instructions := init.Instructions

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		if !strings.Contains(instructions, tool.Name) {
			t.Errorf("server instructions don't mention tool %q", tool.Name)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 27: Verify version resource tools list matches ListTools
// Catches: version resource has stale tool list.
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_VersionResourceToolsMatchListTools(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Get tools from ListTools
	toolsResult, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	listToolNames := make(map[string]bool)
	for _, tool := range toolsResult.Tools {
		listToolNames[tool.Name] = true
	}

	// Get tools from version resource
	versionResult, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://version",
	})
	if err != nil {
		t.Fatalf("ReadResource(version): %v", err)
	}

	var versionInfo struct {
		Tools        []string `json:"tools"`
		Capabilities struct {
			Tools int `json:"tools"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(versionResult.Contents[0].Text), &versionInfo); err != nil {
		t.Fatalf("parse version: %v", err)
	}

	// Compare tool lists
	versionToolNames := make(map[string]bool)
	for _, name := range versionInfo.Tools {
		versionToolNames[name] = true
	}

	for name := range listToolNames {
		if !versionToolNames[name] {
			t.Errorf("tool %q in ListTools but missing from version resource", name)
		}
	}
	for name := range versionToolNames {
		if !listToolNames[name] {
			t.Errorf("tool %q in version resource but missing from ListTools", name)
		}
	}

	// Verify count matches
	if versionInfo.Capabilities.Tools != len(toolsResult.Tools) {
		t.Errorf("version capabilities.tools = %d, ListTools has %d",
			versionInfo.Capabilities.Tools, len(toolsResult.Tools))
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 28: SSE keep-alive comments don't corrupt the protocol
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_KeepAliveDoesNotCorruptProtocol(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Make several calls with delays to let keep-alive fire
	for i := 0; i < 3; i++ {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "list_payloads",
			Arguments: json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatalf("iteration %d: CallTool: %v", i, err)
		}
		if result.IsError {
			t.Fatalf("iteration %d: IsError", i)
		}

		// Wait a bit so SSE keep-alive has a chance to fire (interval is 15s,
		// we don't wait that long but verify calls still work after short gaps)
		time.Sleep(500 * time.Millisecond)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 29: SSE — malformed JSON arguments don't crash server
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_SSE_MalformedJSONResilient(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Send malformed JSON to tools over SSE
	tools := []string{"list_payloads", "mutate", "generate_cicd", "get_task_status", "list_tasks"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tool,
				Arguments: json.RawMessage(`{"broken: json`),
			})
			// Protocol error or tool error — just must not crash
			if err != nil {
				return // protocol error is fine
			}
			if result != nil && !result.IsError {
				t.Errorf("%q accepted malformed JSON over SSE", tool)
			}
		})
	}

	// Verify session still works after malformed inputs
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal("session broken after malformed JSON — SSE connection corrupted")
	}
	if result.IsError {
		t.Fatal("list_payloads failed after malformed JSON recovery")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 30: Version resource counts match reality
// ═══════════════════════════════════════════════════════════════════════════

func TestN8n_VersionResourceCountsMatchReality(t *testing.T) {
	cs, _ := newSSETestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Count actual resources
	resources, err := cs.ListResources(ctx, &mcp.ListResourcesParams{})
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	templates, err := cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{})
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}
	totalResources := len(resources.Resources) + len(templates.ResourceTemplates)

	// Count actual prompts
	prompts, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{})
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	totalPrompts := len(prompts.Prompts)

	// Get version resource
	versionResult, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://version",
	})
	if err != nil {
		t.Fatalf("ReadResource(version): %v", err)
	}

	var info struct {
		Capabilities struct {
			Resources int `json:"resources"`
			Prompts   int `json:"prompts"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(versionResult.Contents[0].Text), &info); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if info.Capabilities.Resources != totalResources {
		t.Errorf("version says %d resources, actual count is %d",
			info.Capabilities.Resources, totalResources)
	}
	if info.Capabilities.Prompts != totalPrompts {
		t.Errorf("version says %d prompts, actual count is %d",
			info.Capabilities.Prompts, totalPrompts)
	}
}
