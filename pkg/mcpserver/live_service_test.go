package mcpserver_test

// Round 12: Live service exerciser — every tool, resource, and prompt
// is exercised through the actual MCP session to verify end-to-end
// routing, argument parsing, and response structure.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/mcpserver"
)

// ---------------------------------------------------------------------------
// Async tools: discover_bypasses, event_crawl, scan_spec
// These return task_id on success. Tests verify arg validation + task launch.
// ---------------------------------------------------------------------------

func TestDiscoverBypasses_ReturnsTaskID(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_bypasses",
		Arguments: json.RawMessage(`{"target": "https://example.com/search?q=test"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("discover_bypasses returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parsing async response: %v\nraw: %s", err, text)
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
	if resp.Tool != "discover_bypasses" {
		t.Errorf("tool = %q, want 'discover_bypasses'", resp.Tool)
	}
}

func TestDiscoverBypasses_RejectsEmptyTarget(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_bypasses",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := extractText(t, result)
	if !strings.Contains(text, "target") {
		t.Errorf("expected error about missing target, got: %s", text)
	}
}

func TestEventCrawl_ReturnsTaskID(t *testing.T) {
	cs := newTestSessionWithHeadless(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "event_crawl",
		Arguments: json.RawMessage(`{"target": "https://example.com", "max_clicks": 5}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("event_crawl returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parsing async response: %v\nraw: %s", err, text)
	}
	if resp.TaskID == "" {
		t.Fatal("task_id should not be empty")
	}
	if resp.Status != "running" {
		t.Errorf("status = %q, want 'running'", resp.Status)
	}
	if resp.Tool != "event_crawl" {
		t.Errorf("tool = %q, want 'event_crawl'", resp.Tool)
	}
}

func TestEventCrawl_RejectsEmptyTarget(t *testing.T) {
	cs := newTestSessionWithHeadless(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "event_crawl",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := extractText(t, result)
	if !strings.Contains(text, "target") {
		t.Errorf("expected error about missing target, got: %s", text)
	}
}

func TestEventCrawl_UnavailableWithoutHeadless(t *testing.T) {
	// Default newTestSession has no EventCrawlFn — event_crawl shouldn't be registered.
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "event_crawl",
		Arguments: json.RawMessage(`{"target": "https://example.com"}`),
	})
	if err != nil {
		// Tool doesn't exist — MCP SDK returns error for unknown tools
		return
	}
	// If we got here, the tool exists but should return an error
	if result.IsError || strings.Contains(extractText(t, result), "not available") {
		return
	}
	t.Error("event_crawl should not be available without headless config")
}

func TestScanSpec_ReturnsTaskID(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan_spec",
		Arguments: json.RawMessage(`{
			"target": "https://example.com",
			"spec_content": "openapi: '3.0.0'\ninfo:\n  title: Test\n  version: '1.0'\npaths:\n  /test:\n    get:\n      summary: Test"
		}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("scan_spec returned error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parsing async response: %v\nraw: %s", err, text)
	}
	if resp.TaskID == "" {
		t.Fatal("task_id should not be empty")
	}
	if resp.Status != "running" {
		t.Errorf("status = %q, want 'running'", resp.Status)
	}
	if resp.Tool != "scan_spec" {
		t.Errorf("tool = %q, want 'scan_spec'", resp.Tool)
	}
}

// ---------------------------------------------------------------------------
// Fast spec tools: preview_spec_scan, spec_intelligence, describe_spec_auth,
// export_spec — exercised via live MCP session.
// ---------------------------------------------------------------------------

const minimalOpenAPISpec = `openapi: "3.0.0"
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
            type: string
  /users/{id}:
    get:
      summary: Get user
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer`

func TestPreviewSpecScan_LiveSession(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"target":       "https://example.com",
		"spec_content": minimalOpenAPISpec,
	})

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "preview_spec_scan",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := extractText(t, result)
	if text == "" {
		t.Fatal("expected non-empty response")
	}
	// Should contain endpoint info from the spec
	if !strings.Contains(text, "user") && !strings.Contains(text, "endpoint") && !strings.Contains(text, "path") {
		t.Errorf("preview response should reference spec content, got: %.200s", text)
	}
}

func TestSpecIntelligence_LiveSession(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"spec_content": minimalOpenAPISpec,
	})

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "spec_intelligence",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := extractText(t, result)
	if text == "" {
		t.Fatal("expected non-empty response")
	}
}

func TestDescribeSpecAuth_LiveSession(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"spec_content": minimalOpenAPISpec,
	})

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "describe_spec_auth",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := extractText(t, result)
	if text == "" {
		t.Fatal("expected non-empty response")
	}
}

func TestExportSpec_LiveSession(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"spec_content": minimalOpenAPISpec,
		"format":       "json",
	})

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "export_spec",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := extractText(t, result)
	if text == "" {
		t.Fatal("expected non-empty response")
	}
}

// ---------------------------------------------------------------------------
// Resources: payloads/unified, spec-formats, intelligence-layers
// ---------------------------------------------------------------------------

func TestReadResource_PayloadsUnified(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://payloads/unified",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(result.Contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	text := result.Contents[0].Text
	if !json.Valid([]byte(text)) {
		t.Errorf("payloads/unified should return valid JSON, got: %.200s", text)
	}
}

func TestReadResource_SpecFormats(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://spec-formats",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(result.Contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	text := result.Contents[0].Text
	if !json.Valid([]byte(text)) {
		t.Errorf("spec-formats should return valid JSON, got: %.200s", text)
	}
	if !strings.Contains(text, "openapi") && !strings.Contains(text, "OpenAPI") {
		t.Errorf("spec-formats should mention OpenAPI, got: %.200s", text)
	}
}

func TestReadResource_IntelligenceLayers(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://intelligence-layers",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(result.Contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	text := result.Contents[0].Text
	if !json.Valid([]byte(text)) {
		t.Errorf("intelligence-layers should return valid JSON, got: %.200s", text)
	}
}

// ---------------------------------------------------------------------------
// Prompts: template_scan, spec_security_audit
// ---------------------------------------------------------------------------

func TestGetPrompt_TemplateScan(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "template_scan",
		Arguments: map[string]string{
			"target": "https://example.com",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(result.Messages) == 0 {
		t.Fatal("prompt returned no messages")
	}

	// All messages should have non-empty content
	for i, msg := range result.Messages {
		if msg.Content.(*mcp.TextContent).Text == "" {
			t.Errorf("message[%d] has empty text", i)
		}
	}

	// Should reference templates
	combined := ""
	for _, msg := range result.Messages {
		combined += msg.Content.(*mcp.TextContent).Text
	}
	if !strings.Contains(combined, "template") && !strings.Contains(combined, "Template") {
		t.Errorf("template_scan prompt should reference templates, got: %.200s", combined)
	}
}

func TestGetPrompt_SpecSecurityAudit(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "spec_security_audit",
		Arguments: map[string]string{
			"target": "https://example.com",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(result.Messages) == 0 {
		t.Fatal("prompt returned no messages")
	}

	// Should reference spec/API/OpenAPI
	combined := ""
	for _, msg := range result.Messages {
		combined += msg.Content.(*mcp.TextContent).Text
	}
	if !strings.Contains(combined, "spec") && !strings.Contains(combined, "API") && !strings.Contains(combined, "OpenAPI") {
		t.Errorf("spec_security_audit prompt should reference specs/APIs, got: %.200s", combined)
	}
}

// ---------------------------------------------------------------------------
// Helper: newTestSessionWithHeadless configures EventCrawlFn for tests.
// ---------------------------------------------------------------------------

func newTestSessionWithHeadless(t *testing.T) *mcp.ClientSession {
	t.Helper()

	srv := mcpserver.New(&mcpserver.Config{
		PayloadDir: "../../payloads",
		EventCrawlFn: func(_ context.Context, _ string, _, _ int) ([]mcpserver.EventCrawlResult, []string, error) {
			return []mcpserver.EventCrawlResult{
				{
					Element:        map[string]any{"tag": "button", "id": "btn"},
					DiscoveredURLs: []string{"https://example.com/api"},
					DOMChanged:     true,
				},
			}, []string{"https://example.com/api"}, nil
		},
	})
	t.Cleanup(func() { srv.Stop() })

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	client := mcp.NewClient(&mcp.Implementation{
		Name: "test-client", Version: "0.0.1",
	}, nil)

	ctx := context.Background()
	go func() { _ = srv.MCPServer().Run(ctx, serverTransport) }()

	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}
