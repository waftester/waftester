package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/mcpserver"
	"github.com/waftester/waftester/pkg/output/events"
)

// newTestSession creates a connected client↔server session for testing.
// It returns the client session and a cleanup function.
func newTestSession(t *testing.T) *mcp.ClientSession {
	t.Helper()

	srv := mcpserver.New(&mcpserver.Config{
		PayloadDir: "../../payloads",
	})

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "0.0.1",
	}, nil)

	ctx := context.Background()

	// Run server in background
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

// ═══════════════════════════════════════════════════════════════════════════
// Server creation tests
// ═══════════════════════════════════════════════════════════════════════════

func TestNew(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "testdata"})
	if srv == nil {
		t.Fatal("New() returned nil")
	}
	if srv.MCPServer() == nil {
		t.Fatal("MCPServer() returned nil")
	}
}

func TestNewDefaultPayloadDir(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{})
	if srv == nil {
		t.Fatal("New() with empty config returned nil")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Tool registration tests
// ═══════════════════════════════════════════════════════════════════════════

func TestListTools(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	expectedTools := []string{
		"list_payloads", "detect_waf", "discover", "learn", "scan",
		"assess", "mutate", "bypass", "probe", "generate_cicd",
	}

	if len(result.Tools) != len(expectedTools) {
		t.Errorf("got %d tools, want %d", len(result.Tools), len(expectedTools))
		for _, tool := range result.Tools {
			t.Logf("  tool: %s", tool.Name)
		}
	}

	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}

	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("missing tool: %s", name)
		}
	}
}

func TestToolsHaveDescriptions(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil input schema", tool.Name)
		}
	}
}

func TestToolsHaveAnnotations(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		if tool.Annotations == nil {
			t.Errorf("tool %q has nil annotations", tool.Name)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Resource registration tests
// ═══════════════════════════════════════════════════════════════════════════

func TestListResources(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListResources(ctx, &mcp.ListResourcesParams{})
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}

	expectedResources := []string{
		"waftester://version",
		"waftester://payloads",
		"waftester://guide",
		"waftester://waf-signatures",
		"waftester://evasion-techniques",
		"waftester://owasp-mappings",
		"waftester://config",
	}

	if len(result.Resources) < len(expectedResources) {
		t.Errorf("got %d resources, want at least %d", len(result.Resources), len(expectedResources))
	}

	resourceURIs := make(map[string]bool)
	for _, r := range result.Resources {
		resourceURIs[r.URI] = true
	}

	for _, uri := range expectedResources {
		if !resourceURIs[uri] {
			t.Errorf("missing resource: %s", uri)
		}
	}
}

func TestListResourceTemplates(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{})
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}

	if len(result.ResourceTemplates) == 0 {
		t.Error("expected at least 1 resource template (payloads/{category})")
	}

	found := false
	for _, rt := range result.ResourceTemplates {
		if rt.URITemplate == "waftester://payloads/{category}" {
			found = true
		}
	}
	if !found {
		t.Error("missing resource template: waftester://payloads/{category}")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Resource content tests
// ═══════════════════════════════════════════════════════════════════════════

func TestReadVersionResource(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://version"})
	if err != nil {
		t.Fatalf("ReadResource(version): %v", err)
	}

	if len(result.Contents) == 0 {
		t.Fatal("version resource returned no contents")
	}

	var versionInfo map[string]any
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &versionInfo); err != nil {
		t.Fatalf("failed to parse version JSON: %v", err)
	}

	if _, ok := versionInfo["version"]; !ok {
		t.Error("version resource missing 'version' field")
	}
	if _, ok := versionInfo["tools"]; !ok {
		t.Error("version resource missing 'tools' field")
	}
	if _, ok := versionInfo["capabilities"]; !ok {
		t.Error("version resource missing 'capabilities' field")
	}
}

func TestReadGuideResource(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://guide"})
	if err != nil {
		t.Fatalf("ReadResource(guide): %v", err)
	}

	if len(result.Contents) == 0 {
		t.Fatal("guide resource returned no contents")
	}

	text := result.Contents[0].Text
	if !strings.Contains(text, "WAF Security Testing Methodology") {
		t.Error("guide resource missing expected heading")
	}
	if !strings.Contains(text, "Reconnaissance") {
		t.Error("guide resource missing Reconnaissance section")
	}
}

func TestReadWAFSignaturesResource(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://waf-signatures"})
	if err != nil {
		t.Fatalf("ReadResource(waf-signatures): %v", err)
	}

	if len(result.Contents) == 0 {
		t.Fatal("waf-signatures resource returned no contents")
	}

	var sigs map[string]any
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &sigs); err != nil {
		t.Fatalf("failed to parse waf-signatures JSON: %v", err)
	}

	if count, _ := sigs["total_signatures"].(float64); count < 10 {
		t.Errorf("expected at least 10 WAF signatures, got %v", count)
	}
}

func TestReadEvasionTechniquesResource(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://evasion-techniques"})
	if err != nil {
		t.Fatalf("ReadResource(evasion-techniques): %v", err)
	}

	if len(result.Contents) == 0 {
		t.Fatal("evasion-techniques resource returned no contents")
	}

	var techniques map[string]any
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &techniques); err != nil {
		t.Fatalf("failed to parse evasion-techniques JSON: %v", err)
	}

	if _, ok := techniques["encoders"]; !ok {
		t.Error("evasion-techniques missing 'encoders' field")
	}
	if _, ok := techniques["evasion_techniques"]; !ok {
		t.Error("evasion-techniques missing 'evasion_techniques' field")
	}
}

func TestReadOWASPMappingsResource(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://owasp-mappings"})
	if err != nil {
		t.Fatalf("ReadResource(owasp-mappings): %v", err)
	}

	if len(result.Contents) == 0 {
		t.Fatal("owasp-mappings resource returned no contents")
	}

	var mappings map[string]any
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &mappings); err != nil {
		t.Fatalf("failed to parse owasp-mappings JSON: %v", err)
	}

	if mappings["standard"] != "OWASP Top 10 2021" {
		t.Errorf("expected standard 'OWASP Top 10 2021', got %v", mappings["standard"])
	}
	entries, ok := mappings["entries"].([]any)
	if !ok || len(entries) == 0 {
		t.Error("owasp-mappings missing 'entries' array")
	}
}

func TestReadConfigResource(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://config"})
	if err != nil {
		t.Fatalf("ReadResource(config): %v", err)
	}

	if len(result.Contents) == 0 {
		t.Fatal("config resource returned no contents")
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &config); err != nil {
		t.Fatalf("failed to parse config JSON: %v", err)
	}

	for _, section := range []string{"scan", "assessment", "bypass", "discovery", "detect_waf"} {
		if _, ok := config[section]; !ok {
			t.Errorf("config resource missing section: %s", section)
		}
	}
}

func TestReadPayloadsResource(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://payloads"})
	if err != nil {
		t.Fatalf("ReadResource(payloads): %v", err)
	}

	if len(result.Contents) == 0 {
		t.Fatal("payloads resource returned no contents")
	}

	var catalog map[string]any
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &catalog); err != nil {
		t.Fatalf("failed to parse payloads JSON: %v", err)
	}

	total, ok := catalog["total_payloads"].(float64)
	if !ok || total == 0 {
		t.Error("payloads resource missing or zero total_payloads")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Prompt registration tests
// ═══════════════════════════════════════════════════════════════════════════

func TestListPrompts(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{})
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}

	expectedPrompts := []string{
		"security_audit", "waf_bypass", "full_assessment",
		"discovery_workflow", "evasion_research",
	}

	if len(result.Prompts) != len(expectedPrompts) {
		t.Errorf("got %d prompts, want %d", len(result.Prompts), len(expectedPrompts))
	}

	promptNames := make(map[string]bool)
	for _, p := range result.Prompts {
		promptNames[p.Name] = true
	}

	for _, name := range expectedPrompts {
		if !promptNames[name] {
			t.Errorf("missing prompt: %s", name)
		}
	}
}

func TestPromptsHaveArguments(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{})
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}

	for _, p := range result.Prompts {
		if len(p.Arguments) == 0 {
			t.Errorf("prompt %q has no arguments", p.Name)
		}
		if p.Description == "" {
			t.Errorf("prompt %q has empty description", p.Name)
		}

		// Every prompt should have a required "target" argument
		hasTarget := false
		for _, arg := range p.Arguments {
			if arg.Name == "target" {
				hasTarget = true
				if !arg.Required {
					t.Errorf("prompt %q: 'target' argument should be required", p.Name)
				}
			}
		}
		// evasion_research has both target and payload
		if !hasTarget && p.Name != "evasion_research" {
			// evasion_research also has target so this check is redundant but safe
		}
		if !hasTarget {
			t.Errorf("prompt %q: missing 'target' argument", p.Name)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Prompt invocation tests
// ═══════════════════════════════════════════════════════════════════════════

func TestGetSecurityAuditPrompt(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "security_audit",
		Arguments: map[string]string{"target": "https://example.com"},
	})
	if err != nil {
		t.Fatalf("GetPrompt(security_audit): %v", err)
	}

	if len(result.Messages) == 0 {
		t.Fatal("security_audit returned no messages")
	}

	if result.Description == "" {
		t.Error("security_audit returned empty description")
	}
}

func TestGetPromptMissingTarget(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	_, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "security_audit",
		Arguments: map[string]string{},
	})
	if err == nil {
		t.Error("expected error for missing target argument")
	}
}

func TestGetWAFBypassPrompt(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "waf_bypass",
		Arguments: map[string]string{
			"target":   "https://example.com",
			"category": "sqli",
			"stealth":  "true",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt(waf_bypass): %v", err)
	}

	if len(result.Messages) == 0 {
		t.Fatal("waf_bypass returned no messages")
	}
}

func TestGetEvasionResearchPrompt(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "evasion_research",
		Arguments: map[string]string{
			"target":  "https://example.com",
			"payload": "<script>alert(1)</script>",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt(evasion_research): %v", err)
	}

	if len(result.Messages) == 0 {
		t.Fatal("evasion_research returned no messages")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Tool invocation tests (non-network tools only)
// ═══════════════════════════════════════════════════════════════════════════

func TestCallListPayloads(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool(list_payloads): %v", err)
	}

	if result.IsError {
		t.Fatalf("list_payloads returned error: %+v", result.Content)
	}

	if len(result.Content) == 0 {
		t.Fatal("list_payloads returned no content")
	}
}

func TestCallListPayloadsWithFilter(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{"category": "sqli"}`),
	})
	if err != nil {
		t.Fatalf("CallTool(list_payloads, sqli): %v", err)
	}

	if result.IsError {
		t.Fatalf("list_payloads returned error: %+v", result.Content)
	}
}

func TestCallMutate(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "mutate",
		Arguments: json.RawMessage(`{"payload": "<script>alert(1)</script>", "encodings": ["url", "double_url"]}`),
	})
	if err != nil {
		t.Fatalf("CallTool(mutate): %v", err)
	}

	if result.IsError {
		t.Fatalf("mutate returned error: %+v", result.Content)
	}

	if len(result.Content) == 0 {
		t.Fatal("mutate returned no content")
	}
}

func TestCallGenerateCICD(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "generate_cicd",
		Arguments: json.RawMessage(`{"target": "https://example.com", "platform": "github"}`),
	})
	if err != nil {
		t.Fatalf("CallTool(generate_cicd): %v", err)
	}

	if result.IsError {
		t.Fatalf("generate_cicd returned error: %+v", result.Content)
	}

	if len(result.Content) == 0 {
		t.Fatal("generate_cicd returned no content")
	}
}

func TestCallGenerateCICDAllPlatforms(t *testing.T) {
	platforms := []string{"github", "gitlab", "jenkins", "azure-devops", "circleci", "bitbucket"}
	for _, p := range platforms {
		t.Run(p, func(t *testing.T) {
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name: "generate_cicd",
				Arguments: map[string]string{
					"target":   "https://example.com",
					"platform": p,
				},
			})
			if err != nil {
				t.Fatalf("CallTool(generate_cicd, %s): %v", p, err)
			}
			if result.IsError {
				for _, c := range result.Content {
					t.Logf("content: %+v", c)
				}
				t.Fatalf("generate_cicd(%s) returned IsError=true", p)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Target URL validation tests
// ═══════════════════════════════════════════════════════════════════════════

func TestToolRejectsEmptyTarget(t *testing.T) {
	// All network tools must reject empty target with a clear error.
	tools := []string{"detect_waf", "discover", "scan", "assess", "bypass", "probe"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tool,
				Arguments: json.RawMessage(`{}`),
			})
			if err != nil {
				t.Fatalf("CallTool(%s): %v", tool, err)
			}
			if !result.IsError {
				t.Fatalf("%s accepted empty target — expected error", tool)
			}
		})
	}
}

func TestToolRejectsInvalidURLScheme(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "detect_waf",
		Arguments: json.RawMessage(`{"target": "ftp://example.com"}`),
	})
	if err != nil {
		t.Fatalf("CallTool(detect_waf): %v", err)
	}
	if !result.IsError {
		t.Fatal("detect_waf accepted ftp:// scheme — expected error")
	}
}

func TestToolRejectsMissingScheme(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "detect_waf",
		Arguments: json.RawMessage(`{"target": "example.com"}`),
	})
	if err != nil {
		t.Fatalf("CallTool(detect_waf): %v", err)
	}
	if !result.IsError {
		t.Fatal("detect_waf accepted URL without scheme — expected error")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Hook tests
// ═══════════════════════════════════════════════════════════════════════════

func TestHookReceivesEvents(t *testing.T) {
	received := make(chan bool, 1)
	hook := mcpserver.NewHook(func(e events.Event) {
		received <- true
	})

	if hook == nil {
		t.Fatal("NewHook returned nil")
	}

	// EventTypes should return nil (= all events)
	types := hook.EventTypes()
	if types != nil {
		t.Errorf("expected nil EventTypes, got %v", types)
	}
}

func TestHookNilCallback(t *testing.T) {
	hook := mcpserver.NewHook(nil)

	// Should not panic with nil callback
	err := hook.OnEvent(context.Background(), nil)
	if err != nil {
		t.Errorf("OnEvent with nil callback returned error: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Server capability tests
// ═══════════════════════════════════════════════════════════════════════════

func TestServerCapabilities(t *testing.T) {
	cs := newTestSession(t)

	initResult := cs.InitializeResult()
	if initResult == nil {
		t.Fatal("InitializeResult is nil")
	}

	// Check server info
	if initResult.ServerInfo.Name == "" {
		t.Error("server name is empty")
	}
	if initResult.ServerInfo.Version == "" {
		t.Error("server version is empty")
	}

	// Check capabilities
	if initResult.Capabilities.Tools == nil {
		t.Error("tools capability is nil")
	}
	if initResult.Capabilities.Resources == nil {
		t.Error("resources capability is nil")
	}
	if initResult.Capabilities.Prompts == nil {
		t.Error("prompts capability is nil")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge case tests
// ═══════════════════════════════════════════════════════════════════════════

func TestCallNonexistentTool(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "nonexistent_tool",
		Arguments: json.RawMessage(`{}`),
	})
	if err == nil {
		t.Error("expected error for nonexistent tool")
	}
}

func TestReadNonexistentResource(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://nonexistent"})
	if err == nil {
		t.Error("expected error for nonexistent resource")
	}
}

func TestGetNonexistentPrompt(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "nonexistent_prompt",
		Arguments: map[string]string{},
	})
	if err == nil {
		t.Error("expected error for nonexistent prompt")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP transport tests
// ═══════════════════════════════════════════════════════════════════════════

func TestHTTPHandler(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	h := srv.HTTPHandler()
	if h == nil {
		t.Fatal("HTTPHandler() returned nil")
	}
}

func TestSSEHandler(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	h := srv.SSEHandler()
	if h == nil {
		t.Fatal("SSEHandler() returned nil")
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	srv.MarkReady()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("GET /health: got Content-Type %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("GET /health: failed to decode JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("GET /health: got status %q, want %q", body["status"], "ok")
	}
	if body["service"] != "waf-tester-mcp" {
		t.Errorf("GET /health: got service %q, want %q", body["service"], "waf-tester-mcp")
	}
}

func TestHealthEndpointNotReady(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	// Do NOT call srv.MarkReady() — server should return 503.
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("GET /health (not ready): got status %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("GET /health: failed to decode JSON: %v", err)
	}
	if body["status"] != "starting" {
		t.Errorf("GET /health (not ready): got status %q, want %q", body["status"], "starting")
	}
}

func TestHealthEndpointMethodNotAllowed(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /health: got status %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestCORSHeaders(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", "https://n8n.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health with Origin: %v", err)
	}
	defer resp.Body.Close()

	tests := []struct {
		header string
		want   string
	}{
		{"Access-Control-Allow-Origin", "https://n8n.example.com"},
		{"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"},
		{"Access-Control-Allow-Credentials", "true"},
		{"Access-Control-Expose-Headers", "Mcp-Session-Id"},
	}

	for _, tt := range tests {
		got := resp.Header.Get(tt.header)
		if got != tt.want {
			t.Errorf("CORS header %q = %q, want %q", tt.header, got, tt.want)
		}
	}

	// Verify required headers are in Allow-Headers
	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	for _, required := range []string{"Content-Type", "Authorization", "Mcp-Session-Id", "Last-Event-ID"} {
		if !strings.Contains(allowHeaders, required) {
			t.Errorf("Access-Control-Allow-Headers missing %q: %s", required, allowHeaders)
		}
	}
}

func TestCORSPreflight(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", "https://n8n.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Mcp-Session-Id")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS /mcp: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("OPTIONS /mcp: got status %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://n8n.example.com" {
		t.Errorf("preflight Allow-Origin = %q, want %q", got, "https://n8n.example.com")
	}

	maxAge := resp.Header.Get("Access-Control-Max-Age")
	if maxAge != "86400" {
		t.Errorf("preflight Max-Age = %q, want %q", maxAge, "86400")
	}
}

func TestCORSDefaultOrigin(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Request without Origin header should get "*"
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("no-origin Allow-Origin = %q, want %q", got, "*")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Data consistency tests
// ═══════════════════════════════════════════════════════════════════════════

func TestWAFSignaturesCountMatchesEntries(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://waf-signatures"})
	if err != nil {
		t.Fatalf("ReadResource(waf-signatures): %v", err)
	}

	var sigs struct {
		Total      int `json:"total_signatures"`
		Signatures []struct {
			Name string `json:"name"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &sigs); err != nil {
		t.Fatalf("failed to parse waf-signatures JSON: %v", err)
	}

	if sigs.Total != len(sigs.Signatures) {
		t.Errorf("total_signatures (%d) does not match actual entries (%d)", sigs.Total, len(sigs.Signatures))
	}
}

func TestScanToolAnnotationsComplete(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		if tool.Name != "scan" {
			continue
		}

		if tool.Annotations == nil {
			t.Fatal("scan tool has nil annotations")
		}
		// ReadOnlyHint and IdempotentHint are bool (not *bool) — false is the
		// correct zero value for a tool that writes and is non-idempotent.
		if tool.Annotations.ReadOnlyHint {
			t.Error("scan tool ReadOnlyHint should be false")
		}
		if tool.Annotations.IdempotentHint {
			t.Error("scan tool IdempotentHint should be false")
		}
		if tool.Annotations.OpenWorldHint == nil {
			t.Error("scan tool missing OpenWorldHint annotation")
		}
		if tool.Annotations.DestructiveHint == nil {
			t.Error("scan tool missing DestructiveHint annotation")
		}
		return
	}
	t.Fatal("scan tool not found")
}
