package mcpserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/defaults"
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
	t.Cleanup(func() { srv.Stop() })

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "0.0.1",
	}, nil)

	ctx := context.Background()

	// Run server in background
	go func() {
		// Best-effort: server errors are not actionable in tests;
		// the client-side assertions surface any real failures.
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
	defer srv.Stop()
	if srv == nil {
		t.Fatal("New() returned nil")
	}
	if srv.MCPServer() == nil {
		t.Fatal("MCPServer() returned nil")
	}
}

func TestNewDefaultPayloadDir(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{})
	defer srv.Stop()
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
		"list_tampers", "discover_bypasses",
		"get_task_status", "cancel_task", "list_tasks",
		"validate_spec", "list_spec_endpoints", "plan_spec", "scan_spec",
		"compare_baselines",
		"preview_spec_scan", "spec_intelligence", "describe_spec_auth", "export_spec",
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
		"discovery_workflow", "evasion_research", "template_scan",
		"spec_security_audit",
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

		// Every prompt should have a required primary argument.
		// Most prompts use "target"; spec_security_audit uses "spec_content".
		hasRequired := false
		for _, arg := range p.Arguments {
			if arg.Required {
				hasRequired = true
			}
		}
		if !hasRequired {
			t.Errorf("prompt %q: missing required argument", p.Name)
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

func TestNewHookCreation(t *testing.T) {
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
	defer srv.Stop()
	h := srv.HTTPHandler()
	if h == nil {
		t.Fatal("HTTPHandler() returned nil")
	}
}

func TestSSEHandler(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
	h := srv.SSEHandler()
	if h == nil {
		t.Fatal("SSEHandler() returned nil")
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
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
	defer srv.Stop()
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
	defer srv.Stop()
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
	defer srv.Stop()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:3000")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health with Origin: %v", err)
	}
	defer resp.Body.Close()

	tests := []struct {
		header string
		want   string
	}{
		{"Access-Control-Allow-Origin", "http://localhost:3000"},
		{"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"},
		{"Access-Control-Allow-Credentials", "true"},
		{"Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version"},
		{"Vary", "Origin"},
	}

	for _, tt := range tests {
		got := resp.Header.Get(tt.header)
		if got != tt.want {
			t.Errorf("CORS header %q = %q, want %q", tt.header, got, tt.want)
		}
	}

	// Verify required headers are in Allow-Headers
	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	for _, required := range []string{"Content-Type", "Authorization", "Mcp-Session-Id", "MCP-Protocol-Version", "Last-Event-ID"} {
		if !strings.Contains(allowHeaders, required) {
			t.Errorf("Access-Control-Allow-Headers missing %q: %s", required, allowHeaders)
		}
	}
}

func TestCORSPreflight(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", "http://127.0.0.1:5173")
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

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:5173" {
		t.Errorf("preflight Allow-Origin = %q, want %q", got, "http://127.0.0.1:5173")
	}

	maxAge := resp.Header.Get("Access-Control-Max-Age")
	if maxAge != "86400" {
		t.Errorf("preflight Max-Age = %q, want %q", maxAge, "86400")
	}
}

func TestCORSDefaultOrigin(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Request without Origin header should NOT get any CORS headers (per Fetch spec).
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("no-origin Allow-Origin = %q, want empty (no CORS headers without Origin)", got)
	}

	// Vary: Origin should still be present for caching correctness.
	if got := resp.Header.Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want %q", got, "Origin")
	}
}

func TestCORSRejectsNonLocalhost(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", "https://evil.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health with non-localhost Origin: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("non-localhost Allow-Origin = %q, want empty", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("non-localhost Allow-Credentials = %q, want empty", got)
	}

	// Vary: Origin should still be set for caching correctness.
	if got := resp.Header.Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want %q", got, "Origin")
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
	srv.MarkReady()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	tests := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
	}
	for _, tt := range tests {
		got := resp.Header.Get(tt.header)
		if got != tt.want {
			t.Errorf("security header %q = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	// The recovery middleware is unexported, so we test it indirectly by
	// verifying the full handler chain doesn't crash on various paths.
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Health endpoint goes through the full middleware chain.
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health through recovery middleware: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health: unexpected status %d", resp.StatusCode)
	}

	// Unknown path goes through recovery middleware + streamable handler.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	handler.ServeHTTP(rec, req)
	// Any status is fine — the point is no crash.
	_ = rec.Result()
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

// ═══════════════════════════════════════════════════════════════════════════
// Battle-tested behavioral tests
// ═══════════════════════════════════════════════════════════════════════════
// These tests validate ACTUAL OUTPUT CORRECTNESS, not just "did it return
// something." They catch real bugs: broken encoding, wrong filters, stale
// counts, missing interpolation, dangerous URL acceptance.

// extractText gets the text string from the first content block of a tool result.
func extractText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content blocks")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want *mcp.TextContent", result.Content[0])
	}
	return tc.Text
}

// ---------------------------------------------------------------------------
// Mutate: encoding correctness
// Catches: wrong hex values, missing chars, encoder filter ignored,
// count/variant mismatch.
// ---------------------------------------------------------------------------

func TestMutateEncodingCorrectness(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		encoders []string
		wantEncs []string          // expected encoder names in output
		checks   map[string]string // encoder → substring that MUST appear
	}{
		{
			name:     "url_encodes_single_quote",
			payload:  "' OR 1=1--",
			encoders: []string{"url"},
			wantEncs: []string{"url"},
			checks:   map[string]string{"url": "%27"},
		},
		{
			name:     "double_url_encodes_percent",
			payload:  "'",
			encoders: []string{"double_url"},
			wantEncs: []string{"double_url"},
			checks:   map[string]string{"double_url": "%2527"},
		},
		{
			name:     "unicode_produces_backslash_u",
			payload:  "<",
			encoders: []string{"unicode"},
			wantEncs: []string{"unicode"},
			checks:   map[string]string{"unicode": "\\u003C"},
		},
		{
			name:     "html_hex_produces_entity",
			payload:  "<",
			encoders: []string{"html_hex"},
			wantEncs: []string{"html_hex"},
			checks:   map[string]string{"html_hex": "&#x3C;"},
		},
		{
			name:     "all_encoders_when_omitted",
			payload:  "'",
			encoders: nil,
			wantEncs: []string{"url", "double_url", "unicode", "html_hex"},
		},
		{
			name:     "alphanumeric_passthrough",
			payload:  "abc123",
			encoders: []string{"url"},
			wantEncs: []string{"url"},
			checks:   map[string]string{"url": "abc123"},
		},
		{
			name:     "encoder_filter_respected",
			payload:  "' OR 1=1",
			encoders: []string{"html_hex"},
			wantEncs: []string{"html_hex"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args := map[string]any{"payload": tt.payload}
			if tt.encoders != nil {
				args["encoders"] = tt.encoders
			}

			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "mutate",
				Arguments: args,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError {
				t.Fatalf("unexpected error: %s", extractText(t, result))
			}

			text := extractText(t, result)
			var mr struct {
				Original string `json:"original"`
				Variants []struct {
					Encoder string `json:"encoder"`
					Encoded string `json:"encoded"`
				} `json:"variants"`
				Count int    `json:"count"`
				Tip   string `json:"tip"`
			}
			if err := json.Unmarshal([]byte(text), &mr); err != nil {
				t.Fatalf("parse mutate response: %v\nraw: %s", err, text)
			}

			if mr.Original != tt.payload {
				t.Errorf("original = %q, want %q", mr.Original, tt.payload)
			}
			if mr.Count != len(mr.Variants) {
				t.Errorf("count (%d) != len(variants) (%d)", mr.Count, len(mr.Variants))
			}

			gotEncoders := make(map[string]string)
			for _, v := range mr.Variants {
				gotEncoders[v.Encoder] = v.Encoded
			}
			for _, want := range tt.wantEncs {
				if _, ok := gotEncoders[want]; !ok {
					t.Errorf("missing encoder %q in output", want)
				}
			}
			// Encoder filter: should not have extra encoders beyond requested
			if tt.encoders != nil && len(mr.Variants) != len(tt.wantEncs) {
				t.Errorf("got %d variants, want %d (filter ignored?)", len(mr.Variants), len(tt.wantEncs))
			}

			for enc, mustContain := range tt.checks {
				got := gotEncoders[enc]
				if !strings.Contains(got, mustContain) {
					t.Errorf("encoder %q output %q missing %q", enc, got, mustContain)
				}
			}
			if mr.Tip == "" {
				t.Error("tip is empty — LLM needs guidance text")
			}
		})
	}
}

func TestMutateEmptyPayload(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "mutate",
		Arguments: json.RawMessage(`{"payload": ""}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("mutate accepted empty payload — should return IsError")
	}
	text := extractText(t, result)
	if !strings.Contains(strings.ToLower(text), "payload") {
		t.Errorf("error %q doesn't mention 'payload'", text)
	}
}

// ---------------------------------------------------------------------------
// List payloads: filter integrity, truncation, edge cases
// Catches: filters returning wrong category, severity ignored,
// snippet overflow, zero-result handling.
// ---------------------------------------------------------------------------

func TestListPayloadsCategoryFilterIntegrity(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{"category": "sqli"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var summary struct {
		TotalPayloads int            `json:"total_payloads"`
		Categories    int            `json:"categories"`
		ByCategory    map[string]int `json:"by_category"`
		FilterApplied string         `json:"filter_applied"`
		Samples       []struct {
			Category string `json:"category"`
			Snippet  string `json:"snippet"`
		} `json:"sample_payloads"`
	}
	if err := json.Unmarshal([]byte(text), &summary); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !strings.Contains(summary.FilterApplied, "category=sqli") {
		t.Errorf("filter_applied = %q, want 'category=sqli'", summary.FilterApplied)
	}
	for cat := range summary.ByCategory {
		if cat != "sqli" {
			t.Errorf("category filter leaked: got %q when filtering sqli", cat)
		}
	}
	for i, s := range summary.Samples {
		if s.Category != "sqli" {
			t.Errorf("sample[%d].category = %q, want sqli", i, s.Category)
		}
	}
	if len(summary.Samples) > 10 {
		t.Errorf("got %d samples, max 10", len(summary.Samples))
	}
	if summary.TotalPayloads == 0 {
		t.Error("sqli filter returned 0 payloads — payload dir broken?")
	}
}

func TestListPayloadsSnippetTruncation(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	text := extractText(t, result)
	var summary struct {
		Samples []struct {
			Snippet string `json:"snippet"`
		} `json:"sample_payloads"`
	}
	if err := json.Unmarshal([]byte(text), &summary); err != nil {
		t.Fatalf("parse: %v", err)
	}

	for i, s := range summary.Samples {
		// Code truncates at len(snippet) > 120 bytes, then adds "…" (3 UTF-8 bytes)
		if len(s.Snippet) > 123 {
			t.Errorf("sample[%d] snippet is %d bytes (max 123): %q", i, len(s.Snippet), s.Snippet)
		}
	}
}

func TestListPayloadsNonexistentCategory(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{"category": "doesnotexist_xyz"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatal("nonexistent category returned IsError — should return empty gracefully")
	}

	text := extractText(t, result)
	var summary struct {
		TotalPayloads int `json:"total_payloads"`
	}
	if err := json.Unmarshal([]byte(text), &summary); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if summary.TotalPayloads != 0 {
		t.Errorf("nonexistent category got %d payloads, want 0", summary.TotalPayloads)
	}
}

// ---------------------------------------------------------------------------
// Response enrichment: summary, next_steps, category_info
// Validates that all tool responses include actionable context for AI agents.
// ---------------------------------------------------------------------------

func TestListPayloadsHasSummaryAndNextSteps(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{"category": "sqli"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	text := extractText(t, result)
	var resp struct {
		Summary        string   `json:"summary"`
		TotalAvailable int      `json:"total_available"`
		NextSteps      []string `json:"next_steps"`
		CategoryInfo   *struct {
			Name        string `json:"name"`
			OWASPCode   string `json:"owasp_code"`
			RiskLevel   string `json:"risk_level"`
			Description string `json:"description"`
		} `json:"category_info"`
		SamplePayloads []struct {
			Tags []string `json:"tags"`
		} `json:"sample_payloads"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if resp.Summary == "" {
		t.Error("summary is empty — should contain a narrative description")
	}
	if !strings.Contains(resp.Summary, "SQL Injection") {
		t.Errorf("summary should mention 'SQL Injection' for sqli category, got: %s", resp.Summary)
	}
	if len(resp.NextSteps) == 0 {
		t.Error("next_steps is empty — should suggest follow-up actions")
	}
	if resp.TotalAvailable == 0 {
		t.Error("total_available should include all payloads across categories")
	}
	if resp.CategoryInfo == nil {
		t.Fatal("category_info should be populated for sqli category")
	}
	if resp.CategoryInfo.Name != "SQL Injection" {
		t.Errorf("category_info.name = %q, want 'SQL Injection'", resp.CategoryInfo.Name)
	}
	if resp.CategoryInfo.OWASPCode == "" {
		t.Error("category_info.owasp_code should not be empty")
	}
}

func TestListPayloadsNoFilterHasGlobalSummary(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	text := extractText(t, result)
	var resp struct {
		Summary   string   `json:"summary"`
		NextSteps []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if resp.Summary == "" {
		t.Error("summary is empty for unfiltered listing")
	}
	if !strings.Contains(resp.Summary, "categories") {
		t.Errorf("unfiltered summary should mention categories, got: %s", resp.Summary)
	}
	if len(resp.NextSteps) == 0 {
		t.Error("next_steps should not be empty")
	}

	// Verify next_steps mention tool names for actionability
	joined := strings.Join(resp.NextSteps, " ")
	for _, tool := range []string{"scan", "detect_waf", "assess"} {
		if !strings.Contains(joined, tool) {
			t.Errorf("next_steps should mention '%s' tool", tool)
		}
	}
}

func TestMutateHasSummaryAndNextSteps(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "mutate",
		Arguments: json.RawMessage(`{"payload": "' OR 1=1--"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	text := extractText(t, result)
	var resp struct {
		Summary   string   `json:"summary"`
		NextSteps []string `json:"next_steps"`
		Tip       string   `json:"tip"`
		Count     int      `json:"count"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if resp.Summary == "" {
		t.Error("mutate summary is empty")
	}
	if !strings.Contains(resp.Summary, "encoded variants") {
		t.Errorf("mutate summary should describe the variants, got: %s", resp.Summary)
	}
	if len(resp.NextSteps) == 0 {
		t.Error("mutate next_steps is empty")
	}
	if resp.Tip == "" {
		t.Error("mutate tip is empty")
	}
}

func TestGenerateCICDHasInstructions(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "generate_cicd",
		Arguments: json.RawMessage(`{"platform": "github", "target": "https://example.com"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	text := extractText(t, result)

	// Response is now JSON with structured fields
	var resp struct {
		Summary   string   `json:"summary"`
		Platform  string   `json:"platform"`
		FileName  string   `json:"file_name"`
		Pipeline  string   `json:"pipeline"`
		NextSteps []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("response should be valid JSON: %v", err)
	}
	if resp.Summary == "" {
		t.Error("CI/CD response should have a summary")
	}
	if resp.Platform != "github" {
		t.Errorf("platform = %q, want github", resp.Platform)
	}
	if resp.FileName == "" {
		t.Error("CI/CD response should have a file_name")
	}
	if resp.Pipeline == "" {
		t.Error("CI/CD response should have pipeline content")
	}
	if len(resp.NextSteps) == 0 {
		t.Error("CI/CD response should have next_steps")
	}
	// Verify security guidance is in next_steps
	found := false
	for _, step := range resp.NextSteps {
		if strings.Contains(step, "secret") || strings.Contains(step, "SECURITY") {
			found = true
			break
		}
	}
	if !found {
		t.Error("next_steps should include security guidance about secrets")
	}
}

func TestCategoryDescriptionsComplete(t *testing.T) {
	// Verify all listed enum categories return a category_info in list_payloads
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	expectedCategories := []string{
		"sqli", "xss", "traversal", "auth", "ssrf", "ssti", "cmdi", "xxe",
		"nosqli", "graphql", "cors", "crlf", "redirect", "upload", "jwt",
		"oauth", "prototype", "deserialize",
	}
	for _, cat := range expectedCategories {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "list_payloads",
			Arguments: json.RawMessage(fmt.Sprintf(`{"category": %q}`, cat)),
		})
		if err != nil {
			t.Fatalf("CallTool(%s): %v", cat, err)
		}

		text := extractText(t, result)
		var resp struct {
			CategoryInfo *struct {
				Name      string `json:"name"`
				OWASPCode string `json:"owasp_code"`
			} `json:"category_info"`
		}
		if err := json.Unmarshal([]byte(text), &resp); err != nil {
			t.Fatalf("parse(%s): %v", cat, err)
		}
		if resp.CategoryInfo == nil {
			t.Errorf("category_info missing for %q", cat)
			continue
		}
		if resp.CategoryInfo.Name == "" {
			t.Errorf("category_info.name empty for %q", cat)
		}
		if resp.CategoryInfo.OWASPCode == "" {
			t.Errorf("category_info.owasp_code empty for %q", cat)
		}
	}
}

// ---------------------------------------------------------------------------
// Generate CI/CD: output content validation
// Catches: target URL not interpolated, scan types ignored, schedule missing,
// platform-specific keywords absent.
// ---------------------------------------------------------------------------

func TestGenerateCICDOutputContent(t *testing.T) {
	tests := []struct {
		name        string
		platform    string
		target      string
		scanTypes   []string
		schedule    string
		mustContain []string
	}{
		{
			name: "github_contains_target_and_types", platform: "github",
			target: "https://staging.example.com", scanTypes: []string{"sqli", "xss"},
			mustContain: []string{
				"https://staging.example.com", "sqli,xss",
				"github/codeql-action", "waf-tester",
			},
		},
		{
			name: "github_schedule_contains_cron", platform: "github",
			target: "https://example.com", schedule: "0 2 * * 1",
			mustContain: []string{"0 2 * * 1", "schedule:"},
		},
		{
			name: "gitlab_contains_artifacts", platform: "gitlab",
			target:      "https://app.example.com",
			mustContain: []string{"https://app.example.com", "artifacts:", "results.json"},
		},
		{
			name: "jenkins_contains_pipeline", platform: "jenkins",
			target:      "https://internal.app",
			mustContain: []string{"pipeline {", "https://internal.app", "archiveArtifacts"},
		},
		{
			name: "azure_devops_contains_publish", platform: "azure-devops",
			target:      "https://myapp.com",
			mustContain: []string{"https://myapp.com", "publish:", "ArtifactStagingDirectory"},
		},
		{
			name: "circleci_contains_store_artifacts", platform: "circleci",
			target:      "https://api.example.com",
			mustContain: []string{"https://api.example.com", "store_artifacts", "workflows:"},
		},
		{
			name: "bitbucket_contains_pipelines", platform: "bitbucket",
			target:      "https://example.com",
			mustContain: []string{"pipelines:", "https://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args := map[string]any{"platform": tt.platform, "target": tt.target}
			if len(tt.scanTypes) > 0 {
				args["scan_types"] = tt.scanTypes
			}
			if tt.schedule != "" {
				args["schedule"] = tt.schedule
			}

			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "generate_cicd",
				Arguments: args,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError {
				t.Fatalf("error: %s", extractText(t, result))
			}

			text := extractText(t, result)
			for _, sub := range tt.mustContain {
				if !strings.Contains(text, sub) {
					t.Errorf("output missing %q", sub)
				}
			}
		})
	}
}

func TestGenerateCICDMissingRequired(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		{"missing_platform", `{"target": "https://example.com"}`},
		{"missing_target", `{"platform": "github"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "generate_cicd",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatal("accepted missing required field without error")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// URL validation: dangerous schemes must be rejected
// Catches: javascript:, data:, file:// accepted; host-less URLs pass.
// ---------------------------------------------------------------------------

func TestURLValidationRejectsDangerousSchemes(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		errorHint string
	}{
		{"javascript_scheme", "javascript:alert(1)", "http:// or https://"},
		{"data_scheme", "data:text/html,<h1>hi</h1>", "http:// or https://"},
		{"file_scheme", "file:///etc/passwd", "http:// or https://"},
		{"ftp_scheme", "ftp://files.example.com", "http:// or https://"},
		{"scheme_only_no_host", "https://", "missing a host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "detect_waf",
				Arguments: map[string]any{"target": tt.target},
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Errorf("accepted dangerous target %q — should reject", tt.target)
			}
			text := extractText(t, result)
			if !strings.Contains(text, tt.errorHint) {
				t.Errorf("error %q missing hint %q", text, tt.errorHint)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Version resource: data integrity cross-check
// Catches: tool count mismatch after adding/removing tools, capabilities
// drifting from actuals.
// ---------------------------------------------------------------------------

func TestVersionResourceDataIntegrity(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	vResult, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://version"})
	if err != nil {
		t.Fatalf("ReadResource(version): %v", err)
	}

	var vInfo struct {
		Capabilities struct {
			Tools     int `json:"tools"`
			Resources int `json:"resources"`
			Prompts   int `json:"prompts"`
		} `json:"capabilities"`
		Tools               []string `json:"tools"`
		SupportedWAFVendors []string `json:"supported_waf_vendors"`
		SupportedCDNVendors []string `json:"supported_cdn_vendors"`
	}
	if err := json.Unmarshal([]byte(vResult.Contents[0].Text), &vInfo); err != nil {
		t.Fatalf("parse version: %v", err)
	}

	tResult, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if vInfo.Capabilities.Tools != len(tResult.Tools) {
		t.Errorf("version says %d tools, ListTools returns %d",
			vInfo.Capabilities.Tools, len(tResult.Tools))
	}
	if len(vInfo.Tools) != len(tResult.Tools) {
		t.Errorf("version.tools array has %d, ListTools has %d",
			len(vInfo.Tools), len(tResult.Tools))
	}

	// Verify tool names match
	actualNames := make(map[string]bool)
	for _, tool := range tResult.Tools {
		actualNames[tool.Name] = true
	}
	for _, name := range vInfo.Tools {
		if !actualNames[name] {
			t.Errorf("version lists tool %q but ListTools doesn't have it", name)
		}
	}

	rResult, err := cs.ListResources(ctx, &mcp.ListResourcesParams{})
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	rtResult, err := cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{})
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}
	actualResources := len(rResult.Resources) + len(rtResult.ResourceTemplates)
	if vInfo.Capabilities.Resources != actualResources {
		t.Errorf("version says %d resources, actual %d (static=%d + templates=%d)",
			vInfo.Capabilities.Resources, actualResources,
			len(rResult.Resources), len(rtResult.ResourceTemplates))
	}

	pResult, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{})
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if vInfo.Capabilities.Prompts != len(pResult.Prompts) {
		t.Errorf("version says %d prompts, ListPrompts returns %d",
			vInfo.Capabilities.Prompts, len(pResult.Prompts))
	}

	if len(vInfo.SupportedWAFVendors) < 20 {
		t.Errorf("only %d WAF vendors, expected 20+", len(vInfo.SupportedWAFVendors))
	}
	if len(vInfo.SupportedCDNVendors) < 5 {
		t.Errorf("only %d CDN vendors, expected 5+", len(vInfo.SupportedCDNVendors))
	}
}

// ---------------------------------------------------------------------------
// Config resource: reflects actual configuration
// Catches: config resource ignoring configured payload_dir.
// ---------------------------------------------------------------------------

func TestConfigResourceReflectsPayloadDir(t *testing.T) {
	const customDir = "/tmp/custom-payloads"
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: customDir})
	defer srv.Stop()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0.0.1"}, nil)
	ctx := context.Background()

	go func() {
		_ = srv.MCPServer().Run(ctx, serverTransport)
	}()

	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://config"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &config); err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, _ := config["payload_dir"].(string)
	if got != customDir {
		t.Errorf("config.payload_dir = %q, want %q", got, customDir)
	}
}

// ---------------------------------------------------------------------------
// Prompt interpolation: target, environment, stealth, service, depth
// Catches: target not inserted, optional args ignored, rate advice wrong.
// ---------------------------------------------------------------------------

func TestPromptTargetInterpolation(t *testing.T) {
	prompts := []struct {
		name string
		args map[string]string
	}{
		{"security_audit", map[string]string{"target": "https://unique-target-111.example.com"}},
		{"waf_bypass", map[string]string{"target": "https://unique-target-222.example.com", "category": "xss"}},
		{"full_assessment", map[string]string{"target": "https://unique-target-333.example.com"}},
		{"discovery_workflow", map[string]string{"target": "https://unique-target-444.example.com"}},
		{"evasion_research", map[string]string{"target": "https://unique-target-555.example.com", "payload": "test"}},
	}

	for _, tt := range prompts {
		t.Run(tt.name, func(t *testing.T) {
			cs := newTestSession(t)
			ctx := context.Background()

			result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
				Name:      tt.name,
				Arguments: tt.args,
			})
			if err != nil {
				t.Fatalf("GetPrompt(%s): %v", tt.name, err)
			}
			if len(result.Messages) == 0 {
				t.Fatal("no messages returned")
			}

			tc, ok := result.Messages[0].Content.(*mcp.TextContent)
			if !ok {
				t.Fatalf("content is %T, want *mcp.TextContent", result.Messages[0].Content)
			}

			target := tt.args["target"]
			if !strings.Contains(tc.Text, target) {
				t.Errorf("prompt %q doesn't contain target %q", tt.name, target)
			}
		})
	}
}

func TestSecurityAuditProductionRateAdvice(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "security_audit",
		Arguments: map[string]string{
			"target":      "https://example.com",
			"environment": "production",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}

	tc := result.Messages[0].Content.(*mcp.TextContent)
	if !strings.Contains(tc.Text, "10-20") {
		t.Error("production audit missing '10-20' rate advice — risky for prod targets")
	}
}

func TestWAFBypassStealthMode(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	stealth, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "waf_bypass",
		Arguments: map[string]string{
			"target": "https://example.com", "category": "sqli", "stealth": "true",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	stealthText := stealth.Messages[0].Content.(*mcp.TextContent).Text

	normal, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "waf_bypass",
		Arguments: map[string]string{
			"target": "https://example.com", "category": "sqli", "stealth": "false",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	normalText := normal.Messages[0].Content.(*mcp.TextContent).Text

	if !strings.Contains(stealthText, "rate_limit: 3") {
		t.Error("stealth mode doesn't set rate_limit to 3")
	}
	if !strings.Contains(normalText, "rate_limit: 10") {
		t.Error("normal mode doesn't set rate_limit to 10")
	}
}

func TestDiscoveryWorkflowDepthMapping(t *testing.T) {
	tests := []struct {
		depth   string
		wantVal string
	}{
		{"shallow", "1"},
		{"normal", "3"},
		{"deep", "5"},
	}

	cs := newTestSession(t)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.depth, func(t *testing.T) {
			result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
				Name: "discovery_workflow",
				Arguments: map[string]string{
					"target": "https://example.com",
					"depth":  tt.depth,
				},
			})
			if err != nil {
				t.Fatalf("GetPrompt: %v", err)
			}
			tc := result.Messages[0].Content.(*mcp.TextContent)
			if !strings.Contains(tc.Text, "max_depth: "+tt.wantVal) {
				t.Errorf("depth=%q: missing 'max_depth: %s'", tt.depth, tt.wantVal)
			}
		})
	}
}

func TestDiscoveryWorkflowServiceParam(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "discovery_workflow",
		Arguments: map[string]string{
			"target":  "https://example.com",
			"service": "authentik",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	tc := result.Messages[0].Content.(*mcp.TextContent)
	if !strings.Contains(tc.Text, "authentik") {
		t.Error("service 'authentik' not reflected in prompt output")
	}
}

// ---------------------------------------------------------------------------
// Server lifecycle: nil config, readiness state machine, health transitions
// Catches: nil config panic, IsReady defaults to true, MarkReady idempotency.
// ---------------------------------------------------------------------------

func TestNewWithNilConfig(t *testing.T) {
	srv := mcpserver.New(nil)
	defer srv.Stop()
	if srv == nil {
		t.Fatal("New(nil) returned nil — should use defaults")
	}
	if srv.MCPServer() == nil {
		t.Fatal("MCPServer() nil after New(nil)")
	}
}

func TestReadinessStateMachine(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	if srv.IsReady() {
		t.Fatal("IsReady() true before MarkReady() — health checks will lie")
	}

	srv.MarkReady()
	if !srv.IsReady() {
		t.Fatal("IsReady() false after MarkReady()")
	}

	// Double MarkReady must not break
	srv.MarkReady()
	if !srv.IsReady() {
		t.Fatal("IsReady() false after double MarkReady()")
	}
}

func TestHealthEndpointStateTransition(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	// Before MarkReady → 503
	resp1, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("before MarkReady: got %d, want 503", resp1.StatusCode)
	}

	srv.MarkReady()

	// After MarkReady → 200
	resp2, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("after MarkReady: got %d, want 200", resp2.StatusCode)
	}
}

func TestHealthEndpointHEAD(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
	srv.MarkReady()
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodHead, ts.URL+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HEAD /health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HEAD /health: got %d, want 200", resp.StatusCode)
	}
}

func TestHealthEndpointPOSTReturns405(t *testing.T) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/health", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /health: got %d, want 405", resp.StatusCode)
	}
	allow := resp.Header.Get("Allow")
	if !strings.Contains(allow, "GET") || !strings.Contains(allow, "HEAD") {
		t.Errorf("Allow header = %q, want 'GET, HEAD'", allow)
	}
}

// ---------------------------------------------------------------------------
// Hook: OnEvent actually dispatches callback
// Catches: OnEvent silently drops events.
// ---------------------------------------------------------------------------

func TestHookOnEventDispatchesCallback(t *testing.T) {
	var called bool
	hook := mcpserver.NewHook(func(_ events.Event) {
		called = true
	})

	if err := hook.OnEvent(context.Background(), nil); err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if !called {
		t.Error("OnEvent did not invoke callback")
	}
}

// ---------------------------------------------------------------------------
// Error message quality: LLM self-correction
// Catches: error messages that don't help the AI fix its input.
// ---------------------------------------------------------------------------

func TestErrorMessagesContainActionableHints(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tests := []struct {
		name        string
		tool        string
		args        string
		mustContain []string
	}{
		{"detect_waf_no_target", "detect_waf", `{}`, []string{"target", "https://"}},
		{"scan_no_target", "scan", `{}`, []string{"target", "https://"}},
		{"bypass_no_target", "bypass", `{}`, []string{"target"}},
		{"bypass_no_payloads", "bypass", `{"target": "https://example.com"}`, []string{"payload"}},
		{"mutate_no_payload", "mutate", `{}`, []string{"payload"}},
		{"learn_no_discovery", "learn", `{}`, []string{"discover"}},
		{"cicd_no_platform", "generate_cicd", `{"target": "https://example.com"}`, []string{"platform"}},
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
				t.Fatal("did not return IsError for bad input")
			}
			text := strings.ToLower(extractText(t, result))
			for _, want := range tt.mustContain {
				if !strings.Contains(text, strings.ToLower(want)) {
					t.Errorf("error missing %q — LLM can't self-correct", want)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Learn tool: invalid discovery JSON
// Catches: garbage discovery data accepted silently.
// ---------------------------------------------------------------------------

func TestLearnWithInvalidDiscoveryJSON(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "learn",
		Arguments: json.RawMessage(`{"discovery_json": "this is not valid json"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("learn accepted invalid discovery JSON")
	}
	text := strings.ToLower(extractText(t, result))
	if !strings.Contains(text, "discover") {
		t.Errorf("error %q doesn't mention 'discover' tool", text)
	}
}

// ---------------------------------------------------------------------------
// Read-only tool annotations: safety contract
// Catches: ReadOnlyHint flipped on a tool that sends traffic.
// ---------------------------------------------------------------------------

func TestReadOnlyToolAnnotations(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	readOnly := map[string]bool{"list_payloads": true, "mutate": true, "generate_cicd": true}
	// scan and bypass send ATTACK traffic — they must NOT be read-only.
	// detect_waf, discover, probe send traffic but are observation-only (don't modify target state).
	sendsTraffic := map[string]bool{"scan": true, "bypass": true}

	for _, tool := range result.Tools {
		if readOnly[tool.Name] {
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Errorf("%q should be ReadOnlyHint=true (no network traffic)", tool.Name)
			}
		}
		if sendsTraffic[tool.Name] {
			if tool.Annotations != nil && tool.Annotations.ReadOnlyHint {
				t.Errorf("%q has ReadOnlyHint=true but sends attack traffic!", tool.Name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Payloads/{category} resource template
// Catches: URI parsing broken, valid category empty, truncation wrong.
// ---------------------------------------------------------------------------

func TestPayloadsByCategoryResource(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://payloads/xss",
	})
	if err != nil {
		t.Fatalf("ReadResource(payloads/xss): %v", err)
	}
	if len(result.Contents) == 0 {
		t.Fatal("payloads/xss returned no contents")
	}

	var catResult struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
		Payloads []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Payload  string `json:"payload"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &catResult); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if catResult.Category != "xss" {
		t.Errorf("category = %q, want xss", catResult.Category)
	}
	if catResult.Count == 0 {
		t.Error("xss returned 0 payloads")
	}
	if catResult.Count != len(catResult.Payloads) {
		t.Errorf("count (%d) != len(payloads) (%d)", catResult.Count, len(catResult.Payloads))
	}

	for i, p := range catResult.Payloads {
		// Code truncates at byte 120 + "…" (3 bytes). UTF-8 slicing edge
		// cases can add a few extra bytes, so we use 130 as a safe ceiling.
		if len(p.Payload) > 130 {
			t.Errorf("payload[%d] is %d bytes (max ~123, ceiling 130)", i, len(p.Payload))
		}
		if p.ID == "" {
			t.Errorf("payload[%d] has empty ID", i)
		}
	}
}

func TestPayloadsByInvalidCategory(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	_, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		URI: "waftester://payloads/nonexistent_category_xyz",
	})
	if err == nil {
		t.Error("nonexistent category should return error")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Gap-closing tests: patterns from top-starred MCP repos
// ═══════════════════════════════════════════════════════════════════════════
// These tests close gaps identified by comparing our implementation against
// the official go-sdk examples and top-starred MCP servers (github/github-mcp-server).

// ---------------------------------------------------------------------------
// HTTP transport integration: full client↔server over httptest + StreamableHTTPHandler
// Catches: handler wiring broken, CORS blocks client, session negotiation fails
// over real HTTP (previously only tested via InMemoryTransport).
// ---------------------------------------------------------------------------

// newHTTPTestSession creates an MCP client session connected through a real
// HTTP transport using httptest.Server + StreamableHTTPHandler. This tests the
// full HTTP path including CORS, session headers, and MCP protocol negotiation.
func newHTTPTestSession(t *testing.T) (*mcp.ClientSession, *httptest.Server) {
	t.Helper()

	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	srv.MarkReady()
	handler := srv.HTTPHandler()
	ts := httptest.NewServer(handler)

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "http-test-client",
		Version: "0.0.1",
	}, nil)

	transport := &mcp.StreamableClientTransport{
		Endpoint:   ts.URL + "/mcp",
		MaxRetries: -1, // disable retries in tests
	}

	ctx := context.Background()
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		ts.Close()
		srv.Stop()
		t.Fatalf("client.Connect via HTTP: %v", err)
	}

	t.Cleanup(func() {
		cs.Close()
		ts.Close()
		srv.Stop()
	})
	return cs, ts
}

func TestHTTPTransportListTools(t *testing.T) {
	cs, _ := newHTTPTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools over HTTP: %v", err)
	}
	if len(result.Tools) != 24 {
		t.Errorf("got %d tools over HTTP, want 24", len(result.Tools))
	}
}

func TestHTTPTransportCallTool(t *testing.T) {
	cs, _ := newHTTPTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: map[string]any{"category": "sqli"},
	})
	if err != nil {
		t.Fatalf("CallTool over HTTP: %v", err)
	}
	if result.IsError {
		t.Fatalf("list_payloads over HTTP returned IsError: %s", extractText(t, result))
	}
	text := extractText(t, result)
	if !strings.Contains(text, "total_payloads") {
		t.Error("HTTP response missing expected payload data")
	}
}

func TestHTTPTransportReadResource(t *testing.T) {
	cs, _ := newHTTPTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://version"})
	if err != nil {
		t.Fatalf("ReadResource over HTTP: %v", err)
	}
	if len(result.Contents) == 0 {
		t.Fatal("version resource over HTTP returned no contents")
	}
	if !strings.Contains(result.Contents[0].Text, "version") {
		t.Error("version resource over HTTP missing version field")
	}
}

func TestHTTPTransportGetPrompt(t *testing.T) {
	cs, _ := newHTTPTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "security_audit",
		Arguments: map[string]string{"target": "https://example.com"},
	})
	if err != nil {
		t.Fatalf("GetPrompt over HTTP: %v", err)
	}
	if len(result.Messages) == 0 {
		t.Fatal("security_audit over HTTP returned no messages")
	}
}

func TestHTTPTransportPing(t *testing.T) {
	cs, _ := newHTTPTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := cs.Ping(ctx, &mcp.PingParams{}); err != nil {
		t.Fatalf("Ping over HTTP: %v", err)
	}
}

func TestHTTPTransportErrorHandling(t *testing.T) {
	cs, _ := newHTTPTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Nonexistent tool should return protocol error over HTTP transport too
	_, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "nonexistent_tool",
		Arguments: map[string]any{},
	})
	if err == nil {
		t.Error("expected error for nonexistent tool over HTTP")
	}
}

// ---------------------------------------------------------------------------
// Context cancellation propagation
// Catches: cancelled context not propagated, tool hangs forever, no error returned.
// ---------------------------------------------------------------------------

func TestContextCancellationReturnsError(t *testing.T) {
	cs := newTestSession(t)

	// Pre-cancelled context — tool should return immediately with error
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: map[string]any{},
	})
	if err == nil {
		t.Error("expected error for pre-cancelled context")
	}
}

func TestContextTimeoutReturnsError(t *testing.T) {
	cs := newTestSession(t)

	// Already-expired timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond) // ensure it expires

	_, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: map[string]any{},
	})
	if err == nil {
		t.Error("expected error for expired context timeout")
	}
}

func TestContextCancellationOnReadResource(t *testing.T) {
	cs := newTestSession(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://version"})
	if err == nil {
		t.Error("expected error for cancelled ReadResource")
	}
}

func TestContextCancellationOnGetPrompt(t *testing.T) {
	cs := newTestSession(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "security_audit",
		Arguments: map[string]string{"target": "https://example.com"},
	})
	if err == nil {
		t.Error("expected error for cancelled GetPrompt")
	}
}

// ---------------------------------------------------------------------------
// Concurrent tool calls: goroutine safety
// Catches: data races (visible with -race), map concurrent write panics,
// shared state corruption between sessions.
// ---------------------------------------------------------------------------

func TestConcurrentToolCalls(t *testing.T) {
	const goroutines = 10

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*2)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			// Call two different tools in each goroutine
			result1, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "list_payloads",
				Arguments: map[string]any{},
			})
			if err != nil {
				errCh <- err
				return
			}
			if result1.IsError {
				errCh <- fmt.Errorf("list_payloads returned IsError")
				return
			}

			result2, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "mutate",
				Arguments: map[string]any{"payload": "<script>alert(1)</script>", "encoders": []string{"url"}},
			})
			if err != nil {
				errCh <- err
				return
			}
			if result2.IsError {
				errCh <- fmt.Errorf("mutate returned IsError")
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent error: %v", err)
	}
}

func TestConcurrentResourceReads(t *testing.T) {
	const goroutines = 10

	resources := []string{
		"waftester://version",
		"waftester://payloads",
		"waftester://guide",
		"waftester://waf-signatures",
		"waftester://evasion-techniques",
		"waftester://owasp-mappings",
		"waftester://config",
	}

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*len(resources))

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			for _, uri := range resources {
				result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
				if err != nil {
					errCh <- fmt.Errorf("ReadResource(%s): %w", uri, err)
					return
				}
				if len(result.Contents) == 0 {
					errCh <- fmt.Errorf("ReadResource(%s): empty contents", uri)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Enhanced capabilities negotiation
// Catches: wrong server name, stale version, missing capability flags,
// instructions not set.
// ---------------------------------------------------------------------------

func TestCapabilitiesNegotiationDetails(t *testing.T) {
	cs := newTestSession(t)
	initResult := cs.InitializeResult()

	if initResult.ServerInfo.Name != "waf-tester" {
		t.Errorf("server name = %q, want %q", initResult.ServerInfo.Name, "waf-tester")
	}
	if initResult.ServerInfo.Version != defaults.Version {
		t.Errorf("server version = %q, want %q", initResult.ServerInfo.Version, defaults.Version)
	}
	if initResult.Instructions == "" {
		t.Error("server instructions are empty — LLM has no operating manual")
	}
	if !strings.Contains(initResult.Instructions, "WAF") {
		t.Error("server instructions don't mention WAF — wrong instructions?")
	}
}

func TestCapabilitiesListChanged(t *testing.T) {
	cs := newTestSession(t)
	initResult := cs.InitializeResult()

	if initResult.Capabilities.Tools != nil && !initResult.Capabilities.Tools.ListChanged {
		t.Error("tools capability should advertise ListChanged=true")
	}
	if initResult.Capabilities.Prompts != nil && !initResult.Capabilities.Prompts.ListChanged {
		t.Error("prompts capability should advertise ListChanged=true")
	}
}

func TestHTTPTransportCapabilities(t *testing.T) {
	cs, _ := newHTTPTestSession(t)
	initResult := cs.InitializeResult()

	if initResult.ServerInfo.Name != "waf-tester" {
		t.Errorf("HTTP: server name = %q, want %q", initResult.ServerInfo.Name, "waf-tester")
	}
	if initResult.ServerInfo.Version != defaults.Version {
		t.Errorf("HTTP: server version = %q, want %q", initResult.ServerInfo.Version, defaults.Version)
	}
	if initResult.Capabilities.Tools == nil {
		t.Error("HTTP: tools capability is nil")
	}
	if initResult.Capabilities.Resources == nil {
		t.Error("HTTP: resources capability is nil")
	}
	if initResult.Capabilities.Prompts == nil {
		t.Error("HTTP: prompts capability is nil")
	}
}

// ---------------------------------------------------------------------------
// Graceful shutdown: Close() + subsequent calls fail cleanly
// Catches: Close() panics, post-close calls hang, resource leak.
// ---------------------------------------------------------------------------

func TestGracefulShutdown(t *testing.T) {
	cs := newTestSession(t)

	// First call should succeed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("pre-close CallTool: %v", err)
	}

	// Close the session
	if err := cs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Post-close calls should fail with an error, not hang
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_, err = cs.CallTool(ctx2, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: map[string]any{},
	})
	if err == nil {
		t.Error("expected error for post-close CallTool")
	}
}

func TestDoubleCloseDoesNotPanic(t *testing.T) {
	cs := newTestSession(t)

	if err := cs.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close should not panic (idempotent)
	if err := cs.Close(); err != nil {
		t.Logf("second Close error (acceptable): %v", err)
	}
}

func TestHTTPTransportGracefulShutdown(t *testing.T) {
	cs, _ := newHTTPTestSession(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Verify the session works
	_, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("pre-close CallTool: %v", err)
	}

	// Close should succeed
	if err := cs.Close(); err != nil {
		t.Fatalf("HTTP Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Session isolation: parallel sessions don't leak state
// Catches: shared mutable state between sessions.
// ---------------------------------------------------------------------------

func TestSessionIsolation(t *testing.T) {
	// Two independent sessions should see the same server state
	// without interfering with each other.
	cs1 := newTestSession(t)
	cs2 := newTestSession(t)
	ctx := context.Background()

	r1, err := cs1.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("session1 ListTools: %v", err)
	}
	r2, err := cs2.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("session2 ListTools: %v", err)
	}

	if len(r1.Tools) != len(r2.Tools) {
		t.Errorf("session tool counts differ: %d vs %d", len(r1.Tools), len(r2.Tools))
	}

	// Closing one session should not affect the other
	cs1.Close()

	ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cs2.CallTool(ctx2, &mcp.CallToolParams{
		Name:      "list_payloads",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("session2 CallTool after session1 close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Ping: client↔server liveness
// Catches: Ping handler not wired, connection silently broken.
// ---------------------------------------------------------------------------

func TestPingInMemory(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cs.Ping(ctx, &mcp.PingParams{}); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Pagination iterators: Tools(), Resources(), Prompts() iterators
// Catches: iterator broken, yields wrong items, panics mid-iteration.
// ---------------------------------------------------------------------------

func TestToolsIterator(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	count := 0
	names := make(map[string]bool)
	for tool, err := range cs.Tools(ctx, &mcp.ListToolsParams{}) {
		if err != nil {
			t.Fatalf("Tools iterator error: %v", err)
		}
		names[tool.Name] = true
		count++
	}

	if count != 24 {
		t.Errorf("Tools iterator yielded %d tools, want 24", count)
	}
	for _, name := range []string{"list_payloads", "scan", "assess", "detect_waf", "mutate", "get_task_status", "cancel_task", "list_tasks"} {
		if !names[name] {
			t.Errorf("Tools iterator missing %q", name)
		}
	}
}

func TestResourcesIterator(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	count := 0
	for _, err := range cs.Resources(ctx, &mcp.ListResourcesParams{}) {
		if err != nil {
			t.Fatalf("Resources iterator error: %v", err)
		}
		count++
	}

	if count < 7 {
		t.Errorf("Resources iterator yielded %d, want at least 7", count)
	}
}

func TestPromptsIterator(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	count := 0
	for _, err := range cs.Prompts(ctx, &mcp.ListPromptsParams{}) {
		if err != nil {
			t.Fatalf("Prompts iterator error: %v", err)
		}
		count++
	}

	if count != 7 {
		t.Errorf("Prompts iterator yielded %d, want 7", count)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks: performance regression tracking
// Catches: unexpected performance degradation between commits.
// ---------------------------------------------------------------------------

func BenchmarkListPayloads(b *testing.B) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	client := mcp.NewClient(&mcp.Implementation{Name: "bench", Version: "0.0.1"}, nil)
	ctx := context.Background()

	go func() { _ = srv.MCPServer().Run(ctx, serverTransport) }()

	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		b.Fatalf("Connect: %v", err)
	}
	defer cs.Close()

	b.ResetTimer()
	for b.Loop() {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "list_payloads",
			Arguments: map[string]any{},
		})
		if err != nil {
			b.Fatalf("CallTool: %v", err)
		}
		if result.IsError {
			b.Fatal("unexpected error")
		}
	}
}

func BenchmarkMutate(b *testing.B) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	client := mcp.NewClient(&mcp.Implementation{Name: "bench", Version: "0.0.1"}, nil)
	ctx := context.Background()

	go func() { _ = srv.MCPServer().Run(ctx, serverTransport) }()

	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		b.Fatalf("Connect: %v", err)
	}
	defer cs.Close()

	b.ResetTimer()
	for b.Loop() {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "mutate",
			Arguments: map[string]any{"payload": "<script>alert(1)</script>", "encoders": []string{"url"}},
		})
		if err != nil {
			b.Fatalf("CallTool: %v", err)
		}
		if result.IsError {
			b.Fatal("unexpected error")
		}
	}
}

func BenchmarkGenerateCICD(b *testing.B) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	client := mcp.NewClient(&mcp.Implementation{Name: "bench", Version: "0.0.1"}, nil)
	ctx := context.Background()

	go func() { _ = srv.MCPServer().Run(ctx, serverTransport) }()

	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		b.Fatalf("Connect: %v", err)
	}
	defer cs.Close()

	b.ResetTimer()
	for b.Loop() {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "generate_cicd",
			Arguments: map[string]any{"target": "https://example.com", "platform": "github"},
		})
		if err != nil {
			b.Fatalf("CallTool: %v", err)
		}
		if result.IsError {
			b.Fatal("unexpected error")
		}
	}
}

func BenchmarkReadResource(b *testing.B) {
	srv := mcpserver.New(&mcpserver.Config{PayloadDir: "../../payloads"})
	defer srv.Stop()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	client := mcp.NewClient(&mcp.Implementation{Name: "bench", Version: "0.0.1"}, nil)
	ctx := context.Background()

	go func() { _ = srv.MCPServer().Run(ctx, serverTransport) }()

	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		b.Fatalf("Connect: %v", err)
	}
	defer cs.Close()

	b.ResetTimer()
	for b.Loop() {
		result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://version"})
		if err != nil {
			b.Fatalf("ReadResource: %v", err)
		}
		if len(result.Contents) == 0 {
			b.Fatal("empty contents")
		}
	}
}

// ---------------------------------------------------------------------------
// OWASP mappings: structural integrity
// Catches: nil categories, missing codes, stale reverse mapping.
// ---------------------------------------------------------------------------

func TestOWASPMappingsIntegrity(t *testing.T) {
	cs := newTestSession(t)
	ctx := context.Background()

	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://owasp-mappings"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}

	var mappings struct {
		Standard string `json:"standard"`
		Entries  []struct {
			Code       string   `json:"code"`
			Name       string   `json:"name"`
			URL        string   `json:"url"`
			Categories []string `json:"mapped_attack_categories"`
		} `json:"entries"`
		CategoryToOWASP map[string]string `json:"category_to_owasp"`
	}
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &mappings); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(mappings.Entries) != 10 {
		t.Errorf("got %d OWASP entries, want 10", len(mappings.Entries))
	}

	validCodes := make(map[string]bool)
	for i, e := range mappings.Entries {
		if e.Code == "" {
			t.Errorf("entry[%d] empty code", i)
		}
		if e.Name == "" {
			t.Errorf("entry[%d] (%s) empty name", i, e.Code)
		}
		if !strings.HasPrefix(e.URL, "https://") {
			t.Errorf("entry[%d] (%s) URL not https: %q", i, e.Code, e.URL)
		}
		validCodes[e.Code] = true
	}

	if len(mappings.CategoryToOWASP) == 0 {
		t.Error("category_to_owasp is empty")
	}
	for cat, code := range mappings.CategoryToOWASP {
		if !validCodes[code] {
			t.Errorf("category %q → OWASP %q which doesn't exist in entries", cat, code)
		}
	}
}

// ---------------------------------------------------------------------------
// Malformed JSON arguments: server must not panic
// ---------------------------------------------------------------------------

func TestMalformedJSONDoesNotPanic(t *testing.T) {
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools := []string{"list_payloads", "mutate", "generate_cicd"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tool,
				Arguments: json.RawMessage(`{"broken: json`),
			})
			// Either protocol error or IsError — just must not panic
			if err != nil {
				return
			}
			if result != nil && !result.IsError {
				t.Errorf("%q accepted malformed JSON", tool)
			}
		})
	}
}
