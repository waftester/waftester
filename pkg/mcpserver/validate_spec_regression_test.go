package mcpserver_test

// Regression tests for validate_spec — path traversal and SSRF bypasses.
//
// Bug: handleValidateSpec called apispec.ParseContext directly with spec_path
// and spec_url without the traversal/SSRF checks that resolveSpecInput applies.
// resolveSpecInput (used by every other spec tool) rejects:
//   - spec_path with ".." components, absolute paths, or rooted paths (e.g. /etc/passwd)
//   - spec_url that resolves to cloud metadata addresses (169.254.x.x, metadata.google.internal, etc.)
//
// Note: localhost and 127.0.0.1 are intentionally allowed by validateTargetURL —
// users can legitimately test WAFs deployed locally.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// extractText is defined in async_tools_test.go (same package), no redeclaration needed.
// If it weren't, a local version would be:
//   func extractText(t *testing.T, r *mcp.CallToolResult) string { ... }

// ---------------------------------------------------------------------------
// Path traversal via spec_path — validate_spec must reject these.
// ---------------------------------------------------------------------------

func TestValidateSpec_PathTraversal_Blocked(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
	}{
		{"parent traversal", "../../../etc/passwd"},
		{"backslash traversal", `..\..\..\\windows\\system32\\config\\sam`},
		{"mid-path traversal", "specs/../../../etc/shadow"},
		{"absolute unix", "/etc/passwd"},
		{"windows absolute", `C:\Windows\System32\drivers\etc\hosts`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"spec_path": tc.path,
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "validate_spec",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatalf("validate_spec should have rejected traversal path %q but returned success", tc.path)
			}
			text := extractText(t, result)
			if !strings.Contains(strings.ToLower(text), "..") &&
				!strings.Contains(strings.ToLower(text), "relative") &&
				!strings.Contains(strings.ToLower(text), "traversal") &&
				!strings.Contains(strings.ToLower(text), "absolute") &&
				!strings.Contains(strings.ToLower(text), "spec_path") {
				t.Errorf("error message should mention the path restriction, got: %s", text)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SSRF via spec_url — validate_spec must reject cloud-metadata URLs.
// ---------------------------------------------------------------------------

func TestValidateSpec_SSRF_Blocked(t *testing.T) {
	t.Parallel()

	// validateTargetURL blocks cloud metadata endpoints, not localhost/127.0.0.1
	// (those are legitimate targets for testing local apps).
	cases := []struct {
		name string
		url  string
	}{
		{"AWS metadata", "http://169.254.169.254/latest/meta-data/"},
		{"GCP metadata", "http://metadata.google.internal/computeMetadata/v1/"},
		{"Azure metadata", "http://169.254.169.254/metadata/instance"},
		{"link-local range", "http://169.254.42.42/latest/meta-data/"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"spec_url": tc.url,
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "validate_spec",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatalf("validate_spec should have blocked SSRF URL %q but returned success", tc.url)
			}
			text := extractText(t, result)
			if !strings.Contains(strings.ToLower(text), "blocked") &&
				!strings.Contains(strings.ToLower(text), "ssrf") &&
				!strings.Contains(strings.ToLower(text), "internal") &&
				!strings.Contains(strings.ToLower(text), "metadata") &&
				!strings.Contains(strings.ToLower(text), "cloud") {
				t.Errorf("error message should explain the SSRF block, got: %s", text)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validate_spec still works for valid inline content.
// ---------------------------------------------------------------------------

func TestValidateSpec_ValidContent_Succeeds(t *testing.T) {
	t.Parallel()

	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	minimalSpec := `openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /ping:
    get:
      summary: Ping`

	args, _ := json.Marshal(map[string]any{
		"spec_content": minimalSpec,
	})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "validate_spec",
		Arguments: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("validate_spec rejected valid spec: %s", extractText(t, result))
	}

	text := extractText(t, result)
	if !strings.Contains(text, "true") {
		t.Errorf("expected valid:true in response, got: %s", text)
	}
}

// ---------------------------------------------------------------------------
// validate_spec with no source — must return a helpful error.
// ---------------------------------------------------------------------------

func TestValidateSpec_NoSource_Error(t *testing.T) {
	t.Parallel()

	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "validate_spec",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when no source provided")
	}
	text := extractText(t, result)
	if !strings.Contains(strings.ToLower(text), "spec_content") &&
		!strings.Contains(strings.ToLower(text), "spec_path") &&
		!strings.Contains(strings.ToLower(text), "spec_url") {
		t.Errorf("error should name the missing parameters, got: %s", text)
	}
}

// ---------------------------------------------------------------------------
// validate_spec with multiple sources — must reject the ambiguity.
// ---------------------------------------------------------------------------

func TestValidateSpec_MultipleSourcesRejected(t *testing.T) {
	t.Parallel()

	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"spec_content": `openapi: "3.0.0"`,
		"spec_path":    "some/path.yaml",
	})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "validate_spec",
		Arguments: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when both spec_content and spec_path provided")
	}
}

// ---------------------------------------------------------------------------
// Consistency: validate_spec and list_spec_endpoints must agree on traversal
// behavior — both should reject the same bad paths.
// ---------------------------------------------------------------------------

func TestValidateSpec_PathTraversal_ConsistentWithListSpecEndpoints(t *testing.T) {
	t.Parallel()

	badPath := "../../../etc/passwd"

	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// validate_spec
	validateArgs, _ := json.Marshal(map[string]any{"spec_path": badPath})
	validateResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "validate_spec",
		Arguments: json.RawMessage(validateArgs),
	})
	if err != nil {
		t.Fatalf("validate_spec CallTool: %v", err)
	}

	// list_spec_endpoints
	listArgs, _ := json.Marshal(map[string]any{"spec_path": badPath})
	listResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_spec_endpoints",
		Arguments: json.RawMessage(listArgs),
	})
	if err != nil {
		t.Fatalf("list_spec_endpoints CallTool: %v", err)
	}

	if validateResult.IsError != listResult.IsError {
		t.Errorf("validate_spec (isError=%v) and list_spec_endpoints (isError=%v) disagree on path traversal rejection — security guard inconsistency",
			validateResult.IsError, listResult.IsError)
	}
}

// Compile-time: ensure *mcp.CallToolResult is usable in test (import check).
var _ *mcp.CallToolResult
