package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ═══════════════════════════════════════════════════════════════════════════
// truncateBytes — UTF-8 safe byte truncation (was: raw byte-index slice)
// ═══════════════════════════════════════════════════════════════════════════

func TestTruncateBytes_MultiByteRune(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		max      int
		wantLen  bool   // true = check len(result) <= max
		wantExact string // non-empty = exact match
	}{
		{
			name:      "ASCII within limit",
			input:     "hello",
			max:       10,
			wantExact: "hello",
		},
		{
			name:      "ASCII at limit",
			input:     "hello",
			max:       5,
			wantExact: "hello",
		},
		{
			name:      "ASCII truncated",
			input:     "hello world",
			max:       5,
			wantExact: "hello",
		},
		{
			name:    "3-byte UTF-8 not split (Japanese)",
			input:   "テスト", // 9 bytes (3 × 3-byte runes)
			max:     7,        // between 2nd and 3rd rune
			wantLen: true,
			wantExact: "テス", // 6 bytes — steps back to rune boundary
		},
		{
			name:    "4-byte UTF-8 not split (emoji)",
			input:   "A💀B", // 1 + 4 + 1 = 6 bytes
			max:     3,       // mid-emoji
			wantLen: true,
			wantExact: "A", // steps back past the 4-byte emoji
		},
		{
			name:      "2-byte UTF-8 not split",
			input:     "café", // c(1) a(1) f(1) é(2) = 5 bytes
			max:       4,      // between the two bytes of é
			wantLen:   true,
			wantExact: "caf",
		},
		{
			name:      "zero max",
			input:     "hello",
			max:       0,
			wantExact: "",
		},
		{
			name:      "empty input",
			input:     "",
			max:       10,
			wantExact: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := truncateBytes(tt.input, tt.max)

			if tt.wantExact != "" || tt.max == 0 {
				if got != tt.wantExact {
					t.Errorf("truncateBytes(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.wantExact)
				}
			}
			if tt.wantLen && len(got) > tt.max {
				t.Errorf("truncateBytes(%q, %d) produced %d bytes (> max)", tt.input, tt.max, len(got))
			}

			// Every result must be valid UTF-8 — this is the core invariant.
			if !utf8.ValidString(got) {
				t.Errorf("truncateBytes(%q, %d) produced invalid UTF-8: %q", tt.input, tt.max, got)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// resolveSpecInput — path traversal blocking (was: no validation)
// ═══════════════════════════════════════════════════════════════════════════

func TestResolveSpecInput_PathTraversal(t *testing.T) {
	t.Parallel()

	traversalPaths := []struct {
		name string
		path string
	}{
		{"parent traversal", "../../../etc/passwd"},
		{"backslash traversal", "..\\..\\..\\windows\\system32\\config\\sam"},
		{"mid-path traversal", "specs/../../../etc/shadow"},
		{"windows absolute", "C:\\Windows\\System32\\drivers\\etc\\hosts"},
	}

	for _, tt := range traversalPaths {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, errResult := resolveSpecInput(context.Background(), "", tt.path, "")
			if errResult == nil {
				t.Fatalf("resolveSpecInput(path=%q) should have returned an error result", tt.path)
			}
			// Verify the error message is about path traversal, not a parse error.
			text := extractTextContent(errResult)
			if !strings.Contains(text, "relative path") && !strings.Contains(text, "..") {
				t.Errorf("expected path traversal error, got: %s", text)
			}
		})
	}
}

func TestResolveSpecInput_SafeRelativePath(t *testing.T) {
	t.Parallel()

	// A relative path without traversal should not be rejected by the path
	// validation — it may fail later on parse, but the error must NOT be
	// about path traversal.
	_, errResult := resolveSpecInput(context.Background(), "", "specs/api.yaml", "")
	if errResult == nil {
		// Parse error is expected if the file doesn't exist, but it must
		// have gotten past the path validation.
		return
	}
	text := extractTextContent(errResult)
	if strings.Contains(text, "relative path") {
		t.Fatalf("safe relative path rejected as traversal: %s", text)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// resolveSpecInput — SSRF blocking for spec_url (was: no validateTargetURL)
// ═══════════════════════════════════════════════════════════════════════════

func TestResolveSpecInput_SSRF(t *testing.T) {
	t.Parallel()

	ssrfURLs := []struct {
		name string
		url  string
	}{
		{"AWS metadata", "http://169.254.169.254/latest/meta-data/"},
		{"GCP metadata", "http://metadata.google.internal/computeMetadata/v1/"},
		{"Alibaba metadata", "http://100.100.100.200/latest/meta-data/"},
		{"Azure Wire Server", "http://168.63.129.16/metadata/instance"},
		{"link-local", "http://169.254.1.1/anything"},
	}

	for _, tt := range ssrfURLs {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, errResult := resolveSpecInput(context.Background(), "", "", tt.url)
			if errResult == nil {
				t.Fatalf("resolveSpecInput(url=%q) should have returned an error result", tt.url)
			}
			text := extractTextContent(errResult)
			if !strings.Contains(text, "blocked") {
				t.Errorf("expected SSRF block error, got: %s", text)
			}
		})
	}
}

func TestResolveSpecInput_SafeURL(t *testing.T) {
	t.Parallel()

	// A valid external URL should pass the SSRF check. It will fail later
	// on fetch/parse, but the error must NOT be about blocking.
	_, errResult := resolveSpecInput(context.Background(), "", "", "https://example.com/api/spec.yaml")
	if errResult == nil {
		return // parse/fetch error is acceptable
	}
	text := extractTextContent(errResult)
	if strings.Contains(text, "blocked") {
		t.Fatalf("safe URL incorrectly blocked as SSRF: %s", text)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// cicdSafePattern — shell injection blocking (was: no validation)
// ═══════════════════════════════════════════════════════════════════════════

func TestCICDSafePattern_RejectsShellMetachars(t *testing.T) {
	t.Parallel()

	dangerous := []struct {
		name  string
		input string
	}{
		{"semicolon", "https://example.com; rm -rf /"},
		{"pipe", "https://example.com | cat /etc/passwd"},
		{"backtick", "https://example.com`id`"},
		{"dollar-paren", "https://example.com$(whoami)"},
		{"ampersand", "https://example.com && curl evil.com"},
		{"angle-bracket", "https://example.com > /tmp/out"},
		{"single-quote", "https://example.com'; DROP TABLE--"},
		{"double-quote", `https://example.com" && id`},
		{"newline", "https://example.com\nid"},
		{"space", "https://example.com /etc/passwd"},
	}

	for _, tt := range dangerous {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if cicdSafePattern.MatchString(tt.input) {
				t.Errorf("cicdSafePattern accepted dangerous input: %q", tt.input)
			}
		})
	}
}

func TestCICDSafePattern_AcceptsSafeInputs(t *testing.T) {
	t.Parallel()

	safe := []string{
		"https://example.com",
		"https://api.example.com/v1",
		"http://10.0.0.1:8080/path",
		"https://example.com/path?query=value&other=123",
		"sqli",
		"xss,cmdi,lfi",
		"https://user@example.com:443/path",
	}

	for _, input := range safe {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if !cicdSafePattern.MatchString(input) {
				t.Errorf("cicdSafePattern rejected safe input: %q", input)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// TaskManager.List — deterministic ordering (was: map iteration order)
// ═══════════════════════════════════════════════════════════════════════════

func TestTaskManagerList_DeterministicOrder(t *testing.T) {
	t.Parallel()

	tm := NewTaskManager()
	defer tm.Stop()

	// Create tasks with staggered timestamps to ensure ordering.
	const n = 5
	tasks := make([]*Task, n)
	for i := 0; i < n; i++ {
		task, _, _ := tm.Create(context.Background(), "tool")
		tasks[i] = task
		// Force distinct CreatedAt values.
		time.Sleep(time.Millisecond)
	}

	// Call List multiple times — output must always be in creation order.
	for attempt := 0; attempt < 20; attempt++ {
		list := tm.List()
		if len(list) != n {
			t.Fatalf("attempt %d: List() returned %d tasks, want %d", attempt, len(list), n)
		}
		for i := 0; i < n; i++ {
			if list[i].ID != tasks[i].ID {
				t.Fatalf("attempt %d: list[%d].ID = %q, want %q (non-deterministic ordering)",
					attempt, i, list[i].ID, tasks[i].ID)
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Headless max_clicks suggestion cap (was: suggestion could exceed schema max 200)
// ═══════════════════════════════════════════════════════════════════════════

func TestBuildEventCrawlResponse_MaxClicksSuggestionCap(t *testing.T) {
	t.Parallel()

	// Simulate a result set where len(results) == MaxClicks (triggers suggestion).
	args := eventCrawlArgs{
		Target:    "https://example.com",
		MaxClicks: 150,
	}

	// Build results that match the limit.
	results := make([]EventCrawlResult, args.MaxClicks)
	for i := range results {
		results[i] = EventCrawlResult{DOMChanged: true}
	}

	resp := buildEventCrawlResponse(results, nil, args)

	// The suggestion should never exceed the schema maximum (200).
	for _, step := range resp.NextSteps {
		if strings.Contains(step, `"max_clicks": 300`) {
			t.Fatalf("suggestion exceeds schema maximum: %s", step)
		}
	}

	// At max_clicks=150, suggestion should cap at 200.
	found200 := false
	for _, step := range resp.NextSteps {
		if strings.Contains(step, `"max_clicks": 200`) {
			found200 = true
			break
		}
	}
	if !found200 {
		t.Fatal("expected max_clicks suggestion capped at 200, but not found in next steps")
	}

	// If max_clicks=200, the suggestion should NOT recommend increasing.
	args200 := eventCrawlArgs{
		Target:    "https://example.com",
		MaxClicks: 200,
	}
	results200 := make([]EventCrawlResult, 200)
	for i := range results200 {
		results200[i] = EventCrawlResult{DOMChanged: true}
	}
	resp200 := buildEventCrawlResponse(results200, nil, args200)
	for _, step := range resp200.NextSteps {
		if strings.Contains(step, `"max_clicks"`) {
			t.Fatalf("at max_clicks=200, should not suggest higher limit: %s", step)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

// extractTextContent pulls the text from an MCP error CallToolResult.
func extractTextContent(result *mcp.CallToolResult) string {
	if result == nil || len(result.Content) == 0 {
		return ""
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}
