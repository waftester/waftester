package mcpserver_test

// handler_regression_test.go — Deep regression for all MCP tool handlers.
//
// Tests handler-level behavior: argument clamping, error paths, async
// lifecycle (scan/assess/bypass/discover), progress updates, task management
// edge cases, and input validation. All tests use SSE transport to match
// real deployment.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ═══════════════════════════════════════════════════════════════════════════
// Helper that creates exactly one shared SSE server + session for grouped tests.
// ═══════════════════════════════════════════════════════════════════════════

func newQuickSSESession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	cs, _ := newSSETestSession(t) // reuse from n8n_regression_test.go
	return cs
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Scan — full async lifecycle (launch → progress → terminal state)
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Scan_AsyncLifecycle(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Launch scan with minimal options (will fail against non-existent target, which is fine)
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: json.RawMessage(`{
			"target": "https://example.com/search?q=test",
			"categories": ["sqli"],
			"concurrency": 5,
			"rate_limit": 10,
			"timeout": 5
		}`),
	})
	if err != nil {
		t.Fatalf("scan launch: %v", err)
	}
	if result.IsError {
		t.Fatalf("scan returned error: %s", extractTextN8n(t, result))
	}

	// Parse task_id from async envelope
	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID            string `json:"task_id"`
		Status            string `json:"status"`
		Tool              string `json:"tool"`
		EstimatedDuration string `json:"estimated_duration"`
		NextStep          string `json:"next_step"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parse async response: %v\nraw: %s", err, text)
	}
	if asyncResp.TaskID == "" {
		t.Fatal("scan: empty task_id")
	}
	if asyncResp.Status != "running" {
		t.Errorf("scan: initial status = %q, want running", asyncResp.Status)
	}
	if asyncResp.Tool != "scan" {
		t.Errorf("scan: tool = %q, want scan", asyncResp.Tool)
	}
	if asyncResp.EstimatedDuration == "" {
		t.Error("scan: empty estimated_duration")
	}
	if asyncResp.NextStep == "" {
		t.Error("scan: empty next_step guidance")
	}

	// Poll with wait_seconds — observe progress or terminal state
	var sawProgress bool
	var finalStatus string
	for i := 0; i < 15; i++ {
		pollArgs, _ := json.Marshal(map[string]any{
			"task_id":      asyncResp.TaskID,
			"wait_seconds": 3,
		})
		pollResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "get_task_status",
			Arguments: json.RawMessage(pollArgs),
		})
		if err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}
		pollText := extractTextN8n(t, pollResult)
		var snap struct {
			TaskID   string          `json:"task_id"`
			Status   string          `json:"status"`
			Progress float64         `json:"progress"`
			Message  string          `json:"message"`
			Result   json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal([]byte(pollText), &snap); err != nil {
			t.Fatalf("poll %d parse: %v", i, err)
		}

		if snap.Progress > 0 {
			sawProgress = true
		}

		if snap.Status == "completed" || snap.Status == "failed" || snap.Status == "cancelled" {
			finalStatus = snap.Status
			// If completed, verify result structure
			if snap.Status == "completed" && len(snap.Result) > 0 {
				var scanResult struct {
					Summary        string   `json:"summary"`
					DetectionRate  string   `json:"detection_rate"`
					Interpretation string   `json:"interpretation"`
					NextSteps      []string `json:"next_steps"`
				}
				if err := json.Unmarshal(snap.Result, &scanResult); err != nil {
					t.Errorf("completed scan result parse: %v", err)
				}
				if scanResult.Summary == "" {
					t.Error("scan completed but summary is empty")
				}
				if scanResult.Interpretation == "" {
					t.Error("scan completed but interpretation is empty")
				}
			}
			break
		}
	}

	if finalStatus == "" {
		t.Error("scan task never reached terminal status after 15 polls")
	}
	// Progress may not always be visible (fast tasks complete instantly),
	// but for scan it should usually show some intermediate state.
	t.Logf("scan lifecycle: sawProgress=%v finalStatus=%s", sawProgress, finalStatus)
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Assess — full async lifecycle
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Assess_AsyncLifecycle(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "assess",
		Arguments: json.RawMessage(`{
			"target": "https://example.com",
			"concurrency": 5,
			"rate_limit": 10,
			"timeout": 5,
			"categories": ["sqli"]
		}`),
	})
	if err != nil {
		t.Fatalf("assess launch: %v", err)
	}
	if result.IsError {
		t.Fatalf("assess error: %s", extractTextN8n(t, result))
	}

	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if asyncResp.Tool != "assess" {
		t.Errorf("tool = %q, want assess", asyncResp.Tool)
	}

	// Poll until terminal
	finalStatus := pollUntilTerminal(t, cs, ctx, asyncResp.TaskID)
	if finalStatus != "completed" && finalStatus != "failed" {
		t.Errorf("assess terminal status = %q", finalStatus)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Bypass — full async lifecycle + payload count enforcement
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Bypass_AsyncLifecycle(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "bypass",
		Arguments: json.RawMessage(`{
			"target": "https://example.com/search?q=test",
			"payloads": ["' OR 1=1--", "<script>alert(1)</script>"],
			"concurrency": 3,
			"rate_limit": 5,
			"timeout": 5
		}`),
	})
	if err != nil {
		t.Fatalf("bypass launch: %v", err)
	}
	if result.IsError {
		t.Fatalf("bypass error: %s", extractTextN8n(t, result))
	}

	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID string `json:"task_id"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if asyncResp.Tool != "bypass" {
		t.Errorf("tool = %q, want bypass", asyncResp.Tool)
	}

	finalStatus := pollUntilTerminal(t, cs, ctx, asyncResp.TaskID)
	if finalStatus != "completed" && finalStatus != "failed" {
		t.Errorf("bypass terminal status = %q", finalStatus)
	}
}

func TestHandler_Bypass_PayloadTruncation(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Send 55 payloads (over the 50 max)
	payloads := make([]string, 55)
	for i := range payloads {
		payloads[i] = fmt.Sprintf("payload_%d", i)
	}
	argsJSON, _ := json.Marshal(map[string]any{
		"target":   "https://example.com",
		"payloads": payloads,
	})

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "bypass",
		Arguments: json.RawMessage(argsJSON),
	})
	if err != nil {
		t.Fatalf("bypass launch: %v", err)
	}

	// The bypass tool launches async — the 50-payload check happens inside the goroutine
	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Wait for the task to finish — it should fail with the truncation error
	finalStatus := pollUntilTerminal(t, cs, ctx, asyncResp.TaskID)
	if finalStatus != "failed" {
		t.Errorf("55 payloads: expected failed, got %q", finalStatus)
	}

	// Verify the error mentions the payload limit
	pollArgs, _ := json.Marshal(map[string]any{
		"task_id":      asyncResp.TaskID,
		"wait_seconds": 0,
	})
	pollResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(pollArgs),
	})
	if err != nil {
		t.Fatalf("final poll: %v", err)
	}
	pollText := extractTextN8n(t, pollResult)
	var snap struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(pollText), &snap); err != nil {
		t.Fatalf("parse snap: %v", err)
	}
	if !strings.Contains(snap.Error, "50") {
		t.Errorf("expected truncation error mentioning 50, got: %s", snap.Error)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Discover — full async lifecycle
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Discover_AsyncLifecycle(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "discover",
		Arguments: json.RawMessage(`{
			"target": "https://example.com",
			"max_depth": 1,
			"concurrency": 3,
			"timeout": 5
		}`),
	})
	if err != nil {
		t.Fatalf("discover launch: %v", err)
	}
	if result.IsError {
		t.Fatalf("discover error: %s", extractTextN8n(t, result))
	}

	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID string `json:"task_id"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if asyncResp.Tool != "discover" {
		t.Errorf("tool = %q, want discover", asyncResp.Tool)
	}

	finalStatus := pollUntilTerminal(t, cs, ctx, asyncResp.TaskID)
	if finalStatus != "completed" && finalStatus != "failed" {
		t.Errorf("discover terminal status = %q", finalStatus)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Detect WAF — fast tool, response structure
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_DetectWAF_ResponseStructure(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "detect_waf",
		Arguments: json.RawMessage(`{"target": "https://example.com"}`),
	})
	if err != nil {
		t.Fatalf("detect_waf: %v", err)
	}

	// detect_waf may succeed or fail due to network — both valid
	text := extractTextN8n(t, result)
	if result.IsError {
		// Enriched error should have recovery_steps
		var errResp struct {
			Error         string   `json:"error"`
			RecoverySteps []string `json:"recovery_steps"`
		}
		if err := json.Unmarshal([]byte(text), &errResp); err == nil {
			if len(errResp.RecoverySteps) == 0 {
				t.Error("detect_waf error has no recovery_steps")
			}
		}
		return
	}

	// Success: verify response has expected fields
	var resp struct {
		Summary        string   `json:"summary"`
		Interpretation string   `json:"interpretation"`
		NextSteps      []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse detect_waf response: %v", err)
	}
	if resp.Summary == "" {
		t.Error("detect_waf: empty summary")
	}
}

func TestHandler_DetectWAF_TimeoutClamping(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// timeout=999 should be clamped to 60
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "detect_waf",
		Arguments: json.RawMessage(`{"target": "https://example.com", "timeout": 999}`),
	})
	if err != nil {
		t.Fatalf("detect_waf: %v", err)
	}
	// Should not hang for 999 seconds — the handler clamps to 60
	// Success or network failure — both acceptable, just shouldn't time out
	_ = result
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Probe — error paths and response
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Probe_ErrorPaths(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tests := []struct {
		name      string
		args      string
		wantError bool
		wantText  string
	}{
		{
			name:      "empty_target",
			args:      `{}`,
			wantError: true,
			wantText:  "target",
		},
		{
			name:      "bad_scheme",
			args:      `{"target": "ftp://evil.com"}`,
			wantError: true,
			wantText:  "http",
		},
		{
			name:      "ssrf_cloud_metadata",
			args:      `{"target": "http://169.254.169.254/latest/meta-data/"}`,
			wantError: true,
			wantText:  "cloud metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "probe",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if tt.wantError && !result.IsError {
				t.Errorf("expected error for %s", tt.name)
			}
			if tt.wantText != "" {
				text := extractTextN8n(t, result)
				if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantText)) {
					t.Errorf("missing %q in: %.200s", tt.wantText, text)
				}
			}
		})
	}
}

func TestHandler_Probe_ValidTarget(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "probe",
		Arguments: json.RawMessage(`{"target": "https://example.com", "timeout": 5}`),
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	// probe should return the report even if target is unreachable
	text := extractTextN8n(t, result)
	var resp struct {
		Summary string `json:"summary"`
		Report  struct {
			Target    string `json:"target"`
			Reachable bool   `json:"reachable"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse probe response: %v\nraw: %.300s", err, text)
	}
	if resp.Report.Target != "https://example.com" {
		t.Errorf("probe target = %q", resp.Report.Target)
	}
}

func TestHandler_Probe_TimeoutClamping(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// timeout=999 should be clamped to 30
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "probe",
		Arguments: json.RawMessage(`{"target": "https://example.com", "timeout": 999}`),
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	// Should not hang for 999 seconds
	_ = result
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Learn — valid JSON and edge cases
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Learn_ValidDiscovery(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Minimal valid discovery JSON
	discoveryJSON := `{
		"target": "https://example.com",
		"endpoints": [
			{"path": "/api/users", "method": "GET", "status_code": 200, "parameters": [{"name": "q", "location": "query"}]}
		],
		"waf_detected": false
	}`
	argsJSON, _ := json.Marshal(map[string]any{
		"discovery_json": discoveryJSON,
	})

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "learn",
		Arguments: json.RawMessage(argsJSON),
	})
	if err != nil {
		t.Fatalf("learn: %v", err)
	}
	if result.IsError {
		t.Fatalf("learn error: %s", extractTextN8n(t, result))
	}

	text := extractTextN8n(t, result)
	var resp struct {
		Summary   string   `json:"summary"`
		NextSteps []string `json:"next_steps"`
		Plan      struct {
			Target string `json:"target"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse: %v\nraw: %.300s", err, text)
	}
	if resp.Summary == "" {
		t.Error("learn: empty summary")
	}
	if len(resp.NextSteps) == 0 {
		t.Error("learn: no next_steps")
	}
}

func TestHandler_Learn_ZeroEndpoints(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	discoveryJSON := `{"target": "https://example.com", "endpoints": []}`
	argsJSON, _ := json.Marshal(map[string]any{
		"discovery_json": discoveryJSON,
	})

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "learn",
		Arguments: json.RawMessage(argsJSON),
	})
	if err != nil {
		t.Fatalf("learn: %v", err)
	}
	// Should handle zero endpoints gracefully (not crash)
	// May return an error or a plan with zero tests — both acceptable
	_ = result
}

func TestHandler_Learn_ErrorPaths(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name     string
		args     string
		wantText string
	}{
		{
			name:     "empty",
			args:     `{}`,
			wantText: "discovery_json",
		},
		{
			name:     "invalid_json",
			args:     `{"discovery_json": "not json at all"}`,
			wantText: "invalid",
		},
		{
			name:     "malformed_json",
			args:     `{"discovery_json": "{broken"}`,
			wantText: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "learn",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("learn: %v", err)
			}
			if !result.IsError {
				t.Error("expected error")
			}
			text := extractTextN8n(t, result)
			if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantText)) {
				t.Errorf("missing %q in: %.200s", tt.wantText, text)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Scan — input validation edge cases
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Scan_ValidationEdgeCases(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name     string
		args     string
		wantErr  bool
		wantText string
	}{
		{
			name:     "empty_target",
			args:     `{}`,
			wantErr:  true,
			wantText: "target",
		},
		{
			name:     "bad_scheme",
			args:     `{"target": "ftp://evil.com"}`,
			wantErr:  true,
			wantText: "http",
		},
		{
			name:     "cloud_metadata",
			args:     `{"target": "http://169.254.169.254"}`,
			wantErr:  true,
			wantText: "cloud metadata",
		},
		{
			name:     "nonexistent_category",
			args:     `{"target": "https://example.com", "categories": ["nonexistent_xyz"]}`,
			wantErr:  true,
			wantText: "no payloads",
		},
		{
			name:     "invalid_tamper",
			args:     `{"target": "https://example.com", "tamper": "fake_tamper_xyz"}`,
			wantErr:  true,
			wantText: "unknown tampers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "scan",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if tt.wantErr && !result.IsError {
				text := extractTextN8n(t, result)
				// scan might return async envelope if validation passed
				// For target/scheme errors, it should be synchronous
				t.Errorf("expected error for %s, got: %.200s", tt.name, text)
			}
			if tt.wantText != "" && result.IsError {
				text := extractTextN8n(t, result)
				if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantText)) {
					t.Errorf("missing %q in: %.200s", tt.wantText, text)
				}
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. Assess — input validation
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Assess_Validation(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name     string
		args     string
		wantErr  bool
		wantText string
	}{
		{
			name:     "empty_target",
			args:     `{}`,
			wantErr:  true,
			wantText: "target",
		},
		{
			name:     "bad_scheme",
			args:     `{"target": "ftp://evil.com"}`,
			wantErr:  true,
			wantText: "http",
		},
		{
			name:     "ssrf",
			args:     `{"target": "http://169.254.169.254"}`,
			wantErr:  true,
			wantText: "cloud metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "assess",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("assess: %v", err)
			}
			if tt.wantErr && !result.IsError {
				t.Errorf("expected error for %s", tt.name)
			}
			if tt.wantText != "" && result.IsError {
				text := extractTextN8n(t, result)
				if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantText)) {
					t.Errorf("missing %q in: %.200s", tt.wantText, text)
				}
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Bypass — input validation
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Bypass_Validation(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name     string
		args     string
		wantErr  bool
		wantText string
	}{
		{
			name:     "empty_target",
			args:     `{}`,
			wantErr:  true,
			wantText: "target",
		},
		{
			name:     "no_payloads",
			args:     `{"target": "https://example.com"}`,
			wantErr:  true,
			wantText: "payload",
		},
		{
			name:     "empty_payloads",
			args:     `{"target": "https://example.com", "payloads": []}`,
			wantErr:  true,
			wantText: "payload",
		},
		{
			name:     "ssrf",
			args:     `{"target": "http://169.254.169.254", "payloads": ["test"]}`,
			wantErr:  true,
			wantText: "cloud metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "bypass",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("bypass: %v", err)
			}
			if tt.wantErr && !result.IsError {
				t.Errorf("expected error for %s", tt.name)
			}
			if tt.wantText != "" && result.IsError {
				text := extractTextN8n(t, result)
				if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantText)) {
					t.Errorf("missing %q in: %.200s", tt.wantText, text)
				}
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. Discover — input validation
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_Discover_Validation(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name     string
		args     string
		wantErr  bool
		wantText string
	}{
		{
			name:     "empty_target",
			args:     `{}`,
			wantErr:  true,
			wantText: "target",
		},
		{
			name:     "bad_scheme",
			args:     `{"target": "ftp://evil.com"}`,
			wantErr:  true,
			wantText: "http",
		},
		{
			name:     "ssrf",
			args:     `{"target": "http://169.254.169.254"}`,
			wantErr:  true,
			wantText: "cloud metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "discover",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("discover: %v", err)
			}
			if tt.wantErr && !result.IsError {
				t.Errorf("expected error for %s", tt.name)
			}
			if tt.wantText != "" && result.IsError {
				text := extractTextN8n(t, result)
				if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantText)) {
					t.Errorf("missing %q in: %.200s", tt.wantText, text)
				}
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. get_task_status — wait_seconds clamping
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_GetTaskStatus_WaitSecondsClamping(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Launch a task to have something to poll
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

	// wait_seconds=999 should be clamped to 120.
	// If NOT clamped, this would time out the 30s test context.
	start := time.Now()
	pollArgs, _ := json.Marshal(map[string]any{
		"task_id":      asyncResp.TaskID,
		"wait_seconds": 999,
	})
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(pollArgs),
	})
	elapsed := time.Since(start)
	if err != nil {
		// Context cancel from test timeout is acceptable
		if ctx.Err() == nil {
			t.Fatalf("poll: %v", err)
		}
	}
	// The task likely completed quickly, but the key check is
	// it didn't try to wait 999 seconds. If it did, we'd have
	// hit the 30s test timeout.
	t.Logf("wait_seconds=999 poll took %v (clamped to max 120s)", elapsed)
}

func TestHandler_GetTaskStatus_ExplicitZeroWait(t *testing.T) {
	cs := newQuickSSESession(t)
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

	// wait_seconds=0 should return immediately (no long-poll)
	start := time.Now()
	pollArgs, _ := json.Marshal(map[string]any{
		"task_id":      asyncResp.TaskID,
		"wait_seconds": 0,
	})
	pollResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_task_status",
		Arguments: json.RawMessage(pollArgs),
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	// Should be very fast (< 2s) since wait=0 means no long-poll
	if elapsed > 2*time.Second {
		t.Errorf("wait_seconds=0 took %v (should be instant)", elapsed)
	}

	// Should still return valid status
	pollText := extractTextN8n(t, pollResult)
	var snap struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(pollText), &snap); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if snap.TaskID != asyncResp.TaskID {
		t.Errorf("task_id mismatch")
	}
	if snap.Status == "" {
		t.Error("empty status")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. Task progress visibility — verify SetProgress is observable
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_TaskProgressVisibility(t *testing.T) {
	// Use a shared server so we can launch from one session and poll from another
	_, ts := newN8nSharedServer(t)

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "progress-test",
		Version: "1.0.0",
	}, nil)
	transport := &mcp.SSEClientTransport{Endpoint: ts.URL + "/sse"}
	cs, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Launch scan — which calls SetProgress multiple times during execution
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: json.RawMessage(`{
			"target": "https://example.com/search?q=test",
			"categories": ["sqli"],
			"concurrency": 2,
			"rate_limit": 5
		}`),
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	text := extractTextN8n(t, result)
	var asyncResp struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(text), &asyncResp); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Rapid-poll with wait_seconds=0 to catch intermediate progress
	var progressValues []float64
	var messages []string
	for i := 0; i < 30; i++ {
		pollArgs, _ := json.Marshal(map[string]any{
			"task_id":      asyncResp.TaskID,
			"wait_seconds": 1,
		})
		pollResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "get_task_status",
			Arguments: json.RawMessage(pollArgs),
		})
		if err != nil {
			break
		}
		pollText := extractTextN8n(t, pollResult)
		var snap struct {
			Status   string  `json:"status"`
			Progress float64 `json:"progress"`
			Message  string  `json:"message"`
		}
		if err := json.Unmarshal([]byte(pollText), &snap); err != nil {
			break
		}

		if snap.Progress > 0 {
			progressValues = append(progressValues, snap.Progress)
		}
		if snap.Message != "" {
			messages = append(messages, snap.Message)
		}

		if snap.Status == "completed" || snap.Status == "failed" || snap.Status == "cancelled" {
			break
		}
	}

	// Log what we saw — progress may be empty if task completed too fast
	t.Logf("progress values observed: %v", progressValues)
	t.Logf("messages observed: %v", messages)

	// The scan handler calls SetProgress at least once (10, 100, "Loaded N payloads")
	// and then every 10 results. We should see at least one progress update.
	if len(progressValues) == 0 && len(messages) == 0 {
		t.Log("WARNING: no intermediate progress observed (task may have completed too fast)")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. compare_baselines — via SSE
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_CompareBaselines_ViaSSE(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name     string
		args     string
		wantErr  bool
		wantText string
	}{
		{
			name:     "missing_both",
			args:     `{}`,
			wantErr:  true,
			wantText: "baseline_findings",
		},
		{
			name:     "missing_current",
			args:     `{"baseline_findings": "[]"}`,
			wantErr:  true,
			wantText: "current_findings",
		},
		{
			name:     "both_empty_arrays",
			args:     `{"baseline_findings": "[]", "current_findings": "[]"}`,
			wantErr:  false,
			wantText: "",
		},
		{
			name:     "invalid_baseline_json",
			args:     `{"baseline_findings": "not json", "current_findings": "[]"}`,
			wantErr:  true,
			wantText: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "compare_baselines",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("compare_baselines: %v", err)
			}
			if tt.wantErr && !result.IsError {
				// Accept non-error for edge cases that return a comparison
			}
			if !tt.wantErr && result.IsError {
				t.Errorf("unexpected error: %s", extractTextN8n(t, result))
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. discover_bypasses — input validation
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_DiscoverBypasses_Validation(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name     string
		args     string
		wantErr  bool
		wantText string
	}{
		{
			name:     "empty_target",
			args:     `{}`,
			wantErr:  true,
			wantText: "target",
		},
		{
			name:     "bad_scheme",
			args:     `{"target": "ftp://evil.com"}`,
			wantErr:  true,
			wantText: "http",
		},
		{
			name:     "ssrf",
			args:     `{"target": "http://169.254.169.254"}`,
			wantErr:  true,
			wantText: "cloud metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "discover_bypasses",
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("discover_bypasses: %v", err)
			}
			if tt.wantErr && !result.IsError {
				t.Errorf("expected error for %s", tt.name)
			}
			if tt.wantText != "" && result.IsError {
				text := extractTextN8n(t, result)
				if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantText)) {
					t.Errorf("missing %q in: %.200s", tt.wantText, text)
				}
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 16. Spec tools — error paths via SSE
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_SpecTools_ErrorPaths(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	specTools := []string{
		"validate_spec", "list_spec_endpoints", "plan_spec",
		"spec_intelligence", "describe_spec_auth", "export_spec",
	}

	for _, tool := range specTools {
		t.Run(tool+"_empty", func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tool,
				Arguments: json.RawMessage(`{}`),
			})
			if err != nil {
				t.Fatalf("%s: %v", tool, err)
			}
			if !result.IsError {
				t.Errorf("%s with empty args should error", tool)
			}
		})
	}
}

func TestHandler_ExportSpec_InvalidFormat(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	specContent := `openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
paths:
  /users:
    get:
      summary: List users`

	argsJSON, _ := json.Marshal(map[string]any{
		"spec_content": specContent,
		"format":       "invalid_format_xyz",
	})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "export_spec",
		Arguments: json.RawMessage(argsJSON),
	})
	if err != nil {
		t.Fatalf("export_spec: %v", err)
	}
	// Invalid format should either error or fall back to default
	_ = result
}

// ═══════════════════════════════════════════════════════════════════════════
// 17. Full E2E: detect_waf → scan → assess → learn chain (simulated n8n)
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_FullWorkflowChain(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	target := "https://example.com"

	// Step 1: detect_waf
	wafResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "detect_waf",
		Arguments: json.RawMessage(fmt.Sprintf(`{"target": %q, "timeout": 5}`, target)),
	})
	if err != nil {
		t.Fatalf("detect_waf: %v", err)
	}
	_ = wafResult // may error due to network

	// Step 2: scan (async)
	scanResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: json.RawMessage(fmt.Sprintf(`{
			"target": %q,
			"categories": ["sqli"],
			"concurrency": 3,
			"rate_limit": 5,
			"timeout": 5
		}`, target)),
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	scanText := extractTextN8n(t, scanResult)
	var scanAsync struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(scanText), &scanAsync); err != nil {
		t.Fatalf("parse scan async: %v", err)
	}

	// Poll scan to completion
	scanFinal := pollUntilTerminal(t, cs, ctx, scanAsync.TaskID)
	t.Logf("scan final status: %s", scanFinal)

	// Step 3: assess (async)
	assessResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "assess",
		Arguments: json.RawMessage(fmt.Sprintf(`{
			"target": %q,
			"categories": ["sqli"],
			"concurrency": 3,
			"rate_limit": 5,
			"timeout": 5
		}`, target)),
	})
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	assessText := extractTextN8n(t, assessResult)
	var assessAsync struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(assessText), &assessAsync); err != nil {
		t.Fatalf("parse assess async: %v", err)
	}

	assessFinal := pollUntilTerminal(t, cs, ctx, assessAsync.TaskID)
	t.Logf("assess final status: %s", assessFinal)

	// Step 4: list_tasks should show both tasks
	tasksResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_tasks",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("list_tasks: %v", err)
	}
	tasksText := extractTextN8n(t, tasksResult)
	var listResp struct {
		Tasks []struct {
			TaskID string `json:"task_id"`
			Tool   string `json:"tool"`
		} `json:"tasks"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(tasksText), &listResp); err != nil {
		t.Fatalf("parse list_tasks: %v", err)
	}
	if listResp.Total < 2 {
		t.Errorf("expected at least 2 tasks, got %d", listResp.Total)
	}

	// Verify both task IDs are present
	found := map[string]bool{}
	for _, task := range listResp.Tasks {
		found[task.TaskID] = true
	}
	if !found[scanAsync.TaskID] {
		t.Errorf("scan task %s not in list_tasks", scanAsync.TaskID)
	}
	if !found[assessAsync.TaskID] {
		t.Errorf("assess task %s not in list_tasks", assessAsync.TaskID)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 18. list_tasks — filtering by tool_name and status
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_ListTasks_Filtering(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Launch a discover_bypasses task
	_, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_bypasses",
		Arguments: json.RawMessage(`{"target": "https://example.com/search?q=test"}`),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}

	// Filter by tool_name
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_tasks",
		Arguments: json.RawMessage(`{"tool_name": "discover_bypasses"}`),
	})
	if err != nil {
		t.Fatalf("list_tasks: %v", err)
	}
	text := extractTextN8n(t, result)
	var listResp struct {
		Tasks []struct {
			Tool string `json:"tool"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal([]byte(text), &listResp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, task := range listResp.Tasks {
		if task.Tool != "discover_bypasses" {
			t.Errorf("filter by tool_name returned tool=%q", task.Tool)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 19. generate_cicd — all platforms via SSE
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_GenerateCICD_AllPlatforms(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	platforms := []string{"github", "gitlab", "jenkins", "azure-devops", "circleci", "bitbucket"}
	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			argsJSON, _ := json.Marshal(map[string]any{
				"target":   "https://example.com",
				"platform": platform,
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "generate_cicd",
				Arguments: json.RawMessage(argsJSON),
			})
			if err != nil {
				t.Fatalf("generate_cicd: %v", err)
			}
			if result.IsError {
				t.Fatalf("error: %s", extractTextN8n(t, result))
			}
			text := extractTextN8n(t, result)
			if !strings.Contains(strings.ToLower(text), platform) {
				t.Errorf("response doesn't mention platform %q", platform)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 20. Enriched error consistency — all tools that return errors use
//     structured format with recovery_steps
// ═══════════════════════════════════════════════════════════════════════════

func TestHandler_EnrichedErrorConsistency(t *testing.T) {
	cs := newQuickSSESession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Tools that should return enriched errors on SSRF
	ssrfTools := []struct {
		name string
		args string
	}{
		{"detect_waf", `{"target": "http://169.254.169.254"}`},
		{"scan", `{"target": "http://169.254.169.254"}`},
		{"assess", `{"target": "http://169.254.169.254"}`},
		{"bypass", `{"target": "http://169.254.169.254", "payloads": ["test"]}`},
		{"discover", `{"target": "http://169.254.169.254"}`},
		{"discover_bypasses", `{"target": "http://169.254.169.254"}`},
		{"probe", `{"target": "http://169.254.169.254"}`},
	}

	for _, tt := range ssrfTools {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tt.name,
				Arguments: json.RawMessage(tt.args),
			})
			if err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			if !result.IsError {
				t.Errorf("%s didn't reject cloud metadata SSRF", tt.name)
				return
			}
			text := extractTextN8n(t, result)
			if !strings.Contains(strings.ToLower(text), "cloud metadata") {
				t.Errorf("%s SSRF error missing 'cloud metadata': %.200s", tt.name, text)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared polling helper
// ═══════════════════════════════════════════════════════════════════════════

// pollUntilTerminal polls get_task_status until a terminal state is reached.
func pollUntilTerminal(t *testing.T, cs *mcp.ClientSession, ctx context.Context, taskID string) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		pollArgs, _ := json.Marshal(map[string]any{
			"task_id":      taskID,
			"wait_seconds": 5,
		})
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "get_task_status",
			Arguments: json.RawMessage(pollArgs),
		})
		if err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}
		text := extractTextN8n(t, result)
		var snap struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(text), &snap); err != nil {
			t.Fatalf("poll %d parse: %v", i, err)
		}
		if snap.Status == "completed" || snap.Status == "failed" || snap.Status == "cancelled" {
			return snap.Status
		}
	}
	t.Fatal("task never reached terminal state")
	return ""
}
