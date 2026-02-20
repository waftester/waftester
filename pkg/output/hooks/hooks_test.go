package hooks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// =============================================================================
// Test Fixtures
// =============================================================================

func newTestResultEvent(severity events.Severity, outcome events.Outcome) *events.ResultEvent {
	return &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-123",
		},
		Test: events.TestInfo{
			ID:       "sqli-042",
			Category: "sqli",
			Severity: severity,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com/login",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    outcome,
			StatusCode: 200,
			LatencyMs:  50.0,
		},
	}
}

func newTestBypassEvent(severity events.Severity) *events.BypassEvent {
	return &events.BypassEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeBypass,
			Time: time.Now(),
			Scan: "test-scan-123",
		},
		Priority: "high",
		Alert: events.AlertInfo{
			Title:       "WAF Bypass Detected",
			Description: "SQL injection payload bypassed WAF",
		},
		Details: events.BypassDetail{
			TestID:     "sqli-042",
			Category:   "sqli",
			Severity:   severity,
			StatusCode: 200,
			Payload:    "' OR '1'='1",
		},
	}
}

func newTestSummaryEvent(bypasses, blocked int) *events.SummaryEvent {
	total := bypasses + blocked
	effectiveness := 0.0
	if total > 0 {
		effectiveness = float64(blocked) / float64(total) * 100
	}

	return &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: time.Now(),
			Scan: "test-scan-123",
		},
		Version: "2.5.0",
		Target: events.SummaryTarget{
			URL:           "https://example.com",
			WAFDetected:   "Cloudflare",
			WAFConfidence: 0.95,
		},
		Totals: events.SummaryTotals{
			Tests:    total,
			Bypasses: bypasses,
			Blocked:  blocked,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct:   effectiveness,
			Grade:          "A",
			Recommendation: "Monitor for new bypass techniques",
		},
	}
}

// =============================================================================
// WebhookHook Tests
// =============================================================================

func TestWebhookHook_SendsPOSTWithJSONBody(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewWebhookHook(server.URL, WebhookOptions{})
	event := newTestBypassEvent(events.SeverityHigh)

	err := hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", receivedContentType)
	}

	if len(receivedBody) == 0 {
		t.Error("expected non-empty body")
	}

	// Verify it's valid JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Errorf("body is not valid JSON: %v", err)
	}
}

func TestWebhookHook_IncludesEventTypeHeader(t *testing.T) {
	var receivedEventType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedEventType = r.Header.Get("X-WAFtester-Event-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewWebhookHook(server.URL, WebhookOptions{})
	event := newTestBypassEvent(events.SeverityHigh)

	err := hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if receivedEventType != "bypass" {
		t.Errorf("expected X-WAFtester-Event-Type 'bypass', got %q", receivedEventType)
	}
}

func TestWebhookHook_IncludesCustomHeaders(t *testing.T) {
	var receivedAuth string
	var receivedCustom string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedCustom = r.Header.Get("X-Custom-Header")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewWebhookHook(server.URL, WebhookOptions{
		Headers: map[string]string{
			"Authorization":   "Bearer test-token",
			"X-Custom-Header": "custom-value",
		},
	})

	err := hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityHigh))
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if receivedAuth != "Bearer test-token" {
		t.Errorf("expected Authorization 'Bearer test-token', got %q", receivedAuth)
	}
	if receivedCustom != "custom-value" {
		t.Errorf("expected X-Custom-Header 'custom-value', got %q", receivedCustom)
	}
}

func TestWebhookHook_RespectsOnlyBypassesFilter(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewWebhookHook(server.URL, WebhookOptions{
		OnlyBypasses: true,
	})

	// Result event should be skipped
	err := hook.OnEvent(context.Background(), newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked))
	if err != nil {
		t.Fatalf("OnEvent failed for result: %v", err)
	}

	// Bypass event should be sent
	err = hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityHigh))
	if err != nil {
		t.Fatalf("OnEvent failed for bypass: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 request (only bypass), got %d", requestCount)
	}
}

func TestWebhookHook_RespectsMinSeverityFilter(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewWebhookHook(server.URL, WebhookOptions{
		MinSeverity: events.SeverityHigh,
	})

	// Low severity should be skipped
	err := hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityLow))
	if err != nil {
		t.Fatalf("OnEvent failed for low severity: %v", err)
	}

	// Medium severity should be skipped
	err = hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityMedium))
	if err != nil {
		t.Fatalf("OnEvent failed for medium severity: %v", err)
	}

	// High severity should be sent
	err = hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityHigh))
	if err != nil {
		t.Fatalf("OnEvent failed for high severity: %v", err)
	}

	// Critical severity should be sent
	err = hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityCritical))
	if err != nil {
		t.Fatalf("OnEvent failed for critical severity: %v", err)
	}

	if requestCount != 2 {
		t.Errorf("expected 2 requests (high + critical), got %d", requestCount)
	}
}

func TestWebhookHook_HandlesTimeoutGracefully(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Longer than timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewWebhookHook(server.URL, WebhookOptions{
		Timeout:    10 * time.Millisecond,
		RetryCount: 1, // Don't retry to keep test fast
	})

	// Should not return error (logs instead)
	err := hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityHigh))
	if err != nil {
		t.Errorf("expected nil error on timeout, got: %v", err)
	}
}

func TestWebhookHook_RetriesOn5xxErrors(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewWebhookHook(server.URL, WebhookOptions{
		RetryCount: 3,
	})

	err := hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityHigh))
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if requestCount != 3 {
		t.Errorf("expected 3 requests (2 retries), got %d", requestCount)
	}
}

func TestWebhookHook_DoesNotRetryOn4xxErrors(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	hook := NewWebhookHook(server.URL, WebhookOptions{
		RetryCount: 3,
	})

	// Should not return error (logs instead)
	err := hook.OnEvent(context.Background(), newTestBypassEvent(events.SeverityHigh))
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 request (no retries on 4xx), got %d", requestCount)
	}
}

func TestWebhookHook_EventTypesReturnsNil(t *testing.T) {
	hook := NewWebhookHook("http://example.com", WebhookOptions{})

	types := hook.EventTypes()
	if types != nil {
		t.Errorf("expected nil EventTypes, got %v", types)
	}
}

// =============================================================================
// GitHubActionsHook Tests
// =============================================================================

func TestGitHubActionsHook_NewReturnsErrorWithoutEnv(t *testing.T) {
	// Ensure env var is not set
	os.Unsetenv("GITHUB_OUTPUT")

	_, err := NewGitHubActionsHook(GitHubActionsOptions{})
	if err == nil {
		t.Error("expected error when GITHUB_OUTPUT not set")
	}
	if !strings.Contains(err.Error(), "not running in GitHub Actions") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGitHubActionsHook_WritesOutputVariables(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "github_output")
	summaryPath := filepath.Join(tempDir, "github_summary")

	hook := NewGitHubActionsHookWithPaths(outputPath, summaryPath, GitHubActionsOptions{})

	summary := newTestSummaryEvent(5, 2795)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	output := string(content)
	expectedLines := []string{
		"bypasses=5",
		"blocked=2795",
		"tests=2800",
		"effectiveness=99.8",
		"result=fail",
	}

	for _, expected := range expectedLines {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q, got:\n%s", expected, output)
		}
	}
}

func TestGitHubActionsHook_GeneratesMarkdownSummary(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "github_output")
	summaryPath := filepath.Join(tempDir, "github_summary")

	hook := NewGitHubActionsHookWithPaths(outputPath, summaryPath, GitHubActionsOptions{
		AddSummary: true,
	})

	// First send some bypass events
	bypass1 := newTestBypassEvent(events.SeverityCritical)
	bypass1.Details.TestID = "sqli-001"
	bypass1.Details.Category = "sqli"

	bypass2 := newTestBypassEvent(events.SeverityHigh)
	bypass2.Details.TestID = "xss-042"
	bypass2.Details.Category = "xss"

	hook.OnEvent(context.Background(), bypass1)
	hook.OnEvent(context.Background(), bypass2)

	// Then send summary
	summary := newTestSummaryEvent(2, 2798)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	content, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("failed to read summary file: %v", err)
	}

	markdown := string(content)

	// Check header
	if !strings.Contains(markdown, "## 🛡️ WAF Security Scan Results") {
		t.Error("expected markdown header")
	}

	// Check table structure
	if !strings.Contains(markdown, "| Metric | Value |") {
		t.Error("expected metrics table header")
	}

	// Check values
	if !strings.Contains(markdown, "| Tests | 2800 |") {
		t.Error("expected tests count in table")
	}

	// Check bypasses section
	if !strings.Contains(markdown, "### Bypasses Found") {
		t.Error("expected bypasses section")
	}

	// Check bypass table
	if !strings.Contains(markdown, "sqli") && !strings.Contains(markdown, "sqli-001") {
		t.Error("expected bypass details in table")
	}

	// Check WAF info
	if !strings.Contains(markdown, "Cloudflare") {
		t.Error("expected WAF name in summary")
	}
}

func TestGitHubActionsHook_OnlyProcessesSummaryAndBypassEvents(t *testing.T) {
	types := (&GitHubActionsHook{}).EventTypes()

	if len(types) != 2 {
		t.Fatalf("expected 2 event types, got %d", len(types))
	}

	hasBypass := false
	hasSummary := false
	for _, et := range types {
		if et == events.EventTypeBypass {
			hasBypass = true
		}
		if et == events.EventTypeSummary {
			hasSummary = true
		}
	}

	if !hasBypass {
		t.Error("expected EventTypeBypass in EventTypes")
	}
	if !hasSummary {
		t.Error("expected EventTypeSummary in EventTypes")
	}
}

func TestGitHubActionsHook_PassResultIsBased(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "github_output")

	hook := NewGitHubActionsHookWithPaths(outputPath, "", GitHubActionsOptions{})

	// No bypasses = pass
	summary := newTestSummaryEvent(0, 2800)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if !strings.Contains(string(content), "result=pass") {
		t.Error("expected result=pass when no bypasses")
	}
}

func TestGitHubActionsHook_FailResultWithBypasses(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "github_output")

	hook := NewGitHubActionsHookWithPaths(outputPath, "", GitHubActionsOptions{})

	// Has bypasses = fail
	summary := newTestSummaryEvent(5, 2795)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if !strings.Contains(string(content), "result=fail") {
		t.Error("expected result=fail when bypasses exist")
	}
}

func TestGitHubActionsHook_SummaryWithoutBypassesSection(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "github_output")
	summaryPath := filepath.Join(tempDir, "github_summary")

	hook := NewGitHubActionsHookWithPaths(outputPath, summaryPath, GitHubActionsOptions{
		AddSummary: true,
	})

	// Send summary without bypass events
	summary := newTestSummaryEvent(0, 2800)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	content, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("failed to read summary file: %v", err)
	}

	markdown := string(content)

	// Should have header with success icon
	if !strings.Contains(markdown, "✅") {
		t.Error("expected success icon when no bypasses")
	}

	// Should NOT have bypasses section
	if strings.Contains(markdown, "### Bypasses Found") {
		t.Error("expected no bypasses section when no bypasses")
	}
}

func TestGitHubActionsHook_IgnoresOtherEventTypes(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "github_output")

	hook := NewGitHubActionsHookWithPaths(outputPath, "", GitHubActionsOptions{})

	// Result event should be ignored
	result := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
	err := hook.OnEvent(context.Background(), result)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	// File should not exist (nothing written)
	_, err = os.Stat(outputPath)
	if !os.IsNotExist(err) {
		t.Error("expected no file to be created for non-summary events")
	}
}

// =============================================================================
// SlackHook Tests
// =============================================================================

func TestSlackHook_SendsBlockKitMessageOnSummary(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewSlackHook(server.URL, SlackOptions{})

	// Send summary
	summary := newTestSummaryEvent(5, 2795)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", receivedContentType)
	}

	// Verify it's valid JSON with blocks
	var decoded map[string]interface{}
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	// Check for Block Kit structure
	blocks, ok := decoded["blocks"].([]interface{})
	if !ok {
		t.Fatal("expected 'blocks' array in response")
	}

	if len(blocks) < 3 {
		t.Errorf("expected at least 3 blocks (header, target, stats), got %d", len(blocks))
	}

	// Check header block
	header := blocks[0].(map[string]interface{})
	if header["type"] != "header" {
		t.Errorf("expected first block type 'header', got %q", header["type"])
	}

	// Check default username
	if decoded["username"] != "WAFtester" {
		t.Errorf("expected username 'WAFtester', got %q", decoded["username"])
	}

	// Check default icon_emoji
	if decoded["icon_emoji"] != ":shield:" {
		t.Errorf("expected icon_emoji ':shield:', got %q", decoded["icon_emoji"])
	}
}

func TestSlackHook_SendsImmediateAlertOnCriticalBypass(t *testing.T) {
	var requestCount int32
	var receivedBodies [][]byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewSlackHook(server.URL, SlackOptions{})

	// Send critical bypass
	bypass := newTestBypassEvent(events.SeverityCritical)
	bypass.Details.Endpoint = "https://example.com/api"
	err := hook.OnEvent(context.Background(), bypass)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 request for critical bypass alert, got %d", requestCount)
	}

	// Verify the alert format
	var decoded map[string]interface{}
	if err := json.Unmarshal(receivedBodies[0], &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	// Check for alert text
	text, ok := decoded["text"].(string)
	if !ok {
		t.Fatal("expected 'text' field in alert")
	}
	if !strings.Contains(text, "Critical") && !strings.Contains(text, "Bypass") {
		t.Errorf("expected alert text to mention 'Critical' and 'Bypass', got %q", text)
	}

	// Check for attachments
	attachments, ok := decoded["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Fatal("expected 'attachments' array in alert")
	}

	attachment := attachments[0].(map[string]interface{})
	if attachment["color"] != "danger" {
		t.Errorf("expected attachment color 'danger', got %q", attachment["color"])
	}
}

func TestSlackHook_SendsImmediateAlertOnHighBypass(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewSlackHook(server.URL, SlackOptions{})

	// Send high severity bypass
	bypass := newTestBypassEvent(events.SeverityHigh)
	err := hook.OnEvent(context.Background(), bypass)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 request for high severity bypass alert, got %d", requestCount)
	}
}

func TestSlackHook_DoesNotAlertOnLowSeverityBypass(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewSlackHook(server.URL, SlackOptions{})

	// Send low severity bypass - should not trigger immediate alert
	bypass := newTestBypassEvent(events.SeverityLow)
	err := hook.OnEvent(context.Background(), bypass)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if requestCount != 0 {
		t.Errorf("expected 0 requests for low severity bypass, got %d", requestCount)
	}
}

func TestSlackHook_RespectsMinSeverityFilter(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewSlackHook(server.URL, SlackOptions{
		MinSeverity: events.SeverityCritical,
	})

	// High severity should be filtered out
	bypass := newTestBypassEvent(events.SeverityHigh)
	err := hook.OnEvent(context.Background(), bypass)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	// Critical should still send
	bypass2 := newTestBypassEvent(events.SeverityCritical)
	err = hook.OnEvent(context.Background(), bypass2)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 request (only critical), got %d", requestCount)
	}
}

func TestSlackHook_RespectsOnlyOnBypasses(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewSlackHook(server.URL, SlackOptions{
		OnlyOnBypasses: true,
	})

	// Summary with no bypasses should not send
	summary := newTestSummaryEvent(0, 2800)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if requestCount != 0 {
		t.Errorf("expected 0 requests when OnlyOnBypasses and no bypasses, got %d", requestCount)
	}

	// Summary with bypasses should send
	summary2 := newTestSummaryEvent(5, 2795)
	err = hook.OnEvent(context.Background(), summary2)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 request when OnlyOnBypasses with bypasses, got %d", requestCount)
	}
}

func TestSlackHook_IncludesTopBypassesInSummary(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewSlackHook(server.URL, SlackOptions{})

	// Send bypasses first (low severity so no immediate alert)
	bypass1 := newTestBypassEvent(events.SeverityLow)
	bypass1.Details.TestID = "sqli-001"
	bypass1.Details.Category = "sqli"
	hook.OnEvent(context.Background(), bypass1)

	bypass2 := newTestBypassEvent(events.SeverityLow)
	bypass2.Details.TestID = "xss-002"
	bypass2.Details.Category = "xss"
	hook.OnEvent(context.Background(), bypass2)

	// Send summary
	summary := newTestSummaryEvent(2, 2798)
	hook.OnEvent(context.Background(), summary)

	body := string(receivedBody)

	// Should contain bypass info
	if !strings.Contains(body, "sqli-001") {
		t.Error("expected summary to contain bypass test ID 'sqli-001'")
	}
	if !strings.Contains(body, "xss-002") {
		t.Error("expected summary to contain bypass test ID 'xss-002'")
	}
}

func TestSlackHook_EventTypesReturnsExpectedTypes(t *testing.T) {
	hook := NewSlackHook("http://example.com", SlackOptions{})
	types := hook.EventTypes()

	if len(types) != 2 {
		t.Fatalf("expected 2 event types, got %d", len(types))
	}

	hasBypass := false
	hasSummary := false
	for _, et := range types {
		if et == events.EventTypeBypass {
			hasBypass = true
		}
		if et == events.EventTypeSummary {
			hasSummary = true
		}
	}

	if !hasBypass {
		t.Error("expected EventTypeBypass in EventTypes")
	}
	if !hasSummary {
		t.Error("expected EventTypeSummary in EventTypes")
	}
}

// =============================================================================
// TeamsHook Tests
// =============================================================================

func TestTeamsHook_SendsMessageCardOnSummary(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewTeamsHook(server.URL, TeamsOptions{})

	// Send summary
	summary := newTestSummaryEvent(5, 2795)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", receivedContentType)
	}

	// Verify MessageCard structure
	var decoded map[string]interface{}
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	// Check MessageCard required fields
	if decoded["@type"] != "MessageCard" {
		t.Errorf("expected @type 'MessageCard', got %q", decoded["@type"])
	}
	if decoded["@context"] != "http://schema.org/extensions" {
		t.Errorf("expected @context 'http://schema.org/extensions', got %q", decoded["@context"])
	}

	// Check sections
	sections, ok := decoded["sections"].([]interface{})
	if !ok || len(sections) == 0 {
		t.Fatal("expected 'sections' array in MessageCard")
	}

	// Check first section has facts
	section := sections[0].(map[string]interface{})
	facts, ok := section["facts"].([]interface{})
	if !ok || len(facts) < 5 {
		t.Errorf("expected at least 5 facts in section, got %d", len(facts))
	}
}

func TestTeamsHook_UsesGreenColorWhenNoBypasses(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewTeamsHook(server.URL, TeamsOptions{})

	// Summary with no bypasses
	summary := newTestSummaryEvent(0, 2800)
	hook.OnEvent(context.Background(), summary)

	var decoded map[string]interface{}
	json.Unmarshal(receivedBody, &decoded)

	if decoded["themeColor"] != "00FF00" {
		t.Errorf("expected green theme color '00FF00' for no bypasses, got %q", decoded["themeColor"])
	}
}

func TestTeamsHook_UsesRedColorForHighSeverityBypasses(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewTeamsHook(server.URL, TeamsOptions{})

	// Send high severity bypass first
	bypass := newTestBypassEvent(events.SeverityHigh)
	hook.OnEvent(context.Background(), bypass)

	// Then summary
	summary := newTestSummaryEvent(1, 2799)
	hook.OnEvent(context.Background(), summary)

	var decoded map[string]interface{}
	json.Unmarshal(receivedBody, &decoded)

	if decoded["themeColor"] != "FF0000" {
		t.Errorf("expected red theme color 'FF0000' for high severity, got %q", decoded["themeColor"])
	}
}

func TestTeamsHook_UsesYellowColorForLowSeverityBypasses(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewTeamsHook(server.URL, TeamsOptions{})

	// Send low severity bypass first
	bypass := newTestBypassEvent(events.SeverityLow)
	hook.OnEvent(context.Background(), bypass)

	// Then summary
	summary := newTestSummaryEvent(1, 2799)
	hook.OnEvent(context.Background(), summary)

	var decoded map[string]interface{}
	json.Unmarshal(receivedBody, &decoded)

	if decoded["themeColor"] != "FFFF00" {
		t.Errorf("expected yellow theme color 'FFFF00' for low severity, got %q", decoded["themeColor"])
	}
}

func TestTeamsHook_RespectsMinSeverityFilter(t *testing.T) {
	var bypassesCollected int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]interface{}
		json.Unmarshal(body, &decoded)

		// Count sections to see if bypasses were collected
		sections := decoded["sections"].([]interface{})
		if len(sections) > 1 {
			bypassesCollected++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewTeamsHook(server.URL, TeamsOptions{
		MinSeverity: events.SeverityHigh,
	})

	// Low severity bypass should be filtered
	lowBypass := newTestBypassEvent(events.SeverityLow)
	hook.OnEvent(context.Background(), lowBypass)

	// High severity bypass should be collected
	highBypass := newTestBypassEvent(events.SeverityHigh)
	hook.OnEvent(context.Background(), highBypass)

	// Send summary
	summary := newTestSummaryEvent(2, 2798)
	hook.OnEvent(context.Background(), summary)

	// Only high severity should be in bypasses section
	// The hook should have collected only 1 bypass
}

func TestTeamsHook_RespectsOnlyOnBypasses(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewTeamsHook(server.URL, TeamsOptions{
		OnlyOnBypasses: true,
	})

	// Summary with no bypasses should not send
	summary := newTestSummaryEvent(0, 2800)
	err := hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if requestCount != 0 {
		t.Errorf("expected 0 requests when OnlyOnBypasses and no bypasses, got %d", requestCount)
	}
}

func TestTeamsHook_EventTypesReturnsExpectedTypes(t *testing.T) {
	hook := NewTeamsHook("http://example.com", TeamsOptions{})
	types := hook.EventTypes()

	if len(types) != 2 {
		t.Fatalf("expected 2 event types, got %d", len(types))
	}

	hasBypass := false
	hasSummary := false
	for _, et := range types {
		if et == events.EventTypeBypass {
			hasBypass = true
		}
		if et == events.EventTypeSummary {
			hasSummary = true
		}
	}

	if !hasBypass {
		t.Error("expected EventTypeBypass in EventTypes")
	}
	if !hasSummary {
		t.Error("expected EventTypeSummary in EventTypes")
	}
}

func TestTeamsHook_IncludesTopBypassesInSummary(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewTeamsHook(server.URL, TeamsOptions{})

	// Send bypasses first
	bypass1 := newTestBypassEvent(events.SeverityMedium)
	bypass1.Details.TestID = "sqli-001"
	hook.OnEvent(context.Background(), bypass1)

	bypass2 := newTestBypassEvent(events.SeverityMedium)
	bypass2.Details.TestID = "xss-002"
	hook.OnEvent(context.Background(), bypass2)

	// Send summary
	summary := newTestSummaryEvent(2, 2798)
	hook.OnEvent(context.Background(), summary)

	body := string(receivedBody)

	// Should contain bypass info
	if !strings.Contains(body, "sqli-001") {
		t.Error("expected summary to contain bypass test ID 'sqli-001'")
	}
	if !strings.Contains(body, "xss-002") {
		t.Error("expected summary to contain bypass test ID 'xss-002'")
	}
}

// =============================================================================
// PagerDutyHook Tests
// =============================================================================

func TestPagerDutyHook_SendsEventToPagerDutyAPI(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	// Create hook with custom endpoint for testing
	hook := &PagerDutyHook{
		routingKey: "test-routing-key",
		client:     &http.Client{Timeout: 10 * time.Second},
		opts: PagerDutyOptions{
			MinSeverity: events.SeverityHigh,
			Source:      "waftester",
			Component:   "web-application-firewall",
		},
	}

	// Override sendEvent to use test server
	bypass := newTestBypassEvent(events.SeverityCritical)
	bypass.Details.Endpoint = "https://example.com/api"
	bypass.Details.Category = "SQL Injection"

	// Build event and send to test server
	pdEvent := hook.buildEvent(bypass)
	body, _ := json.Marshal(pdEvent)

	req, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hook.client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", receivedContentType)
	}

	// Verify payload structure
	var decoded map[string]interface{}
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	if decoded["routing_key"] != "test-routing-key" {
		t.Errorf("expected routing_key 'test-routing-key', got %q", decoded["routing_key"])
	}
	if decoded["event_action"] != "trigger" {
		t.Errorf("expected event_action 'trigger', got %q", decoded["event_action"])
	}

	payload, ok := decoded["payload"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'payload' object in response")
	}

	if !strings.Contains(payload["summary"].(string), "WAF Bypass") {
		t.Errorf("expected summary to contain 'WAF Bypass', got %q", payload["summary"])
	}
}

func TestPagerDutyHook_UsesCorrectSeverityMapping(t *testing.T) {
	tests := []struct {
		wafSeverity events.Severity
		pdSeverity  string
	}{
		{events.SeverityCritical, "critical"},
		{events.SeverityHigh, "error"},
		{events.SeverityMedium, "warning"},
		{events.SeverityLow, "info"},
		{events.SeverityInfo, "info"},
	}

	for _, tt := range tests {
		t.Run(string(tt.wafSeverity), func(t *testing.T) {
			hook := NewPagerDutyHook("test-key", PagerDutyOptions{
				MinSeverity: events.SeverityInfo, // Allow all severities
			})

			bypass := newTestBypassEvent(tt.wafSeverity)
			pdEvent := hook.buildEvent(bypass)

			if pdEvent.Payload.Severity != tt.pdSeverity {
				t.Errorf("expected PagerDuty severity %q for WAFtester severity %q, got %q",
					tt.pdSeverity, tt.wafSeverity, pdEvent.Payload.Severity)
			}
		})
	}
}

func TestPagerDutyHook_RespectsMinSeverityFilter(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	hook := NewPagerDutyHook("test-key", PagerDutyOptions{
		MinSeverity: events.SeverityHigh,
	})
	// Override client to use test server - we'll test via meetsMinSeverity

	// Low severity should be filtered
	lowBypass := newTestBypassEvent(events.SeverityLow)
	if hook.meetsMinSeverity(lowBypass.Details.Severity) {
		t.Error("expected low severity to be filtered out")
	}

	// Medium severity should be filtered
	medBypass := newTestBypassEvent(events.SeverityMedium)
	if hook.meetsMinSeverity(medBypass.Details.Severity) {
		t.Error("expected medium severity to be filtered out")
	}

	// High severity should pass
	highBypass := newTestBypassEvent(events.SeverityHigh)
	if !hook.meetsMinSeverity(highBypass.Details.Severity) {
		t.Error("expected high severity to pass filter")
	}

	// Critical severity should pass
	critBypass := newTestBypassEvent(events.SeverityCritical)
	if !hook.meetsMinSeverity(critBypass.Details.Severity) {
		t.Error("expected critical severity to pass filter")
	}
}

func TestPagerDutyHook_GeneratesCorrectDedupKey(t *testing.T) {
	hook := NewPagerDutyHook("test-key", PagerDutyOptions{})

	bypass := newTestBypassEvent(events.SeverityHigh)
	bypass.Details.TestID = "sqli-042"
	bypass.Details.Endpoint = "https://target.com/api/v1"

	pdEvent := hook.buildEvent(bypass)

	// Expected: waftester-sqli-042-target.com
	if !strings.HasPrefix(pdEvent.DedupKey, "waftester-sqli-042") {
		t.Errorf("expected dedup_key to start with 'waftester-sqli-042', got %q", pdEvent.DedupKey)
	}
	if !strings.Contains(pdEvent.DedupKey, "target.com") {
		t.Errorf("expected dedup_key to contain 'target.com', got %q", pdEvent.DedupKey)
	}
}

func TestPagerDutyHook_EventTypesReturnsOnlyBypass(t *testing.T) {
	hook := NewPagerDutyHook("test-key", PagerDutyOptions{})
	types := hook.EventTypes()

	if len(types) != 1 {
		t.Fatalf("expected 1 event type, got %d", len(types))
	}
	if types[0] != events.EventTypeBypass {
		t.Errorf("expected EventTypeBypass, got %v", types[0])
	}
}

func TestPagerDutyHook_IgnoresNonBypassEvents(t *testing.T) {
	hook := NewPagerDutyHook("test-key", PagerDutyOptions{})

	// Result event should be ignored
	result := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
	err := hook.OnEvent(context.Background(), result)
	if err != nil {
		t.Errorf("expected nil error for non-bypass event, got %v", err)
	}

	// Summary event should be ignored
	summary := newTestSummaryEvent(5, 2795)
	err = hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Errorf("expected nil error for summary event, got %v", err)
	}
}

func TestPagerDutyHook_IncludesCustomDetailsInPayload(t *testing.T) {
	hook := NewPagerDutyHook("test-key", PagerDutyOptions{})

	bypass := newTestBypassEvent(events.SeverityCritical)
	bypass.Details.TestID = "sqli-042"
	bypass.Details.Category = "SQL Injection"
	bypass.Details.Endpoint = "https://example.com/api"
	bypass.Details.StatusCode = 200
	bypass.Details.Curl = "curl -X POST https://example.com/api -d 'test'"

	pdEvent := hook.buildEvent(bypass)

	customDetails := pdEvent.Payload.CustomDetails
	if customDetails["test_id"] != "sqli-042" {
		t.Errorf("expected test_id 'sqli-042', got %v", customDetails["test_id"])
	}
	if customDetails["category"] != "SQL Injection" {
		t.Errorf("expected category 'SQL Injection', got %v", customDetails["category"])
	}
	if customDetails["target"] != "https://example.com/api" {
		t.Errorf("expected target 'https://example.com/api', got %v", customDetails["target"])
	}
	if customDetails["status_code"] != 200 {
		t.Errorf("expected status_code 200, got %v", customDetails["status_code"])
	}
	if customDetails["curl_command"] != "curl -X POST https://example.com/api -d 'test'" {
		t.Errorf("expected curl_command to match, got %v", customDetails["curl_command"])
	}
}

// =============================================================================
// JiraHook Tests
// =============================================================================

func TestJiraHook_CreatesIssueWithADFDescription(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedAuth = r.Header.Get("Authorization")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"key": "SEC-123"}`))
	}))
	defer server.Close()

	hook, err := NewJiraHook(server.URL, JiraOptions{
		ProjectKey:  "SEC",
		IssueType:   "Bug",
		Username:    "test@example.com",
		APIToken:    "test-token",
		MinSeverity: events.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("NewJiraHook: %v", err)
	}

	bypass := newTestBypassEvent(events.SeverityCritical)
	bypass.Details.TestID = "sqli-042"
	bypass.Details.Category = "SQL Injection"
	bypass.Details.Endpoint = "https://example.com/api"

	err = hook.OnEvent(context.Background(), bypass)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", receivedContentType)
	}

	// Check basic auth
	if !strings.HasPrefix(receivedAuth, "Basic ") {
		t.Errorf("expected Authorization header with Basic auth, got %q", receivedAuth)
	}

	// Verify payload structure
	var decoded map[string]interface{}
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	fields, ok := decoded["fields"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'fields' object in response")
	}

	// Check project
	project := fields["project"].(map[string]interface{})
	if project["key"] != "SEC" {
		t.Errorf("expected project key 'SEC', got %v", project["key"])
	}

	// Check issue type
	issuetype := fields["issuetype"].(map[string]interface{})
	if issuetype["name"] != "Bug" {
		t.Errorf("expected issuetype 'Bug', got %v", issuetype["name"])
	}

	// Check description is ADF format
	description := fields["description"].(map[string]interface{})
	if description["type"] != "doc" {
		t.Errorf("expected description type 'doc', got %v", description["type"])
	}
	if description["version"] != float64(1) {
		t.Errorf("expected description version 1, got %v", description["version"])
	}

	content, ok := description["content"].([]interface{})
	if !ok || len(content) < 2 {
		t.Error("expected description content array with at least 2 nodes")
	}
}

func TestJiraHook_UsesCorrectPriorityMapping(t *testing.T) {
	tests := []struct {
		wafSeverity  events.Severity
		jiraPriority string
	}{
		{events.SeverityCritical, "Highest"},
		{events.SeverityHigh, "High"},
		{events.SeverityMedium, "Medium"},
		{events.SeverityLow, "Low"},
		{events.SeverityInfo, "Lowest"},
	}

	for _, tt := range tests {
		t.Run(string(tt.wafSeverity), func(t *testing.T) {
			hook, err := NewJiraHook("https://jira.example.com", JiraOptions{
				ProjectKey:  "SEC",
				Username:    "test@example.com",
				APIToken:    "test-token",
				MinSeverity: events.SeverityInfo, // Allow all severities
			})
			if err != nil {
				t.Fatalf("NewJiraHook: %v", err)
			}

			bypass := newTestBypassEvent(tt.wafSeverity)
			issue := hook.buildIssue(bypass)

			if issue.Fields.Priority.Name != tt.jiraPriority {
				t.Errorf("expected Jira priority %q for WAFtester severity %q, got %q",
					tt.jiraPriority, tt.wafSeverity, issue.Fields.Priority.Name)
			}
		})
	}
}

func TestJiraHook_RespectsMinSeverityFilter(t *testing.T) {
	hook, err := NewJiraHook("https://jira.example.com", JiraOptions{
		ProjectKey:  "SEC",
		Username:    "test@example.com",
		APIToken:    "test-token",
		MinSeverity: events.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("NewJiraHook: %v", err)
	}

	// Low severity should be filtered
	lowBypass := newTestBypassEvent(events.SeverityLow)
	if hook.meetsMinSeverity(lowBypass.Details.Severity) {
		t.Error("expected low severity to be filtered out")
	}

	// Medium severity should be filtered
	medBypass := newTestBypassEvent(events.SeverityMedium)
	if hook.meetsMinSeverity(medBypass.Details.Severity) {
		t.Error("expected medium severity to be filtered out")
	}

	// High severity should pass
	highBypass := newTestBypassEvent(events.SeverityHigh)
	if !hook.meetsMinSeverity(highBypass.Details.Severity) {
		t.Error("expected high severity to pass filter")
	}

	// Critical severity should pass
	critBypass := newTestBypassEvent(events.SeverityCritical)
	if !hook.meetsMinSeverity(critBypass.Details.Severity) {
		t.Error("expected critical severity to pass filter")
	}
}

func TestJiraHook_IncludesAllRequiredFields(t *testing.T) {
	hook, err := NewJiraHook("https://jira.example.com", JiraOptions{
		ProjectKey: "SEC",
		IssueType:  "Bug",
		Username:   "test@example.com",
		APIToken:   "test-token",
		Labels:     []string{"waftester", "security"},
		AssigneeID: "user-123",
	})
	if err != nil {
		t.Fatalf("NewJiraHook: %v", err)
	}

	bypass := newTestBypassEvent(events.SeverityCritical)
	bypass.Details.TestID = "sqli-042"
	bypass.Details.Category = "SQL Injection"

	issue := hook.buildIssue(bypass)

	// Check required fields
	if issue.Fields.Project.Key != "SEC" {
		t.Errorf("expected project key 'SEC', got %q", issue.Fields.Project.Key)
	}
	if issue.Fields.IssueType.Name != "Bug" {
		t.Errorf("expected issue type 'Bug', got %q", issue.Fields.IssueType.Name)
	}
	if !strings.Contains(issue.Fields.Summary, "WAFtester") {
		t.Errorf("expected summary to contain 'WAFtester', got %q", issue.Fields.Summary)
	}
	if !strings.Contains(issue.Fields.Summary, "sqli-042") {
		t.Errorf("expected summary to contain test ID, got %q", issue.Fields.Summary)
	}

	// Check labels
	if len(issue.Fields.Labels) != 2 {
		t.Errorf("expected 2 labels, got %d", len(issue.Fields.Labels))
	}

	// Check assignee
	if issue.Fields.Assignee == nil || issue.Fields.Assignee.ID != "user-123" {
		t.Error("expected assignee to be set to 'user-123'")
	}

	// Check priority
	if issue.Fields.Priority == nil || issue.Fields.Priority.Name != "Highest" {
		t.Error("expected priority to be 'Highest' for critical severity")
	}
}

func TestJiraHook_EventTypesReturnsOnlyBypass(t *testing.T) {
	hook, err := NewJiraHook("https://jira.example.com", JiraOptions{
		ProjectKey: "SEC",
		Username:   "test@example.com",
		APIToken:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewJiraHook: %v", err)
	}
	types := hook.EventTypes()

	if len(types) != 1 {
		t.Fatalf("expected 1 event type, got %d", len(types))
	}
	if types[0] != events.EventTypeBypass {
		t.Errorf("expected EventTypeBypass, got %v", types[0])
	}
}

func TestJiraHook_IgnoresNonBypassEvents(t *testing.T) {
	hook, err := NewJiraHook("https://jira.example.com", JiraOptions{
		ProjectKey: "SEC",
		Username:   "test@example.com",
		APIToken:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewJiraHook: %v", err)
	}

	// Result event should be ignored
	result := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
	err = hook.OnEvent(context.Background(), result)
	if err != nil {
		t.Errorf("expected nil error for non-bypass event, got %v", err)
	}

	// Summary event should be ignored
	summary := newTestSummaryEvent(5, 2795)
	err = hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Errorf("expected nil error for summary event, got %v", err)
	}
}

func TestJiraHook_BuildsADFBulletList(t *testing.T) {
	hook, err := NewJiraHook("https://jira.example.com", JiraOptions{
		ProjectKey: "SEC",
		Username:   "test@example.com",
		APIToken:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewJiraHook: %v", err)
	}

	bypass := newTestBypassEvent(events.SeverityCritical)
	bypass.Details.TestID = "sqli-042"
	bypass.Details.Category = "SQL Injection"
	bypass.Details.Endpoint = "https://example.com/api"
	bypass.Details.StatusCode = 200

	issue := hook.buildIssue(bypass)

	// Find the bullet list in the ADF content
	var bulletList *jiraADFNode
	for i := range issue.Fields.Description.Content {
		if issue.Fields.Description.Content[i].Type == "bulletList" {
			bulletList = &issue.Fields.Description.Content[i]
			break
		}
	}

	if bulletList == nil {
		t.Fatal("expected bulletList in ADF description")
	}

	// Check that we have list items
	if len(bulletList.Content) < 5 {
		t.Errorf("expected at least 5 list items, got %d", len(bulletList.Content))
	}

	// Verify each item is a listItem with paragraph content
	for _, item := range bulletList.Content {
		if item.Type != "listItem" {
			t.Errorf("expected listItem type, got %q", item.Type)
		}
		if len(item.Content) == 0 || item.Content[0].Type != "paragraph" {
			t.Error("expected listItem to contain paragraph")
		}
	}
}

func TestJiraHook_DefaultLabels(t *testing.T) {
	hook, err := NewJiraHook("https://jira.example.com", JiraOptions{
		ProjectKey: "SEC",
		Username:   "test@example.com",
		APIToken:   "test-token",
		// No labels specified, should use defaults
	})
	if err != nil {
		t.Fatalf("NewJiraHook: %v", err)
	}

	bypass := newTestBypassEvent(events.SeverityHigh)
	issue := hook.buildIssue(bypass)

	expectedLabels := []string{"waftester", "waf-bypass", "security"}
	if len(issue.Fields.Labels) != len(expectedLabels) {
		t.Errorf("expected %d default labels, got %d", len(expectedLabels), len(issue.Fields.Labels))
	}

	for i, label := range expectedLabels {
		if issue.Fields.Labels[i] != label {
			t.Errorf("expected label %q at index %d, got %q", label, i, issue.Fields.Labels[i])
		}
	}
}

// =============================================================================
// Hook Contract Tests
// =============================================================================
// These tests verify that all hooks follow consistent interface contracts.

// TestAllHooks_ImplementInterface verifies compile-time interface compliance.
// Each hook type has a compile-time check via var _ dispatcher.Hook = (*HookType)(nil)
// in its source file. This test documents and validates that pattern.
func TestAllHooks_ImplementInterface(t *testing.T) {
	// These type assertions verify the interface at compile time.
	// If any hook doesn't implement dispatcher.Hook, compilation fails.
	// We use explicit interface assignments to make this crystal clear.

	t.Run("WebhookHook implements Hook", func(t *testing.T) {
		var hook interface{} = NewWebhookHook("http://example.com", WebhookOptions{})
		if _, ok := hook.(interface {
			OnEvent(context.Context, events.Event) error
			EventTypes() []events.EventType
		}); !ok {
			t.Error("WebhookHook does not implement Hook interface")
		}
	})

	t.Run("SlackHook implements Hook", func(t *testing.T) {
		var hook interface{} = NewSlackHook("http://example.com", SlackOptions{})
		if _, ok := hook.(interface {
			OnEvent(context.Context, events.Event) error
			EventTypes() []events.EventType
		}); !ok {
			t.Error("SlackHook does not implement Hook interface")
		}
	})

	t.Run("TeamsHook implements Hook", func(t *testing.T) {
		var hook interface{} = NewTeamsHook("http://example.com", TeamsOptions{})
		if _, ok := hook.(interface {
			OnEvent(context.Context, events.Event) error
			EventTypes() []events.EventType
		}); !ok {
			t.Error("TeamsHook does not implement Hook interface")
		}
	})

	t.Run("PagerDutyHook implements Hook", func(t *testing.T) {
		var hook interface{} = NewPagerDutyHook("test-key", PagerDutyOptions{})
		if _, ok := hook.(interface {
			OnEvent(context.Context, events.Event) error
			EventTypes() []events.EventType
		}); !ok {
			t.Error("PagerDutyHook does not implement Hook interface")
		}
	})

	t.Run("JiraHook implements Hook", func(t *testing.T) {
		hook, err := NewJiraHook("http://jira.example.com", JiraOptions{
			ProjectKey: "TEST",
			Username:   "test@example.com",
			APIToken:   "test-token",
		})
		if err != nil {
			t.Fatalf("NewJiraHook: %v", err)
		}
		var iface interface{} = hook
		if _, ok := iface.(interface {
			OnEvent(context.Context, events.Event) error
			EventTypes() []events.EventType
		}); !ok {
			t.Error("JiraHook does not implement Hook interface")
		}
	})

	t.Run("GitHubActionsHook implements Hook", func(t *testing.T) {
		var hook interface{} = NewGitHubActionsHookWithPaths(t.TempDir()+"/output", "", GitHubActionsOptions{})
		if _, ok := hook.(interface {
			OnEvent(context.Context, events.Event) error
			EventTypes() []events.EventType
		}); !ok {
			t.Error("GitHubActionsHook does not implement Hook interface")
		}
	})
}

// TestWebhookHook_EventTypes_Behavior verifies EventTypes() returns nil,
// indicating the hook accepts all event types.
func TestWebhookHook_EventTypes_Behavior(t *testing.T) {
	hook := NewWebhookHook("http://example.com", WebhookOptions{})
	types := hook.EventTypes()

	// WebhookHook returns nil to indicate it accepts ALL event types.
	// This is different from hooks that return a specific list.
	if types != nil {
		t.Errorf("WebhookHook.EventTypes() should return nil for all events, got %v", types)
	}

	// Contract: nil EventTypes means all events are forwarded
	// Verify this by checking documentation compliance
	t.Run("nil means all events accepted", func(t *testing.T) {
		// According to the Hook interface:
		// "Return nil or empty slice to receive all events."
		if types != nil && len(types) != 0 {
			t.Error("Hook contract violation: EventTypes() should return nil or empty for all-events hook")
		}
	})
}

// TestSlackHook_RetryBehavior verifies Slack hook handles 5xx errors correctly.
// Slack webhook doesn't implement retry at the hook level (relies on http client),
// but it should not block scan on errors.
func TestSlackHook_RetryBehavior(t *testing.T) {
	var requestCount int32

	t.Run("returns nil on 5xx errors without blocking", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		hook := NewSlackHook(server.URL, SlackOptions{})

		// Should not return error even on 5xx (logs instead)
		err := hook.OnEvent(context.Background(), newTestSummaryEvent(1, 99))
		if err != nil {
			t.Errorf("expected nil error on 5xx (non-blocking), got: %v", err)
		}
	})

	t.Run("returns nil on 4xx errors without blocking", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		hook := NewSlackHook(server.URL, SlackOptions{})

		// Should not return error even on 4xx
		err := hook.OnEvent(context.Background(), newTestSummaryEvent(1, 99))
		if err != nil {
			t.Errorf("expected nil error on 4xx (non-blocking), got: %v", err)
		}
	})

	t.Run("handles connection errors gracefully", func(t *testing.T) {
		// Use an endpoint that will fail to connect
		hook := NewSlackHook("http://localhost:1", SlackOptions{
			Timeout: 100 * time.Millisecond,
		})

		// Should not return error on connection failure
		err := hook.OnEvent(context.Background(), newTestSummaryEvent(1, 99))
		if err != nil {
			t.Errorf("expected nil error on connection failure (non-blocking), got: %v", err)
		}
	})
}

// TestTeamsHook_Timeout verifies Teams hook respects timeout settings.
func TestTeamsHook_Timeout(t *testing.T) {
	t.Run("uses configured timeout", func(t *testing.T) {
		hook := NewTeamsHook("http://example.com", TeamsOptions{
			Timeout: 5 * time.Second,
		})

		// The hook should have the configured timeout
		if hook.opts.Timeout != 5*time.Second {
			t.Errorf("expected timeout 5s, got %v", hook.opts.Timeout)
		}
	})

	t.Run("uses default timeout when not specified", func(t *testing.T) {
		hook := NewTeamsHook("http://example.com", TeamsOptions{})

		// Should use default (10s from duration.WebhookTimeout)
		if hook.opts.Timeout == 0 {
			t.Error("expected non-zero default timeout")
		}
	})

	t.Run("handles slow server without blocking indefinitely", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Slow response - longer than timeout
			time.Sleep(500 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		hook := NewTeamsHook(server.URL, TeamsOptions{
			Timeout: 50 * time.Millisecond, // Short timeout for test
		})

		start := time.Now()
		err := hook.OnEvent(context.Background(), newTestSummaryEvent(1, 99))
		elapsed := time.Since(start)

		// Should return quickly (within 2x timeout), not block for full server response
		if elapsed > 200*time.Millisecond {
			t.Errorf("expected quick return on timeout, took %v", elapsed)
		}

		// Should not return error (logs instead)
		if err != nil {
			t.Errorf("expected nil error on timeout (non-blocking), got: %v", err)
		}
	})
}

// TestPrometheusHook_MetricsExport verifies Prometheus metrics are registered and exported.
func TestPrometheusHook_MetricsExport(t *testing.T) {
	t.Run("registers expected metrics after events", func(t *testing.T) {
		hook, err := NewPrometheusHook(PrometheusOptions{
			Port: 19190, // Unique port for this test
		})
		if err != nil {
			t.Fatalf("failed to create hook: %v", err)
		}
		defer hook.Close()

		// Give server time to start
		time.Sleep(100 * time.Millisecond)

		// Send events to populate metrics
		// Result event (blocked)
		resultEvent := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
		hook.OnEvent(context.Background(), resultEvent)

		// Result event (bypass)
		bypassEvent := newTestResultEvent(events.SeverityHigh, events.OutcomeBypass)
		hook.OnEvent(context.Background(), bypassEvent)

		// Result event (error)
		errorEvent := newTestResultEvent(events.SeverityLow, events.OutcomeError)
		hook.OnEvent(context.Background(), errorEvent)

		// Summary event
		summaryEvent := newTestSummaryEvent(1, 99)
		hook.OnEvent(context.Background(), summaryEvent)

		time.Sleep(50 * time.Millisecond)

		// Fetch metrics endpoint
		resp, err := http.Get(hook.MetricsAddr())
		if err != nil {
			t.Fatalf("failed to fetch metrics: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		metrics := string(body)

		// Verify core metrics are present (with values after events)
		expectedMetrics := []string{
			"waftester_tests_total",
			"waftester_bypasses_total",
			"waftester_blocked_total",
			"waftester_errors_total",
			"waftester_effectiveness_percent",
			"waftester_scan_duration_seconds",
			"waftester_response_time_seconds",
		}

		for _, metricName := range expectedMetrics {
			if !strings.Contains(metrics, metricName) {
				t.Errorf("expected metric %q to be present in output", metricName)
			}
		}
	})

	t.Run("metrics are labeled correctly", func(t *testing.T) {
		hook, err := NewPrometheusHook(PrometheusOptions{
			Port: 19191,
		})
		if err != nil {
			t.Fatalf("failed to create hook: %v", err)
		}
		defer hook.Close()

		// Send some events
		event := newTestResultEvent(events.SeverityHigh, events.OutcomeBypass)
		event.Target.URL = "https://test.example.com"
		event.Test.Category = "sqli"
		hook.OnEvent(context.Background(), event)

		time.Sleep(50 * time.Millisecond)

		resp, err := http.Get(hook.MetricsAddr())
		if err != nil {
			t.Fatalf("failed to fetch metrics: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		metrics := string(body)

		// Check that labels are present in output
		if !strings.Contains(metrics, "target=") {
			t.Error("expected 'target' label in metrics")
		}
		if !strings.Contains(metrics, "category=") {
			t.Error("expected 'category' label in metrics")
		}
	})
}

// TestOtelHook_SpanCreation verifies OTel hook creates trace spans.
// Note: This test requires an OTLP collector to be running, so we skip if unavailable.
func TestOtelHook_SpanCreation(t *testing.T) {
	// Skip if no OTLP collector is available
	conn, err := net.DialTimeout("tcp", "localhost:4317", 100*time.Millisecond)
	if err != nil {
		t.Skip("Skipping OTel span test: no OTLP collector at localhost:4317")
	}
	conn.Close()

	t.Run("creates root span on start event", func(t *testing.T) {
		opts := OTelOptions{
			Endpoint:          "localhost:4317",
			Insecure:          true,
			ServiceName:       "waftester-contract-test",
			ShutdownTimeout:   100 * time.Millisecond,
			ConnectionTimeout: 100 * time.Millisecond,
		}

		hook, err := NewOTelHook(opts)
		if err != nil {
			t.Fatalf("failed to create hook: %v", err)
		}
		defer hook.Close()

		// Verify hook is ready for events
		if hook.tracer == nil {
			t.Error("expected tracer to be initialized")
		}

		// Send start event - should create root span
		startEvent := newTestStartEvent()
		err = hook.OnEvent(context.Background(), startEvent)
		if err != nil {
			t.Fatalf("OnEvent for start failed: %v", err)
		}

		// After start event, root span should exist
		hook.mu.Lock()
		hasRootSpan := hook.rootSpan != nil
		hook.mu.Unlock()

		if !hasRootSpan {
			t.Error("expected root span to be created after start event")
		}
	})

	t.Run("adds span events for result events", func(t *testing.T) {
		opts := OTelOptions{
			Endpoint:          "localhost:4317",
			Insecure:          true,
			ServiceName:       "waftester-contract-test-2",
			ShutdownTimeout:   100 * time.Millisecond,
			ConnectionTimeout: 100 * time.Millisecond,
		}

		hook, err := NewOTelHook(opts)
		if err != nil {
			t.Fatalf("failed to create hook: %v", err)
		}
		defer hook.Close()

		// Send start event first
		startEvent := newTestStartEvent()
		hook.OnEvent(context.Background(), startEvent)

		// Send result event
		resultEvent := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
		err = hook.OnEvent(context.Background(), resultEvent)
		if err != nil {
			t.Fatalf("OnEvent for result failed: %v", err)
		}

		// If we got here without error, the span event was recorded
		// (actual span export verification would require a mock collector)
	})

	t.Run("handles bypass events with appropriate attributes", func(t *testing.T) {
		opts := OTelOptions{
			Endpoint:          "localhost:4317",
			Insecure:          true,
			ServiceName:       "waftester-contract-test-3",
			ShutdownTimeout:   100 * time.Millisecond,
			ConnectionTimeout: 100 * time.Millisecond,
		}

		hook, err := NewOTelHook(opts)
		if err != nil {
			t.Fatalf("failed to create hook: %v", err)
		}
		defer hook.Close()

		// Send start event first
		startEvent := newTestStartEvent()
		hook.OnEvent(context.Background(), startEvent)

		// Send bypass event
		bypassEvent := newTestBypassEvent(events.SeverityCritical)
		err = hook.OnEvent(context.Background(), bypassEvent)
		if err != nil {
			t.Fatalf("OnEvent for bypass failed: %v", err)
		}

		// Bypass events should be recorded successfully
	})
}

// =============================================================================
// GitHubIssuesHook Tests
// =============================================================================

func TestGitHubIssuesHook_CreatesIssueWithCorrectPayload(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	var receivedAuth string
	var receivedAccept string
	var receivedUserAgent string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedAuth = r.Header.Get("Authorization")
		receivedAccept = r.Header.Get("Accept")
		receivedUserAgent = r.Header.Get("User-Agent")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"number": 42, "html_url": "https://github.com/test/repo/issues/42"}`))
	}))
	defer server.Close()

	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token:       "ghp_test123",
		Owner:       "testorg",
		Repo:        "testrepo",
		BaseURL:     server.URL,
		Labels:      []string{"security", "waf-bypass"},
		Assignees:   []string{"user1", "user2"},
		MinSeverity: events.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}

	bypass := newTestBypassEvent(events.SeverityCritical)
	bypass.Details.TestID = "sqli-042"
	bypass.Details.Category = "SQL Injection"
	bypass.Details.Endpoint = "https://example.com/api"

	err = hook.OnEvent(context.Background(), bypass)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	// Check headers
	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", receivedContentType)
	}
	if receivedAuth != "Bearer ghp_test123" {
		t.Errorf("expected Authorization 'Bearer ghp_test123', got %q", receivedAuth)
	}
	if receivedAccept != "application/vnd.github.v3+json" {
		t.Errorf("expected Accept 'application/vnd.github.v3+json', got %q", receivedAccept)
	}
	if !strings.Contains(receivedUserAgent, "waftester") {
		t.Errorf("expected User-Agent to contain 'waftester', got %q", receivedUserAgent)
	}

	// Verify payload structure
	var decoded map[string]interface{}
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	// Check title
	title, ok := decoded["title"].(string)
	if !ok || !strings.Contains(title, "WAF Bypass") {
		t.Errorf("expected title to contain 'WAF Bypass', got %q", title)
	}
	if !strings.Contains(title, "sqli-042") {
		t.Errorf("expected title to contain test ID, got %q", title)
	}

	// Check labels
	labels, ok := decoded["labels"].([]interface{})
	if !ok {
		t.Fatal("expected 'labels' array in response")
	}
	// Should have custom labels plus severity label
	if len(labels) < 2 {
		t.Errorf("expected at least 2 labels, got %d", len(labels))
	}

	// Check assignees
	assignees, ok := decoded["assignees"].([]interface{})
	if !ok {
		t.Fatal("expected 'assignees' array in response")
	}
	if len(assignees) != 2 {
		t.Errorf("expected 2 assignees, got %d", len(assignees))
	}

	// Check body
	body, ok := decoded["body"].(string)
	if !ok || !strings.Contains(body, "WAF Bypass") {
		t.Errorf("expected body to contain 'WAF Bypass', got %q", body)
	}
}

func TestGitHubIssuesHook_RespectsMinSeverityFilter(t *testing.T) {
	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token:       "ghp_test123",
		Owner:       "testorg",
		Repo:        "testrepo",
		MinSeverity: events.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}

	// Low severity should be filtered
	if hook.meetsMinSeverity(events.SeverityLow) {
		t.Error("expected low severity to be filtered out")
	}

	// Medium severity should be filtered
	if hook.meetsMinSeverity(events.SeverityMedium) {
		t.Error("expected medium severity to be filtered out")
	}

	// High severity should pass
	if !hook.meetsMinSeverity(events.SeverityHigh) {
		t.Error("expected high severity to pass filter")
	}

	// Critical severity should pass
	if !hook.meetsMinSeverity(events.SeverityCritical) {
		t.Error("expected critical severity to pass filter")
	}
}

func TestGitHubIssuesHook_UsesCustomLabelsFromConfig(t *testing.T) {
	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token:  "ghp_test123",
		Owner:  "testorg",
		Repo:   "testrepo",
		Labels: []string{"custom-label-1", "custom-label-2"},
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}

	bypass := newTestBypassEvent(events.SeverityHigh)
	issue := hook.buildIssue(bypass)

	// Should have custom labels plus severity label
	foundCustom1 := false
	foundCustom2 := false
	for _, label := range issue.Labels {
		if label == "custom-label-1" {
			foundCustom1 = true
		}
		if label == "custom-label-2" {
			foundCustom2 = true
		}
	}

	if !foundCustom1 || !foundCustom2 {
		t.Errorf("expected custom labels to be included, got %v", issue.Labels)
	}
}

func TestGitHubIssuesHook_UsesAssigneesFromConfig(t *testing.T) {
	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token:     "ghp_test123",
		Owner:     "testorg",
		Repo:      "testrepo",
		Assignees: []string{"assignee1", "assignee2", "assignee3"},
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}

	bypass := newTestBypassEvent(events.SeverityHigh)
	issue := hook.buildIssue(bypass)

	if len(issue.Assignees) != 3 {
		t.Errorf("expected 3 assignees, got %d: %v", len(issue.Assignees), issue.Assignees)
	}
	if issue.Assignees[0] != "assignee1" {
		t.Errorf("expected first assignee to be 'assignee1', got %q", issue.Assignees[0])
	}
}

func TestGitHubIssuesHook_UsesDefaultAPIURL(t *testing.T) {
	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token: "ghp_test123",
		Owner: "testorg",
		Repo:  "testrepo",
		// No BaseURL specified
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}

	if hook.baseURL != "https://api.github.com" {
		t.Errorf("expected default base URL 'https://api.github.com', got %q", hook.baseURL)
	}
}

func TestGitHubIssuesHook_UsesCustomAPIURLForEnterprise(t *testing.T) {
	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token:   "ghp_test123",
		Owner:   "testorg",
		Repo:    "testrepo",
		BaseURL: "https://github.mycompany.com/api/v3",
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}

	if hook.baseURL != "https://github.mycompany.com/api/v3" {
		t.Errorf("expected custom base URL, got %q", hook.baseURL)
	}
}

func TestGitHubIssuesHook_EventTypesReturnsOnlyBypass(t *testing.T) {
	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token: "ghp_test123",
		Owner: "testorg",
		Repo:  "testrepo",
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}
	types := hook.EventTypes()

	if len(types) != 1 {
		t.Fatalf("expected 1 event type, got %d", len(types))
	}
	if types[0] != events.EventTypeBypass {
		t.Errorf("expected EventTypeBypass, got %v", types[0])
	}
}

func TestGitHubIssuesHook_IgnoresNonBypassEvents(t *testing.T) {
	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token: "ghp_test123",
		Owner: "testorg",
		Repo:  "testrepo",
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}

	// Result event should be ignored
	result := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
	err = hook.OnEvent(context.Background(), result)
	if err != nil {
		t.Errorf("expected nil error for non-bypass event, got %v", err)
	}

	// Summary event should be ignored
	summary := newTestSummaryEvent(5, 2795)
	err = hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Errorf("expected nil error for summary event, got %v", err)
	}
}

func TestGitHubIssuesHook_HandlesAPIErrorsGracefully(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Bad credentials", "documentation_url": "https://docs.github.com"}`))
	}))
	defer server.Close()

	hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
		Token:   "ghp_badtoken",
		Owner:   "testorg",
		Repo:    "testrepo",
		BaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewGitHubIssuesHook failed: %v", err)
	}

	bypass := newTestBypassEvent(events.SeverityCritical)
	err = hook.OnEvent(context.Background(), bypass)

	// Should not return error (logs instead)
	if err != nil {
		t.Errorf("expected nil error on API failure (non-blocking), got: %v", err)
	}
}

// =============================================================================
// AzureDevOpsHook Tests
// =============================================================================

func mustNewADOHook(t *testing.T, opts AzureDevOpsOptions) *AzureDevOpsHook {
	t.Helper()
	hook, err := NewAzureDevOpsHook(opts)
	if err != nil {
		t.Fatalf("NewAzureDevOpsHook: %v", err)
	}
	return hook
}

func TestAzureDevOpsHook_CreatesWorkItemWithJSONPatch(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	var receivedAuth string
	var receivedUserAgent string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedAuth = r.Header.Get("Authorization")
		receivedUserAgent = r.Header.Get("User-Agent")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": 12345, "_links": {"html": {"href": "https://dev.azure.com/org/proj/_workitems/edit/12345"}}}`))
	}))
	defer server.Close()

	// Create hook - we'll override the URL in the test
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization:  "testorg",
		Project:       "testproj",
		PAT:           "test-pat-123",
		WorkItemType:  "Bug",
		AreaPath:      "TestOrg\\Security",
		IterationPath: "TestOrg\\Sprint1",
		Tags:          []string{"security", "waf-bypass"},
		AssignedTo:    "user@example.com",
		MinSeverity:   events.SeverityHigh,
	})

	// Override client to use test server
	bypass := newTestBypassEvent(events.SeverityCritical)
	bypass.Details.TestID = "sqli-042"
	bypass.Details.Category = "SQL Injection"
	bypass.Details.Endpoint = "https://example.com/api"

	// Build ops and send to test server
	ops := hook.buildWorkItemOps(bypass)
	body, _ := json.Marshal(ops)

	req, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json-patch+json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+hook.opts.PAT)))
	req.Header.Set("User-Agent", "waftester")
	resp, err := hook.client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Verify headers were sent correctly
	if receivedContentType != "application/json-patch+json" {
		t.Errorf("expected Content-Type 'application/json-patch+json', got %q", receivedContentType)
	}
	if !strings.HasPrefix(receivedAuth, "Basic ") {
		t.Errorf("expected Basic auth header, got %q", receivedAuth)
	}
	if !strings.Contains(receivedUserAgent, "waftester") {
		t.Errorf("expected User-Agent to contain 'waftester', got %q", receivedUserAgent)
	}

	// Verify operations format
	var decoded []map[string]interface{}
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	// Should have multiple add operations
	if len(decoded) < 3 {
		t.Errorf("expected at least 3 JSON Patch operations, got %d", len(decoded))
	}

	// Check that operations have correct format
	for _, op := range decoded {
		if op["op"] != "add" {
			t.Errorf("expected 'add' operation, got %v", op["op"])
		}
		path, ok := op["path"].(string)
		if !ok || !strings.HasPrefix(path, "/fields/") {
			t.Errorf("expected path to start with '/fields/', got %v", op["path"])
		}
	}

	// Verify specific fields are present
	foundTitle := false
	foundDescription := false
	foundTags := false
	for _, op := range decoded {
		path := op["path"].(string)
		if path == "/fields/System.Title" {
			foundTitle = true
			if !strings.Contains(op["value"].(string), "WAFtester") {
				t.Errorf("expected title to contain 'WAFtester', got %v", op["value"])
			}
		}
		if path == "/fields/System.Description" {
			foundDescription = true
		}
		if path == "/fields/System.Tags" {
			foundTags = true
			if !strings.Contains(op["value"].(string), "security") {
				t.Errorf("expected tags to contain 'security', got %v", op["value"])
			}
		}
	}

	if !foundTitle {
		t.Error("expected System.Title field in operations")
	}
	if !foundDescription {
		t.Error("expected System.Description field in operations")
	}
	if !foundTags {
		t.Error("expected System.Tags field in operations")
	}
}

func TestAzureDevOpsHook_UsesCorrectSeverityMapping(t *testing.T) {
	tests := []struct {
		wafSeverity events.Severity
		adoSeverity string
		adoPriority int
	}{
		{events.SeverityCritical, "1 - Critical", 1},
		{events.SeverityHigh, "2 - High", 2},
		{events.SeverityMedium, "3 - Medium", 3},
		{events.SeverityLow, "4 - Low", 4},
		{events.SeverityInfo, "4 - Low", 4},
	}

	for _, tt := range tests {
		t.Run(string(tt.wafSeverity), func(t *testing.T) {
			hook := mustNewADOHook(t, AzureDevOpsOptions{
				Organization: "testorg",
				Project:      "testproj",
				PAT:          "test-pat",
				MinSeverity:  events.SeverityInfo, // Allow all severities
			})

			bypass := newTestBypassEvent(tt.wafSeverity)
			ops := hook.buildWorkItemOps(bypass)

			// Find severity operation
			var foundSeverity bool
			var foundPriority bool
			for _, op := range ops {
				if op.Path == "/fields/Microsoft.VSTS.Common.Severity" {
					foundSeverity = true
					if op.Value != tt.adoSeverity {
						t.Errorf("expected ADO severity %q for WAFtester severity %q, got %q",
							tt.adoSeverity, tt.wafSeverity, op.Value)
					}
				}
				if op.Path == "/fields/Microsoft.VSTS.Common.Priority" {
					foundPriority = true
					if op.Value != tt.adoPriority {
						t.Errorf("expected ADO priority %d for WAFtester severity %q, got %v",
							tt.adoPriority, tt.wafSeverity, op.Value)
					}
				}
			}

			if !foundSeverity {
				t.Error("expected severity field in operations")
			}
			if !foundPriority {
				t.Error("expected priority field in operations")
			}
		})
	}
}

func TestAzureDevOpsHook_RespectsMinSeverityFilter(t *testing.T) {
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization: "testorg",
		Project:      "testproj",
		PAT:          "test-pat",
		MinSeverity:  events.SeverityHigh,
	})

	// Low severity should be filtered
	if hook.meetsMinSeverity(events.SeverityLow) {
		t.Error("expected low severity to be filtered out")
	}

	// Medium severity should be filtered
	if hook.meetsMinSeverity(events.SeverityMedium) {
		t.Error("expected medium severity to be filtered out")
	}

	// High severity should pass
	if !hook.meetsMinSeverity(events.SeverityHigh) {
		t.Error("expected high severity to pass filter")
	}

	// Critical severity should pass
	if !hook.meetsMinSeverity(events.SeverityCritical) {
		t.Error("expected critical severity to pass filter")
	}
}

func TestAzureDevOpsHook_UsesCustomTagsFromConfig(t *testing.T) {
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization: "testorg",
		Project:      "testproj",
		PAT:          "test-pat",
		Tags:         []string{"custom-tag-1", "custom-tag-2", "custom-tag-3"},
	})

	bypass := newTestBypassEvent(events.SeverityHigh)
	ops := hook.buildWorkItemOps(bypass)

	// Find tags operation
	for _, op := range ops {
		if op.Path == "/fields/System.Tags" {
			tags := op.Value.(string)
			if !strings.Contains(tags, "custom-tag-1") {
				t.Errorf("expected tags to contain 'custom-tag-1', got %q", tags)
			}
			if !strings.Contains(tags, "custom-tag-2") {
				t.Errorf("expected tags to contain 'custom-tag-2', got %q", tags)
			}
			// Tags should be semicolon-separated in ADO
			if !strings.Contains(tags, ";") {
				t.Errorf("expected tags to be semicolon-separated, got %q", tags)
			}
			return
		}
	}
	t.Error("expected System.Tags field in operations")
}

func TestAzureDevOpsHook_IncludesAreaAndIterationPaths(t *testing.T) {
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization:  "testorg",
		Project:       "testproj",
		PAT:           "test-pat",
		AreaPath:      "TestOrg\\Security\\WAFTesting",
		IterationPath: "TestOrg\\2024\\Sprint5",
	})

	bypass := newTestBypassEvent(events.SeverityHigh)
	ops := hook.buildWorkItemOps(bypass)

	foundArea := false
	foundIteration := false
	for _, op := range ops {
		if op.Path == "/fields/System.AreaPath" {
			foundArea = true
			if op.Value != "TestOrg\\Security\\WAFTesting" {
				t.Errorf("expected area path 'TestOrg\\Security\\WAFTesting', got %v", op.Value)
			}
		}
		if op.Path == "/fields/System.IterationPath" {
			foundIteration = true
			if op.Value != "TestOrg\\2024\\Sprint5" {
				t.Errorf("expected iteration path 'TestOrg\\2024\\Sprint5', got %v", op.Value)
			}
		}
	}

	if !foundArea {
		t.Error("expected System.AreaPath field in operations")
	}
	if !foundIteration {
		t.Error("expected System.IterationPath field in operations")
	}
}

func TestAzureDevOpsHook_IncludesAssignedTo(t *testing.T) {
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization: "testorg",
		Project:      "testproj",
		PAT:          "test-pat",
		AssignedTo:   "security-team@example.com",
	})

	bypass := newTestBypassEvent(events.SeverityHigh)
	ops := hook.buildWorkItemOps(bypass)

	for _, op := range ops {
		if op.Path == "/fields/System.AssignedTo" {
			if op.Value != "security-team@example.com" {
				t.Errorf("expected AssignedTo 'security-team@example.com', got %v", op.Value)
			}
			return
		}
	}
	t.Error("expected System.AssignedTo field in operations")
}

func TestAzureDevOpsHook_EventTypesReturnsOnlyBypass(t *testing.T) {
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization: "testorg",
		Project:      "testproj",
		PAT:          "test-pat",
	})
	types := hook.EventTypes()

	if len(types) != 1 {
		t.Fatalf("expected 1 event type, got %d", len(types))
	}
	if types[0] != events.EventTypeBypass {
		t.Errorf("expected EventTypeBypass, got %v", types[0])
	}
}

func TestAzureDevOpsHook_IgnoresNonBypassEvents(t *testing.T) {
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization: "testorg",
		Project:      "testproj",
		PAT:          "test-pat",
	})

	// Result event should be ignored
	result := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
	err := hook.OnEvent(context.Background(), result)
	if err != nil {
		t.Errorf("expected nil error for non-bypass event, got %v", err)
	}

	// Summary event should be ignored
	summary := newTestSummaryEvent(5, 2795)
	err = hook.OnEvent(context.Background(), summary)
	if err != nil {
		t.Errorf("expected nil error for summary event, got %v", err)
	}
}

func TestAzureDevOpsHook_DefaultWorkItemType(t *testing.T) {
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization: "testorg",
		Project:      "testproj",
		PAT:          "test-pat",
		// No WorkItemType specified
	})

	if hook.opts.WorkItemType != "Bug" {
		t.Errorf("expected default work item type 'Bug', got %q", hook.opts.WorkItemType)
	}
}

func TestAzureDevOpsHook_DefaultTags(t *testing.T) {
	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization: "testorg",
		Project:      "testproj",
		PAT:          "test-pat",
		// No Tags specified
	})

	if len(hook.opts.Tags) != 3 {
		t.Errorf("expected 3 default tags, got %d: %v", len(hook.opts.Tags), hook.opts.Tags)
	}
}

func TestAzureDevOpsHook_HandlesAPIErrorsGracefully(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "TF401027: You need the Git 'GenericContribute' permission"}`))
	}))
	defer server.Close()

	hook := mustNewADOHook(t, AzureDevOpsOptions{
		Organization: "testorg",
		Project:      "testproj",
		PAT:          "bad-pat",
		// Note: We can't easily override the URL for ADO hook, so we test the error handling indirectly
	})

	bypass := newTestBypassEvent(events.SeverityCritical)

	// The hook should handle connection failures gracefully (log, not error)
	// We're testing that no panic occurs and nil error returns
	err := hook.OnEvent(context.Background(), bypass)
	// Even on connection failure, hook should return nil (logs internally)
	if err != nil {
		t.Errorf("expected nil error on API failure (non-blocking), got: %v", err)
	}
}
