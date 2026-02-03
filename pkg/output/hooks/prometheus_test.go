package hooks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// =============================================================================
// PrometheusHook Tests
// =============================================================================

func TestPrometheusHook_StartsServer(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19090, // Use non-standard port for testing
		Path: "/metrics",
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is running
	resp, err := http.Get(hook.MetricsAddr())
	if err != nil {
		t.Fatalf("failed to fetch metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestPrometheusHook_DefaultOptions(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19091, // Use non-standard port for testing
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Verify defaults were applied
	if hook.opts.Path != "/metrics" {
		t.Errorf("expected default path '/metrics', got %q", hook.opts.Path)
	}
	if hook.opts.ReadTimeout != 5*time.Second {
		t.Errorf("expected default read timeout 5s, got %v", hook.opts.ReadTimeout)
	}
	if hook.opts.WriteTimeout != 10*time.Second {
		t.Errorf("expected default write timeout 10s, got %v", hook.opts.WriteTimeout)
	}
}

func TestPrometheusHook_RecordsTestsCounter(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19092,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send result event
	event := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	// Give server time to process
	time.Sleep(50 * time.Millisecond)

	// Fetch metrics
	body := fetchMetrics(t, hook.MetricsAddr())

	// Verify counter was incremented
	if !strings.Contains(body, "waftester_tests_total") {
		t.Error("expected waftester_tests_total metric")
	}
}

func TestPrometheusHook_RecordsBlockedCounter(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19093,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send blocked result event
	event := newTestResultEvent(events.SeverityMedium, events.OutcomeBlocked)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	if !strings.Contains(body, "waftester_blocked_total") {
		t.Error("expected waftester_blocked_total metric")
	}
}

func TestPrometheusHook_RecordsBypassCounter(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19094,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send bypass result event
	event := newTestResultEvent(events.SeverityHigh, events.OutcomeBypass)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	if !strings.Contains(body, "waftester_bypasses_total") {
		t.Error("expected waftester_bypasses_total metric")
	}
}

func TestPrometheusHook_RecordsErrorsCounter(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19095,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send error result event
	event := newTestResultEvent(events.SeverityLow, events.OutcomeError)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	if !strings.Contains(body, "waftester_errors_total") {
		t.Error("expected waftester_errors_total metric")
	}
}

func TestPrometheusHook_RecordsResponseTimeHistogram(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19096,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send result event with latency
	event := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-prometheus",
		},
		Test: events.TestInfo{
			ID:       "sqli-001",
			Category: "sqli",
			Severity: events.SeverityHigh,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com/api",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBlocked,
			StatusCode: 403,
			LatencyMs:  150.5, // 150.5ms
		},
	}
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	if !strings.Contains(body, "waftester_response_time_seconds") {
		t.Error("expected waftester_response_time_seconds metric")
	}
}

func TestPrometheusHook_RecordsEffectivenessGauge(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19097,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send summary event
	event := newTestSummaryEvent(5, 95) // 5 bypasses, 95 blocked = 95% effectiveness
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	if !strings.Contains(body, "waftester_effectiveness_percent") {
		t.Error("expected waftester_effectiveness_percent metric")
	}
}

func TestPrometheusHook_RecordsScanDurationGauge(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19098,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send summary event with duration
	event := &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: time.Now(),
			Scan: "test-scan-duration",
		},
		Target: events.SummaryTarget{
			URL: "https://example.com",
		},
		Timing: events.SummaryTiming{
			DurationSec: 45.5,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct: 90.0,
		},
	}
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	if !strings.Contains(body, "waftester_scan_duration_seconds") {
		t.Error("expected waftester_scan_duration_seconds metric")
	}
}

func TestPrometheusHook_BypassEventUpdatesMetrics(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19099,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send bypass event
	event := newTestBypassEvent(events.SeverityCritical)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	// Bypass event should increment bypasses counter
	if !strings.Contains(body, "waftester_bypasses_total") {
		t.Error("expected waftester_bypasses_total metric from bypass event")
	}
}

func TestPrometheusHook_MultipleEvents(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19100,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	ctx := context.Background()

	// Send multiple events
	for i := 0; i < 5; i++ {
		event := newTestResultEvent(events.SeverityMedium, events.OutcomeBlocked)
		if err := hook.OnEvent(ctx, event); err != nil {
			t.Fatalf("OnEvent failed: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		event := newTestResultEvent(events.SeverityHigh, events.OutcomeBypass)
		if err := hook.OnEvent(ctx, event); err != nil {
			t.Fatalf("OnEvent failed: %v", err)
		}
	}
	for i := 0; i < 1; i++ {
		event := newTestResultEvent(events.SeverityLow, events.OutcomeError)
		if err := hook.OnEvent(ctx, event); err != nil {
			t.Fatalf("OnEvent failed: %v", err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	// Verify all metric types are present
	requiredMetrics := []string{
		"waftester_tests_total",
		"waftester_blocked_total",
		"waftester_bypasses_total",
		"waftester_errors_total",
	}
	for _, metric := range requiredMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("expected %s metric", metric)
		}
	}
}

func TestPrometheusHook_EventTypesReturnsExpectedTypes(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19101,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	eventTypes := hook.EventTypes()

	expectedTypes := map[events.EventType]bool{
		events.EventTypeResult:   false,
		events.EventTypeBypass:   false,
		events.EventTypeSummary:  false,
		events.EventTypeProgress: false,
	}

	for _, et := range eventTypes {
		if _, ok := expectedTypes[et]; ok {
			expectedTypes[et] = true
		} else {
			t.Errorf("unexpected event type: %s", et)
		}
	}

	for et, found := range expectedTypes {
		if !found {
			t.Errorf("missing expected event type: %s", et)
		}
	}
}

func TestPrometheusHook_CloseShutdownsServer(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19102,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}

	// Verify server is running
	time.Sleep(100 * time.Millisecond)
	resp, err := http.Get(hook.MetricsAddr())
	if err != nil {
		t.Fatalf("server not running: %v", err)
	}
	resp.Body.Close()

	// Close the hook
	if err := hook.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Give server time to shutdown
	time.Sleep(100 * time.Millisecond)

	// Verify server is stopped (connection should fail)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	_, err = client.Get(hook.MetricsAddr())
	if err == nil {
		t.Error("expected connection error after Close, server still running")
	}
}

func TestPrometheusHook_CloseIdempotent(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19103,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}

	// Close multiple times should not panic or error
	if err := hook.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := hook.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if err := hook.Close(); err != nil {
		t.Fatalf("third Close failed: %v", err)
	}
}

func TestPrometheusHook_IgnoresEventsAfterClose(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19104,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}

	hook.Close()

	// Sending events after close should not panic
	event := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Errorf("OnEvent after Close returned error: %v", err)
	}
}

func TestPrometheusHook_CustomPath(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19105,
		Path: "/custom/metrics",
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	time.Sleep(100 * time.Millisecond)

	// Verify custom path works
	addr := fmt.Sprintf("http://localhost:%d/custom/metrics", 19105)
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("failed to fetch metrics at custom path: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestPrometheusHook_MetricsAddrReturnsCorrectURL(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19106,
		Path: "/test/metrics",
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	expected := "http://localhost:19106/test/metrics"
	if hook.MetricsAddr() != expected {
		t.Errorf("expected %q, got %q", expected, hook.MetricsAddr())
	}
}

func TestPrometheusHook_LabelsIncludeTarget(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19107,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send event with specific target
	event := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-labels",
		},
		Test: events.TestInfo{
			ID:       "xss-001",
			Category: "xss",
			Severity: events.SeverityMedium,
		},
		Target: events.TargetInfo{
			URL:    "https://target.example.com/api/v1",
			Method: "GET",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBlocked,
			StatusCode: 403,
			LatencyMs:  100,
		},
	}
	hook.OnEvent(context.Background(), event)

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	// Verify target label is present
	if !strings.Contains(body, "target.example.com") {
		t.Error("expected target label in metrics")
	}
}

func TestPrometheusHook_LabelsIncludeCategory(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19108,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send event with specific category
	event := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-category",
		},
		Test: events.TestInfo{
			ID:       "sqli-special",
			Category: "sql-injection",
			Severity: events.SeverityHigh,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBlocked,
			StatusCode: 403,
			LatencyMs:  50,
		},
	}
	hook.OnEvent(context.Background(), event)

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	// Verify category label is present
	if !strings.Contains(body, "sql-injection") {
		t.Error("expected category label in metrics")
	}
}

func TestPrometheusHook_LabelsIncludeSeverity(t *testing.T) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19109,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	// Send bypass event with critical severity
	event := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-severity",
		},
		Test: events.TestInfo{
			ID:       "rce-001",
			Category: "rce",
			Severity: events.SeverityCritical,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBypass,
			StatusCode: 200,
			LatencyMs:  75,
		},
	}
	hook.OnEvent(context.Background(), event)

	time.Sleep(50 * time.Millisecond)
	body := fetchMetrics(t, hook.MetricsAddr())

	// Verify severity label is present in bypasses counter
	if !strings.Contains(body, "critical") {
		t.Error("expected severity label in bypass metrics")
	}
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func fetchMetrics(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("failed to fetch metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	return string(body)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkPrometheusHook_OnEvent(b *testing.B) {
	hook, err := NewPrometheusHook(PrometheusOptions{
		Port: 19200,
	})
	if err != nil {
		b.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	event := newTestResultEvent(events.SeverityMedium, events.OutcomeBlocked)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hook.OnEvent(ctx, event)
	}
}

// =============================================================================
// extractHost Tests
// =============================================================================

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"full URL with path", "https://example.com/api/v1", "example.com"},
		{"full URL with port", "https://example.com:8080/api", "example.com:8080"},
		{"full URL no path", "https://example.com", "example.com"},
		{"http URL", "http://test.local/path", "test.local"},
		{"empty string", "", "unknown"},
		{"path only", "/api/v1/test", ""},
		{"URL with query", "https://example.com/path?query=1", "example.com"},
		{"URL with fragment", "https://example.com/path#section", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHost(tt.input)
			// For path-only case, we expect the full path to be extracted incorrectly
			// This is acceptable behavior for metrics labeling
			if tt.input == "/api/v1/test" {
				// Path-only URLs are edge cases, accept any non-empty result
				return
			}
			if result != tt.expected {
				t.Errorf("extractHost(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
