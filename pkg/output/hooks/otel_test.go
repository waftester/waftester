package hooks

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// =============================================================================
// OTelHook Tests
// =============================================================================

// testOTelOptions returns OTelOptions configured for fast test execution.
func testOTelOptions() OTelOptions {
	return OTelOptions{
		Endpoint:          "localhost:4317",
		Insecure:          true,
		ShutdownTimeout:   100 * time.Millisecond,
		ConnectionTimeout: 100 * time.Millisecond,
	}
}

// skipIfNoOTLPCollector skips the test if no OTLP collector is listening.
// This prevents test failures when running without infrastructure.
func skipIfNoOTLPCollector(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "localhost:4317", 100*time.Millisecond)
	if err != nil {
		t.Skipf("Skipping: no OTLP collector at localhost:4317: %v", err)
	}
	conn.Close()
}

func TestOTelHook_NewWithDefaults(t *testing.T) {
	skipIfNoOTLPCollector(t)

	opts := testOTelOptions()
	hook, err := NewOTelHook(opts)
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	if hook.ServiceName() != "waftester" {
		t.Errorf("expected default service name 'waftester', got %q", hook.ServiceName())
	}
	if hook.Endpoint() != "localhost:4317" {
		t.Errorf("expected endpoint 'localhost:4317', got %q", hook.Endpoint())
	}
}

func TestOTelHook_CustomServiceName(t *testing.T) {
	skipIfNoOTLPCollector(t)

	opts := testOTelOptions()
	opts.ServiceName = "custom-scanner"
	hook, err := NewOTelHook(opts)
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	if hook.ServiceName() != "custom-scanner" {
		t.Errorf("expected service name 'custom-scanner', got %q", hook.ServiceName())
	}
}

func TestOTelHook_EventTypesReturnsExpectedTypes(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	eventTypes := hook.EventTypes()

	expectedTypes := map[events.EventType]bool{
		events.EventTypeStart:    false,
		events.EventTypeProgress: false,
		events.EventTypeResult:   false,
		events.EventTypeBypass:   false,
		events.EventTypeSummary:  false,
		events.EventTypeComplete: false,
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

func TestOTelHook_HandlesStartEvent(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	event := newTestStartEvent()
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent failed: %v", err)
	}
}

func TestOTelHook_HandlesProgressEvent(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// First send start event to create root span
	startEvent := newTestStartEvent()
	if err := hook.OnEvent(context.Background(), startEvent); err != nil {
		t.Fatalf("OnEvent for start failed: %v", err)
	}

	// Now send progress event
	event := newTestProgressEvent()
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent for progress failed: %v", err)
	}
}

func TestOTelHook_HandlesResultEvent(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// First send start event to create root span
	startEvent := newTestStartEvent()
	if err := hook.OnEvent(context.Background(), startEvent); err != nil {
		t.Fatalf("OnEvent for start failed: %v", err)
	}

	// Now send result event
	event := newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent for result failed: %v", err)
	}
}

func TestOTelHook_HandlesBypassEvent(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// First send start event to create root span
	startEvent := newTestStartEvent()
	if err := hook.OnEvent(context.Background(), startEvent); err != nil {
		t.Fatalf("OnEvent for start failed: %v", err)
	}

	// Now send bypass event
	event := newTestBypassEvent(events.SeverityCritical)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent for bypass failed: %v", err)
	}
}

func TestOTelHook_HandlesSummaryEvent(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// First send start event to create root span
	startEvent := newTestStartEvent()
	if err := hook.OnEvent(context.Background(), startEvent); err != nil {
		t.Fatalf("OnEvent for start failed: %v", err)
	}

	// Now send summary event
	event := newTestSummaryEvent(5, 95)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent for summary failed: %v", err)
	}
}

func TestOTelHook_HandlesCompleteEvent(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// First send start event to create root span
	startEvent := newTestStartEvent()
	if err := hook.OnEvent(context.Background(), startEvent); err != nil {
		t.Fatalf("OnEvent for start failed: %v", err)
	}

	// Now send complete event
	event := newTestCompleteEvent(true)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("OnEvent for complete failed: %v", err)
	}
}

func TestOTelHook_FullScanLifecycle(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	ctx := context.Background()

	// 1. Start scan
	if err := hook.OnEvent(ctx, newTestStartEvent()); err != nil {
		t.Fatalf("OnEvent for start failed: %v", err)
	}

	// 2. Progress updates
	for i := 0; i < 3; i++ {
		if err := hook.OnEvent(ctx, newTestProgressEvent()); err != nil {
			t.Fatalf("OnEvent for progress %d failed: %v", i, err)
		}
	}

	// 3. Result events
	for i := 0; i < 5; i++ {
		event := newTestResultEvent(events.SeverityMedium, events.OutcomeBlocked)
		if err := hook.OnEvent(ctx, event); err != nil {
			t.Fatalf("OnEvent for result %d failed: %v", i, err)
		}
	}

	// 4. Bypass event
	if err := hook.OnEvent(ctx, newTestBypassEvent(events.SeverityHigh)); err != nil {
		t.Fatalf("OnEvent for bypass failed: %v", err)
	}

	// 5. Summary
	if err := hook.OnEvent(ctx, newTestSummaryEvent(1, 5)); err != nil {
		t.Fatalf("OnEvent for summary failed: %v", err)
	}

	// 6. Complete
	if err := hook.OnEvent(ctx, newTestCompleteEvent(true)); err != nil {
		t.Fatalf("OnEvent for complete failed: %v", err)
	}
}

func TestOTelHook_IgnoresEventsAfterClose(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}

	// Close the hook
	if err := hook.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Events after close should be ignored (no error)
	event := newTestStartEvent()
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Errorf("expected no error after close, got: %v", err)
	}
}

func TestOTelHook_CloseIsIdempotent(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}

	// Close multiple times should not panic or error
	for i := 0; i < 3; i++ {
		if err := hook.Close(); err != nil {
			t.Errorf("Close %d failed: %v", i, err)
		}
	}
}

func TestOTelHook_HandleProgressWithoutStartReturnsNil(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// Send progress without start - should not error
	event := newTestProgressEvent()
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Errorf("expected no error for progress without start, got: %v", err)
	}
}

func TestOTelHook_HandleResultWithoutStartReturnsNil(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// Send result without start - should not error
	event := newTestResultEvent(events.SeverityHigh, events.OutcomeBypass)
	err = hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Errorf("expected no error for result without start, got: %v", err)
	}
}

func TestOTelHook_HandleBypassEventRecordsCorrectSeverity(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// Send start event
	if err := hook.OnEvent(context.Background(), newTestStartEvent()); err != nil {
		t.Fatalf("OnEvent for start failed: %v", err)
	}

	// Test different severity levels
	severities := []events.Severity{
		events.SeverityCritical,
		events.SeverityHigh,
		events.SeverityMedium,
		events.SeverityLow,
		events.SeverityInfo,
	}

	for _, sev := range severities {
		event := newTestBypassEvent(sev)
		err := hook.OnEvent(context.Background(), event)
		if err != nil {
			t.Errorf("OnEvent for bypass with severity %s failed: %v", sev, err)
		}
	}
}

func TestOTelHook_HandleResultEventRecordsAllOutcomes(t *testing.T) {
	skipIfNoOTLPCollector(t)

	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	// Send start event
	if err := hook.OnEvent(context.Background(), newTestStartEvent()); err != nil {
		t.Fatalf("OnEvent for start failed: %v", err)
	}

	// Test all outcome types
	outcomes := []events.Outcome{
		events.OutcomeBlocked,
		events.OutcomeBypass,
		events.OutcomeError,
		events.OutcomePass,
		events.OutcomeTimeout,
	}

	for _, outcome := range outcomes {
		event := newTestResultEvent(events.SeverityMedium, outcome)
		err := hook.OnEvent(context.Background(), event)
		if err != nil {
			t.Errorf("OnEvent for result with outcome %s failed: %v", outcome, err)
		}
	}
}

func TestOTelHook_OptionsApplied(t *testing.T) {
	skipIfNoOTLPCollector(t)

	opts := testOTelOptions()
	opts.ServiceName = "my-scanner"
	opts.Headers = map[string]string{
		"X-Custom-Header": "value",
	}

	hook, err := NewOTelHook(opts)
	if err != nil {
		t.Fatalf("NewOTelHook failed: %v", err)
	}
	defer hook.Close()

	if hook.ServiceName() != "my-scanner" {
		t.Errorf("expected service name 'my-scanner', got %q", hook.ServiceName())
	}
	if hook.Endpoint() != "localhost:4317" {
		t.Errorf("expected endpoint 'localhost:4317', got %q", hook.Endpoint())
	}
}

// =============================================================================
// OTelHook Integration Tests (require collector)
// =============================================================================

func TestOTelHook_IntegrationWithCollector(t *testing.T) {
	// Check if collector is available
	conn, err := net.DialTimeout("tcp", "localhost:4317", 100*time.Millisecond)
	if err != nil {
		t.Skip("Skipping integration test: no OTLP collector at localhost:4317")
	}
	conn.Close()

	hook, err := NewOTelHook(OTelOptions{
		Endpoint:    "localhost:4317",
		ServiceName: "waftester-test",
		Insecure:    true,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	defer hook.Close()

	ctx := context.Background()

	// Run full lifecycle
	if err := hook.OnEvent(ctx, newTestStartEvent()); err != nil {
		t.Errorf("start event failed: %v", err)
	}

	if err := hook.OnEvent(ctx, newTestResultEvent(events.SeverityHigh, events.OutcomeBlocked)); err != nil {
		t.Errorf("result event failed: %v", err)
	}

	if err := hook.OnEvent(ctx, newTestBypassEvent(events.SeverityCritical)); err != nil {
		t.Errorf("bypass event failed: %v", err)
	}

	if err := hook.OnEvent(ctx, newTestSummaryEvent(1, 10)); err != nil {
		t.Errorf("summary event failed: %v", err)
	}

	if err := hook.OnEvent(ctx, newTestCompleteEvent(true)); err != nil {
		t.Errorf("complete event failed: %v", err)
	}

	// Flush
	if err := hook.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

// =============================================================================
// OTelHook Test Helpers
// =============================================================================

func newTestStartEvent() *events.StartEvent {
	return &events.StartEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeStart,
			Time: time.Now(),
			Scan: "test-scan-otel-001",
		},
		Target:    "https://example.com",
		WAFVendor: "Cloudflare",
		Config: events.ScanConfig{
			Concurrency: 10,
			Timeout:     30,
			Categories:  []string{"sqli", "xss"},
		},
		Categories: []string{"sqli", "xss"},
		TotalTests: 100,
	}
}

func newTestProgressEvent() *events.ProgressEvent {
	return &events.ProgressEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeProgress,
			Time: time.Now(),
			Scan: "test-scan-otel-001",
		},
		Progress: events.ProgressInfo{
			Phase:      "testing",
			Current:    50,
			Total:      100,
			Percentage: 50.0,
		},
		Rate: events.RateInfo{
			RequestsPerSec: 25.5,
			AvgLatencyMs:   45.2,
			ErrorsPerMin:   0.5,
		},
		Timing: events.TimingInfo{
			ElapsedSec: 30,
			ETASec:     30,
			StartedAt:  time.Now().Add(-30 * time.Second),
		},
		Stats: events.StatsInfo{
			Bypasses:         2,
			Blocked:          45,
			Errors:           3,
			Passes:           0,
			EffectivenessPct: 90.0,
		},
	}
}

func newTestCompleteEvent(success bool) *events.CompleteEvent {
	exitCode := 0
	exitReason := "scan completed successfully"
	if !success {
		exitCode = 1
		exitReason = "scan failed with errors"
	}

	return &events.CompleteEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeComplete,
			Time: time.Now(),
			Scan: "test-scan-otel-001",
		},
		Success:    success,
		ExitCode:   exitCode,
		ExitReason: exitReason,
	}
}

// =============================================================================
// OTelHook Benchmark Tests
// =============================================================================

func BenchmarkOTelHook_OnEvent_Result(b *testing.B) {
	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		b.Skipf("Skipping: no OTLP collector available: %v", err)
	}
	defer hook.Close()

	// Create start event to initialize span
	if err := hook.OnEvent(context.Background(), newTestStartEvent()); err != nil {
		b.Fatalf("start event failed: %v", err)
	}

	event := newTestResultEvent(events.SeverityMedium, events.OutcomeBlocked)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hook.OnEvent(ctx, event)
	}
}

func BenchmarkOTelHook_OnEvent_Bypass(b *testing.B) {
	hook, err := NewOTelHook(testOTelOptions())
	if err != nil {
		b.Skipf("Skipping: no OTLP collector available: %v", err)
	}
	defer hook.Close()

	// Create start event to initialize span
	if err := hook.OnEvent(context.Background(), newTestStartEvent()); err != nil {
		b.Fatalf("start event failed: %v", err)
	}

	event := newTestBypassEvent(events.SeverityCritical)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hook.OnEvent(ctx, event)
	}
}
