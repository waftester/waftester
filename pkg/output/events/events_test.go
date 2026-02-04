package events

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestEventInterface verifies BaseEvent implements Event interface
func TestEventInterface(t *testing.T) {
	now := time.Now()
	base := BaseEvent{
		Type: EventTypeResult,
		Time: now,
		Scan: "scan-123",
	}

	// Verify interface methods
	var _ Event = base // Compile-time check

	if base.EventType() != EventTypeResult {
		t.Errorf("expected EventTypeResult, got %v", base.EventType())
	}
	if base.ScanID() != "scan-123" {
		t.Errorf("expected scan-123, got %v", base.ScanID())
	}
	if base.Timestamp().IsZero() {
		t.Error("expected non-zero timestamp")
	}
	if !base.Timestamp().Equal(now) {
		t.Errorf("expected timestamp %v, got %v", now, base.Timestamp())
	}
}

// TestEventTypeConstants verifies all event type constants
func TestEventTypeConstants(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventTypeStart, "start"},
		{EventTypeResult, "result"},
		{EventTypeProgress, "progress"},
		{EventTypeBypass, "bypass"},
		{EventTypeError, "error"},
		{EventTypeSummary, "summary"},
		{EventTypeComplete, "complete"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if string(tc.eventType) != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, tc.eventType)
			}
		})
	}
}

// TestOutcomeConstants verifies all outcome constants
func TestOutcomeConstants(t *testing.T) {
	tests := []struct {
		outcome  Outcome
		expected string
	}{
		{OutcomeBlocked, "blocked"},
		{OutcomeBypass, "bypass"},
		{OutcomeError, "error"},
		{OutcomePass, "pass"},
		{OutcomeTimeout, "timeout"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if string(tc.outcome) != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, tc.outcome)
			}
		})
	}
}

// TestSeverityConstants verifies all severity constants
func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if string(tc.severity) != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, tc.severity)
			}
		})
	}
}

// TestBaseEventJSON verifies BaseEvent JSON serialization
func TestBaseEventJSON(t *testing.T) {
	now := time.Now()
	base := BaseEvent{
		Type: EventTypeResult,
		Time: now,
		Scan: "scan-123",
	}

	data, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	required := []string{"type", "timestamp", "scan_id"}
	for _, field := range required {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing required field: %s\nJSON: %s", field, jsonStr)
		}
	}
}

// TestResultEventJSON verifies ResultEvent JSON serialization
func TestResultEventJSON(t *testing.T) {
	now := time.Now()
	event := &ResultEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeResult,
			Time: now,
			Scan: "scan-123",
		},
		Test: TestInfo{
			ID:       "sqli-001",
			Name:     "SQL Injection Test",
			Category: "sqli",
			Severity: SeverityCritical,
			OWASP:    []string{"A03:2021"},
			CWE:      []int{89},
		},
		Target: TargetInfo{
			URL:       "https://example.com/api",
			Method:    "POST",
			Endpoint:  "/api/login",
			Parameter: "username",
		},
		Result: ResultInfo{
			Outcome:       OutcomeBypass,
			StatusCode:    200,
			LatencyMs:     42.5,
			ContentLength: 1024,
		},
		Evidence: &Evidence{
			Payload:         "' OR 1=1--",
			EncodedPayload:  "%27%20OR%201%3D1--",
			CurlCommand:     "curl -X POST https://example.com/api",
			RequestHeaders:  map[string]string{"Content-Type": "application/json"},
			ResponsePreview: "<html>...",
		},
		Context: &ContextInfo{
			Phase:            "scanning",
			Tamper:           "space2comment",
			Encoding:         "url",
			EvasionTechnique: "case-switching",
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify key JSON field names
	jsonStr := string(data)
	required := []string{
		"type", "timestamp", "scan_id",
		"test", "target", "result",
		"evidence", "context",
	}
	for _, field := range required {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing required field: %s\nJSON: %s", field, jsonStr)
		}
	}

	// Verify nested field names
	nestedFields := []string{
		"id", "category", "severity", // test
		"url", "method", // target
		"outcome", "status_code", "latency_ms", // result
		"payload", "curl_command", // evidence
		"phase", "tamper", // context
	}
	for _, field := range nestedFields {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing nested field: %s\nJSON: %s", field, jsonStr)
		}
	}
}

// TestResultEventEmbeddedFields verifies embedded BaseEvent fields are accessible
func TestResultEventEmbeddedFields(t *testing.T) {
	now := time.Now()
	event := &ResultEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeResult,
			Time: now,
			Scan: "scan-456",
		},
	}

	// Access embedded fields directly
	if event.Type != EventTypeResult {
		t.Errorf("expected EventTypeResult, got %v", event.Type)
	}
	if event.Scan != "scan-456" {
		t.Errorf("expected scan-456, got %v", event.Scan)
	}
	if !event.Time.Equal(now) {
		t.Errorf("expected %v, got %v", now, event.Time)
	}

	// Access via interface methods
	if event.EventType() != EventTypeResult {
		t.Errorf("expected EventTypeResult from interface, got %v", event.EventType())
	}
	if event.ScanID() != "scan-456" {
		t.Errorf("expected scan-456 from interface, got %v", event.ScanID())
	}
}

// TestProgressEventJSON verifies ProgressEvent JSON serialization
func TestProgressEventJSON(t *testing.T) {
	startedAt := time.Now().Add(-2 * time.Minute)
	event := &ProgressEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeProgress,
			Time: time.Now(),
			Scan: "scan-123",
		},
		Progress: ProgressInfo{
			Phase:      "scanning",
			Current:    500,
			Total:      2800,
			Percentage: 17.86,
		},
		Rate: RateInfo{
			RequestsPerSec: 145.2,
			AvgLatencyMs:   42.0,
			ErrorsPerMin:   0.5,
		},
		Timing: TimingInfo{
			ElapsedSec: 120,
			ETASec:     90,
			StartedAt:  startedAt,
		},
		Stats: StatsInfo{
			Bypasses:         3,
			Blocked:          450,
			Errors:           12,
			Passes:           35,
			EffectivenessPct: 99.3,
		},
		Resources: &ResourceInfo{
			MemoryMB:        256,
			Goroutines:      100,
			OpenConnections: 50,
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify key JSON field names
	jsonStr := string(data)
	required := []string{
		"type", "timestamp", "scan_id",
		"progress", "rate", "timing", "stats", "resources",
	}
	for _, field := range required {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing required field: %s\nJSON: %s", field, jsonStr)
		}
	}

	// Verify nested field names
	nestedFields := []string{
		"phase", "current", "total", "percentage", // progress
		"requests_per_sec", "avg_latency_ms", "errors_per_min", // rate
		"elapsed_sec", "eta_sec", "started_at", // timing
		"bypasses", "blocked", "errors", "passes", "effectiveness_pct", // stats
		"memory_mb", "goroutines", "open_connections", // resources
	}
	for _, field := range nestedFields {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing nested field: %s\nJSON: %s", field, jsonStr)
		}
	}
}

// TestProgressEventOmitResources verifies resources field is omitted when nil
func TestProgressEventOmitResources(t *testing.T) {
	event := &ProgressEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeProgress,
			Time: time.Now(),
			Scan: "scan-123",
		},
		Progress: ProgressInfo{Phase: "scanning"},
		Rate:     RateInfo{},
		Timing:   TimingInfo{StartedAt: time.Now()},
		Stats:    StatsInfo{},
		// Resources is nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if containsField(jsonStr, "resources") {
		t.Errorf("expected resources to be omitted when nil\nJSON: %s", jsonStr)
	}
}

// TestSummaryEventJSON verifies SummaryEvent JSON serialization
func TestSummaryEventJSON(t *testing.T) {
	startedAt := time.Now().Add(-5 * time.Minute)
	completedAt := time.Now()
	event := &SummaryEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeSummary,
			Time: completedAt,
			Scan: "scan-123",
		},
		Version: "2.5.0",
		Target: SummaryTarget{
			URL:           "https://example.com",
			WAFDetected:   "Cloudflare",
			WAFConfidence: 0.95,
		},
		Totals: SummaryTotals{
			Tests:    2800,
			Bypasses: 12,
			Blocked:  2750,
			Errors:   5,
			Passes:   30,
			Timeouts: 3,
		},
		Effectiveness: EffectivenessInfo{
			BlockRatePct:   99.6,
			Grade:          "A+",
			Recommendation: "WAF is performing well",
		},
		Breakdown: BreakdownInfo{
			BySeverity: map[string]CategoryStats{
				"critical": {Total: 100, Bypasses: 5, BlockRate: 95.0},
			},
			ByCategory: map[string]CategoryStats{
				"sqli": {Total: 500, Bypasses: 3, BlockRate: 99.4},
			},
			ByOWASP: map[string]OWASPStats{
				"A03:2021": {Name: "Injection", Total: 600, Bypasses: 4},
			},
			ByEncoding: map[string]CategoryStats{
				"url": {Total: 1000, Bypasses: 2, BlockRate: 99.8},
			},
		},
		TopBypasses: []BypassInfo{
			{
				ID:       "sqli-042",
				Severity: "critical",
				Category: "SQL Injection",
				Encoding: "url",
				Curl:     "curl -X POST...",
			},
		},
		Latency: LatencyInfo{
			MinMs: 10,
			MaxMs: 500,
			AvgMs: 50,
			P50Ms: 45,
			P95Ms: 150,
			P99Ms: 300,
		},
		Timing: SummaryTiming{
			StartedAt:      startedAt,
			CompletedAt:    completedAt,
			DurationSec:    300.0,
			RequestsPerSec: 9.33,
		},
		ExitCode:   1,
		ExitReason: "bypasses_detected",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify key fields
	jsonStr := string(data)
	required := []string{
		"type", "timestamp", "scan_id",
		"version", "target", "totals", "effectiveness",
		"breakdown", "top_bypasses", "latency", "timing",
		"exit_code", "exit_reason",
	}
	for _, field := range required {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing required field: %s\nJSON: %s", field, jsonStr)
		}
	}

	// Verify nested field names
	nestedFields := []string{
		"url", "waf_detected", "waf_confidence", // target
		"tests", "bypasses", "blocked", // totals
		"block_rate_pct", "grade", "recommendation", // effectiveness
		"by_severity", "by_category", "by_owasp", "by_encoding", // breakdown
		"min_ms", "max_ms", "avg_ms", "p50_ms", "p95_ms", "p99_ms", // latency
		"started_at", "completed_at", "duration_sec", "requests_per_sec", // timing
	}
	for _, field := range nestedFields {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing nested field: %s\nJSON: %s", field, jsonStr)
		}
	}
}

// TestSummaryEventOmitTopBypasses verifies top_bypasses is omitted when empty
func TestSummaryEventOmitTopBypasses(t *testing.T) {
	event := &SummaryEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeSummary,
			Time: time.Now(),
			Scan: "scan-123",
		},
		// TopBypasses is nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if containsField(jsonStr, "top_bypasses") {
		t.Errorf("expected top_bypasses to be omitted when nil\nJSON: %s", jsonStr)
	}
}

// TestBypassEventJSON verifies BypassEvent JSON serialization
func TestBypassEventJSON(t *testing.T) {
	event := &BypassEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeBypass,
			Time: time.Now(),
			Scan: "scan-123",
		},
		Priority: "critical",
		Alert: AlertInfo{
			Title:          "WAF BYPASS DETECTED",
			Description:    "SQL injection bypassed WAF",
			ActionRequired: "Review and remediate immediately",
		},
		Details: BypassDetail{
			TestID:     "sqli-042",
			Category:   "SQL Injection",
			Severity:   SeverityCritical,
			OWASP:      []string{"A03:2021"},
			CWE:        []int{89},
			Endpoint:   "/api/login",
			Method:     "POST",
			StatusCode: 200,
			Payload:    "' OR 1=1--",
			Curl:       "curl -X POST...",
			Encoding:   "url",
			Tamper:     "space2comment",
		},
		Context: AlertContext{
			WAFDetected:   "Cloudflare",
			TestsSoFar:    1500,
			BypassesSoFar: 3,
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify key fields
	jsonStr := string(data)
	required := []string{
		"type", "timestamp", "scan_id",
		"priority", "alert", "details", "context",
	}
	for _, field := range required {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing required field: %s\nJSON: %s", field, jsonStr)
		}
	}

	// Verify nested field names
	nestedFields := []string{
		"title", "description", "action_required", // alert
		"test_id", "category", "severity", "endpoint", "method", "status_code", // details
		"waf_detected", "total_tests_so_far", "bypasses_so_far", // context
	}
	for _, field := range nestedFields {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing nested field: %s\nJSON: %s", field, jsonStr)
		}
	}
}

// TestBypassEventEmbeddedFields verifies embedded BaseEvent fields are accessible
func TestBypassEventEmbeddedFields(t *testing.T) {
	now := time.Now()
	event := &BypassEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeBypass,
			Time: now,
			Scan: "scan-789",
		},
		Priority: "high",
	}

	// Access embedded fields directly
	if event.Type != EventTypeBypass {
		t.Errorf("expected EventTypeBypass, got %v", event.Type)
	}
	if event.Scan != "scan-789" {
		t.Errorf("expected scan-789, got %v", event.Scan)
	}
	if !event.Time.Equal(now) {
		t.Errorf("expected %v, got %v", now, event.Time)
	}
}

// TestJSONRoundTrip verifies events can be marshaled and unmarshaled
func TestJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("ResultEvent", func(t *testing.T) {
		original := &ResultEvent{
			BaseEvent: BaseEvent{
				Type: EventTypeResult,
				Time: now,
				Scan: "scan-roundtrip",
			},
			Test: TestInfo{
				ID:       "test-001",
				Category: "xss",
				Severity: SeverityHigh,
			},
			Target: TargetInfo{
				URL:    "https://example.com",
				Method: "GET",
			},
			Result: ResultInfo{
				Outcome:    OutcomeBlocked,
				StatusCode: 403,
				LatencyMs:  25.5,
			},
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var decoded ResultEvent
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if decoded.Type != original.Type {
			t.Errorf("Type mismatch: got %v, want %v", decoded.Type, original.Type)
		}
		if decoded.Scan != original.Scan {
			t.Errorf("Scan mismatch: got %v, want %v", decoded.Scan, original.Scan)
		}
		if decoded.Test.ID != original.Test.ID {
			t.Errorf("Test.ID mismatch: got %v, want %v", decoded.Test.ID, original.Test.ID)
		}
		if decoded.Result.Outcome != original.Result.Outcome {
			t.Errorf("Result.Outcome mismatch: got %v, want %v", decoded.Result.Outcome, original.Result.Outcome)
		}
	})

	t.Run("ProgressEvent", func(t *testing.T) {
		original := &ProgressEvent{
			BaseEvent: BaseEvent{
				Type: EventTypeProgress,
				Time: now,
				Scan: "scan-progress",
			},
			Progress: ProgressInfo{
				Phase:      "testing",
				Current:    100,
				Total:      500,
				Percentage: 20.0,
			},
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var decoded ProgressEvent
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if decoded.Progress.Phase != original.Progress.Phase {
			t.Errorf("Progress.Phase mismatch: got %v, want %v", decoded.Progress.Phase, original.Progress.Phase)
		}
		if decoded.Progress.Percentage != original.Progress.Percentage {
			t.Errorf("Progress.Percentage mismatch: got %v, want %v", decoded.Progress.Percentage, original.Progress.Percentage)
		}
	})
}

// TestStartEventJSON verifies StartEvent JSON serialization
func TestStartEventJSON(t *testing.T) {
	event := &StartEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeStart,
			Time: time.Now(),
			Scan: "scan-start-123",
		},
		Target:    "https://example.com",
		WAFVendor: "Cloudflare",
		Config: ScanConfig{
			Concurrency:     10,
			Timeout:         30,
			Categories:      []string{"sqli", "xss"},
			Encodings:       []string{"url", "base64"},
			Tampers:         []string{"space2comment"},
			Severity:        "high",
			ThrottleMs:      100,
			FollowRedirects: true,
			VerifySSL:       true,
		},
		Categories: []string{"sqli", "xss", "rce"},
		TotalTests: 2800,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify key fields
	jsonStr := string(data)
	required := []string{
		"type", "timestamp", "scan_id",
		"target", "waf_vendor", "config", "categories", "total_tests",
	}
	for _, field := range required {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing required field: %s\nJSON: %s", field, jsonStr)
		}
	}

	// Verify nested config fields
	nestedFields := []string{
		"concurrency", "timeout_sec", "encodings", "tampers",
		"severity", "throttle_ms", "follow_redirects", "verify_ssl",
	}
	for _, field := range nestedFields {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing nested field: %s\nJSON: %s", field, jsonStr)
		}
	}
}

// TestStartEventOmitWAFVendor verifies waf_vendor is omitted when empty
func TestStartEventOmitWAFVendor(t *testing.T) {
	event := &StartEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeStart,
			Time: time.Now(),
			Scan: "scan-123",
		},
		Target:     "https://example.com",
		TotalTests: 100,
		// WAFVendor is empty
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if containsField(jsonStr, "waf_vendor") {
		t.Errorf("expected waf_vendor to be omitted when empty\nJSON: %s", jsonStr)
	}
}

// TestStartEventEmbeddedFields verifies embedded BaseEvent fields are accessible
func TestStartEventEmbeddedFields(t *testing.T) {
	now := time.Now()
	event := &StartEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeStart,
			Time: now,
			Scan: "scan-start-456",
		},
		Target: "https://example.com",
	}

	// Access embedded fields directly
	if event.Type != EventTypeStart {
		t.Errorf("expected EventTypeStart, got %v", event.Type)
	}
	if event.Scan != "scan-start-456" {
		t.Errorf("expected scan-start-456, got %v", event.Scan)
	}
	if !event.Time.Equal(now) {
		t.Errorf("expected %v, got %v", now, event.Time)
	}

	// Access via interface methods
	if event.EventType() != EventTypeStart {
		t.Errorf("expected EventTypeStart from interface, got %v", event.EventType())
	}
}

// TestCompleteEventJSON verifies CompleteEvent JSON serialization
func TestCompleteEventJSON(t *testing.T) {
	completedAt := time.Now()
	event := &CompleteEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeComplete,
			Time: completedAt,
			Scan: "scan-complete-123",
		},
		Success:    true,
		ExitCode:   0,
		ExitReason: "success",
		Summary: &SummaryEvent{
			BaseEvent: BaseEvent{
				Type: EventTypeSummary,
				Time: completedAt,
				Scan: "scan-complete-123",
			},
			Version: "2.5.0",
			Target: SummaryTarget{
				URL:         "https://example.com",
				WAFDetected: "Cloudflare",
			},
			Totals: SummaryTotals{
				Tests:    1000,
				Bypasses: 0,
				Blocked:  990,
			},
			ExitCode:   0,
			ExitReason: "success",
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify key fields
	jsonStr := string(data)
	required := []string{
		"type", "timestamp", "scan_id",
		"success", "exit_code", "exit_reason", "summary",
	}
	for _, field := range required {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing required field: %s\nJSON: %s", field, jsonStr)
		}
	}
}

// TestCompleteEventOmitSummary verifies summary is omitted when nil
func TestCompleteEventOmitSummary(t *testing.T) {
	event := &CompleteEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeComplete,
			Time: time.Now(),
			Scan: "scan-123",
		},
		Success:    false,
		ExitCode:   1,
		ExitReason: "error",
		// Summary is nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if containsField(jsonStr, "summary") {
		t.Errorf("expected summary to be omitted when nil\nJSON: %s", jsonStr)
	}
}

// TestCompleteEventEmbeddedFields verifies embedded BaseEvent fields are accessible
func TestCompleteEventEmbeddedFields(t *testing.T) {
	now := time.Now()
	event := &CompleteEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeComplete,
			Time: now,
			Scan: "scan-complete-456",
		},
		Success:  true,
		ExitCode: 0,
	}

	// Access embedded fields directly
	if event.Type != EventTypeComplete {
		t.Errorf("expected EventTypeComplete, got %v", event.Type)
	}
	if event.Scan != "scan-complete-456" {
		t.Errorf("expected scan-complete-456, got %v", event.Scan)
	}

	// Access via interface methods
	if event.EventType() != EventTypeComplete {
		t.Errorf("expected EventTypeComplete from interface, got %v", event.EventType())
	}
}

// TestErrorEventJSON verifies ErrorEvent JSON serialization
func TestErrorEventJSON(t *testing.T) {
	event := &ErrorEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeError,
			Time: time.Now(),
			Scan: "scan-error-123",
		},
		Target:    "https://example.com/api",
		ErrorType: "connection_timeout",
		Message:   "Failed to connect to target: connection timed out after 30s",
		Fatal:     false,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify key fields
	jsonStr := string(data)
	required := []string{
		"type", "timestamp", "scan_id",
		"target", "error_type", "message", "fatal",
	}
	for _, field := range required {
		if !containsField(jsonStr, field) {
			t.Errorf("JSON missing required field: %s\nJSON: %s", field, jsonStr)
		}
	}
}

// TestErrorEventFatal verifies fatal error serialization
func TestErrorEventFatal(t *testing.T) {
	event := &ErrorEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeError,
			Time: time.Now(),
			Scan: "scan-error-456",
		},
		ErrorType: "invalid_config",
		Message:   "Invalid configuration: missing target URL",
		Fatal:     true,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ErrorEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !decoded.Fatal {
		t.Error("expected Fatal to be true")
	}
	if decoded.ErrorType != "invalid_config" {
		t.Errorf("expected error_type invalid_config, got %s", decoded.ErrorType)
	}
}

// TestErrorEventOmitTarget verifies target is omitted when empty
func TestErrorEventOmitTarget(t *testing.T) {
	event := &ErrorEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeError,
			Time: time.Now(),
			Scan: "scan-123",
		},
		ErrorType: "license_error",
		Message:   "License expired",
		Fatal:     true,
		// Target is empty
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if containsField(jsonStr, "target") {
		t.Errorf("expected target to be omitted when empty\nJSON: %s", jsonStr)
	}
}

// TestErrorEventEmbeddedFields verifies embedded BaseEvent fields are accessible
func TestErrorEventEmbeddedFields(t *testing.T) {
	now := time.Now()
	event := &ErrorEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeError,
			Time: now,
			Scan: "scan-error-789",
		},
		ErrorType: "test_error",
		Message:   "Test error message",
	}

	// Access embedded fields directly
	if event.Type != EventTypeError {
		t.Errorf("expected EventTypeError, got %v", event.Type)
	}
	if event.Scan != "scan-error-789" {
		t.Errorf("expected scan-error-789, got %v", event.Scan)
	}

	// Access via interface methods
	if event.EventType() != EventTypeError {
		t.Errorf("expected EventTypeError from interface, got %v", event.EventType())
	}
}

// TestJSONRoundTripNewEvents verifies new events can be marshaled and unmarshaled
func TestJSONRoundTripNewEvents(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("StartEvent", func(t *testing.T) {
		original := &StartEvent{
			BaseEvent: BaseEvent{
				Type: EventTypeStart,
				Time: now,
				Scan: "scan-roundtrip-start",
			},
			Target:     "https://example.com",
			WAFVendor:  "Cloudflare",
			TotalTests: 500,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var decoded StartEvent
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if decoded.Type != original.Type {
			t.Errorf("Type mismatch: got %v, want %v", decoded.Type, original.Type)
		}
		if decoded.Target != original.Target {
			t.Errorf("Target mismatch: got %v, want %v", decoded.Target, original.Target)
		}
		if decoded.WAFVendor != original.WAFVendor {
			t.Errorf("WAFVendor mismatch: got %v, want %v", decoded.WAFVendor, original.WAFVendor)
		}
	})

	t.Run("CompleteEvent", func(t *testing.T) {
		original := &CompleteEvent{
			BaseEvent: BaseEvent{
				Type: EventTypeComplete,
				Time: now,
				Scan: "scan-roundtrip-complete",
			},
			Success:    true,
			ExitCode:   0,
			ExitReason: "success",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var decoded CompleteEvent
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if decoded.Success != original.Success {
			t.Errorf("Success mismatch: got %v, want %v", decoded.Success, original.Success)
		}
		if decoded.ExitCode != original.ExitCode {
			t.Errorf("ExitCode mismatch: got %v, want %v", decoded.ExitCode, original.ExitCode)
		}
	})

	t.Run("ErrorEvent", func(t *testing.T) {
		original := &ErrorEvent{
			BaseEvent: BaseEvent{
				Type: EventTypeError,
				Time: now,
				Scan: "scan-roundtrip-error",
			},
			Target:    "https://example.com",
			ErrorType: "timeout",
			Message:   "Connection timed out",
			Fatal:     false,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var decoded ErrorEvent
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if decoded.ErrorType != original.ErrorType {
			t.Errorf("ErrorType mismatch: got %v, want %v", decoded.ErrorType, original.ErrorType)
		}
		if decoded.Fatal != original.Fatal {
			t.Errorf("Fatal mismatch: got %v, want %v", decoded.Fatal, original.Fatal)
		}
	})
}

// containsField checks if JSON contains a specific field name
func containsField(jsonStr, field string) bool {
	return strings.Contains(jsonStr, `"`+field+`"`)
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

// TestEvent_ConcurrentJSON_Race tests concurrent JSON marshaling of the same event.
// This verifies that events are safe to marshal from multiple goroutines.
func TestEvent_ConcurrentJSON_Race(t *testing.T) {
	now := time.Now()
	event := &ResultEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeResult,
			Time: now,
			Scan: "scan-concurrent-123",
		},
		Test: TestInfo{
			ID:       "sqli-001",
			Name:     "SQL Injection Test",
			Category: "sqli",
			Severity: SeverityCritical,
			OWASP:    []string{"A03:2021"},
			CWE:      []int{89},
		},
		Target: TargetInfo{
			URL:       "https://example.com/api",
			Method:    "POST",
			Endpoint:  "/api/login",
			Parameter: "username",
		},
		Result: ResultInfo{
			Outcome:       OutcomeBypass,
			StatusCode:    200,
			LatencyMs:     42.5,
			ContentLength: 1024,
		},
		Evidence: &Evidence{
			Payload:         "' OR 1=1--",
			EncodedPayload:  "%27%20OR%201%3D1--",
			CurlCommand:     "curl -X POST https://example.com/api",
			RequestHeaders:  map[string]string{"Content-Type": "application/json"},
			ResponsePreview: "<html>...",
		},
		Context: &ContextInfo{
			Phase:            "scanning",
			Tamper:           "space2comment",
			Encoding:         "url",
			EvasionTechnique: "case-switching",
		},
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			data, err := json.Marshal(event)
			if err != nil {
				errors <- err
				return
			}
			// Verify the JSON is valid and contains expected fields
			if !containsField(string(data), "type") {
				errors <- json.Unmarshal([]byte("invalid"), nil) // Force an error
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent JSON marshaling failed: %v", err)
	}
}

// TestResultEvent_ConcurrentAccess tests concurrent field reads on ResultEvent.
// This verifies that reading event fields from multiple goroutines is safe.
func TestResultEvent_ConcurrentAccess(t *testing.T) {
	now := time.Now()
	event := &ResultEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeResult,
			Time: now,
			Scan: "scan-result-concurrent",
		},
		Test: TestInfo{
			ID:       "xss-042",
			Name:     "XSS Detection Test",
			Category: "xss",
			Severity: SeverityHigh,
			OWASP:    []string{"A03:2021", "A07:2021"},
			CWE:      []int{79, 80},
			Tags:     []string{"browser", "dom"},
		},
		Target: TargetInfo{
			URL:       "https://example.com/search",
			Method:    "GET",
			Endpoint:  "/search",
			Parameter: "q",
		},
		Result: ResultInfo{
			Outcome:       OutcomeBlocked,
			StatusCode:    403,
			LatencyMs:     15.2,
			ContentLength: 512,
			WAFSignature:  "cloudflare-block",
		},
		Evidence: &Evidence{
			Payload:        "<script>alert(1)</script>",
			EncodedPayload: "%3Cscript%3Ealert(1)%3C/script%3E",
			CurlCommand:    "curl -X GET 'https://example.com/search?q=<script>alert(1)</script>'",
		},
		Context: &ContextInfo{
			Phase:    "testing",
			Encoding: "url",
		},
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Read BaseEvent fields via interface methods
			_ = event.EventType()
			_ = event.ScanID()
			_ = event.Timestamp()

			// Read embedded BaseEvent fields directly
			_ = event.Type
			_ = event.Time
			_ = event.Scan

			// Read Test fields
			_ = event.Test.ID
			_ = event.Test.Name
			_ = event.Test.Category
			_ = event.Test.Severity
			_ = len(event.Test.OWASP)
			_ = len(event.Test.CWE)
			_ = len(event.Test.Tags)

			// Read Target fields
			_ = event.Target.URL
			_ = event.Target.Method
			_ = event.Target.Endpoint
			_ = event.Target.Parameter

			// Read Result fields
			_ = event.Result.Outcome
			_ = event.Result.StatusCode
			_ = event.Result.LatencyMs
			_ = event.Result.ContentLength
			_ = event.Result.WAFSignature

			// Read Evidence fields (pointer)
			if event.Evidence != nil {
				_ = event.Evidence.Payload
				_ = event.Evidence.EncodedPayload
				_ = event.Evidence.CurlCommand
			}

			// Read Context fields (pointer)
			if event.Context != nil {
				_ = event.Context.Phase
				_ = event.Context.Encoding
			}
		}(i)
	}

	wg.Wait()
}

// TestBypassEvent_ConcurrentAccess tests concurrent field reads on BypassEvent.
// This verifies that reading bypass event fields from multiple goroutines is safe.
func TestBypassEvent_ConcurrentAccess(t *testing.T) {
	now := time.Now()
	event := &BypassEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeBypass,
			Time: now,
			Scan: "scan-bypass-concurrent",
		},
		Priority: "critical",
		Alert: AlertInfo{
			Title:          "WAF BYPASS DETECTED",
			Description:    "SQL injection bypassed WAF protection",
			ActionRequired: "Immediate review and remediation required",
		},
		Details: BypassDetail{
			TestID:     "sqli-042",
			Category:   "SQL Injection",
			Severity:   SeverityCritical,
			OWASP:      []string{"A03:2021"},
			CWE:        []int{89},
			Endpoint:   "/api/login",
			Method:     "POST",
			StatusCode: 200,
			Payload:    "' OR 1=1--",
			Curl:       "curl -X POST https://example.com/api/login -d 'username=' OR 1=1--'",
			Encoding:   "url",
			Tamper:     "space2comment",
		},
		Context: AlertContext{
			WAFDetected:   "Cloudflare",
			TestsSoFar:    1500,
			BypassesSoFar: 3,
		},
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Read BaseEvent fields via interface methods
			_ = event.EventType()
			_ = event.ScanID()
			_ = event.Timestamp()

			// Read embedded BaseEvent fields directly
			_ = event.Type
			_ = event.Time
			_ = event.Scan

			// Read Priority
			_ = event.Priority

			// Read Alert fields
			_ = event.Alert.Title
			_ = event.Alert.Description
			_ = event.Alert.ActionRequired

			// Read Details fields
			_ = event.Details.TestID
			_ = event.Details.Category
			_ = event.Details.Severity
			_ = len(event.Details.OWASP)
			_ = len(event.Details.CWE)
			_ = event.Details.Endpoint
			_ = event.Details.Method
			_ = event.Details.StatusCode
			_ = event.Details.Payload
			_ = event.Details.Curl
			_ = event.Details.Encoding
			_ = event.Details.Tamper

			// Read Context fields
			_ = event.Context.WAFDetected
			_ = event.Context.TestsSoFar
			_ = event.Context.BypassesSoFar
		}(i)
	}

	wg.Wait()
}

// TestSummaryEvent_ConcurrentAccess tests concurrent field reads on SummaryEvent.
// This verifies that reading summary event fields from multiple goroutines is safe.
func TestSummaryEvent_ConcurrentAccess(t *testing.T) {
	startedAt := time.Now().Add(-5 * time.Minute)
	completedAt := time.Now()
	event := &SummaryEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeSummary,
			Time: completedAt,
			Scan: "scan-summary-concurrent",
		},
		Version: "2.5.0",
		Target: SummaryTarget{
			URL:           "https://example.com",
			WAFDetected:   "Cloudflare",
			WAFConfidence: 0.95,
		},
		Totals: SummaryTotals{
			Tests:    2800,
			Bypasses: 12,
			Blocked:  2750,
			Errors:   5,
			Passes:   30,
			Timeouts: 3,
		},
		Effectiveness: EffectivenessInfo{
			BlockRatePct:   99.6,
			Grade:          "A+",
			Recommendation: "WAF is performing excellently",
		},
		Breakdown: BreakdownInfo{
			BySeverity: map[string]CategoryStats{
				"critical": {Total: 100, Bypasses: 5, BlockRate: 95.0},
				"high":     {Total: 200, Bypasses: 4, BlockRate: 98.0},
				"medium":   {Total: 300, Bypasses: 2, BlockRate: 99.3},
				"low":      {Total: 400, Bypasses: 1, BlockRate: 99.75},
			},
			ByCategory: map[string]CategoryStats{
				"sqli": {Total: 500, Bypasses: 3, BlockRate: 99.4},
				"xss":  {Total: 600, Bypasses: 5, BlockRate: 99.2},
				"lfi":  {Total: 400, Bypasses: 2, BlockRate: 99.5},
			},
			ByOWASP: map[string]OWASPStats{
				"A03:2021": {Name: "Injection", Total: 600, Bypasses: 4},
				"A07:2021": {Name: "XSS", Total: 500, Bypasses: 5},
			},
			ByEncoding: map[string]CategoryStats{
				"url":    {Total: 1000, Bypasses: 2, BlockRate: 99.8},
				"base64": {Total: 500, Bypasses: 3, BlockRate: 99.4},
			},
		},
		TopBypasses: []BypassInfo{
			{ID: "sqli-042", Severity: "critical", Category: "SQL Injection", Encoding: "url"},
			{ID: "xss-015", Severity: "high", Category: "XSS", Encoding: "html"},
			{ID: "lfi-008", Severity: "high", Category: "LFI", Encoding: "double-url"},
		},
		Latency: LatencyInfo{
			MinMs: 10,
			MaxMs: 500,
			AvgMs: 50,
			P50Ms: 45,
			P95Ms: 150,
			P99Ms: 300,
		},
		Timing: SummaryTiming{
			StartedAt:      startedAt,
			CompletedAt:    completedAt,
			DurationSec:    300.0,
			RequestsPerSec: 9.33,
		},
		ExitCode:   1,
		ExitReason: "bypasses_detected",
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Read BaseEvent fields via interface methods
			_ = event.EventType()
			_ = event.ScanID()
			_ = event.Timestamp()

			// Read embedded BaseEvent fields directly
			_ = event.Type
			_ = event.Time
			_ = event.Scan

			// Read Version
			_ = event.Version

			// Read Target fields
			_ = event.Target.URL
			_ = event.Target.WAFDetected
			_ = event.Target.WAFConfidence

			// Read Totals fields
			_ = event.Totals.Tests
			_ = event.Totals.Bypasses
			_ = event.Totals.Blocked
			_ = event.Totals.Errors
			_ = event.Totals.Passes
			_ = event.Totals.Timeouts

			// Read Effectiveness fields
			_ = event.Effectiveness.BlockRatePct
			_ = event.Effectiveness.Grade
			_ = event.Effectiveness.Recommendation

			// Read Breakdown fields (maps - concurrent read is safe)
			_ = len(event.Breakdown.BySeverity)
			_ = len(event.Breakdown.ByCategory)
			_ = len(event.Breakdown.ByOWASP)
			_ = len(event.Breakdown.ByEncoding)

			// Read individual map entries (concurrent read is safe if no writes)
			if stats, ok := event.Breakdown.BySeverity["critical"]; ok {
				_ = stats.Total
				_ = stats.Bypasses
				_ = stats.BlockRate
			}

			// Read TopBypasses slice
			_ = len(event.TopBypasses)
			if len(event.TopBypasses) > 0 {
				_ = event.TopBypasses[0].ID
				_ = event.TopBypasses[0].Severity
				_ = event.TopBypasses[0].Category
			}

			// Read Latency fields
			_ = event.Latency.MinMs
			_ = event.Latency.MaxMs
			_ = event.Latency.AvgMs
			_ = event.Latency.P50Ms
			_ = event.Latency.P95Ms
			_ = event.Latency.P99Ms

			// Read Timing fields
			_ = event.Timing.StartedAt
			_ = event.Timing.CompletedAt
			_ = event.Timing.DurationSec
			_ = event.Timing.RequestsPerSec

			// Read exit fields
			_ = event.ExitCode
			_ = event.ExitReason
		}(i)
	}

	wg.Wait()
}
