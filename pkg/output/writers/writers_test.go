package writers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// failWriter is a test helper that implements io.Writer and io.Closer
// and can be configured to fail on Write or Close calls.
type failWriter struct {
	failOnWrite bool
	failOnClose bool
	closed      bool
}

func (fw *failWriter) Write(p []byte) (int, error) {
	if fw.failOnWrite {
		return 0, fmt.Errorf("simulated write error")
	}
	return len(p), nil
}

func (fw *failWriter) Close() error {
	fw.closed = true
	if fw.failOnClose {
		return fmt.Errorf("simulated close error")
	}
	return nil
}

// makeTestResultEvent creates a test result event for testing.
func makeTestResultEvent(id, category string, severity events.Severity, outcome events.Outcome) *events.ResultEvent {
	return &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-123",
		},
		Test: events.TestInfo{
			ID:       id,
			Name:     id + " test",
			Category: category,
			Severity: severity,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com/api",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    outcome,
			StatusCode: 200,
			LatencyMs:  42.5,
		},
		Evidence: &events.Evidence{
			Payload: "test-payload",
		},
	}
}

// TestJSONLWriter tests JSONL streaming output.
func TestJSONLWriter(t *testing.T) {
	t.Run("writes one JSON per line", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJSONLWriter(buf, JSONLOptions{})

		testEvents := []*events.ResultEvent{
			makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass),
			makeTestResultEvent("test-2", "xss", events.SeverityHigh, events.OutcomeBlocked),
		}

		for _, e := range testEvents {
			if err := w.Write(e); err != nil {
				t.Fatalf("write failed: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 2 {
			t.Errorf("expected 2 lines, got %d", len(lines))
		}

		// Verify each line is valid JSON
		for i, line := range lines {
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Errorf("line %d is not valid JSON: %v", i+1, err)
			}
		}
	})

	t.Run("OnlyBypasses filters correctly", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJSONLWriter(buf, JSONLOptions{OnlyBypasses: true})

		bypass := makeTestResultEvent("bypass-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		blocked := makeTestResultEvent("blocked-1", "xss", events.SeverityHigh, events.OutcomeBlocked)

		if err := w.Write(bypass); err != nil {
			t.Fatalf("write bypass failed: %v", err)
		}
		if err := w.Write(blocked); err != nil {
			t.Fatalf("write blocked failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		output := strings.TrimSpace(buf.String())
		if output == "" {
			t.Error("expected at least one line of output")
			return
		}
		lines := strings.Split(output, "\n")
		if len(lines) != 1 {
			t.Errorf("expected 1 line (bypass only), got %d", len(lines))
		}
	})

	t.Run("OmitEvidence removes evidence", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJSONLWriter(buf, JSONLOptions{OmitEvidence: true})

		e := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		w.Close()

		var result map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		if _, hasEvidence := result["evidence"]; hasEvidence {
			t.Error("evidence should be omitted")
		}
	})

	t.Run("SupportsEvent returns true for all types", func(t *testing.T) {
		w := NewJSONLWriter(&bytes.Buffer{}, JSONLOptions{})
		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should support progress events")
		}
		if !w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should support bypass events")
		}
		if !w.SupportsEvent(events.EventTypeSummary) {
			t.Error("should support summary events")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewJSONLWriter(&bytes.Buffer{}, JSONLOptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})
}

// TestJSONWriter tests JSON array output.
func TestJSONWriter(t *testing.T) {
	t.Run("writes JSON array on Close", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJSONWriter(buf, JSONOptions{})

		e1 := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		e2 := makeTestResultEvent("test-2", "xss", events.SeverityHigh, events.OutcomeBlocked)

		if err := w.Write(e1); err != nil {
			t.Fatalf("write e1 failed: %v", err)
		}
		if err := w.Write(e2); err != nil {
			t.Fatalf("write e2 failed: %v", err)
		}

		// Before Close, buffer should be empty
		if buf.Len() > 0 {
			t.Error("expected no output before Close")
		}

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		// After Close, should have JSON array
		var arr []map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
			t.Fatalf("output is not valid JSON array: %v", err)
		}

		if len(arr) != 2 {
			t.Errorf("expected 2 elements, got %d", len(arr))
		}
	})

	t.Run("writes empty array when no events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJSONWriter(buf, JSONOptions{})
		w.Close()

		var arr []interface{}
		if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
			t.Fatalf("output is not valid JSON array: %v", err)
		}

		if len(arr) != 0 {
			t.Errorf("expected empty array, got %d elements", len(arr))
		}
	})

	t.Run("Pretty option adds indentation", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJSONWriter(buf, JSONOptions{Pretty: true})

		e := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(e)
		w.Close()

		output := buf.String()
		if !strings.Contains(output, "\n") {
			t.Error("pretty output should contain newlines")
		}
	})

	t.Run("SupportsEvent filters correctly", func(t *testing.T) {
		w := NewJSONWriter(&bytes.Buffer{}, JSONOptions{})
		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should support bypass events")
		}
		if !w.SupportsEvent(events.EventTypeSummary) {
			t.Error("should support summary events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewJSONWriter(&bytes.Buffer{}, JSONOptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})
}

// TestSARIFWriter tests SARIF 2.1.0 output.
func TestSARIFWriter(t *testing.T) {
	t.Run("produces valid SARIF structure", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSARIFWriter(buf, SARIFOptions{
			ToolName:    "waftester",
			ToolVersion: "2.5.0",
		})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(bypass); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var sarif sarifDocument
		if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
			t.Fatalf("invalid SARIF JSON: %v", err)
		}

		if sarif.Version != "2.1.0" {
			t.Errorf("expected version 2.1.0, got %s", sarif.Version)
		}

		if len(sarif.Runs) != 1 {
			t.Errorf("expected 1 run, got %d", len(sarif.Runs))
		}

		if sarif.Runs[0].Tool.Driver.Name != "waftester" {
			t.Errorf("expected tool name waftester, got %s", sarif.Runs[0].Tool.Driver.Name)
		}

		if sarif.Runs[0].Tool.Driver.Version != "2.5.0" {
			t.Errorf("expected version 2.5.0, got %s", sarif.Runs[0].Tool.Driver.Version)
		}
	})

	t.Run("filters blocked results", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSARIFWriter(buf, SARIFOptions{})

		blocked := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBlocked)
		w.Write(blocked)
		w.Close()

		var sarif sarifDocument
		if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
			t.Fatalf("invalid SARIF JSON: %v", err)
		}

		if len(sarif.Runs[0].Results) != 0 {
			t.Error("blocked results should not appear in SARIF output")
		}
	})

	t.Run("includes bypass results", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSARIFWriter(buf, SARIFOptions{})

		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var sarif sarifDocument
		json.Unmarshal(buf.Bytes(), &sarif)

		if len(sarif.Runs[0].Results) != 1 {
			t.Errorf("expected 1 result, got %d", len(sarif.Runs[0].Results))
		}
	})

	t.Run("includes error outcomes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSARIFWriter(buf, SARIFOptions{})

		errResult := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeError)
		w.Write(errResult)
		w.Close()

		var sarif sarifDocument
		json.Unmarshal(buf.Bytes(), &sarif)

		if len(sarif.Runs[0].Results) != 1 {
			t.Errorf("expected 1 result for error outcome, got %d", len(sarif.Runs[0].Results))
		}
	})

	t.Run("severity mapping", func(t *testing.T) {
		tests := []struct {
			severity events.Severity
			expected string
		}{
			{events.SeverityCritical, "error"},
			{events.SeverityHigh, "error"},
			{events.SeverityMedium, "warning"},
			{events.SeverityLow, "note"},
			{events.SeverityInfo, "note"},
		}

		for _, tc := range tests {
			level := severityToLevel(tc.severity)
			if level != tc.expected {
				t.Errorf("severity %s: expected level %s, got %s", tc.severity, tc.expected, level)
			}
		}
	})

	t.Run("default tool name is waftester", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSARIFWriter(buf, SARIFOptions{})
		w.Close()

		var sarif sarifDocument
		json.Unmarshal(buf.Bytes(), &sarif)

		if sarif.Runs[0].Tool.Driver.Name != "waftester" {
			t.Errorf("expected default tool name waftester, got %s", sarif.Runs[0].Tool.Driver.Name)
		}
	})

	t.Run("SupportsEvent for result and bypass", func(t *testing.T) {
		w := NewSARIFWriter(&bytes.Buffer{}, SARIFOptions{})
		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should support bypass events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewSARIFWriter(&bytes.Buffer{}, SARIFOptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})
}

// TestCSVWriter tests CSV output.
func TestCSVWriter(t *testing.T) {
	t.Run("writes header and rows", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCSVWriter(buf, CSVOptions{IncludeHeader: true})

		e := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("flush failed: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 2 {
			t.Errorf("expected 2 lines (header + 1 row), got %d", len(lines))
		}

		// Verify header contains expected columns
		header := lines[0]
		if !strings.Contains(header, "timestamp") {
			t.Error("header should contain 'timestamp'")
		}
		if !strings.Contains(header, "category") {
			t.Error("header should contain 'category'")
		}
		if !strings.Contains(header, "severity") {
			t.Error("header should contain 'severity'")
		}
		if !strings.Contains(header, "outcome") {
			t.Error("header should contain 'outcome'")
		}
	})

	t.Run("no header when IncludeHeader is false", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCSVWriter(buf, CSVOptions{IncludeHeader: false})

		e := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(e)
		w.Flush()

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 1 {
			t.Errorf("expected 1 line (no header), got %d", len(lines))
		}
	})

	t.Run("row contains correct data", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCSVWriter(buf, CSVOptions{IncludeHeader: false})

		e := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(e)
		w.Flush()

		row := buf.String()
		if !strings.Contains(row, "test-1") {
			t.Error("row should contain test ID")
		}
		if !strings.Contains(row, "sqli") {
			t.Error("row should contain category")
		}
		if !strings.Contains(row, "CRITICAL") {
			t.Error("row should contain severity (uppercase)")
		}
		if !strings.Contains(row, "BYPASS") {
			t.Error("row should contain outcome (uppercase)")
		}
	})

	t.Run("custom delimiter", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCSVWriter(buf, CSVOptions{IncludeHeader: true, Delimiter: ';'})

		e := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(e)
		w.Flush()

		output := buf.String()
		if !strings.Contains(output, ";") {
			t.Error("output should use semicolon delimiter")
		}
	})

	t.Run("SupportsEvent for results and summary", func(t *testing.T) {
		w := NewCSVWriter(&bytes.Buffer{}, CSVOptions{})
		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeSummary) {
			t.Error("should support summary events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
		if w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should not support bypass events")
		}
	})

	t.Run("skips non-result events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCSVWriter(buf, CSVOptions{IncludeHeader: false})

		// Write a BaseEvent (not a ResultEvent)
		baseEvent := &events.BaseEvent{
			Type: events.EventTypeProgress,
			Time: time.Now(),
			Scan: "test-scan",
		}

		// This should be silently skipped
		err := w.Write(baseEvent)
		if err != nil {
			t.Errorf("write should not fail for non-result events: %v", err)
		}
		w.Flush()

		if buf.Len() > 0 {
			t.Error("non-result events should be skipped")
		}
	})

	t.Run("Close flushes and returns no error", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCSVWriter(buf, CSVOptions{IncludeHeader: true})

		e := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(e)

		if err := w.Close(); err != nil {
			t.Errorf("close should not fail: %v", err)
		}

		// Verify data was flushed
		if !strings.Contains(buf.String(), "test-1") {
			t.Error("data should be flushed on Close")
		}
	})
}

// TestJUnitWriter tests JUnit XML output.
func TestJUnitWriter(t *testing.T) {
	t.Run("produces valid XML structure", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{
			SuiteName: "waftester",
			Package:   "waftester",
			Hostname:  "scanner",
		})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(bypass); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		output := buf.String()

		// Check XML header
		if !strings.Contains(output, `<?xml version="1.0" encoding="UTF-8"?>`) {
			t.Error("expected XML header")
		}

		// Check testsuites structure
		if !strings.Contains(output, "<testsuites>") {
			t.Error("expected testsuites element")
		}
		if !strings.Contains(output, `<testsuite name="waftester"`) {
			t.Error("expected testsuite element with name")
		}
		if !strings.Contains(output, `hostname="scanner"`) {
			t.Error("expected hostname attribute")
		}
		if !strings.Contains(output, "<testcase") {
			t.Error("expected testcase element")
		}
	})

	t.Run("blocked results become success", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{})

		blocked := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBlocked)
		w.Write(blocked)
		w.Close()

		output := buf.String()

		// Should have testcase but no failure or error elements
		if !strings.Contains(output, "<testcase") {
			t.Error("expected testcase element")
		}
		if strings.Contains(output, "<failure") {
			t.Error("blocked result should not have failure element")
		}
		if strings.Contains(output, "<error") {
			t.Error("blocked result should not have error element")
		}
	})

	t.Run("bypass results become failure", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{})

		bypass := makeTestResultEvent("sqli-002", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "<failure") {
			t.Error("bypass result should have failure element")
		}
		if !strings.Contains(output, `message="WAF bypass detected"`) {
			t.Error("failure should have WAF bypass message")
		}
		if !strings.Contains(output, `type="bypass"`) {
			t.Error("failure type should be bypass")
		}
		if !strings.Contains(output, "Bypass Details:") {
			t.Error("failure content should contain bypass details")
		}
	})

	t.Run("error results become error element", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{})

		errResult := makeTestResultEvent("test-3", "sqli", events.SeverityHigh, events.OutcomeError)
		w.Write(errResult)
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "<error") {
			t.Error("error result should have error element")
		}
		if !strings.Contains(output, `type="error"`) {
			t.Error("error element should have type attribute")
		}
	})

	t.Run("timeout results become error element", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{})

		timeout := makeTestResultEvent("test-4", "sqli", events.SeverityHigh, events.OutcomeTimeout)
		w.Write(timeout)
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "<error") {
			t.Error("timeout result should have error element")
		}
		if !strings.Contains(output, `type="timeout"`) {
			t.Error("timeout error should have type timeout")
		}
	})

	t.Run("calculates totals correctly", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{})

		// Write various outcomes
		blocked := makeTestResultEvent("blocked-1", "sqli", events.SeverityHigh, events.OutcomeBlocked)
		bypass1 := makeTestResultEvent("bypass-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		bypass2 := makeTestResultEvent("bypass-2", "xss", events.SeverityHigh, events.OutcomeBypass)
		errResult := makeTestResultEvent("error-1", "sqli", events.SeverityHigh, events.OutcomeError)
		timeout := makeTestResultEvent("timeout-1", "sqli", events.SeverityHigh, events.OutcomeTimeout)
		pass := makeTestResultEvent("pass-1", "sqli", events.SeverityHigh, events.OutcomePass)

		w.Write(blocked)
		w.Write(bypass1)
		w.Write(bypass2)
		w.Write(errResult)
		w.Write(timeout)
		w.Write(pass)
		w.Close()

		output := buf.String()

		// 6 tests total
		if !strings.Contains(output, `tests="6"`) {
			t.Error("expected 6 tests")
		}
		// 2 failures (bypasses)
		if !strings.Contains(output, `failures="2"`) {
			t.Error("expected 2 failures")
		}
		// 2 errors (error + timeout)
		if !strings.Contains(output, `errors="2"`) {
			t.Error("expected 2 errors")
		}
	})

	t.Run("SupportsEvent filters correctly", func(t *testing.T) {
		w := NewJUnitWriter(&bytes.Buffer{}, JUnitOptions{})

		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
		if w.SupportsEvent(events.EventTypeSummary) {
			t.Error("should not support summary events")
		}
		if w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should not support bypass events (only result)")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewJUnitWriter(&bytes.Buffer{}, JUnitOptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})

	t.Run("default suite name is waftester", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{})
		w.Close()

		output := buf.String()
		if !strings.Contains(output, `name="waftester"`) {
			t.Error("expected default suite name waftester")
		}
	})

	t.Run("classname includes package and category", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{Package: "mypackage"})

		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		output := buf.String()
		if !strings.Contains(output, `classname="mypackage.sqli"`) {
			t.Error("expected classname with package.category format")
		}
	})

	t.Run("handles empty results", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJUnitWriter(buf, JUnitOptions{})
		w.Close()

		output := buf.String()
		if !strings.Contains(output, `tests="0"`) {
			t.Error("expected 0 tests")
		}
		if !strings.Contains(output, `failures="0"`) {
			t.Error("expected 0 failures")
		}
		if !strings.Contains(output, `errors="0"`) {
			t.Error("expected 0 errors")
		}
	})
}

// TestWritersImplementInterface verifies all writers implement dispatcher.Writer.
func TestWritersImplementInterface(t *testing.T) {
	// These are compile-time checks via the var _ dispatcher.Writer lines
	// in each file, but we can also verify behavior here.

	t.Run("JSONLWriter has all interface methods", func(t *testing.T) {
		w := NewJSONLWriter(&bytes.Buffer{}, JSONLOptions{})
		_ = w.Write(makeTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass))
		_ = w.Flush()
		_ = w.Close()
		_ = w.SupportsEvent(events.EventTypeResult)
	})

	t.Run("JUnitWriter has all interface methods", func(t *testing.T) {
		w := NewJUnitWriter(&bytes.Buffer{}, JUnitOptions{})
		_ = w.Write(makeTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass))
		_ = w.Flush()
		_ = w.Close()
		_ = w.SupportsEvent(events.EventTypeResult)
	})

	t.Run("JSONWriter has all interface methods", func(t *testing.T) {
		w := NewJSONWriter(&bytes.Buffer{}, JSONOptions{})
		_ = w.Write(makeTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass))
		_ = w.Flush()
		_ = w.Close()
		_ = w.SupportsEvent(events.EventTypeResult)
	})

	t.Run("SARIFWriter has all interface methods", func(t *testing.T) {
		w := NewSARIFWriter(&bytes.Buffer{}, SARIFOptions{})
		_ = w.Write(makeTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass))
		_ = w.Flush()
		_ = w.Close()
		_ = w.SupportsEvent(events.EventTypeResult)
	})

	t.Run("CSVWriter has all interface methods", func(t *testing.T) {
		w := NewCSVWriter(&bytes.Buffer{}, CSVOptions{})
		_ = w.Write(makeTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass))
		_ = w.Flush()
		_ = w.Close()
		_ = w.SupportsEvent(events.EventTypeResult)
	})
}

// TestMultipleWrites verifies writers handle multiple events correctly.
func TestMultipleWrites(t *testing.T) {
	t.Run("JSONL handles many events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJSONLWriter(buf, JSONLOptions{})

		for i := 0; i < 100; i++ {
			e := makeTestResultEvent("test", "sqli", events.SeverityHigh, events.OutcomeBypass)
			if err := w.Write(e); err != nil {
				t.Fatalf("write %d failed: %v", i, err)
			}
		}
		w.Close()

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 100 {
			t.Errorf("expected 100 lines, got %d", len(lines))
		}
	})

	t.Run("JSON handles many events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewJSONWriter(buf, JSONOptions{})

		for i := 0; i < 100; i++ {
			e := makeTestResultEvent("test", "sqli", events.SeverityHigh, events.OutcomeBypass)
			if err := w.Write(e); err != nil {
				t.Fatalf("write %d failed: %v", i, err)
			}
		}
		w.Close()

		var arr []interface{}
		if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if len(arr) != 100 {
			t.Errorf("expected 100 elements, got %d", len(arr))
		}
	})

	t.Run("SARIF deduplicates rules", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSARIFWriter(buf, SARIFOptions{})

		// Write multiple events with same category
		for i := 0; i < 5; i++ {
			e := makeTestResultEvent("test", "sqli", events.SeverityHigh, events.OutcomeBypass)
			w.Write(e)
		}
		w.Close()

		var sarif sarifDocument
		json.Unmarshal(buf.Bytes(), &sarif)

		// Should have 5 results but only 1 rule (same category/id)
		if len(sarif.Runs[0].Results) != 5 {
			t.Errorf("expected 5 results, got %d", len(sarif.Runs[0].Results))
		}
		if len(sarif.Runs[0].Tool.Driver.Rules) != 1 {
			t.Errorf("expected 1 rule (deduplicated), got %d", len(sarif.Runs[0].Tool.Driver.Rules))
		}
	})
}

// TestSonarQubeWriter tests SonarQube Generic Issue Import output.
func TestSonarQubeWriter(t *testing.T) {
	t.Run("produces valid structure", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSonarQubeWriter(buf, SonarQubeOptions{
			ToolName:    "waftester",
			ToolVersion: "2.5.0",
		})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(bypass); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var doc sonarQubeDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid SonarQube JSON: %v", err)
		}

		if len(doc.Issues) != 1 {
			t.Fatalf("expected 1 issue, got %d", len(doc.Issues))
		}

		issue := doc.Issues[0]
		if issue.EngineID != "waftester" {
			t.Errorf("expected engineId waftester, got %s", issue.EngineID)
		}
		if issue.RuleID != "sqli-sqli-001" {
			t.Errorf("expected ruleId sqli-sqli-001, got %s", issue.RuleID)
		}
		if issue.Type != "VULNERABILITY" {
			t.Errorf("expected type VULNERABILITY, got %s", issue.Type)
		}
		if issue.PrimaryLocation.FilePath != "https://example.com/api" {
			t.Errorf("expected filePath https://example.com/api, got %s", issue.PrimaryLocation.FilePath)
		}
		if issue.PrimaryLocation.TextRange.StartLine != 1 {
			t.Errorf("expected startLine 1, got %d", issue.PrimaryLocation.TextRange.StartLine)
		}
		if issue.EffortMinutes != 30 {
			t.Errorf("expected effortMinutes 30, got %d", issue.EffortMinutes)
		}
	})

	t.Run("severity mapping", func(t *testing.T) {
		tests := []struct {
			severity events.Severity
			expected string
		}{
			{events.SeverityCritical, "CRITICAL"},
			{events.SeverityHigh, "MAJOR"},
			{events.SeverityMedium, "MINOR"},
			{events.SeverityLow, "INFO"},
			{events.SeverityInfo, "INFO"},
		}

		for _, tc := range tests {
			level := severityToSonarQube(tc.severity)
			if level != tc.expected {
				t.Errorf("severity %s: expected %s, got %s", tc.severity, tc.expected, level)
			}
		}
	})

	t.Run("only includes bypass/error outcomes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSonarQubeWriter(buf, SonarQubeOptions{})

		// Write events with different outcomes
		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBypass)
		blocked := makeTestResultEvent("test-2", "xss", events.SeverityMedium, events.OutcomeBlocked)
		errResult := makeTestResultEvent("test-3", "rce", events.SeverityCritical, events.OutcomeError)
		timeout := makeTestResultEvent("test-4", "lfi", events.SeverityLow, events.OutcomeTimeout)

		w.Write(bypass)
		w.Write(blocked)
		w.Write(errResult)
		w.Write(timeout)
		w.Close()

		var doc sonarQubeDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid SonarQube JSON: %v", err)
		}

		// Should only have bypass and error outcomes (2 issues)
		if len(doc.Issues) != 2 {
			t.Errorf("expected 2 issues (bypass + error), got %d", len(doc.Issues))
		}
	})

	t.Run("filters blocked results", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSonarQubeWriter(buf, SonarQubeOptions{})

		blocked := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBlocked)
		w.Write(blocked)
		w.Close()

		var doc sonarQubeDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid SonarQube JSON: %v", err)
		}

		if len(doc.Issues) != 0 {
			t.Error("blocked results should not appear in SonarQube output")
		}
	})

	t.Run("includes error outcomes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSonarQubeWriter(buf, SonarQubeOptions{})

		errResult := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeError)
		w.Write(errResult)
		w.Close()

		var doc sonarQubeDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Issues) != 1 {
			t.Errorf("expected 1 issue for error outcome, got %d", len(doc.Issues))
		}
	})

	t.Run("default tool name is waftester", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSonarQubeWriter(buf, SonarQubeOptions{})

		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var doc sonarQubeDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Issues) > 0 && doc.Issues[0].EngineID != "waftester" {
			t.Errorf("expected default engineId waftester, got %s", doc.Issues[0].EngineID)
		}
	})

	t.Run("SupportsEvent for result and bypass", func(t *testing.T) {
		w := NewSonarQubeWriter(&bytes.Buffer{}, SonarQubeOptions{})
		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should support bypass events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewSonarQubeWriter(&bytes.Buffer{}, SonarQubeOptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})

	t.Run("writes empty issues array when no events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewSonarQubeWriter(buf, SonarQubeOptions{})
		w.Close()

		var doc sonarQubeDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid SonarQube JSON: %v", err)
		}

		if doc.Issues == nil {
			t.Error("issues should be empty array, not nil")
		}
		if len(doc.Issues) != 0 {
			t.Errorf("expected 0 issues, got %d", len(doc.Issues))
		}
	})
}

// TestGitLabSASTWriter tests GitLab SAST Report output.
func TestGitLabSASTWriter(t *testing.T) {
	t.Run("produces valid structure", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{
			ScannerID:      "waftester",
			ScannerVersion: "2.5.0",
			ScannerVendor:  "WAFtester",
		})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(bypass); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var doc gitlabSASTDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid GitLab SAST JSON: %v", err)
		}

		// Check version
		if doc.Version != "15.0.0" {
			t.Errorf("expected version 15.0.0, got %s", doc.Version)
		}

		// Check vulnerabilities
		if len(doc.Vulnerabilities) != 1 {
			t.Fatalf("expected 1 vulnerability, got %d", len(doc.Vulnerabilities))
		}

		vuln := doc.Vulnerabilities[0]
		if vuln.Category != "sast" {
			t.Errorf("expected category sast, got %s", vuln.Category)
		}
		if vuln.Severity != "Critical" {
			t.Errorf("expected severity Critical, got %s", vuln.Severity)
		}
		if vuln.Confidence != "High" {
			t.Errorf("expected confidence High, got %s", vuln.Confidence)
		}
		if vuln.Scanner.ID != "waftester" {
			t.Errorf("expected scanner ID waftester, got %s", vuln.Scanner.ID)
		}
		if vuln.Location.File != "https://example.com/api" {
			t.Errorf("expected location file https://example.com/api, got %s", vuln.Location.File)
		}
		if vuln.Location.StartLine != 1 {
			t.Errorf("expected start_line 1, got %d", vuln.Location.StartLine)
		}

		// Check scan section
		if doc.Scan.Type != "sast" {
			t.Errorf("expected scan type sast, got %s", doc.Scan.Type)
		}
		if doc.Scan.Status != "success" {
			t.Errorf("expected scan status success, got %s", doc.Scan.Status)
		}
		if doc.Scan.Scanner.ID != "waftester" {
			t.Errorf("expected scan scanner ID waftester, got %s", doc.Scan.Scanner.ID)
		}
		if doc.Scan.Scanner.Version != "2.5.0" {
			t.Errorf("expected scan scanner version 2.5.0, got %s", doc.Scan.Scanner.Version)
		}
		if doc.Scan.Scanner.Vendor.Name != "WAFtester" {
			t.Errorf("expected vendor name WAFtester, got %s", doc.Scan.Scanner.Vendor.Name)
		}
	})

	t.Run("severity mapping", func(t *testing.T) {
		tests := []struct {
			severity events.Severity
			expected string
		}{
			{events.SeverityCritical, "Critical"},
			{events.SeverityHigh, "High"},
			{events.SeverityMedium, "Medium"},
			{events.SeverityLow, "Low"},
			{events.SeverityInfo, "Info"},
		}

		for _, tc := range tests {
			level := severityToGitLab(tc.severity)
			if level != tc.expected {
				t.Errorf("severity %s: expected %s, got %s", tc.severity, tc.expected, level)
			}
		}
	})

	t.Run("only includes bypass/error outcomes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})

		// Write events with different outcomes
		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBypass)
		blocked := makeTestResultEvent("test-2", "xss", events.SeverityMedium, events.OutcomeBlocked)
		errResult := makeTestResultEvent("test-3", "rce", events.SeverityCritical, events.OutcomeError)
		timeout := makeTestResultEvent("test-4", "lfi", events.SeverityLow, events.OutcomeTimeout)

		w.Write(bypass)
		w.Write(blocked)
		w.Write(errResult)
		w.Write(timeout)
		w.Close()

		var doc gitlabSASTDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid GitLab SAST JSON: %v", err)
		}

		// Should only have bypass and error outcomes (2 vulnerabilities)
		if len(doc.Vulnerabilities) != 2 {
			t.Errorf("expected 2 vulnerabilities (bypass + error), got %d", len(doc.Vulnerabilities))
		}
	})

	t.Run("filters blocked results", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})

		blocked := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBlocked)
		w.Write(blocked)
		w.Close()

		var doc gitlabSASTDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid GitLab SAST JSON: %v", err)
		}

		if len(doc.Vulnerabilities) != 0 {
			t.Error("blocked results should not appear in GitLab SAST output")
		}
	})

	t.Run("includes error outcomes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})

		errResult := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeError)
		w.Write(errResult)
		w.Close()

		var doc gitlabSASTDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Vulnerabilities) != 1 {
			t.Errorf("expected 1 vulnerability for error outcome, got %d", len(doc.Vulnerabilities))
		}
	})

	t.Run("default scanner ID is waftester", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})

		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var doc gitlabSASTDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if doc.Scan.Scanner.ID != "waftester" {
			t.Errorf("expected default scanner ID waftester, got %s", doc.Scan.Scanner.ID)
		}
		if len(doc.Vulnerabilities) > 0 && doc.Vulnerabilities[0].Scanner.ID != "waftester" {
			t.Errorf("expected vulnerability scanner ID waftester, got %s", doc.Vulnerabilities[0].Scanner.ID)
		}
	})

	t.Run("default vendor is WAFtester", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})
		w.Close()

		var doc gitlabSASTDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if doc.Scan.Scanner.Vendor.Name != "WAFtester" {
			t.Errorf("expected default vendor WAFtester, got %s", doc.Scan.Scanner.Vendor.Name)
		}
	})

	t.Run("includes CWE identifiers", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})

		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var doc gitlabSASTDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Vulnerabilities) == 0 {
			t.Fatal("expected at least 1 vulnerability")
		}

		vuln := doc.Vulnerabilities[0]
		if len(vuln.Identifiers) == 0 {
			t.Error("expected at least 1 identifier (CWE)")
		}

		// Check for CWE-89 (SQL Injection)
		foundCWE := false
		for _, id := range vuln.Identifiers {
			if id.Type == "cwe" && id.Value == "89" {
				foundCWE = true
				if id.Name != "CWE-89" {
					t.Errorf("expected CWE name CWE-89, got %s", id.Name)
				}
				if id.URL != "https://cwe.mitre.org/data/definitions/89.html" {
					t.Errorf("unexpected CWE URL: %s", id.URL)
				}
			}
		}
		if !foundCWE {
			t.Error("expected CWE-89 identifier for sqli category")
		}
	})

	t.Run("generates unique vulnerability IDs", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})

		bypass1 := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		bypass2 := makeTestResultEvent("test-2", "sqli", events.SeverityCritical, events.OutcomeBypass)

		w.Write(bypass1)
		w.Write(bypass2)
		w.Close()

		var doc gitlabSASTDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Vulnerabilities) != 2 {
			t.Fatalf("expected 2 vulnerabilities, got %d", len(doc.Vulnerabilities))
		}

		if doc.Vulnerabilities[0].ID == doc.Vulnerabilities[1].ID {
			t.Error("vulnerability IDs should be unique")
		}
	})

	t.Run("SupportsEvent for result and bypass", func(t *testing.T) {
		w := NewGitLabSASTWriter(&bytes.Buffer{}, GitLabSASTOptions{})
		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should support bypass events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewGitLabSASTWriter(&bytes.Buffer{}, GitLabSASTOptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})

	t.Run("writes empty vulnerabilities array when no events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})
		w.Close()

		var doc gitlabSASTDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid GitLab SAST JSON: %v", err)
		}

		if doc.Vulnerabilities == nil {
			t.Error("vulnerabilities should be empty array, not nil")
		}
		if len(doc.Vulnerabilities) != 0 {
			t.Errorf("expected 0 vulnerabilities, got %d", len(doc.Vulnerabilities))
		}
	})

	t.Run("scan times are valid RFC3339", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewGitLabSASTWriter(buf, GitLabSASTOptions{})
		w.Close()

		var doc gitlabSASTDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if _, err := time.Parse(time.RFC3339, doc.Scan.StartTime); err != nil {
			t.Errorf("start_time is not valid RFC3339: %v", err)
		}
		if _, err := time.Parse(time.RFC3339, doc.Scan.EndTime); err != nil {
			t.Errorf("end_time is not valid RFC3339: %v", err)
		}
	})

	t.Run("category name mapping", func(t *testing.T) {
		tests := []struct {
			category string
			expected string
		}{
			{"sqli", "SQL Injection"},
			{"xss", "Cross-Site Scripting"},
			{"rce", "Remote Code Execution"},
			{"unknown", "unknown WAF Bypass"},
		}

		for _, tc := range tests {
			name := categoryToName(tc.category)
			if name != tc.expected {
				t.Errorf("category %s: expected %s, got %s", tc.category, tc.expected, name)
			}
		}
	})
}

// TestDefectDojoWriter tests DefectDojo Generic Findings JSON output.
func TestDefectDojoWriter(t *testing.T) {
	t.Run("produces valid structure", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{
			ToolName:    "waftester",
			ToolVersion: "2.5.0",
		})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(bypass); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var doc defectDojoDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid DefectDojo JSON: %v", err)
		}

		// Check findings array
		if len(doc.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
		}

		finding := doc.Findings[0]
		if finding.Title != "SQL Injection WAF Bypass - sqli-001" {
			t.Errorf("expected title 'SQL Injection WAF Bypass - sqli-001', got %s", finding.Title)
		}
		if finding.Severity != "Critical" {
			t.Errorf("expected severity Critical, got %s", finding.Severity)
		}
		if finding.CWE != 89 {
			t.Errorf("expected CWE 89, got %d", finding.CWE)
		}
		if finding.FilePath != "https://example.com/api" {
			t.Errorf("expected file_path https://example.com/api, got %s", finding.FilePath)
		}
		if finding.Line != 0 {
			t.Errorf("expected line 0, got %d", finding.Line)
		}
		if finding.Verified != false {
			t.Error("expected verified to be false")
		}
		if finding.Active != true {
			t.Error("expected active to be true")
		}
		if finding.Duplicate != false {
			t.Error("expected duplicate to be false")
		}
		if finding.VulnIDFromTool != "sqli-001" {
			t.Errorf("expected vuln_id_from_tool sqli-001, got %s", finding.VulnIDFromTool)
		}
	})

	t.Run("severity mapping", func(t *testing.T) {
		tests := []struct {
			severity events.Severity
			expected string
		}{
			{events.SeverityCritical, "Critical"},
			{events.SeverityHigh, "High"},
			{events.SeverityMedium, "Medium"},
			{events.SeverityLow, "Low"},
			{events.SeverityInfo, "Info"},
		}

		for _, tc := range tests {
			level := severityToDefectDojo(tc.severity)
			if level != tc.expected {
				t.Errorf("severity %s: expected %s, got %s", tc.severity, tc.expected, level)
			}
		}
	})

	t.Run("only includes bypass/error outcomes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{})

		// Write events with different outcomes
		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBypass)
		blocked := makeTestResultEvent("test-2", "xss", events.SeverityMedium, events.OutcomeBlocked)
		errResult := makeTestResultEvent("test-3", "rce", events.SeverityCritical, events.OutcomeError)
		timeout := makeTestResultEvent("test-4", "lfi", events.SeverityLow, events.OutcomeTimeout)

		w.Write(bypass)
		w.Write(blocked)
		w.Write(errResult)
		w.Write(timeout)
		w.Close()

		var doc defectDojoDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid DefectDojo JSON: %v", err)
		}

		// Should only have bypass and error outcomes (2 findings)
		if len(doc.Findings) != 2 {
			t.Errorf("expected 2 findings (bypass + error), got %d", len(doc.Findings))
		}
	})

	t.Run("filters blocked results", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{})

		blocked := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBlocked)
		w.Write(blocked)
		w.Close()

		var doc defectDojoDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid DefectDojo JSON: %v", err)
		}

		if len(doc.Findings) != 0 {
			t.Error("blocked results should not appear in DefectDojo output")
		}
	})

	t.Run("includes error outcomes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{})

		errResult := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeError)
		w.Write(errResult)
		w.Close()

		var doc defectDojoDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Findings) != 1 {
			t.Errorf("expected 1 finding for error outcome, got %d", len(doc.Findings))
		}
	})

	t.Run("default tool name is waftester", func(t *testing.T) {
		w := NewDefectDojoWriter(&bytes.Buffer{}, DefectDojoOptions{})
		if w.opts.ToolName != "waftester" {
			t.Errorf("expected default tool name waftester, got %s", w.opts.ToolName)
		}
	})

	t.Run("SupportsEvent returns true for result and bypass", func(t *testing.T) {
		w := NewDefectDojoWriter(&bytes.Buffer{}, DefectDojoOptions{})
		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should support bypass events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
		if w.SupportsEvent(events.EventTypeSummary) {
			t.Error("should not support summary events")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewDefectDojoWriter(&bytes.Buffer{}, DefectDojoOptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})

	t.Run("writes empty findings array when no events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{})
		w.Close()

		var doc defectDojoDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid DefectDojo JSON: %v", err)
		}

		if doc.Findings == nil {
			t.Error("findings should be empty array, not nil")
		}
		if len(doc.Findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(doc.Findings))
		}
	})

	t.Run("date is valid YYYY-MM-DD format", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{})

		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityHigh, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var doc defectDojoDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
		}

		dateStr := doc.Findings[0].Date
		if _, err := time.Parse("2006-01-02", dateStr); err != nil {
			t.Errorf("date is not valid YYYY-MM-DD format: %s", dateStr)
		}
	})

	t.Run("includes references with OWASP and CWE", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var doc defectDojoDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
		}

		refs := doc.Findings[0].References
		if !strings.Contains(refs, "OWASP") {
			t.Error("references should contain OWASP")
		}
		if !strings.Contains(refs, "CWE-89") {
			t.Error("references should contain CWE-89 for SQL injection")
		}
	})

	t.Run("includes mitigation", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{})

		bypass := makeTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var doc defectDojoDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
		}

		mitigation := doc.Findings[0].Mitigation
		if mitigation == "" {
			t.Error("mitigation should not be empty")
		}
		if !strings.Contains(mitigation, "xss") {
			t.Error("mitigation should reference the attack category")
		}
	})

	t.Run("includes impact", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewDefectDojoWriter(buf, DefectDojoOptions{})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var doc defectDojoDocument
		json.Unmarshal(buf.Bytes(), &doc)

		if len(doc.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
		}

		impact := doc.Findings[0].Impact
		if impact == "" {
			t.Error("impact should not be empty")
		}
		if !strings.Contains(impact, "SQL") {
			t.Error("impact should describe SQL injection consequence")
		}
	})

	t.Run("CWE mapping for different categories", func(t *testing.T) {
		tests := []struct {
			category    string
			expectedCWE int
		}{
			{"sqli", 89},
			{"xss", 79},
			{"rce", 94},
			{"lfi", 22},
			{"ssrf", 918},
			{"xxe", 611},
			{"cmdi", 78},
			{"ldap", 90},
		}

		for _, tc := range tests {
			buf := &bytes.Buffer{}
			w := NewDefectDojoWriter(buf, DefectDojoOptions{})

			bypass := makeTestResultEvent("test-1", tc.category, events.SeverityHigh, events.OutcomeBypass)
			w.Write(bypass)
			w.Close()

			var doc defectDojoDocument
			json.Unmarshal(buf.Bytes(), &doc)

			if len(doc.Findings) != 1 {
				t.Fatalf("category %s: expected 1 finding, got %d", tc.category, len(doc.Findings))
			}

			if doc.Findings[0].CWE != tc.expectedCWE {
				t.Errorf("category %s: expected CWE %d, got %d", tc.category, tc.expectedCWE, doc.Findings[0].CWE)
			}
		}
	})
}

// TestHARWriter tests HAR 1.2 output.
func TestHARWriter(t *testing.T) {
	t.Run("produces valid HAR structure", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{
			CreatorName:    "waftester",
			CreatorVersion: "2.5.0",
		})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(bypass); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var har harDocument
		if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
			t.Fatalf("invalid HAR JSON: %v", err)
		}

		if har.Log.Version != "1.2" {
			t.Errorf("expected version 1.2, got %s", har.Log.Version)
		}

		if har.Log.Creator.Name != "waftester" {
			t.Errorf("expected creator name waftester, got %s", har.Log.Creator.Name)
		}

		if har.Log.Creator.Version != "2.5.0" {
			t.Errorf("expected creator version 2.5.0, got %s", har.Log.Creator.Version)
		}

		if len(har.Log.Entries) != 1 {
			t.Errorf("expected 1 entry, got %d", len(har.Log.Entries))
		}
	})

	t.Run("default creator name is waftester", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		bypass := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if har.Log.Creator.Name != "waftester" {
			t.Errorf("expected default creator name waftester, got %s", har.Log.Creator.Name)
		}
	})

	t.Run("includes all events by default", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		bypass := makeTestResultEvent("bypass-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		blocked := makeTestResultEvent("blocked-1", "xss", events.SeverityHigh, events.OutcomeBlocked)

		w.Write(bypass)
		w.Write(blocked)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries) != 2 {
			t.Errorf("expected 2 entries (all events), got %d", len(har.Log.Entries))
		}
	})

	t.Run("OnlyBypasses filters correctly", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{OnlyBypasses: true})

		bypass := makeTestResultEvent("bypass-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		blocked := makeTestResultEvent("blocked-1", "xss", events.SeverityHigh, events.OutcomeBlocked)

		w.Write(bypass)
		w.Write(blocked)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries) != 1 {
			t.Errorf("expected 1 entry (bypass only), got %d", len(har.Log.Entries))
		}
	})

	t.Run("entry contains correct request info", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := &events.ResultEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeResult,
				Time: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
				Scan: "test-scan-123",
			},
			Test: events.TestInfo{
				ID:       "sqli-001",
				Name:     "SQL Injection Test",
				Category: "sqli",
				Severity: events.SeverityCritical,
			},
			Target: events.TargetInfo{
				URL:    "https://example.com/api?id=1",
				Method: "POST",
			},
			Result: events.ResultInfo{
				Outcome:       events.OutcomeBypass,
				StatusCode:    200,
				LatencyMs:     42.5,
				ContentLength: 1024,
			},
			Evidence: &events.Evidence{
				Payload: "' OR '1'='1",
				RequestHeaders: map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				},
			},
		}

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(har.Log.Entries))
		}

		entry := har.Log.Entries[0]
		if entry.Request.Method != "POST" {
			t.Errorf("expected method POST, got %s", entry.Request.Method)
		}
		if entry.Request.URL != "https://example.com/api?id=1" {
			t.Errorf("expected URL https://example.com/api?id=1, got %s", entry.Request.URL)
		}
		if entry.Request.HTTPVersion != "HTTP/1.1" {
			t.Errorf("expected HTTP/1.1, got %s", entry.Request.HTTPVersion)
		}
		if entry.Time != 42.5 {
			t.Errorf("expected time 42.5, got %f", entry.Time)
		}
	})

	t.Run("entry contains correct response info", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Result.StatusCode = 200
		event.Result.ContentLength = 1024

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if entry.Response.Status != 200 {
			t.Errorf("expected status 200, got %d", entry.Response.Status)
		}
		if entry.Response.StatusText != "OK" {
			t.Errorf("expected status text OK, got %s", entry.Response.StatusText)
		}
		if entry.Response.Content.Size != 1024 {
			t.Errorf("expected content size 1024, got %d", entry.Response.Content.Size)
		}
	})

	t.Run("entry contains timings", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Result.LatencyMs = 42.5

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if entry.Timings.Wait != 42.5 {
			t.Errorf("expected wait 42.5, got %f", entry.Timings.Wait)
		}
		if entry.Timings.Send != -1 {
			t.Errorf("expected send -1, got %f", entry.Timings.Send)
		}
		if entry.Timings.Receive != -1 {
			t.Errorf("expected receive -1, got %f", entry.Timings.Receive)
		}
	})

	t.Run("entry contains bypass comment", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		bypass := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(bypass)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if !strings.Contains(entry.Comment, "WAF bypass") {
			t.Errorf("expected comment to contain 'WAF bypass', got %s", entry.Comment)
		}
		if !strings.Contains(entry.Comment, "sqli-001") {
			t.Errorf("expected comment to contain test ID, got %s", entry.Comment)
		}
	})

	t.Run("parses query string from URL", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Target.URL = "https://example.com/api?id=1&name=test"

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if len(entry.Request.QueryString) != 2 {
			t.Errorf("expected 2 query params, got %d", len(entry.Request.QueryString))
		}
	})

	t.Run("writes empty entries when no events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})
		w.Close()

		var har harDocument
		if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
			t.Fatalf("invalid HAR JSON: %v", err)
		}

		if har.Log.Entries == nil {
			t.Error("entries should not be nil")
		}
		if len(har.Log.Entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(har.Log.Entries))
		}
	})

	t.Run("SupportsEvent for result and bypass", func(t *testing.T) {
		w := NewHARWriter(&bytes.Buffer{}, HAROptions{})
		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should support bypass events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
		if w.SupportsEvent(events.EventTypeSummary) {
			t.Error("should not support summary events")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewHARWriter(&bytes.Buffer{}, HAROptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})

	t.Run("includes request headers from evidence", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Evidence = &events.Evidence{
			Payload: "test-payload",
			RequestHeaders: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer token",
			},
		}

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if len(entry.Request.Headers) != 2 {
			t.Errorf("expected 2 headers, got %d", len(entry.Request.Headers))
		}
	})

	t.Run("includes postData for POST requests", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Target.Method = "POST"
		event.Evidence = &events.Evidence{
			Payload: "username=admin&password=test",
		}

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if entry.Request.PostData == nil {
			t.Fatal("expected postData to be present for POST request")
		}
		if entry.Request.PostData.Text != "username=admin&password=test" {
			t.Errorf("expected postData text, got %s", entry.Request.PostData.Text)
		}
	})

	t.Run("no postData for GET requests", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Target.Method = "GET"
		event.Evidence = &events.Evidence{
			Payload: "test-payload",
		}

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if entry.Request.PostData != nil {
			t.Error("expected no postData for GET request")
		}
	})

	t.Run("statusText mapping", func(t *testing.T) {
		tests := []struct {
			code     int
			expected string
		}{
			{200, "OK"},
			{201, "Created"},
			{400, "Bad Request"},
			{401, "Unauthorized"},
			{403, "Forbidden"},
			{404, "Not Found"},
			{429, "Too Many Requests"},
			{500, "Internal Server Error"},
			{502, "Bad Gateway"},
			{503, "Service Unavailable"},
			{999, "Status 999"},
		}

		for _, tc := range tests {
			text := statusText(tc.code)
			if text != tc.expected {
				t.Errorf("status %d: expected %s, got %s", tc.code, tc.expected, text)
			}
		}
	})

	t.Run("BypassEvent is converted to HAR entry", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		bypass := &events.BypassEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeBypass,
				Time: time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC),
				Scan: "scan-bypass-test",
			},
			Priority: "critical",
			Alert: events.AlertInfo{
				Title:       "WAF Bypass Detected",
				Description: "SQL injection payload bypassed WAF",
			},
			Details: events.BypassDetail{
				TestID:     "sqli-042",
				Category:   "sqli",
				Severity:   events.SeverityCritical,
				StatusCode: 200,
				Endpoint:   "https://example.com/login",
				Method:     "POST",
				Payload:    "' OR '1'='1",
				OWASP:      []string{"A03:2021"},
				CWE:        []int{89},
			},
		}

		if err := w.Write(bypass); err != nil {
			t.Fatalf("write bypass: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		var har harDocument
		if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
			t.Fatalf("invalid HAR JSON: %v", err)
		}

		if len(har.Log.Entries) != 1 {
			t.Fatalf("expected 1 entry from BypassEvent, got %d", len(har.Log.Entries))
		}

		entry := har.Log.Entries[0]
		if entry.Request.Method != "POST" {
			t.Errorf("method: want POST, got %s", entry.Request.Method)
		}
		if entry.Request.URL != "https://example.com/login" {
			t.Errorf("URL: want https://example.com/login, got %s", entry.Request.URL)
		}
		if entry.Response.Status != 200 {
			t.Errorf("status: want 200, got %d", entry.Response.Status)
		}
		if !strings.Contains(entry.Comment, "WAF bypass") {
			t.Errorf("comment should contain 'WAF bypass', got %s", entry.Comment)
		}
		if !strings.Contains(entry.Comment, "sqli-042") {
			t.Errorf("comment should contain test ID, got %s", entry.Comment)
		}
	})

	t.Run("BypassEvent mixed with ResultEvent", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		result := makeTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBlocked)
		bypass := &events.BypassEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeBypass,
				Time: time.Now(),
				Scan: "scan-mixed",
			},
			Details: events.BypassDetail{
				TestID:     "sqli-042",
				Category:   "sqli",
				Severity:   events.SeverityCritical,
				StatusCode: 200,
				Endpoint:   "https://example.com/api",
				Method:     "GET",
			},
		}

		w.Write(result)
		w.Write(bypass)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries) != 2 {
			t.Errorf("expected 2 entries (ResultEvent + BypassEvent), got %d", len(har.Log.Entries))
		}
	})

	t.Run("OnlyBypasses also includes BypassEvent", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{OnlyBypasses: true})

		blocked := makeTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBlocked)
		bypass := &events.BypassEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeBypass,
				Time: time.Now(),
				Scan: "scan-filtered",
			},
			Details: events.BypassDetail{
				TestID:     "sqli-042",
				Category:   "sqli",
				Severity:   events.SeverityCritical,
				StatusCode: 200,
				Endpoint:   "https://example.com/api",
				Method:     "GET",
			},
		}

		w.Write(blocked) // Should be filtered out
		w.Write(bypass)  // Should be included
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries) != 1 {
			t.Errorf("expected 1 entry (only BypassEvent), got %d", len(har.Log.Entries))
		}
	})

	t.Run("Close closes underlying writer on encode error", func(t *testing.T) {
		fw := &failWriter{failOnWrite: true}
		w := NewHARWriter(fw, HAROptions{})

		result := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(result)

		err := w.Close()
		if err == nil {
			t.Fatal("expected error from Close when write fails")
		}
		if !fw.closed {
			t.Error("underlying writer was not closed on encode error")
		}
	})

	t.Run("Close returns close error when encode succeeds", func(t *testing.T) {
		fw := &failWriter{failOnClose: true}
		w := NewHARWriter(fw, HAROptions{})

		err := w.Close()
		if err == nil {
			t.Fatal("expected error from Close")
		}
		if !strings.Contains(err.Error(), "har: close:") {
			t.Errorf("expected 'har: close:' prefix, got: %v", err)
		}
	})

	t.Run("headers are sorted deterministically", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			buf := &bytes.Buffer{}
			w := NewHARWriter(buf, HAROptions{})

			event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
			event.Evidence = &events.Evidence{
				Payload: "test",
				RequestHeaders: map[string]string{
					"Z-Custom":      "last",
					"Authorization": "Bearer token",
					"Accept":        "text/html",
					"Content-Type":  "application/json",
				},
			}

			w.Write(event)
			w.Close()

			var har harDocument
			json.Unmarshal(buf.Bytes(), &har)

			headers := har.Log.Entries[0].Request.Headers
			if len(headers) != 4 {
				t.Fatalf("expected 4 headers, got %d", len(headers))
			}
			if headers[0].Name != "Accept" {
				t.Errorf("iteration %d: first header should be Accept, got %s", i, headers[0].Name)
			}
			if headers[1].Name != "Authorization" {
				t.Errorf("iteration %d: second header should be Authorization, got %s", i, headers[1].Name)
			}
			if headers[2].Name != "Content-Type" {
				t.Errorf("iteration %d: third header should be Content-Type, got %s", i, headers[2].Name)
			}
			if headers[3].Name != "Z-Custom" {
				t.Errorf("iteration %d: fourth header should be Z-Custom, got %s", i, headers[3].Name)
			}
		}
	})

	t.Run("query params are sorted deterministically", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			buf := &bytes.Buffer{}
			w := NewHARWriter(buf, HAROptions{})

			event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
			event.Target.URL = "https://example.com/api?z=3&a=1&m=2"

			w.Write(event)
			w.Close()

			var har harDocument
			json.Unmarshal(buf.Bytes(), &har)

			params := har.Log.Entries[0].Request.QueryString
			if len(params) != 3 {
				t.Fatalf("expected 3 params, got %d", len(params))
			}
			if params[0].Name != "a" {
				t.Errorf("iteration %d: first param should be 'a', got %s", i, params[0].Name)
			}
			if params[1].Name != "m" {
				t.Errorf("iteration %d: second param should be 'm', got %s", i, params[1].Name)
			}
			if params[2].Name != "z" {
				t.Errorf("iteration %d: third param should be 'z', got %s", i, params[2].Name)
			}
		}
	})

	t.Run("statusText covers WAF-relevant codes via http.StatusText", func(t *testing.T) {
		wafCodes := []struct {
			code     int
			expected string
		}{
			{406, "Not Acceptable"},
			{418, "I'm a teapot"},
			{429, "Too Many Requests"},
			{451, "Unavailable For Legal Reasons"},
			{511, "Network Authentication Required"},
		}

		for _, tc := range wafCodes {
			text := statusText(tc.code)
			if text != tc.expected {
				t.Errorf("status %d: expected %q, got %q", tc.code, tc.expected, text)
			}
		}
	})

	t.Run("response MIME inferred from ResponsePreview content", func(t *testing.T) {
		tests := []struct {
			name            string
			responsePreview string
			wantMIME        string
		}{
			{"json response", `{"error":"forbidden"}`, "application/json"},
			{"xml response", `<?xml version="1.0"?><error/>`, "application/xml"},
			{"html response", "<html><body>Blocked</body></html>", "text/html"},
			{"plain text response", "Access denied", "text/plain"},
			{"no preview", "", "text/html"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				buf := &bytes.Buffer{}
				w := NewHARWriter(buf, HAROptions{})

				event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
				if tc.responsePreview != "" {
					event.Evidence = &events.Evidence{
						Payload:         "test",
						ResponsePreview: tc.responsePreview,
					}
				} else {
					event.Evidence = nil
				}

				w.Write(event)
				w.Close()

				var har harDocument
				json.Unmarshal(buf.Bytes(), &har)

				got := har.Log.Entries[0].Response.Content.MimeType
				if got != tc.wantMIME {
					t.Errorf("MIME: want %s, got %s", tc.wantMIME, got)
				}
			})
		}
	})

	t.Run("postData uses actual Content-Type from headers", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Target.Method = "POST"
		event.Evidence = &events.Evidence{
			Payload:        `{"username":"admin"}`,
			RequestHeaders: map[string]string{"Content-Type": "application/json"},
		}

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		pd := har.Log.Entries[0].Request.PostData
		if pd == nil {
			t.Fatal("expected postData for POST with JSON body")
		}
		if pd.MimeType != "application/json" {
			t.Errorf("postData MIME: want application/json, got %s", pd.MimeType)
		}
	})

	t.Run("unknown event types are silently ignored", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		progress := &events.ProgressEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeProgress,
				Time: time.Now(),
				Scan: "test",
			},
		}

		if err := w.Write(progress); err != nil {
			t.Fatalf("Write should not error on unsupported event: %v", err)
		}

		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries) != 0 {
			t.Errorf("expected 0 entries for unsupported event, got %d", len(har.Log.Entries))
		}
	})

	t.Run("nil evidence produces safe defaults", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Evidence = nil

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if entry.Request.BodySize != -1 {
			t.Errorf("expected bodySize -1 with nil evidence, got %d", entry.Request.BodySize)
		}
		if len(entry.Request.Headers) != 0 {
			t.Errorf("expected 0 headers with nil evidence, got %d", len(entry.Request.Headers))
		}
		if entry.Request.PostData != nil {
			t.Error("expected nil postData with nil evidence")
		}
		if entry.Response.Content.MimeType != "text/html" {
			t.Errorf("expected text/html fallback MIME, got %s", entry.Response.Content.MimeType)
		}
	})

	t.Run("write after close is silently ignored", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(event)
		w.Close()

		// Capture what was written
		firstOutput := buf.String()

		// Write after close should not panic or modify output
		if err := w.Write(event); err != nil {
			t.Fatalf("Write after Close should not error: %v", err)
		}

		if buf.String() != firstOutput {
			t.Error("Write after Close modified the output buffer")
		}
	})

	t.Run("double close is idempotent", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(event)

		if err := w.Close(); err != nil {
			t.Fatalf("first Close failed: %v", err)
		}
		firstOutput := buf.String()

		if err := w.Close(); err != nil {
			t.Fatalf("second Close should not error: %v", err)
		}

		if buf.String() != firstOutput {
			t.Error("double Close produced additional output")
		}
	})

	t.Run("bypassToResult defaults empty method to GET", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		bypass := &events.BypassEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeBypass,
				Time: time.Now(),
				Scan: "scan-empty-method",
			},
			Details: events.BypassDetail{
				TestID:     "sqli-001",
				Category:   "sqli",
				Severity:   events.SeverityCritical,
				StatusCode: 200,
				Endpoint:   "https://example.com/api",
				// Method intentionally empty
			},
		}

		w.Write(bypass)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(har.Log.Entries))
		}
		if har.Log.Entries[0].Request.Method != "GET" {
			t.Errorf("expected default method GET, got %s", har.Log.Entries[0].Request.Method)
		}
	})

	t.Run("EncodedPayload preferred over raw Payload", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Target.Method = "POST"
		event.Evidence = &events.Evidence{
			Payload:        "' OR 1=1",
			EncodedPayload: "%27%20OR%201%3D1",
		}

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if entry.Request.PostData == nil {
			t.Fatal("expected postData")
		}
		if entry.Request.PostData.Text != "%27%20OR%201%3D1" {
			t.Errorf("postData should use EncodedPayload, got %s", entry.Request.PostData.Text)
		}
		if entry.Request.BodySize != len("%27%20OR%201%3D1") {
			t.Errorf("bodySize should reflect EncodedPayload length, got %d", entry.Request.BodySize)
		}
	})

	t.Run("ResponsePreview mapped to content text", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Evidence = &events.Evidence{
			Payload:         "test",
			ResponsePreview: `{"error": "blocked by WAF"}`,
		}
		event.Result.ContentLength = 0

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		content := har.Log.Entries[0].Response.Content
		if content.Text != `{"error": "blocked by WAF"}` {
			t.Errorf("content.text should contain ResponsePreview, got %s", content.Text)
		}
		if content.MimeType != "application/json" {
			t.Errorf("content MIME should be inferred as JSON from preview, got %s", content.MimeType)
		}
		if content.Size != 0 {
			t.Errorf("content.size should remain 0 (unknown) when ContentLength is 0, got %d", content.Size)
		}
	})

	t.Run("CreatorVersion defaults to defaults.Version", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if har.Log.Creator.Version == "" {
			t.Error("creator version should not be empty when using defaults")
		}
	})

	t.Run("DELETE method includes postData", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		event.Target.Method = "DELETE"
		event.Evidence = &events.Evidence{
			Payload: `{"id": 42}`,
		}

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		entry := har.Log.Entries[0]
		if entry.Request.PostData == nil {
			t.Error("expected postData for DELETE with body")
		}
	})

	t.Run("trailing question mark in URL produces no empty query params", func(t *testing.T) {
		params := extractQueryParams("https://example.com/api?")
		if len(params) != 0 {
			t.Errorf("expected 0 params for trailing ?, got %d: %+v", len(params), params)
		}

		params = extractQueryParams("https://example.com/api?&")
		if len(params) != 0 {
			t.Errorf("expected 0 params for ?&, got %d: %+v", len(params), params)
		}
	})

	t.Run("buildComment handles empty fields gracefully", func(t *testing.T) {
		event := &events.ResultEvent{
			BaseEvent: events.BaseEvent{Type: events.EventTypeResult},
			Test:      events.TestInfo{},
			Result:    events.ResultInfo{},
		}

		comment := buildComment(event)
		if comment != "" {
			t.Errorf("expected empty comment for empty fields, got %q", comment)
		}

		// Only outcome set
		event.Result.Outcome = events.OutcomeBlocked
		comment = buildComment(event)
		if comment != "blocked" {
			t.Errorf("expected 'blocked', got %q", comment)
		}

		// Only ID set
		event.Result.Outcome = ""
		event.Test.ID = "test-1"
		comment = buildComment(event)
		if comment != "test-1" {
			t.Errorf("expected 'test-1', got %q", comment)
		}
	})

	t.Run("startedDateTime has consistent millisecond precision", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		event := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		// Use a time with zero nanoseconds to verify we get .000 not truncation
		event.Time = time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

		w.Write(event)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		ts := har.Log.Entries[0].StartedDateTime
		if !strings.Contains(ts, ".000") {
			t.Errorf("expected millisecond precision (.000), got %s", ts)
		}
	})

	t.Run("HAR output includes pages array", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})
		w.Close()

		// Parse as generic map to check pages field
		var raw map[string]any
		json.Unmarshal(buf.Bytes(), &raw)

		logObj := raw["log"].(map[string]any)
		pages, ok := logObj["pages"]
		if !ok {
			t.Fatal("HAR log should contain 'pages' array")
		}
		pageArr, ok := pages.([]any)
		if !ok {
			t.Fatal("pages should be an array")
		}
		if len(pageArr) != 0 {
			t.Errorf("pages should be empty array, got %d items", len(pageArr))
		}
	})

	t.Run("inferMIMEFromContent identifies formats correctly", func(t *testing.T) {
		tests := []struct {
			content  string
			wantMIME string
		}{
			{`{"key":"val"}`, "application/json"},
			{`[1,2,3]`, "application/json"},
			{`  {"spaced": true}`, "application/json"},
			{`<?xml version="1.0"?><root/>`, "application/xml"},
			{`<html><body>test</body></html>`, "text/html"},
			{`Access denied`, "text/plain"},
			{``, "text/html"},
			{`   `, "text/html"},
		}

		for _, tc := range tests {
			got := inferMIMEFromContent(tc.content)
			if got != tc.wantMIME {
				t.Errorf("inferMIMEFromContent(%q): want %s, got %s", tc.content, tc.wantMIME, got)
			}
		}
	})

	t.Run("effectivePayload prefers EncodedPayload", func(t *testing.T) {
		ev := &events.Evidence{
			Payload:        "raw",
			EncodedPayload: "encoded",
		}
		if got := effectivePayload(ev); got != "encoded" {
			t.Errorf("expected encoded, got %s", got)
		}

		ev.EncodedPayload = ""
		if got := effectivePayload(ev); got != "raw" {
			t.Errorf("expected raw, got %s", got)
		}

		if got := effectivePayload(nil); got != "" {
			t.Errorf("expected empty for nil evidence, got %s", got)
		}
	})

	t.Run("empty method defaults to GET in resultToEntry", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		re.Target.Method = "" // empty method
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(har.Log.Entries))
		}
		if har.Log.Entries[0].Request.Method != "GET" {
			t.Errorf("expected empty method to default to GET, got %q", har.Log.Entries[0].Request.Method)
		}
	})

	t.Run("evasion context appears in comment", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		re.Context = &events.ContextInfo{
			Encoding:         "unicode",
			Tamper:           "case-swap",
			EvasionTechnique: "double-encode",
		}
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		comment := har.Log.Entries[0].Comment
		if !strings.Contains(comment, "encoding: unicode") {
			t.Errorf("comment should contain encoding, got: %s", comment)
		}
		if !strings.Contains(comment, "tamper: case-swap") {
			t.Errorf("comment should contain tamper, got: %s", comment)
		}
		if !strings.Contains(comment, "evasion: double-encode") {
			t.Errorf("comment should contain evasion technique, got: %s", comment)
		}
	})

	t.Run("evasion context omitted when nil context", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		re.Context = nil
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		comment := har.Log.Entries[0].Comment
		if strings.Contains(comment, "(") {
			t.Errorf("comment should not contain context parens when nil, got: %s", comment)
		}
	})

	t.Run("Cookie header parsed into request cookies", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		re.Evidence = &events.Evidence{
			Payload: "<script>alert(1)</script>",
			RequestHeaders: map[string]string{
				"Cookie": "session=abc123; lang=en; theme=dark",
			},
		}
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		cookies := har.Log.Entries[0].Request.Cookies
		if len(cookies) != 3 {
			t.Fatalf("expected 3 cookies, got %d", len(cookies))
		}

		// Check all cookie names exist
		cookieMap := make(map[string]string)
		for _, c := range cookies {
			cookieMap[c.Name] = c.Value
		}
		if cookieMap["session"] != "abc123" {
			t.Errorf("session cookie: want abc123, got %s", cookieMap["session"])
		}
		if cookieMap["lang"] != "en" {
			t.Errorf("lang cookie: want en, got %s", cookieMap["lang"])
		}
		if cookieMap["theme"] != "dark" {
			t.Errorf("theme cookie: want dark, got %s", cookieMap["theme"])
		}
	})

	t.Run("no Cookie header produces empty cookies array", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		re.Evidence = &events.Evidence{
			Payload: "test",
			RequestHeaders: map[string]string{
				"Content-Type": "text/plain",
			},
		}
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		if len(har.Log.Entries[0].Request.Cookies) != 0 {
			t.Errorf("expected empty cookies, got %d", len(har.Log.Entries[0].Request.Cookies))
		}
	})

	t.Run("form-encoded postData includes params", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		re.Target.Method = "POST"
		re.Evidence = &events.Evidence{
			Payload: "user=admin&pass=secret&action=login",
			RequestHeaders: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
		}
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		pd := har.Log.Entries[0].Request.PostData
		if pd == nil {
			t.Fatal("expected postData for POST request")
		}
		if len(pd.Params) != 3 {
			t.Fatalf("expected 3 form params, got %d", len(pd.Params))
		}

		paramMap := make(map[string]string)
		for _, p := range pd.Params {
			paramMap[p.Name] = p.Value
		}
		if paramMap["user"] != "admin" {
			t.Errorf("user param: want admin, got %s", paramMap["user"])
		}
		if paramMap["pass"] != "secret" {
			t.Errorf("pass param: want secret, got %s", paramMap["pass"])
		}
	})

	t.Run("non-form postData has no params", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		re.Target.Method = "POST"
		re.Evidence = &events.Evidence{
			Payload: `{"admin": true}`,
			RequestHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		}
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		pd := har.Log.Entries[0].Request.PostData
		if pd == nil {
			t.Fatal("expected postData for POST request")
		}
		if pd.Params != nil {
			t.Errorf("JSON postData should have nil params, got %d", len(pd.Params))
		}
	})

	t.Run("atomic write prevents partial output on write error", func(t *testing.T) {
		fw := &failWriter{failOnWrite: true}
		w := NewHARWriter(fw, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		w.Write(re)
		err := w.Close()
		if err == nil {
			t.Fatal("expected error from failing writer")
		}

		// The key behavior: failWriter should have received zero bytes
		// because encoding goes to an intermediate buffer first.
		if !strings.Contains(err.Error(), "har: write:") {
			t.Errorf("expected har: write: error, got: %v", err)
		}
	})

	t.Run("parseCookieHeader handles edge cases", func(t *testing.T) {
		tests := []struct {
			name   string
			header string
			want   int
		}{
			{"empty", "", 0},
			{"single", "session=abc", 1},
			{"multiple", "a=1; b=2; c=3", 3},
			{"trailing semicolon", "a=1; b=2;", 2},
			{"empty segments", "a=1;; b=2", 2},
			{"value with equals", "token=abc=def", 1},
			{"no value", "flag", 1},
			{"whitespace only", "  ;  ;  ", 0},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got := parseCookieHeader(tc.header)
				if len(got) != tc.want {
					t.Errorf("parseCookieHeader(%q): want %d cookies, got %d: %+v", tc.header, tc.want, len(got), got)
				}
			})
		}

		// Check value with equals sign preserves everything after first =
		cookies := parseCookieHeader("token=abc=def")
		if cookies[0].Value != "abc=def" {
			t.Errorf("expected value abc=def, got %s", cookies[0].Value)
		}
	})

	t.Run("buildFormParams returns nil for non-form types", func(t *testing.T) {
		if got := buildFormParams("application/json", `{"a":1}`); got != nil {
			t.Errorf("expected nil for JSON, got %v", got)
		}
		if got := buildFormParams("text/plain", "hello"); got != nil {
			t.Errorf("expected nil for text/plain, got %v", got)
		}
	})

	t.Run("buildFormParams parses url-encoded body", func(t *testing.T) {
		params := buildFormParams("application/x-www-form-urlencoded", "a=1&b=2&a=3")
		if params == nil {
			t.Fatal("expected params for form-urlencoded")
		}
		if len(params) != 3 {
			t.Fatalf("expected 3 params (a has 2 values), got %d", len(params))
		}
	})

	t.Run("buildContextTag formats evasion info", func(t *testing.T) {
		// nil context
		if got := buildContextTag(nil); got != "" {
			t.Errorf("nil context: expected empty, got %q", got)
		}

		// empty context
		if got := buildContextTag(&events.ContextInfo{}); got != "" {
			t.Errorf("empty context: expected empty, got %q", got)
		}

		// partial context
		got := buildContextTag(&events.ContextInfo{Encoding: "base64"})
		if got != "(encoding: base64)" {
			t.Errorf("partial context: expected (encoding: base64), got %q", got)
		}

		// full context
		got = buildContextTag(&events.ContextInfo{
			Encoding:         "unicode",
			Tamper:           "case-swap",
			EvasionTechnique: "double-encode",
		})
		if !strings.Contains(got, "encoding: unicode") || !strings.Contains(got, "tamper: case-swap") || !strings.Contains(got, "evasion: double-encode") {
			t.Errorf("full context missing fields: %q", got)
		}
	})

	t.Run("ResponsePreview size not used as content.size", func(t *testing.T) {
		// F1: ResponsePreview is a truncated snippet. Its length should not
		// be used as the content size when ContentLength is 0 (unknown).
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		re.Evidence = &events.Evidence{
			Payload:         "test",
			ResponsePreview: strings.Repeat("x", 512), // 512-byte preview of a much larger response
		}
		re.Result.ContentLength = 0

		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		content := har.Log.Entries[0].Response.Content
		if content.Size != 0 {
			t.Errorf("content.size should remain 0 (unknown), not preview length %d", content.Size)
		}
		if content.Text == "" {
			t.Error("content.text should still contain the preview")
		}
	})

	t.Run("ResponsePreview with known ContentLength preserves size", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		re.Evidence = &events.Evidence{
			Payload:         "test",
			ResponsePreview: `{"error": "blocked"}`,
		}
		re.Result.ContentLength = 4096

		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		content := har.Log.Entries[0].Response.Content
		if content.Size != 4096 {
			t.Errorf("content.size should be ContentLength 4096, got %d", content.Size)
		}
	})

	t.Run("BypassEvent propagates WAFDetected to WAFSignature", func(t *testing.T) {
		// F2: WAFDetected from AlertContext should carry through to the
		// synthetic ResultEvent as WAFSignature.
		be := &events.BypassEvent{
			BaseEvent: events.BaseEvent{Type: events.EventTypeBypass},
			Details: events.BypassDetail{
				TestID:   "sqli-001",
				Category: "sqli",
				Endpoint: "https://example.com/api",
				Method:   "POST",
				Payload:  "' OR 1=1--",
			},
			Context: events.AlertContext{
				WAFDetected: "Cloudflare",
			},
		}

		re := bypassToResult(be)
		if re.Result.WAFSignature != "Cloudflare" {
			t.Errorf("WAFSignature should be Cloudflare, got %q", re.Result.WAFSignature)
		}
	})

	t.Run("BypassEvent with empty WAFDetected", func(t *testing.T) {
		be := &events.BypassEvent{
			BaseEvent: events.BaseEvent{Type: events.EventTypeBypass},
			Details: events.BypassDetail{
				TestID:   "xss-001",
				Category: "xss",
				Endpoint: "https://example.com",
			},
		}

		re := bypassToResult(be)
		if re.Result.WAFSignature != "" {
			t.Errorf("WAFSignature should be empty when WAFDetected is empty, got %q", re.Result.WAFSignature)
		}
	})

	t.Run("form-encoded with charset parameter in Content-Type", func(t *testing.T) {
		// F3: Content-Type with parameters like "; charset=utf-8" should
		// still match application/x-www-form-urlencoded.
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		re.Target.Method = "POST"
		re.Evidence = &events.Evidence{
			Payload: "user=admin&role=root",
			RequestHeaders: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
			},
		}
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		pd := har.Log.Entries[0].Request.PostData
		if pd == nil {
			t.Fatal("expected postData for form-encoded POST")
		}
		if pd.MimeType != "application/x-www-form-urlencoded; charset=utf-8" {
			t.Errorf("postData.mimeType should preserve full Content-Type, got %s", pd.MimeType)
		}
		if len(pd.Params) != 2 {
			t.Fatalf("expected 2 form params despite charset parameter, got %d", len(pd.Params))
		}
	})

	t.Run("baseMIMEType strips parameters", func(t *testing.T) {
		tests := []struct {
			input string
			want  string
		}{
			{"application/json", "application/json"},
			{"application/x-www-form-urlencoded; charset=utf-8", "application/x-www-form-urlencoded"},
			{"text/html; charset=ISO-8859-1", "text/html"},
			{"multipart/form-data; boundary=----", "multipart/form-data"},
			{"", ""},
		}
		for _, tc := range tests {
			got := baseMIMEType(tc.input)
			if got != tc.want {
				t.Errorf("baseMIMEType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		}
	})

	t.Run("case-insensitive Cookie header lookup", func(t *testing.T) {
		// F4: HTTP/2 normalizes headers to lowercase.
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		re.Evidence = &events.Evidence{
			Payload: "test",
			RequestHeaders: map[string]string{
				"cookie": "session=abc; lang=en", // lowercase (HTTP/2 style)
			},
		}
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		cookies := har.Log.Entries[0].Request.Cookies
		if len(cookies) != 2 {
			t.Fatalf("expected 2 cookies from lowercase cookie header, got %d", len(cookies))
		}
	})

	t.Run("case-insensitive Content-Type header lookup", func(t *testing.T) {
		// F4+F5: Content-Type lookup in postData should also be case-insensitive.
		buf := &bytes.Buffer{}
		w := NewHARWriter(buf, HAROptions{})

		re := makeTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass)
		re.Target.Method = "POST"
		re.Evidence = &events.Evidence{
			Payload: `{"admin": true}`,
			RequestHeaders: map[string]string{
				"content-type": "application/json", // lowercase (HTTP/2 style)
			},
		}
		w.Write(re)
		w.Close()

		var har harDocument
		json.Unmarshal(buf.Bytes(), &har)

		pd := har.Log.Entries[0].Request.PostData
		if pd == nil {
			t.Fatal("expected postData for POST with lowercase content-type")
		}
		if pd.MimeType != "application/json" {
			t.Errorf("postData.mimeType should pick up lowercase content-type, got %s", pd.MimeType)
		}
	})

	t.Run("headerValue case insensitive with fast path", func(t *testing.T) {
		headers := map[string]string{
			"Content-Type": "text/html",
			"cookie":       "session=abc",
			"X-Custom":     "value",
		}

		// Exact match (fast path)
		if got := headerValue(headers, "Content-Type"); got != "text/html" {
			t.Errorf("exact match: want text/html, got %s", got)
		}

		// Case-insensitive (slow path)
		if got := headerValue(headers, "content-type"); got != "text/html" {
			t.Errorf("case-insensitive: want text/html, got %s", got)
		}

		// Uppercase cookie
		if got := headerValue(headers, "Cookie"); got != "session=abc" {
			t.Errorf("uppercase Cookie: want session=abc, got %s", got)
		}

		// Nil headers
		if got := headerValue(nil, "Content-Type"); got != "" {
			t.Errorf("nil headers: want empty, got %s", got)
		}

		// Missing header
		if got := headerValue(headers, "Authorization"); got != "" {
			t.Errorf("missing header: want empty, got %s", got)
		}
	})
}
