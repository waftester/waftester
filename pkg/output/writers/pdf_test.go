package writers

import (
	"bytes"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// makePDFTestResultEvent creates a test result event for PDF tests.
func makePDFTestResultEvent(id, category string, severity events.Severity, outcome events.Outcome, owasp []string) *events.ResultEvent {
	return &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-pdf-123",
		},
		Test: events.TestInfo{
			ID:       id,
			Name:     id + " test",
			Category: category,
			Severity: severity,
			OWASP:    owasp,
			CWE:      []int{89, 79},
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
			Payload:     "test-payload-" + id,
			CurlCommand: "curl -X POST 'https://example.com/api' -d 'payload=...'",
		},
	}
}

// makePDFTestSummaryEvent creates a test summary event for PDF tests.
func makePDFTestSummaryEvent() *events.SummaryEvent {
	return &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: time.Now(),
			Scan: "test-scan-pdf-123",
		},
		Version: "2.5.0",
		Target: events.SummaryTarget{
			URL:           "https://example.com",
			WAFDetected:   "Cloudflare",
			WAFConfidence: 0.95,
		},
		Totals: events.SummaryTotals{
			Tests:    100,
			Bypasses: 5,
			Blocked:  90,
			Errors:   3,
			Passes:   0,
			Timeouts: 2,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct:   90.0,
			Grade:          "A",
			Recommendation: "Consider enabling additional rules for injection attacks.",
		},
		Breakdown: events.BreakdownInfo{
			BySeverity: map[string]events.CategoryStats{
				"critical": {Total: 10, Bypasses: 2, BlockRate: 80.0},
				"high":     {Total: 20, Bypasses: 2, BlockRate: 90.0},
				"medium":   {Total: 30, Bypasses: 1, BlockRate: 96.7},
				"low":      {Total: 25, Bypasses: 0, BlockRate: 100.0},
				"info":     {Total: 15, Bypasses: 0, BlockRate: 100.0},
			},
			ByCategory: map[string]events.CategoryStats{
				"sqli": {Total: 40, Bypasses: 3, BlockRate: 92.5},
				"xss":  {Total: 35, Bypasses: 2, BlockRate: 94.3},
			},
			ByOWASP: map[string]events.OWASPStats{
				"A03:2021": {Name: "Injection", Total: 40, Bypasses: 3},
				"A07:2021": {Name: "Identification and Authentication Failures", Total: 10, Bypasses: 0},
			},
		},
		Timing: events.SummaryTiming{
			StartedAt:      time.Now().Add(-5 * time.Minute),
			CompletedAt:    time.Now(),
			DurationSec:    300.0,
			RequestsPerSec: 0.33,
		},
		ExitCode:   0,
		ExitReason: "completed",
	}
}

func TestPDFWriter_GeneratesValidPDF(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{
		Title:           "Test Security Report",
		CompanyName:     "Test Company",
		Author:          "Security Team",
		IncludeEvidence: true,
		PageSize:        "A4",
		Orientation:     "P",
	})

	e := makePDFTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, []string{"A03:2021"})
	if err := w.Write(e); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	summary := makePDFTestSummaryEvent()
	if err := w.Write(summary); err != nil {
		t.Fatalf("write summary failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.Bytes()

	// Check for PDF magic number
	if len(output) < 4 || string(output[:4]) != "%PDF" {
		t.Error("expected output to start with PDF magic number")
	}

	// Check for PDF end marker
	if !bytes.Contains(output, []byte("%%EOF")) {
		t.Error("expected output to contain PDF end marker")
	}

	// Check minimum size (a valid PDF with content should be reasonably sized)
	if len(output) < 1000 {
		t.Errorf("PDF output seems too small: %d bytes", len(output))
	}
}

func TestPDFWriter_DefaultConfig(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})

	// Should use default values
	if w.config.Title != "WAFtester Security Report" {
		t.Errorf("expected default title, got %q", w.config.Title)
	}
	if w.config.PageSize != "A4" {
		t.Errorf("expected default page size A4, got %q", w.config.PageSize)
	}
	if w.config.Orientation != "P" {
		t.Errorf("expected default orientation P, got %q", w.config.Orientation)
	}
}

func TestPDFWriter_SupportsEvent(t *testing.T) {
	w := NewPDFWriter(&bytes.Buffer{}, PDFConfig{})

	tests := []struct {
		eventType events.EventType
		expected  bool
	}{
		{events.EventTypeResult, true},
		{events.EventTypeSummary, true},
		{events.EventTypeProgress, false},
		{events.EventTypeStart, false},
		{events.EventTypeError, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.eventType), func(t *testing.T) {
			if got := w.SupportsEvent(tc.eventType); got != tc.expected {
				t.Errorf("SupportsEvent(%s) = %v, want %v", tc.eventType, got, tc.expected)
			}
		})
	}
}

func TestPDFWriter_LetterPageSize(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{
		PageSize:    "Letter",
		Orientation: "L",
	})

	e := makePDFTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBypass, nil)
	w.Write(e)
	w.Write(makePDFTestSummaryEvent())
	w.Close()

	output := buf.Bytes()

	// Verify it's still a valid PDF
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output")
	}
}

func TestPDFWriter_MultipleFindings(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{
		Title:           "Multi-Finding Report",
		IncludeEvidence: true,
	})

	// Add multiple findings with different severities and categories
	findings := []struct {
		id       string
		category string
		severity events.Severity
		outcome  events.Outcome
		owasp    []string
	}{
		{"sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, []string{"A03:2021"}},
		{"sqli-002", "sqli", events.SeverityHigh, events.OutcomeBypass, []string{"A03:2021"}},
		{"xss-001", "xss", events.SeverityHigh, events.OutcomeBypass, []string{"A03:2021"}},
		{"xss-002", "xss", events.SeverityMedium, events.OutcomeBlocked, []string{"A03:2021"}},
		{"lfi-001", "lfi", events.SeverityMedium, events.OutcomeBypass, []string{"A01:2021"}},
		{"ssrf-001", "ssrf", events.SeverityLow, events.OutcomeBlocked, []string{"A10:2021"}},
	}

	for _, f := range findings {
		e := makePDFTestResultEvent(f.id, f.category, f.severity, f.outcome, f.owasp)
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed for %s: %v", f.id, err)
		}
	}

	if err := w.Write(makePDFTestSummaryEvent()); err != nil {
		t.Fatalf("write summary failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.Bytes()

	// Verify valid PDF
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output")
	}

	// PDF should be larger with more content
	if len(output) < 5000 {
		t.Errorf("PDF with multiple findings seems too small: %d bytes", len(output))
	}
}

func TestPDFWriter_NoBypassFindings(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{
		Title: "All Blocked Report",
	})

	// Add only blocked results
	e := makePDFTestResultEvent("sqli-001", "sqli", events.SeverityHigh, events.OutcomeBlocked, nil)
	w.Write(e)
	w.Write(makePDFTestSummaryEvent())
	w.Close()

	output := buf.Bytes()

	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output")
	}
}

func TestPDFWriter_FlushIsNoOp(t *testing.T) {
	w := NewPDFWriter(&bytes.Buffer{}, PDFConfig{})

	// Flush should not error and should be a no-op
	if err := w.Flush(); err != nil {
		t.Errorf("Flush() returned error: %v", err)
	}
}

func TestPDFWriter_SeverityColors(t *testing.T) {
	// Verify all severity colors are defined
	severities := []string{"critical", "high", "medium", "low", "info"}

	for _, sev := range severities {
		color, ok := pdfSeverityColors[sev]
		if !ok {
			t.Errorf("missing severity color for %q", sev)
			continue
		}
		if len(color) != 3 {
			t.Errorf("severity color for %q should have 3 components, got %d", sev, len(color))
		}
		for i, c := range color {
			if c < 0 || c > 255 {
				t.Errorf("severity color %q component %d out of range: %d", sev, i, c)
			}
		}
	}
}

func TestPDFWriter_OutcomeColors(t *testing.T) {
	// Verify all outcome colors are defined
	outcomes := []events.Outcome{
		events.OutcomeBypass,
		events.OutcomeBlocked,
		events.OutcomeError,
		events.OutcomeTimeout,
		events.OutcomePass,
	}

	for _, outcome := range outcomes {
		color, ok := pdfOutcomeColors[outcome]
		if !ok {
			t.Errorf("missing outcome color for %q", outcome)
			continue
		}
		if len(color) != 3 {
			t.Errorf("outcome color for %q should have 3 components, got %d", outcome, len(color))
		}
	}
}

func TestPDFWriter_WithoutSummary(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{
		Title: "No Summary Report",
	})

	// Add result without summary
	e := makePDFTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass, nil)
	w.Write(e)

	// Should not panic without summary
	err := w.Close()
	if err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	output := buf.Bytes()
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output even without summary")
	}
}

func TestPDFWriter_OWASPCoverage(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})

	// Add results with various OWASP mappings
	owaspMappings := [][]string{
		{"A01:2021"}, // Broken Access Control
		{"A03:2021"}, // Injection
		{"A03:2021"}, // Injection (duplicate)
		{"A07:2021"}, // Auth failures
		{"A10:2021"}, // SSRF
	}

	for i, owasp := range owaspMappings {
		e := makePDFTestResultEvent(
			"test-"+string(rune('0'+i)),
			"various",
			events.SeverityHigh,
			events.OutcomeBypass,
			owasp,
		)
		w.Write(e)
	}

	w.Write(makePDFTestSummaryEvent())
	w.Close()

	output := buf.Bytes()
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output")
	}
}

func TestPDFWriter_TruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a very long string", 10, "this is..."},
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "..."},
	}

	for _, tc := range tests {
		result := truncateString(tc.input, tc.maxLen)
		if result != tc.expected {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tc.input, tc.maxLen, result, tc.expected)
		}
	}
}

func TestPDFWriter_ConcurrentWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})

	// Concurrent writes should be safe
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(n int) {
			e := makePDFTestResultEvent(
				"concurrent-"+string(rune('0'+n)),
				"test",
				events.SeverityMedium,
				events.OutcomeBypass,
				nil,
			)
			w.Write(e)
			done <- true
		}(i)
	}

	// Wait for all writes
	for i := 0; i < 10; i++ {
		<-done
	}

	w.Write(makePDFTestSummaryEvent())
	err := w.Close()
	if err != nil {
		t.Fatalf("Close() failed after concurrent writes: %v", err)
	}

	output := buf.Bytes()
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output after concurrent writes")
	}
}

func TestPDFWriter_GradeColors(t *testing.T) {
	w := NewPDFWriter(&bytes.Buffer{}, PDFConfig{})

	tests := []struct {
		grade         string
		expectedGreen bool // Should be green (good grade)
	}{
		{"A+", true},
		{"A", true},
		{"A-", true},
		{"B+", false},
		{"B", false},
		{"C", false},
		{"D", false},
		{"F", false},
	}

	for _, tc := range tests {
		color := w.getGradeColor(tc.grade)
		if len(color) != 3 {
			t.Errorf("getGradeColor(%q) should return 3-component color", tc.grade)
			continue
		}

		// Green color check (R < 100, G > 100, B < 100)
		isGreenish := color[1] > color[0] && color[1] > color[2]
		if tc.expectedGreen && !isGreenish {
			t.Errorf("getGradeColor(%q) should return greenish color for good grades", tc.grade)
		}
	}
}

func TestPDFWriter_EvidenceExclusion(t *testing.T) {
	// When IncludeEvidence is explicitly set to false via a custom config
	buf := &bytes.Buffer{}
	config := PDFConfig{
		Title: "No Evidence Report",
	}
	// Manually set to false after creation (since constructor defaults to true)
	w := &PDFWriter{
		w:       buf,
		config:  config,
		results: make([]*events.ResultEvent, 0),
	}
	w.config.IncludeEvidence = false

	e := makePDFTestResultEvent("test-001", "sqli", events.SeverityHigh, events.OutcomeBypass, nil)
	w.Write(e)
	w.Write(makePDFTestSummaryEvent())
	w.Close()

	output := buf.Bytes()
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output")
	}
}

func TestPDFWriter_CompanyBranding(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{
		Title:       "Branded Report",
		CompanyName: "Acme Security Corp",
		Author:      "John Smith",
	})

	w.Write(makePDFTestSummaryEvent())
	if err := w.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	output := buf.Bytes()
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output with branding")
	}

	// Verify the PDF is reasonably sized (branding adds content)
	if len(output) < 2000 {
		t.Errorf("PDF with branding seems too small: %d bytes", len(output))
	}
}

func TestPDFWriter_CategoryGrouping(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})

	// Add findings from multiple categories
	categories := []string{"sqli", "xss", "lfi", "ssrf", "rce"}
	for i, cat := range categories {
		e := makePDFTestResultEvent(
			cat+"-001",
			cat,
			events.SeverityHigh,
			events.OutcomeBypass,
			nil,
		)
		w.results = append(w.results, e)

		// Add second finding to some categories
		if i%2 == 0 {
			e2 := makePDFTestResultEvent(
				cat+"-002",
				cat,
				events.SeverityMedium,
				events.OutcomeBypass,
				nil,
			)
			w.results = append(w.results, e2)
		}
	}

	grouped := w.groupByCategory(w.results)

	// Verify grouping
	if len(grouped) != 5 {
		t.Errorf("expected 5 categories, got %d", len(grouped))
	}

	// sqli, lfi, rce should have 2 findings each
	for _, cat := range []string{"sqli", "lfi", "rce"} {
		if len(grouped[cat]) != 2 {
			t.Errorf("expected 2 findings in %s, got %d", cat, len(grouped[cat]))
		}
	}

	// xss, ssrf should have 1 finding each
	for _, cat := range []string{"xss", "ssrf"} {
		if len(grouped[cat]) != 1 {
			t.Errorf("expected 1 finding in %s, got %d", cat, len(grouped[cat]))
		}
	}
}
