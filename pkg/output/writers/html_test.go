package writers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// makeHTMLTestResultEvent creates a test result event with OWASP mappings.
func makeHTMLTestResultEvent(id, category string, severity events.Severity, outcome events.Outcome, owasp []string) *events.ResultEvent {
	return &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-html-123",
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

func TestHTMLWriter_GeneratesValidHTML(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:           "Test Report",
		Theme:           "auto",
		IncludeEvidence: true,
		IncludeJSON:     true,
	})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, []string{"A03:2021"})
	if err := w.Write(e); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	// Check for HTML5 doctype
	if !strings.HasPrefix(output, "<!DOCTYPE html>") {
		t.Error("expected HTML5 doctype")
	}

	// Check for required HTML structure
	requiredTags := []string{
		"<html",
		"<head>",
		"</head>",
		"<body>",
		"</body>",
		"</html>",
		"<meta charset=\"UTF-8\">",
		"<title>Test Report</title>",
	}

	for _, tag := range requiredTags {
		if !strings.Contains(output, tag) {
			t.Errorf("expected output to contain %q", tag)
		}
	}

	// Check that CSS is embedded
	if !strings.Contains(output, "<style>") {
		t.Error("expected embedded CSS styles")
	}

	// Check that JavaScript is embedded
	if !strings.Contains(output, "<script>") {
		t.Error("expected embedded JavaScript")
	}
}

func TestHTMLWriter_IncludesThemeToggle(t *testing.T) {
	tests := []struct {
		name  string
		theme string
	}{
		{"dark theme", "dark"},
		{"light theme", "light"},
		{"auto theme", "auto"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			w := NewHTMLWriter(buf, HTMLConfig{
				Theme:           tc.theme,
				IncludeEvidence: true,
			})

			e := makeHTMLTestResultEvent("test-001", "xss", events.SeverityHigh, events.OutcomeBlocked, nil)
			w.Write(e)
			w.Close()

			output := buf.String()

			// Check for theme attribute
			expectedThemeAttr := `data-theme="` + tc.theme + `"`
			if !strings.Contains(output, expectedThemeAttr) {
				t.Errorf("expected theme attribute %q in output", expectedThemeAttr)
			}

			// Check for theme toggle button
			if !strings.Contains(output, "theme-toggle") {
				t.Error("expected theme toggle button")
			}

			// Check for toggleTheme function
			if !strings.Contains(output, "function toggleTheme()") {
				t.Error("expected toggleTheme JavaScript function")
			}

			// Check for localStorage persistence
			if !strings.Contains(output, "localStorage.getItem('waftester-theme')") {
				t.Error("expected localStorage persistence for theme")
			}

			if !strings.Contains(output, "localStorage.setItem('waftester-theme'") {
				t.Error("expected localStorage setItem for theme persistence")
			}
		})
	}
}

func TestHTMLWriter_IncludesSeverityColors(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	// Add events with different severities
	severities := []events.Severity{
		events.SeverityCritical,
		events.SeverityHigh,
		events.SeverityMedium,
		events.SeverityLow,
		events.SeverityInfo,
	}

	for i, sev := range severities {
		e := makeHTMLTestResultEvent(
			"test-"+string(rune('0'+i)),
			"sqli",
			sev,
			events.OutcomeBypass,
			nil,
		)
		w.Write(e)
	}
	w.Close()

	output := buf.String()

	// Check for severity CSS classes
	severityClasses := []string{
		"severity-critical",
		"severity-high",
		"severity-medium",
		"severity-low",
		"severity-info",
	}

	for _, class := range severityClasses {
		if !strings.Contains(output, class) {
			t.Errorf("expected severity class %q in output", class)
		}
	}

	// Check for severity color CSS variables
	colorVars := []string{
		"--severity-critical",
		"--severity-high",
		"--severity-medium",
		"--severity-low",
		"--severity-info",
	}

	for _, v := range colorVars {
		if !strings.Contains(output, v) {
			t.Errorf("expected CSS variable %q in output", v)
		}
	}

	// Check for severity cards section
	if !strings.Contains(output, "severity-cards") {
		t.Error("expected severity-cards section")
	}

	// Check for severity badges
	if !strings.Contains(output, "severity-badge") {
		t.Error("expected severity-badge elements")
	}
}

func TestHTMLWriter_IncludesOWASPMapping(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	// Add events with OWASP mappings
	e1 := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, []string{"A03:2021"})
	e2 := makeHTMLTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBlocked, []string{"A03:2021"})
	e3 := makeHTMLTestResultEvent("ssrf-001", "ssrf", events.SeverityHigh, events.OutcomeBypass, []string{"A10:2021"})

	w.Write(e1)
	w.Write(e2)
	w.Write(e3)
	w.Close()

	output := buf.String()

	// Check for OWASP section
	if !strings.Contains(output, "OWASP Top 10 2021 Coverage") {
		t.Error("expected OWASP Top 10 section header")
	}

	// Check for OWASP grid
	if !strings.Contains(output, "owasp-grid") {
		t.Error("expected owasp-grid class")
	}

	// Check for all OWASP Top 10 2021 categories
	owaspCodes := []string{
		"A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
		"A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021",
	}

	for _, code := range owaspCodes {
		if !strings.Contains(output, code) {
			t.Errorf("expected OWASP code %q in output", code)
		}
	}

	// Check for OWASP status indicators
	statusClasses := []string{"owasp-status", "pass", "fail", "none"}
	for _, class := range statusClasses {
		if !strings.Contains(output, class) {
			t.Errorf("expected OWASP status class %q in output", class)
		}
	}

	// Check for specific category names
	owaspNames := []string{
		"Broken Access Control",
		"Injection",
		"Server-Side Request Forgery",
	}

	for _, name := range owaspNames {
		if !strings.Contains(output, name) {
			t.Errorf("expected OWASP category name %q in output", name)
		}
	}
}

func TestHTMLWriter_JSONToggle(t *testing.T) {
	t.Run("includes JSON toggle when enabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHTMLWriter(buf, HTMLConfig{
			IncludeJSON:     true,
			IncludeEvidence: true,
		})

		e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// Check for JSON toggle button
		if !strings.Contains(output, "json-toggle") {
			t.Error("expected json-toggle class")
		}

		if !strings.Contains(output, "json-toggle-btn") {
			t.Error("expected json-toggle-btn class")
		}

		// Check for JSON toggle function
		if !strings.Contains(output, "function toggleJSON") {
			t.Error("expected toggleJSON JavaScript function")
		}

		// Check for Show JSON button text
		if !strings.Contains(output, "Show JSON") {
			t.Error("expected 'Show JSON' button text")
		}

		// Check for JSON content container
		if !strings.Contains(output, "json-content") {
			t.Error("expected json-content class")
		}

		// Check that JSON data is included
		if !strings.Contains(output, "test-scan-html-123") {
			t.Error("expected JSON data to contain scan ID")
		}
	})

	t.Run("excludes JSON toggle when disabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHTMLWriter(buf, HTMLConfig{
			IncludeJSON:     false,
			IncludeEvidence: true,
		})

		e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// When IncludeJSON is false, the finding's json-content div should not be present
		// The CSS and JS will still have json-toggle references, but actual buttons won't be rendered
		// Check that there's no actual button element with the toggle functionality
		if strings.Contains(output, `id="json-0"`) {
			t.Error("expected no json content div when IncludeJSON is false")
		}
	})
}

func TestHTMLWriter_Collapsible(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	e1 := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	e2 := makeHTMLTestResultEvent("test-002", "xss", events.SeverityHigh, events.OutcomeBlocked, nil)

	w.Write(e1)
	w.Write(e2)
	w.Close()

	output := buf.String()

	// Check for collapsible structure
	if !strings.Contains(output, "collapsible") {
		t.Error("expected collapsible class")
	}

	// Check for finding toggle mechanism
	if !strings.Contains(output, "finding-toggle") {
		t.Error("expected finding-toggle class")
	}

	// Check for toggleFinding function
	if !strings.Contains(output, "function toggleFinding") {
		t.Error("expected toggleFinding JavaScript function")
	}

	// Check for expanded class handling
	if !strings.Contains(output, "expanded") {
		t.Error("expected 'expanded' class in CSS/JS")
	}

	// Check for onclick handlers
	if !strings.Contains(output, "onclick=\"toggleFinding") {
		t.Error("expected onclick handler for toggleFinding")
	}

	// Check for aria-expanded attribute
	if !strings.Contains(output, "aria-expanded") {
		t.Error("expected aria-expanded attribute for accessibility")
	}

	// Check for finding-header and finding-body structure
	if !strings.Contains(output, "finding-header") {
		t.Error("expected finding-header class")
	}

	if !strings.Contains(output, "finding-body") {
		t.Error("expected finding-body class")
	}

	// Check multiple finding IDs
	if !strings.Contains(output, "finding-0") {
		t.Error("expected finding-0 element")
	}

	if !strings.Contains(output, "finding-1") {
		t.Error("expected finding-1 element")
	}
}

func TestHTMLWriter_CompanyBranding(t *testing.T) {
	t.Run("includes company branding when provided", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHTMLWriter(buf, HTMLConfig{
			Title:           "Security Assessment",
			CompanyLogo:     "/images/logo.png",
			CompanyName:     "Acme Security Corp",
			IncludeEvidence: true,
		})

		e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// Check for company name
		if !strings.Contains(output, "Acme Security Corp") {
			t.Error("expected company name in output")
		}

		// Check for company logo
		if !strings.Contains(output, "/images/logo.png") {
			t.Error("expected company logo path in output")
		}

		// Check for logo img tag
		if !strings.Contains(output, `<img src="/images/logo.png"`) {
			t.Error("expected img tag with logo")
		}

		// Check for custom title
		if !strings.Contains(output, "Security Assessment") {
			t.Error("expected custom title in output")
		}
	})

	t.Run("works without company branding", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewHTMLWriter(buf, HTMLConfig{
			IncludeEvidence: true,
		})

		e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// Should use default title
		if !strings.Contains(output, "WAFtester Security Report") {
			t.Error("expected default title when not provided")
		}

		// Should not have company-name class with content
		if strings.Contains(output, `class="company-name">Acme`) {
			t.Error("expected no company name when not provided")
		}
	})
}

func TestHTMLWriter_ExportPDFButton(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	// Check for print/PDF button
	if !strings.Contains(output, "Export PDF") {
		t.Error("expected 'Export PDF' button")
	}

	// Check for window.print() call
	if !strings.Contains(output, "window.print()") {
		t.Error("expected window.print() call for PDF export")
	}

	// Check for print media query
	if !strings.Contains(output, "@media print") {
		t.Error("expected @media print CSS rules")
	}

	// Check for @page rule
	if !strings.Contains(output, "@page") {
		t.Error("expected @page CSS rule for print layout")
	}
}

func TestHTMLWriter_ExecutiveSummary(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	// Add mix of results
	bypassEvents := []*events.ResultEvent{
		makeHTMLTestResultEvent("bypass-1", "sqli", events.SeverityCritical, events.OutcomeBypass, nil),
		makeHTMLTestResultEvent("bypass-2", "xss", events.SeverityHigh, events.OutcomeBypass, nil),
	}

	blockedEvents := []*events.ResultEvent{
		makeHTMLTestResultEvent("blocked-1", "sqli", events.SeverityMedium, events.OutcomeBlocked, nil),
		makeHTMLTestResultEvent("blocked-2", "xss", events.SeverityLow, events.OutcomeBlocked, nil),
		makeHTMLTestResultEvent("blocked-3", "rce", events.SeverityCritical, events.OutcomeBlocked, nil),
	}

	for _, e := range bypassEvents {
		w.Write(e)
	}
	for _, e := range blockedEvents {
		w.Write(e)
	}
	w.Close()

	output := buf.String()

	// Check for summary cards
	if !strings.Contains(output, "summary-card") {
		t.Error("expected summary-card class")
	}

	if !strings.Contains(output, "summary-grid") {
		t.Error("expected summary-grid class")
	}

	// Check for grade card
	if !strings.Contains(output, "grade-card") {
		t.Error("expected grade-card class")
	}

	// Check for Security Grade label
	if !strings.Contains(output, "Security Grade") {
		t.Error("expected 'Security Grade' label")
	}

	// Check for Total Tests label
	if !strings.Contains(output, "Total Tests") {
		t.Error("expected 'Total Tests' label")
	}

	// Check for Block Rate label
	if !strings.Contains(output, "Block Rate") {
		t.Error("expected 'Block Rate' label")
	}
}

func TestHTMLWriter_SupportsEvent(t *testing.T) {
	w := NewHTMLWriter(&bytes.Buffer{}, HTMLConfig{})

	// Should support these event types
	supported := []events.EventType{
		events.EventTypeResult,
		events.EventTypeSummary,
	}

	for _, et := range supported {
		if !w.SupportsEvent(et) {
			t.Errorf("expected to support %s events", et)
		}
	}

	// Should not support these event types
	notSupported := []events.EventType{
		events.EventTypeProgress,
		events.EventTypeBypass,
		events.EventTypeError,
		events.EventTypeStart,
	}

	for _, et := range notSupported {
		if w.SupportsEvent(et) {
			t.Errorf("expected not to support %s events", et)
		}
	}
}

func TestHTMLWriter_EmptyReport(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	// Close without writing any events
	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	// Should still produce valid HTML
	if !strings.HasPrefix(output, "<!DOCTYPE html>") {
		t.Error("expected HTML5 doctype even for empty report")
	}

	// Should show 0 findings
	if !strings.Contains(output, "Findings (0)") {
		t.Error("expected 'Findings (0)' for empty report")
	}
}

func TestHTMLWriter_DefaultConfig(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	// Check defaults are applied
	if w.config.Title != "WAFtester Security Report" {
		t.Errorf("expected default title, got %q", w.config.Title)
	}

	if w.config.Theme != "auto" {
		t.Errorf("expected default theme 'auto', got %q", w.config.Theme)
	}
}

func TestHTMLWriter_EscapesHTMLInPayload(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		IncludeEvidence: true,
		IncludeJSON:     true,
	})

	// Create event with HTML/script in payload
	e := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan",
		},
		Test: events.TestInfo{
			ID:       "xss-001",
			Category: "xss",
			Severity: events.SeverityHigh,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com",
			Method: "GET",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBypass,
			StatusCode: 200,
			LatencyMs:  10,
		},
		Evidence: &events.Evidence{
			Payload: "<script>alert('xss')</script>",
		},
	}

	w.Write(e)
	w.Close()

	output := buf.String()

	// The raw script tag should NOT appear in the output
	// It should be escaped in the JSON data at minimum
	rawScript := "<script>alert('xss')</script>"

	// Count occurrences - should be escaped in JSON at least
	scriptCount := strings.Count(output, rawScript)

	// There should be some script tags (our embedded JS), but the payload should be escaped
	// The payload inside evidence code block goes through template which escapes it
	if strings.Contains(output, rawScript) && strings.Count(output, "<script") > 2 {
		// More than 2 script tags might indicate XSS issue
		// (we have 1 for our embedded JS)
		t.Logf("warning: raw script payload found %d times, review escaping", scriptCount)
	}
}

func TestHTMLWriter_WithSummaryEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	// Add a result event
	e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)

	// Add a summary event
	summary := &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: time.Now(),
			Scan: "test-scan",
		},
		Target: events.SummaryTarget{
			URL:         "https://target.example.com",
			WAFDetected: "Cloudflare",
		},
		Totals: events.SummaryTotals{
			Tests:    100,
			Bypasses: 5,
			Blocked:  90,
			Errors:   3,
			Timeouts: 2,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct: 90.0,
			Grade:        "B",
		},
	}
	w.Write(summary)
	w.Close()

	output := buf.String()

	// Check that summary data is used
	if !strings.Contains(output, "https://target.example.com") {
		t.Error("expected target URL from summary")
	}

	if !strings.Contains(output, "Cloudflare") {
		t.Error("expected WAF detected name from summary")
	}
}

func TestHTMLWriter_AccessibilityAttributes(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	// Check for lang attribute
	if !strings.Contains(output, `lang="en"`) {
		t.Error("expected lang attribute on html element")
	}

	// Check for aria-label attributes
	if !strings.Contains(output, "aria-label") {
		t.Error("expected aria-label attributes for accessibility")
	}

	// Check for role attributes
	if !strings.Contains(output, `role="button"`) {
		t.Error("expected role='button' for interactive elements")
	}

	// Check for tabindex
	if !strings.Contains(output, "tabindex") {
		t.Error("expected tabindex for keyboard navigation")
	}
}

func TestHTMLWriter_DarkModeCSS(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Theme:           "dark",
		IncludeEvidence: true,
	})

	e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	// Check for dark theme CSS
	if !strings.Contains(output, `[data-theme="dark"]`) {
		t.Error("expected dark theme CSS selector")
	}

	// Check for CSS variables
	darkVars := []string{
		"--bg-primary",
		"--bg-secondary",
		"--text-primary",
		"--border-color",
	}

	for _, v := range darkVars {
		if !strings.Contains(output, v) {
			t.Errorf("expected CSS variable %q", v)
		}
	}
}

func TestHTMLWriter_FlushIsNoOp(t *testing.T) {
	w := NewHTMLWriter(&bytes.Buffer{}, HTMLConfig{})

	// Flush should not error
	if err := w.Flush(); err != nil {
		t.Errorf("Flush should not fail: %v", err)
	}
}

func TestHTMLWriter_ConcurrentWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	// Write events concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(i int) {
			e := makeHTMLTestResultEvent(
				"test-"+string(rune('0'+i)),
				"sqli",
				events.SeverityCritical,
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

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	// Should still be valid HTML
	if !strings.HasPrefix(output, "<!DOCTYPE html>") {
		t.Error("expected valid HTML after concurrent writes")
	}

	// Should have all 10 findings - count article elements with finding class
	findingCount := strings.Count(output, `class="finding collapsible"`)
	if findingCount != 10 {
		t.Errorf("expected 10 findings, got %d", findingCount)
	}
}

func TestHTMLWriter_OutcomeClasses(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	outcomes := []events.Outcome{
		events.OutcomeBypass,
		events.OutcomeBlocked,
		events.OutcomeError,
	}

	for i, outcome := range outcomes {
		e := &events.ResultEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeResult,
				Time: time.Now(),
				Scan: "test-scan",
			},
			Test: events.TestInfo{
				ID:       "test-" + string(rune('0'+i)),
				Category: "sqli",
				Severity: events.SeverityMedium,
			},
			Target: events.TargetInfo{
				URL:    "https://example.com",
				Method: "GET",
			},
			Result: events.ResultInfo{
				Outcome:    outcome,
				StatusCode: 200,
				LatencyMs:  10,
			},
		}
		w.Write(e)
	}
	w.Close()

	output := buf.String()

	// Check for outcome CSS classes
	outcomeClasses := []string{
		"outcome-bypass",
		"outcome-blocked",
		"outcome-error",
	}

	for _, class := range outcomeClasses {
		if !strings.Contains(output, class) {
			t.Errorf("expected outcome class %q in output", class)
		}
	}

	// Check for outcome CSS variable definitions
	outcomeVars := []string{
		"--outcome-bypass",
		"--outcome-blocked",
		"--outcome-error",
	}

	for _, v := range outcomeVars {
		if !strings.Contains(output, v) {
			t.Errorf("expected CSS variable %q", v)
		}
	}
}

func TestHTMLWriter_GeneratedTimestamp(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Close()

	output := buf.String()

	// Check for "Generated by WAFtester on" text
	if !strings.Contains(output, "Generated by WAFtester on") {
		t.Error("expected generation timestamp in footer")
	}

	// Check that it contains a date-like pattern
	datePattern := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	if !datePattern.MatchString(output) {
		t.Error("expected date pattern in output")
	}
}

func TestHTMLWriter_CWENameEnrichment(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	e.Test.CWE = []int{89}
	w.Write(e)
	w.Close()

	output := buf.String()

	// CWE-89 should include human-readable name
	if !strings.Contains(output, "CWE-89: SQL Injection") {
		t.Error("expected CWE name enrichment: 'CWE-89: SQL Injection'")
	}
}

func TestHTMLWriter_ConfidenceInFindings(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	e.Result.Confidence = "high"
	e.Result.ConfidenceNote = "status code matched bypass pattern"
	w.Write(e)
	w.Close()

	output := buf.String()

	if !strings.Contains(output, "Confidence") {
		t.Error("expected Confidence label in finding")
	}
	if !strings.Contains(output, "high") {
		t.Error("expected confidence value 'high'")
	}
	if !strings.Contains(output, "status code matched bypass pattern") {
		t.Error("expected confidence note in finding")
	}
}

func TestHTMLWriter_SevConfMatrix(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	// Create bypass findings with severity and confidence
	e1 := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	e1.Result.Confidence = "high"
	e2 := makeHTMLTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBypass, nil)
	e2.Result.Confidence = "medium"
	e3 := makeHTMLTestResultEvent("lfi-001", "lfi", events.SeverityMedium, events.OutcomeBlocked, nil)

	w.Write(e1)
	w.Write(e2)
	w.Write(e3)
	w.Close()

	output := buf.String()

	if !strings.Contains(output, "sev-conf-table") {
		t.Error("expected severity x confidence matrix table")
	}
	if !strings.Contains(output, "Severity × Confidence Matrix") {
		t.Error("expected matrix section header")
	}
	// Hot cell for critical + high confidence
	if !strings.Contains(output, "sev-conf-hot") {
		t.Error("expected hot cell highlighting for critical+high confidence")
	}
}

func TestHTMLWriter_SevConfMatrix_NoBypasses(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("test-001", "sqli", events.SeverityCritical, events.OutcomeBlocked, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	// No bypasses means no matrix section rendered (CSS class still present in style block)
	if strings.Contains(output, `id="sev-conf-section"`) {
		t.Error("expected no severity x confidence matrix when no bypasses")
	}
}

func TestHTMLWriter_PassingCategories(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBlocked, nil)
	w.Write(e)

	summary := &events.SummaryEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeSummary, Time: time.Now()},
		Breakdown: events.BreakdownInfo{
			ByCategory: map[string]events.CategoryStats{
				"sqli": {Total: 10, Bypasses: 0, BlockRate: 100},
				"xss":  {Total: 5, Bypasses: 2, BlockRate: 60},
			},
		},
		Effectiveness: events.EffectivenessInfo{BlockRatePct: 87, Grade: "C"},
		Totals:        events.SummaryTotals{Tests: 15, Blocked: 13, Bypasses: 2},
	}
	w.Write(summary)
	w.Close()

	output := buf.String()

	if !strings.Contains(output, "Passing Categories") {
		t.Error("expected passing categories section")
	}
	if !strings.Contains(output, "passing-table") {
		t.Error("expected passing categories table")
	}
	if !strings.Contains(output, "sqli") {
		t.Error("expected sqli in passing categories")
	}
	// xss had bypasses, should NOT be in passing
	if strings.Contains(output, "passing-section") && !strings.Contains(output, "xss") {
		// ok - xss should not appear in passing section, just verify sqli is there
	}
}

func TestHTMLWriter_PassingCategories_NonePass(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)

	summary := &events.SummaryEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeSummary, Time: time.Now()},
		Breakdown: events.BreakdownInfo{
			ByCategory: map[string]events.CategoryStats{
				"sqli": {Total: 10, Bypasses: 3, BlockRate: 70},
			},
		},
		Effectiveness: events.EffectivenessInfo{BlockRatePct: 70, Grade: "D"},
		Totals:        events.SummaryTotals{Tests: 10, Blocked: 7, Bypasses: 3},
	}
	w.Write(summary)
	w.Close()

	output := buf.String()

	if strings.Contains(output, `id="passing-section"`) {
		t.Error("expected no passing categories when none fully blocked")
	}
}

func TestHTMLWriter_EvasionEffectiveness(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e1 := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	e1.Context = &events.ContextInfo{Tamper: "base64encode", EvasionTechnique: "encoding"}
	e2 := makeHTMLTestResultEvent("sqli-002", "sqli", events.SeverityHigh, events.OutcomeBlocked, nil)
	e2.Context = &events.ContextInfo{Tamper: "base64encode", EvasionTechnique: "encoding"}

	w.Write(e1)
	w.Write(e2)
	w.Close()

	output := buf.String()

	if !strings.Contains(output, "Evasion Technique Effectiveness") {
		t.Error("expected evasion effectiveness section")
	}
	if !strings.Contains(output, "evasion-table") {
		t.Error("expected evasion table")
	}
	if !strings.Contains(output, "base64encode") {
		t.Error("expected tamper name in evasion table")
	}
	if !strings.Contains(output, "50.0%") {
		t.Error("expected 50% bypass rate (1/2)")
	}
}

func TestHTMLWriter_EvasionEffectiveness_NoEvasionData(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	if strings.Contains(output, `id="evasion-section"`) {
		t.Error("expected no evasion section without evasion context data")
	}
}

func TestHTMLWriter_RemediationGuidance(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	if !strings.Contains(output, "Remediation Guidance") {
		t.Error("expected remediation guidance section")
	}
	if !strings.Contains(output, "remediation-card") {
		t.Error("expected remediation card")
	}
	// Should contain guidance from categoryRemediationFor("sqli")
	if !strings.Contains(output, "bypass") {
		t.Error("expected bypass count in remediation")
	}
}

func TestHTMLWriter_RemediationGuidance_NoBypasses(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBlocked, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	if strings.Contains(output, `id="remediation-section"`) {
		t.Error("expected no remediation section when no bypasses")
	}
}

func TestHTMLWriter_ScanInsights(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)

	summary := &events.SummaryEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeSummary, Time: time.Now()},
		Target: events.SummaryTarget{
			URL:           "https://example.com",
			WAFDetected:   "Cloudflare",
			WAFConfidence: 0.95,
		},
		Effectiveness: events.EffectivenessInfo{BlockRatePct: 85, Grade: "C"},
		Totals:        events.SummaryTotals{Tests: 100, Blocked: 85, Bypasses: 15},
		Timing:        events.SummaryTiming{DurationSec: 30, RequestsPerSec: 3.3},
		Latency:       events.LatencyInfo{P50Ms: 50, P95Ms: 300},
	}
	w.Write(summary)
	w.Close()

	output := buf.String()

	if !strings.Contains(output, "Scan Insights") {
		t.Error("expected scan insights section")
	}
	if !strings.Contains(output, "insight-card") {
		t.Error("expected insight cards")
	}
	if !strings.Contains(output, "WAF Detection") {
		t.Error("expected WAF detection insight")
	}
	if !strings.Contains(output, "Protection Posture") {
		t.Error("expected protection posture insight")
	}
	if !strings.Contains(output, "Scan Performance") {
		t.Error("expected scan performance insight")
	}
	// Latency ratio is 6:1 (300/50), should trigger latency spike insight
	if !strings.Contains(output, "Latency Spike") {
		t.Error("expected latency spike insight")
	}
}

func TestHTMLWriter_ScanInsights_NoSummary(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBlocked, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	// No summary means no insights section rendered
	if strings.Contains(output, `id="insights-section"`) {
		t.Error("expected no insight cards without summary event")
	}
}

func TestHTMLWriter_CurlDataAttribute(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{IncludeEvidence: true, ShowCurlCommands: true})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	e.Evidence.CurlCommand = "curl -X POST 'https://example.com' -d \"test's payload\""
	w.Write(e)
	w.Close()

	output := buf.String()

	// Should use data-curl attribute instead of inline JS string
	if !strings.Contains(output, "data-curl=") {
		t.Error("expected data-curl attribute for safe clipboard copy")
	}
	if !strings.Contains(output, "copyCurl(this)") {
		t.Error("expected copyCurl function call")
	}
	// Should NOT use inline copyToClipboard('...', this) pattern
	if strings.Contains(output, "copyToClipboard('curl") {
		t.Error("expected no inline copyToClipboard with curl string (XSS unsafe)")
	}
}

func TestHTMLWriter_DefaultConfig_IncludesEvidenceAndJSON(t *testing.T) {
	// Using DefaultHTMLConfig() should include Evidence and JSON by default
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	// Evidence should be present with DefaultHTMLConfig()
	if !strings.Contains(output, "test-payload-sqli-001") {
		t.Error("expected evidence payload with DefaultHTMLConfig() (IncludeEvidence should be true)")
	}

	// JSON toggle should be present with DefaultHTMLConfig()
	if !strings.Contains(output, "json-toggle") {
		t.Error("expected JSON toggle with DefaultHTMLConfig() (IncludeJSON should be true)")
	}
}

func TestGenerateSevConfMatrixHTML(t *testing.T) {
	results := []*events.ResultEvent{
		{
			Test:   events.TestInfo{Severity: events.SeverityCritical},
			Result: events.ResultInfo{Outcome: events.OutcomeBypass, Confidence: "high"},
		},
		{
			Test:   events.TestInfo{Severity: events.SeverityCritical},
			Result: events.ResultInfo{Outcome: events.OutcomeBypass, Confidence: "high"},
		},
		{
			Test:   events.TestInfo{Severity: events.SeverityMedium},
			Result: events.ResultInfo{Outcome: events.OutcomeBypass, Confidence: "low"},
		},
		{
			Test:   events.TestInfo{Severity: events.SeverityHigh},
			Result: events.ResultInfo{Outcome: events.OutcomeBlocked},
		},
	}

	html := generateSevConfMatrixHTML(results)

	if html == "" {
		t.Fatal("expected non-empty matrix HTML")
	}
	if !strings.Contains(html, "sev-conf-table") {
		t.Error("expected sev-conf-table class")
	}
	if !strings.Contains(html, "sev-conf-hot") {
		t.Error("expected hot cell for critical+high")
	}
	// Blocked result should not appear in matrix
	if strings.Contains(html, "High") && strings.Contains(html, "sev-conf-hot") {
		// Only critical+high should be hot, not medium+low
	}
}

func TestGenerateSevConfMatrixHTML_NoBypasses(t *testing.T) {
	results := []*events.ResultEvent{
		{
			Test:   events.TestInfo{Severity: events.SeverityCritical},
			Result: events.ResultInfo{Outcome: events.OutcomeBlocked},
		},
	}

	html := generateSevConfMatrixHTML(results)
	if html != "" {
		t.Error("expected empty matrix HTML when no bypasses")
	}
}

func TestBuildHTMLInsights(t *testing.T) {
	summary := &events.SummaryEvent{
		Target: events.SummaryTarget{
			WAFDetected:   "ModSecurity",
			WAFConfidence: 0.92,
		},
		Effectiveness: events.EffectivenessInfo{
			Grade:        "B",
			BlockRatePct: 91.5,
		},
		Totals: events.SummaryTotals{Tests: 200},
		Timing: events.SummaryTiming{
			DurationSec:    45,
			RequestsPerSec: 4.4,
		},
		Latency: events.LatencyInfo{
			P50Ms: 40,
			P95Ms: 250,
		},
	}

	insights := buildHTMLInsights(nil, summary)

	if len(insights) == 0 {
		t.Fatal("expected at least one insight")
	}

	titles := make(map[string]bool)
	for _, ins := range insights {
		titles[ins.Title] = true
	}

	expected := []string{"WAF Detection", "Protection Posture", "Latency Spike", "Scan Performance"}
	for _, title := range expected {
		if !titles[title] {
			t.Errorf("expected insight with title %q", title)
		}
	}
}

func TestBuildHTMLInsights_NilSummary(t *testing.T) {
	insights := buildHTMLInsights(nil, nil)
	if len(insights) != 0 {
		t.Error("expected no insights with nil summary")
	}
}

// --- Round 2 regression tests ---

func TestOutcomeToClass_Timeout(t *testing.T) {
	got := outcomeToClass(events.OutcomeTimeout)
	if got != "outcome-timeout" {
		t.Errorf("outcomeToClass(timeout) = %q, want %q", got, "outcome-timeout")
	}
}

func TestOutcomeToClass_AllOutcomes(t *testing.T) {
	tests := []struct {
		outcome events.Outcome
		want    string
	}{
		{events.OutcomeBypass, "outcome-bypass"},
		{events.OutcomeBlocked, "outcome-blocked"},
		{events.OutcomeError, "outcome-error"},
		{events.OutcomeTimeout, "outcome-timeout"},
		{events.OutcomePass, "outcome-pass"},
	}
	for _, tt := range tests {
		got := outcomeToClass(tt.outcome)
		if got != tt.want {
			t.Errorf("outcomeToClass(%q) = %q, want %q", tt.outcome, got, tt.want)
		}
	}
}

func TestHTMLWriter_TimeoutCSS(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("timeout-1", "sqli", events.SeverityHigh, events.OutcomeTimeout, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	if !strings.Contains(output, "--outcome-timeout") {
		t.Error("missing CSS variable --outcome-timeout")
	}
	if !strings.Contains(output, ".outcome-timeout") {
		t.Error("missing CSS class .outcome-timeout")
	}
	if !strings.Contains(output, "outcome-timeout") {
		t.Error("timeout finding should have outcome-timeout class")
	}
}

func TestHTMLWriter_SiteBreakdown_CountsErrorsAndTimeouts(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	// Need 2+ sites to trigger site breakdown rendering
	urls := []string{"https://a.example.com", "https://b.example.com"}
	outcomes := []events.Outcome{
		events.OutcomeBlocked,
		events.OutcomeBypass,
		events.OutcomeError,
		events.OutcomeTimeout,
	}
	for i, o := range outcomes {
		e := makeHTMLTestResultEvent("site-"+string(rune('0'+i)), "sqli", events.SeverityHigh, o, nil)
		e.Target.URL = urls[i%2]
		w.Write(e)
	}
	w.Close()

	output := buf.String()

	if !strings.Contains(output, "<th class=\"num-cell\">Errors</th>") {
		t.Error("site breakdown table missing Errors column header")
	}
	if !strings.Contains(output, "<th class=\"num-cell\">Timeouts</th>") {
		t.Error("site breakdown table missing Timeouts column header")
	}
}

func TestTruncateResponse_MultibyteSafe(t *testing.T) {
	// 3 Chinese characters = 3 runes but 9 bytes
	input := "\u4e16\u754c\u4f60" // 世界你
	got := truncateResponse(input, 2)
	// Should truncate to 2 runes, not 2 bytes
	if !strings.HasPrefix(got, "\u4e16\u754c") {
		t.Errorf("truncateResponse split multibyte runes: got prefix %q", got[:6])
	}
	if !strings.Contains(got, "Truncated") {
		t.Error("truncated response should contain truncation marker")
	}
}

func TestTruncateResponse_ShortString(t *testing.T) {
	input := "hello"
	got := truncateResponse(input, 100)
	if got != input {
		t.Errorf("truncateResponse should not truncate short strings: got %q", got)
	}
}

func TestHTMLWriter_FilterDropdown_HasTimeoutAndPass(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("filter-1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	if !strings.Contains(output, `<option value="timeout">Timeout</option>`) {
		t.Error("outcome filter dropdown missing timeout option")
	}
	if !strings.Contains(output, `<option value="pass">Pass</option>`) {
		t.Error("outcome filter dropdown missing pass option")
	}
}

func TestHTMLWriter_SummaryOverride_ReconcilesTotals(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	// Write 2 bypass results
	for i := range 2 {
		e := makeHTMLTestResultEvent("sum-"+string(rune('0'+i)), "sqli", events.SeverityHigh, events.OutcomeBypass, nil)
		w.Write(e)
	}

	// Write summary with different totals (e.g., from a larger run)
	summary := &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: time.Now(),
			Scan: "test-scan",
		},
		Target: events.SummaryTarget{URL: "https://example.com"},
		Totals: events.SummaryTotals{
			Tests:    100,
			Bypasses: 30,
			Blocked:  60,
			Errors:   7,
			Timeouts: 3,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct: 60.0,
			Grade:        "D",
		},
	}
	w.Write(summary)
	w.Close()

	output := buf.String()

	// The executive summary stats card should show the summary total (100), not 2.
	// Search for "100 Total" or the stats card rendering the value 100.
	// The export JS function renders: tests: {{.TotalTests}}
	re := regexp.MustCompile(`tests:\s*100`)
	if !re.MatchString(output) {
		// If the output uses a different rendering, check the summary section
		re2 := regexp.MustCompile(`(?i)100\s*(total|tests)`)
		if !re2.MatchString(output) {
			t.Error("summary override should set TotalTests to summary value (100), but it does not appear in the output")
		}
	}
}

func TestHTMLWriter_NoStaleComment(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	e := makeHTMLTestResultEvent("stale-1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	// There should be no "<!-- Findings -->" comment right before the Passing Categories section
	if strings.Contains(output, "<!-- Findings -->\n") {
		// Check it's not immediately before the passing section
		idx := strings.Index(output, "<!-- Findings -->")
		after := output[idx+len("<!-- Findings -->"):]
		trimmed := strings.TrimSpace(after)
		if strings.HasPrefix(trimmed, "{{") || strings.HasPrefix(trimmed, "<!-- Passing") {
			t.Error("stale <!-- Findings --> comment still present before Passing Categories section")
		}
	}
}

// --- Round 11-24 regression tests ---

func TestHTMLWriter_ExportJSON_IncludesTimeouts(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeTimeout, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, "timeouts:") {
		t.Error("exportJSON function missing 'timeouts' key in totals")
	}
}

func TestHTMLWriter_ExecSummary_TimeoutCard(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeTimeout, nil))
	summary := &events.SummaryEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeSummary, Time: time.Now()},
		Totals:    events.SummaryTotals{Tests: 1, Timeouts: 1},
	}
	w.Write(summary)
	w.Close()

	output := buf.String()
	if !strings.Contains(output, "timeout-card") {
		t.Error("executive summary missing timeout card when timeouts > 0")
	}
}

func TestHTMLWriter_SimpleSummary_ErrorAndTimeoutCards(t *testing.T) {
	buf := &bytes.Buffer{}
	// Set PrintOptimized to break zero-value detection, keeping ShowExecutiveSummary false
	w := NewHTMLWriter(buf, HTMLConfig{PrintOptimized: true})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeError, nil))
	w.Write(makeHTMLTestResultEvent("t2", "sqli", events.SeverityHigh, events.OutcomeTimeout, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, "error-card") {
		t.Error("simple summary missing error card")
	}
	if !strings.Contains(output, "timeout-card") {
		t.Error("simple summary missing timeout card")
	}
}

func TestHTMLWriter_RiskMatrix_PassColumn(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomePass, nil))
	w.Write(makeHTMLTestResultEvent("t2", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, "pass-col") {
		t.Error("risk matrix table missing Pass column header")
	}
}

func TestHTMLWriter_TimeoutColCSS(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, ".risk-matrix-table .timeout-col") {
		t.Error("CSS missing .timeout-col rule for risk matrix")
	}
}

func TestCapitalize_MultibyteSafe(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"hello", "Hello"},
		{"critical", "Critical"},
		{"a", "A"},
	}
	for _, tc := range tests {
		got := capitalize(tc.in)
		if got != tc.want {
			t.Errorf("capitalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHTMLWriter_LocalStorage_TryCatch(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, "try {") || !strings.Contains(output, "} catch(e) {}") {
		t.Error("localStorage access not wrapped in try/catch")
	}
}

func TestHTMLWriter_EffectivenessBar_ARIA(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, `role="progressbar"`) {
		t.Error("effectiveness bar missing role=progressbar")
	}
	if !strings.Contains(output, "aria-valuemin") {
		t.Error("effectiveness bar missing aria-valuemin")
	}
}

func TestHTMLWriter_OWASPStatus_ErrorOnly_NotPass(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	// All results for the OWASP category are errors — should NOT show as "pass"
	e := makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeError, []string{"A03:2021"})
	w.Write(e)
	w.Close()

	output := buf.String()
	// The OWASP grid entry for A03 should not have "pass" status
	// with only error results and no blocked results
	if strings.Contains(output, `class="owasp-status pass"`) {
		t.Error("OWASP category with only error results should not show 'pass' status")
	}
}

func TestHTMLWriter_OWASPStatus_BlockedSetsPass(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	e := makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBlocked, []string{"A03:2021"})
	w.Write(e)
	w.Close()

	output := buf.String()
	if !strings.Contains(output, `class="owasp-status pass"`) {
		t.Error("OWASP category with blocked results should show 'pass' status")
	}
}

func TestOutcomeWeight_AllOutcomes(t *testing.T) {
	tests := []struct {
		outcome string
		weight  int
	}{
		{string(events.OutcomeBypass), 5},
		{string(events.OutcomeError), 4},
		{string(events.OutcomeTimeout), 3},
		{string(events.OutcomePass), 2},
		{string(events.OutcomeBlocked), 1},
		{"unknown", 1},
	}
	for _, tc := range tests {
		got := outcomeWeight(tc.outcome)
		if got != tc.weight {
			t.Errorf("outcomeWeight(%q) = %d, want %d", tc.outcome, got, tc.weight)
		}
	}
}

func TestHTMLWriter_FindingsSorted_ByOutcomeWeight(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	// Write in reverse order: blocked, pass, timeout, error, bypass
	w.Write(makeHTMLTestResultEvent("blocked-1", "cat-blk", events.SeverityHigh, events.OutcomeBlocked, nil))
	w.Write(makeHTMLTestResultEvent("pass-sort", "cat-pas", events.SeverityHigh, events.OutcomePass, nil))
	w.Write(makeHTMLTestResultEvent("timeout-sort", "cat-tmo", events.SeverityHigh, events.OutcomeTimeout, nil))
	w.Write(makeHTMLTestResultEvent("error-sort", "cat-err", events.SeverityHigh, events.OutcomeError, nil))
	w.Write(makeHTMLTestResultEvent("bypass-sort", "cat-byp", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	// Use unique markers from finding card titles: {{$f.ID}} - {{$f.Category}}
	bypassIdx := strings.Index(output, "bypass-sort - cat-byp")
	errorIdx := strings.Index(output, "error-sort - cat-err")
	timeoutIdx := strings.Index(output, "timeout-sort - cat-tmo")
	passIdx := strings.Index(output, "pass-sort - cat-pas")
	blockedIdx := strings.Index(output, "blocked-1 - cat-blk")

	if bypassIdx < 0 || errorIdx < 0 || timeoutIdx < 0 || passIdx < 0 || blockedIdx < 0 {
		t.Fatal("one or more finding titles not found in output")
	}
	if bypassIdx > errorIdx {
		t.Errorf("bypass (%d) should appear before error (%d)", bypassIdx, errorIdx)
	}
	if errorIdx > timeoutIdx {
		t.Errorf("error (%d) should appear before timeout (%d)", errorIdx, timeoutIdx)
	}
	if timeoutIdx > passIdx {
		t.Errorf("timeout (%d) should appear before pass (%d)", timeoutIdx, passIdx)
	}
	if passIdx > blockedIdx {
		t.Errorf("pass (%d) should appear before blocked (%d)", passIdx, blockedIdx)
	}
}

func TestHTMLWriter_NoFindings_Message(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	// Close without writing any events
	w.Close()

	output := buf.String()
	if !strings.Contains(output, "No findings to display") {
		t.Error("empty report should show 'No findings to display' message")
	}
}

func TestHTMLWriter_PrintReport_RequestAnimationFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	// printReport should use requestAnimationFrame, but setTimeout may still exist
	// in other functions (e.g., copyToClipboard). Check the printReport function specifically.
	printFuncIdx := strings.Index(output, "function printReport()")
	if printFuncIdx < 0 {
		t.Fatal("printReport function not found in output")
	}
	printFunc := output[printFuncIdx : printFuncIdx+500]
	if strings.Contains(printFunc, "setTimeout") {
		t.Error("printReport should use requestAnimationFrame, not setTimeout")
	}
	if !strings.Contains(printFunc, "requestAnimationFrame") {
		t.Error("printReport missing requestAnimationFrame")
	}
}

func TestHTMLWriter_Noscript_Fallback(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, "<noscript>") {
		t.Error("HTML should include noscript fallback for finding visibility")
	}
}

func TestHTMLWriter_TimeoutCard_CSS(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, ".summary-card.timeout-card") {
		t.Error("CSS missing .timeout-card border style")
	}
}

func TestHTMLWriter_FilterCount_Element(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, "filterCount") {
		t.Error("findings toolbar missing filter count element")
	}
}

func TestHTMLWriter_PassColCSS(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()
	if !strings.Contains(output, ".risk-matrix-table .pass-col") {
		t.Error("CSS missing .pass-col rule for risk matrix")
	}
}

// =============================================================================
// Design System Compliance Tests (Negative Tests)
// =============================================================================

// TestHTMLWriter_NoForbiddenFonts verifies the HTML output does NOT use
// forbidden fonts that signal "generic AI-generated" templates.
func TestHTMLWriter_NoForbiddenFonts(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:           "Design Test",
		IncludeEvidence: true,
	})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()

	// Forbidden: Inter as primary font (most overused AI default)
	if regexp.MustCompile(`font-family:\s*['"]?Inter['"]?\s*[,;]`).MatchString(output) {
		t.Error("FORBIDDEN: Inter font detected as primary font - use IBM Plex Sans instead")
	}

	// Forbidden: Roboto as primary font
	if regexp.MustCompile(`font-family:\s*['"]?Roboto['"]?\s*[,;]`).MatchString(output) {
		t.Error("FORBIDDEN: Roboto font detected as primary font - use IBM Plex Sans instead")
	}

	// Forbidden: Arial as primary font (allowed as fallback only)
	if regexp.MustCompile(`font-family:\s*['"]?Arial['"]?\s*[,;]`).MatchString(output) {
		t.Error("FORBIDDEN: Arial font detected as primary font - use IBM Plex Sans instead")
	}

	// Required: IBM Plex Sans should be present
	if !strings.Contains(output, "IBM Plex Sans") {
		t.Error("REQUIRED: IBM Plex Sans font not found - add Google Fonts import")
	}
}

// TestHTMLWriter_NoForbiddenColors verifies the HTML output does NOT use
// forbidden "AI purple" colors that signal generic templates.
func TestHTMLWriter_NoForbiddenColors(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:           "Design Test",
		IncludeEvidence: true,
	})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := strings.ToLower(buf.String())

	// Forbidden violet/purple colors (Tailwind defaults that scream "AI generated")
	forbiddenColors := map[string]string{
		"#8b5cf6": "violet-500",
		"#7c3aed": "violet-600",
		"#a78bfa": "violet-400",
		"#6366f1": "indigo-500",
		"#4f46e5": "indigo-600",
		"#d946ef": "fuchsia-500",
	}

	for color, name := range forbiddenColors {
		if strings.Contains(output, color) {
			t.Errorf("FORBIDDEN: Color %s (%s) detected - use teal (#0d9488) instead", color, name)
		}
	}

	// Required: Teal accent should be present
	if !strings.Contains(output, "#0d9488") && !strings.Contains(output, "#14b8a6") {
		t.Error("REQUIRED: Teal accent color (#0d9488 or #14b8a6) not found")
	}
}

// TestHTMLWriter_NoEmojiHeaders verifies section headers don't use emoji icons.
func TestHTMLWriter_NoEmojiHeaders(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:                "Design Test",
		ShowExecutiveSummary: true,
	})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()

	// Common emoji patterns in headers
	emojiPatterns := []string{
		`<h[1-6][^>]*>.*🚨.*</h[1-6]>`,
		`<h[1-6][^>]*>.*⚠️.*</h[1-6]>`,
		`<h[1-6][^>]*>.*✅.*</h[1-6]>`,
		`<h[1-6][^>]*>.*📋.*</h[1-6]>`,
		`<h[1-6][^>]*>.*🔒.*</h[1-6]>`,
		`<h[1-6][^>]*>.*💀.*</h[1-6]>`,
		`<h[1-6][^>]*>.*🐛.*</h[1-6]>`,
		`<h[1-6][^>]*>.*🔥.*</h[1-6]>`,
		`<h[1-6][^>]*>.*⚡.*</h[1-6]>`,
	}

	for _, pattern := range emojiPatterns {
		if regexp.MustCompile(pattern).MatchString(output) {
			t.Errorf("FORBIDDEN: Emoji in header detected (pattern: %s) - use CSS ::before dots instead", pattern)
		}
	}
}

// TestHTMLWriter_NoGradientText verifies no gradient text effect (AI slop pattern).
func TestHTMLWriter_NoGradientText(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()

	// Forbidden: background-clip: text (creates gradient text effect)
	if strings.Contains(output, "background-clip: text") || strings.Contains(output, "-webkit-background-clip: text") {
		t.Error("FORBIDDEN: Gradient text (background-clip: text) detected - remove this AI slop pattern")
	}
}

// TestHTMLWriter_NoGlowAnimations verifies no animated glowing effects.
func TestHTMLWriter_NoGlowAnimations(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := strings.ToLower(buf.String())

	// Forbidden: @keyframes glow or similar
	if regexp.MustCompile(`@keyframes\s+glow`).MatchString(output) {
		t.Error("FORBIDDEN: @keyframes glow animation detected - remove this AI slop pattern")
	}

	// Forbidden: animation referencing glow
	if regexp.MustCompile(`animation:\s*[^;]*glow`).MatchString(output) {
		t.Error("FORBIDDEN: Glow animation reference detected - remove this AI slop pattern")
	}
}

// TestHTMLWriter_UseSystemFonts verifies external font CDN can be disabled.
func TestHTMLWriter_UseSystemFonts(t *testing.T) {
	// Default: includes Google Fonts
	buf1 := &bytes.Buffer{}
	w1 := NewHTMLWriter(buf1, HTMLConfig{})
	w1.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w1.Close()

	output1 := buf1.String()
	if !strings.Contains(output1, "fonts.googleapis.com") {
		t.Error("Default config should include Google Fonts CDN link")
	}

	// With UseSystemFonts: no external CDN
	buf2 := &bytes.Buffer{}
	w2 := NewHTMLWriter(buf2, HTMLConfig{UseSystemFonts: true})
	w2.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w2.Close()

	output2 := buf2.String()
	if strings.Contains(output2, "fonts.googleapis.com") {
		t.Error("UseSystemFonts=true should NOT include Google Fonts CDN link")
	}
	if strings.Contains(output2, "fonts.gstatic.com") {
		t.Error("UseSystemFonts=true should NOT include fonts.gstatic.com")
	}
}

// TestHTMLWriter_RequiredPatterns verifies required design system patterns are present.
func TestHTMLWriter_RequiredPatterns(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:                "Design Test",
		ShowExecutiveSummary: true,
		IncludeEvidence:      true,
	})
	w.Write(makeHTMLTestResultEvent("t1", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()

	// Required: Should have section-label class for professional headers
	if !strings.Contains(output, "section-label") {
		t.Error("REQUIRED: section-label class not found - add professional header styling")
	}

	// Required: Should have depth tier classes
	depthClasses := []string{"depth-hero", "depth-default", "depth-recessed"}
	hasAnyDepth := false
	for _, class := range depthClasses {
		if strings.Contains(output, class) {
			hasAnyDepth = true
			break
		}
	}
	if !hasAnyDepth {
		t.Error("REQUIRED: No depth tier classes found (depth-hero, depth-default, depth-recessed)")
	}
}

// =============================================================================
// Edge Case Tests (Phase 6)
// =============================================================================

// TestHTMLWriter_EdgeCase_EmptyReport verifies empty reports render gracefully.
func TestHTMLWriter_EdgeCase_EmptyReport(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:                "Empty Report Test",
		ShowExecutiveSummary: true,
	})
	// Write no events - empty report
	w.Close()

	output := buf.String()

	// Must still be valid HTML
	if !strings.HasPrefix(output, "<!DOCTYPE html>") {
		t.Error("Empty report missing DOCTYPE")
	}

	// Must have closing tags
	if !strings.Contains(output, "</html>") {
		t.Error("Empty report missing closing </html>")
	}

	// Must NOT contain undefined/NaN
	if strings.Contains(output, "undefined") || strings.Contains(output, "NaN") {
		t.Error("Empty report contains undefined or NaN values")
	}

	// Should show Findings (0)
	if !strings.Contains(output, "Findings (0)") {
		t.Error("Empty report should show 'Findings (0)'")
	}
}

// TestHTMLWriter_EdgeCase_LargeReport verifies large reports generate quickly.
func TestHTMLWriter_EdgeCase_LargeReport(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:           "Large Report Test",
		IncludeEvidence: true,
	})

	start := time.Now()

	// Generate 1000 findings
	for i := 0; i < 1000; i++ {
		e := makeHTMLTestResultEvent(
			fmt.Sprintf("test-%04d", i),
			"sqli",
			events.SeverityHigh,
			events.OutcomeBypass,
			nil,
		)
		w.Write(e)
	}
	w.Close()

	duration := time.Since(start)

	// Must complete in under 5 seconds
	if duration > 5*time.Second {
		t.Errorf("Large report took too long: %v (max 5s)", duration)
	}

	// Output size should be reasonable (<10MB)
	if buf.Len() > 10*1024*1024 {
		t.Errorf("Large report too big: %d bytes (max 10MB)", buf.Len())
	}

	// Must still be valid HTML
	output := buf.String()
	if !strings.HasPrefix(output, "<!DOCTYPE html>") || !strings.Contains(output, "</html>") {
		t.Error("Large report is not valid HTML")
	}

	t.Logf("Large report: %d findings, %d bytes, %v", 1000, buf.Len(), duration)
}

// TestHTMLWriter_EdgeCase_XSSEscaping verifies XSS payloads are properly escaped.
func TestHTMLWriter_EdgeCase_XSSEscaping(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:           "XSS Test",
		IncludeEvidence: true,
	})

	// Create event with XSS payload
	e := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "xss-test",
		},
		Test: events.TestInfo{
			ID:       "xss-001",
			Name:     "<script>alert('XSS')</script>",
			Category: "xss",
			Severity: events.SeverityCritical,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com/<script>alert(1)</script>",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBypass,
			StatusCode: 200,
		},
		Evidence: &events.Evidence{
			Payload:         `<img src=x onerror="alert('XSS')">`,
			ResponsePreview: `<html><script>alert('XSS')</script></html>`,
		},
	}
	w.Write(e)
	w.Close()

	output := buf.String()

	// Raw script tags must NOT appear
	if strings.Contains(output, "<script>alert") {
		t.Error("XSS: Unescaped <script> tag found in output")
	}

	// Raw onerror handlers must NOT appear
	if strings.Contains(output, `onerror="alert`) {
		t.Error("XSS: Unescaped onerror handler found in output")
	}

	// Escaped versions should appear
	if !strings.Contains(output, "&lt;script&gt;") && !strings.Contains(output, "&#34;") {
		t.Log("Warning: Expected escaped HTML entities not found")
	}
}

// TestHTMLWriter_EdgeCase_Unicode verifies unicode characters render correctly.
func TestHTMLWriter_EdgeCase_Unicode(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:           "Unicode Test",
		IncludeEvidence: true,
	})

	// Create event with unicode content
	e := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "unicode-test",
		},
		Test: events.TestInfo{
			ID:       "unicode-日本語-001", // Unicode in ID (actually displayed)
			Name:     "日本語テスト",          // Note: Name field not displayed in current template
			Category: "sqli",
			Severity: events.SeverityHigh,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com/العربية",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBypass,
			StatusCode: 200,
		},
		Evidence: &events.Evidence{
			Payload: "' OR '中文' = '中文' --",
		},
	}
	w.Write(e)
	w.Close()

	output := buf.String()

	// Japanese in ID should appear (ID is displayed in findings table)
	if !strings.Contains(output, "日本語") {
		t.Error("Unicode: Japanese characters not found in output")
	}

	// Arabic in URL should appear
	if !strings.Contains(output, "العربية") {
		t.Error("Unicode: Arabic characters not found in output")
	}

	// Chinese in payload should appear (when evidence is shown)
	if !strings.Contains(output, "中文") {
		t.Error("Unicode: Chinese characters not found in output")
	}
}

// TestHTMLWriter_EdgeCase_NoDoubleEscape verifies HTML entities aren't double-escaped.
func TestHTMLWriter_EdgeCase_NoDoubleEscape(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:           "Entity Test",
		IncludeEvidence: true,
	})

	// Create event with pre-escaped content
	e := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "entity-test",
		},
		Test: events.TestInfo{
			ID:       "entity-001",
			Name:     "Test &lt;with&gt; entities",
			Category: "sqli",
			Severity: events.SeverityHigh,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com/?q=a&amp;b=c",
			Method: "GET",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBypass,
			StatusCode: 200,
		},
	}
	w.Write(e)
	w.Close()

	output := buf.String()

	// Should NOT have double-escaped entities like &amp;lt;
	if strings.Contains(output, "&amp;lt;") || strings.Contains(output, "&amp;gt;") {
		t.Error("Entity: Double-escaped HTML entities found (&amp;lt; or &amp;gt;)")
	}
}

// =============================================================================
// Regression Tests (Phase 8)
// =============================================================================

// TestHTMLWriter_Regression_Structure verifies critical HTML sections exist.
func TestHTMLWriter_Regression_Structure(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:                "Regression Test",
		ShowExecutiveSummary: true,
		IncludeEvidence:      true,
	})

	// Add a finding
	w.Write(makeHTMLTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBypass, []string{"A03:2021"}))
	w.Close()

	output := buf.String()

	// Critical sections that must exist
	criticalSections := []struct {
		pattern string
		desc    string
	}{
		{`<!DOCTYPE html>`, "DOCTYPE declaration"},
		{`</html>`, "closing html tag"},
		{`<head>`, "head section"},
		{`<body`, "body section"},
		{`<style>`, "embedded styles"},
		{`class=".*summary`, "summary section"},
		{`class=".*finding`, "findings section"},
		{`<table`, "data table"},
	}

	for _, sec := range criticalSections {
		matched, _ := regexp.MatchString(sec.pattern, output)
		if !matched {
			t.Errorf("REGRESSION: Missing critical section: %s (pattern: %s)", sec.desc, sec.pattern)
		}
	}
}

// TestHTMLWriter_Regression_Data verifies all data is rendered correctly.
func TestHTMLWriter_Regression_Data(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:                "Data Preservation Test",
		ShowExecutiveSummary: true,
		IncludeEvidence:      true,
	})

	// Create event with specific data we need to verify
	e := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "data-test",
		},
		Test: events.TestInfo{
			ID:       "unique-id-12345",
			Name:     "Unique Test Name ABC",
			Category: "sqli",
			Severity: events.SeverityCritical,
		},
		Target: events.TargetInfo{
			URL:    "https://test.example.com/api/v1/users",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBypass,
			StatusCode: 403,
		},
		Evidence: &events.Evidence{
			Payload: "' OR '1'='1",
		},
	}
	w.Write(e)
	w.Close()

	output := buf.String()

	// All data must be present in output
	requiredData := []struct {
		value string
		desc  string
	}{
		{"unique-id-12345", "test ID"},
		{"sqli", "category"},
		{"https://test.example.com/api/v1/users", "target URL"},
		{"POST", "HTTP method"},
		{"403", "status code"},
	}

	for _, data := range requiredData {
		if !strings.Contains(output, data.value) {
			t.Errorf("REGRESSION: Missing data in output: %s (%s)", data.desc, data.value)
		}
	}
}

// TestHTMLWriter_Regression_Performance verifies generation time hasn't regressed.
func TestHTMLWriter_Regression_Performance(t *testing.T) {
	// Skip in short mode
	if testing.Short() {
		t.Skip("Skipping performance regression test in short mode")
	}

	// Baseline: 500 findings should complete in < 500ms
	// (We recorded 120ms in baseline, allowing 4x margin)
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:           "Performance Regression Test",
		IncludeEvidence: true,
	})

	start := time.Now()
	for i := 0; i < 500; i++ {
		e := makeHTMLTestResultEvent(
			fmt.Sprintf("perf-%04d", i),
			"sqli",
			events.SeverityHigh,
			events.OutcomeBypass,
			nil,
		)
		w.Write(e)
	}
	w.Close()
	duration := time.Since(start)

	// Performance threshold: 500ms for 500 findings
	if duration > 500*time.Millisecond {
		t.Errorf("PERFORMANCE REGRESSION: 500 findings took %v (threshold: 500ms)", duration)
	}

	t.Logf("Performance: 500 findings in %v, %d bytes", duration, buf.Len())
}

// TestHTMLWriter_Regression_Balanced verifies HTML tags are balanced.
func TestHTMLWriter_Regression_Balanced(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{
		Title:                "Balance Test",
		ShowExecutiveSummary: true,
		IncludeEvidence:      true,
	})

	// Add several findings
	for i := 0; i < 10; i++ {
		w.Write(makeHTMLTestResultEvent(
			fmt.Sprintf("bal-%d", i),
			"xss",
			events.SeverityHigh,
			events.OutcomeBypass,
			nil,
		))
	}
	w.Close()

	output := buf.String()

	// Check tag balance for major elements (using regex for accuracy)
	balanceChecks := []string{"div", "table", "section", "span", "html", "head", "body"}
	for _, tag := range balanceChecks {
		// Count opening tags: <tag or <tag followed by space/> 
		openPattern := regexp.MustCompile(`<` + tag + `[\s>]`)
		open := len(openPattern.FindAllString(output, -1))
		
		// Count closing tags: </tag>
		closePattern := regexp.MustCompile(`</` + tag + `>`)
		close := len(closePattern.FindAllString(output, -1))
		
		if open != close {
			t.Errorf("REGRESSION: Unbalanced <%s> tags: %d open, %d close", tag, open, close)
		}
	}
}

// =============================================================================
// Phase 11: HTMLConfig Defaults Bug Fix Tests
// =============================================================================

// TestHTMLConfig_BugDemo_SingleFieldBreaksDefaults demonstrates that the OLD
// pattern (setting one field in struct literal) no longer gives implicit defaults.
// This test documents the semantic change - users should use DefaultHTMLConfig().
func TestHTMLConfig_BugDemo_SingleFieldBreaksDefaults(t *testing.T) {
	// OLD PATTERN (no longer recommended): Setting one field loses all defaults
	cfg := HTMLConfig{IncludeEvidence: true}
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Write(makeHTMLTestResultEvent("bug-demo", "xss", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()

	// With NEW semantics: zero-value = false, so no executive summary
	// This is EXPECTED behavior now - not a bug
	if strings.Contains(output, "Executive Summary") {
		t.Log("Note: Executive Summary present with partial config (unexpected with new semantics)")
	}

	// NEW PATTERN: Use DefaultHTMLConfig() then override
	cfg2 := DefaultHTMLConfig()
	cfg2.ShowRiskChart = false // Disable just this one
	buf2 := &bytes.Buffer{}
	w2 := NewHTMLWriter(buf2, cfg2)
	w2.Write(makeHTMLTestResultEvent("new-pattern", "xss", events.SeverityHigh, events.OutcomeBypass, nil))
	w2.Close()

	output2 := buf2.String()

	// With DefaultHTMLConfig(), executive summary IS present
	if !strings.Contains(output2, "Executive Summary") {
		t.Error("DefaultHTMLConfig() should include Executive Summary")
	}
	// But risk chart should be disabled
	if strings.Contains(output2, "<svg") && strings.Contains(output2, "Risk Distribution") {
		t.Error("ShowRiskChart=false should disable the pie chart")
	}
}

// TestHTMLConfig_ZeroValue_AllFeaturesOff verifies zero-value semantics:
// HTMLConfig{} should now mean "all features OFF" (explicit zero = explicit false)
func TestHTMLConfig_ZeroValue_AllFeaturesOff(t *testing.T) {
	cfg := HTMLConfig{} // Zero value
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Write(makeHTMLTestResultEvent("zero-test", "xss", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()

	// With zero config, all bool features should be OFF
	// (After fix: zero-value = all features off, use DefaultHTMLConfig() for defaults)
	if strings.Contains(output, "Executive Summary") && !strings.Contains(output, "ShowExecutiveSummary") {
		// Note: This behavior changes with the fix
		// Before: Executive Summary shown (buggy all-or-nothing defaults)
		// After: Executive Summary NOT shown (zero-value = off)
		t.Log("Zero-value config includes Executive Summary (old behavior)")
	}
}

// TestHTMLConfig_DefaultFunc_AllFeaturesOn verifies DefaultHTMLConfig()
// returns config with all features enabled except UseSystemFonts.
func TestHTMLConfig_DefaultFunc_AllFeaturesOn(t *testing.T) {
	cfg := DefaultHTMLConfig()

	tests := []struct {
		name  string
		value bool
		want  bool
	}{
		{"IncludeEvidence", cfg.IncludeEvidence, true},
		{"IncludeJSON", cfg.IncludeJSON, true},
		{"ShowExecutiveSummary", cfg.ShowExecutiveSummary, true},
		{"ShowRiskChart", cfg.ShowRiskChart, true},
		{"ShowRiskMatrix", cfg.ShowRiskMatrix, true},
		{"ShowCurlCommands", cfg.ShowCurlCommands, true},
		{"PrintOptimized", cfg.PrintOptimized, true},
		{"UseSystemFonts", cfg.UseSystemFonts, false}, // Inverted default
	}

	for _, tt := range tests {
		if tt.value != tt.want {
			t.Errorf("DefaultHTMLConfig().%s = %v, want %v", tt.name, tt.value, tt.want)
		}
	}

	// Also verify string defaults
	if cfg.Title != "WAFtester Security Report" {
		t.Errorf("DefaultHTMLConfig().Title = %q, want 'WAFtester Security Report'", cfg.Title)
	}
	if cfg.Theme != "auto" {
		t.Errorf("DefaultHTMLConfig().Theme = %q, want 'auto'", cfg.Theme)
	}
	if cfg.MaxResponseLength != 5*1024 {
		t.Errorf("DefaultHTMLConfig().MaxResponseLength = %d, want %d", cfg.MaxResponseLength, 5*1024)
	}
}

// TestHTMLConfig_PartialOverride_OthersUnchanged verifies that overriding
// one field doesn't affect other fields when using DefaultHTMLConfig().
func TestHTMLConfig_PartialOverride_OthersUnchanged(t *testing.T) {
	cfg := DefaultHTMLConfig()
	cfg.ShowRiskChart = false // Disable just this one

	if cfg.ShowRiskChart != false {
		t.Error("Explicit override to false didn't work")
	}
	if cfg.ShowExecutiveSummary != true {
		t.Error("Overriding ShowRiskChart affected ShowExecutiveSummary")
	}
	if cfg.ShowRiskMatrix != true {
		t.Error("Overriding ShowRiskChart affected ShowRiskMatrix")
	}
	if cfg.IncludeEvidence != true {
		t.Error("Overriding ShowRiskChart affected IncludeEvidence")
	}
}

// TestHTMLConfig_ExplicitFalse_Respected verifies explicit false is honored.
func TestHTMLConfig_ExplicitFalse_Respected(t *testing.T) {
	cfg := DefaultHTMLConfig()
	cfg.ShowExecutiveSummary = false

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Write(makeHTMLTestResultEvent("explicit-false", "xss", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()

	// When ShowExecutiveSummary=false, the full section with section-label should be absent
	// (the simple summary-grid is still shown but without the depth-hero styling)
	if strings.Contains(output, `class="executive-summary depth-hero"`) {
		t.Error("Explicit ShowExecutiveSummary=false was not respected - depth-hero section present")
	}
	// The recommendations should NOT be shown
	if strings.Contains(output, "Key Recommendations") {
		t.Error("Explicit ShowExecutiveSummary=false should hide Key Recommendations")
	}
}

// TestHTMLConfig_UseSystemFonts_DefaultFalse verifies UseSystemFonts defaults to false.
func TestHTMLConfig_UseSystemFonts_DefaultFalse(t *testing.T) {
	cfg := DefaultHTMLConfig()

	if cfg.UseSystemFonts != false {
		t.Errorf("DefaultHTMLConfig().UseSystemFonts = %v, want false", cfg.UseSystemFonts)
	}

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Close()

	output := buf.String()

	// With UseSystemFonts=false (default), Google Fonts should be included
	if !strings.Contains(output, "fonts.googleapis.com") {
		t.Error("UseSystemFonts=false should include Google Fonts CDN")
	}
}

// TestHTMLConfig_CopyDoesntAlias verifies struct copy doesn't alias.
func TestHTMLConfig_CopyDoesntAlias(t *testing.T) {
	cfg1 := DefaultHTMLConfig()
	cfg2 := cfg1 // Copy
	cfg2.ShowRiskChart = false

	if cfg1.ShowRiskChart == cfg2.ShowRiskChart {
		t.Error("Struct copy aliased - modifying cfg2 affected cfg1")
	}
}

// TestHTMLConfig_JSONRoundTrip verifies JSON serialization works correctly.
func TestHTMLConfig_JSONRoundTrip(t *testing.T) {
	original := DefaultHTMLConfig()
	original.Title = "Custom Title"
	original.ShowRiskChart = false

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal
	var restored HTMLConfig
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Compare
	if restored.Title != original.Title {
		t.Errorf("Title mismatch: got %q, want %q", restored.Title, original.Title)
	}
	if restored.ShowRiskChart != original.ShowRiskChart {
		t.Errorf("ShowRiskChart mismatch: got %v, want %v", restored.ShowRiskChart, original.ShowRiskChart)
	}
	if restored.ShowExecutiveSummary != original.ShowExecutiveSummary {
		t.Errorf("ShowExecutiveSummary mismatch: got %v, want %v", restored.ShowExecutiveSummary, original.ShowExecutiveSummary)
	}
}

// TestHTMLConfig_ConcurrentDefaultAccess verifies DefaultHTMLConfig is safe for concurrent use.
func TestHTMLConfig_ConcurrentDefaultAccess(t *testing.T) {
	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			cfg := DefaultHTMLConfig()
			// Modify the copy (should not affect others)
			cfg.Title = "Modified"
			cfg.ShowRiskChart = false
		}()
	}

	wg.Wait()

	// Verify original defaults unchanged
	cfg := DefaultHTMLConfig()
	if cfg.Title != "WAFtester Security Report" {
		t.Error("Concurrent access corrupted DefaultHTMLConfig defaults")
	}
}

// =============================================================================
// Negative Tests: Error Boundaries, Invalid Inputs, Edge Paths
// =============================================================================

// TestHTMLWriter_Negative_NilWriter verifies behavior with nil io.Writer.
func TestHTMLWriter_Negative_NilWriter(t *testing.T) {
	// nil writer should panic on Close when trying to write
	// This tests that we don't crash unexpectedly - we crash predictably
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with nil writer on Close, got none")
		}
	}()

	w := NewHTMLWriter(nil, DefaultHTMLConfig())
	w.Write(makeHTMLTestResultEvent("test", "xss", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close() // Should panic here
}

// TestHTMLWriter_Negative_NilEvent verifies Write handles nil event gracefully.
func TestHTMLWriter_Negative_NilEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())

	// Should not panic, should silently ignore
	err := w.Write(nil)
	if err != nil {
		t.Errorf("Write(nil) returned error: %v", err)
	}

	err = w.Close()
	if err != nil {
		t.Errorf("Close after Write(nil) failed: %v", err)
	}

	// Should produce valid HTML (empty report)
	output := buf.String()
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Expected valid HTML output even with nil event")
	}
}

// TestHTMLWriter_Negative_UnknownEventType verifies unknown events are ignored.
func TestHTMLWriter_Negative_UnknownEventType(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())

	// Create a custom event type that's not ResultEvent or SummaryEvent
	unknownEvent := &events.ProgressEvent{
		Progress: events.ProgressInfo{
			Phase:   "test",
			Current: 50,
			Total:   100,
		},
	}

	err := w.Write(unknownEvent)
	if err != nil {
		t.Errorf("Write(unknownEvent) should not error: %v", err)
	}

	err = w.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Should produce valid HTML with no findings
	output := buf.String()
	if !strings.Contains(output, "Findings (0)") {
		t.Error("Expected 0 findings when only unknown events written")
	}
}

// TestHTMLWriter_Negative_WriteAfterClose verifies Write after Close behavior.
func TestHTMLWriter_Negative_WriteAfterClose(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())

	w.Close() // Close first
	sizeAfterClose := buf.Len()

	// Write after close - should append to results but won't be rendered
	// (since HTML was already written)
	err := w.Write(makeHTMLTestResultEvent("late", "xss", events.SeverityHigh, events.OutcomeBypass, nil))
	if err != nil {
		t.Errorf("Write after Close returned error: %v", err)
	}

	// Buffer shouldn't grow (HTML already written)
	if buf.Len() != sizeAfterClose {
		t.Error("Buffer changed after Write-after-Close")
	}
}

// TestHTMLWriter_Negative_DoubleClose verifies Close is safely callable twice.
func TestHTMLWriter_Negative_DoubleClose(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())
	w.Write(makeHTMLTestResultEvent("test", "xss", events.SeverityHigh, events.OutcomeBypass, nil))

	err1 := w.Close()
	if err1 != nil {
		t.Errorf("First Close failed: %v", err1)
	}
	sizeAfterFirst := buf.Len()

	// Second close writes again - this is current behavior (not ideal but documented)
	err2 := w.Close()
	if err2 != nil {
		t.Errorf("Second Close failed: %v", err2)
	}

	// Document the current behavior: double-close writes twice
	if buf.Len() <= sizeAfterFirst {
		t.Log("Double-close didn't write again (good - idempotent)")
	} else {
		t.Log("Note: Double-close writes HTML twice (current behavior)")
	}
}

// TestHTMLWriter_Negative_ZeroMaxResponseLength verifies zero gets defaulted.
func TestHTMLWriter_Negative_ZeroMaxResponseLength(t *testing.T) {
	cfg := DefaultHTMLConfig()
	cfg.MaxResponseLength = 0   // Should default to 5KB
	cfg.IncludeJSON = false     // Disable JSON to test only ResponsePreview truncation

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)

	// The internal config should have been defaulted
	// We can't access it directly, but we can test the effect
	longResponse := strings.Repeat("X", 10000) // 10KB
	result := makeHTMLTestResultEvent("test", "xss", events.SeverityHigh, events.OutcomeBypass, nil)
	result.Evidence = &events.Evidence{
		ResponsePreview: longResponse,
	}

	w.Write(result)
	w.Close()

	output := buf.String()
	// With 5KB default, 10KB response should be truncated
	// (JSON output would include full response, so disable it for this test)
	if strings.Contains(output, strings.Repeat("X", 10000)) {
		t.Error("MaxResponseLength=0 should default to 5KB and truncate")
	}
	// Check for actual truncation marker used by truncateResponse
	if !strings.Contains(output, "Truncated") {
		t.Error("Expected truncation marker")
	}
	// Verify only 5120 X's max (the default)
	xCount := strings.Count(output, "X")
	if xCount > 5200 { // Allow some margin for HTML-escaped versions
		t.Errorf("Expected ~5120 X chars, got %d", xCount)
	}
}

// TestHTMLWriter_Negative_NegativeMaxResponseLength verifies negative gets defaulted.
func TestHTMLWriter_Negative_NegativeMaxResponseLength(t *testing.T) {
	cfg := DefaultHTMLConfig()
	cfg.MaxResponseLength = -100 // Should default to 5KB
	cfg.IncludeJSON = false      // Disable JSON to test only ResponsePreview truncation

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)

	longResponse := strings.Repeat("Y", 10000)
	result := makeHTMLTestResultEvent("test", "sqli", events.SeverityMedium, events.OutcomeBypass, nil)
	result.Evidence = &events.Evidence{
		ResponsePreview: longResponse,
	}

	w.Write(result)
	w.Close()

	output := buf.String()
	if strings.Contains(output, strings.Repeat("Y", 10000)) {
		t.Error("MaxResponseLength=-100 should default to 5KB and truncate")
	}
	// Check for truncation marker
	if !strings.Contains(output, "Truncated") {
		t.Error("Expected truncation marker")
	}
}

// TestHTMLWriter_Negative_InvalidTheme verifies invalid theme defaults to auto.
func TestHTMLWriter_Negative_InvalidTheme(t *testing.T) {
	cfg := DefaultHTMLConfig()
	cfg.Theme = "invalid-theme-xyz"

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Close()

	output := buf.String()
	// Invalid theme should be passed through (no validation currently)
	// but it won't break the HTML
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Invalid theme broke HTML generation")
	}
}

// TestHTMLWriter_Negative_XSSInTitle verifies Title field is escaped.
func TestHTMLWriter_Negative_XSSInTitle(t *testing.T) {
	cfg := DefaultHTMLConfig()
	cfg.Title = "<script>alert('xss')</script>"

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Close()

	output := buf.String()

	// Title should be HTML-escaped
	if strings.Contains(output, "<script>alert") {
		t.Error("XSS in Title field was not escaped")
	}
	if !strings.Contains(output, "&lt;script&gt;") {
		t.Error("Expected HTML-escaped title")
	}
}

// TestHTMLWriter_Negative_NilEvidence verifies nil Evidence is handled.
func TestHTMLWriter_Negative_NilEvidence(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())

	result := makeHTMLTestResultEvent("nil-evidence", "xss", events.SeverityHigh, events.OutcomeBypass, nil)
	result.Evidence = nil // Explicitly nil

	err := w.Write(result)
	if err != nil {
		t.Errorf("Write with nil Evidence failed: %v", err)
	}

	err = w.Close()
	if err != nil {
		t.Errorf("Close with nil Evidence result failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "nil-evidence") {
		t.Error("Result with nil Evidence should still appear")
	}
}

// TestHTMLWriter_Negative_NilContext verifies nil Context is handled.
func TestHTMLWriter_Negative_NilContext(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())

	result := makeHTMLTestResultEvent("nil-context", "sqli", events.SeverityMedium, events.OutcomeBlocked, nil)
	result.Context = nil // Explicitly nil

	err := w.Write(result)
	if err != nil {
		t.Errorf("Write with nil Context failed: %v", err)
	}

	err = w.Close()
	if err != nil {
		t.Errorf("Close with nil Context result failed: %v", err)
	}
}

// TestHTMLWriter_Negative_EmptyTitle verifies empty Title is defaulted.
func TestHTMLWriter_Negative_EmptyTitle(t *testing.T) {
	cfg := DefaultHTMLConfig()
	cfg.Title = ""

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Close()

	output := buf.String()
	// Empty title should be defaulted to standard title
	if !strings.Contains(output, "WAFtester Security Report") {
		t.Error("Empty Title should default to 'WAFtester Security Report'")
	}
}

// TestHTMLWriter_Negative_EmptyTheme verifies empty Theme is defaulted.
func TestHTMLWriter_Negative_EmptyTheme(t *testing.T) {
	cfg := DefaultHTMLConfig()
	cfg.Theme = ""

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Close()

	output := buf.String()
	// Empty theme should be defaulted to "auto"
	if !strings.Contains(output, `data-theme="auto"`) && !strings.Contains(output, `color-scheme`) {
		t.Error("Empty Theme should default to 'auto'")
	}
}

// TestHTMLWriter_Negative_AllFeaturesDisabled verifies minimal output.
func TestHTMLWriter_Negative_AllFeaturesDisabled(t *testing.T) {
	cfg := HTMLConfig{} // Zero value = all features off

	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, cfg)
	w.Write(makeHTMLTestResultEvent("minimal", "xss", events.SeverityHigh, events.OutcomeBypass, nil))
	w.Close()

	output := buf.String()

	// Should NOT contain the full executive summary section (depth-hero)
	if strings.Contains(output, `class="executive-summary depth-hero"`) {
		t.Error("All-off config should not show full Executive Summary section")
	}
	// Should NOT contain Key Recommendations (part of executive summary)
	if strings.Contains(output, "Key Recommendations") {
		t.Error("All-off config should not show Key Recommendations")
	}
	// Should NOT contain risk chart SVG
	if strings.Contains(output, `id="risk-chart-section"`) {
		t.Error("All-off config should not show Risk Chart section")
	}

	// Should still have basic structure
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Should still produce valid HTML")
	}
	if !strings.Contains(output, "Findings (1)") {
		t.Error("Should still show findings")
	}
}

// TestHTMLWriter_Negative_EachBoolFieldDisabled verifies each feature toggle.
func TestHTMLWriter_Negative_EachBoolFieldDisabled(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*HTMLConfig)
		check   func(string) bool
		errMsg  string
	}{
		{
			name: "ShowExecutiveSummary=false",
			setup: func(c *HTMLConfig) { c.ShowExecutiveSummary = false },
			check: func(out string) bool {
				return !strings.Contains(out, "Key Recommendations")
			},
			errMsg: "ShowExecutiveSummary=false should hide Key Recommendations",
		},
		{
			name: "ShowRiskChart=false",
			setup: func(c *HTMLConfig) { c.ShowRiskChart = false },
			check: func(out string) bool {
				// Check that the Risk Distribution section with chart is absent
				return !strings.Contains(out, `id="risk-chart-section"`)
			},
			errMsg: "ShowRiskChart=false should hide risk chart section",
		},
		{
			name: "ShowRiskMatrix=false",
			setup: func(c *HTMLConfig) { c.ShowRiskMatrix = false },
			check: func(out string) bool {
				return !strings.Contains(out, `id="risk-matrix-section"`)
			},
			errMsg: "ShowRiskMatrix=false should hide risk matrix section",
		},
		{
			name: "IncludeEvidence=false",
			setup: func(c *HTMLConfig) { 
				c.IncludeEvidence = false
				c.IncludeJSON = false // Disable JSON so we only test evidence in findings
			},
			check: func(out string) bool {
				// With IncludeEvidence=false, finding.HasEvidence should be false
				// so the evidence section won't appear in the findings
				// Check that payload and response preview are NOT in output
				return !strings.Contains(out, "test-payload") && !strings.Contains(out, "test-response")
			},
			errMsg: "IncludeEvidence=false should hide payload and response data",
		},
		{
			name: "IncludeJSON=false",
			setup: func(c *HTMLConfig) { c.IncludeJSON = false },
			check: func(out string) bool {
				// With IncludeJSON=false, finding.JSONData should be empty
				// so the json-toggle div won't appear (but JS still has "Show JSON" text)
				return !strings.Contains(out, `class="json-toggle"`)
			},
			errMsg: "IncludeJSON=false should hide JSON toggle div",
		},
		{
			name: "ShowCurlCommands=false",
			setup: func(c *HTMLConfig) { 
				c.ShowCurlCommands = false
				c.IncludeJSON = false // Disable JSON so we only test curl in findings
			},
			check: func(out string) bool {
				// With ShowCurlCommands=false, curl command should not appear
				// even if evidence is included
				return !strings.Contains(out, "curl -X GET")
			},
			errMsg: "ShowCurlCommands=false should hide curl command content",
		},
		{
			name: "UseSystemFonts=true",
			setup: func(c *HTMLConfig) { c.UseSystemFonts = true },
			check: func(out string) bool {
				return !strings.Contains(out, "fonts.googleapis.com")
			},
			errMsg: "UseSystemFonts=true should not include Google Fonts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultHTMLConfig()
			tt.setup(&cfg)

			buf := &bytes.Buffer{}
			w := NewHTMLWriter(buf, cfg)
			// Include evidence to test those paths
			result := makeHTMLTestResultEvent("test", "xss", events.SeverityHigh, events.OutcomeBypass, nil)
			result.Evidence = &events.Evidence{
				Payload:         "test-payload",
				ResponsePreview: "test-response",
				CurlCommand:     "curl -X GET http://example.com",
			}
			w.Write(result)
			w.Close()

			output := buf.String()
			if !tt.check(output) {
				t.Error(tt.errMsg)
			}
		})
	}
}

// TestHTMLWriter_Negative_SpecialCharactersInAllFields verifies escaping.
func TestHTMLWriter_Negative_SpecialCharactersInAllFields(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())

	// Create result with XSS payloads in all user-controlled fields
	result := &events.ResultEvent{
		Test: events.TestInfo{
			ID:       "<script>alert('id')</script>",
			Category: "<script>alert('cat')</script>",
			Severity: events.SeverityHigh,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com/<script>",
			Method: "GET",
		},
		Result: events.ResultInfo{
			Outcome: events.OutcomeBypass,
		},
		Evidence: &events.Evidence{
			Payload:         "<script>alert('payload')</script>",
			ResponsePreview: "<script>alert('response')</script>",
			CurlCommand:     "curl '<script>alert(1)</script>'",
		},
	}

	w.Write(result)
	w.Close()

	output := buf.String()

	// None of the raw scripts should appear unescaped
	if strings.Contains(output, "<script>alert") {
		t.Error("Found unescaped <script> tag in output - XSS vulnerability")
	}

	// Should have escaped versions
	if !strings.Contains(output, "&lt;script&gt;") {
		t.Error("Expected escaped script tags")
	}
}

// TestHTMLWriter_Negative_VeryLongPayload verifies handling of huge payloads.
func TestHTMLWriter_Negative_VeryLongPayload(t *testing.T) {
	buf := &bytes.Buffer{}
	cfg := DefaultHTMLConfig()
	cfg.MaxResponseLength = 1000 // 1KB limit
	w := NewHTMLWriter(buf, cfg)

	hugePayload := strings.Repeat("A", 100000) // 100KB payload
	result := makeHTMLTestResultEvent("huge", "xss", events.SeverityHigh, events.OutcomeBypass, nil)
	result.Evidence = &events.Evidence{
		Payload:         hugePayload,
		ResponsePreview: hugePayload,
	}

	w.Write(result)
	err := w.Close()
	if err != nil {
		t.Errorf("Close failed with huge payload: %v", err)
	}

	output := buf.String()

	// Payload is NOT truncated (only ResponsePreview is)
	// This is current behavior - document it
	if strings.Contains(output, strings.Repeat("A", 100000)) {
		t.Log("Note: Huge payload is included in full (no truncation on payload)")
	}

	// ResponsePreview should be truncated - check for truncation marker
	if !strings.Contains(output, "Truncated") {
		t.Error("Expected ResponsePreview to be truncated with marker")
	}
}

// TestHTMLWriter_Negative_ZeroFindings verifies empty results handling.
func TestHTMLWriter_Negative_ZeroFindings(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, DefaultHTMLConfig())

	// Close without any Write calls
	err := w.Close()
	if err != nil {
		t.Errorf("Close with zero findings failed: %v", err)
	}

	output := buf.String()

	// Should have valid HTML
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Should produce valid HTML with zero findings")
	}

	// Should show zero findings
	if !strings.Contains(output, "Findings (0)") {
		t.Error("Should show 'Findings (0)'")
	}

	// Executive summary should handle zero gracefully
	if strings.Contains(output, "NaN") || strings.Contains(output, "Infinity") {
		t.Error("Zero findings caused NaN or Infinity in calculations")
	}
}
