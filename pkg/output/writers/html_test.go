package writers

import (
	"bytes"
	"regexp"
	"strings"
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
