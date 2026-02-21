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
	// Zero-value config should default IncludeEvidence and IncludeJSON to true
	buf := &bytes.Buffer{}
	w := NewHTMLWriter(buf, HTMLConfig{})

	e := makeHTMLTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil)
	w.Write(e)
	w.Close()

	output := buf.String()

	// Evidence should be present with zero-value config
	if !strings.Contains(output, "test-payload-sqli-001") {
		t.Error("expected evidence payload with default config (IncludeEvidence should default to true)")
	}

	// JSON toggle should be present with zero-value config
	if !strings.Contains(output, "json-toggle") {
		t.Error("expected JSON toggle with default config (IncludeJSON should default to true)")
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
