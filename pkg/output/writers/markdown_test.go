package writers

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// makeMarkdownTestResultEvent creates a test result event with OWASP and CWE mappings.
func makeMarkdownTestResultEvent(id, category string, severity events.Severity, outcome events.Outcome, owasp []string, cwe []int) *events.ResultEvent {
	return &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-md-123",
		},
		Test: events.TestInfo{
			ID:       id,
			Name:     id + " test",
			Category: category,
			Severity: severity,
			OWASP:    owasp,
			CWE:      cwe,
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

// makeMarkdownTestSummaryEvent creates a test summary event.
func makeMarkdownTestSummaryEvent() *events.SummaryEvent {
	return &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: time.Now(),
			Scan: "test-scan-md-123",
		},
		Version: "2.5.0",
		Target: events.SummaryTarget{
			URL:         "https://example.com",
			WAFDetected: "Cloudflare",
		},
		Totals: events.SummaryTotals{
			Tests:    100,
			Bypasses: 5,
			Blocked:  90,
			Errors:   3,
			Passes:   2,
			Timeouts: 0,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct:   90.0,
			Grade:          "B",
			Recommendation: "Enable more protection rules",
		},
		Breakdown: events.BreakdownInfo{
			BySeverity: map[string]events.CategoryStats{
				"critical": {Total: 10, Bypasses: 2, BlockRate: 80.0},
				"high":     {Total: 30, Bypasses: 2, BlockRate: 93.3},
				"medium":   {Total: 40, Bypasses: 1, BlockRate: 97.5},
			},
			ByCategory: map[string]events.CategoryStats{
				"sqli": {Total: 50, Bypasses: 3, BlockRate: 94.0},
				"xss":  {Total: 50, Bypasses: 2, BlockRate: 96.0},
			},
		},
		Timing: events.SummaryTiming{
			StartedAt:      time.Now().Add(-5 * time.Minute),
			CompletedAt:    time.Now(),
			DurationSec:    300.0,
			RequestsPerSec: 0.33,
		},
	}
}

func TestMarkdownWriter_NewMarkdownWriter(t *testing.T) {
	t.Run("applies default config", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{})

		// Verify defaults by closing and checking output
		w.Close()
		output := buf.String()

		if !strings.Contains(output, "WAFtester Security Report") {
			t.Error("expected default title 'WAFtester Security Report'")
		}
	})

	t.Run("respects custom config", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			Title:           "Custom Security Report",
			Flavor:          "gitlab",
			SortBy:          "category",
			IncludeTOC:      true,
			IncludeEvidence: true,
			IncludeOWASP:    true,
			IncludeCWE:      true,
			MaxPayloadLen:   100,
		})

		w.Close()
		output := buf.String()

		if !strings.Contains(output, "Custom Security Report") {
			t.Error("expected custom title 'Custom Security Report'")
		}
	})
}

func TestMarkdownWriter_Write(t *testing.T) {
	t.Run("buffers result events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		// Buffer should be empty before Close
		if buf.Len() > 0 {
			t.Error("expected no output before Close")
		}
	})

	t.Run("buffers summary events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{})

		e := makeMarkdownTestSummaryEvent()
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		// Buffer should be empty before Close
		if buf.Len() > 0 {
			t.Error("expected no output before Close")
		}
	})
}

func TestMarkdownWriter_Close(t *testing.T) {
	t.Run("writes complete markdown report", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeTOC:      true,
			IncludeEvidence: true,
			IncludeOWASP:    true,
			IncludeCWE:      true,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, []string{"A03:2021"}, []int{89})
		w.Write(e)
		w.Write(makeMarkdownTestSummaryEvent())

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		output := buf.String()

		if output == "" {
			t.Fatal("expected non-empty output after Close")
		}

		// Check for markdown structure
		if !strings.HasPrefix(output, "#") {
			t.Error("expected output to start with markdown header")
		}
	})
}

func TestMarkdownWriter_Flush(t *testing.T) {
	t.Run("returns nil (no-op)", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{})

		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})
}

func TestMarkdownWriter_SupportsEvent(t *testing.T) {
	w := NewMarkdownWriter(&bytes.Buffer{}, MarkdownConfig{})

	tests := []struct {
		eventType events.EventType
		expected  bool
	}{
		{events.EventTypeStart, false},
		{events.EventTypeResult, true},
		{events.EventTypeSummary, true},
		{events.EventTypeProgress, false},
		{events.EventTypeBypass, false},
		{events.EventTypeError, false},
		{events.EventTypeComplete, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.eventType), func(t *testing.T) {
			result := w.SupportsEvent(tc.eventType)
			if result != tc.expected {
				t.Errorf("SupportsEvent(%s) = %v, want %v", tc.eventType, result, tc.expected)
			}
		})
	}
}

func TestMarkdownWriter_TableOfContents(t *testing.T) {
	t.Run("includes TOC when enabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeTOC:   true,
			IncludeOWASP: true,
			IncludeCWE:   true,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, []string{"A03:2021"}, []int{89})
		w.Write(e)
		w.Close()

		output := buf.String()

		// Check for TOC header
		if !strings.Contains(output, "## Table of Contents") {
			t.Error("expected Table of Contents header")
		}

		// Check for TOC links
		tocLinks := []string{
			"[Executive Summary](#executive-summary)",
			"[Summary](#summary)",
			"[Risk Distribution](#risk-distribution)",
			"[OWASP Top 10 Mapping](#owasp-top-10-mapping)",
			"[CWE References](#cwe-references)",
			"[Findings](#findings)",
		}

		for _, link := range tocLinks {
			if !strings.Contains(output, link) {
				t.Errorf("expected TOC link %q", link)
			}
		}
	})

	t.Run("excludes TOC when disabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeTOC: false,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		if strings.Contains(output, "## Table of Contents") {
			t.Error("expected no Table of Contents when disabled")
		}
	})
}

func TestMarkdownWriter_SeverityIcons(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewMarkdownWriter(buf, MarkdownConfig{})

	// Add events with different severities
	severities := []struct {
		severity events.Severity
		icon     string
	}{
		{events.SeverityCritical, "🔴"},
		{events.SeverityHigh, "🟠"},
		{events.SeverityMedium, "🟡"},
		{events.SeverityLow, "🟢"},
		{events.SeverityInfo, "🔵"},
	}

	for i, s := range severities {
		e := makeMarkdownTestResultEvent(
			"test-"+string(rune('0'+i)),
			"test",
			s.severity,
			events.OutcomeBypass,
			nil,
			nil,
		)
		w.Write(e)
	}
	w.Close()

	output := buf.String()

	for _, s := range severities {
		if !strings.Contains(output, s.icon) {
			t.Errorf("expected severity icon %q for %s", s.icon, s.severity)
		}
	}
}

func TestMarkdownWriter_OutcomeIcons(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewMarkdownWriter(buf, MarkdownConfig{
		CollapseSections: false, // Use flat output to see all outcomes
	})

	outcomes := []struct {
		outcome events.Outcome
		icon    string
	}{
		{events.OutcomeBypass, "⚠️"},
		{events.OutcomeBlocked, "✅"},
		{events.OutcomeError, "❌"},
		{events.OutcomeTimeout, "⏱️"},
	}

	for i, o := range outcomes {
		e := makeMarkdownTestResultEvent(
			"test-"+string(rune('0'+i)),
			"test",
			events.SeverityHigh,
			o.outcome,
			nil,
			nil,
		)
		w.Write(e)
	}
	w.Close()

	output := buf.String()

	for _, o := range outcomes {
		if !strings.Contains(output, o.icon) {
			t.Errorf("expected outcome icon %q for %s", o.icon, o.outcome)
		}
	}
}

func TestMarkdownWriter_OWASPMapping(t *testing.T) {
	t.Run("includes OWASP table when enabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeOWASP: true,
		})

		e1 := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, []string{"A03:2021"}, nil)
		e2 := makeMarkdownTestResultEvent("ssrf-001", "ssrf", events.SeverityHigh, events.OutcomeBlocked, []string{"A10:2021"}, nil)

		w.Write(e1)
		w.Write(e2)
		w.Close()

		output := buf.String()

		// Check for OWASP section header
		if !strings.Contains(output, "## OWASP Top 10 Mapping") {
			t.Error("expected OWASP Top 10 Mapping header")
		}

		// Check for table headers
		if !strings.Contains(output, "| Category | Description | Tests | Bypasses | Status |") {
			t.Error("expected OWASP table headers")
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

		// Check for status indicators
		if !strings.Contains(output, "⚠️ Fail") {
			t.Error("expected fail status for bypassed category")
		}
		if !strings.Contains(output, "✅ Pass") {
			t.Error("expected pass status for blocked category")
		}
	})

	t.Run("excludes OWASP table when disabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeOWASP: false,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, []string{"A03:2021"}, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		if strings.Contains(output, "## OWASP Top 10 Mapping") {
			t.Error("expected no OWASP section when disabled")
		}
	})
}

func TestMarkdownWriter_CWEReferences(t *testing.T) {
	t.Run("includes CWE table when enabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeCWE: true,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, []int{89, 79})
		w.Write(e)
		w.Close()

		output := buf.String()

		// Check for CWE section header
		if !strings.Contains(output, "## CWE References") {
			t.Error("expected CWE References header")
		}

		// Check for table headers
		if !strings.Contains(output, "| CWE ID | Description | Count | Bypasses |") {
			t.Error("expected CWE table headers")
		}

		// Check for CWE links
		if !strings.Contains(output, "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)") {
			t.Error("expected CWE-89 link")
		}

		if !strings.Contains(output, "[CWE-79](https://cwe.mitre.org/data/definitions/79.html)") {
			t.Error("expected CWE-79 link")
		}

		// Check for CWE descriptions
		if !strings.Contains(output, "SQL Injection") {
			t.Error("expected SQL Injection description")
		}

		if !strings.Contains(output, "Cross-site Scripting") {
			t.Error("expected Cross-site Scripting description")
		}
	})

	t.Run("excludes CWE table when disabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeCWE: false,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, []int{89})
		w.Write(e)
		w.Close()

		output := buf.String()

		if strings.Contains(output, "## CWE References") {
			t.Error("expected no CWE section when disabled")
		}
	})

	t.Run("excludes CWE table when no CWEs present", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeCWE: true,
		})

		e := makeMarkdownTestResultEvent("test-001", "test", events.SeverityHigh, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		if strings.Contains(output, "## CWE References") {
			t.Error("expected no CWE section when no CWEs present")
		}
	})
}

func TestMarkdownWriter_CollapsibleSections(t *testing.T) {
	t.Run("uses details/summary for GitHub flavor", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			Flavor:           "github",
			CollapseSections: true,
			IncludeEvidence:  true,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// Check for collapsible sections
		if !strings.Contains(output, "<details") {
			t.Error("expected <details> tag for collapsible sections")
		}

		if !strings.Contains(output, "<summary>") {
			t.Error("expected <summary> tag for collapsible sections")
		}

		if !strings.Contains(output, "</details>") {
			t.Error("expected </details> closing tag")
		}
	})

	t.Run("uses details/summary for GitLab flavor", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			Flavor:           "gitlab",
			CollapseSections: true,
			IncludeEvidence:  true,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "<details") {
			t.Error("expected <details> tag for GitLab flavor")
		}
	})

	t.Run("uses flat output for standard flavor", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			Flavor:           "standard",
			CollapseSections: true,
			IncludeEvidence:  true,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// Standard flavor should not use HTML
		if strings.Contains(output, "<details") {
			t.Error("expected no <details> tag for standard flavor")
		}
	})

	t.Run("bypasses shown first with 'open' attribute", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			Flavor:           "github",
			CollapseSections: true,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// Bypasses section should be open by default
		if !strings.Contains(output, "<details open>") {
			t.Error("expected bypasses section to have 'open' attribute")
		}
	})
}

func TestMarkdownWriter_Evidence(t *testing.T) {
	t.Run("includes evidence when enabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			Flavor:           "github",
			IncludeEvidence:  true,
			CollapseSections: true,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// Check for evidence section
		if !strings.Contains(output, "### Evidence") {
			t.Error("expected Evidence section")
		}

		// Check for payload
		if !strings.Contains(output, "**Payload:**") {
			t.Error("expected Payload label")
		}

		if !strings.Contains(output, "test-payload-sqli-001") {
			t.Error("expected payload content")
		}

		// Check for cURL command (now labeled as Reproduce)
		if !strings.Contains(output, "**Reproduce:**") {
			t.Error("expected cURL Command label")
		}

		if !strings.Contains(output, "curl -X POST") {
			t.Error("expected cURL content")
		}
	})

	t.Run("excludes evidence when disabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			IncludeEvidence: false,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		if strings.Contains(output, "### Evidence") {
			t.Error("expected no Evidence section when disabled")
		}
	})
}

func TestMarkdownWriter_PayloadTruncation(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewMarkdownWriter(buf, MarkdownConfig{
		IncludeEvidence: true,
		MaxPayloadLen:   20,
	})

	e := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan",
		},
		Test: events.TestInfo{
			ID:       "test-001",
			Category: "test",
			Severity: events.SeverityCritical,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com",
			Method: "GET",
		},
		Result: events.ResultInfo{
			Outcome:    events.OutcomeBypass,
			StatusCode: 200,
		},
		Evidence: &events.Evidence{
			Payload: "this-is-a-very-long-payload-that-should-be-truncated-for-display",
		},
	}

	w.Write(e)
	w.Close()

	output := buf.String()

	// Check that payload is truncated
	if strings.Contains(output, "truncated-for-display") {
		t.Error("expected payload to be truncated")
	}

	if !strings.Contains(output, "...") {
		t.Error("expected truncation indicator '...'")
	}
}

func TestMarkdownWriter_SortBy(t *testing.T) {
	t.Run("sorts by severity", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			SortBy:           "severity",
			CollapseSections: false,
		})

		// Add events in random severity order
		e1 := makeMarkdownTestResultEvent("low-001", "test", events.SeverityLow, events.OutcomeBypass, nil, nil)
		e2 := makeMarkdownTestResultEvent("critical-001", "test", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		e3 := makeMarkdownTestResultEvent("high-001", "test", events.SeverityHigh, events.OutcomeBypass, nil, nil)

		w.Write(e1)
		w.Write(e2)
		w.Write(e3)
		w.Close()

		output := buf.String()

		// Critical should appear before High, which should appear before Low
		criticalIdx := strings.Index(output, "critical-001")
		highIdx := strings.Index(output, "high-001")
		lowIdx := strings.Index(output, "low-001")

		if criticalIdx > highIdx || highIdx > lowIdx {
			t.Error("expected findings sorted by severity (critical > high > low)")
		}
	})

	t.Run("sorts by category", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			SortBy:           "category",
			CollapseSections: false,
		})

		e1 := makeMarkdownTestResultEvent("test-001", "xss", events.SeverityHigh, events.OutcomeBypass, nil, nil)
		e2 := makeMarkdownTestResultEvent("test-002", "sqli", events.SeverityHigh, events.OutcomeBypass, nil, nil)

		w.Write(e1)
		w.Write(e2)
		w.Close()

		output := buf.String()

		// sqli should appear before xss (alphabetical)
		sqliIdx := strings.Index(output, "| sqli |")
		xssIdx := strings.Index(output, "| xss |")

		if sqliIdx > xssIdx {
			t.Error("expected findings sorted by category (alphabetical)")
		}
	})

	t.Run("sorts by target", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			SortBy:           "target",
			CollapseSections: false,
		})

		e1 := &events.ResultEvent{
			BaseEvent: events.BaseEvent{Type: events.EventTypeResult, Time: time.Now(), Scan: "test"},
			Test:      events.TestInfo{ID: "test-001", Category: "test", Severity: events.SeverityHigh},
			Target:    events.TargetInfo{URL: "https://z-example.com", Method: "GET"},
			Result:    events.ResultInfo{Outcome: events.OutcomeBypass, StatusCode: 200},
		}
		e2 := &events.ResultEvent{
			BaseEvent: events.BaseEvent{Type: events.EventTypeResult, Time: time.Now(), Scan: "test"},
			Test:      events.TestInfo{ID: "test-002", Category: "test", Severity: events.SeverityHigh},
			Target:    events.TargetInfo{URL: "https://a-example.com", Method: "GET"},
			Result:    events.ResultInfo{Outcome: events.OutcomeBypass, StatusCode: 200},
		}

		w.Write(e1)
		w.Write(e2)
		w.Close()

		output := buf.String()

		// a-example should appear before z-example (alphabetical)
		aIdx := strings.Index(output, "a-example.com")
		zIdx := strings.Index(output, "z-example.com")

		if aIdx > zIdx {
			t.Error("expected findings sorted by target (alphabetical)")
		}
	})
}

func TestMarkdownWriter_SummarySection(t *testing.T) {
	t.Run("renders summary with metrics", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{})

		summary := makeMarkdownTestSummaryEvent()
		w.Write(summary)
		w.Close()

		output := buf.String()

		// Check for summary section
		if !strings.Contains(output, "## Summary") {
			t.Error("expected Summary section")
		}

		// Check for target URL
		if !strings.Contains(output, "https://example.com") {
			t.Error("expected target URL in summary")
		}

		// Check for WAF detected
		if !strings.Contains(output, "Cloudflare") {
			t.Error("expected WAF name in summary")
		}

		// Check for metrics table
		requiredMetrics := []string{
			"Total Tests",
			"Bypasses",
			"Blocked",
			"Block Rate",
			"Grade",
			"Duration",
		}

		for _, metric := range requiredMetrics {
			if !strings.Contains(output, metric) {
				t.Errorf("expected metric %q in summary table", metric)
			}
		}
	})

	t.Run("shows bypasses by severity", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{})

		summary := makeMarkdownTestSummaryEvent()
		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)

		w.Write(e)
		w.Write(summary)
		w.Close()

		output := buf.String()

		// Check for bypasses by severity section
		if !strings.Contains(output, "### Bypasses by Severity") {
			t.Error("expected Bypasses by Severity section")
		}

		// Check for severity table
		if !strings.Contains(output, "| Severity | Count |") {
			t.Error("expected severity breakdown table")
		}
	})
}

func TestMarkdownWriter_SeverityDistribution(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewMarkdownWriter(buf, MarkdownConfig{})

	// Add multiple bypasses with different severities
	e1 := makeMarkdownTestResultEvent("crit-001", "test", events.SeverityCritical, events.OutcomeBypass, nil, nil)
	e2 := makeMarkdownTestResultEvent("crit-002", "test", events.SeverityCritical, events.OutcomeBypass, nil, nil)
	e3 := makeMarkdownTestResultEvent("high-001", "test", events.SeverityHigh, events.OutcomeBypass, nil, nil)

	w.Write(e1)
	w.Write(e2)
	w.Write(e3)
	w.Close()

	output := buf.String()

	// Check for severity distribution section (now called Risk Distribution)
	if !strings.Contains(output, "## Risk Distribution") {
		t.Error("expected Severity Distribution section")
	}

	// Check for ASCII bar chart indicators
	if !strings.Contains(output, "█") {
		t.Error("expected bar chart characters")
	}
}

func TestMarkdownWriter_FindingsSection(t *testing.T) {
	t.Run("renders findings table", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{
			CollapseSections: false,
		})

		e := makeMarkdownTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass, nil, nil)
		w.Write(e)
		w.Close()

		output := buf.String()

		// Check for findings section
		if !strings.Contains(output, "## Findings") {
			t.Error("expected Findings section")
		}

		// Check for table headers
		if !strings.Contains(output, "| Severity | ID | Category | Target | Outcome | Status |") {
			t.Error("expected findings table headers")
		}

		// Check for finding row
		if !strings.Contains(output, "sqli-001") {
			t.Error("expected finding ID in table")
		}

		if !strings.Contains(output, "| sqli |") {
			t.Error("expected category in table")
		}
	})

	t.Run("shows no findings message when empty", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewMarkdownWriter(buf, MarkdownConfig{})
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "No findings to report") {
			t.Error("expected 'No findings to report' message")
		}
	})
}

func TestMarkdownWriter_URLTruncation(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewMarkdownWriter(buf, MarkdownConfig{
		CollapseSections: false,
	})

	longURL := "https://example.com/very/long/path/that/exceeds/the/maximum/allowed/length/for/display/in/the/table"
	e := &events.ResultEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeResult, Time: time.Now(), Scan: "test"},
		Test:      events.TestInfo{ID: "test-001", Category: "test", Severity: events.SeverityHigh},
		Target:    events.TargetInfo{URL: longURL, Method: "GET"},
		Result:    events.ResultInfo{Outcome: events.OutcomeBypass, StatusCode: 200},
	}

	w.Write(e)
	w.Close()

	output := buf.String()

	// URL should be truncated
	if strings.Contains(output, "length/for/display/in/the/table") {
		t.Error("expected URL to be truncated")
	}
}

func TestMarkdownWriter_ConcurrentWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewMarkdownWriter(buf, MarkdownConfig{})

	// Write events concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			e := makeMarkdownTestResultEvent(
				"test-"+string(rune('0'+id)),
				"test",
				events.SeverityHigh,
				events.OutcomeBypass,
				nil,
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

	// Should not panic and Close should work
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed after concurrent writes: %v", err)
	}
}

func TestCapitalizeFirst(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", "Critical"},
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
		{"info", "Info"},
		{"", ""},
		{"a", "A"},
		{"ALREADY", "ALREADY"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := capitalizeFirst(tc.input)
			if result != tc.expected {
				t.Errorf("capitalizeFirst(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is..."},
		{"abc", 3, "abc"},
		{"abcd", 3, "..."},
		{"", 10, ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := truncateString(tc.input, tc.maxLen)
			if result != tc.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tc.input, tc.maxLen, result, tc.expected)
			}
		})
	}
}

func TestSeverityIcon(t *testing.T) {
	tests := []struct {
		severity events.Severity
		expected string
	}{
		{events.SeverityCritical, "🔴"},
		{events.SeverityHigh, "🟠"},
		{events.SeverityMedium, "🟡"},
		{events.SeverityLow, "🟢"},
		{events.SeverityInfo, "🔵"},
		{events.Severity("unknown"), "🔵"}, // Default to info icon
	}

	for _, tc := range tests {
		t.Run(string(tc.severity), func(t *testing.T) {
			result := severityIcon(tc.severity)
			if result != tc.expected {
				t.Errorf("severityIcon(%q) = %q, want %q", tc.severity, result, tc.expected)
			}
		})
	}
}

func TestSeverityPriority(t *testing.T) {
	tests := []struct {
		severity events.Severity
		expected int
	}{
		{events.SeverityCritical, 5},
		{events.SeverityHigh, 4},
		{events.SeverityMedium, 3},
		{events.SeverityLow, 2},
		{events.SeverityInfo, 1},
		{events.Severity("unknown"), 1}, // Default to lowest priority
	}

	for _, tc := range tests {
		t.Run(string(tc.severity), func(t *testing.T) {
			result := severityPriority(tc.severity)
			if result != tc.expected {
				t.Errorf("severityPriority(%q) = %d, want %d", tc.severity, result, tc.expected)
			}
		})
	}
}

func TestOutcomeIcon(t *testing.T) {
	tests := []struct {
		outcome  events.Outcome
		expected string
	}{
		{events.OutcomeBypass, "⚠️"},
		{events.OutcomeBlocked, "✅"},
		{events.OutcomeError, "❌"},
		{events.OutcomeTimeout, "⏱️"},
		{events.OutcomePass, "ℹ️"},
		{events.Outcome("unknown"), "ℹ️"}, // Default to info icon
	}

	for _, tc := range tests {
		t.Run(string(tc.outcome), func(t *testing.T) {
			result := outcomeIcon(tc.outcome)
			if result != tc.expected {
				t.Errorf("outcomeIcon(%q) = %q, want %q", tc.outcome, result, tc.expected)
			}
		})
	}
}
