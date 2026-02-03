package writers

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// makeTemplateTestResultEvent creates a test result event for template tests.
func makeTemplateTestResultEvent(id, category string, severity events.Severity, outcome events.Outcome) *events.ResultEvent {
	return &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-template-123",
		},
		Test: events.TestInfo{
			ID:       id,
			Name:     id + " test",
			Category: category,
			Severity: severity,
			OWASP:    []string{"A03:2021"},
			CWE:      []int{89},
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

// makeTemplateTestSummaryEvent creates a test summary event for template tests.
func makeTemplateTestSummaryEvent() *events.SummaryEvent {
	return &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: time.Now(),
			Scan: "test-scan-template-123",
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
			Timeouts: 2,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct: 90.0,
			Grade:        "A",
		},
		Timing: events.SummaryTiming{
			StartedAt:   time.Now().Add(-time.Minute),
			CompletedAt: time.Now(),
			DurationSec: 60.0,
		},
	}
}

func TestTemplateWriter_BuiltInCSV(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		BuiltIn: "csv",
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	// Write test events
	e1 := makeTemplateTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
	e2 := makeTemplateTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBlocked)

	if err := w.Write(e1); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := w.Write(e2); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	// Check CSV header
	if !strings.Contains(output, "ID,Category,Severity,Method,Status,Outcome,ResponseTime,Payload") {
		t.Error("expected CSV header in output")
	}

	// Check first result row
	if !strings.Contains(output, "sqli-001") {
		t.Error("expected sqli-001 in output")
	}
	if !strings.Contains(output, "sqli") {
		t.Error("expected sqli category in output")
	}
	if !strings.Contains(output, "critical") {
		t.Error("expected critical severity in output")
	}
	if !strings.Contains(output, "POST") {
		t.Error("expected POST method in output")
	}
	if !strings.Contains(output, "bypass") {
		t.Error("expected bypass outcome in output")
	}

	// Check second result row
	if !strings.Contains(output, "xss-001") {
		t.Error("expected xss-001 in output")
	}
	if !strings.Contains(output, "blocked") {
		t.Error("expected blocked outcome in output")
	}
}

func TestTemplateWriter_BuiltInTextSummary(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		BuiltIn: "text-summary",
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	// Write bypass events to generate severity counts
	e1 := makeTemplateTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
	e2 := makeTemplateTestResultEvent("sqli-002", "sqli", events.SeverityCritical, events.OutcomeBypass)
	e3 := makeTemplateTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBlocked)

	w.Write(e1)
	w.Write(e2)
	w.Write(e3)

	// Write summary
	summary := makeTemplateTestSummaryEvent()
	w.Write(summary)

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	// Check title
	if !strings.Contains(output, "WAFtester Scan Summary") {
		t.Error("expected summary title in output")
	}

	// Check target
	if !strings.Contains(output, "Target: https://example.com") {
		t.Error("expected target URL in output")
	}

	// Check results counts
	if !strings.Contains(output, "Total Tests:") {
		t.Error("expected total tests in output")
	}
	if !strings.Contains(output, "Bypasses:") {
		t.Error("expected bypasses count in output")
	}
	if !strings.Contains(output, "Blocked:") {
		t.Error("expected blocked count in output")
	}

	// Check effectiveness
	if !strings.Contains(output, "WAF Effectiveness:") {
		t.Error("expected effectiveness in output")
	}

	// Check severity icons (since we have bypasses)
	if !strings.Contains(output, "Bypasses by Severity:") {
		t.Error("expected severity breakdown in output")
	}
}

func TestTemplateWriter_CustomTemplate(t *testing.T) {
	customTemplate := `Custom Report
Target: {{ .Target }}
Results: {{ len .Results }}
{{- range .Results }}
- {{ .Test.ID }}: {{ .Result.Outcome }}
{{- end }}`

	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		TemplateString: customTemplate,
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	e := makeTemplateTestResultEvent("test-001", "test", events.SeverityMedium, events.OutcomeBlocked)
	w.Write(e)

	summary := makeTemplateTestSummaryEvent()
	w.Write(summary)

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Custom Report") {
		t.Error("expected custom report title in output")
	}
	if !strings.Contains(output, "Results: 1") {
		t.Error("expected results count in output")
	}
	if !strings.Contains(output, "- test-001: blocked") {
		t.Error("expected result line in output")
	}
}

func TestTemplateWriter_CustomTemplateFile(t *testing.T) {
	// Create a temporary template file
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "custom.tmpl")

	templateContent := `File Template Test
Scan ID: {{ .ScanID }}
Total: {{ .TotalTests }}`

	if err := os.WriteFile(templatePath, []byte(templateContent), 0644); err != nil {
		t.Fatalf("failed to write template file: %v", err)
	}

	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		TemplatePath: templatePath,
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	e := makeTemplateTestResultEvent("file-test-001", "test", events.SeverityLow, events.OutcomePass)
	w.Write(e)

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "File Template Test") {
		t.Error("expected file template title in output")
	}
	if !strings.Contains(output, "Scan ID: test-scan-template-123") {
		t.Error("expected scan ID in output")
	}
	if !strings.Contains(output, "Total: 1") {
		t.Error("expected total count in output")
	}
}

func TestTemplateWriter_SprigFunctions(t *testing.T) {
	tests := []struct {
		name     string
		template string
		expected string
	}{
		{
			name:     "upper function",
			template: `{{ "hello" | upper }}`,
			expected: "HELLO",
		},
		{
			name:     "lower function",
			template: `{{ "WORLD" | lower }}`,
			expected: "world",
		},
		{
			name:     "title function",
			template: `{{ "hello world" | title }}`,
			expected: "Hello World",
		},
		{
			name:     "trim function",
			template: `{{ "  spaces  " | trim }}`,
			expected: "spaces",
		},
		{
			name:     "default function",
			template: `{{ "" | default "fallback" }}`,
			expected: "fallback",
		},
		{
			name:     "now function",
			template: `{{ now | date "2006" }}`,
			expected: time.Now().Format("2006"),
		},
		{
			name:     "add function",
			template: `{{ add 1 2 }}`,
			expected: "3",
		},
		{
			name:     "sub function",
			template: `{{ sub 5 2 }}`,
			expected: "3",
		},
		{
			name:     "list and join",
			template: `{{ list "a" "b" "c" | join "," }}`,
			expected: "a,b,c",
		},
		{
			name:     "repeat function",
			template: `{{ repeat 3 "x" }}`,
			expected: "xxx",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			w, err := NewTemplateWriter(buf, TemplateConfig{
				TemplateString: tc.template,
			})
			if err != nil {
				t.Fatalf("failed to create writer: %v", err)
			}

			if err := w.Close(); err != nil {
				t.Fatalf("close failed: %v", err)
			}

			output := strings.TrimSpace(buf.String())
			if output != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, output)
			}
		})
	}
}

func TestTemplateWriter_CustomFunctions(t *testing.T) {
	t.Run("escapeCSV", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"simple", "simple"},
			{"with,comma", `"with,comma"`},
			{`with"quote`, `"with""quote"`},
			{"with\nnewline", `"with` + "\n" + `newline"`},
			{"", ""},
		}

		for _, tc := range tests {
			result := tmplEscapeCSV(tc.input)
			if result != tc.expected {
				t.Errorf("tmplEscapeCSV(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		}
	})

	t.Run("escapeXML", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"simple", "simple"},
			{"<tag>", "&lt;tag&gt;"},
			{"a & b", "a &amp; b"},
			{`a "b" c`, "a &#34;b&#34; c"},
		}

		for _, tc := range tests {
			result := tmplEscapeXML(tc.input)
			if result != tc.expected {
				t.Errorf("tmplEscapeXML(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		}
	})

	t.Run("severityIcon", func(t *testing.T) {
		tests := []struct {
			severity string
			expected string
		}{
			{"critical", "🔴"},
			{"CRITICAL", "🔴"},
			{"high", "🟠"},
			{"medium", "🟡"},
			{"low", "🟢"},
			{"info", "🔵"},
			{"unknown", "⚪"},
		}

		for _, tc := range tests {
			result := tmplSeverityIcon(tc.severity)
			if result != tc.expected {
				t.Errorf("tmplSeverityIcon(%q) = %q, expected %q", tc.severity, result, tc.expected)
			}
		}
	})

	t.Run("json function", func(t *testing.T) {
		data := map[string]int{"count": 42}
		result := tmplToJSON(data)
		if result != `{"count":42}` {
			t.Errorf("tmplToJSON() = %q, expected %q", result, `{"count":42}`)
		}
	})

	t.Run("prettyJSON function", func(t *testing.T) {
		data := map[string]int{"count": 42}
		result := tmplPrettyJSON(data)
		expected := "{\n  \"count\": 42\n}"
		if result != expected {
			t.Errorf("tmplPrettyJSON() = %q, expected %q", result, expected)
		}
	})

	t.Run("owaspLink", func(t *testing.T) {
		tests := []struct {
			id       string
			expected string
		}{
			{"A03:2021", "https://owasp.org/Top10/a03-2021/"},
			{"A01:2021", "https://owasp.org/Top10/a01-2021/"},
		}

		for _, tc := range tests {
			result := tmplOwaspLink(tc.id)
			if result != tc.expected {
				t.Errorf("tmplOwaspLink(%q) = %q, expected %q", tc.id, result, tc.expected)
			}
		}
	})

	t.Run("cweLink", func(t *testing.T) {
		tests := []struct {
			id       int
			expected string
		}{
			{89, "https://cwe.mitre.org/data/definitions/89.html"},
			{79, "https://cwe.mitre.org/data/definitions/79.html"},
		}

		for _, tc := range tests {
			result := tmplCweLink(tc.id)
			if result != tc.expected {
				t.Errorf("tmplCweLink(%d) = %q, expected %q", tc.id, result, tc.expected)
			}
		}
	})
}

func TestTemplateWriter_CustomFunctionsInTemplate(t *testing.T) {
	template := `
{{- $payload := "test<script>alert(1)</script>" }}
CSV: {{ $payload | escapeCSV }}
XML: {{ $payload | escapeXML }}
Severity: {{ "critical" | severityIcon }}
OWASP: {{ owaspLink "A03:2021" }}
CWE: {{ cweLink 89 }}`

	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		TemplateString: template,
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "CSV: test<script>alert(1)</script>") {
		t.Error("expected CSV escaped payload in output")
	}
	if !strings.Contains(output, "XML: test&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("expected XML escaped payload in output")
	}
	if !strings.Contains(output, "Severity: 🔴") {
		t.Error("expected severity icon in output")
	}
	if !strings.Contains(output, "OWASP: https://owasp.org/Top10/a03-2021/") {
		t.Error("expected OWASP link in output")
	}
	if !strings.Contains(output, "CWE: https://cwe.mitre.org/data/definitions/89.html") {
		t.Error("expected CWE link in output")
	}
}

func TestTemplateWriter_InvalidTemplate(t *testing.T) {
	t.Run("invalid template syntax", func(t *testing.T) {
		buf := &bytes.Buffer{}
		_, err := NewTemplateWriter(buf, TemplateConfig{
			TemplateString: "{{ .Invalid | unknownFunc }}",
		})
		if err == nil {
			t.Error("expected error for invalid template")
		}
		if !strings.Contains(err.Error(), "template parse error") {
			t.Errorf("expected template parse error, got: %v", err)
		}
	})

	t.Run("unknown built-in template", func(t *testing.T) {
		buf := &bytes.Buffer{}
		_, err := NewTemplateWriter(buf, TemplateConfig{
			BuiltIn: "nonexistent",
		})
		if err == nil {
			t.Error("expected error for unknown built-in template")
		}
		if !strings.Contains(err.Error(), "unknown built-in template") {
			t.Errorf("expected unknown built-in template error, got: %v", err)
		}
	})

	t.Run("no template specified", func(t *testing.T) {
		buf := &bytes.Buffer{}
		_, err := NewTemplateWriter(buf, TemplateConfig{})
		if err == nil {
			t.Error("expected error when no template specified")
		}
		if !strings.Contains(err.Error(), "no template specified") {
			t.Errorf("expected no template specified error, got: %v", err)
		}
	})

	t.Run("nonexistent template file", func(t *testing.T) {
		buf := &bytes.Buffer{}
		_, err := NewTemplateWriter(buf, TemplateConfig{
			TemplatePath: "/nonexistent/path/template.tmpl",
		})
		if err == nil {
			t.Error("expected error for nonexistent template file")
		}
		if !strings.Contains(err.Error(), "failed to read template file") {
			t.Errorf("expected file read error, got: %v", err)
		}
	})

	t.Run("unclosed template action", func(t *testing.T) {
		buf := &bytes.Buffer{}
		_, err := NewTemplateWriter(buf, TemplateConfig{
			TemplateString: "{{ .ScanID",
		})
		if err == nil {
			t.Error("expected error for unclosed template action")
		}
	})
}

func TestTemplateWriter_SupportsEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		TemplateString: "test",
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	tests := []struct {
		eventType events.EventType
		expected  bool
	}{
		{events.EventTypeResult, true},
		{events.EventTypeSummary, true},
		{events.EventTypeProgress, false},
		{events.EventTypeBypass, false},
		{events.EventTypeError, false},
		{events.EventTypeStart, false},
		{events.EventTypeComplete, false},
	}

	for _, tc := range tests {
		result := w.SupportsEvent(tc.eventType)
		if result != tc.expected {
			t.Errorf("SupportsEvent(%s) = %v, expected %v", tc.eventType, result, tc.expected)
		}
	}
}

func TestTemplateWriter_FlushIsNoOp(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		TemplateString: "test",
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	// Flush should not error and should not write anything
	if err := w.Flush(); err != nil {
		t.Errorf("Flush() returned error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Flush() wrote data, expected no output")
	}
}

func TestTemplateWriter_SeverityCountsAndHighest(t *testing.T) {
	template := `Highest: {{ .HighestSeverity }}
{{- range $sev, $count := .SeverityCounts }}
{{ $sev }}: {{ $count }}
{{- end }}`

	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		TemplateString: template,
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	// Write bypasses with different severities
	w.Write(makeTemplateTestResultEvent("crit-001", "test", events.SeverityCritical, events.OutcomeBypass))
	w.Write(makeTemplateTestResultEvent("high-001", "test", events.SeverityHigh, events.OutcomeBypass))
	w.Write(makeTemplateTestResultEvent("high-002", "test", events.SeverityHigh, events.OutcomeBypass))
	w.Write(makeTemplateTestResultEvent("med-001", "test", events.SeverityMedium, events.OutcomeBlocked)) // Not a bypass

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	// Critical should be highest
	if !strings.Contains(output, "Highest: critical") {
		t.Error("expected highest severity to be critical")
	}

	// Check counts (only bypasses counted)
	if !strings.Contains(output, "critical: 1") {
		t.Error("expected critical count of 1")
	}
	if !strings.Contains(output, "high: 2") {
		t.Error("expected high count of 2")
	}
}

func TestTemplateWriter_BuiltInASFF(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := NewTemplateWriter(buf, TemplateConfig{
		BuiltIn: "asff",
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	// Write bypass events
	e1 := makeTemplateTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
	e2 := makeTemplateTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBypass)
	w.Write(e1)
	w.Write(e2)

	// Write summary
	summary := makeTemplateTestSummaryEvent()
	w.Write(summary)

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	// Check ASFF structure
	if !strings.Contains(output, `"SchemaVersion": "2018-10-08"`) {
		t.Error("expected ASFF schema version in output")
	}
	if !strings.Contains(output, `"ProductArn": "arn:aws:securityhub:us-east-1::product/waftester/waftester"`) {
		t.Error("expected ASFF product ARN in output")
	}
	if !strings.Contains(output, `"GeneratorId": "waftester"`) {
		t.Error("expected ASFF generator ID in output")
	}
	if !strings.Contains(output, `"Title": "WAFtester Security Scan Results"`) {
		t.Error("expected ASFF title in output")
	}
	if !strings.Contains(output, `"Findings":`) {
		t.Error("expected ASFF findings array in output")
	}
}
