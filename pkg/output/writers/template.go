// Package writers provides output writers for various formats.
package writers

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*TemplateWriter)(nil)

// TemplateConfig configures the template writer.
type TemplateConfig struct {
	// TemplatePath is the path to a custom template file.
	TemplatePath string

	// TemplateString is an inline template string (alternative to TemplatePath).
	TemplateString string

	// BuiltIn is the name of a built-in template: "csv", "asff", "text-summary".
	BuiltIn string
}

// builtInTemplates contains pre-defined templates for common output formats.
var builtInTemplates = map[string]string{
	"csv": `ID,Category,Severity,Method,Status,Outcome,ResponseTime,Payload
{{- range .Results }}
{{ .Test.ID }},{{ .Test.Category }},{{ .Test.Severity }},{{ .Target.Method }},{{ .Result.StatusCode }},{{ .Result.Outcome }},{{ printf "%.2f" .Result.LatencyMs }},{{ escapeCSV .Payload }}
{{- end }}`,

	"asff": `{
  "SchemaVersion": "2018-10-08",
  "Id": "{{ .ScanID }}/waftester",
  "ProductArn": "arn:aws:securityhub:us-east-1::product/waftester/waftester",
  "GeneratorId": "waftester",
  "AwsAccountId": "{{ .AWSAccountID | default "000000000000" }}",
  "Types": ["Software and Configuration Checks/Vulnerabilities/WAF"],
  "CreatedAt": "{{ .Timestamp }}",
  "UpdatedAt": "{{ .Timestamp }}",
  "Severity": {
    "Label": "{{ .HighestSeverity | toString | upper }}"
  },
  "Title": "WAFtester Security Scan Results",
  "Description": "WAF security testing found {{ .BypassCount }} bypasses out of {{ .TotalTests }} tests",
  "Resources": [
    {
      "Type": "Other",
      "Id": "{{ .Target }}",
      "Partition": "aws",
      "Region": "{{ .Region | default "us-east-1" }}"
    }
  ],
  "Findings": [
{{- $last := sub (len .Bypasses) 1 }}
{{- range $i, $bypass := .Bypasses }}
    {
      "Id": "{{ $.ScanID }}/{{ $bypass.Test.ID }}",
      "Severity": "{{ $bypass.Test.Severity | toString | upper }}",
      "Title": "WAF Bypass: {{ $bypass.Test.Category }}",
      "Description": "{{ $bypass.Test.Name | default $bypass.Test.ID }}"
    }{{ if lt $i $last }},{{ end }}
{{- end }}
  ]
}`,

	"text-summary": `WAFtester Scan Summary
======================
Target: {{ .Target }}
Generated: {{ .Timestamp }}
Duration: {{ printf "%.2f" .Duration }}s

Results:
  Total Tests: {{ .TotalTests }}
  Blocked: {{ .Blocked }}
  Bypasses: {{ .BypassCount }}
  Errors: {{ .Errors }}

WAF Effectiveness: {{ printf "%.1f" .Effectiveness }}%
{{ if gt .BypassCount 0 }}
Bypasses by Severity:
{{- range $sev, $count := .SeverityCounts }}
  {{ severityIcon $sev }} {{ $sev | title }}: {{ $count }}
{{- end }}
{{ end }}`,
}

// TemplateWriter renders events using Go templates.
// It buffers all events in memory and renders the template on Close.
// The writer supports custom templates, inline templates, and built-in templates.
// Sprig functions and WAFtester-specific functions are available in templates.
type TemplateWriter struct {
	w         io.Writer
	mu        sync.Mutex
	config    TemplateConfig
	tmpl      *template.Template
	results   []*events.ResultEvent
	summary   *events.SummaryEvent
	scanID    string
	startTime time.Time
}

// NewTemplateWriter creates a new template writer.
// It parses the template immediately and returns an error if the template is invalid.
// The writer buffers all events and writes the rendered template on Close.
func NewTemplateWriter(w io.Writer, config TemplateConfig) (*TemplateWriter, error) {
	tw := &TemplateWriter{
		w:         w,
		config:    config,
		results:   make([]*events.ResultEvent, 0),
		startTime: time.Now(),
	}

	// Parse template
	if err := tw.parseTemplate(); err != nil {
		return nil, fmt.Errorf("template parse error: %w", err)
	}

	return tw, nil
}

// parseTemplate parses the template from config (path, string, or built-in).
func (tw *TemplateWriter) parseTemplate() error {
	var templateContent string

	// Determine template source
	switch {
	case tw.config.TemplatePath != "":
		content, err := os.ReadFile(tw.config.TemplatePath)
		if err != nil {
			return fmt.Errorf("failed to read template file: %w", err)
		}
		templateContent = string(content)

	case tw.config.TemplateString != "":
		templateContent = tw.config.TemplateString

	case tw.config.BuiltIn != "":
		content, ok := builtInTemplates[tw.config.BuiltIn]
		if !ok {
			return fmt.Errorf("unknown built-in template: %s (available: csv, asff, text-summary)", tw.config.BuiltIn)
		}
		templateContent = content

	default:
		return fmt.Errorf("no template specified: set TemplatePath, TemplateString, or BuiltIn")
	}

	// Create function map with Sprig functions
	funcMap := sprig.TxtFuncMap()

	// Add WAFtester-specific functions
	funcMap["escapeCSV"] = tmplEscapeCSV
	funcMap["escapeXML"] = tmplEscapeXML
	funcMap["severityIcon"] = tmplSeverityIcon
	funcMap["json"] = tmplToJSON
	funcMap["prettyJSON"] = tmplPrettyJSON
	funcMap["owaspLink"] = tmplOwaspLink
	funcMap["cweLink"] = tmplCweLink

	// Parse template with all functions
	tmpl, err := template.New("waftester").Funcs(funcMap).Parse(templateContent)
	if err != nil {
		return fmt.Errorf("parse output template: %w", err)
	}

	tw.tmpl = tmpl
	return nil
}

// Write buffers an event for later template rendering.
func (tw *TemplateWriter) Write(event events.Event) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	// Capture scan ID from first event
	if tw.scanID == "" {
		tw.scanID = event.ScanID()
	}

	switch e := event.(type) {
	case *events.ResultEvent:
		tw.results = append(tw.results, e)
	case *events.SummaryEvent:
		tw.summary = e
	}
	return nil
}

// Flush is a no-op for template writer.
// All events are rendered as a single document on Close.
func (tw *TemplateWriter) Flush() error {
	return nil
}

// Close renders the template with all buffered events and writes to the output.
func (tw *TemplateWriter) Close() error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	data := tw.buildTemplateData()

	var buf bytes.Buffer
	if err := tw.tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("template execution error: %w", err)
	}

	if _, err := tw.w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	if closer, ok := tw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SupportsEvent returns true for result and summary events.
func (tw *TemplateWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeSummary:
		return true
	default:
		return false
	}
}

// tmplData holds all data available to templates.
type tmplData struct {
	// Basic info
	ScanID    string
	Target    string
	Timestamp string
	Duration  float64

	// Results
	Results  []*tmplResultData
	Bypasses []*tmplResultData

	// Summary counts
	TotalTests    int
	Blocked       int
	BypassCount   int
	Errors        int
	Timeouts      int
	Effectiveness float64
	Grade         string

	// Breakdown
	SeverityCounts  map[string]int
	CategoryCounts  map[string]int
	HighestSeverity string

	// AWS-specific fields for ASFF template
	AWSAccountID string
	Region       string
}

// tmplResultData is a flattened view of ResultEvent for easier template access.
type tmplResultData struct {
	Test     events.TestInfo
	Target   events.TargetInfo
	Result   events.ResultInfo
	Evidence *events.Evidence
	Context  *events.ContextInfo
	Payload  string
}

// buildTemplateData constructs the data object for template rendering.
func (tw *TemplateWriter) buildTemplateData() *tmplData {
	data := &tmplData{
		ScanID:         tw.scanID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Results:        make([]*tmplResultData, 0, len(tw.results)),
		Bypasses:       make([]*tmplResultData, 0),
		SeverityCounts: make(map[string]int),
		CategoryCounts: make(map[string]int),
	}

	// Process results
	for _, r := range tw.results {
		rd := &tmplResultData{
			Test:     r.Test,
			Target:   r.Target,
			Result:   r.Result,
			Evidence: r.Evidence,
			Context:  r.Context,
		}
		if r.Evidence != nil {
			rd.Payload = r.Evidence.Payload
		}
		data.Results = append(data.Results, rd)

		// Count by outcome
		switch r.Result.Outcome {
		case events.OutcomeBypass:
			data.BypassCount++
			data.Bypasses = append(data.Bypasses, rd)
			// Count by severity
			sev := string(r.Test.Severity)
			data.SeverityCounts[sev]++
			// Track highest severity
			if isHigherSeverity(sev, data.HighestSeverity) {
				data.HighestSeverity = sev
			}
		case events.OutcomeBlocked:
			data.Blocked++
		case events.OutcomeError:
			data.Errors++
		case events.OutcomeTimeout:
			data.Timeouts++
		}

		// Count by category
		data.CategoryCounts[r.Test.Category]++
	}

	data.TotalTests = len(tw.results)

	// Calculate effectiveness
	if data.TotalTests > 0 {
		data.Effectiveness = float64(data.Blocked) / float64(data.TotalTests) * 100
	}

	// Extract summary data if available
	if tw.summary != nil {
		data.Target = tw.summary.Target.URL
		data.Duration = tw.summary.Timing.DurationSec
		data.Grade = tw.summary.Effectiveness.Grade
		if data.Effectiveness == 0 {
			data.Effectiveness = tw.summary.Effectiveness.BlockRatePct
		}
	}

	return data
}

// isHigherSeverity returns true if sev is higher than current.
func isHigherSeverity(sev, current string) bool {
	order := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}
	return order[strings.ToLower(sev)] > order[strings.ToLower(current)]
}

// Template helper functions

// tmplEscapeCSV escapes a string for CSV output.
// It wraps the value in quotes if it contains commas, quotes, or newlines.
func tmplEscapeCSV(s string) string {
	if s == "" {
		return ""
	}
	needsQuote := strings.ContainsAny(s, ",\"\n\r")
	if needsQuote {
		escaped := strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + escaped + "\""
	}
	return s
}

// tmplEscapeXML escapes a string for XML output.
func tmplEscapeXML(s string) string {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return s
	}
	return buf.String()
}

// tmplSeverityIcon returns an emoji icon for a severity level.
func tmplSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	case "info":
		return "🔵"
	default:
		return "⚪"
	}
}

// tmplToJSON converts a value to a JSON string.
func tmplToJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(b)
}

// tmplPrettyJSON converts a value to a formatted JSON string.
func tmplPrettyJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(b)
}

// tmplOwaspLink returns a link to the OWASP Top 10 page for a given ID.
func tmplOwaspLink(id string) string {
	// Normalize the ID (e.g., "A03:2021" -> "a03-2021")
	normalized := strings.ToLower(strings.ReplaceAll(id, ":", "-"))
	return fmt.Sprintf("https://owasp.org/Top10/%s/", normalized)
}

// tmplCweLink returns a link to the CWE page for a given ID.
func tmplCweLink(id int) string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", id)
}
