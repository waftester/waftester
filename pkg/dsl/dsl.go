// Package dsl provides DSL-based output formatting for scan results
package dsl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Formatter handles DSL template-based output formatting
type Formatter struct {
	// Template is the Go template string
	Template string

	// Compiled template
	tmpl *template.Template

	// StrictMode causes errors on missing fields
	StrictMode bool
}

// Result represents a generic scan result for DSL formatting
type Result struct {
	// Core fields
	URL    string `json:"url"`
	Target string `json:"target"`
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
	Path   string `json:"path"`

	// HTTP fields
	StatusCode     int               `json:"status_code"`
	Status         string            `json:"status"`
	ContentLength  int64             `json:"content_length"`
	ContentType    string            `json:"content_type"`
	Server         string            `json:"server"`
	Title          string            `json:"title"`
	Method         string            `json:"method"`
	Location       string            `json:"location"`
	ResponseTime   time.Duration     `json:"response_time"`
	ResponseTimeMs int64             `json:"response_time_ms"`
	Headers        map[string]string `json:"headers"`

	// Body analysis
	WordCount   int    `json:"word_count"`
	LineCount   int    `json:"line_count"`
	BodyHash    string `json:"body_hash"`
	BodyPreview string `json:"body_preview"`

	// Security/Detection
	WAF          string   `json:"waf"`
	CDN          string   `json:"cdn"`
	Technologies []string `json:"technologies"`
	Tech         string   `json:"tech"` // Comma-joined technologies
	Fingerprint  string   `json:"fingerprint"`

	// TLS
	TLSVersion string `json:"tls_version"`
	TLSCipher  string `json:"tls_cipher"`
	TLSExpiry  string `json:"tls_expiry"`
	JARM       string `json:"jarm"`

	// Network
	ASN      string `json:"asn"`
	ASNOrg   string `json:"asn_org"`
	CNAME    string `json:"cname"`
	Alive    bool   `json:"alive"`
	Duration string `json:"duration"`

	// Metadata
	Timestamp  time.Time `json:"timestamp"`
	ScanType   string    `json:"scan_type"`
	Severity   string    `json:"severity"`
	Confidence string    `json:"confidence"`
	MatchedBy  string    `json:"matched_by"`

	// Custom fields (for plugins/extensions)
	Custom map[string]interface{} `json:"custom,omitempty"`
}

// Common preset formats
var Presets = map[string]string{
	"url":    "{{.URL}}",
	"host":   "{{.Host}}",
	"ip":     "{{.IP}}",
	"status": "{{.URL}} [{{.StatusCode}}]",
	"tech":   "{{.URL}} [{{.Tech}}]",
	"full":   "{{.URL}} [{{.StatusCode}}] [{{.ContentLength}}] [{{.Title}}]",
	"httpx":  "{{.URL}} [{{.StatusCode}}] [{{.ContentType}}] [{{.ContentLength}}] [{{.Title}}]",
	"csv":    "{{.URL}},{{.StatusCode}},{{.ContentLength}},{{.Title}}",
	"nuclei": "[{{.Severity}}] {{.URL}} [{{.MatchedBy}}]",
	"json":   "", // Special case - outputs JSON
	"jsonl":  "", // Special case - outputs JSONL
}

// templateFuncs provides helper functions for templates
var templateFuncs = template.FuncMap{
	// String functions
	"lower":     strings.ToLower,
	"upper":     strings.ToUpper,
	"title":     cases.Title(language.English).String,
	"trim":      strings.TrimSpace,
	"replace":   strings.ReplaceAll,
	"contains":  strings.Contains,
	"hasPrefix": strings.HasPrefix,
	"hasSuffix": strings.HasSuffix,
	"split":     strings.Split,
	"join":      strings.Join,
	"repeat": func(s string, n int) string {
		const maxRepeat = 10000
		if n > maxRepeat {
			n = maxRepeat
		}
		if n < 0 {
			n = 0
		}
		return strings.Repeat(s, n)
	},
	"trimPrefix": strings.TrimPrefix,
	"trimSuffix": strings.TrimSuffix,

	// Formatting functions
	"printf":   fmt.Sprintf,
	"default":  defaultValue,
	"coalesce": coalesce,
	"ternary":  ternary,

	// JSON functions
	"toJson":       toJSON,
	"toPrettyJson": toPrettyJSON,

	// Time functions
	"now":        time.Now,
	"formatTime": formatTime,
	"duration":   formatDuration,

	// Numeric functions
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
	"mul": func(a, b int) int { return a * b },
	"div": func(a, b int) int {
		if b == 0 {
			return 0
		}
		return a / b
	},

	// Status helpers
	"isSuccess":     func(code int) bool { return code >= 200 && code < 300 },
	"isRedirect":    func(code int) bool { return code >= 300 && code < 400 },
	"isClientError": func(code int) bool { return code >= 400 && code < 500 },
	"isServerError": func(code int) bool { return code >= 500 },

	// Color helpers (ANSI) — only emit codes when stdout is a terminal
	"red":     dslColor("\033[31m"),
	"green":   dslColor("\033[32m"),
	"yellow":  dslColor("\033[33m"),
	"blue":    dslColor("\033[34m"),
	"magenta": dslColor("\033[35m"),
	"cyan":    dslColor("\033[36m"),
	"bold":    dslColor("\033[1m"),
	"dim":     dslColor("\033[2m"),

	// Severity colors
	"severityColor": severityColor,
}

// New creates a new DSL formatter with the given template
func New(templateStr string) (*Formatter, error) {
	f := &Formatter{
		Template: templateStr,
	}

	// Check for preset
	if preset, ok := Presets[templateStr]; ok {
		if preset == "" {
			// Special case for json/jsonl
			f.Template = templateStr
		} else {
			f.Template = preset
		}
	}

	// Parse template
	if f.Template != "json" && f.Template != "jsonl" {
		tmpl, err := template.New("dsl").Funcs(templateFuncs).Parse(f.Template)
		if err != nil {
			return nil, fmt.Errorf("invalid template: %w", err)
		}
		f.tmpl = tmpl
	}

	return f, nil
}

// Format formats a result using the DSL template
func (f *Formatter) Format(result *Result) (string, error) {
	// Special case for JSON output
	if f.Template == "json" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	// Special case for JSONL output
	if f.Template == "jsonl" {
		data, err := json.Marshal(result)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	// Execute template
	var buf bytes.Buffer
	if err := f.tmpl.Execute(&buf, result); err != nil {
		if f.StrictMode {
			return "", err
		}
		// In non-strict mode, return what we can
		return buf.String(), nil
	}

	return buf.String(), nil
}

// FormatMap formats a map using the DSL template
func (f *Formatter) FormatMap(data map[string]interface{}) (string, error) {
	// Special case for JSON output
	if f.Template == "json" {
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return "", err
		}
		return string(jsonData), nil
	}

	// Special case for JSONL output
	if f.Template == "jsonl" {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return "", err
		}
		return string(jsonData), nil
	}

	// Execute template
	var buf bytes.Buffer
	if err := f.tmpl.Execute(&buf, data); err != nil {
		if f.StrictMode {
			return "", err
		}
		return buf.String(), nil
	}

	return buf.String(), nil
}

// Validate checks if a template string is valid
func Validate(templateStr string) error {
	// Check for preset
	if preset, ok := Presets[templateStr]; ok {
		if preset == "" {
			return nil // json/jsonl are always valid
		}
		templateStr = preset
	}

	_, err := template.New("validate").Funcs(templateFuncs).Parse(templateStr)
	return err
}

// ListPresets returns available preset names in sorted order.
func ListPresets() []string {
	presets := make([]string, 0, len(Presets))
	for name := range Presets {
		presets = append(presets, name)
	}
	sort.Strings(presets)
	return presets
}

// Helper functions

func defaultValue(def, val interface{}) interface{} {
	if val == nil || val == "" {
		return def
	}
	switch v := val.(type) {
	case int:
		if v == 0 {
			return def
		}
	case int64:
		if v == 0 {
			return def
		}
	case float64:
		if v == 0 {
			return def
		}
	case bool:
		if !v {
			return def
		}
	}
	return val
}

func coalesce(values ...interface{}) interface{} {
	for _, v := range values {
		if v == nil || v == "" {
			continue
		}
		switch tv := v.(type) {
		case int:
			if tv == 0 {
				continue
			}
		case int64:
			if tv == 0 {
				continue
			}
		case float64:
			if tv == 0 {
				continue
			}
		case bool:
			if !tv {
				continue
			}
		}
		return v
	}
	return ""
}

func ternary(condition bool, trueVal, falseVal interface{}) interface{} {
	if condition {
		return trueVal
	}
	return falseVal
}

func toJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("toJson: %w", err)
	}
	return string(data), nil
}

func toPrettyJSON(v interface{}) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("toPrettyJson: %w", err)
	}
	return string(data), nil
}

func formatTime(t time.Time, format string) string {
	return t.Format(format)
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func severityColor(severity string) string {
	if !ui.StdoutIsTerminal() {
		return severity
	}
	switch strings.ToLower(severity) {
	case "critical":
		return "\033[1;31m" + severity + "\033[0m" // Bold red
	case "high":
		return "\033[31m" + severity + "\033[0m" // Red
	case "medium":
		return "\033[33m" + severity + "\033[0m" // Yellow
	case "low":
		return "\033[34m" + severity + "\033[0m" // Blue
	case "info":
		return "\033[36m" + severity + "\033[0m" // Cyan
	default:
		return severity
	}
}

// dslColor returns a template function that wraps text in the given
// ANSI code when stdout is a terminal, returns text unchanged otherwise.
func dslColor(code string) func(string) string {
	return func(s string) string {
		if !ui.StdoutIsTerminal() {
			return s
		}
		return code + s + "\033[0m"
	}
}

// DSLExpression represents a DSL condition expression
type DSLExpression struct {
	Raw      string
	compiled *regexp.Regexp
}

// ParseExpression parses a DSL expression for matching
func ParseExpression(expr string) (*DSLExpression, error) {
	e := &DSLExpression{Raw: expr}

	// Handle regex patterns
	if strings.HasPrefix(expr, "regex:") {
		pattern := strings.TrimPrefix(expr, "regex:")
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		e.compiled = re
	}

	return e, nil
}

// Match evaluates the expression against a result
func (e *DSLExpression) Match(result *Result) bool {
	if e.compiled != nil {
		// Regex match against URL
		return e.compiled.MatchString(result.URL)
	}

	// Simple field comparison expressions
	expr := e.Raw

	// Handle status_code comparisons
	if strings.Contains(expr, "status_code") {
		return evaluateStatusCode(expr, result.StatusCode)
	}

	// Handle contains() function
	if strings.Contains(expr, "contains(") {
		return evaluateContains(expr, result)
	}

	return false
}

func evaluateStatusCode(expr string, statusCode int) bool {
	// Parse expressions like "status_code == 200" or "status_code >= 400"
	expr = strings.ReplaceAll(expr, " ", "")

	if strings.Contains(expr, "==") {
		parts := strings.Split(expr, "==")
		if len(parts) == 2 {
			var val int
			if n, _ := fmt.Sscanf(parts[1], "%d", &val); n == 1 {
				return statusCode == val
			}
		}
	}

	if strings.Contains(expr, ">=") {
		parts := strings.Split(expr, ">=")
		if len(parts) == 2 {
			var val int
			if n, _ := fmt.Sscanf(parts[1], "%d", &val); n == 1 {
				return statusCode >= val
			}
		}
	}

	if strings.Contains(expr, "<=") {
		parts := strings.Split(expr, "<=")
		if len(parts) == 2 {
			var val int
			if n, _ := fmt.Sscanf(parts[1], "%d", &val); n == 1 {
				return statusCode <= val
			}
		}
	}

	if strings.Contains(expr, ">") {
		parts := strings.Split(expr, ">")
		if len(parts) == 2 {
			var val int
			if n, _ := fmt.Sscanf(parts[1], "%d", &val); n == 1 {
				return statusCode > val
			}
		}
	}

	if strings.Contains(expr, "<") {
		parts := strings.Split(expr, "<")
		if len(parts) == 2 {
			var val int
			if n, _ := fmt.Sscanf(parts[1], "%d", &val); n == 1 {
				return statusCode < val
			}
		}
	}

	return false
}

func evaluateContains(expr string, result *Result) bool {
	// Parse contains(field, "value")
	re := regexcache.MustGet(`contains\((\w+),\s*"([^"]+)"\)`)
	matches := re.FindStringSubmatch(expr)
	if len(matches) != 3 {
		return false
	}

	field := matches[1]
	value := strings.ToLower(matches[2])

	switch field {
	case "body", "body_preview":
		return strings.Contains(strings.ToLower(result.BodyPreview), value)
	case "title":
		return strings.Contains(strings.ToLower(result.Title), value)
	case "server":
		return strings.Contains(strings.ToLower(result.Server), value)
	case "url":
		return strings.Contains(strings.ToLower(result.URL), value)
	case "tech":
		return strings.Contains(strings.ToLower(result.Tech), value)
	case "content_type":
		return strings.Contains(strings.ToLower(result.ContentType), value)
	}

	return false
}
