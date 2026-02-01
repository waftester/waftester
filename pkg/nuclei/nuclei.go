// Package nuclei provides compatibility for running Nuclei-style YAML templates
package nuclei

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
	"gopkg.in/yaml.v3"
)

// Template represents a Nuclei-compatible template
type Template struct {
	ID   string `yaml:"id"`
	Info Info   `yaml:"info"`

	// HTTP requests
	HTTP []HTTPRequest `yaml:"http,omitempty"`

	// Variables
	Variables map[string]string `yaml:"variables,omitempty"`
}

// Info contains template metadata
type Info struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description,omitempty"`
	Reference   []string `yaml:"reference,omitempty"`
	Tags        string   `yaml:"tags,omitempty"`
	Remediation string   `yaml:"remediation,omitempty"`

	// Classification
	Classification *Classification `yaml:"classification,omitempty"`

	// Metadata
	Metadata map[string]interface{} `yaml:"metadata,omitempty"`
}

// Classification contains vulnerability classification
type Classification struct {
	CVSSMetrics string   `yaml:"cvss-metrics,omitempty"`
	CVSSScore   float64  `yaml:"cvss-score,omitempty"`
	CWE         []string `yaml:"cwe-id,omitempty"`
	CVE         string   `yaml:"cve-id,omitempty"`
}

// HTTPRequest represents an HTTP request in a template
type HTTPRequest struct {
	// Request method
	Method string `yaml:"method,omitempty"`

	// Path(s) to request
	Path []string `yaml:"path,omitempty"`

	// Raw HTTP request
	Raw []string `yaml:"raw,omitempty"`

	// Headers
	Headers map[string]string `yaml:"headers,omitempty"`

	// Body
	Body string `yaml:"body,omitempty"`

	// Matchers
	Matchers          []Matcher `yaml:"matchers,omitempty"`
	MatchersCondition string    `yaml:"matchers-condition,omitempty"` // and, or

	// Extractors
	Extractors []Extractor `yaml:"extractors,omitempty"`

	// Options
	MaxRedirects     int  `yaml:"max-redirects,omitempty"`
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty"`
	FollowRedirects  bool `yaml:"redirects,omitempty"`

	// Attack type for multiple payloads
	AttackType string                 `yaml:"attack,omitempty"` // batteringram, pitchfork, clusterbomb
	Payloads   map[string]interface{} `yaml:"payloads,omitempty"`
}

// Matcher defines matching conditions
type Matcher struct {
	// Type: word, regex, status, binary, size, dsl
	Type string `yaml:"type"`

	// Condition: and, or
	Condition string `yaml:"condition,omitempty"`

	// Words to match
	Words []string `yaml:"words,omitempty"`

	// Regex patterns
	Regex []string `yaml:"regex,omitempty"`

	// Status codes
	Status []int `yaml:"status,omitempty"`

	// Size matches
	Size []int `yaml:"size,omitempty"`

	// DSL expressions
	DSL []string `yaml:"dsl,omitempty"`

	// Where to match: body, header, all
	Part string `yaml:"part,omitempty"`

	// Negative matching
	Negative bool `yaml:"negative,omitempty"`

	// Case insensitive
	CaseInsensitive bool `yaml:"case-insensitive,omitempty"`

	// Internal flag
	Internal bool `yaml:"internal,omitempty"`
}

// Extractor defines extraction rules
type Extractor struct {
	// Type: regex, kval, json, xpath, dsl
	Type string `yaml:"type"`

	// Name for the extracted value
	Name string `yaml:"name,omitempty"`

	// Regex patterns
	Regex []string `yaml:"regex,omitempty"`

	// Group to extract
	Group int `yaml:"group,omitempty"`

	// KVal keys
	KVal []string `yaml:"kval,omitempty"`

	// JSON path
	JSON []string `yaml:"json,omitempty"`

	// XPath
	XPath []string `yaml:"xpath,omitempty"`

	// DSL expressions
	DSL []string `yaml:"dsl,omitempty"`

	// Part to extract from
	Part string `yaml:"part,omitempty"`

	// Internal extraction (not shown in output)
	Internal bool `yaml:"internal,omitempty"`
}

// Result represents a template execution result
type Result struct {
	TemplateID    string              `json:"template_id"`
	TemplateName  string              `json:"template_name"`
	Severity      string              `json:"severity"`
	Matched       bool                `json:"matched"`
	MatchedAt     string              `json:"matched_at,omitempty"`
	ExtractedData map[string][]string `json:"extracted,omitempty"`
	Error         string              `json:"error,omitempty"`
	Timestamp     time.Time           `json:"timestamp"`
	Duration      time.Duration       `json:"duration"`
}

// Engine executes Nuclei templates
type Engine struct {
	// HTTPClient for requests
	HTTPClient *http.Client

	// Variables available to templates
	Variables map[string]string

	// Verbose output
	Verbose bool
}

// NewEngine creates a new template engine
func NewEngine() *Engine {
	return &Engine{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		Variables: make(map[string]string),
	}
}

// LoadTemplate loads a template from a file
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read template: %w", err)
	}

	return ParseTemplate(data)
}

// ParseTemplate parses a template from YAML data
func ParseTemplate(data []byte) (*Template, error) {
	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Validate required fields
	if tmpl.ID == "" {
		return nil, fmt.Errorf("template missing required field: id")
	}
	if tmpl.Info.Name == "" {
		return nil, fmt.Errorf("template missing required field: info.name")
	}

	return &tmpl, nil
}

// Execute runs a template against a target
func (e *Engine) Execute(ctx context.Context, tmpl *Template, target string) (*Result, error) {
	start := time.Now()
	result := &Result{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		ExtractedData: make(map[string][]string),
		Timestamp:     start,
	}

	// Merge template variables
	vars := make(map[string]string)
	for k, v := range e.Variables {
		vars[k] = v
	}
	for k, v := range tmpl.Variables {
		vars[k] = v
	}
	vars["BaseURL"] = target
	vars["Hostname"] = extractHostname(target)

	// Execute HTTP requests
	for _, req := range tmpl.HTTP {
		matched, extracted, err := e.executeHTTPRequest(ctx, &req, target, vars)
		if err != nil {
			result.Error = err.Error()
			continue
		}

		if matched {
			result.Matched = true
			result.MatchedAt = target
		}

		for k, v := range extracted {
			result.ExtractedData[k] = append(result.ExtractedData[k], v...)
		}

		if matched && req.StopAtFirstMatch {
			break
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *Engine) executeHTTPRequest(ctx context.Context, req *HTTPRequest, target string, vars map[string]string) (bool, map[string][]string, error) {
	extracted := make(map[string][]string)

	// Determine paths to request
	paths := req.Path
	if len(paths) == 0 {
		paths = []string{"/"}
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	// Check if we have raw requests
	if len(req.Raw) > 0 {
		// Parse raw HTTP requests to extract paths
		paths = []string{""}
		for _, raw := range req.Raw {
			// Parse raw request for path
			lines := strings.Split(raw, "\n")
			if len(lines) > 0 {
				parts := strings.Fields(lines[0])
				if len(parts) >= 2 {
					paths = append(paths, parts[1])
				}
			}
		}
	}

	condition := req.MatchersCondition
	if condition == "" {
		condition = "or"
	}

	anyMatched := false

	for _, path := range paths {
		// Expand variables in path
		expandedPath := expandVariables(path, vars)
		fullURL := strings.TrimSuffix(target, "/") + expandedPath

		// Build request
		body := expandVariables(req.Body, vars)
		httpReq, err := http.NewRequestWithContext(ctx, method, fullURL, strings.NewReader(body))
		if err != nil {
			continue
		}

		// Add headers
		for k, v := range req.Headers {
			httpReq.Header.Set(k, expandVariables(v, vars))
		}

		// Set default headers
		if httpReq.Header.Get("User-Agent") == "" {
			httpReq.Header.Set("User-Agent", ui.UserAgent())
		}

		// Execute request
		resp, err := e.HTTPClient.Do(httpReq)
		if err != nil {
			continue
		}

		respBody, err := iohelper.ReadBody(resp.Body, 10*1024*1024) // 10MB limit
		iohelper.DrainAndClose(resp.Body)
		if err != nil {
			continue
		}

		// Collect response data for matching
		respData := &ResponseData{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       respBody,
			URL:        fullURL,
		}

		// Run matchers
		matched := evaluateMatchers(req.Matchers, condition, respData)
		if matched {
			anyMatched = true
		}

		// Run extractors
		for _, extractor := range req.Extractors {
			values := runExtractor(&extractor, respData)
			name := extractor.Name
			if name == "" {
				name = "extracted"
			}
			extracted[name] = append(extracted[name], values...)
		}
	}

	return anyMatched, extracted, nil
}

// ResponseData holds response information for matching
type ResponseData struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	URL        string
}

func evaluateMatchers(matchers []Matcher, condition string, resp *ResponseData) bool {
	if len(matchers) == 0 {
		return true // No matchers = match everything
	}

	results := make([]bool, len(matchers))
	for i, m := range matchers {
		results[i] = evaluateMatcher(&m, resp)
	}

	// Apply condition
	switch strings.ToLower(condition) {
	case "and":
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	default: // "or"
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}
}

func evaluateMatcher(m *Matcher, resp *ResponseData) bool {
	var content string
	switch strings.ToLower(m.Part) {
	case "header":
		var buf bytes.Buffer
		for k, v := range resp.Headers {
			buf.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
		}
		content = buf.String()
	case "body":
		content = string(resp.Body)
	default: // "all" or empty
		var buf bytes.Buffer
		for k, v := range resp.Headers {
			buf.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
		}
		buf.Write(resp.Body)
		content = buf.String()
	}

	if m.CaseInsensitive {
		content = strings.ToLower(content)
	}

	var matched bool

	switch strings.ToLower(m.Type) {
	case "word", "words":
		matched = matchWords(m.Words, content, m.Condition, m.CaseInsensitive)
	case "regex":
		matched = matchRegex(m.Regex, content, m.Condition)
	case "status":
		matched = matchStatus(m.Status, resp.StatusCode, m.Condition)
	case "size":
		matched = matchSize(m.Size, len(resp.Body), m.Condition)
	case "dsl":
		// Basic DSL support
		matched = matchDSL(m.DSL, resp, m.Condition)
	}

	// Handle negative matching
	if m.Negative {
		matched = !matched
	}

	return matched
}

func matchWords(words []string, content, condition string, caseInsensitive bool) bool {
	if len(words) == 0 {
		return true
	}

	if condition == "and" {
		for _, word := range words {
			searchWord := word
			if caseInsensitive {
				searchWord = strings.ToLower(word)
			}
			if !strings.Contains(content, searchWord) {
				return false
			}
		}
		return true
	}

	// Default: or
	for _, word := range words {
		searchWord := word
		if caseInsensitive {
			searchWord = strings.ToLower(word)
		}
		if strings.Contains(content, searchWord) {
			return true
		}
	}
	return false
}

func matchRegex(patterns []string, content, condition string) bool {
	if len(patterns) == 0 {
		return true
	}

	if condition == "and" {
		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if !re.MatchString(content) {
				return false
			}
		}
		return true
	}

	// Default: or
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(content) {
			return true
		}
	}
	return false
}

func matchStatus(statuses []int, code int, condition string) bool {
	if len(statuses) == 0 {
		return true
	}

	for _, status := range statuses {
		if status == code {
			return true
		}
	}
	return false
}

func matchSize(sizes []int, size int, condition string) bool {
	if len(sizes) == 0 {
		return true
	}

	for _, s := range sizes {
		if s == size {
			return true
		}
	}
	return false
}

func matchDSL(expressions []string, resp *ResponseData, condition string) bool {
	if len(expressions) == 0 {
		return true
	}

	// Basic DSL support
	for _, expr := range expressions {
		// status_code == X
		if strings.Contains(expr, "status_code") {
			if matched := evaluateDSLStatusCode(expr, resp.StatusCode); matched {
				if condition != "and" {
					return true
				}
			} else if condition == "and" {
				return false
			}
		}

		// contains(body, "X")
		if strings.Contains(expr, "contains") {
			if matched := evaluateDSLContains(expr, string(resp.Body)); matched {
				if condition != "and" {
					return true
				}
			} else if condition == "and" {
				return false
			}
		}
	}

	return condition == "and"
}

func evaluateDSLStatusCode(expr string, statusCode int) bool {
	// Parse: status_code == 200
	re := regexcache.MustGet(`status_code\s*(==|!=|>=|<=|>|<)\s*(\d+)`)
	matches := re.FindStringSubmatch(expr)
	if len(matches) != 3 {
		return false
	}

	op := matches[1]
	var expected int
	fmt.Sscanf(matches[2], "%d", &expected)

	switch op {
	case "==":
		return statusCode == expected
	case "!=":
		return statusCode != expected
	case ">":
		return statusCode > expected
	case "<":
		return statusCode < expected
	case ">=":
		return statusCode >= expected
	case "<=":
		return statusCode <= expected
	}
	return false
}

func evaluateDSLContains(expr string, content string) bool {
	// Parse: contains(body, "string")
	re := regexcache.MustGet(`contains\s*\(\s*\w+\s*,\s*"([^"]+)"\s*\)`)
	matches := re.FindStringSubmatch(expr)
	if len(matches) != 2 {
		return false
	}

	return strings.Contains(content, matches[1])
}

func runExtractor(e *Extractor, resp *ResponseData) []string {
	var content string
	switch strings.ToLower(e.Part) {
	case "header":
		var buf bytes.Buffer
		for k, v := range resp.Headers {
			buf.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
		}
		content = buf.String()
	case "body":
		content = string(resp.Body)
	default:
		content = string(resp.Body)
	}

	var results []string

	switch strings.ToLower(e.Type) {
	case "regex":
		for _, pattern := range e.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			matches := re.FindAllStringSubmatch(content, -1)
			for _, m := range matches {
				if e.Group < len(m) {
					results = append(results, m[e.Group])
				} else if len(m) > 0 {
					results = append(results, m[0])
				}
			}
		}
	case "kval":
		for _, key := range e.KVal {
			// Look in headers
			if v := resp.Headers.Get(key); v != "" {
				results = append(results, v)
			}
		}
	}

	return results
}

func expandVariables(input string, vars map[string]string) string {
	tmpl, err := template.New("").Parse(input)
	if err != nil {
		// Fallback: simple replacement
		result := input
		for k, v := range vars {
			result = strings.ReplaceAll(result, "{{"+k+"}}", v)
		}
		return result
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return input
	}
	return buf.String()
}

func extractHostname(url string) string {
	// Simple hostname extraction
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	return url
}

// LoadTemplatesFromDir loads all templates from a directory
func LoadTemplatesFromDir(dir string) ([]*Template, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var templates []*Template
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		tmpl, err := LoadTemplate(dir + "/" + name)
		if err != nil {
			continue
		}
		templates = append(templates, tmpl)
	}

	return templates, nil
}

// FilterTemplates filters templates by tags, severity, etc.
func FilterTemplates(templates []*Template, tags []string, severities []string) []*Template {
	if len(tags) == 0 && len(severities) == 0 {
		return templates
	}

	var result []*Template
	for _, tmpl := range templates {
		// Check severity
		if len(severities) > 0 {
			found := false
			for _, s := range severities {
				if strings.EqualFold(tmpl.Info.Severity, s) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Check tags
		if len(tags) > 0 {
			tmplTags := strings.Split(tmpl.Info.Tags, ",")
			found := false
			for _, t := range tags {
				for _, tt := range tmplTags {
					if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(tt)) {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				continue
			}
		}

		result = append(result, tmpl)
	}

	return result
}
