// Package nuclei provides compatibility for running Nuclei-style YAML templates
package nuclei

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
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

	// DNS queries
	DNS []DNSRequest `yaml:"dns,omitempty"`

	// Network (TCP/UDP) requests
	Network []NetworkRequest `yaml:"network,omitempty"`

	// Flow control DSL for conditional execution between blocks
	Flow string `yaml:"flow,omitempty"`

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
	// Block identifier for flow control
	ID string `yaml:"id,omitempty"`

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

// BlockResult holds the outcome of executing a single template block.
type BlockResult struct {
	ID            string              `json:"id"`
	Matched       bool                `json:"matched"`
	StatusCode    int                 `json:"status_code,omitempty"`
	ExtractedData map[string][]string `json:"extracted_data,omitempty"`
}

// Result represents a template execution result
type Result struct {
	TemplateID    string                  `json:"template_id"`
	TemplateName  string                  `json:"template_name"`
	Severity      string                  `json:"severity"`
	Matched       bool                    `json:"matched"`
	MatchedAt     string                  `json:"matched_at,omitempty"`
	ExtractedData map[string][]string     `json:"extracted,omitempty"`
	BlockResults  map[string]*BlockResult `json:"block_results,omitempty"`
	Error         string                  `json:"error,omitempty"`
	Timestamp     time.Time               `json:"timestamp"`
	Duration      time.Duration           `json:"duration"`
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
		HTTPClient: httpclient.Default(),
		Variables:  make(map[string]string),
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

// Execute runs a template against a target. If the template has a Flow field,
// it uses flow-controlled execution with conditionals; otherwise it runs blocks
// sequentially with variable chaining between them.
func (e *Engine) Execute(ctx context.Context, tmpl *Template, target string) (*Result, error) {
	if tmpl.Flow != "" {
		return e.executeFlow(ctx, tmpl, target)
	}
	return e.executeSequential(ctx, tmpl, target)
}

// executeSequential runs HTTP blocks in order, chaining extracted variables.
func (e *Engine) executeSequential(ctx context.Context, tmpl *Template, target string) (*Result, error) {
	start := time.Now()
	result := &Result{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		ExtractedData: make(map[string][]string),
		BlockResults:  make(map[string]*BlockResult),
		Timestamp:     start,
	}

	vars := e.mergeVars(tmpl, target)

	for i, req := range tmpl.HTTP {
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
			// Chain extracted values into vars for subsequent requests
			if len(v) > 0 {
				vars[k] = v[0]
			}
		}

		// Track per-block results
		blockID := req.ID
		if blockID == "" {
			blockID = fmt.Sprintf("request-%d", i)
		}
		result.BlockResults[blockID] = &BlockResult{
			ID:            blockID,
			Matched:       matched,
			ExtractedData: extracted,
		}

		if matched && req.StopAtFirstMatch {
			break
		}
	}

	// Execute DNS requests sequentially
	for i, req := range tmpl.DNS {
		matched, extracted, err := e.executeDNSRequest(ctx, &req, vars)
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
			if len(v) > 0 {
				vars[k] = v[0]
			}
		}
		blockID := req.ID
		if blockID == "" {
			blockID = fmt.Sprintf("dns-%d", i)
		}
		result.BlockResults[blockID] = &BlockResult{
			ID:            blockID,
			Matched:       matched,
			ExtractedData: extracted,
		}
	}

	// Execute Network requests sequentially
	for i, req := range tmpl.Network {
		matched, extracted, err := e.executeNetworkRequest(ctx, &req, vars)
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
			if len(v) > 0 {
				vars[k] = v[0]
			}
		}
		blockID := req.ID
		if blockID == "" {
			blockID = fmt.Sprintf("network-%d", i)
		}
		result.BlockResults[blockID] = &BlockResult{
			ID:            blockID,
			Matched:       matched,
			ExtractedData: extracted,
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// protocolBlock identifies a block by protocol and index.
type protocolBlock struct {
	protocol string // "http", "dns", "network"
	index    int
}

// executeFlow runs template blocks according to a flow DSL with conditionals.
func (e *Engine) executeFlow(ctx context.Context, tmpl *Template, target string) (*Result, error) {
	flow, err := ParseFlow(tmpl.Flow)
	if err != nil {
		return nil, fmt.Errorf("parse flow: %w", err)
	}

	// Build block index across all protocols
	blocks := make(map[string]protocolBlock)
	for i := range tmpl.HTTP {
		id := tmpl.HTTP[i].ID
		if id == "" {
			id = fmt.Sprintf("request-%d", i)
		}
		blocks[id] = protocolBlock{protocol: "http", index: i}
	}
	for i := range tmpl.DNS {
		id := tmpl.DNS[i].ID
		if id == "" {
			id = fmt.Sprintf("dns-%d", i)
		}
		blocks[id] = protocolBlock{protocol: "dns", index: i}
	}
	for i := range tmpl.Network {
		id := tmpl.Network[i].ID
		if id == "" {
			id = fmt.Sprintf("network-%d", i)
		}
		blocks[id] = protocolBlock{protocol: "network", index: i}
	}

	start := time.Now()
	vars := e.mergeVars(tmpl, target)

	result := &Result{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		ExtractedData: make(map[string][]string),
		BlockResults:  make(map[string]*BlockResult),
		Timestamp:     start,
	}

	for _, step := range flow.Steps {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		blockID := step.BlockID

		// Evaluate condition if present
		if step.Condition != nil {
			if !EvaluateCondition(step.Condition, vars, result.BlockResults) {
				if step.ElseBlock != "" {
					blockID = step.ElseBlock
				} else {
					continue
				}
			}
		}

		block, ok := blocks[blockID]
		if !ok {
			result.Error = fmt.Sprintf("flow references unknown block %q", blockID)
			continue
		}

		// Dispatch to protocol-specific executor
		var matched bool
		var extracted map[string][]string
		switch block.protocol {
		case "http":
			matched, extracted, err = e.executeHTTPRequest(ctx, &tmpl.HTTP[block.index], target, vars)
		case "dns":
			matched, extracted, err = e.executeDNSRequest(ctx, &tmpl.DNS[block.index], vars)
		case "network":
			matched, extracted, err = e.executeNetworkRequest(ctx, &tmpl.Network[block.index], vars)
		}
		if err != nil {
			result.Error = err.Error()
			continue
		}

		br := &BlockResult{
			ID:            blockID,
			Matched:       matched,
			ExtractedData: extracted,
		}
		result.BlockResults[blockID] = br

		for k, v := range extracted {
			result.ExtractedData[k] = append(result.ExtractedData[k], v...)
			if len(v) > 0 {
				vars[k] = v[0]
			}
		}

		if matched {
			result.Matched = true
			result.MatchedAt = target
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// mergeVars creates a variable map from engine defaults, template variables, and target.
func (e *Engine) mergeVars(tmpl *Template, target string) map[string]string {
	vars := make(map[string]string)
	for k, v := range e.Variables {
		vars[k] = v
	}
	for k, v := range tmpl.Variables {
		vars[k] = v
	}
	vars["BaseURL"] = target
	vars["Hostname"] = extractHostname(target)
	return vars
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
		return e.executeRawRequests(ctx, req, target, vars)
	}

	condition := req.MatchersCondition
	if condition == "" {
		condition = "or"
	}

	anyMatched := false
	var lastErr error

	for _, path := range paths {
		// Expand variables in path
		expandedPath := expandVariables(path, vars)
		fullURL := strings.TrimSuffix(target, "/") + expandedPath

		// Build request
		body := expandVariables(req.Body, vars)
		httpReq, err := http.NewRequestWithContext(ctx, method, fullURL, strings.NewReader(body))
		if err != nil {
			lastErr = err
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
			lastErr = err
			continue
		}

		respBody, err := iohelper.ReadBody(resp.Body, 10*1024*1024) // 10MB limit
		iohelper.DrainAndClose(resp.Body)
		if err != nil {
			lastErr = err
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

	return anyMatched, extracted, lastErr
}

// ResponseData holds response information for matching
type ResponseData struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	URL        string
}

// executeRawRequests handles templates with raw HTTP request strings.
// Parses method, path, headers, and body from each raw request.
func (e *Engine) executeRawRequests(ctx context.Context, req *HTTPRequest, target string, vars map[string]string) (bool, map[string][]string, error) {
	extracted := make(map[string][]string)
	condition := req.MatchersCondition
	if condition == "" {
		condition = "or"
	}

	anyMatched := false
	var lastErr error

	for _, raw := range req.Raw {
		expandedRaw := expandVariables(raw, vars)
		rawMethod, rawPath, rawHeaders, rawBody := parseRawRequest(expandedRaw)

		fullURL := strings.TrimSuffix(target, "/") + rawPath

		httpReq, err := http.NewRequestWithContext(ctx, rawMethod, fullURL, strings.NewReader(rawBody))
		if err != nil {
			lastErr = err
			continue
		}

		for k, v := range rawHeaders {
			httpReq.Header.Set(k, v)
		}
		if httpReq.Header.Get("User-Agent") == "" {
			httpReq.Header.Set("User-Agent", ui.UserAgent())
		}

		resp, err := e.HTTPClient.Do(httpReq)
		if err != nil {
			lastErr = err
			continue
		}

		respBody, err := iohelper.ReadBody(resp.Body, 10*1024*1024)
		iohelper.DrainAndClose(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		respData := &ResponseData{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       respBody,
			URL:        fullURL,
		}

		matched := evaluateMatchers(req.Matchers, condition, respData)
		if matched {
			anyMatched = true
		}

		for _, extractor := range req.Extractors {
			values := runExtractor(&extractor, respData)
			name := extractor.Name
			if name == "" {
				name = "extracted"
			}
			extracted[name] = append(extracted[name], values...)
		}
	}

	return anyMatched, extracted, lastErr
}

// parseRawRequest extracts method, path, headers, and body from a raw HTTP request string.
func parseRawRequest(raw string) (method, path string, headers map[string]string, body string) {
	headers = make(map[string]string)
	method = "GET"
	path = "/"

	// Normalize line endings
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.SplitN(raw, "\n\n", 2)

	headerSection := parts[0]
	if len(parts) == 2 {
		body = parts[1]
	}

	lines := strings.Split(headerSection, "\n")
	if len(lines) == 0 {
		return
	}

	// Parse request line: METHOD /path HTTP/1.1
	requestLine := strings.Fields(lines[0])
	if len(requestLine) >= 2 {
		method = requestLine[0]
		path = requestLine[1]
	}

	// Parse headers
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		headers[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
	}

	return
}

// buildHeaderString produces a deterministic string from HTTP headers by sorting keys.
func buildHeaderString(headers http.Header) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	for _, k := range keys {
		buf.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(headers[k], ", ")))
	}
	return buf.String()
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
		content = buildHeaderString(resp.Headers)
	case "body":
		content = string(resp.Body)
	default: // "all" or empty
		var buf bytes.Buffer
		buf.WriteString(buildHeaderString(resp.Headers))
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
			re, err := regexcache.Get(pattern)
			if err != nil {
				return false // invalid pattern fails AND
			}
			if !re.MatchString(content) {
				return false
			}
		}
		return true
	}

	// Default: or
	for _, pattern := range patterns {
		re, err := regexcache.Get(pattern)
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
		var matched bool
		var handled bool

		trimmed := strings.TrimSpace(expr)

		// status_code == X
		if strings.HasPrefix(trimmed, "status_code") {
			matched = evaluateDSLStatusCode(expr, resp.StatusCode)
			handled = true
		}

		// contains(part, "X")
		if !handled && strings.HasPrefix(trimmed, "contains(") {
			matched = evaluateDSLContains(expr, resp)
			handled = true
		}

		if !handled {
			// Unrecognized expression — fail closed
			if condition == "and" {
				return false
			}
			continue
		}

		if matched {
			if condition != "and" {
				return true
			}
		} else if condition == "and" {
			return false
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

func evaluateDSLContains(expr string, resp *ResponseData) bool {
	// Parse: contains(part, "string")
	re := regexcache.MustGet(`contains\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
	matches := re.FindStringSubmatch(expr)
	if len(matches) != 3 {
		return false
	}

	part := strings.ToLower(matches[1])
	needle := matches[2]

	var content string
	switch part {
	case "header":
		content = buildHeaderString(resp.Headers)
	default:
		content = string(resp.Body)
	}

	return strings.Contains(content, needle)
}

func runExtractor(e *Extractor, resp *ResponseData) []string {
	var content string
	switch strings.ToLower(e.Part) {
	case "header":
		content = buildHeaderString(resp.Headers)
	case "body":
		content = string(resp.Body)
	default:
		content = string(resp.Body)
	}

	var results []string

	switch strings.ToLower(e.Type) {
	case "regex":
		for _, pattern := range e.Regex {
			re, err := regexcache.Get(pattern)
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
	tmpl, err := template.New("").Option("missingkey=error").Parse(input)
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
		// text/template can't resolve bare {{VarName}} (needs {{.VarName}}).
		// Fall through to simple string replacement.
		result := input
		for k, v := range vars {
			result = strings.ReplaceAll(result, "{{"+k+"}}", v)
		}
		return result
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

		tmpl, err := LoadTemplate(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		templates = append(templates, tmpl)
	}

	return templates, nil
}

// FilterOptions provides filtering options for templates
type FilterOptions struct {
	Tags        string // Comma-separated tags to include
	Severity    string // Comma-separated severities
	ExcludeTags string // Comma-separated tags to exclude
}

// FilterTemplates filters templates using FilterOptions
func FilterTemplates(templates []*Template, opts FilterOptions) []*Template {
	var includeTags, excludeTags, severities []string

	if opts.Tags != "" {
		includeTags = strings.Split(opts.Tags, ",")
	}
	if opts.ExcludeTags != "" {
		excludeTags = strings.Split(opts.ExcludeTags, ",")
	}
	if opts.Severity != "" {
		severities = strings.Split(opts.Severity, ",")
	}

	if len(includeTags) == 0 && len(excludeTags) == 0 && len(severities) == 0 {
		return templates
	}

	var result []*Template
	for _, tmpl := range templates {
		// Check severity
		if len(severities) > 0 {
			found := false
			for _, s := range severities {
				if strings.EqualFold(tmpl.Info.Severity, strings.TrimSpace(s)) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		tmplTags := strings.Split(tmpl.Info.Tags, ",")

		// Check exclude tags
		excluded := false
		for _, et := range excludeTags {
			for _, tt := range tmplTags {
				if strings.EqualFold(strings.TrimSpace(et), strings.TrimSpace(tt)) {
					excluded = true
					break
				}
			}
			if excluded {
				break
			}
		}
		if excluded {
			continue
		}

		// Check include tags
		if len(includeTags) > 0 {
			found := false
			for _, t := range includeTags {
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

// LoadDirectory loads all templates from a directory recursively
func LoadDirectory(dir string) ([]*Template, error) {
	var templates []*Template

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		tmpl, err := LoadTemplate(path)
		if err != nil {
			// Log but don't fail on individual template errors
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return templates, nil
}
