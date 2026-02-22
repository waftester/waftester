// Package apifuzz provides comprehensive API fuzzing capabilities.
// Supports OpenAPI/Swagger parsing, GraphQL introspection, automatic parameter mutation,
// type confusion testing, and intelligent fuzzing based on API schema analysis.
package apifuzz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/strutil"
	"github.com/waftester/waftester/pkg/ui"
)

// infoDisclosurePatterns contains pre-compiled regexes for detecting information disclosure.
var infoDisclosurePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)stack\s*trace`),
	regexp.MustCompile(`(?i)at\s+[\w.]+\([\w.]+:\d+\)`),
	regexp.MustCompile(`(?i)file\s+"[^"]+"\s*,\s*line\s+\d+`),
	regexp.MustCompile(`(?i)(password|api.?key|secret|token)\s*[:=]`),
	regexp.MustCompile(`(?i)/(?:home|var|usr|etc)/[\w/]+`),
	regexp.MustCompile(`(?i)[A-Za-z]:\\[\w\\]+`),
}

// FuzzType represents the type of fuzzing to perform.
type FuzzType string

const (
	// FuzzRandom performs random fuzzing.
	FuzzRandom FuzzType = "random"
	// FuzzMutation performs mutation-based fuzzing.
	FuzzMutation FuzzType = "mutation"
	// FuzzGeneration performs generation-based fuzzing.
	FuzzGeneration FuzzType = "generation"
	// FuzzDictionary uses dictionary-based fuzzing.
	FuzzDictionary FuzzType = "dictionary"
	// FuzzSmart performs intelligent schema-aware fuzzing.
	FuzzSmart FuzzType = "smart"
)

// ParameterType represents the type of a parameter.
type ParameterType string

const (
	ParamString   ParameterType = "string"
	ParamInteger  ParameterType = "integer"
	ParamNumber   ParameterType = "number"
	ParamBoolean  ParameterType = "boolean"
	ParamArray    ParameterType = "array"
	ParamObject   ParameterType = "object"
	ParamNull     ParameterType = "null"
	ParamFile     ParameterType = "file"
	ParamDate     ParameterType = "date"
	ParamDateTime ParameterType = "datetime"
	ParamEmail    ParameterType = "email"
	ParamUUID     ParameterType = "uuid"
	ParamURL      ParameterType = "url"
)

// VulnerabilityType represents the type of vulnerability found.
type VulnerabilityType string

const (
	VulnTypeConfusion   VulnerabilityType = "type-confusion"
	VulnBoundaryError   VulnerabilityType = "boundary-error"
	VulnInputValidation VulnerabilityType = "input-validation"
	VulnInjection       VulnerabilityType = "injection"
	VulnOverflow        VulnerabilityType = "overflow"
	VulnFormatString    VulnerabilityType = "format-string"
	VulnDoS             VulnerabilityType = "denial-of-service"
	VulnInfoDisclosure  VulnerabilityType = "info-disclosure"
	VulnAuthBypass      VulnerabilityType = "auth-bypass"
)

// Vulnerability represents a detected API vulnerability.
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    finding.Severity  `json:"severity"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	Parameter   string            `json:"parameter,omitempty"`
	Payload     string            `json:"payload,omitempty"`
	Response    FuzzResponse      `json:"response,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	ConfirmedBy int               `json:"confirmed_by,omitempty"`
}

// FuzzResponse represents a response from a fuzz request.
type FuzzResponse struct {
	StatusCode   int               `json:"status_code"`
	ContentType  string            `json:"content_type,omitempty"`
	Body         string            `json:"body,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	ResponseTime time.Duration     `json:"response_time"`
	Size         int               `json:"size"`
}

// Endpoint represents an API endpoint to fuzz.
type Endpoint struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Parameters  []Parameter       `json:"parameters,omitempty"`
	RequestBody *RequestBody      `json:"request_body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Responses   map[int]Response  `json:"responses,omitempty"`
}

// Parameter represents an API parameter.
type Parameter struct {
	Name      string        `json:"name"`
	In        string        `json:"in"` // query, path, header, cookie
	Type      ParameterType `json:"type"`
	Required  bool          `json:"required"`
	Default   interface{}   `json:"default,omitempty"`
	Enum      []interface{} `json:"enum,omitempty"`
	Minimum   *float64      `json:"minimum,omitempty"`
	Maximum   *float64      `json:"maximum,omitempty"`
	MinLength *int          `json:"min_length,omitempty"`
	MaxLength *int          `json:"max_length,omitempty"`
	Pattern   string        `json:"pattern,omitempty"`
	Format    string        `json:"format,omitempty"`
}

// RequestBody represents a request body schema.
type RequestBody struct {
	ContentType string                 `json:"content_type"`
	Required    bool                   `json:"required"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
}

// Response represents an expected API response.
type Response struct {
	Description string                 `json:"description"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
}

// TesterConfig holds configuration for the API fuzzer.
type TesterConfig struct {
	attackconfig.Base
	MaxIterations int
	FuzzTypes     []FuzzType
	Dictionary    []string
	SkipCodes     []int
	AuthHeader    string
	Cookies       map[string]string
	EnableSmart   bool
	DelayBetween  time.Duration
}

// Tester handles API fuzzing.
type Tester struct {
	config   *TesterConfig
	client   *http.Client
	detector *detection.Detector
}

// DefaultConfig returns default configuration.
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Base: attackconfig.Base{
			Timeout:     duration.HTTPFuzzing,
			UserAgent:   ui.UserAgentWithContext("API Fuzzer"),
			Concurrency: defaults.ConcurrencyMedium,
		},
		MaxIterations: 100,
		FuzzTypes:     []FuzzType{FuzzMutation, FuzzSmart},
		SkipCodes:     []int{404},
		Cookies:       make(map[string]string),
		EnableSmart:   true,
		DelayBetween:  0,
		Dictionary:    DefaultDictionary(),
	}
}

// NewTester creates a new API fuzzer.
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	return &Tester{
		config:   config,
		client:   httpclient.Fuzzing(),
		detector: detection.Default(),
	}
}

// FuzzEndpoint fuzzes a single API endpoint.
func (t *Tester) FuzzEndpoint(ctx context.Context, baseURL string, endpoint Endpoint) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Generate fuzz cases for each parameter
	for _, param := range endpoint.Parameters {
		payloads := t.generatePayloads(param)

		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return vulns, ctx.Err()
			default:
			}

			resp, err := t.sendFuzzRequest(ctx, baseURL, endpoint, param, payload)
			if err != nil {
				continue
			}

			if vuln := t.analyzeResponse(endpoint, param, payload, resp); vuln != nil {
				vulns = append(vulns, *vuln)
				t.config.NotifyVulnerabilityFound()
			}

			if t.config.DelayBetween > 0 {
				time.Sleep(t.config.DelayBetween)
			}
		}
	}

	// Fuzz request body if present
	if endpoint.RequestBody != nil {
		bodyPayloads := t.generateBodyPayloads(endpoint.RequestBody)
		for _, payload := range bodyPayloads {
			select {
			case <-ctx.Done():
				return vulns, ctx.Err()
			default:
			}

			resp, err := t.sendBodyFuzzRequest(ctx, baseURL, endpoint, payload)
			if err != nil {
				continue
			}

			if vuln := t.analyzeBodyResponse(endpoint, payload, resp); vuln != nil {
				vulns = append(vulns, *vuln)
				t.config.NotifyVulnerabilityFound()
			}

			if t.config.DelayBetween > 0 {
				time.Sleep(t.config.DelayBetween)
			}
		}
	}

	return vulns, nil
}

// FuzzAPI fuzzes all endpoints in an API.
func (t *Tester) FuzzAPI(ctx context.Context, baseURL string, endpoints []Endpoint) ([]Vulnerability, error) {
	var vulns []Vulnerability
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, t.config.Concurrency)

	var firstErr error
	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(ep Endpoint) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			endpointVulns, err := t.FuzzEndpoint(ctx, baseURL, ep)
			mu.Lock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				vulns = append(vulns, endpointVulns...)
			}
			mu.Unlock()
		}(endpoint)
	}

	wg.Wait()
	return vulns, firstErr
}

// generatePayloads generates fuzz payloads for a parameter.
func (t *Tester) generatePayloads(param Parameter) []string {
	var payloads []string

	// Type confusion payloads
	payloads = append(payloads, t.typeConfusionPayloads(param.Type)...)

	// Boundary payloads
	payloads = append(payloads, t.boundaryPayloads(param)...)

	// Injection payloads
	payloads = append(payloads, t.injectionPayloads()...)

	// Format-specific payloads
	payloads = append(payloads, t.formatPayloads(param.Format)...)

	// Dictionary payloads
	payloads = append(payloads, t.config.Dictionary...)

	// Random mutations
	for i := 0; i < 10; i++ {
		payloads = append(payloads, t.randomMutation())
	}

	return payloads
}

// typeConfusionPayloads generates type confusion payloads.
func (t *Tester) typeConfusionPayloads(expectedType ParameterType) []string {
	payloads := []string{
		// Null/undefined
		"null",
		"undefined",
		"None",
		"nil",

		// Boolean confusion
		"true",
		"false",
		"True",
		"False",
		"0",
		"1",

		// Number confusion
		"NaN",
		"Infinity",
		"-Infinity",
		"1e999",
		"-1e999",
		"0x7FFFFFFF",
		"0xFFFFFFFF",
		"9999999999999999999999",
		"-9999999999999999999999",
		"1.7976931348623157E+10308",

		// String confusion
		"",
		"''",
		`""`,
		"[]",
		"{}",
		"[object Object]",

		// Array confusion
		"[]",
		"[null]",
		"[1,2,3]",
		`["a","b"]`,

		// Object confusion
		"{}",
		`{"key":"value"}`,
		`{"__proto__":{}}`,
		`{"constructor":{}}`,
	}

	// Add type-specific payloads
	switch expectedType {
	case ParamInteger:
		payloads = append(payloads, "1.5", "1.0", "-0", "0.0", "1e10", "0x10")
	case ParamString:
		payloads = append(payloads, "123", "true", "null", "[]")
	case ParamBoolean:
		payloads = append(payloads, "yes", "no", "1", "0", "on", "off")
	case ParamArray:
		payloads = append(payloads, `"not_array"`, "123", `{"not":"array"}`)
	case ParamObject:
		payloads = append(payloads, `["not","object"]`, "123", `"not_object"`)
	}

	return payloads
}

// boundaryPayloads generates boundary testing payloads.
func (t *Tester) boundaryPayloads(param Parameter) []string {
	var payloads []string

	// Integer boundaries
	intBoundaries := []string{
		"0",
		"-1",
		"1",
		"127",
		"128",
		"255",
		"256",
		"32767",
		"32768",
		"65535",
		"65536",
		"2147483647",
		"2147483648",
		"-2147483648",
		"-2147483649",
		"9223372036854775807",
		"-9223372036854775808",
	}
	payloads = append(payloads, intBoundaries...)

	// Length boundaries (cap to prevent OOM on huge schema values)
	const maxBoundaryLen = 100_000
	if param.MaxLength != nil {
		max := *param.MaxLength
		if max > maxBoundaryLen {
			max = maxBoundaryLen
		}
		if max >= 0 {
			payloads = append(payloads,
				strings.Repeat("A", max),
				strings.Repeat("A", max+1),
				strings.Repeat("A", max+100),
			)
		}
	}

	if param.MinLength != nil && *param.MinLength > 0 {
		payloads = append(payloads, "")
		if *param.MinLength > 1 {
			payloads = append(payloads, strings.Repeat("A", *param.MinLength-1))
		}
	}

	// Value boundaries
	if param.Minimum != nil {
		min := *param.Minimum
		payloads = append(payloads,
			fmt.Sprintf("%f", min),
			fmt.Sprintf("%f", min-1),
			fmt.Sprintf("%f", min-0.01),
		)
	}

	if param.Maximum != nil {
		max := *param.Maximum
		payloads = append(payloads,
			fmt.Sprintf("%f", max),
			fmt.Sprintf("%f", max+1),
			fmt.Sprintf("%f", max+0.01),
		)
	}

	return payloads
}

// injectionPayloads generates injection testing payloads.
func (t *Tester) injectionPayloads() []string {
	return []string{
		// SQL injection
		"' OR '1'='1",
		"'; DROP TABLE users;--",
		"1 UNION SELECT * FROM users",

		// NoSQL injection
		`{"$gt":""}`,
		`{"$ne":null}`,
		`{"$where":"sleep(1000)"}`,

		// Command injection
		"; ls -la",
		"| cat /etc/passwd",
		"`id`",
		"$(whoami)",

		// XSS
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",

		// Path traversal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",

		// SSRF
		"http://localhost:22",
		"http://127.0.0.1:6379",
		"file:///etc/passwd",

		// Template injection
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",

		// LDAP injection
		"*)(uid=*))(|(uid=*",

		// XML injection
		"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>",
	}
}

// formatPayloads generates format-specific payloads.
func (t *Tester) formatPayloads(format string) []string {
	switch format {
	case "email":
		return []string{
			"test",
			"test@",
			"@test.com",
			"test@test",
			"a" + strings.Repeat("@", 100) + ".com",
			"test@" + strings.Repeat("a", 255) + ".com",
		}
	case "uuid":
		return []string{
			"not-a-uuid",
			"00000000-0000-0000-0000-000000000000",
			"ffffffff-ffff-ffff-ffff-ffffffffffff",
			"00000000000000000000000000000000",
		}
	case "url", "uri":
		return []string{
			"not-a-url",
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
			"file:///etc/passwd",
			"//evil.com",
		}
	case "date", "date-time":
		return []string{
			"not-a-date",
			"0000-00-00",
			"9999-99-99",
			"2020-13-01",
			"2020-01-32",
		}
	case "ipv4":
		return []string{
			"not-an-ip",
			"256.256.256.256",
			"0.0.0.0",
			"127.0.0.1",
			"192.168.1.1",
		}
	default:
		return nil
	}
}

// randomMutation generates a random fuzz string.
func (t *Tester) randomMutation() string {
	mutations := []func() string{
		// Random bytes
		func() string {
			b := make([]byte, rand.Intn(100)+1)
			for i := range b {
				b[i] = byte(rand.Intn(256))
			}
			return string(b)
		},
		// Random unicode
		func() string {
			runes := make([]rune, rand.Intn(50)+1)
			for i := range runes {
				runes[i] = rune(rand.Intn(0x10000))
			}
			return string(runes)
		},
		// Format string
		func() string {
			formats := []string{"%s", "%x", "%n", "%p", "%.9999999s", "%s%s%s%s%s"}
			return formats[rand.Intn(len(formats))]
		},
		// Long string
		func() string {
			return strings.Repeat("A", rand.Intn(10000)+1000)
		},
	}

	return mutations[rand.Intn(len(mutations))]()
}

// sendFuzzRequest sends a fuzz request.
func (t *Tester) sendFuzzRequest(ctx context.Context, baseURL string, endpoint Endpoint, param Parameter, payload string) (*FuzzResponse, error) {
	// Check if host should be skipped due to connection issues
	if skip, _ := t.detector.ShouldSkipHost(baseURL); skip {
		return nil, fmt.Errorf("host skipped due to connection issues")
	}

	fullURL := baseURL + endpoint.Path

	// Build request based on parameter location
	var req *http.Request
	var err error

	switch param.In {
	case "query":
		u, parseErr := url.Parse(fullURL)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing URL %q: %w", fullURL, parseErr)
		}
		q := u.Query()
		q.Set(param.Name, payload)
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, endpoint.Method, u.String(), nil)

	case "path":
		fullURL = strings.Replace(fullURL, "{"+param.Name+"}", url.PathEscape(payload), 1)
		req, err = http.NewRequestWithContext(ctx, endpoint.Method, fullURL, nil)

	case "header":
		req, err = http.NewRequestWithContext(ctx, endpoint.Method, fullURL, nil)
		if err == nil {
			req.Header.Set(param.Name, payload)
		}

	case "cookie":
		req, err = http.NewRequestWithContext(ctx, endpoint.Method, fullURL, nil)
		if err == nil {
			req.AddCookie(&http.Cookie{Name: param.Name, Value: payload})
		}

	default:
		return nil, fmt.Errorf("unsupported parameter location %q for param %q", param.In, param.Name)
	}

	if err != nil {
		return nil, err
	}

	t.applyHeaders(req)

	startTime := time.Now()
	resp, err := t.client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		t.detector.RecordError(baseURL, err)
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	t.detector.RecordResponse(baseURL, resp, duration, len(body))

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &FuzzResponse{
		StatusCode:   resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		Body:         string(body),
		Headers:      headers,
		ResponseTime: duration,
		Size:         len(body),
	}, nil
}

// sendBodyFuzzRequest sends a fuzz request with body.
func (t *Tester) sendBodyFuzzRequest(ctx context.Context, baseURL string, endpoint Endpoint, payload string) (*FuzzResponse, error) {
	// Check if host should be skipped due to connection issues
	if skip, _ := t.detector.ShouldSkipHost(baseURL); skip {
		return nil, fmt.Errorf("host skipped due to connection issues")
	}

	fullURL := baseURL + endpoint.Path

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, fullURL, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, err
	}

	if endpoint.RequestBody != nil {
		req.Header.Set("Content-Type", endpoint.RequestBody.ContentType)
	}

	t.applyHeaders(req)

	startTime := time.Now()
	resp, err := t.client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		t.detector.RecordError(baseURL, err)
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	t.detector.RecordResponse(baseURL, resp, duration, len(body))

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &FuzzResponse{
		StatusCode:   resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		Body:         string(body),
		Headers:      headers,
		ResponseTime: duration,
		Size:         len(body),
	}, nil
}

// generateBodyPayloads generates body fuzz payloads.
func (t *Tester) generateBodyPayloads(body *RequestBody) []string {
	var payloads []string

	// Invalid JSON
	payloads = append(payloads,
		"",
		"null",
		"{}",
		"[]",
		`{"":}`,
		`{key:value}`,
		`{"key":"value"`,
		`{"key":"value"}}`,
		strings.Repeat("{", 1000),
	)

	// Type confusion in body
	payloads = append(payloads,
		`{"id":"string_instead_of_int"}`,
		`{"id":null}`,
		`{"id":[1,2,3]}`,
		`{"id":{"nested":"object"}}`,
		`{"id":true}`,
	)

	// Prototype pollution
	payloads = append(payloads,
		`{"__proto__":{"admin":true}}`,
		`{"constructor":{"prototype":{"admin":true}}}`,
	)

	// Large payloads
	payloads = append(payloads,
		`{"data":"`+strings.Repeat("A", 10000)+`"}`,
	)

	return payloads
}

// analyzeResponse analyzes a fuzz response for vulnerabilities.
func (t *Tester) analyzeResponse(endpoint Endpoint, param Parameter, payload string, resp *FuzzResponse) *Vulnerability {
	// Skip certain status codes
	for _, skip := range t.config.SkipCodes {
		if resp.StatusCode == skip {
			return nil
		}
	}

	// Check for error indicators
	if hasErrorIndicator(resp.Body) {
		return &Vulnerability{
			Type:        VulnInputValidation,
			Description: "Server error triggered by fuzz input",
			Severity:    finding.Medium,
			Endpoint:    endpoint.Path,
			Method:      endpoint.Method,
			Parameter:   param.Name,
			Payload:     strutil.Truncate(payload, 200),
			Response:    *resp,
			Evidence:    extractEvidence(resp.Body),
		}
	}

	// Check for injection indicators
	if hasInjectionIndicator(resp.Body, payload) {
		return &Vulnerability{
			Type:        VulnInjection,
			Description: "Potential injection vulnerability",
			Severity:    finding.High,
			Endpoint:    endpoint.Path,
			Method:      endpoint.Method,
			Parameter:   param.Name,
			Payload:     strutil.Truncate(payload, 200),
			Response:    *resp,
			Evidence:    extractEvidence(resp.Body),
			CVSS:        8.6,
		}
	}

	// Check for information disclosure
	if hasInfoDisclosure(resp.Body) {
		return &Vulnerability{
			Type:        VulnInfoDisclosure,
			Description: "Information disclosure in error response",
			Severity:    finding.Medium,
			Endpoint:    endpoint.Path,
			Method:      endpoint.Method,
			Parameter:   param.Name,
			Payload:     strutil.Truncate(payload, 200),
			Response:    *resp,
			Evidence:    extractEvidence(resp.Body),
			CVSS:        5.3,
		}
	}

	// Check for DoS indicators (very slow response)
	if resp.ResponseTime > duration.VerySlowResponse {
		return &Vulnerability{
			Type:        VulnDoS,
			Description: fmt.Sprintf("Slow response (%v) may indicate DoS vulnerability", resp.ResponseTime),
			Severity:    finding.Medium,
			Endpoint:    endpoint.Path,
			Method:      endpoint.Method,
			Parameter:   param.Name,
			Payload:     strutil.Truncate(payload, 200),
			Response:    *resp,
			CVSS:        6.5,
		}
	}

	return nil
}

// analyzeBodyResponse analyzes a body fuzz response.
func (t *Tester) analyzeBodyResponse(endpoint Endpoint, payload string, resp *FuzzResponse) *Vulnerability {
	return t.analyzeResponse(endpoint, Parameter{Name: "body"}, payload, resp)
}

// Helper functions

func (t *Tester) applyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", t.config.UserAgent)

	if t.config.AuthHeader != "" {
		req.Header.Set("Authorization", t.config.AuthHeader)
	}

	for name, value := range t.config.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
}

func hasErrorIndicator(body string) bool {
	indicators := []string{
		"error", "exception", "traceback", "stack trace",
		"syntax error", "fatal", "undefined", "null pointer",
		"segmentation fault", "core dump", "panic",
	}

	lowerBody := strings.ToLower(body)
	for _, ind := range indicators {
		if strings.Contains(lowerBody, ind) {
			return true
		}
	}
	return false
}

// minReflectionLen is the minimum payload length to check for reflection.
// Shorter payloads (empty string, "0", "1", "true", etc.) match almost
// every response body, flooding results with false positives.
const minReflectionLen = 8

func hasInjectionIndicator(body, payload string) bool {
	// Check if payload is reflected (skip short payloads that match everything)
	if len(payload) >= minReflectionLen && strings.Contains(body, payload) {
		return true
	}

	// Check for SQL error messages
	sqlErrors := []string{
		"sql", "mysql", "postgresql", "sqlite", "oracle",
		"syntax error", "unexpected", "unterminated",
	}
	lowerBody := strings.ToLower(body)
	for _, err := range sqlErrors {
		if strings.Contains(lowerBody, err) && strings.Contains(lowerBody, "error") {
			return true
		}
	}

	return false
}

func hasInfoDisclosure(body string) bool {
	for _, p := range infoDisclosurePatterns {
		if p.MatchString(body) {
			return true
		}
	}
	return false
}

func extractEvidence(body string) string {
	return strutil.Truncate(body, 500)
}

// DefaultDictionary returns default fuzzing dictionary.
func DefaultDictionary() []string {
	return []string{
		// Empty/null values
		"", "null", "undefined", "nil", "None",

		// Boolean variants
		"true", "false", "True", "False", "TRUE", "FALSE",
		"yes", "no", "on", "off", "1", "0",

		// Special characters
		"!", "@", "#", "$", "%", "^", "&", "*",
		"(", ")", "{", "}", "[", "]", "<", ">",
		"|", "\\", "/", "?", ";", ":", "'", "\"",

		// Unicode
		"ñ", "ü", "中文", "🔥", "☠️",

		// Control characters
		"\x00", "\x0a", "\x0d", "\t", "\r\n",
	}
}

// ParseOpenAPISpec parses an OpenAPI specification.
func ParseOpenAPISpec(spec []byte) ([]Endpoint, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(spec, &data); err != nil {
		return nil, fmt.Errorf("parsing OpenAPI spec: %w", err)
	}

	var endpoints []Endpoint

	paths, ok := data["paths"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no paths found in spec")
	}

	for path, methods := range paths {
		methodsMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		for method, details := range methodsMap {
			if method == "parameters" {
				continue
			}

			endpoint := Endpoint{
				Path:   path,
				Method: strings.ToUpper(method),
			}

			detailsMap, ok := details.(map[string]interface{})
			if !ok {
				endpoints = append(endpoints, endpoint)
				continue
			}

			// Parse parameters
			if params, ok := detailsMap["parameters"].([]interface{}); ok {
				for _, p := range params {
					if param := parseParameter(p); param != nil {
						endpoint.Parameters = append(endpoint.Parameters, *param)
					}
				}
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints, nil
}

func parseParameter(p interface{}) *Parameter {
	pMap, ok := p.(map[string]interface{})
	if !ok {
		return nil
	}

	param := &Parameter{}

	if name, ok := pMap["name"].(string); ok {
		param.Name = name
	}
	if in, ok := pMap["in"].(string); ok {
		param.In = in
	}
	if required, ok := pMap["required"].(bool); ok {
		param.Required = required
	}

	// Parse type from schema
	if schema, ok := pMap["schema"].(map[string]interface{}); ok {
		if t, ok := schema["type"].(string); ok {
			param.Type = ParameterType(t)
		}
		if format, ok := schema["format"].(string); ok {
			param.Format = format
		}
	} else if t, ok := pMap["type"].(string); ok {
		param.Type = ParameterType(t)
	}

	return param
}

// AllVulnerabilityTypes returns all vulnerability types.
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnTypeConfusion,
		VulnBoundaryError,
		VulnInputValidation,
		VulnInjection,
		VulnOverflow,
		VulnFormatString,
		VulnDoS,
		VulnInfoDisclosure,
		VulnAuthBypass,
	}
}

// VulnerabilityToJSON converts a vulnerability to JSON.
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GenerateFuzzReport generates a report of fuzz results.
func GenerateFuzzReport(vulns []Vulnerability) map[string]interface{} {
	bySeverity := make(map[string]int)
	byType := make(map[string]int)
	for _, v := range vulns {
		bySeverity[string(v.Severity)]++
		byType[string(v.Type)]++
	}
	return map[string]interface{}{
		"total_vulnerabilities": len(vulns),
		"by_severity":           bySeverity,
		"by_type":               byType,
		"vulnerabilities":       vulns,
	}
}

// IntPtr returns a pointer to an int.
func IntPtr(i int) *int {
	return &i
}

// Float64Ptr returns a pointer to a float64.
func Float64Ptr(f float64) *float64 {
	return &f
}

// StrToInt converts string to int, returning 0 on error.
func StrToInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
