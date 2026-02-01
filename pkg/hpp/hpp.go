// Package hpp provides HTTP Parameter Pollution detection capabilities.
// It tests for parameter priority, array injection, delimiter confusion,
// and WAF bypass techniques using HPP.
package hpp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of HPP vulnerability
type VulnerabilityType string

const (
	VulnParameterPriority  VulnerabilityType = "parameter-priority"
	VulnArrayInjection     VulnerabilityType = "array-injection"
	VulnDelimiterConfusion VulnerabilityType = "delimiter-confusion"
	VulnWAFBypass          VulnerabilityType = "waf-bypass"
	VulnServerSideHPP      VulnerabilityType = "server-side-hpp"
	VulnClientSideHPP      VulnerabilityType = "client-side-hpp"
	VulnParameterOverwrite VulnerabilityType = "parameter-overwrite"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

// Technology represents the backend technology
type Technology string

const (
	TechPHP     Technology = "php"
	TechASP     Technology = "asp"
	TechJava    Technology = "java"
	TechPython  Technology = "python"
	TechNodeJS  Technology = "nodejs"
	TechRuby    Technology = "ruby"
	TechGo      Technology = "go"
	TechUnknown Technology = "unknown"
)

// Vulnerability represents a detected HPP vulnerability
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	URL         string            `json:"url"`
	Parameter   string            `json:"parameter"`
	Payload     string            `json:"payload"`
	Evidence    string            `json:"evidence"`
	Technology  Technology        `json:"technology,omitempty"`
	Remediation string            `json:"remediation"`
}

// Payload represents an HPP test payload
type Payload struct {
	Query            string
	Description      string
	Type             VulnerabilityType
	ExpectedBehavior string
}

// ScanResult contains the results of an HPP scan
type ScanResult struct {
	URL             string          `json:"url"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Technology      Technology      `json:"detected_technology"`
	TestedPayloads  int             `json:"tested_payloads"`
}

// TesterConfig configures the HPP tester
type TesterConfig struct {
	Timeout       time.Duration
	UserAgent     string
	Concurrency   int
	TestParams    []string
	Technology    Technology
	Client        *http.Client
	BaselineFirst bool
}

// Tester performs HPP tests
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:     30 * time.Second,
		UserAgent:   ui.UserAgent(),
		Concurrency: 5,
		Technology:  TechUnknown,
		TestParams: []string{
			"id",
			"page",
			"search",
			"q",
			"query",
			"user",
			"name",
			"email",
			"action",
			"cmd",
			"redirect",
			"url",
			"file",
			"path",
		},
		BaselineFirst: true,
	}
}

// NewTester creates a new HPP tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &Tester{
		config: config,
		client: client,
	}
}

// GetPayloads returns HPP test payloads for a parameter
func (t *Tester) GetPayloads(param string) []Payload {
	return []Payload{
		// Parameter priority tests (duplicate parameter)
		{
			Query:            fmt.Sprintf("%s=first&%s=second", param, param),
			Description:      "Duplicate parameter test",
			Type:             VulnParameterPriority,
			ExpectedBehavior: "Check which value is used",
		},
		{
			Query:            fmt.Sprintf("%s=first&%s=INJECTED", param, param),
			Description:      "Parameter overwrite test",
			Type:             VulnParameterOverwrite,
			ExpectedBehavior: "Check if second value overwrites first",
		},

		// Array injection tests
		{
			Query:            fmt.Sprintf("%s[]=first&%s[]=second", param, param),
			Description:      "PHP array injection",
			Type:             VulnArrayInjection,
			ExpectedBehavior: "Array created in PHP",
		},
		{
			Query:            fmt.Sprintf("%s[0]=first&%s[1]=second", param, param),
			Description:      "Indexed array injection",
			Type:             VulnArrayInjection,
			ExpectedBehavior: "Indexed array created",
		},

		// Delimiter confusion
		{
			Query:            fmt.Sprintf("%s=val1%%00val2", param),
			Description:      "Null byte delimiter",
			Type:             VulnDelimiterConfusion,
			ExpectedBehavior: "Check null byte handling",
		},
		{
			Query:            fmt.Sprintf("%s=val1;%s=val2", param, param),
			Description:      "Semicolon delimiter",
			Type:             VulnDelimiterConfusion,
			ExpectedBehavior: "Check semicolon parsing",
		},
		{
			Query:            fmt.Sprintf("%s=val1&%s=val2&%s=val3", param, param, param),
			Description:      "Triple parameter",
			Type:             VulnParameterPriority,
			ExpectedBehavior: "Check behavior with 3+ values",
		},

		// WAF bypass using HPP
		{
			Query:            fmt.Sprintf("%s=<scr&%s=ipt>alert(1)</script>", param, param),
			Description:      "XSS WAF bypass via HPP",
			Type:             VulnWAFBypass,
			ExpectedBehavior: "Bypass XSS filter using split payload",
		},
		{
			Query:            fmt.Sprintf("%s=SELECT&%s=%%20*%%20FROM%%20users", param, param),
			Description:      "SQLi WAF bypass via HPP",
			Type:             VulnWAFBypass,
			ExpectedBehavior: "Bypass SQLi filter using split payload",
		},
		{
			Query:            fmt.Sprintf("%s=../&%s=../&%s=etc/passwd", param, param, param),
			Description:      "Path traversal via HPP",
			Type:             VulnWAFBypass,
			ExpectedBehavior: "Bypass path filter using split payload",
		},

		// Server-side HPP
		{
			Query:            fmt.Sprintf("%s=legit&%s=malicious", param, param),
			Description:      "Server-side HPP",
			Type:             VulnServerSideHPP,
			ExpectedBehavior: "Check if server concatenates or selects values",
		},

		// Different encoding
		{
			Query:            fmt.Sprintf("%s=val1&%s=val2", param, url.QueryEscape(param)),
			Description:      "URL encoded parameter name",
			Type:             VulnDelimiterConfusion,
			ExpectedBehavior: "Check URL encoding handling",
		},
	}
}

// TestParameter tests a specific parameter for HPP vulnerabilities
func (t *Tester) TestParameter(ctx context.Context, baseURL string, param string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	// Get baseline response
	var baseline string
	if t.config.BaselineFirst {
		q := u.Query()
		q.Set(param, "baseline_test")
		u.RawQuery = q.Encode()

		baseline, err = t.getResponse(ctx, u.String())
		if err != nil {
			return nil, err
		}
	}

	payloads := t.GetPayloads(param)

	for _, payload := range payloads {
		// Construct test URL
		testURL := baseURL
		if strings.Contains(testURL, "?") {
			testURL += "&" + payload.Query
		} else {
			testURL += "?" + payload.Query
		}

		response, err := t.getResponse(ctx, testURL)
		if err != nil {
			continue
		}

		evidence := t.detectVulnerability(response, baseline, payload)
		if evidence != "" {
			vulns = append(vulns, Vulnerability{
				Type:        payload.Type,
				Description: payload.Description,
				Severity:    getSeverity(payload.Type),
				URL:         testURL,
				Parameter:   param,
				Payload:     payload.Query,
				Evidence:    evidence,
				Technology:  t.config.Technology,
				Remediation: GetHPPRemediation(),
			})
		}
	}

	return vulns, nil
}

// getResponse makes an HTTP request and returns the response body
func (t *Tester) getResponse(ctx context.Context, targetURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, err := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// detectVulnerability checks if the response indicates HPP vulnerability
func (t *Tester) detectVulnerability(response, baseline string, payload Payload) string {
	// Check for different indicators based on payload type
	switch payload.Type {
	case VulnParameterPriority, VulnParameterOverwrite:
		// Look for evidence that second value was used
		if strings.Contains(response, "second") || strings.Contains(response, "INJECTED") {
			return "Second parameter value was used"
		}
		// Check if concatenation occurred
		if strings.Contains(response, "firstsecond") || strings.Contains(response, "first,second") {
			return "Parameters were concatenated"
		}

	case VulnArrayInjection:
		// PHP-specific array patterns
		if strings.Contains(response, "Array") || strings.Contains(response, "[0]") {
			return "Array processing detected"
		}

	case VulnWAFBypass:
		// Check for XSS payload reflection
		if strings.Contains(response, "<script>") || strings.Contains(response, "alert(1)") {
			return "XSS payload reflected (WAF bypass successful)"
		}
		// Check for SQL error or content leak
		if strings.Contains(strings.ToLower(response), "sql") ||
			strings.Contains(response, "users") {
			return "SQLi indicators detected (WAF bypass possible)"
		}
		// Check for file content (path traversal)
		if strings.Contains(response, "root:") || strings.Contains(response, "/bin/") {
			return "Path traversal successful (WAF bypass)"
		}

	case VulnDelimiterConfusion:
		// Check for multiple value processing
		if strings.Contains(response, "val1") && strings.Contains(response, "val2") {
			return "Multiple values processed via delimiter confusion"
		}

	case VulnServerSideHPP:
		// Look for unusual behavior
		if len(response) > 0 && len(baseline) > 0 && response != baseline {
			// Check for significant difference
			if len(response)-len(baseline) > 50 || len(baseline)-len(response) > 50 {
				return "Response differs significantly with duplicate parameters"
			}
		}
	}

	// Check for error messages that indicate HPP handling
	errorPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)array to string conversion`),
		regexp.MustCompile(`(?i)invalid.*parameter`),
		regexp.MustCompile(`(?i)multiple.*values`),
		regexp.MustCompile(`(?i)unexpected.*array`),
	}

	for _, p := range errorPatterns {
		if match := p.FindString(response); match != "" {
			return fmt.Sprintf("Error pattern: %s", match)
		}
	}

	return ""
}

// DetectTechnology attempts to detect the backend technology
func (t *Tester) DetectTechnology(ctx context.Context, targetURL string) (Technology, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return TechUnknown, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return TechUnknown, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Check headers
	server := strings.ToLower(resp.Header.Get("Server"))
	xPowered := strings.ToLower(resp.Header.Get("X-Powered-By"))

	if strings.Contains(xPowered, "php") || strings.Contains(server, "php") {
		return TechPHP, nil
	}
	if strings.Contains(xPowered, "asp") || strings.Contains(server, "asp") ||
		strings.Contains(server, "iis") {
		return TechASP, nil
	}
	if strings.Contains(xPowered, "express") || strings.Contains(xPowered, "node") {
		return TechNodeJS, nil
	}
	if strings.Contains(server, "apache tomcat") || strings.Contains(xPowered, "servlet") {
		return TechJava, nil
	}
	if strings.Contains(xPowered, "rack") || strings.Contains(server, "passenger") {
		return TechRuby, nil
	}

	// Check cookies for session naming patterns
	for _, cookie := range resp.Cookies() {
		name := strings.ToLower(cookie.Name)
		if strings.Contains(name, "phpsessid") {
			return TechPHP, nil
		}
		if strings.Contains(name, "aspsession") || strings.Contains(name, "asp.net") {
			return TechASP, nil
		}
		if strings.Contains(name, "jsessionid") {
			return TechJava, nil
		}
	}

	return TechUnknown, nil
}

// Scan performs a comprehensive HPP scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	// Detect technology
	tech, _ := t.DetectTechnology(ctx, targetURL)
	if t.config.Technology != TechUnknown {
		tech = t.config.Technology
	}
	result.Technology = tech

	// Test each parameter
	totalPayloads := 0
	for _, param := range t.config.TestParams {
		vulns, err := t.TestParameter(ctx, targetURL, param)
		if err != nil {
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
		totalPayloads += len(t.GetPayloads(param))
	}

	result.TestedPayloads = totalPayloads
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	return result, nil
}

// TestPOST tests HPP in POST body
func (t *Tester) TestPOST(ctx context.Context, targetURL string, param string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	payloads := t.GetPayloads(param)

	for _, payload := range payloads {
		req, err := http.NewRequestWithContext(ctx, "POST", targetURL,
			strings.NewReader(payload.Query))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", t.config.UserAgent)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)
		iohelper.DrainAndClose(resp.Body)

		evidence := t.detectVulnerability(string(body), "", payload)
		if evidence != "" {
			vulns = append(vulns, Vulnerability{
				Type:        payload.Type,
				Description: fmt.Sprintf("POST HPP: %s", payload.Description),
				Severity:    getSeverity(payload.Type),
				URL:         targetURL,
				Parameter:   param,
				Payload:     payload.Query,
				Evidence:    evidence,
				Remediation: GetHPPRemediation(),
			})
		}
	}

	return vulns, nil
}

// Helper functions

func getSeverity(vulnType VulnerabilityType) Severity {
	switch vulnType {
	case VulnWAFBypass:
		return SeverityHigh
	case VulnServerSideHPP, VulnParameterOverwrite:
		return SeverityMedium
	case VulnParameterPriority, VulnArrayInjection, VulnDelimiterConfusion:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Remediation guidance

// GetHPPRemediation returns remediation for HPP vulnerabilities
func GetHPPRemediation() string {
	return `To fix HTTP Parameter Pollution vulnerabilities:
1. Use only the first or last occurrence of each parameter consistently
2. Validate that parameters appear only once in requests
3. Implement strict input validation for all parameters
4. Use URL parsing libraries that handle duplicates safely
5. Apply WAF rules that detect multiple parameter instances
6. Log and alert on attempts to submit duplicate parameters
7. Use frameworks with built-in HPP protection
8. Consider URL encoding all user inputs`
}

// GetTechnologyBehavior describes how different technologies handle HPP
func GetTechnologyBehavior(tech Technology) string {
	behaviors := map[Technology]string{
		TechPHP:    "PHP: Uses last parameter value by default, arrays via param[]",
		TechASP:    "ASP.NET: Concatenates all values with comma",
		TechJava:   "Java Servlet: Returns first value via getParameter(), array via getParameterValues()",
		TechPython: "Python/Flask: Returns first value, can get all via getlist()",
		TechNodeJS: "Node.js/Express: Returns all values as array",
		TechRuby:   "Ruby on Rails: Returns last value",
		TechGo:     "Go: Returns first value via Get(), all via Values[]",
	}

	if behavior, ok := behaviors[tech]; ok {
		return behavior
	}
	return "Unknown technology behavior"
}

// AllVulnerabilityTypes returns all HPP vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnParameterPriority,
		VulnArrayInjection,
		VulnDelimiterConfusion,
		VulnWAFBypass,
		VulnServerSideHPP,
		VulnClientSideHPP,
		VulnParameterOverwrite,
	}
}

// AllTechnologies returns all supported technology types
func AllTechnologies() []Technology {
	return []Technology{
		TechPHP,
		TechASP,
		TechJava,
		TechPython,
		TechNodeJS,
		TechRuby,
		TechGo,
	}
}

// GenerateWAFBypassPayloads generates payloads to bypass WAFs using HPP
func GenerateWAFBypassPayloads(param, attackPayload string) []Payload {
	// Split the attack payload into parts
	parts := splitPayload(attackPayload)

	var payloads []Payload

	// Create HPP variants
	for i := 2; i <= 4; i++ {
		chunks := chunkPayload(attackPayload, i)
		query := ""
		for _, chunk := range chunks {
			if query != "" {
				query += "&"
			}
			query += param + "=" + url.QueryEscape(chunk)
		}
		payloads = append(payloads, Payload{
			Query:       query,
			Description: fmt.Sprintf("Split into %d parts", i),
			Type:        VulnWAFBypass,
		})
	}

	_ = parts // may be used for future variants

	return payloads
}

func splitPayload(payload string) []string {
	// Split at natural boundaries
	var parts []string
	mid := len(payload) / 2
	if mid > 0 && mid < len(payload) {
		parts = append(parts, payload[:mid], payload[mid:])
	}
	return parts
}

func chunkPayload(payload string, n int) []string {
	var chunks []string
	chunkSize := len(payload) / n
	if chunkSize == 0 {
		chunkSize = 1
	}

	for i := 0; i < len(payload); i += chunkSize {
		end := i + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, payload[i:end])
	}

	// Merge last small chunk if needed
	if len(chunks) > n && len(chunks[len(chunks)-1]) < chunkSize/2 {
		chunks[len(chunks)-2] += chunks[len(chunks)-1]
		chunks = chunks[:len(chunks)-1]
	}

	return chunks
}

// IsParameterDuplicate checks if a URL has duplicate parameters
func IsParameterDuplicate(rawURL string) (bool, []string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, nil
	}

	params := u.Query()
	var duplicates []string

	for key, values := range params {
		if len(values) > 1 {
			duplicates = append(duplicates, key)
		}
	}

	return len(duplicates) > 0, duplicates
}

// VulnerabilityToJSON converts vulnerability to JSON
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
