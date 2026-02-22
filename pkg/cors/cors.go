// Package cors provides CORS (Cross-Origin Resource Sharing) misconfiguration testing.
// It supports detection of origin reflection, null origin trust, credential exposure,
// and other CORS security issues.
package cors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// VulnerabilityType represents different CORS vulnerability types
type VulnerabilityType string

const (
	VulnOriginReflection    VulnerabilityType = "origin_reflection"    // Arbitrary origin accepted
	VulnNullOrigin          VulnerabilityType = "null_origin"          // null origin accepted
	VulnWildcardCredentials VulnerabilityType = "wildcard_credentials" // * with credentials
	VulnSubdomainTrust      VulnerabilityType = "subdomain_trust"      // Trusts any subdomain
	VulnWeakRegex           VulnerabilityType = "weak_regex"           // Weak origin validation
	VulnCredentialExposure  VulnerabilityType = "credential_exposure"  // Credentials exposed to untrusted origin
	VulnPreflight           VulnerabilityType = "preflight_bypass"     // Preflight bypass possible
)

// TestOrigin represents an origin to test
type TestOrigin struct {
	Origin      string            // The Origin header value
	Type        VulnerabilityType // Type of vulnerability being tested
	Description string            // Description of the test
}

// Vulnerability represents a detected CORS vulnerability
type Vulnerability struct {
	Type         VulnerabilityType `json:"type"`
	Description  string            `json:"description"`
	Severity     finding.Severity  `json:"severity"`
	TestedOrigin string            `json:"tested_origin"`
	AllowOrigin  string            `json:"allow_origin"`
	Credentials  bool              `json:"credentials"`
	Evidence     string            `json:"evidence"`
	URL          string            `json:"url"`
	Remediation  string            `json:"remediation"`
	ConfirmedBy  int               `json:"confirmed_by,omitempty"`
}

// TesterConfig configures the CORS tester
type TesterConfig struct {
	attackconfig.Base
	Headers         http.Header
	Cookies         []*http.Cookie
	FollowRedirects bool
}

// DefaultConfig returns a default tester configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Base: attackconfig.Base{
			Timeout:   httpclient.TimeoutProbing,
			UserAgent: defaults.UAChrome,
		},
		FollowRedirects: false,
	}
}

// Tester performs CORS misconfiguration testing
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// NewTester creates a new CORS tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	return &Tester{
		config: config,
		client: httpclient.Default(),
	}
}

// GenerateTestOrigins generates test origins based on target URL
func GenerateTestOrigins(targetURL string) []*TestOrigin {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return defaultTestOrigins()
	}

	host := parsed.Host
	scheme := parsed.Scheme
	baseDomain := extractBaseDomain(host)

	var origins []*TestOrigin

	// Origin reflection tests
	origins = append(origins, &TestOrigin{
		Origin:      "https://evil.com",
		Type:        VulnOriginReflection,
		Description: "Test for arbitrary origin acceptance",
	})

	origins = append(origins, &TestOrigin{
		Origin:      "https://attacker.example.com",
		Type:        VulnOriginReflection,
		Description: "Test with different domain",
	})

	// Null origin test
	origins = append(origins, &TestOrigin{
		Origin:      "null",
		Type:        VulnNullOrigin,
		Description: "Test for null origin acceptance",
	})

	// Subdomain trust tests
	origins = append(origins, &TestOrigin{
		Origin:      fmt.Sprintf("%s://evil.%s", scheme, baseDomain),
		Type:        VulnSubdomainTrust,
		Description: "Test for malicious subdomain trust",
	})

	origins = append(origins, &TestOrigin{
		Origin:      fmt.Sprintf("%s://test.%s", scheme, baseDomain),
		Type:        VulnSubdomainTrust,
		Description: "Test for arbitrary subdomain trust",
	})

	// Weak regex bypass tests
	origins = append(origins, &TestOrigin{
		Origin:      fmt.Sprintf("%s://%sevil.com", scheme, strings.TrimSuffix(baseDomain, ".")),
		Type:        VulnWeakRegex,
		Description: "Test for suffix matching bypass",
	})

	origins = append(origins, &TestOrigin{
		Origin:      fmt.Sprintf("%s://evil.com.%s", scheme, baseDomain),
		Type:        VulnWeakRegex,
		Description: "Test for prefix bypass",
	})

	origins = append(origins, &TestOrigin{
		Origin:      fmt.Sprintf("%s://%s.evil.com", scheme, baseDomain),
		Type:        VulnWeakRegex,
		Description: "Test for domain as subdomain of attacker",
	})

	// Protocol downgrade
	if scheme == "https" {
		origins = append(origins, &TestOrigin{
			Origin:      fmt.Sprintf("http://%s", host),
			Type:        VulnWeakRegex,
			Description: "Test for HTTP origin accepted on HTTPS",
		})
	}

	return origins
}

func defaultTestOrigins() []*TestOrigin {
	return []*TestOrigin{
		{Origin: "https://evil.com", Type: VulnOriginReflection, Description: "Arbitrary origin"},
		{Origin: "null", Type: VulnNullOrigin, Description: "Null origin"},
		{Origin: "https://attacker.com", Type: VulnOriginReflection, Description: "Attacker origin"},
	}
}

func extractBaseDomain(host string) string {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Use publicsuffix for correct multi-part TLD handling (e.g., .co.uk, .com.au)
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: get last two parts
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return host
	}
	return domain
}

// TestOrigin tests a specific origin against the target
func (t *Tester) TestOrigin(ctx context.Context, targetURL string, origin *TestOrigin) (*Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Origin", origin.Origin)
	req.Header.Set("User-Agent", t.config.UserAgent)

	for key, values := range t.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	for _, cookie := range t.config.Cookies {
		req.AddCookie(cookie)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Analyze CORS headers
	return t.analyzeResponse(targetURL, origin, resp)
}

// TestPreflight tests preflight (OPTIONS) request handling
func (t *Tester) TestPreflight(ctx context.Context, targetURL string, origin string) (*Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "PUT")
	req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header")
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")

	// Check for overly permissive preflight
	if allowOrigin == "*" || allowOrigin == origin {
		if strings.Contains(strings.ToLower(allowMethods), "put") ||
			strings.Contains(strings.ToLower(allowMethods), "delete") ||
			strings.Contains(strings.ToLower(allowMethods), "*") {

			severity := finding.Medium
			if allowCreds == "true" {
				severity = finding.High
			}

			return &Vulnerability{
				Type:         VulnPreflight,
				Description:  "Preflight allows dangerous methods from untrusted origin",
				Severity:     severity,
				TestedOrigin: origin,
				AllowOrigin:  allowOrigin,
				Credentials:  allowCreds == "true",
				Evidence:     fmt.Sprintf("Methods: %s, Headers: %s", allowMethods, allowHeaders),
				URL:          targetURL,
				Remediation:  "Restrict allowed methods and validate origins in preflight responses",
			}, nil
		}
	}

	return nil, nil
}

func (t *Tester) analyzeResponse(targetURL string, origin *TestOrigin, resp *http.Response) (*Vulnerability, error) {
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")

	// No CORS headers - not vulnerable (or CORS not enabled)
	if allowOrigin == "" {
		return nil, nil
	}

	var vuln *Vulnerability

	switch {
	// Wildcard with credentials - critical misconfiguration
	case allowOrigin == "*" && allowCreds == "true":
		vuln = &Vulnerability{
			Type:         VulnWildcardCredentials,
			Description:  "Wildcard origin with credentials enabled",
			Severity:     finding.Critical,
			TestedOrigin: origin.Origin,
			AllowOrigin:  allowOrigin,
			Credentials:  true,
			Evidence:     "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
			URL:          targetURL,
			Remediation:  "Never use wildcard origin with credentials. Validate specific origins.",
		}

	// Origin reflected back
	case allowOrigin == origin.Origin:
		severity := finding.High
		if allowCreds == "true" {
			severity = finding.Critical
		}

		vuln = &Vulnerability{
			Type:         origin.Type,
			Description:  fmt.Sprintf("Origin reflected: %s", origin.Description),
			Severity:     severity,
			TestedOrigin: origin.Origin,
			AllowOrigin:  allowOrigin,
			Credentials:  allowCreds == "true",
			Evidence:     fmt.Sprintf("Attacker origin %s is allowed", origin.Origin),
			URL:          targetURL,
			Remediation:  getRemediation(origin.Type),
		}

	// Null origin accepted
	case origin.Origin == "null" && allowOrigin == "null":
		vuln = &Vulnerability{
			Type:         VulnNullOrigin,
			Description:  "Null origin is trusted",
			Severity:     finding.High,
			TestedOrigin: origin.Origin,
			AllowOrigin:  allowOrigin,
			Credentials:  allowCreds == "true",
			Evidence:     "Access-Control-Allow-Origin: null",
			URL:          targetURL,
			Remediation:  "Never trust null origin. It can be sent from sandboxed iframes or local files.",
		}
	}

	return vuln, nil
}

func getRemediation(vulnType VulnerabilityType) string {
	remediations := map[VulnerabilityType]string{
		VulnOriginReflection:    "Implement a strict allowlist of trusted origins instead of reflecting the Origin header.",
		VulnNullOrigin:          "Never trust null origin. Remove null from allowed origins list.",
		VulnWildcardCredentials: "Use specific origins instead of wildcard when credentials are needed.",
		VulnSubdomainTrust:      "Validate exact origin matches. Don't trust arbitrary subdomains.",
		VulnWeakRegex:           "Use exact string matching for origin validation, not regex or substring matching.",
		VulnCredentialExposure:  "Only allow credentials with explicitly trusted origins.",
		VulnPreflight:           "Validate origins in preflight. Restrict allowed methods to minimum required.",
	}

	if r, ok := remediations[vulnType]; ok {
		return r
	}
	return "Implement proper origin validation with a strict allowlist."
}

// Result represents a CORS scan result
type Result struct {
	URL             string           `json:"url"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	TestedOrigins   int              `json:"tested_origins"`
	Duration        time.Duration    `json:"duration"`
	CORSEnabled     bool             `json:"cors_enabled"`
}

// Scan performs a comprehensive CORS scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*Result, error) {
	start := time.Now()

	result := &Result{
		URL: targetURL,
	}

	origins := GenerateTestOrigins(targetURL)
	result.TestedOrigins = len(origins)

	var vulns []*Vulnerability

	for _, origin := range origins {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		vuln, err := t.TestOrigin(ctx, targetURL, origin)
		if err != nil {
			continue
		}

		if vuln != nil {
			result.CORSEnabled = true
			vulns = append(vulns, vuln)
			t.config.NotifyVulnerabilityFound()
		}
	}

	// Test preflight
	preflightVuln, _ := t.TestPreflight(ctx, targetURL, "https://evil.com")
	if preflightVuln != nil {
		vulns = append(vulns, preflightVuln)
		t.config.NotifyVulnerabilityFound()
	}

	result.Vulnerabilities = vulns
	result.Duration = time.Since(start)

	return result, nil
}

// CheckCORSHeaders extracts and analyzes CORS headers from a response
func CheckCORSHeaders(headers http.Header) *CORSAnalysis {
	analysis := &CORSAnalysis{
		AllowOrigin:      headers.Get("Access-Control-Allow-Origin"),
		AllowCredentials: headers.Get("Access-Control-Allow-Credentials") == "true",
		AllowMethods:     headers.Get("Access-Control-Allow-Methods"),
		AllowHeaders:     headers.Get("Access-Control-Allow-Headers"),
		ExposeHeaders:    headers.Get("Access-Control-Expose-Headers"),
		MaxAge:           headers.Get("Access-Control-Max-Age"),
	}

	analysis.CORSEnabled = analysis.AllowOrigin != ""

	// Analyze security posture
	if analysis.AllowOrigin == "*" {
		analysis.Issues = append(analysis.Issues, "Wildcard origin allows any domain")
	}

	if analysis.AllowOrigin == "*" && analysis.AllowCredentials {
		analysis.Issues = append(analysis.Issues, "Critical: Wildcard with credentials")
	}

	if analysis.AllowOrigin == "null" {
		analysis.Issues = append(analysis.Issues, "Null origin is trusted")
	}

	if strings.Contains(strings.ToLower(analysis.AllowMethods), "*") {
		analysis.Issues = append(analysis.Issues, "All methods are allowed")
	}

	if strings.Contains(strings.ToLower(analysis.AllowHeaders), "*") {
		analysis.Issues = append(analysis.Issues, "All headers are allowed")
	}

	analysis.Secure = len(analysis.Issues) == 0

	return analysis
}

// CORSAnalysis contains analysis of CORS headers
type CORSAnalysis struct {
	CORSEnabled      bool     `json:"cors_enabled"`
	AllowOrigin      string   `json:"allow_origin"`
	AllowCredentials bool     `json:"allow_credentials"`
	AllowMethods     string   `json:"allow_methods"`
	AllowHeaders     string   `json:"allow_headers"`
	ExposeHeaders    string   `json:"expose_headers"`
	MaxAge           string   `json:"max_age"`
	Issues           []string `json:"issues"`
	Secure           bool     `json:"secure"`
}

// AllVulnerabilityTypes returns all CORS vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnOriginReflection,
		VulnNullOrigin,
		VulnWildcardCredentials,
		VulnSubdomainTrust,
		VulnWeakRegex,
		VulnCredentialExposure,
		VulnPreflight,
	}
}

// GetCORSHeaders performs a request and returns CORS headers
func (t *Tester) GetCORSHeaders(ctx context.Context, targetURL string, origin string) (*CORSAnalysis, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	return CheckCORSHeaders(resp.Header), nil
}

// VaryOriginCheck checks if Vary: Origin is properly set
func (t *Tester) VaryOriginCheck(ctx context.Context, targetURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return false, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	vary := resp.Header.Get("Vary")
	return strings.Contains(strings.ToLower(vary), "origin"), nil
}
