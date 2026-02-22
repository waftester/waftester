// Package csrf provides Cross-Site Request Forgery testing
package csrf

import (
	"context"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures CSRF testing
type Config struct {
	attackconfig.Base
	Headers map[string]string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyMedium,
			Timeout:     httpclient.TimeoutProbing,
		},
	}
}

// Result represents a CSRF test result
type Result struct {
	URL           string
	Method        string
	HasCSRFToken  bool
	TokenName     string
	TokenLocation string
	SameSite      string
	Referer       string
	Vulnerable    bool
	Evidence      string
	Severity      string
	Timestamp     time.Time
}

// Scanner performs CSRF testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new CSRF scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyMedium
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutProbing
	}

	return &Scanner{
		config:  config,
		client:  httpclient.Default(),
		results: make([]Result, 0),
	}
}

// Scan tests a URL for CSRF vulnerabilities
func (s *Scanner) Scan(ctx context.Context, targetURL string, method string) (Result, error) {
	result := Result{
		URL:       targetURL,
		Method:    method,
		Timestamp: time.Now(),
	}

	// First, get the page to analyze
	pageResult := s.analyzePage(ctx, targetURL)
	result.HasCSRFToken = pageResult.HasCSRFToken
	result.TokenName = pageResult.TokenName
	result.TokenLocation = pageResult.TokenLocation

	// Test without CSRF token
	if method != "GET" {
		vulnerable := s.testWithoutToken(ctx, targetURL, method)
		if vulnerable {
			result.Vulnerable = true
			result.Evidence = "Request accepted without CSRF token"
			result.Severity = "MEDIUM"
			s.config.NotifyVulnerabilityFound()
		}
	}

	// Check SameSite cookie attribute
	result.SameSite = s.checkSameSite(ctx, targetURL)
	if result.SameSite == "None" || result.SameSite == "" {
		if !result.Vulnerable {
			result.Vulnerable = true
			result.Evidence = "Missing or weak SameSite cookie attribute"
			result.Severity = "LOW"
			s.config.NotifyVulnerabilityFound()
		}
	}

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	return result, nil
}

// PageAnalysis contains CSRF token analysis
type PageAnalysis struct {
	HasCSRFToken  bool
	TokenName     string
	TokenLocation string
}

// analyzePage analyzes a page for CSRF tokens
func (s *Scanner) analyzePage(ctx context.Context, url string) PageAnalysis {
	result := PageAnalysis{}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	bodyStr := string(body)

	// Check for common CSRF token patterns in forms, meta tags, and headers
	tokenPatterns := []struct {
		name     string
		pattern  string
		location string
	}{
		// Hidden form fields
		{"csrf_token", `name="csrf_token"`, "form"},
		{"_token", `name="_token"`, "form"},
		{"authenticity_token", `name="authenticity_token"`, "form"},
		{"csrfmiddlewaretoken", `name="csrfmiddlewaretoken"`, "form"},
		{"__RequestVerificationToken", `name="__RequestVerificationToken"`, "form"},
		{"_csrf", `name="_csrf"`, "form"},
		{"nonce", `name="nonce"`, "form"},
		// Meta tags (Rails, Laravel, generic frameworks)
		{"csrf-token", `name="csrf-token"`, "meta"},
		{"csrf-param", `name="csrf-param"`, "meta"},
		{"_token", `name="_token" content=`, "meta"},
		{"csrf", `name="csrf" content=`, "meta"},
		// Header-based tokens
		{"X-CSRF-TOKEN", "X-CSRF-TOKEN", "header"},
		{"X-XSRF-TOKEN", "X-XSRF-TOKEN", "header"},
		{"X-CSRFToken", "X-CSRFToken", "header"},
	}

	for _, tp := range tokenPatterns {
		if strings.Contains(bodyStr, tp.pattern) {
			result.HasCSRFToken = true
			result.TokenName = tp.name
			result.TokenLocation = tp.location
			break
		}
	}

	return result
}

// testWithoutToken tests if request succeeds without CSRF token
func (s *Scanner) testWithoutToken(ctx context.Context, url string, method string) bool {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader("test=1"))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", defaults.ContentTypeForm)

	// Remove referer to simulate cross-origin
	req.Header.Set("Origin", "https://attacker.com")

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer iohelper.DrainAndClose(resp.Body)

	// If request succeeds (2xx or 3xx), might be vulnerable
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// checkSameSite checks the SameSite cookie attribute
func (s *Scanner) checkSameSite(ctx context.Context, url string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return ""
	}
	defer iohelper.DrainAndClose(resp.Body)

	for _, cookie := range resp.Cookies() {
		switch cookie.SameSite {
		case http.SameSiteStrictMode:
			return "Strict"
		case http.SameSiteLaxMode:
			return "Lax"
		case http.SameSiteNoneMode:
			return "None"
		}
	}

	return ""
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// GeneratePOC generates a CSRF proof-of-concept
func GeneratePOC(targetURL, method string, params map[string]string) string {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
<h1>CSRF Proof of Concept</h1>
<form id="csrf-form" action="`)
	sb.WriteString(html.EscapeString(targetURL))
	sb.WriteString(`" method="`)
	sb.WriteString(html.EscapeString(method))
	sb.WriteString(`">
`)

	for name, value := range params {
		sb.WriteString(`  <input type="hidden" name="`)
		sb.WriteString(html.EscapeString(name))
		sb.WriteString(`" value="`)
		sb.WriteString(html.EscapeString(value))
		sb.WriteString(`" />
`)
	}

	sb.WriteString(`</form>
<script>document.getElementById('csrf-form').submit();</script>
</body>
</html>`)

	return sb.String()
}

// CommonTargets returns common CSRF-prone endpoints
func CommonTargets() []string {
	return []string{
		"/account/settings",
		"/user/profile/update",
		"/password/change",
		"/email/change",
		"/transfer",
		"/payment",
		"/admin/user/delete",
		"/api/settings",
	}
}
