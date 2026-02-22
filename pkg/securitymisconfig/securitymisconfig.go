// Package securitymisconfig provides Security Misconfiguration testing
package securitymisconfig

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures security misconfiguration testing
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

// Result represents a security misconfiguration test result
type Result struct {
	URL         string
	TestType    string
	Description string
	StatusCode  int
	Vulnerable  bool
	Evidence    string
	Severity    string
	Timestamp   time.Time
}

// Scanner performs security misconfiguration testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new security misconfiguration scanner
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

// TestSecurityHeaders tests for missing security headers
func (s *Scanner) TestSecurityHeaders(ctx context.Context, targetURL string) ([]Result, error) {
	results := make([]Result, 0)

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)
	iohelper.ReadBodyDefault(resp.Body)

	for _, header := range RequiredSecurityHeaders() {
		result := Result{
			URL:         targetURL,
			TestType:    "missing_header",
			Description: header.Name,
			StatusCode:  resp.StatusCode,
			Timestamp:   time.Now(),
		}

		value := resp.Header.Get(header.Name)
		if value == "" {
			result.Vulnerable = true
			result.Evidence = "Missing security header: " + header.Name
			result.Severity = header.Severity
			s.config.NotifyVulnerabilityFound()
		} else if header.Validator != nil && !header.Validator(value) {
			result.Vulnerable = true
			result.Evidence = "Weak header value: " + header.Name + "=" + value
			result.Severity = header.Severity
			s.config.NotifyVulnerabilityFound()
		}

		results = append(results, result)
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// TestDebugEndpoints tests for exposed debug endpoints
func (s *Scanner) TestDebugEndpoints(ctx context.Context, baseURL string) ([]Result, error) {
	results := make([]Result, 0)

	for _, endpoint := range DebugEndpoints() {
		fullURL := strings.TrimSuffix(baseURL, "/") + endpoint
		result := s.testEndpoint(ctx, fullURL, "debug_endpoint", endpoint)
		results = append(results, result)
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// TestDefaultCredentials tests for default credentials in common paths
func (s *Scanner) TestDefaultCredentials(ctx context.Context, baseURL string) ([]Result, error) {
	results := make([]Result, 0)

	for _, endpoint := range AdminEndpoints() {
		fullURL := strings.TrimSuffix(baseURL, "/") + endpoint
		result := s.testEndpoint(ctx, fullURL, "admin_exposure", endpoint)
		results = append(results, result)
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

func (s *Scanner) testEndpoint(ctx context.Context, url, testType, endpoint string) Result {
	result := Result{
		URL:         url,
		TestType:    testType,
		Description: endpoint,
		Timestamp:   time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result
	}
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)
	iohelper.ReadBodyDefault(resp.Body)

	result.StatusCode = resp.StatusCode

	// Check if endpoint is accessible
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		result.Vulnerable = true
		result.Evidence = "Endpoint accessible: " + endpoint
		result.Severity = "high"
		s.config.NotifyVulnerabilityFound()
	}

	return result
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// SecurityHeader represents a security header to check
type SecurityHeader struct {
	Name      string
	Severity  string
	Validator func(string) bool
}

// RequiredSecurityHeaders returns security headers that should be present
func RequiredSecurityHeaders() []SecurityHeader {
	return []SecurityHeader{
		{
			Name:     "X-Frame-Options",
			Severity: "medium",
			Validator: func(v string) bool {
				v = strings.ToUpper(v)
				return v == "DENY" || v == "SAMEORIGIN"
			},
		},
		{
			Name:     "X-Content-Type-Options",
			Severity: "medium",
			Validator: func(v string) bool {
				return strings.ToLower(v) == "nosniff"
			},
		},
		{
			Name:     "Strict-Transport-Security",
			Severity: "high",
			Validator: func(v string) bool {
				return strings.Contains(strings.ToLower(v), "max-age=")
			},
		},
		{
			Name:      "Content-Security-Policy",
			Severity:  "medium",
			Validator: nil, // Any CSP is better than none
		},
		{
			Name:     "X-XSS-Protection",
			Severity: "low",
			Validator: func(v string) bool {
				return strings.HasPrefix(v, "1")
			},
		},
		{
			Name:      "Referrer-Policy",
			Severity:  "low",
			Validator: nil,
		},
		{
			Name:      "Permissions-Policy",
			Severity:  "low",
			Validator: nil,
		},
	}
}

// DebugEndpoints returns common debug endpoints
func DebugEndpoints() []string {
	return []string{
		"/debug",
		"/debug/pprof",
		"/debug/vars",
		"/.env",
		"/.git/config",
		"/.git/HEAD",
		"/phpinfo.php",
		"/info.php",
		"/server-status",
		"/server-info",
		"/.htaccess",
		"/.htpasswd",
		"/web.config",
		"/elmah.axd",
		"/trace.axd",
		"/actuator",
		"/actuator/health",
		"/actuator/env",
		"/metrics",
		"/prometheus",
		"/graphql",
		"/graphiql",
		"/swagger.json",
		"/swagger-ui.html",
		"/api-docs",
		"/.well-known/security.txt",
	}
}

// AdminEndpoints returns common admin endpoints
func AdminEndpoints() []string {
	return []string{
		"/admin",
		"/administrator",
		"/admin.php",
		"/wp-admin",
		"/wp-login.php",
		"/phpmyadmin",
		"/adminer.php",
		"/manager/html",
		"/console",
		"/admin/login",
		"/backend",
		"/cpanel",
		"/webmail",
	}
}

// SensitiveFiles returns sensitive files to check
func SensitiveFiles() []string {
	return []string{
		"/robots.txt",
		"/sitemap.xml",
		"/crossdomain.xml",
		"/clientaccesspolicy.xml",
		"/.DS_Store",
		"/Thumbs.db",
		"/backup.sql",
		"/dump.sql",
		"/database.sql",
		"/config.php",
		"/settings.py",
		"/application.properties",
		"/application.yml",
	}
}
