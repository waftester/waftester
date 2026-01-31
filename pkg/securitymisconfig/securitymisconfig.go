// Package securitymisconfig provides Security Misconfiguration testing
package securitymisconfig

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures security misconfiguration testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: 10,
		Timeout:     10 * time.Second,
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
		config.Concurrency = 10
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}

	return &Scanner{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
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
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

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
		} else if header.Validator != nil && !header.Validator(value) {
			result.Vulnerable = true
			result.Evidence = "Weak header value: " + header.Name + "=" + value
			result.Severity = header.Severity
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

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	result.StatusCode = resp.StatusCode

	// Check if endpoint is accessible
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		result.Vulnerable = true
		result.Evidence = "Endpoint accessible: " + endpoint
		result.Severity = "HIGH"
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
			Severity: "MEDIUM",
			Validator: func(v string) bool {
				v = strings.ToUpper(v)
				return v == "DENY" || v == "SAMEORIGIN"
			},
		},
		{
			Name:     "X-Content-Type-Options",
			Severity: "MEDIUM",
			Validator: func(v string) bool {
				return strings.ToLower(v) == "nosniff"
			},
		},
		{
			Name:     "Strict-Transport-Security",
			Severity: "HIGH",
			Validator: func(v string) bool {
				return strings.Contains(strings.ToLower(v), "max-age=")
			},
		},
		{
			Name:      "Content-Security-Policy",
			Severity:  "MEDIUM",
			Validator: nil, // Any CSP is better than none
		},
		{
			Name:     "X-XSS-Protection",
			Severity: "LOW",
			Validator: func(v string) bool {
				return strings.HasPrefix(v, "1")
			},
		},
		{
			Name:      "Referrer-Policy",
			Severity:  "LOW",
			Validator: nil,
		},
		{
			Name:      "Permissions-Policy",
			Severity:  "LOW",
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
