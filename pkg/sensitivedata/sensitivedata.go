// Package sensitivedata provides Sensitive Data Exposure testing
package sensitivedata

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/strutil"
)

// Config configures sensitive data testing
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

// Result represents a sensitive data exposure test result
type Result struct {
	URL         string
	DataType    string
	Description string
	Location    string // body, header, url
	Match       string
	Vulnerable  bool
	Evidence    string
	Severity    string
	Timestamp   time.Time
}

// Scanner performs sensitive data exposure testing
type Scanner struct {
	config   Config
	client   *http.Client
	patterns []Pattern
	results  []Result
	mu       sync.RWMutex
}

// Pattern represents a sensitive data pattern
type Pattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
}

// NewScanner creates a new sensitive data scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyMedium
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutProbing
	}

	return &Scanner{
		config:   config,
		client:   httpclient.Default(),
		patterns: compilePatterns(),
		results:  make([]Result, 0),
	}
}

func compilePatterns() []Pattern {
	patterns := []Pattern{
		{Name: "AWS Access Key", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Severity: "CRITICAL"},
		{Name: "AWS Secret Key", Regex: regexp.MustCompile(`(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`), Severity: "CRITICAL"},
		{Name: "GitHub Token", Regex: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), Severity: "CRITICAL"},
		{Name: "Google API Key", Regex: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`), Severity: "HIGH"},
		{Name: "Private Key", Regex: regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`), Severity: "CRITICAL"},
		{Name: "Credit Card", Regex: regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`), Severity: "CRITICAL"},
		{Name: "SSN", Regex: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), Severity: "CRITICAL"},
		{Name: "Email", Regex: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), Severity: "LOW"},
		{Name: "JWT", Regex: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`), Severity: "HIGH"},
		{Name: "Basic Auth", Regex: regexp.MustCompile(`(?i)basic\s+[a-zA-Z0-9+/=]{10,}`), Severity: "HIGH"},
		{Name: "Bearer Token", Regex: regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9._-]{10,}`), Severity: "HIGH"},
		{Name: "Password in URL", Regex: regexp.MustCompile(`(?i)password[=:][^&\s]+`), Severity: "HIGH"},
		{Name: "API Key Generic", Regex: regexp.MustCompile(`(?i)api[_-]?key[=:]['"]?[a-zA-Z0-9]{16,}['"]?`), Severity: "HIGH"},
		{Name: "Slack Token", Regex: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`), Severity: "CRITICAL"},
		{Name: "Heroku API Key", Regex: regexp.MustCompile(`(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Severity: "CRITICAL"},
	}
	return patterns
}

// Scan tests a URL for sensitive data exposure
func (s *Scanner) Scan(ctx context.Context, targetURL string) ([]Result, error) {
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

	body, _ := iohelper.ReadBodyDefault(resp.Body)

	// Check body for sensitive data
	bodyResults := s.scanContent(targetURL, string(body), "body")
	results = append(results, bodyResults...)

	// Check headers
	for key, values := range resp.Header {
		for _, value := range values {
			headerResults := s.scanContent(targetURL, value, "header:"+key)
			results = append(results, headerResults...)
		}
	}

	// Check URL
	urlResults := s.scanContent(targetURL, targetURL, "url")
	results = append(results, urlResults...)

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// scanContent checks content for sensitive data patterns
func (s *Scanner) scanContent(url, content, location string) []Result {
	results := make([]Result, 0)

	for _, pattern := range s.patterns {
		if matches := pattern.Regex.FindAllString(content, -1); len(matches) > 0 {
			for _, match := range matches {
				result := Result{
					URL:        url,
					DataType:   pattern.Name,
					Location:   location,
					Match:      strutil.Truncate(match, 50),
					Vulnerable: true,
					Evidence:   pattern.Name + " found in " + location,
					Severity:   pattern.Severity,
					Timestamp:  time.Now(),
				}
				s.config.NotifyVulnerabilityFound()
				results = append(results, result)
			}
		}
	}

	return results
}



// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// SensitivePatterns returns pattern names for sensitive data
func SensitivePatterns() []string {
	return []string{
		"AWS Access Key",
		"AWS Secret Key",
		"GitHub Token",
		"Google API Key",
		"Private Key",
		"Credit Card",
		"SSN",
		"Email",
		"JWT",
		"Basic Auth",
		"Bearer Token",
		"Password in URL",
		"API Key Generic",
		"Slack Token",
		"Heroku API Key",
	}
}

// SensitiveEndpoints returns endpoints likely to contain sensitive data
func SensitiveEndpoints() []string {
	return []string{
		"/api/config",
		"/api/settings",
		"/api/user/profile",
		"/api/keys",
		"/debug/vars",
		"/.env",
		"/config.json",
		"/settings.json",
		"/api/v1/me",
		"/api/credentials",
		"/api/tokens",
	}
}

// InsecureTransmissionPatterns returns patterns for insecure data transmission
func InsecureTransmissionPatterns() []string {
	return []string{
		"password",
		"secret",
		"apikey",
		"api_key",
		"access_token",
		"auth_token",
		"private_key",
		"session_id",
	}
}

// CheckHTTPS checks if HTTPS is properly used
func CheckHTTPS(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "https://")
}
