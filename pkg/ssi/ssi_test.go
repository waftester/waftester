package ssi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 10 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 10", config.Concurrency)
	}
	if config.Timeout != 10*1e9 {
		t.Errorf("DefaultConfig().Timeout = %v, want 10s", config.Timeout)
	}
}

func TestNewScanner(t *testing.T) {
	config := DefaultConfig()
	scanner := NewScanner(config)
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if scanner.client == nil {
		t.Error("Scanner client is nil")
	}
}

func TestScanner_Scan_Vulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		if strings.Contains(query, "include") || strings.Contains(query, "exec") {
			// Simulate SSI error
			w.Write([]byte("[an error occurred while processing this directive]"))
		} else {
			w.Write([]byte("OK"))
		}
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL, map[string]string{
		"input": "test",
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			if r.Severity != "HIGH" {
				t.Errorf("Vulnerable result severity = %s, want HIGH", r.Severity)
			}
		}
	}

	if !foundVuln {
		t.Error("Expected to find vulnerability with SSI error")
	}
}

func TestScanner_Scan_Safe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK - no SSI processing"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL, map[string]string{
		"input": "test",
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, r := range results {
		if r.Vulnerable {
			t.Error("Expected no vulnerabilities in safe endpoint")
		}
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("GetResults returned nil")
	}
}

func TestPayloads(t *testing.T) {
	payloads := Payloads()
	if len(payloads) < 10 {
		t.Errorf("Payloads count = %d, want at least 10", len(payloads))
	}

	// Check for include payloads
	foundInclude := false
	for _, p := range payloads {
		if strings.Contains(p, "include") {
			foundInclude = true
			break
		}
	}
	if !foundInclude {
		t.Error("Expected include payloads")
	}

	// Check for exec payloads
	foundExec := false
	for _, p := range payloads {
		if strings.Contains(p, "exec") {
			foundExec = true
			break
		}
	}
	if !foundExec {
		t.Error("Expected exec payloads")
	}
}

func TestExecPayloads(t *testing.T) {
	payloads := ExecPayloads("id")
	if len(payloads) < 1 {
		t.Errorf("ExecPayloads count = %d, want at least 1", len(payloads))
	}

	for _, p := range payloads {
		if !strings.Contains(p, "id") {
			t.Errorf("ExecPayload should contain command: %s", p)
		}
		if !strings.Contains(p, "<!--#exec") {
			t.Errorf("ExecPayload should be SSI exec directive: %s", p)
		}
	}
}

func TestIncludePayloads(t *testing.T) {
	payloads := IncludePayloads("/etc/passwd")
	if len(payloads) < 1 {
		t.Errorf("IncludePayloads count = %d, want at least 1", len(payloads))
	}

	for _, p := range payloads {
		if !strings.Contains(p, "/etc/passwd") {
			t.Errorf("IncludePayload should contain path: %s", p)
		}
		if !strings.Contains(p, "<!--#include") {
			t.Errorf("IncludePayload should be SSI include directive: %s", p)
		}
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:        "http://example.com",
		Parameter:  "input",
		Payload:    "<!--#exec cmd=\"id\" -->",
		StatusCode: 200,
		Vulnerable: true,
		Evidence:   "SSI error",
		Severity:   "HIGH",
	}

	if result.URL != "http://example.com" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
	if result.Severity != "HIGH" {
		t.Error("Severity not set correctly")
	}
}

func TestDetectVulnerability_ErrorPatterns(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		body     string
		payload  string
		expected bool
	}{
		{"[an error occurred while processing this directive]", "<!--#exec cmd=\"id\" -->", true},
		{"SSI Error: invalid directive", "<!--#include file=\"x\" -->", true},
		{"mod_include error", "<!--#exec cmd=\"ls\" -->", true},
		{"Safe response", "<!--#exec cmd=\"id\" -->", false},
	}

	for _, tt := range tests {
		vuln, _ := scanner.detectVulnerability(tt.body, tt.payload)
		if vuln != tt.expected {
			t.Errorf("detectVulnerability(%q, %q) = %v, want %v", tt.body, tt.payload, vuln, tt.expected)
		}
	}
}
