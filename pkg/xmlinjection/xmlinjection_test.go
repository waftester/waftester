package xmlinjection

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
	if config.Timeout != 15*1e9 {
		t.Errorf("DefaultConfig().Timeout = %v, want 15s", config.Timeout)
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
	// Server that shows XML parsing errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("XML Parsing Error: not well-formed"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
		}
	}

	if !foundVuln {
		t.Error("Expected to find XML injection vulnerability")
	}
}

func TestScanner_Scan_Safe(t *testing.T) {
	// Server that handles XML safely
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK - request processed"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL)

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
	if len(payloads) < 5 {
		t.Errorf("Payloads count = %d, want at least 5", len(payloads))
	}

	// Check for XXE payloads
	foundXXE := false
	for _, p := range payloads {
		if p.Type == "xxe" {
			foundXXE = true
			if !strings.Contains(p.Value, "ENTITY") {
				t.Error("XXE payload should contain ENTITY")
			}
		}
	}
	if !foundXXE {
		t.Error("Expected XXE payloads")
	}

	// Check for billion laughs
	foundDoS := false
	for _, p := range payloads {
		if p.Type == "billion-laughs" {
			foundDoS = true
		}
	}
	if !foundDoS {
		t.Error("Expected Billion Laughs DoS payload")
	}
}

func TestXXEPayloads(t *testing.T) {
	payloads := XXEPayloads("attacker.com")
	if len(payloads) < 1 {
		t.Errorf("XXEPayloads count = %d, want at least 1", len(payloads))
	}

	for _, p := range payloads {
		if !strings.Contains(p.Value, "attacker.com") {
			t.Error("XXE OOB payload should contain OOB domain")
		}
	}
}

func TestSoapPayloads(t *testing.T) {
	payloads := SoapPayloads()
	if len(payloads) < 1 {
		t.Errorf("SoapPayloads count = %d, want at least 1", len(payloads))
	}

	for _, p := range payloads {
		if !strings.Contains(p.Value, "soapenv:Envelope") {
			t.Error("SOAP payload should contain SOAP envelope")
		}
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "http://example.com/api",
		Parameter:   "data",
		Payload:     "<test/>",
		PayloadType: "xxe",
		StatusCode:  200,
		Vulnerable:  true,
		Evidence:    "XXE detected",
		Severity:    "CRITICAL",
	}

	if result.URL != "http://example.com/api" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
	if result.Severity != "CRITICAL" {
		t.Error("Severity not set correctly")
	}
}

func TestDetectVulnerability_XXE(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	payload := Payload{Type: "xxe", Value: "test"}

	tests := []struct {
		body     string
		expected bool
	}{
		{"root:x:0:0:root:/root:/bin/bash", true},
		{"/etc/passwd content here", true},
		{"Safe response", false},
	}

	for _, tt := range tests {
		vuln, _ := scanner.detectVulnerability(tt.body, payload)
		if vuln != tt.expected {
			t.Errorf("detectVulnerability(%q) = %v, want %v", tt.body, vuln, tt.expected)
		}
	}
}

func TestDetectVulnerability_Errors(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	payload := Payload{Type: "malformed", Value: "test"}

	tests := []struct {
		body     string
		expected bool
	}{
		{"XML Parsing Error: not well-formed", true},
		{"SAXParseException occurred", true},
		{"parser error at line 5", true},
		{"Safe response", false},
	}

	for _, tt := range tests {
		vuln, _ := scanner.detectVulnerability(tt.body, payload)
		if vuln != tt.expected {
			t.Errorf("detectVulnerability(%q) = %v, want %v", tt.body, vuln, tt.expected)
		}
	}
}
