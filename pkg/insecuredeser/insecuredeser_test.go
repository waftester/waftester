package insecuredeser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 5 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 5", config.Concurrency)
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		data := r.FormValue("data")
		if strings.Contains(data, "stdClass") {
			w.Write([]byte("Error: unserialize() failed"))
		} else {
			w.Write([]byte("OK"))
		}
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL, map[string]string{
		"data": "test",
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			if r.Severity != "CRITICAL" {
				t.Errorf("Vulnerable result severity = %s, want CRITICAL", r.Severity)
			}
		}
	}

	if !foundVuln {
		t.Error("Expected to find vulnerability with unserialize() error")
	}
}

func TestScanner_Scan_Safe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK - no deserialization"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL, map[string]string{
		"data": "test",
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
	if len(payloads) < 5 {
		t.Errorf("Payloads count = %d, want at least 5", len(payloads))
	}

	// Check for PHP payloads
	foundPHP := false
	for _, p := range payloads {
		if p.Language == "PHP" {
			foundPHP = true
			break
		}
	}
	if !foundPHP {
		t.Error("Expected PHP payloads")
	}

	// Check for Java payloads
	foundJava := false
	for _, p := range payloads {
		if p.Language == "Java" {
			foundJava = true
			break
		}
	}
	if !foundJava {
		t.Error("Expected Java payloads")
	}

	// Check for Python payloads
	foundPython := false
	for _, p := range payloads {
		if p.Language == "Python" {
			foundPython = true
			break
		}
	}
	if !foundPython {
		t.Error("Expected Python payloads")
	}
}

func TestJavaGadgetPayloads(t *testing.T) {
	payloads := JavaGadgetPayloads("id")
	if len(payloads) < 5 {
		t.Errorf("JavaGadgetPayloads count = %d, want at least 5", len(payloads))
	}

	// Check for CommonsCollections
	foundCC := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "CommonsCollections") {
			foundCC = true
			break
		}
	}
	if !foundCC {
		t.Error("Expected CommonsCollections gadget")
	}
}

func TestPHPGadgetPayloads(t *testing.T) {
	payloads := PHPGadgetPayloads("id")
	if len(payloads) < 1 {
		t.Errorf("PHPGadgetPayloads count = %d, want at least 1", len(payloads))
	}

	// Check for Laravel/Illuminate
	for _, p := range payloads {
		if p.Language != "PHP" {
			t.Errorf("Expected PHP language, got %s", p.Language)
		}
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "http://example.com",
		Parameter:   "data",
		Payload:     "test",
		PayloadType: "php",
		StatusCode:  200,
		Vulnerable:  true,
		Evidence:    "unserialize",
		Severity:    "CRITICAL",
	}

	if result.URL != "http://example.com" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
	if result.Severity != "CRITICAL" {
		t.Error("Severity not set correctly")
	}
}

func TestDetectVulnerability_ErrorPatterns(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		body     string
		expected bool
	}{
		{"Error: unserialize() failed", true},
		{"java.io.InvalidClassException", true},
		{"ObjectInputStream error", true},
		{"pickle.loads failed", true},
		{"Safe response", false},
	}

	for _, tt := range tests {
		vuln, _ := scanner.detectVulnerability(tt.body, nil)
		if vuln != tt.expected {
			t.Errorf("detectVulnerability(%q) = %v, want %v", tt.body, vuln, tt.expected)
		}
	}
}
