package sensitivedata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 10 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 10", config.Concurrency)
	}
	if config.Timeout != httpclient.TimeoutProbing {
		t.Errorf("DefaultConfig().Timeout = %v, want %v", config.Timeout, httpclient.TimeoutProbing)
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
	if len(scanner.patterns) == 0 {
		t.Error("Expected patterns to be compiled")
	}
}

func TestScanner_Scan_FindsAWSKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulated AWS key exposure
		w.Write([]byte(`{"aws_key": "AKIAIOSFODNN7EXAMPLE"}`))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundAWS := false
	for _, r := range results {
		if r.DataType == "AWS Access Key" {
			foundAWS = true
			if r.Severity != "CRITICAL" {
				t.Errorf("AWS key severity = %s, want CRITICAL", r.Severity)
			}
		}
	}

	if !foundAWS {
		t.Error("Expected to find AWS Access Key")
	}
}

func TestScanner_Scan_FindsJWT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulated JWT exposure
		w.Write([]byte(`{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundJWT := false
	for _, r := range results {
		if r.DataType == "JWT" {
			foundJWT = true
		}
	}

	if !foundJWT {
		t.Error("Expected to find JWT")
	}
}

func TestScanner_Scan_NoSensitiveData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"message": "Hello World"}`))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, r := range results {
		if r.Vulnerable && r.Severity == "CRITICAL" {
			t.Errorf("Found unexpected sensitive data: %s", r.DataType)
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

func TestSensitivePatterns(t *testing.T) {
	patterns := SensitivePatterns()
	if len(patterns) < 10 {
		t.Errorf("SensitivePatterns count = %d, want at least 10", len(patterns))
	}

	found := map[string]bool{
		"AWS Access Key": false,
		"Credit Card":    false,
		"Private Key":    false,
	}

	for _, p := range patterns {
		if _, ok := found[p]; ok {
			found[p] = true
		}
	}

	for name, ok := range found {
		if !ok {
			t.Errorf("Expected pattern: %s", name)
		}
	}
}

func TestSensitiveEndpoints(t *testing.T) {
	endpoints := SensitiveEndpoints()
	if len(endpoints) < 5 {
		t.Errorf("SensitiveEndpoints count = %d, want at least 5", len(endpoints))
	}
}

func TestInsecureTransmissionPatterns(t *testing.T) {
	patterns := InsecureTransmissionPatterns()
	if len(patterns) < 5 {
		t.Errorf("InsecureTransmissionPatterns count = %d, want at least 5", len(patterns))
	}
}

func TestCheckHTTPS(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com", true},
		{"HTTPS://example.com", true},
		{"http://example.com", false},
		{"HTTP://example.com", false},
		{"ftp://example.com", false},
	}

	for _, tt := range tests {
		result := CheckHTTPS(tt.url)
		if result != tt.expected {
			t.Errorf("CheckHTTPS(%q) = %v, want %v", tt.url, result, tt.expected)
		}
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:        "http://example.com",
		DataType:   "AWS Access Key",
		Location:   "body",
		Match:      "AKIAIOSFODNN7EXAMPLE",
		Vulnerable: true,
		Evidence:   "AWS Access Key found in body",
		Severity:   "CRITICAL",
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

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		n        int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a long string", 10, "this is a ..."},
		{"exact", 5, "exact"},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.n)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, result, tt.expected)
		}
	}
}
