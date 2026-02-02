package ldap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 10 {
		t.Errorf("expected Concurrency 10, got %d", config.Concurrency)
	}
	if config.Timeout != httpclient.TimeoutProbing {
		t.Errorf("expected Timeout %v, got %v", httpclient.TimeoutProbing, config.Timeout)
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestNewScanner_Defaults(t *testing.T) {
	scanner := NewScanner(Config{})
	if scanner.config.Concurrency != 10 {
		t.Error("default concurrency not set")
	}
}

func TestScanner_Scan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	params := map[string]string{"user": "admin"}

	results, err := scanner.Scan(context.Background(), server.URL, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = results // Results depend on vulnerability detection
}

func TestScanner_DetectVulnerability(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		body       string
		vulnerable bool
	}{
		{"ldap_search failed", true},
		{"LDAP Error: invalid DN syntax", true},
		{"cn=admin,dc=example,dc=com", true},
		{"Normal response", false},
		{"objectClass violation", true},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			vulnerable, _ := scanner.detectVulnerability(tt.body)
			if vulnerable != tt.vulnerable {
				t.Errorf("detectVulnerability(%s) = %v, want %v", tt.body, vulnerable, tt.vulnerable)
			}
		})
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("expected non-nil results")
	}
}

func TestPayloads(t *testing.T) {
	payloads := Payloads()
	if len(payloads) == 0 {
		t.Error("expected payloads")
	}
	if len(payloads) < 20 {
		t.Errorf("expected at least 20 payloads, got %d", len(payloads))
	}
}

func TestBlindPayloads(t *testing.T) {
	payloads := BlindPayloads()
	if len(payloads) == 0 {
		t.Error("expected blind payloads")
	}
}

func TestAuthBypassPayloads(t *testing.T) {
	payloads := AuthBypassPayloads()
	if len(payloads) == 0 {
		t.Error("expected auth bypass payloads")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:        "https://example.com",
		Parameter:  "user",
		Payload:    "*",
		StatusCode: 200,
		Vulnerable: true,
		Evidence:   "LDAP error",
		Severity:   "HIGH",
		Timestamp:  time.Now(),
	}

	if result.URL != "https://example.com" {
		t.Error("URL field incorrect")
	}
	if !result.Vulnerable {
		t.Error("Vulnerable field incorrect")
	}
}

func TestScanner_VulnerableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("LDAP Error: invalid DN syntax in query"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	params := map[string]string{"user": "test"}

	results, err := scanner.Scan(context.Background(), server.URL, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find vulnerabilities
	if len(results) == 0 {
		t.Error("expected to find vulnerabilities")
	}
}
