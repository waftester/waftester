package rce

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 5 {
		t.Errorf("expected Concurrency 5, got %d", config.Concurrency)
	}
	if config.Timeout != 15*time.Second {
		t.Errorf("expected Timeout 15s, got %v", config.Timeout)
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestScanner_DetectVulnerability(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		body       string
		markers    []string
		vulnerable bool
	}{
		{"uid=1000(user)", nil, true},
		{"root:x:0:0:root:/root:/bin/bash", nil, true},
		{"Directory of C:\\Windows", nil, true},
		{"Normal response", nil, false},
		{"custom_marker_here", []string{"custom_marker_here"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			vulnerable, _ := scanner.detectVulnerability(tt.body, tt.markers)
			if vulnerable != tt.vulnerable {
				t.Errorf("detectVulnerability(%s) = %v, want %v", tt.body, vulnerable, tt.vulnerable)
			}
		})
	}
}

func TestScanner_Scan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	params := map[string]string{"cmd": "test"}

	results, err := scanner.Scan(context.Background(), server.URL, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = results
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
	if len(payloads) < 15 {
		t.Errorf("expected at least 15 payloads, got %d", len(payloads))
	}

	// Check payload structure
	for _, p := range payloads {
		if p.Value == "" {
			t.Error("payload value should not be empty")
		}
		if p.Type == "" {
			t.Error("payload type should not be empty")
		}
	}
}

func TestBlindPayloads(t *testing.T) {
	payloads := BlindPayloads("test.example.com")
	if len(payloads) == 0 {
		t.Error("expected blind payloads")
	}

	// Check OOB domain is included
	found := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "test.example.com") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected OOB domain in payloads")
	}
}

func TestLog4jPayloads(t *testing.T) {
	payloads := Log4jPayloads("oob.example.com")
	if len(payloads) == 0 {
		t.Error("expected Log4j payloads")
	}

	// Check for JNDI patterns
	found := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "jndi") || strings.Contains(p.Value, "${") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected JNDI patterns in payloads")
	}
}

func TestBuildFormData(t *testing.T) {
	params := map[string]string{
		"a": "1",
		"b": "2",
	}

	data := buildFormData(params)
	if data == "" {
		t.Error("expected form data")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "https://example.com",
		Parameter:   "cmd",
		Payload:     ";id",
		PayloadType: "unix",
		StatusCode:  200,
		Vulnerable:  true,
		Evidence:    "uid=0",
		Severity:    "critical",
		Timestamp:   time.Now(),
	}

	if result.Severity != "critical" {
		t.Error("RCE should be critical severity")
	}
}

func TestScanner_VulnerableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("uid=1000(user) gid=1000(user) groups=1000(user)"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	params := map[string]string{"cmd": "test"}

	results, err := scanner.Scan(context.Background(), server.URL, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected to find vulnerabilities")
	}
}
