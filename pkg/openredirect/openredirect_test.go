package openredirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 10 {
		t.Errorf("expected Concurrency 10, got %d", config.Concurrency)
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestScanner_Scan_Vulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("url")
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	params := map[string]string{"url": ""}

	results, err := scanner.Scan(context.Background(), server.URL, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vulnerable := false
	for _, r := range results {
		if r.Vulnerable {
			vulnerable = true
			break
		}
	}
	if !vulnerable {
		t.Error("expected to find vulnerable redirect")
	}
}

func TestScanner_Scan_Safe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	params := map[string]string{"url": ""}

	results, err := scanner.Scan(context.Background(), server.URL, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, r := range results {
		if r.Vulnerable {
			t.Error("should not find vulnerabilities on safe server")
		}
	}
}

func TestScanner_IsExternalRedirect(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		location string
		payload  string
		external bool
	}{
		{"https://evil.com/path", "https://evil.com", true},
		{"//attacker.com", "//attacker.com", true},
		{"/safe/path", "/safe/path", false},
		{"https://google.com", "https://google.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.location, func(t *testing.T) {
			result := scanner.isExternalRedirect(tt.location, tt.payload)
			if result != tt.external {
				t.Errorf("isExternalRedirect = %v, want %v", result, tt.external)
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
	if len(payloads) < 15 {
		t.Errorf("expected at least 15 payloads, got %d", len(payloads))
	}
}

func TestCommonParameters(t *testing.T) {
	params := CommonParameters()
	if len(params) == 0 {
		t.Error("expected common parameters")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "https://example.com",
		Parameter:   "url",
		Payload:     "//evil.com",
		RedirectURL: "//evil.com",
		StatusCode:  302,
		Vulnerable:  true,
		Severity:    "MEDIUM",
		Timestamp:   time.Now(),
	}

	if result.RedirectURL != "//evil.com" {
		t.Error("RedirectURL field incorrect")
	}
}
