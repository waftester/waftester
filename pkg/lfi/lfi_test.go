package lfi

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
	if config.OS != "both" {
		t.Error("expected OS both")
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
		{"root:x:0:0:root:/root:/bin/bash", nil, true},
		{"[fonts]", nil, true},
		{"<?php echo 'test'; ?>", nil, true},
		{"Normal response", nil, false},
		{"custom_marker", []string{"custom_marker"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			vulnerable, _ := scanner.detectVulnerability(tt.body, tt.markers)
			if vulnerable != tt.vulnerable {
				t.Errorf("detectVulnerability = %v, want %v", vulnerable, tt.vulnerable)
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
	params := map[string]string{"file": "test.txt"}

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

func TestPayloads_Linux(t *testing.T) {
	payloads := Payloads("linux")
	if len(payloads) == 0 {
		t.Error("expected Linux payloads")
	}
}

func TestPayloads_Windows(t *testing.T) {
	payloads := Payloads("windows")
	if len(payloads) == 0 {
		t.Error("expected Windows payloads")
	}
}

func TestPayloads_Both(t *testing.T) {
	payloads := Payloads("both")
	linux := Payloads("linux")
	windows := Payloads("windows")

	if len(payloads) != len(linux)+len(windows) {
		t.Error("both should include linux and windows payloads")
	}
}

func TestNullBytePayloads(t *testing.T) {
	payloads := NullBytePayloads()
	if len(payloads) == 0 {
		t.Error("expected null byte payloads")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "https://example.com",
		Parameter:   "file",
		Payload:     "../etc/passwd",
		StatusCode:  200,
		Vulnerable:  true,
		FileContent: "root:x:0:0",
		Severity:    "HIGH",
		Timestamp:   time.Now(),
	}

	if result.FileContent == "" {
		t.Error("FileContent should be set")
	}
}

func TestScanner_VulnerableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	params := map[string]string{"file": "test"}

	results, err := scanner.Scan(context.Background(), server.URL, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected to find vulnerabilities")
	}
}
