package rfi

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

func TestScanner_DetectVulnerability(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		body       string
		markers    []string
		vulnerable bool
	}{
		{"<?php echo 'test'; ?>", nil, true},
		{"#!/bin/bash", nil, true},
		{"<script>alert(1)</script>", nil, true},
		{"Normal response", nil, false},
		{"RFI_TEST_MARKER", nil, true},
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
	params := map[string]string{"page": "home"}

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
	payloads := Payloads("")
	if len(payloads) == 0 {
		t.Error("expected payloads")
	}
	if len(payloads) < 10 {
		t.Errorf("expected at least 10 payloads, got %d", len(payloads))
	}
}

func TestPayloads_WithCallback(t *testing.T) {
	payloads := Payloads("http://test.example.com/shell.txt")
	found := false
	for _, p := range payloads {
		if p.Value == "http://test.example.com/shell.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected callback URL in payloads")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:        "https://example.com",
		Parameter:  "page",
		Payload:    "http://evil.com/shell.txt",
		StatusCode: 200,
		Vulnerable: true,
		Severity:   "CRITICAL",
		Timestamp:  time.Now(),
	}

	if result.Severity != "CRITICAL" {
		t.Error("RFI should be CRITICAL severity")
	}
}

func TestScanner_VulnerableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<?php echo 'included'; ?>"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	params := map[string]string{"page": "test"}

	results, err := scanner.Scan(context.Background(), server.URL, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected to find vulnerabilities")
	}
}
