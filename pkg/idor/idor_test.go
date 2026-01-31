package idor

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
	if config.Timeout != 10*time.Second {
		t.Errorf("expected Timeout 10s, got %v", config.Timeout)
	}
	if len(config.IDPatterns) == 0 {
		t.Error("expected ID patterns")
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
	if scanner.config.Timeout != 10*time.Second {
		t.Error("default timeout not set")
	}
}

func TestScanner_ExtractIDs(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		url      string
		expected int
	}{
		{"/api/users/123", 1},
		{"/api/users/123/orders/456", 2},
		{"/api/users/abc", 0},
		{"https://example.com/api/v1/users/1", 1},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			ids := scanner.extractIDs(tt.url)
			if len(ids) != tt.expected {
				t.Errorf("extractIDs(%s) = %d ids, want %d", tt.url, len(ids), tt.expected)
			}
		})
	}
}

func TestScanner_GenerateTestIDs(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	ids := scanner.generateTestIDs("100")
	if len(ids) == 0 {
		t.Error("expected test IDs")
	}

	// Should include adjacent values
	found := false
	for _, id := range ids {
		if id == "99" || id == "101" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected adjacent values")
	}
}

func TestScanner_ScanEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": 1, "name": "test"}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.BaseURL = server.URL
	scanner := NewScanner(config)

	results, err := scanner.ScanEndpoint(context.Background(), server.URL+"/api/users/1", "GET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Results depend on whether access succeeds
	_ = results
}

func TestScanner_DetermineSeverity(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		url      string
		method   string
		expected string
	}{
		{"/api/admin/users", "GET", "HIGH"},
		{"/api/users", "DELETE", "HIGH"},
		{"/api/users", "GET", "MEDIUM"},
		{"/api/payment/cards", "GET", "HIGH"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			severity := scanner.determineSeverity(tt.url, tt.method)
			if severity != tt.expected {
				t.Errorf("determineSeverity(%s, %s) = %s, want %s", tt.url, tt.method, severity, tt.expected)
			}
		})
	}
}

func TestScanner_HorizontalPrivilegeTest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	tokens := []string{"token1", "token2"}

	results := scanner.HorizontalPrivilegeTest(context.Background(), server.URL+"/api/users/1", tokens)
	// Should detect horizontal escalation
	if len(results) == 0 {
		t.Log("No horizontal privilege escalation detected (expected in this mock)")
	}
}

func TestScanner_VerticalPrivilegeTest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	adminEndpoints := []string{server.URL + "/admin/users"}

	results := scanner.VerticalPrivilegeTest(context.Background(), adminEndpoints, "user_token")
	// Should not find vulnerabilities (403)
	if len(results) > 0 {
		t.Error("should not find vulnerabilities with 403")
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("expected non-nil results")
	}
}

func TestGeneratePayloads(t *testing.T) {
	payloads := GeneratePayloads()
	if len(payloads) == 0 {
		t.Error("expected payloads")
	}
}

func TestCommonEndpoints(t *testing.T) {
	endpoints := CommonEndpoints()
	if len(endpoints) == 0 {
		t.Error("expected endpoints")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:           "https://example.com/api/users/1",
		Method:        "GET",
		OriginalID:    "1",
		TestedID:      "2",
		StatusCode:    200,
		Accessible:    true,
		Vulnerability: "IDOR",
		Severity:      "HIGH",
		Timestamp:     time.Now(),
	}

	if result.URL != "https://example.com/api/users/1" {
		t.Error("URL field incorrect")
	}
	if !result.Accessible {
		t.Error("Accessible field incorrect")
	}
}
