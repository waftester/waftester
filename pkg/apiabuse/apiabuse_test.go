package apiabuse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 5 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 5", config.Concurrency)
	}
	if config.Timeout != 10*1e9 {
		t.Errorf("DefaultConfig().Timeout = %v, want 10s", config.Timeout)
	}
	if config.RateLimit != 100 {
		t.Errorf("DefaultConfig().RateLimit = %d, want 100", config.RateLimit)
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

func TestScanner_TestRateLimiting_Vulnerable(t *testing.T) {
	// Server without rate limiting
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.TestRateLimiting(context.Background(), server.URL, 10)

	if err != nil {
		t.Fatalf("TestRateLimiting error: %v", err)
	}

	if result.RateLimited {
		t.Error("Expected no rate limiting")
	}
}

func TestScanner_TestRateLimiting_Safe(t *testing.T) {
	var requestCount int32

	// Server with rate limiting (429 after 5 requests)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count > 5 {
			w.WriteHeader(429)
			w.Write([]byte("Too Many Requests"))
			return
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.TestRateLimiting(context.Background(), server.URL, 10)

	if err != nil {
		t.Fatalf("TestRateLimiting error: %v", err)
	}

	if !result.RateLimited {
		t.Error("Expected rate limiting to be detected")
	}
}

func TestScanner_TestResourceExhaustion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.TestResourceExhaustion(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("TestResourceExhaustion error: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected at least one result")
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("GetResults returned nil")
	}
}

func TestResourceExhaustionPayloads(t *testing.T) {
	payloads := ResourceExhaustionPayloads()
	if len(payloads) < 3 {
		t.Errorf("ResourceExhaustionPayloads count = %d, want at least 3", len(payloads))
	}

	// Check for specific payload types
	found := map[string]bool{}
	for _, p := range payloads {
		found[p.Name] = true
	}

	if !found["deep_nesting"] {
		t.Error("Expected deep_nesting payload")
	}
	if !found["large_array"] {
		t.Error("Expected large_array payload")
	}
}

func TestBruteForcePayloads(t *testing.T) {
	payloads := BruteForcePayloads()

	if len(payloads["username"]) < 5 {
		t.Error("Expected at least 5 username payloads")
	}
	if len(payloads["password"]) < 5 {
		t.Error("Expected at least 5 password payloads")
	}
}

func TestCommonAPIEndpoints(t *testing.T) {
	endpoints := CommonAPIEndpoints()
	if len(endpoints) < 5 {
		t.Errorf("CommonAPIEndpoints count = %d, want at least 5", len(endpoints))
	}

	// Check for critical endpoints
	foundAdmin := false
	foundLogin := false
	for _, ep := range endpoints {
		if ep == "/api/v1/admin" {
			foundAdmin = true
		}
		if ep == "/api/login" {
			foundLogin = true
		}
	}

	if !foundAdmin {
		t.Error("Expected /api/v1/admin endpoint")
	}
	if !foundLogin {
		t.Error("Expected /api/login endpoint")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "http://example.com/api",
		TestType:    "rate_limiting",
		Method:      "GET",
		StatusCode:  200,
		RateLimited: false,
		Vulnerable:  true,
		Evidence:    "No rate limiting",
		Severity:    "MEDIUM",
	}

	if result.URL != "http://example.com/api" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
}

func TestGenerateDeepJSON(t *testing.T) {
	result := generateDeepJSON(3)

	// Should be nested maps
	if m, ok := result.(map[string]interface{}); ok {
		if _, ok := m["nested"]; !ok {
			t.Error("Expected nested key")
		}
	} else {
		t.Error("Expected map result")
	}
}

func TestGenerateLargeArray(t *testing.T) {
	result := generateLargeArray(100)
	if len(result) != 100 {
		t.Errorf("Array length = %d, want 100", len(result))
	}
}
