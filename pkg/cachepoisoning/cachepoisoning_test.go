package cachepoisoning

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	// Server that simulates cache poisoning - always returns same poisoned content
	// regardless of whether header is present (simulating cached poisoned response)
	var cachedContent string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Age", "100")
		w.Header().Set("X-Cache", "HIT")

		// First request with header sets the cache, subsequent requests return cached
		if host := r.Header.Get("X-Forwarded-Host"); host != "" && cachedContent == "" {
			cachedContent = "<a href='http://" + host + "/'>Link</a>"
		}

		if cachedContent != "" {
			w.Write([]byte(cachedContent))
		} else {
			w.Write([]byte("<a href='http://example.com/'>Link</a>"))
		}
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
			if r.Severity != "HIGH" {
				t.Errorf("Vulnerable result severity = %s, want HIGH", r.Severity)
			}
		}
	}

	if !foundVuln {
		t.Error("Expected to find cache poisoning vulnerability")
	}
}

func TestScanner_Scan_Safe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Does not reflect headers
		w.Write([]byte("Static response"))
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

func TestUnkeyedHeaders(t *testing.T) {
	headers := UnkeyedHeaders()
	if len(headers) < 10 {
		t.Errorf("UnkeyedHeaders count = %d, want at least 10", len(headers))
	}

	// Check for common unkeyed headers
	found := map[string]bool{
		"X-Forwarded-Host":  false,
		"X-Forwarded-Proto": false,
		"X-Original-URL":    false,
	}

	for _, h := range headers {
		if _, ok := found[h]; ok {
			found[h] = true
		}
	}

	for h, f := range found {
		if !f {
			t.Errorf("Expected unkeyed header: %s", h)
		}
	}
}

func TestFatGetPayloads(t *testing.T) {
	payloads := FatGetPayloads()
	if len(payloads) < 1 {
		t.Errorf("FatGetPayloads count = %d, want at least 1", len(payloads))
	}

	// Should have callback parameter
	if _, ok := payloads["callback"]; !ok {
		t.Error("Expected callback parameter in FatGetPayloads")
	}
}

func TestParameterClobberingPayloads(t *testing.T) {
	payloads := ParameterClobberingPayloads()
	if len(payloads) < 1 {
		t.Errorf("ParameterClobberingPayloads count = %d, want at least 1", len(payloads))
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:        "http://example.com",
		Technique:  "Unkeyed Header",
		Header:     "X-Forwarded-Host",
		Payload:    "evil.com",
		IsCached:   true,
		Vulnerable: true,
		Evidence:   "Header reflected in cached response",
		Severity:   "HIGH",
	}

	if result.URL != "http://example.com" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
	if result.IsCached != true {
		t.Error("IsCached not set correctly")
	}
}

func TestExtractCacheHeaders(t *testing.T) {
	header := http.Header{}
	header.Set("Cache-Control", "max-age=3600")
	header.Set("Age", "100")
	header.Set("X-Cache", "HIT")

	cacheHeaders := extractCacheHeaders(header)

	if cacheHeaders["Cache-Control"] != "max-age=3600" {
		t.Error("Cache-Control not extracted")
	}
	if cacheHeaders["Age"] != "100" {
		t.Error("Age not extracted")
	}
	if cacheHeaders["X-Cache"] != "HIT" {
		t.Error("X-Cache not extracted")
	}
}

func TestIsCacheableResponse(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected bool
	}{
		{
			name: "X-Cache HIT",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("X-Cache", "HIT")
				return h
			}(),
			expected: true,
		},
		{
			name: "CF-Cache-Status HIT",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("CF-Cache-Status", "HIT")
				return h
			}(),
			expected: true,
		},
		{
			name: "Age header present",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Age", "100")
				return h
			}(),
			expected: true,
		},
		{
			name:     "No cache indicators",
			headers:  http.Header{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCacheableResponse(tt.headers)
			if result != tt.expected {
				t.Errorf("isCacheableResponse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGenerateCacheBuster(t *testing.T) {
	cb1 := generateCacheBuster()
	cb2 := generateCacheBuster()

	if cb1 == cb2 {
		t.Error("Cache busters should be unique")
	}

	if len(cb1) < 8 {
		t.Error("Cache buster too short")
	}
}
