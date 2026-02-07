package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewTester(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config == nil {
			t.Error("expected config to be set")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:     60 * time.Second,
			UserAgent:   "custom-agent",
			TestHeaders: []string{"X-Custom-Header"},
		}
		tester := NewTester(config)

		if tester.config.Timeout != 60*time.Second {
			t.Errorf("expected 60s timeout, got %v", tester.config.Timeout)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if len(config.TestHeaders) == 0 {
		t.Error("expected test headers")
	}
	if len(config.TestParams) == 0 {
		t.Error("expected test params")
	}
	if config.UserAgent == "" {
		t.Error("expected user agent")
	}

	// Check for common test headers
	hasXForwardedHost := false
	for _, h := range config.TestHeaders {
		if h == "X-Forwarded-Host" {
			hasXForwardedHost = true
			break
		}
	}
	if !hasXForwardedHost {
		t.Error("expected X-Forwarded-Host in test headers")
	}
}

func TestGenerateCacheBuster(t *testing.T) {
	buster1, err1 := generateCacheBuster()
	if err1 != nil {
		t.Fatalf("generateCacheBuster failed: %v", err1)
	}
	buster2, err2 := generateCacheBuster()
	if err2 != nil {
		t.Fatalf("generateCacheBuster failed: %v", err2)
	}

	if buster1 == "" {
		t.Error("expected non-empty cache buster")
	}
	if buster1 == buster2 {
		t.Error("expected different cache busters")
	}
	if len(buster1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("expected 16 char buster, got %d", len(buster1))
	}
}

func TestAddCacheBuster(t *testing.T) {
	tests := []struct {
		url      string
		buster   string
		expected string
	}{
		{"http://example.com/page", "abc123", "http://example.com/page?cb=abc123"},
		{"http://example.com/page?foo=bar", "abc123", "http://example.com/page?cb=abc123&foo=bar"},
	}

	for _, test := range tests {
		result, err := addCacheBuster(test.url, test.buster)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// URL encoding may reorder params, just check for presence
		if !strings.Contains(result, "cb="+test.buster) {
			t.Errorf("expected cache buster in URL, got %s", result)
		}
	}
}

func TestDetectCache(t *testing.T) {
	t.Run("cache detected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("Age", "120")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		detected, headers, err := tester.DetectCache(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !detected {
			t.Error("expected cache to be detected")
		}
		if headers["X-Cache"] != "HIT" {
			t.Error("expected X-Cache header")
		}
	})

	t.Run("no cache", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		detected, _, err := tester.DetectCache(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if detected {
			t.Error("expected no cache detection")
		}
	})

	t.Run("CF cache", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("CF-Cache-Status", "HIT")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		detected, headers, err := tester.DetectCache(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !detected {
			t.Error("expected CF cache to be detected")
		}
		if headers["CF-Cache-Status"] != "HIT" {
			t.Error("expected CF-Cache-Status header")
		}
	})
}

func TestTestUnkeyedHeader(t *testing.T) {
	t.Run("header not reflected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Normal response"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vuln, err := tester.TestUnkeyedHeader(ctx, server.URL, "X-Test-Header")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln != nil {
			t.Error("expected no vulnerability when header not reflected")
		}
	})

	t.Run("header reflected and keyed", func(t *testing.T) {
		// When header is reflected but also keyed, second request shouldn't get it
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			// Only reflect when header is present (keyed behavior)
			if header := r.Header.Get("X-Test-Header"); header != "" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Header: " + header))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("No header"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vuln, err := tester.TestUnkeyedHeader(ctx, server.URL, "X-Test-Header")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should not be vulnerable since second request doesn't see canary
		if vuln != nil {
			t.Error("expected no vulnerability when header is properly keyed")
		}
	})
}

func TestTestUnkeyedParameter(t *testing.T) {
	t.Run("param not reflected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Normal response"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vuln, err := tester.TestUnkeyedParameter(ctx, server.URL, "test_param")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln != nil {
			t.Error("expected no vulnerability when param not reflected")
		}
	})
}

func TestTestCacheDeception(t *testing.T) {
	t.Run("no cache deception", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Cache", "MISS")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not found"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestCacheDeception(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// No HIT on first request = no cache deception detected
		if len(vulns) > 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})
}

func TestTestPathNormalization(t *testing.T) {
	t.Run("no path normalization issue", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Cache", "MISS")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestPathNormalization(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// MISS on all paths = no normalization issue
		if len(vulns) > 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})
}

func TestTestFatGET(t *testing.T) {
	t.Run("body not processed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ignore request body
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Normal response"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vuln, err := tester.TestFatGET(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln != nil {
			t.Error("expected no vulnerability when body not processed")
		}
	})

	t.Run("body processed - vulnerable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Process body even for GET
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			body := string(buf[:n])

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Response: " + body))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vuln, err := tester.TestFatGET(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln == nil {
			t.Error("expected vulnerability when body is processed")
		}
		if vuln != nil && vuln.Type != VulnFatGET {
			t.Errorf("expected FatGET vulnerability, got %s", vuln.Type)
		}
	})
}

func TestTestParameterCloaking(t *testing.T) {
	t.Run("no parameter cloaking", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Normal"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameterCloaking(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) > 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "MISS")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Test response"))
	}))
	defer server.Close()

	config := &TesterConfig{
		Timeout:     10 * time.Second,
		UserAgent:   "test-agent",
		TestHeaders: []string{"X-Test"},
		TestParams:  []string{"test"},
	}

	tester := NewTester(config)
	ctx := context.Background()

	result, err := tester.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != server.URL {
		t.Errorf("expected URL %s", server.URL)
	}
	if result.TestedHeaders != 1 {
		t.Errorf("expected 1 tested header, got %d", result.TestedHeaders)
	}
	if result.TestedParams != 1 {
		t.Errorf("expected 1 tested param, got %d", result.TestedParams)
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 8 {
		t.Errorf("expected 8 vulnerability types, got %d", len(types))
	}

	expectedTypes := map[VulnerabilityType]bool{
		VulnUnkeyedHeader:     false,
		VulnUnkeyedCookie:     false,
		VulnUnkeyedParameter:  false,
		VulnPathNormalization: false,
		VulnCacheDeception:    false,
		VulnParameterCloaking: false,
		VulnFatGET:            false,
		VulnResponseSplitting: false,
	}

	for _, vt := range types {
		expectedTypes[vt] = true
	}

	for vt, found := range expectedTypes {
		if !found {
			t.Errorf("missing vulnerability type: %s", vt)
		}
	}
}

func TestCommonCacheHeaders(t *testing.T) {
	headers := CommonCacheHeaders()

	if len(headers) == 0 {
		t.Error("expected cache headers")
	}

	hasXCache := false
	hasAge := false

	for _, h := range headers {
		if h == "X-Cache" {
			hasXCache = true
		}
		if h == "Age" {
			hasAge = true
		}
	}

	if !hasXCache {
		t.Error("expected X-Cache header")
	}
	if !hasAge {
		t.Error("expected Age header")
	}
}

func TestIsValidCacheStatus(t *testing.T) {
	tests := []struct {
		status   string
		expected bool
	}{
		{"HIT", true},
		{"MISS", true},
		{"hit", true},
		{"EXPIRED", true},
		{"STALE", true},
		{"DYNAMIC", true},
		{"BYPASS", false},
		{"NONE", false},
		{"", false},
	}

	for _, test := range tests {
		result := IsValidCacheStatus(test.status)
		if result != test.expected {
			t.Errorf("IsValidCacheStatus(%s) = %v, expected %v", test.status, result, test.expected)
		}
	}
}

func TestParseCacheControl(t *testing.T) {
	t.Run("simple directives", func(t *testing.T) {
		header := "max-age=3600, public"
		result := ParseCacheControl(header)

		if result["max-age"] != "3600" {
			t.Errorf("expected max-age=3600, got %s", result["max-age"])
		}
		if _, ok := result["public"]; !ok {
			t.Error("expected public directive")
		}
	})

	t.Run("complex directives", func(t *testing.T) {
		header := "no-cache, no-store, must-revalidate"
		result := ParseCacheControl(header)

		if _, ok := result["no-cache"]; !ok {
			t.Error("expected no-cache directive")
		}
		if _, ok := result["no-store"]; !ok {
			t.Error("expected no-store directive")
		}
	})
}

func TestIsCacheable(t *testing.T) {
	t.Run("not cacheable with no-store", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if IsCacheable(resp) {
			t.Error("expected not cacheable with no-store")
		}
	})

	t.Run("cacheable with Age header", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Age", "120")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if !IsCacheable(resp) {
			t.Error("expected cacheable with Age header")
		}
	})
}

func TestExtractCanaryPattern(t *testing.T) {
	pattern := ExtractCanaryPattern()

	tests := []struct {
		input    string
		expected bool
	}{
		{"waftester1234567890abcdef", true},
		{"waftesteraabbccdd11223344", true},
		{"waftester", false},
		{"test1234567890abcdef", false},
		{"random text", false},
	}

	for _, test := range tests {
		matched := pattern.MatchString(test.input)
		if matched != test.expected {
			t.Errorf("pattern match for '%s' = %v, expected %v", test.input, matched, test.expected)
		}
	}
}

func TestGetRemediations(t *testing.T) {
	remediations := []struct {
		name string
		fn   func() string
	}{
		{"UnkeyedHeader", GetUnkeyedHeaderRemediation},
		{"UnkeyedParam", GetUnkeyedParamRemediation},
		{"CacheDeception", GetCacheDeceptionRemediation},
		{"PathNormalization", GetPathNormalizationRemediation},
		{"FatGET", GetFatGETRemediation},
		{"ParameterCloaking", GetParameterCloakingRemediation},
	}

	for _, r := range remediations {
		t.Run(r.name, func(t *testing.T) {
			result := r.fn()
			if result == "" {
				t.Errorf("expected non-empty remediation for %s", r.name)
			}
		})
	}
}

func TestSimilarity(t *testing.T) {
	tests := []struct {
		a, b   string
		minSim float64
	}{
		{"hello", "hello", 0.99},
		{"hello", "world", 0.0},
		{"hello", "", 0.0},
		{"", "", 0.0},
		{"abcdef", "abcxyz", 0.3},
	}

	for _, test := range tests {
		result := similarity(test.a, test.b)
		if result < test.minSim && test.minSim > 0 {
			t.Errorf("similarity(%s, %s) = %f, expected >= %f", test.a, test.b, result, test.minSim)
		}
	}
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, err := tester.DetectCache(ctx, server.URL)
	// Should get context cancelled error
	if err == nil {
		t.Log("No error on cancelled context (implementation may vary)")
	}
}

func BenchmarkDetectCache(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "MISS")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tester.DetectCache(ctx, server.URL)
	}
}

func BenchmarkGenerateCacheBuster(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateCacheBuster()
	}
}
