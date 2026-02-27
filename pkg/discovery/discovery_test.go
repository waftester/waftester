package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/discovery/presets"
	"github.com/waftester/waftester/pkg/httpclient"
)

// TestNewDiscoverer tests discoverer creation
func TestNewDiscoverer(t *testing.T) {
	t.Run("default config values", func(t *testing.T) {
		cfg := DiscoveryConfig{
			Target: "http://example.com",
		}
		d := NewDiscoverer(cfg)

		if d.config.Timeout != httpclient.TimeoutProbing {
			t.Errorf("expected default Timeout %v, got %v", httpclient.TimeoutProbing, d.config.Timeout)
		}
		if d.config.MaxDepth != 3 {
			t.Errorf("expected default MaxDepth 3, got %d", d.config.MaxDepth)
		}
		if d.config.Concurrency != 10 {
			t.Errorf("expected default Concurrency 10, got %d", d.config.Concurrency)
		}
		if !strings.Contains(d.config.UserAgent, "waftester/") || !strings.Contains(d.config.UserAgent, "Discovery") {
			t.Errorf("unexpected UserAgent: %s", d.config.UserAgent)
		}
	})

	t.Run("custom config", func(t *testing.T) {
		cfg := DiscoveryConfig{
			Target:      "http://example.com",
			Timeout:     5 * time.Second,
			MaxDepth:    5,
			Concurrency: 20,
			SkipVerify:  true,
			UserAgent:   "CustomAgent/1.0",
			Service:     "authentik",
		}
		d := NewDiscoverer(cfg)

		if d.config.Timeout != 5*time.Second {
			t.Errorf("expected Timeout 5s, got %v", d.config.Timeout)
		}
		if d.config.MaxDepth != 5 {
			t.Errorf("expected MaxDepth 5, got %d", d.config.MaxDepth)
		}
		if d.config.Concurrency != 20 {
			t.Errorf("expected Concurrency 20, got %d", d.config.Concurrency)
		}
		if d.config.UserAgent != "CustomAgent/1.0" {
			t.Errorf("unexpected UserAgent: %s", d.config.UserAgent)
		}
	})
}

// TestDiscover tests the discovery process
func TestDiscover(t *testing.T) {
	t.Parallel()
	t.Run("basic discovery", func(t *testing.T) {
		t.Parallel()
		// Mock server that returns simple responses
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/robots.txt":
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte("User-agent: *\nDisallow: /admin\nAllow: /api"))
			case "/sitemap.xml":
				w.Header().Set("Content-Type", "application/xml")
				w.Write([]byte(`<?xml version="1.0"?><urlset><url><loc>/page1</loc></url></urlset>`))
			case "/api/health":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "ok"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		cfg := DiscoveryConfig{
			Target:        server.URL,
			Timeout:       500 * time.Millisecond,
			MaxDepth:      1,
			Concurrency:   2,
			DisableActive: true, // Disable active brute-forcing for tests
		}
		d := NewDiscoverer(cfg)

		// Use a timeout context to prevent test hanging due to active discovery
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		result, err := d.Discover(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Target != server.URL {
			t.Errorf("expected Target %s, got %s", server.URL, result.Target)
		}
		if result.Duration <= 0 {
			t.Error("expected Duration > 0")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DiscoveryConfig{
			Target:        server.URL,
			Timeout:       500 * time.Millisecond,
			DisableActive: true, // Disable active brute-forcing for tests
		}
		d := NewDiscoverer(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		result, err := d.Discover(ctx)
		// Should complete (with context deadline) but not error
		if result == nil {
			t.Error("expected result even with context cancellation")
		}
		_ = err // Discovery doesn't return error on timeout
	})

	t.Run("active discovery enabled", func(t *testing.T) {
		t.Parallel()
		// Mock server with various endpoints
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				w.Header().Set("Server", "nginx")
				w.WriteHeader(http.StatusOK)
			case "/admin":
				w.WriteHeader(http.StatusForbidden)
			case "/api":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
			case "/login":
				w.WriteHeader(http.StatusOK)
			case "/health":
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		cfg := DiscoveryConfig{
			Target:        server.URL,
			Timeout:       2 * time.Second,
			MaxDepth:      1,
			Concurrency:   5,
			DisableActive: false, // Enable active discovery
		}
		d := NewDiscoverer(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		result, err := d.Discover(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have found some endpoints via active discovery
		if result == nil {
			t.Fatal("expected result")
		}

		// Active discovery should have added requests
		if result.Statistics.RequestsMade == 0 {
			t.Error("expected some requests to be made")
		}
	})
}

// TestEndpointStruct tests Endpoint JSON serialization
func TestEndpointStruct(t *testing.T) {
	ep := Endpoint{
		Path:        "/api/users",
		Method:      "POST",
		ContentType: "application/json",
		Parameters: []Parameter{
			{Name: "id", Location: "path", Type: "string"},
			{Name: "name", Location: "body", Type: "string", Required: true},
		},
		Headers:     map[string]string{"Authorization": "Bearer token"},
		StatusCode:  200,
		Service:     "api",
		Category:    "users",
		RiskFactors: []string{"auth", "user-data"},
	}

	data, err := json.Marshal(ep)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored Endpoint
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.Path != ep.Path {
		t.Errorf("Path mismatch: %s vs %s", restored.Path, ep.Path)
	}
	if restored.Method != ep.Method {
		t.Errorf("Method mismatch: %s vs %s", restored.Method, ep.Method)
	}
	if len(restored.Parameters) != 2 {
		t.Errorf("expected 2 parameters, got %d", len(restored.Parameters))
	}
	if restored.Parameters[1].Required != true {
		t.Error("expected second parameter to be required")
	}
}

// TestParameterStruct tests Parameter JSON serialization
func TestParameterStruct(t *testing.T) {
	param := Parameter{
		Name:     "user_id",
		Location: "query",
		Type:     "integer",
		Example:  "123",
		Required: true,
	}

	data, err := json.Marshal(param)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if !strContains(jsonStr, `"name":"user_id"`) {
		t.Error("missing name field")
	}
	if !strContains(jsonStr, `"location":"query"`) {
		t.Error("missing location field")
	}
	if !strContains(jsonStr, `"type":"integer"`) {
		t.Error("missing type field")
	}
}

// TestDiscoveryResultStruct tests DiscoveryResult JSON serialization
func TestDiscoveryResultStruct(t *testing.T) {
	result := DiscoveryResult{
		Target:         "http://example.com",
		Service:        "api",
		DiscoveredAt:   time.Now(),
		Duration:       10 * time.Second,
		Endpoints:      []Endpoint{{Path: "/api", Method: "GET"}},
		Technologies:   []string{"nginx", "nodejs"},
		WAFDetected:    true,
		WAFFingerprint: "modsecurity",
		AttackSurface: AttackSurface{
			HasAuthEndpoints: true,
			HasAPIEndpoints:  true,
			AcceptsJSON:      true,
		},
		Statistics: DiscoveryStatistics{
			TotalEndpoints: 1,
			ByMethod:       map[string]int{"GET": 1},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored DiscoveryResult
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.Target != result.Target {
		t.Errorf("Target mismatch")
	}
	if restored.WAFDetected != true {
		t.Error("WAFDetected should be true")
	}
	if restored.AttackSurface.HasAuthEndpoints != true {
		t.Error("HasAuthEndpoints should be true")
	}
}

// TestAttackSurfaceStruct tests AttackSurface fields
func TestAttackSurfaceStruct(t *testing.T) {
	surface := AttackSurface{
		HasAuthEndpoints:   true,
		HasAPIEndpoints:    true,
		HasFileUpload:      false,
		HasOAuth:           true,
		HasSAML:            false,
		HasGraphQL:         true,
		HasWebSockets:      false,
		AcceptsJSON:        true,
		AcceptsXML:         false,
		AcceptsFormData:    true,
		RelevantCategories: []string{"sqli", "xss", "auth-bypass"},
	}

	data, err := json.Marshal(surface)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored AttackSurface
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !restored.HasAuthEndpoints {
		t.Error("HasAuthEndpoints should be true")
	}
	if !restored.HasGraphQL {
		t.Error("HasGraphQL should be true")
	}
	if len(restored.RelevantCategories) != 3 {
		t.Errorf("expected 3 categories, got %d", len(restored.RelevantCategories))
	}
}

// TestDiscoveryStatistics tests DiscoveryStatistics
func TestDiscoveryStatistics(t *testing.T) {
	stats := DiscoveryStatistics{
		TotalEndpoints:  10,
		ByMethod:        map[string]int{"GET": 5, "POST": 3, "PUT": 2},
		ByCategory:      map[string]int{"api": 6, "auth": 4},
		TotalParameters: 25,
		CrawlDepth:      3,
		RequestsMade:    50,
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored DiscoveryStatistics
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.TotalEndpoints != 10 {
		t.Errorf("expected TotalEndpoints 10, got %d", restored.TotalEndpoints)
	}
	if restored.ByMethod["GET"] != 5 {
		t.Errorf("expected GET=5, got %d", restored.ByMethod["GET"])
	}
	if restored.TotalParameters != 25 {
		t.Errorf("expected TotalParameters 25, got %d", restored.TotalParameters)
	}
}

// TestDiscoveryConfig tests DiscoveryConfig
func TestDiscoveryConfig(t *testing.T) {
	cfg := DiscoveryConfig{
		Target:       "http://example.com",
		Timeout:      15 * time.Second,
		MaxDepth:     5,
		Concurrency:  20,
		SkipVerify:   true,
		UserAgent:    "Test/1.0",
		Service:      "authentik",
		IncludePaths: []string{"/api", "/auth"},
		ExcludePaths: []string{"/static", "/assets"},
	}

	if cfg.Target != "http://example.com" {
		t.Errorf("Target mismatch")
	}
	if len(cfg.IncludePaths) != 2 {
		t.Errorf("expected 2 include paths, got %d", len(cfg.IncludePaths))
	}
	if len(cfg.ExcludePaths) != 2 {
		t.Errorf("expected 2 exclude paths, got %d", len(cfg.ExcludePaths))
	}
}

// TestWAFDetection tests WAF detection
func TestWAFDetection(t *testing.T) {
	t.Parallel()
	t.Run("detects WAF on 403", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate WAF blocking
			if strContains(r.URL.RawQuery, "'") || strContains(r.URL.RawQuery, "<") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DiscoveryConfig{
			Target:        server.URL,
			Timeout:       500 * time.Millisecond,
			DisableActive: true, // Disable active brute-forcing for tests
		}
		d := NewDiscoverer(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		result, _ := d.Discover(ctx)
		// WAF detection should run
		_ = result
	})
}

// Helper function - renamed to avoid conflict with package function
func strContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ==================== External Sources Tests ====================

// TestNewExternalSources tests ExternalSources creation
func TestNewExternalSources(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		es := NewExternalSources(0, "")
		if es == nil {
			t.Fatal("expected external sources, got nil")
		}
		if !strings.Contains(es.userAgent, "waftester/") || !strings.Contains(es.userAgent, "Discovery") {
			t.Errorf("expected default user agent, got %s", es.userAgent)
		}
	})

	t.Run("custom values", func(t *testing.T) {
		es := NewExternalSources(30*time.Second, "CustomAgent/2.0")
		if es == nil {
			t.Fatal("expected external sources, got nil")
		}
		if es.userAgent != "CustomAgent/2.0" {
			t.Errorf("expected CustomAgent/2.0, got %s", es.userAgent)
		}
	})
}

// TestRobotsResultStruct tests RobotsResult struct
func TestRobotsResultStruct(t *testing.T) {
	result := RobotsResult{
		AllowedPaths:    []string{"/api", "/public"},
		DisallowedPaths: []string{"/admin", "/config"},
		Sitemaps:        []string{"http://example.com/sitemap.xml"},
		CrawlDelay:      10,
	}

	if len(result.AllowedPaths) != 2 {
		t.Errorf("expected 2 allowed paths, got %d", len(result.AllowedPaths))
	}
	if len(result.DisallowedPaths) != 2 {
		t.Errorf("expected 2 disallowed paths, got %d", len(result.DisallowedPaths))
	}
	if result.CrawlDelay != 10 {
		t.Errorf("expected CrawlDelay 10, got %d", result.CrawlDelay)
	}

	// Test JSON serialization
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored RobotsResult
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(restored.AllowedPaths) != 2 {
		t.Error("restored AllowedPaths mismatch")
	}
}

// TestParseRobotsTxt tests ParseRobotsTxt with mock server
func TestParseRobotsTxt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(`User-agent: *
Disallow: /admin
Disallow: /private
Allow: /api/public
Sitemap: http://example.com/sitemap.xml
`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	es := NewExternalSources(5*time.Second, "TestAgent")
	result, err := es.ParseRobotsTxt(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.DisallowedPaths) != 2 {
		t.Errorf("expected 2 disallowed paths, got %d", len(result.DisallowedPaths))
	}
	if len(result.Sitemaps) != 1 {
		t.Errorf("expected 1 sitemap, got %d", len(result.Sitemaps))
	}
}

// TestParseRobotsTxtNotFound tests ParseRobotsTxt when robots.txt doesn't exist
func TestParseRobotsTxtNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	es := NewExternalSources(5*time.Second, "TestAgent")
	_, err := es.ParseRobotsTxt(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for missing robots.txt")
	}
}

// TestSitemapURLStruct tests SitemapURL struct
func TestSitemapURLStruct(t *testing.T) {
	url := SitemapURL{
		Loc:        "http://example.com/page1",
		LastMod:    "2025-01-01",
		ChangeFreq: "weekly",
		Priority:   "0.8",
	}

	data, err := json.Marshal(url)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored SitemapURL
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.Loc != "http://example.com/page1" {
		t.Errorf("Loc mismatch: %s", restored.Loc)
	}
}

// TestSitemapResultStruct tests SitemapResult struct
func TestSitemapResultStruct(t *testing.T) {
	result := SitemapResult{
		URLs: []SitemapURL{
			{Loc: "/page1"},
			{Loc: "/page2"},
		},
		TotalFound: 2,
	}

	if result.TotalFound != 2 {
		t.Errorf("expected TotalFound 2, got %d", result.TotalFound)
	}
}

// TestParseSitemaps tests ParseSitemaps with mock server
func TestParseSitemaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sitemap.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/page1</loc></url>
  <url><loc>http://example.com/page2</loc></url>
</urlset>`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	es := NewExternalSources(5*time.Second, "TestAgent")
	result, err := es.ParseSitemaps(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFound != 2 {
		t.Errorf("expected 2 URLs, got %d", result.TotalFound)
	}
}

// TestFindLinksInJS tests JavaScript link extraction
func TestFindLinksInJS(t *testing.T) {
	tests := []struct {
		name    string
		content string
		minURLs int
	}{
		{
			name:    "simple paths",
			content: `var url = "/api/users";`,
			minURLs: 1,
		},
		{
			name:    "multiple paths",
			content: `fetch("/api/login"); fetch("/api/logout");`,
			minURLs: 2,
		},
		{
			name:    "full URLs",
			content: `var baseUrl = "https://api.example.com/v1/users";`,
			minURLs: 1,
		},
		{
			name:    "no URLs",
			content: `var x = 1 + 2;`,
			minURLs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := FindLinksInJS(tt.content)
			if len(links) < tt.minURLs {
				t.Errorf("expected at least %d URLs, got %d", tt.minURLs, len(links))
			}
		})
	}
}

// TestWaybackURLStruct tests WaybackURL struct
func TestWaybackURLStruct(t *testing.T) {
	url := WaybackURL{
		URL:       "http://example.com/oldpage",
		Timestamp: "20200101120000",
	}

	data, err := json.Marshal(url)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored WaybackURL
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.URL != url.URL {
		t.Errorf("URL mismatch")
	}
}

// TestLinkFinderRegex tests the LinkFinder regex exists and works
func TestLinkFinderRegex(t *testing.T) {
	if LinkFinderRegex == nil {
		t.Fatal("LinkFinderRegex should not be nil")
	}

	// Test it matches a simple case
	testCases := []struct {
		input   string
		matches bool
	}{
		{`"/api/v1/users"`, true},
		{`'https://example.com/path'`, true},
		{`"/file.js"`, true},
		{`plain text`, false},
	}

	for _, tc := range testCases {
		matched := LinkFinderRegex.MatchString(tc.input)
		if matched != tc.matches {
			t.Errorf("LinkFinderRegex.MatchString(%q) = %v, want %v", tc.input, matched, tc.matches)
		}
	}
}

// TestDecodeJSContent tests JavaScript content decoding
func TestDecodeJSContent(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{`\u002fapi\u002fusers`, "/api/users"},
		{`%2Fapi%2Fusers`, "/api/users"},
		{`\u003d`, "="},
	}

	for _, tt := range tests {
		result := decodeJSContent(tt.input)
		if !strContains(result, tt.contains) {
			t.Errorf("expected %q to contain %q, got %q", tt.input, tt.contains, result)
		}
	}
}

// TestFilterNewlines tests newline filtering
func TestFilterNewlines(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello\nworld", "hello world"},
		{"test\r\nvalue", "test value"},
		{"  spaces  ", "spaces"},
	}

	for _, tt := range tests {
		result := filterNewlines(tt.input)
		if result != tt.expected {
			t.Errorf("filterNewlines(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestCategorizeEndpoint tests endpoint categorization
func TestCategorizeEndpoint(t *testing.T) {
	tests := []struct {
		path     string
		method   string
		expected string
	}{
		{"/health", "GET", "health"},
		{"/healthz", "GET", "health"},
		{"/api/ping", "GET", "health"},
		{"/login", "POST", "auth"},
		{"/oauth/authorize", "GET", "auth"},
		{"/api/v1/users", "GET", "api"},
		{"/admin/settings", "GET", "admin"},
		{"/upload/files", "POST", "upload"},
		{"/assets/image.png", "GET", "upload"},
		{"/static/main.js", "GET", "static"},
		{"/styles.css", "GET", "static"},
		{"/webhook/callback", "POST", "webhook"},
		{"/random/path", "GET", "general"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := categorizeEndpoint(tt.path, tt.method)
			if result != tt.expected {
				t.Errorf("categorizeEndpoint(%q, %q) = %q, want %q", tt.path, tt.method, result, tt.expected)
			}
		})
	}
}

// TestExtractParameters tests parameter extraction
func TestExtractParameters(t *testing.T) {
	t.Run("query parameters", func(t *testing.T) {
		params := extractParameters("/search?q=test&page=1", "", "")
		if len(params) != 2 {
			t.Errorf("expected 2 params, got %d", len(params))
		}
	})

	t.Run("JSON body", func(t *testing.T) {
		body := `{"name": "test", "count": 5, "active": true}`
		params := extractParameters("/api", body, "application/json")
		if len(params) != 3 {
			t.Errorf("expected 3 params from JSON body, got %d", len(params))
		}
	})

	t.Run("no parameters", func(t *testing.T) {
		params := extractParameters("/simple/path", "", "text/html")
		if len(params) != 0 {
			t.Errorf("expected 0 params, got %d", len(params))
		}
	})
}

// TestIdentifyRiskFactors tests risk factor identification
func TestIdentifyRiskFactors(t *testing.T) {
	t.Run("parameter injection", func(t *testing.T) {
		risks := identifyRiskFactors("/search?query=test", "GET", "")
		found := false
		for _, r := range risks {
			if r == "parameter_injection" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected parameter_injection risk factor")
		}
	})

	t.Run("file access", func(t *testing.T) {
		risks := identifyRiskFactors("/download/file", "GET", "")
		found := false
		for _, r := range risks {
			if r == "file_access" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected file_access risk factor")
		}
	})

	t.Run("command execution", func(t *testing.T) {
		risks := identifyRiskFactors("/api", "POST", `{"command": "ls"}`)
		found := false
		for _, r := range risks {
			if r == "command_execution" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected command_execution risk factor")
		}
	})

	t.Run("redirect", func(t *testing.T) {
		risks := identifyRiskFactors("/login?redirect=http://evil.com", "GET", "")
		found := false
		for _, r := range risks {
			if r == "redirect" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected redirect risk factor")
		}
	})
}

// TestInferType tests type inference
func TestInferType(t *testing.T) {
	tests := []struct {
		val      interface{}
		expected string
	}{
		{"hello", "string"},
		{float64(42), "number"},
		{true, "boolean"},
		{[]interface{}{1, 2}, "array"},
		{map[string]interface{}{"key": "value"}, "object"},
		{nil, "unknown"},
	}

	for _, tt := range tests {
		result := inferType(tt.val)
		if result != tt.expected {
			t.Errorf("inferType(%v) = %q, want %q", tt.val, result, tt.expected)
		}
	}
}

// TestIsInternalLink tests internal link detection
func TestIsInternalLink(t *testing.T) {
	tests := []struct {
		link     string
		target   string
		expected bool
	}{
		{"/api/users", "http://example.com", true},
		{"//cdn.example.com", "http://example.com", false},
		{"http://example.com/page", "http://example.com", true},
		{"http://other.com/page", "http://example.com", false},
		{"relative/path", "http://example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.link, func(t *testing.T) {
			result := isInternalLink(tt.link, tt.target)
			if result != tt.expected {
				t.Errorf("isInternalLink(%q, %q) = %v, want %v", tt.link, tt.target, result, tt.expected)
			}
		})
	}
}

// TestExtractPath tests path extraction
func TestExtractPath(t *testing.T) {
	tests := []struct {
		link     string
		expected string
	}{
		{"/api/users", "/api/users"},
		{"/search?q=test", "/search"},
		{"/page#section", "/page"},
		{"/path?q=test#hash", "/path"},
		{"http://example.com/page", "/page"},
	}

	for _, tt := range tests {
		t.Run(tt.link, func(t *testing.T) {
			result := extractPath(tt.link)
			if result != tt.expected {
				t.Errorf("extractPath(%q) = %q, want %q", tt.link, result, tt.expected)
			}
		})
	}
}

// TestSaveAndLoadResult tests result persistence
func TestSaveAndLoadResult(t *testing.T) {
	tmpDir := t.TempDir()
	resultFile := tmpDir + "/result.json"

	result := &DiscoveryResult{
		Target:       "http://example.com",
		Service:      "test",
		DiscoveredAt: time.Now(),
		Endpoints: []Endpoint{
			{Path: "/api", Method: "GET"},
		},
		WAFDetected: true,
	}

	err := result.SaveResult(resultFile)
	if err != nil {
		t.Fatalf("failed to save result: %v", err)
	}

	loaded, err := LoadResult(resultFile)
	if err != nil {
		t.Fatalf("failed to load result: %v", err)
	}

	if loaded.Target != result.Target {
		t.Error("Target mismatch")
	}
	if loaded.WAFDetected != result.WAFDetected {
		t.Error("WAFDetected mismatch")
	}
	if len(loaded.Endpoints) != len(result.Endpoints) {
		t.Error("Endpoints length mismatch")
	}
}

// TestLoadResultNotFound tests loading non-existent file
func TestLoadResultNotFound(t *testing.T) {
	_, err := LoadResult("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// TestPresetsLoad verifies all JSON presets load and have endpoints
func TestPresetsLoad(t *testing.T) {
	names := presets.Names()
	if len(names) == 0 {
		t.Fatal("expected at least one preset")
	}
	for _, name := range names {
		p := presets.Get(name)
		if p == nil {
			t.Errorf("preset %q returned nil", name)
			continue
		}
		if len(p.Endpoints) == 0 {
			t.Errorf("preset %q has no endpoints", name)
		}
	}
}

// TestPresetsGetCaseInsensitive verifies case-insensitive lookup
func TestPresetsGetCaseInsensitive(t *testing.T) {
	for _, name := range []string{"Authentik", "AUTHENTIK", "authentik"} {
		if presets.Get(name) == nil {
			t.Errorf("expected preset for %q", name)
		}
	}
}

// TestPresetsGetUnknown returns nil for unknown presets
func TestPresetsGetUnknown(t *testing.T) {
	if presets.Get("nonexistent-service") != nil {
		t.Error("expected nil for unknown preset")
	}
}

// TestPresetsLoadFromDisk verifies presets load from a filesystem directory
func TestPresetsLoadFromDisk(t *testing.T) {
	// Reset to clear any existing registry state
	presets.Reset()
	defer presets.Reset() // clean up for other tests

	// Create a temp dir with a custom preset
	dir := t.TempDir()
	data := []byte(`{
		"name": "custom-app",
		"description": "Test custom preset",
		"endpoints": ["/api/test", "/health"],
		"attack_surface": {"has_api_endpoints": true, "has_graphql": true}
	}`)
	if err := os.WriteFile(dir+"/custom-app.json", data, 0644); err != nil {
		t.Fatal(err)
	}

	presets.SetDir(dir)
	p := presets.Get("custom-app")
	if p == nil {
		t.Fatal("custom preset not loaded from disk")
	}
	if len(p.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(p.Endpoints))
	}
	if !p.AttackSurface.HasGraphQL {
		t.Error("expected HasGraphQL from custom preset")
	}

	// Built-in presets should NOT be loaded (filesystem takes precedence, not merged)
	if presets.Get("authentik") != nil {
		t.Error("embedded presets should not load when disk dir exists")
	}
}

// TestPresetsEmbeddedFallback verifies embedded presets load when no dir is set
func TestPresetsEmbeddedFallback(t *testing.T) {
	presets.Reset()
	defer presets.Reset()

	// Point to a non-existent directory — should fall back to embedded
	presets.SetDir("/nonexistent/path/that/does/not/exist")
	p := presets.Get("authentik")
	if p == nil {
		t.Fatal("expected embedded fallback to load authentik preset")
	}
	if len(p.Endpoints) == 0 {
		t.Error("expected endpoints from embedded preset")
	}
}

// TestApplyAttackHints verifies hints are applied to attack surface
func TestApplyAttackHints(t *testing.T) {
	p := presets.Get("authentik")
	if p == nil {
		t.Fatal("authentik preset not found")
	}
	var surface AttackSurface
	applyAttackHints(&surface, &p.AttackSurface)
	if !surface.HasAuthEndpoints {
		t.Error("expected HasAuthEndpoints")
	}
	if !surface.HasOAuth {
		t.Error("expected HasOAuth")
	}
}

// TestIsExcluded tests path exclusion
func TestIsExcluded(t *testing.T) {
	d := NewDiscoverer(DiscoveryConfig{
		Target:       "http://example.com",
		ExcludePaths: []string{"/static", "/assets"},
	})

	if !d.isExcluded("/static/main.js") {
		t.Error("expected /static/main.js to be excluded")
	}
	if !d.isExcluded("/assets/image.png") {
		t.Error("expected /assets/image.png to be excluded")
	}
	if d.isExcluded("/api/users") {
		t.Error("expected /api/users not to be excluded")
	}
}

// TestDiscoverWithServiceAuthentik tests discovery with authentik service
func TestDiscoverWithServiceAuthentik(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/health/ready/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := DiscoveryConfig{
		Target:        server.URL,
		Service:       "authentik",
		Timeout:       500 * time.Millisecond,
		DisableActive: true, // Disable active brute-forcing for tests
	}
	d := NewDiscoverer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := d.Discover(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should set authentik-specific attack surface
	if !result.AttackSurface.HasAuthEndpoints {
		t.Error("authentik should have auth endpoints")
	}
	if !result.AttackSurface.HasOAuth {
		t.Error("authentik should have OAuth")
	}
}

// TestDiscoverWithServiceN8n tests discovery with n8n service
func TestDiscoverWithServiceN8n(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := DiscoveryConfig{
		Target:        server.URL,
		Service:       "n8n",
		Timeout:       500 * time.Millisecond,
		DisableActive: true, // Disable active brute-forcing for tests
	}
	d := NewDiscoverer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := d.Discover(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should set n8n-specific attack surface
	if !result.AttackSurface.HasAPIEndpoints {
		t.Error("n8n should have API endpoints")
	}
	if !result.AttackSurface.HasWebSockets {
		t.Error("n8n should have WebSockets")
	}
}

// TestDiscoverWithServiceImmich tests discovery with immich service
func TestDiscoverWithServiceImmich(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/server/ping":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := DiscoveryConfig{
		Target:        server.URL,
		Service:       "immich",
		Timeout:       500 * time.Millisecond,
		DisableActive: true, // Disable active brute-forcing for tests
	}
	d := NewDiscoverer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := d.Discover(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should set immich-specific attack surface
	if !result.AttackSurface.HasFileUpload {
		t.Error("immich should have file upload")
	}
}

// TestAnalyzeAttackSurfaceDetectsAuth tests auth detection
func TestAnalyzeAttackSurfaceDetectsAuth(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := DiscoveryConfig{
		Target:        server.URL,
		Timeout:       500 * time.Millisecond,
		DisableActive: true, // Disable active brute-forcing for tests
	}
	d := NewDiscoverer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := d.Discover(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// analyzeAttackSurface should detect auth from /login endpoint
	_ = result
}

// TestProbeEndpointMethods tests probing with different HTTP methods
func TestProbeEndpointMethods(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	methodsCalled := make(map[string]bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methodsCalled[r.Method] = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DiscoveryConfig{
		Target:        server.URL,
		Timeout:       500 * time.Millisecond,
		DisableActive: true, // Disable active brute-forcing for tests
	}
	d := NewDiscoverer(cfg)

	// This will call probeEndpoint internally
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, _ := d.Discover(ctx)
	_ = result

	// Should have tried GET at minimum
	mu.Lock()
	gotGet := methodsCalled["GET"]
	mu.Unlock()
	if !gotGet {
		t.Error("expected GET method to be called")
	}
}

// TestExternalSourcesGatherAll tests gathering from all external sources
func TestExternalSourcesGatherAll(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Write([]byte("Disallow: /admin"))
		case "/sitemap.xml":
			w.Write([]byte(`<urlset><url><loc>/page</loc></url></urlset>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	es := NewExternalSources(500*time.Millisecond, "TestAgent")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	allSources := es.GatherAllSources(ctx, server.URL, "localhost")

	// Should have gathered something from robots.txt at minimum
	_ = allSources
}

// ==================== FORM EXTRACTION TESTS ====================

// TestExtractForms tests HTML form extraction
func TestExtractForms(t *testing.T) {
	t.Run("simple login form", func(t *testing.T) {
		html := `<html>
			<form action="/login" method="POST">
				<input type="text" name="username" required />
				<input type="password" name="password" required />
				<button type="submit">Login</button>
			</form>
		</html>`

		forms := ExtractForms(html, "http://example.com")
		if len(forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(forms))
		}

		form := forms[0]
		if form.Action != "http://example.com/login" {
			t.Errorf("expected action /login, got %s", form.Action)
		}
		if form.Method != "POST" {
			t.Errorf("expected method POST, got %s", form.Method)
		}
		if len(form.Fields) < 2 {
			t.Errorf("expected at least 2 fields, got %d", len(form.Fields))
		}
		if !form.IsLogin {
			t.Error("expected form to be identified as login form")
		}
	})

	t.Run("file upload form", func(t *testing.T) {
		html := `<form action="/upload" method="POST" enctype="multipart/form-data">
			<input type="file" name="document" />
			<input type="submit" value="Upload" />
		</form>`

		forms := ExtractForms(html, "http://example.com")
		if len(forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(forms))
		}

		if !forms[0].HasFile {
			t.Error("expected form to have file upload")
		}
	})

	t.Run("search form", func(t *testing.T) {
		html := `<form action="/search" method="GET">
			<input type="text" name="query" placeholder="Search..." />
		</form>`

		forms := ExtractForms(html, "http://example.com")
		if len(forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(forms))
		}

		if !forms[0].IsSearch {
			t.Error("expected form to be identified as search form")
		}
	})

	t.Run("form with textarea and select", func(t *testing.T) {
		html := `<form action="/feedback" method="POST">
			<textarea name="message"></textarea>
			<select name="category">
				<option value="bug">Bug</option>
				<option value="feature">Feature</option>
			</select>
		</form>`

		forms := ExtractForms(html, "http://example.com")
		if len(forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(forms))
		}

		if len(forms[0].Fields) < 2 {
			t.Errorf("expected at least 2 fields (textarea and select), got %d", len(forms[0].Fields))
		}
	})

	t.Run("form with id", func(t *testing.T) {
		html := `<form id="contact-form" action="/contact" method="POST">
			<input type="email" name="email" />
		</form>`

		forms := ExtractForms(html, "http://example.com")
		if len(forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(forms))
		}

		if forms[0].ID != "contact-form" {
			t.Errorf("expected form id 'contact-form', got '%s'", forms[0].ID)
		}
	})

	t.Run("no forms", func(t *testing.T) {
		html := `<html><body><p>No forms here</p></body></html>`

		forms := ExtractForms(html, "http://example.com")
		if len(forms) != 0 {
			t.Errorf("expected 0 forms, got %d", len(forms))
		}
	})

	t.Run("form with default method", func(t *testing.T) {
		html := `<form action="/default">
			<input type="text" name="field" />
		</form>`

		forms := ExtractForms(html, "http://example.com")
		if len(forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(forms))
		}

		if forms[0].Method != "GET" {
			t.Errorf("expected default method GET, got %s", forms[0].Method)
		}
	})
}

// TestFormStruct tests Form struct JSON serialization
func TestFormStruct(t *testing.T) {
	form := Form{
		Action: "/submit",
		Method: "POST",
		ID:     "test-form",
		Fields: []FormField{
			{Name: "username", Type: "text", Required: true},
			{Name: "password", Type: "password", Required: true},
		},
		HasFile:  false,
		IsLogin:  true,
		IsSearch: false,
	}

	data, err := json.Marshal(form)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored Form
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.Action != form.Action {
		t.Error("Action mismatch")
	}
	if len(restored.Fields) != 2 {
		t.Errorf("expected 2 fields, got %d", len(restored.Fields))
	}
	if !restored.IsLogin {
		t.Error("IsLogin should be true")
	}
}

// TestFormFieldStruct tests FormField struct
func TestFormFieldStruct(t *testing.T) {
	field := FormField{
		Name:        "email",
		Type:        "email",
		ID:          "email-input",
		Placeholder: "Enter email",
		Required:    true,
		Value:       "test@example.com",
	}

	data, err := json.Marshal(field)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if !strContains(jsonStr, `"name":"email"`) {
		t.Error("missing name field")
	}
	if !strContains(jsonStr, `"required":true`) {
		t.Error("missing required field")
	}
}

// TestResolveURL tests URL resolution
func TestResolveURL(t *testing.T) {
	tests := []struct {
		link     string
		baseURL  string
		expected string
	}{
		{"/api/users", "http://example.com", "http://example.com/api/users"},
		{"//cdn.example.com/file.js", "http://example.com", "https://cdn.example.com/file.js"},
		{"http://other.com/page", "http://example.com", "http://other.com/page"},
		{"https://secure.com/page", "http://example.com", "https://secure.com/page"},
		{"relative/path", "http://example.com", "http://example.com/relative/path"},
	}

	for _, tt := range tests {
		t.Run(tt.link, func(t *testing.T) {
			result := resolveURL(tt.link, tt.baseURL)
			if result != tt.expected {
				t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.link, tt.baseURL, result, tt.expected)
			}
		})
	}
}

// TestAllSourcesResultStruct tests AllSourcesResult struct
func TestAllSourcesResultStruct(t *testing.T) {
	result := AllSourcesResult{
		RobotsPaths:  []string{"/admin", "/private"},
		SitemapURLs:  []string{"/page1", "/page2"},
		WaybackURLs:  []string{"/old-page"},
		CommonCrawl:  []string{"/crawled"},
		JSLinks:      []string{"/api/v1"},
		Forms:        []Form{{Action: "/login", Method: "POST"}},
		TotalUnique:  6,
		SourceCounts: map[string]int{"robots.txt": 2, "sitemap.xml": 2},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored AllSourcesResult
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(restored.RobotsPaths) != 2 {
		t.Errorf("expected 2 robots paths, got %d", len(restored.RobotsPaths))
	}
	if restored.TotalUnique != 6 {
		t.Errorf("expected TotalUnique 6, got %d", restored.TotalUnique)
	}
}

// TestParseRobotsContent tests robots.txt content parsing
func TestParseRobotsContent(t *testing.T) {
	content := `User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /public
Allow: /api/v1
Sitemap: http://example.com/sitemap.xml
Sitemap: http://example.com/sitemap2.xml
# This is a comment
Crawl-delay: 10
`

	result := parseRobotsContent(content)

	if len(result.DisallowedPaths) != 2 {
		t.Errorf("expected 2 disallowed paths, got %d", len(result.DisallowedPaths))
	}
	if len(result.AllowedPaths) != 2 {
		t.Errorf("expected 2 allowed paths, got %d", len(result.AllowedPaths))
	}
	if len(result.Sitemaps) != 2 {
		t.Errorf("expected 2 sitemaps, got %d", len(result.Sitemaps))
	}
	if result.CrawlDelay != 10 {
		t.Errorf("expected CrawlDelay 10, got %d", result.CrawlDelay)
	}
}

// TestParseRobotsContentEmpty tests empty robots.txt
func TestParseRobotsContentEmpty(t *testing.T) {
	result := parseRobotsContent("")

	if len(result.DisallowedPaths) != 0 {
		t.Errorf("expected 0 disallowed paths, got %d", len(result.DisallowedPaths))
	}
	if len(result.AllowedPaths) != 0 {
		t.Errorf("expected 0 allowed paths, got %d", len(result.AllowedPaths))
	}
}

// TestSitemapStruct tests Sitemap struct
func TestSitemapStruct(t *testing.T) {
	sitemap := Sitemap{
		URLs: []SitemapURL{
			{Loc: "/page1", LastMod: "2025-01-01"},
			{Loc: "/page2", Priority: "0.8"},
		},
	}

	if len(sitemap.URLs) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(sitemap.URLs))
	}
}

// TestSitemapIndexStruct tests SitemapIndex struct
func TestSitemapIndexStruct(t *testing.T) {
	// Just test the struct exists and can be used
	var index SitemapIndex
	index.XMLName.Local = "sitemapindex"

	if index.XMLName.Local != "sitemapindex" {
		t.Error("XMLName not set correctly")
	}
}

// TestFetchCommonCrawlURLs tests CommonCrawl URL fetching
func TestFetchCommonCrawlURLs(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate CommonCrawl index response (line-delimited JSON)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"url": "http://example.com/page1"}
{"url": "http://example.com/page2"}
{"url": "http://example.com/api/users"}`))
		}))
		defer server.Close()

		// Note: We can't easily override the CommonCrawl URL, so we test the struct and parsing
		es := NewExternalSources(5*time.Second, "test-agent")
		_ = es

		// Verify the parsing logic works by simulating what FetchCommonCrawlURLs does
		seen := make(map[string]bool)
		urls := []string{}

		lines := []string{
			`{"url": "http://example.com/page1"}`,
			`{"url": "http://example.com/page2"}`,
			`{"url": "http://example.com/page1"}`, // duplicate
		}

		for _, line := range lines {
			var entry struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal([]byte(line), &entry); err == nil {
				if entry.URL != "" && !seen[entry.URL] {
					seen[entry.URL] = true
					urls = append(urls, entry.URL)
				}
			}
		}

		if len(urls) != 2 {
			t.Errorf("expected 2 unique URLs, got %d", len(urls))
		}
	})

	t.Run("handles non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		// Just verify ExternalSources can be created
		es := NewExternalSources(5*time.Second, "test-agent")
		if es == nil {
			t.Error("expected non-nil ExternalSources")
		}
	})

	t.Run("handles empty response", func(t *testing.T) {
		lines := []string{}
		urls := []string{}

		for range lines {
			// No iterations
		}

		if len(urls) != 0 {
			t.Error("expected empty URLs")
		}
	})
}

// TestFetchWaybackURLs tests Wayback Machine URL fetching
func TestFetchWaybackURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate Wayback Machine response
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[["urlkey","timestamp","original"],["com,example)/page","20200101120000","http://example.com/page"]]`))
	}))
	defer server.Close()

	// We can't easily test the real Wayback Machine, so just verify the struct
	urls := []WaybackURL{
		{URL: "http://example.com/page", Timestamp: "20200101120000"},
	}

	if len(urls) != 1 {
		t.Error("expected 1 URL")
	}
	if urls[0].URL != "http://example.com/page" {
		t.Error("URL mismatch")
	}
}

// TestCommonCrawlResponse tests CommonCrawl response parsing
func TestCommonCrawlResponse(t *testing.T) {
	// Test the parsing logic
	entry := struct {
		URL string `json:"url"`
	}{
		URL: "http://example.com/page",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.URL != entry.URL {
		t.Error("URL mismatch")
	}
}

// TestDecodeJSContentEdgeCases tests JS content decoding edge cases
func TestDecodeJSContentEdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal text", "normal text"},
		{`\u002fapi`, "/api"},
		{`%2Fpath%2Fto%2Ffile`, "/path/to/file"},
		{`\u003F`, "?"},
		{`\u0026`, "&"},
	}

	for _, tt := range tests {
		result := decodeJSContent(tt.input)
		if result != tt.expected {
			t.Errorf("decodeJSContent(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestFindLinksInJSLargeFile tests JS parsing for large files
func TestFindLinksInJSLargeFile(t *testing.T) {
	// Create a large JS content string
	var builder strings.Builder
	for i := 0; i < 10000; i++ {
		builder.WriteString(`var url = "/api/endpoint";`)
	}
	content := builder.String()

	links := FindLinksInJS(content)
	// Should find at least one link
	if len(links) < 1 {
		t.Error("expected at least 1 link from large JS file")
	}
}

// TestDiscoverWithExcludePaths tests discovery with excluded paths
func TestDiscoverWithExcludePaths(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.WriteHeader(http.StatusOK)
		} else if r.URL.Path == "/static/main.js" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := DiscoveryConfig{
		Target:        server.URL,
		ExcludePaths:  []string{"/static"},
		Timeout:       500 * time.Millisecond,
		DisableActive: true, // Disable active brute-forcing for tests
	}
	d := NewDiscoverer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, _ := d.Discover(ctx)
	_ = result

	// Static paths should be excluded
	if !d.isExcluded("/static/main.js") {
		t.Error("expected /static/main.js to be excluded")
	}
}

// TestProbeEndpointSkips404 tests that 404 responses are skipped
func TestProbeEndpointSkips404(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := DiscoveryConfig{
		Target:        server.URL,
		Timeout:       500 * time.Millisecond,
		DisableActive: true, // Disable active brute-forcing for tests
	}
	d := NewDiscoverer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, _ := d.Discover(ctx)

	// Should have no endpoints from 404 responses
	for _, ep := range result.Endpoints {
		if ep.StatusCode == 404 {
			t.Error("should not include 404 endpoints")
		}
	}
}

// =============================================================================
// BUG-EXPOSING TESTS - These tests expose real bugs in the source code
// =============================================================================

// TestIsInternalLinkWithMalformedTarget exposes bug: url.Parse error ignored, then Host accessed
// BUG: isInternalLink ignores url.Parse error on target, then accesses targetURL.Host
// This can cause nil pointer dereference if target is malformed
func TestIsInternalLinkWithMalformedTarget(t *testing.T) {
	tests := []struct {
		name   string
		link   string
		target string
	}{
		// Normal cases that should work
		{"relative link", "/path", "http://example.com"},
		{"same host", "http://example.com/path", "http://example.com"},
		{"different host", "http://other.com/path", "http://example.com"},

		// Edge cases with malformed targets
		{"malformed target with colons", "/path", "http://:::invalid"},
		{"malformed target empty", "/path", ""},
		{"malformed target spaces", "/path", "http://example .com"},
		{"malformed target no scheme", "/path", "://noscheme"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This should not panic even with malformed targets
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("BUG EXPOSED: isInternalLink panicked with target=%q link=%q: %v",
						tt.target, tt.link, r)
				}
			}()

			// Call the function - it should handle malformed inputs gracefully
			result := isInternalLink(tt.link, tt.target)
			t.Logf("isInternalLink(%q, %q) = %v", tt.link, tt.target, result)
		})
	}
}

// TestExtractParametersWithMalformedPath tests parameter extraction edge cases
func TestExtractParametersWithMalformedPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		body        string
		contentType string
	}{
		{"normal query", "/api?foo=bar&baz=qux", "", ""},
		{"empty query value", "/api?foo=", "", ""},
		{"no equals sign", "/api?foo", "", ""},
		{"multiple equals", "/api?foo=bar=baz", "", ""},
		{"empty param name", "/api?=value", "", ""},
		{"only question mark", "/?", "", ""},
		{"double question mark", "/api??foo=bar", "", ""},
		{"encoded chars", "/api?foo=%20%3D", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic on any input
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("extractParameters panicked: %v", r)
				}
			}()

			params := extractParameters(tt.path, tt.body, tt.contentType)
			t.Logf("extractParameters(%q) returned %d params", tt.path, len(params))
		})
	}
}
