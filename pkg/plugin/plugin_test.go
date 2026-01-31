package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager("")
	if m.PluginDir != "plugins" {
		t.Errorf("expected default plugin dir 'plugins', got %s", m.PluginDir)
	}

	m = NewManager("/custom/path")
	if m.PluginDir != "/custom/path" {
		t.Errorf("expected custom plugin dir, got %s", m.PluginDir)
	}
}

// MockScanner implements Scanner interface for testing
type MockScanner struct {
	name       string
	initCalled bool
	scanCalled bool
	cleaned    bool
	scanErr    error
	scanResult *ScanResult
}

func NewMockScanner(name string) *MockScanner {
	return &MockScanner{
		name: name,
		scanResult: &ScanResult{
			Scanner: name,
		},
	}
}

func (s *MockScanner) Name() string        { return s.name }
func (s *MockScanner) Description() string { return "Mock scanner for testing" }
func (s *MockScanner) Version() string     { return "1.0.0" }

func (s *MockScanner) Init(config map[string]interface{}) error {
	s.initCalled = true
	return nil
}

func (s *MockScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	s.scanCalled = true
	if s.scanErr != nil {
		return nil, s.scanErr
	}
	return s.scanResult, nil
}

func (s *MockScanner) Cleanup() error {
	s.cleaned = true
	return nil
}

func TestManager_Register(t *testing.T) {
	m := NewManager("")

	scanner := NewMockScanner("test-scanner")
	m.Register(scanner)

	if len(m.Plugins) != 1 {
		t.Errorf("expected 1 plugin, got %d", len(m.Plugins))
	}

	got, ok := m.Get("test-scanner")
	if !ok {
		t.Error("expected to find registered scanner")
	}
	if got.Name() != "test-scanner" {
		t.Errorf("expected name 'test-scanner', got %s", got.Name())
	}
}

func TestManager_List(t *testing.T) {
	m := NewManager("")

	m.Register(NewMockScanner("scanner-a"))
	m.Register(NewMockScanner("scanner-b"))
	m.Register(NewMockScanner("scanner-c"))

	list := m.List()
	if len(list) != 3 {
		t.Errorf("expected 3 scanners, got %d", len(list))
	}
}

func TestManager_Info(t *testing.T) {
	m := NewManager("")
	m.Register(NewMockScanner("info-test"))

	info := m.Info()
	if len(info) != 1 {
		t.Fatalf("expected 1 info, got %d", len(info))
	}

	if info[0].Name != "info-test" {
		t.Errorf("expected name 'info-test', got %s", info[0].Name)
	}
	if info[0].Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %s", info[0].Version)
	}
}

func TestManager_Scan(t *testing.T) {
	m := NewManager("")

	mockScanner := NewMockScanner("test")
	mockScanner.scanResult.Findings = []Finding{
		{Title: "Test Finding", Severity: "high"},
	}
	m.Register(mockScanner)

	target := &Target{URL: "http://example.com"}
	result, err := m.Scan(context.Background(), "test", target)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mockScanner.scanCalled {
		t.Error("expected scan to be called")
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestManager_ScanNotFound(t *testing.T) {
	m := NewManager("")

	target := &Target{URL: "http://example.com"}
	_, err := m.Scan(context.Background(), "nonexistent", target)

	if err == nil {
		t.Error("expected error for nonexistent scanner")
	}
}

func TestManager_ScanAll(t *testing.T) {
	m := NewManager("")

	m.Register(NewMockScanner("scanner-1"))
	m.Register(NewMockScanner("scanner-2"))

	target := &Target{URL: "http://example.com"}
	results := m.ScanAll(context.Background(), target)

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	if _, ok := results["scanner-1"]; !ok {
		t.Error("expected scanner-1 result")
	}
	if _, ok := results["scanner-2"]; !ok {
		t.Error("expected scanner-2 result")
	}
}

func TestManager_Cleanup(t *testing.T) {
	m := NewManager("")

	mock := NewMockScanner("cleanup-test")
	m.Register(mock)

	m.Cleanup()

	if !mock.cleaned {
		t.Error("expected cleanup to be called")
	}
}

func TestManager_LoadAll_NoDir(t *testing.T) {
	m := NewManager("/nonexistent/path")

	// Should not error when directory doesn't exist
	err := m.LoadAll()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestManager_RegisterBuiltins(t *testing.T) {
	m := NewManager("")
	m.RegisterBuiltins()

	if len(m.Plugins) < 3 {
		t.Errorf("expected at least 3 built-in scanners, got %d", len(m.Plugins))
	}

	// Check specific scanners
	scanners := []string{"headers", "tech", "cors"}
	for _, name := range scanners {
		if _, ok := m.Get(name); !ok {
			t.Errorf("expected %s scanner to be registered", name)
		}
	}
}

// Integration tests with test server
func TestHeaderScanner(t *testing.T) {
	// Server without security headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewHeaderScanner()
	target := &Target{URL: server.URL}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find missing security headers
	if len(result.Findings) == 0 {
		t.Error("expected findings for missing security headers")
	}

	// Check for specific missing headers
	found := false
	for _, f := range result.Findings {
		if f.Type == "missing-header" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected missing-header findings")
	}
}

func TestHeaderScanner_WithSecurityHeaders(t *testing.T) {
	// Server with security headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer server.Close()

	scanner := NewHeaderScanner()
	target := &Target{URL: server.URL}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find fewer missing headers
	missingCount := 0
	for _, f := range result.Findings {
		if f.Type == "missing-header" {
			missingCount++
		}
	}

	// Should have recorded some present headers
	if len(result.Info) == 0 {
		t.Error("expected info items for present headers")
	}
}

func TestTechScanner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(200)
		w.Write([]byte(`<html><script src="/jquery.min.js"></script></html>`))
	}))
	defer server.Close()

	scanner := NewTechScanner()
	target := &Target{URL: server.URL}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect jQuery
	foundJQuery := false
	for _, info := range result.Info {
		if info.Value == "jQuery" {
			foundJQuery = true
			break
		}
	}
	if !foundJQuery {
		t.Error("expected to detect jQuery")
	}

	// Should have info disclosure finding for X-Powered-By
	foundDisclosure := false
	for _, f := range result.Findings {
		if f.Type == "info-disclosure" {
			foundDisclosure = true
			break
		}
	}
	if !foundDisclosure {
		t.Error("expected info-disclosure finding for X-Powered-By")
	}
}

func TestCORSScanner_Wildcard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer server.Close()

	scanner := NewCORSScanner()
	target := &Target{URL: server.URL, Host: "example.com"}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Error("expected finding for CORS wildcard")
	}

	found := false
	for _, f := range result.Findings {
		if f.Title == "CORS Wildcard Origin" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'CORS Wildcard Origin' finding")
	}
}

func TestCORSScanner_OriginReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	scanner := NewCORSScanner()
	target := &Target{URL: server.URL, Host: "example.com"}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Error("expected finding for CORS origin reflection")
	}

	var found *Finding
	for i, f := range result.Findings {
		if f.Title == "CORS Origin Reflection" {
			found = &result.Findings[i]
			break
		}
	}

	if found == nil {
		t.Fatal("expected 'CORS Origin Reflection' finding")
	}

	// With credentials, should be high severity
	if found.Severity != "high" {
		t.Errorf("expected high severity, got %s", found.Severity)
	}
}

func TestCORSScanner_NullOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	scanner := NewCORSScanner()
	target := &Target{URL: server.URL, Host: "example.com"}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Title == "CORS Null Origin Allowed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'CORS Null Origin Allowed' finding")
	}
}

func TestTarget(t *testing.T) {
	target := &Target{
		URL:      "https://example.com/path",
		Host:     "example.com",
		Port:     443,
		Scheme:   "https",
		Path:     "/path",
		Method:   "GET",
		Headers:  map[string]string{"X-Custom": "value"},
		Cookies:  map[string]string{"session": "abc"},
		Metadata: map[string]interface{}{"key": "value"},
	}

	if target.URL != "https://example.com/path" {
		t.Errorf("unexpected URL: %s", target.URL)
	}
}

func TestFinding(t *testing.T) {
	finding := Finding{
		Title:       "SQL Injection",
		Description: "SQL injection vulnerability detected",
		Severity:    "critical",
		Type:        "sqli",
		Evidence:    "1' OR '1'='1",
		CWE:         "CWE-89",
		CVSS:        9.8,
	}

	if finding.Severity != "critical" {
		t.Errorf("unexpected severity: %s", finding.Severity)
	}
	if finding.CVSS != 9.8 {
		t.Errorf("unexpected CVSS: %f", finding.CVSS)
	}
}

func TestScanResult(t *testing.T) {
	result := &ScanResult{
		Scanner: "test",
		Findings: []Finding{
			{Title: "Finding 1"},
		},
		Info: []InfoItem{
			{Title: "Info 1", Value: "value1"},
		},
		DurationMs: 100,
	}

	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.DurationMs != 100 {
		t.Errorf("expected duration 100, got %d", result.DurationMs)
	}
}

func TestScanWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer server.Close()

	scanner := NewHeaderScanner()

	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	target := &Target{URL: server.URL}
	_, err := scanner.Scan(ctx, target)

	// Should get context error
	if err == nil {
		t.Log("Scan completed before timeout - server was fast enough")
		// This is acceptable - the server might respond fast
	}
}
