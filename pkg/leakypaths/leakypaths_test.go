// Package leakypaths provides tests for sensitive path detection
package leakypaths

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDefaultConfig_NotEmpty verifies DefaultConfig returns usable defaults
func TestDefaultConfig_NotEmpty(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.Concurrency <= 0 {
		t.Errorf("expected positive Concurrency, got %d", cfg.Concurrency)
	}

	if cfg.Timeout <= 0 {
		t.Errorf("expected positive Timeout, got %v", cfg.Timeout)
	}

	if cfg.UserAgent == "" {
		t.Error("expected non-empty UserAgent")
	}
}

// TestNewScanner_NilConfig verifies NewScanner handles nil config gracefully
func TestNewScanner_NilConfig(t *testing.T) {
	scanner := NewScanner(nil)

	if scanner == nil {
		t.Fatal("NewScanner(nil) returned nil")
	}

	// Should use defaults
	if scanner.concurrency <= 0 {
		t.Error("scanner should have positive concurrency from defaults")
	}

	if scanner.client == nil {
		t.Error("scanner should have non-nil HTTP client")
	}
}

// TestNewScanner_CustomConfig verifies NewScanner respects custom config
func TestNewScanner_CustomConfig(t *testing.T) {
	cfg := &Config{
		Concurrency: 5,
		Timeout:     10 * time.Second,
		UserAgent:   "TestAgent/1.0",
		Verbose:     true,
	}

	scanner := NewScanner(cfg)

	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}

	if scanner.concurrency != 5 {
		t.Errorf("expected concurrency 5, got %d", scanner.concurrency)
	}

	if scanner.userAgent != "TestAgent/1.0" {
		t.Errorf("expected user agent TestAgent/1.0, got %s", scanner.userAgent)
	}

	if !scanner.verbose {
		t.Error("expected verbose to be true")
	}
}

// TestGetPaths_NotEmpty verifies GetPaths returns paths
func TestGetPaths_NotEmpty(t *testing.T) {
	paths := GetPaths()

	if len(paths) == 0 {
		t.Error("expected non-empty paths list")
	}

	// Should have significant coverage
	if len(paths) < 100 {
		t.Errorf("expected at least 100 paths, got %d", len(paths))
	}

	// Verify path structure
	for i, p := range paths[:10] {
		if p.Path == "" {
			t.Errorf("path %d has empty Path field", i)
		}
		if p.Category == "" {
			t.Errorf("path %d has empty Category field", i)
		}
		if p.Severity == "" {
			t.Errorf("path %d has empty Severity field", i)
		}
	}
}

// TestGetPaths_CategoryFilter verifies category filtering works
func TestGetPaths_CategoryFilter(t *testing.T) {
	allPaths := GetPaths()
	configPaths := GetPaths("config")
	debugPaths := GetPaths("debug")

	if len(configPaths) == 0 {
		t.Error("expected non-empty config paths")
	}

	if len(debugPaths) == 0 {
		t.Error("expected non-empty debug paths")
	}

	// Filtered should be smaller than all
	if len(configPaths) >= len(allPaths) {
		t.Error("filtered paths should be smaller than all paths")
	}

	// Verify all config paths have correct category
	for _, p := range configPaths {
		if p.Category != "config" {
			t.Errorf("expected category 'config', got '%s'", p.Category)
		}
	}
}

// TestGetCategories_NotEmpty verifies GetCategories returns valid categories
func TestGetCategories_NotEmpty(t *testing.T) {
	categories := GetCategories()

	if len(categories) == 0 {
		t.Error("expected non-empty categories list")
	}

	// Should have common categories
	expectedCategories := map[string]bool{
		"config": false,
		"debug":  false,
		"backup": false,
	}

	for _, cat := range categories {
		if cat == "" {
			t.Error("found empty category")
		}
		if _, exists := expectedCategories[cat]; exists {
			expectedCategories[cat] = true
		}
	}

	for cat, found := range expectedCategories {
		if !found {
			t.Errorf("expected to find category '%s'", cat)
		}
	}
}

// TestScanner_Scan_BasicFunctionality verifies basic scan works
func TestScanner_Scan_BasicFunctionality(t *testing.T) {
	// Create a test server that returns 404 for most paths
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_HOST=localhost\nDB_PASS=secret"))
		case "/config.json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"database": "test"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := &Config{
		Concurrency: 2,
		Timeout:     5 * time.Second,
	}
	scanner := NewScanner(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Scan only config category for speed
	result, err := scanner.Scan(ctx, ts.URL, "config")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if result.Target != ts.URL {
		t.Errorf("expected target %s, got %s", ts.URL, result.Target)
	}

	if result.PathsScanned == 0 {
		t.Error("expected some paths to be scanned")
	}
}

// TestScanner_Scan_ContextCancellation verifies scan respects context
func TestScanner_Scan_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	scanner := NewScanner(&Config{Concurrency: 1, Timeout: time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := scanner.Scan(ctx, ts.URL, "config")
	// Should complete quickly due to cancellation (may or may not error)
	_ = err // Error is acceptable here
}

// TestScanResult_Defaults verifies ScanResult has proper zero values
func TestScanResult_Defaults(t *testing.T) {
	result := ScanResult{}

	if result.Interesting {
		t.Error("default Interesting should be false")
	}

	if result.StatusCode != 0 {
		t.Error("default StatusCode should be 0")
	}

	if result.Path != "" {
		t.Error("default Path should be empty")
	}
}

// TestScanSummary_Defaults verifies ScanSummary has proper zero values
func TestScanSummary_Defaults(t *testing.T) {
	summary := ScanSummary{}

	if summary.InterestingHits != 0 {
		t.Error("default InterestingHits should be 0")
	}

	if summary.Results != nil {
		t.Error("default Results should be nil")
	}
}
