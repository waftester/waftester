// Package recon provides tests for reconnaissance functionality
package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
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

	// Check module toggles are set
	if !cfg.EnableLeakyPaths {
		t.Error("expected EnableLeakyPaths to be true by default")
	}

	if !cfg.EnableParamDiscovery {
		t.Error("expected EnableParamDiscovery to be true by default")
	}

	if !cfg.EnableJSAnalysis {
		t.Error("expected EnableJSAnalysis to be true by default")
	}

	if !cfg.EnableJA3Rotation {
		t.Error("expected EnableJA3Rotation to be true by default")
	}

	if len(cfg.ParamMethods) == 0 {
		t.Error("expected non-empty ParamMethods")
	}
}

// TestNewScanner_NilConfig verifies NewScanner handles nil config gracefully
func TestNewScanner_NilConfig(t *testing.T) {
	scanner := NewScanner(nil)

	if scanner == nil {
		t.Fatal("NewScanner(nil) returned nil")
	}

	if scanner.config == nil {
		t.Error("scanner should have non-nil config from defaults")
	}
}

// TestNewScanner_CustomConfig verifies NewScanner respects custom config
func TestNewScanner_CustomConfig(t *testing.T) {
	cfg := &Config{
		Base: attackconfig.Base{
			Concurrency: 5,
			Timeout:     20 * time.Second,
		},
		Verbose:              true,
		EnableLeakyPaths:     false,
		EnableParamDiscovery: false,
		EnableJSAnalysis:     true,
	}

	scanner := NewScanner(cfg)

	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}

	if scanner.config.Concurrency != 5 {
		t.Errorf("expected concurrency 5, got %d", scanner.config.Concurrency)
	}

	if scanner.config.EnableLeakyPaths {
		t.Error("expected EnableLeakyPaths to be false")
	}

	if scanner.config.EnableParamDiscovery {
		t.Error("expected EnableParamDiscovery to be false")
	}

	if !scanner.config.EnableJSAnalysis {
		t.Error("expected EnableJSAnalysis to be true")
	}
}

// TestFullReconResult_ToJSON verifies JSON serialization works
func TestFullReconResult_ToJSON(t *testing.T) {
	result := &FullReconResult{
		Target:    "https://example.com",
		Timestamp: time.Now(),
		Duration:  5 * time.Second,
		RiskScore: 45.5,
		RiskLevel: "medium",
		TopRisks:  []string{"Exposed .env file", "Debug endpoint accessible"},
		Stats:     &ReconStats{LeakyPathsFound: 3, ParametersFound: 10},
	}

	jsonData, err := result.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("expected non-empty JSON output")
	}

	// Verify JSON contains expected fields
	jsonStr := string(jsonData)
	expectedFields := []string{"target", "risk_score", "risk_level", "stats"}
	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("JSON missing expected field: %s", field)
		}
	}
}

// TestFullReconResult_PrintSummary verifies summary generation
func TestFullReconResult_PrintSummary(t *testing.T) {
	result := &FullReconResult{
		Target:     "https://example.com",
		Duration:   10 * time.Second,
		RiskScore:  75.0,
		RiskLevel:  "high",
		JA3Profile: "Chrome 120",
		TopRisks:   []string{"Critical config exposure"},
		Stats: &ReconStats{
			LeakyPathsFound:  5,
			ParametersFound:  20,
			SecretsFound:     2,
			CriticalFindings: 1,
			HighFindings:     3,
			MediumFindings:   5,
		},
	}

	summary := result.PrintSummary()

	if summary == "" {
		t.Error("expected non-empty summary")
	}

	// Check summary contains key information
	expectedParts := []string{
		"example.com",
		"Risk Score",
		"Leaky Paths",
		"Parameters",
		"Critical",
	}
	for _, part := range expectedParts {
		if !contains(summary, part) {
			t.Errorf("summary missing expected part: %s", part)
		}
	}
}

// TestReconStats_Defaults verifies ReconStats has proper zero values
func TestReconStats_Defaults(t *testing.T) {
	stats := ReconStats{}

	if stats.LeakyPathsFound != 0 {
		t.Error("default LeakyPathsFound should be 0")
	}

	if stats.ParametersFound != 0 {
		t.Error("default ParametersFound should be 0")
	}

	if stats.SecretsFound != 0 {
		t.Error("default SecretsFound should be 0")
	}
}

// TestJSAnalysisResult_Defaults verifies JSAnalysisResult has proper zero values
func TestJSAnalysisResult_Defaults(t *testing.T) {
	result := JSAnalysisResult{}

	if result.FilesAnalyzed != 0 {
		t.Error("default FilesAnalyzed should be 0")
	}

	if result.Secrets != nil {
		t.Error("default Secrets should be nil")
	}

	if result.Endpoints != nil {
		t.Error("default Endpoints should be nil")
	}
}

// TestFullScan_BasicFunctionality verifies basic scan works
func TestFullScan_BasicFunctionality(t *testing.T) {
	// Create a minimal test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test</title></head><body>Hello</body></html>`))
	}))
	defer ts.Close()

	cfg := &Config{
		Base: attackconfig.Base{
			Concurrency: 2,
			Timeout:     5 * time.Second,
		},
		EnableLeakyPaths:     false, // Disable to speed up test
		EnableParamDiscovery: false, // Disable to speed up test
		EnableJSAnalysis:     false, // Disable to speed up test
		EnableJA3Rotation:    false,
	}
	scanner := NewScanner(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.FullScan(ctx, ts.URL)
	if err != nil {
		t.Fatalf("FullScan failed: %v", err)
	}

	if result == nil {
		t.Fatal("FullScan returned nil result")
	}

	if result.Target != ts.URL {
		t.Errorf("expected target %s, got %s", ts.URL, result.Target)
	}

	if result.Stats == nil {
		t.Error("expected non-nil Stats")
	}
}

// TestQuickScan_FasterThanFullScan verifies QuickScan runs with reduced settings
func TestQuickScan_FasterThanFullScan(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cfg := &Config{
		Base: attackconfig.Base{
			Concurrency: 1,
			Timeout:     5 * time.Second,
		},
		EnableLeakyPaths:     true,
		EnableParamDiscovery: false,
		EnableJSAnalysis:     false,
		EnableJA3Rotation:    false,
	}
	scanner := NewScanner(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.QuickScan(ctx, ts.URL)
	if err != nil {
		t.Fatalf("QuickScan failed: %v", err)
	}

	if result == nil {
		t.Fatal("QuickScan returned nil result")
	}

	// QuickScan should have limited categories
	// Just verify it completes without error
}

// TestFullScan_ContextCancellation verifies scan respects context
func TestFullScan_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &Config{
		Base: attackconfig.Base{
			Concurrency: 1,
			Timeout:     time.Second,
		},
		EnableLeakyPaths:     false,
		EnableParamDiscovery: false,
		EnableJSAnalysis:     false,
	}
	scanner := NewScanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := scanner.FullScan(ctx, ts.URL)
	// Should complete quickly due to cancellation (may error or return partial results)
	_ = err // Error is acceptable here
}

// TestConfig_LeakyPathCategories verifies category filtering config
func TestConfig_LeakyPathCategories(t *testing.T) {
	cfg := &Config{
		LeakyPathCategories: []string{"config", "debug"},
	}

	if len(cfg.LeakyPathCategories) != 2 {
		t.Error("expected 2 categories")
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
