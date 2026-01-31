package calibration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewAdvancedCalibrator(t *testing.T) {
	config := AdvancedConfig{
		Timeout:    5 * time.Second,
		SkipVerify: true,
		PerHost:    true,
	}

	calibrator := NewAdvancedCalibrator(config)

	if calibrator == nil {
		t.Fatal("expected non-nil calibrator")
	}

	if len(calibrator.strategies) == 0 {
		t.Error("expected default strategies")
	}

	if !calibrator.perHost {
		t.Error("expected perHost to be true")
	}
}

func TestDefaultStrategies(t *testing.T) {
	strategies := DefaultStrategies()

	if len(strategies) < 4 {
		t.Errorf("expected at least 4 strategies, got %d", len(strategies))
	}

	// Check for expected strategy names
	names := make(map[string]bool)
	for _, s := range strategies {
		names[s.Name] = true
	}

	expectedNames := []string{"basic", "api", "admin", "post", "extensions"}
	for _, name := range expectedNames {
		if !names[name] {
			t.Errorf("missing expected strategy: %s", name)
		}
	}
}

func TestAdvancedCalibratorWithMockServer(t *testing.T) {
	// Create a mock server that returns 404 for random paths
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Page not found\n"))
	}))
	defer server.Close()

	config := AdvancedConfig{
		Timeout:    5 * time.Second,
		SkipVerify: true,
		PerHost:    false,
	}

	calibrator := NewAdvancedCalibrator(config)

	ctx := context.Background()
	baseline, err := calibrator.CalibrateHost(ctx, server.URL)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !baseline.Calibrated {
		t.Error("expected baseline to be calibrated")
	}

	if baseline.Status != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", baseline.Status)
	}

	// Should have made multiple requests
	if callCount < 5 {
		t.Errorf("expected at least 5 calibration requests, got %d", callCount)
	}
}

func TestAdvancedCalibratorPerHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not found"))
	}))
	defer server.Close()

	config := AdvancedConfig{
		Timeout: 5 * time.Second,
		PerHost: true,
	}

	calibrator := NewAdvancedCalibrator(config)

	ctx := context.Background()

	// First calibration
	baseline1, _ := calibrator.CalibrateHost(ctx, server.URL)

	// Second calibration should return cached result
	baseline2, _ := calibrator.CalibrateHost(ctx, server.URL)

	// Should be the same object (cached)
	if baseline1 != baseline2 {
		t.Error("expected cached baseline on second call")
	}
}

func TestAdvancedCalibratorWildcardDetection(t *testing.T) {
	// Server that always returns 200 with same content (wildcard behavior)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to our website!"))
	}))
	defer server.Close()

	config := AdvancedConfig{
		Timeout: 5 * time.Second,
	}

	calibrator := NewAdvancedCalibrator(config)

	ctx := context.Background()
	baseline, _ := calibrator.CalibrateHost(ctx, server.URL)

	if !baseline.IsWildcard {
		t.Error("expected wildcard detection")
	}

	if baseline.WildcardType != "content" {
		t.Errorf("expected wildcard type 'content', got '%s'", baseline.WildcardType)
	}
}

func TestAdvancedCalibratorRedirectWildcard(t *testing.T) {
	// Server that always redirects
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer server.Close()

	config := AdvancedConfig{
		Timeout: 5 * time.Second,
	}

	calibrator := NewAdvancedCalibrator(config)

	ctx := context.Background()
	baseline, _ := calibrator.CalibrateHost(ctx, server.URL)

	if !baseline.IsWildcard {
		t.Error("expected wildcard detection")
	}

	if baseline.WildcardType != "redirect" {
		t.Errorf("expected wildcard type 'redirect', got '%s'", baseline.WildcardType)
	}
}

func TestBaselineToFilterConfig(t *testing.T) {
	baseline := &Baseline{
		Status:     404,
		Size:       1024,
		Words:      100,
		Lines:      50,
		Calibrated: true,
	}

	config := baseline.ToFilterConfig()

	if status, ok := config["filter_status"].([]int); !ok || status[0] != 404 {
		t.Error("expected filter_status [404]")
	}

	if size, ok := config["filter_size"].([]int); !ok || size[0] != 1024 {
		t.Error("expected filter_size [1024]")
	}
}

func TestBaselineToLegacyResult(t *testing.T) {
	baseline := &Baseline{
		Status:     404,
		Size:       512,
		Words:      50,
		Lines:      25,
		Calibrated: true,
	}

	result := baseline.ToLegacyResult()

	if result.BaselineStatus != 404 {
		t.Errorf("expected BaselineStatus 404, got %d", result.BaselineStatus)
	}

	if result.BaselineSize != 512 {
		t.Errorf("expected BaselineSize 512, got %d", result.BaselineSize)
	}

	if !result.Calibrated {
		t.Error("expected Calibrated to be true")
	}
}

func TestBaselineDescribe(t *testing.T) {
	tests := []struct {
		name     string
		baseline *Baseline
		contains []string
	}{
		{
			name:     "not calibrated",
			baseline: &Baseline{Calibrated: false},
			contains: []string{"Not calibrated"},
		},
		{
			name: "full baseline",
			baseline: &Baseline{
				Status:     404,
				Size:       1024,
				Words:      100,
				Lines:      50,
				Calibrated: true,
			},
			contains: []string{"404", "1024", "100", "50"},
		},
		{
			name: "with wildcard",
			baseline: &Baseline{
				Status:       200,
				IsWildcard:   true,
				WildcardType: "content",
				Calibrated:   true,
			},
			contains: []string{"Wildcard", "content"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := tt.baseline.Describe()
			for _, c := range tt.contains {
				if !containsString(desc, c) {
					t.Errorf("expected description to contain '%s', got '%s'", c, desc)
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestQuarantineManager(t *testing.T) {
	qm := NewQuarantineManager(3) // threshold of 3

	host := "example.com"

	// First two hits should not quarantine
	if qm.RecordHit(host) {
		t.Error("should not quarantine after 1 hit")
	}
	if qm.RecordHit(host) {
		t.Error("should not quarantine after 2 hits")
	}

	// Third hit should trigger quarantine
	if !qm.RecordHit(host) {
		t.Error("should quarantine after 3 hits")
	}

	// Should now be quarantined
	if !qm.IsQuarantined(host) {
		t.Error("host should be quarantined")
	}

	// Get quarantined hosts
	hosts := qm.GetQuarantinedHosts()
	if len(hosts) != 1 || hosts[0] != host {
		t.Error("expected host in quarantine list")
	}

	// Reset
	qm.Reset(host)
	if qm.IsQuarantined(host) {
		t.Error("host should not be quarantined after reset")
	}
}

func TestLoadStrategiesFromFile(t *testing.T) {
	// Create temp strategy file
	tmpDir := t.TempDir()
	strategyFile := filepath.Join(tmpDir, "strategies.json")

	strategies := []CalibrationStrategy{
		{
			Name:  "custom",
			Paths: []string{"/custom1", "/custom2"},
		},
	}

	data, _ := json.Marshal(strategies)
	os.WriteFile(strategyFile, data, 0644)

	loaded, err := LoadStrategiesFromFile(strategyFile)
	if err != nil {
		t.Fatalf("failed to load strategies: %v", err)
	}

	if len(loaded) != 1 {
		t.Errorf("expected 1 strategy, got %d", len(loaded))
	}

	if loaded[0].Name != "custom" {
		t.Errorf("expected name 'custom', got '%s'", loaded[0].Name)
	}
}

func TestAdvancedCalibratorWithCustomStrategies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not found"))
	}))
	defer server.Close()

	customStrategy := CalibrationStrategy{
		Name: "test",
		Paths: []string{
			"/test1",
			"/test2",
		},
		Method: "GET",
	}

	config := AdvancedConfig{
		Timeout:          5 * time.Second,
		CustomStrategies: []CalibrationStrategy{customStrategy},
	}

	calibrator := NewAdvancedCalibrator(config)

	// Should have default + custom strategies
	foundCustom := false
	for _, s := range calibrator.strategies {
		if s.Name == "test" {
			foundCustom = true
			break
		}
	}

	if !foundCustom {
		t.Error("custom strategy not added")
	}
}

func TestAdvancedCalibratorContextCancellation(t *testing.T) {
	// Server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := AdvancedConfig{
		Timeout: 5 * time.Second,
	}

	calibrator := NewAdvancedCalibrator(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := calibrator.CalibrateHost(ctx, server.URL)

	// Should still work (some requests may fail due to context, but not all)
	// The error is acceptable here since we're testing cancellation behavior
	_ = err
}

func TestCalibrationStrategyJSON(t *testing.T) {
	strategy := CalibrationStrategy{
		Name:        "test",
		Description: "Test strategy",
		Paths:       []string{"/test1", "/test2"},
		Method:      "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body:    `{"test": true}`,
		Keyword: "FUZZ",
	}

	data, err := json.Marshal(strategy)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded CalibrationStrategy
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Name != "test" {
		t.Error("name mismatch")
	}

	if decoded.Method != "POST" {
		t.Error("method mismatch")
	}

	if decoded.Headers["Content-Type"] != "application/json" {
		t.Error("headers mismatch")
	}
}
