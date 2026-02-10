package fp

import (
	"context"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
)

func TestNewTester(t *testing.T) {
	// Test with nil config (should use defaults)
	tester := NewTester(nil)
	if tester == nil {
		t.Fatal("NewTester returned nil")
	}
	if tester.corpus == nil {
		t.Error("Tester corpus should not be nil")
	}
	if tester.httpClient == nil {
		t.Error("Tester httpClient should not be nil")
	}
	if tester.limiter == nil {
		t.Error("Tester limiter should not be nil")
	}
}

func TestNewTesterWithConfig(t *testing.T) {
	cfg := &Config{
		TargetURL: "https://example.com",
		Base: attackconfig.Base{
			Concurrency: 10,
			Timeout:     30 * time.Second,
		},
		RateLimit:     50.0,
		ParanoiaLevel: 3,
		CorpusSources: []string{"leipzig", "forms"},
		Verbose:       true,
	}

	tester := NewTester(cfg)
	if tester == nil {
		t.Fatal("NewTester returned nil")
	}
	if tester.config.TargetURL != "https://example.com" {
		t.Errorf("Expected target URL 'https://example.com', got '%s'", tester.config.TargetURL)
	}
	if tester.config.Concurrency != 10 {
		t.Errorf("Expected concurrency 10, got %d", tester.config.Concurrency)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.Concurrency <= 0 {
		t.Error("Default concurrency should be positive")
	}
	if cfg.RateLimit <= 0 {
		t.Error("Default rate limit should be positive")
	}
	if cfg.Timeout <= 0 {
		t.Error("Default timeout should be positive")
	}
	if cfg.ParanoiaLevel < 1 || cfg.ParanoiaLevel > 4 {
		t.Errorf("Default paranoia level should be 1-4, got %d", cfg.ParanoiaLevel)
	}
}

func TestGetCorpus(t *testing.T) {
	tester := NewTester(nil)
	corpus := tester.GetCorpus()
	if corpus == nil {
		t.Error("GetCorpus should not return nil")
	}
}

func TestFPDetailStruct(t *testing.T) {
	detail := FPDetail{
		Payload:       "test payload",
		Corpus:        "leipzig",
		Location:      "query_param",
		StatusCode:    403,
		ResponseBody:  "blocked",
		RuleID:        942100,
		ParanoiaLevel: 2,
	}

	if detail.Payload != "test payload" {
		t.Errorf("Expected payload 'test payload', got '%s'", detail.Payload)
	}
	if detail.RuleID != 942100 {
		t.Errorf("Expected rule ID 942100, got %d", detail.RuleID)
	}
}

func TestResultStruct(t *testing.T) {
	result := &Result{
		TargetURL:      "https://example.com",
		TotalTests:     100,
		FalsePositives: 5,
		TrueNegatives:  95,
		Errors:         0,
		FPRatio:        0.05,
		ByCorpus:       map[string]int64{"leipzig": 3, "forms": 2},
		ByLocation:     map[string]int64{"query_param": 4, "post_json": 1},
	}

	if result.TotalTests != 100 {
		t.Errorf("Expected 100 total tests, got %d", result.TotalTests)
	}
	if result.FPRatio != 0.05 {
		t.Errorf("Expected FP ratio 0.05, got %f", result.FPRatio)
	}
}

func TestTesterRunWithoutTarget(t *testing.T) {
	cfg := &Config{
		TargetURL: "", // Empty target
	}
	tester := NewTester(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Run returns error or empty result when target is empty
	result, _ := tester.Run(ctx)
	if result != nil && result.TotalTests > 0 {
		t.Error("Expected no tests to run without target URL")
	}
}
