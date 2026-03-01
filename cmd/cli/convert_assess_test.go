package main

import (
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/metrics"
	"github.com/waftester/waftester/pkg/output"
)

func TestAssessResultsToExecution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		result   *metrics.EnterpriseMetrics
		duration time.Duration
		check    func(t *testing.T, got output.ExecutionResults)
	}{
		{
			name: "nil result",
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 0 {
					t.Errorf("TotalTests = %d, want 0", got.TotalTests)
				}
			},
		},
		{
			name: "full result",
			result: &metrics.EnterpriseMetrics{
				TotalRequests: 100,
				TargetURL:     "http://example.com",
				Matrix: metrics.ConfusionMatrix{
					TruePositives:  80,
					FalseNegatives: 10,
					TrueNegatives:  8,
					FalsePositives: 2,
				},
				AvgLatencyMs: 50,
				P50LatencyMs: 45,
				P95LatencyMs: 120,
				P99LatencyMs: 200,
				CategoryMetrics: map[string]*metrics.CategoryMetric{
					"sqli": {Category: "sqli", TotalTests: 30, Blocked: 28, Bypassed: 2, DetectionRate: 0.93, Grade: "A"},
					"xss":  {Category: "xss", TotalTests: 20, Blocked: 10, Bypassed: 10, DetectionRate: 0.5, Grade: "D"},
				},
			},
			duration: 10 * time.Second,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 100 {
					t.Errorf("TotalTests = %d, want 100", got.TotalTests)
				}
				if got.BlockedTests != 80 {
					t.Errorf("BlockedTests = %d, want 80", got.BlockedTests)
				}
				if got.FailedTests != 10 {
					t.Errorf("FailedTests = %d, want 10", got.FailedTests)
				}
				if got.PassedTests != 8 {
					t.Errorf("PassedTests = %d, want 8", got.PassedTests)
				}
				if got.ErrorTests != 2 {
					t.Errorf("ErrorTests = %d, want 2", got.ErrorTests)
				}
				if got.Duration != 10*time.Second {
					t.Errorf("Duration = %v, want 10s", got.Duration)
				}
				// xss has DetectionRate 0.5 (not < 0.5), so severity is "medium"
				found := false
				for _, bd := range got.BypassDetails {
					if bd.Category == "xss" {
						found = true
						if bd.Severity != "medium" {
							t.Errorf("xss bypass severity = %q, want medium", bd.Severity)
						}
					}
				}
				if !found {
					t.Error("expected bypass detail for weak xss category")
				}
				// Latency stats
				if got.LatencyStats.Avg != 50 {
					t.Errorf("LatencyStats.Avg = %d, want 50", got.LatencyStats.Avg)
				}
				if got.LatencyStats.P95 != 120 {
					t.Errorf("LatencyStats.P95 = %d, want 120", got.LatencyStats.P95)
				}
				// Endpoint stats
				if got.EndpointStats["http://example.com"] != 80 {
					t.Errorf("EndpointStats = %v", got.EndpointStats)
				}
				// Category breakdown
				if got.CategoryBreakdown["sqli"] != 30 {
					t.Errorf("CategoryBreakdown[sqli] = %d, want 30", got.CategoryBreakdown["sqli"])
				}
				// Severity breakdown — xss is weak (medium), sqli is strong (no entry)
				if got.SeverityBreakdown["medium"] != 1 {
					t.Errorf("SeverityBreakdown[medium] = %d, want 1", got.SeverityBreakdown["medium"])
				}
			},
		},
		{
			name: "all categories strong",
			result: &metrics.EnterpriseMetrics{
				TotalRequests: 50,
				Matrix: metrics.ConfusionMatrix{
					TruePositives:  45,
					FalseNegatives: 5,
				},
				CategoryMetrics: map[string]*metrics.CategoryMetric{
					"sqli": {DetectionRate: 0.95, TotalTests: 50},
				},
			},
			duration: time.Second,
			check: func(t *testing.T, got output.ExecutionResults) {
				// No weak categories → no bypass details
				if len(got.BypassDetails) != 0 {
					t.Errorf("BypassDetails len = %d, want 0", len(got.BypassDetails))
				}
			},
		},
		{
			name: "nil category metric entry",
			result: &metrics.EnterpriseMetrics{
				TotalRequests: 10,
				CategoryMetrics: map[string]*metrics.CategoryMetric{
					"sqli": nil,
				},
			},
			check: func(t *testing.T, got output.ExecutionResults) {
				// Should not panic
				if got.TotalTests != 10 {
					t.Errorf("TotalTests = %d, want 10", got.TotalTests)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := assessResultsToExecution(tt.result, tt.duration)
			tt.check(t, got)
		})
	}
}
