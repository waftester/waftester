package main

import (
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/fuzz"
	"github.com/waftester/waftester/pkg/output"
)

func TestFuzzResultsToExecution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		target   string
		results  []*fuzz.Result
		stats    *fuzz.Stats
		duration time.Duration
		check    func(t *testing.T, got output.ExecutionResults)
	}{
		{
			name: "nil stats and results",
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 0 {
					t.Errorf("TotalTests = %d, want 0", got.TotalTests)
				}
			},
		},
		{
			name: "stats only no results",
			stats: &fuzz.Stats{
				TotalRequests: 1000,
				Matches:       5,
				Errors:        2,
				Filtered:      10,
				StatusBreakdown: map[int]int{
					200: 900,
					404: 95,
					500: 5,
				},
			},
			target:   "http://example.com/FUZZ",
			duration: 10 * time.Second,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 1000 {
					t.Errorf("TotalTests = %d, want 1000", got.TotalTests)
				}
				if got.FailedTests != 5 {
					t.Errorf("FailedTests = %d, want 5", got.FailedTests)
				}
				if got.ErrorTests != 2 {
					t.Errorf("ErrorTests = %d, want 2", got.ErrorTests)
				}
				if got.FilteredTests != 10 {
					t.Errorf("FilteredTests = %d, want 10", got.FilteredTests)
				}
				if got.BlockedTests != 993 {
					t.Errorf("BlockedTests = %d, want 993", got.BlockedTests)
				}
				if got.StatusCodes[200] != 900 {
					t.Errorf("StatusCodes[200] = %d, want 900", got.StatusCodes[200])
				}
				if got.EndpointStats["http://example.com/FUZZ"] != 993 {
					t.Errorf("EndpointStats = %v", got.EndpointStats)
				}
			},
		},
		{
			name: "results with latencies",
			results: []*fuzz.Result{
				{Input: "admin", URL: "http://x/admin", StatusCode: 200, ResponseTime: 50 * time.Millisecond},
				{Input: "test", URL: "http://x/test", StatusCode: 200, ResponseTime: 100 * time.Millisecond},
			},
			stats: &fuzz.Stats{TotalRequests: 100, Matches: 2},
			check: func(t *testing.T, got output.ExecutionResults) {
				if len(got.BypassDetails) != 2 {
					t.Errorf("BypassDetails len = %d, want 2", len(got.BypassDetails))
				}
				if got.BypassDetails[0].Payload != "admin" {
					t.Errorf("BypassDetails[0].Payload = %q, want admin", got.BypassDetails[0].Payload)
				}
				if len(got.Latencies) != 2 {
					t.Errorf("Latencies len = %d, want 2", len(got.Latencies))
				}
				if got.SeverityBreakdown["info"] != 2 {
					t.Errorf("SeverityBreakdown[info] = %d, want 2", got.SeverityBreakdown["info"])
				}
			},
		},
		{
			name: "nil entry in results slice",
			results: []*fuzz.Result{
				nil,
				{Input: "test", URL: "http://x/test", StatusCode: 200},
			},
			stats: &fuzz.Stats{TotalRequests: 10, Matches: 1},
			check: func(t *testing.T, got output.ExecutionResults) {
				if len(got.BypassDetails) != 1 {
					t.Errorf("BypassDetails len = %d, want 1", len(got.BypassDetails))
				}
			},
		},
		{
			name:  "matches plus errors exceed total clamps BlockedTests to zero",
			stats: &fuzz.Stats{TotalRequests: 5, Matches: 4, Errors: 3},
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 5 {
					t.Errorf("TotalTests = %d, want 5", got.TotalTests)
				}
				if got.BlockedTests != 0 {
					t.Errorf("BlockedTests = %d, want 0 (clamped)", got.BlockedTests)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := fuzzResultsToExecution(tt.target, tt.results, tt.stats, tt.duration)
			tt.check(t, got)
		})
	}
}
