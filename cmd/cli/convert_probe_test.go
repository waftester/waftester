package main

import (
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output"
)

func TestProbeResultsToExecution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		results []*ProbeResults
		elapsed time.Duration
		check   func(t *testing.T, got output.ExecutionResults)
	}{
		{
			name: "nil results",
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 0 {
					t.Errorf("TotalTests = %d, want 0", got.TotalTests)
				}
			},
		},
		{
			name:    "empty results",
			results: []*ProbeResults{},
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 0 {
					t.Errorf("TotalTests = %d, want 0", got.TotalTests)
				}
			},
		},
		{
			name: "mixed alive and dead",
			results: []*ProbeResults{
				{Target: "http://a.com", Alive: true, StatusCode: 200, Server: "nginx"},
				{Target: "http://b.com", Alive: false, StatusCode: 0},
				{Target: "http://c.com", Alive: true, StatusCode: 301, Server: "nginx"},
				{Target: "http://d.com", Alive: true, StatusCode: 403, Server: "cloudflare"},
			},
			elapsed: 3 * time.Second,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 4 {
					t.Errorf("TotalTests = %d, want 4", got.TotalTests)
				}
				if got.PassedTests != 3 {
					t.Errorf("PassedTests = %d, want 3", got.PassedTests)
				}
				if got.FailedTests != 1 {
					t.Errorf("FailedTests = %d, want 1", got.FailedTests)
				}
				if got.StatusCodes[200] != 1 {
					t.Errorf("StatusCodes[200] = %d, want 1", got.StatusCodes[200])
				}
				if got.StatusCodes[301] != 1 {
					t.Errorf("StatusCodes[301] = %d, want 1", got.StatusCodes[301])
				}
				// Only alive probes produce bypass details
				if len(got.BypassDetails) != 3 {
					t.Errorf("BypassDetails len = %d, want 3", len(got.BypassDetails))
				}
				// Server distribution
				if got.EndpointStats["nginx"] != 2 {
					t.Errorf("EndpointStats[nginx] = %d, want 2", got.EndpointStats["nginx"])
				}
				if got.Duration != 3*time.Second {
					t.Errorf("Duration = %v, want 3s", got.Duration)
				}
			},
		},
		{
			name: "nil entry in slice",
			results: []*ProbeResults{
				nil,
				{Target: "http://a.com", Alive: true, StatusCode: 200},
			},
			check: func(t *testing.T, got output.ExecutionResults) {
				// nil entries are skipped — only 1 non-nil result
				if got.TotalTests != 1 {
					t.Errorf("TotalTests = %d, want 1", got.TotalTests)
				}
				if got.PassedTests != 1 {
					t.Errorf("PassedTests = %d, want 1", got.PassedTests)
				}
			},
		},
		{
			name: "severity breakdown for alive probes",
			results: []*ProbeResults{
				{Alive: true, StatusCode: 200},
				{Alive: true, StatusCode: 200},
			},
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.SeverityBreakdown["info"] != 2 {
					t.Errorf("SeverityBreakdown[info] = %d, want 2", got.SeverityBreakdown["info"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := probeResultsToExecution(tt.results, tt.elapsed)
			tt.check(t, got)
		})
	}
}
