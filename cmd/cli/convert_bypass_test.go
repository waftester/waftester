package main

import (
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/output"
)

func TestBypassResultsToExecution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		target   string
		bypasses []*mutation.TestResult
		total    int64
		duration time.Duration
		check    func(t *testing.T, got output.ExecutionResults)
	}{
		{
			name:     "nil bypasses",
			total:    5,
			duration: time.Second,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 5 {
					t.Errorf("TotalTests = %d, want 5", got.TotalTests)
				}
				if got.FailedTests != 0 {
					t.Errorf("FailedTests = %d, want 0", got.FailedTests)
				}
				if got.BlockedTests != 5 {
					t.Errorf("BlockedTests = %d, want 5", got.BlockedTests)
				}
				if len(got.BypassDetails) != 0 {
					t.Errorf("BypassDetails len = %d, want 0", len(got.BypassDetails))
				}
			},
		},
		{
			name:     "empty bypasses",
			bypasses: []*mutation.TestResult{},
			total:    10,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 10 {
					t.Errorf("TotalTests = %d, want 10", got.TotalTests)
				}
				if got.BlockedTests != 10 {
					t.Errorf("BlockedTests = %d, want 10", got.BlockedTests)
				}
			},
		},
		{
			name: "three bypasses of ten",
			bypasses: []*mutation.TestResult{
				{ID: "bp-1", StatusCode: 200, MutatedPayload: "test1", EncoderUsed: "url", URL: "http://x/1", Method: "GET", LatencyMs: 50},
				{ID: "bp-2", StatusCode: 200, MutatedPayload: "test2", EncoderUsed: "html", URL: "http://x/2", Method: "POST", LatencyMs: 100},
				{ID: "bp-3", StatusCode: 200, MutatedPayload: "test3", EncoderUsed: "url", URL: "http://x/3", Method: "GET", LatencyMs: 75},
			},
			target:   "http://example.com",
			total:    10,
			duration: 5 * time.Second,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 10 {
					t.Errorf("TotalTests = %d, want 10", got.TotalTests)
				}
				if got.FailedTests != 3 {
					t.Errorf("FailedTests = %d, want 3", got.FailedTests)
				}
				if got.BlockedTests != 7 {
					t.Errorf("BlockedTests = %d, want 7", got.BlockedTests)
				}
				if len(got.BypassDetails) != 3 {
					t.Errorf("BypassDetails len = %d, want 3", len(got.BypassDetails))
				}
				if got.BypassDetails[0].Payload != "test1" {
					t.Errorf("BypassDetails[0].Payload = %q, want test1", got.BypassDetails[0].Payload)
				}
				if got.BypassDetails[0].Category != "bypass" {
					t.Errorf("BypassDetails[0].Category = %q, want bypass", got.BypassDetails[0].Category)
				}
				if got.BypassDetails[0].Severity != "high" {
					t.Errorf("BypassDetails[0].Severity = %q, want high", got.BypassDetails[0].Severity)
				}
				// Severity breakdown
				if got.SeverityBreakdown["high"] != 3 {
					t.Errorf("SeverityBreakdown[high] = %d, want 3", got.SeverityBreakdown["high"])
				}
				if len(got.BypassPayloads) != 3 {
					t.Errorf("BypassPayloads len = %d, want 3", len(got.BypassPayloads))
				}
				if got.EncodingStats == nil {
					t.Fatal("EncodingStats is nil")
				}
				if got.EncodingStats["url"] == nil || got.EncodingStats["url"].Bypasses != 2 {
					t.Errorf("EncodingStats[url].Bypasses = %v, want 2", got.EncodingStats["url"])
				}
				if got.StatusCodes[200] != 3 {
					t.Errorf("StatusCodes[200] = %d, want 3", got.StatusCodes[200])
				}
				if len(got.Latencies) != 3 {
					t.Errorf("Latencies len = %d, want 3", len(got.Latencies))
				}
				if got.EndpointStats["http://example.com"] != 7 {
					t.Errorf("EndpointStats = %v, want {http://example.com: 7}", got.EndpointStats)
				}
				if got.Duration != 5*time.Second {
					t.Errorf("Duration = %v, want 5s", got.Duration)
				}
				if got.RequestsPerSec < 1.9 || got.RequestsPerSec > 2.1 {
					t.Errorf("RequestsPerSec = %f, want ~2.0", got.RequestsPerSec)
				}
			},
		},
		{
			name: "nil entry in bypasses slice",
			bypasses: []*mutation.TestResult{
				nil,
				{ID: "bp-1", StatusCode: 200, MutatedPayload: "p1"},
			},
			total: 5,
			check: func(t *testing.T, got output.ExecutionResults) {
				// nil entries are skipped — only 1 non-nil bypass counted
				if got.FailedTests != 1 {
					t.Errorf("FailedTests = %d, want 1", got.FailedTests)
				}
				if got.BlockedTests != 4 {
					t.Errorf("BlockedTests = %d, want 4", got.BlockedTests)
				}
				if len(got.BypassDetails) != 1 {
					t.Errorf("BypassDetails len = %d, want 1", len(got.BypassDetails))
				}
			},
		},
		{
			name:  "zero total",
			total: 0,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 0 {
					t.Errorf("TotalTests = %d, want 0", got.TotalTests)
				}
				if got.RequestsPerSec != 0 {
					t.Errorf("RequestsPerSec = %f, want 0", got.RequestsPerSec)
				}
			},
		},
		{
			name: "bypasses exceed total clamps BlockedTests to zero",
			bypasses: []*mutation.TestResult{
				{ID: "bp-1", StatusCode: 200, MutatedPayload: "p1"},
				{ID: "bp-2", StatusCode: 200, MutatedPayload: "p2"},
				{ID: "bp-3", StatusCode: 200, MutatedPayload: "p3"},
			},
			total: 1,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 1 {
					t.Errorf("TotalTests = %d, want 1", got.TotalTests)
				}
				if got.FailedTests != 3 {
					t.Errorf("FailedTests = %d, want 3", got.FailedTests)
				}
				if got.BlockedTests != 0 {
					t.Errorf("BlockedTests = %d, want 0", got.BlockedTests)
				}
			},
		},
		{
			name: "encoding stats have BypassRate computed",
			bypasses: []*mutation.TestResult{
				{ID: "bp-1", StatusCode: 200, MutatedPayload: "p1", EncoderUsed: "url"},
				{ID: "bp-2", StatusCode: 200, MutatedPayload: "p2", EncoderUsed: "url"},
			},
			total: 10,
			check: func(t *testing.T, got output.ExecutionResults) {
				enc := got.EncodingStats["url"]
				if enc == nil {
					t.Fatal("EncodingStats[url] is nil")
				}
				if enc.BypassRate != 100.0 {
					t.Errorf("BypassRate = %f, want 100.0", enc.BypassRate)
				}
				if enc.BlockedTests != 0 {
					t.Errorf("BlockedTests = %d, want 0", enc.BlockedTests)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := bypassResultsToExecution(tt.target, tt.bypasses, tt.total, tt.duration)
			tt.check(t, got)
		})
	}
}
