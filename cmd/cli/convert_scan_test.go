package main

import (
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/sqli"
	"github.com/waftester/waftester/pkg/xss"
)

func TestScanResultToExecution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
		result *ScanResult
		check  func(t *testing.T, got output.ExecutionResults)
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
			name:   "empty result",
			target: "http://example.com",
			result: &ScanResult{
				Target:     "http://example.com",
				TotalVulns: 0,
				Duration:   5 * time.Second,
			},
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 0 {
					t.Errorf("TotalTests = %d, want 0", got.TotalTests)
				}
				if got.FailedTests != 0 {
					t.Errorf("FailedTests = %d, want 0", got.FailedTests)
				}
				if got.Duration != 5*time.Second {
					t.Errorf("Duration = %v, want 5s", got.Duration)
				}
			},
		},
		{
			name:   "result with severity and category breakdown",
			target: "http://example.com",
			result: &ScanResult{
				Target:     "http://example.com",
				TotalVulns: 5,
				Duration:   10 * time.Second,
				BySeverity: map[string]int{
					"critical": 1,
					"high":     2,
					"medium":   2,
				},
				ByCategory: map[string]int{
					"sqli": 3,
					"xss":  2,
				},
				SQLi: &sqli.ScanResult{
					Vulnerabilities: []sqli.Vulnerability{
						{Vulnerability: finding.Vulnerability{URL: "http://x/1", Method: "GET", Payload: "' OR 1=1", Parameter: "id", Severity: "high"}},
						{Vulnerability: finding.Vulnerability{URL: "http://x/2", Method: "POST", Payload: "1 UNION SELECT", Parameter: "q", Severity: "critical"}},
						{Vulnerability: finding.Vulnerability{URL: "http://x/3", Method: "GET", Payload: "'; DROP TABLE", Parameter: "name", Severity: "high"}},
					},
				},
				XSS: &xss.ScanResult{
					Vulnerabilities: []xss.Vulnerability{
						{Vulnerability: finding.Vulnerability{URL: "http://x/4", Method: "GET", Payload: "<script>alert(1)</script>", Parameter: "search", Severity: "medium"}},
						{Vulnerability: finding.Vulnerability{URL: "http://x/5", Method: "GET", Payload: "<img onerror=alert(1)>", Parameter: "q", Severity: "medium"}},
					},
				},
			},
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 5 {
					t.Errorf("TotalTests = %d, want 5", got.TotalTests)
				}
				if got.FailedTests != 5 {
					t.Errorf("FailedTests = %d, want 5", got.FailedTests)
				}
				// Severity breakdown copied from ScanResult
				if got.SeverityBreakdown["critical"] != 1 {
					t.Errorf("SeverityBreakdown[critical] = %d, want 1", got.SeverityBreakdown["critical"])
				}
				if got.SeverityBreakdown["high"] != 2 {
					t.Errorf("SeverityBreakdown[high] = %d, want 2", got.SeverityBreakdown["high"])
				}
				// Category breakdown
				if got.CategoryBreakdown["sqli"] != 3 {
					t.Errorf("CategoryBreakdown[sqli] = %d, want 3", got.CategoryBreakdown["sqli"])
				}
				// BypassDetails populated from findings
				if len(got.BypassDetails) != 5 {
					t.Errorf("BypassDetails len = %d, want 5", len(got.BypassDetails))
				}
				// Check first bypass detail
				if got.BypassDetails[0].Category != "sqli" {
					t.Errorf("BypassDetails[0].Category = %q, want sqli", got.BypassDetails[0].Category)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := scanResultsToExecution(tt.target, tt.result)
			tt.check(t, got)
		})
	}
}
