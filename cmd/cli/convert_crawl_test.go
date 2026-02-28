package main

import (
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/crawler"
	"github.com/waftester/waftester/pkg/output"
)

func TestCrawlResultsToExecution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		target   string
		results  []*crawler.CrawlResult
		forms    []crawler.FormInfo
		scripts  []string
		urls     []string
		duration time.Duration
		check    func(t *testing.T, got output.ExecutionResults)
	}{
		{
			name: "nil everything",
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 0 {
					t.Errorf("TotalTests = %d, want 0", got.TotalTests)
				}
			},
		},
		{
			name:   "pages with forms and scripts",
			target: "http://example.com",
			results: []*crawler.CrawlResult{
				{URL: "http://example.com/", StatusCode: 200},
				{URL: "http://example.com/about", StatusCode: 200},
				{URL: "http://example.com/error", StatusCode: 500, Error: "timeout"},
			},
			forms: []crawler.FormInfo{
				{Action: "/login", Method: "POST"},
				{Action: "/search", Method: "GET"},
			},
			scripts:  []string{"app.js", "analytics.js", "tracker.js"},
			urls:     []string{"http://example.com/", "http://example.com/about"},
			duration: 5 * time.Second,
			check: func(t *testing.T, got output.ExecutionResults) {
				if got.TotalTests != 3 {
					t.Errorf("TotalTests = %d, want 3", got.TotalTests)
				}
				if got.PassedTests != 2 {
					t.Errorf("PassedTests = %d, want 2", got.PassedTests)
				}
				if got.ErrorTests != 1 {
					t.Errorf("ErrorTests = %d, want 1", got.ErrorTests)
				}
				if got.StatusCodes[200] != 2 {
					t.Errorf("StatusCodes[200] = %d, want 2", got.StatusCodes[200])
				}
				if got.StatusCodes[500] != 1 {
					t.Errorf("StatusCodes[500] = %d, want 1", got.StatusCodes[500])
				}
				// Forms become bypass details
				if len(got.BypassDetails) != 2 {
					t.Errorf("BypassDetails len = %d, want 2", len(got.BypassDetails))
				}
				// Category breakdown
				if got.CategoryBreakdown["forms"] != 2 {
					t.Errorf("CategoryBreakdown[forms] = %d, want 2", got.CategoryBreakdown["forms"])
				}
				if got.CategoryBreakdown["scripts"] != 3 {
					t.Errorf("CategoryBreakdown[scripts] = %d, want 3", got.CategoryBreakdown["scripts"])
				}
				if got.CategoryBreakdown["urls"] != 2 {
					t.Errorf("CategoryBreakdown[urls] = %d, want 2", got.CategoryBreakdown["urls"])
				}
				if got.EndpointStats["http://example.com"] != 3 {
					t.Errorf("EndpointStats = %v", got.EndpointStats)
				}
				// Severity breakdown — forms produce info severity
				if got.SeverityBreakdown["info"] != 2 {
					t.Errorf("SeverityBreakdown[info] = %d, want 2", got.SeverityBreakdown["info"])
				}
				if len(got.TopErrors) != 1 {
					t.Errorf("TopErrors len = %d, want 1", len(got.TopErrors))
				}
			},
		},
		{
			name:    "nil entry in results",
			results: []*crawler.CrawlResult{nil, {URL: "http://x", StatusCode: 200}},
			check: func(t *testing.T, got output.ExecutionResults) {
				// nil entries are skipped — only 1 valid result
				if got.TotalTests != 1 {
					t.Errorf("TotalTests = %d, want 1", got.TotalTests)
				}
				if got.PassedTests != 1 {
					t.Errorf("PassedTests = %d, want 1", got.PassedTests)
				}
				if got.StatusCodes[200] != 1 {
					t.Errorf("StatusCodes[200] = %d, want 1", got.StatusCodes[200])
				}
			},
		},
		{
			name: "no forms no scripts",
			results: []*crawler.CrawlResult{
				{URL: "http://x", StatusCode: 200},
			},
			check: func(t *testing.T, got output.ExecutionResults) {
				if len(got.BypassDetails) != 0 {
					t.Errorf("BypassDetails len = %d, want 0", len(got.BypassDetails))
				}
				if got.CategoryBreakdown != nil && len(got.CategoryBreakdown) != 0 {
					t.Errorf("CategoryBreakdown = %v, want empty", got.CategoryBreakdown)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := crawlResultsToExecution(tt.target, tt.results, tt.forms, tt.scripts, tt.urls, tt.duration)
			tt.check(t, got)
		})
	}
}
