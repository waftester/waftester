package main

import (
	"time"

	"github.com/waftester/waftester/pkg/crawler"
	"github.com/waftester/waftester/pkg/output"
)

// crawlResultsToExecution converts crawl results into the unified ExecutionResults format.
// Pages are "tests"; forms discovered become findings (potential attack surface).
func crawlResultsToExecution(target string, results []*crawler.CrawlResult, forms []crawler.FormInfo, scripts, urls []string, duration time.Duration) output.ExecutionResults {
	var res output.ExecutionResults

	// Count non-nil results to avoid inflating totals
	for _, r := range results {
		if r == nil {
			continue
		}
		res.TotalTests++
		if r.StatusCode > 0 {
			incStatusCode(&res.StatusCodes, r.StatusCode)
		}
		if r.Error != "" {
			res.ErrorTests++
			res.TopErrors = append(res.TopErrors, r.Error)
		} else {
			res.PassedTests++
		}
	}

	setTiming(&res, duration, res.TotalTests)

	// Forms discovered are attack surface findings
	for _, form := range forms {
		res.BypassDetails = append(res.BypassDetails, output.BypassDetail{
			PayloadID: "crawl-form",
			Endpoint:  form.Action,
			Method:    form.Method,
			Category:  "crawl-form",
			Severity:  "info",
		})
	}

	// Track category breakdown
	if len(forms) > 0 || len(scripts) > 0 || len(urls) > 0 {
		res.CategoryBreakdown = make(map[string]int)
		if len(forms) > 0 {
			res.CategoryBreakdown["forms"] = len(forms)
		}
		if len(scripts) > 0 {
			res.CategoryBreakdown["scripts"] = len(scripts)
		}
		if len(urls) > 0 {
			res.CategoryBreakdown["urls"] = len(urls)
		}
	}

	setSeverityBreakdown(&res, "info", len(forms))
	setEndpointStats(&res, target, res.TotalTests)

	return res
}
