package main

import (
	"time"

	"github.com/waftester/waftester/pkg/fuzz"
	"github.com/waftester/waftester/pkg/output"
)

// fuzzResultsToExecution converts fuzz results into the unified ExecutionResults format.
// Each matching fuzz result becomes a finding; filtered results are tracked separately.
func fuzzResultsToExecution(target string, results []*fuzz.Result, stats *fuzz.Stats, duration time.Duration) output.ExecutionResults {
	var res output.ExecutionResults

	if stats != nil {
		res.TotalTests = int(stats.TotalRequests)
		res.FailedTests = int(stats.Matches) // Matches = interesting findings
		res.BlockedTests = clampNonNegative(int(stats.TotalRequests) - int(stats.Matches) - int(stats.Errors))
		res.ErrorTests = int(stats.Errors)
		res.FilteredTests = int(stats.Filtered)

		// Copy status breakdown
		if len(stats.StatusBreakdown) > 0 {
			res.StatusCodes = make(map[int]int, len(stats.StatusBreakdown))
			for code, count := range stats.StatusBreakdown {
				res.StatusCodes[code] = count
			}
		}
	}

	setTiming(&res, duration, res.TotalTests)

	nonNilResults := 0
	for _, r := range results {
		if r == nil {
			continue
		}
		nonNilResults++

		res.BypassDetails = append(res.BypassDetails, output.BypassDetail{
			PayloadID:  r.Input,
			Payload:    r.Input,
			Endpoint:   r.URL,
			StatusCode: r.StatusCode,
			Category:   "fuzz",
			Severity:   "info",
		})

		// Track latency
		if r.ResponseTime > 0 {
			res.Latencies = append(res.Latencies, r.ResponseTime.Milliseconds())
		}
	}

	setSeverityBreakdown(&res, "info", nonNilResults)
	setEndpointStats(&res, target, res.BlockedTests)

	return res
}
