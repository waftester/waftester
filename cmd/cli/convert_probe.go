package main

import (
	"time"

	"github.com/waftester/waftester/pkg/output"
)

// probeResultsToExecution converts probe results into the unified ExecutionResults format.
// Each alive probe is a "passed" test; dead probes are "failed".
func probeResultsToExecution(results []*ProbeResults, elapsed time.Duration) output.ExecutionResults {
	var res output.ExecutionResults

	for _, r := range results {
		if r == nil {
			continue
		}
		res.TotalTests++
		if r.Alive {
			res.PassedTests++
		} else {
			res.FailedTests++
		}

		if r.StatusCode > 0 {
			incStatusCode(&res.StatusCodes, r.StatusCode)
		}

		// Track server distribution as endpoint stats
		if r.Server != "" {
			incEndpointStat(&res.EndpointStats, r.Server)
		}

		// Each alive probe with details becomes a bypass detail (for SARIF/JSON export)
		if r.Alive {
			res.BypassDetails = append(res.BypassDetails, output.BypassDetail{
				PayloadID:  "probe-" + r.Target,
				Endpoint:   r.Target,
				StatusCode: r.StatusCode,
				Category:   "probe",
				Severity:   "info",
			})
		}
	}

	setTiming(&res, elapsed, res.TotalTests)
	setSeverityBreakdown(&res, "info", res.PassedTests)

	return res
}
