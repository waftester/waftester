package main

import (
	"time"

	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/output"
)

// bypassResultsToExecution converts bypass hunt results into the unified ExecutionResults format.
// Bypasses are treated as "failed" tests (WAF failed to block the payload).
func bypassResultsToExecution(target string, bypasses []*mutation.TestResult, totalTested int64, duration time.Duration) output.ExecutionResults {
	var res output.ExecutionResults
	res.TotalTests = int(totalTested)

	setTiming(&res, duration, int(totalTested))

	for _, bp := range bypasses {
		if bp == nil {
			continue
		}

		res.FailedTests++
		incStatusCode(&res.StatusCodes, bp.StatusCode)

		res.BypassPayloads = append(res.BypassPayloads, bp.MutatedPayload)
		res.BypassDetails = append(res.BypassDetails, output.BypassDetail{
			PayloadID:  bp.ID,
			Payload:    bp.MutatedPayload,
			Endpoint:   bp.URL,
			Method:     bp.Method,
			StatusCode: bp.StatusCode,
			Category:   "bypass",
			Severity:   "high",
		})

		// Track encoding effectiveness
		if bp.EncoderUsed != "" {
			if res.EncodingStats == nil {
				res.EncodingStats = make(map[string]*output.EncodingEffectiveness)
			}
			enc := res.EncodingStats[bp.EncoderUsed]
			if enc == nil {
				enc = &output.EncodingEffectiveness{Name: bp.EncoderUsed}
				res.EncodingStats[bp.EncoderUsed] = enc
			}
			enc.TotalTests++
			enc.Bypasses++
		}

		// Track latency
		if bp.LatencyMs > 0 {
			res.Latencies = append(res.Latencies, bp.LatencyMs)
		}
	}

	res.BlockedTests = clampNonNegative(res.TotalTests - res.FailedTests)

	// Compute BypassRate on encoding stats.
	// Note: only bypass results are available here (blocked results aren't passed),
	// so BypassRate reflects per-encoding bypass count relative to encoding usage in bypasses.
	for _, enc := range res.EncodingStats {
		if enc.TotalTests > 0 {
			enc.BypassRate = float64(enc.Bypasses) / float64(enc.TotalTests) * 100
			enc.BlockedTests = enc.TotalTests - enc.Bypasses
		}
	}

	setEndpointStats(&res, target, res.BlockedTests)
	setSeverityBreakdown(&res, "high", res.FailedTests)

	return res
}
