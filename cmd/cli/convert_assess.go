package main

import (
	"time"

	"github.com/waftester/waftester/pkg/metrics"
	"github.com/waftester/waftester/pkg/output"
)

// assessResultsToExecution converts WAF assessment metrics into the unified ExecutionResults format.
func assessResultsToExecution(result *metrics.EnterpriseMetrics, duration time.Duration) output.ExecutionResults {
	var res output.ExecutionResults
	if result == nil {
		return res
	}

	res.TotalTests = int(result.TotalRequests)
	setTiming(&res, duration, res.TotalTests)

	// Map confusion matrix to test outcomes
	blocked := int(result.Matrix.TruePositives)   // Attacks correctly blocked
	bypassed := int(result.Matrix.FalseNegatives) // Attacks that got through
	passed := int(result.Matrix.TrueNegatives)    // Benign correctly allowed
	errors := int(result.Matrix.FalsePositives)   // Benign incorrectly blocked
	res.BlockedTests = blocked
	res.FailedTests = bypassed
	res.PassedTests = passed
	res.ErrorTests = errors

	// Category breakdown from per-category metrics
	for cat, cm := range result.CategoryMetrics {
		if cm == nil {
			continue
		}
		if res.CategoryBreakdown == nil {
			res.CategoryBreakdown = make(map[string]int)
		}
		res.CategoryBreakdown[cat] = int(cm.TotalTests)

		// Each weak category (< 80% detection) gets a bypass detail
		if cm.DetectionRate < 0.8 {
			severity := "medium"
			if cm.DetectionRate < 0.5 {
				severity = "high"
			}
			res.BypassDetails = append(res.BypassDetails, output.BypassDetail{
				PayloadID: "weak-category-" + cat,
				Category:  cat,
				Severity:  severity,
				Endpoint:  result.TargetURL,
			})
			incSeverity(&res.SeverityBreakdown, severity)
		}
	}

	// Latency stats
	res.LatencyStats = output.LatencyStats{
		Avg: int64(result.AvgLatencyMs),
		P50: int64(result.P50LatencyMs),
		P95: int64(result.P95LatencyMs),
		P99: int64(result.P99LatencyMs),
	}

	setEndpointStats(&res, result.TargetURL, blocked)

	return res
}
