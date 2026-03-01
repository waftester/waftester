package main

import (
	"github.com/waftester/waftester/pkg/output"
)

// scanResultsToExecution converts vulnerability scan results into the unified ExecutionResults format.
// Each vulnerability finding is a "failed" test (WAF failed to protect against it).
func scanResultsToExecution(target string, result *ScanResult) output.ExecutionResults {
	var res output.ExecutionResults
	if result == nil {
		return res
	}

	findings := collectScanFindings(result)

	// TotalVulns includes vulnerability types not covered by collectScanFindings
	// (CORS, WebSocket, Cache, Smuggling, etc.), so use the larger value to avoid
	// FailedTests > TotalTests.
	res.FailedTests = result.TotalVulns
	res.TotalTests = len(findings)
	if res.TotalTests < res.FailedTests {
		res.TotalTests = res.FailedTests
	}
	res.Duration = result.Duration
	res.StartTime = result.StartTime

	// Copy severity breakdown directly from ScanResult
	if len(result.BySeverity) > 0 {
		res.SeverityBreakdown = make(map[string]int, len(result.BySeverity))
		for sev, count := range result.BySeverity {
			res.SeverityBreakdown[normalizeSeverity(sev)] = count
		}
	}

	// Copy category breakdown directly from ScanResult
	if len(result.ByCategory) > 0 {
		res.CategoryBreakdown = make(map[string]int, len(result.ByCategory))
		for cat, count := range result.ByCategory {
			res.CategoryBreakdown[cat] = count
		}
	}

	// Convert each finding into a BypassDetail for SARIF/JSON/CSV export
	for _, f := range findings {
		res.BypassDetails = append(res.BypassDetails, output.BypassDetail{
			PayloadID: f.Category + "-" + f.Parameter,
			Payload:   f.Payload,
			Endpoint:  f.URL,
			Method:    f.Method,
			Category:  f.Category,
			Severity:  normalizeSeverity(f.Severity),
		})
	}

	setEndpointStats(&res, target, res.TotalTests)

	return res
}
