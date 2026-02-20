package main

import (
	"sort"
	"strings"

	"github.com/waftester/waftester/pkg/intelligence"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/ratelimit"
	"github.com/waftester/waftester/pkg/strutil"
)

// handleAdaptiveRate processes adaptive rate limiting based on response.
// On HTTP 429, it triggers the limiter's error backoff and escalates.
// On successful non-error outcomes, it signals recovery to the limiter.
func handleAdaptiveRate(statusCode int, outcome string, limiter *ratelimit.Limiter, escalate func(string)) {
	if limiter == nil {
		return
	}
	if statusCode == 429 {
		limiter.OnError()
		escalate("HTTP 429 Too Many Requests")
	} else if outcome != "Error" && outcome != "Skipped" {
		limiter.OnSuccess()
	}
}

// inferHTTPMethod tries to determine the HTTP method from path and source.
// It inspects path segments for REST-like keywords (create, update, delete)
// and falls back to examining the source string for explicit method hints.
func inferHTTPMethod(path, source string) string {
	pathLower := strings.ToLower(path)

	// POST indicators
	if strings.Contains(pathLower, "create") ||
		strings.Contains(pathLower, "add") ||
		strings.Contains(pathLower, "new") ||
		strings.Contains(pathLower, "upload") ||
		strings.Contains(pathLower, "submit") ||
		strings.Contains(pathLower, "login") ||
		strings.Contains(pathLower, "register") ||
		strings.Contains(pathLower, "signup") {
		return "POST"
	}

	// PUT/PATCH indicators
	if strings.Contains(pathLower, "update") ||
		strings.Contains(pathLower, "edit") ||
		strings.Contains(pathLower, "modify") ||
		strings.Contains(pathLower, "save") {
		return "PUT"
	}

	// DELETE indicators
	if strings.Contains(pathLower, "delete") ||
		strings.Contains(pathLower, "remove") ||
		strings.Contains(pathLower, "destroy") {
		return "DELETE"
	}

	// Check source for whole-word HTTP method names to avoid false positives
	// from substrings (e.g., "signpost" matching "post", "output" matching "put").
	sourceUpper := strings.ToUpper(source)
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		idx := strings.Index(sourceUpper, method)
		if idx < 0 {
			continue
		}
		// Check word boundaries: char before and after must be non-alpha
		before := idx == 0 || !isAlpha(sourceUpper[idx-1])
		after := idx+len(method) >= len(sourceUpper) || !isAlpha(sourceUpper[idx+len(method)])
		if before && after {
			return method
		}
	}

	return "GET"
}

func isAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// truncateString truncates a string to max length with ellipsis.
// Delegates to strutil.Truncate for proper UTF-8 rune handling.
func truncateString(s string, max int) string {
	return strutil.Truncate(s, max)
}

// severityToScore converts severity string to CVSS-like score string.
func severityToScore(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "3.0"
	default:
		return "1.0"
	}
}

// payloadsToCandidates converts a slice of payloads to intelligence candidates
// for use with GetTopPayloads and other predictor-based ranking.
func payloadsToCandidates(pp []payloads.Payload) []intelligence.PayloadCandidate {
	candidates := make([]intelligence.PayloadCandidate, len(pp))
	for i, p := range pp {
		candidates[i] = intelligence.PayloadCandidate{
			Category: p.Category,
			Payload:  p.Payload,
			Path:     p.TargetPath,
			Encoding: p.EncodingUsed,
		}
	}
	return candidates
}

// mergeExecutionResults merges src into dst, combining all counters and maps.
// Timing fields (StartTime, EndTime, Duration, RequestsPerSec, LatencyStats)
// are intentionally not merged — they aren't additive across passes and are
// recalculated by the final summary renderer.
func mergeExecutionResults(dst *output.ExecutionResults, src output.ExecutionResults) {
	dst.TotalTests += src.TotalTests
	dst.PassedTests += src.PassedTests
	dst.FailedTests += src.FailedTests
	dst.BlockedTests += src.BlockedTests
	dst.ErrorTests += src.ErrorTests
	dst.DropsDetected += src.DropsDetected
	dst.BansDetected += src.BansDetected
	dst.HostsSkipped += src.HostsSkipped
	dst.FilteredTests += src.FilteredTests
	dst.BypassPayloads = append(dst.BypassPayloads, src.BypassPayloads...)
	dst.BypassDetails = append(dst.BypassDetails, src.BypassDetails...)
	dst.TopErrors = append(dst.TopErrors, src.TopErrors...)
	dst.Latencies = append(dst.Latencies, src.Latencies...)

	mergeIntMap := func(dstMap *map[int]int, srcMap map[int]int) {
		if *dstMap == nil {
			*dstMap = make(map[int]int)
		}
		for k, v := range srcMap {
			(*dstMap)[k] += v
		}
	}
	mergeStrIntMap := func(dstMap *map[string]int, srcMap map[string]int) {
		if *dstMap == nil {
			*dstMap = make(map[string]int)
		}
		for k, v := range srcMap {
			(*dstMap)[k] += v
		}
	}

	mergeIntMap(&dst.StatusCodes, src.StatusCodes)
	mergeStrIntMap(&dst.SeverityBreakdown, src.SeverityBreakdown)
	mergeStrIntMap(&dst.CategoryBreakdown, src.CategoryBreakdown)
	mergeStrIntMap(&dst.OWASPBreakdown, src.OWASPBreakdown)
	mergeStrIntMap(&dst.EndpointStats, src.EndpointStats)
	mergeStrIntMap(&dst.MethodStats, src.MethodStats)
	mergeStrIntMap(&dst.DetectionStats, src.DetectionStats)

	if dst.EncodingStats == nil {
		dst.EncodingStats = make(map[string]*output.EncodingEffectiveness)
	}
	for k, v := range src.EncodingStats {
		if v == nil {
			continue
		}
		if dst.EncodingStats[k] == nil {
			clone := *v
			dst.EncodingStats[k] = &clone
		} else {
			dst.EncodingStats[k].TotalTests += v.TotalTests
			dst.EncodingStats[k].Bypasses += v.Bypasses
			dst.EncodingStats[k].BlockedTests += v.BlockedTests
		}
	}

	// Recalculate bypass rates from merged counters.
	for _, ee := range dst.EncodingStats {
		if ee != nil && ee.TotalTests > 0 {
			ee.BypassRate = float64(ee.Bypasses) / float64(ee.TotalTests) * 100
		}
	}
}

// recalculateLatencyStats recomputes percentile stats from merged raw latencies.
// Call after mergeExecutionResults to keep LatencyStats consistent with Latencies.
func recalculateLatencyStats(r *output.ExecutionResults) {
	if len(r.Latencies) == 0 {
		r.LatencyStats = output.LatencyStats{}
		return
	}

	sorted := make([]int64, len(r.Latencies))
	copy(sorted, r.Latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	n := len(sorted)
	var sum int64
	for _, l := range sorted {
		sum += l
	}

	r.LatencyStats.Min = sorted[0]
	r.LatencyStats.Max = sorted[n-1]
	r.LatencyStats.Avg = sum / int64(n)
	r.LatencyStats.P50 = sorted[n*50/100]
	r.LatencyStats.P95 = sorted[n*95/100]
	p99Idx := n * 99 / 100
	if p99Idx >= n {
		p99Idx = n - 1
	}
	r.LatencyStats.P99 = sorted[p99Idx]
}
