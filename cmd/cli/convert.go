package main

import (
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/output"
)

// execResults is a type alias for output.ExecutionResults, used in MaybeExport
// closures to avoid import shadowing in files that have a local "output" variable.
type execResults = output.ExecutionResults

// normalizeSeverity lowercases severity strings for consistent map keys.
func normalizeSeverity(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// incSeverity increments a severity breakdown map entry, initializing the map if nil.
func incSeverity(m *map[string]int, severity string) {
	if *m == nil {
		*m = make(map[string]int)
	}
	(*m)[normalizeSeverity(severity)]++
}

// incStatusCode increments a status code map entry, initializing the map if nil.
func incStatusCode(m *map[int]int, code int) {
	if *m == nil {
		*m = make(map[int]int)
	}
	(*m)[code]++
}

// incEndpointStat increments an endpoint stats map entry, initializing the map if nil.
func incEndpointStat(m *map[string]int, key string) {
	if *m == nil {
		*m = make(map[string]int)
	}
	(*m)[key]++
}

// setTiming populates Duration and RequestsPerSec on an ExecutionResults.
func setTiming(res *output.ExecutionResults, duration time.Duration, totalRequests int) {
	res.Duration = duration
	if duration > 0 && totalRequests > 0 {
		res.RequestsPerSec = float64(totalRequests) / duration.Seconds()
	}
}

// setEndpointStats sets a single-endpoint stat map when the target is non-empty.
func setEndpointStats(res *output.ExecutionResults, target string, count int) {
	if target != "" {
		res.EndpointStats = map[string]int{target: count}
	}
}

// setSeverityBreakdown sets a single-severity breakdown map when count > 0.
func setSeverityBreakdown(res *output.ExecutionResults, severity string, count int) {
	if count > 0 {
		res.SeverityBreakdown = map[string]int{severity: count}
	}
}

// clampNonNegative returns 0 if n < 0, otherwise n.
func clampNonNegative(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
