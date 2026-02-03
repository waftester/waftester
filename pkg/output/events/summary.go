package events

import "time"

// SummaryEvent represents the final scan summary.
// It contains comprehensive statistics about the completed scan including
// test totals, WAF effectiveness metrics, breakdowns by category, and timing.
type SummaryEvent struct {
	BaseEvent
	Version       string            `json:"version"`
	Target        SummaryTarget     `json:"target"`
	Totals        SummaryTotals     `json:"totals"`
	Effectiveness EffectivenessInfo `json:"effectiveness"`
	Breakdown     BreakdownInfo     `json:"breakdown"`
	TopBypasses   []BypassInfo      `json:"top_bypasses,omitempty"`
	Latency       LatencyInfo       `json:"latency"`
	Timing        SummaryTiming     `json:"timing"`
	ExitCode      int               `json:"exit_code"`
	ExitReason    string            `json:"exit_reason"`
}

// SummaryTarget contains target information for the scanned URL.
type SummaryTarget struct {
	URL           string  `json:"url"`
	WAFDetected   string  `json:"waf_detected,omitempty"`
	WAFConfidence float64 `json:"waf_confidence,omitempty"`
}

// SummaryTotals contains aggregate counts for all test results.
type SummaryTotals struct {
	Tests    int `json:"tests"`
	Bypasses int `json:"bypasses"`
	Blocked  int `json:"blocked"`
	Errors   int `json:"errors"`
	Passes   int `json:"passes"`
	Timeouts int `json:"timeouts"`
}

// EffectivenessInfo contains WAF effectiveness metrics and recommendations.
type EffectivenessInfo struct {
	BlockRatePct   float64 `json:"block_rate_pct"`
	Grade          string  `json:"grade"`
	Recommendation string  `json:"recommendation"`
}

// BreakdownInfo contains detailed breakdowns of results by various dimensions.
type BreakdownInfo struct {
	BySeverity map[string]CategoryStats `json:"by_severity"`
	ByCategory map[string]CategoryStats `json:"by_category"`
	ByOWASP    map[string]OWASPStats    `json:"by_owasp"`
	ByEncoding map[string]CategoryStats `json:"by_encoding"`
}

// CategoryStats contains statistics for a specific category or dimension.
type CategoryStats struct {
	Total     int     `json:"total"`
	Bypasses  int     `json:"bypasses"`
	BlockRate float64 `json:"block_rate"`
}

// OWASPStats contains statistics for an OWASP Top 10 category.
type OWASPStats struct {
	Name     string `json:"name"`
	Total    int    `json:"total"`
	Bypasses int    `json:"bypasses"`
}

// BypassInfo contains details about a specific bypass for top bypasses list.
type BypassInfo struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Encoding string `json:"encoding,omitempty"`
	Curl     string `json:"curl,omitempty"`
}

// LatencyInfo contains latency statistics from the scan.
type LatencyInfo struct {
	MinMs int64 `json:"min_ms"`
	MaxMs int64 `json:"max_ms"`
	AvgMs int64 `json:"avg_ms"`
	P50Ms int64 `json:"p50_ms"`
	P95Ms int64 `json:"p95_ms"`
	P99Ms int64 `json:"p99_ms"`
}

// SummaryTiming contains timing information for the scan.
type SummaryTiming struct {
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	DurationSec    float64   `json:"duration_sec"`
	RequestsPerSec float64   `json:"requests_per_sec"`
}
