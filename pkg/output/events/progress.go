package events

import "time"

// ProgressEvent represents a progress update during scanning.
// It provides real-time metrics about scan progress, performance rates,
// timing information, cumulative statistics, and optional resource usage.
type ProgressEvent struct {
	BaseEvent
	Progress  ProgressInfo  `json:"progress"`
	Rate      RateInfo      `json:"rate"`
	Timing    TimingInfo    `json:"timing"`
	Stats     StatsInfo     `json:"stats"`
	Resources *ResourceInfo `json:"resources,omitempty"`
}

// ProgressInfo contains progress metrics for the current scan phase.
type ProgressInfo struct {
	Phase      string  `json:"phase"`
	Current    int     `json:"current"`
	Total      int     `json:"total"`
	Percentage float64 `json:"percentage"`
}

// RateInfo contains rate metrics for scan performance.
type RateInfo struct {
	RequestsPerSec float64 `json:"requests_per_sec"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	ErrorsPerMin   float64 `json:"errors_per_min"`
}

// TimingInfo contains timing metrics for the scan.
type TimingInfo struct {
	ElapsedSec int64     `json:"elapsed_sec"`
	ETASec     int64     `json:"eta_sec"`
	StartedAt  time.Time `json:"started_at"`
}

// StatsInfo contains cumulative statistics for the scan.
type StatsInfo struct {
	Bypasses         int     `json:"bypasses"`
	Blocked          int     `json:"blocked"`
	Errors           int     `json:"errors"`
	Passes           int     `json:"passes"`
	EffectivenessPct float64 `json:"effectiveness_pct"`
}

// ResourceInfo contains resource usage metrics.
type ResourceInfo struct {
	MemoryMB        int `json:"memory_mb"`
	Goroutines      int `json:"goroutines"`
	OpenConnections int `json:"open_connections"`
}
