// Package duration provides canonical time constants for the entire codebase.
// This is the SINGLE SOURCE OF TRUTH for all time-based configuration.
//
// Usage:
//
//	ctx, cancel := context.WithTimeout(ctx, duration.ContextShort)
//	StreamInterval: duration.StreamStd,
//	if resp.ResponseTime > duration.SlowResponse {
//
// DO NOT use hardcoded time.Duration values like `30 * time.Second` anywhere.
// Instead, reference the appropriate constant from this package.
package duration

import "time"

// ============================================================================
// HTTP CLIENT TIMEOUTS
// ============================================================================
//
// These match the presets in pkg/httpclient and are re-exported here for
// packages that need timeout values without importing httpclient.
// ============================================================================

const (
	// HTTPProbing is for quick fingerprinting and health checks (5s)
	HTTPProbing = 5 * time.Second

	// HTTPScanning is for WAF detection and security scanning (15s)
	HTTPScanning = 15 * time.Second

	// HTTPFuzzing is for deep payload testing (30s) - the default
	HTTPFuzzing = 30 * time.Second

	// HTTPLongOps is for crawling, uploads, and authenticated flows (5min)
	HTTPLongOps = 5 * time.Minute

	// HTTPAPI is for external API calls like AI services (60s)
	HTTPAPI = 60 * time.Second
)

// ============================================================================
// CONTEXT/OPERATION TIMEOUTS
// ============================================================================
//
// Use these for context.WithTimeout() calls to bound operation duration.
// ============================================================================

const (
	// ContextShort is for quick operations (30s)
	ContextShort = 30 * time.Second

	// ContextMedium is for standard operations (5min)
	ContextMedium = 5 * time.Minute

	// ContextLong is for extended operations like assessments (15min)
	ContextLong = 15 * time.Minute

	// ContextMax is for full scan operations (30min)
	ContextMax = 30 * time.Minute

	// ContextExtended is for very long operations like crawling (10min)
	ContextExtended = 10 * time.Minute
)

// ============================================================================
// UI/STREAMING INTERVALS
// ============================================================================
//
// Use these for progress updates, streaming output, and UI refresh rates.
// ============================================================================

const (
	// StreamFast is for real-time updates (1s)
	StreamFast = 1 * time.Second

	// StreamStd is for normal progress reporting (3s)
	StreamStd = 3 * time.Second

	// StreamSlow is for low-frequency updates (5s)
	StreamSlow = 5 * time.Second

	// TipRotate is for rotating pro tips in UI (8s)
	TipRotate = 8 * time.Second
)

// ============================================================================
// BROWSER/HEADLESS TIMEOUTS
// ============================================================================
//
// Use these for chromedp and headless browser operations.
// ============================================================================

const (
	// BrowserPage is for page load timeout (30s)
	BrowserPage = 30 * time.Second

	// BrowserLogin is for user login wait time (3min)
	BrowserLogin = 3 * time.Minute

	// BrowserIdle is for idle detection between actions (2s)
	BrowserIdle = 2 * time.Second

	// BrowserPostWait is for delay after login/action (5s)
	BrowserPostWait = 5 * time.Second

	// BrowserMinWait is minimum wait for dynamic content (15s)
	BrowserMinWait = 15 * time.Second
)

// ============================================================================
// HEALTH/RETRY INTERVALS
// ============================================================================
//
// Use these for health checks, retries, and worker coordination.
// ============================================================================

const (
	// RetryFast is for quick retries (1s)
	RetryFast = 1 * time.Second

	// RetryStd is for standard retry delay (5s)
	RetryStd = 5 * time.Second

	// HealthCheck is for health check intervals (2s)
	HealthCheck = 2 * time.Second

	// CrawlDelay is the delay between crawl/recursive requests (100ms)
	CrawlDelay = 100 * time.Millisecond

	// WorkerHeartbeat is for distributed worker heartbeat (10s)
	WorkerHeartbeat = 10 * time.Second

	// WorkerStale is threshold for considering a worker stale (30s)
	WorkerStale = 30 * time.Second
)

// ============================================================================
// RESPONSE TIME THRESHOLDS
// ============================================================================
//
// Use these for anomaly detection and timing-based analysis.
// ============================================================================

const (
	// SlowResponse flags a response as slow (5s)
	SlowResponse = 5 * time.Second

	// VerySlowResponse flags a response as very slow (10s)
	VerySlowResponse = 10 * time.Second
)

// ============================================================================
// CACHE TTLs
// ============================================================================
//
// Use these for cache expiration times.
// ============================================================================

const (
	// CacheShort is for short-lived cache entries (1min)
	CacheShort = 1 * time.Minute

	// CacheMedium is for medium-lived cache entries (5min)
	CacheMedium = 5 * time.Minute

	// CacheLong is for long-lived cache entries (30min)
	CacheLong = 30 * time.Minute
)

// ============================================================================
// NETWORK/TRANSPORT
// ============================================================================
//
// Use these for low-level network configuration.
// ============================================================================

const (
	// DialTimeout is for establishing TCP connections (10s)
	DialTimeout = 10 * time.Second

	// KeepAlive is for TCP keep-alive interval (30s)
	KeepAlive = 30 * time.Second

	// IdleConnTimeout is for idle connection pool timeout (90s)
	IdleConnTimeout = 90 * time.Second

	// TLSHandshake is for TLS handshake timeout (10s)
	TLSHandshake = 10 * time.Second

	// DNSTimeout is for DNS resolution timeout (3s)
	DNSTimeout = 3 * time.Second
)

// ============================================================================
// COMMAND INJECTION TIMING
// ============================================================================
//
// Use these for time-based command injection testing.
// ============================================================================

const (
	// CMDIThreshold is the baseline threshold for timing attacks (5s)
	CMDIThreshold = 5 * time.Second

	// CMDITolerance is the tolerance window for timing comparison (1s)
	CMDITolerance = 1 * time.Second
)
