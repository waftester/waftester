// Package defaults provides canonical default values for the entire codebase.
// This is the SINGLE SOURCE OF TRUTH for all runtime configuration defaults.
//
// Usage:
//
//	config.Concurrency = defaults.ConcurrencyMedium
//	config.MaxRetries = defaults.RetryMedium
//	req.Header.Set("Content-Type", defaults.ContentTypeJSON)
//
// DO NOT use hardcoded values like `Concurrency: 10` anywhere.
// Instead, reference the appropriate constant from this package.
package defaults

import "fmt"

// Version is the current WAFtester version
const Version = "2.4.3"

// ============================================================================
// CONCURRENCY SETTINGS
// ============================================================================
//
// Use these for worker pools, semaphores, and parallel operations.
// Choose based on the aggressiveness of the operation.
// ============================================================================

const (
	// ConcurrencyMinimal is for single-threaded operations (1)
	ConcurrencyMinimal = 1

	// ConcurrencyLow is for light scanning, auth testing (5)
	ConcurrencyLow = 5

	// ConcurrencyMedium is for standard scanning operations (10)
	ConcurrencyMedium = 10

	// ConcurrencyHigh is for aggressive scanning (20)
	ConcurrencyHigh = 20

	// ConcurrencyVeryHigh is for high-throughput operations (40)
	ConcurrencyVeryHigh = 40

	// ConcurrencyMax is for maximum parallelism (50)
	ConcurrencyMax = 50

	// ConcurrencyDNS is for DNS brute forcing (100)
	ConcurrencyDNS = 100
)

// ============================================================================
// RETRY SETTINGS
// ============================================================================
//
// Use these for retry loops and error recovery.
// ============================================================================

const (
	// RetryNone disables retries (0)
	RetryNone = 0

	// RetryLow is for quick operations (2)
	RetryLow = 2

	// RetryMedium is the standard retry count (3)
	RetryMedium = 3

	// RetryHigh is for flaky operations (5)
	RetryHigh = 5

	// RetryMax is the maximum retry count (10)
	RetryMax = 10
)

// ============================================================================
// BUFFER SIZES
// ============================================================================
//
// Use these for byte buffers, slices, and I/O operations.
// ============================================================================

const (
	// BufferTiny is for small reads (1KB)
	BufferTiny = 1 * 1024

	// BufferSmall is for typical reads (4KB)
	BufferSmall = 4 * 1024

	// BufferMedium is for larger reads (32KB)
	BufferMedium = 32 * 1024

	// BufferLarge is for bulk reads (64KB)
	BufferLarge = 64 * 1024

	// BufferHuge is for very large reads (1MB)
	BufferHuge = 1024 * 1024

	// BufferMax is the maximum response body size (10MB)
	BufferMax = 10 * 1024 * 1024
)

// ============================================================================
// CHANNEL SIZES
// ============================================================================
//
// Use these for buffered channels.
// ============================================================================

const (
	// ChannelTiny is for small buffers (10)
	ChannelTiny = 10

	// ChannelSmall is for typical buffers (100)
	ChannelSmall = 100

	// ChannelMedium is for larger buffers (1000)
	ChannelMedium = 1000

	// ChannelLarge is for high-throughput buffers (10000)
	ChannelLarge = 10000
)

// ============================================================================
// HTTP CONTENT TYPES
// ============================================================================
//
// Use these for Content-Type headers.
// ============================================================================

const (
	// ContentTypeJSON is application/json
	ContentTypeJSON = "application/json"

	// ContentTypeForm is application/x-www-form-urlencoded
	ContentTypeForm = "application/x-www-form-urlencoded"

	// ContentTypeMultipart is multipart/form-data
	ContentTypeMultipart = "multipart/form-data"

	// ContentTypeXML is application/xml
	ContentTypeXML = "application/xml"

	// ContentTypeHTML is text/html
	ContentTypeHTML = "text/html"

	// ContentTypePlain is text/plain
	ContentTypePlain = "text/plain"

	// ContentTypeOctetStream is application/octet-stream
	ContentTypeOctetStream = "application/octet-stream"
)

// ============================================================================
// HTTP ACCEPT HEADERS
// ============================================================================
//
// Use these for Accept headers.
// ============================================================================

const (
	// AcceptAll accepts any content type
	AcceptAll = "*/*"

	// AcceptJSON accepts JSON
	AcceptJSON = "application/json"

	// AcceptHTML accepts HTML and related types (standard browser)
	AcceptHTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

	// AcceptHTMLFull is the full browser Accept header
	AcceptHTMLFull = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
)

// ============================================================================
// USER AGENTS
// ============================================================================
//
// Use UserAgent() for dynamic user agent strings.
// Use the constants for specific browser emulation.
// ============================================================================

const (
	// UAChrome is a Chrome user agent
	UAChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	// UAFirefox is a Firefox user agent
	UAFirefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"

	// UASafari is a Safari user agent
	UASafari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"

	// UAEdge is an Edge user agent
	UAEdge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"

	// UABot is a generic bot user agent
	UABot = "Mozilla/5.0 (compatible; WAFtester/" + Version + ")"

	// UAMinimal is a minimal user agent
	UAMinimal = "WAFtester/" + Version
)

// UserAgent returns the WAFtester user agent with context
func UserAgent(context string) string {
	if context == "" {
		return UAMinimal
	}
	return fmt.Sprintf("WAFtester/%s (%s)", Version, context)
}

// ============================================================================
// DEPTH/RECURSION LIMITS
// ============================================================================
//
// Use these for crawling, recursion, and depth limits.
// ============================================================================

const (
	// DepthMinimal is for shallow scans (1)
	DepthMinimal = 1

	// DepthLow is for light crawling (2)
	DepthLow = 2

	// DepthMedium is for standard crawling (3)
	DepthMedium = 3

	// DepthHigh is for deep crawling (5)
	DepthHigh = 5

	// DepthMax is the maximum crawl depth (10)
	DepthMax = 10
)

// ============================================================================
// RATE LIMITING
// ============================================================================
//
// Use these for rate limiting and throttling.
// ============================================================================

const (
	// RateLimitNone disables rate limiting (0)
	RateLimitNone = 0

	// RateLimitLow is conservative rate limiting (10 req/s)
	RateLimitLow = 10

	// RateLimitMedium is moderate rate limiting (50 req/s)
	RateLimitMedium = 50

	// RateLimitHigh is aggressive rate limiting (100 req/s)
	RateLimitHigh = 100

	// RateLimitMax is maximum rate (unlimited effectively) (1000 req/s)
	RateLimitMax = 1000
)

// ============================================================================
// THRESHOLDS
// ============================================================================
//
// Use these for detection thresholds and limits.
// ============================================================================

const (
	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects = 10

	// MaxHeaderSize is the maximum header size (8KB)
	MaxHeaderSize = 8 * 1024

	// MaxURLLength is the maximum URL length
	MaxURLLength = 8192

	// MaxPayloadSize is the maximum payload size (1MB)
	MaxPayloadSize = 1024 * 1024

	// MaxCookies is the maximum number of cookies to track
	MaxCookies = 50

	// MaxParams is the maximum number of parameters to fuzz
	MaxParams = 100
)

// ============================================================================
// WAF DETECTION
// ============================================================================
//
// Use these for WAF detection settings.
// ============================================================================

const (
	// WAFProbeCount is the number of probes for WAF detection
	WAFProbeCount = 5

	// WAFConfidenceThreshold is the minimum confidence for WAF detection (0.7 = 70%)
	WAFConfidenceThreshold = 0.7

	// WAFMinSamples is the minimum samples needed for detection
	WAFMinSamples = 3
)

// ============================================================================
// PORTS
// ============================================================================
//
// Common port numbers.
// ============================================================================

const (
	PortHTTP    = 80
	PortHTTPS   = 443
	PortHTTP8080 = 8080
	PortHTTP8443 = 8443
)
