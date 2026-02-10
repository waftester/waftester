package waf

import "errors"

// Sentinel errors for WAF detection failure modes.
// Callers should use errors.Is() to check for these.
var (
	// ErrDetectionFailed indicates the WAF detection process could
	// not complete (network error, unexpected response format, etc.).
	ErrDetectionFailed = errors.New("waf: detection failed")

	// ErrUnknownWAF indicates a WAF was detected but could not be
	// identified as any known vendor.
	ErrUnknownWAF = errors.New("waf: unknown WAF vendor")
)
