package runner

import "errors"

// Sentinel errors for runner failure modes.
// Callers should use errors.Is() to check for these.
var (
	// ErrHostBlocked indicates a specific host was blocked by
	// policy or access control.
	ErrHostBlocked = errors.New("runner: host blocked")

	// ErrAllHostsFailed indicates every target host in the scan
	// failed, leaving no results.
	ErrAllHostsFailed = errors.New("runner: all hosts failed")
)
