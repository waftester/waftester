package finding

import "errors"

// Sentinel errors for common scan failure modes.
// Callers should use errors.Is() to check for these.
var (
	// ErrTimeout indicates the target did not respond within the
	// configured deadline.
	ErrTimeout = errors.New("finding: timeout")

	// ErrTargetUnreachable indicates the target host could not be
	// reached (DNS failure, connection refused, etc.).
	ErrTargetUnreachable = errors.New("finding: target unreachable")

	// ErrNoPayloads indicates no payloads were available for the
	// requested attack type.
	ErrNoPayloads = errors.New("finding: no payloads available")

	// ErrRateLimited indicates the target is rate-limiting requests.
	ErrRateLimited = errors.New("finding: target rate limiting detected")
)
