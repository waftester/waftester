package waf

import "context"

// WAFDetector is the consumer-side interface for WAF detection.
// Define interfaces where they're consumed, not where they're implemented.
// This enables unit testing without real WAF detection and allows
// swapping implementations (e.g., cached, mock, remote).
type WAFDetector interface {
	Detect(ctx context.Context, target string) (*DetectionResult, error)
}

// WAFFingerprinter is the consumer-side interface for WAF fingerprinting.
type WAFFingerprinter interface {
	CreateFingerprint(ctx context.Context, target string) (*Fingerprint, error)
}

// Ensure concrete types satisfy interfaces at compile time.
var (
	_ WAFDetector      = (*Detector)(nil)
	_ WAFFingerprinter = (*Fingerprinter)(nil)
)
