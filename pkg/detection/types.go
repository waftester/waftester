// Package detection provides types and utilities for detecting connection drops
// and silent bans from WAF and security systems.
package detection

import "time"

// DropType represents the type of connection drop detected.
type DropType int

const (
	// DropTypeNone indicates no drop was detected.
	DropTypeNone DropType = iota
	// DropTypeTCPReset indicates the connection was reset by peer (RST packet).
	DropTypeTCPReset
	// DropTypeTLSAbort indicates a TLS handshake failure or abort.
	DropTypeTLSAbort
	// DropTypeTimeout indicates no response was received within the timeout period.
	DropTypeTimeout
	// DropTypeEOF indicates an unexpected end of stream.
	DropTypeEOF
	// DropTypeTarpit indicates an extremely slow response (tarpit behavior).
	DropTypeTarpit
	// DropTypeRefused indicates the connection was refused.
	DropTypeRefused
	// DropTypeDNS indicates a DNS resolution failure.
	DropTypeDNS
)

// String returns a human-readable representation of the DropType.
func (d DropType) String() string {
	switch d {
	case DropTypeNone:
		return "none"
	case DropTypeTCPReset:
		return "tcp_reset"
	case DropTypeTLSAbort:
		return "tls_abort"
	case DropTypeTimeout:
		return "timeout"
	case DropTypeEOF:
		return "eof"
	case DropTypeTarpit:
		return "tarpit"
	case DropTypeRefused:
		return "refused"
	case DropTypeDNS:
		return "dns_failure"
	default:
		return "unknown"
	}
}

// BanType represents the type of silent ban detected.
type BanType int

const (
	// BanTypeNone indicates no ban was detected.
	BanTypeNone BanType = iota
	// BanTypeRateLimit indicates a rate limiting ban.
	BanTypeRateLimit
	// BanTypeIPBlock indicates an IP-based block.
	BanTypeIPBlock
	// BanTypeBehavioral indicates a behavioral analysis ban.
	BanTypeBehavioral
	// BanTypeHoneypot indicates detection via honeypot.
	BanTypeHoneypot
	// BanTypeGeoBlock indicates a geographic location block.
	BanTypeGeoBlock
	// BanTypeSessionPoison indicates session poisoning detection.
	BanTypeSessionPoison
)

// String returns a human-readable representation of the BanType.
func (b BanType) String() string {
	switch b {
	case BanTypeNone:
		return "none"
	case BanTypeRateLimit:
		return "rate_limit"
	case BanTypeIPBlock:
		return "ip_block"
	case BanTypeBehavioral:
		return "behavioral"
	case BanTypeHoneypot:
		return "honeypot"
	case BanTypeGeoBlock:
		return "geo_block"
	case BanTypeSessionPoison:
		return "session_poison"
	default:
		return "unknown"
	}
}

// DropResult contains the result of connection drop detection.
type DropResult struct {
	// Dropped indicates whether a connection drop was detected.
	Dropped bool
	// Type specifies the type of drop detected.
	Type DropType
	// Consecutive is the number of consecutive drops observed.
	Consecutive int
	// Error contains the underlying error that caused the drop, if any.
	Error error
	// RecoveryWait is the recommended duration to wait before retrying.
	RecoveryWait time.Duration
}

// BanResult contains the result of silent ban detection.
type BanResult struct {
	// Banned indicates whether a silent ban was detected.
	Banned bool
	// Type specifies the type of ban detected.
	Type BanType
	// Confidence is the confidence level of the ban detection (0.0 to 1.0).
	Confidence float64
	// Evidence contains human-readable evidence supporting the ban detection.
	Evidence []string
	// LatencyDrift is the percentage drift in response latency from baseline.
	LatencyDrift float64
	// BodySizeDrift is the percentage drift in response body size from baseline.
	BodySizeDrift float64
	// RecommendedWait is the suggested duration to wait before resuming requests.
	RecommendedWait time.Duration
}

// DetectionResult is the combined result of drop and ban detection.
type DetectionResult struct {
	// Drop contains connection drop detection results, if any.
	Drop *DropResult
	// Ban contains silent ban detection results, if any.
	Ban *BanResult
	// Host is the target host that was analyzed.
	Host string
	// Time is when the detection was performed.
	Time time.Time
}
