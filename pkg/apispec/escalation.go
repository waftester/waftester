package apispec

import "time"

// EscalationLevel controls how aggressively payloads are encoded
// and transformed to bypass WAF detection.
type EscalationLevel int

const (
	// EscalationStandard sends raw payloads with no encoding.
	EscalationStandard EscalationLevel = 1

	// EscalationEncoded applies single-layer encoding: URL, double-URL,
	// Unicode, HTML entity encoding.
	EscalationEncoded EscalationLevel = 2

	// EscalationWAFSpecific uses bypass techniques targeting the detected
	// WAF vendor (e.g., Cloudflare-specific chunked encoding).
	EscalationWAFSpecific EscalationLevel = 3

	// EscalationMultiVector chains multiple techniques: combined encoders,
	// chunked transfer, boundary manipulation, protocol tricks.
	EscalationMultiVector EscalationLevel = 4
)

// String returns a human-readable label for the escalation level.
func (l EscalationLevel) String() string {
	switch l {
	case EscalationStandard:
		return "standard"
	case EscalationEncoded:
		return "encoded"
	case EscalationWAFSpecific:
		return "waf-specific"
	case EscalationMultiVector:
		return "multi-vector"
	default:
		return "unknown"
	}
}

// Encoders returns the encoder names to use for this escalation level.
// These names correspond to encoders registered in pkg/encoding.
func (l EscalationLevel) Encoders() []string {
	switch l {
	case EscalationStandard:
		return []string{"plain"}
	case EscalationEncoded:
		return []string{"plain", "url", "double_url", "html_hex", "unicode"}
	case EscalationWAFSpecific:
		// All standard encoders plus WAF-specific techniques.
		return []string{"plain", "url", "double_url", "html_hex", "unicode", "base64", "utf8_overlong"}
	case EscalationMultiVector:
		// All encoders including chained/composite techniques.
		return []string{"plain", "url", "double_url", "html_hex", "unicode", "base64", "utf8_overlong", "js_escape", "hex"}
	default:
		return []string{"plain"}
	}
}

// SelectEscalationLevel determines the escalation level based on the
// observed block rate from the probe phase.
//
// blockRate is the fraction of probe requests blocked (0.0 to 1.0).
// wafDetected indicates whether a WAF was fingerprinted.
func SelectEscalationLevel(blockRate float64, wafDetected bool) EscalationLevel {
	switch {
	case blockRate <= 0:
		// Nothing blocked — WAF is absent or passive. Standard payloads suffice.
		return EscalationStandard
	case blockRate < 0.5:
		// Partial blocking — WAF catches some patterns. Encoding helps.
		return EscalationEncoded
	case blockRate < 0.9:
		// Most payloads blocked. If WAF detected, use vendor-specific bypasses.
		if wafDetected {
			return EscalationWAFSpecific
		}
		return EscalationEncoded
	default:
		// Everything blocked. Escalate to maximum.
		if wafDetected {
			return EscalationMultiVector
		}
		return EscalationWAFSpecific
	}
}

// ShouldEscalate returns true when the current block rate warrants
// moving to the next escalation level.
func ShouldEscalate(currentLevel EscalationLevel, blockRate float64) bool {
	if currentLevel >= EscalationMultiVector {
		return false // already at maximum
	}
	// Escalate when 80%+ of payloads at current level are blocked.
	return blockRate >= 0.8
}

// RequestBudget controls the maximum resources the executor may consume.
type RequestBudget struct {
	// MaxTotal caps the total number of requests across all endpoints.
	// Zero means no limit.
	MaxTotal int

	// MaxPerEndpoint caps requests per endpoint. Zero means no limit.
	MaxPerEndpoint int

	// TimeLimit is a hard wall-clock timeout for the entire scan.
	// Zero means no time limit (context deadline still applies).
	TimeLimit time.Duration
}

// Allows returns true if the budget permits another request.
// sent is the total requests sent so far. elapsed is the time since scan start.
func (b *RequestBudget) Allows(sent int, elapsed time.Duration) bool {
	if b == nil {
		return true
	}
	if b.MaxTotal > 0 && sent >= b.MaxTotal {
		return false
	}
	if b.TimeLimit > 0 && elapsed >= b.TimeLimit {
		return false
	}
	return true
}

// AllowsForEndpoint returns true if the budget permits another request
// for a specific endpoint. sentForEndpoint is the requests sent for that endpoint.
func (b *RequestBudget) AllowsForEndpoint(sentForEndpoint int) bool {
	if b == nil {
		return true
	}
	if b.MaxPerEndpoint > 0 && sentForEndpoint >= b.MaxPerEndpoint {
		return false
	}
	return true
}

// CorrelationRecord tracks a single request in the scan session for
// post-scan analysis and WAF log correlation.
type CorrelationRecord struct {
	SessionID      string    `json:"session_id"`
	CorrelationID  string    `json:"correlation_id"`
	EndpointTag    string    `json:"endpoint_tag"`
	AttackCategory string    `json:"attack_category"`
	InjectionPoint string    `json:"injection_point"`
	PayloadHash    string    `json:"payload_hash"` // hash, not full payload
	Timestamp      time.Time `json:"timestamp"`
	Blocked        bool      `json:"blocked"`
	WAFResponse    string    `json:"waf_response,omitempty"`
}

// ScanState holds mutable state shared across the scan session.
// Endpoints in a dependency chain consume and produce state here.
type ScanState struct {
	// CSRFTokens maps endpoint tags to extracted CSRF tokens.
	CSRFTokens map[string]string

	// AuthTokens maps scheme names to current auth tokens.
	AuthTokens map[string]string

	// ExtractedVars maps variable names to values extracted from responses.
	// Used for chaining values between dependent endpoints.
	ExtractedVars map[string]string

	// BlockSignature is the response pattern that indicates a WAF block.
	// Learned during the probe phase.
	BlockSignature *BlockSignature
}

// NewScanState returns an initialized ScanState.
func NewScanState() *ScanState {
	return &ScanState{
		CSRFTokens:    make(map[string]string),
		AuthTokens:    make(map[string]string),
		ExtractedVars: make(map[string]string),
	}
}

// BlockSignature describes what a WAF block response looks like.
// Learned during the fingerprint/probe phase.
type BlockSignature struct {
	// StatusCodes that indicate a block (e.g., 403, 406, 429).
	StatusCodes []int `json:"status_codes"`

	// BodyPatterns are substrings found in WAF block response bodies.
	BodyPatterns []string `json:"body_patterns"`

	// HeaderPatterns are header names/values that indicate a block.
	HeaderPatterns map[string]string `json:"header_patterns,omitempty"`
}

// FingerprintResult holds the output of the fingerprint phase.
type FingerprintResult struct {
	// WAFDetected indicates whether a WAF was found.
	WAFDetected bool `json:"waf_detected"`

	// WAFVendor is the detected WAF vendor name (e.g., "cloudflare", "aws-waf").
	WAFVendor string `json:"waf_vendor,omitempty"`

	// WAFConfidence is the detection confidence (0.0-1.0).
	WAFConfidence float64 `json:"waf_confidence"`

	// BlockSignature is the learned block response pattern.
	BlockSignature *BlockSignature `json:"block_signature,omitempty"`

	// HTTP2Supported indicates whether the target supports HTTP/2.
	HTTP2Supported bool `json:"http2_supported"`

	// BaselineStatus is the normal response status code.
	BaselineStatus int `json:"baseline_status"`

	// BaselineSize is the normal response body size.
	BaselineSize int `json:"baseline_size"`
}

// ProbeResult holds the output of the probe phase.
type ProbeResult struct {
	// BlockRate is the fraction of probe requests that were blocked (0.0-1.0).
	BlockRate float64 `json:"block_rate"`

	// TotalProbes is the number of probe requests sent.
	TotalProbes int `json:"total_probes"`

	// BlockedProbes is the number of probes that were blocked.
	BlockedProbes int `json:"blocked_probes"`

	// EscalationLevel is the selected escalation level based on block rate.
	EscalationLevel EscalationLevel `json:"escalation_level"`

	// PerCategoryBlockRate tracks block rates per attack category.
	PerCategoryBlockRate map[string]float64 `json:"per_category_block_rate,omitempty"`
}
