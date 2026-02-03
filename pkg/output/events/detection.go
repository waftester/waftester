// Package events defines the event types for WAFtester output.
package events

import "time"

// EventTypeDropDetected indicates a connection drop was detected.
const EventTypeDropDetected EventType = "drop_detected"

// EventTypeBanDetected indicates a silent ban was detected.
const EventTypeBanDetected EventType = "ban_detected"

// DropDetectedEvent is emitted when a connection drop is detected.
type DropDetectedEvent struct {
	BaseEvent
	Host          string `json:"host"`
	DropType      string `json:"drop_type"`        // tcp_reset, tls_abort, timeout, eof, tarpit, refused, dns
	Consecutive   int    `json:"consecutive"`      // Number of consecutive drops
	RecoveryWait  int64  `json:"recovery_wait_ms"` // Recommended wait time in ms
	OriginalError string `json:"original_error,omitempty"`
}

// NewDropDetectedEvent creates a new drop detected event.
func NewDropDetectedEvent(scanID, host, dropType string, consecutive int, recoveryWait time.Duration, originalErr string) *DropDetectedEvent {
	return &DropDetectedEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeDropDetected,
			Time: time.Now(),
			Scan: scanID,
		},
		Host:          host,
		DropType:      dropType,
		Consecutive:   consecutive,
		RecoveryWait:  recoveryWait.Milliseconds(),
		OriginalError: originalErr,
	}
}

// BanDetectedEvent is emitted when a silent ban is detected.
type BanDetectedEvent struct {
	BaseEvent
	Host            string   `json:"host"`
	BanType         string   `json:"ban_type"`        // rate_limit, ip_block, behavioral, honeypot, geo_block, session_poison
	Confidence      float64  `json:"confidence"`      // 0.0-1.0
	Evidence        []string `json:"evidence"`        // Detection evidence
	LatencyDrift    float64  `json:"latency_drift"`   // Latency change ratio
	BodySizeDrift   float64  `json:"body_size_drift"` // Body size change ratio
	RecommendedWait int64    `json:"recommended_wait_ms"`
}

// NewBanDetectedEvent creates a new ban detected event.
func NewBanDetectedEvent(scanID, host, banType string, confidence float64, evidence []string, latencyDrift, bodySizeDrift float64, recommendedWait time.Duration) *BanDetectedEvent {
	return &BanDetectedEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeBanDetected,
			Time: time.Now(),
			Scan: scanID,
		},
		Host:            host,
		BanType:         banType,
		Confidence:      confidence,
		Evidence:        evidence,
		LatencyDrift:    latencyDrift,
		BodySizeDrift:   bodySizeDrift,
		RecommendedWait: recommendedWait.Milliseconds(),
	}
}
