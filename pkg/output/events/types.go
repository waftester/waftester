// Package events defines the event types for WAFtester output.
// All events are designed for JSON serialization and CI/CD integration.
//
// This package provides the foundational types that all other event types
// will embed. The BaseEvent struct is designed to be embedded in specific
// event types (ResultEvent, ProgressEvent, etc.).
package events

import (
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

// EventType represents the type of output event.
type EventType string

const (
	// EventTypeStart indicates a scan has started.
	EventTypeStart EventType = "start"
	// EventTypeResult indicates a single test result.
	EventTypeResult EventType = "result"
	// EventTypeProgress indicates progress update during scanning.
	EventTypeProgress EventType = "progress"
	// EventTypeBypass indicates a WAF bypass was detected.
	EventTypeBypass EventType = "bypass"
	// EventTypeError indicates an error occurred.
	EventTypeError EventType = "error"
	// EventTypeSummary indicates a summary of results.
	EventTypeSummary EventType = "summary"
	// EventTypeComplete indicates a scan has completed.
	EventTypeComplete EventType = "complete"
)

// Outcome represents the result of a single test.
type Outcome string

const (
	// OutcomeBlocked indicates the request was blocked by the WAF.
	OutcomeBlocked Outcome = "blocked"
	// OutcomeBypass indicates the request bypassed the WAF.
	OutcomeBypass Outcome = "bypass"
	// OutcomeError indicates an error occurred during the test.
	OutcomeError Outcome = "error"
	// OutcomePass indicates the test passed (expected behavior).
	OutcomePass Outcome = "pass"
	// OutcomeTimeout indicates the request timed out.
	OutcomeTimeout Outcome = "timeout"
)

// Severity represents the severity level of an event or finding.
// This is a type alias for finding.Severity to maintain backward compatibility.
type Severity = finding.Severity

const (
	// SeverityCritical indicates a critical severity finding.
	SeverityCritical = finding.Critical
	// SeverityHigh indicates a high severity finding.
	SeverityHigh = finding.High
	// SeverityMedium indicates a medium severity finding.
	SeverityMedium = finding.Medium
	// SeverityLow indicates a low severity finding.
	SeverityLow = finding.Low
	// SeverityInfo indicates an informational finding.
	SeverityInfo = finding.Info
)

// Confidence represents the detection confidence level of a finding.
// Follows Burp Suite and OWASP ZAP patterns for triage.
type Confidence string

const (
	// ConfidenceCertain indicates definitive confirmation (e.g., payload reflected in response).
	ConfidenceCertain Confidence = "certain"
	// ConfidenceHigh indicates high likelihood (e.g., error-based detection).
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium indicates probable finding (e.g., status code change).
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow indicates possible finding (e.g., timing difference).
	ConfidenceLow Confidence = "low"
	// ConfidenceTentative indicates requires manual verification.
	ConfidenceTentative Confidence = "tentative"
)

// ConfidencePriority returns numeric priority for sorting (higher = more confident).
func ConfidencePriority(c Confidence) int {
	switch c {
	case ConfidenceCertain:
		return 5
	case ConfidenceHigh:
		return 4
	case ConfidenceMedium:
		return 3
	case ConfidenceLow:
		return 2
	case ConfidenceTentative:
		return 1
	default:
		return 0
	}
}

// Event is the base interface for all events.
type Event interface {
	EventType() EventType
	Timestamp() time.Time
	ScanID() string
}

// BaseEvent contains common fields for all events.
// It is designed to be embedded in specific event types.
type BaseEvent struct {
	Type EventType `json:"type"`
	Time time.Time `json:"timestamp"`
	Scan string    `json:"scan_id"`
}

// EventType returns the type of this event.
func (e BaseEvent) EventType() EventType { return e.Type }

// Timestamp returns when this event occurred.
func (e BaseEvent) Timestamp() time.Time { return e.Time }

// ScanID returns the unique identifier for the scan that produced this event.
func (e BaseEvent) ScanID() string { return e.Scan }
