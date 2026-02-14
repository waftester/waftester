package events

import "time"

// Spec scanning event types.
const (
	// EventTypeSpecScanStarted indicates a spec-driven scan has started.
	EventTypeSpecScanStarted EventType = "spec_scan_started"

	// EventTypeEndpointScanStarted indicates scanning of a single endpoint has started.
	EventTypeEndpointScanStarted EventType = "endpoint_scan_started"

	// EventTypeEndpointFinding indicates a finding was discovered on an endpoint.
	EventTypeEndpointFinding EventType = "endpoint_finding"

	// EventTypeEndpointScanCompleted indicates scanning of a single endpoint has completed.
	EventTypeEndpointScanCompleted EventType = "endpoint_scan_completed"

	// EventTypeSpecScanCompleted indicates a spec-driven scan has completed.
	EventTypeSpecScanCompleted EventType = "spec_scan_completed"
)

// SpecScanStartedEvent is emitted when a spec-driven scan begins.
type SpecScanStartedEvent struct {
	BaseEvent
	SpecSource     string   `json:"spec_source"`
	SpecFormat     string   `json:"spec_format"`
	TotalEndpoints int      `json:"total_endpoints"`
	TotalTests     int      `json:"total_tests"`
	ScanTypes      []string `json:"scan_types"`
	Intensity      string   `json:"intensity"`
}

// NewSpecScanStartedEvent creates a SpecScanStartedEvent.
func NewSpecScanStartedEvent(scanID, source, format string, endpoints, tests int, scanTypes []string, intensity string) *SpecScanStartedEvent {
	return &SpecScanStartedEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeSpecScanStarted,
			Time: time.Now(),
			Scan: scanID,
		},
		SpecSource:     source,
		SpecFormat:     format,
		TotalEndpoints: endpoints,
		TotalTests:     tests,
		ScanTypes:      scanTypes,
		Intensity:      intensity,
	}
}

// EndpointScanStartedEvent is emitted when scanning begins on a single endpoint.
type EndpointScanStartedEvent struct {
	BaseEvent
	Method         string `json:"method"`
	Path           string `json:"path"`
	CorrelationTag string `json:"correlation_tag"`
	ScanType       string `json:"scan_type"`
}

// NewEndpointScanStartedEvent creates an EndpointScanStartedEvent.
func NewEndpointScanStartedEvent(scanID, method, path, correlationTag, scanType string) *EndpointScanStartedEvent {
	return &EndpointScanStartedEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeEndpointScanStarted,
			Time: time.Now(),
			Scan: scanID,
		},
		Method:         method,
		Path:           path,
		CorrelationTag: correlationTag,
		ScanType:       scanType,
	}
}

// EndpointFindingEvent is emitted when a finding is discovered on an endpoint.
type EndpointFindingEvent struct {
	BaseEvent
	Method         string `json:"method"`
	Path           string `json:"path"`
	CorrelationTag string `json:"correlation_tag"`
	Category       string `json:"category"`
	Parameter      string `json:"parameter,omitempty"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Evidence       string `json:"evidence,omitempty"`
}

// NewEndpointFindingEvent creates an EndpointFindingEvent.
func NewEndpointFindingEvent(scanID, method, path, correlationTag, category, param, severity, title, evidence string) *EndpointFindingEvent {
	return &EndpointFindingEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeEndpointFinding,
			Time: time.Now(),
			Scan: scanID,
		},
		Method:         method,
		Path:           path,
		CorrelationTag: correlationTag,
		Category:       category,
		Parameter:      param,
		Severity:       severity,
		Title:          title,
		Evidence:       evidence,
	}
}

// EndpointScanCompletedEvent is emitted when scanning completes on a single endpoint.
type EndpointScanCompletedEvent struct {
	BaseEvent
	Method         string        `json:"method"`
	Path           string        `json:"path"`
	CorrelationTag string        `json:"correlation_tag"`
	ScanType       string        `json:"scan_type"`
	FindingCount   int           `json:"finding_count"`
	Duration       time.Duration `json:"duration"`
	Error          string        `json:"error,omitempty"`
}

// NewEndpointScanCompletedEvent creates an EndpointScanCompletedEvent.
func NewEndpointScanCompletedEvent(scanID, method, path, correlationTag, scanType string, findings int, dur time.Duration, errMsg string) *EndpointScanCompletedEvent {
	return &EndpointScanCompletedEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeEndpointScanCompleted,
			Time: time.Now(),
			Scan: scanID,
		},
		Method:         method,
		Path:           path,
		CorrelationTag: correlationTag,
		ScanType:       scanType,
		FindingCount:   findings,
		Duration:       dur,
		Error:          errMsg,
	}
}

// SpecScanCompletedEvent is emitted when a spec-driven scan finishes.
type SpecScanCompletedEvent struct {
	BaseEvent
	SpecSource     string         `json:"spec_source"`
	TotalEndpoints int            `json:"total_endpoints"`
	TotalTests     int            `json:"total_tests"`
	TotalFindings  int            `json:"total_findings"`
	Duration       time.Duration  `json:"duration"`
	BySeverity     map[string]int `json:"by_severity,omitempty"`
	ByCategory     map[string]int `json:"by_category,omitempty"`
}

// NewSpecScanCompletedEvent creates a SpecScanCompletedEvent.
func NewSpecScanCompletedEvent(scanID, source string, endpoints, tests, findings int, dur time.Duration, bySev, byCat map[string]int) *SpecScanCompletedEvent {
	return &SpecScanCompletedEvent{
		BaseEvent: BaseEvent{
			Type: EventTypeSpecScanCompleted,
			Time: time.Now(),
			Scan: scanID,
		},
		SpecSource:     source,
		TotalEndpoints: endpoints,
		TotalTests:     tests,
		TotalFindings:  findings,
		Duration:       dur,
		BySeverity:     bySev,
		ByCategory:     byCat,
	}
}
