package events

// BypassEvent represents a critical WAF bypass alert.
// This event is emitted when a test payload successfully bypasses
// the WAF protection, indicating a potential security vulnerability.
type BypassEvent struct {
	BaseEvent
	Priority string       `json:"priority"`
	Alert    AlertInfo    `json:"alert"`
	Details  BypassDetail `json:"details"`
	Context  AlertContext `json:"context"`
}

// AlertInfo contains alert metadata describing the bypass.
type AlertInfo struct {
	Title          string `json:"title"`
	Description    string `json:"description"`
	ActionRequired string `json:"action_required"`
}

// BypassDetail contains the specifics of the WAF bypass.
type BypassDetail struct {
	TestID     string   `json:"test_id"`
	Category   string   `json:"category"`
	Severity   Severity `json:"severity"`
	OWASP      []string `json:"owasp,omitempty"`
	CWE        []int    `json:"cwe,omitempty"`
	Endpoint   string   `json:"endpoint"`
	Method     string   `json:"method"`
	StatusCode int      `json:"status_code"`
	Payload    string   `json:"payload,omitempty"`
	Curl       string   `json:"curl,omitempty"`
	Encoding   string   `json:"encoding,omitempty"`
	Tamper     string   `json:"tamper,omitempty"`
}

// AlertContext contains the scan context at the time of the alert.
type AlertContext struct {
	WAFDetected   string `json:"waf_detected,omitempty"`
	TestsSoFar    int    `json:"total_tests_so_far"`
	BypassesSoFar int    `json:"bypasses_so_far"`
}
