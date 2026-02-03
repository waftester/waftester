package events

// StartEvent is emitted when a scan begins.
// It contains all initial configuration and target information
// that will be used throughout the scan.
type StartEvent struct {
	BaseEvent
	Target     string     `json:"target"`
	WAFVendor  string     `json:"waf_vendor,omitempty"`
	Config     ScanConfig `json:"config"`
	Categories []string   `json:"categories,omitempty"`
	TotalTests int        `json:"total_tests"`
}

// ScanConfig contains the scan configuration settings.
type ScanConfig struct {
	Concurrency     int      `json:"concurrency"`
	Timeout         int      `json:"timeout_sec"`
	Categories      []string `json:"categories,omitempty"`
	Encodings       []string `json:"encodings,omitempty"`
	Tampers         []string `json:"tampers,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	ThrottleMs      int      `json:"throttle_ms,omitempty"`
	FollowRedirects bool     `json:"follow_redirects"`
	VerifySSL       bool     `json:"verify_ssl"`
}
