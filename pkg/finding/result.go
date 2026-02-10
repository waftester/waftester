package finding

import "time"

// ScanResult is the base result type for scan operations.
// Attack packages embed this and add domain-specific result fields
// such as vulnerability lists.
//
// Example embedding:
//
//	type SQLiScanResult struct {
//	    finding.ScanResult
//	    Vulnerabilities []SQLiVuln `json:"vulnerabilities,omitempty"`
//	}
type ScanResult struct {
	Target       string        `json:"target"`
	TestedParams int           `json:"tested_params,omitempty"`
	StartTime    time.Time     `json:"start_time,omitempty"`
	Duration     time.Duration `json:"duration,omitempty"`
}
