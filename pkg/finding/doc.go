// Package finding provides shared vulnerability finding types
// used across all WAFtester attack packages.
//
// This package eliminates the 28 duplicate Severity type
// declarations and 27 duplicate Vulnerability struct
// declarations found across attack packages by providing
// canonical base types that packages embed.
//
// Usage:
//
//	type SQLiVuln struct {
//	    finding.Vulnerability
//	    DBMS          string `json:"dbms,omitempty"`
//	    InjectionType string `json:"injection_type"`
//	}
package finding
