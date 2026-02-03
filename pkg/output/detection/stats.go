package detection

import (
	"github.com/waftester/waftester/pkg/detection"
)

// Stats holds detection statistics for display.
// This struct provides a unified interface for all output formats.
type Stats struct {
	// DropsDetected is the total number of connection drops detected.
	DropsDetected int `json:"drops_detected"`

	// BansDetected is the total number of silent bans detected.
	BansDetected int `json:"bans_detected"`

	// HostsSkipped is the number of hosts skipped due to detection.
	HostsSkipped int `json:"hosts_skipped"`

	// Details contains additional breakdown stats (e.g., reset_count, timeout_count).
	Details map[string]int `json:"details,omitempty"`
}

// StatsProvider abstracts the stats source for testability.
// The detection.Detector implements this interface via its Stats() method.
type StatsProvider interface {
	Stats() map[string]int
}

// FromDetector extracts stats from the global detector singleton.
// This is the primary way to get stats in production code.
func FromDetector() Stats {
	return FromMap(detection.Default().Stats())
}

// FromProvider creates Stats from any StatsProvider.
// Useful for testing with mock providers.
func FromProvider(p StatsProvider) Stats {
	return FromMap(p.Stats())
}

// FromMap creates Stats from a raw map.
// This is useful for converting existing code that already has stats as a map.
func FromMap(m map[string]int) Stats {
	s := Stats{
		Details: make(map[string]int),
	}

	// Extract core fields
	if v, ok := m["connmon_total_drops"]; ok {
		s.DropsDetected = v
	}
	if v, ok := m["silentban_total_bans"]; ok {
		s.BansDetected = v
	}
	if v, ok := m["hosts_skipped"]; ok {
		s.HostsSkipped = v
	}

	// Copy all stats to Details for detailed reporting
	for k, v := range m {
		s.Details[k] = v
	}

	return s
}

// HasData returns true if any detection stats are non-zero.
// Use this to conditionally display the detection section.
func (s Stats) HasData() bool {
	return s.DropsDetected > 0 || s.BansDetected > 0 || s.HostsSkipped > 0
}

// Severity returns the severity level based on detection stats.
// Returns: "none", "info", "warning", or "error"
func (s Stats) Severity() string {
	if s.BansDetected > 0 {
		return "error"
	}
	if s.DropsDetected > 0 {
		return "warning"
	}
	if s.HostsSkipped > 0 {
		return "info"
	}
	return "none"
}

// ExitCodeContribution returns the exit code contribution for CI/CD.
// Returns: 0 (none/info), 1 (warning), 2 (error)
func (s Stats) ExitCodeContribution() int {
	switch s.Severity() {
	case "error":
		return 2
	case "warning":
		return 1
	default:
		return 0
	}
}

// ToJSON returns the stats as a map suitable for JSON marshaling.
// This ensures consistent JSON output across all callers.
func (s Stats) ToJSON() map[string]interface{} {
	result := map[string]interface{}{
		"drops_detected": s.DropsDetected,
		"bans_detected":  s.BansDetected,
		"hosts_skipped":  s.HostsSkipped,
	}

	if len(s.Details) > 0 {
		result["details"] = s.Details
	}

	return result
}
