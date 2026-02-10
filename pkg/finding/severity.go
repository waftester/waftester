package finding

// Severity represents the severity level of a security finding.
// All values are lowercase strings matching the existing codebase
// convention used across 28 attack packages.
type Severity string

const (
	// Critical represents immediate system compromise (RCE, auth bypass).
	Critical Severity = "critical"

	// High represents significant impact requiring prompt fix (SQLi, stored XSS).
	High Severity = "high"

	// Medium represents moderate impact (reflected XSS, CSRF).
	Medium Severity = "medium"

	// Low represents limited impact (verbose errors, minor info leak).
	Low Severity = "low"

	// Info represents informational findings with no direct security impact.
	Info Severity = "info"
)

// IsValid reports whether s is a recognized severity level.
func (s Severity) IsValid() bool {
	switch s {
	case Critical, High, Medium, Low, Info:
		return true
	}
	return false
}

// Score returns a numeric score for sorting and comparison.
// Critical=5, High=4, Medium=3, Low=2, Info=1, Unknown=0.
func (s Severity) Score() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// String returns the severity as a string.
func (s Severity) String() string {
	return string(s)
}
