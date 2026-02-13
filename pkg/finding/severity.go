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

// ToSonarQube maps severity to SonarQube Generic Issue Import severity.
// Critical → CRITICAL, High → MAJOR, Medium → MINOR, Low/Info → INFO.
// See: https://docs.sonarqube.org/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/
func (s Severity) ToSonarQube() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "MAJOR"
	case Medium:
		return "MINOR"
	default:
		return "INFO"
	}
}

// ToGitLab maps severity to GitLab SAST severity.
// Critical → Critical, High → High, Medium → Medium, Low → Low, Info → Info.
// See: https://docs.gitlab.com/ee/development/integrations/secure.html
func (s Severity) ToGitLab() string {
	switch s {
	case Critical:
		return "Critical"
	case High:
		return "High"
	case Medium:
		return "Medium"
	case Low:
		return "Low"
	default:
		return "Info"
	}
}

// ToSARIF maps severity to SARIF result level.
// Critical/High → error, Medium → warning, Low/Info → note.
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
func (s Severity) ToSARIF() string {
	switch s {
	case Critical, High:
		return "error"
	case Medium:
		return "warning"
	default:
		return "note"
	}
}

// ToSARIFScore maps severity to GitHub security-severity score.
// These scores align with GitHub Advanced Security severity thresholds.
func (s Severity) ToSARIFScore() string {
	switch s {
	case Critical:
		return "9.5"
	case High:
		return "8.0"
	case Medium:
		return "5.5"
	case Low:
		return "2.0"
	default:
		return "0.0"
	}
}
