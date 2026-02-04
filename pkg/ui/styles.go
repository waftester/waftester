package ui

import "github.com/charmbracelet/lipgloss"

// ANSI escape codes for simple terminal output (CLI commands)
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	BoldRed = "\033[1;31m"
)

// Color palette inspired by top security tools
var (
	// Brand colors
	Primary   = lipgloss.Color("#7D56F4") // Purple - brand color
	Secondary = lipgloss.Color("#00D4AA") // Cyan/Teal

	// Severity colors (matching OWASP/Nuclei standards)
	Critical = lipgloss.Color("#FF0000") // Bright red
	High     = lipgloss.Color("#FF6B6B") // Red/Orange
	Medium   = lipgloss.Color("#FFD93D") // Yellow
	Low      = lipgloss.Color("#6BCB77") // Green
	Info     = lipgloss.Color("#4D96FF") // Blue

	// Status colors
	Success = lipgloss.Color("#00D26A") // Bright green
	Warning = lipgloss.Color("#FFB800") // Amber
	Error   = lipgloss.Color("#FF3838") // Red
	Muted   = lipgloss.Color("#6B7280") // Gray

	// Outcome colors
	Blocked = lipgloss.Color("#00D26A") // Green - WAF did its job
	Pass    = lipgloss.Color("#00D26A") // Green
	Fail    = lipgloss.Color("#FF3838") // Red - payload got through
	Errored = lipgloss.Color("#FFB800") // Yellow

	// HTTP status code colors
	Status2xx = lipgloss.Color("#00D26A") // Green
	Status3xx = lipgloss.Color("#4D96FF") // Blue
	Status4xx = lipgloss.Color("#FFD93D") // Yellow
	Status5xx = lipgloss.Color("#FF3838") // Red

	// Background colors
	DarkBg  = lipgloss.Color("#1A1A2E")
	LightBg = lipgloss.Color("#16213E")
)

// Pre-configured styles
var (
	// Title and headers
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(Primary).
			Padding(0, 1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(Muted).
			Italic(true)

	// Banner style
	BannerStyle = lipgloss.NewStyle().
			Foreground(Primary).
			Bold(true)

	// Version badge
	VersionStyle = lipgloss.NewStyle().
			Foreground(Secondary).
			Bold(true)

	// Section headers
	SectionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Bold(true).
			MarginTop(1)

	// Configuration display
	ConfigLabelStyle = lipgloss.NewStyle().
				Foreground(Muted).
				Width(15)

	ConfigValueStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FAFAFA"))

	// Progress bar
	ProgressFullStyle = lipgloss.NewStyle().
				Foreground(Primary)

	ProgressEmptyStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#3B3B4F"))

	// Statistics
	StatLabelStyle = lipgloss.NewStyle().
			Foreground(Muted)

	StatValueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Bold(true)

	// Bracketed metadata (nuclei-style)
	BracketStyle = lipgloss.NewStyle().
			Foreground(Muted)

	// Outcome styles
	BlockedStyle = lipgloss.NewStyle().
			Foreground(Blocked).
			Bold(true)

	PassStyle = lipgloss.NewStyle().
			Foreground(Pass).
			Bold(true)

	FailStyle = lipgloss.NewStyle().
			Foreground(Fail).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(Errored).
			Bold(true)

	// Divider
	DividerStyle = lipgloss.NewStyle().
			Foreground(Muted)

	// Help/footer
	HelpStyle = lipgloss.NewStyle().
			Foreground(Muted).
			Italic(true)

	// URL style
	URLStyle = lipgloss.NewStyle().
			Foreground(Secondary).
			Underline(true)

	// Category badge
	CategoryStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#3B3B4F")).
			Padding(0, 1)

	// Spinner frames
	SpinnerStyle = lipgloss.NewStyle().
			Foreground(Primary)
)

// SeverityStyle returns the appropriate style for a severity level
func SeverityStyle(severity string) lipgloss.Style {
	base := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch severity {
	case "Critical":
		return base.Foreground(lipgloss.Color("#FFFFFF")).Background(Critical)
	case "High":
		return base.Foreground(lipgloss.Color("#FFFFFF")).Background(High)
	case "Medium":
		return base.Foreground(lipgloss.Color("#000000")).Background(Medium)
	case "Low":
		return base.Foreground(lipgloss.Color("#000000")).Background(Low)
	case "Info":
		return base.Foreground(lipgloss.Color("#FFFFFF")).Background(Info)
	default:
		return base.Foreground(Muted)
	}
}

// StatusCodeStyle returns the appropriate style for HTTP status codes
func StatusCodeStyle(code int) lipgloss.Style {
	base := lipgloss.NewStyle().Bold(true)
	switch {
	case code >= 200 && code < 300:
		return base.Foreground(Status2xx)
	case code >= 300 && code < 400:
		return base.Foreground(Status3xx)
	case code >= 400 && code < 500:
		return base.Foreground(Status4xx)
	case code >= 500:
		return base.Foreground(Status5xx)
	default:
		return base.Foreground(Muted)
	}
}

// OutcomeStyle returns the appropriate style for test outcomes
func OutcomeStyle(outcome string) lipgloss.Style {
	base := lipgloss.NewStyle().Bold(true)
	switch outcome {
	case "Blocked":
		return base.Foreground(Blocked)
	case "Pass":
		return base.Foreground(Pass)
	case "Fail":
		return base.Foreground(Fail)
	case "Error":
		return base.Foreground(Errored)
	default:
		return base.Foreground(Muted)
	}
}
