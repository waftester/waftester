package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ResultFormatter formats test results for display
type ResultFormatter struct {
	verbose     bool
	showPayload bool
}

// NewResultFormatter creates a new result formatter
func NewResultFormatter(verbose, showPayload bool) *ResultFormatter {
	return &ResultFormatter{
		verbose:     verbose,
		showPayload: showPayload,
	}
}

// FormatResult formats a single test result in nuclei-style
// Output: [severity] [category] [outcome] test-id [status-code] [latency]
func (rf *ResultFormatter) FormatResult(id, category, severity, outcome string, statusCode int, latencyMs int64, payload string) string {
	var parts []string

	// Severity badge
	sevStyle := SeverityStyle(severity)
	parts = append(parts, BracketStyle.Render("[")+sevStyle.Render(strings.ToLower(severity))+BracketStyle.Render("]"))

	// Category
	parts = append(parts, BracketStyle.Render("[")+CategoryStyle.Render(category)+BracketStyle.Render("]"))

	// Outcome
	outcomeStyle := OutcomeStyle(outcome)
	parts = append(parts, BracketStyle.Render("[")+outcomeStyle.Render(strings.ToLower(outcome))+BracketStyle.Render("]"))

	// Test ID
	parts = append(parts, StatValueStyle.Render(id))

	// Status code
	statusStyle := StatusCodeStyle(statusCode)
	parts = append(parts, BracketStyle.Render("[")+statusStyle.Render(fmt.Sprintf("%d", statusCode))+BracketStyle.Render("]"))

	// Latency
	latencyStr := formatLatency(latencyMs)
	parts = append(parts, BracketStyle.Render("[")+StatLabelStyle.Render(latencyStr)+BracketStyle.Render("]"))

	result := strings.Join(parts, " ")

	// Add payload if verbose
	if rf.showPayload && payload != "" {
		truncatedPayload := truncateString(payload, 60)
		result += "\n      " + SubtitleStyle.Render("-> "+truncatedPayload)
	}

	return result
}

// FormatFailure formats a failed test with more detail
func (rf *ResultFormatter) FormatFailure(id, category, severity string, statusCode int, latencyMs int64, payload string) string {
	output := strings.Builder{}

	// Header line
	output.WriteString(FailStyle.Render("  [X] BYPASS DETECTED"))
	output.WriteString("\n")

	// Details
	output.WriteString(fmt.Sprintf("    %s %s\n",
		ConfigLabelStyle.Render("ID:"),
		StatValueStyle.Render(id),
	))
	output.WriteString(fmt.Sprintf("    %s %s\n",
		ConfigLabelStyle.Render("Category:"),
		CategoryStyle.Render(category),
	))
	output.WriteString(fmt.Sprintf("    %s %s\n",
		ConfigLabelStyle.Render("Severity:"),
		SeverityStyle(severity).Render(severity),
	))
	output.WriteString(fmt.Sprintf("    %s %s\n",
		ConfigLabelStyle.Render("Status:"),
		StatusCodeStyle(statusCode).Render(fmt.Sprintf("%d", statusCode)),
	))
	output.WriteString(fmt.Sprintf("    %s %s\n",
		ConfigLabelStyle.Render("Latency:"),
		StatLabelStyle.Render(formatLatency(latencyMs)),
	))

	if payload != "" {
		output.WriteString(fmt.Sprintf("    %s %s\n",
			ConfigLabelStyle.Render("Payload:"),
			SubtitleStyle.Render(truncateString(payload, 80)),
		))
	}

	return output.String()
}

// FormatError formats an error result
func (rf *ResultFormatter) FormatError(id, category, errorMsg string) string {
	return fmt.Sprintf("  %s %s %s %s: %s",
		ErrorStyle.Render("!"),
		BracketStyle.Render("[")+CategoryStyle.Render(category)+BracketStyle.Render("]"),
		StatValueStyle.Render(id),
		ErrorStyle.Render("Error"),
		SubtitleStyle.Render(truncateString(errorMsg, 50)),
	)
}

// formatLatency formats latency in a human-readable way
func formatLatency(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.2fs", float64(ms)/1000)
}

// truncateString truncates a string with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// StatusBracket returns a formatted status code bracket
func StatusBracket(code int) string {
	statusStyle := StatusCodeStyle(code)
	return statusStyle.Render(fmt.Sprintf("%d", code))
}

// Summary holds test execution summary data
type Summary struct {
	TotalTests     int
	BlockedTests   int
	PassedTests    int
	FailedTests    int
	ErrorTests     int
	Duration       time.Duration
	RequestsPerSec float64
	TargetURL      string
	Category       string
	Severity       string
}

// PrintSummary prints a beautiful summary box
func PrintSummary(s Summary) {
	fmt.Println()
	PrintSection("Execution Summary")
	fmt.Println()

	// Target info
	fmt.Printf("  %s %s\n",
		ConfigLabelStyle.Render("Target:"),
		URLStyle.Render(s.TargetURL),
	)

	if s.Category != "" {
		fmt.Printf("  %s %s\n",
			ConfigLabelStyle.Render("Category:"),
			CategoryStyle.Render(s.Category),
		)
	}

	if s.Severity != "" {
		fmt.Printf("  %s %s\n",
			ConfigLabelStyle.Render("Severity:"),
			SeverityStyle(s.Severity).Render(s.Severity+"+"),
		)
	}

	fmt.Println()

	// Results box - simple fixed-width layout
	// Use simple ASCII to avoid Unicode width issues
	boxWidth := 50

	topBorder := "+" + strings.Repeat("-", boxWidth-2) + "+"
	bottomBorder := "+" + strings.Repeat("-", boxWidth-2) + "+"
	separator := "+" + strings.Repeat("-", boxWidth-2) + "+"

	fmt.Println(BracketStyle.Render("  " + topBorder))

	// Simple row format: "|  Label:          Value                    |"
	printRow := func(label string, value string, valueStyle lipgloss.Style) {
		// Fixed widths: label=18, value fills rest
		const labelW = 18
		const totalInner = 46 // boxWidth - 4 for borders and spaces

		// Pad label to fixed width
		labelPadded := label
		for len(labelPadded) < labelW {
			labelPadded += " "
		}

		// Calculate value padding (use rune count for visible width)
		valueW := totalInner - labelW
		valuePadded := value
		for len([]rune(valuePadded)) < valueW {
			valuePadded += " "
		}

		fmt.Printf("  |  %s%s|\n",
			StatLabelStyle.Render(labelPadded),
			valueStyle.Render(valuePadded),
		)
	}

	// Total tests
	printRow("Total Tests:", fmt.Sprintf("%d", s.TotalTests), StatValueStyle)

	// Separator
	fmt.Println(BracketStyle.Render("  " + separator))

	// Results breakdown - use simple text symbols
	printRow("Blocked (WAF):", fmt.Sprintf("[OK] %d", s.BlockedTests), BlockedStyle)
	printRow("Passed:", fmt.Sprintf("[--] %d", s.PassedTests), PassStyle)
	printRow("Failed (Bypass):", fmt.Sprintf("[!!] %d", s.FailedTests), FailStyle)
	printRow("Errors:", fmt.Sprintf("[??] %d", s.ErrorTests), ErrorStyle)

	// Separator
	fmt.Println(BracketStyle.Render("  " + separator))

	// Performance stats
	printRow("Duration:", formatDuration(s.Duration), StatValueStyle)
	printRow("Req/sec:", fmt.Sprintf("%.1f", s.RequestsPerSec), StatValueStyle)

	fmt.Println(BracketStyle.Render("  " + bottomBorder))

	// WAF effectiveness = Blocked / (Blocked + Failed)
	// This measures what % of attack payloads were stopped by the WAF
	fmt.Println()
	attackTests := s.BlockedTests + s.FailedTests
	var effectiveness float64
	if attackTests > 0 {
		effectiveness = float64(s.BlockedTests) / float64(attackTests) * 100
	} else {
		effectiveness = 0 // No attack tests executed
	}
	PrintWAFEffectiveness(effectiveness)

	// Final verdict
	fmt.Println()
	if s.FailedTests > 0 {
		PrintError(fmt.Sprintf("%d payloads bypassed the WAF - Review required!", s.FailedTests))
	} else if s.ErrorTests > s.TotalTests/10 {
		PrintWarning("High error rate detected - check connectivity")
	} else {
		PrintSuccess("All attack payloads were blocked by the WAF")
	}
	fmt.Println()
}

// PrintWAFEffectiveness prints a visual WAF effectiveness meter
func PrintWAFEffectiveness(percent float64) {
	barWidth := 25

	var color lipgloss.Color
	var icon string
	switch {
	case percent >= 99:
		color = lipgloss.Color("#00D26A")
		icon = "[+]"
	case percent >= 95:
		color = lipgloss.Color("#6BCB77")
		icon = "[+]"
	case percent >= 90:
		color = lipgloss.Color("#FFD93D")
		icon = "[!]"
	case percent >= 80:
		color = lipgloss.Color("#FF6B6B")
		icon = "[!]"
	default:
		color = lipgloss.Color("#FF0000")
		icon = "[X]"
	}

	filled := int(float64(barWidth) * percent / 100)
	bar := strings.Builder{}
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar.WriteString(lipgloss.NewStyle().Foreground(color).Render("#"))
		} else {
			bar.WriteString(ProgressEmptyStyle.Render("."))
		}
	}

	percentStyle := lipgloss.NewStyle().Foreground(color).Bold(true)

	// Print on single line - avoid style rendering issues
	labelStyled := StatLabelStyle.Render("WAF Effectiveness: ")
	fmt.Printf("  %s%s %s %s %s\n",
		labelStyled,
		bar.String(),
		percentStyle.Render(fmt.Sprintf("%.1f%%", percent)),
		icon,
		getEffectivenessRating(percent),
	)
}

// getEffectivenessRating returns a text rating for effectiveness
func getEffectivenessRating(percent float64) string {
	switch {
	case percent >= 99:
		return PassStyle.Render("Excellent")
	case percent >= 95:
		return PassStyle.Render("Good")
	case percent >= 90:
		return ErrorStyle.Render("Fair")
	case percent >= 80:
		return ErrorStyle.Render("Poor")
	default:
		return FailStyle.Render("Critical")
	}
}

// padRight pads a string to the right to reach a specific width
// Uses lipgloss.Width to correctly measure visible width (excludes ANSI codes)
func padRight(s string, width int) string {
	visibleWidth := lipgloss.Width(s)
	padding := width - visibleWidth
	if padding <= 0 {
		return s
	}
	return s + strings.Repeat(" ", padding)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// PrintLiveResult prints a single result during execution (for verbose mode)
func PrintLiveResult(outcome, id, category, severity string, statusCode int) {
	switch outcome {
	case "Fail":
		fmt.Printf("\n  %s %s %s %s %s\n",
			FailStyle.Render("[X]"),
			SeverityStyle(severity).Render(strings.ToLower(severity)),
			BracketStyle.Render("[")+CategoryStyle.Render(category)+BracketStyle.Render("]"),
			StatValueStyle.Render(id),
			StatusCodeStyle(statusCode).Render(fmt.Sprintf("[%d]", statusCode)),
		)
	case "Error":
		fmt.Printf("\n  %s %s %s\n",
			ErrorStyle.Render("[!]"),
			BracketStyle.Render("[")+CategoryStyle.Render(category)+BracketStyle.Render("]"),
			StatValueStyle.Render(id),
		)
	}
}
