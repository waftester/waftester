package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Version information - these can be overridden at build time via ldflags:
// go build -ldflags "-X github.com/waftester/waftester/pkg/ui.Version=1.0.0"
var (
	Version   = "2.3.5"
	BuildDate = "2026-02-02"
	Commit    = "dev"
)

const (
	Author  = "WAFtester Team"
	Website = "https://waftester.com"
)

// UserAgent returns the standard User-Agent string for WAFtester requests
func UserAgent() string {
	return fmt.Sprintf("waftester/%s", Version)
}

// UserAgentWithContext returns a User-Agent with context (e.g., "waftester/X.Y.Z (Calibration)")
func UserAgentWithContext(context string) string {
	return fmt.Sprintf("waftester/%s (%s)", Version, context)
}

// Global UI state
var (
	silentMode  bool
	noColorMode bool
	uiMu        sync.RWMutex
)

// SetSilent enables or disables silent mode (suppresses most output)
func SetSilent(silent bool) {
	uiMu.Lock()
	defer uiMu.Unlock()
	silentMode = silent
}

// IsSilent returns whether silent mode is enabled
func IsSilent() bool {
	uiMu.RLock()
	defer uiMu.RUnlock()
	return silentMode
}

// SetNoColor disables colored output
func SetNoColor(noColor bool) {
	uiMu.Lock()
	defer uiMu.Unlock()
	noColorMode = noColor
	if noColor {
		// Use ASCII profile to disable colors
		lipgloss.SetColorProfile(termenv.Ascii)
	}
}

// IsNoColor returns whether color is disabled
func IsNoColor() bool {
	uiMu.RLock()
	defer uiMu.RUnlock()
	return noColorMode
}

// ASCII art banner - nuclei/httpx inspired design
const bannerArt = `
               ____          __            __           
 _      ____  / __/         / /____  _____/ /____  _____
| | /| / / _ \/ /_   ____  / __/ _ \/ ___/ __/ _ \/ ___/
| |/ |/ /  __/ __/  /___/ / /_/  __(__  ) /_/  __/ /    
|__/|__/\___/_/           \__/\___/____/\__/\___/_/     
`

// Compact banner for smaller terminals
const compactBanner = `
               ____          __            __           
 _      ____  / __/         / /____  _____/ /____  _____
| | /| / / _ \/ /_   ____  / __/ _ \/ ___/ __/ _ \/ ___/
| |/ |/ /  __/ __/  /___/ / /_/  __(__  ) /_/  __/ /    
|__/|__/\___/_/           \__/\___/____/\__/\___/_/     
`

// Minimalist banner (ffuf-style box)
const miniBanner = `
________________________________________________

 waf-tester v%s
________________________________________________`

// Separator line
const bannerSeparator = "________________________________________________"

// PrintBanner prints the httpx/nuclei-style application banner with version info
func PrintBanner() {
	// Print the styled banner to stderr (like httpx/nuclei)
	lines := strings.Split(bannerArt, "\n")
	for _, line := range lines {
		if line != "" {
			fmt.Fprintln(os.Stderr, BannerStyle.Render(line))
		}
	}

	// Version line centered below banner (httpx-style)
	fmt.Fprintf(os.Stderr, "                       v%s\n", VersionStyle.Render(Version))
	fmt.Fprintf(os.Stderr, "\n\t\twaftester.com\n\n")
}

// PrintCompactBanner prints a smaller banner for constrained environments
func PrintCompactBanner() {
	lines := strings.Split(compactBanner, "\n")
	for _, line := range lines {
		if line != "" {
			fmt.Fprintln(os.Stderr, BannerStyle.Render(line))
		}
	}
	fmt.Fprintf(os.Stderr, "                       v%s\n\n", VersionStyle.Render(Version))
}

// PrintMiniBanner prints the minimal banner (ffuf-style box)
func PrintMiniBanner() {
	fmt.Fprintf(os.Stderr, "%s\n", BannerStyle.Render(fmt.Sprintf(miniBanner, Version)))
	fmt.Fprintln(os.Stderr)
}

// printOption prints a configuration option in ffuf/nuclei style
// Format:  :: Option              : Value
func printOption(name, value string) {
	fmt.Fprintf(os.Stderr, " :: %-20s : %s\n", ConfigLabelStyle.Render(name), ConfigValueStyle.Render(value))
}

// PrintConfigBanner prints the configuration banner like ffuf/nuclei
// This shows all the current settings before execution starts
// Uses ordered keys for consistent display
func PrintConfigBanner(options map[string]string) {
	// Define display order for config options (ffuf-style)
	order := []string{
		"Target", "Method", "Payload Dir", "Category", "Min Severity",
		"Test Plan", "Concurrency", "Rate Limit", "Timeout",
		"Match Codes", "Filter Codes", "Calibration",
		"Output", "Format", "Proxy",
	}

	// Print in defined order first
	printed := make(map[string]bool)
	for _, name := range order {
		if value, ok := options[name]; ok && value != "" {
			printOption(name, value)
			printed[name] = true
		}
	}

	// Print any remaining options not in the order list
	for name, value := range options {
		if !printed[name] && value != "" {
			printOption(name, value)
		}
	}

	fmt.Fprintf(os.Stderr, "%s\n\n", DividerStyle.Render(bannerSeparator))
}

// PrintDivider prints a stylized divider (to stderr)
func PrintDivider() {
	divider := strings.Repeat("-", 75)
	fmt.Fprintln(os.Stderr, DividerStyle.Render(divider))
}

// PrintSection prints a section header (to stderr)
func PrintSection(title string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, SectionStyle.Render("> "+title))
	PrintDivider()
}

// PrintConfig prints configuration in a nice format
func PrintConfig(config map[string]string) {
	if IsSilent() {
		return
	}

	maxKeyLen := 0
	for key := range config {
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
	}

	for key, value := range config {
		paddedKey := key + strings.Repeat(" ", maxKeyLen-len(key))
		fmt.Fprintf(os.Stderr, "  %s : %s\n",
			ConfigLabelStyle.Render(paddedKey),
			ConfigValueStyle.Render(value),
		)
	}
}

// PrintConfigLine prints a single config line
func PrintConfigLine(key, value string) {
	if IsSilent() {
		return
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		ConfigLabelStyle.Render(key+":"),
		ConfigValueStyle.Render(value),
	)
}

// PrintBracketedInfo prints nuclei-style bracketed information
// Example: [critical] [sqli] https://example.com [payload-id]
func PrintBracketedInfo(parts ...BracketPart) {
	if IsSilent() {
		return
	}

	var output strings.Builder
	for _, part := range parts {
		output.WriteString(BracketStyle.Render("["))
		output.WriteString(part.Style.Render(part.Text))
		output.WriteString(BracketStyle.Render("] "))
	}
	fmt.Fprintln(os.Stderr, output.String())
}

// BracketPart represents a piece of bracketed output
type BracketPart struct {
	Text  string
	Style Style
}

// Style is a simplified style type for bracket parts
type Style = lipgloss.Style

// Helper functions for creating bracket parts
func SeverityBracket(severity string) BracketPart {
	return BracketPart{
		Text:  strings.ToLower(severity),
		Style: SeverityStyle(severity),
	}
}

func CategoryBracket(category string) BracketPart {
	return BracketPart{
		Text:  category,
		Style: CategoryStyle,
	}
}

func OutcomeBracket(outcome string) BracketPart {
	return BracketPart{
		Text:  strings.ToLower(outcome),
		Style: OutcomeStyle(outcome),
	}
}

func TextBracket(text string) BracketPart {
	return BracketPart{
		Text:  text,
		Style: lipgloss.NewStyle().Foreground(lipgloss.Color("#FAFAFA")),
	}
}

func MutedBracket(text string) BracketPart {
	return BracketPart{
		Text:  text,
		Style: lipgloss.NewStyle().Foreground(Muted),
	}
}

// PrintHelp prints contextual help (to stderr like ffuf/nuclei)
func PrintHelp(text string) {
	fmt.Fprintln(os.Stderr, HelpStyle.Render("  [i] "+text))
}

// PrintSuccess prints a success message (to stderr)
func PrintSuccess(message string) {
	fmt.Fprintln(os.Stderr, PassStyle.Render("  [+] "+message))
}

// PrintError prints an error message (to stderr)
func PrintError(message string) {
	fmt.Fprintln(os.Stderr, FailStyle.Render("  [X] "+message))
}

// PrintWarning prints a warning message (to stderr)
func PrintWarning(message string) {
	fmt.Fprintln(os.Stderr, ErrorStyle.Render("  [!] "+message))
}

// PrintInfo prints an info message (to stderr)
func PrintInfo(message string) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", SpinnerStyle.Render("*"), message)
}

// PrintResult prints a live result line in nuclei/httpx style
// Format: [timestamp] [severity] [category] target [status] [outcome] [latency]
func PrintResult(id, category, severity, outcome string, statusCode int, latencyMs int64, target string, showTimestamp bool) {
	var output strings.Builder

	// Timestamp (optional, like nuclei's -ts flag)
	if showTimestamp {
		ts := time.Now().Format("15:04:05")
		output.WriteString(BracketStyle.Render("["))
		output.WriteString(StatValueStyle.Render(ts))
		output.WriteString(BracketStyle.Render("] "))
	}

	// Severity badge
	output.WriteString(BracketStyle.Render("["))
	output.WriteString(SeverityStyle(severity).Render(strings.ToLower(severity)))
	output.WriteString(BracketStyle.Render("] "))

	// Category
	output.WriteString(BracketStyle.Render("["))
	output.WriteString(CategoryStyle.Render(category))
	output.WriteString(BracketStyle.Render("] "))

	// Target/ID
	output.WriteString(ConfigValueStyle.Render(id))
	output.WriteString(" ")

	// Status code (colorized)
	output.WriteString(BracketStyle.Render("["))
	output.WriteString(StatusCodeStyle(statusCode).Render(fmt.Sprintf("%d", statusCode)))
	output.WriteString(BracketStyle.Render("] "))

	// Outcome
	output.WriteString(BracketStyle.Render("["))
	output.WriteString(OutcomeStyle(outcome).Render(strings.ToLower(outcome)))
	output.WriteString(BracketStyle.Render("] "))

	// Latency
	output.WriteString(BracketStyle.Render("["))
	output.WriteString(StatLabelStyle.Render(fmt.Sprintf("%dms", latencyMs)))
	output.WriteString(BracketStyle.Render("]"))

	if !IsSilent() {
		fmt.Fprintln(os.Stderr, output.String())
	}
}

// PrintResultCompact prints a compact result line (ffuf-style)
// Format: target [Status: 403, Size: 1234, Duration: 45ms]
func PrintResultCompact(id string, statusCode, size int, latencyMs int64) {
	if IsSilent() {
		return
	}

	var output strings.Builder

	output.WriteString(ConfigValueStyle.Render(id))
	output.WriteString(" ")
	output.WriteString(BracketStyle.Render("["))

	// Status with color
	output.WriteString("Status: ")
	output.WriteString(StatusCodeStyle(statusCode).Render(fmt.Sprintf("%d", statusCode)))
	output.WriteString(", ")

	// Size
	output.WriteString(fmt.Sprintf("Size: %d, ", size))

	// Duration
	output.WriteString(fmt.Sprintf("Duration: %dms", latencyMs))

	output.WriteString(BracketStyle.Render("]"))

	fmt.Fprintln(os.Stderr, output.String())
}
