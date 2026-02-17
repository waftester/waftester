// Package writers provides output writers for various formats.
package writers

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
	"golang.org/x/term"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*TableWriter)(nil)

// ANSI color constants for terminal output (legacy, kept for compatibility).
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[91m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorBlue   = "\033[94m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// colorEnabled controls whether ANSI color codes are emitted.
var colorEnabled = true

// ansiSprint wraps text in an ANSI escape code, respecting colorEnabled.
func ansiSprint(code string, a ...interface{}) string {
	s := fmt.Sprint(a...)
	if !colorEnabled {
		return s
	}
	return code + s + "\033[0m"
}

// Color functions using ANSI escape codes for terminal colorization.
var (
	// Severity colors
	fmtCritical = func(a ...interface{}) string { return ansiSprint("\033[1;91m", a...) }
	fmtHigh     = func(a ...interface{}) string { return ansiSprint("\033[31m", a...) }
	fmtMedium   = func(a ...interface{}) string { return ansiSprint("\033[33m", a...) }
	fmtLow      = func(a ...interface{}) string { return ansiSprint("\033[34m", a...) }
	fmtInfo     = func(a ...interface{}) string { return ansiSprint("\033[36m", a...) }

	// Outcome colors
	fmtBlocked = func(a ...interface{}) string { return ansiSprint("\033[32m", a...) }
	fmtBypass  = func(a ...interface{}) string { return ansiSprint("\033[1;91m", a...) }
	fmtError   = func(a ...interface{}) string { return ansiSprint("\033[35m", a...) }
	fmtTimeout = func(a ...interface{}) string { return ansiSprint("\033[33m", a...) }
	fmtPass    = func(a ...interface{}) string { return ansiSprint("\033[32m", a...) }

	// Formatting helpers
	fmtBold = func(a ...interface{}) string { return ansiSprint("\033[1m", a...) }
	fmtDim  = func(a ...interface{}) string { return ansiSprint("\033[2m", a...) }
)

// colorSeverity returns a colorized severity string.
func colorSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return fmtCritical(severity)
	case "high":
		return fmtHigh(severity)
	case "medium":
		return fmtMedium(severity)
	case "low":
		return fmtLow(severity)
	default:
		return fmtInfo(severity)
	}
}

// colorOutcome returns a colorized outcome string.
func colorOutcome(outcome string) string {
	switch strings.ToLower(outcome) {
	case "blocked", "pass":
		return fmtBlocked(outcome)
	case "fail", "bypass":
		return fmtBypass(outcome)
	case "error":
		return fmtError(outcome)
	case "timeout":
		return fmtTimeout(outcome)
	default:
		return outcome
	}
}

// severityColors maps severity levels to ANSI color codes (legacy).
var severityColors = map[string]string{
	"critical": "\033[91m\033[1m", // bright red + bold
	"high":     "\033[38;5;208m",  // orange
	"medium":   "\033[93m",        // bright yellow
	"low":      "\033[92m",        // bright green
	"info":     "\033[94m",        // bright blue
}

// outcomeColors maps outcomes to ANSI color codes (legacy).
var outcomeColors = map[events.Outcome]string{
	events.OutcomeBypass:  colorRed,
	events.OutcomeBlocked: colorGreen,
	events.OutcomeError:   colorYellow,
	events.OutcomeTimeout: colorBlue,
	events.OutcomePass:    colorGreen,
}

// boxChars contains Unicode box-drawing characters.
var boxChars = struct {
	TopLeft, TopRight, BottomLeft, BottomRight, Horizontal, Vertical string
}{
	"┌", "┐", "└", "┘", "─", "│",
}

// asciiChars contains ASCII fallback characters for box drawing.
var asciiChars = struct {
	TopLeft, TopRight, BottomLeft, BottomRight, Horizontal, Vertical string
}{
	"+", "+", "+", "+", "-", "|",
}

// TableConfig configures the table writer behavior.
type TableConfig struct {
	// Mode controls the output detail level: "summary", "detailed", "minimal", "streaming"
	Mode string

	// ColorEnabled enables ANSI color output.
	// If not explicitly set, auto-detected based on terminal.
	ColorEnabled bool

	// UnicodeEnabled enables Unicode box-drawing characters.
	// Defaults to true. Set to false and DisableUnicode to true for ASCII fallback.
	UnicodeEnabled bool

	// DisableUnicode explicitly disables Unicode when set to true.
	// This allows distinguishing between "not set" (use Unicode) and "explicitly disabled".
	DisableUnicode bool

	// ShowOnlyBypasses filters output to show only bypass results.
	ShowOnlyBypasses bool

	// MaxResults limits the number of results displayed (0 = unlimited).
	MaxResults int

	// Width sets the table width (0 = auto-detect from terminal).
	Width int

	// MaxWidth sets the maximum table width (0 = no maximum, use terminal width).
	MaxWidth int

	// ShowTimestamps adds timestamps to each result row.
	ShowTimestamps bool

	// ShowCurlCommand enables cURL command display for each request.
	ShowCurlCommand bool

	// ShowLegend displays a severity color legend at the end of output.
	ShowLegend bool

	// TruncateAt sets the response/payload truncation length (0 = no truncation).
	TruncateAt int

	// ShowDeduplication indicates duplicate payloads in results.
	ShowDeduplication bool
}

// TableWriter writes events as formatted ASCII/Unicode tables to a terminal.
// It supports streaming mode for real-time output and batch mode for final reports.
// The writer is safe for concurrent use.
type TableWriter struct {
	w              io.Writer
	mu             sync.Mutex
	config         TableConfig
	results        []*events.ResultEvent
	progressEvents []*events.ProgressEvent
	summary        *events.SummaryEvent
	chars          *struct {
		TopLeft, TopRight, BottomLeft, BottomRight, Horizontal, Vertical string
	}
	resultCount  int
	seenPayloads map[string]int // tracks payload hashes for deduplication display
	columnWidths columnWidths   // cached responsive column widths
}

// columnWidths stores calculated column widths for responsive table layout.
type columnWidths struct {
	outcome  int
	severity int
	category int
	testID   int
	url      int
}

// NewTableWriter creates a new table writer with the specified configuration.
// If ColorEnabled is not explicitly set, it auto-detects terminal support.
// UnicodeEnabled defaults to true unless DisableUnicode is set.
func NewTableWriter(w io.Writer, config TableConfig) *TableWriter {
	// Auto-detect color support if not explicitly configured
	if !config.ColorEnabled {
		config.ColorEnabled = detectColorSupport(w)
	}

	// Configure color output based on our color detection
	colorEnabled = config.ColorEnabled

	// Default mode to summary
	if config.Mode == "" {
		config.Mode = "summary"
	}

	// Select box-drawing character set
	// Use Unicode by default, ASCII only if explicitly disabled
	chars := &boxChars
	if config.DisableUnicode {
		chars = &asciiChars
	}

	tw := &TableWriter{
		w:            w,
		config:       config,
		results:      make([]*events.ResultEvent, 0),
		chars:        chars,
		seenPayloads: make(map[string]int),
	}

	// Calculate responsive column widths
	tw.calculateColumnWidths()

	return tw
}

// detectColorSupport checks if the writer supports ANSI colors.
func detectColorSupport(w io.Writer) bool {
	// Check for NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check for FORCE_COLOR environment variable
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}

	// Check if output is a terminal
	if f, ok := w.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}

	return false
}

// Write processes an event and outputs it according to the configured mode.
func (tw *TableWriter) Write(event events.Event) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	switch e := event.(type) {
	case *events.ResultEvent:
		return tw.handleResultEvent(e)
	case *events.ProgressEvent:
		return tw.handleProgressEvent(e)
	case *events.SummaryEvent:
		tw.summary = e
		return nil
	}
	return nil
}

// handleResultEvent processes a result event based on the mode.
func (tw *TableWriter) handleResultEvent(e *events.ResultEvent) error {
	// Filter bypasses only if configured
	if tw.config.ShowOnlyBypasses && e.Result.Outcome != events.OutcomeBypass {
		return nil
	}

	// Check max results limit
	if tw.config.MaxResults > 0 && tw.resultCount >= tw.config.MaxResults {
		return nil
	}

	tw.resultCount++

	// In streaming mode, output immediately
	if tw.config.Mode == "streaming" {
		return tw.writeStreamingResult(e)
	}

	// Otherwise buffer for later
	tw.results = append(tw.results, e)
	return nil
}

// handleProgressEvent processes a progress event in streaming mode.
func (tw *TableWriter) handleProgressEvent(e *events.ProgressEvent) error {
	if tw.config.Mode == "streaming" {
		return tw.writeStreamingProgress(e)
	}
	tw.progressEvents = append(tw.progressEvents, e)
	return nil
}

// writeStreamingResult outputs a single result in streaming mode.
func (tw *TableWriter) writeStreamingResult(e *events.ResultEvent) error {
	line := tw.formatResultLine(e)
	_, err := fmt.Fprintln(tw.w, line)
	return err
}

// writeStreamingProgress outputs a progress update in streaming mode.
func (tw *TableWriter) writeStreamingProgress(e *events.ProgressEvent) error {
	line := tw.formatProgressLine(e)
	_, err := fmt.Fprintf(tw.w, "\r%s", line)
	return err
}

// formatResultLine formats a single result for streaming output.
func (tw *TableWriter) formatResultLine(e *events.ResultEvent) string {
	outcome := strings.ToUpper(string(e.Result.Outcome))
	severity := string(e.Test.Severity)

	// Build optional prefix components
	var prefix string

	// Add timestamp if enabled
	if tw.config.ShowTimestamps {
		prefix = fmt.Sprintf("[%s] ", time.Now().Format("15:04:05"))
	}

	// Check for deduplication indicator
	var dedupMarker string
	if tw.config.ShowDeduplication && e.Evidence != nil {
		payloadHash := hashPayload(e.Evidence.Payload)
		if count, seen := tw.seenPayloads[payloadHash]; seen {
			dedupMarker = fmt.Sprintf(" [DUP:%d]", count)
			tw.seenPayloads[payloadHash] = count + 1
		} else {
			tw.seenPayloads[payloadHash] = 1
		}
	}

	if tw.config.ColorEnabled {
		coloredOutcome := colorOutcome(outcome)
		coloredSeverity := colorSeverity(severity)
		result := fmt.Sprintf("%s[%s] %-8s %s %s (%dms)%s",
			prefix,
			coloredOutcome,
			coloredSeverity,
			e.Test.Category,
			e.Test.ID,
			int(e.Result.LatencyMs),
			dedupMarker,
		)
		return result
	}

	return fmt.Sprintf("%s[%s] %-8s %s %s (%dms)%s",
		prefix,
		outcome,
		severity,
		e.Test.Category,
		e.Test.ID,
		int(e.Result.LatencyMs),
		dedupMarker,
	)
}

// formatProgressLine formats a progress update for streaming output.
func (tw *TableWriter) formatProgressLine(e *events.ProgressEvent) string {
	if tw.config.ColorEnabled {
		return fmt.Sprintf("%s[%s]%s %d/%d (%.1f%%) %s%.1f req/s%s ETA: %ds",
			colorBlue, e.Progress.Phase, colorReset,
			e.Progress.Current, e.Progress.Total, e.Progress.Percentage,
			colorDim, e.Rate.RequestsPerSec, colorReset,
			e.Timing.ETASec,
		)
	}

	return fmt.Sprintf("[%s] %d/%d (%.1f%%) %.1f req/s ETA: %ds",
		e.Progress.Phase,
		e.Progress.Current, e.Progress.Total, e.Progress.Percentage,
		e.Rate.RequestsPerSec,
		e.Timing.ETASec,
	)
}

// Flush ensures all buffered events are written.
// For streaming mode, this is typically a no-op.
func (tw *TableWriter) Flush() error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	// In streaming mode, nothing to flush
	if tw.config.Mode == "streaming" {
		return nil
	}

	return nil
}

// Close renders and writes the complete table output.
func (tw *TableWriter) Close() error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	var err error

	switch tw.config.Mode {
	case "streaming":
		// Write final newline and summary
		fmt.Fprintln(tw.w)
		if tw.summary != nil {
			err = tw.writeSummaryTable()
		}
	case "minimal":
		err = tw.writeMinimalOutput()
	case "detailed":
		err = tw.writeDetailedTable()
	default: // "summary"
		err = tw.writeSummaryTable()
	}

	if err != nil {
		return fmt.Errorf("table: write: %w", err)
	}

	// Render legend if enabled
	if tw.config.ShowLegend && tw.config.ColorEnabled {
		tw.renderLegend()
	}

	if closer, ok := tw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SupportsEvent returns true for result, progress, and summary events.
func (tw *TableWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeProgress, events.EventTypeSummary:
		return true
	default:
		return false
	}
}

// writeSummaryTable renders a summary-focused table.
func (tw *TableWriter) writeSummaryTable() error {
	sb := &strings.Builder{}

	// Header
	tw.writeTableHeader(sb, "WAF Test Summary")

	// WAF effectiveness score
	if tw.summary != nil {
		tw.writeEffectivenessScore(sb)
		tw.writeTotalsTable(sb)
		tw.writeSeverityBreakdown(sb)
	} else {
		// Generate stats from buffered results
		tw.writeResultsStats(sb)
	}

	// Top bypasses (limited)
	tw.writeTopBypasses(sb, 5)

	// Footer
	tw.writeTableFooter(sb)

	_, err := io.WriteString(tw.w, sb.String())
	return err
}

// writeDetailedTable renders a detailed table with all results.
func (tw *TableWriter) writeDetailedTable() error {
	sb := &strings.Builder{}

	// Header
	tw.writeTableHeader(sb, "WAF Test Results - Detailed")

	// All results table
	tw.writeResultsTable(sb)

	// Summary if available
	if tw.summary != nil {
		sb.WriteString("\n")
		tw.writeEffectivenessScore(sb)
		tw.writeTotalsTable(sb)
	}

	// Footer
	tw.writeTableFooter(sb)

	_, err := io.WriteString(tw.w, sb.String())
	return err
}

// writeMinimalOutput renders a minimal single-line summary.
func (tw *TableWriter) writeMinimalOutput() error {
	var bypasses, blocked, total int

	if tw.summary != nil {
		bypasses = tw.summary.Totals.Bypasses
		blocked = tw.summary.Totals.Blocked
		total = tw.summary.Totals.Tests
	} else {
		for _, r := range tw.results {
			total++
			switch r.Result.Outcome {
			case events.OutcomeBypass:
				bypasses++
			case events.OutcomeBlocked:
				blocked++
			}
		}
	}

	var effectiveness float64
	if total > 0 {
		effectiveness = float64(blocked) / float64(total) * 100
	}

	line := fmt.Sprintf("Tests: %d | Blocked: %d | Bypasses: %d | Effectiveness: %.1f%%",
		total, blocked, bypasses, effectiveness)

	if tw.config.ColorEnabled {
		color := colorGreen
		if bypasses > 0 {
			color = colorRed
		}
		line = fmt.Sprintf("%s%s%s", color, line, colorReset)
	}

	_, err := fmt.Fprintln(tw.w, line)
	return err
}

// writeTableHeader writes the table header with title.
func (tw *TableWriter) writeTableHeader(sb *strings.Builder, title string) {
	width := tw.getWidth()
	chars := tw.chars

	// Top border
	sb.WriteString(chars.TopLeft)
	sb.WriteString(strings.Repeat(chars.Horizontal, width-2))
	sb.WriteString(chars.TopRight)
	sb.WriteString("\n")

	// Title line
	titleLine := tw.centerText(title, width-4)
	sb.WriteString(chars.Vertical)
	sb.WriteString(" ")
	if tw.config.ColorEnabled {
		sb.WriteString(colorBold)
	}
	sb.WriteString(titleLine)
	if tw.config.ColorEnabled {
		sb.WriteString(colorReset)
	}
	sb.WriteString(" ")
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Separator
	sb.WriteString(chars.Vertical)
	sb.WriteString(strings.Repeat(chars.Horizontal, width-2))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")
}

// writeTableFooter writes the table footer.
func (tw *TableWriter) writeTableFooter(sb *strings.Builder) {
	width := tw.getWidth()
	chars := tw.chars

	sb.WriteString(chars.BottomLeft)
	sb.WriteString(strings.Repeat(chars.Horizontal, width-2))
	sb.WriteString(chars.BottomRight)
	sb.WriteString("\n")
}

// writeEffectivenessScore displays the WAF effectiveness score with visual indicator.
func (tw *TableWriter) writeEffectivenessScore(sb *strings.Builder) {
	if tw.summary == nil {
		return
	}

	eff := tw.summary.Effectiveness
	chars := tw.chars
	width := tw.getWidth()

	// Score line
	scoreLine := fmt.Sprintf("WAF Effectiveness: %.1f%% (Grade: %s)",
		eff.BlockRatePct, eff.Grade)

	if tw.config.ColorEnabled {
		color := tw.getGradeColor(eff.Grade)
		scoreLine = fmt.Sprintf("%sWAF Effectiveness: %.1f%% (Grade: %s)%s",
			color, eff.BlockRatePct, eff.Grade, colorReset)
	}

	sb.WriteString(chars.Vertical)
	sb.WriteString(" ")
	sb.WriteString(scoreLine)
	sb.WriteString(strings.Repeat(" ", width-4-len(stripANSI(scoreLine))))
	sb.WriteString(" ")
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Visual progress bar
	barWidth := width - 8
	filledWidth := int(eff.BlockRatePct / 100 * float64(barWidth))
	if filledWidth > barWidth {
		filledWidth = barWidth
	}
	if filledWidth < 0 {
		filledWidth = 0
	}

	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)

	sb.WriteString(chars.Vertical)
	sb.WriteString("  [")
	if tw.config.ColorEnabled {
		sb.WriteString(tw.getGradeColor(eff.Grade))
	}
	sb.WriteString(bar)
	if tw.config.ColorEnabled {
		sb.WriteString(colorReset)
	}
	sb.WriteString("]  ")
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Recommendation
	if eff.Recommendation != "" {
		recLine := fmt.Sprintf("Recommendation: %s", eff.Recommendation)
		if len(recLine) > width-4 {
			recLine = recLine[:width-7] + "..."
		}
		sb.WriteString(chars.Vertical)
		sb.WriteString(" ")
		if tw.config.ColorEnabled {
			sb.WriteString(colorDim)
		}
		sb.WriteString(recLine)
		sb.WriteString(strings.Repeat(" ", width-4-len(recLine)))
		if tw.config.ColorEnabled {
			sb.WriteString(colorReset)
		}
		sb.WriteString(" ")
		sb.WriteString(chars.Vertical)
		sb.WriteString("\n")
	}

	// Separator
	sb.WriteString(chars.Vertical)
	sb.WriteString(strings.Repeat(chars.Horizontal, width-2))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")
}

// writeTotalsTable writes the test totals as a table row.
func (tw *TableWriter) writeTotalsTable(sb *strings.Builder) {
	if tw.summary == nil {
		return
	}

	chars := tw.chars
	width := tw.getWidth()
	totals := tw.summary.Totals

	// Header row
	header := "  Tests   | Blocked  | Bypasses | Errors   | Timeouts"
	sb.WriteString(chars.Vertical)
	sb.WriteString(header)
	sb.WriteString(strings.Repeat(" ", width-2-len(header)))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Values row
	valuesLine := fmt.Sprintf("  %-7d | %-8d | %-8d | %-8d | %-8d",
		totals.Tests, totals.Blocked, totals.Bypasses, totals.Errors, totals.Timeouts)

	sb.WriteString(chars.Vertical)
	if tw.config.ColorEnabled {
		// Color the bypasses count
		parts := strings.Split(valuesLine, "|")
		for i, part := range parts {
			if i == 2 && totals.Bypasses > 0 { // Bypasses column
				sb.WriteString(colorRed)
				sb.WriteString(part)
				sb.WriteString(colorReset)
			} else if i == 1 { // Blocked column
				sb.WriteString(colorGreen)
				sb.WriteString(part)
				sb.WriteString(colorReset)
			} else {
				sb.WriteString(part)
			}
			if i < len(parts)-1 {
				sb.WriteString("|")
			}
		}
	} else {
		sb.WriteString(valuesLine)
	}
	sb.WriteString(strings.Repeat(" ", width-2-len(valuesLine)))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Separator
	sb.WriteString(chars.Vertical)
	sb.WriteString(strings.Repeat(chars.Horizontal, width-2))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")
}

// writeSeverityBreakdown writes severity-based statistics.
func (tw *TableWriter) writeSeverityBreakdown(sb *strings.Builder) {
	if tw.summary == nil || tw.summary.Breakdown.BySeverity == nil {
		return
	}

	chars := tw.chars
	width := tw.getWidth()

	sb.WriteString(chars.Vertical)
	sb.WriteString(" Severity Breakdown:")
	sb.WriteString(strings.Repeat(" ", width-22))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Sort severities by priority
	severities := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severities {
		stats, ok := tw.summary.Breakdown.BySeverity[sev]
		if !ok || stats.Total == 0 {
			continue
		}

		line := fmt.Sprintf("  %-8s: %d tests, %d bypasses (%.1f%% blocked)",
			capitalizeFirst(sev), stats.Total, stats.Bypasses, stats.BlockRate)

		sb.WriteString(chars.Vertical)
		if tw.config.ColorEnabled {
			sevColor := severityColors[sev]
			sb.WriteString(sevColor)
			sb.WriteString(line)
			sb.WriteString(colorReset)
		} else {
			sb.WriteString(line)
		}
		sb.WriteString(strings.Repeat(" ", width-2-len(line)))
		sb.WriteString(chars.Vertical)
		sb.WriteString("\n")
	}

	// Separator
	sb.WriteString(chars.Vertical)
	sb.WriteString(strings.Repeat(chars.Horizontal, width-2))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")
}

// writeResultsStats writes stats calculated from buffered results.
func (tw *TableWriter) writeResultsStats(sb *strings.Builder) {
	chars := tw.chars
	width := tw.getWidth()

	var bypasses, blocked, errors, timeouts int
	for _, r := range tw.results {
		switch r.Result.Outcome {
		case events.OutcomeBypass:
			bypasses++
		case events.OutcomeBlocked:
			blocked++
		case events.OutcomeError:
			errors++
		case events.OutcomeTimeout:
			timeouts++
		}
	}

	total := len(tw.results)
	var effectiveness float64
	if total > 0 {
		effectiveness = float64(blocked) / float64(total) * 100
	}

	// Effectiveness line
	effLine := fmt.Sprintf("Effectiveness: %.1f%% (%d/%d blocked)", effectiveness, blocked, total)
	sb.WriteString(chars.Vertical)
	sb.WriteString(" ")
	if tw.config.ColorEnabled {
		color := colorGreen
		if bypasses > 0 {
			color = colorYellow
		}
		if bypasses > total/10 {
			color = colorRed
		}
		sb.WriteString(color)
	}
	sb.WriteString(effLine)
	if tw.config.ColorEnabled {
		sb.WriteString(colorReset)
	}
	sb.WriteString(strings.Repeat(" ", width-4-len(effLine)))
	sb.WriteString(" ")
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Stats line
	statsLine := fmt.Sprintf("Bypasses: %d | Errors: %d | Timeouts: %d", bypasses, errors, timeouts)
	sb.WriteString(chars.Vertical)
	sb.WriteString(" ")
	sb.WriteString(statsLine)
	sb.WriteString(strings.Repeat(" ", width-4-len(statsLine)))
	sb.WriteString(" ")
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Separator
	sb.WriteString(chars.Vertical)
	sb.WriteString(strings.Repeat(chars.Horizontal, width-2))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")
}

// writeTopBypasses writes the top N bypass results.
func (tw *TableWriter) writeTopBypasses(sb *strings.Builder, limit int) {
	chars := tw.chars
	width := tw.getWidth()

	// Collect bypasses
	var bypasses []*events.ResultEvent
	for _, r := range tw.results {
		if r.Result.Outcome == events.OutcomeBypass {
			bypasses = append(bypasses, r)
		}
	}

	// Also check summary top bypasses
	if tw.summary != nil && len(tw.summary.TopBypasses) > 0 && len(bypasses) == 0 {
		sb.WriteString(chars.Vertical)
		sb.WriteString(" Top Bypasses:")
		sb.WriteString(strings.Repeat(" ", width-16))
		sb.WriteString(chars.Vertical)
		sb.WriteString("\n")

		for i, bp := range tw.summary.TopBypasses {
			if i >= limit {
				break
			}
			line := fmt.Sprintf("  %d. [%s] %s - %s", i+1, bp.Severity, bp.Category, bp.ID)
			if len(line) > width-4 {
				line = line[:width-7] + "..."
			}

			sb.WriteString(chars.Vertical)
			if tw.config.ColorEnabled {
				sevColor := severityColors[bp.Severity]
				sb.WriteString(sevColor)
			}
			sb.WriteString(line)
			if tw.config.ColorEnabled {
				sb.WriteString(colorReset)
			}
			sb.WriteString(strings.Repeat(" ", width-2-len(line)))
			sb.WriteString(chars.Vertical)
			sb.WriteString("\n")
		}
		return
	}

	if len(bypasses) == 0 {
		sb.WriteString(chars.Vertical)
		if tw.config.ColorEnabled {
			sb.WriteString(colorGreen)
		}
		sb.WriteString(" No bypasses detected!")
		if tw.config.ColorEnabled {
			sb.WriteString(colorReset)
		}
		sb.WriteString(strings.Repeat(" ", width-24))
		sb.WriteString(chars.Vertical)
		sb.WriteString("\n")
		return
	}

	// Sort by severity
	sort.Slice(bypasses, func(i, j int) bool {
		return severityPriority(bypasses[i].Test.Severity) > severityPriority(bypasses[j].Test.Severity)
	})

	sb.WriteString(chars.Vertical)
	sb.WriteString(" Top Bypasses:")
	sb.WriteString(strings.Repeat(" ", width-16))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	for i, r := range bypasses {
		if i >= limit {
			break
		}

		line := fmt.Sprintf("  %d. [%s] %s - %s",
			i+1, r.Test.Severity, r.Test.Category, r.Test.ID)
		if len(line) > width-4 {
			line = line[:width-7] + "..."
		}

		sb.WriteString(chars.Vertical)
		if tw.config.ColorEnabled {
			sevColor := severityColors[string(r.Test.Severity)]
			sb.WriteString(sevColor)
		}
		sb.WriteString(line)
		if tw.config.ColorEnabled {
			sb.WriteString(colorReset)
		}
		sb.WriteString(strings.Repeat(" ", width-2-len(line)))
		sb.WriteString(chars.Vertical)
		sb.WriteString("\n")
	}
}

// writeResultsTable writes all buffered results as a table.
func (tw *TableWriter) writeResultsTable(sb *strings.Builder) {
	chars := tw.chars
	width := tw.getWidth()

	if len(tw.results) == 0 {
		sb.WriteString(chars.Vertical)
		sb.WriteString(" No results to display")
		sb.WriteString(strings.Repeat(" ", width-24))
		sb.WriteString(chars.Vertical)
		sb.WriteString("\n")
		return
	}

	// Table header
	header := " Outcome  | Severity | Category     | Test ID"
	sb.WriteString(chars.Vertical)
	sb.WriteString(header)
	sb.WriteString(strings.Repeat(" ", width-2-len(header)))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Separator
	sb.WriteString(chars.Vertical)
	sb.WriteString(strings.Repeat("-", width-2))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")

	// Results
	for _, r := range tw.results {
		outcome := fmt.Sprintf("%-8s", r.Result.Outcome)
		severity := fmt.Sprintf("%-8s", r.Test.Severity)
		category := r.Test.Category
		if len(category) > 12 {
			category = category[:9] + "..."
		}
		category = fmt.Sprintf("%-12s", category)

		testID := r.Test.ID
		maxIDLen := width - 38
		if len(testID) > maxIDLen && maxIDLen > 3 {
			testID = testID[:maxIDLen-3] + "..."
		}

		line := fmt.Sprintf(" %s | %s | %s | %s", outcome, severity, category, testID)

		sb.WriteString(chars.Vertical)
		if tw.config.ColorEnabled {
			// Apply colors
			outcomeColor := outcomeColors[r.Result.Outcome]
			sevColor := severityColors[string(r.Test.Severity)]
			coloredLine := fmt.Sprintf(" %s%s%s | %s%s%s | %s | %s",
				outcomeColor, outcome, colorReset,
				sevColor, severity, colorReset,
				category, testID)
			sb.WriteString(coloredLine)
			// Pad without colors
			sb.WriteString(strings.Repeat(" ", width-2-len(line)))
		} else {
			sb.WriteString(line)
			sb.WriteString(strings.Repeat(" ", width-2-len(line)))
		}
		sb.WriteString(chars.Vertical)
		sb.WriteString("\n")
	}

	// Separator
	sb.WriteString(chars.Vertical)
	sb.WriteString(strings.Repeat(chars.Horizontal, width-2))
	sb.WriteString(chars.Vertical)
	sb.WriteString("\n")
}

// getWidth returns the configured or auto-detected terminal width.
func (tw *TableWriter) getWidth() int {
	if tw.config.Width > 0 {
		return tw.config.Width
	}

	// Try to detect terminal width
	width := getTerminalWidth(tw.w)

	// Apply MaxWidth constraint if set
	if tw.config.MaxWidth > 0 && width > tw.config.MaxWidth {
		return tw.config.MaxWidth
	}

	return width
}

// getTerminalWidth detects the terminal width from the writer or returns default.
func getTerminalWidth(w io.Writer) int {
	// Try from provided writer
	if f, ok := w.(*os.File); ok {
		if width, _, err := term.GetSize(int(f.Fd())); err == nil && width > 0 {
			return width
		}
	}

	// Try stdout directly
	if width, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && width > 0 {
		return width
	}

	// Default width for non-terminal or detection failure
	return 120
}

// calculateColumnWidths calculates responsive column widths based on terminal size.
// Priority order: ID, Category, Severity, Outcome, URL (truncate URL last)
func (tw *TableWriter) calculateColumnWidths() {
	termWidth := tw.getWidth()

	// Minimum widths for each column
	const (
		minOutcome  = 8
		minSeverity = 8
		minCategory = 12
		minTestID   = 20
		minURL      = 20
		separators  = 16 // space for separators and padding
	)

	// Start with minimum widths
	tw.columnWidths = columnWidths{
		outcome:  minOutcome,
		severity: minSeverity,
		category: minCategory,
		testID:   minTestID,
		url:      minURL,
	}

	// Calculate available extra space
	usedWidth := minOutcome + minSeverity + minCategory + minTestID + minURL + separators
	extraSpace := termWidth - usedWidth

	if extraSpace <= 0 {
		return // Use minimum widths
	}

	// Distribute extra space: prioritize test ID, then category, then URL
	if extraSpace > 20 {
		tw.columnWidths.testID += 10
		extraSpace -= 10
	}
	if extraSpace > 10 {
		tw.columnWidths.category += 8
		extraSpace -= 8
	}
	// Remaining space goes to URL
	if extraSpace > 0 {
		tw.columnWidths.url += extraSpace
	}
}

// renderSummaryBanner renders a visual summary banner with effectiveness bar.
func (tw *TableWriter) renderSummaryBanner(bypasses, blocked, errors, total int) {
	if total == 0 {
		return
	}

	effectiveness := float64(blocked) / float64(total) * 100

	// Visual effectiveness bar
	const barLen = 40
	filledLen := int(effectiveness / 100 * float64(barLen))
	if filledLen > barLen {
		filledLen = barLen
	}
	if filledLen < 0 {
		filledLen = 0
	}

	var bar string
	if tw.config.ColorEnabled {
		filledPart := fmtBlocked(strings.Repeat("█", filledLen))
		emptyPart := fmtDim(strings.Repeat("░", barLen-filledLen))
		bar = filledPart + emptyPart
	} else {
		bar = strings.Repeat("█", filledLen) + strings.Repeat("░", barLen-filledLen)
	}

	fmt.Fprintf(tw.w, "\n%s WAF Effectiveness: %.1f%%\n", bar, effectiveness)

	if tw.config.ColorEnabled {
		fmt.Fprintf(tw.w, "Blocked: %s | Bypasses: %s | Errors: %s\n",
			fmtBlocked(fmt.Sprintf("%d", blocked)),
			fmtBypass(fmt.Sprintf("%d", bypasses)),
			fmtError(fmt.Sprintf("%d", errors)))
	} else {
		fmt.Fprintf(tw.w, "Blocked: %d | Bypasses: %d | Errors: %d\n",
			blocked, bypasses, errors)
	}
}

// renderLegend renders a severity color legend.
func (tw *TableWriter) renderLegend() {
	if !tw.config.ColorEnabled {
		return
	}

	fmt.Fprintf(tw.w, "\nSeverity: %s %s %s %s %s\n",
		fmtCritical("●Critical"),
		fmtHigh("●High"),
		fmtMedium("●Medium"),
		fmtLow("●Low"),
		fmtInfo("●Info"))

	fmt.Fprintf(tw.w, "Outcome:  %s %s %s\n",
		fmtBlocked("●Blocked"),
		fmtBypass("●Bypass"),
		fmtError("●Error"))
}

// truncateWithMarker truncates a string and adds a clear truncation marker.
func truncateWithMarker(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	if maxLen <= 5 {
		return s[:maxLen]
	}
	return s[:maxLen-5] + "[...]"
}

// hashPayload creates a simple hash for payload deduplication tracking.
func hashPayload(payload string) string {
	// Simple hash for deduplication - first 32 chars or full string if shorter
	if len(payload) <= 32 {
		return payload
	}
	return payload[:32]
}

// formatCurlCommand generates a cURL command for a result event.
func formatCurlCommand(e *events.ResultEvent) string {
	if e == nil || e.Target.URL == "" {
		return ""
	}

	method := e.Target.Method
	if method == "" {
		method = "GET"
	}

	cmd := fmt.Sprintf("curl -X %s '%s'", method, e.Target.URL)

	if e.Evidence != nil && e.Evidence.Payload != "" {
		// Escape single quotes in payload
		escaped := strings.ReplaceAll(e.Evidence.Payload, "'", "'\"'\"'")
		cmd += fmt.Sprintf(" -d '%s'", escaped)
	}

	return cmd
}

// getGradeColor returns the ANSI color for a grade.
func (tw *TableWriter) getGradeColor(grade string) string {
	switch grade {
	case "A+", "A":
		return colorGreen
	case "B+", "B":
		return colorYellow
	case "C+", "C":
		return "\033[38;5;208m" // orange
	default:
		return colorRed
	}
}

// centerText centers text within a given width.
func (tw *TableWriter) centerText(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
}

// stripANSI removes ANSI escape codes from a string for length calculation.
func stripANSI(s string) string {
	// Simple ANSI stripper - handles common escape sequences
	result := s
	// Remove color codes like \033[...m
	for {
		start := strings.Index(result, "\033[")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "m")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+1:]
	}
	return result
}
