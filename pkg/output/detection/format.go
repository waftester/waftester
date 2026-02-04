package detection

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
)

// Format represents an output format for detection stats.
type Format int

const (
	// FormatConsole outputs colored text suitable for terminal display.
	FormatConsole Format = iota
	// FormatJSON outputs machine-readable JSON.
	FormatJSON
	// FormatMarkdown outputs Markdown suitable for reports.
	FormatMarkdown
	// FormatSARIF outputs SARIF format for security tools.
	FormatSARIF
)

// WriteTo writes the stats in the specified format to the writer.
func (s Stats) WriteTo(w io.Writer, format Format) error {
	switch format {
	case FormatConsole:
		return s.writeConsole(w)
	case FormatJSON:
		return s.writeJSON(w)
	case FormatMarkdown:
		return s.writeMarkdown(w)
	case FormatSARIF:
		return s.writeSARIF(w)
	default:
		return fmt.Errorf("unknown format: %d", format)
	}
}

// PrintConsole prints colored stats to stderr.
// This is a convenience method for the most common use case.
func (s Stats) PrintConsole() {
	s.WriteTo(color.Error, FormatConsole)
}

// writeConsole writes colored console output
func (s Stats) writeConsole(w io.Writer) error {
	if !s.HasData() {
		return nil
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("─", 40))
	fmt.Fprintln(w, "  Detection Stats:")
	fmt.Fprintln(w)

	if s.DropsDetected > 0 {
		yellow := color.New(color.FgYellow)
		yellow.Fprintf(w, "    ⚠ Connection Drops: %d\n", s.DropsDetected)
	}
	if s.BansDetected > 0 {
		red := color.New(color.FgRed)
		red.Fprintf(w, "    🚫 Silent Bans:      %d\n", s.BansDetected)
	}
	if s.HostsSkipped > 0 {
		cyan := color.New(color.FgCyan)
		cyan.Fprintf(w, "    ⏭ Hosts Skipped:     %d\n", s.HostsSkipped)
	}

	// Show recommendations if any
	recs := s.Recommendations()
	if len(recs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Recommendations:")
		for _, rec := range recs {
			fmt.Fprintf(w, "    • %s\n", rec)
		}
	}

	fmt.Fprintln(w)
	return nil
}

// writeJSON writes JSON output
func (s Stats) writeJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(s.ToJSON())
}

// writeMarkdown writes Markdown output
func (s Stats) writeMarkdown(w io.Writer) error {
	if !s.HasData() {
		fmt.Fprintln(w, "No detection events recorded.")
		return nil
	}

	fmt.Fprintln(w, "### Detection Stats")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Metric | Value |")
	fmt.Fprintln(w, "|--------|-------|")

	if s.DropsDetected > 0 {
		fmt.Fprintf(w, "| ⚠️ Connection Drops | %d |\n", s.DropsDetected)
	}
	if s.BansDetected > 0 {
		fmt.Fprintf(w, "| 🚫 Silent Bans | %d |\n", s.BansDetected)
	}
	if s.HostsSkipped > 0 {
		fmt.Fprintf(w, "| ⏭️ Hosts Skipped | %d |\n", s.HostsSkipped)
	}

	// Add severity indicator
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Severity:** %s\n", s.Severity())

	// Add recommendations
	recs := s.Recommendations()
	if len(recs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "**Recommendations:**")
		for _, rec := range recs {
			fmt.Fprintf(w, "- %s\n", rec)
		}
	}

	return nil
}

// writeSARIF writes SARIF format output (for security tools integration)
func (s Stats) writeSARIF(w io.Writer) error {
	// SARIF structure for detection events
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "waftester-detection",
						"version": "2.5.3",
					},
				},
				"results": s.toSARIFResults(),
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

// toSARIFResults converts stats to SARIF result entries
func (s Stats) toSARIFResults() []map[string]interface{} {
	var results []map[string]interface{}

	if s.DropsDetected > 0 {
		results = append(results, map[string]interface{}{
			"ruleId":  "detection/connection-drops",
			"level":   "warning",
			"message": map[string]string{"text": fmt.Sprintf("%d connection drops detected", s.DropsDetected)},
		})
	}

	if s.BansDetected > 0 {
		results = append(results, map[string]interface{}{
			"ruleId":  "detection/silent-bans",
			"level":   "error",
			"message": map[string]string{"text": fmt.Sprintf("%d silent bans detected", s.BansDetected)},
		})
	}

	if s.HostsSkipped > 0 {
		results = append(results, map[string]interface{}{
			"ruleId":  "detection/hosts-skipped",
			"level":   "note",
			"message": map[string]string{"text": fmt.Sprintf("%d hosts skipped", s.HostsSkipped)},
		})
	}

	return results
}
