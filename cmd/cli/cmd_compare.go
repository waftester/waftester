package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/waftester/waftester/pkg/compare"
	"github.com/waftester/waftester/pkg/ui"
)

// runCompare executes the compare command: loads two scan result JSON files
// and displays a structured diff showing what changed between them.
func runCompare() {
	ui.PrintCompactBanner()
	ui.PrintSection("Scan Comparison")

	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	beforePath := fs.String("before", "", "First scan result JSON (baseline)")
	afterPath := fs.String("after", "", "Second scan result JSON (current)")
	format := fs.String("format", "console", "Output format: console, json")
	output := fs.String("o", "", "Output file (default: stdout)")

	fs.Parse(os.Args[2:])

	// Support positional args: waf-tester compare before.json after.json
	// Also handles mixed: waf-tester compare -before base.json current.json
	args := fs.Args()
	if *beforePath == "" && *afterPath == "" && len(args) >= 2 {
		*beforePath = args[0]
		*afterPath = args[1]
	} else if *beforePath != "" && *afterPath == "" && len(args) >= 1 {
		*afterPath = args[0]
	} else if *beforePath == "" && *afterPath != "" && len(args) >= 1 {
		*beforePath = args[0]
	}

	// Validate format
	switch *format {
	case "console", "json":
		// valid
	default:
		exitWithError("Unknown format %q. Supported: console, json", *format)
	}

	if *beforePath == "" || *afterPath == "" {
		exitWithUsage(
			"Both -before and -after files are required.",
			"waf-tester compare -before baseline.json -after current.json\n       waf-tester compare baseline.json current.json",
		)
	}

	before, err := compare.LoadSummary(*beforePath)
	if err != nil {
		exitWithError("Loading before file: %v", err)
	}

	after, err := compare.LoadSummary(*afterPath)
	if err != nil {
		exitWithError("Loading after file: %v", err)
	}

	result := compare.Compare(before, after)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			exitWithError("Marshaling result: %v", err)
		}
		if *output != "" {
			if err := os.WriteFile(*output, data, 0o644); err != nil {
				exitWithError("Writing output: %v", err)
			}
			ui.PrintSuccess(fmt.Sprintf("Comparison written to %s", *output))
		} else {
			fmt.Println(string(data))
		}
	default:
		printCompareConsole(result, *beforePath, *afterPath)
		if *output != "" {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				exitWithError("Marshaling result: %v", err)
			}
			if err := os.WriteFile(*output, data, 0o644); err != nil {
				exitWithError("Writing output: %v", err)
			}
			fmt.Fprintln(os.Stderr)
			ui.PrintSuccess(fmt.Sprintf("JSON result written to %s", *output))
		}
	}

	// Exit with code 1 if scan regressed (useful for CI/CD gating)
	if result.Verdict == "regressed" {
		os.Exit(1)
	}
}

// printCompareConsole renders the comparison result to stderr in a readable format.
func printCompareConsole(r *compare.Result, beforePath, afterPath string) {
	fmt.Fprintln(os.Stderr)

	// File info
	beforeTime := ""
	if !r.Before.StartTime.IsZero() {
		beforeTime = r.Before.StartTime.Format("2006-01-02")
	}
	afterTime := ""
	if !r.After.StartTime.IsZero() {
		afterTime = r.After.StartTime.Format("2006-01-02")
	}

	beforeInfo := beforePath
	if r.Before.Target != "" {
		beforeInfo += " (" + r.Before.Target
		if beforeTime != "" {
			beforeInfo += ", " + beforeTime
		}
		beforeInfo += ")"
	}

	afterInfo := afterPath
	if r.After.Target != "" {
		afterInfo += " (" + r.After.Target
		if afterTime != "" {
			afterInfo += ", " + afterTime
		}
		afterInfo += ")"
	}

	ui.PrintConfigLine("Before", beforeInfo)
	ui.PrintConfigLine("After", afterInfo)
	fmt.Fprintln(os.Stderr)

	// Verdict
	var verdictSymbol string
	switch r.Verdict {
	case "improved":
		verdictSymbol = "IMPROVED \u25bc"
	case "regressed":
		verdictSymbol = "REGRESSED \u25b2"
	default:
		verdictSymbol = "UNCHANGED ="
	}
	ui.PrintConfigLine("Verdict", verdictSymbol)
	fmt.Fprintln(os.Stderr)

	// Severity table
	severities := collectSeverityKeys(r)
	if len(severities) > 0 || r.VulnDelta != 0 {
		fmt.Fprintln(os.Stderr, "  Severity Breakdown:")
		fmt.Fprintln(os.Stderr)
		for _, sev := range severities {
			beforeVal := r.Before.BySeverity[sev]
			afterVal := r.After.BySeverity[sev]
			delta := r.SeverityDeltas[sev]
			fmt.Fprintf(os.Stderr, "    %-12s %4d -> %4d  %s\n", sev, beforeVal, afterVal, formatDelta(delta))
		}
		fmt.Fprintf(os.Stderr, "    %-12s %4d -> %4d  %s\n", "TOTAL", r.Before.TotalVulns, r.After.TotalVulns, formatDelta(r.VulnDelta))
		fmt.Fprintln(os.Stderr)
	}

	// Category changes
	if len(r.FixedCategories) > 0 {
		ui.PrintSuccess("Fixed: " + strings.Join(r.FixedCategories, ", "))
	}
	if len(r.NewCategories) > 0 {
		ui.PrintError("New: " + strings.Join(r.NewCategories, ", "))
	}

	// WAF change
	if r.WAFChanged {
		beforeWAF := r.Before.WAFVendor
		if beforeWAF == "" {
			beforeWAF = "none"
		}
		afterWAF := r.After.WAFVendor
		if afterWAF == "" {
			afterWAF = "none"
		}
		ui.PrintConfigLine("WAF", beforeWAF+" -> "+afterWAF)
	} else if r.Before.WAFVendor != "" {
		ui.PrintConfigLine("WAF", r.Before.WAFVendor+" (unchanged)")
	}
}

// collectSeverityKeys returns all unique severity keys from both summaries,
// sorted in standard order: critical, high, medium, low, then any others alphabetically.
func collectSeverityKeys(r *compare.Result) []string {
	seen := make(map[string]bool)
	for k := range r.Before.BySeverity {
		seen[k] = true
	}
	for k := range r.After.BySeverity {
		seen[k] = true
	}

	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	var keys []string
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		oi, oki := order[keys[i]]
		oj, okj := order[keys[j]]
		if oki && okj {
			return oi < oj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return keys[i] < keys[j]
	})
	return keys
}

// formatDelta returns a human-readable delta string like "+3 ▲" or "-2 ▼" or "0 =".
func formatDelta(d int) string {
	switch {
	case d > 0:
		return fmt.Sprintf("+%d \u25b2", d)
	case d < 0:
		return fmt.Sprintf("%d \u25bc", d)
	default:
		return "0 ="
	}
}
