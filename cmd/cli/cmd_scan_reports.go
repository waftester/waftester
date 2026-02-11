package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/ui"
)

// printScanCSV writes scan results in CSV format.
func printScanCSV(w io.Writer, target string, result *ScanResult) {
	fmt.Fprintln(w, "target,category,severity,count")
	for cat, count := range result.ByCategory {
		fmt.Fprintf(w, "%s,%s,various,%d\n", target, cat, count)
	}
}

// printScanMarkdown writes scan results in Markdown format.
func printScanMarkdown(w io.Writer, result *ScanResult) {
	fmt.Fprintln(w, "# Vulnerability Scan Report")
	fmt.Fprintln(w)
	if result.ReportTitle != "" {
		fmt.Fprintf(w, "**Report:** %s\n", result.ReportTitle)
	}
	if result.ReportAuthor != "" {
		fmt.Fprintf(w, "**Author:** %s\n", result.ReportAuthor)
	}
	fmt.Fprintf(w, "**Target:** %s\n", result.Target)
	fmt.Fprintf(w, "**Date:** %s\n", result.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "**Duration:** %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "**Total Vulnerabilities:** %d\n", result.TotalVulns)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## By Severity")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Severity | Count |")
	fmt.Fprintln(w, "|----------|-------|")
	for sev, count := range result.BySeverity {
		fmt.Fprintf(w, "| %s | %d |\n", sev, count)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## By Category")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Category | Count |")
	fmt.Fprintln(w, "|----------|-------|")
	for cat, count := range result.ByCategory {
		if count > 0 {
			fmt.Fprintf(w, "| %s | %d |\n", cat, count)
		}
	}
}

// printScanHTML writes scan results in HTML format.
func printScanHTML(w io.Writer, result *ScanResult) {
	fmt.Fprintln(w, "<!DOCTYPE html><html><head><title>Scan Report</title>")
	fmt.Fprintln(w, "<style>body{font-family:Arial,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#4CAF50;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#ffc107}.low{color:#4caf50}</style></head><body>")
	if result.ReportTitle != "" {
		fmt.Fprintf(w, "<h1>%s</h1>\n", html.EscapeString(result.ReportTitle))
	} else {
		fmt.Fprintln(w, "<h1>Vulnerability Scan Report</h1>")
	}
	if result.ReportAuthor != "" {
		fmt.Fprintf(w, "<p><strong>Author:</strong> %s</p>\n", html.EscapeString(result.ReportAuthor))
	}
	fmt.Fprintf(w, "<p><strong>Target:</strong> %s</p>\n", html.EscapeString(result.Target))
	fmt.Fprintf(w, "<p><strong>Date:</strong> %s</p>\n", result.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "<p><strong>Total Vulnerabilities:</strong> %d</p>\n", result.TotalVulns)
	fmt.Fprintln(w, "<h2>By Severity</h2><table><tr><th>Severity</th><th>Count</th></tr>")
	for sev, count := range result.BySeverity {
		fmt.Fprintf(w, "<tr><td class='%s'>%s</td><td>%d</td></tr>\n", strings.ToLower(html.EscapeString(sev)), html.EscapeString(sev), count)
	}
	fmt.Fprintln(w, "</table><h2>By Category</h2><table><tr><th>Category</th><th>Count</th></tr>")
	for cat, count := range result.ByCategory {
		if count > 0 {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%d</td></tr>\n", html.EscapeString(cat), count)
		}
	}
	fmt.Fprintln(w, "</table></body></html>")
}

// printScanSARIF writes scan results in SARIF 2.1.0 format for CI/CD integration.
func printScanSARIF(w io.Writer, target string, result *ScanResult) {
	var sarifResults []map[string]interface{}
	for cat, count := range result.ByCategory {
		if count > 0 {
			sarifResults = append(sarifResults, map[string]interface{}{
				"ruleId":  cat,
				"level":   "warning",
				"message": map[string]string{"text": fmt.Sprintf("Found %d %s issues", count, cat)},
				"locations": []map[string]interface{}{
					{"physicalLocation": map[string]interface{}{"artifactLocation": map[string]string{"uri": target}}},
				},
			})
		}
	}

	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "waf-tester",
						"version":        ui.Version,
						"informationUri": "https://github.com/waftester/waftester",
					},
				},
				"results": sarifResults,
			},
		},
	}
	jsonData, _ := json.MarshalIndent(sarif, "", "  ")
	fmt.Fprintln(w, string(jsonData))
}

// printScanJSONL writes scan results in JSON Lines format.
func printScanJSONL(w io.Writer, target string, result *ScanResult) {
	for cat, count := range result.ByCategory {
		line, _ := json.Marshal(map[string]interface{}{"category": cat, "count": count, "target": target})
		fmt.Fprintln(w, string(line))
	}
}

// printScanConsoleSummary writes scan results to console with colored formatting.
func printScanConsoleSummary(result *ScanResult) {
	fmt.Println()
	ui.PrintSection("Scan Results")
	ui.PrintConfigLine("Duration", result.Duration.Round(time.Millisecond).String())
	ui.PrintConfigLine("Total Vulnerabilities", fmt.Sprintf("%d", result.TotalVulns))
	fmt.Println()

	if result.TotalVulns > 0 {
		ui.PrintSection("By Severity")
		for sev, count := range result.BySeverity {
			switch sev {
			case "Critical":
				ui.PrintError(fmt.Sprintf("  %s: %d", sev, count))
			case "High":
				ui.PrintError(fmt.Sprintf("  %s: %d", sev, count))
			case "Medium":
				ui.PrintWarning(fmt.Sprintf("  %s: %d", sev, count))
			default:
				ui.PrintInfo(fmt.Sprintf("  %s: %d", sev, count))
			}
		}
		fmt.Println()

		ui.PrintSection("By Category")
		for cat, count := range result.ByCategory {
			if count > 0 {
				ui.PrintConfigLine(cat, fmt.Sprintf("%d vulnerabilities", count))
			}
		}
		fmt.Println()

		// Print detailed findings
		if result.SQLi != nil && len(result.SQLi.Vulnerabilities) > 0 {
			ui.PrintSection("SQLi Findings")
			for _, v := range result.SQLi.Vulnerabilities[:min(5, len(result.SQLi.Vulnerabilities))] {
				if v.ConfirmedBy > 1 {
					ui.PrintError(fmt.Sprintf("  [%s] %s - %s (%d payloads)", v.Severity, v.Parameter, v.Type, v.ConfirmedBy))
				} else {
					ui.PrintError(fmt.Sprintf("  [%s] %s - %s", v.Severity, v.Parameter, v.Type))
				}
			}
			if len(result.SQLi.Vulnerabilities) > 5 {
				ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.SQLi.Vulnerabilities)-5))
			}
			fmt.Println()
		}

		if result.XSS != nil && len(result.XSS.Vulnerabilities) > 0 {
			ui.PrintSection("XSS Findings")
			for _, v := range result.XSS.Vulnerabilities[:min(5, len(result.XSS.Vulnerabilities))] {
				if v.ConfirmedBy > 1 {
					ui.PrintError(fmt.Sprintf("  [%s] %s - %s (%d payloads)", v.Severity, v.Parameter, v.Type, v.ConfirmedBy))
				} else {
					ui.PrintError(fmt.Sprintf("  [%s] %s - %s", v.Severity, v.Parameter, v.Type))
				}
			}
			if len(result.XSS.Vulnerabilities) > 5 {
				ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.XSS.Vulnerabilities)-5))
			}
			fmt.Println()
		}
	} else {
		ui.PrintSuccess("No vulnerabilities found!")
	}
}
