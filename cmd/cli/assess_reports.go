package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/metrics"
	"github.com/waftester/waftester/pkg/ui"
)

// writeAssessExports writes assessment results to enterprise export files (--json-export, --sarif-export, etc.).
func writeAssessExports(outFlags *OutputFlags, result *metrics.EnterpriseMetrics, duration time.Duration) {
	if outFlags.JSONExport == "" && outFlags.JSONLExport == "" && outFlags.SARIFExport == "" &&
		outFlags.CSVExport == "" && outFlags.HTMLExport == "" && outFlags.MDExport == "" &&
		outFlags.JUnitExport == "" && outFlags.PDFExport == "" && outFlags.HARExport == "" {
		return
	}

	if outFlags.HARExport != "" {
		ui.PrintWarning("HAR export is not supported for assess (no individual HTTP request data)")
	}
	if outFlags.JUnitExport != "" {
		ui.PrintError("JUnit export is not supported for assess")
	}
	if outFlags.PDFExport != "" {
		ui.PrintError("PDF export is not supported for assess")
	}

	if outFlags.JSONExport != "" {
		if err := writeJSONFile(outFlags.JSONExport, result); err != nil {
			ui.PrintError(fmt.Sprintf("JSON export: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("JSON export saved to %s", outFlags.JSONExport))
		}
	}

	if outFlags.JSONLExport != "" {
		f, err := os.Create(outFlags.JSONLExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("JSONL export: %v", err))
		} else {
			enc := json.NewEncoder(f)
			writeErr := error(nil)
			// One line per category metric, plus a summary line
			if err := enc.Encode(map[string]interface{}{
				"type":           "summary",
				"target":         result.TargetURL,
				"grade":          result.Grade,
				"detection_rate": result.DetectionRate,
				"fpr":            result.FalsePositiveRate,
				"f1":             result.F1Score,
				"duration":       duration.String(),
			}); err != nil {
				writeErr = err
			}
			if writeErr == nil {
				for cat, cm := range result.CategoryMetrics {
					if err := enc.Encode(map[string]interface{}{
						"type":           "category",
						"category":       cat,
						"total_tests":    cm.TotalTests,
						"blocked":        cm.Blocked,
						"bypassed":       cm.Bypassed,
						"detection_rate": cm.DetectionRate,
						"grade":          cm.Grade,
					}); err != nil {
						writeErr = err
						break
					}
				}
			}
			if err := f.Close(); err != nil && writeErr == nil {
				writeErr = err
			}
			if writeErr != nil {
				ui.PrintError(fmt.Sprintf("JSONL export: %v", writeErr))
			} else {
				ui.PrintSuccess(fmt.Sprintf("JSONL export saved to %s", outFlags.JSONLExport))
			}
		}
	}

	if outFlags.SARIFExport != "" {
		sarif := buildAssessSARIF(result)
		if err := writeJSONFile(outFlags.SARIFExport, sarif); err != nil {
			ui.PrintError(fmt.Sprintf("SARIF export: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("SARIF export saved to %s", outFlags.SARIFExport))
		}
	}

	if outFlags.CSVExport != "" {
		f, err := os.Create(outFlags.CSVExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("CSV export: %v", err))
		} else {
			fmt.Fprintln(f, "category,total_tests,blocked,bypassed,detection_rate,grade")
			for cat, cm := range result.CategoryMetrics {
				fmt.Fprintf(f, "%s,%d,%d,%d,%.4f,%s\n",
					cat, cm.TotalTests, cm.Blocked, cm.Bypassed, cm.DetectionRate, cm.Grade)
			}
			if err := f.Close(); err != nil {
				ui.PrintError(fmt.Sprintf("CSV export: %v", err))
			} else {
				ui.PrintSuccess(fmt.Sprintf("CSV export saved to %s", outFlags.CSVExport))
			}
		}
	}

	if outFlags.HTMLExport != "" {
		f, err := os.Create(outFlags.HTMLExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("HTML export: %v", err))
		} else {
			fmt.Fprintf(f, "<html><head><title>WAF Assessment</title></head><body>\n")
			fmt.Fprintf(f, "<h1>WAF Assessment: Grade %s</h1>\n", html.EscapeString(result.Grade))
			fmt.Fprintf(f, "<p>Target: %s | WAF: %s | Duration: %s</p>\n",
				html.EscapeString(result.TargetURL), html.EscapeString(result.WAFVendor),
				duration.Round(time.Millisecond))
			fmt.Fprintf(f, "<h2>Metrics</h2>\n")
			fmt.Fprintf(f, "<ul>\n")
			fmt.Fprintf(f, "<li>Detection Rate: %.2f%%</li>\n", result.DetectionRate*100)
			fmt.Fprintf(f, "<li>False Positive Rate: %.2f%%</li>\n", result.FalsePositiveRate*100)
			fmt.Fprintf(f, "<li>F1 Score: %.2f%%</li>\n", result.F1Score*100)
			fmt.Fprintf(f, "<li>Bypass Resistance: %.2f%%</li>\n", result.BypassResistance*100)
			fmt.Fprintf(f, "</ul>\n")
			if len(result.CategoryMetrics) > 0 {
				fmt.Fprintf(f, "<h2>Category Breakdown</h2>\n")
				fmt.Fprintf(f, "<table border='1'><tr><th>Category</th><th>Tests</th><th>Blocked</th><th>Detection</th><th>Grade</th></tr>\n")
				for cat, cm := range result.CategoryMetrics {
					fmt.Fprintf(f, "<tr><td>%s</td><td>%d</td><td>%d</td><td>%.1f%%</td><td>%s</td></tr>\n",
						html.EscapeString(cat), cm.TotalTests, cm.Blocked, cm.DetectionRate*100, cm.Grade)
				}
				fmt.Fprintf(f, "</table>\n")
			}
			fmt.Fprintf(f, "</body></html>\n")
			if err := f.Close(); err != nil {
				ui.PrintError(fmt.Sprintf("HTML export: %v", err))
			} else {
				ui.PrintSuccess(fmt.Sprintf("HTML export saved to %s", outFlags.HTMLExport))
			}
		}
	}

	if outFlags.MDExport != "" {
		f, err := os.Create(outFlags.MDExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Markdown export: %v", err))
		} else {
			fmt.Fprintf(f, "# WAF Assessment: Grade %s\n\n", result.Grade)
			fmt.Fprintf(f, "- **Target:** %s\n- **WAF:** %s\n- **Duration:** %s\n- **Grade Reason:** %s\n\n",
				result.TargetURL, result.WAFVendor, duration.Round(time.Millisecond), result.GradeReason)
			fmt.Fprintf(f, "## Metrics\n\n")
			fmt.Fprintf(f, "| Metric | Value |\n|--------|-------|\n")
			fmt.Fprintf(f, "| Detection Rate | %.2f%% |\n", result.DetectionRate*100)
			fmt.Fprintf(f, "| False Positive Rate | %.2f%% |\n", result.FalsePositiveRate*100)
			fmt.Fprintf(f, "| F1 Score | %.2f%% |\n", result.F1Score*100)
			fmt.Fprintf(f, "| Bypass Resistance | %.2f%% |\n", result.BypassResistance*100)
			fmt.Fprintf(f, "| MCC | %+.4f |\n\n", result.MCC)
			if len(result.CategoryMetrics) > 0 {
				fmt.Fprintf(f, "## Category Breakdown\n\n")
				fmt.Fprintf(f, "| Category | Tests | Blocked | Detection | Grade |\n")
				fmt.Fprintf(f, "|----------|-------|---------|-----------|-------|\n")
				for cat, cm := range result.CategoryMetrics {
					fmt.Fprintf(f, "| %s | %d | %d | %.1f%% | %s |\n",
						cat, cm.TotalTests, cm.Blocked, cm.DetectionRate*100, cm.Grade)
				}
			}
			if len(result.Recommendations) > 0 {
				fmt.Fprintf(f, "\n## Recommendations\n\n")
				for i, rec := range result.Recommendations {
					fmt.Fprintf(f, "%d. %s\n", i+1, rec)
				}
			}
			if err := f.Close(); err != nil {
				ui.PrintError(fmt.Sprintf("Markdown export: %v", err))
			} else {
				ui.PrintSuccess(fmt.Sprintf("Markdown export saved to %s", outFlags.MDExport))
			}
		}
	}
}

// buildAssessSARIF creates a SARIF 2.1.0 structure for assessment findings.
func buildAssessSARIF(result *metrics.EnterpriseMetrics) map[string]interface{} {
	sarifResults := make([]map[string]interface{}, 0)

	// Emit weak categories as findings
	for cat, cm := range result.CategoryMetrics {
		if cm.DetectionRate < 0.8 {
			level := "warning"
			if cm.DetectionRate < 0.5 {
				level = "error"
			}
			sarifResults = append(sarifResults, map[string]interface{}{
				"ruleId":  "weak-category",
				"level":   level,
				"message": map[string]string{"text": fmt.Sprintf("Weak category %s: %.1f%% detection (%d/%d blocked), grade %s", cat, cm.DetectionRate*100, cm.Blocked, cm.TotalTests, cm.Grade)},
				"locations": []map[string]interface{}{
					{"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{"uri": result.TargetURL},
					}},
				},
			})
		}
	}

	return map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "WAFtester",
						"version":        defaults.Version,
						"informationUri": "https://github.com/waftester/waftester",
						"rules": []map[string]interface{}{
							{
								"id":               "weak-category",
								"shortDescription": map[string]string{"text": "Attack category with low WAF detection rate"},
							},
						},
					},
				},
				"results": sarifResults,
				"invocations": []map[string]interface{}{
					{
						"executionSuccessful": true,
						"commandLine":         fmt.Sprintf("waftester assess -u %s", result.TargetURL),
					},
				},
			},
		},
	}
}
