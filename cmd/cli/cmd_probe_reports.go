package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/ui"
)

// writeProbeExports writes probe results to enterprise export files (--json-export, --sarif-export, etc.).
func writeProbeExports(outFlags *OutputFlags, results []*ProbeResults, elapsed time.Duration) {
	if outFlags.JSONExport == "" && outFlags.JSONLExport == "" && outFlags.SARIFExport == "" &&
		outFlags.CSVExport == "" && outFlags.HTMLExport == "" && outFlags.MDExport == "" {
		return
	}

	if outFlags.JSONExport != "" {
		output := struct {
			Results     []*ProbeResults `json:"results"`
			Total       int             `json:"total"`
			Duration    string          `json:"duration"`
			CompletedAt time.Time       `json:"completed_at"`
		}{
			Results:     results,
			Total:       len(results),
			Duration:    elapsed.String(),
			CompletedAt: time.Now(),
		}
		if err := writeJSONFile(outFlags.JSONExport, output); err != nil {
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
			for _, r := range results {
				_ = enc.Encode(r)
			}
			f.Close()
			ui.PrintSuccess(fmt.Sprintf("JSONL export saved to %s", outFlags.JSONLExport))
		}
	}

	if outFlags.SARIFExport != "" {
		sarif := buildProbeSARIF(results)
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
			fmt.Fprintln(f, "target,status_code,content_length,content_type,server,word_count,line_count,alive")
			for _, r := range results {
				fmt.Fprintf(f, "%s,%d,%d,%s,%s,%d,%d,%t\n",
					r.Target, r.StatusCode, r.ContentLength, r.ContentType, r.Server, r.WordCount, r.LineCount, r.Alive)
			}
			f.Close()
			ui.PrintSuccess(fmt.Sprintf("CSV export saved to %s", outFlags.CSVExport))
		}
	}

	if outFlags.HTMLExport != "" {
		f, err := os.Create(outFlags.HTMLExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("HTML export: %v", err))
		} else {
			alive := 0
			for _, r := range results {
				if r.Alive {
					alive++
				}
			}
			fmt.Fprintf(f, "<html><head><title>Probe Results</title></head><body>\n")
			fmt.Fprintf(f, "<h1>Probe Results</h1>\n")
			fmt.Fprintf(f, "<p>Total: %d | Alive: %d | Duration: %s</p>\n",
				len(results), alive, elapsed.Round(time.Millisecond))
			if len(results) > 0 {
				fmt.Fprintf(f, "<table border='1'><tr><th>Target</th><th>Status</th><th>Content-Type</th><th>Server</th><th>Alive</th></tr>\n")
				for _, r := range results {
					fmt.Fprintf(f, "<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%t</td></tr>\n",
						r.Target, r.StatusCode, r.ContentType, r.Server, r.Alive)
				}
				fmt.Fprintf(f, "</table>\n")
			}
			fmt.Fprintf(f, "</body></html>\n")
			f.Close()
			ui.PrintSuccess(fmt.Sprintf("HTML export saved to %s", outFlags.HTMLExport))
		}
	}

	if outFlags.MDExport != "" {
		f, err := os.Create(outFlags.MDExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Markdown export: %v", err))
		} else {
			alive := 0
			for _, r := range results {
				if r.Alive {
					alive++
				}
			}
			fmt.Fprintf(f, "# Probe Results\n\n")
			fmt.Fprintf(f, "- **Total:** %d\n- **Alive:** %d\n- **Duration:** %s\n\n",
				len(results), alive, elapsed.Round(time.Millisecond))
			if len(results) > 0 {
				fmt.Fprintf(f, "| Target | Status | Content-Type | Server | Alive |\n")
				fmt.Fprintf(f, "|--------|--------|--------------|--------|-------|\n")
				for _, r := range results {
					fmt.Fprintf(f, "| %s | %d | %s | %s | %t |\n",
						r.Target, r.StatusCode, r.ContentType, r.Server, r.Alive)
				}
			}
			f.Close()
			ui.PrintSuccess(fmt.Sprintf("Markdown export saved to %s", outFlags.MDExport))
		}
	}
}

// buildProbeSARIF creates a minimal SARIF 2.1.0 structure for probe findings.
func buildProbeSARIF(results []*ProbeResults) map[string]interface{} {
	sarifResults := make([]map[string]interface{}, 0, len(results))
	for _, r := range results {
		if !r.Alive {
			continue
		}
		sarifResults = append(sarifResults, map[string]interface{}{
			"ruleId":  "probe-finding",
			"level":   "note",
			"message": map[string]string{"text": fmt.Sprintf("Probe: %s (status %d, server: %s)", r.Target, r.StatusCode, r.Server)},
			"locations": []map[string]interface{}{
				{"physicalLocation": map[string]interface{}{
					"artifactLocation": map[string]string{"uri": r.Target},
				}},
			},
		})
	}
	return map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "WAFtester",
						"version": defaults.Version,
					},
				},
				"results": sarifResults,
			},
		},
	}
}
