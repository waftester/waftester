package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/crawler"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/ui"
)

// writeCrawlExports writes crawl results to enterprise export files (--json-export, --sarif-export, etc.).
func writeCrawlExports(outFlags *OutputFlags, target string, results []*crawler.CrawlResult, forms []crawler.FormInfo, scripts, urls []string, duration time.Duration) {
	if outFlags.JSONExport == "" && outFlags.JSONLExport == "" && outFlags.SARIFExport == "" &&
		outFlags.CSVExport == "" && outFlags.HTMLExport == "" && outFlags.MDExport == "" &&
		outFlags.JUnitExport == "" && outFlags.PDFExport == "" {
		return
	}

	if outFlags.JUnitExport != "" {
		ui.PrintError("JUnit export is not supported for crawl")
	}
	if outFlags.PDFExport != "" {
		ui.PrintError("PDF export is not supported for crawl")
	}

	output := struct {
		Target      string                 `json:"target"`
		Results     []*crawler.CrawlResult `json:"results"`
		Forms       []crawler.FormInfo     `json:"forms"`
		Scripts     []string               `json:"scripts"`
		URLs        []string               `json:"urls"`
		Duration    string                 `json:"duration"`
		CompletedAt time.Time              `json:"completed_at"`
	}{
		Target:      target,
		Results:     results,
		Forms:       forms,
		Scripts:     scripts,
		URLs:        urls,
		Duration:    duration.String(),
		CompletedAt: time.Now(),
	}

	if outFlags.JSONExport != "" {
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
			writeErr := error(nil)
			for _, r := range results {
				if err := enc.Encode(r); err != nil {
					writeErr = err
					break
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
		sarif := buildCrawlSARIF(target, results, forms)
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
			fmt.Fprintln(f, "url,status_code,content_type,title,depth,forms,scripts")
			for _, r := range results {
				fmt.Fprintf(f, "%s,%d,%s,%s,%d,%d,%d\n",
					r.URL, r.StatusCode, r.ContentType, r.Title, r.Depth, len(r.Forms), len(r.Scripts))
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
			fmt.Fprintf(f, "<html><head><title>Crawl Results</title></head><body>\n")
			fmt.Fprintf(f, "<h1>Crawl Results</h1>\n")
			fmt.Fprintf(f, "<p>Target: %s | Pages: %d | Forms: %d | Scripts: %d</p>\n",
				html.EscapeString(target), len(results), len(forms), len(scripts))
			if len(results) > 0 {
				fmt.Fprintf(f, "<table border='1'><tr><th>URL</th><th>Status</th><th>Type</th><th>Title</th><th>Depth</th></tr>\n")
				for _, r := range results {
					fmt.Fprintf(f, "<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td></tr>\n",
						html.EscapeString(r.URL), r.StatusCode, html.EscapeString(r.ContentType),
						html.EscapeString(r.Title), r.Depth)
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
			fmt.Fprintf(f, "# Crawl Results\n\n")
			fmt.Fprintf(f, "- **Target:** %s\n- **Pages:** %d\n- **Forms:** %d\n- **Scripts:** %d\n- **Duration:** %s\n\n",
				target, len(results), len(forms), len(scripts), duration.Round(time.Millisecond))
			if len(results) > 0 {
				fmt.Fprintf(f, "| URL | Status | Type | Title | Depth |\n")
				fmt.Fprintf(f, "|-----|--------|------|-------|-------|\n")
				for _, r := range results {
					fmt.Fprintf(f, "| %s | %d | %s | %s | %d |\n",
						r.URL, r.StatusCode, r.ContentType, r.Title, r.Depth)
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

// buildCrawlSARIF creates a minimal SARIF 2.1.0 structure for crawl findings.
func buildCrawlSARIF(target string, results []*crawler.CrawlResult, forms []crawler.FormInfo) map[string]interface{} {
	sarifResults := make([]map[string]interface{}, 0, len(forms))
	for _, form := range forms {
		sarifResults = append(sarifResults, map[string]interface{}{
			"ruleId":  "crawl-form",
			"level":   "note",
			"message": map[string]string{"text": fmt.Sprintf("Form found: %s %s (%d inputs)", form.Method, form.Action, len(form.Inputs))},
			"locations": []map[string]interface{}{
				{"physicalLocation": map[string]interface{}{
					"artifactLocation": map[string]string{"uri": form.Action},
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
						"name":           "WAFtester",
						"version":        defaults.Version,
						"informationUri": "https://github.com/waftester/waftester",
						"rules": []map[string]interface{}{
							{
								"id":               "crawl-form",
								"shortDescription": map[string]string{"text": "HTML form discovered during crawl"},
							},
						},
					},
				},
				"results": sarifResults,
				"invocations": []map[string]interface{}{
					{
						"executionSuccessful": true,
						"commandLine":         fmt.Sprintf("waftester crawl -u %s", target),
					},
				},
			},
		},
	}
}
