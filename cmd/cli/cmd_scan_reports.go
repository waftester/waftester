package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/ui"
)

// severityOrder defines canonical display ordering for severity levels.
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

// sortedSeverities returns the keys of a severity map sorted by severity order
// (Critical first, Info last). Unknown severities sort after known ones alphabetically.
func sortedSeverities(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		oi, oki := severityOrder[keys[i]]
		oj, okj := severityOrder[keys[j]]
		if !oki {
			oi = 100
		}
		if !okj {
			oj = 100
		}
		if oi != oj {
			return oi < oj
		}
		return keys[i] < keys[j]
	})
	return keys
}

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
	for _, sev := range sortedSeverities(result.BySeverity) {
		fmt.Fprintf(w, "| %s | %d |\n", sev, result.BySeverity[sev])
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
	for _, sev := range sortedSeverities(result.BySeverity) {
		count := result.BySeverity[sev]
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
	jsonData, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		ui.PrintError(fmt.Sprintf("marshal SARIF: %v", err))
		return
	}
	fmt.Fprintln(w, string(jsonData))
}

// printScanJSONL writes scan results in JSON Lines format.
func printScanJSONL(w io.Writer, target string, result *ScanResult) {
	for cat, count := range result.ByCategory {
		line, err := json.Marshal(map[string]interface{}{"category": cat, "count": count, "target": target})
		if err != nil {
			continue
		}
		fmt.Fprintln(w, string(line))
	}
}

// printScanConsoleSummary writes scan results to console with colored formatting.
func printScanConsoleSummary(result *ScanResult) {
	fmt.Println() // debug:keep
	ui.PrintSection("Scan Results")
	ui.PrintConfigLine("Duration", result.Duration.Round(time.Millisecond).String())
	ui.PrintConfigLine("Total Vulnerabilities", fmt.Sprintf("%d", result.TotalVulns))
	fmt.Println() // debug:keep

	if result.TotalVulns > 0 {
		ui.PrintSection("By Severity")
		for _, sev := range sortedSeverities(result.BySeverity) {
			count := result.BySeverity[sev]
			switch sev {
			case "critical":
				ui.PrintError(fmt.Sprintf("  %s: %d", sev, count))
			case "high":
				ui.PrintError(fmt.Sprintf("  %s: %d", sev, count))
			case "medium":
				ui.PrintWarning(fmt.Sprintf("  %s: %d", sev, count))
			default:
				ui.PrintInfo(fmt.Sprintf("  %s: %d", sev, count))
			}
		}
		fmt.Println() // debug:keep

		ui.PrintSection("By Category")
		for cat, count := range result.ByCategory {
			if count > 0 {
				word := "vulnerabilities"
				if count == 1 {
					word = "vulnerability"
				}
				ui.PrintConfigLine(cat, fmt.Sprintf("%d %s", count, word))
			}
		}
		fmt.Println() // debug:keep

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
			fmt.Println() // debug:keep
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
			fmt.Println() // debug:keep
		}
	} else {
		ui.PrintSuccess("No vulnerabilities found!")
	}
}

// scanFinding is an intermediate type for collecting vulnerability data
// from heterogeneous scan result types into a uniform HAR-exportable format.
type scanFinding struct {
	URL          string
	Method       string
	Payload      string
	Parameter    string
	Category     string
	Severity     string
	ResponseTime time.Duration
}

// collectScanFindings extracts all vulnerability findings from ScanResult
// into a flat list suitable for HAR entry generation.
func collectScanFindings(result *ScanResult) []scanFinding {
	var findings []scanFinding

	// add creates a scanFinding from individual fields.
	add := func(u, method, payload, param, category, severity string) {
		findings = append(findings, scanFinding{
			URL:       u,
			Method:    method,
			Payload:   payload,
			Parameter: param,
			Category:  category,
			Severity:  severity,
		})
	}

	// addBase creates a scanFinding from an embedded finding.Vulnerability.
	addBase := func(v finding.Vulnerability, category string) {
		add(v.URL, v.Method, v.Payload, v.Parameter, category, string(v.Severity))
	}

	// Types that embed finding.Vulnerability
	if r := result.SQLi; r != nil {
		for _, v := range r.Vulnerabilities {
			addBase(v.Vulnerability, "sqli")
		}
	}
	if r := result.XSS; r != nil {
		for _, v := range r.Vulnerabilities {
			addBase(v.Vulnerability, "xss")
		}
	}
	if r := result.Traversal; r != nil {
		for _, v := range r.Vulnerabilities {
			addBase(v.Vulnerability, "traversal")
		}
	}
	if r := result.CMDI; r != nil {
		for _, v := range r.Vulnerabilities {
			if v != nil {
				addBase(v.Vulnerability, "cmdi")
			}
		}
	}
	if r := result.Prototype; r != nil {
		for _, v := range r.Vulnerabilities {
			addBase(v.Vulnerability, "prototype")
		}
	}
	for _, v := range result.Upload {
		addBase(v.Vulnerability, "upload")
	}
	for _, v := range result.SSTI {
		if v != nil {
			addBase(v.Vulnerability, "ssti")
		}
	}
	for _, v := range result.XXE {
		if v != nil {
			addBase(v.Vulnerability, "xxe")
		}
	}

	// Types with their own URL/Payload/Parameter/Severity fields
	if r := result.NoSQLi; r != nil {
		for _, v := range r.Vulnerabilities {
			add(v.URL, "", v.Payload, v.Parameter, "nosqli", string(v.Severity))
		}
	}
	if r := result.HPP; r != nil {
		for _, v := range r.Vulnerabilities {
			add(v.URL, "", v.Payload, v.Parameter, "hpp", string(v.Severity))
		}
	}
	if r := result.CRLF; r != nil {
		for _, v := range r.Vulnerabilities {
			add(v.URL, "", v.Payload, v.Parameter, "crlf", string(v.Severity))
		}
	}
	if r := result.Redirect; r != nil {
		for _, v := range r.Vulnerabilities {
			payload := ""
			if v.Payload != nil {
				payload = v.Payload.Value
			}
			add(v.URL, "", payload, v.Parameter, "redirect", string(v.Severity))
		}
	}
	if r := result.HostHeader; r != nil {
		for _, v := range r.Vulnerabilities {
			add(v.URL, "", v.InjectedValue, v.Header, "hostheader", string(v.Severity))
		}
	}
	for _, v := range result.Deserialize {
		add(v.URL, "", v.Payload, v.Parameter, "deserialization", string(v.Severity))
	}
	for _, v := range result.OAuth {
		add(v.URL, "", v.Payload, v.Parameter, "oauth", string(v.Severity))
	}
	if r := result.SSRF; r != nil {
		for _, v := range r.Vulnerabilities {
			add(r.Target, "", v.Payload, v.Parameter, "ssrf", string(v.Severity))
		}
	}
	if r := result.GraphQL; r != nil {
		for _, v := range r.Vulnerabilities {
			add("", "POST", v.Query, "", "graphql", string(v.Severity))
		}
	}
	for _, v := range result.JWT {
		if v != nil {
			add("", "", "", "", "jwt", v.Severity)
		}
	}
	for _, v := range result.BizLogic {
		add(v.URL, v.Method, "", v.Parameter, "bizlogic", string(v.Severity))
	}
	for _, v := range result.APIFuzz {
		add(v.Endpoint, v.Method, v.Payload, v.Parameter, "apifuzz", string(v.Severity))
	}

	// Simple Result types with URL, Payload, Parameter, Severity as string
	for _, v := range result.LDAP {
		add(v.URL, "", v.Payload, v.Parameter, "ldap", string(v.Severity))
	}
	for _, v := range result.SSI {
		add(v.URL, "", v.Payload, v.Parameter, "ssi", string(v.Severity))
	}
	for _, v := range result.XPath {
		add(v.URL, "", v.Payload, v.Parameter, "xpath", string(v.Severity))
	}
	for _, v := range result.XMLInjection {
		add(v.URL, "", v.Payload, v.Parameter, "xmlinjection", string(v.Severity))
	}
	for _, v := range result.RFI {
		add(v.URL, "", v.Payload, v.Parameter, "rfi", string(v.Severity))
	}
	for _, v := range result.LFI {
		add(v.URL, "", v.Payload, v.Parameter, "lfi", string(v.Severity))
	}
	for _, v := range result.RCE {
		add(v.URL, "", v.Payload, v.Parameter, "rce", string(v.Severity))
	}
	return findings
}

// writeScanHAR generates a HAR 1.2 document from scan vulnerability findings.
// Each vulnerability becomes a HAR entry representing the request that triggered it.
func writeScanHAR(w io.Writer, result *ScanResult) error {
	findings := collectScanFindings(result)

	type nv struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type harContent struct {
		Size     int    `json:"size"`
		MimeType string `json:"mimeType"`
	}
	type harTimings struct {
		Send    float64 `json:"send"`
		Wait    float64 `json:"wait"`
		Receive float64 `json:"receive"`
	}
	type harRequest struct {
		Method      string `json:"method"`
		URL         string `json:"url"`
		HTTPVersion string `json:"httpVersion"`
		Headers     []nv   `json:"headers"`
		QueryString []nv   `json:"queryString"`
		Cookies     []nv   `json:"cookies"`
		HeadersSize int    `json:"headersSize"`
		BodySize    int    `json:"bodySize"`
	}
	type harResponse struct {
		Status      int        `json:"status"`
		StatusText  string     `json:"statusText"`
		HTTPVersion string     `json:"httpVersion"`
		Headers     []nv       `json:"headers"`
		Cookies     []nv       `json:"cookies"`
		Content     harContent `json:"content"`
		RedirectURL string     `json:"redirectURL"`
		HeadersSize int        `json:"headersSize"`
		BodySize    int        `json:"bodySize"`
	}
	type harEntry struct {
		Pageref         string      `json:"pageref"`
		StartedDateTime string      `json:"startedDateTime"`
		Time            float64     `json:"time"`
		Request         harRequest  `json:"request"`
		Response        harResponse `json:"response"`
		Cache           struct{}    `json:"cache"`
		Timings         harTimings  `json:"timings"`
		Comment         string      `json:"comment,omitempty"`
	}
	type pageTimings struct {
		OnLoad float64 `json:"onLoad"`
	}
	type harPage struct {
		StartedDateTime string      `json:"startedDateTime"`
		ID              string      `json:"id"`
		Title           string      `json:"title"`
		PageTimings     pageTimings `json:"pageTimings"`
	}

	startTime := result.StartTime.Format("2006-01-02T15:04:05.000Z")
	pageID := "page_1"

	entries := make([]harEntry, 0, len(findings))
	for _, f := range findings {
		method := f.Method
		if method == "" {
			method = "GET"
		}
		reqURL := f.URL
		if reqURL == "" {
			reqURL = result.Target
		}

		var qs []nv
		if parsed, err := url.Parse(reqURL); err == nil && parsed.RawQuery != "" {
			for k, vs := range parsed.Query() {
				for _, v := range vs {
					qs = append(qs, nv{Name: k, Value: v})
				}
			}
		}

		latencyMs := float64(f.ResponseTime.Milliseconds())
		comment := fmt.Sprintf("[%s] %s", f.Severity, f.Category)
		if f.Parameter != "" {
			comment += " param=" + f.Parameter
		}

		entries = append(entries, harEntry{
			Pageref:         pageID,
			StartedDateTime: startTime,
			Time:            latencyMs,
			Request: harRequest{
				Method:      method,
				URL:         reqURL,
				HTTPVersion: "HTTP/1.1",
				Headers:     []nv{},
				QueryString: qs,
				Cookies:     []nv{},
				HeadersSize: -1,
				BodySize:    -1,
			},
			Response: harResponse{
				Status:      0,
				StatusText:  "",
				HTTPVersion: "HTTP/1.1",
				Headers:     []nv{},
				Cookies:     []nv{},
				Content:     harContent{Size: 0, MimeType: "text/html"},
				RedirectURL: "",
				HeadersSize: -1,
				BodySize:    -1,
			},
			Cache: struct{}{},
			Timings: harTimings{
				Send:    0,
				Wait:    latencyMs,
				Receive: 0,
			},
			Comment: comment,
		})
	}

	doc := map[string]interface{}{
		"log": map[string]interface{}{
			"version": "1.2",
			"creator": map[string]string{
				"name":    "waftester",
				"version": defaults.Version,
			},
			"pages": []harPage{{
				StartedDateTime: startTime,
				ID:              pageID,
				Title:           "WAFtester Scan: " + result.Target,
				PageTimings:     pageTimings{OnLoad: float64(result.Duration.Milliseconds())},
			}},
			"entries": entries,
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// writeScanExports writes scan results to all configured enterprise export files.
// The scan command produces ScanResult (vulnerability findings), not ExecutionResults
// (test pass/fail), so it needs its own export logic using the scan-specific formatters.
func writeScanExports(outFlags *OutputFlags, target string, result *ScanResult) {
	if !outFlags.HasEnterpriseExports() {
		return
	}

	outFlags.PrintOutputConfig()

	writeToFile := func(path string, writeFn func(w io.Writer) error) {
		f, err := os.Create(path)
		if err != nil {
			ui.PrintError(fmt.Sprintf("export %s: %v", path, err))
			return
		}
		if err := writeFn(f); err != nil {
			_ = f.Close()
			ui.PrintError(fmt.Sprintf("export %s: %v", path, err))
			return
		}
		if err := f.Close(); err != nil {
			ui.PrintError(fmt.Sprintf("export %s: %v", path, err))
			return
		}
		ui.PrintSuccess(fmt.Sprintf("Exported: %s", path))
	}

	if outFlags.JUnitExport != "" {
		ui.PrintError("JUnit export is not supported for scan")
	}
	if outFlags.PDFExport != "" {
		ui.PrintError("PDF export is not supported for scan")
	}
	if outFlags.SonarQubeExport != "" {
		ui.PrintError("SonarQube export is not supported for scan")
	}
	if outFlags.GitLabSASTExport != "" {
		ui.PrintError("GitLab SAST export is not supported for scan")
	}
	if outFlags.DefectDojoExport != "" {
		ui.PrintError("DefectDojo export is not supported for scan")
	}
	if outFlags.HARExport != "" {
		writeToFile(outFlags.HARExport, func(w io.Writer) error {
			return writeScanHAR(w, result)
		})
	}
	if outFlags.CycloneDXExport != "" {
		ui.PrintError("CycloneDX export is not supported for scan")
	}
	if outFlags.XMLExport != "" {
		ui.PrintError("XML export is not supported for scan")
	}

	if outFlags.JSONExport != "" {
		writeToFile(outFlags.JSONExport, func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		})
	}
	if outFlags.JSONLExport != "" {
		writeToFile(outFlags.JSONLExport, func(w io.Writer) error {
			printScanJSONL(w, target, result)
			return nil
		})
	}
	if outFlags.SARIFExport != "" {
		writeToFile(outFlags.SARIFExport, func(w io.Writer) error {
			printScanSARIF(w, target, result)
			return nil
		})
	}
	if outFlags.CSVExport != "" {
		writeToFile(outFlags.CSVExport, func(w io.Writer) error {
			printScanCSV(w, target, result)
			return nil
		})
	}
	if outFlags.HTMLExport != "" {
		writeToFile(outFlags.HTMLExport, func(w io.Writer) error {
			printScanHTML(w, result)
			return nil
		})
	}
	if outFlags.MDExport != "" {
		writeToFile(outFlags.MDExport, func(w io.Writer) error {
			printScanMarkdown(w, result)
			return nil
		})
	}
}
