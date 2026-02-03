// Package output provides the CLI builder for wiring up output dispatching.
package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/hooks"
	"github.com/waftester/waftester/pkg/output/writers"
)

// Config configures the output dispatcher based on CLI flags.
type Config struct {
	// File outputs
	OutputFile  string
	Format      string
	JSONExport  string
	JSONLExport string
	SARIFExport string
	JUnitExport string
	CSVExport   string
	HTMLExport  string
	MDExport    string
	PDFExport   string

	// Enterprise exports
	SonarQubeExport  string
	GitLabSASTExport string
	DefectDojoExport string
	HARExport        string
	CycloneDXExport  string

	// Streaming
	JSONMode   bool
	StreamMode bool
	BatchSize  int

	// Content
	OmitRaw      bool
	OmitEvidence bool
	OnlyBypasses bool

	// Progress
	ShowStats     bool
	StatsJSON     bool
	StatsInterval int
	Silent        bool
	NoColor       bool

	// Hooks
	WebhookURL    string
	WebhookAll    bool
	GitHubOutput  bool
	GitHubSummary bool
	SlackWebhook  string
	TeamsWebhook  string
	PagerDutyKey  string
	MetricsPort   int

	// Jira
	JiraURL     string
	JiraProject string
	JiraEmail   string
	JiraToken   string

	// OpenTelemetry
	OTelEndpoint string
	OTelInsecure bool

	// Version for reports
	Version string
}

// BuildDispatcher creates a dispatcher configured with writers and hooks based on the config.
// It opens all output files and registers the appropriate writers and hooks.
// The caller is responsible for calling Close() on the dispatcher when done.
func BuildDispatcher(cfg Config) (*dispatcher.Dispatcher, error) {
	// Create dispatcher with config
	dispatcherCfg := dispatcher.Config{
		BatchSize: cfg.BatchSize,
		Async:     true, // Enable async hook processing for performance
	}
	if dispatcherCfg.BatchSize <= 0 {
		dispatcherCfg.BatchSize = 100
	}
	d := dispatcher.New(dispatcherCfg)

	// Track opened files for cleanup on error
	var openedFiles []*os.File
	cleanup := func() {
		for _, f := range openedFiles {
			f.Close()
		}
	}

	// Helper to open a file for writing
	openFile := func(path string) (*os.File, error) {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file %s: %w", path, err)
		}
		openedFiles = append(openedFiles, f)
		return f, nil
	}

	// === FILE WRITERS ===

	// JSON export
	if cfg.JSONExport != "" {
		f, err := openFile(cfg.JSONExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewJSONWriter(f, writers.JSONOptions{
			OmitRaw:      cfg.OmitRaw,
			OmitEvidence: cfg.OmitEvidence,
			Pretty:       true,
		})
		d.RegisterWriter(writer)
	}

	// JSONL export (streaming)
	if cfg.JSONLExport != "" {
		f, err := openFile(cfg.JSONLExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewJSONLWriter(f, writers.JSONLOptions{
			OmitRaw:      cfg.OmitRaw,
			OmitEvidence: cfg.OmitEvidence,
			OnlyBypasses: cfg.OnlyBypasses,
		})
		d.RegisterWriter(writer)
	}

	// SARIF export (GitHub/GitLab security)
	if cfg.SARIFExport != "" {
		f, err := openFile(cfg.SARIFExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewSARIFWriter(f, writers.SARIFOptions{
			ToolName:    defaults.ToolName,
			ToolVersion: cfg.Version,
			ToolURI:     "https://github.com/waftester/waftester",
		})
		d.RegisterWriter(writer)
	}

	// JUnit export (CI/CD)
	if cfg.JUnitExport != "" {
		f, err := openFile(cfg.JUnitExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewJUnitWriter(f, writers.JUnitOptions{
			SuiteName: defaults.ToolName,
			Package:   defaults.ToolName + ".security",
		})
		d.RegisterWriter(writer)
	}

	// CSV export
	if cfg.CSVExport != "" {
		f, err := openFile(cfg.CSVExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewCSVWriter(f, writers.CSVOptions{
			IncludeHeader: true,
		})
		d.RegisterWriter(writer)
	}

	// HTML export
	if cfg.HTMLExport != "" {
		f, err := openFile(cfg.HTMLExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewHTMLWriter(f, writers.HTMLConfig{
			Title:           "WAFtester Security Report",
			Theme:           "auto",
			IncludeEvidence: !cfg.OmitEvidence,
			IncludeJSON:     true,
		})
		d.RegisterWriter(writer)
	}

	// Markdown export
	if cfg.MDExport != "" {
		f, err := openFile(cfg.MDExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewMarkdownWriter(f, writers.MarkdownConfig{
			Title:           "WAFtester Security Report",
			Flavor:          "github",
			SortBy:          "severity",
			IncludeTOC:      true,
			IncludeEvidence: !cfg.OmitEvidence,
			IncludeOWASP:    true,
			IncludeCWE:      true,
		})
		d.RegisterWriter(writer)
	}

	// PDF export
	if cfg.PDFExport != "" {
		f, err := openFile(cfg.PDFExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewPDFWriter(f, writers.PDFConfig{
			Title:           "WAFtester Security Report",
			IncludeEvidence: !cfg.OmitEvidence,
			PageSize:        "A4",
			Orientation:     "P",
		})
		d.RegisterWriter(writer)
	}

	// === ENTERPRISE EXPORTS ===

	// SonarQube export
	if cfg.SonarQubeExport != "" {
		f, err := openFile(cfg.SonarQubeExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewSonarQubeWriter(f, writers.SonarQubeOptions{
			ToolName:    defaults.ToolName,
			ToolVersion: cfg.Version,
		})
		d.RegisterWriter(writer)
	}

	// GitLab SAST export
	if cfg.GitLabSASTExport != "" {
		f, err := openFile(cfg.GitLabSASTExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewGitLabSASTWriter(f, writers.GitLabSASTOptions{
			ScannerID:      defaults.ToolName,
			ScannerVersion: cfg.Version,
			ScannerVendor:  defaults.ToolNameDisplay,
		})
		d.RegisterWriter(writer)
	}

	// DefectDojo export
	if cfg.DefectDojoExport != "" {
		f, err := openFile(cfg.DefectDojoExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewDefectDojoWriter(f, writers.DefectDojoOptions{
			ToolName:    defaults.ToolName,
			ToolVersion: cfg.Version,
		})
		d.RegisterWriter(writer)
	}

	// HAR export
	if cfg.HARExport != "" {
		f, err := openFile(cfg.HARExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewHARWriter(f, writers.HAROptions{
			CreatorName:    defaults.ToolName,
			CreatorVersion: cfg.Version,
			OnlyBypasses:   cfg.OnlyBypasses,
		})
		d.RegisterWriter(writer)
	}

	// CycloneDX VEX export
	if cfg.CycloneDXExport != "" {
		f, err := openFile(cfg.CycloneDXExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewCycloneDXWriter(f, writers.CycloneDXOptions{
			ToolName:    defaults.ToolName,
			ToolVersion: cfg.Version,
		})
		d.RegisterWriter(writer)
	}

	// === CONSOLE OUTPUT ===

	// Table writer for console output (unless silent or JSON mode)
	if !cfg.Silent && !cfg.JSONMode {
		mode := "summary"
		if cfg.StreamMode {
			mode = "streaming"
		}
		writer := writers.NewTableWriter(os.Stdout, writers.TableConfig{
			Mode:             mode,
			ColorEnabled:     !cfg.NoColor,
			UnicodeEnabled:   true,
			ShowOnlyBypasses: cfg.OnlyBypasses,
		})
		d.RegisterWriter(writer)
	}

	// JSON streaming mode (to stdout)
	if cfg.JSONMode {
		writer := writers.NewJSONLWriter(os.Stdout, writers.JSONLOptions{
			OmitRaw:      cfg.OmitRaw,
			OmitEvidence: cfg.OmitEvidence,
			OnlyBypasses: cfg.OnlyBypasses,
		})
		d.RegisterWriter(writer)
	}

	// === HOOKS ===

	// Generic webhook
	if cfg.WebhookURL != "" {
		hook := hooks.NewWebhookHook(cfg.WebhookURL, hooks.WebhookOptions{
			OnlyBypasses: !cfg.WebhookAll,
		})
		d.RegisterHook(hook)
	}

	// GitHub Actions
	if cfg.GitHubOutput {
		hook, err := hooks.NewGitHubActionsHook(hooks.GitHubActionsOptions{
			AddSummary: cfg.GitHubSummary,
		})
		if err != nil {
			// Log warning but don't fail - might not be in GitHub Actions
			// The hook validates environment, so we skip if not in GHA
		} else {
			d.RegisterHook(hook)
		}
	}

	// Slack
	if cfg.SlackWebhook != "" {
		hook := hooks.NewSlackHook(cfg.SlackWebhook, hooks.SlackOptions{
			Username:       defaults.ToolNameDisplay,
			IconEmoji:      ":shield:",
			OnlyOnBypasses: cfg.OnlyBypasses,
		})
		d.RegisterHook(hook)
	}

	// Microsoft Teams
	if cfg.TeamsWebhook != "" {
		hook := hooks.NewTeamsHook(cfg.TeamsWebhook, hooks.TeamsOptions{
			OnlyOnBypasses: cfg.OnlyBypasses,
		})
		d.RegisterHook(hook)
	}

	// PagerDuty
	if cfg.PagerDutyKey != "" {
		hook := hooks.NewPagerDutyHook(cfg.PagerDutyKey, hooks.PagerDutyOptions{
			Source: defaults.ToolName,
		})
		d.RegisterHook(hook)
	}

	// Prometheus metrics
	if cfg.MetricsPort > 0 {
		hook, err := hooks.NewPrometheusHook(hooks.PrometheusOptions{
			Port: cfg.MetricsPort,
			Path: "/metrics",
		})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to create Prometheus hook: %w", err)
		}
		d.RegisterHook(hook)
	}

	// Jira
	if cfg.JiraURL != "" && cfg.JiraProject != "" {
		hook := hooks.NewJiraHook(cfg.JiraURL, hooks.JiraOptions{
			ProjectKey: cfg.JiraProject,
			Username:   cfg.JiraEmail,
			APIToken:   cfg.JiraToken,
			IssueType:  "Bug",
			Labels:     []string{defaults.ToolName, "security"},
		})
		d.RegisterHook(hook)
	}

	// OpenTelemetry
	if cfg.OTelEndpoint != "" {
		hook, err := hooks.NewOTelHook(hooks.OTelOptions{
			Endpoint:    cfg.OTelEndpoint,
			ServiceName: defaults.ToolName,
			Insecure:    cfg.OTelInsecure,
		})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to create OpenTelemetry hook: %w", err)
		}
		d.RegisterHook(hook)
	}

	return d, nil
}

// WriteEnterpriseExports writes execution results to all configured enterprise export formats.
// This is used by commands that aggregate results before writing (e.g., run command with multi-target).
func WriteEnterpriseExports(cfg Config, results ExecutionResults) error {
	var errs []error

	// JSON export - write results directly as JSON
	if cfg.JSONExport != "" {
		if err := writeResultsJSON(cfg.JSONExport, results, cfg.OmitRaw); err != nil {
			errs = append(errs, fmt.Errorf("JSON export: %w", err))
		}
	}

	// JSONL export - write as single-line JSON
	if cfg.JSONLExport != "" {
		if err := writeResultsJSONL(cfg.JSONLExport, results); err != nil {
			errs = append(errs, fmt.Errorf("JSONL export: %w", err))
		}
	}

	// SARIF export
	if cfg.SARIFExport != "" {
		if err := writeResultsSARIF(cfg.SARIFExport, results, cfg.Version); err != nil {
			errs = append(errs, fmt.Errorf("SARIF export: %w", err))
		}
	}

	// JUnit export
	if cfg.JUnitExport != "" {
		if err := writeResultsJUnit(cfg.JUnitExport, results); err != nil {
			errs = append(errs, fmt.Errorf("JUnit export: %w", err))
		}
	}

	// CSV export
	if cfg.CSVExport != "" {
		if err := writeResultsCSV(cfg.CSVExport, results); err != nil {
			errs = append(errs, fmt.Errorf("CSV export: %w", err))
		}
	}

	// HTML export
	if cfg.HTMLExport != "" {
		if err := writeResultsHTML(cfg.HTMLExport, results); err != nil {
			errs = append(errs, fmt.Errorf("HTML export: %w", err))
		}
	}

	// Markdown export
	if cfg.MDExport != "" {
		if err := writeResultsMarkdown(cfg.MDExport, results); err != nil {
			errs = append(errs, fmt.Errorf("Markdown export: %w", err))
		}
	}

	// SonarQube export
	if cfg.SonarQubeExport != "" {
		if err := writeResultsSonarQube(cfg.SonarQubeExport, results); err != nil {
			errs = append(errs, fmt.Errorf("SonarQube export: %w", err))
		}
	}

	// GitLab SAST export
	if cfg.GitLabSASTExport != "" {
		if err := writeResultsGitLabSAST(cfg.GitLabSASTExport, results); err != nil {
			errs = append(errs, fmt.Errorf("GitLab SAST export: %w", err))
		}
	}

	// DefectDojo export
	if cfg.DefectDojoExport != "" {
		if err := writeResultsDefectDojo(cfg.DefectDojoExport, results); err != nil {
			errs = append(errs, fmt.Errorf("DefectDojo export: %w", err))
		}
	}

	// CycloneDX export
	if cfg.CycloneDXExport != "" {
		if err := writeResultsCycloneDX(cfg.CycloneDXExport, results); err != nil {
			errs = append(errs, fmt.Errorf("CycloneDX export: %w", err))
		}
	}

	// Combine errors if any
	if len(errs) > 0 {
		return fmt.Errorf("enterprise export errors: %v", errs)
	}

	return nil
}

// writeResultsJSON writes ExecutionResults as a JSON file.
func writeResultsJSON(path string, results ExecutionResults, omitRaw bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// writeResultsJSONL writes ExecutionResults as a single-line JSON.
func writeResultsJSONL(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	return encoder.Encode(results)
}

// writeResultsSARIF writes ExecutionResults in SARIF format.
func writeResultsSARIF(path string, results ExecutionResults, version string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Generate minimal SARIF structure
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           defaults.ToolName,
						"version":        version,
						"informationUri": "https://github.com/waftester/waftester",
					},
				},
				"results": convertToSARIFResults(results),
			},
		},
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

// convertToSARIFResults converts ExecutionResults to SARIF result format.
func convertToSARIFResults(results ExecutionResults) []map[string]interface{} {
	var sarifResults []map[string]interface{}
	for _, bypass := range results.BypassDetails {
		sarifResults = append(sarifResults, map[string]interface{}{
			"ruleId": bypass.PayloadID,
			"level":  severityToSARIFLevel(bypass.Severity),
			"message": map[string]interface{}{
				"text": fmt.Sprintf("WAF bypass detected: %s", bypass.Category),
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": bypass.Endpoint,
						},
					},
				},
			},
		})
	}
	return sarifResults
}

// severityToSARIFLevel converts severity to SARIF level.
func severityToSARIFLevel(severity string) string {
	switch severity {
	case "Critical", "High":
		return "error"
	case "Medium":
		return "warning"
	default:
		return "note"
	}
}

// writeResultsJUnit writes ExecutionResults in JUnit XML format.
func writeResultsJUnit(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Generate JUnit XML
	fmt.Fprintf(f, `<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="%d" failures="%d" errors="%d" time="%.2f">
  <testsuite name="`+defaults.ToolNameDisplay+`" tests="%d" failures="%d" errors="%d" time="%.2f">
`,
		results.TotalTests, results.PassedTests, results.ErrorTests, results.Duration.Seconds(),
		results.TotalTests, results.PassedTests, results.ErrorTests, results.Duration.Seconds())

	for _, bypass := range results.BypassDetails {
		fmt.Fprintf(f, `    <testcase name="%s" classname="%s">
      <failure message="WAF bypass detected">%s</failure>
    </testcase>
`, bypass.PayloadID, bypass.Category, bypass.Payload)
	}

	fmt.Fprintf(f, "  </testsuite>\n</testsuites>\n")
	return nil
}

// writeResultsCSV writes ExecutionResults in CSV format.
func writeResultsCSV(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write header
	fmt.Fprintln(f, "PayloadID,Category,Severity,Endpoint,Method,StatusCode")

	// Write bypass details
	for _, bypass := range results.BypassDetails {
		fmt.Fprintf(f, "%s,%s,%s,%s,%s,%d\n",
			bypass.PayloadID, bypass.Category, bypass.Severity,
			bypass.Endpoint, bypass.Method, bypass.StatusCode)
	}

	return nil
}

// writeResultsHTML writes ExecutionResults in HTML format.
func writeResultsHTML(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, `<!DOCTYPE html>
<html>
<head><title>WAFtester Report</title></head>
<body>
<h1>WAFtester Security Report</h1>
<h2>Summary</h2>
<ul>
<li>Total Tests: %d</li>
<li>Passed (Bypasses): %d</li>
<li>Blocked: %d</li>
<li>Failed: %d</li>
<li>Errors: %d</li>
<li>Duration: %v</li>
</ul>
</body>
</html>
`, results.TotalTests, results.PassedTests, results.BlockedTests, results.FailedTests, results.ErrorTests, results.Duration)

	return nil
}

// writeResultsMarkdown writes ExecutionResults in Markdown format.
func writeResultsMarkdown(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, `# WAFtester Security Report

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | %d |
| Bypasses | %d |
| Blocked | %d |
| Failed | %d |
| Errors | %d |
| Duration | %v |
`, results.TotalTests, results.PassedTests, results.BlockedTests, results.FailedTests, results.ErrorTests, results.Duration)

	return nil
}

// writeResultsSonarQube writes ExecutionResults in SonarQube format.
func writeResultsSonarQube(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sonarReport := map[string]interface{}{
		"issues": convertToSonarQubeIssues(results),
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sonarReport)
}

func convertToSonarQubeIssues(results ExecutionResults) []map[string]interface{} {
	var issues []map[string]interface{}
	for _, bypass := range results.BypassDetails {
		issues = append(issues, map[string]interface{}{
			"engineId": defaults.ToolName,
			"ruleId":   bypass.PayloadID,
			"severity": severityToSonarQube(bypass.Severity),
			"type":     "VULNERABILITY",
			"primaryLocation": map[string]interface{}{
				"message":  fmt.Sprintf("WAF bypass: %s", bypass.Category),
				"filePath": bypass.Endpoint,
			},
		})
	}
	return issues
}

func severityToSonarQube(severity string) string {
	switch severity {
	case "Critical":
		return "BLOCKER"
	case "High":
		return "CRITICAL"
	case "Medium":
		return "MAJOR"
	default:
		return "MINOR"
	}
}

// writeResultsGitLabSAST writes ExecutionResults in GitLab SAST format.
func writeResultsGitLabSAST(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	report := map[string]interface{}{
		"version": "15.0.0",
		"scan": map[string]interface{}{
			"type":    "sast",
			"scanner": map[string]interface{}{"id": defaults.ToolName, "name": defaults.ToolNameDisplay},
		},
		"vulnerabilities": convertToGitLabVulns(results),
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func convertToGitLabVulns(results ExecutionResults) []map[string]interface{} {
	var vulns []map[string]interface{}
	for _, bypass := range results.BypassDetails {
		vulns = append(vulns, map[string]interface{}{
			"id":       bypass.PayloadID,
			"category": "sast",
			"name":     bypass.Category,
			"message":  fmt.Sprintf("WAF bypass: %s", bypass.Payload),
			"severity": severityToGitLab(bypass.Severity),
		})
	}
	return vulns
}

func severityToGitLab(severity string) string {
	switch severity {
	case "Critical":
		return "Critical"
	case "High":
		return "High"
	case "Medium":
		return "Medium"
	default:
		return "Low"
	}
}

// writeResultsDefectDojo writes ExecutionResults in DefectDojo format.
func writeResultsDefectDojo(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	report := map[string]interface{}{
		"findings": convertToDefectDojoFindings(results),
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func convertToDefectDojoFindings(results ExecutionResults) []map[string]interface{} {
	var findings []map[string]interface{}
	for _, bypass := range results.BypassDetails {
		findings = append(findings, map[string]interface{}{
			"title":       bypass.PayloadID,
			"description": fmt.Sprintf("WAF bypass detected: %s", bypass.Payload),
			"severity":    bypass.Severity,
			"endpoint":    bypass.Endpoint,
		})
	}
	return findings
}

// writeResultsCycloneDX writes ExecutionResults in CycloneDX VEX format.
func writeResultsCycloneDX(path string, results ExecutionResults) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	report := map[string]interface{}{
		"bomFormat":       "CycloneDX",
		"specVersion":     "1.5",
		"vulnerabilities": convertToCycloneDXVulns(results),
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func convertToCycloneDXVulns(results ExecutionResults) []map[string]interface{} {
	var vulns []map[string]interface{}
	for _, bypass := range results.BypassDetails {
		vulns = append(vulns, map[string]interface{}{
			"id": bypass.PayloadID,
			"ratings": []map[string]interface{}{
				{"severity": bypass.Severity},
			},
			"description": fmt.Sprintf("WAF bypass: %s", bypass.Category),
		})
	}
	return vulns
}
