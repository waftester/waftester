// Package output provides the CLI builder for wiring up output dispatching.
package output

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/jsonutil"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/hooks"
	"github.com/waftester/waftester/pkg/output/writers"
	"github.com/waftester/waftester/pkg/report"
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

	// Template configuration path for HTML reports
	TemplateConfigPath string

	// Enterprise exports
	SonarQubeExport  string
	GitLabSASTExport string
	DefectDojoExport string
	HARExport        string
	CycloneDXExport  string
	XMLExport        string

	// Elasticsearch streaming
	ElasticsearchURL      string
	ElasticsearchAPIKey   string
	ElasticsearchUsername string
	ElasticsearchPassword string
	ElasticsearchIndex    string
	ElasticsearchInsecure bool

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
	JiraURL       string
	JiraProject   string
	JiraEmail     string
	JiraToken     string
	JiraIssueType string
	JiraLabels    string
	JiraAssignee  string

	// GitHub Issues
	GitHubIssuesToken     string
	GitHubIssuesOwner     string
	GitHubIssuesRepo      string
	GitHubIssuesURL       string
	GitHubIssuesLabels    string
	GitHubIssuesAssignees string

	// Azure DevOps
	ADOOrganization  string
	ADOProject       string
	ADOPAT           string
	ADOWorkItemType  string
	ADOAreaPath      string
	ADOIterationPath string
	ADOAssignedTo    string
	ADOTags          string

	// OpenTelemetry
	OTelEndpoint string
	OTelInsecure bool

	// History storage
	HistoryPath string
	HistoryTags []string

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

		// Build HTMLConfig with optional template customization
		htmlCfg := writers.HTMLConfig{
			Title:           "WAFtester Security Report",
			Theme:           "auto",
			IncludeEvidence: !cfg.OmitEvidence,
			IncludeJSON:     true,
		}

		// Load template config if provided
		if cfg.TemplateConfigPath != "" {
			templateCfg, err := report.LoadTemplateConfig(cfg.TemplateConfigPath)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("failed to load template config: %w", err)
			}
			// Apply template settings to HTML config
			applyTemplateToHTMLConfig(&htmlCfg, templateCfg)
		}

		writer := writers.NewHTMLWriter(f, htmlCfg)
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

	// XML export
	if cfg.XMLExport != "" {
		f, err := openFile(cfg.XMLExport)
		if err != nil {
			cleanup()
			return nil, err
		}
		writer := writers.NewXMLWriter(f, writers.XMLOptions{
			CreatorName:     defaults.ToolName,
			CreatorVersion:  cfg.Version,
			IncludeEvidence: !cfg.OmitEvidence,
			PrettyPrint:     true,
		})
		d.RegisterWriter(writer)
	}

	// Elasticsearch streaming
	if cfg.ElasticsearchURL != "" {
		writer := writers.NewElasticsearchWriter(writers.ElasticsearchConfig{
			URL:                cfg.ElasticsearchURL,
			APIKey:             cfg.ElasticsearchAPIKey,
			Username:           cfg.ElasticsearchUsername,
			Password:           cfg.ElasticsearchPassword,
			Index:              cfg.ElasticsearchIndex,
			InsecureSkipVerify: cfg.ElasticsearchInsecure,
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
		issueType := cfg.JiraIssueType
		if issueType == "" {
			issueType = "Bug"
		}
		// Parse labels - use custom if provided, otherwise defaults
		labels := []string{defaults.ToolName, "security"}
		if cfg.JiraLabels != "" {
			labels = parseCSV(cfg.JiraLabels)
		}
		hook := hooks.NewJiraHook(cfg.JiraURL, hooks.JiraOptions{
			ProjectKey: cfg.JiraProject,
			Username:   cfg.JiraEmail,
			APIToken:   cfg.JiraToken,
			IssueType:  issueType,
			Labels:     labels,
			AssigneeID: cfg.JiraAssignee,
		})
		d.RegisterHook(hook)
	}

	// GitHub Issues
	if cfg.GitHubIssuesToken != "" && cfg.GitHubIssuesOwner != "" && cfg.GitHubIssuesRepo != "" {
		// Parse labels - use custom if provided, otherwise defaults
		labels := []string{defaults.ToolName, "security", "waf-bypass"}
		if cfg.GitHubIssuesLabels != "" {
			labels = parseCSV(cfg.GitHubIssuesLabels)
		}

		// Parse assignees
		var assignees []string
		if cfg.GitHubIssuesAssignees != "" {
			assignees = parseCSV(cfg.GitHubIssuesAssignees)
		}

		hook, err := hooks.NewGitHubIssuesHook(hooks.GitHubIssuesOptions{
			Token:     cfg.GitHubIssuesToken,
			Owner:     cfg.GitHubIssuesOwner,
			Repo:      cfg.GitHubIssuesRepo,
			BaseURL:   cfg.GitHubIssuesURL,
			Labels:    labels,
			Assignees: assignees,
		})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("github issues hook: %w", err)
		}
		d.RegisterHook(hook)
	}

	// Azure DevOps
	if cfg.ADOOrganization != "" && cfg.ADOProject != "" && cfg.ADOPAT != "" {
		// Parse tags - use custom if provided, otherwise defaults (semicolon-separated for ADO)
		tags := []string{defaults.ToolName, "security", "waf-bypass"}
		if cfg.ADOTags != "" {
			tags = parseSemicolonSeparated(cfg.ADOTags)
		}
		hook := hooks.NewAzureDevOpsHook(hooks.AzureDevOpsOptions{
			Organization:  cfg.ADOOrganization,
			Project:       cfg.ADOProject,
			PAT:           cfg.ADOPAT,
			WorkItemType:  cfg.ADOWorkItemType,
			AreaPath:      cfg.ADOAreaPath,
			IterationPath: cfg.ADOIterationPath,
			Tags:          tags,
			AssignedTo:    cfg.ADOAssignedTo,
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

	// History storage
	if cfg.HistoryPath != "" {
		hook, err := hooks.NewHistoryHook(hooks.HistoryHookOptions{
			StorePath: cfg.HistoryPath,
			Tags:      cfg.HistoryTags,
		})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to create history hook: %w", err)
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

// closeFile captures file close errors into a named error return.
// Use with named returns: defer closeFile(f, &err)
func closeFile(f *os.File, errp *error) {
	if cerr := f.Close(); cerr != nil && *errp == nil {
		*errp = cerr
	}
}

// writeResultsJSON writes ExecutionResults as a JSON file.
func writeResultsJSON(path string, results ExecutionResults, omitRaw bool) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	encoder := jsonutil.NewStreamEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// writeResultsJSONL writes ExecutionResults as a single-line JSON.
func writeResultsJSONL(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	encoder := jsonutil.NewStreamEncoder(f)
	return encoder.Encode(results)
}

// writeResultsSARIF writes ExecutionResults in SARIF format.
func writeResultsSARIF(path string, results ExecutionResults, version string) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

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

	encoder := jsonutil.NewStreamEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

// convertToSARIFResults converts ExecutionResults to SARIF result format.
func convertToSARIFResults(results ExecutionResults) []map[string]interface{} {
	var sarifResults []map[string]interface{}
	for _, bypass := range results.BypassDetails {
		sarifResults = append(sarifResults, map[string]interface{}{
			"ruleId": bypass.PayloadID,
			"level":  finding.Severity(bypass.Severity).ToSARIF(),
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

// writeResultsJUnit writes ExecutionResults in JUnit XML format.
func writeResultsJUnit(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	// Generate JUnit XML
	if _, err = fmt.Fprintf(f, `<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="%d" failures="%d" errors="%d" time="%.2f">
  <testsuite name="`+defaults.ToolNameDisplay+`" tests="%d" failures="%d" errors="%d" time="%.2f">
`,
		results.TotalTests, results.PassedTests, results.ErrorTests, results.Duration.Seconds(),
		results.TotalTests, results.PassedTests, results.ErrorTests, results.Duration.Seconds()); err != nil {
		return err
	}

	for _, bypass := range results.BypassDetails {
		if _, err = fmt.Fprintf(f, `    <testcase name="%s" classname="%s">
      <failure message="WAF bypass detected">`, xmlEscape(bypass.PayloadID), xmlEscape(bypass.Category)); err != nil {
			return err
		}
		if err = xml.EscapeText(f, []byte(bypass.Payload)); err != nil {
			return err
		}
		if _, err = fmt.Fprint(f, "</failure>\n    </testcase>\n"); err != nil {
			return err
		}
	}

	_, err = fmt.Fprintf(f, "  </testsuite>\n</testsuites>\n")
	return err
}

// writeResultsCSV writes ExecutionResults in CSV format.
func writeResultsCSV(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	// Write header
	w := csv.NewWriter(f)
	w.Write([]string{"PayloadID", "Category", "Severity", "Endpoint", "Method", "StatusCode"})

	// Write bypass details
	for _, bypass := range results.BypassDetails {
		w.Write([]string{
			bypass.PayloadID, bypass.Category, bypass.Severity,
			bypass.Endpoint, bypass.Method, fmt.Sprintf("%d", bypass.StatusCode),
		})
	}
	w.Flush()

	return w.Error()
}

// writeResultsHTML writes ExecutionResults in HTML format.
func writeResultsHTML(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	_, err = fmt.Fprintf(f, `<!DOCTYPE html>
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

	return err
}

// writeResultsMarkdown writes ExecutionResults in Markdown format.
func writeResultsMarkdown(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	_, err = fmt.Fprintf(f, `# WAFtester Security Report

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

	return err
}

// writeResultsSonarQube writes ExecutionResults in SonarQube format.
func writeResultsSonarQube(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	sonarReport := map[string]interface{}{
		"issues": convertToSonarQubeIssues(results),
	}

	encoder := jsonutil.NewStreamEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sonarReport)
}

func convertToSonarQubeIssues(results ExecutionResults) []map[string]interface{} {
	var issues []map[string]interface{}
	for _, bypass := range results.BypassDetails {
		issues = append(issues, map[string]interface{}{
			"engineId": defaults.ToolName,
			"ruleId":   bypass.PayloadID,
			"severity": finding.Severity(bypass.Severity).ToSonarQube(),
			"type":     "VULNERABILITY",
			"primaryLocation": map[string]interface{}{
				"message":  fmt.Sprintf("WAF bypass: %s", bypass.Category),
				"filePath": bypass.Endpoint,
			},
		})
	}
	return issues
}

// writeResultsGitLabSAST writes ExecutionResults in GitLab SAST format.
func writeResultsGitLabSAST(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	report := map[string]interface{}{
		"version": "15.0.0",
		"scan": map[string]interface{}{
			"type":    "sast",
			"scanner": map[string]interface{}{"id": defaults.ToolName, "name": defaults.ToolNameDisplay},
		},
		"vulnerabilities": convertToGitLabVulns(results),
	}

	encoder := jsonutil.NewStreamEncoder(f)
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
			"severity": finding.Severity(bypass.Severity).ToGitLab(),
		})
	}
	return vulns
}

// writeResultsDefectDojo writes ExecutionResults in DefectDojo format.
func writeResultsDefectDojo(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	report := map[string]interface{}{
		"findings": convertToDefectDojoFindings(results),
	}

	encoder := jsonutil.NewStreamEncoder(f)
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
func writeResultsCycloneDX(path string, results ExecutionResults) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer closeFile(f, &err)

	report := map[string]interface{}{
		"bomFormat":       "CycloneDX",
		"specVersion":     "1.5",
		"vulnerabilities": convertToCycloneDXVulns(results),
	}

	encoder := jsonutil.NewStreamEncoder(f)
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

// applyTemplateToHTMLConfig applies template configuration settings to HTML writer config.
func applyTemplateToHTMLConfig(htmlCfg *writers.HTMLConfig, templateCfg *report.TemplateConfig) {
	// Branding
	if templateCfg.Branding.CompanyName != "" {
		htmlCfg.CompanyName = templateCfg.Branding.CompanyName
	}
	if templateCfg.Branding.LogoURL != "" {
		htmlCfg.CompanyLogo = templateCfg.Branding.LogoURL
	}

	// Layout
	if templateCfg.Layout.Theme != "" {
		htmlCfg.Theme = templateCfg.Layout.Theme
	}
	if templateCfg.Layout.PrintOptimized {
		htmlCfg.PrintOptimized = true
	}

	// Sections
	htmlCfg.ShowExecutiveSummary = templateCfg.Sections.ExecutiveSummary
	htmlCfg.ShowRiskChart = templateCfg.Sections.CategoryBreakdown || templateCfg.Sections.RadarChart
}

// parseCSV splits a comma-separated string into a slice of trimmed strings.
// Empty strings are filtered out.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// parseSemicolonSeparated splits a semicolon-separated string into a slice of trimmed strings.
// Azure DevOps uses semicolons for tag separation.
func parseSemicolonSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ";")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// xmlEscape escapes a string for use in XML attribute values.
func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
