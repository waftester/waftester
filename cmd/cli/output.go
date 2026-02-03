// Package main provides the CLI for waftester.
// This file contains unified output flag handling for all scan commands.
package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/output/baseline"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
	"github.com/waftester/waftester/pkg/output/policy"
	"github.com/waftester/waftester/pkg/ui"
)

// OutputFlags defines all output-related CLI flags.
// All scan commands should use this struct for unified output configuration.
type OutputFlags struct {
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

	// Webhooks
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

	// Policy and baseline
	PolicyFile   string
	BaselineFile string

	// Version for reports
	Version string
}

// RegisterFlags registers all output flags on a FlagSet.
// Call this in each command's flag setup to get unified output options.
func (o *OutputFlags) RegisterFlags(fs *flag.FlagSet) {
	// File outputs
	fs.StringVar(&o.OutputFile, "o", "", "Output file path")
	fs.StringVar(&o.OutputFile, "output", "", "Output file path")
	fs.StringVar(&o.Format, "format", "console", "Output format: console,json,jsonl,sarif,csv,md,html,pdf")
	fs.StringVar(&o.JSONExport, "json-export", "", "Export results to JSON file")
	fs.StringVar(&o.JSONLExport, "jsonl-export", "", "Export results to JSONL file (streaming)")
	fs.StringVar(&o.SARIFExport, "sarif-export", "", "Export results to SARIF file")
	fs.StringVar(&o.JUnitExport, "junit-export", "", "Export results to JUnit XML file")
	fs.StringVar(&o.CSVExport, "csv-export", "", "Export results to CSV file")
	fs.StringVar(&o.HTMLExport, "html-export", "", "Export results to HTML file")
	fs.StringVar(&o.MDExport, "md-export", "", "Export results to Markdown file")
	fs.StringVar(&o.PDFExport, "pdf-export", "", "Export results to PDF file")

	// Enterprise exports
	fs.StringVar(&o.SonarQubeExport, "sonarqube-export", "", "Export results to SonarQube format")
	fs.StringVar(&o.GitLabSASTExport, "gitlab-sast-export", "", "Export results to GitLab SAST format")
	fs.StringVar(&o.DefectDojoExport, "defectdojo-export", "", "Export results to DefectDojo format")
	fs.StringVar(&o.HARExport, "har-export", "", "Export HTTP Archive (HAR) file")
	fs.StringVar(&o.CycloneDXExport, "cyclonedx-export", "", "Export CycloneDX VEX file")

	// Streaming
	fs.BoolVar(&o.JSONMode, "json", false, "Output JSON to stdout")
	fs.BoolVar(&o.JSONMode, "j", false, "Output JSON to stdout (alias)")
	fs.BoolVar(&o.StreamMode, "stream", false, "Enable streaming output mode")
	fs.IntVar(&o.BatchSize, "batch-size", 100, "Batch size for streaming output")

	// Content
	fs.BoolVar(&o.OmitRaw, "omit-raw", false, "Omit raw request/response from output")
	fs.BoolVar(&o.OmitEvidence, "omit-evidence", false, "Omit evidence from output")
	fs.BoolVar(&o.OnlyBypasses, "only-bypasses", false, "Only show WAF bypasses in output")

	// Progress
	fs.BoolVar(&o.ShowStats, "stats", false, "Show statistics during execution")
	fs.BoolVar(&o.StatsJSON, "stats-json", false, "Output statistics as JSON")
	fs.IntVar(&o.StatsInterval, "stats-interval", 5, "Statistics update interval in seconds")
	fs.BoolVar(&o.Silent, "silent", false, "Silent mode - no progress output")
	fs.BoolVar(&o.Silent, "s", false, "Silent mode (alias)")
	fs.BoolVar(&o.NoColor, "no-color", false, "Disable colored output")
	fs.BoolVar(&o.NoColor, "nc", false, "No color (alias)")

	// Webhooks
	fs.StringVar(&o.WebhookURL, "webhook", "", "Webhook URL for real-time notifications")
	fs.BoolVar(&o.WebhookAll, "webhook-all", false, "Send all findings to webhook (not just bypasses)")
	fs.BoolVar(&o.GitHubOutput, "github-output", false, "Enable GitHub Actions output")
	fs.BoolVar(&o.GitHubSummary, "github-summary", false, "Add to GitHub Actions job summary")
	fs.StringVar(&o.SlackWebhook, "slack-webhook", "", "Slack webhook URL for notifications")
	fs.StringVar(&o.TeamsWebhook, "teams-webhook", "", "Microsoft Teams webhook URL")
	fs.StringVar(&o.PagerDutyKey, "pagerduty-key", "", "PagerDuty routing key for alerts")
	fs.IntVar(&o.MetricsPort, "metrics-port", 0, "Prometheus metrics port (0 = disabled)")

	// Jira
	fs.StringVar(&o.JiraURL, "jira-url", "", "Jira instance URL")
	fs.StringVar(&o.JiraProject, "jira-project", "", "Jira project key")
	fs.StringVar(&o.JiraEmail, "jira-email", "", "Jira user email")
	fs.StringVar(&o.JiraToken, "jira-token", "", "Jira API token")

	// OpenTelemetry
	fs.StringVar(&o.OTelEndpoint, "otel-endpoint", "", "OpenTelemetry endpoint URL")
	fs.BoolVar(&o.OTelInsecure, "otel-insecure", false, "Use insecure connection for OTEL")

	// Policy and baseline
	fs.StringVar(&o.PolicyFile, "policy", "", "Policy YAML file for exit code rules")
	fs.StringVar(&o.BaselineFile, "baseline", "", "Baseline JSON file for regression detection")
}

// RegisterEnterpriseFlags registers only the NEW enterprise output flags.
// Use this for commands that already have legacy output flags defined.
// This avoids flag redefinition panics while adding new capabilities.
func (o *OutputFlags) RegisterEnterpriseFlags(fs *flag.FlagSet) {
	// File exports (new enterprise formats)
	fs.StringVar(&o.JSONExport, "json-export", "", "Export results to JSON file")
	fs.StringVar(&o.JSONLExport, "jsonl-export", "", "Export results to JSONL file (streaming)")
	fs.StringVar(&o.SARIFExport, "sarif-export", "", "Export results to SARIF file")
	fs.StringVar(&o.JUnitExport, "junit-export", "", "Export results to JUnit XML file")
	fs.StringVar(&o.CSVExport, "csv-export", "", "Export results to CSV file")
	fs.StringVar(&o.HTMLExport, "html-export", "", "Export results to HTML file")
	fs.StringVar(&o.MDExport, "md-export", "", "Export results to Markdown file")
	fs.StringVar(&o.PDFExport, "pdf-export", "", "Export results to PDF file")

	// Enterprise exports
	fs.StringVar(&o.SonarQubeExport, "sonarqube-export", "", "Export results to SonarQube format")
	fs.StringVar(&o.GitLabSASTExport, "gitlab-sast-export", "", "Export results to GitLab SAST format")
	fs.StringVar(&o.DefectDojoExport, "defectdojo-export", "", "Export results to DefectDojo format")
	fs.StringVar(&o.HARExport, "har-export", "", "Export HTTP Archive (HAR) file")
	fs.StringVar(&o.CycloneDXExport, "cyclonedx-export", "", "Export CycloneDX VEX file")

	// Content options
	fs.BoolVar(&o.OmitRaw, "omit-raw", false, "Omit raw request/response from output")
	fs.BoolVar(&o.OmitEvidence, "omit-evidence", false, "Omit evidence from output")
	fs.BoolVar(&o.OnlyBypasses, "only-bypasses", false, "Only show WAF bypasses in output")
	fs.IntVar(&o.BatchSize, "batch-size", 100, "Batch size for streaming output")

	// Stats options
	fs.BoolVar(&o.ShowStats, "stats", false, "Show statistics during execution")
	fs.BoolVar(&o.StatsJSON, "stats-json", false, "Output statistics as JSON")
	fs.IntVar(&o.StatsInterval, "stats-interval", 5, "Statistics update interval in seconds")

	// Webhooks
	fs.StringVar(&o.WebhookURL, "webhook", "", "Webhook URL for real-time notifications")
	fs.BoolVar(&o.WebhookAll, "webhook-all", false, "Send all findings to webhook (not just bypasses)")
	fs.BoolVar(&o.GitHubOutput, "github-output", false, "Enable GitHub Actions output")
	fs.BoolVar(&o.GitHubSummary, "github-summary", false, "Add to GitHub Actions job summary")
	fs.StringVar(&o.SlackWebhook, "slack-webhook", "", "Slack webhook URL for notifications")
	fs.StringVar(&o.TeamsWebhook, "teams-webhook", "", "Microsoft Teams webhook URL")
	fs.StringVar(&o.PagerDutyKey, "pagerduty-key", "", "PagerDuty routing key for alerts")
	fs.IntVar(&o.MetricsPort, "metrics-port", 0, "Prometheus metrics port (0 = disabled)")

	// Jira
	fs.StringVar(&o.JiraURL, "jira-url", "", "Jira instance URL")
	fs.StringVar(&o.JiraProject, "jira-project", "", "Jira project key")
	fs.StringVar(&o.JiraEmail, "jira-email", "", "Jira user email")
	fs.StringVar(&o.JiraToken, "jira-token", "", "Jira API token")

	// OpenTelemetry
	fs.StringVar(&o.OTelEndpoint, "otel-endpoint", "", "OpenTelemetry endpoint URL")
	fs.BoolVar(&o.OTelInsecure, "otel-insecure", false, "Use insecure connection for OTEL")

	// Policy and baseline
	fs.StringVar(&o.PolicyFile, "policy", "", "Policy YAML file for exit code rules")
	fs.StringVar(&o.BaselineFile, "baseline", "", "Baseline JSON file for regression detection")
}

// RegisterRunEnterpriseFlags registers enterprise flags for the run command.
// This excludes flags that config.ParseFlags() already defines:
// - o, output (output file)
// - format (output format)
// - j, jsonl (JSON mode)
// - silent, s (silent mode)
// - no-color, nc (color control)
// - stats, stats-interval (statistics)
// - verbose, v (verbose mode)
// The run command uses config.ParseFlags() which handles the global flag package.
func (o *OutputFlags) RegisterRunEnterpriseFlags(fs *flag.FlagSet) {
	// File exports (new enterprise formats)
	fs.StringVar(&o.JSONExport, "json-export", "", "Export results to JSON file")
	fs.StringVar(&o.JSONLExport, "jsonl-export", "", "Export results to JSONL file (streaming)")
	fs.StringVar(&o.SARIFExport, "sarif-export", "", "Export results to SARIF file")
	fs.StringVar(&o.JUnitExport, "junit-export", "", "Export results to JUnit XML file")
	fs.StringVar(&o.CSVExport, "csv-export", "", "Export results to CSV file")
	fs.StringVar(&o.HTMLExport, "html-export", "", "Export results to HTML file")
	fs.StringVar(&o.MDExport, "md-export", "", "Export results to Markdown file")
	fs.StringVar(&o.PDFExport, "pdf-export", "", "Export results to PDF file")

	// Enterprise exports
	fs.StringVar(&o.SonarQubeExport, "sonarqube-export", "", "Export results to SonarQube format")
	fs.StringVar(&o.GitLabSASTExport, "gitlab-sast-export", "", "Export results to GitLab SAST format")
	fs.StringVar(&o.DefectDojoExport, "defectdojo-export", "", "Export results to DefectDojo format")
	fs.StringVar(&o.HARExport, "har-export", "", "Export HTTP Archive (HAR) file")
	fs.StringVar(&o.CycloneDXExport, "cyclonedx-export", "", "Export CycloneDX VEX file")

	// Content options
	fs.BoolVar(&o.OmitRaw, "omit-raw", false, "Omit raw request/response from output")
	fs.BoolVar(&o.OmitEvidence, "omit-evidence", false, "Omit evidence from output")
	fs.BoolVar(&o.OnlyBypasses, "only-bypasses", false, "Only show WAF bypasses in output")
	fs.IntVar(&o.BatchSize, "batch-size", 100, "Batch size for streaming output")

	// NOTE: stats/stats-interval excluded - config.ParseFlags() already defines them

	// Webhooks
	fs.StringVar(&o.WebhookURL, "webhook", "", "Webhook URL for real-time notifications")
	fs.BoolVar(&o.WebhookAll, "webhook-all", false, "Send all findings to webhook (not just bypasses)")
	fs.BoolVar(&o.GitHubOutput, "github-output", false, "Enable GitHub Actions output")
	fs.BoolVar(&o.GitHubSummary, "github-summary", false, "Add to GitHub Actions job summary")
	fs.StringVar(&o.SlackWebhook, "slack-webhook", "", "Slack webhook URL for notifications")
	fs.StringVar(&o.TeamsWebhook, "teams-webhook", "", "Microsoft Teams webhook URL")
	fs.StringVar(&o.PagerDutyKey, "pagerduty-key", "", "PagerDuty routing key for alerts")
	fs.IntVar(&o.MetricsPort, "metrics-port", 0, "Prometheus metrics port (0 = disabled)")

	// Jira
	fs.StringVar(&o.JiraURL, "jira-url", "", "Jira instance URL")
	fs.StringVar(&o.JiraProject, "jira-project", "", "Jira project key")
	fs.StringVar(&o.JiraEmail, "jira-email", "", "Jira user email")
	fs.StringVar(&o.JiraToken, "jira-token", "", "Jira API token")

	// OpenTelemetry
	fs.StringVar(&o.OTelEndpoint, "otel-endpoint", "", "OpenTelemetry endpoint URL")
	fs.BoolVar(&o.OTelInsecure, "otel-insecure", false, "Use insecure connection for OTEL")

	// Policy and baseline (critical for CI/CD gating)
	fs.StringVar(&o.PolicyFile, "policy", "", "Policy YAML file for exit code rules")
	fs.StringVar(&o.BaselineFile, "baseline", "", "Baseline JSON file for regression detection")
}

// RegisterProbeEnterpriseFlags registers enterprise flags for probe command.
// This excludes flags that probe already defines (stats, stats-interval).
func (o *OutputFlags) RegisterProbeEnterpriseFlags(fs *flag.FlagSet) {
	// File exports (new enterprise formats)
	fs.StringVar(&o.JSONExport, "json-export", "", "Export results to JSON file")
	fs.StringVar(&o.JSONLExport, "jsonl-export", "", "Export results to JSONL file (streaming)")
	fs.StringVar(&o.SARIFExport, "sarif-export", "", "Export results to SARIF file")
	fs.StringVar(&o.JUnitExport, "junit-export", "", "Export results to JUnit XML file")
	fs.StringVar(&o.CSVExport, "csv-export", "", "Export results to CSV file")
	fs.StringVar(&o.HTMLExport, "html-export", "", "Export results to HTML file")
	fs.StringVar(&o.MDExport, "md-export", "", "Export results to Markdown file")
	fs.StringVar(&o.PDFExport, "pdf-export", "", "Export results to PDF file")

	// Enterprise exports
	fs.StringVar(&o.SonarQubeExport, "sonarqube-export", "", "Export results to SonarQube format")
	fs.StringVar(&o.GitLabSASTExport, "gitlab-sast-export", "", "Export results to GitLab SAST format")
	fs.StringVar(&o.DefectDojoExport, "defectdojo-export", "", "Export results to DefectDojo format")
	fs.StringVar(&o.HARExport, "har-export", "", "Export HTTP Archive (HAR) file")
	fs.StringVar(&o.CycloneDXExport, "cyclonedx-export", "", "Export CycloneDX VEX file")

	// Content options
	fs.BoolVar(&o.OmitRaw, "omit-raw", false, "Omit raw request/response from output")
	fs.BoolVar(&o.OmitEvidence, "omit-evidence", false, "Omit evidence from output")
	fs.BoolVar(&o.OnlyBypasses, "only-bypasses", false, "Only show WAF bypasses in output")
	fs.IntVar(&o.BatchSize, "batch-size", 100, "Batch size for streaming output")

	// NOTE: stats flags excluded - probe already defines them

	// Webhooks
	fs.StringVar(&o.WebhookURL, "webhook", "", "Webhook URL for real-time notifications")
	fs.BoolVar(&o.WebhookAll, "webhook-all", false, "Send all findings to webhook (not just bypasses)")
	fs.BoolVar(&o.GitHubOutput, "github-output", false, "Enable GitHub Actions output")
	fs.BoolVar(&o.GitHubSummary, "github-summary", false, "Add to GitHub Actions job summary")
	fs.StringVar(&o.SlackWebhook, "slack-webhook", "", "Slack webhook URL for notifications")
	fs.StringVar(&o.TeamsWebhook, "teams-webhook", "", "Microsoft Teams webhook URL")
	fs.StringVar(&o.PagerDutyKey, "pagerduty-key", "", "PagerDuty routing key for alerts")
	fs.IntVar(&o.MetricsPort, "metrics-port", 0, "Prometheus metrics port (0 = disabled)")

	// Jira
	fs.StringVar(&o.JiraURL, "jira-url", "", "Jira instance URL")
	fs.StringVar(&o.JiraProject, "jira-project", "", "Jira project key")
	fs.StringVar(&o.JiraEmail, "jira-email", "", "Jira user email")
	fs.StringVar(&o.JiraToken, "jira-token", "", "Jira API token")

	// OpenTelemetry
	fs.StringVar(&o.OTelEndpoint, "otel-endpoint", "", "OpenTelemetry endpoint URL")
	fs.BoolVar(&o.OTelInsecure, "otel-insecure", false, "Use insecure connection for OTEL")

	// Policy and baseline
	fs.StringVar(&o.PolicyFile, "policy", "", "Policy YAML file for exit code rules")
	fs.StringVar(&o.BaselineFile, "baseline", "", "Baseline JSON file for regression detection")
}

// RegisterFuzzEnterpriseFlags registers enterprise flags for fuzz command.
// This excludes flags that fuzz already defines:
// - silent/s, no-color/nc (UI flags)
// - json, stream (output mode flags)
// - csv, md, html-output (format flags - fuzz uses boolean versions)
func (o *OutputFlags) RegisterFuzzEnterpriseFlags(fs *flag.FlagSet) {
	// File exports (excluding csv, md, html which fuzz defines as booleans)
	fs.StringVar(&o.JSONExport, "json-export", "", "Export results to JSON file")
	fs.StringVar(&o.JSONLExport, "jsonl-export", "", "Export results to JSONL file (streaming)")
	fs.StringVar(&o.SARIFExport, "sarif-export", "", "Export results to SARIF file")
	fs.StringVar(&o.JUnitExport, "junit-export", "", "Export results to JUnit XML file")
	fs.StringVar(&o.PDFExport, "pdf-export", "", "Export results to PDF file")

	// Enterprise exports
	fs.StringVar(&o.SonarQubeExport, "sonarqube-export", "", "Export results to SonarQube format")
	fs.StringVar(&o.GitLabSASTExport, "gitlab-sast-export", "", "Export results to GitLab SAST format")
	fs.StringVar(&o.DefectDojoExport, "defectdojo-export", "", "Export results to DefectDojo format")
	fs.StringVar(&o.HARExport, "har-export", "", "Export HTTP Archive (HAR) file")
	fs.StringVar(&o.CycloneDXExport, "cyclonedx-export", "", "Export CycloneDX VEX file")

	// Content options
	fs.BoolVar(&o.OmitRaw, "omit-raw", false, "Omit raw request/response from output")
	fs.BoolVar(&o.OmitEvidence, "omit-evidence", false, "Omit evidence from output")
	fs.BoolVar(&o.OnlyBypasses, "only-bypasses", false, "Only show WAF bypasses in output")
	fs.IntVar(&o.BatchSize, "batch-size", 100, "Batch size for streaming output")

	// Stats options
	fs.BoolVar(&o.ShowStats, "stats", false, "Show statistics during execution")
	fs.BoolVar(&o.StatsJSON, "stats-json", false, "Output statistics as JSON")
	fs.IntVar(&o.StatsInterval, "stats-interval", 5, "Statistics update interval in seconds")

	// Webhooks
	fs.StringVar(&o.WebhookURL, "webhook", "", "Webhook URL for real-time notifications")
	fs.BoolVar(&o.WebhookAll, "webhook-all", false, "Send all findings to webhook (not just bypasses)")
	fs.BoolVar(&o.GitHubOutput, "github-output", false, "Enable GitHub Actions output")
	fs.BoolVar(&o.GitHubSummary, "github-summary", false, "Add to GitHub Actions job summary")
	fs.StringVar(&o.SlackWebhook, "slack-webhook", "", "Slack webhook URL for notifications")
	fs.StringVar(&o.TeamsWebhook, "teams-webhook", "", "Microsoft Teams webhook URL")
	fs.StringVar(&o.PagerDutyKey, "pagerduty-key", "", "PagerDuty routing key for alerts")
	fs.IntVar(&o.MetricsPort, "metrics-port", 0, "Prometheus metrics port (0 = disabled)")

	// Jira
	fs.StringVar(&o.JiraURL, "jira-url", "", "Jira instance URL")
	fs.StringVar(&o.JiraProject, "jira-project", "", "Jira project key")
	fs.StringVar(&o.JiraEmail, "jira-email", "", "Jira user email")
	fs.StringVar(&o.JiraToken, "jira-token", "", "Jira API token")

	// OpenTelemetry
	fs.StringVar(&o.OTelEndpoint, "otel-endpoint", "", "OpenTelemetry endpoint URL")
	fs.BoolVar(&o.OTelInsecure, "otel-insecure", false, "Use insecure connection for OTEL")

	// Policy and baseline
	fs.StringVar(&o.PolicyFile, "policy", "", "Policy YAML file for exit code rules")
	fs.StringVar(&o.BaselineFile, "baseline", "", "Baseline JSON file for regression detection")
}

// RegisterBypassEnterpriseFlags registers enterprise flags for bypass command.
// This excludes flags that bypass already defines:
// - o (output file)
// - stream (streaming mode)
func (o *OutputFlags) RegisterBypassEnterpriseFlags(fs *flag.FlagSet) {
	// File exports (excluding -o which bypass defines as outputFile)
	fs.StringVar(&o.JSONExport, "json-export", "", "Export results to JSON file")
	fs.StringVar(&o.JSONLExport, "jsonl-export", "", "Export results to JSONL file (streaming)")
	fs.StringVar(&o.SARIFExport, "sarif-export", "", "Export results to SARIF file")
	fs.StringVar(&o.JUnitExport, "junit-export", "", "Export results to JUnit XML file")
	fs.StringVar(&o.CSVExport, "csv-export", "", "Export results to CSV file")
	fs.StringVar(&o.HTMLExport, "html-export", "", "Export results to HTML file")
	fs.StringVar(&o.MDExport, "md-export", "", "Export results to Markdown file")
	fs.StringVar(&o.PDFExport, "pdf-export", "", "Export results to PDF file")

	// Enterprise exports
	fs.StringVar(&o.SonarQubeExport, "sonarqube-export", "", "Export results to SonarQube format")
	fs.StringVar(&o.GitLabSASTExport, "gitlab-sast-export", "", "Export results to GitLab SAST format")
	fs.StringVar(&o.DefectDojoExport, "defectdojo-export", "", "Export results to DefectDojo format")
	fs.StringVar(&o.HARExport, "har-export", "", "Export HTTP Archive (HAR) file")
	fs.StringVar(&o.CycloneDXExport, "cyclonedx-export", "", "Export CycloneDX VEX file")

	// Content options
	fs.BoolVar(&o.OmitRaw, "omit-raw", false, "Omit raw request/response from output")
	fs.BoolVar(&o.OmitEvidence, "omit-evidence", false, "Omit evidence from output")
	fs.BoolVar(&o.OnlyBypasses, "only-bypasses", false, "Only show WAF bypasses in output")
	fs.IntVar(&o.BatchSize, "batch-size", 100, "Batch size for streaming output")

	// Stats options
	fs.BoolVar(&o.ShowStats, "stats", false, "Show statistics during execution")
	fs.BoolVar(&o.StatsJSON, "stats-json", false, "Output statistics as JSON")
	fs.IntVar(&o.StatsInterval, "stats-interval", 5, "Statistics update interval in seconds")

	// Webhooks
	fs.StringVar(&o.WebhookURL, "webhook", "", "Webhook URL for real-time notifications")
	fs.BoolVar(&o.WebhookAll, "webhook-all", false, "Send all findings to webhook (not just bypasses)")
	fs.BoolVar(&o.GitHubOutput, "github-output", false, "Enable GitHub Actions output")
	fs.BoolVar(&o.GitHubSummary, "github-summary", false, "Add to GitHub Actions job summary")
	fs.StringVar(&o.SlackWebhook, "slack-webhook", "", "Slack webhook URL for notifications")
	fs.StringVar(&o.TeamsWebhook, "teams-webhook", "", "Microsoft Teams webhook URL")
	fs.StringVar(&o.PagerDutyKey, "pagerduty-key", "", "PagerDuty routing key for alerts")
	fs.IntVar(&o.MetricsPort, "metrics-port", 0, "Prometheus metrics port (0 = disabled)")

	// Jira
	fs.StringVar(&o.JiraURL, "jira-url", "", "Jira instance URL")
	fs.StringVar(&o.JiraProject, "jira-project", "", "Jira project key")
	fs.StringVar(&o.JiraEmail, "jira-email", "", "Jira user email")
	fs.StringVar(&o.JiraToken, "jira-token", "", "Jira API token")

	// OpenTelemetry
	fs.StringVar(&o.OTelEndpoint, "otel-endpoint", "", "OpenTelemetry endpoint URL")
	fs.BoolVar(&o.OTelInsecure, "otel-insecure", false, "Use insecure connection for OTEL")

	// Policy and baseline
	fs.StringVar(&o.PolicyFile, "policy", "", "Policy YAML file for exit code rules")
	fs.StringVar(&o.BaselineFile, "baseline", "", "Baseline JSON file for regression detection")
}

// RegisterOutputAliases registers additional aliases that some commands use.
// Call this after RegisterFlags if the command uses legacy flag names.
func (o *OutputFlags) RegisterOutputAliases(fs *flag.FlagSet) {
	// Some commands use these alternative names
	fs.StringVar(&o.SARIFExport, "sarif", "", "Export results to SARIF file (alias)")
	fs.StringVar(&o.JUnitExport, "junit", "", "Export results to JUnit XML file (alias)")
	fs.StringVar(&o.HTMLExport, "html", "", "Export results to HTML file (alias)")
	fs.StringVar(&o.MDExport, "md", "", "Export results to Markdown file (alias)")
	fs.StringVar(&o.CSVExport, "csv", "", "Export results to CSV file (alias)")
	fs.StringVar(&o.PDFExport, "pdf", "", "Export results to PDF file (alias)")
}

// ToConfig converts OutputFlags to output.Config.
func (o *OutputFlags) ToConfig() output.Config {
	return output.Config{
		OutputFile:       o.OutputFile,
		Format:           o.Format,
		JSONExport:       o.JSONExport,
		JSONLExport:      o.JSONLExport,
		SARIFExport:      o.SARIFExport,
		JUnitExport:      o.JUnitExport,
		CSVExport:        o.CSVExport,
		HTMLExport:       o.HTMLExport,
		MDExport:         o.MDExport,
		PDFExport:        o.PDFExport,
		SonarQubeExport:  o.SonarQubeExport,
		GitLabSASTExport: o.GitLabSASTExport,
		DefectDojoExport: o.DefectDojoExport,
		HARExport:        o.HARExport,
		CycloneDXExport:  o.CycloneDXExport,
		JSONMode:         o.JSONMode,
		StreamMode:       o.StreamMode,
		BatchSize:        o.BatchSize,
		OmitRaw:          o.OmitRaw,
		OmitEvidence:     o.OmitEvidence,
		OnlyBypasses:     o.OnlyBypasses,
		ShowStats:        o.ShowStats,
		StatsJSON:        o.StatsJSON,
		StatsInterval:    o.StatsInterval,
		Silent:           o.Silent,
		NoColor:          o.NoColor,
		WebhookURL:       o.WebhookURL,
		WebhookAll:       o.WebhookAll,
		GitHubOutput:     o.GitHubOutput,
		GitHubSummary:    o.GitHubSummary,
		SlackWebhook:     o.SlackWebhook,
		TeamsWebhook:     o.TeamsWebhook,
		PagerDutyKey:     o.PagerDutyKey,
		MetricsPort:      o.MetricsPort,
		JiraURL:          o.JiraURL,
		JiraProject:      o.JiraProject,
		JiraEmail:        o.JiraEmail,
		JiraToken:        o.JiraToken,
		OTelEndpoint:     o.OTelEndpoint,
		OTelInsecure:     o.OTelInsecure,
		Version:          o.Version,
	}
}

// BuildDispatcher creates an output dispatcher from flags.
// The caller is responsible for calling Close() on the dispatcher.
func (o *OutputFlags) BuildDispatcher() (*dispatcher.Dispatcher, error) {
	cfg := o.ToConfig()
	return output.BuildDispatcher(cfg)
}

// LoadPolicy loads policy from file if specified.
// Returns nil if no policy file is configured.
func (o *OutputFlags) LoadPolicy() (*policy.Policy, error) {
	if o.PolicyFile == "" {
		return nil, nil
	}

	p, err := policy.LoadPolicy(o.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}

	return p, nil
}

// LoadBaseline loads baseline from file if specified.
// Returns nil if no baseline file is configured.
func (o *OutputFlags) LoadBaseline() (*baseline.Baseline, error) {
	if o.BaselineFile == "" {
		return nil, nil
	}

	b, err := baseline.LoadBaseline(o.BaselineFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load baseline: %w", err)
	}

	return b, nil
}

// ApplyUISettings applies silent and color settings to the UI.
func (o *OutputFlags) ApplyUISettings() {
	if o.Silent {
		ui.SetSilent(true)
	}
	if o.NoColor {
		ui.SetNoColor(true)
	}
}

// ShouldSuppressBanner returns true if banner output should be suppressed.
func (o *OutputFlags) ShouldSuppressBanner() bool {
	return o.Silent || o.JSONMode || o.StreamMode
}

// PrintOutputConfig prints output configuration to stderr (for verbose mode).
func (o *OutputFlags) PrintOutputConfig() {
	if o.Silent {
		return
	}

	hasFileOutput := o.OutputFile != "" || o.JSONExport != "" || o.JSONLExport != "" ||
		o.SARIFExport != "" || o.JUnitExport != "" || o.CSVExport != "" ||
		o.HTMLExport != "" || o.MDExport != "" || o.PDFExport != "" ||
		o.SonarQubeExport != "" || o.GitLabSASTExport != "" ||
		o.DefectDojoExport != "" || o.HARExport != "" || o.CycloneDXExport != ""

	if !hasFileOutput && !o.hasHooks() {
		return
	}

	ui.PrintSection("Output Configuration")

	if o.OutputFile != "" {
		ui.PrintConfigLine("Output File", o.OutputFile)
	}
	if o.Format != "" && o.Format != "console" {
		ui.PrintConfigLine("Format", o.Format)
	}
	if o.JSONExport != "" {
		ui.PrintConfigLine("JSON Export", o.JSONExport)
	}
	if o.JSONLExport != "" {
		ui.PrintConfigLine("JSONL Export", o.JSONLExport)
	}
	if o.SARIFExport != "" {
		ui.PrintConfigLine("SARIF Export", o.SARIFExport)
	}
	if o.JUnitExport != "" {
		ui.PrintConfigLine("JUnit Export", o.JUnitExport)
	}
	if o.CSVExport != "" {
		ui.PrintConfigLine("CSV Export", o.CSVExport)
	}
	if o.HTMLExport != "" {
		ui.PrintConfigLine("HTML Export", o.HTMLExport)
	}
	if o.MDExport != "" {
		ui.PrintConfigLine("Markdown Export", o.MDExport)
	}
	if o.PDFExport != "" {
		ui.PrintConfigLine("PDF Export", o.PDFExport)
	}
	if o.SonarQubeExport != "" {
		ui.PrintConfigLine("SonarQube Export", o.SonarQubeExport)
	}
	if o.GitLabSASTExport != "" {
		ui.PrintConfigLine("GitLab SAST Export", o.GitLabSASTExport)
	}
	if o.DefectDojoExport != "" {
		ui.PrintConfigLine("DefectDojo Export", o.DefectDojoExport)
	}
	if o.CycloneDXExport != "" {
		ui.PrintConfigLine("CycloneDX Export", o.CycloneDXExport)
	}
	if o.HARExport != "" {
		ui.PrintConfigLine("HAR Export", o.HARExport)
	}
	if o.PolicyFile != "" {
		ui.PrintConfigLine("Policy File", o.PolicyFile)
	}
	if o.BaselineFile != "" {
		ui.PrintConfigLine("Baseline File", o.BaselineFile)
	}
	if o.WebhookURL != "" {
		ui.PrintConfigLine("Webhook", o.WebhookURL)
	}
	if o.SlackWebhook != "" {
		ui.PrintConfigLine("Slack Webhook", "configured")
	}
	if o.TeamsWebhook != "" {
		ui.PrintConfigLine("Teams Webhook", "configured")
	}
	if o.PagerDutyKey != "" {
		ui.PrintConfigLine("PagerDuty", "configured")
	}
	if o.OTelEndpoint != "" {
		ui.PrintConfigLine("OpenTelemetry", o.OTelEndpoint)
	}
	if o.GitHubOutput {
		ui.PrintConfigLine("GitHub Actions", "enabled")
	}
	if o.MetricsPort > 0 {
		ui.PrintConfigLine("Metrics Port", fmt.Sprintf(":%d", o.MetricsPort))
	}
}

// hasHooks returns true if any hooks are configured.
func (o *OutputFlags) hasHooks() bool {
	return o.WebhookURL != "" || o.SlackWebhook != "" || o.TeamsWebhook != "" ||
		o.PagerDutyKey != "" || o.OTelEndpoint != "" || o.GitHubOutput ||
		o.JiraURL != "" || o.MetricsPort > 0
}

// ExportDescriptions returns a slice of export descriptions for summary.
func (o *OutputFlags) ExportDescriptions() []string {
	var exports []string

	if o.OutputFile != "" {
		exports = append(exports, fmt.Sprintf("Output: %s", o.OutputFile))
	}
	if o.JSONExport != "" {
		exports = append(exports, fmt.Sprintf("JSON: %s", o.JSONExport))
	}
	if o.JSONLExport != "" {
		exports = append(exports, fmt.Sprintf("JSONL: %s", o.JSONLExport))
	}
	if o.SARIFExport != "" {
		exports = append(exports, fmt.Sprintf("SARIF: %s", o.SARIFExport))
	}
	if o.JUnitExport != "" {
		exports = append(exports, fmt.Sprintf("JUnit: %s", o.JUnitExport))
	}
	if o.CSVExport != "" {
		exports = append(exports, fmt.Sprintf("CSV: %s", o.CSVExport))
	}
	if o.HTMLExport != "" {
		exports = append(exports, fmt.Sprintf("HTML: %s", o.HTMLExport))
	}
	if o.MDExport != "" {
		exports = append(exports, fmt.Sprintf("Markdown: %s", o.MDExport))
	}
	if o.PDFExport != "" {
		exports = append(exports, fmt.Sprintf("PDF: %s", o.PDFExport))
	}
	if o.SonarQubeExport != "" {
		exports = append(exports, fmt.Sprintf("SonarQube: %s", o.SonarQubeExport))
	}
	if o.GitLabSASTExport != "" {
		exports = append(exports, fmt.Sprintf("GitLab SAST: %s", o.GitLabSASTExport))
	}
	if o.DefectDojoExport != "" {
		exports = append(exports, fmt.Sprintf("DefectDojo: %s", o.DefectDojoExport))
	}
	if o.CycloneDXExport != "" {
		exports = append(exports, fmt.Sprintf("CycloneDX: %s", o.CycloneDXExport))
	}
	if o.HARExport != "" {
		exports = append(exports, fmt.Sprintf("HAR: %s", o.HARExport))
	}

	return exports
}

// HasEnterpriseExports returns true if any enterprise export formats are configured.
func (o *OutputFlags) HasEnterpriseExports() bool {
	return o.JSONExport != "" || o.JSONLExport != "" ||
		o.SARIFExport != "" || o.JUnitExport != "" ||
		o.CSVExport != "" || o.HTMLExport != "" ||
		o.MDExport != "" || o.PDFExport != "" ||
		o.SonarQubeExport != "" || o.GitLabSASTExport != "" ||
		o.DefectDojoExport != "" || o.HARExport != "" ||
		o.CycloneDXExport != ""
}

// WriteEnterpriseExports writes results to all configured enterprise export formats.
func (o *OutputFlags) WriteEnterpriseExports(results output.ExecutionResults) error {
	cfg := o.ToConfig()
	return output.WriteEnterpriseExports(cfg, results)
}

// NeedsDispatcher returns true if any hooks or streaming writers are configured
// that require the dispatcher to be initialized.
func (o *OutputFlags) NeedsDispatcher() bool {
	return o.hasHooks() || o.HasEnterpriseExports()
}

// DispatcherContext wraps a dispatcher with the context and helper methods
// for easy event emission from CLI commands.
type DispatcherContext struct {
	Dispatcher *dispatcher.Dispatcher
	ScanID     string
	Target     string
}

// InitDispatcher creates and initializes a dispatcher if hooks or exports are configured.
// Returns nil if no dispatcher is needed.
// The caller MUST call Close() when done.
func (o *OutputFlags) InitDispatcher(scanID, target string) (*DispatcherContext, error) {
	if !o.NeedsDispatcher() {
		return nil, nil
	}

	d, err := o.BuildDispatcher()
	if err != nil {
		return nil, err
	}

	return &DispatcherContext{
		Dispatcher: d,
		ScanID:     scanID,
		Target:     target,
	}, nil
}

// RegisterDetectionCallbacks sets up callbacks on the default detector
// to emit events when drops or bans are detected.
func (dc *DispatcherContext) RegisterDetectionCallbacks(ctx context.Context) {
	if dc == nil || dc.Dispatcher == nil {
		return
	}

	detector := detection.Default()

	// Register drop callback
	detector.OnDrop(func(host string, result *detection.DropResult) {
		errStr := ""
		if result.Error != nil {
			errStr = result.Error.Error()
		}
		_ = dc.EmitDropDetected(ctx, host, result.Type.String(), result.Consecutive, result.RecoveryWait.Milliseconds(), errStr)
	})

	// Register ban callback
	detector.OnBan(func(host string, result *detection.BanResult) {
		_ = dc.EmitBanDetected(ctx, host, result.Type.String(), result.Confidence, result.Evidence, result.LatencyDrift, result.BodySizeDrift, result.RecommendedWait.Milliseconds())
	})
}

// Close shuts down the dispatcher and releases resources.
func (dc *DispatcherContext) Close() error {
	if dc == nil || dc.Dispatcher == nil {
		return nil
	}
	return dc.Dispatcher.Close()
}

// EmitStart sends a start event to hooks when a scan begins.
// This notifies external systems that a new scan has started with the given configuration.
func (dc *DispatcherContext) EmitStart(ctx context.Context, target string, totalTests, concurrency int, categories []string) error {
	if dc == nil || dc.Dispatcher == nil {
		return nil
	}

	event := &events.StartEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeStart,
			Time: time.Now(),
			Scan: dc.ScanID,
		},
		Target:     target,
		TotalTests: totalTests,
		Config: events.ScanConfig{
			Concurrency: concurrency,
			Categories:  categories,
		},
		Categories: categories,
	}

	return dc.Dispatcher.Dispatch(ctx, event)
}

// EmitBypass sends a bypass event to all registered hooks.
// This is the primary method for notifying integrations about WAF bypasses.
func (dc *DispatcherContext) EmitBypass(ctx context.Context, category, severity, endpoint, payload string, statusCode int) error {
	if dc == nil || dc.Dispatcher == nil {
		return nil
	}

	event := &events.BypassEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeBypass,
			Time: time.Now(),
			Scan: dc.ScanID,
		},
		Priority: "high",
		Alert: events.AlertInfo{
			Title:          fmt.Sprintf("WAF Bypass: %s", category),
			Description:    fmt.Sprintf("A %s attack payload bypassed WAF protection", category),
			ActionRequired: "Investigate and update WAF rules",
		},
		Details: events.BypassDetail{
			TestID:     fmt.Sprintf("%s-%d", category, time.Now().UnixNano()),
			Category:   category,
			Severity:   events.Severity(severity),
			Endpoint:   endpoint,
			StatusCode: statusCode,
			Payload:    payload,
		},
		Context: events.AlertContext{
			WAFDetected: "",
		},
	}

	return dc.Dispatcher.Dispatch(ctx, event)
}

// EmitResult sends a test result event to all registered hooks.
func (dc *DispatcherContext) EmitResult(ctx context.Context, category, severity string, blocked bool, statusCode int, latencyMs float64) error {
	if dc == nil || dc.Dispatcher == nil {
		return nil
	}

	outcome := events.OutcomeBypass
	if blocked {
		outcome = events.OutcomeBlocked
	}

	event := &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: dc.ScanID,
		},
		Test: events.TestInfo{
			ID:       fmt.Sprintf("%s-%d", category, time.Now().UnixNano()),
			Category: category,
			Severity: events.Severity(severity),
		},
		Target: events.TargetInfo{
			URL: dc.Target,
		},
		Result: events.ResultInfo{
			Outcome:    outcome,
			StatusCode: statusCode,
			LatencyMs:  latencyMs,
		},
	}

	return dc.Dispatcher.Dispatch(ctx, event)
}

// EmitError sends an error event to hooks when a command fails.
// This allows external systems (Slack, PagerDuty, etc.) to be notified of failures.
func (dc *DispatcherContext) EmitError(ctx context.Context, command, errorMsg string, fatal bool) error {
	if dc == nil || dc.Dispatcher == nil {
		return nil
	}

	severity := "error"
	if fatal {
		severity = "critical"
	}

	event := &events.BypassEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeBypass,
			Time: time.Now(),
			Scan: dc.ScanID,
		},
		Priority: "high",
		Alert: events.AlertInfo{
			Title:          fmt.Sprintf("Command Failed: %s", command),
			Description:    errorMsg,
			ActionRequired: "Investigate and retry",
		},
		Details: events.BypassDetail{
			TestID:   fmt.Sprintf("error-%s-%d", command, time.Now().UnixNano()),
			Category: "command-error",
			Severity: events.Severity(severity),
			Endpoint: dc.Target,
			Payload:  errorMsg,
		},
		Context: events.AlertContext{
			WAFDetected: "",
		},
	}

	return dc.Dispatcher.Dispatch(ctx, event)
}

// EmitSummary sends a summary event with final scan statistics.
func (dc *DispatcherContext) EmitSummary(ctx context.Context, totalTests, blocked, bypassed int, duration time.Duration) error {
	if dc == nil || dc.Dispatcher == nil {
		return nil
	}

	effectiveness := float64(0)
	if totalTests > 0 {
		effectiveness = float64(blocked) / float64(totalTests) * 100
	}

	now := time.Now()
	event := &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: now,
			Scan: dc.ScanID,
		},
		Target: events.SummaryTarget{
			URL: dc.Target,
		},
		Totals: events.SummaryTotals{
			Tests:    totalTests,
			Blocked:  blocked,
			Bypasses: bypassed,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct: effectiveness,
		},
		Timing: events.SummaryTiming{
			StartedAt:   now.Add(-duration),
			CompletedAt: now,
			DurationSec: duration.Seconds(),
		},
	}

	return dc.Dispatcher.Dispatch(ctx, event)
}

// EmitDropDetected sends a connection drop event to all registered hooks.
// This notifies integrations when targets are dropping connections.
func (dc *DispatcherContext) EmitDropDetected(ctx context.Context, host, dropType string, consecutive int, recoveryWaitMs int64, originalErr string) error {
	if dc == nil || dc.Dispatcher == nil {
		return nil
	}

	event := events.NewDropDetectedEvent(dc.ScanID, host, dropType, consecutive, time.Duration(recoveryWaitMs)*time.Millisecond, originalErr)
	return dc.Dispatcher.Dispatch(ctx, event)
}

// EmitBanDetected sends a silent ban detection event to all registered hooks.
// This notifies integrations when targets appear to be silently banning the scanner.
func (dc *DispatcherContext) EmitBanDetected(ctx context.Context, host, banType string, confidence float64, evidence []string, latencyDrift, bodySizeDrift float64, recommendedWaitMs int64) error {
	if dc == nil || dc.Dispatcher == nil {
		return nil
	}

	event := events.NewBanDetectedEvent(dc.ScanID, host, banType, confidence, evidence, latencyDrift, bodySizeDrift, time.Duration(recommendedWaitMs)*time.Millisecond)
	return dc.Dispatcher.Dispatch(ctx, event)
}
