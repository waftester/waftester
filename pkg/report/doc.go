// Package report provides comprehensive security report generation.
//
// The package is organized by logical concern across multiple files:
//
// # Core Report Types (report.go)
//
// Report, ReportBuilder, ReportGenerator, ReportConfig, Finding,
// ExecutiveSummary, TechnicalDetails, Statistics, ComparisonReport.
// These are the primary types for building and rendering security reports
// in multiple formats (HTML, JSON, Markdown, Text, PDF).
//
// # Compliance Mapping (compliance.go)
//
// ComplianceMapper, ComplianceReport, ComplianceControl, ComplianceFramework.
// Maps WAF test results to compliance frameworks: PCI-DSS, OWASP, SOC2,
// ISO 27001, HIPAA, GDPR, NIST.
//
// # Enterprise HTML Reports (html_report.go)
//
// EnterpriseReport, EnterpriseHTMLGenerator, EnterpriseMetricsData,
// CategoryResult, BypassFinding, FalsePositiveFinding, Grade,
// RadarChartData, ConfusionMatrixData, ComparisonRow.
// Rich HTML reports with charts, grades, and WAF comparison tables.
//
// # Report Building (html_builder.go)
//
// BuildFromMetrics, GenerateEnterpriseHTMLReport and related functions
// for constructing EnterpriseReport from scan metrics and workspace data.
//
// # Finding Enrichment (html_enrichment.go, html_vulndb.go)
//
// EnrichBypassFinding, VulnerabilityDatabase, GenerateCurlCommand.
// Adds CWE IDs, OWASP categories, CVSS scores, and reproduction commands
// to bypass findings for enterprise reporting.
//
// # Template Configuration (template_config.go)
//
// TemplateConfig, BrandingConfig, LayoutConfig, SectionConfig, StylingConfig.
// Customizable report appearance via YAML configuration files.
package report
