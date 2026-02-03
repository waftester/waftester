// Package report provides executive reporting and PDF/HTML generation
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"
)

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ReportFormat defines output format
type ReportFormat string

const (
	FormatHTML     ReportFormat = "html"
	FormatPDF      ReportFormat = "pdf"
	FormatJSON     ReportFormat = "json"
	FormatMarkdown ReportFormat = "markdown"
	FormatText     ReportFormat = "text"
)

// Finding represents a security finding for reporting
type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Type        string            `json:"type"`
	Target      string            `json:"target"`
	Endpoint    string            `json:"endpoint"`
	Evidence    string            `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	CWE         string            `json:"cwe,omitempty"`
	CVE         string            `json:"cve,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	Risk        string            `json:"risk,omitempty"`
	Impact      string            `json:"impact,omitempty"`
	References  []string          `json:"references,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ExecutiveSummary contains high-level summary for executives
type ExecutiveSummary struct {
	Title           string           `json:"title"`
	Organization    string           `json:"organization"`
	ReportDate      time.Time        `json:"report_date"`
	AssessmentType  string           `json:"assessment_type"` // pentest, vuln-scan, waf-test
	Scope           []string         `json:"scope"`
	OverallRisk     string           `json:"overall_risk"` // Critical, High, Medium, Low
	RiskScore       float64          `json:"risk_score"`   // 0-100
	TotalFindings   int              `json:"total_findings"`
	FindingsByRisk  map[Severity]int `json:"findings_by_risk"`
	KeyFindings     []string         `json:"key_findings"`
	Recommendations []string         `json:"recommendations"`
	Conclusion      string           `json:"conclusion"`
}

// TechnicalDetails contains detailed technical information
type TechnicalDetails struct {
	Methodology   string     `json:"methodology"`
	Tools         []string   `json:"tools"`
	TestingPeriod TimeRange  `json:"testing_period"`
	Findings      []*Finding `json:"findings"`
	Statistics    Statistics `json:"statistics"`
	Appendices    []Appendix `json:"appendices,omitempty"`
}

// TimeRange represents a time period
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Statistics contains scan statistics
type Statistics struct {
	TotalRequests   int            `json:"total_requests"`
	BlockedRequests int            `json:"blocked_requests"`
	PassedRequests  int            `json:"passed_requests"`
	BlockRate       float64        `json:"block_rate"`
	TestsPerformed  int            `json:"tests_performed"`
	VulnsFound      int            `json:"vulns_found"`
	FalsePositives  int            `json:"false_positives"`
	Coverage        float64        `json:"coverage"` // 0-100
	ByCategory      map[string]int `json:"by_category"`
	ByEndpoint      map[string]int `json:"by_endpoint"`
	// Detection statistics (v2.5.2)
	DropsDetected  int            `json:"drops_detected,omitempty"`
	BansDetected   int            `json:"bans_detected,omitempty"`
	HostsSkipped   int            `json:"hosts_skipped,omitempty"`
	DetectionStats map[string]int `json:"detection_stats,omitempty"`
	TrendData      []TrendPoint   `json:"trend_data,omitempty"`
}

// TrendPoint represents a data point in a trend
type TrendPoint struct {
	Date  time.Time `json:"date"`
	Value int       `json:"value"`
	Label string    `json:"label"`
}

// Appendix contains supplementary information
type Appendix struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

// Report represents a complete security report
type Report struct {
	ID             string           `json:"id"`
	Version        string           `json:"version"`
	GeneratedAt    time.Time        `json:"generated_at"`
	Executive      ExecutiveSummary `json:"executive"`
	Technical      TechnicalDetails `json:"technical"`
	Format         ReportFormat     `json:"format"`
	Classification string           `json:"classification"` // Public, Internal, Confidential
	PreparedBy     string           `json:"prepared_by"`
	PreparedFor    string           `json:"prepared_for"`
}

// ReportBuilder builds reports from findings
type ReportBuilder struct {
	findings       []*Finding
	config         ReportConfig
	detectionStats DetectionStats // v2.5.2: Detection statistics
}

// DetectionStats holds connection drop and silent ban detection data
type DetectionStats struct {
	DropsDetected  int
	BansDetected   int
	HostsSkipped   int
	Details        map[string]int
}

// ReportConfig configures report generation
type ReportConfig struct {
	Title           string       `json:"title"`
	Organization    string       `json:"organization"`
	AssessmentType  string       `json:"assessment_type"`
	Scope           []string     `json:"scope"`
	Tools           []string     `json:"tools"`
	Methodology     string       `json:"methodology"`
	Format          ReportFormat `json:"format"`
	Classification  string       `json:"classification"`
	PreparedBy      string       `json:"prepared_by"`
	PreparedFor     string       `json:"prepared_for"`
	IncludeAppendix bool         `json:"include_appendix"`
	CustomCSS       string       `json:"custom_css,omitempty"`
	LogoURL         string       `json:"logo_url,omitempty"`
}

// NewReportBuilder creates a new report builder
func NewReportBuilder(config ReportConfig) *ReportBuilder {
	return &ReportBuilder{
		findings: make([]*Finding, 0),
		config:   config,
	}
}

// AddFinding adds a finding to the report
func (b *ReportBuilder) AddFinding(finding *Finding) {
	b.findings = append(b.findings, finding)
}

// AddFindings adds multiple findings
func (b *ReportBuilder) AddFindings(findings []*Finding) {
	b.findings = append(b.findings, findings...)
}

// SetConfig updates the configuration
func (b *ReportBuilder) SetConfig(config ReportConfig) {
	b.config = config
}

// GetConfig returns the current configuration
func (b *ReportBuilder) GetConfig() ReportConfig {
	return b.config
}

// SetDetectionStats sets the detection statistics for the report (v2.5.2)
func (b *ReportBuilder) SetDetectionStats(drops, bans, skipped int, details map[string]int) {
	b.detectionStats = DetectionStats{
		DropsDetected: drops,
		BansDetected:  bans,
		HostsSkipped:  skipped,
		Details:       details,
	}
}

// Build generates the report
func (b *ReportBuilder) Build() *Report {
	// Sort findings by severity
	sort.Slice(b.findings, func(i, j int) bool {
		return severityOrder(b.findings[i].Severity) > severityOrder(b.findings[j].Severity)
	})

	report := &Report{
		ID:             fmt.Sprintf("RPT-%d", time.Now().Unix()),
		Version:        "1.0",
		GeneratedAt:    time.Now(),
		Format:         b.config.Format,
		Classification: b.config.Classification,
		PreparedBy:     b.config.PreparedBy,
		PreparedFor:    b.config.PreparedFor,
	}

	// Build executive summary
	report.Executive = b.buildExecutiveSummary()

	// Build technical details
	report.Technical = b.buildTechnicalDetails()

	return report
}

func (b *ReportBuilder) buildExecutiveSummary() ExecutiveSummary {
	summary := ExecutiveSummary{
		Title:           b.config.Title,
		Organization:    b.config.Organization,
		ReportDate:      time.Now(),
		AssessmentType:  b.config.AssessmentType,
		Scope:           b.config.Scope,
		TotalFindings:   len(b.findings),
		FindingsByRisk:  make(map[Severity]int),
		KeyFindings:     make([]string, 0),
		Recommendations: make([]string, 0),
	}

	// Count by severity
	for _, f := range b.findings {
		summary.FindingsByRisk[f.Severity]++
	}

	// Calculate overall risk
	summary.OverallRisk, summary.RiskScore = b.calculateOverallRisk(summary.FindingsByRisk)

	// Key findings (top 5 critical/high)
	count := 0
	for _, f := range b.findings {
		if count >= 5 {
			break
		}
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			summary.KeyFindings = append(summary.KeyFindings, f.Title)
			count++
		}
	}

	// Recommendations
	summary.Recommendations = b.generateRecommendations()

	// Conclusion
	summary.Conclusion = b.generateConclusion(summary.OverallRisk, summary.TotalFindings)

	return summary
}

func (b *ReportBuilder) buildTechnicalDetails() TechnicalDetails {
	details := TechnicalDetails{
		Methodology: b.config.Methodology,
		Tools:       b.config.Tools,
		Findings:    b.findings,
		Statistics:  b.calculateStatistics(),
	}

	if b.config.IncludeAppendix {
		details.Appendices = b.generateAppendices()
	}

	return details
}

func (b *ReportBuilder) calculateOverallRisk(byRisk map[Severity]int) (string, float64) {
	criticalCount := byRisk[SeverityCritical]
	highCount := byRisk[SeverityHigh]
	mediumCount := byRisk[SeverityMedium]
	lowCount := byRisk[SeverityLow]

	// Calculate weighted score
	score := float64(criticalCount*40 + highCount*20 + mediumCount*10 + lowCount*5)

	// Normalize to 0-100
	if score > 100 {
		score = 100
	}

	var risk string
	switch {
	case criticalCount > 0 || score >= 80:
		risk = "Critical"
	case highCount > 0 || score >= 60:
		risk = "High"
	case mediumCount > 0 || score >= 30:
		risk = "Medium"
	default:
		risk = "Low"
	}

	return risk, score
}

func (b *ReportBuilder) calculateStatistics() Statistics {
	stats := Statistics{
		VulnsFound: len(b.findings),
		ByCategory: make(map[string]int),
		ByEndpoint: make(map[string]int),
		// v2.5.2: Include detection statistics
		DropsDetected:  b.detectionStats.DropsDetected,
		BansDetected:   b.detectionStats.BansDetected,
		HostsSkipped:   b.detectionStats.HostsSkipped,
		DetectionStats: b.detectionStats.Details,
	}

	for _, f := range b.findings {
		stats.ByCategory[f.Type]++
		stats.ByEndpoint[f.Endpoint]++
	}

	return stats
}

func (b *ReportBuilder) generateRecommendations() []string {
	recommendations := make([]string, 0)
	hasType := make(map[string]bool)

	for _, f := range b.findings {
		if hasType[f.Type] {
			continue
		}
		hasType[f.Type] = true

		switch f.Type {
		case "sqli":
			recommendations = append(recommendations, "Implement parameterized queries and input validation for all database operations")
		case "xss":
			recommendations = append(recommendations, "Implement output encoding and Content Security Policy (CSP) headers")
		case "lfi":
			recommendations = append(recommendations, "Validate and sanitize file paths, implement allowlist for file access")
		case "rce":
			recommendations = append(recommendations, "Disable dangerous functions, implement strict input validation")
		case "ssrf":
			recommendations = append(recommendations, "Implement URL allowlisting and network segmentation")
		case "auth-bypass":
			recommendations = append(recommendations, "Implement multi-factor authentication and session management improvements")
		default:
			if f.Remediation != "" {
				recommendations = append(recommendations, f.Remediation)
			}
		}
	}

	// Add general recommendations
	recommendations = append(recommendations, "Conduct regular security assessments")
	recommendations = append(recommendations, "Implement security monitoring and alerting")

	return recommendations
}

func (b *ReportBuilder) generateConclusion(risk string, total int) string {
	switch risk {
	case "Critical":
		return fmt.Sprintf("The assessment identified %d vulnerabilities with critical severity issues that require immediate attention. These findings pose significant risk to the organization and should be addressed as a priority.", total)
	case "High":
		return fmt.Sprintf("The assessment identified %d vulnerabilities including high severity issues. While no critical vulnerabilities were found, the high severity findings should be addressed promptly to reduce security risk.", total)
	case "Medium":
		return fmt.Sprintf("The assessment identified %d vulnerabilities of medium or lower severity. The organization maintains a reasonable security posture, but improvements are recommended.", total)
	default:
		return fmt.Sprintf("The assessment identified %d findings of low severity. The organization demonstrates good security practices. Continue monitoring and regular assessments.", total)
	}
}

func (b *ReportBuilder) generateAppendices() []Appendix {
	appendices := make([]Appendix, 0)

	// Methodology appendix
	appendices = append(appendices, Appendix{
		Title:   "Testing Methodology",
		Content: "The security assessment followed OWASP Testing Guide v4 methodology...",
	})

	// Tool reference
	if len(b.config.Tools) > 0 {
		appendices = append(appendices, Appendix{
			Title:   "Tools Used",
			Content: strings.Join(b.config.Tools, ", "),
		})
	}

	return appendices
}

// ReportGenerator generates reports in various formats
type ReportGenerator struct {
	templates map[ReportFormat]*template.Template
}

// NewReportGenerator creates a new generator
func NewReportGenerator() *ReportGenerator {
	g := &ReportGenerator{
		templates: make(map[ReportFormat]*template.Template),
	}
	g.loadDefaultTemplates()
	return g
}

func (g *ReportGenerator) loadDefaultTemplates() {
	// HTML template
	htmlTmpl := `<!DOCTYPE html>
<html>
<head>
    <title>{{.Executive.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; margin-bottom: 40px; }
        .section { margin-bottom: 30px; }
        .finding { border: 1px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .critical { border-left: 5px solid #dc3545; }
        .high { border-left: 5px solid #fd7e14; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #17a2b8; }
        .info { border-left: 5px solid #6c757d; }
        .risk-score { font-size: 48px; font-weight: bold; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
        .stat-box { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .classification { color: red; text-align: center; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    {{if .Classification}}<p class="classification">{{.Classification}}</p>{{end}}
    <div class="header">
        <h1>{{.Executive.Title}}</h1>
        <p>Prepared for: {{.PreparedFor}}</p>
        <p>Prepared by: {{.PreparedBy}}</p>
        <p>Date: {{.Executive.ReportDate.Format "January 2, 2006"}}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <div class="risk-score">{{printf "%.0f" .Executive.RiskScore}}</div>
                <div>Risk Score</div>
            </div>
            <div class="stat-box">
                <div style="font-size: 24px;">{{.Executive.OverallRisk}}</div>
                <div>Overall Risk</div>
            </div>
            <div class="stat-box">
                <div style="font-size: 24px;">{{.Executive.TotalFindings}}</div>
                <div>Total Findings</div>
            </div>
            <div class="stat-box">
                <div style="font-size: 24px;">{{len .Executive.Scope}}</div>
                <div>Systems Tested</div>
            </div>
        </div>
        <h3>Findings by Severity</h3>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            {{range $sev, $count := .Executive.FindingsByRisk}}
            <tr><td>{{$sev}}</td><td>{{$count}}</td></tr>
            {{end}}
        </table>
        <h3>Key Findings</h3>
        <ul>
            {{range .Executive.KeyFindings}}<li>{{.}}</li>{{end}}
        </ul>
        <h3>Recommendations</h3>
        <ul>
            {{range .Executive.Recommendations}}<li>{{.}}</li>{{end}}
        </ul>
        <h3>Conclusion</h3>
        <p>{{.Executive.Conclusion}}</p>
    </div>

    <div class="section">
        <h2>Technical Details</h2>
        <h3>Findings</h3>
        {{range .Technical.Findings}}
        <div class="finding {{.Severity}}">
            <h4>{{.Title}}</h4>
            <p><strong>Severity:</strong> {{.Severity}} | <strong>Type:</strong> {{.Type}}</p>
            <p><strong>Target:</strong> {{.Target}}{{.Endpoint}}</p>
            <p>{{.Description}}</p>
            {{if .Evidence}}<p><strong>Evidence:</strong> {{.Evidence}}</p>{{end}}
            {{if .Remediation}}<p><strong>Remediation:</strong> {{.Remediation}}</p>{{end}}
        </div>
        {{end}}
    </div>
</body>
</html>`

	t, _ := template.New("html").Parse(htmlTmpl)
	g.templates[FormatHTML] = t

	// Markdown template
	mdTmpl := `# {{.Executive.Title}}

**Prepared for:** {{.PreparedFor}}  
**Prepared by:** {{.PreparedBy}}  
**Date:** {{.Executive.ReportDate.Format "January 2, 2006"}}  
**Classification:** {{.Classification}}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Risk Score | {{printf "%.0f" .Executive.RiskScore}} |
| Overall Risk | {{.Executive.OverallRisk}} |
| Total Findings | {{.Executive.TotalFindings}} |

### Findings by Severity

| Severity | Count |
|----------|-------|
{{range $sev, $count := .Executive.FindingsByRisk}}| {{$sev}} | {{$count}} |
{{end}}

### Key Findings

{{range .Executive.KeyFindings}}- {{.}}
{{end}}

### Recommendations

{{range .Executive.Recommendations}}- {{.}}
{{end}}

### Conclusion

{{.Executive.Conclusion}}

---

## Technical Details

{{range .Technical.Findings}}
### {{.Title}}

**Severity:** {{.Severity}} | **Type:** {{.Type}}  
**Target:** {{.Target}}{{.Endpoint}}

{{.Description}}

{{if .Evidence}}**Evidence:** {{.Evidence}}{{end}}

{{if .Remediation}}**Remediation:** {{.Remediation}}{{end}}

---

{{end}}`

	g.templates[FormatMarkdown] = template.Must(template.New("markdown").Parse(mdTmpl))
}

// Generate creates a report in the specified format
func (g *ReportGenerator) Generate(report *Report, w io.Writer) error {
	switch report.Format {
	case FormatJSON:
		return g.generateJSON(report, w)
	case FormatHTML:
		return g.generateHTML(report, w)
	case FormatMarkdown:
		return g.generateMarkdown(report, w)
	case FormatText:
		return g.generateText(report, w)
	case FormatPDF:
		// PDF generation not implemented - return error instead of silently outputting HTML
		return fmt.Errorf("PDF format not supported: use --format html and convert with external tools (wkhtmltopdf, Chrome --print-to-pdf)")
	default:
		return fmt.Errorf("unsupported format: %s", report.Format)
	}
}

func (g *ReportGenerator) generateJSON(report *Report, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (g *ReportGenerator) generateHTML(report *Report, w io.Writer) error {
	tmpl := g.templates[FormatHTML]
	if tmpl == nil {
		return fmt.Errorf("HTML template not loaded")
	}
	return tmpl.Execute(w, report)
}

func (g *ReportGenerator) generateMarkdown(report *Report, w io.Writer) error {
	tmpl := g.templates[FormatMarkdown]
	if tmpl == nil {
		return fmt.Errorf("Markdown template not loaded")
	}
	return tmpl.Execute(w, report)
}

func (g *ReportGenerator) generateText(report *Report, w io.Writer) error {
	var buf bytes.Buffer

	buf.WriteString(strings.Repeat("=", 60) + "\n")
	buf.WriteString(fmt.Sprintf("  %s\n", report.Executive.Title))
	buf.WriteString(strings.Repeat("=", 60) + "\n\n")

	buf.WriteString(fmt.Sprintf("Prepared for: %s\n", report.PreparedFor))
	buf.WriteString(fmt.Sprintf("Prepared by: %s\n", report.PreparedBy))
	buf.WriteString(fmt.Sprintf("Date: %s\n\n", report.Executive.ReportDate.Format("January 2, 2006")))

	buf.WriteString("EXECUTIVE SUMMARY\n")
	buf.WriteString(strings.Repeat("-", 40) + "\n")
	buf.WriteString(fmt.Sprintf("Risk Score: %.0f\n", report.Executive.RiskScore))
	buf.WriteString(fmt.Sprintf("Overall Risk: %s\n", report.Executive.OverallRisk))
	buf.WriteString(fmt.Sprintf("Total Findings: %d\n\n", report.Executive.TotalFindings))

	buf.WriteString("FINDINGS\n")
	buf.WriteString(strings.Repeat("-", 40) + "\n")
	for _, f := range report.Technical.Findings {
		buf.WriteString(fmt.Sprintf("[%s] %s\n", strings.ToUpper(string(f.Severity)), f.Title))
		buf.WriteString(fmt.Sprintf("  Target: %s%s\n", f.Target, f.Endpoint))
		buf.WriteString(fmt.Sprintf("  %s\n\n", f.Description))
	}

	_, err := w.Write(buf.Bytes())
	return err
}

// GenerateToString generates report to a string
func (g *ReportGenerator) GenerateToString(report *Report) (string, error) {
	var buf bytes.Buffer
	err := g.Generate(report, &buf)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// SetTemplate sets a custom template for a format
func (g *ReportGenerator) SetTemplate(format ReportFormat, tmpl *template.Template) {
	g.templates[format] = tmpl
}

// GetTemplate returns the template for a format
func (g *ReportGenerator) GetTemplate(format ReportFormat) *template.Template {
	return g.templates[format]
}

// Helper functions
func severityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ComparisonReport compares findings between two scans
type ComparisonReport struct {
	BaselineDate  time.Time  `json:"baseline_date"`
	CurrentDate   time.Time  `json:"current_date"`
	NewFindings   []*Finding `json:"new_findings"`
	FixedFindings []*Finding `json:"fixed_findings"`
	Unchanged     []*Finding `json:"unchanged"`
	RiskTrend     string     `json:"risk_trend"` // improving, degrading, stable
	Summary       string     `json:"summary"`
}

// CompareReports generates a comparison between two reports
func CompareReports(baseline, current *Report) *ComparisonReport {
	comparison := &ComparisonReport{
		BaselineDate:  baseline.GeneratedAt,
		CurrentDate:   current.GeneratedAt,
		NewFindings:   make([]*Finding, 0),
		FixedFindings: make([]*Finding, 0),
		Unchanged:     make([]*Finding, 0),
	}

	// Create maps for comparison
	baselineMap := make(map[string]*Finding)
	for _, f := range baseline.Technical.Findings {
		key := f.Target + f.Endpoint + f.Type
		baselineMap[key] = f
	}

	currentMap := make(map[string]*Finding)
	for _, f := range current.Technical.Findings {
		key := f.Target + f.Endpoint + f.Type
		currentMap[key] = f
	}

	// Find new and unchanged
	for key, f := range currentMap {
		if _, exists := baselineMap[key]; exists {
			comparison.Unchanged = append(comparison.Unchanged, f)
		} else {
			comparison.NewFindings = append(comparison.NewFindings, f)
		}
	}

	// Find fixed
	for key, f := range baselineMap {
		if _, exists := currentMap[key]; !exists {
			comparison.FixedFindings = append(comparison.FixedFindings, f)
		}
	}

	// Determine trend
	if len(comparison.FixedFindings) > len(comparison.NewFindings) {
		comparison.RiskTrend = "improving"
	} else if len(comparison.NewFindings) > len(comparison.FixedFindings) {
		comparison.RiskTrend = "degrading"
	} else {
		comparison.RiskTrend = "stable"
	}

	comparison.Summary = fmt.Sprintf(
		"Comparison shows %d new findings, %d fixed, and %d unchanged. Risk trend: %s",
		len(comparison.NewFindings),
		len(comparison.FixedFindings),
		len(comparison.Unchanged),
		comparison.RiskTrend,
	)

	return comparison
}
