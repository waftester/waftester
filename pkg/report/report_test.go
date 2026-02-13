package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

func TestSeverityLevels(t *testing.T) {
	severities := []finding.Severity{
		finding.Critical, finding.High, finding.Medium,
		finding.Low, finding.Info,
	}

	if len(severities) != 5 {
		t.Errorf("Expected 5 severity levels, got %d", len(severities))
	}

	if string(finding.Critical) != "critical" {
		t.Error("finding.Critical should be 'critical'")
	}
}

func TestReportFormats(t *testing.T) {
	formats := []ReportFormat{
		FormatHTML, FormatPDF, FormatJSON, FormatMarkdown, FormatText,
	}

	if len(formats) != 5 {
		t.Errorf("Expected 5 formats, got %d", len(formats))
	}

	if string(FormatHTML) != "html" {
		t.Error("FormatHTML should be 'html'")
	}
}

func TestNewReportBuilder(t *testing.T) {
	config := ReportConfig{
		Title:        "Security Report",
		Organization: "Test Org",
	}

	builder := NewReportBuilder(config)
	if builder == nil {
		t.Fatal("NewReportBuilder returned nil")
	}

	if builder.GetConfig().Title != "Security Report" {
		t.Error("Config not set correctly")
	}
}

func TestReportBuilder_AddFinding(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})

	finding := &Finding{
		ID:       "f1",
		Title:    "SQL Injection",
		Severity: finding.High,
	}

	builder.AddFinding(finding)
	report := builder.Build()

	if len(report.Technical.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(report.Technical.Findings))
	}
}

func TestReportBuilder_AddFindings(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})

	findings := []*Finding{
		{ID: "f1", Title: "SQLi", Severity: finding.High},
		{ID: "f2", Title: "XSS", Severity: finding.Medium},
		{ID: "f3", Title: "Info Leak", Severity: finding.Low},
	}

	builder.AddFindings(findings)
	report := builder.Build()

	if len(report.Technical.Findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(report.Technical.Findings))
	}
}

func TestReportBuilder_SetConfig(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{Title: "Old"})

	builder.SetConfig(ReportConfig{Title: "New"})

	if builder.GetConfig().Title != "New" {
		t.Error("Config should be updated")
	}
}

func TestReportBuilder_Build(t *testing.T) {
	config := ReportConfig{
		Title:          "WAF Security Assessment",
		Organization:   "Test Corp",
		AssessmentType: "waf-test",
		Scope:          []string{"https://example.com"},
		Tools:          []string{"waf-tester"},
		Methodology:    "OWASP Testing Guide",
		Format:         FormatHTML,
		Classification: "Confidential",
		PreparedBy:     "Security Team",
		PreparedFor:    "Management",
	}

	builder := NewReportBuilder(config)
	builder.AddFindings([]*Finding{
		{ID: "f1", Title: "Critical SQLi", Severity: finding.Critical, Type: "sqli"},
		{ID: "f2", Title: "XSS", Severity: finding.Medium, Type: "xss"},
	})

	report := builder.Build()

	// Check report structure
	if report.ID == "" {
		t.Error("Report ID should be generated")
	}
	if report.Version != "1.0" {
		t.Error("Version should be 1.0")
	}
	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be set")
	}

	// Check executive summary
	if report.Executive.Title != "WAF Security Assessment" {
		t.Error("Executive title mismatch")
	}
	if report.Executive.TotalFindings != 2 {
		t.Error("Total findings mismatch")
	}
	if report.Executive.OverallRisk != "Critical" {
		t.Errorf("Expected Critical risk, got %s", report.Executive.OverallRisk)
	}
}

func TestReportBuilder_SortBySeverity(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})
	builder.AddFindings([]*Finding{
		{ID: "low", Severity: finding.Low},
		{ID: "critical", Severity: finding.Critical},
		{ID: "medium", Severity: finding.Medium},
	})

	report := builder.Build()

	// First should be critical
	if report.Technical.Findings[0].ID != "critical" {
		t.Error("Findings should be sorted by severity (critical first)")
	}
}

func TestReportBuilder_OverallRisk_High(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})
	builder.AddFindings([]*Finding{
		{ID: "f1", Severity: finding.High},
		{ID: "f2", Severity: finding.Medium},
	})

	report := builder.Build()

	if report.Executive.OverallRisk != "High" {
		t.Errorf("Expected High risk, got %s", report.Executive.OverallRisk)
	}
}

func TestReportBuilder_OverallRisk_Medium(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})
	builder.AddFindings([]*Finding{
		{ID: "f1", Severity: finding.Medium},
		{ID: "f2", Severity: finding.Low},
	})

	report := builder.Build()

	if report.Executive.OverallRisk != "Medium" {
		t.Errorf("Expected Medium risk, got %s", report.Executive.OverallRisk)
	}
}

func TestReportBuilder_OverallRisk_Low(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})
	builder.AddFindings([]*Finding{
		{ID: "f1", Severity: finding.Low},
		{ID: "f2", Severity: finding.Info},
	})

	report := builder.Build()

	if report.Executive.OverallRisk != "Low" {
		t.Errorf("Expected Low risk, got %s", report.Executive.OverallRisk)
	}
}

func TestReportBuilder_KeyFindings(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})
	for i := 0; i < 10; i++ {
		builder.AddFinding(&Finding{
			ID:       string(rune('a' + i)),
			Title:    "Critical Finding " + string(rune('0'+i)),
			Severity: finding.Critical,
		})
	}

	report := builder.Build()

	// Should only have top 5
	if len(report.Executive.KeyFindings) != 5 {
		t.Errorf("Expected 5 key findings, got %d", len(report.Executive.KeyFindings))
	}
}

func TestReportBuilder_Recommendations(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})
	builder.AddFindings([]*Finding{
		{Type: "sqli", Severity: finding.High},
		{Type: "xss", Severity: finding.Medium},
	})

	report := builder.Build()

	// Should have recommendations for both types plus general
	if len(report.Executive.Recommendations) < 4 {
		t.Errorf("Expected at least 4 recommendations, got %d", len(report.Executive.Recommendations))
	}
}

func TestReportBuilder_IncludeAppendix(t *testing.T) {
	config := ReportConfig{
		IncludeAppendix: true,
		Tools:           []string{"tool1", "tool2"},
	}
	builder := NewReportBuilder(config)

	report := builder.Build()

	if len(report.Technical.Appendices) == 0 {
		t.Error("Should have appendices when IncludeAppendix is true")
	}
}

func TestReportBuilder_SetDetectionStats(t *testing.T) {
	builder := NewReportBuilder(ReportConfig{})
	builder.SetDetectionStats(10, 5, 3, map[string]int{
		"tcp_reset":     4,
		"tls_handshake": 3,
		"timeout":       3,
	})

	report := builder.Build()

	if report.Technical.Statistics.DropsDetected != 10 {
		t.Errorf("DropsDetected = %d, want 10", report.Technical.Statistics.DropsDetected)
	}
	if report.Technical.Statistics.BansDetected != 5 {
		t.Errorf("BansDetected = %d, want 5", report.Technical.Statistics.BansDetected)
	}
	if report.Technical.Statistics.HostsSkipped != 3 {
		t.Errorf("HostsSkipped = %d, want 3", report.Technical.Statistics.HostsSkipped)
	}
	if report.Technical.Statistics.DetectionStats == nil {
		t.Error("DetectionStats should not be nil")
	}
	if report.Technical.Statistics.DetectionStats["tcp_reset"] != 4 {
		t.Errorf("DetectionStats[tcp_reset] = %d, want 4", report.Technical.Statistics.DetectionStats["tcp_reset"])
	}
}

func TestNewReportGenerator(t *testing.T) {
	gen := NewReportGenerator()
	if gen == nil {
		t.Fatal("NewReportGenerator returned nil")
	}

	// Should have default templates
	if gen.GetTemplate(FormatHTML) == nil {
		t.Error("HTML template should be loaded")
	}
	if gen.GetTemplate(FormatMarkdown) == nil {
		t.Error("Markdown template should be loaded")
	}
}

func TestReportGenerator_GenerateJSON(t *testing.T) {
	gen := NewReportGenerator()
	builder := NewReportBuilder(ReportConfig{
		Title:  "JSON Test",
		Format: FormatJSON,
	})
	builder.AddFinding(&Finding{ID: "f1", Title: "Test", Severity: finding.High})
	report := builder.Build()

	var buf bytes.Buffer
	err := gen.Generate(report, &buf)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Errorf("Invalid JSON output: %v", err)
	}
}

func TestReportGenerator_GenerateHTML(t *testing.T) {
	gen := NewReportGenerator()
	builder := NewReportBuilder(ReportConfig{
		Title:  "HTML Test",
		Format: FormatHTML,
	})
	builder.AddFinding(&Finding{ID: "f1", Title: "Test Finding", Severity: finding.High})
	report := builder.Build()

	var buf bytes.Buffer
	err := gen.Generate(report, &buf)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Should contain HTML doctype")
	}
	if !strings.Contains(output, "HTML Test") {
		t.Error("Should contain report title")
	}
	if !strings.Contains(output, "Test Finding") {
		t.Error("Should contain finding title")
	}
}

func TestReportGenerator_GenerateMarkdown(t *testing.T) {
	gen := NewReportGenerator()
	builder := NewReportBuilder(ReportConfig{
		Title:  "MD Test",
		Format: FormatMarkdown,
	})
	builder.AddFinding(&Finding{ID: "f1", Title: "Test", Severity: finding.High})
	report := builder.Build()

	var buf bytes.Buffer
	err := gen.Generate(report, &buf)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "# MD Test") {
		t.Error("Should contain markdown heading")
	}
}

func TestReportGenerator_GenerateText(t *testing.T) {
	gen := NewReportGenerator()
	builder := NewReportBuilder(ReportConfig{
		Title:       "Text Test",
		Format:      FormatText,
		PreparedBy:  "Tester",
		PreparedFor: "Client",
	})
	builder.AddFinding(&Finding{
		ID:          "f1",
		Title:       "Test Finding",
		Severity:    finding.High,
		Target:      "https://example.com",
		Endpoint:    "/api",
		Description: "A test vulnerability",
	})
	report := builder.Build()

	var buf bytes.Buffer
	err := gen.Generate(report, &buf)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Text Test") {
		t.Error("Should contain title")
	}
	if !strings.Contains(output, "[HIGH] Test Finding") {
		t.Error("Should contain finding with severity")
	}
}

func TestReportGenerator_GenerateToString(t *testing.T) {
	gen := NewReportGenerator()
	builder := NewReportBuilder(ReportConfig{Format: FormatJSON})
	report := builder.Build()

	output, err := gen.GenerateToString(report)
	if err != nil {
		t.Fatalf("GenerateToString failed: %v", err)
	}
	if output == "" {
		t.Error("Output should not be empty")
	}
}

func TestReportGenerator_UnsupportedFormat(t *testing.T) {
	gen := NewReportGenerator()
	report := &Report{Format: ReportFormat("unknown")}

	var buf bytes.Buffer
	err := gen.Generate(report, &buf)
	if err == nil {
		t.Error("Should error on unsupported format")
	}
}

func TestCompareReports_NewFindings(t *testing.T) {
	baseline := &Report{
		GeneratedAt: time.Now().Add(-24 * time.Hour),
		Technical: TechnicalDetails{
			Findings: []*Finding{
				{Target: "https://a.com", Endpoint: "/api", Type: "sqli"},
			},
		},
	}

	current := &Report{
		GeneratedAt: time.Now(),
		Technical: TechnicalDetails{
			Findings: []*Finding{
				{Target: "https://a.com", Endpoint: "/api", Type: "sqli"},
				{Target: "https://a.com", Endpoint: "/new", Type: "xss"}, // New
			},
		},
	}

	comparison := CompareReports(baseline, current)

	if len(comparison.NewFindings) != 1 {
		t.Errorf("Expected 1 new finding, got %d", len(comparison.NewFindings))
	}
	if len(comparison.Unchanged) != 1 {
		t.Errorf("Expected 1 unchanged, got %d", len(comparison.Unchanged))
	}
	if comparison.RiskTrend != "degrading" {
		t.Errorf("Expected degrading trend, got %s", comparison.RiskTrend)
	}
}

func TestCompareReports_FixedFindings(t *testing.T) {
	baseline := &Report{
		GeneratedAt: time.Now().Add(-24 * time.Hour),
		Technical: TechnicalDetails{
			Findings: []*Finding{
				{Target: "https://a.com", Endpoint: "/api", Type: "sqli"},
				{Target: "https://a.com", Endpoint: "/old", Type: "xss"},
			},
		},
	}

	current := &Report{
		GeneratedAt: time.Now(),
		Technical: TechnicalDetails{
			Findings: []*Finding{
				{Target: "https://a.com", Endpoint: "/api", Type: "sqli"},
			},
		},
	}

	comparison := CompareReports(baseline, current)

	if len(comparison.FixedFindings) != 1 {
		t.Errorf("Expected 1 fixed finding, got %d", len(comparison.FixedFindings))
	}
	if comparison.RiskTrend != "improving" {
		t.Errorf("Expected improving trend, got %s", comparison.RiskTrend)
	}
}

func TestCompareReports_Stable(t *testing.T) {
	baseline := &Report{
		GeneratedAt: time.Now().Add(-24 * time.Hour),
		Technical: TechnicalDetails{
			Findings: []*Finding{
				{Target: "https://a.com", Endpoint: "/api", Type: "sqli"},
			},
		},
	}

	current := &Report{
		GeneratedAt: time.Now(),
		Technical: TechnicalDetails{
			Findings: []*Finding{
				{Target: "https://a.com", Endpoint: "/api", Type: "sqli"},
			},
		},
	}

	comparison := CompareReports(baseline, current)

	if comparison.RiskTrend != "stable" {
		t.Errorf("Expected stable trend, got %s", comparison.RiskTrend)
	}
	if !strings.Contains(comparison.Summary, "stable") {
		t.Error("Summary should mention stable trend")
	}
}

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		severity finding.Severity
		expected int
	}{
		{finding.Critical, 5},
		{finding.High, 4},
		{finding.Medium, 3},
		{finding.Low, 2},
		{finding.Info, 1},
		{finding.Severity("unknown"), 0},
	}

	for _, tc := range tests {
		result := tc.severity.Score()
		if result != tc.expected {
			t.Errorf("Score(%s) = %d, want %d", tc.severity, result, tc.expected)
		}
	}
}

func TestFinding_Struct(t *testing.T) {
	f := &Finding{
		ID:          "f1",
		Title:       "SQL Injection",
		Description: "Found SQL injection",
		Severity:    finding.High,
		Type:        "sqli",
		Target:      "https://example.com",
		Endpoint:    "/api",
		Evidence:    "SQL error",
		Remediation: "Use prepared statements",
		CWE:         "CWE-89",
		CVE:         "CVE-2021-1234",
		CVSS:        7.5,
		Risk:        "High",
		Impact:      "Data breach",
		References:  []string{"https://owasp.org"},
		Tags:        []string{"sqli"},
		Metadata:    map[string]string{"db": "mysql"},
	}

	if f.ID != "f1" {
		t.Error("ID mismatch")
	}
	if f.CVSS != 7.5 {
		t.Error("CVSS mismatch")
	}
}

func TestExecutiveSummary_Struct(t *testing.T) {
	es := &ExecutiveSummary{
		Title:           "Report",
		Organization:    "Org",
		ReportDate:      time.Now(),
		AssessmentType:  "pentest",
		Scope:           []string{"https://a.com"},
		OverallRisk:     "High",
		RiskScore:       75.0,
		TotalFindings:   10,
		FindingsByRisk:  map[finding.Severity]int{finding.High: 5},
		KeyFindings:     []string{"Finding 1"},
		Recommendations: []string{"Fix it"},
		Conclusion:      "Needs work",
	}

	if es.Title != "Report" {
		t.Error("Title mismatch")
	}
	if es.RiskScore != 75.0 {
		t.Error("RiskScore mismatch")
	}
}

func TestTechnicalDetails_Struct(t *testing.T) {
	td := &TechnicalDetails{
		Methodology:   "OWASP",
		Tools:         []string{"tool1"},
		TestingPeriod: TimeRange{Start: time.Now(), End: time.Now()},
		Findings:      []*Finding{},
		Statistics:    Statistics{TotalRequests: 1000},
		Appendices:    []Appendix{{Title: "A", Content: "B"}},
	}

	if td.Methodology != "OWASP" {
		t.Error("Methodology mismatch")
	}
	if td.Statistics.TotalRequests != 1000 {
		t.Error("Statistics mismatch")
	}
}

func TestStatistics_Struct(t *testing.T) {
	s := &Statistics{
		TotalRequests:   1000,
		BlockedRequests: 100,
		PassedRequests:  900,
		BlockRate:       10.0,
		TestsPerformed:  500,
		VulnsFound:      5,
		FalsePositives:  2,
		Coverage:        85.0,
		ByCategory:      map[string]int{"sqli": 3},
		ByEndpoint:      map[string]int{"/api": 5},
		TrendData:       []TrendPoint{{Value: 10}},
	}

	if s.TotalRequests != 1000 {
		t.Error("TotalRequests mismatch")
	}
	if s.Coverage != 85.0 {
		t.Error("Coverage mismatch")
	}
}

func TestReport_Struct(t *testing.T) {
	r := &Report{
		ID:             "rpt-1",
		Version:        "1.0",
		GeneratedAt:    time.Now(),
		Executive:      ExecutiveSummary{Title: "Test"},
		Technical:      TechnicalDetails{},
		Format:         FormatHTML,
		Classification: "Confidential",
		PreparedBy:     "Team",
		PreparedFor:    "Client",
	}

	if r.ID != "rpt-1" {
		t.Error("ID mismatch")
	}
	if r.Format != FormatHTML {
		t.Error("Format mismatch")
	}
}

func TestReportConfig_Struct(t *testing.T) {
	rc := &ReportConfig{
		Title:           "Report",
		Organization:    "Org",
		AssessmentType:  "waf-test",
		Scope:           []string{"a.com"},
		Tools:           []string{"tool"},
		Methodology:     "OWASP",
		Format:          FormatPDF,
		Classification:  "Internal",
		PreparedBy:      "Me",
		PreparedFor:     "You",
		IncludeAppendix: true,
		CustomCSS:       ".test {}",
		LogoURL:         "https://logo.png",
	}

	if rc.Title != "Report" {
		t.Error("Title mismatch")
	}
	if !rc.IncludeAppendix {
		t.Error("IncludeAppendix mismatch")
	}
}

func TestComparisonReport_Struct(t *testing.T) {
	cr := &ComparisonReport{
		BaselineDate:  time.Now().Add(-24 * time.Hour),
		CurrentDate:   time.Now(),
		NewFindings:   []*Finding{},
		FixedFindings: []*Finding{},
		Unchanged:     []*Finding{},
		RiskTrend:     "stable",
		Summary:       "All good",
	}

	if cr.RiskTrend != "stable" {
		t.Error("RiskTrend mismatch")
	}
}

func TestTrendPoint_Struct(t *testing.T) {
	tp := &TrendPoint{
		Date:  time.Now(),
		Value: 100,
		Label: "Test",
	}

	if tp.Value != 100 {
		t.Error("Value mismatch")
	}
}

func TestAppendix_Struct(t *testing.T) {
	a := &Appendix{
		Title:   "Appendix A",
		Content: "Content here",
	}

	if a.Title != "Appendix A" {
		t.Error("Title mismatch")
	}
}

func TestTimeRange_Struct(t *testing.T) {
	tr := &TimeRange{
		Start: time.Now(),
		End:   time.Now().Add(1 * time.Hour),
	}

	if tr.End.Before(tr.Start) {
		t.Error("End should be after Start")
	}
}
