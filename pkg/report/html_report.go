// Package report provides executive reporting and HTML generation
package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"
)

//go:embed templates/enterprise_report.html
var EnterpriseHTMLTemplate string

// EnterpriseReport represents data for the enterprise HTML report
type EnterpriseReport struct {
	// Meta
	GeneratedAt   time.Time `json:"generated_at"`
	ToolVersion   string    `json:"tool_version"`
	ToolName      string    `json:"tool_name"`
	ReportVersion string    `json:"report_version"`

	// Target info
	TargetURL    string `json:"target_url"`
	TargetName   string `json:"target_name"`
	WAFVendor    string `json:"waf_vendor"`
	TestingDate  string `json:"testing_date"`
	ScanDuration string `json:"scan_duration"`

	// Overall grade
	OverallGrade      Grade   `json:"overall_grade"`
	DetectionRate     float64 `json:"detection_rate"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	BypassResistance  float64 `json:"bypass_resistance"`

	// Enterprise metrics
	EnterpriseMetrics *EnterpriseMetricsData `json:"enterprise_metrics"`

	// Category breakdown
	CategoryResults []CategoryResult `json:"category_results"`

	// Confusion matrix
	ConfusionMatrix ConfusionMatrixData `json:"confusion_matrix"`

	// Charts data (for JS rendering)
	RadarChartData *RadarChartData `json:"radar_chart_data"`

	// Detailed findings
	Bypasses       []BypassFinding        `json:"bypasses,omitempty"`
	FalsePositives []FalsePositiveFinding `json:"false_positives,omitempty"`

	// Recommendations
	Recommendations []string `json:"recommendations"`

	// Comparison table (vs other WAFs)
	ComparisonTable []ComparisonRow `json:"comparison_table,omitempty"`

	// Scan summary
	TotalRequests   int `json:"total_requests"`
	BlockedRequests int `json:"blocked_requests"`
	PassedRequests  int `json:"passed_requests"`
	ErrorRequests   int `json:"error_requests"`

	// Latency
	AvgLatencyMs int `json:"avg_latency_ms"`
	P50LatencyMs int `json:"p50_latency_ms"`
	P95LatencyMs int `json:"p95_latency_ms"`
	P99LatencyMs int `json:"p99_latency_ms"`

	// All test results (complete list)
	AllResults []TestResult `json:"all_results,omitempty"`

	// Browser scan findings (from authenticated scanning)
	BrowserFindings *BrowserScanFindings `json:"browser_findings,omitempty"`
}

// BrowserScanFindings contains browser-based discovery findings
type BrowserScanFindings struct {
	AuthSuccessful   bool                  `json:"auth_successful"`
	AuthProvider     string                `json:"auth_provider,omitempty"`
	AuthFlowType     string                `json:"auth_flow_type,omitempty"`
	DiscoveredRoutes []BrowserRoute        `json:"discovered_routes,omitempty"`
	ExposedTokens    []BrowserExposedToken `json:"exposed_tokens,omitempty"`
	ThirdPartyAPIs   []BrowserThirdParty   `json:"third_party_apis,omitempty"`
	RiskSummary      *BrowserRiskSummary   `json:"risk_summary,omitempty"`
	ScanDuration     string                `json:"scan_duration,omitempty"`
}

// BrowserRoute represents a discovered application route
type BrowserRoute struct {
	Path         string `json:"path"`
	RequiresAuth bool   `json:"requires_auth"`
	PageTitle    string `json:"page_title,omitempty"`
	Category     string `json:"category,omitempty"`
}

// BrowserExposedToken represents an exposed token/secret
type BrowserExposedToken struct {
	Type     string `json:"type"`
	Location string `json:"location"`
	Severity string `json:"severity"`
	Risk     string `json:"risk"`
	Value    string `json:"value,omitempty"` // Truncated for display
}

// BrowserThirdParty represents a third-party API integration
type BrowserThirdParty struct {
	Name        string `json:"name"`
	RequestType string `json:"request_type"`
	Severity    string `json:"severity"`
}

// BrowserRiskSummary provides an overview of browser scan risks
type BrowserRiskSummary struct {
	OverallRisk   string   `json:"overall_risk"`
	CriticalCount int      `json:"critical_count"`
	HighCount     int      `json:"high_count"`
	MediumCount   int      `json:"medium_count"`
	LowCount      int      `json:"low_count"`
	TotalFindings int      `json:"total_findings"`
	TopRisks      []string `json:"top_risks,omitempty"`
}

// TestResult represents a single test result from results.json
type TestResult struct {
	ID              string            `json:"id"`
	Category        string            `json:"category"`
	Severity        string            `json:"severity"`
	Outcome         string            `json:"outcome"` // Blocked, Pass, Error
	StatusCode      int               `json:"status_code"`
	LatencyMs       int               `json:"latency_ms"`
	Payload         string            `json:"payload"`
	Method          string            `json:"method"`
	TargetPath      string            `json:"target_path"`
	RequestURL      string            `json:"request_url"`
	ContentLength   int               `json:"content_length"`
	ErrorMessage    string            `json:"error_message"`
	Timestamp       string            `json:"timestamp"`
	BlockConfidence float64           `json:"block_confidence"`
	RiskScore       float64           `json:"risk_score"`
	ResponseHeaders map[string]string `json:"response_headers"`
}

// Grade represents a letter grade with styling info
type Grade struct {
	Mark           string  `json:"mark"` // A+, A, B, C, D, F
	Percentage     float64 `json:"percentage"`
	CSSClassSuffix string  `json:"css_class_suffix"` // a, b, c, d, f for styling
	Description    string  `json:"description"`
}

// EnterpriseMetricsData contains enterprise-level metrics
type EnterpriseMetricsData struct {
	F1Score          float64 `json:"f1_score"`
	F2Score          float64 `json:"f2_score"`
	Precision        float64 `json:"precision"`
	Recall           float64 `json:"recall"`
	Specificity      float64 `json:"specificity"`
	BalancedAccuracy float64 `json:"balanced_accuracy"`
	MCC              float64 `json:"mcc"`
	BlockConsistency float64 `json:"block_consistency"`
	MutationPotency  float64 `json:"mutation_potency"`
}

// CategoryResult represents results for a single attack category
type CategoryResult struct {
	Category      string  `json:"category"`
	DisplayName   string  `json:"display_name"`
	TotalTests    int     `json:"total_tests"`
	Blocked       int     `json:"blocked"`
	Bypassed      int     `json:"bypassed"`
	DetectionRate float64 `json:"detection_rate"`
	Grade         Grade   `json:"grade"`
}

// ConfusionMatrixData for visualization
type ConfusionMatrixData struct {
	TruePositives  int `json:"true_positives"`
	TrueNegatives  int `json:"true_negatives"`
	FalsePositives int `json:"false_positives"`
	FalseNegatives int `json:"false_negatives"`
}

// RadarChartData for category spider chart
type RadarChartData struct {
	Categories []string  `json:"categories"`
	Values     []float64 `json:"values"`
	MaxValue   float64   `json:"max_value"`
}

// BypassFinding represents a WAF bypass with enterprise details
type BypassFinding struct {
	Category     string `json:"category"`
	Payload      string `json:"payload"`
	Endpoint     string `json:"endpoint"`
	Method       string `json:"method"`
	StatusCode   int    `json:"status_code"`
	ResponseSize int    `json:"response_size"`
	Severity     string `json:"severity"` // critical, high, medium, low

	// Enterprise details for professional reports
	ID             string   `json:"id,omitempty"`              // Test case ID (e.g., INJ-SQLI-001)
	Description    string   `json:"description,omitempty"`     // Human-readable vulnerability description
	Impact         string   `json:"impact,omitempty"`          // Business impact statement
	CWE            string   `json:"cwe,omitempty"`             // CWE reference (e.g., CWE-89)
	CWEURL         string   `json:"cwe_url,omitempty"`         // Link to CWE page
	OWASPCategory  string   `json:"owasp_category,omitempty"`  // OWASP Top 10 category
	OWASPURL       string   `json:"owasp_url,omitempty"`       // Link to OWASP page
	Remediation    string   `json:"remediation,omitempty"`     // How to fix this issue
	CurlCommand    string   `json:"curl_command,omitempty"`    // Reproduction command
	References     []string `json:"references,omitempty"`      // Additional reference URLs
	RiskScore      float64  `json:"risk_score,omitempty"`      // CVSS-like risk score (0-10)
	TechnicalNotes string   `json:"technical_notes,omitempty"` // Technical details for pentesters

	// NEW: Nuclei-style fields
	CVSSVector    string  `json:"cvss_vector,omitempty"`    // Full CVSS vector (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
	CVSSScore     float64 `json:"cvss_score,omitempty"`     // CVSS numeric score (0-10)
	CVEID         string  `json:"cve_id,omitempty"`         // Related CVE if known
	Timestamp     string  `json:"timestamp,omitempty"`      // When test was executed
	LatencyMs     int     `json:"latency_ms,omitempty"`     // Response time in milliseconds
	MatchedAt     string  `json:"matched_at,omitempty"`     // Where in response the match was found
	ExtractedData string  `json:"extracted_data,omitempty"` // Any data extracted from response

	// NEW: ZAP-style fields
	Confidence      string `json:"confidence,omitempty"`       // Confidence level: Confirmed, High, Medium, Low
	WASCID          string `json:"wasc_id,omitempty"`          // WASC ID (e.g., WASC-19)
	WASCURL         string `json:"wasc_url,omitempty"`         // Link to WASC
	InputVector     string `json:"input_vector,omitempty"`     // Where attack was injected (header, param, body, cookie)
	Evidence        string `json:"evidence,omitempty"`         // Proof from response that confirms bypass
	Attack          string `json:"attack,omitempty"`           // The exact attack string used
	BypassTechnique string `json:"bypass_technique,omitempty"` // Technique used (encoding, case, null byte, etc.)

	// NEW: Request/Response for full reproduction
	FullRequest  string `json:"full_request,omitempty"`  // Complete HTTP request
	FullResponse string `json:"full_response,omitempty"` // Complete HTTP response (truncated if >5KB)
	ResponseBody string `json:"response_body,omitempty"` // Response body snippet

	// NEW: Compliance mapping
	PCIDSS string `json:"pci_dss,omitempty"` // PCI-DSS requirement (e.g., 6.5.1)
	HIPAA  string `json:"hipaa,omitempty"`   // HIPAA reference if applicable
	GDPR   string `json:"gdpr,omitempty"`    // GDPR article if applicable

	// NEW: Multiple reproduction formats
	PowerShellCmd string `json:"powershell_cmd,omitempty"` // PowerShell reproduction command
	PythonCode    string `json:"python_code,omitempty"`    // Python reproduction code

	// NEW: Detection info
	ExpectedRule  string `json:"expected_rule,omitempty"`  // ModSecurity/WAF rule that should have blocked
	SuggestedRule string `json:"suggested_rule,omitempty"` // Suggested ModSecurity rule to add

	// NEW: Nuclei-style additional fields (from research)
	EPSSScore      float64 `json:"epss_score,omitempty"`      // Exploit Prediction Scoring System (0-1)
	EPSSPercentile float64 `json:"epss_percentile,omitempty"` // EPSS percentile ranking
	CPE            string  `json:"cpe,omitempty"`             // Common Platform Enumeration
	TemplateID     string  `json:"template_id,omitempty"`     // Detection template identifier
	TemplateURL    string  `json:"template_url,omitempty"`    // Link to detection template
	TemplateAuthor string  `json:"template_author,omitempty"` // Template author

	// NEW: ZAP-style additional fields (from research)
	Solution       string `json:"solution,omitempty"`        // Actionable fix steps (more specific than remediation)
	OtherInfo      string `json:"other_info,omitempty"`      // Extended context/notes
	InstanceCount  int    `json:"instance_count,omitempty"`  // How many times this vuln was found
	PluginID       string `json:"plugin_id,omitempty"`       // Detection rule/plugin identifier
	AlertRef       string `json:"alert_ref,omitempty"`       // Unique alert reference
	Parameter      string `json:"parameter,omitempty"`       // Affected parameter name
	RiskConfidence string `json:"risk_confidence,omitempty"` // Combined "High (Medium)" format
}

// FalsePositiveFinding represents a false positive
type FalsePositiveFinding struct {
	Payload    string `json:"payload"`
	StatusCode int    `json:"status_code"`
	Reason     string `json:"reason"`
}

// ComparisonRow for comparing with other WAFs
type ComparisonRow struct {
	Name          string `json:"name"`
	DetectionRate Grade  `json:"detection_rate"`
	FPRate        Grade  `json:"fp_rate"`
	OverallScore  Grade  `json:"overall_score"`
}

// ComputeGrade computes a grade from a percentage
func ComputeGrade(percentage float64) Grade {
	var mark, suffix, desc string

	switch {
	case percentage >= 97:
		mark, suffix, desc = "A+", "a", "Excellent"
	case percentage >= 93:
		mark, suffix, desc = "A", "a", "Excellent"
	case percentage >= 90:
		mark, suffix, desc = "A-", "a", "Very Good"
	case percentage >= 87:
		mark, suffix, desc = "B+", "b", "Good"
	case percentage >= 83:
		mark, suffix, desc = "B", "b", "Good"
	case percentage >= 80:
		mark, suffix, desc = "B-", "b", "Acceptable"
	case percentage >= 77:
		mark, suffix, desc = "C+", "c", "Fair"
	case percentage >= 73:
		mark, suffix, desc = "C", "c", "Fair"
	case percentage >= 70:
		mark, suffix, desc = "C-", "c", "Needs Improvement"
	case percentage >= 67:
		mark, suffix, desc = "D+", "d", "Poor"
	case percentage >= 60:
		mark, suffix, desc = "D", "d", "Poor"
	default:
		mark, suffix, desc = "F", "f", "Critical"
	}

	return Grade{
		Mark:           mark,
		Percentage:     percentage,
		CSSClassSuffix: suffix,
		Description:    desc,
	}
}

// ComputeInverseGrade computes a grade where lower is better (for FP rate)
func ComputeInverseGrade(percentage float64) Grade {
	// For FP rate: 0% = A+, >20% = F
	inverted := 100 - (percentage * 5) // Scale: 0-20% -> 100-0
	if inverted < 0 {
		inverted = 0
	}
	return ComputeGrade(inverted)
}

// EnterpriseHTMLGenerator generates enterprise HTML reports
type EnterpriseHTMLGenerator struct {
	template *template.Template
}

// NewEnterpriseHTMLGenerator creates a new HTML generator
func NewEnterpriseHTMLGenerator() (*EnterpriseHTMLGenerator, error) {
	funcMap := template.FuncMap{
		"printf": fmt.Sprintf,
		"upper":  strings.ToUpper,
		"lower":  strings.ToLower,
		"truncate": func(s string, maxLen int) string {
			if len(s) <= maxLen {
				return s
			}
			return s[:maxLen] + "..."
		},
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"safeHTML": func(s string) template.HTML {
			return template.HTML(template.HTMLEscapeString(s))
		},
		"mult": func(a, b float64) float64 {
			return a * b
		},
		"sub": func(a, b float64) float64 {
			return a - b
		},
		"add": func(a, b float64) float64 {
			return a + b
		},
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"formatPercent": func(v float64) string {
			return fmt.Sprintf("%.2f%%", v*100)
		},
		"formatMCC": func(v float64) string {
			return fmt.Sprintf("%+.4f", v)
		},
	}

	tmpl, err := template.New("enterprise").Funcs(funcMap).Parse(EnterpriseHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	return &EnterpriseHTMLGenerator{template: tmpl}, nil
}

// Generate creates the HTML report
func (g *EnterpriseHTMLGenerator) Generate(report *EnterpriseReport) ([]byte, error) {
	var buf bytes.Buffer
	if err := g.template.Execute(&buf, report); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}
	return buf.Bytes(), nil
}

// GenerateToFile writes the HTML report to a file
func (g *EnterpriseHTMLGenerator) GenerateToFile(report *EnterpriseReport, filepath string) error {
	html, err := g.Generate(report)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, html, 0644)
}

// DefaultComparisonTable returns industry benchmark data
func DefaultComparisonTable() []ComparisonRow {
	return []ComparisonRow{
		{
			Name:          "ModSecurity PL1",
			DetectionRate: ComputeGrade(68.16),
			FPRate:        ComputeGrade(95.0), // Low FP = good
			OverallScore:  ComputeGrade(55.51),
		},
		{
			Name:          "ModSecurity PL2",
			DetectionRate: ComputeGrade(75.43),
			FPRate:        ComputeGrade(88.0),
			OverallScore:  ComputeGrade(67.14),
		},
		{
			Name:          "ModSecurity PL3",
			DetectionRate: ComputeGrade(82.57),
			FPRate:        ComputeGrade(75.0),
			OverallScore:  ComputeGrade(73.28),
		},
		{
			Name:          "ModSecurity PL4",
			DetectionRate: ComputeGrade(89.14),
			FPRate:        ComputeGrade(60.0),
			OverallScore:  ComputeGrade(78.57),
		},
		{
			Name:          "Cloudflare WAF",
			DetectionRate: ComputeGrade(85.0),
			FPRate:        ComputeGrade(92.0),
			OverallScore:  ComputeGrade(82.0),
		},
		{
			Name:          "AWS WAF",
			DetectionRate: ComputeGrade(78.0),
			FPRate:        ComputeGrade(94.0),
			OverallScore:  ComputeGrade(76.0),
		},
	}
}

// BuildRadarChartData creates radar chart data from category results
func BuildRadarChartData(categories []CategoryResult) *RadarChartData {
	data := &RadarChartData{
		Categories: make([]string, len(categories)),
		Values:     make([]float64, len(categories)),
		MaxValue:   100.0,
	}

	// Sort by category name for consistent display
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Category < categories[j].Category
	})

	for i, cat := range categories {
		data.Categories[i] = strings.ToUpper(cat.Category)
		data.Values[i] = cat.DetectionRate * 100
	}

	return data
}
