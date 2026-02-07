// Package report provides executive reporting and HTML generation
package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/ui"
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

// CategoryDisplayNames maps internal names to display names
var CategoryDisplayNames = map[string]string{
	"sqli":      "SQL Injection",
	"xss":       "Cross-Site Scripting",
	"cmdi":      "Command Injection",
	"lfi":       "Local File Inclusion",
	"rfi":       "Remote File Inclusion",
	"rce":       "Remote Code Execution",
	"ssrf":      "Server-Side Request Forgery",
	"ssti":      "Server-Side Template Injection",
	"xxe":       "XML External Entity",
	"traversal": "Path Traversal",
	"ldap":      "LDAP Injection",
	"header":    "Header Injection",
	"log":       "Log Injection",
	"nosqli":    "NoSQL Injection",
	"crlf":      "CRLF Injection",
	"injection": "Injection",
	"evasion":   "WAF Evasion",
	"bypass":    "Security Bypass",
	"cache":     "Cache Poisoning",
	"auth":      "Authentication Bypass",
}

// VulnerabilityInfo contains enterprise vulnerability details for each category
type VulnerabilityInfo struct {
	Description   string
	Impact        string
	CWE           string
	CWEURL        string
	OWASPCategory string
	OWASPURL      string
	Remediation   string
	References    []string
	RiskScore     float64

	// NEW: Nuclei-style fields
	CVSSVector string  // Full CVSS 3.1 vector
	CVSSScore  float64 // Calculated CVSS score
	CVEID      string  // Related CVE if applicable

	// NEW: EPSS (Exploit Prediction Scoring System) - Nuclei feature
	EPSSScore      float64 // Probability of exploitation (0.0-1.0)
	EPSSPercentile float64 // Percentile rank (0-100)
	CPE            string  // Common Platform Enumeration identifier

	// NEW: ZAP-style fields
	WASCID    string // WASC Threat Classification ID
	WASCURL   string // Link to WASC
	Solution  string // Specific actionable fix (more targeted than remediation)
	OtherInfo string // Additional context and related information

	// NEW: Compliance mapping
	PCIDSS string // PCI-DSS requirement
	HIPAA  string // HIPAA reference
	GDPR   string // GDPR article

	// NEW: ModSecurity rule info
	ModSecRuleID     string   // ModSecurity rule that should block this
	SuggestedRule    string   // Example ModSecurity rule
	BypassTechniques []string // Common bypass techniques for this category

	// NEW: Additional metadata for reporting
	DetectionDifficulty string // How hard is this to detect (Low/Medium/High)
	ExploitationEase    string // How easy to exploit (Low/Medium/High)
}

// VulnerabilityDatabase contains enterprise-grade vulnerability information
var VulnerabilityDatabase = map[string]VulnerabilityInfo{
	"sqli": {
		Description:   "SQL Injection allows attackers to interfere with database queries, potentially accessing, modifying, or deleting data.",
		Impact:        "Attackers can extract sensitive data, bypass authentication, modify or delete database records, and potentially gain complete control of the database server.",
		CWE:           "CWE-89",
		CWEURL:        "https://cwe.mitre.org/data/definitions/89.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Use parameterized queries (prepared statements) with bound, typed parameters. Implement input validation with allowlists. Apply the principle of least privilege for database accounts. Configure WAF rules to block SQLi patterns.",
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		},
		RiskScore:           9.8,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:           9.8,
		EPSSScore:           0.97,
		EPSSPercentile:      99.8,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Replace dynamic SQL with parameterized queries. Example: Use `PreparedStatement` in Java, `@param` in Go, or `${}` in SQLAlchemy.",
		OtherInfo:           "SQL injection is consistently among the top web vulnerabilities. OWASP Top 10 ranks it #3 in 2021. Automated tools can find many SQLi vulnerabilities, making this a high-risk issue.",
		WASCID:              "WASC-19",
		WASCURL:             "http://projects.webappsec.org/SQL-Injection",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "942100-942999",
		SuggestedRule:       `SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_BODY "@detectSQLi" "id:100001,phase:2,deny,status:403,msg:'SQL Injection Detected'"`,
		BypassTechniques:    []string{"Unicode encoding", "Double URL encoding", "Null byte injection", "Case variation", "Comment insertion", "Whitespace manipulation"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "High",
	},
	"injection": {
		Description:   "Injection flaws allow attackers to send malicious data through an interpreter, leading to unintended command execution.",
		Impact:        "Data theft, data loss, denial of service, or complete system compromise depending on the injection type.",
		CWE:           "CWE-74",
		CWEURL:        "https://cwe.mitre.org/data/definitions/74.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Validate and sanitize all user input. Use parameterized APIs. Implement allowlists for input validation. Configure WAF to detect injection patterns.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/",
		},
		RiskScore:           8.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
		CVSSScore:           8.5,
		EPSSScore:           0.85,
		EPSSPercentile:      95.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Implement strict input validation at the API layer. Use type-safe libraries and avoid string concatenation for building interpreter commands.",
		OtherInfo:           "Injection covers multiple attack types including SQL, OS Command, LDAP, XPath, and Expression Language injection. Each has specific mitigations.",
		WASCID:              "WASC-19",
		WASCURL:             "http://projects.webappsec.org/Improper-Input-Handling",
		PCIDSS:              "6.5.1",
		BypassTechniques:    []string{"Encoding variations", "Null byte injection", "Unicode normalization"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
	"xss": {
		Description:   "Cross-Site Scripting (XSS) enables attackers to inject malicious scripts into web pages viewed by other users.",
		Impact:        "Session hijacking, credential theft, defacement, malware distribution, and phishing attacks targeting users.",
		CWE:           "CWE-79",
		CWEURL:        "https://cwe.mitre.org/data/definitions/79.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Encode all user-supplied output. Use Content Security Policy (CSP) headers. Implement HttpOnly and Secure flags on cookies. Use frameworks with built-in XSS protection.",
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		CVSSScore:           6.1,
		EPSSScore:           0.78,
		EPSSPercentile:      89.5,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use context-aware output encoding: HTML entity encode for HTML context, JavaScript encode for JS context. Implement CSP with script-src 'self'.",
		OtherInfo:           "XSS can be Reflected (non-persistent), Stored (persistent), or DOM-based. Stored XSS is most dangerous as it affects all users viewing the infected content.",
		WASCID:              "WASC-8",
		WASCURL:             "http://projects.webappsec.org/Cross-Site-Scripting",
		PCIDSS:              "6.5.7",
		ModSecRuleID:        "941100-941999",
		SuggestedRule:       `SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES "@detectXSS" "id:100002,phase:2,deny,status:403,msg:'XSS Attack Detected'"`,
		BypassTechniques:    []string{"HTML entity encoding", "JavaScript Unicode escapes", "SVG/MathML vectors", "DOM clobbering", "Mutation XSS"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"cmdi": {
		Description:   "Command Injection allows attackers to execute arbitrary system commands on the host operating system.",
		Impact:        "Complete system compromise, data exfiltration, lateral movement, and persistent access to infrastructure.",
		CWE:           "CWE-78",
		CWEURL:        "https://cwe.mitre.org/data/definitions/78.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Avoid calling OS commands directly. Use language-specific APIs instead of shell commands. Validate and sanitize all inputs. Implement strict WAF rules for command injection patterns.",
		References: []string{
			"https://owasp.org/www-community/attacks/Command_Injection",
		},
		RiskScore:           10.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		CVSSScore:           10.0,
		EPSSScore:           0.95,
		EPSSPercentile:      99.5,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Replace shell command execution with native library functions. Example: Use os.Stat() instead of `ls`, use net/http instead of `curl`.",
		OtherInfo:           "Command injection is often chained with other vulnerabilities. A successful attack grants same privileges as the web server process.",
		WASCID:              "WASC-31",
		WASCURL:             "http://projects.webappsec.org/OS-Commanding",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "932100-932999",
		SuggestedRule:       `SecRule ARGS|REQUEST_BODY "@rx (?:;|\||&&|\$\(|` + "`" + `)" "id:100003,phase:2,deny,status:403,msg:'Command Injection Detected'"`,
		BypassTechniques:    []string{"Backtick execution", "$(command) substitution", "Newline injection", "Null byte", "Variable expansion"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "High",
	},
	"rce": {
		Description:   "Remote Code Execution enables attackers to run arbitrary code on the server, leading to complete system compromise.",
		Impact:        "Full server control, data breach, ransomware deployment, and use of compromised systems for further attacks.",
		CWE:           "CWE-94",
		CWEURL:        "https://cwe.mitre.org/data/definitions/94.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Avoid deserialization of untrusted data. Disable dangerous functions. Use sandboxing and containerization. Keep all software updated. Implement application-layer firewalls.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
		},
		RiskScore:           10.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		CVSSScore:           10.0,
		EPSSScore:           0.98,
		EPSSPercentile:      99.9,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Disable dangerous PHP functions (eval, exec, system, passthru). Use sandboxed execution environments. Deploy RASP for runtime protection.",
		OtherInfo:           "RCE vulnerabilities are the highest priority issues. They are often targeted by ransomware and APT groups. Immediate patching is critical.",
		WASCID:              "WASC-31",
		WASCURL:             "http://projects.webappsec.org/OS-Commanding",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "932100-932999",
		BypassTechniques:    []string{"Serialization gadgets", "Template injection", "Expression language injection", "File upload RCE"},
		DetectionDifficulty: "High",
		ExploitationEase:    "High",
	},
	"lfi": {
		Description:   "Local File Inclusion allows attackers to read sensitive files from the server filesystem.",
		Impact:        "Exposure of configuration files, source code, credentials, and sensitive system information.",
		CWE:           "CWE-98",
		CWEURL:        "https://cwe.mitre.org/data/definitions/98.html",
		OWASPCategory: "A01:2021 - Broken Access Control",
		OWASPURL:      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		Remediation:   "Avoid file operations with user-supplied input. Use allowlists for permitted files. Implement chroot jails. Configure WAF to block path traversal patterns.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
		},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:           7.5,
		EPSSScore:           0.72,
		EPSSPercentile:      85.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use a whitelist of allowed file paths. Never pass user input directly to file operations. Use basename() to strip directory components.",
		OtherInfo:           "LFI can lead to RCE through log poisoning, PHP wrappers, or /proc/self/environ injection. Common targets: /etc/passwd, wp-config.php, .env files.",
		WASCID:              "WASC-33",
		WASCURL:             "http://projects.webappsec.org/Path-Traversal",
		PCIDSS:              "6.5.8",
		ModSecRuleID:        "930100-930999",
		SuggestedRule:       `SecRule REQUEST_URI|ARGS "@rx (?:\.\./|\.\.\\)" "id:100004,phase:2,deny,status:403,msg:'Path Traversal Detected'"`,
		BypassTechniques:    []string{"Double encoding", "Null byte", "Unicode encoding", "PHP wrappers", "Long paths"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"traversal": {
		Description:   "Path Traversal (Directory Traversal) allows attackers to access files and directories outside the intended path.",
		Impact:        "Unauthorized file access, configuration disclosure, source code exposure, and potential system compromise.",
		CWE:           "CWE-22",
		CWEURL:        "https://cwe.mitre.org/data/definitions/22.html",
		OWASPCategory: "A01:2021 - Broken Access Control",
		OWASPURL:      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		Remediation:   "Validate and canonicalize all file paths. Use allowlists for permitted files. Implement proper access controls. Block path traversal sequences (../) in WAF.",
		References: []string{
			"https://owasp.org/www-community/attacks/Path_Traversal",
		},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:           7.5,
		EPSSScore:           0.68,
		EPSSPercentile:      82.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use filepath.Clean() in Go, realpath() in PHP, or os.path.normpath() in Python to canonicalize paths before use.",
		OtherInfo:           "Traversal attacks often target configuration files, SSH keys, database credentials, and environment files.",
		WASCID:              "WASC-33",
		WASCURL:             "http://projects.webappsec.org/Path-Traversal",
		PCIDSS:              "6.5.8",
		ModSecRuleID:        "930100-930999",
		SuggestedRule:       `SecRule REQUEST_URI|ARGS "@rx (?:\.\./|\.\.\\)" "id:100005,phase:2,deny,status:403,msg:'Path Traversal Detected'"`,
		BypassTechniques:    []string{"URL encoding", "Double encoding", "UTF-8 encoding", "Overlong UTF-8", "Backslash substitution"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"ssrf": {
		Description:   "Server-Side Request Forgery allows attackers to induce the server to make requests to unintended locations.",
		Impact:        "Access to internal services, cloud metadata exploitation, port scanning, and potential RCE through internal services.",
		CWE:           "CWE-918",
		CWEURL:        "https://cwe.mitre.org/data/definitions/918.html",
		OWASPCategory: "A10:2021 - Server-Side Request Forgery",
		OWASPURL:      "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
		Remediation:   "Validate and sanitize all URLs. Use allowlists for permitted domains. Block requests to private IP ranges. Disable unnecessary URL schemas.",
		References: []string{
			"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
		},
		RiskScore:           9.1,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
		CVSSScore:           9.1,
		EPSSScore:           0.88,
		EPSSPercentile:      96.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Block requests to internal IPs (127.0.0.1, 10.x, 172.16.x, 192.168.x, 169.254.169.254). Use DNS resolution validation before making requests.",
		OtherInfo:           "SSRF is the #1 technique for cloud metadata attacks. AWS IMDSv2, Azure IMDS, and GCP metadata can all be exploited through SSRF.",
		WASCID:              "WASC-15",
		WASCURL:             "http://projects.webappsec.org/Server-Side-Request-Forgery",
		PCIDSS:              "6.5.10",
		ModSecRuleID:        "934100-934199",
		SuggestedRule:       `SecRule ARGS "@rx (?:127\.0\.0\.1|localhost|169\.254\.169\.254|10\.\d{1,3}\.\d{1,3}\.\d{1,3})" "id:100006,phase:2,deny,status:403,msg:'SSRF Attempt Detected'"`,
		BypassTechniques:    []string{"IP obfuscation", "DNS rebinding", "Redirect chains", "IPv6 addresses", "URL parsing differences"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "High",
	},
	"ssti": {
		Description:   "Server-Side Template Injection allows attackers to inject malicious code into template engines.",
		Impact:        "Remote code execution, sensitive data exposure, and complete server compromise.",
		CWE:           "CWE-1336",
		CWEURL:        "https://cwe.mitre.org/data/definitions/1336.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Use logic-less templates when possible. Sandbox template execution. Never pass user input directly to templates. Validate all template variables.",
		References: []string{
			"https://portswigger.net/research/server-side-template-injection",
		},
		RiskScore:           9.8,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:           9.8,
		EPSSScore:           0.92,
		EPSSPercentile:      98.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use logic-less templates (Mustache). If using powerful templates (Jinja2, Twig), enable sandboxing and restrict dangerous methods.",
		OtherInfo:           "SSTI payloads vary by template engine. Common targets: Jinja2 {{...}}, Twig {{...}}, Freemarker ${...}, Velocity #set().",
		WASCID:              "WASC-20",
		WASCURL:             "http://projects.webappsec.org/Improper-Input-Handling",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "941100-941199",
		SuggestedRule:       `SecRule ARGS "@rx (?:\{\{.*\}\}|\$\{.*\})" "id:100007,phase:2,deny,status:403,msg:'Template Injection Detected'"`,
		BypassTechniques:    []string{"Alternate template syntax", "String concatenation", "Attribute access chains", "Filter abuse"},
		DetectionDifficulty: "High",
		ExploitationEase:    "High",
	},
	"xxe": {
		Description:   "XML External Entity injection exploits XML parsers to access files, perform SSRF, or cause denial of service.",
		Impact:        "File disclosure, SSRF, denial of service, and potential remote code execution.",
		CWE:           "CWE-611",
		CWEURL:        "https://cwe.mitre.org/data/definitions/611.html",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		OWASPURL:      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		Remediation:   "Disable DTD processing and external entities. Use less complex data formats (JSON). Validate and sanitize all XML input. Keep XML parsers updated.",
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
		},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
		CVSSScore:           7.5,
		EPSSScore:           0.75,
		EPSSPercentile:      88.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Set XMLReader.DtdProcessing = DtdProcessing.Prohibit. In Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true).",
		OtherInfo:           "XXE was OWASP Top 10 #4 in 2017. Most modern parsers disable external entities by default, but many legacy applications remain vulnerable.",
		WASCID:              "WASC-43",
		WASCURL:             "http://projects.webappsec.org/XML-External-Entities",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "931100-931199",
		SuggestedRule:       `SecRule REQUEST_BODY "@rx <!ENTITY" "id:100008,phase:2,deny,status:403,msg:'XXE Attack Detected'"`,
		BypassTechniques:    []string{"Parameter entities", "DTD in external subset", "UTF-7 encoding", "XInclude"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
	"nosqli": {
		Description:   "NoSQL Injection allows attackers to manipulate NoSQL database queries to access or modify data.",
		Impact:        "Data theft, authentication bypass, and unauthorized data manipulation.",
		CWE:           "CWE-943",
		CWEURL:        "https://cwe.mitre.org/data/definitions/943.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Use parameterized queries. Validate input types. Avoid using operators that accept user input. Implement proper access controls.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
		},
		RiskScore:           8.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
		CVSSScore:           8.0,
		EPSSScore:           0.70,
		EPSSPercentile:      84.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Sanitize user input before passing to MongoDB queries. Avoid $where. Use strict type checking for query operators.",
		OtherInfo:           "NoSQL injection commonly exploits MongoDB operators ($ne, $gt, $regex). JavaScript execution via $where is particularly dangerous.",
		WASCID:              "WASC-19",
		WASCURL:             "http://projects.webappsec.org/SQL-Injection",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "942100-942999",
		BypassTechniques:    []string{"Operator injection", "JavaScript injection", "Array injection", "Type coercion"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
	"ldap": {
		Description:   "LDAP Injection allows attackers to modify LDAP queries to access or modify directory information.",
		Impact:        "Authentication bypass, unauthorized access to directory data, and privilege escalation.",
		CWE:           "CWE-90",
		CWEURL:        "https://cwe.mitre.org/data/definitions/90.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Validate and escape all user input. Use LDAP libraries with parameterized queries. Implement strict input validation.",
		References: []string{
			"https://owasp.org/www-community/attacks/LDAP_Injection",
		},
		RiskScore:           7.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:           7.0,
		EPSSScore:           0.55,
		EPSSPercentile:      72.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use parameterized LDAP queries. Escape special characters: * ( ) \\ NUL. Use allowlists for attribute names.",
		OtherInfo:           "LDAP injection commonly targets authentication (user=*), wildcard attacks, and blind injection via response timing.",
		WASCID:              "WASC-29",
		WASCURL:             "http://projects.webappsec.org/LDAP-Injection",
		PCIDSS:              "6.5.1",
		BypassTechniques:    []string{"Wildcard injection", "Boolean-based blind", "OR injection", "Comment injection"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
	"crlf": {
		Description:   "CRLF Injection allows attackers to inject carriage return and line feed characters to manipulate HTTP responses.",
		Impact:        "HTTP response splitting, session fixation, XSS, and cache poisoning attacks.",
		CWE:           "CWE-113",
		CWEURL:        "https://cwe.mitre.org/data/definitions/113.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Validate and encode all user input used in HTTP headers. Remove or encode CR and LF characters. Use framework-provided header setting functions.",
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
		},
		RiskScore:           6.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		CVSSScore:           6.1,
		EPSSScore:           0.45,
		EPSSPercentile:      65.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Strip or encode \\r\\n (CR/LF) from user input before using in headers. Use framework header APIs that handle encoding automatically.",
		OtherInfo:           "CRLF injection can lead to response splitting where attackers inject entire HTTP responses, enabling cache poisoning and XSS.",
		WASCID:              "WASC-25",
		WASCURL:             "http://projects.webappsec.org/HTTP-Response-Splitting",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "921100-921199",
		SuggestedRule:       `SecRule ARGS|ARGS_NAMES "@rx [\r\n]" "id:100009,phase:2,deny,status:403,msg:'CRLF Injection Detected'"`,
		BypassTechniques:    []string{"URL encoding", "Unicode encoding", "Null byte injection", "Header continuation"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"header": {
		Description:         "Header Injection allows attackers to inject malicious content into HTTP headers.",
		Impact:              "Response splitting, cache poisoning, session hijacking, and XSS attacks.",
		CWE:                 "CWE-113",
		CWEURL:              "https://cwe.mitre.org/data/definitions/113.html",
		OWASPCategory:       "A03:2021 - Injection",
		OWASPURL:            "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:         "Sanitize all user input used in headers. Use framework-provided header functions. Validate header values against allowlists.",
		References:          []string{},
		RiskScore:           6.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		CVSSScore:           6.1,
		EPSSScore:           0.42,
		EPSSPercentile:      62.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use allowlists for header values. Avoid reflecting user input in headers. Use Content-Disposition: attachment for downloads.",
		OtherInfo:           "Header injection is often combined with CRLF injection for full response control. X-Forwarded-For and Host headers are common targets.",
		WASCID:              "WASC-25",
		WASCURL:             "http://projects.webappsec.org/HTTP-Response-Splitting",
		PCIDSS:              "6.5.1",
		BypassTechniques:    []string{"Header continuation", "Null byte", "Unicode normalization"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"cache": {
		Description:   "Cache Poisoning attacks exploit caching mechanisms to serve malicious content to users.",
		Impact:        "XSS delivery to all cached users, defacement, credential theft, and widespread malware distribution.",
		CWE:           "CWE-444",
		CWEURL:        "https://cwe.mitre.org/data/definitions/444.html",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		OWASPURL:      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		Remediation:   "Include all relevant headers in cache keys. Validate Host and X-Forwarded headers. Implement cache key normalization. Use signed cache keys.",
		References: []string{
			"https://portswigger.net/research/practical-web-cache-poisoning",
		},
		RiskScore:           8.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
		CVSSScore:           7.2,
		EPSSScore:           0.60,
		EPSSPercentile:      78.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Include all keyed headers in Vary. Normalize request paths before caching. Use cache busting for sensitive resources.",
		OtherInfo:           "Cache poisoning can affect CDNs, reverse proxies, and browser caches. A single poisoned cache entry can affect thousands of users.",
		WASCID:              "WASC-34",
		WASCURL:             "http://projects.webappsec.org/Predictable-Resource-Location",
		PCIDSS:              "6.5.10",
		BypassTechniques:    []string{"Unkeyed headers", "Cache key normalization differences", "HTTP desync", "Request smuggling"},
		DetectionDifficulty: "High",
		ExploitationEase:    "Medium",
	},
	"evasion": {
		Description:   "WAF Evasion techniques bypass security filters through encoding, obfuscation, or protocol manipulation.",
		Impact:        "Successful bypass of security controls, enabling exploitation of underlying vulnerabilities.",
		CWE:           "CWE-693",
		CWEURL:        "https://cwe.mitre.org/data/definitions/693.html",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		OWASPURL:      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		Remediation:   "Normalize and decode input before inspection. Implement multiple WAF rules for common evasions. Use request body inspection. Keep WAF signatures updated.",
		References: []string{
			"https://owasp.org/www-community/attacks/",
		},
		RiskScore:           7.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
		CVSSScore:           6.5,
		EPSSScore:           0.50,
		EPSSPercentile:      70.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Enable recursive decoding. Normalize Unicode before inspection. Parse chunked encoding. Validate Content-Type matches body.",
		OtherInfo:           "WAF evasion is a meta-vulnerability. Successful evasion enables other attacks (SQLi, XSS, etc.) to bypass protection.",
		WASCID:              "WASC-42",
		WASCURL:             "http://projects.webappsec.org/Abuse-of-Functionality",
		PCIDSS:              "6.6",
		BypassTechniques:    []string{"Double encoding", "Unicode normalization", "Case variation", "Chunked encoding", "HTTP/2 downgrade"},
		DetectionDifficulty: "High",
		ExploitationEase:    "Low",
	},
	"auth": {
		Description:   "Authentication Bypass allows attackers to gain access without valid credentials.",
		Impact:        "Unauthorized access to accounts, privilege escalation, and data exposure.",
		CWE:           "CWE-287",
		CWEURL:        "https://cwe.mitre.org/data/definitions/287.html",
		OWASPCategory: "A07:2021 - Identification and Authentication Failures",
		OWASPURL:      "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
		Remediation:   "Implement proper authentication checks. Use secure session management. Implement MFA. Validate all authentication tokens server-side.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		},
		RiskScore:           8.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		CVSSScore:           9.1,
		EPSSScore:           0.80,
		EPSSPercentile:      92.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Enforce authentication at every endpoint. Use centralized auth middleware. Implement rate limiting. Add MFA for sensitive operations.",
		OtherInfo:           "Authentication bypass is often the gateway to all other attacks. Look for hidden endpoints, default credentials, and JWT weaknesses.",
		WASCID:              "WASC-1",
		WASCURL:             "http://projects.webappsec.org/Brute-Force",
		PCIDSS:              "8.2.1",
		BypassTechniques:    []string{"Default credentials", "JWT manipulation", "Session fixation", "Parameter tampering", "Race conditions"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "High",
	},
	"bypass": {
		Description:         "Security Bypass allows attackers to circumvent security controls and access protected resources.",
		Impact:              "Access to restricted functionality, privilege escalation, and exploitation of protected endpoints.",
		CWE:                 "CWE-284",
		CWEURL:              "https://cwe.mitre.org/data/definitions/284.html",
		OWASPCategory:       "A01:2021 - Broken Access Control",
		OWASPURL:            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		Remediation:         "Implement defense in depth. Validate access controls at multiple layers. Use allowlists for permitted actions. Audit all security bypasses.",
		References:          []string{},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
		CVSSScore:           7.1,
		EPSSScore:           0.65,
		EPSSPercentile:      80.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Deny by default. Implement RBAC. Validate authorization on every request. Log and alert on bypass attempts.",
		OtherInfo:           "Security bypass often exploits inconsistencies between frontend restrictions and backend enforcement.",
		WASCID:              "WASC-2",
		WASCURL:             "http://projects.webappsec.org/Insufficient-Authorization",
		PCIDSS:              "7.1",
		BypassTechniques:    []string{"IDOR", "Forced browsing", "HTTP method tampering", "Path traversal", "Parameter pollution"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
}

// GetVulnerabilityInfo returns enterprise vulnerability info for a category
func GetVulnerabilityInfo(category string) VulnerabilityInfo {
	normalizedCat := strings.ToLower(category)
	if info, ok := VulnerabilityDatabase[normalizedCat]; ok {
		return info
	}
	// Check for partial matches
	for key, info := range VulnerabilityDatabase {
		if strings.Contains(normalizedCat, key) || strings.Contains(key, normalizedCat) {
			return info
		}
	}
	// Default generic info
	return VulnerabilityInfo{
		Description:   fmt.Sprintf("Security vulnerability detected in %s category.", category),
		Impact:        "Potential security breach depending on the specific vulnerability.",
		CWE:           "CWE-20",
		CWEURL:        "https://cwe.mitre.org/data/definitions/20.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/",
		Remediation:   "Review and remediate the specific vulnerability. Implement input validation and proper security controls.",
		RiskScore:     5.0,
	}
}

// GenerateCurlCommand creates a curl reproduction command for a bypass finding
func GenerateCurlCommand(finding *BypassFinding) string {
	if finding.Endpoint == "" {
		return ""
	}

	// Escape payload for shell
	escapedPayload := strings.ReplaceAll(finding.Payload, "'", "'\\''")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\n", "\\n")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\r", "\\r")

	method := finding.Method
	if method == "" {
		method = "GET"
	}

	var cmd strings.Builder
	cmd.WriteString("curl -X ")
	cmd.WriteString(method)
	cmd.WriteString(" '")
	cmd.WriteString(finding.Endpoint)
	cmd.WriteString("'")

	// Add payload as appropriate for method
	if method == "POST" || method == "PUT" || method == "PATCH" {
		cmd.WriteString(" \\\n  -d '")
		cmd.WriteString(escapedPayload)
		cmd.WriteString("'")
	} else if len(escapedPayload) < 200 && !strings.Contains(escapedPayload, "\n") {
		// For GET requests with short payloads, show as comment
		cmd.WriteString(" \\\n  # Payload: ")
		cmd.WriteString(escapedPayload)
	}

	cmd.WriteString(" \\\n  -H 'User-Agent: SecurityTester/1.0'")
	cmd.WriteString(" \\\n  -i -k")

	return cmd.String()
}

// EnrichBypassFinding adds enterprise details to a bypass finding
func EnrichBypassFinding(finding *BypassFinding) {
	if finding == nil {
		return
	}

	vulnInfo := GetVulnerabilityInfo(finding.Category)

	// Basic fields
	if finding.Description == "" {
		finding.Description = vulnInfo.Description
	}
	if finding.Impact == "" {
		finding.Impact = vulnInfo.Impact
	}
	if finding.CWE == "" {
		finding.CWE = vulnInfo.CWE
		finding.CWEURL = vulnInfo.CWEURL
	}
	if finding.OWASPCategory == "" {
		finding.OWASPCategory = vulnInfo.OWASPCategory
		finding.OWASPURL = vulnInfo.OWASPURL
	}
	if finding.Remediation == "" {
		finding.Remediation = vulnInfo.Remediation
	}
	if finding.RiskScore == 0 {
		finding.RiskScore = vulnInfo.RiskScore
	}
	if len(finding.References) == 0 {
		finding.References = vulnInfo.References
	}

	// NEW: Nuclei-style CVSS fields
	if finding.CVSSVector == "" && vulnInfo.CVSSVector != "" {
		finding.CVSSVector = vulnInfo.CVSSVector
	}
	if finding.CVSSScore == 0 && vulnInfo.CVSSScore > 0 {
		finding.CVSSScore = vulnInfo.CVSSScore
	}
	if finding.Timestamp == "" {
		finding.Timestamp = time.Now().Format("2006-01-02T15:04:05-07:00")
	}

	// NEW: Nuclei-style EPSS fields
	if finding.EPSSScore == 0 && vulnInfo.EPSSScore > 0 {
		finding.EPSSScore = vulnInfo.EPSSScore
	}
	if finding.EPSSPercentile == 0 && vulnInfo.EPSSPercentile > 0 {
		finding.EPSSPercentile = vulnInfo.EPSSPercentile
	}
	if finding.CPE == "" && vulnInfo.CPE != "" {
		finding.CPE = vulnInfo.CPE
	}

	// NEW: ZAP-style Solution and OtherInfo fields
	if finding.Solution == "" && vulnInfo.Solution != "" {
		finding.Solution = vulnInfo.Solution
	}
	if finding.OtherInfo == "" && vulnInfo.OtherInfo != "" {
		finding.OtherInfo = vulnInfo.OtherInfo
	}
	if finding.RiskConfidence == "" {
		// Generate ZAP-style "High (Medium)" format
		finding.RiskConfidence = fmt.Sprintf("%s (%s)", finding.Severity, finding.Confidence)
	}

	// NEW: ZAP-style WASC fields
	if finding.WASCID == "" && vulnInfo.WASCID != "" {
		finding.WASCID = vulnInfo.WASCID
		finding.WASCURL = vulnInfo.WASCURL
	}
	if finding.Confidence == "" {
		// Default confidence based on bypass success
		finding.Confidence = "High"
	}
	if finding.InputVector == "" {
		// Detect input vector from payload/endpoint
		finding.InputVector = detectInputVector(finding)
	}
	if finding.Attack == "" {
		finding.Attack = finding.Payload
	}
	if finding.BypassTechnique == "" && len(vulnInfo.BypassTechniques) > 0 {
		finding.BypassTechnique = detectBypassTechnique(finding.Payload, vulnInfo.BypassTechniques)
	}

	// NEW: Compliance mapping
	if finding.PCIDSS == "" && vulnInfo.PCIDSS != "" {
		finding.PCIDSS = vulnInfo.PCIDSS
	}

	// NEW: ModSecurity rules
	if finding.ExpectedRule == "" && vulnInfo.ModSecRuleID != "" {
		finding.ExpectedRule = vulnInfo.ModSecRuleID
	}
	if finding.SuggestedRule == "" && vulnInfo.SuggestedRule != "" {
		finding.SuggestedRule = vulnInfo.SuggestedRule
	}

	// NEW: Detection metadata from vulnerability database
	if finding.InstanceCount == 0 {
		finding.InstanceCount = 1 // Default to 1 instance
	}

	// Generate reproduction commands
	if finding.CurlCommand == "" {
		finding.CurlCommand = GenerateCurlCommand(finding)
	}
	if finding.PowerShellCmd == "" {
		finding.PowerShellCmd = GeneratePowerShellCommand(finding)
	}
	if finding.PythonCode == "" {
		finding.PythonCode = GeneratePythonCode(finding)
	}
}

// detectInputVector determines where the attack was injected
func detectInputVector(finding *BypassFinding) string {
	payload := strings.ToLower(finding.Payload)
	endpoint := strings.ToLower(finding.Endpoint)

	if strings.Contains(payload, "cookie:") || strings.Contains(payload, "set-cookie") {
		return "Cookie"
	}
	if strings.Contains(payload, "referer:") || strings.Contains(payload, "x-forwarded") {
		return "Header"
	}
	if finding.Method == "POST" || finding.Method == "PUT" || finding.Method == "PATCH" {
		return "Request Body"
	}
	if strings.Contains(endpoint, "?") || strings.Contains(endpoint, "&") {
		return "Query Parameter"
	}
	return "URL Path"
}

// detectBypassTechnique identifies the evasion technique used
func detectBypassTechnique(payload string, techniques []string) string {
	payloadLower := strings.ToLower(payload)

	if strings.Contains(payload, "%00") || strings.Contains(payloadLower, "\\x00") {
		return "Null Byte Injection"
	}
	if strings.Contains(payload, "%25") || strings.Contains(payload, "%252") {
		return "Double URL Encoding"
	}
	if strings.Contains(payload, "\\u") || strings.Contains(payload, "%u") {
		return "Unicode Encoding"
	}
	if strings.Contains(payload, "/*") || strings.Contains(payload, "--") || strings.Contains(payload, "#") {
		return "Comment Insertion"
	}
	if payload != strings.ToLower(payload) && payload != strings.ToUpper(payload) {
		return "Case Variation"
	}
	if strings.Contains(payload, "\t") || strings.Contains(payload, "  ") {
		return "Whitespace Manipulation"
	}
	if len(techniques) > 0 {
		return techniques[0] // Return first technique as fallback
	}
	return "Unknown Technique"
}

// GeneratePowerShellCommand creates a PowerShell reproduction command
func GeneratePowerShellCommand(finding *BypassFinding) string {
	if finding.Endpoint == "" {
		return ""
	}

	escapedPayload := strings.ReplaceAll(finding.Payload, "'", "''")
	escapedPayload = strings.ReplaceAll(escapedPayload, "`", "``")

	method := finding.Method
	if method == "" {
		method = "GET"
	}

	var cmd strings.Builder
	cmd.WriteString("Invoke-WebRequest -Uri '")
	cmd.WriteString(finding.Endpoint)
	cmd.WriteString("' -Method ")
	cmd.WriteString(method)

	if method == "POST" || method == "PUT" || method == "PATCH" {
		cmd.WriteString(" -Body '")
		cmd.WriteString(escapedPayload)
		cmd.WriteString("'")
	}

	cmd.WriteString(" -Headers @{'User-Agent'='SecurityTester/1.0'}")
	cmd.WriteString(" -SkipCertificateCheck")

	return cmd.String()
}

// GeneratePythonCode creates Python reproduction code
func GeneratePythonCode(finding *BypassFinding) string {
	if finding.Endpoint == "" {
		return ""
	}

	escapedPayload := strings.ReplaceAll(finding.Payload, "\"", "\\\"")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\n", "\\n")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\r", "\\r")

	method := strings.ToLower(finding.Method)
	if method == "" {
		method = "get"
	}

	var code strings.Builder
	code.WriteString("import requests\n\n")
	code.WriteString("url = \"")
	code.WriteString(finding.Endpoint)
	code.WriteString("\"\n")
	code.WriteString("payload = \"")
	code.WriteString(escapedPayload)
	code.WriteString("\"\n")
	code.WriteString("headers = {'User-Agent': 'SecurityTester/1.0'}\n\n")

	if method == "post" || method == "put" || method == "patch" {
		code.WriteString("response = requests.")
		code.WriteString(method)
		code.WriteString("(url, data=payload, headers=headers, verify=False)\n")
	} else {
		code.WriteString("# Payload: ")
		code.WriteString(escapedPayload)
		code.WriteString("\nresponse = requests.")
		code.WriteString(method)
		code.WriteString("(url, headers=headers, verify=False)\n")
	}

	code.WriteString("print(f'Status: {response.status_code}')\n")
	code.WriteString("print(response.text[:500])")

	return code.String()
}

// GetCategoryDisplayName returns a human-readable name
func GetCategoryDisplayName(category string) string {
	if name, ok := CategoryDisplayNames[strings.ToLower(category)]; ok {
		return name
	}
	if len(category) > 0 {
		return strings.ToUpper(category[:1]) + category[1:]
	}
	return category
}

// BuildFromMetrics creates an EnterpriseReport from metrics.EnterpriseMetrics
// This is the main conversion function used by the auto command
func BuildFromMetrics(m interface{}, targetName string, scanDuration time.Duration) (*EnterpriseReport, error) {
	// Use reflection-free approach: marshal to JSON and unmarshal into our expected structure
	// This avoids import cycles while maintaining type safety
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metrics: %w", err)
	}

	// Parse into a map for flexible access
	var metricsMap map[string]interface{}
	if err := json.Unmarshal(data, &metricsMap); err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %w", err)
	}

	report := &EnterpriseReport{
		GeneratedAt:   time.Now(),
		ToolVersion:   ui.Version,
		ToolName:      "WAF-Tester",
		ReportVersion: "1.0",
		TargetName:    targetName,
		TestingDate:   time.Now().Format("2006-01-02 15:04:05"),
		ScanDuration:  scanDuration.Round(time.Second).String(),
	}

	// Extract target URL
	if url, ok := metricsMap["target_url"].(string); ok {
		report.TargetURL = url
	}

	// Extract WAF vendor
	if vendor, ok := metricsMap["waf_vendor"].(string); ok {
		report.WAFVendor = vendor
	}

	// Extract grade
	if grade, ok := metricsMap["grade"].(string); ok && len(grade) > 0 {
		// Compute grade from detection rate for styling
		detRate := 0.0
		if dr, ok := metricsMap["detection_rate"].(float64); ok {
			detRate = dr * 100
		}
		report.OverallGrade = Grade{
			Mark:           grade,
			Percentage:     detRate,
			CSSClassSuffix: strings.ToLower(string(grade[0])),
			Description:    "",
		}
		if gradeReason, ok := metricsMap["grade_reason"].(string); ok {
			report.OverallGrade.Description = gradeReason
		}
	}

	// Extract primary metrics
	if dr, ok := metricsMap["detection_rate"].(float64); ok {
		report.DetectionRate = dr
	}
	if fpr, ok := metricsMap["false_positive_rate"].(float64); ok {
		report.FalsePositiveRate = fpr
	}
	if br, ok := metricsMap["bypass_resistance"].(float64); ok {
		report.BypassResistance = br
	}

	// Extract enterprise metrics
	report.EnterpriseMetrics = &EnterpriseMetricsData{}
	if f1, ok := metricsMap["f1_score"].(float64); ok {
		report.EnterpriseMetrics.F1Score = f1
	}
	if f2, ok := metricsMap["f2_score"].(float64); ok {
		report.EnterpriseMetrics.F2Score = f2
	}
	if prec, ok := metricsMap["precision"].(float64); ok {
		report.EnterpriseMetrics.Precision = prec
	}
	if rec, ok := metricsMap["recall"].(float64); ok {
		report.EnterpriseMetrics.Recall = rec
	} else if dr, ok := metricsMap["detection_rate"].(float64); ok {
		report.EnterpriseMetrics.Recall = dr
	}
	if spec, ok := metricsMap["specificity"].(float64); ok {
		report.EnterpriseMetrics.Specificity = spec
	}
	if ba, ok := metricsMap["balanced_accuracy"].(float64); ok {
		report.EnterpriseMetrics.BalancedAccuracy = ba
	}
	if mcc, ok := metricsMap["mcc"].(float64); ok {
		report.EnterpriseMetrics.MCC = mcc
	}
	if bc, ok := metricsMap["block_consistency"].(float64); ok {
		report.EnterpriseMetrics.BlockConsistency = bc
	}
	if mp, ok := metricsMap["mutation_potency"].(float64); ok {
		report.EnterpriseMetrics.MutationPotency = mp
	}

	// Extract confusion matrix
	if cm, ok := metricsMap["confusion_matrix"].(map[string]interface{}); ok {
		if tp, ok := cm["true_positives"].(float64); ok {
			report.ConfusionMatrix.TruePositives = int(tp)
		}
		if tn, ok := cm["true_negatives"].(float64); ok {
			report.ConfusionMatrix.TrueNegatives = int(tn)
		}
		if fp, ok := cm["false_positives"].(float64); ok {
			report.ConfusionMatrix.FalsePositives = int(fp)
		}
		if fn, ok := cm["false_negatives"].(float64); ok {
			report.ConfusionMatrix.FalseNegatives = int(fn)
		}
	}

	// Extract latency
	if lat, ok := metricsMap["avg_latency_ms"].(float64); ok {
		report.AvgLatencyMs = int(lat)
	}
	if lat, ok := metricsMap["p50_latency_ms"].(float64); ok {
		report.P50LatencyMs = int(lat)
	}
	if lat, ok := metricsMap["p95_latency_ms"].(float64); ok {
		report.P95LatencyMs = int(lat)
	}
	if lat, ok := metricsMap["p99_latency_ms"].(float64); ok {
		report.P99LatencyMs = int(lat)
	}

	// Extract total requests
	if tr, ok := metricsMap["total_requests"].(float64); ok {
		report.TotalRequests = int(tr)
	}

	// Calculate blocked/passed from confusion matrix
	report.BlockedRequests = report.ConfusionMatrix.TruePositives + report.ConfusionMatrix.FalsePositives
	report.PassedRequests = report.ConfusionMatrix.TrueNegatives + report.ConfusionMatrix.FalseNegatives

	// Extract category metrics
	if catMetrics, ok := metricsMap["category_metrics"].(map[string]interface{}); ok {
		report.CategoryResults = make([]CategoryResult, 0, len(catMetrics))
		for cat, metrics := range catMetrics {
			catMap, ok := metrics.(map[string]interface{})
			if !ok {
				continue
			}

			cr := CategoryResult{
				Category:    cat,
				DisplayName: GetCategoryDisplayName(cat),
			}

			if dr, ok := catMap["detection_rate"].(float64); ok {
				cr.DetectionRate = dr
				cr.Grade = ComputeGrade(dr * 100)
			}
			if t, ok := catMap["total_tests"].(float64); ok {
				cr.TotalTests = int(t)
			}
			if b, ok := catMap["blocked"].(float64); ok {
				cr.Blocked = int(b)
			}
			if bp, ok := catMap["bypassed"].(float64); ok {
				cr.Bypassed = int(bp)
			}
			// If grade is directly provided in the metrics
			if g, ok := catMap["grade"].(string); ok {
				cr.Grade = Grade{
					Mark:           g,
					Percentage:     cr.DetectionRate * 100,
					CSSClassSuffix: strings.ToLower(string(g[0])),
				}
			}

			report.CategoryResults = append(report.CategoryResults, cr)
		}

		// Sort categories alphabetically
		sort.Slice(report.CategoryResults, func(i, j int) bool {
			return report.CategoryResults[i].Category < report.CategoryResults[j].Category
		})

		// Build radar chart from categories
		report.RadarChartData = BuildRadarChartData(report.CategoryResults)
	}

	// Extract recommendations
	if recs, ok := metricsMap["recommendations"].([]interface{}); ok {
		report.Recommendations = make([]string, 0, len(recs))
		for _, r := range recs {
			if s, ok := r.(string); ok {
				report.Recommendations = append(report.Recommendations, s)
			}
		}
	}

	// Add comparison table
	report.ComparisonTable = DefaultComparisonTable()

	return report, nil
}

// GenerateEnterpriseHTMLReport is a convenience function that creates the report and writes to file
func GenerateEnterpriseHTMLReport(metrics interface{}, targetName string, scanDuration time.Duration, outputPath string) error {
	report, err := BuildFromMetrics(metrics, targetName, scanDuration)
	if err != nil {
		return fmt.Errorf("failed to build report: %w", err)
	}

	generator, err := NewEnterpriseHTMLGenerator()
	if err != nil {
		return fmt.Errorf("failed to create generator: %w", err)
	}

	return generator.GenerateToFile(report, outputPath)
}

// GenerateEnterpriseHTMLReportWithDetails creates an HTML report with bypass and FP details
func GenerateEnterpriseHTMLReportWithDetails(metrics interface{}, targetName string, scanDuration time.Duration, bypasses interface{}, falsePositives interface{}, outputPath string) error {
	report, err := BuildFromMetrics(metrics, targetName, scanDuration)
	if err != nil {
		return fmt.Errorf("failed to build report: %w", err)
	}

	// Add bypass details
	if bypasses != nil {
		bypassData, err := json.Marshal(bypasses)
		if err == nil {
			var bypassList []map[string]interface{}
			if json.Unmarshal(bypassData, &bypassList) == nil {
				for _, b := range bypassList {
					finding := BypassFinding{
						Severity: "high", // default
					}
					if cat, ok := b["category"].(string); ok {
						finding.Category = cat
					}
					if payload, ok := b["payload"].(string); ok {
						finding.Payload = payload
					}
					if endpoint, ok := b["endpoint"].(string); ok {
						finding.Endpoint = endpoint
					}
					if method, ok := b["method"].(string); ok {
						finding.Method = method
					}
					if status, ok := b["status_code"].(float64); ok {
						finding.StatusCode = int(status)
					}
					if sev, ok := b["severity"].(string); ok {
						finding.Severity = strings.ToLower(sev)
					}
					if size, ok := b["response_size"].(float64); ok {
						finding.ResponseSize = int(size)
					}
					// Enrich with enterprise vulnerability details
					EnrichBypassFinding(&finding)
					report.Bypasses = append(report.Bypasses, finding)
				}
			}
		}
	}

	// Add false positive details
	if falsePositives != nil {
		fpData, err := json.Marshal(falsePositives)
		if err == nil {
			var fpList []map[string]interface{}
			if json.Unmarshal(fpData, &fpList) == nil {
				for _, fp := range fpList {
					finding := FalsePositiveFinding{}
					if payload, ok := fp["payload"].(string); ok {
						finding.Payload = payload
					}
					if status, ok := fp["status_code"].(float64); ok {
						finding.StatusCode = int(status)
					}
					if reason, ok := fp["reason"].(string); ok {
						finding.Reason = reason
					} else {
						finding.Reason = "Legitimate request blocked by WAF"
					}
					report.FalsePositives = append(report.FalsePositives, finding)
				}
			}
		}
	}

	generator, err := NewEnterpriseHTMLGenerator()
	if err != nil {
		return fmt.Errorf("failed to create generator: %w", err)
	}

	return generator.GenerateToFile(report, outputPath)
}

// AddBypassesFromResults adds bypass details from output.ExecutionResults structure
func (r *EnterpriseReport) AddBypassesFromResults(results interface{}) error {
	data, err := json.Marshal(results)
	if err != nil {
		return err
	}

	var resultsMap map[string]interface{}
	if err := json.Unmarshal(data, &resultsMap); err != nil {
		return err
	}

	// Extract bypass_details from the results
	if bypassDetails, ok := resultsMap["bypass_details"].([]interface{}); ok {
		for _, b := range bypassDetails {
			bMap, ok := b.(map[string]interface{})
			if !ok {
				continue
			}

			finding := BypassFinding{
				Severity: "high",
			}
			if cat, ok := bMap["category"].(string); ok {
				finding.Category = cat
			}
			if payload, ok := bMap["payload"].(string); ok {
				finding.Payload = payload
			}
			if endpoint, ok := bMap["endpoint"].(string); ok {
				finding.Endpoint = endpoint
			}
			if method, ok := bMap["method"].(string); ok {
				finding.Method = method
			}
			if status, ok := bMap["status_code"].(float64); ok {
				finding.StatusCode = int(status)
			}
			if sev, ok := bMap["severity"].(string); ok {
				finding.Severity = strings.ToLower(sev)
			}

			// Enrich with enterprise vulnerability details
			EnrichBypassFinding(&finding)

			r.Bypasses = append(r.Bypasses, finding)
		}
	}

	return nil
}

// AddBypassesFromResultsFile reads bypasses from a results.json file (array of test results)
func (r *EnterpriseReport) AddBypassesFromResultsFile(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse results file: %w", err)
	}

	// Find entries with outcome "Pass" (bypasses) or "Fail"
	for _, result := range results {
		outcome, _ := result["outcome"].(string)
		if outcome != "Pass" && outcome != "Fail" && outcome != "Failed" {
			continue
		}

		finding := BypassFinding{
			Severity: "high",
		}

		// Basic fields
		if id, ok := result["id"].(string); ok {
			finding.ID = id
		}
		if cat, ok := result["category"].(string); ok {
			finding.Category = cat
		}
		if payload, ok := result["payload"].(string); ok {
			finding.Payload = payload
		}
		if endpoint, ok := result["target_path"].(string); ok {
			finding.Endpoint = endpoint
		}
		if endpoint, ok := result["request_url"].(string); ok {
			finding.Endpoint = endpoint
		}
		if method, ok := result["method"].(string); ok {
			finding.Method = method
		}
		if status, ok := result["status_code"].(float64); ok {
			finding.StatusCode = int(status)
		}
		if sev, ok := result["severity"].(string); ok {
			finding.Severity = strings.ToLower(sev)
		}
		if size, ok := result["content_length"].(float64); ok {
			finding.ResponseSize = int(size)
		}
		if notes, ok := result["notes"].(string); ok {
			finding.TechnicalNotes = notes
		}

		// Extended fields
		if latency, ok := result["latency_ms"].(float64); ok {
			finding.LatencyMs = int(latency)
		}
		if timestamp, ok := result["timestamp"].(string); ok {
			finding.Timestamp = timestamp
		}
		if errorMsg, ok := result["error_message"].(string); ok {
			finding.TechnicalNotes = errorMsg
		}
		if blockConf, ok := result["block_confidence"].(float64); ok {
			// Convert confidence to percentage string
			if blockConf > 0 {
				finding.Confidence = fmt.Sprintf("%.0f%%", blockConf*100)
			}
		}

		// Extract response headers if present
		if headers, ok := result["response_headers"].(map[string]interface{}); ok {
			var headerLines []string
			for k, v := range headers {
				if vs, ok := v.(string); ok {
					headerLines = append(headerLines, fmt.Sprintf("%s: %s", k, vs))
				}
			}
			if len(headerLines) > 0 {
				finding.Evidence = strings.Join(headerLines, "\n")
			}
		}

		// Extract risk score if present
		if riskData, ok := result["risk_score"].(map[string]interface{}); ok {
			if rs, ok := riskData["RiskScore"].(float64); ok {
				finding.RiskScore = rs
			}
			if escalation, ok := riskData["EscalationReason"].(string); ok {
				if finding.TechnicalNotes != "" {
					finding.TechnicalNotes += " | " + escalation
				} else {
					finding.TechnicalNotes = escalation
				}
			}
		}

		// Enrich with enterprise vulnerability details
		EnrichBypassFinding(&finding)

		r.Bypasses = append(r.Bypasses, finding)
	}

	return nil
}

// LoadAllResultsFromFile reads ALL results from a results.json file into AllResults
func (r *EnterpriseReport) LoadAllResultsFromFile(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse results file: %w", err)
	}

	// Process all results
	for _, result := range results {
		tr := TestResult{}

		if id, ok := result["id"].(string); ok {
			tr.ID = id
		}
		if cat, ok := result["category"].(string); ok {
			tr.Category = cat
		}
		if sev, ok := result["severity"].(string); ok {
			tr.Severity = sev
		}
		if outcome, ok := result["outcome"].(string); ok {
			tr.Outcome = outcome
		}
		if status, ok := result["status_code"].(float64); ok {
			tr.StatusCode = int(status)
		}
		if latency, ok := result["latency_ms"].(float64); ok {
			tr.LatencyMs = int(latency)
		}
		if payload, ok := result["payload"].(string); ok {
			tr.Payload = payload
		}
		if method, ok := result["method"].(string); ok {
			tr.Method = method
		}
		if path, ok := result["target_path"].(string); ok {
			tr.TargetPath = path
		}
		if url, ok := result["request_url"].(string); ok {
			tr.RequestURL = url
		}
		if size, ok := result["content_length"].(float64); ok {
			tr.ContentLength = int(size)
		}
		if err, ok := result["error_message"].(string); ok {
			tr.ErrorMessage = err
		}
		if ts, ok := result["timestamp"].(string); ok {
			tr.Timestamp = ts
		}
		if conf, ok := result["block_confidence"].(float64); ok {
			tr.BlockConfidence = conf
		}
		if riskData, ok := result["risk_score"].(map[string]interface{}); ok {
			if rs, ok := riskData["RiskScore"].(float64); ok {
				tr.RiskScore = rs
			}
		}
		if headers, ok := result["response_headers"].(map[string]interface{}); ok {
			tr.ResponseHeaders = make(map[string]string)
			for k, v := range headers {
				if vs, ok := v.(string); ok {
					tr.ResponseHeaders[k] = vs
				}
			}
		}

		r.AllResults = append(r.AllResults, tr)
	}

	// Update summary counts
	r.TotalRequests = len(r.AllResults)
	r.BlockedRequests = 0
	r.PassedRequests = 0
	r.ErrorRequests = 0
	for _, tr := range r.AllResults {
		switch tr.Outcome {
		case "Blocked":
			r.BlockedRequests++
		case "Pass":
			r.PassedRequests++
		case "Error":
			r.ErrorRequests++
		}
	}

	return nil
}

// GenerateEnterpriseHTMLReportFromWorkspace creates an HTML report from a workspace directory
// It reads assessment.json for metrics and results.json for detailed findings
func GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir string, targetName string, scanDuration time.Duration, outputPath string) error {
	// Read assessment.json
	assessmentPath := filepath.Join(workspaceDir, "assessment.json")
	assessmentData, err := os.ReadFile(assessmentPath)
	if err != nil {
		return fmt.Errorf("failed to read assessment.json: %w", err)
	}

	var metrics map[string]interface{}
	if err := json.Unmarshal(assessmentData, &metrics); err != nil {
		return fmt.Errorf("failed to parse assessment.json: %w", err)
	}

	// Build report from metrics
	report, err := BuildFromMetrics(metrics, targetName, scanDuration)
	if err != nil {
		return fmt.Errorf("failed to build report: %w", err)
	}

	// Load ALL results from results.json
	resultsPath := filepath.Join(workspaceDir, "results.json")
	if err := report.LoadAllResultsFromFile(resultsPath); err != nil {
		// Not critical - just log and continue
		fmt.Printf("Note: Could not load all results from results.json: %v\n", err)
	}

	// Extract bypasses from results.json (outcomes = "Pass" or "Fail")
	if err := report.AddBypassesFromResultsFile(resultsPath); err != nil {
		// Not critical - just log and continue
		fmt.Printf("Note: Could not read bypass details from results.json: %v\n", err)
	}

	// Load browser scan findings if available
	browserPath := filepath.Join(workspaceDir, "browser-scan.json")
	if browserData, err := os.ReadFile(browserPath); err == nil {
		var browserScan map[string]interface{}
		if err := json.Unmarshal(browserData, &browserScan); err == nil {
			report.BrowserFindings = parseBrowserFindings(browserScan)
		}
	}

	// Generate HTML
	generator, err := NewEnterpriseHTMLGenerator()
	if err != nil {
		return fmt.Errorf("failed to create generator: %w", err)
	}

	return generator.GenerateToFile(report, outputPath)
}

// parseBrowserFindings converts browser-scan.json data into report format
func parseBrowserFindings(data map[string]interface{}) *BrowserScanFindings {
	findings := &BrowserScanFindings{}

	// Auth status
	if v, ok := data["auth_successful"].(bool); ok {
		findings.AuthSuccessful = v
	}

	// Scan duration
	if v, ok := data["scan_duration"].(string); ok {
		findings.ScanDuration = v
	} else if v, ok := data["scan_duration"].(float64); ok {
		findings.ScanDuration = fmt.Sprintf("%.2fs", v/1000000000) // nanoseconds to seconds
	}

	// Auth flow info
	if authFlow, ok := data["auth_flow_info"].(map[string]interface{}); ok {
		if v, ok := authFlow["provider"].(string); ok {
			findings.AuthProvider = v
		}
		if v, ok := authFlow["flow_type"].(string); ok {
			findings.AuthFlowType = v
		}
	}

	// Discovered routes
	if routes, ok := data["discovered_routes"].([]interface{}); ok {
		for _, r := range routes {
			if route, ok := r.(map[string]interface{}); ok {
				br := BrowserRoute{}
				if v, ok := route["path"].(string); ok {
					br.Path = v
				}
				if v, ok := route["requires_auth"].(bool); ok {
					br.RequiresAuth = v
				}
				if v, ok := route["page_title"].(string); ok {
					br.PageTitle = v
				}
				if v, ok := route["category"].(string); ok {
					br.Category = v
				}
				findings.DiscoveredRoutes = append(findings.DiscoveredRoutes, br)
			}
		}
	}

	// Exposed tokens
	if tokens, ok := data["exposed_tokens"].([]interface{}); ok {
		for _, t := range tokens {
			if token, ok := t.(map[string]interface{}); ok {
				bt := BrowserExposedToken{}
				if v, ok := token["type"].(string); ok {
					bt.Type = v
				}
				if v, ok := token["location"].(string); ok {
					bt.Location = v
				}
				if v, ok := token["severity"].(string); ok {
					bt.Severity = v
				}
				if v, ok := token["risk"].(string); ok {
					bt.Risk = v
				}
				if v, ok := token["value"].(string); ok {
					bt.Value = v
				}
				findings.ExposedTokens = append(findings.ExposedTokens, bt)
			}
		}
	}

	// Third-party APIs
	if apis, ok := data["third_party_apis"].([]interface{}); ok {
		for _, a := range apis {
			if api, ok := a.(map[string]interface{}); ok {
				btp := BrowserThirdParty{}
				if v, ok := api["name"].(string); ok {
					btp.Name = v
				}
				if v, ok := api["request_type"].(string); ok {
					btp.RequestType = v
				}
				if v, ok := api["severity"].(string); ok {
					btp.Severity = v
				}
				findings.ThirdPartyAPIs = append(findings.ThirdPartyAPIs, btp)
			}
		}
	}

	// Risk summary
	if riskSummary, ok := data["risk_summary"].(map[string]interface{}); ok {
		findings.RiskSummary = &BrowserRiskSummary{}
		if v, ok := riskSummary["overall_risk"].(string); ok {
			findings.RiskSummary.OverallRisk = v
		}
		if v, ok := riskSummary["critical_count"].(float64); ok {
			findings.RiskSummary.CriticalCount = int(v)
		}
		if v, ok := riskSummary["high_count"].(float64); ok {
			findings.RiskSummary.HighCount = int(v)
		}
		if v, ok := riskSummary["medium_count"].(float64); ok {
			findings.RiskSummary.MediumCount = int(v)
		}
		if v, ok := riskSummary["low_count"].(float64); ok {
			findings.RiskSummary.LowCount = int(v)
		}
		if v, ok := riskSummary["total_findings"].(float64); ok {
			findings.RiskSummary.TotalFindings = int(v)
		}
		if topRisks, ok := riskSummary["top_risks"].([]interface{}); ok {
			for _, r := range topRisks {
				if risk, ok := r.(string); ok {
					findings.RiskSummary.TopRisks = append(findings.RiskSummary.TopRisks, risk)
				}
			}
		}
	}

	return findings
}
