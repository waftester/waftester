// Package report extended with compliance and enhanced PDF capabilities
package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// ComplianceFramework represents a compliance framework
type ComplianceFramework string

const (
	FrameworkPCIDSS   ComplianceFramework = "PCI DSS"
	FrameworkOWASP    ComplianceFramework = "OWASP Top 10"
	FrameworkSOC2     ComplianceFramework = "SOC 2"
	FrameworkISO27001 ComplianceFramework = "ISO 27001"
	FrameworkHIPAA    ComplianceFramework = "HIPAA"
	FrameworkGDPR     ComplianceFramework = "GDPR"
	FrameworkNIST     ComplianceFramework = "NIST CSF"
)

// ComplianceStatus represents the status of a control check
type ComplianceStatus string

const (
	StatusPass          ComplianceStatus = "PASS"
	StatusFail          ComplianceStatus = "FAIL"
	StatusPartial       ComplianceStatus = "PARTIAL"
	StatusNotApplicable ComplianceStatus = "N/A"
)

// ComplianceControl represents a single compliance control check
type ComplianceControl struct {
	Framework   ComplianceFramework `json:"framework"`
	ControlID   string              `json:"control_id"`
	ControlName string              `json:"control_name"`
	Description string              `json:"description"`
	Status      ComplianceStatus    `json:"status"`
	Evidence    string              `json:"evidence"`
	Remediation string              `json:"remediation,omitempty"`
	LastTested  time.Time           `json:"last_tested"`
	References  []string            `json:"references,omitempty"`
}

// ComplianceReport represents a full compliance assessment
type ComplianceReport struct {
	Framework       ComplianceFramework `json:"framework"`
	OrganizationID  string              `json:"organization_id"`
	AssessmentDate  time.Time           `json:"assessment_date"`
	Assessor        string              `json:"assessor"`
	Scope           []string            `json:"scope"`
	Controls        []ComplianceControl `json:"controls"`
	OverallScore    float64             `json:"overall_score"`
	PassRate        float64             `json:"pass_rate"`
	Recommendations []string            `json:"recommendations"`
}

// ComplianceMapper maps WAF test results to compliance controls
type ComplianceMapper struct {
	framework ComplianceFramework
	mappings  map[string][]string // attack category -> control IDs
}

// NewComplianceMapper creates a mapper for a specific framework
func NewComplianceMapper(framework ComplianceFramework) *ComplianceMapper {
	mapper := &ComplianceMapper{
		framework: framework,
		mappings:  make(map[string][]string),
	}
	mapper.loadMappings()
	return mapper
}

func (m *ComplianceMapper) loadMappings() {
	switch m.framework {
	case FrameworkPCIDSS:
		m.mappings = map[string][]string{
			"sql_injection":  {"6.5.1", "6.6"},
			"xss":            {"6.5.7", "6.6"},
			"csrf":           {"6.5.5"},
			"path_traversal": {"6.5.8"},
			"rce":            {"6.5.1", "6.6"},
			"file_upload":    {"6.5.8"},
			"rate_limiting":  {"10.2", "10.3"},
		}
	case FrameworkOWASP:
		m.mappings = map[string][]string{
			"sql_injection":            {"A03:2021"},
			"xss":                      {"A07:2021", "A03:2021"},
			"xxe":                      {"A05:2017"},
			"broken_auth":              {"A07:2021"},
			"sensitive_data":           {"A02:2021"},
			"access_control":           {"A01:2021"},
			"security_misconfig":       {"A05:2021"},
			"insecure_deserialization": {"A08:2021"},
			"vulnerable_components":    {"A06:2021"},
			"logging_monitoring":       {"A09:2021"},
		}
	case FrameworkSOC2:
		m.mappings = map[string][]string{
			"sql_injection":  {"CC6.1", "CC7.1"},
			"xss":            {"CC6.1"},
			"access_control": {"CC6.1", "CC6.2", "CC6.3"},
			"rate_limiting":  {"CC7.2"},
			"logging":        {"CC7.3"},
		}
	case FrameworkISO27001:
		m.mappings = map[string][]string{
			"sql_injection":  {"A.14.2.5"},
			"xss":            {"A.14.2.5"},
			"access_control": {"A.9.4.1", "A.9.4.4"},
			"encryption":     {"A.10.1.1"},
			"logging":        {"A.12.4.1"},
			"firewall":       {"A.13.1.1", "A.13.1.3"},
		}
	case FrameworkHIPAA:
		m.mappings = map[string][]string{
			"access_control": {"164.312(a)(1)", "164.312(d)"},
			"encryption":     {"164.312(a)(2)(iv)", "164.312(e)(1)"},
			"audit_controls": {"164.312(b)"},
			"integrity":      {"164.312(c)(1)"},
			"transmission":   {"164.312(e)(1)"},
		}
	}
}

// MapResults maps WAF test results to compliance controls
func (m *ComplianceMapper) MapResults(stats *Statistics) []ComplianceControl {
	controls := make([]ComplianceControl, 0)
	seenControls := make(map[string]bool)

	for category, count := range stats.ByCategory {
		if controlIDs, ok := m.mappings[category]; ok {
			for _, controlID := range controlIDs {
				if seenControls[controlID] {
					continue
				}
				seenControls[controlID] = true

				control := ComplianceControl{
					Framework:   m.framework,
					ControlID:   controlID,
					ControlName: m.getControlName(controlID),
					Description: m.getControlDescription(controlID),
					Status:      m.determineStatus(category, count, stats),
					Evidence: fmt.Sprintf("WAF blocked %d/%d %s attacks (%.1f%% block rate)",
						stats.BlockedRequests, stats.TotalRequests, category, stats.BlockRate),
					LastTested: time.Now(),
				}
				controls = append(controls, control)
			}
		}
	}

	return controls
}

func (m *ComplianceMapper) determineStatus(category string, count int, stats *Statistics) ComplianceStatus {
	if stats.BlockRate >= 95 {
		return StatusPass
	} else if stats.BlockRate >= 80 {
		return StatusPartial
	}
	return StatusFail
}

func (m *ComplianceMapper) getControlName(controlID string) string {
	names := map[string]string{
		// PCI DSS
		"6.5.1": "Injection Flaws",
		"6.5.7": "Cross-Site Scripting",
		"6.5.5": "CSRF Protection",
		"6.5.8": "Access Control",
		"6.6":   "Web Application Firewall",
		"10.2":  "Audit Logging",
		"10.3":  "Audit Trail",
		// OWASP
		"A01:2021": "Broken Access Control",
		"A02:2021": "Cryptographic Failures",
		"A03:2021": "Injection",
		"A05:2021": "Security Misconfiguration",
		"A06:2021": "Vulnerable Components",
		"A07:2021": "Auth Failures",
		"A08:2021": "Software Integrity",
		"A09:2021": "Security Monitoring",
		// SOC 2
		"CC6.1": "Logical Access Security",
		"CC6.2": "Access Provisioning",
		"CC6.3": "Access Removal",
		"CC7.1": "System Operations",
		"CC7.2": "Capacity Management",
		"CC7.3": "Monitoring",
		// ISO 27001
		"A.9.4.1":  "Information Access Restriction",
		"A.9.4.4":  "Privileged Utility Programs",
		"A.10.1.1": "Cryptographic Controls",
		"A.12.4.1": "Event Logging",
		"A.13.1.1": "Network Controls",
		"A.13.1.3": "Network Segregation",
		"A.14.2.5": "Secure Development",
	}
	if name, ok := names[controlID]; ok {
		return name
	}
	return controlID
}

func (m *ComplianceMapper) getControlDescription(controlID string) string {
	descriptions := map[string]string{
		"6.6":      "Protect public-facing web applications via WAF or code review",
		"A03:2021": "User-supplied data is not validated, filtered, or sanitized",
		"CC6.1":    "Logical access security controls are in place",
	}
	if desc, ok := descriptions[controlID]; ok {
		return desc
	}
	return "Security control validation"
}

// GenerateComplianceReport creates a full compliance report
func GenerateComplianceReport(framework ComplianceFramework, stats *Statistics, org string, assessor string) *ComplianceReport {
	mapper := NewComplianceMapper(framework)
	controls := mapper.MapResults(stats)

	// Calculate scores
	passCount := 0
	for _, c := range controls {
		if c.Status == StatusPass {
			passCount++
		}
	}

	passRate := 0.0
	if len(controls) > 0 {
		passRate = float64(passCount) / float64(len(controls)) * 100
	}

	report := &ComplianceReport{
		Framework:      framework,
		OrganizationID: org,
		AssessmentDate: time.Now(),
		Assessor:       assessor,
		Controls:       controls,
		OverallScore:   passRate,
		PassRate:       passRate,
	}

	// Generate recommendations
	report.Recommendations = generateComplianceRecommendations(controls)

	return report
}

func generateComplianceRecommendations(controls []ComplianceControl) []string {
	recs := make([]string, 0)

	failCount := 0
	partialCount := 0

	for _, c := range controls {
		switch c.Status {
		case StatusFail:
			failCount++
			recs = append(recs, fmt.Sprintf("CRITICAL: Control %s (%s) failed - %s",
				c.ControlID, c.ControlName, c.Remediation))
		case StatusPartial:
			partialCount++
		}
	}

	if failCount == 0 && partialCount == 0 {
		recs = append(recs, "✓ All assessed controls are passing. Continue monitoring.")
	}

	return recs
}

// PDFEnhancer enhances PDF reports with branding and formatting
type PDFEnhancer struct {
	Logo            string
	Watermark       string
	Confidential    bool
	HeaderText      string
	FooterText      string
	PageNumbers     bool
	TableOfContents bool
}

// NewPDFEnhancer creates a new PDF enhancer
func NewPDFEnhancer() *PDFEnhancer {
	return &PDFEnhancer{
		PageNumbers:     true,
		TableOfContents: true,
	}
}

// WithLogo sets the logo path/URL
func (p *PDFEnhancer) WithLogo(logo string) *PDFEnhancer {
	p.Logo = logo
	return p
}

// WithWatermark sets the watermark text
func (p *PDFEnhancer) WithWatermark(text string) *PDFEnhancer {
	p.Watermark = text
	return p
}

// WithConfidential marks the report as confidential
func (p *PDFEnhancer) WithConfidential(confidential bool) *PDFEnhancer {
	p.Confidential = confidential
	return p
}

// EnhanceHTML adds PDF-specific HTML metadata for conversion
func (p *PDFEnhancer) EnhanceHTML(html []byte) []byte {
	var sb bytes.Buffer

	// Add PDF-specific CSS
	sb.WriteString(`<style>
@page {
  size: A4;
  margin: 2cm;
}
@page :first {
  margin-top: 3cm;
}
`)

	if p.Watermark != "" {
		sb.WriteString(fmt.Sprintf(`
@page {
  background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500"><text x="50%%" y="50%%" font-size="40" fill="rgba(0,0,0,0.05)" text-anchor="middle" transform="rotate(-45 250 250)">%s</text></svg>');
}
`, p.Watermark))
	}

	if p.Confidential {
		sb.WriteString(`
.confidential-banner {
  background: #ff0000;
  color: white;
  text-align: center;
  padding: 10px;
  font-weight: bold;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
}
`)
	}

	sb.WriteString(`
.page-break {
  page-break-before: always;
}
.no-break {
  page-break-inside: avoid;
}
</style>
`)

	// Insert before </head>
	htmlStr := string(html)
	if idx := strings.Index(htmlStr, "</head>"); idx > 0 {
		return []byte(htmlStr[:idx] + sb.String() + htmlStr[idx:])
	}

	return append(sb.Bytes(), html...)
}

// FormatComplianceTable formats compliance controls as an HTML table
func FormatComplianceTable(controls []ComplianceControl) string {
	var sb strings.Builder

	sb.WriteString(`<table class="compliance-table">
<thead>
<tr>
<th>Framework</th>
<th>Control ID</th>
<th>Control Name</th>
<th>Status</th>
<th>Evidence</th>
</tr>
</thead>
<tbody>
`)

	for _, c := range controls {
		statusClass := "status-" + strings.ToLower(string(c.Status))
		sb.WriteString(fmt.Sprintf(`<tr>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td class="%s">%s</td>
<td>%s</td>
</tr>
`, c.Framework, c.ControlID, c.ControlName, statusClass, c.Status, c.Evidence))
	}

	sb.WriteString("</tbody></table>")
	return sb.String()
}

// GetSupportedFrameworks returns all supported compliance frameworks
func GetSupportedFrameworks() []ComplianceFramework {
	return []ComplianceFramework{
		FrameworkPCIDSS,
		FrameworkOWASP,
		FrameworkSOC2,
		FrameworkISO27001,
		FrameworkHIPAA,
		FrameworkGDPR,
		FrameworkNIST,
	}
}
