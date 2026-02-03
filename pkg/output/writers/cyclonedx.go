// Package writers provides output writers for various formats.
package writers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*CycloneDXWriter)(nil)

// CycloneDXWriter writes events in CycloneDX VEX (Vulnerability Exploitability eXchange) format.
// This format is used for SBOM integration and vulnerability exchange.
// Results are buffered and written as a complete VEX document on Close.
// See: https://cyclonedx.org/capabilities/vex/
type CycloneDXWriter struct {
	w               io.Writer
	mu              sync.Mutex
	opts            CycloneDXOptions
	vulnerabilities []cycloneDXVulnerability
	startTime       time.Time
}

// CycloneDXOptions configures the CycloneDX VEX writer.
type CycloneDXOptions struct {
	// ToolName is the name of the tool (default: "waftester").
	ToolName string

	// ToolVersion is the version of the tool.
	ToolVersion string

	// BOMVersion is the BOM document version (default: 1).
	BOMVersion int

	// ToolURL is the URL for the tool (default: "https://github.com/waftester/waftester").
	ToolURL string

	// IncludeEPSS includes EPSS score and percentile when available (default: false).
	IncludeEPSS bool

	// IncludeCPE includes CPE identifiers for asset correlation (default: false).
	IncludeCPE bool
}

// CycloneDX VEX 1.5 structures.

type cycloneDXDocument struct {
	BOMFormat       string                   `json:"bomFormat"`
	SpecVersion     string                   `json:"specVersion"`
	Version         int                      `json:"version"`
	Metadata        cycloneDXMetadata        `json:"metadata"`
	Vulnerabilities []cycloneDXVulnerability `json:"vulnerabilities,omitempty"`
}

type cycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []cycloneDXTool `json:"tools"`
}

type cycloneDXTool struct {
	Vendor             string            `json:"vendor"`
	Name               string            `json:"name"`
	Version            string            `json:"version,omitempty"`
	Hashes             []cycloneDXHash   `json:"hashes,omitempty"`
	ExternalReferences []cycloneDXExtRef `json:"externalReferences,omitempty"`
}

// cycloneDXHash represents a cryptographic hash.
type cycloneDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// cycloneDXExtRef represents an external reference URL.
type cycloneDXExtRef struct {
	Type string `json:"type"` // website, documentation, vcs, issue-tracker, advisories
	URL  string `json:"url"`
}

type cycloneDXVulnerability struct {
	ID             string              `json:"id"`
	Source         cycloneDXSource     `json:"source"`
	References     []cycloneDXRef      `json:"references,omitempty"`
	Ratings        []cycloneDXRating   `json:"ratings,omitempty"`
	CWEs           []int               `json:"cwes,omitempty"`
	Description    string              `json:"description"`
	Detail         string              `json:"detail,omitempty"`
	Recommendation string              `json:"recommendation,omitempty"`
	Advisories     []cycloneDXAdvisory `json:"advisories,omitempty"`
	Published      string              `json:"published,omitempty"` // RFC3339 timestamp
	Updated        string              `json:"updated,omitempty"`   // RFC3339 timestamp
	Analysis       *cycloneDXAnalysis  `json:"analysis,omitempty"`
	Affects        []cycloneDXAffects  `json:"affects,omitempty"`
	Properties     []cycloneDXProperty `json:"properties,omitempty"`
}

// cycloneDXRef represents a vulnerability reference (CVE, etc.).
type cycloneDXRef struct {
	ID     string          `json:"id"`
	Source cycloneDXSource `json:"source"`
}

type cycloneDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// cycloneDXRating represents a vulnerability severity rating with CVSS support.
type cycloneDXRating struct {
	Source   *cycloneDXSource `json:"source,omitempty"`
	Score    *float64         `json:"score,omitempty"`
	Severity string           `json:"severity"`
	Method   string           `json:"method"` // CVSSv2, CVSSv3, CVSSv31, CVSSv40, other
	Vector   string           `json:"vector,omitempty"`
}

// cycloneDXAdvisory represents a security advisory reference.
type cycloneDXAdvisory struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url"`
}

// cycloneDXAnalysis represents VEX analysis information.
type cycloneDXAnalysis struct {
	State         string   `json:"state"`                   // exploitable, in_triage, not_affected, resolved, false_positive
	Justification string   `json:"justification,omitempty"` // code_not_present, code_not_reachable, requires_configuration, etc.
	Response      []string `json:"response,omitempty"`      // will_fix, update, workaround_available, rollback, will_not_fix
	Detail        string   `json:"detail,omitempty"`
}

type cycloneDXAffects struct {
	Ref      string                  `json:"ref"`
	Versions []cycloneDXVersionRange `json:"versions,omitempty"`
}

// cycloneDXVersionRange represents an affected version range.
type cycloneDXVersionRange struct {
	Version string `json:"version,omitempty"`
	Range   string `json:"range,omitempty"`
	Status  string `json:"status"` // affected, unaffected
}

// cycloneDXProperty represents a name-value property with namespace.
type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// NewCycloneDXWriter creates a new CycloneDX VEX 1.5 writer.
// The writer buffers all results and writes a complete VEX document on Close.
// The writer is safe for concurrent use.
func NewCycloneDXWriter(w io.Writer, opts CycloneDXOptions) *CycloneDXWriter {
	if opts.ToolName == "" {
		opts.ToolName = defaults.ToolName
	}
	if opts.ToolURL == "" {
		opts.ToolURL = "https://github.com/waftester/waftester"
	}
	if opts.BOMVersion <= 0 {
		opts.BOMVersion = 1
	}
	return &CycloneDXWriter{
		w:               w,
		opts:            opts,
		vulnerabilities: make([]cycloneDXVulnerability, 0),
		startTime:       time.Now(),
	}
}

// severityToCycloneDX maps WAFtester severity to CycloneDX severity.
// CycloneDX uses: critical, high, medium, low, info, none, unknown.
func severityToCycloneDX(severity events.Severity) string {
	switch severity {
	case events.SeverityCritical:
		return "critical"
	case events.SeverityHigh:
		return "high"
	case events.SeverityMedium:
		return "medium"
	case events.SeverityLow:
		return "low"
	case events.SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// categoryToCWEs returns CWE IDs for a given attack category.
// Returns a slice to support categories that map to multiple CWEs.
func categoryToCWEs(category string) []int {
	cweMap := map[string][]int{
		"sqli":          {89},     // SQL Injection
		"xss":           {79},     // Cross-site Scripting
		"traversal":     {22},     // Path Traversal
		"path":          {22},     // Path Traversal (alias)
		"lfi":           {22, 98}, // Local File Inclusion
		"rfi":           {98},     // Remote File Inclusion
		"rce":           {78, 94}, // Remote Code Execution
		"cmdi":          {78},     // Command Injection
		"ssrf":          {918},    // Server-Side Request Forgery
		"xxe":           {611},    // XML External Entity
		"ssti":          {94},     // Server-Side Template Injection
		"ldap":          {90},     // LDAP Injection
		"nosqli":        {943},    // NoSQL Injection
		"crlf":          {93},     // CRLF Injection
		"idor":          {639},    // Insecure Direct Object Reference
		"jwt":           {347},    // JWT Validation
		"cors":          {346},    // CORS Misconfiguration
		"csrf":          {352},    // Cross-Site Request Forgery
		"clickjack":     {1021},   // Clickjacking
		"open_redirect": {601},    // Open Redirect
		"redirect":      {601},    // Open Redirect (alias)
		"deserialize":   {502},    // Deserialization
		"upload":        {434},    // Unrestricted Upload
		"smuggling":     {444},    // HTTP Request Smuggling
	}
	if cwes, ok := cweMap[category]; ok {
		return cwes
	}
	return nil
}

// generateVulnID creates a unique vulnerability ID for CycloneDX.
func generateVulnID(testID, category string, seq int) string {
	return fmt.Sprintf("WAFTESTER-%s-%s-%d", category, testID, seq)
}

// cycloneDXSeverityToScore maps severity to approximate CVSS 3.1 score.
func cycloneDXSeverityToScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5.5
	case "low":
		return 2.5
	case "info":
		return 0.0
	default:
		return 0.0
	}
}

// buildRatings generates CVSS ratings array for a vulnerability.
// Returns ratings with proper source attribution and method.
func (cw *CycloneDXWriter) buildRatings(severity events.Severity) []cycloneDXRating {
	severityStr := severityToCycloneDX(severity)
	score := cycloneDXSeverityToScore(severityStr)

	return []cycloneDXRating{
		{
			Source: &cycloneDXSource{
				Name: cw.opts.ToolName,
				URL:  cw.opts.ToolURL,
			},
			Score:    &score,
			Severity: severityStr,
			Method:   "other", // WAFtester uses its own severity assessment
		},
	}
}

// buildAnalysis creates VEX analysis based on test outcome.
func buildAnalysis(outcome events.Outcome) *cycloneDXAnalysis {
	switch outcome {
	case events.OutcomeBypass:
		return &cycloneDXAnalysis{
			State:         "exploitable",
			Justification: "requires_configuration",
			Response:      []string{"will_fix", "update"},
			Detail:        "WAF bypass confirmed - payload successfully reached the application without being blocked",
		}
	case events.OutcomeError:
		return &cycloneDXAnalysis{
			State:         "in_triage",
			Justification: "requires_configuration",
			Response:      []string{"workaround_available"},
			Detail:        "WAF test encountered an error - requires investigation",
		}
	default:
		return nil
	}
}

// buildProperties creates namespaced properties for the vulnerability.
func (cw *CycloneDXWriter) buildProperties(re *events.ResultEvent) []cycloneDXProperty {
	props := []cycloneDXProperty{
		{Name: "waftester:test:id", Value: re.Test.ID},
		{Name: "waftester:test:category", Value: re.Test.Category},
		{Name: "waftester:result:outcome", Value: string(re.Result.Outcome)},
		{Name: "waftester:result:status_code", Value: fmt.Sprintf("%d", re.Result.StatusCode)},
		{Name: "waftester:result:latency_ms", Value: fmt.Sprintf("%.2f", re.Result.LatencyMs)},
	}

	if re.Evidence != nil && re.Evidence.Payload != "" {
		props = append(props, cycloneDXProperty{
			Name:  "waftester:evidence:payload",
			Value: re.Evidence.Payload,
		})
	}

	return props
}

// buildAdvisories creates advisory references for the vulnerability.
func buildAdvisories(category string) []cycloneDXAdvisory {
	advisories := make([]cycloneDXAdvisory, 0)

	// Add OWASP reference based on category
	owaspURLs := map[string]string{
		"sqli":          "https://owasp.org/www-community/attacks/SQL_Injection",
		"xss":           "https://owasp.org/www-community/attacks/xss/",
		"ssrf":          "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
		"xxe":           "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
		"ssti":          "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
		"cmdi":          "https://owasp.org/www-community/attacks/Command_Injection",
		"rce":           "https://owasp.org/www-community/attacks/Command_Injection",
		"csrf":          "https://owasp.org/www-community/attacks/csrf",
		"idor":          "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
		"traversal":     "https://owasp.org/www-community/attacks/Path_Traversal",
		"lfi":           "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
		"open_redirect": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
	}

	if url, ok := owaspURLs[category]; ok {
		advisories = append(advisories, cycloneDXAdvisory{
			Title: "OWASP Reference",
			URL:   url,
		})
	}

	return advisories
}

// Write converts a result event to CycloneDX VEX vulnerability format.
// Only bypass and error outcomes are included in the output.
func (cw *CycloneDXWriter) Write(event events.Event) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	re, ok := event.(*events.ResultEvent)
	if !ok {
		return nil // Skip non-result events
	}

	// Only include bypass/error outcomes
	if re.Result.Outcome != events.OutcomeBypass && re.Result.Outcome != events.OutcomeError {
		return nil
	}

	name := categoryToName(re.Test.Category)
	vulnID := generateVulnID(re.Test.ID, re.Test.Category, len(cw.vulnerabilities)+1)

	// Build description
	var description string
	if re.Result.Outcome == events.OutcomeBypass {
		description = fmt.Sprintf("WAF bypass detected for %s (%s). "+
			"The payload was not blocked, potentially exposing the application to attack.",
			name, re.Test.Category)
	} else {
		description = fmt.Sprintf("WAF test error for %s (%s). "+
			"The test encountered an error during execution.",
			name, re.Test.Category)
	}

	// Build detail with more specifics
	detail := fmt.Sprintf("Test ID: %s\nTarget: %s %s\nHTTP Status: %d\nLatency: %.2fms",
		re.Test.ID, re.Target.Method, re.Target.URL, re.Result.StatusCode, re.Result.LatencyMs)
	if re.Evidence != nil && re.Evidence.Payload != "" {
		detail += fmt.Sprintf("\nPayload: %s", re.Evidence.Payload)
	}

	recommendation := fmt.Sprintf("Review and strengthen WAF rules for %s detection. "+
		"Ensure proper coverage for payload variations and evasion techniques.", name)

	// Get CWEs - use test-provided CWEs if available, otherwise map from category
	cwes := re.Test.CWE
	if len(cwes) == 0 {
		cwes = categoryToCWEs(re.Test.Category)
	}

	// Generate timestamps
	now := time.Now().UTC().Format(time.RFC3339)

	// Build vulnerability with enterprise-grade fields
	vuln := cycloneDXVulnerability{
		ID: vulnID,
		Source: cycloneDXSource{
			Name: cw.opts.ToolName,
			URL:  cw.opts.ToolURL,
		},
		Ratings:        cw.buildRatings(re.Test.Severity),
		CWEs:           cwes,
		Description:    description,
		Detail:         detail,
		Recommendation: recommendation,
		Advisories:     buildAdvisories(re.Test.Category),
		Published:      now,
		Updated:        now,
		Analysis:       buildAnalysis(re.Result.Outcome),
		Affects: []cycloneDXAffects{
			{Ref: re.Target.URL},
		},
		Properties: cw.buildProperties(re),
	}

	cw.vulnerabilities = append(cw.vulnerabilities, vuln)
	return nil
}

// Flush is a no-op for CycloneDX writer.
// All results are written as a single document on Close.
func (cw *CycloneDXWriter) Flush() error { return nil }

// Close writes all buffered vulnerabilities as a complete CycloneDX VEX 1.5 document.
// If the underlying writer implements io.Closer, it will be closed.
func (cw *CycloneDXWriter) Close() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	// Build tool with external references
	tool := cycloneDXTool{
		Vendor:  defaults.ToolNameDisplay,
		Name:    cw.opts.ToolName,
		Version: cw.opts.ToolVersion,
		ExternalReferences: []cycloneDXExtRef{
			{Type: "website", URL: cw.opts.ToolURL},
			{Type: "vcs", URL: cw.opts.ToolURL},
			{Type: "documentation", URL: "https://github.com/waftester/waftester#readme"},
			{Type: "issue-tracker", URL: "https://github.com/waftester/waftester/issues"},
		},
	}

	doc := cycloneDXDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     cw.opts.BOMVersion,
		Metadata: cycloneDXMetadata{
			Timestamp: cw.startTime.UTC().Format(time.RFC3339),
			Tools:     []cycloneDXTool{tool},
		},
		Vulnerabilities: cw.vulnerabilities,
	}

	encoder := json.NewEncoder(cw.w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return err
	}

	// Close underlying writer if it implements io.Closer
	if closer, ok := cw.w.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// SupportsEvent returns true for result and bypass events.
// These are the event types relevant for VEX vulnerability reporting.
func (cw *CycloneDXWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeBypass:
		return true
	default:
		return false
	}
}
