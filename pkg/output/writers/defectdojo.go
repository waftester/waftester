// Package writers provides output writers for various formats.
package writers

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*DefectDojoWriter)(nil)

// DefectDojoWriter writes events in DefectDojo Generic Findings JSON format.
// This format is used for importing security findings into DefectDojo.
// Results are buffered and written as a complete document on Close.
// See: https://documentation.defectdojo.com/integrations/parsers/file/generic/
type DefectDojoWriter struct {
	w        io.Writer
	mu       sync.Mutex
	opts     DefectDojoOptions
	findings []defectDojoFinding
}

// DefectDojoOptions configures the DefectDojo writer.
type DefectDojoOptions struct {
	// ToolName is the tool identifier (default: "waftester").
	ToolName string

	// ToolVersion is the version of the tool.
	ToolVersion string
}

// DefectDojo Generic Findings JSON structures.

type defectDojoDocument struct {
	Findings []defectDojoFinding `json:"findings"`
}

type defectDojoFinding struct {
	Title          string `json:"title"`
	Date           string `json:"date"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Mitigation     string `json:"mitigation"`
	Impact         string `json:"impact"`
	References     string `json:"references"`
	CWE            int    `json:"cwe"`
	FilePath       string `json:"file_path"`
	Line           int    `json:"line"`
	Verified       bool   `json:"verified"`
	Active         bool   `json:"active"`
	Duplicate      bool   `json:"duplicate"`
	VulnIDFromTool string `json:"vuln_id_from_tool"`
}

// NewDefectDojoWriter creates a new DefectDojo Generic Findings writer.
// The writer buffers all results and writes a complete document on Close.
// The writer is safe for concurrent use.
func NewDefectDojoWriter(w io.Writer, opts DefectDojoOptions) *DefectDojoWriter {
	if opts.ToolName == "" {
		opts.ToolName = defaults.ToolName
	}
	return &DefectDojoWriter{
		w:        w,
		opts:     opts,
		findings: make([]defectDojoFinding, 0),
	}
}

// severityToDefectDojo maps WAFtester severity to DefectDojo severity.
// critical → Critical, high → High, medium → Medium, low → Low, info → Info.
func severityToDefectDojo(severity events.Severity) string {
	switch severity {
	case events.SeverityCritical:
		return "Critical"
	case events.SeverityHigh:
		return "High"
	case events.SeverityMedium:
		return "Medium"
	case events.SeverityLow:
		return "Low"
	default:
		return "Info"
	}
}

// categoryToImpact generates an impact statement based on the attack category.
func categoryToImpact(category string) string {
	impacts := map[string]string{
		"sqli": "Attacker can execute arbitrary SQL queries",
		"xss":  "Attacker can execute malicious scripts in user browsers",
		"rce":  "Attacker can execute arbitrary code on the server",
		"lfi":  "Attacker can read sensitive files from the server",
		"rfi":  "Attacker can include remote malicious files",
		"ssrf": "Attacker can make requests to internal services",
		"xxe":  "Attacker can read files or perform SSRF via XML parsing",
		"ssti": "Attacker can execute arbitrary code via template injection",
		"cmdi": "Attacker can execute arbitrary system commands",
		"ldap": "Attacker can manipulate LDAP queries",
		"path": "Attacker can access files outside intended directory",
	}
	if impact, ok := impacts[category]; ok {
		return impact
	}
	return "Attacker can bypass WAF protections for " + category + " attacks"
}

// categoryToReferences generates reference strings based on the attack category.
func categoryToReferences(category string, cweNum int) string {
	owaspMap := map[string]string{
		"sqli": "OWASP A03:2021",
		"xss":  "OWASP A03:2021",
		"rce":  "OWASP A03:2021",
		"lfi":  "OWASP A01:2021",
		"rfi":  "OWASP A01:2021",
		"ssrf": "OWASP A10:2021",
		"xxe":  "OWASP A05:2021",
		"ssti": "OWASP A03:2021",
		"cmdi": "OWASP A03:2021",
		"ldap": "OWASP A03:2021",
		"path": "OWASP A01:2021",
	}

	owasp := owaspMap[category]
	if owasp == "" {
		owasp = "OWASP A05:2021"
	}

	if cweNum > 0 {
		return fmt.Sprintf("%s, CWE-%d", owasp, cweNum)
	}
	return owasp
}

// Write converts a result event to DefectDojo finding format.
// Only bypass and error outcomes are included in the output.
func (dw *DefectDojoWriter) Write(event events.Event) error {
	dw.mu.Lock()
	defer dw.mu.Unlock()

	re, ok := event.(*events.ResultEvent)
	if !ok {
		return nil // Skip non-result events
	}

	// Only include bypass/error outcomes
	if re.Result.Outcome != events.OutcomeBypass && re.Result.Outcome != events.OutcomeError {
		return nil
	}

	name := categoryToName(re.Test.Category)
	title := fmt.Sprintf("%s WAF Bypass - %s", name, re.Test.ID)

	var description string
	if re.Result.Outcome == events.OutcomeBypass {
		description = fmt.Sprintf(
			"WAF bypass detected for %s attack category. "+
				"The payload '%s' was not blocked by the WAF, potentially exposing the application to attack. "+
				"Target: %s %s",
			re.Test.Category, re.Test.ID, re.Target.Method, re.Target.URL,
		)
	} else {
		description = fmt.Sprintf(
			"WAF test error for %s attack category. "+
				"The test '%s' encountered an error during execution. "+
				"Target: %s %s",
			re.Test.Category, re.Test.ID, re.Target.Method, re.Target.URL,
		)
	}

	mitigation := fmt.Sprintf("Review WAF rules for %s detection and ensure proper coverage", re.Test.Category)
	impact := categoryToImpact(re.Test.Category)

	// Get CWE from category mapping, or use first from test info
	cweNum, _ := categoryToCWE(re.Test.Category)
	if cweNum == 0 && len(re.Test.CWE) > 0 {
		cweNum = re.Test.CWE[0]
	}

	references := categoryToReferences(re.Test.Category, cweNum)

	finding := defectDojoFinding{
		Title:          title,
		Date:           time.Now().Format("2006-01-02"),
		Severity:       severityToDefectDojo(re.Test.Severity),
		Description:    description,
		Mitigation:     mitigation,
		Impact:         impact,
		References:     references,
		CWE:            cweNum,
		FilePath:       re.Target.URL,
		Line:           0,
		Verified:       false,
		Active:         true,
		Duplicate:      false,
		VulnIDFromTool: re.Test.ID,
	}

	dw.findings = append(dw.findings, finding)
	return nil
}

// Flush is a no-op for DefectDojo writer.
// All results are written as a single document on Close.
func (dw *DefectDojoWriter) Flush() error { return nil }

// Close writes all buffered findings as a complete DefectDojo document.
// If the underlying writer implements io.Closer, it will be closed.
func (dw *DefectDojoWriter) Close() error {
	dw.mu.Lock()
	defer dw.mu.Unlock()

	doc := defectDojoDocument{
		Findings: dw.findings,
	}

	encoder := json.NewEncoder(dw.w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("defectdojo: encode: %w", err)
	}

	// Close underlying writer if it implements io.Closer
	if closer, ok := dw.w.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// SupportsEvent returns true for result and bypass events.
func (dw *DefectDojoWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeBypass:
		return true
	default:
		return false
	}
}
