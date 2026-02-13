// Package writers provides output writers for various formats.
package writers

import (
	"crypto/sha256"
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
var _ dispatcher.Writer = (*GitLabSASTWriter)(nil)

// GitLabSASTWriter writes events in GitLab SAST Report format (v15.0.0+).
// This format is used for importing security findings into GitLab's Security Dashboard.
// Results are buffered and written as a complete document on Close.
// See: https://docs.gitlab.com/ee/development/integrations/secure.html
type GitLabSASTWriter struct {
	w               io.Writer
	mu              sync.Mutex
	opts            GitLabSASTOptions
	vulnerabilities []gitlabVulnerability
	startTime       time.Time
}

// GitLabSASTOptions configures the GitLab SAST writer.
type GitLabSASTOptions struct {
	// ScannerID is the scanner identifier (default: "waftester").
	ScannerID string

	// ScannerVersion is the version of the scanner.
	ScannerVersion string

	// ScannerVendor is the vendor name (default: "WAFtester").
	ScannerVendor string
}

// GitLab SAST Report structures (v15.0.0+).

type gitlabSASTDocument struct {
	Version         string                `json:"version"`
	Vulnerabilities []gitlabVulnerability `json:"vulnerabilities"`
	Scan            gitlabScan            `json:"scan"`
}

type gitlabVulnerability struct {
	ID          string             `json:"id"`
	Category    string             `json:"category"`
	Name        string             `json:"name"`
	Message     string             `json:"message"`
	Description string             `json:"description"`
	CVE         string             `json:"cve"`
	Severity    string             `json:"severity"`
	Confidence  string             `json:"confidence"`
	Scanner     gitlabScanner      `json:"scanner"`
	Location    gitlabLocation     `json:"location"`
	Identifiers []gitlabIdentifier `json:"identifiers"`
}

type gitlabScanner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type gitlabLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
}

type gitlabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type gitlabScan struct {
	Scanner   gitlabScanScanner `json:"scanner"`
	Type      string            `json:"type"`
	StartTime string            `json:"start_time"`
	EndTime   string            `json:"end_time"`
	Status    string            `json:"status"`
}

type gitlabScanScanner struct {
	ID      string              `json:"id"`
	Name    string              `json:"name"`
	Version string              `json:"version"`
	Vendor  gitlabScannerVendor `json:"vendor"`
}

type gitlabScannerVendor struct {
	Name string `json:"name"`
}

// NewGitLabSASTWriter creates a new GitLab SAST Report writer.
// The writer buffers all results and writes a complete document on Close.
// The writer is safe for concurrent use.
func NewGitLabSASTWriter(w io.Writer, opts GitLabSASTOptions) *GitLabSASTWriter {
	if opts.ScannerID == "" {
		opts.ScannerID = defaults.ToolName
	}
	if opts.ScannerVendor == "" {
		opts.ScannerVendor = defaults.ToolNameDisplay
	}
	return &GitLabSASTWriter{
		w:               w,
		opts:            opts,
		vulnerabilities: make([]gitlabVulnerability, 0),
		startTime:       time.Now(),
	}
}

// severityToGitLab maps WAFtester severity to GitLab SAST severity.
// Delegates to finding.Severity.ToGitLab for canonical mapping.
func severityToGitLab(severity events.Severity) string {
	return severity.ToGitLab()
}

// categoryToName converts a test category to a human-readable name.
func categoryToName(category string) string {
	names := map[string]string{
		"sqli": "SQL Injection",
		"xss":  "Cross-Site Scripting",
		"rce":  "Remote Code Execution",
		"lfi":  "Local File Inclusion",
		"rfi":  "Remote File Inclusion",
		"ssrf": "Server-Side Request Forgery",
		"xxe":  "XML External Entity",
		"ssti": "Server-Side Template Injection",
		"cmdi": "Command Injection",
		"ldap": "LDAP Injection",
		"path": "Path Traversal",
	}
	if name, ok := names[category]; ok {
		return name
	}
	return category + " WAF Bypass"
}

// categoryToCWE maps test categories to common CWE identifiers.
func categoryToCWE(category string) (cweNum int, cweName string) {
	cweMap := map[string]struct {
		num  int
		name string
	}{
		"sqli": {89, "CWE-89"},
		"xss":  {79, "CWE-79"},
		"rce":  {94, "CWE-94"},
		"lfi":  {22, "CWE-22"},
		"rfi":  {98, "CWE-98"},
		"ssrf": {918, "CWE-918"},
		"xxe":  {611, "CWE-611"},
		"ssti": {94, "CWE-94"},
		"cmdi": {78, "CWE-78"},
		"ldap": {90, "CWE-90"},
		"path": {22, "CWE-22"},
	}
	if cwe, ok := cweMap[category]; ok {
		return cwe.num, cwe.name
	}
	return 0, ""
}

// generateVulnerabilityID creates a unique ID for a vulnerability based on test and target.
func generateVulnerabilityID(testID, category, targetURL string) string {
	data := fmt.Sprintf("%s:%s:%s", testID, category, targetURL)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16])
}

// Write converts a result event to GitLab SAST vulnerability format.
// Only bypass and error outcomes are included in the output.
func (gw *GitLabSASTWriter) Write(event events.Event) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	re, ok := event.(*events.ResultEvent)
	if !ok {
		return nil // Skip non-result events
	}

	// Only include bypass/error outcomes
	if re.Result.Outcome != events.OutcomeBypass && re.Result.Outcome != events.OutcomeError {
		return nil
	}

	vulnID := generateVulnerabilityID(re.Test.ID, re.Test.Category, re.Target.URL)
	name := categoryToName(re.Test.Category)

	var message string
	if re.Result.Outcome == events.OutcomeBypass {
		message = fmt.Sprintf("WAF bypass detected: %s payload succeeded", re.Test.Category)
	} else {
		message = fmt.Sprintf("WAF test error: %s test encountered an error", re.Test.Category)
	}

	description := fmt.Sprintf(
		"A WAF bypass was detected for %s attack category. "+
			"The payload '%s' was not blocked by the WAF, potentially exposing the application to attack.",
		re.Test.Category, re.Test.ID,
	)

	identifiers := make([]gitlabIdentifier, 0)

	// Add CWE identifier based on category
	cweNum, cweName := categoryToCWE(re.Test.Category)
	if cweNum > 0 {
		identifiers = append(identifiers, gitlabIdentifier{
			Type:  "cwe",
			Name:  cweName,
			Value: fmt.Sprintf("%d", cweNum),
			URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", cweNum),
		})
	}

	// Add CWE from test info if available
	for _, cwe := range re.Test.CWE {
		// Skip if already added from category mapping
		if cwe == cweNum {
			continue
		}
		identifiers = append(identifiers, gitlabIdentifier{
			Type:  "cwe",
			Name:  fmt.Sprintf("CWE-%d", cwe),
			Value: fmt.Sprintf("%d", cwe),
			URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", cwe),
		})
	}

	vuln := gitlabVulnerability{
		ID:          vulnID,
		Category:    "sast",
		Name:        name,
		Message:     message,
		Description: description,
		CVE:         "",
		Severity:    severityToGitLab(re.Test.Severity),
		Confidence:  "High",
		Scanner: gitlabScanner{
			ID:   gw.opts.ScannerID,
			Name: gw.opts.ScannerVendor,
		},
		Location: gitlabLocation{
			File:      re.Target.URL,
			StartLine: 1,
		},
		Identifiers: identifiers,
	}

	gw.vulnerabilities = append(gw.vulnerabilities, vuln)
	return nil
}

// Flush is a no-op for GitLab SAST writer.
// All results are written as a single document on Close.
func (gw *GitLabSASTWriter) Flush() error { return nil }

// Close writes all buffered vulnerabilities as a complete GitLab SAST document.
// If the underlying writer implements io.Closer, it will be closed.
func (gw *GitLabSASTWriter) Close() error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	endTime := time.Now()

	doc := gitlabSASTDocument{
		Version:         "15.0.0",
		Vulnerabilities: gw.vulnerabilities,
		Scan: gitlabScan{
			Scanner: gitlabScanScanner{
				ID:      gw.opts.ScannerID,
				Name:    gw.opts.ScannerVendor,
				Version: gw.opts.ScannerVersion,
				Vendor: gitlabScannerVendor{
					Name: gw.opts.ScannerVendor,
				},
			},
			Type:      "sast",
			StartTime: gw.startTime.Format(time.RFC3339),
			EndTime:   endTime.Format(time.RFC3339),
			Status:    "success",
		},
	}

	encoder := json.NewEncoder(gw.w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return err
	}

	// Close underlying writer if it implements io.Closer
	if closer, ok := gw.w.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// SupportsEvent returns true for result and bypass events.
func (gw *GitLabSASTWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeBypass:
		return true
	default:
		return false
	}
}
