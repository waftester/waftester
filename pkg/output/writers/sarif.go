// Package writers provides output writers for various formats.
package writers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/jsonutil"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*SARIFWriter)(nil)

// SARIFWriter writes events in SARIF 2.1.0 format.
// SARIF (Static Analysis Results Interchange Format) is the standard
// for GitHub Security tab, GitLab SAST, and Azure DevOps integration.
// Results are buffered and written as a complete SARIF document on Close.
//
// This implementation follows GitHub-certified patterns from Semgrep, Trivy,
// and Nuclei including:
//   - matchBasedId/v1 fingerprints for result deduplication
//   - security-severity scores for GitHub Advanced Security
//   - Rich markdown help for IDE integration
//   - CWE and OWASP tagging for vulnerability classification
type SARIFWriter struct {
	w       io.Writer
	mu      sync.Mutex
	opts    SARIFOptions
	results []sarifResult
	rules   map[string]sarifRule
}

// SARIFOptions configures the SARIF writer.
type SARIFOptions struct {
	// ToolName is the name of the tool (default: waftester).
	ToolName string

	// ToolVersion is the version of the tool.
	ToolVersion string

	// ToolURI is the information URI for the tool.
	ToolURI string

	// ToolDownloadURI is the download URI for the tool.
	ToolDownloadURI string

	// Organization is the organization that produces the tool.
	Organization string
}

// SARIF 2.1.0 structures.

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool     `json:"tool"`
	Results    []sarifResult `json:"results"`
	ColumnKind string        `json:"columnKind,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	DownloadURI     string      `json:"downloadUri,omitempty"`
	Organization    string      `json:"organization,omitempty"`
	Rules           []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription *sarifMessage       `json:"shortDescription,omitempty"`
	FullDescription  *sarifMessage       `json:"fullDescription,omitempty"`
	DefaultConfig    *sarifConfiguration `json:"defaultConfiguration,omitempty"`
	Help             *sarifHelp          `json:"help,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       map[string]any      `json:"properties,omitempty"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations,omitempty"`
	Fingerprints map[string]string  `json:"fingerprints,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
	Properties   map[string]any     `json:"properties,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// NewSARIFWriter creates a new SARIF 2.1.0 writer.
// The writer buffers all results and writes a complete SARIF document on Close.
// The writer is safe for concurrent use.
func NewSARIFWriter(w io.Writer, opts SARIFOptions) *SARIFWriter {
	if opts.ToolName == "" {
		opts.ToolName = defaults.ToolName
	}
	if opts.ToolURI == "" {
		opts.ToolURI = "https://github.com/waftester/waftester"
	}
	if opts.ToolDownloadURI == "" {
		opts.ToolDownloadURI = "https://github.com/waftester/waftester/releases"
	}
	if opts.Organization == "" {
		opts.Organization = defaults.ToolNameDisplay
	}
	return &SARIFWriter{
		w:       w,
		opts:    opts,
		results: make([]sarifResult, 0),
		rules:   make(map[string]sarifRule),
	}
}

// severityToLevel maps WAFtester severity to SARIF level.
// Delegates to finding.Severity.ToSARIF for canonical mapping.
func severityToLevel(severity events.Severity) string {
	return severity.ToSARIF()
}

// severityToScore maps WAFtester severity to GitHub security-severity score.
// Delegates to finding.Severity.ToSARIFScore for canonical mapping.
func severityToScore(severity events.Severity) string {
	return severity.ToSARIFScore()
}

// generateFingerprint creates a matchBasedId/v1 fingerprint for result deduplication.
// The fingerprint is a SHA256 hash of the rule ID, file path, line number, and payload.
func generateFingerprint(ruleID, filePath string, line int, payload string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%d:%s", ruleID, filePath, line, payload)))
	return hex.EncodeToString(h.Sum(nil))
}

// categoryToOWASP maps attack categories to OWASP Top 10 2021 categories.
// Uses centralized defaults.OWASPCategoryMapping for consistency.
func categoryToOWASP(category string) string {
	code := defaults.GetOWASPCategory(category)
	if cat, ok := defaults.OWASPTop10[code]; ok {
		return strings.ReplaceAll(cat.FullName, " - ", "-")
	}
	return "A00:2021-Unknown"
}

// categoryToReadableName converts attack category to human-readable name.
// Uses centralized defaults.CategoryReadableNames for consistency.
func categoryToReadableName(category string) string {
	return defaults.GetCategoryReadableName(category)
}

// buildTags creates the tags array for a rule including CWE, OWASP, and security tags.
func buildTags(category string, cwes []int, owasp string) []string {
	tags := []string{"security", "external/cwe"}
	for _, cwe := range cwes {
		tags = append(tags, fmt.Sprintf("CWE-%d", cwe))
	}
	if owasp != "" && owasp != "A00:2021-Unknown" {
		tags = append(tags, owasp)
	}
	tags = append(tags, "waf-bypass")
	return tags
}

// buildHelp creates rich help content with markdown for IDE display.
func buildHelp(category, name string, cwes []int, owasp string) *sarifHelp {
	plainText := fmt.Sprintf(
		"%s vulnerability detected. The WAF failed to block a %s payload, "+
			"potentially exposing the application to attack. Review and strengthen "+
			"WAF rules for %s detection.",
		name, strings.ToLower(name), strings.ToLower(name))

	var cweLinks strings.Builder
	for _, cwe := range cwes {
		cweLinks.WriteString(fmt.Sprintf("- [CWE-%d](https://cwe.mitre.org/data/definitions/%d.html)\n", cwe, cwe))
	}

	markdown := fmt.Sprintf(`## %s

A WAF bypass was detected for **%s** attacks.

### Description

The Web Application Firewall failed to block a malicious payload targeting %s vulnerabilities. This indicates a gap in WAF rule coverage that could be exploited by attackers.

### Impact

| Severity | OWASP Category |
|----------|----------------|
| Based on payload | %s |

### Remediation

1. Review and strengthen WAF rules for %s detection
2. Ensure proper coverage for payload variations and evasion techniques
3. Consider adding custom rules for application-specific attack patterns
4. Test WAF rules with a comprehensive payload set

### References

%s- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [WAFtester Documentation](https://github.com/waftester/waftester/docs)
`, name, name, strings.ToLower(name), owasp, strings.ToLower(name), cweLinks.String())

	return &sarifHelp{
		Text:     plainText,
		Markdown: markdown,
	}
}

// Write converts a result event to SARIF format.
// Only bypass and error outcomes are included in the SARIF output.
func (sw *SARIFWriter) Write(event events.Event) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	re, ok := event.(*events.ResultEvent)
	if !ok {
		return nil // Skip non-result events
	}

	// Only include bypass/error outcomes
	if re.Result.Outcome != events.OutcomeBypass && re.Result.Outcome != events.OutcomeError {
		return nil
	}

	ruleID := re.Test.Category + "-" + re.Test.ID
	name := categoryToReadableName(re.Test.Category)
	owasp := categoryToOWASP(re.Test.Category)

	// Get CWEs - use test-provided CWEs if available, otherwise map from category
	cwes := re.Test.CWE
	if len(cwes) == 0 {
		cwes = categoryToCWEs(re.Test.Category)
	}

	// Add rule if not exists
	if _, exists := sw.rules[ruleID]; !exists {
		tags := buildTags(re.Test.Category, cwes, owasp)
		help := buildHelp(re.Test.Category, name, cwes, owasp)
		helpURI := fmt.Sprintf("https://github.com/waftester/waftester/docs/%s", re.Test.Category)

		properties := map[string]any{
			"precision":         "very-high",
			"tags":              tags,
			"security-severity": severityToScore(re.Test.Severity),
		}

		sw.rules[ruleID] = sarifRule{
			ID:   ruleID,
			Name: name,
			ShortDescription: &sarifMessage{
				Text: fmt.Sprintf("%s vulnerability detected", name),
			},
			FullDescription: &sarifMessage{
				Text: fmt.Sprintf(
					"WAF bypass detected for %s (%s). The payload was not blocked, "+
						"potentially exposing the application to %s attacks.",
					name, re.Test.Category, strings.ToLower(name)),
			},
			DefaultConfig: &sarifConfiguration{
				Level: severityToLevel(re.Test.Severity),
			},
			Help:       help,
			HelpURI:    helpURI,
			Properties: properties,
		}
	}

	// Generate fingerprint for result deduplication
	payload := ""
	if re.Evidence != nil {
		payload = re.Evidence.Payload
	}
	fingerprint := generateFingerprint(ruleID, re.Target.URL, 1, payload)

	// Build result message with markdown
	msgText := fmt.Sprintf("WAF bypass detected: %s", re.Test.Category)
	msgMarkdown := fmt.Sprintf(
		"**WAF Bypass Detected:** %s\n\n"+
			"| Property | Value |\n"+
			"|----------|-------|\n"+
			"| Category | %s |\n"+
			"| Severity | %s |\n"+
			"| Target | `%s` |\n"+
			"| Status | %d |",
		name, re.Test.Category, re.Test.Severity, re.Target.URL, re.Result.StatusCode)

	if payload != "" {
		// Truncate payload for display
		displayPayload := payload
		if len(displayPayload) > 100 {
			payloadRunes := []rune(displayPayload)
			if len(payloadRunes) > 100 {
				displayPayload = string(payloadRunes[:100]) + "..."
			}
		}
		msgMarkdown += fmt.Sprintf("\n| Payload | `%s` |", displayPayload)
	}

	// Build result
	result := sarifResult{
		RuleID: ruleID,
		Level:  severityToLevel(re.Test.Severity),
		Message: sarifMessage{
			Text:     msgText,
			Markdown: msgMarkdown,
		},
		Locations: []sarifLocation{
			{
				PhysicalLocation: &sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI: re.Target.URL,
					},
					Region: &sarifRegion{
						StartLine: 1,
					},
				},
			},
		},
		Fingerprints: map[string]string{
			"matchBasedId/v1": fingerprint,
		},
		Properties: map[string]any{
			"category":    re.Test.Category,
			"severity":    string(re.Test.Severity),
			"status_code": re.Result.StatusCode,
			"latency_ms":  re.Result.LatencyMs,
		},
	}

	// Add payload to properties if available
	if payload != "" {
		result.Properties["payload_hash"] = generateFingerprint("", "", 0, payload)[:16]
	}

	sw.results = append(sw.results, result)

	return nil
}

// Flush is a no-op for SARIF writer.
// All results are written as a single document on Close.
func (sw *SARIFWriter) Flush() error { return nil }

// Close writes all buffered results as a complete SARIF 2.1.0 document.
// If the underlying writer implements io.Closer, it will be closed.
func (sw *SARIFWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	// Build rules array from map and sort by ID for deterministic output.
	rules := make([]sarifRule, 0, len(sw.rules))
	for _, rule := range sw.rules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	// Ensure results is never nil so JSON encodes as [] not null per SARIF spec.
	results := sw.results
	if results == nil {
		results = make([]sarifResult, 0)
	}

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            sw.opts.ToolName,
						Version:         sw.opts.ToolVersion,
						SemanticVersion: sw.opts.ToolVersion,
						InformationURI:  sw.opts.ToolURI,
						DownloadURI:     sw.opts.ToolDownloadURI,
						Organization:    sw.opts.Organization,
						Rules:           rules,
					},
				},
				Results:    results,
				ColumnKind: "utf16CodeUnits",
			},
		},
	}

	encoder := jsonutil.NewStreamEncoder(sw.w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("sarif: encode: %w", err)
	}

	if closer, ok := sw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SupportsEvent returns true for result and bypass events.
// These are the event types relevant for SARIF security reporting.
func (sw *SARIFWriter) SupportsEvent(eventType events.EventType) bool {
	return eventType == events.EventTypeResult || eventType == events.EventTypeBypass
}
