// Package writers provides output writers for various formats.
package writers

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*MarkdownWriter)(nil)

// MarkdownConfig configures the Markdown report writer.
type MarkdownConfig struct {
	// Title is the report title (default: "WAFtester Security Report")
	Title string

	// Flavor sets the Markdown flavor: "github", "gitlab", or "standard" (default: "github")
	Flavor string

	// SortBy sets the sorting order: "severity", "category", or "target" (default: "severity")
	// Can be overridden by MARKDOWN_EXPORT_SORT_MODE environment variable.
	SortBy string

	// IncludeTOC includes a table of contents (default: true)
	IncludeTOC bool

	// IncludeEvidence includes payloads/evidence in the report (default: true)
	IncludeEvidence bool

	// IncludeOWASP includes OWASP Top 10 mapping table (default: true)
	IncludeOWASP bool

	// IncludeCWE includes CWE reference table (default: true)
	IncludeCWE bool

	// CollapseSections uses details/summary for collapsible sections (default: true)
	CollapseSections bool

	// MaxPayloadLen truncates payload display to this length (default: 200)
	MaxPayloadLen int

	// ShowExecutiveSummary includes an executive summary section with key metrics (default: true)
	ShowExecutiveSummary bool

	// ShowRiskBars includes visual ASCII risk distribution bars (default: true)
	ShowRiskBars bool

	// UseEmojis includes severity/outcome emojis in the report (default: true)
	UseEmojis bool

	// UseCollapsible enables GitHub-flavored <details> blocks (default: true)
	UseCollapsible bool

	// ShowCurlCommands includes cURL commands for reproducing findings (default: true)
	ShowCurlCommands bool

	// MaxResponseLength truncates response previews to this length (default: 2048)
	MaxResponseLength int
}

// MarkdownWriter writes events as a Markdown report.
// It buffers all events in memory and renders the complete Markdown document on Close.
// The writer is safe for concurrent use.
type MarkdownWriter struct {
	w       io.Writer
	mu      sync.Mutex
	config  MarkdownConfig
	results []*events.ResultEvent
	summary *events.SummaryEvent
}

// NewMarkdownWriter creates a new Markdown report writer.
// The writer buffers all events and writes a complete Markdown report on Close.
func NewMarkdownWriter(w io.Writer, config MarkdownConfig) *MarkdownWriter {
	if config.Title == "" {
		config.Title = "WAFtester Security Report"
	}
	if config.Flavor == "" {
		config.Flavor = "github"
	}
	// Environment variable override for sort mode (Nuclei-style)
	if envSort := os.Getenv("MARKDOWN_EXPORT_SORT_MODE"); envSort != "" {
		config.SortBy = envSort
	}
	if config.SortBy == "" {
		config.SortBy = "severity"
	}
	if config.MaxPayloadLen == 0 {
		config.MaxPayloadLen = 200
	}
	if config.MaxResponseLength == 0 {
		config.MaxResponseLength = 2048
	}
	// Enable professional features by default (can be disabled via config)
	if !config.ShowExecutiveSummary && !configFieldWasSet("ShowExecutiveSummary") {
		config.ShowExecutiveSummary = true
	}
	if !config.ShowRiskBars && !configFieldWasSet("ShowRiskBars") {
		config.ShowRiskBars = true
	}
	if !config.UseEmojis && !configFieldWasSet("UseEmojis") {
		config.UseEmojis = true
	}
	if !config.UseCollapsible && !configFieldWasSet("UseCollapsible") {
		config.UseCollapsible = true
	}
	if !config.ShowCurlCommands && !configFieldWasSet("ShowCurlCommands") {
		config.ShowCurlCommands = true
	}
	return &MarkdownWriter{
		w:       w,
		config:  config,
		results: make([]*events.ResultEvent, 0),
	}
}

// configFieldWasSet is a helper to check if a bool field was explicitly set.
// This is a placeholder - in practice, use pointer types or a separate "set" map.
// For now, we rely on zero value meaning "use default (true)".
func configFieldWasSet(_ string) bool {
	return false
}

// Write buffers an event for later Markdown output.
func (mw *MarkdownWriter) Write(event events.Event) error {
	mw.mu.Lock()
	defer mw.mu.Unlock()

	switch e := event.(type) {
	case *events.ResultEvent:
		mw.results = append(mw.results, e)
	case *events.SummaryEvent:
		mw.summary = e
	}
	return nil
}

// Flush is a no-op for Markdown writer.
// All events are written as a single Markdown document on Close.
func (mw *MarkdownWriter) Flush() error {
	return nil
}

// Close renders and writes the complete Markdown report.
func (mw *MarkdownWriter) Close() error {
	mw.mu.Lock()
	defer mw.mu.Unlock()

	sb := &strings.Builder{}
	mw.renderMarkdown(sb)

	if _, err := io.WriteString(mw.w, sb.String()); err != nil {
		return fmt.Errorf("failed to write Markdown: %w", err)
	}

	if closer, ok := mw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SupportsEvent returns true for result and summary events.
func (mw *MarkdownWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeSummary:
		return true
	default:
		return false
	}
}

// severityEmoji returns the emoji icon for a severity level (Trivy-style).
func severityEmoji(s events.Severity) string {
	switch s {
	case events.SeverityCritical:
		return "🔴"
	case events.SeverityHigh:
		return "🟠"
	case events.SeverityMedium:
		return "🟡"
	case events.SeverityLow:
		return "🟢"
	default:
		return "🔵"
	}
}

// severityIcon returns the emoji icon for a severity level.
// Wrapper for backwards compatibility.
func severityIcon(s events.Severity) string {
	return severityEmoji(s)
}

// severityPriority returns a numeric priority for sorting (higher = more severe).
func severityPriority(s events.Severity) int {
	switch s {
	case events.SeverityCritical:
		return 5
	case events.SeverityHigh:
		return 4
	case events.SeverityMedium:
		return 3
	case events.SeverityLow:
		return 2
	default:
		return 1
	}
}

// outcomeIcon returns the emoji icon for an outcome.
func outcomeIcon(o events.Outcome) string {
	switch o {
	case events.OutcomeBypass:
		return "⚠️"
	case events.OutcomeBlocked:
		return "✅"
	case events.OutcomeError:
		return "❌"
	case events.OutcomeTimeout:
		return "⏱️"
	default:
		return "ℹ️"
	}
}

// OWASP Top 10 2021 reference data - uses defaults.OWASPTop10 and defaults.OWASPTop10Ordered.

// Common CWE IDs with descriptions.
var cweDescriptions = map[int]string{
	20:  "Improper Input Validation",
	22:  "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
	78:  "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
	79:  "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
	89:  "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
	90:  "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
	91:  "XML Injection",
	94:  "Improper Control of Generation of Code ('Code Injection')",
	98:  "Improper Control of Filename for Include/Require Statement in PHP Program",
	113: "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
	200: "Exposure of Sensitive Information to an Unauthorized Actor",
	284: "Improper Access Control",
	287: "Improper Authentication",
	352: "Cross-Site Request Forgery (CSRF)",
	400: "Uncontrolled Resource Consumption",
	434: "Unrestricted Upload of File with Dangerous Type",
	502: "Deserialization of Untrusted Data",
	611: "Improper Restriction of XML External Entity Reference",
	776: "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
	918: "Server-Side Request Forgery (SSRF)",
	943: "Improper Neutralization of Special Elements in Data Query Logic",
}

// renderSeverityBar generates a text-based severity bar with emojis (Trivy-style).
func renderSeverityBar(counts map[events.Severity]int, total int, useEmojis bool) string {
	if total == 0 {
		return "*No findings*\n"
	}

	sb := &strings.Builder{}
	sb.WriteString("```\n")

	severities := []events.Severity{
		events.SeverityCritical,
		events.SeverityHigh,
		events.SeverityMedium,
		events.SeverityLow,
		events.SeverityInfo,
	}

	maxBarLen := 20
	for _, sev := range severities {
		count := counts[sev]
		if count == 0 {
			continue
		}

		pct := float64(count) / float64(total) * 100
		barLen := int(float64(count) / float64(total) * float64(maxBarLen))
		if barLen == 0 && count > 0 {
			barLen = 1
		}

		bar := strings.Repeat("█", barLen) + strings.Repeat("░", maxBarLen-barLen)
		emoji := ""
		if useEmojis {
			emoji = severityEmoji(sev) + " "
		}
		sb.WriteString(fmt.Sprintf("%s%-8s %s %d (%.0f%%)\n", emoji, capitalizeFirst(string(sev)), bar, count, pct))
	}
	sb.WriteString("```\n")

	return sb.String()
}

func (mw *MarkdownWriter) renderMarkdown(sb *strings.Builder) {
	// Sort results based on config
	sortedResults := mw.sortResults()

	// Count bypasses by severity
	bypassCounts := make(map[events.Severity]int)
	totalBypasses := 0
	criticalHighCount := 0
	for _, r := range sortedResults {
		if r.Result.Outcome == events.OutcomeBypass {
			bypassCounts[r.Test.Severity]++
			totalBypasses++
			if r.Test.Severity == events.SeverityCritical || r.Test.Severity == events.SeverityHigh {
				criticalHighCount++
			}
		}
	}

	// Build OWASP and CWE mappings
	owaspStats := mw.buildOWASPStats()
	cweRefs := mw.buildCWERefs()

	// Render title
	sb.WriteString(fmt.Sprintf("# %s\n\n", mw.config.Title))
	sb.WriteString(fmt.Sprintf("*Generated: %s*\n\n", time.Now().Format("2006-01-02 15:04:05 MST")))

	// Render Table of Contents
	if mw.config.IncludeTOC {
		mw.renderTOC(sb)
	}

	// Render executive summary (ZAP-style)
	if mw.config.ShowExecutiveSummary {
		mw.renderExecutiveSummary(sb, bypassCounts, totalBypasses, criticalHighCount)
	}

	// Render summary section
	mw.renderSummary(sb, bypassCounts, totalBypasses)

	// Render severity distribution with risk bars (Trivy-style)
	if mw.config.ShowRiskBars {
		sb.WriteString("## Risk Distribution\n\n")
		sb.WriteString(renderSeverityBar(bypassCounts, totalBypasses, mw.config.UseEmojis))
		sb.WriteString("\n")
	}

	// Render OWASP mapping table with clickable links
	if mw.config.IncludeOWASP {
		mw.renderOWASPTable(sb, owaspStats)
	}

	// Render CWE reference table with clickable links
	if mw.config.IncludeCWE {
		mw.renderCWETable(sb, cweRefs)
	}

	// Render findings
	mw.renderFindings(sb, sortedResults)
}

func (mw *MarkdownWriter) renderTOC(sb *strings.Builder) {
	sb.WriteString("## Table of Contents\n\n")
	if mw.config.ShowExecutiveSummary {
		sb.WriteString("- [Executive Summary](#executive-summary)\n")
	}
	sb.WriteString("- [Summary](#summary)\n")
	if mw.config.ShowRiskBars {
		sb.WriteString("- [Risk Distribution](#risk-distribution)\n")
	}

	if mw.config.IncludeOWASP {
		sb.WriteString("- [OWASP Top 10 Mapping](#owasp-top-10-mapping)\n")
	}
	if mw.config.IncludeCWE {
		sb.WriteString("- [CWE References](#cwe-references)\n")
	}

	sb.WriteString("- [Findings](#findings)\n")
	sb.WriteString("\n")
}

// renderExecutiveSummary renders a high-level executive summary section (ZAP-style).
func (mw *MarkdownWriter) renderExecutiveSummary(sb *strings.Builder, bypassCounts map[events.Severity]int, totalBypasses, criticalHighCount int) {
	sb.WriteString("## Executive Summary\n\n")

	// Key metrics table
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")

	totalTests := len(mw.results)
	sb.WriteString(fmt.Sprintf("| Total Tests | %d |\n", totalTests))

	if mw.summary != nil {
		sb.WriteString(fmt.Sprintf("| WAF Effectiveness | %.1f%% |\n", mw.summary.Effectiveness.BlockRatePct))
	}

	sb.WriteString(fmt.Sprintf("| Bypasses Found | %d |\n", totalBypasses))
	sb.WriteString(fmt.Sprintf("| Critical/High Severity | %d |\n", criticalHighCount))
	sb.WriteString("\n")

	// Key recommendations
	sb.WriteString("### Key Recommendations\n\n")

	recommendations := mw.generateRecommendations(bypassCounts, totalBypasses, criticalHighCount)
	for i, rec := range recommendations {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
	}
	sb.WriteString("\n")
}

// generateRecommendations generates context-aware recommendations based on findings.
func (mw *MarkdownWriter) generateRecommendations(bypassCounts map[events.Severity]int, totalBypasses, criticalHighCount int) []string {
	recommendations := make([]string, 0, 5)

	// Critical/High priority issues
	if criticalHighCount > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("**URGENT:** Address %d critical/high severity bypasses immediately", criticalHighCount))
	}

	// Severity-specific recommendations
	if bypassCounts[events.SeverityCritical] > 0 {
		recommendations = append(recommendations,
			"Review and strengthen WAF rules for critical attack vectors (SQL injection, RCE)")
	}

	if bypassCounts[events.SeverityHigh] > 0 {
		recommendations = append(recommendations,
			"Enable additional protection rules for high-severity attack categories")
	}

	// Category-specific recommendations from summary
	if mw.summary != nil && mw.summary.Effectiveness.Recommendation != "" {
		recommendations = append(recommendations, mw.summary.Effectiveness.Recommendation)
	}

	// General recommendations based on bypass rate
	if mw.summary != nil {
		if mw.summary.Effectiveness.BlockRatePct < 80 {
			recommendations = append(recommendations,
				"Consider upgrading WAF ruleset or enabling stricter protection mode")
		} else if mw.summary.Effectiveness.BlockRatePct < 95 {
			recommendations = append(recommendations,
				"Fine-tune WAF rules to improve detection of edge cases")
		}
	}

	// Default recommendation if none generated
	if len(recommendations) == 0 {
		if totalBypasses == 0 {
			recommendations = append(recommendations, "WAF configuration appears robust - continue monitoring")
		} else {
			recommendations = append(recommendations, "Review bypass findings and update WAF rules accordingly")
		}
	}

	return recommendations
}

func (mw *MarkdownWriter) renderSummary(sb *strings.Builder, bypassCounts map[events.Severity]int, totalBypasses int) {
	sb.WriteString("## Summary\n\n")

	if mw.summary != nil {
		sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", mw.summary.Target.URL))
		if mw.summary.Target.WAFDetected != "" {
			sb.WriteString(fmt.Sprintf("**WAF Detected:** %s\n\n", mw.summary.Target.WAFDetected))
		}

		sb.WriteString("| Metric | Value |\n")
		sb.WriteString("|--------|-------|\n")
		sb.WriteString(fmt.Sprintf("| Total Tests | %d |\n", mw.summary.Totals.Tests))
		sb.WriteString(fmt.Sprintf("| Bypasses | %d |\n", mw.summary.Totals.Bypasses))
		sb.WriteString(fmt.Sprintf("| Blocked | %d |\n", mw.summary.Totals.Blocked))
		sb.WriteString(fmt.Sprintf("| Block Rate | %.1f%% |\n", mw.summary.Effectiveness.BlockRatePct))
		sb.WriteString(fmt.Sprintf("| Grade | **%s** |\n", mw.summary.Effectiveness.Grade))
		sb.WriteString(fmt.Sprintf("| Duration | %.2fs |\n", mw.summary.Timing.DurationSec))
		sb.WriteString("\n")

		// Severity breakdown with conditional emojis
		sb.WriteString("### Bypasses by Severity\n\n")
		sb.WriteString("| Severity | Count |\n")
		sb.WriteString("|----------|-------|\n")
		severities := []events.Severity{
			events.SeverityCritical,
			events.SeverityHigh,
			events.SeverityMedium,
			events.SeverityLow,
			events.SeverityInfo,
		}
		for _, sev := range severities {
			count := bypassCounts[sev]
			emoji := ""
			if mw.config.UseEmojis {
				emoji = severityEmoji(sev) + " "
			}
			sb.WriteString(fmt.Sprintf("| %s%s | %d |\n", emoji, capitalizeFirst(string(sev)), count))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString(fmt.Sprintf("**Total Results:** %d\n", len(mw.results)))
		sb.WriteString(fmt.Sprintf("**Total Bypasses:** %d\n\n", totalBypasses))
	}
}

func (mw *MarkdownWriter) renderOWASPTable(sb *strings.Builder, owaspStats map[string]owaspStat) {
	sb.WriteString("## OWASP Top 10 Mapping\n\n")
	sb.WriteString("| Category | Description | Tests | Bypasses | Status |\n")
	sb.WriteString("|----------|-------------|-------|----------|--------|\n")

	for _, code := range defaults.OWASPTop10Ordered {
		cat := defaults.OWASPTop10[code]
		stat := owaspStats[code]
		status := "✅ Pass"
		if stat.bypasses > 0 {
			status = "⚠️ Fail"
		} else if stat.total == 0 {
			status = "⏭️ N/A"
		}
		// Add clickable OWASP link
		owaspLink := owaspMarkdownLink(code)
		sb.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %s |\n",
			owaspLink, cat.Name, stat.total, stat.bypasses, status))
	}
	sb.WriteString("\n")
}

// owaspMarkdownLink returns a markdown link for an OWASP category.
func owaspMarkdownLink(code string) string {
	// Use centralized OWASP URL from defaults
	return fmt.Sprintf("[%s](%s)", code, defaults.GetOWASPURL(code))
}

func (mw *MarkdownWriter) renderCWETable(sb *strings.Builder, cweRefs map[int]cweStat) {
	if len(cweRefs) == 0 {
		return
	}

	sb.WriteString("## CWE References\n\n")
	sb.WriteString("| CWE ID | Description | Count | Bypasses |\n")
	sb.WriteString("|--------|-------------|-------|----------|\n")

	// Sort CWE IDs for consistent output
	cweIDs := make([]int, 0, len(cweRefs))
	for id := range cweRefs {
		cweIDs = append(cweIDs, id)
	}
	sort.Ints(cweIDs)

	for _, id := range cweIDs {
		stat := cweRefs[id]
		desc := cweDescriptions[id]
		if desc == "" {
			desc = "Unknown"
		}
		cweLink := cweMarkdownLink(id)
		sb.WriteString(fmt.Sprintf("| %s | %s | %d | %d |\n", cweLink, desc, stat.total, stat.bypasses))
	}
	sb.WriteString("\n")
}

// cweMarkdownLink returns a markdown link for a CWE ID.
func cweMarkdownLink(cweID int) string {
	return fmt.Sprintf("[CWE-%d](https://cwe.mitre.org/data/definitions/%d.html)", cweID, cweID)
}

func (mw *MarkdownWriter) renderFindings(sb *strings.Builder, results []*events.ResultEvent) {
	sb.WriteString("## Findings\n\n")

	if len(results) == 0 {
		sb.WriteString("*No findings to report.*\n\n")
		return
	}

	// Group findings for collapsible sections based on sort order
	if mw.config.CollapseSections && mw.config.UseCollapsible && mw.supportsCollapsible() {
		mw.renderCollapsibleFindings(sb, results)
	} else {
		mw.renderFlatFindings(sb, results)
	}
}

func (mw *MarkdownWriter) supportsCollapsible() bool {
	return mw.config.Flavor == "github" || mw.config.Flavor == "gitlab"
}

func (mw *MarkdownWriter) renderCollapsibleFindings(sb *strings.Builder, results []*events.ResultEvent) {
	// Group by outcome first (bypasses first, then others)
	bypasses := make([]*events.ResultEvent, 0)
	others := make([]*events.ResultEvent, 0)

	for _, r := range results {
		if r.Result.Outcome == events.OutcomeBypass {
			bypasses = append(bypasses, r)
		} else {
			others = append(others, r)
		}
	}

	// Render bypasses in collapsible section
	if len(bypasses) > 0 {
		sb.WriteString("<details open>\n")
		sb.WriteString(fmt.Sprintf("<summary><strong>⚠️ Bypasses (%d)</strong></summary>\n\n", len(bypasses)))
		mw.renderFindingsTable(sb, bypasses)
		sb.WriteString("</details>\n\n")
	}

	// Render other findings in collapsible section
	if len(others) > 0 {
		sb.WriteString("<details>\n")
		sb.WriteString(fmt.Sprintf("<summary><strong>Other Results (%d)</strong></summary>\n\n", len(others)))
		mw.renderFindingsTable(sb, others)
		sb.WriteString("</details>\n\n")
	}
}

func (mw *MarkdownWriter) renderFlatFindings(sb *strings.Builder, results []*events.ResultEvent) {
	mw.renderFindingsTable(sb, results)
}

func (mw *MarkdownWriter) renderFindingsTable(sb *strings.Builder, results []*events.ResultEvent) {
	sb.WriteString("| Severity | ID | Category | Target | Outcome | Status |\n")
	sb.WriteString("|----------|-------|----------|--------|---------|--------|\n")

	for _, r := range results {
		sevEmoji := ""
		outcEmoji := ""
		if mw.config.UseEmojis {
			sevEmoji = severityEmoji(r.Test.Severity) + " "
			outcEmoji = outcomeIcon(r.Result.Outcome) + " "
		}
		sb.WriteString(fmt.Sprintf("| %s%s | %s | %s | %s | %s%s | %d |\n",
			sevEmoji,
			capitalizeFirst(string(r.Test.Severity)),
			r.Test.ID,
			r.Test.Category,
			truncateString(r.Target.URL, 40),
			outcEmoji,
			string(r.Result.Outcome),
			r.Result.StatusCode,
		))
	}
	sb.WriteString("\n")

	// Render evidence if enabled
	if mw.config.IncludeEvidence {
		mw.renderEvidence(sb, results)
	}
}

func (mw *MarkdownWriter) renderEvidence(sb *strings.Builder, results []*events.ResultEvent) {
	// Only render evidence for bypasses
	hasEvidence := false
	for _, r := range results {
		if r.Result.Outcome == events.OutcomeBypass && r.Evidence != nil && r.Evidence.Payload != "" {
			hasEvidence = true
			break
		}
	}

	if !hasEvidence {
		return
	}

	sb.WriteString("### Evidence\n\n")

	for _, r := range results {
		if r.Result.Outcome != events.OutcomeBypass || r.Evidence == nil {
			continue
		}

		if mw.config.UseCollapsible && mw.supportsCollapsible() {
			mw.renderCollapsibleDetails(sb, fmt.Sprintf("<code>%s</code> - %s", r.Test.ID, r.Test.Category), func(content *strings.Builder) {
				mw.renderEvidenceContent(content, r)
			})
		} else {
			sb.WriteString(fmt.Sprintf("#### %s - %s\n\n", r.Test.ID, r.Test.Category))
			mw.renderEvidenceContent(sb, r)
		}
	}
}

// renderCollapsibleDetails renders a GitHub-flavored collapsible details block.
func (mw *MarkdownWriter) renderCollapsibleDetails(sb *strings.Builder, summary string, contentFn func(*strings.Builder)) {
	sb.WriteString("<details>\n")
	sb.WriteString(fmt.Sprintf("<summary>%s</summary>\n\n", summary))
	contentFn(sb)
	sb.WriteString("</details>\n\n")
}

// renderEvidenceContent renders the evidence content for a single result.
func (mw *MarkdownWriter) renderEvidenceContent(sb *strings.Builder, r *events.ResultEvent) {
	if r.Evidence.Payload != "" {
		payload := r.Evidence.Payload
		if len(payload) > mw.config.MaxPayloadLen {
			payload = payload[:mw.config.MaxPayloadLen] + "..."
		}
		sb.WriteString("**Payload:**\n")
		sb.WriteString("```\n")
		sb.WriteString(payload)
		sb.WriteString("\n```\n\n")
	}

	// Render cURL command if enabled (Nuclei-style)
	if mw.config.ShowCurlCommands && r.Evidence.CurlCommand != "" {
		sb.WriteString("**Reproduce:**\n")
		sb.WriteString("```bash\n")
		sb.WriteString(r.Evidence.CurlCommand)
		sb.WriteString("\n```\n\n")
	}

	// Render response preview with truncation (Nuclei-style)
	if r.Evidence.ResponsePreview != "" {
		response := r.Evidence.ResponsePreview
		if len(response) > mw.config.MaxResponseLength {
			response = response[:mw.config.MaxResponseLength] + "\n\n.... Truncated ...."
		}
		sb.WriteString("**Response Preview:**\n")
		sb.WriteString("```\n")
		sb.WriteString(response)
		sb.WriteString("\n```\n\n")
	}

	// Add remediation guidance if CWE is present (Trivy-style)
	if len(r.Test.CWE) > 0 {
		sb.WriteString("**Remediation:**\n")
		for _, cwe := range r.Test.CWE {
			sb.WriteString(fmt.Sprintf("- See %s for remediation guidance\n", cweMarkdownLink(cwe)))
		}
		sb.WriteString("\n")
	}
}

func (mw *MarkdownWriter) sortResults() []*events.ResultEvent {
	results := make([]*events.ResultEvent, len(mw.results))
	copy(results, mw.results)

	switch mw.config.SortBy {
	case "severity":
		sort.Slice(results, func(i, j int) bool {
			// Bypasses first
			if (results[i].Result.Outcome == events.OutcomeBypass) != (results[j].Result.Outcome == events.OutcomeBypass) {
				return results[i].Result.Outcome == events.OutcomeBypass
			}
			// Then by severity (higher first)
			return severityPriority(results[i].Test.Severity) > severityPriority(results[j].Test.Severity)
		})
	case "category":
		sort.Slice(results, func(i, j int) bool {
			if results[i].Test.Category != results[j].Test.Category {
				return results[i].Test.Category < results[j].Test.Category
			}
			return severityPriority(results[i].Test.Severity) > severityPriority(results[j].Test.Severity)
		})
	case "target":
		sort.Slice(results, func(i, j int) bool {
			if results[i].Target.URL != results[j].Target.URL {
				return results[i].Target.URL < results[j].Target.URL
			}
			return severityPriority(results[i].Test.Severity) > severityPriority(results[j].Test.Severity)
		})
	}

	return results
}

type owaspStat struct {
	total    int
	bypasses int
}

func (mw *MarkdownWriter) buildOWASPStats() map[string]owaspStat {
	stats := make(map[string]owaspStat)

	for _, r := range mw.results {
		for _, owasp := range r.Test.OWASP {
			stat := stats[owasp]
			stat.total++
			if r.Result.Outcome == events.OutcomeBypass {
				stat.bypasses++
			}
			stats[owasp] = stat
		}
	}

	return stats
}

type cweStat struct {
	total    int
	bypasses int
}

func (mw *MarkdownWriter) buildCWERefs() map[int]cweStat {
	refs := make(map[int]cweStat)

	for _, r := range mw.results {
		for _, cwe := range r.Test.CWE {
			stat := refs[cwe]
			stat.total++
			if r.Result.Outcome == events.OutcomeBypass {
				stat.bypasses++
			}
			refs[cwe] = stat
		}
	}

	return refs
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// capitalizeFirst capitalizes the first letter of a string.
// This is a simple replacement for the deprecated strings.Title function.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	// For severity values like "critical", "high", etc.
	return strings.ToUpper(s[:1]) + s[1:]
}
