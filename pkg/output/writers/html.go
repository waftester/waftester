// Package writers provides output writers for various formats.
package writers

import (
	"fmt"
	"html"
	"html/template"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/jsonutil"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*HTMLWriter)(nil)

// HTMLConfig configures the HTML report writer.
type HTMLConfig struct {
	// Title is the report title (default: "WAFtester Security Report")
	Title string

	// Theme sets the default theme: "dark", "light", or "auto" (default: "auto")
	Theme string

	// IncludeEvidence includes request/response bodies in the report (default: true)
	IncludeEvidence bool

	// IncludeJSON includes JSON toggle view for each finding (default: true)
	IncludeJSON bool

	// CompanyLogo is the path to company logo (optional)
	CompanyLogo string

	// CompanyName is the company name for branding (optional)
	CompanyName string

	// ShowExecutiveSummary shows the executive summary section at the top (default: true)
	ShowExecutiveSummary bool

	// ShowRiskChart shows the inline SVG pie chart for risk distribution (default: true)
	ShowRiskChart bool

	// ShowRiskMatrix shows the risk × outcome matrix cross-tabulation (default: true)
	ShowRiskMatrix bool

	// ShowCurlCommands displays curl commands for reproducing requests (default: true)
	ShowCurlCommands bool

	// MaxResponseLength is the maximum length for response preview before truncation (default: 5120)
	MaxResponseLength int

	// PrintOptimized adds print-optimized styles for PDF export (default: true)
	PrintOptimized bool
}

// HTMLWriter writes events as a styled HTML report.
// It buffers all events in memory and renders the complete HTML document on Close.
// The writer is safe for concurrent use.
type HTMLWriter struct {
	w       io.Writer
	mu      sync.Mutex
	config  HTMLConfig
	results []*events.ResultEvent
	summary *events.SummaryEvent
}

// NewHTMLWriter creates a new HTML report writer.
// The writer buffers all events and writes a complete HTML report on Close.
func NewHTMLWriter(w io.Writer, config HTMLConfig) *HTMLWriter {
	if config.Title == "" {
		config.Title = "WAFtester Security Report"
	}
	if config.Theme == "" {
		config.Theme = "auto"
	}
	if config.MaxResponseLength <= 0 {
		config.MaxResponseLength = 5 * 1024 // 5KB default
	}
	// Set defaults to true for new features
	if !config.ShowExecutiveSummary && !config.ShowRiskChart && !config.ShowRiskMatrix &&
		!config.ShowCurlCommands && !config.PrintOptimized {
		// If none are explicitly set, enable all by default
		config.ShowExecutiveSummary = true
		config.ShowRiskChart = true
		config.ShowRiskMatrix = true
		config.ShowCurlCommands = true
		config.PrintOptimized = true
	}
	return &HTMLWriter{
		w:       w,
		config:  config,
		results: make([]*events.ResultEvent, 0),
	}
}

// Write buffers an event for later HTML output.
func (hw *HTMLWriter) Write(event events.Event) error {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	switch e := event.(type) {
	case *events.ResultEvent:
		hw.results = append(hw.results, e)
	case *events.SummaryEvent:
		hw.summary = e
	}
	return nil
}

// Flush is a no-op for HTML writer.
// All events are written as a single HTML document on Close.
func (hw *HTMLWriter) Flush() error {
	return nil
}

// Close renders and writes the complete HTML report.
func (hw *HTMLWriter) Close() error {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	data := hw.prepareTemplateData()
	return hw.renderHTML(data)
}

// SupportsEvent returns true for result and summary events.
func (hw *HTMLWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeSummary:
		return true
	default:
		return false
	}
}

// templateData holds all data needed for HTML rendering.
type templateData struct {
	Config          HTMLConfig
	GeneratedAt     string
	Summary         *summaryData
	SeverityCounts  map[string]int
	OWASPCoverage   []owaspCategory
	Findings        []findingData
	TotalTests      int
	TotalBypasses   int
	TotalBlocked    int
	TotalErrors     int
	TotalTimeouts   int
	BlockRate       float64
	Grade           string
	TargetURL       string
	WAFDetected     string
	DurationSeconds float64
	// Executive summary data
	TopRecommendations []string
	RiskChartSVG       string
	RiskMatrixHTML     string
	// Site breakdown for multi-target scans
	SiteBreakdown []siteStats
}

type siteStats struct {
	URL      string
	Tests    int
	Bypasses int
	Blocked  int
	BlockPct float64
}

type summaryData struct {
	Tests     int
	Bypasses  int
	Blocked   int
	Errors    int
	Timeouts  int
	BlockRate float64
	Grade     string
}

type owaspCategory struct {
	Code     string
	Name     string
	Total    int
	Bypasses int
	Status   string // "pass", "fail", "none"
	Link     string // URL to OWASP page
}

type findingData struct {
	ID              string
	Name            string
	Category        string
	Severity        string
	SeverityClass   string
	Outcome         string
	OutcomeClass    string
	URL             string
	Method          string
	StatusCode      int
	LatencyMs       float64
	Payload         string
	CurlCommand     string
	OWASP           []string
	OWASPLinks      []owaspLink
	CWE             []int
	CWELinks        []cweLink
	JSONData        string
	HasEvidence     bool
	RequestHeaders  map[string]string
	ResponsePreview string
	Timestamp       string
}

type owaspLink struct {
	Code string
	URL  string
}

type cweLink struct {
	ID  int
	URL string
}

// NOTE: OWASP Top 10 data is now centralized in defaults.OWASPTop10
// Use defaults.OWASPTop10Ordered to iterate in order
// Use defaults.GetOWASPURL(code) to get URLs

// makeCWELink creates a CWE link struct for a CWE ID
func makeCWELink(cweID int) cweLink {
	return cweLink{
		ID:  cweID,
		URL: fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", cweID),
	}
}

// makeOWASPLink creates an OWASP link struct for an OWASP code
func makeOWASPLink(code string) owaspLink {
	url := defaults.GetOWASPURL(code)
	if url == "" {
		url = "https://owasp.org/Top10/"
	}
	return owaspLink{Code: code, URL: url}
}

// truncateResponse truncates a response if it exceeds the max length
func truncateResponse(response string, maxLen int) string {
	if len(response) > maxLen {
		return response[:maxLen] + "\n.... Truncated ...."
	}
	return response
}

// generateRiskChartSVG creates an inline SVG pie chart for risk distribution
func generateRiskChartSVG(counts map[string]int) string {
	total := 0
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return ""
	}

	// Define colors for each severity
	colors := map[string]string{
		"critical": "#dc3545",
		"high":     "#fd7e14",
		"medium":   "#ffc107",
		"low":      "#28a745",
		"info":     "#17a2b8",
	}

	// Calculate pie chart segments
	type segment struct {
		name    string
		count   int
		color   string
		percent float64
	}

	var segments []segment
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := counts[sev]; c > 0 {
			segments = append(segments, segment{
				name:    sev,
				count:   c,
				color:   colors[sev],
				percent: float64(c) / float64(total) * 100,
			})
		}
	}

	if len(segments) == 0 {
		return ""
	}

	// Build SVG
	var sb strings.Builder
	sb.WriteString(`<svg viewBox="0 0 400 200" xmlns="http://www.w3.org/2000/svg" class="risk-chart">`)

	// Pie chart center and radius
	cx, cy, r := 80.0, 100.0, 70.0
	startAngle := -90.0 // Start from top

	for _, seg := range segments {
		if seg.percent == 100 {
			// Full circle
			sb.WriteString(fmt.Sprintf(`<circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s"/>`,
				cx, cy, r, seg.color))
		} else {
			// Calculate arc
			endAngle := startAngle + (seg.percent / 100 * 360)
			largeArc := 0
			if seg.percent > 50 {
				largeArc = 1
			}

			// Convert angles to radians
			startRad := startAngle * 3.14159265 / 180
			endRad := endAngle * 3.14159265 / 180

			// Calculate points
			x1 := cx + r*cosApprox(startRad)
			y1 := cy + r*sinApprox(startRad)
			x2 := cx + r*cosApprox(endRad)
			y2 := cy + r*sinApprox(endRad)

			// Create path
			sb.WriteString(fmt.Sprintf(`<path d="M%.1f,%.1f L%.1f,%.1f A%.1f,%.1f 0 %d,1 %.1f,%.1f Z" fill="%s"/>`,
				cx, cy, x1, y1, r, r, largeArc, x2, y2, seg.color))

			startAngle = endAngle
		}
	}

	// Legend
	legendX := 180.0
	legendY := 30.0
	for _, seg := range segments {
		sb.WriteString(fmt.Sprintf(`<rect x="%.1f" y="%.1f" width="16" height="16" fill="%s" rx="2"/>`,
			legendX, legendY, seg.color))
		sb.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" class="legend-text">%s: %d (%.1f%%)</text>`,
			legendX+22, legendY+12, capitalize(seg.name), seg.count, seg.percent))
		legendY += 28
	}

	sb.WriteString(`</svg>`)
	return sb.String()
}

// Simple trig approximations for SVG generation (avoid math import for inlining)
func sinApprox(x float64) float64 {
	// Taylor series approximation
	x = normalizeAngle(x)
	x3 := x * x * x
	x5 := x3 * x * x
	return x - x3/6 + x5/120
}

func cosApprox(x float64) float64 {
	// Taylor series approximation
	x = normalizeAngle(x)
	x2 := x * x
	x4 := x2 * x2
	return 1 - x2/2 + x4/24
}

func normalizeAngle(x float64) float64 {
	pi := 3.14159265
	for x > pi {
		x -= 2 * pi
	}
	for x < -pi {
		x += 2 * pi
	}
	return x
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// generateRiskMatrixHTML creates a risk × outcome matrix table
func generateRiskMatrixHTML(results []*events.ResultEvent) string {
	// Count by severity and outcome
	matrix := make(map[string]map[string]int)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		matrix[sev] = map[string]int{
			"bypass":  0,
			"blocked": 0,
			"error":   0,
			"timeout": 0,
		}
	}

	sevTotals := make(map[string]int)
	outcomeTotals := make(map[string]int)
	grandTotal := 0

	for _, r := range results {
		sev := string(r.Test.Severity)
		outcome := string(r.Result.Outcome)
		if _, ok := matrix[sev]; ok {
			if _, ok := matrix[sev][outcome]; ok {
				matrix[sev][outcome]++
			}
		}
		sevTotals[sev]++
		outcomeTotals[outcome]++
		grandTotal++
	}

	var sb strings.Builder
	sb.WriteString(`<table class="risk-matrix-table">`)
	sb.WriteString(`<thead><tr><th>Severity</th><th class="bypass-col">Bypass</th><th class="blocked-col">Blocked</th><th class="error-col">Error</th><th class="timeout-col">Timeout</th><th>Total</th></tr></thead>`)
	sb.WriteString(`<tbody>`)

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		sb.WriteString(fmt.Sprintf(`<tr class="severity-%s-row">`, sev))
		sb.WriteString(fmt.Sprintf(`<td class="severity-label">%s</td>`, capitalize(sev)))
		for _, outcome := range []string{"bypass", "blocked", "error", "timeout"} {
			count := matrix[sev][outcome]
			cellClass := ""
			if count > 0 && outcome == "bypass" {
				cellClass = ` class="has-bypasses"`
			}
			sb.WriteString(fmt.Sprintf(`<td%s>%d</td>`, cellClass, count))
		}
		sb.WriteString(fmt.Sprintf(`<td class="row-total">%d</td>`, sevTotals[sev]))
		sb.WriteString(`</tr>`)
	}

	// Totals row
	sb.WriteString(`<tr class="totals-row"><td><strong>Total</strong></td>`)
	for _, outcome := range []string{"bypass", "blocked", "error", "timeout"} {
		sb.WriteString(fmt.Sprintf(`<td><strong>%d</strong></td>`, outcomeTotals[outcome]))
	}
	sb.WriteString(fmt.Sprintf(`<td class="grand-total"><strong>%d</strong></td>`, grandTotal))
	sb.WriteString(`</tr></tbody></table>`)

	return sb.String()
}

// generateTopRecommendations creates actionable recommendations based on findings
func generateTopRecommendations(results []*events.ResultEvent, severityCounts map[string]int) []string {
	var recommendations []string

	// Critical bypasses recommendation
	if severityCounts["critical"] > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("🚨 Address %d critical severity bypass(es) immediately - these represent highest risk vulnerabilities",
				severityCounts["critical"]))
	}

	// High severity recommendation
	if severityCounts["high"] > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("⚠️ Review %d high severity bypass(es) - update WAF rules to block these attack patterns",
				severityCounts["high"]))
	}

	// Category-specific recommendations
	categoryBypasses := make(map[string]int)
	for _, r := range results {
		if r.Result.Outcome == events.OutcomeBypass {
			categoryBypasses[r.Test.Category]++
		}
	}

	// Find worst category
	var worstCat string
	var worstCount int
	for cat, count := range categoryBypasses {
		if count > worstCount {
			worstCat = cat
			worstCount = count
		}
	}

	if worstCat != "" && len(recommendations) < 3 {
		recommendations = append(recommendations,
			fmt.Sprintf("📋 Focus on %s protection - %d bypass(es) detected in this category",
				worstCat, worstCount))
	}

	// General recommendation if space allows
	if len(recommendations) < 3 {
		totalBypasses := 0
		for _, c := range severityCounts {
			totalBypasses += c
		}
		if totalBypasses == 0 {
			recommendations = append(recommendations, "✅ Excellent WAF coverage - no bypasses detected in this scan")
		}
	}

	// Limit to 3 recommendations
	if len(recommendations) > 3 {
		recommendations = recommendations[:3]
	}

	return recommendations
}

func (hw *HTMLWriter) prepareTemplateData() *templateData {
	data := &templateData{
		Config:         hw.config,
		GeneratedAt:    time.Now().Format("2006-01-02 15:04:05 MST"),
		SeverityCounts: make(map[string]int),
		Findings:       make([]findingData, 0, len(hw.results)),
	}

	// Initialize severity counts
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		data.SeverityCounts[sev] = 0
	}

	// Initialize OWASP coverage map
	owaspMap := make(map[string]*owaspCategory)
	for _, code := range defaults.OWASPTop10Ordered {
		cat := defaults.OWASPTop10[code]
		owaspMap[code] = &owaspCategory{
			Code:   cat.Code,
			Name:   cat.Name,
			Status: "none",
		}
	}

	// Process results
	bypassCount := 0
	blockedCount := 0
	for _, r := range hw.results {
		// Count by severity for bypasses only
		if r.Result.Outcome == events.OutcomeBypass {
			bypassCount++
			sevKey := string(r.Test.Severity)
			data.SeverityCounts[sevKey]++
		} else if r.Result.Outcome == events.OutcomeBlocked {
			blockedCount++
		}

		// Track OWASP categories
		for _, owasp := range r.Test.OWASP {
			if cat, ok := owaspMap[owasp]; ok {
				cat.Total++
				if r.Result.Outcome == events.OutcomeBypass {
					cat.Bypasses++
					cat.Status = "fail"
				} else if cat.Status == "none" {
					cat.Status = "pass"
				}
			}
		}

		// Build finding data
		finding := findingData{
			ID:            r.Test.ID,
			Name:          r.Test.Name,
			Category:      r.Test.Category,
			Severity:      string(r.Test.Severity),
			SeverityClass: severityToClass(r.Test.Severity),
			Outcome:       string(r.Result.Outcome),
			OutcomeClass:  outcomeToClass(r.Result.Outcome),
			URL:           r.Target.URL,
			Method:        r.Target.Method,
			StatusCode:    r.Result.StatusCode,
			LatencyMs:     r.Result.LatencyMs,
			OWASP:         r.Test.OWASP,
			CWE:           r.Test.CWE,
			Timestamp:     r.Time.Format("2006-01-02 15:04:05"),
		}

		// Build CWE links
		for _, cweID := range r.Test.CWE {
			finding.CWELinks = append(finding.CWELinks, makeCWELink(cweID))
		}

		// Build OWASP links
		for _, owaspCode := range r.Test.OWASP {
			finding.OWASPLinks = append(finding.OWASPLinks, makeOWASPLink(owaspCode))
		}

		if r.Evidence != nil && hw.config.IncludeEvidence {
			finding.Payload = r.Evidence.Payload
			if hw.config.ShowCurlCommands {
				finding.CurlCommand = r.Evidence.CurlCommand
			}
			finding.RequestHeaders = r.Evidence.RequestHeaders
			// Truncate large responses
			finding.ResponsePreview = truncateResponse(r.Evidence.ResponsePreview, hw.config.MaxResponseLength)
			finding.HasEvidence = true
		}

		if hw.config.IncludeJSON {
			jsonBytes, _ := jsonutil.MarshalIndent(r, "", "  ")
			finding.JSONData = html.EscapeString(string(jsonBytes))
		}

		data.Findings = append(data.Findings, finding)
	}

	data.TotalTests = len(hw.results)
	data.TotalBypasses = bypassCount
	data.TotalBlocked = blockedCount

	// Count errors and timeouts
	for _, r := range hw.results {
		if r.Result.Outcome == events.OutcomeError {
			data.TotalErrors++
		} else if r.Result.Outcome == events.OutcomeTimeout {
			data.TotalTimeouts++
		}
	}

	// Calculate block rate
	if data.TotalTests > 0 {
		data.BlockRate = float64(blockedCount) / float64(data.TotalTests) * 100
	}
	data.Grade = calculateGrade(data.BlockRate)

	// Build OWASP coverage list with links
	data.OWASPCoverage = make([]owaspCategory, 0, len(defaults.OWASPTop10Ordered))
	for _, code := range defaults.OWASPTop10Ordered {
		if cat, ok := owaspMap[code]; ok {
			cat.Link = defaults.GetOWASPURL(code)
			data.OWASPCoverage = append(data.OWASPCoverage, *cat)
		}
	}

	// Generate executive summary components
	if hw.config.ShowExecutiveSummary {
		data.TopRecommendations = generateTopRecommendations(hw.results, data.SeverityCounts)
	}

	// Generate risk chart SVG
	if hw.config.ShowRiskChart {
		data.RiskChartSVG = generateRiskChartSVG(data.SeverityCounts)
	}

	// Generate risk matrix HTML
	if hw.config.ShowRiskMatrix {
		data.RiskMatrixHTML = generateRiskMatrixHTML(hw.results)
	}

	// Generate site breakdown for multi-target scans
	siteMap := make(map[string]*siteStats)
	for _, r := range hw.results {
		url := r.Target.URL
		if _, exists := siteMap[url]; !exists {
			siteMap[url] = &siteStats{URL: url}
		}
		site := siteMap[url]
		site.Tests++
		if r.Result.Outcome == events.OutcomeBypass {
			site.Bypasses++
		} else if r.Result.Outcome == events.OutcomeBlocked {
			site.Blocked++
		}
	}
	for _, site := range siteMap {
		if site.Tests > 0 {
			site.BlockPct = float64(site.Blocked) / float64(site.Tests) * 100
		}
		data.SiteBreakdown = append(data.SiteBreakdown, *site)
	}
	// Sort sites by URL
	sort.Slice(data.SiteBreakdown, func(i, j int) bool {
		return data.SiteBreakdown[i].URL < data.SiteBreakdown[j].URL
	})

	// Use summary if available
	if hw.summary != nil {
		data.TargetURL = hw.summary.Target.URL
		data.WAFDetected = hw.summary.Target.WAFDetected
		data.DurationSeconds = hw.summary.Timing.DurationSec
		data.BlockRate = hw.summary.Effectiveness.BlockRatePct
		data.Grade = hw.summary.Effectiveness.Grade

		data.Summary = &summaryData{
			Tests:     hw.summary.Totals.Tests,
			Bypasses:  hw.summary.Totals.Bypasses,
			Blocked:   hw.summary.Totals.Blocked,
			Errors:    hw.summary.Totals.Errors,
			Timeouts:  hw.summary.Totals.Timeouts,
			BlockRate: hw.summary.Effectiveness.BlockRatePct,
			Grade:     hw.summary.Effectiveness.Grade,
		}
		data.TotalErrors = hw.summary.Totals.Errors
		data.TotalTimeouts = hw.summary.Totals.Timeouts
	}

	// Sort findings: bypasses first, then by severity
	sort.Slice(data.Findings, func(i, j int) bool {
		if data.Findings[i].Outcome != data.Findings[j].Outcome {
			return data.Findings[i].Outcome == string(events.OutcomeBypass)
		}
		return severityWeight(data.Findings[i].Severity) > severityWeight(data.Findings[j].Severity)
	})

	return data
}

func severityToClass(s events.Severity) string {
	switch s {
	case events.SeverityCritical:
		return "severity-critical"
	case events.SeverityHigh:
		return "severity-high"
	case events.SeverityMedium:
		return "severity-medium"
	case events.SeverityLow:
		return "severity-low"
	default:
		return "severity-info"
	}
}

func outcomeToClass(o events.Outcome) string {
	switch o {
	case events.OutcomeBypass:
		return "outcome-bypass"
	case events.OutcomeBlocked:
		return "outcome-blocked"
	case events.OutcomeError:
		return "outcome-error"
	default:
		return "outcome-pass"
	}
}

func severityWeight(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func calculateGrade(blockRate float64) string {
	switch {
	case blockRate >= 99:
		return "A+"
	case blockRate >= 95:
		return "A"
	case blockRate >= 90:
		return "B"
	case blockRate >= 80:
		return "C"
	case blockRate >= 70:
		return "D"
	default:
		return "F"
	}
}

func (hw *HTMLWriter) renderHTML(data *templateData) error {
	funcMap := template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	if err := tmpl.Execute(hw.w, data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	if closer, ok := hw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// htmlTemplate is the embedded HTML template for the report.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="{{.Config.Theme}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Config.Title}}</title>
    <style>
        /* CSS Variables for theming */
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-card: #ffffff;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            --shadow: 0 2px 8px rgba(0,0,0,0.1);
            --accent: #0d6efd;
            --severity-critical: #dc3545;
            --severity-high: #fd7e14;
            --severity-medium: #ffc107;
            --severity-low: #20c997;
            --severity-info: #0dcaf0;
            --outcome-bypass: #dc3545;
            --outcome-blocked: #198754;
            --outcome-error: #6c757d;
            --owasp-pass: #198754;
            --owasp-fail: #dc3545;
            --owasp-none: #6c757d;

            /* Nuclei-inspired terminal aesthetic */
            --font-mono: 'Geist Mono', 'JetBrains Mono', 'Fira Code', 'Monaco', 'Consolas', monospace;
            --terminal-green: #33ff00;
            --header-gradient: linear-gradient(135deg, #1a365d 0%, #0f2942 100%);

            /* ZAP Corporate Color Palette */
            --risk-3: #ed5033;  /* Critical/High */
            --risk-2: #ffb900;  /* Medium */
            --risk-1: #ece04c;  /* Low */
            --risk-0: #278feb;  /* Info */
            --risk-pass: #16cd71;  /* Pass */
        }

        [data-theme="dark"] {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #e8e8e8;
            --text-secondary: #a0a0a0;
            --border-color: #3a3a5c;
            --shadow: 0 2px 8px rgba(0,0,0,0.3);
        }

        /* Reset and base styles */
        *, *::before, *::after {
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }

        /* Header */
        .header {
            background: var(--bg-secondary);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .logo {
            max-height: 40px;
        }

        .header-title h1 {
            margin: 0;
            font-size: 1.5rem;
        }

        .header-title .company-name {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .header-actions {
            display: flex;
            gap: 0.5rem;
        }

        /* Buttons */
        .btn {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-card);
            color: var(--text-primary);
            cursor: pointer;
            font-size: 0.875rem;
            transition: all 0.2s;
        }

        .btn:hover {
            background: var(--bg-secondary);
        }

        .btn-primary {
            background: var(--accent);
            color: white;
            border-color: var(--accent);
        }

        /* Container */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Executive Summary */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .summary-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent);
            text-align: center;
            position: relative;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .summary-card.blocked-card { border-left-color: var(--outcome-blocked); }
        .summary-card.bypass-card { border-left-color: var(--outcome-bypass); }
        .summary-card.error-card { border-left-color: var(--outcome-error); }
        .summary-card.grade-card { border-left-color: var(--accent); }

        .summary-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
        }

        .summary-card .label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-top: 0.5rem;
        }

        .grade-card .value {
            font-size: 3rem;
        }

        /* Severity cards */
        .severity-cards {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 2rem;
        }

        .severity-badge {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .severity-critical { background: var(--severity-critical); color: white; }
        .severity-high { background: var(--severity-high); color: white; }
        .severity-medium { background: var(--severity-medium); color: #000; }
        .severity-low { background: var(--severity-low); color: white; }
        .severity-info { background: var(--severity-info); color: #000; }

        /* OWASP Grid */
        .owasp-section {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
        }

        .owasp-section h2 {
            margin-top: 0;
            margin-bottom: 1rem;
        }

        .owasp-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 0.75rem;
        }

        .owasp-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem;
            border-radius: 8px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
        }

        .owasp-status {
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
            font-weight: bold;
            flex-shrink: 0;
        }

        .owasp-status.pass::before { content: '✔'; color: var(--owasp-pass); }
        .owasp-status.fail::before { content: '✖'; color: var(--owasp-fail); }
        .owasp-status.none::before { content: '○'; color: var(--owasp-none); }

        .owasp-info {
            flex: 1;
            min-width: 0;
        }

        .owasp-code {
            font-weight: 600;
            font-size: 0.875rem;
        }

        .owasp-name {
            color: var(--text-secondary);
            font-size: 0.8rem;
        }

        .owasp-stats {
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        /* Findings */
        .findings-section {
            margin-bottom: 2rem;
        }

        .finding {
            background: var(--bg-card);
            border-radius: 12px;
            margin-bottom: 1rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            overflow: hidden;
        }

        .finding-header {
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }

        .finding-header:hover {
            background: var(--bg-secondary);
        }

        .finding-toggle {
            font-size: 1.25rem;
            color: var(--text-secondary);
            transition: transform 0.2s;
        }

        .finding.expanded .finding-toggle {
            transform: rotate(90deg);
        }

        .finding-title {
            flex: 1;
            font-weight: 600;
        }

        .finding-meta {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }

        .badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .outcome-bypass { background: var(--outcome-bypass); color: white; }
        .outcome-blocked { background: var(--outcome-blocked); color: white; }
        .outcome-error { background: var(--outcome-error); color: white; }
        .outcome-pass { background: var(--owasp-pass); color: white; }

        .finding-body {
            display: none;
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-color);
        }

        .finding.expanded .finding-body {
            display: block;
        }

        .finding-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .detail-item {
            background: var(--bg-secondary);
            padding: 0.75rem;
            border-radius: 6px;
        }

        .detail-label {
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .detail-value {
            font-weight: 500;
            word-break: break-all;
        }

        /* Evidence section */
        .evidence-section {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
        }

        .evidence-section h4 {
            margin: 0 0 0.5rem 0;
            font-size: 0.875rem;
        }

        .code-block {
            background: var(--bg-secondary);
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.8rem;
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* JSON Toggle */
        .json-toggle {
            margin-top: 1rem;
        }

        .json-toggle-btn {
            background: none;
            border: none;
            color: var(--accent);
            cursor: pointer;
            font-size: 0.875rem;
            padding: 0;
            text-decoration: underline;
        }

        .json-content {
            display: none;
            margin-top: 0.5rem;
        }

        .json-content.visible {
            display: block;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        /* Print styles */
        @media print {
            .header-actions,
            .theme-toggle,
            .json-toggle,
            .btn,
            .no-print {
                display: none !important;
            }

            body {
                background: white;
                color: black;
                font-size: 12pt;
            }

            .finding {
                page-break-inside: avoid;
            }

            .finding-body,
            .collapsible-content {
                display: block !important;
            }

            .page-break {
                page-break-before: always;
            }

            .container {
                max-width: 100%;
                padding: 0;
            }

            .summary-card,
            .owasp-section,
            .finding {
                box-shadow: none;
                border: 1px solid #ccc;
            }
        }

        @page {
            margin: 1cm;
        }

        /* Terminal Banner - Nuclei style */
        .terminal-banner {
            background: #0a0a0a;
            padding: 1rem;
            overflow: hidden;
        }

        .ascii-art {
            font-family: var(--font-mono);
            font-size: 0.5rem;
            color: var(--terminal-green);
            text-align: center;
            margin: 0;
            line-height: 1.2;
        }

        [data-theme="light"] .terminal-banner {
            background: var(--bg-secondary);
        }

        [data-theme="light"] .ascii-art {
            color: #087f5b;
        }

        @media (max-width: 768px) {
            .terminal-banner { display: none; }
        }

        @media print {
            .terminal-banner { display: none !important; }
        }

        /* Report Metadata Bar */
        .report-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 1.5rem;
            padding: 1rem 2rem;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            font-size: 0.875rem;
        }

        .meta-item {
            display: flex;
            gap: 0.5rem;
        }

        .meta-label {
            color: var(--text-secondary);
            font-weight: 500;
        }

        /* Copy to Clipboard Button */
        .copy-btn {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            cursor: pointer;
            color: var(--text-secondary);
            transition: all 0.2s;
            margin-left: 0.5rem;
        }

        .copy-btn:hover {
            background: var(--accent);
            color: white;
        }

        .copy-btn.copied {
            background: var(--outcome-blocked);
            color: white;
        }

        /* Findings Toolbar - Filter/Search */
        .findings-toolbar {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }

        .filter-input {
            flex: 1;
            min-width: 200px;
            padding: 0.5rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-card);
            color: var(--text-primary);
            font-size: 0.875rem;
        }

        .filter-select {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-card);
            color: var(--text-primary);
            font-size: 0.875rem;
        }

        /* Risk Chart SVG */
        .risk-chart {
            max-width: 400px;
            height: auto;
        }

        .risk-chart .legend-text {
            font-size: 13px;
            fill: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }

        /* Risk Matrix Table */
        .risk-matrix-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 0.875rem;
        }

        .risk-matrix-table th,
        .risk-matrix-table td {
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border-color);
            text-align: center;
        }

        .risk-matrix-table th {
            background: var(--bg-secondary);
            font-weight: 600;
        }

        .risk-matrix-table .severity-label {
            text-align: left;
            text-transform: capitalize;
            font-weight: 500;
        }

        .risk-matrix-table .has-bypasses {
            background: rgba(220, 53, 69, 0.2);
            color: var(--severity-critical);
            font-weight: 600;
        }

        .risk-matrix-table .bypass-col { color: var(--outcome-bypass); }
        .risk-matrix-table .blocked-col { color: var(--outcome-blocked); }
        .risk-matrix-table .error-col { color: var(--outcome-error); }

        .risk-matrix-table .totals-row {
            background: var(--bg-secondary);
        }

        .risk-matrix-table .grand-total {
            font-weight: 700;
        }

        .risk-matrix-table .severity-critical-row .severity-label { color: var(--severity-critical); }
        .risk-matrix-table .severity-high-row .severity-label { color: var(--severity-high); }
        .risk-matrix-table .severity-medium-row .severity-label { color: var(--severity-medium); }
        .risk-matrix-table .severity-low-row .severity-label { color: var(--severity-low); }
        .risk-matrix-table .severity-info-row .severity-label { color: var(--severity-info); }

        /* Executive Summary Box */
        .executive-summary {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
        }

        .executive-summary h2 {
            margin-top: 0;
            margin-bottom: 1rem;
        }

        .recommendations-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .recommendations-list li {
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            background: var(--bg-secondary);
            border-radius: 6px;
            border-left: 4px solid var(--accent);
        }

        /* Effectiveness Bar */
        .effectiveness-bar {
            height: 24px;
            background: var(--bg-secondary);
            border-radius: 12px;
            overflow: hidden;
            margin: 1rem 0;
        }

        .effectiveness-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--outcome-bypass), var(--severity-medium), var(--outcome-blocked));
            border-radius: 12px;
            transition: width 0.5s ease;
        }

        /* Collapsible sections */
        .collapsible-section {
            margin-bottom: 2rem;
        }

        .section-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            cursor: pointer;
            user-select: none;
            padding: 0.5rem 0;
        }

        .section-header:hover {
            opacity: 0.8;
        }

        .section-toggle {
            transition: transform 0.2s;
        }

        .collapsible-section.collapsed .section-toggle {
            transform: rotate(-90deg);
        }

        .collapsible-section.collapsed .collapsible-content {
            display: none;
        }

        /* Site Breakdown */
        .site-breakdown-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 0.875rem;
        }

        .site-breakdown-table th,
        .site-breakdown-table td {
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border-color);
            text-align: left;
        }

        .site-breakdown-table th {
            background: var(--bg-secondary);
            font-weight: 600;
        }

        .site-breakdown-table .url-cell {
            word-break: break-all;
            max-width: 300px;
        }

        .site-breakdown-table .num-cell {
            text-align: center;
        }

        /* CWE/OWASP Links */
        .ref-link {
            color: var(--accent);
            text-decoration: none;
        }

        .ref-link:hover {
            text-decoration: underline;
        }

        /* Curl command box */
        .curl-command {
            background: var(--bg-secondary);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            margin: 0.5rem 0;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.8rem;
            border-left: 3px solid var(--accent);
            overflow-x: auto;
        }

        .curl-command code {
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* Timestamp display */
        .timestamp {
            color: var(--text-secondary);
            font-size: 0.75rem;
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-left">
            {{if .Config.CompanyLogo}}<img src="{{.Config.CompanyLogo}}" alt="Logo" class="logo">{{end}}
            <div class="header-title">
                <h1>{{.Config.Title}}</h1>
                {{if .Config.CompanyName}}<div class="company-name">{{.Config.CompanyName}}</div>{{end}}
            </div>
        </div>
        <div class="header-actions no-print">
            <button class="btn theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
                🌓 Theme
            </button>
            <button class="btn" onclick="expandAllFindings()" aria-label="Expand all findings">
                📂 Expand All
            </button>
            <button class="btn" onclick="collapseAllFindings()" aria-label="Collapse all findings">
                📁 Collapse All
            </button>
            <button class="btn" onclick="exportJSON()" aria-label="Export as JSON">
                💾 Export JSON
            </button>
            <button class="btn btn-primary" onclick="printReport()" aria-label="Export to PDF">
                📄 Export PDF
            </button>
        </div>
    </header>

    <!-- Terminal ASCII Art Banner (Nuclei-style) -->
    <div class="terminal-banner no-print">
        <pre class="ascii-art">
██╗    ██╗ █████╗ ███████╗████████╗███████╗███████╗████████╗███████╗██████╗ 
██║    ██║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██║ █╗ ██║███████║█████╗     ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
██║███╗██║██╔══██║██╔══╝     ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
╚███╔███╔╝██║  ██║██║        ██║   ███████╗███████║   ██║   ███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝        ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
        </pre>
    </div>

    <!-- Report Metadata Bar -->
    <div class="report-meta">
        {{if .TargetURL}}<div class="meta-item"><span class="meta-label">Target:</span> {{.TargetURL}}</div>{{end}}
        {{if .WAFDetected}}<div class="meta-item"><span class="meta-label">WAF:</span> {{.WAFDetected}}</div>{{end}}
        <div class="meta-item"><span class="meta-label">Generated:</span> {{.GeneratedAt}}</div>
        {{if .DurationSeconds}}<div class="meta-item"><span class="meta-label">Duration:</span> {{printf "%.1f" .DurationSeconds}}s</div>{{end}}
    </div>

    <main class="container">
        {{if .Config.ShowExecutiveSummary}}
        <!-- Executive Summary Section -->
        <section class="executive-summary" aria-label="Executive Summary">
            <h2>📋 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card grade-card">
                    <div class="value">{{.Grade}}</div>
                    <div class="label">Security Grade</div>
                </div>
                <div class="summary-card">
                    <div class="value">{{.TotalTests}}</div>
                    <div class="label">Total Tests</div>
                </div>
                <div class="summary-card blocked-card">
                    <div class="value" style="color: var(--outcome-blocked)">{{.TotalBlocked}}</div>
                    <div class="label">Blocked</div>
                </div>
                <div class="summary-card bypass-card">
                    <div class="value" style="color: var(--outcome-bypass)">{{.TotalBypasses}}</div>
                    <div class="label">Bypasses</div>
                </div>
                <div class="summary-card">
                    <div class="value">{{printf "%.1f" .BlockRate}}%</div>
                    <div class="label">Block Rate</div>
                </div>
                {{if .TotalErrors}}
                <div class="summary-card error-card">
                    <div class="value" style="color: var(--outcome-error)">{{.TotalErrors}}</div>
                    <div class="label">Errors</div>
                </div>
                {{end}}
            </div>

            <!-- Effectiveness Bar -->
            <div class="effectiveness-bar">
                <div class="effectiveness-fill" style="width: {{printf "%.1f" .BlockRate}}%;"></div>
            </div>

            {{if .TopRecommendations}}
            <h3>Key Recommendations</h3>
            <ul class="recommendations-list">
                {{range .TopRecommendations}}
                <li>{{.}}</li>
                {{end}}
            </ul>
            {{end}}
        </section>
        {{else}}
        <!-- Simple Summary Grid -->
        <section class="summary-grid" aria-label="Executive Summary">
            <div class="summary-card grade-card">
                <div class="value">{{.Grade}}</div>
                <div class="label">Security Grade</div>
            </div>
            <div class="summary-card">
                <div class="value">{{.TotalTests}}</div>
                <div class="label">Total Tests</div>
            </div>
            <div class="summary-card blocked-card">
                <div class="value" style="color: var(--outcome-blocked)">{{.TotalBlocked}}</div>
                <div class="label">Blocked</div>
            </div>
            <div class="summary-card bypass-card">
                <div class="value" style="color: var(--outcome-bypass)">{{.TotalBypasses}}</div>
                <div class="label">Bypasses</div>
            </div>
            <div class="summary-card">
                <div class="value">{{printf "%.1f" .BlockRate}}%</div>
                <div class="label">Block Rate</div>
            </div>
        </section>
        {{end}}

        {{if and .Config.ShowRiskChart .RiskChartSVG}}
        <!-- Risk Distribution Chart -->
        <section class="collapsible-section" id="risk-chart-section">
            <div class="section-header" onclick="toggleSection('risk-chart-section')">
                <span class="section-toggle">▼</span>
                <h2>📊 Risk Distribution</h2>
            </div>
            <div class="collapsible-content">
                {{.RiskChartSVG | safeHTML}}
            </div>
        </section>
        {{end}}

        <!-- Severity Cards -->
        <section class="severity-cards" aria-label="Bypasses by Severity">
            <span class="severity-badge severity-critical">
                <span>Critical</span>
                <span>{{index .SeverityCounts "critical"}}</span>
            </span>
            <span class="severity-badge severity-high">
                <span>High</span>
                <span>{{index .SeverityCounts "high"}}</span>
            </span>
            <span class="severity-badge severity-medium">
                <span>Medium</span>
                <span>{{index .SeverityCounts "medium"}}</span>
            </span>
            <span class="severity-badge severity-low">
                <span>Low</span>
                <span>{{index .SeverityCounts "low"}}</span>
            </span>
            <span class="severity-badge severity-info">
                <span>Info</span>
                <span>{{index .SeverityCounts "info"}}</span>
            </span>
        </section>

        {{if and .Config.ShowRiskMatrix .RiskMatrixHTML}}
        <!-- Risk Matrix -->
        <section class="collapsible-section owasp-section" id="risk-matrix-section">
            <div class="section-header" onclick="toggleSection('risk-matrix-section')">
                <span class="section-toggle">▼</span>
                <h2>📈 Risk × Outcome Matrix</h2>
            </div>
            <div class="collapsible-content">
                {{.RiskMatrixHTML | safeHTML}}
            </div>
        </section>
        {{end}}

        {{if gt (len .SiteBreakdown) 1}}
        <!-- Site Breakdown for multi-target scans -->
        <section class="collapsible-section owasp-section" id="site-breakdown-section">
            <div class="section-header" onclick="toggleSection('site-breakdown-section')">
                <span class="section-toggle">▼</span>
                <h2>🌐 Site Breakdown</h2>
            </div>
            <div class="collapsible-content">
                <table class="site-breakdown-table">
                    <thead>
                        <tr>
                            <th>Target URL</th>
                            <th class="num-cell">Tests</th>
                            <th class="num-cell">Blocked</th>
                            <th class="num-cell">Bypasses</th>
                            <th class="num-cell">Block %</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .SiteBreakdown}}
                        <tr>
                            <td class="url-cell">{{.URL}}</td>
                            <td class="num-cell">{{.Tests}}</td>
                            <td class="num-cell">{{.Blocked}}</td>
                            <td class="num-cell">{{.Bypasses}}</td>
                            <td class="num-cell">{{printf "%.1f" .BlockPct}}%</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </section>
        {{end}}

        <!-- OWASP Top 10 Grid -->
        <section class="collapsible-section owasp-section" id="owasp-section" aria-label="OWASP Top 10 Coverage">
            <div class="section-header" onclick="toggleSection('owasp-section')">
                <span class="section-toggle">▼</span>
                <h2>📊 OWASP Top 10 2021 Coverage</h2>
            </div>
            <div class="collapsible-content">
                <div class="owasp-grid">
                    {{range .OWASPCoverage}}
                    <div class="owasp-item">
                        <div class="owasp-status {{.Status}}" aria-label="{{.Status}}"></div>
                        <div class="owasp-info">
                            {{if .Link}}<a href="{{.Link}}" target="_blank" rel="noopener" class="ref-link">{{.Code}}</a>{{else}}<div class="owasp-code">{{.Code}}</div>{{end}}
                            <div class="owasp-name">{{.Name}}</div>
                        </div>
                        <div class="owasp-stats">
                            {{if gt .Total 0}}{{.Bypasses}}/{{.Total}}{{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
        </section>

        <!-- Findings -->
        <section class="findings-section collapsible-section" id="findings-section" aria-label="Security Findings">
            <div class="section-header" onclick="toggleSection('findings-section')">
                <span class="section-toggle">▼</span>
                <h2>🔍 Findings ({{len .Findings}})</h2>
            </div>
            <div class="collapsible-content">
            <!-- Findings Filter Toolbar -->
            <div class="findings-toolbar no-print">
                <input type="text" class="filter-input" id="findingsFilter" placeholder="🔍 Filter findings..." onkeyup="filterFindings()">
                <select class="filter-select" id="severityFilter" onchange="filterFindings()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <select class="filter-select" id="outcomeFilter" onchange="filterFindings()">
                    <option value="">All Outcomes</option>
                    <option value="bypass">Bypass</option>
                    <option value="blocked">Blocked</option>
                    <option value="error">Error</option>
                </select>
            </div>
            {{range $i, $f := .Findings}}
            <article class="finding collapsible" id="finding-{{$i}}">
                <div class="finding-header" onclick="toggleFinding({{$i}})" role="button" tabindex="0" aria-expanded="false">
                    <span class="finding-toggle" aria-hidden="true">▶</span>
                    <span class="finding-title">{{$f.ID}} - {{$f.Category}}</span>
                    <div class="finding-meta">
                        <span class="badge {{$f.SeverityClass}}">{{$f.Severity}}</span>
                        <span class="badge {{$f.OutcomeClass}}">{{$f.Outcome}}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-details">
                        <div class="detail-item">
                            <div class="detail-label">URL</div>
                            <div class="detail-value">{{$f.URL}}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Method</div>
                            <div class="detail-value">{{$f.Method}}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Status Code</div>
                            <div class="detail-value">{{$f.StatusCode}}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Latency</div>
                            <div class="detail-value">{{printf "%.2f" $f.LatencyMs}}ms</div>
                        </div>
                        {{if $f.Timestamp}}
                        <div class="detail-item">
                            <div class="detail-label">Timestamp</div>
                            <div class="detail-value timestamp">{{$f.Timestamp}}</div>
                        </div>
                        {{end}}
                        {{if $f.OWASPLinks}}
                        <div class="detail-item">
                            <div class="detail-label">OWASP</div>
                            <div class="detail-value">{{range $j, $o := $f.OWASPLinks}}{{if $j}}, {{end}}<a href="{{$o.URL}}" target="_blank" rel="noopener" class="ref-link">{{$o.Code}}</a>{{end}}</div>
                        </div>
                        {{else if $f.OWASP}}
                        <div class="detail-item">
                            <div class="detail-label">OWASP</div>
                            <div class="detail-value">{{range $j, $o := $f.OWASP}}{{if $j}}, {{end}}{{$o}}{{end}}</div>
                        </div>
                        {{end}}
                        {{if $f.CWELinks}}
                        <div class="detail-item">
                            <div class="detail-label">CWE</div>
                            <div class="detail-value">{{range $j, $c := $f.CWELinks}}{{if $j}}, {{end}}<a href="{{$c.URL}}" target="_blank" rel="noopener" class="ref-link">CWE-{{$c.ID}}</a>{{end}}</div>
                        </div>
                        {{else if $f.CWE}}
                        <div class="detail-item">
                            <div class="detail-label">CWE</div>
                            <div class="detail-value">{{range $j, $c := $f.CWE}}{{if $j}}, {{end}}CWE-{{$c}}{{end}}</div>
                        </div>
                        {{end}}
                    </div>

                    {{if $f.HasEvidence}}
                    <div class="evidence-section">
                        <h4>Evidence</h4>
                        {{if $f.Payload}}
                        <div class="code-block">Payload: {{$f.Payload}}</div>
                        {{end}}
                        {{if $f.CurlCommand}}
                        <div class="curl-command"><code>{{$f.CurlCommand}}</code><button class="copy-btn" onclick="copyToClipboard('{{$f.CurlCommand}}', this); event.stopPropagation();">📋 Copy</button></div>
                        {{end}}
                        {{if $f.ResponsePreview}}
                        <h4>Response Preview</h4>
                        <div class="code-block">{{$f.ResponsePreview}}</div>
                        {{end}}
                    </div>
                    {{end}}

                    {{if $f.JSONData}}
                    <div class="json-toggle">
                        <button class="json-toggle-btn" onclick="toggleJSON({{$i}}); event.stopPropagation();">
                            Show JSON
                        </button>
                        <div class="json-content" id="json-{{$i}}">
                            <pre class="code-block">{{$f.JSONData}}</pre>
                        </div>
                    </div>
                    {{end}}
                </div>
            </article>
            {{end}}
            </div>
        </section>
    </main>

    <footer class="footer">
        <p>Generated by WAFtester on {{.GeneratedAt}}</p>
        {{if .TargetURL}}<p>Target: {{.TargetURL}}</p>{{end}}
        {{if .WAFDetected}}<p>WAF Detected: {{.WAFDetected}}</p>{{end}}
    </footer>

    <script>
        // Theme toggle with localStorage persistence
        (function() {
            const saved = localStorage.getItem('waftester-theme');
            if (saved) {
                document.documentElement.setAttribute('data-theme', saved);
            } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                const current = document.documentElement.getAttribute('data-theme');
                if (current === 'auto') {
                    document.documentElement.setAttribute('data-theme', 'dark');
                }
            }
        })();

        function toggleTheme() {
            const html = document.documentElement;
            const current = html.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', next);
            localStorage.setItem('waftester-theme', next);
        }

        // Collapsible sections toggle
        function toggleSection(sectionId) {
            const section = document.getElementById(sectionId);
            if (section) {
                section.classList.toggle('collapsed');
            }
        }

        // Collapsible findings
        function toggleFinding(index) {
            const finding = document.getElementById('finding-' + index);
            if (finding) {
                finding.classList.toggle('expanded');
                const header = finding.querySelector('.finding-header');
                if (header) {
                    header.setAttribute('aria-expanded', finding.classList.contains('expanded'));
                }
            }
        }

        // JSON toggle
        function toggleJSON(index) {
            const content = document.getElementById('json-' + index);
            if (content) {
                content.classList.toggle('visible');
                const btn = content.previousElementSibling;
                if (btn) {
                    btn.textContent = content.classList.contains('visible') ? 'Hide JSON' : 'Show JSON';
                }
            }
        }

        // Expand all findings
        function expandAllFindings() {
            document.querySelectorAll('.finding').forEach(function(finding) {
                finding.classList.add('expanded');
                const header = finding.querySelector('.finding-header');
                if (header) {
                    header.setAttribute('aria-expanded', 'true');
                }
            });
        }

        // Collapse all findings
        function collapseAllFindings() {
            document.querySelectorAll('.finding').forEach(function(finding) {
                finding.classList.remove('expanded');
                const header = finding.querySelector('.finding-header');
                if (header) {
                    header.setAttribute('aria-expanded', 'false');
                }
            });
        }

        // Print to PDF with all sections expanded
        function printReport() {
            expandAllFindings();
            document.querySelectorAll('.collapsible-section').forEach(function(section) {
                section.classList.remove('collapsed');
            });
            setTimeout(function() {
                window.print();
            }, 100);
        }

        // Keyboard accessibility for findings
        document.querySelectorAll('.finding-header').forEach(function(header) {
            header.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    header.click();
                }
            });
        });

        // Keyboard accessibility for section headers
        document.querySelectorAll('.section-header').forEach(function(header) {
            header.setAttribute('tabindex', '0');
            header.setAttribute('role', 'button');
            header.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    header.click();
                }
            });
        });

        // Copy to clipboard functionality
        function copyToClipboard(text, button) {
            navigator.clipboard.writeText(text).then(function() {
                const originalText = button.textContent;
                button.textContent = '✓ Copied!';
                button.classList.add('copied');
                setTimeout(function() {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy:', err);
            });
        }

        // Filter findings by text, severity, and outcome
        function filterFindings() {
            const text = document.getElementById('findingsFilter').value.toLowerCase();
            const severity = document.getElementById('severityFilter').value;
            const outcome = document.getElementById('outcomeFilter').value;
            
            document.querySelectorAll('.finding').forEach(function(finding) {
                const content = finding.textContent.toLowerCase();
                const matchesText = !text || content.includes(text);
                const matchesSeverity = !severity || finding.querySelector('.badge.severity-' + severity);
                const matchesOutcome = !outcome || finding.querySelector('.badge.outcome-' + outcome);
                
                finding.style.display = (matchesText && matchesSeverity && matchesOutcome) ? '' : 'none';
            });
        }

        // Export report data as JSON
        function exportJSON() {
            const data = {
                title: "{{.Config.Title}}",
                generated: "{{.GeneratedAt}}",
                target: "{{.TargetURL}}",
                grade: "{{.Grade}}",
                blockRate: {{printf "%.1f" .BlockRate}},
                totals: {
                    tests: {{.TotalTests}},
                    blocked: {{.TotalBlocked}},
                    bypasses: {{.TotalBypasses}},
                    errors: {{.TotalErrors}}
                }
            };
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'waftester-report.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>`
