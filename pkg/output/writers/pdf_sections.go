// Package writers provides output writers for various formats.
package writers

import (
	"fmt"
	"sort"
	"strings"

	gofpdf "github.com/go-pdf/fpdf"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/output/events"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// addSeverityConfidenceMatrix renders a 2D cross-tabulation of bypass counts
// by severity (rows) and confidence (columns). Gives reviewers a quick view
// of which findings are both high-severity AND high-confidence.
func (pw *PDFWriter) addSeverityConfidenceMatrix(pdf *gofpdf.Fpdf) {
	if len(pw.results) == 0 {
		return
	}

	// Build the matrix: severity → confidence → count (bypasses only).
	type cell struct{ sev, conf string }
	counts := make(map[cell]int)
	for _, r := range pw.results {
		if r.Result.Outcome != events.OutcomeBypass {
			continue
		}
		sev := string(r.Test.Severity)
		conf := string(r.Result.Confidence)
		if conf == "" {
			conf = "unknown"
		}
		counts[cell{sev, conf}]++
	}

	// If no bypasses at all, skip the section entirely.
	if len(counts) == 0 {
		return
	}

	pdf.AddPage()
	pw.addSectionHeader(pdf, "Severity vs Confidence Matrix")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.MultiCell(0, 5, "Cross-tabulation of bypass findings by severity and detection confidence. "+
		"Cells with high severity and high confidence represent confirmed, exploitable vulnerabilities "+
		"that should be prioritized for remediation.", "", "L", false)
	pdf.Ln(5)

	sevOrder := finding.OrderedStrings()
	confOrder := []string{"certain", "high", "medium", "low", "tentative", "unknown"}

	// Prune empty columns.
	activeConf := make([]string, 0, len(confOrder))
	for _, c := range confOrder {
		for _, s := range sevOrder {
			if counts[cell{s, c}] > 0 {
				activeConf = append(activeConf, c)
				break
			}
		}
	}
	if len(activeConf) == 0 {
		return
	}

	titleCase := cases.Title(language.English)
	pageW, _ := pdf.GetPageSize()
	labelW := 30.0
	cellW := (pageW - 30 - labelW) / float64(len(activeConf))
	if cellW > 35 {
		cellW = 35
	}

	// Header row.
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(30, 41, 59)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(labelW, 8, "Severity", "1", 0, "C", true, 0, "")
	for _, c := range activeConf {
		pdf.CellFormat(cellW, 8, titleCase.String(c), "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// Data rows.
	pdf.SetFont("Helvetica", "", 9)
	for _, sev := range sevOrder {
		// Skip severity rows that have no data.
		hasRow := false
		for _, c := range activeConf {
			if counts[cell{sev, c}] > 0 {
				hasRow = true
				break
			}
		}
		if !hasRow {
			continue
		}

		sevColor := pdfSeverityColors[sev]
		if sevColor == nil {
			sevColor = []int{128, 128, 128}
		}

		pdf.SetTextColor(sevColor[0], sevColor[1], sevColor[2])
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(labelW, 7, titleCase.String(sev), "1", 0, "L", false, 0, "")

		pdf.SetFont("Helvetica", "", 9)
		for _, c := range activeConf {
			n := counts[cell{sev, c}]
			if n > 0 {
				// Hot cells: red text for high-severity + high-confidence.
				if (sev == "critical" || sev == "high") && (c == "certain" || c == "high") {
					pdf.SetTextColor(220, 38, 38)
					pdf.SetFont("Helvetica", "B", 9)
				} else {
					pdf.SetTextColor(60, 60, 60)
					pdf.SetFont("Helvetica", "", 9)
				}
				pdf.CellFormat(cellW, 7, fmt.Sprintf("%d", n), "1", 0, "C", false, 0, "")
			} else {
				pdf.SetTextColor(180, 180, 180)
				pdf.CellFormat(cellW, 7, "-", "1", 0, "C", false, 0, "")
			}
		}
		pdf.Ln(-1)
	}

	// Row totals line.
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetTextColor(60, 60, 60)
	pdf.CellFormat(labelW, 7, "Total", "1", 0, "L", false, 0, "")
	for _, c := range activeConf {
		total := 0
		for _, s := range sevOrder {
			total += counts[cell{s, c}]
		}
		pdf.CellFormat(cellW, 7, fmt.Sprintf("%d", total), "1", 0, "C", false, 0, "")
	}
	pdf.Ln(-1)
}

// hasPassingCategories reports whether any tested category had a 100% block rate.
func (pw *PDFWriter) hasPassingCategories() bool {
	if pw.summary == nil || len(pw.summary.Breakdown.ByCategory) == 0 {
		return false
	}
	for _, stats := range pw.summary.Breakdown.ByCategory {
		if stats.Total > 0 && stats.Bypasses == 0 {
			return true
		}
	}
	return false
}

// addPassingCategories lists attack categories where the WAF blocked 100% of tests.
// This is the "good news" section — categories the WAF handles well.
func (pw *PDFWriter) addPassingCategories(pdf *gofpdf.Fpdf) {
	if !pw.hasPassingCategories() {
		return
	}

	pdf.AddPage()
	pw.addSectionHeader(pdf, "Passing Categories")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.MultiCell(0, 5, "The following attack categories were fully blocked by the WAF. "+
		"No bypass payloads succeeded in these categories during testing.", "", "L", false)
	pdf.Ln(5)

	type passRow struct {
		name  string
		total int
	}
	var rows []passRow
	for cat, stats := range pw.summary.Breakdown.ByCategory {
		if stats.Total > 0 && stats.Bypasses == 0 {
			rows = append(rows, passRow{name: cat, total: stats.Total})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].total > rows[j].total })

	// Table header.
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetFillColor(22, 163, 74) // Green header
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(60, 8, "Category", "1", 0, "L", true, 0, "")
	pdf.CellFormat(30, 8, "Tests", "1", 0, "C", true, 0, "")
	pdf.CellFormat(35, 8, "Block Rate", "1", 0, "C", true, 0, "")
	pdf.CellFormat(0, 8, "Status", "1", 1, "C", true, 0, "")

	// Rows.
	pdf.SetFont("Helvetica", "", 10)
	for i, row := range rows {
		if i%2 == 0 {
			pdf.SetFillColor(245, 255, 245)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}

		pdf.SetTextColor(60, 60, 60)
		pdf.CellFormat(60, 7, strings.ToUpper(row.name), "1", 0, "L", true, 0, "")
		pdf.CellFormat(30, 7, fmt.Sprintf("%d", row.total), "1", 0, "C", true, 0, "")

		pdf.SetTextColor(22, 163, 74)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(35, 7, "100.0%", "1", 0, "C", true, 0, "")
		pdf.CellFormat(0, 7, "PASS", "1", 1, "C", true, 0, "")
		pdf.SetFont("Helvetica", "", 10)
	}

	// Summary line.
	pdf.Ln(3)
	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(22, 163, 74)
	total := len(pw.summary.Breakdown.ByCategory)
	pdf.CellFormat(0, 6, fmt.Sprintf("%d of %d tested categories fully blocked.", len(rows), total), "", 1, "L", false, 0, "")
}

// hasEvasionData reports whether any results contain evasion context.
func (pw *PDFWriter) hasEvasionData() bool {
	for _, r := range pw.results {
		if r.Context != nil && (r.Context.Tamper != "" || r.Context.EvasionTechnique != "") {
			return true
		}
	}
	return false
}

// addEvasionEffectiveness aggregates bypass success rates per evasion technique
// and tamper chain. Shows which evasion methods are most effective against the WAF.
func (pw *PDFWriter) addEvasionEffectiveness(pdf *gofpdf.Fpdf) {
	if !pw.hasEvasionData() {
		return
	}

	// Aggregate by technique: total tests and bypasses.
	type evasionStat struct {
		total    int
		bypasses int
	}
	tampers := make(map[string]*evasionStat)
	techniques := make(map[string]*evasionStat)

	for _, r := range pw.results {
		if r.Context == nil {
			continue
		}
		if r.Context.Tamper != "" {
			s := tampers[r.Context.Tamper]
			if s == nil {
				s = &evasionStat{}
				tampers[r.Context.Tamper] = s
			}
			s.total++
			if r.Result.Outcome == events.OutcomeBypass {
				s.bypasses++
			}
		}
		if r.Context.EvasionTechnique != "" {
			s := techniques[r.Context.EvasionTechnique]
			if s == nil {
				s = &evasionStat{}
				techniques[r.Context.EvasionTechnique] = s
			}
			s.total++
			if r.Result.Outcome == events.OutcomeBypass {
				s.bypasses++
			}
		}
	}

	pdf.AddPage()
	pw.addSectionHeader(pdf, "Evasion Technique Effectiveness")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.MultiCell(0, 5, "Effectiveness of evasion techniques and tamper chains used during testing. "+
		"Higher bypass rates indicate techniques the WAF does not handle well.", "", "L", false)
	pdf.Ln(5)

	renderEvasionTable := func(title string, data map[string]*evasionStat) {
		if len(data) == 0 {
			return
		}

		type row struct {
			name       string
			total      int
			bypasses   int
			bypassRate float64
		}
		rows := make([]row, 0, len(data))
		for name, s := range data {
			rate := 0.0
			if s.total > 0 {
				rate = float64(s.bypasses) / float64(s.total) * 100
			}
			rows = append(rows, row{name: name, total: s.total, bypasses: s.bypasses, bypassRate: rate})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].bypassRate > rows[j].bypassRate })

		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(60, 60, 60)
		pdf.CellFormat(0, 9, title, "", 1, "L", false, 0, "")
		pdf.Ln(2)

		// Header.
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetFillColor(30, 41, 59)
		pdf.SetTextColor(255, 255, 255)
		pdf.CellFormat(70, 7, "Technique", "1", 0, "L", true, 0, "")
		pdf.CellFormat(25, 7, "Tests", "1", 0, "C", true, 0, "")
		pdf.CellFormat(25, 7, "Bypasses", "1", 0, "C", true, 0, "")
		pdf.CellFormat(30, 7, "Bypass Rate", "1", 1, "C", true, 0, "")

		pdf.SetFont("Helvetica", "", 9)
		for i, r := range rows {
			if i >= 20 {
				break // cap displayed rows
			}
			if i%2 == 0 {
				pdf.SetFillColor(250, 250, 250)
			} else {
				pdf.SetFillColor(255, 255, 255)
			}

			pdf.SetTextColor(60, 60, 60)
			pdf.CellFormat(70, 6, truncateString(r.name, 40), "1", 0, "L", true, 0, "")
			pdf.CellFormat(25, 6, fmt.Sprintf("%d", r.total), "1", 0, "C", true, 0, "")

			if r.bypasses > 0 {
				pdf.SetTextColor(220, 38, 38)
			}
			pdf.CellFormat(25, 6, fmt.Sprintf("%d", r.bypasses), "1", 0, "C", true, 0, "")

			// Color-code bypass rate.
			var brColor []int
			if r.bypassRate >= 50 {
				brColor = []int{220, 38, 38}
			} else if r.bypassRate >= 20 {
				brColor = []int{202, 138, 4}
			} else {
				brColor = []int{22, 163, 74}
			}
			pdf.SetTextColor(brColor[0], brColor[1], brColor[2])
			pdf.SetFont("Helvetica", "B", 9)
			pdf.CellFormat(30, 6, fmt.Sprintf("%.1f%%", r.bypassRate), "1", 1, "C", true, 0, "")
			pdf.SetFont("Helvetica", "", 9)
		}
		pdf.Ln(5)
	}

	renderEvasionTable("Tamper Chains", tampers)
	renderEvasionTable("Evasion Techniques", techniques)
}

// addRemediationGuidance renders actionable remediation advice for each bypass category.
func (pw *PDFWriter) addRemediationGuidance(pdf *gofpdf.Fpdf, byCategory map[string][]*events.ResultEvent) {
	if len(byCategory) == 0 {
		return
	}

	pdf.AddPage()
	pw.addSectionHeader(pdf, "Remediation Guidance")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.MultiCell(0, 5, "Targeted remediation guidance for each attack category where bypasses were detected. "+
		"Prioritize categories with the highest bypass counts and severity.", "", "L", false)
	pdf.Ln(5)

	// Sort categories by bypass count descending.
	type catEntry struct {
		category string
		count    int
	}
	sorted := make([]catEntry, 0, len(byCategory))
	for cat, findings := range byCategory {
		sorted = append(sorted, catEntry{category: cat, count: len(findings)})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })

	_, pageH := pdf.GetPageSize()
	pageBreakY := pageH - 47

	for i, entry := range sorted {
		info := categoryRemediationFor(entry.category)

		// Page break check: each guidance block needs ~35mm.
		if i > 0 && pdf.GetY()+35 > pageBreakY {
			pdf.AddPage()
		}

		// Category header with bypass count.
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(30, 41, 59)
		pdf.CellFormat(0, 8, fmt.Sprintf("%s (%d bypasses)", info.Title, entry.count), "", 1, "L", false, 0, "")

		// Guidance text.
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(80, 80, 80)
		pdf.MultiCell(0, 5, info.Guidance, "", "L", false)

		// Reference URL.
		if info.ReferenceURL != "" {
			pdf.SetFont("Helvetica", "I", 8)
			pdf.SetTextColor(37, 99, 235)
			pdf.CellFormat(0, 5, "Reference: "+info.ReferenceURL, "", 1, "L", false, 0, "")
		}

		pdf.Ln(4)
	}
}

// addScanInsights derives and renders heuristic observations from the scan data.
// Covers: latency anomalies, error-prone categories, effective encodings,
// WAF detection confidence, and overall posture.
func (pw *PDFWriter) addScanInsights(pdf *gofpdf.Fpdf) {
	pdf.AddPage()
	pw.addSectionHeader(pdf, "Scan Insights")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.MultiCell(0, 5, "Automated observations derived from the scan results. "+
		"These insights highlight patterns that may warrant further investigation.", "", "L", false)
	pdf.Ln(5)

	insights := pw.deriveInsights()
	if len(insights) == 0 {
		pdf.SetFont("Helvetica", "I", 10)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 8, "No notable insights from this scan.", "", 1, "L", false, 0, "")
		return
	}

	for i, ins := range insights {
		if i > 0 {
			pdf.Ln(2)
		}

		// Icon + title.
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(30, 41, 59)
		pdf.CellFormat(0, 7, fmt.Sprintf("%s %s", ins.icon, ins.title), "", 1, "L", false, 0, "")

		// Body.
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(80, 80, 80)
		pdf.MultiCell(0, 5, ins.body, "", "L", false)
	}
}

// insight is one automatically derived observation.
type insight struct {
	icon  string
	title string
	body  string
}

// deriveInsights builds a list of heuristic observations from the scan data.
func (pw *PDFWriter) deriveInsights() []insight {
	var out []insight

	// 1. WAF detection confidence.
	if pw.summary != nil && pw.summary.Target.WAFDetected != "" {
		conf := pw.summary.Target.WAFConfidence
		desc := "detected"
		if conf >= 0.9 {
			desc = "detected with high confidence"
		} else if conf < 0.5 {
			desc = "detected with low confidence (may be a false positive)"
		}
		out = append(out, insight{
			icon:  "[WAF]",
			title: "WAF Detection",
			body:  fmt.Sprintf("WAF identified as %s, %s (%.0f%% confidence).", pw.summary.Target.WAFDetected, desc, conf*100),
		})
	}

	// 2. Overall posture.
	if pw.summary != nil {
		grade := pw.summary.Effectiveness.Grade
		rate := pw.summary.Effectiveness.BlockRatePct
		if grade != "" {
			out = append(out, insight{
				icon:  "[GRADE]",
				title: "Protection Posture",
				body:  fmt.Sprintf("Overall WAF grade: %s (%.1f%% block rate). %s", grade, rate, postureSummary(rate)),
			})
		}
	}

	// 3. Categories with highest error rates.
	if pw.summary != nil {
		type errEntry struct {
			cat    string
			errors int
			total  int
		}
		var errCats []errEntry
		for _, r := range pw.results {
			if r.Result.Outcome == events.OutcomeError {
				// count per category
				cat := r.Test.Category
				if cat == "" {
					cat = "uncategorized"
				}
				found := false
				for i := range errCats {
					if errCats[i].cat == cat {
						errCats[i].errors++
						found = true
						break
					}
				}
				if !found {
					errCats = append(errCats, errEntry{cat: cat, errors: 1})
				}
			}
		}
		// Fill totals.
		for i := range errCats {
			if stats, ok := pw.summary.Breakdown.ByCategory[errCats[i].cat]; ok {
				errCats[i].total = stats.Total
			}
		}

		sort.Slice(errCats, func(i, j int) bool { return errCats[i].errors > errCats[j].errors })
		if len(errCats) > 0 && errCats[0].errors >= 3 {
			top := errCats[0]
			pct := 0.0
			if top.total > 0 {
				pct = float64(top.errors) / float64(top.total) * 100
			}
			out = append(out, insight{
				icon:  "[ERR]",
				title: "Error-Prone Category",
				body:  fmt.Sprintf("Category %q had %d errors (%.0f%% of its tests). This may indicate server-side issues or aggressive rate limiting.", strings.ToUpper(top.cat), top.errors, pct),
			})
		}
	}

	// 4. Most effective encoding.
	if pw.summary != nil && len(pw.summary.Breakdown.ByEncoding) > 0 {
		bestEnc := ""
		bestRate := 0.0
		for enc, stats := range pw.summary.Breakdown.ByEncoding {
			if stats.Total >= 5 { // threshold for significance
				bypassRate := 100.0 - stats.BlockRate
				if bypassRate > bestRate {
					bestRate = bypassRate
					bestEnc = enc
				}
			}
		}
		if bestEnc != "" && bestRate > 10 {
			out = append(out, insight{
				icon:  "[ENC]",
				title: "Most Effective Encoding",
				body:  fmt.Sprintf("Encoding %q achieved a %.1f%% bypass rate, suggesting the WAF does not adequately decode this format.", bestEnc, bestRate),
			})
		}
	}

	// 5. Latency anomalies.
	if pw.summary != nil && pw.summary.Latency.P95Ms > 0 {
		ratio := float64(pw.summary.Latency.P95Ms) / float64(pw.summary.Latency.P50Ms)
		if pw.summary.Latency.P50Ms > 0 && ratio > 5 {
			out = append(out, insight{
				icon:  "[LAT]",
				title: "Latency Spike",
				body: fmt.Sprintf("P95 latency (%d ms) is %.0fx the median (%d ms). "+
					"This may indicate WAF rule processing delays or backend throttling on certain payloads.",
					pw.summary.Latency.P95Ms, ratio, pw.summary.Latency.P50Ms),
			})
		}
	}

	// 6. Request throughput.
	if pw.summary != nil && pw.summary.Timing.RequestsPerSec > 0 {
		rps := pw.summary.Timing.RequestsPerSec
		durSec := pw.summary.Timing.DurationSec
		out = append(out, insight{
			icon:  "[PERF]",
			title: "Scan Performance",
			body:  fmt.Sprintf("Completed %d tests in %.1f seconds (%.1f req/s).", pw.summary.Totals.Tests, durSec, rps),
		})
	}

	return out
}

// postureSummary returns a single-sentence assessment for the given block rate.
func postureSummary(rate float64) string {
	switch {
	case rate >= 97:
		return "The WAF provides near-complete coverage with minimal gaps."
	case rate >= 90:
		return "Strong protection with a few exploitable gaps that should be addressed."
	case rate >= 80:
		return "Moderate protection; several attack vectors are not adequately covered."
	case rate >= 60:
		return "Weak protection; many common attack payloads bypass the WAF."
	default:
		return "Critical protection gaps; the WAF blocks fewer than half of tested payloads."
	}
}
