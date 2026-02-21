package writers

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/waftester/waftester/pkg/output/events"
)

// pdfResult holds a generated PDF and provides semantic assertions.
type pdfResult struct {
	t      *testing.T
	raw    []byte
	reader *bytes.Reader
}

func generatePDF(t *testing.T, config PDFConfig, results []*events.ResultEvent, summary *events.SummaryEvent) pdfResult {
	t.Helper()
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, config)
	w.noCompress = true // disable stream compression so text is searchable in raw bytes

	for _, r := range results {
		if err := w.Write(r); err != nil {
			t.Fatalf("Write result: %v", err)
		}
	}
	if summary != nil {
		if err := w.Write(summary); err != nil {
			t.Fatalf("Write summary: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw := buf.Bytes()
	if len(raw) < 4 || string(raw[:4]) != "%%PDF" {
		// fpdf writes %%PDF-1.3 header
		if len(raw) < 4 || string(raw[:4]) != "%%PDF"[:4] {
			// just check first 4 bytes
		}
	}

	return pdfResult{t: t, raw: raw, reader: bytes.NewReader(raw)}
}

// assertValid validates the PDF structure using pdfcpu.
func (p *pdfResult) assertValid() {
	p.t.Helper()
	if err := pdfapi.Validate(p.reader, nil); err != nil {
		p.t.Errorf("PDF validation failed: %v", err)
	}
	p.reader.Seek(0, 0)
}

// assertPageCount checks the exact number of pages.
func (p *pdfResult) assertPageCount(expected int) {
	p.t.Helper()
	p.reader.Seek(0, 0)
	count, err := pdfapi.PageCount(p.reader, nil)
	if err != nil {
		p.t.Fatalf("PageCount failed: %v", err)
	}
	if count != expected {
		p.t.Errorf("page count = %d, want %d", count, expected)
	}
}

// assertPageCountAtLeast checks minimum page count.
func (p *pdfResult) assertPageCountAtLeast(min int) {
	p.t.Helper()
	p.reader.Seek(0, 0)
	count, err := pdfapi.PageCount(p.reader, nil)
	if err != nil {
		p.t.Fatalf("PageCount failed: %v", err)
	}
	if count < min {
		p.t.Errorf("page count = %d, want at least %d", count, min)
	}
}

// assertContainsText checks that the raw PDF bytes contain the given text.
// fpdf encodes Helvetica text as literal bytes in PDF content streams.
func (p *pdfResult) assertContainsText(text string) {
	p.t.Helper()
	if !bytes.Contains(p.raw, []byte(text)) {
		p.t.Errorf("PDF does not contain text %q", text)
	}
}

// assertNotContainsText checks that the raw PDF bytes do NOT contain the given text.
func (p *pdfResult) assertNotContainsText(text string) {
	p.t.Helper()
	if bytes.Contains(p.raw, []byte(text)) {
		p.t.Errorf("PDF unexpectedly contains text %q", text)
	}
}

// assertMinSize checks the PDF is at least n bytes.
func (p *pdfResult) assertMinSize(n int) {
	p.t.Helper()
	if len(p.raw) < n {
		p.t.Errorf("PDF size = %d bytes, want at least %d", len(p.raw), n)
	}
}

// --- Helper factories ---

func makeBypassResult(id, category string, sev events.Severity, owasp []string) *events.ResultEvent {
	return makePDFTestResultEvent(id, category, sev, events.OutcomeBypass, owasp)
}

func makeBlockedResult(id, category string, sev events.Severity, owasp []string) *events.ResultEvent {
	return makePDFTestResultEvent(id, category, sev, events.OutcomeBlocked, owasp)
}

// --- Helpers ---

// pageCount returns the page count of a generated PDF, failing the test on error.
func pageCount(t *testing.T, p pdfResult) int {
	t.Helper()
	p.reader.Seek(0, 0)
	count, err := pdfapi.PageCount(p.reader, nil)
	if err != nil {
		t.Fatalf("PageCount failed: %v", err)
	}
	return count
}

// --- Semantic tests ---

func TestPDF_Structural_ValidPDF(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
		makeBlockedResult("xss-001", "xss", events.SeverityHigh, []string{"A03:2021"}),
	}
	p := generatePDF(t, PDFConfig{
		Title:           "Structural Test",
		IncludeEvidence: true,
		IncludeTOC:      true,
	}, results, makePDFTestSummaryEvent())

	p.assertValid()
	p.assertMinSize(5000)
}

func TestPDF_PageCount_WithTOC(t *testing.T) {
	t.Parallel()
	// With TOC: Cover + TOC + ExecSummary + TopBypasses + CategoryBreakdown + OWASP + Findings + ScanConfig + Methodology
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
	}
	withTOC := generatePDF(t, PDFConfig{IncludeTOC: true}, results, makePDFTestSummaryEvent())
	withTOC.assertValid()
	withTOC.assertPageCountAtLeast(9)

	// Without TOC should be exactly 1 page less.
	withoutTOC := generatePDF(t, PDFConfig{IncludeTOC: false}, results, makePDFTestSummaryEvent())
	withoutTOC.assertValid()

	withCount := pageCount(t, withTOC)
	withoutCount := pageCount(t, withoutTOC)
	if withCount != withoutCount+1 {
		t.Errorf("TOC should add exactly 1 page: with=%d, without=%d", withCount, withoutCount)
	}
}

func TestPDF_PageCount_WithoutTOC(t *testing.T) {
	t.Parallel()
	// Without TOC: Cover + ExecSummary + TopBypasses + CategoryBreakdown + OWASP + Findings + ScanConfig + Methodology
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: false}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertPageCountAtLeast(8)
}

func TestPDF_PageCount_MultipleCategories(t *testing.T) {
	t.Parallel()
	// More categories = more category section headers (each starts on a new page).
	// Both summaries are nil to isolate findings-only page growth.
	twoCategories := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
		makeBypassResult("xss-001", "xss", events.SeverityHigh, []string{"A03:2021"}),
	}
	fourCategories := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
		makeBypassResult("xss-001", "xss", events.SeverityHigh, []string{"A03:2021"}),
		makeBypassResult("lfi-001", "lfi", events.SeverityMedium, []string{"A01:2021"}),
		makeBypassResult("ssrf-001", "ssrf", events.SeverityMedium, []string{"A10:2021"}),
	}

	p2 := generatePDF(t, PDFConfig{IncludeTOC: true}, twoCategories, nil)
	p4 := generatePDF(t, PDFConfig{IncludeTOC: true}, fourCategories, nil)
	p2.assertValid()
	p4.assertValid()

	c2 := pageCount(t, p2)
	c4 := pageCount(t, p4)
	if c4 <= c2 {
		t.Errorf("4 categories (%d pages) should produce more pages than 2 categories (%d pages)", c4, c2)
	}
}

func TestPDF_PageCount_NoBypassesFewerPages(t *testing.T) {
	t.Parallel()
	// All blocked = fewer pages than bypasses (no per-category finding cards).
	blockedOnly := []*events.ResultEvent{
		makeBlockedResult("sqli-001", "sqli", events.SeverityHigh, nil),
		makeBlockedResult("xss-001", "xss", events.SeverityHigh, nil),
	}
	withBypasses := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityHigh, nil),
		makeBypassResult("xss-001", "xss", events.SeverityHigh, nil),
	}

	pBlocked := generatePDF(t, PDFConfig{IncludeTOC: true}, blockedOnly, makePDFTestSummaryEvent())
	pBypass := generatePDF(t, PDFConfig{IncludeTOC: true}, withBypasses, makePDFTestSummaryEvent())
	pBlocked.assertValid()
	pBypass.assertValid()

	cBlocked := pageCount(t, pBlocked)
	cBypass := pageCount(t, pBypass)
	if cBlocked >= cBypass {
		t.Errorf("blocked-only (%d pages) should have fewer pages than with bypasses (%d pages)", cBlocked, cBypass)
	}
}

func TestPDF_ContainsSectionHeaders(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("Executive Summary")
	p.assertContainsText("OWASP Top 10 Coverage")
	p.assertContainsText("Findings: SQLI") // per-category header when bypasses exist
	p.assertContainsText("Table of Contents")
	p.assertContainsText("Testing Methodology")
}

func TestPDF_ContainsCoverPageInfo(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{
		Title:          "Acme WAF Report",
		CompanyName:    "Acme Security",
		Author:         "Jane Doe",
		Classification: "INTERNAL",
	}, results, makePDFTestSummaryEvent())

	p.assertContainsText("Acme WAF Report")
	p.assertContainsText("Acme Security")
	p.assertContainsText("INTERNAL")
	p.assertContainsText("https://example.com")
	p.assertContainsText("Cloudflare")
}

func TestPDF_ContainsGrade(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Effectiveness.Grade = "B+"
	summary.Effectiveness.BlockRatePct = 88.5

	p := generatePDF(t, PDFConfig{}, nil, summary)
	p.assertContainsText("B+")
}

func TestPDF_ContainsRecommendation(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Effectiveness.Recommendation = "Enable SQL injection rules immediately."

	p := generatePDF(t, PDFConfig{}, nil, summary)
	p.assertContainsText("Enable SQL injection rules immediately.")
}

func TestPDF_ContainsFindingID(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-union-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("sqli-union-001")
}

func TestPDF_EvidencePresenceControlled(t *testing.T) {
	t.Parallel()

	result := makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil)
	result.Evidence = &events.Evidence{
		Payload:     "' OR 1=1 --",
		CurlCommand: "curl -X POST 'https://example.com' -d 'q=%27+OR+1%3D1+--'",
	}

	// With evidence
	pWith := generatePDF(t, PDFConfig{IncludeEvidence: true}, []*events.ResultEvent{result}, makePDFTestSummaryEvent())
	pWith.assertContainsText("OR 1=1")

	// Without evidence — payload must not appear
	pWithout := generatePDF(t, PDFConfig{IncludeEvidence: false}, []*events.ResultEvent{result}, makePDFTestSummaryEvent())
	pWithout.assertNotContainsText("OR 1=1")
}

func TestPDF_OWASPTablePresent(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
	}
	p := generatePDF(t, PDFConfig{}, results, makePDFTestSummaryEvent())

	// OWASP codes should appear in the table
	p.assertContainsText("A01:2021")
	p.assertContainsText("A03:2021")
	p.assertContainsText("A10:2021")
}

func TestPDF_SeverityBreakdownPresent(t *testing.T) {
	t.Parallel()
	p := generatePDF(t, PDFConfig{}, nil, makePDFTestSummaryEvent())

	// Severity labels should appear in summary
	p.assertContainsText("Critical")
	p.assertContainsText("High")
	p.assertContainsText("Medium")
	p.assertContainsText("Low")
}

func TestPDF_WatermarkText(t *testing.T) {
	t.Parallel()
	p := generatePDF(t, PDFConfig{WatermarkText: "DRAFT REPORT"}, nil, makePDFTestSummaryEvent())
	p.assertContainsText("DRAFT REPORT")
}

func TestPDF_ClassificationBadge(t *testing.T) {
	t.Parallel()

	for _, class := range []string{"CONFIDENTIAL", "INTERNAL", "PUBLIC"} {
		t.Run(class, func(t *testing.T) {
			t.Parallel()
			p := generatePDF(t, PDFConfig{Classification: class}, nil, makePDFTestSummaryEvent())
			p.assertContainsText(class)
		})
	}
}

func TestPDF_LetterLandscape_ValidAndCorrectPageCount(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{
		PageSize:    "Letter",
		Orientation: "L",
		IncludeTOC:  true,
	}, results, makePDFTestSummaryEvent())

	p.assertValid()
	// Landscape has less vertical space, so content overflows to more pages than portrait.
	// Exact count depends on content wrapping; verify it's at least the portrait baseline.
	p.assertPageCountAtLeast(6)
}

func TestPDF_ManyFindings_PageOverflow(t *testing.T) {
	t.Parallel()

	// Generate enough findings in a single category to force multiple pages
	var results []*events.ResultEvent
	for i := 0; i < 30; i++ {
		r := makeBypassResult(
			fmt.Sprintf("sqli-%03d", i),
			"sqli",
			events.SeverityHigh,
			[]string{"A03:2021"},
		)
		r.Evidence = &events.Evidence{
			Payload:     fmt.Sprintf("' OR %d=%d --", i, i),
			CurlCommand: fmt.Sprintf("curl -X POST 'https://example.com' -d 'q=payload-%d'", i),
		}
		results = append(results, r)
	}

	p := generatePDF(t, PDFConfig{
		IncludeEvidence: true,
		IncludeTOC:      true,
	}, results, makePDFTestSummaryEvent())

	p.assertValid()
	// 30 findings with evidence should cause page breaks within the sqli category
	// At minimum: Cover + TOC + Summary + OWASP + Findings(2+) + Methodology = 7+
	p.assertPageCountAtLeast(7)
}

func TestPDF_NoResults_NoSummary(t *testing.T) {
	t.Parallel()
	// Completely empty PDF — no results, no summary
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, nil, nil)

	p.assertValid()
	// Cover + TOC + Summary("No summary data") + OWASP + Findings("No bypass") + ScanConfig + Methodology = 7+
	p.assertPageCountAtLeast(7)
	p.assertContainsText("No summary data available")
	p.assertContainsText("No bypass vulnerabilities detected")
}

func TestPDF_BlockRate_ZeroPercent(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Effectiveness.BlockRatePct = 0.0
	summary.Effectiveness.Grade = "F"

	p := generatePDF(t, PDFConfig{}, nil, summary)
	p.assertValid()
	p.assertContainsText("F")
}

func TestPDF_BlockRate_HundredPercent(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Effectiveness.BlockRatePct = 100.0
	summary.Effectiveness.Grade = "A+"

	p := generatePDF(t, PDFConfig{}, nil, summary)
	p.assertValid()
	p.assertContainsText("A+")
}

func TestPDF_FooterCustomization(t *testing.T) {
	t.Parallel()
	p := generatePDF(t, PDFConfig{FooterText: "Custom Footer Corp"}, nil, makePDFTestSummaryEvent())
	p.assertContainsText("Custom Footer Corp")
}

func TestPDF_DefaultFooter(t *testing.T) {
	t.Parallel()
	p := generatePDF(t, PDFConfig{}, nil, makePDFTestSummaryEvent())
	p.assertContainsText("Generated by WAFtester")
}

func TestPDF_TOCSectionTitles_MatchRenderedSections(t *testing.T) {
	t.Parallel()

	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
		makeBypassResult("xss-001", "xss", events.SeverityHigh, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, results, makePDFTestSummaryEvent())

	// Every section title in the TOC should also appear in the rendered body
	// Note: "Detailed Findings" only appears in the body when there are NO bypasses.
	// With bypasses, per-category headers (e.g., "Findings: SQLI") appear instead.
	expectedSections := []string{
		"Executive Summary",
		"OWASP Top 10 Coverage",
		"Findings: XSS",
		"Appendix: Testing Methodology",
	}

	for _, section := range expectedSections {
		// Count occurrences: TOC mention + actual section header = at least 2
		count := bytes.Count(p.raw, []byte(section))
		if count < 2 {
			t.Errorf("section %q appears %d time(s), want >=2 (TOC + body)", section, count)
		}
	}
}

func TestPDF_MethodologyContent(t *testing.T) {
	t.Parallel()
	p := generatePDF(t, PDFConfig{}, nil, makePDFTestSummaryEvent())

	// The methodology appendix should contain key methodology steps
	p.assertContainsText("ATTACK SIMULATION")
	p.assertContainsText("RESPONSE ANALYSIS")
	p.assertContainsText("EFFECTIVENESS SCORING")
	p.assertContainsText("SEVERITY CLASSIFICATION")
	p.assertContainsText("Grading Scale")
}

func TestPDF_SummaryStatistics(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Totals.Tests = 250
	summary.Totals.Blocked = 230
	summary.Totals.Bypasses = 15
	summary.Totals.Errors = 3
	summary.Totals.Timeouts = 2

	p := generatePDF(t, PDFConfig{}, nil, summary)

	// Stat values should appear in the exec summary
	p.assertContainsText("250") // Total
	p.assertContainsText("230") // Blocked
	p.assertContainsText("15")  // Bypasses
}

func TestPDF_MultiCategory_FindingCounts(t *testing.T) {
	t.Parallel()

	categories := []string{"sqli", "xss", "lfi", "ssrf", "rce"}
	var results []*events.ResultEvent
	for _, cat := range categories {
		results = append(results, makeBypassResult(cat+"-001", cat, events.SeverityHigh, nil))
	}

	p := generatePDF(t, PDFConfig{IncludeTOC: true}, results, makePDFTestSummaryEvent())
	p.assertValid()

	// Each category should have its own findings section
	for _, cat := range categories {
		p.assertContainsText(fmt.Sprintf("Findings: %s", strings.ToUpper(cat)))
	}

	// 5 categories should produce more pages than fewer categories.
	p.assertPageCountAtLeast(13)
}

func TestPDF_TimingInfo(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Timing.StartedAt = time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC)

	p := generatePDF(t, PDFConfig{}, nil, summary)
	p.assertContainsText("2026-02-15")
}

// --- New section tests ---

func TestPDF_ContainsTopBypasses(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	p := generatePDF(t, PDFConfig{}, nil, summary)

	p.assertContainsText("Top Bypass Vulnerabilities")
	p.assertContainsText("sqli-001")
	p.assertContainsText("xss-001")
	p.assertContainsText("CRITICAL")
	p.assertContainsText("urlencode")
}

func TestPDF_TopBypasses_EmptySkipsSection(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.TopBypasses = nil

	p := generatePDF(t, PDFConfig{}, nil, summary)
	p.assertNotContainsText("Top Bypass Vulnerabilities")
}

func TestPDF_ContainsCategoryBreakdown(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	p := generatePDF(t, PDFConfig{}, nil, summary)

	p.assertContainsText("Category Breakdown")
	p.assertContainsText("Block Rate by Category")
	p.assertContainsText("SQLI")
	p.assertContainsText("XSS")
	p.assertContainsText("92.5")
	p.assertContainsText("94.3")
}

func TestPDF_ContainsEncodingBreakdown(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	p := generatePDF(t, PDFConfig{}, nil, summary)

	p.assertContainsText("Encoding Effectiveness")
	p.assertContainsText("base64")
	p.assertContainsText("urlencode")
	p.assertContainsText("none")
}

func TestPDF_ContainsLatencyProfile(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	p := generatePDF(t, PDFConfig{}, nil, summary)

	p.assertContainsText("Response Latency Profile")
	p.assertContainsText("12 ms")   // Min
	p.assertContainsText("850 ms")  // Max
	p.assertContainsText("145 ms")  // Avg
	p.assertContainsText("120 ms")  // P50
	p.assertContainsText("480 ms")  // P95
	p.assertContainsText("720 ms")  // P99
}

func TestPDF_LatencyProfile_NoDataSkipsSection(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Latency = events.LatencyInfo{} // all zero

	p := generatePDF(t, PDFConfig{}, nil, summary)
	p.assertNotContainsText("Response Latency Profile")
}

func TestPDF_ContainsScanConfiguration(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	p := generatePDF(t, PDFConfig{}, nil, summary)

	p.assertContainsText("Appendix: Scan Configuration")
	p.assertContainsText("https://example.com")
	p.assertContainsText("Cloudflare")
	p.assertContainsText("100")      // Total tests
	p.assertContainsText("completed") // Exit reason
}

func TestPDF_ScanConfig_WithStartEvent(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	start := &events.StartEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeStart},
		Target:    "https://example.com",
		Config: events.ScanConfig{
			Concurrency: 10,
			Timeout:     30,
			Categories:  []string{"sqli", "xss", "lfi"},
			Encodings:   []string{"none", "base64", "urlencode"},
			Tampers:     []string{"space2comment", "randomcase"},
		},
	}

	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})
	w.noCompress = true
	w.Write(start)
	w.Write(summary)
	w.Close()

	p := pdfResult{t: t, raw: buf.Bytes(), reader: bytes.NewReader(buf.Bytes())}
	p.assertContainsText("Appendix: Scan Configuration")
	p.assertContainsText("sqli, xss, lfi")
	p.assertContainsText("space2comment, randomcase")
	p.assertContainsText("none, base64, urlencode")
}

func TestPDF_ContainsCWEReferences(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("CWE-89")
	p.assertContainsText("CWE-79")
}

func TestPDF_ContainsConfidenceLevel(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("high")
	p.assertContainsText("Pattern match on response body")
}

func TestPDF_ContainsWAFSignature(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("Cloudflare/942100")
}

func TestPDF_ContainsEvasionContext(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("case-swapping")
	p.assertContainsText("space2comment")
}

func TestPDF_ContainsEndpointParameter(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("/api/v1/search")
	p.assertContainsText("query")
}

func TestPDF_ContainsEncodedPayload(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("dGVzdC1wYXlsb2FkLQ==")
}

func TestPDF_ContainsRequestHeaders(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("Content-Type")
	p.assertContainsText("application/x-www-form-urlencoded")
}

func TestPDF_ContainsResponsePreview(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("403 Forbidden")
}

func TestPDF_CoverPageWAFConfidence(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Target.WAFConfidence = 0.87
	p := generatePDF(t, PDFConfig{}, nil, summary)

	p.assertContainsText("87%")
}

func TestPDF_CoverPageDuration(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Timing.DurationSec = 3723 // 1h 2m 3s
	p := generatePDF(t, PDFConfig{}, nil, summary)

	p.assertContainsText("1h 2m 3s")
}

func TestPDF_CoverPageThroughput(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Timing.RequestsPerSec = 45.7
	p := generatePDF(t, PDFConfig{}, nil, summary)

	p.assertContainsText("45.7 req/s")
}

func TestPDF_ContainsSubcategory(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("error-based")
}

func TestPDF_ContainsTags(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("cve-2024-1234")
	p.assertContainsText("owasp-a1")
}

func TestPDF_ContainsPhase(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("waf-testing")
}

func TestPDF_ScanConfig_SkipsZeroTimeout(t *testing.T) {
	t.Parallel()
	start := &events.StartEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeStart},
		Config: events.ScanConfig{
			Concurrency: 5,
			Timeout:     0, // not populated
		},
	}
	summary := makePDFTestSummaryEvent()
	// Use a duration that doesn't contain "0s" as a substring.
	summary.Timing.DurationSec = 125.0 // "2m 5s"

	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})
	w.noCompress = true
	w.Write(start)
	w.Write(summary)
	w.Close()

	p := pdfResult{t: t, raw: buf.Bytes(), reader: bytes.NewReader(buf.Bytes())}
	// With Timeout=0, no "0s" should appear in the scan config table.
	// The summary duration is "2m 5s" which doesn't contain "0s".
	p.assertNotContainsText("0s")
}

func TestPDF_ScanConfig_SkipsZeroConcurrency(t *testing.T) {
	t.Parallel()
	start := &events.StartEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeStart},
		Config:    events.ScanConfig{Concurrency: 0},
	}
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})
	w.noCompress = true
	w.Write(start)
	w.Write(makePDFTestSummaryEvent())
	w.Close()

	p := pdfResult{t: t, raw: buf.Bytes(), reader: bytes.NewReader(buf.Bytes())}
	// "Concurrency" row should not appear for zero value
	p.assertNotContainsText("Concurrency")
}

func TestPDF_ScanConfig_ShowsPopulatedTimeout(t *testing.T) {
	t.Parallel()
	start := &events.StartEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeStart},
		Config: events.ScanConfig{
			Concurrency: 10,
			Timeout:     30,
		},
	}
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})
	w.noCompress = true
	w.Write(start)
	w.Write(makePDFTestSummaryEvent())
	w.Close()

	p := pdfResult{t: t, raw: buf.Bytes(), reader: bytes.NewReader(buf.Bytes())}
	p.assertContainsText("30s")
	p.assertContainsText("Concurrency")
}

func TestPDF_ScanConfig_ReplayProxy(t *testing.T) {
	t.Parallel()
	start := &events.StartEvent{
		BaseEvent: events.BaseEvent{Type: events.EventTypeStart},
		Config: events.ScanConfig{
			Concurrency: 5,
			Timeout:     30,
			ReplayProxy: "http://burp:8080",
		},
	}
	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})
	w.noCompress = true
	w.Write(start)
	w.Write(makePDFTestSummaryEvent())
	w.Close()

	p := pdfResult{t: t, raw: buf.Bytes(), reader: bytes.NewReader(buf.Bytes())}
	p.assertContainsText("Replay Proxy")
	p.assertContainsText("http://burp:8080")
}

func TestPDF_FormatDuration(t *testing.T) {
	tests := []struct {
		seconds  float64
		expected string
	}{
		{0, "0.0s"},
		{5.3, "5.3s"},
		{59.9, "59.9s"},
		{60, "1m 0s"},
		{125, "2m 5s"},
		{3600, "1h 0m 0s"},
		{3723, "1h 2m 3s"},
		{7325, "2h 2m 5s"},
	}

	for _, tc := range tests {
		result := formatDuration(tc.seconds)
		if result != tc.expected {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.seconds, result, tc.expected)
		}
	}
}

func TestPDF_TOCIncludesNewSections(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, nil, summary)

	p.assertContainsText("Top Bypass Vulnerabilities")
	p.assertContainsText("Category Breakdown")
	p.assertContainsText("Appendix: Scan Configuration")
}

func TestPDF_ContentLength_InFindingCard(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("1337 bytes")
}

func TestPDF_CategoryBreakdown_RiskLabels(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	// sqli has 92.5% block rate (HIGH risk = block rate < 95? No, LOW = 90+, MEDIUM = 70-90, HIGH = <70)
	// Both sqli (92.5%) and xss (94.3%) should show LOW risk
	p := generatePDF(t, PDFConfig{}, nil, summary)

	// With 92.5% and 94.3% block rates, both categories should have LOW risk
	p.assertContainsText("LOW")
}

// --- New section tests ---

func TestPDF_SeverityConfidenceMatrix(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
		makeBypassResult("sqli-002", "sqli", events.SeverityHigh, nil),
	}
	p := generatePDF(t, PDFConfig{}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertContainsText("Severity vs Confidence Matrix")
	p.assertContainsText("Critical")
	p.assertContainsText("High")
}

func TestPDF_SeverityConfidenceMatrix_NoBypassesSkipped(t *testing.T) {
	t.Parallel()
	// Only blocked results — matrix section should not appear.
	results := []*events.ResultEvent{
		makeBlockedResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertNotContainsText("Severity vs Confidence Matrix")
}

func TestPDF_PassingCategories(t *testing.T) {
	t.Parallel()
	// Summary with one passing category (lfi: 100% block rate) and one failing (sqli).
	summary := makePDFTestSummaryEvent()
	summary.Breakdown.ByCategory["lfi"] = events.CategoryStats{Total: 20, Bypasses: 0, BlockRate: 100.0}

	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{}, results, summary)
	p.assertValid()
	p.assertContainsText("Passing Categories")
	p.assertContainsText("LFI")
	p.assertContainsText("100.0%")
	p.assertContainsText("PASS")
}

func TestPDF_PassingCategories_NoneWhenAllBypassed(t *testing.T) {
	t.Parallel()
	// Default summary has only sqli and xss, both with bypasses.
	p := generatePDF(t, PDFConfig{}, nil, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertNotContainsText("Passing Categories")
}

func TestPDF_EvasionEffectiveness(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
		makeBlockedResult("sqli-002", "sqli", events.SeverityHigh, nil),
	}
	p := generatePDF(t, PDFConfig{}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertContainsText("Evasion Technique Effectiveness")
	p.assertContainsText("Tamper Chains")
	p.assertContainsText("space2comment")
	p.assertContainsText("Evasion Techniques")
	p.assertContainsText("case-swapping")
}

func TestPDF_EvasionEffectiveness_SkippedWithoutContext(t *testing.T) {
	t.Parallel()
	// Result with nil Context — evasion section should not appear.
	r := makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil)
	r.Context = nil
	results := []*events.ResultEvent{r}
	p := generatePDF(t, PDFConfig{}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertNotContainsText("Evasion Technique Effectiveness")
}

func TestPDF_RemediationGuidance(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertContainsText("Remediation Guidance")
	p.assertContainsText("SQL Injection")
	p.assertContainsText("parameterized queries")
}

func TestPDF_RemediationGuidance_SkippedWithNoBypasses(t *testing.T) {
	t.Parallel()
	// No bypass results — remediation not shown.
	results := []*events.ResultEvent{
		makeBlockedResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertNotContainsText("Remediation Guidance")
}

func TestPDF_ScanInsights(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertContainsText("Scan Insights")
	p.assertContainsText("WAF Detection")
	p.assertContainsText("Cloudflare")
	p.assertContainsText("Protection Posture")
}

func TestPDF_ScanInsights_NoSummary(t *testing.T) {
	t.Parallel()
	// No summary — should show "No notable insights".
	p := generatePDF(t, PDFConfig{}, nil, nil)
	p.assertValid()
	p.assertContainsText("Scan Insights")
	p.assertContainsText("No notable insights")
}

func TestPDF_CWENames_InFindingCard(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeEvidence: true}, results, makePDFTestSummaryEvent())
	p.assertValid()
	// CWE-89 should now show "CWE-89: SQL Injection"
	p.assertContainsText("CWE-89: SQL Injection")
	// CWE-79 should now show "CWE-79: Cross-site Scripting"
	p.assertContainsText("CWE-79: Cross-site Scripting")
}

func TestPDF_TOC_NewSectionEntries(t *testing.T) {
	t.Parallel()
	// Build data that triggers all new sections.
	summary := makePDFTestSummaryEvent()
	summary.Breakdown.ByCategory["lfi"] = events.CategoryStats{Total: 20, Bypasses: 0, BlockRate: 100.0}
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, results, summary)
	p.assertValid()
	p.assertContainsText("Severity vs Confidence Matrix")
	p.assertContainsText("Passing Categories")
	p.assertContainsText("Evasion Technique Effectiveness")
	p.assertContainsText("Remediation Guidance")
	p.assertContainsText("Scan Insights")
}
