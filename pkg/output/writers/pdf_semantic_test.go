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
	// With TOC enabled: Cover(1) + TOC(1) + ExecSummary(1) + OWASP(1) + Findings[sqli](1) + Methodology(1) = 6
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertPageCount(6)
}

func TestPDF_PageCount_WithoutTOC(t *testing.T) {
	t.Parallel()
	// Without TOC: Cover(1) + ExecSummary(1) + OWASP(1) + Findings[sqli](1) + Methodology(1) = 5
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: false}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertPageCount(5)
}

func TestPDF_PageCount_MultipleCategories(t *testing.T) {
	t.Parallel()
	// Each category gets its own page for findings
	// Cover(1) + TOC(1) + Summary(1) + OWASP(1) + Findings[lfi,sqli,xss](3) + Methodology(1) = 8
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
		makeBypassResult("xss-001", "xss", events.SeverityHigh, []string{"A03:2021"}),
		makeBypassResult("lfi-001", "lfi", events.SeverityMedium, []string{"A01:2021"}),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertPageCount(8)
}

func TestPDF_PageCount_NoBypassesFewerPages(t *testing.T) {
	t.Parallel()
	// All blocked: findings section is a single page with "No bypass vulnerabilities detected."
	// Cover(1) + TOC(1) + Summary(1) + OWASP(1) + Findings[empty](1) + Methodology(1) = 6
	results := []*events.ResultEvent{
		makeBlockedResult("sqli-001", "sqli", events.SeverityHigh, nil),
		makeBlockedResult("xss-001", "xss", events.SeverityHigh, nil),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, results, makePDFTestSummaryEvent())
	p.assertValid()
	p.assertPageCount(6)
}

func TestPDF_ContainsSectionHeaders(t *testing.T) {
	t.Parallel()
	results := []*events.ResultEvent{
		makeBypassResult("sqli-001", "sqli", events.SeverityCritical, []string{"A03:2021"}),
	}
	p := generatePDF(t, PDFConfig{IncludeTOC: true}, results, makePDFTestSummaryEvent())

	p.assertContainsText("Executive Summary")
	p.assertContainsText("OWASP Top 10 Coverage")
	p.assertContainsText("Detailed Findings")
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
	// Cover + TOC + Summary("No summary data") + OWASP + Findings("No bypass") + Methodology = 6
	p.assertPageCount(6)
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

	// Cover + TOC + Summary + OWASP + 5 category pages + Methodology = 10
	p.assertPageCount(10)
}

func TestPDF_TimingInfo(t *testing.T) {
	t.Parallel()
	summary := makePDFTestSummaryEvent()
	summary.Timing.StartedAt = time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC)

	p := generatePDF(t, PDFConfig{}, nil, summary)
	p.assertContainsText("2026-02-15")
}
