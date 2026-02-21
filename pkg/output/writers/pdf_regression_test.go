// Regression tests for PDFWriter bugs.
package writers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/output/events"
)

func TestNewPDFWriter_RespectsIncludeEvidenceFalse(t *testing.T) {
	t.Parallel()

	cfg := PDFConfig{
		IncludeEvidence: false,
	}

	w := NewPDFWriter(&bytes.Buffer{}, cfg)
	if w.config.IncludeEvidence {
		t.Error("IncludeEvidence was overridden to true; user's false setting was ignored")
	}
}

func TestNewPDFWriter_RespectsIncludeEvidenceTrue(t *testing.T) {
	t.Parallel()

	cfg := PDFConfig{
		IncludeEvidence: true,
	}

	w := NewPDFWriter(&bytes.Buffer{}, cfg)
	if !w.config.IncludeEvidence {
		t.Error("IncludeEvidence should be true when explicitly set")
	}
}

func TestNewPDFWriter_DefaultValues(t *testing.T) {
	t.Parallel()

	// Zero-value config — IncludeEvidence defaults to false (Go zero value).
	w := NewPDFWriter(&bytes.Buffer{}, PDFConfig{})

	if w.config.Title == "" {
		t.Error("default Title should be set")
	}
	if w.config.PageSize == "" {
		t.Error("default PageSize should be set")
	}
	if w.config.Orientation == "" {
		t.Error("default Orientation should be set")
	}
	// IncludeEvidence defaults to false — callers must explicitly opt in.
	if w.config.IncludeEvidence {
		t.Error("IncludeEvidence should default to false (Go zero value)")
	}
}

// Regression: Write after Close must return error, not silently buffer.
func TestPDFWriter_WriteAfterClose(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	err := w.Write(makePDFTestResultEvent("sqli-001", "sqli", events.SeverityHigh, events.OutcomeBypass, nil))
	if err == nil {
		t.Error("Write after Close should return error")
	}
	if err != nil && !strings.Contains(err.Error(), "write after close") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Regression: blockRate > 100 must not produce negative arc angle.
func TestPDFWriter_RiskGauge_ClampsBlockRate(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})

	summary := makePDFTestSummaryEvent()
	// Malformed data: block rate above 100
	summary.Effectiveness.BlockRatePct = 150.0
	w.Write(summary)

	if err := w.Close(); err != nil {
		t.Fatalf("Close should not panic or error with blockRate>100: %v", err)
	}

	output := buf.Bytes()
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF with clamped block rate")
	}
}

// Regression: negative block rate must not produce malformed arc.
func TestPDFWriter_RiskGauge_NegativeBlockRate(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{})

	summary := makePDFTestSummaryEvent()
	summary.Effectiveness.BlockRatePct = -10.0
	w.Write(summary)

	if err := w.Close(); err != nil {
		t.Fatalf("Close should not panic with negative blockRate: %v", err)
	}
}

// Regression: Letter landscape has smaller page height; findings must not clip.
func TestPDFWriter_LetterLandscape_DynamicPageBreak(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	w := NewPDFWriter(buf, PDFConfig{
		PageSize:        "Letter",
		Orientation:     "L",
		IncludeEvidence: true,
	})

	// Add many findings to force page breaks
	for i := 0; i < 20; i++ {
		e := makePDFTestResultEvent(
			"sqli-"+string(rune('A'+i)),
			"sqli",
			events.SeverityHigh,
			events.OutcomeBypass,
			[]string{"A03:2021"},
		)
		w.Write(e)
	}
	w.Write(makePDFTestSummaryEvent())

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed for Letter landscape: %v", err)
	}

	output := buf.Bytes()
	if string(output[:4]) != "%PDF" {
		t.Error("expected valid PDF output for Letter landscape")
	}
}
