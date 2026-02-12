// Regression test for bug: PDFWriter constructor overrode IncludeEvidence=false.
//
// Before the fix, NewPDFWriter had:
//   if !config.IncludeEvidence { config.IncludeEvidence = true }
// This forced IncludeEvidence to true regardless of what the user set,
// making it impossible to exclude evidence from PDF reports.
// The fix removes this override so the user's config is respected.
package writers

import (
	"bytes"
	"testing"
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
