// Regression test for Bug #5: RiskConfidence computed before Confidence default.
//
// Before the fix, enrichFinding() computed RiskConfidence using finding.Confidence
// before setting the default ("High"), resulting in output like "critical ()"
// instead of "critical (High)".
package report

import (
	"fmt"
	"testing"

	"github.com/waftester/waftester/pkg/finding"
)

// TestEnrichFinding_RiskConfidence_IncludesConfidence verifies that
// RiskConfidence contains a non-empty Confidence value.
//
// Regression: Confidence default was set AFTER RiskConfidence was computed,
// producing "severity ()" instead of "severity (High)".
func TestEnrichFinding_RiskConfidence_IncludesConfidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		severity   string
		confidence string
		wantRC     string
	}{
		{
			name:       "empty confidence gets default High",
			severity:   "critical",
			confidence: "",
			wantRC:     "critical (High)",
		},
		{
			name:       "explicit confidence preserved",
			severity:   "high",
			confidence: "Medium",
			wantRC:     "high (Medium)",
		},
		{
			name:       "info severity with default",
			severity:   "info",
			confidence: "",
			wantRC:     "info (High)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			finding := &BypassFinding{
				Severity:   tt.severity,
				Confidence: tt.confidence,
				Category:   "test",
			}

			EnrichBypassFinding(finding)

			if finding.RiskConfidence != tt.wantRC {
				t.Errorf("RiskConfidence = %q, want %q", finding.RiskConfidence, tt.wantRC)
			}

			// Confidence must never be empty after enrichment.
			if finding.Confidence == "" {
				t.Error("Confidence is empty after EnrichBypassFinding()")
			}
		})
	}
}

// TestEnrichFinding_RiskConfidence_FormatConsistency verifies the format is
// always "severity (confidence)" with no empty parenthesized values.
func TestEnrichFinding_RiskConfidence_FormatConsistency(t *testing.T) {
	t.Parallel()

	severities := finding.OrderedStrings()
	for _, sev := range severities {
		t.Run(sev, func(t *testing.T) {
			t.Parallel()

			finding := &BypassFinding{
				Severity: sev,
				Category: "xss",
			}

			EnrichBypassFinding(finding)

			// Must match "severity (confidence)" format.
			want := fmt.Sprintf("%s (%s)", sev, finding.Confidence)
			if finding.RiskConfidence != want {
				t.Errorf("RiskConfidence = %q, want %q", finding.RiskConfidence, want)
			}

			// Must NOT contain empty parens.
			if finding.RiskConfidence == sev+" ()" {
				t.Errorf("RiskConfidence contains empty parentheses: %q", finding.RiskConfidence)
			}
		})
	}
}
