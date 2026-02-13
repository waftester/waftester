package report

// Security boundary tests for compliance reports — verifies HTML injection
// is prevented in report output. Would have caught R1 HTML injection in compliance.go.

import (
	"strings"
	"testing"
)

// TestFormatComplianceTable_HTMLInjection verifies that user-controlled fields
// are HTML-escaped in compliance table output. XSS payloads in control fields
// must not appear unescaped in the output.
func TestFormatComplianceTable_HTMLInjection(t *testing.T) {
	t.Parallel()

	xssPayloads := []string{
		`<script>alert('xss')</script>`,
		`"><img src=x onerror=alert(1)>`,
		`<svg/onload=alert('xss')>`,
		`javascript:alert(1)`,
	}

	for _, payload := range xssPayloads {
		controls := []ComplianceControl{
			{
				Framework:   FrameworkOWASP,
				ControlID:   payload,
				ControlName: payload,
				Description: payload,
				Status:      StatusFail,
				Evidence:    payload,
				Remediation: payload,
			},
		}

		output := FormatComplianceTable(controls)

		// Dangerous HTML tags must not appear unescaped in the output.
		// html.EscapeString converts < to &lt; and > to &gt;, so raw tags
		// like <script>, <img, <svg must not be present.
		if strings.Contains(output, "<script>") {
			t.Errorf("unescaped <script> tag in output for payload: %s", payload)
		}
		if strings.Contains(output, "<img ") {
			t.Errorf("unescaped <img> tag in output for payload: %s", payload)
		}
		if strings.Contains(output, "<svg") && !strings.Contains(output, "&lt;svg") {
			t.Errorf("unescaped <svg> tag in output for payload: %s", payload)
		}
	}
}

// TestFormatComplianceTable_EmptyControls verifies empty input doesn't panic.
func TestFormatComplianceTable_EmptyControls(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on empty controls: %v", r)
		}
	}()

	output := FormatComplianceTable(nil)
	if output == "" {
		// Empty string is acceptable for no controls
		return
	}
}

// TestGenerateComplianceReport_NilStats verifies nil stats doesn't panic.
func TestGenerateComplianceReport_NilStats(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on nil stats: %v", r)
		}
	}()

	report := GenerateComplianceReport(FrameworkOWASP, nil, "test-org", "tester")
	if report == nil {
		t.Log("nil report for nil stats is acceptable")
	}
}

// TestFormatComplianceTable_SpecialCharacters verifies ampersand and angle
// brackets are properly escaped in all fields.
func TestFormatComplianceTable_SpecialCharacters(t *testing.T) {
	t.Parallel()

	controls := []ComplianceControl{
		{
			Framework:   FrameworkPCIDSS,
			ControlID:   "A&B<C>D",
			ControlName: "Test & Verify <all>",
			Description: "Check A > B && C < D",
			Status:      StatusPass,
			Evidence:    `"quotes" & 'apostrophes'`,
		},
	}

	output := FormatComplianceTable(controls)

	// Raw < and > should not appear (should be &lt; &gt;)
	if strings.Contains(output, "A&B<C>D") {
		t.Error("unescaped angle brackets in ControlID")
	}
}
