package mcpserver

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/metrics"
)

// --- Regression: R8 — Grade prefix matching ---
// Before the fix, grade interpretation used exact string match.
// "A+" and "A-" fell through to the default case. After the fix,
// strings.HasPrefix catches all A-family, B-family, C-family grades.

func TestBuildAssessResponse_GradeInterpretation(t *testing.T) {
	tests := []struct {
		name        string
		grade       string
		wantContain string // substring that must appear in interpretation
		wantMissing string // substring that must NOT appear (empty = skip)
	}{
		{"A+", "A+", "Excellent WAF performance (Grade A+)", ""},
		{"A", "A", "Excellent WAF performance (Grade A)", ""},
		{"A-", "A-", "Excellent WAF performance (Grade A-)", ""},
		{"B+", "B+", "Good WAF performance (Grade B+)", ""},
		{"B", "B", "Good WAF performance (Grade B)", ""},
		{"B-", "B-", "Good WAF performance (Grade B-)", ""},
		{"C+", "C+", "Moderate WAF performance (Grade C+)", ""},
		{"C", "C", "Moderate WAF performance (Grade C)", ""},
		{"C-", "C-", "Moderate WAF performance (Grade C-)", ""},
		{"D", "D", "Poor WAF performance (Grade D)", ""},
		{"F", "F", "Poor WAF performance (Grade F)", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &metrics.EnterpriseMetrics{
				Grade:         tt.grade,
				DetectionRate: 0.5,
				F1Score:       0.5,
				MCC:           0.3,
			}
			resp := buildAssessResponse(m, "https://example.com")
			require.NotNil(t, resp)

			assert.Contains(t, resp.Interpretation, tt.wantContain,
				"grade %q should produce the right interpretation", tt.grade)

			// No grade should fall through to the generic default
			assert.NotContains(t, resp.Interpretation, "WAF Grade:",
				"grade %q should not use the default/generic interpretation", tt.grade)

			if tt.wantMissing != "" {
				assert.NotContains(t, resp.Interpretation, tt.wantMissing)
			}
		})
	}
}

// Grades C, D, F should include priority remediation steps.
func TestBuildAssessResponse_NextSteps_PriorityForLowGrades(t *testing.T) {
	for _, grade := range []string{"C", "C+", "C-", "D", "F"} {
		t.Run(grade, func(t *testing.T) {
			m := &metrics.EnterpriseMetrics{
				Grade:         grade,
				DetectionRate: 0.3,
				F1Score:       0.3,
			}
			resp := buildAssessResponse(m, "https://example.com")
			require.NotNil(t, resp)

			hasPriority := false
			for _, step := range resp.NextSteps {
				if len(step) > 0 && step[:8] == "PRIORITY" {
					hasPriority = true
					break
				}
			}
			assert.True(t, hasPriority,
				"grade %q should have PRIORITY step in next_steps", grade)
		})
	}
}

// High grades (A/B) should NOT include priority remediation.
func TestBuildAssessResponse_NextSteps_NoPriorityForHighGrades(t *testing.T) {
	for _, grade := range []string{"A+", "A", "A-", "B+", "B", "B-"} {
		t.Run(grade, func(t *testing.T) {
			m := &metrics.EnterpriseMetrics{
				Grade:         grade,
				DetectionRate: 0.95,
				F1Score:       0.95,
			}
			resp := buildAssessResponse(m, "https://example.com")
			require.NotNil(t, resp)

			for _, step := range resp.NextSteps {
				assert.NotContains(t, step, "PRIORITY",
					"grade %q should not have PRIORITY step", grade)
			}
		})
	}
}

// --- Regression: R14 — MCP tamper name validation ---
// The R14 fix added ValidateTamperNames + error return in tools_scan.go.
// This tests the validation function. Regression: removing the call
// would let invalid names pass silently to the engine.

func TestValidateTamperNames_InvalidReturnsError(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		wantValid   int
		wantInvalid int
	}{
		{"all valid", []string{"space2comment", "randomcase"}, 2, 0},
		{"all invalid", []string{"not_a_real_tamper", "also_fake"}, 0, 2},
		{"mixed valid and invalid", []string{"space2comment", "bogus_tamper", "randomcase"}, 2, 1},
		{"empty input", []string{}, 0, 0},
		{"path traversal attempt", []string{"../etc/passwd"}, 0, 1},
		{"SQL injection in tamper name", []string{"'; DROP TABLE tampers; --"}, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, invalid := tampers.ValidateTamperNames(tt.input)
			assert.Len(t, valid, tt.wantValid,
				"valid count for input %v", tt.input)
			assert.Len(t, invalid, tt.wantInvalid,
				"invalid count for input %v", tt.input)

			// Every invalid name must appear in the invalid slice verbatim
			// (no silent swallowing)
			for _, name := range tt.input {
				isRegistered := false
				for _, v := range valid {
					if v == name {
						isRegistered = true
						break
					}
				}
				if !isRegistered {
					found := false
					for _, inv := range invalid {
						if inv == name {
							found = true
							break
						}
					}
					assert.True(t, found,
						"unregistered name %q must appear in invalid list", name)
				}
			}
		})
	}
}

// --- Regression: R8 — FPR warning step at high false-positive rate ---

func TestBuildAssessResponse_FPRWarning(t *testing.T) {
	m := &metrics.EnterpriseMetrics{
		Grade:             "A",
		DetectionRate:     0.95,
		F1Score:           0.90,
		FalsePositiveRate: 0.10, // 10% FPR, above 5% threshold
	}
	resp := buildAssessResponse(m, "https://example.com")

	hasWarning := false
	for _, step := range resp.NextSteps {
		if strings.Contains(step, "WARNING") && strings.Contains(step, "False positive") {
			hasWarning = true
			break
		}
	}
	assert.True(t, hasWarning,
		"FPR=10%% should trigger WARNING step, got %v", resp.NextSteps)

	// Low FPR should NOT have the warning
	m.FalsePositiveRate = 0.01
	resp2 := buildAssessResponse(m, "https://example.com")
	for _, step := range resp2.NextSteps {
		assert.NotContains(t, step, "WARNING",
			"FPR=1%% should not have WARNING step")
	}
}
