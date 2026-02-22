// Regression tests for scoring determinism with multiple sensitive patterns.
package scoring

import (
	"testing"
)

// TestMultiplePatterns_DeterministicHighestImpact verifies that when a response
// contains multiple sensitive patterns, the HIGHEST impact one is always selected.
// Regression: map iteration order in Go is random, causing non-deterministic scoring.
// The same input could produce different RiskScore and FinalSeverity across runs.
func TestMultiplePatterns_DeterministicHighestImpact(t *testing.T) {
	t.Parallel()

	// Response contains ALL sensitive patterns
	allPatterns := "root:x:0:0 AWS_ACCESS_KEY_ID=xxx DATABASE_URL=postgres://x SECRET_KEY=abc -----BEGIN RSA PRIVATE KEY----- SQL syntax error"

	input := Input{
		Severity:         "Medium",
		Outcome:          "Fail",
		ResponseContains: allPatterns,
	}

	// Run 200 times — must be identical every time
	firstResult := Calculate(input)

	for i := 0; i < 200; i++ {
		result := Calculate(input)

		if result.RiskScore != firstResult.RiskScore {
			t.Fatalf("Non-deterministic scoring at iteration %d: got RiskScore=%.2f, first was %.2f",
				i, result.RiskScore, firstResult.RiskScore)
		}

		if result.FinalSeverity != firstResult.FinalSeverity {
			t.Fatalf("Non-deterministic severity at iteration %d: got %q, first was %q",
				i, result.FinalSeverity, firstResult.FinalSeverity)
		}

		if result.EscalationReason != firstResult.EscalationReason {
			t.Fatalf("Non-deterministic escalation at iteration %d: got %q, first was %q",
				i, result.EscalationReason, firstResult.EscalationReason)
		}
	}
}

// TestMultiplePatterns_HighestImpactWins verifies the highest-impact pattern
// is selected (not the first one found or a random one).
func TestMultiplePatterns_HighestImpactWins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		response       string
		wantReason     string
		wantEscalation bool // true if FinalSeverity should be "critical"
	}{
		{
			name:           "aws_and_passwd",
			response:       "root:x:0:0 AWS_ACCESS_KEY_ID=xxx",
			wantReason:     "AWS credentials exposed", // Impact 4.0 > 3.0
			wantEscalation: true,                      // Impact >= 4.0
		},
		{
			name:           "private_key_and_sql_error",
			response:       "SQL syntax error near -----BEGIN RSA PRIVATE KEY-----",
			wantReason:     "Private key exposed", // Impact 4.0 > 2.5
			wantEscalation: true,
		},
		{
			name:           "database_url_and_secret_key",
			response:       "DATABASE_URL=postgres://x SECRET_KEY=abc",
			wantReason:     "Database connection string leaked", // Impact 3.5 > 3.0
			wantEscalation: false,                               // Both < 4.0
		},
		{
			name:           "single_low_impact_pattern",
			response:       "SQL syntax error at line 1",
			wantReason:     "SQL error indicates injection success", // Impact 2.5
			wantEscalation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := Input{
				Severity:         "Low",
				Outcome:          "Fail",
				ResponseContains: tt.response,
			}

			result := Calculate(input)

			if result.EscalationReason != tt.wantReason {
				t.Errorf("EscalationReason = %q, want %q", result.EscalationReason, tt.wantReason)
			}

			if tt.wantEscalation && result.FinalSeverity != "critical" {
				t.Errorf("FinalSeverity = %q, want critical (impact >= 4.0)", result.FinalSeverity)
			}

			if !tt.wantEscalation && result.FinalSeverity == "critical" {
				t.Errorf("FinalSeverity = %q, should NOT be critical (impact < 4.0)", result.FinalSeverity)
			}
		})
	}
}

// TestSinglePatternStillWorks verifies the fix doesn't break single-pattern detection.
func TestSinglePatternStillWorks(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"root:x:0:0":        "/etc/passwd contents detected",
		"AWS_ACCESS_KEY_ID": "AWS credentials exposed",
		"DATABASE_URL":      "Database connection string leaked",
		"SECRET_KEY":        "Application secret key exposed",
		"-----BEGIN":        "Private key exposed",
		"SQL syntax":        "SQL error indicates injection success",
	}

	for pattern, wantReason := range patterns {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			input := Input{
				Severity:         "Medium",
				Outcome:          "Fail",
				ResponseContains: pattern,
			}

			result := Calculate(input)

			if result.EscalationReason != wantReason {
				t.Errorf("Pattern %q: got reason %q, want %q",
					pattern, result.EscalationReason, wantReason)
			}
		})
	}
}
