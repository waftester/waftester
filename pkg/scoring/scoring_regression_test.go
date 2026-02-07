// Regression test for bug: case-sensitive severity comparison in scoring
package scoring

import (
"testing"
)

// TestCalculate_CaseInsensitiveSeverity verifies that severity matching is
// case-insensitive. All case variants of the same severity must produce
// identical base scores.
// Regression test for bug: case-sensitive severity map lookup
func TestCalculate_CaseInsensitiveSeverity(t *testing.T) {
tests := []struct {
severity  string
wantScore float64
}{
// Critical variants → base 10.0
{"CRITICAL", 10.0},
{"Critical", 10.0},
{"critical", 10.0},
{"CrItIcAl", 10.0},
// High variants → base 7.0
{"HIGH", 7.0},
{"High", 7.0},
{"high", 7.0},
// Medium variants → base 5.0
{"MEDIUM", 5.0},
{"Medium", 5.0},
{"medium", 5.0},
// Low variants → base 3.0
{"LOW", 3.0},
{"Low", 3.0},
{"low", 3.0},
}

for _, tt := range tests {
t.Run(tt.severity, func(t *testing.T) {
input := Input{
Severity:   tt.severity,
Outcome:    "Bypassed",
StatusCode: 200,
}
result := Calculate(input)

// All case variants must produce the same RiskScore
referenceInput := Input{
Severity:   "critical",
Outcome:    "Bypassed",
StatusCode: 200,
}
if tt.wantScore == 10.0 {
referenceInput.Severity = "critical"
} else if tt.wantScore == 7.0 {
referenceInput.Severity = "high"
} else if tt.wantScore == 5.0 {
referenceInput.Severity = "medium"
} else {
referenceInput.Severity = "low"
}
referenceResult := Calculate(referenceInput)

if result.RiskScore != referenceResult.RiskScore {
t.Errorf("Calculate(%q).RiskScore = %f, want %f (same as %q)",
tt.severity, result.RiskScore, referenceResult.RiskScore, referenceInput.Severity)
}
})
}
}

// TestCalculate_UnknownSeverity_DefaultsToMedium verifies that unknown or empty
// severity values default to the medium baseline (5.0).
// Regression test for bug: unknown severity causing zero score
func TestCalculate_UnknownSeverity_DefaultsToMedium(t *testing.T) {
tests := []struct {
name     string
severity string
}{
{"unknown_string", "UNKNOWN"},
{"empty_string", ""},
{"garbage", "not-a-severity"},
{"numeric", "42"},
}

// Get reference score for explicit "medium"
mediumResult := Calculate(Input{
Severity:   "medium",
Outcome:    "Bypassed",
StatusCode: 200,
})

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
input := Input{
Severity:   tt.severity,
Outcome:    "Bypassed",
StatusCode: 200,
}
result := Calculate(input)

if result.RiskScore != mediumResult.RiskScore {
t.Errorf("Calculate(severity=%q).RiskScore = %f, want %f (medium default)",
tt.severity, result.RiskScore, mediumResult.RiskScore)
}
})
}
}
