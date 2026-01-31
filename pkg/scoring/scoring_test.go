package scoring

import (
	"strings"
	"testing"
)

// TestCalculateBlockedLowScore verifies blocked attacks get low scores
func TestCalculateBlockedLowScore(t *testing.T) {
	input := Input{
		Severity:   "Critical",
		Outcome:    "Blocked",
		StatusCode: 403,
		Category:   "sqli",
	}

	result := Calculate(input)

	// Blocked should have very low score despite Critical severity
	if result.RiskScore > 20 {
		t.Errorf("Blocked Critical attack scored too high: %.1f (want < 20)", result.RiskScore)
	}
}

// TestCalculateFailHighScore verifies failed blocks get high scores
func TestCalculateFailHighScore(t *testing.T) {
	input := Input{
		Severity:   "Critical",
		Outcome:    "Fail",
		StatusCode: 200,
		Category:   "sqli",
	}

	result := Calculate(input)

	// Failed block on Critical should score high
	if result.RiskScore < 50 {
		t.Errorf("Failed Critical attack scored too low: %.1f (want > 50)", result.RiskScore)
	}
}

// TestCalculateSeverityLevels verifies severity affects score
func TestCalculateSeverityLevels(t *testing.T) {
	outcomes := []string{"Fail"} // Same outcome for comparison

	for _, outcome := range outcomes {
		criticalInput := Input{Severity: "Critical", Outcome: outcome}
		highInput := Input{Severity: "High", Outcome: outcome}
		mediumInput := Input{Severity: "Medium", Outcome: outcome}
		lowInput := Input{Severity: "Low", Outcome: outcome}

		criticalResult := Calculate(criticalInput)
		highResult := Calculate(highInput)
		mediumResult := Calculate(mediumInput)
		lowResult := Calculate(lowInput)

		if criticalResult.RiskScore <= highResult.RiskScore {
			t.Errorf("Critical (%.1f) should score higher than High (%.1f)",
				criticalResult.RiskScore, highResult.RiskScore)
		}
		if highResult.RiskScore <= mediumResult.RiskScore {
			t.Errorf("High (%.1f) should score higher than Medium (%.1f)",
				highResult.RiskScore, mediumResult.RiskScore)
		}
		if mediumResult.RiskScore <= lowResult.RiskScore {
			t.Errorf("Medium (%.1f) should score higher than Low (%.1f)",
				mediumResult.RiskScore, lowResult.RiskScore)
		}
	}
}

// TestCalculateSensitivePatternEscalation verifies pattern detection
func TestCalculateSensitivePatternEscalation(t *testing.T) {
	testCases := []struct {
		name           string
		response       string
		expectEscalate bool
		expectReason   string
	}{
		{
			name:           "AWS credentials",
			response:       "config: AWS_ACCESS_KEY_ID=AKIA...",
			expectEscalate: true,
			expectReason:   "AWS credentials exposed",
		},
		{
			name:           "passwd file",
			response:       "root:x:0:0:root:/root:/bin/bash",
			expectEscalate: false, // Impact 3.0 < 4.0 threshold for escalation
			expectReason:   "/etc/passwd contents detected",
		},
		{
			name:           "private key",
			response:       "-----BEGIN RSA PRIVATE KEY-----",
			expectEscalate: true,
			expectReason:   "Private key exposed",
		},
		{
			name:           "normal response",
			response:       "Welcome to our website",
			expectEscalate: false,
			expectReason:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := Input{
				Severity:         "Medium",
				Outcome:          "Fail",
				ResponseContains: tc.response,
			}

			result := Calculate(input)

			// Check escalation reason (pattern detection)
			if tc.expectReason != "" {
				if result.EscalationReason != tc.expectReason {
					t.Errorf("EscalationReason: got %q, want %q",
						result.EscalationReason, tc.expectReason)
				}
			}

			// Check severity escalation
			if tc.expectEscalate {
				if result.FinalSeverity != "Critical" {
					t.Errorf("Should escalate to Critical, got %s", result.FinalSeverity)
				}
			}
		})
	}
}

// TestCalculateXSSReflection verifies reflected XSS detection
func TestCalculateXSSReflection(t *testing.T) {
	input := Input{
		Severity:  "High",
		Outcome:   "Fail",
		Reflected: true,
	}

	result := Calculate(input)

	if result.EscalationReason != "XSS payload reflected" {
		t.Errorf("Should detect XSS reflection, got: %s", result.EscalationReason)
	}
}

// TestCalculateTimingAttack verifies blind injection timing detection
func TestCalculateTimingAttack(t *testing.T) {
	input := Input{
		Severity:  "High",
		Outcome:   "Fail",
		LatencyMs: 6000, // > 5 seconds
	}

	result := Calculate(input)

	if result.EscalationReason != "Timing differential suggests blind injection" {
		t.Errorf("Should detect timing attack, got: %s", result.EscalationReason)
	}
}

// TestCalculateUnknownSeverityDefaults verifies default handling
func TestCalculateUnknownSeverityDefaults(t *testing.T) {
	input := Input{
		Severity: "Unknown",
		Outcome:  "Fail",
	}

	result := Calculate(input)

	// Should not panic and should use Medium default
	if result.RiskScore == 0 {
		t.Error("Unknown severity should still calculate a score")
	}
}

// TestNormalizeRange verifies scores are 0-100
func TestNormalizeRange(t *testing.T) {
	testCases := []Input{
		{Severity: "Critical", Outcome: "Fail", Reflected: true, ResponseContains: "root:x:0:0"},
		{Severity: "Low", Outcome: "Blocked"},
		{Severity: "Low", Outcome: "Pass"},
	}

	for _, input := range testCases {
		result := Calculate(input)
		if result.RiskScore < 0 || result.RiskScore > 100 {
			t.Errorf("Score out of range: %.1f (input: %+v)", result.RiskScore, input)
		}
	}
}

// =============================================================================
// DEEP BUG-FINDING TESTS - Line by line analysis
// =============================================================================

// TestSeverityScoreMapCompleteness verifies all severities have scores
func TestSeverityScoreMapCompleteness(t *testing.T) {
	// The severityScores map should have these exact values
	expectedScores := map[string]float64{
		"Critical": 10.0,
		"High":     7.0,
		"Medium":   5.0,
		"Low":      3.0,
	}

	for sev, expectedScore := range expectedScores {
		if score := severityScores[sev]; score != expectedScore {
			t.Errorf("severityScores[%q] = %.1f, want %.1f", sev, score, expectedScore)
		}
	}

	// BUG CHECK: What about case variants?
	caseVariants := []string{"critical", "CRITICAL", "high", "HIGH", "medium", "MEDIUM", "low", "LOW"}
	for _, variant := range caseVariants {
		if score := severityScores[variant]; score != 0 {
			t.Errorf("Unexpected: severityScores[%q] = %.1f (case-sensitive?)", variant, score)
		} else {
			// This documents that severity scoring IS case-sensitive
			// Unlike validation which accepts both Critical and critical
		}
	}
	t.Log("NOTE: severityScores is case-sensitive - only 'Critical'/'High'/'Medium'/'Low' work")
}

// TestCalculateEmptyInput tests completely empty input
func TestCalculateEmptyInput(t *testing.T) {
	input := Input{} // All zero values

	result := Calculate(input)

	// Should not panic
	// Empty severity should use default 5.0
	// Empty outcome should not match any case
	if result.RiskScore < 0 || result.RiskScore > 100 {
		t.Errorf("Empty input produced invalid score: %.1f", result.RiskScore)
	}

	// Document: empty outcome doesn't trigger any modifier
	t.Logf("Empty input score: %.1f (FinalSeverity: %q)", result.RiskScore, result.FinalSeverity)
}

// TestCalculateUnknownOutcome tests unknown outcome values
func TestCalculateUnknownOutcome(t *testing.T) {
	outcomes := []string{"", "Unknown", "Timeout", "Redirect", "error", "fail", "FAIL"}

	for _, outcome := range outcomes {
		input := Input{Severity: "High", Outcome: outcome}
		result := Calculate(input)

		// Should not panic and should produce valid score
		if result.RiskScore < 0 || result.RiskScore > 100 {
			t.Errorf("Outcome %q produced invalid score: %.1f", outcome, result.RiskScore)
		}
	}

	// BUG: outcome is case-sensitive
	// "Fail" works, but "fail" doesn't get the impactWeight=1.5
	failResult := Calculate(Input{Severity: "High", Outcome: "Fail"})
	lowercaseResult := Calculate(Input{Severity: "High", Outcome: "fail"})

	// BUG: Outcomes should be case-INSENSITIVE!
	if failResult.RiskScore != lowercaseResult.RiskScore {
		t.Errorf("BUG: 'Fail' scores %.1f but 'fail' scores %.1f - outcomes should be case-insensitive!",
			failResult.RiskScore, lowercaseResult.RiskScore)
	}
}

// TestCalculateNegativeLatency tests negative latency handling
func TestCalculateNegativeLatency(t *testing.T) {
	input := Input{
		Severity:  "High",
		Outcome:   "Fail",
		LatencyMs: -1000, // Negative - should this happen?
	}

	result := Calculate(input)

	// Should handle gracefully
	if result.RiskScore < 0 || result.RiskScore > 100 {
		t.Errorf("Negative latency produced invalid score: %.1f", result.RiskScore)
	}

	// Check that timing attack detection doesn't trigger for negative values
	if result.EscalationReason == "Timing differential suggests blind injection" {
		t.Error("BUG: Negative latency should NOT trigger timing attack detection")
	}
}

// TestCalculateExtremeLatency tests very large latency values
func TestCalculateExtremeLatency(t *testing.T) {
	// Test with max int64 value
	input := Input{
		Severity:  "High",
		Outcome:   "Fail",
		LatencyMs: 9223372036854775807, // max int64
	}

	result := Calculate(input)

	// Should not overflow
	if result.RiskScore < 0 || result.RiskScore > 100 {
		t.Errorf("Extreme latency produced invalid score: %.1f", result.RiskScore)
	}

	// Should trigger timing detection (> 5000ms)
	if result.EscalationReason != "Timing differential suggests blind injection" {
		t.Errorf("Extreme latency should trigger timing detection")
	}
}

// TestCalculatePatternMatchingEdgeCases tests pattern matching edge cases
func TestCalculatePatternMatchingEdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		response        string
		wantPatternHit  bool   // True if sensitive pattern should be detected
		wantSpecificMsg string // Expected reason substring (empty = any category fallback is OK)
	}{
		{"empty response", "", false, ""},
		{"pattern at start", "root:x:0:0 and more", true, "/etc/passwd"},
		{"pattern at end", "prefix root:x:0:0", true, "/etc/passwd"},
		{"pattern partial", "root:x:0", false, ""}, // Not complete pattern
		// BUG: "notroot:x:0:0" should NOT match - this is a false positive!
		// Simple substring matching causes security false positives
		{"pattern with prefix - FALSE POSITIVE BUG", "notroot:x:0:0", false, ""},
		{"only pattern", "root:x:0:0", true, "/etc/passwd"},
		{"pattern surrounded", "xxx root:x:0:0 yyy", true, "/etc/passwd"},
		{"very long response", string(make([]byte, 100000)) + "root:x:0:0", true, "/etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := Input{
				Severity:         "Medium",
				Outcome:          "Fail",
				ResponseContains: tt.response,
			}

			result := Calculate(input)

			// All Fail outcomes now get an EscalationReason (pattern-specific or category fallback)
			if result.EscalationReason == "" {
				t.Errorf("Expected EscalationReason for %q but got empty", tt.name)
			}

			// Check if pattern-specific reason was detected
			if tt.wantPatternHit {
				if tt.wantSpecificMsg != "" && !strings.Contains(result.EscalationReason, tt.wantSpecificMsg) {
					t.Errorf("Expected pattern-specific reason containing %q for %q, got: %s",
						tt.wantSpecificMsg, tt.name, result.EscalationReason)
				}
			} else {
				// Should get category fallback, not a pattern-specific message
				patternKeywords := []string{"/etc/passwd", "AWS", "DATABASE", "SECRET", "Private key", "SQL"}
				for _, kw := range patternKeywords {
					if strings.Contains(result.EscalationReason, kw) {
						t.Errorf("Unexpected pattern hit for %q: %s", tt.name, result.EscalationReason)
						break
					}
				}
			}
		})
	}
}

// TestCalculateMultiplePatternsFirstWins tests pattern priority
func TestCalculateMultiplePatternsFirstWins(t *testing.T) {
	// Response contains multiple sensitive patterns
	input := Input{
		Severity:         "Medium",
		Outcome:          "Fail",
		ResponseContains: "root:x:0:0 and AWS_ACCESS_KEY_ID=xxx and -----BEGIN PRIVATE KEY-----",
	}

	result := Calculate(input)

	// BUG CHECK: Which pattern wins? It depends on map iteration order!
	// Maps in Go have non-deterministic iteration order
	// This could cause flaky behavior
	if result.EscalationReason == "" {
		t.Error("Should detect at least one pattern")
	}

	t.Logf("Pattern detected: %s (note: map iteration order is non-deterministic!)", result.EscalationReason)
}

// TestCalculateSeverityEscalationThreshold tests the 4.0 threshold
func TestCalculateSeverityEscalationThreshold(t *testing.T) {
	// Patterns with Impact >= 4.0 should escalate to Critical
	highImpactPatterns := []string{"AWS_ACCESS_KEY_ID", "-----BEGIN"}
	lowImpactPatterns := []string{"root:x:0:0", "DATABASE_URL", "SECRET_KEY", "SQL syntax"}

	for _, pattern := range highImpactPatterns {
		input := Input{Severity: "Low", Outcome: "Fail", ResponseContains: pattern}
		result := Calculate(input)
		if result.FinalSeverity != "Critical" {
			t.Errorf("Pattern %q (impact>=4.0) should escalate to Critical, got %s",
				pattern, result.FinalSeverity)
		}
	}

	for _, pattern := range lowImpactPatterns {
		input := Input{Severity: "Low", Outcome: "Fail", ResponseContains: pattern}
		result := Calculate(input)
		if result.FinalSeverity == "Critical" {
			t.Errorf("Pattern %q (impact<4.0) should NOT escalate to Critical", pattern)
		}
	}
}

// TestCalculateXSSAndPatternCombination tests XSS with pattern
func TestCalculateXSSAndPatternCombination(t *testing.T) {
	input := Input{
		Severity:         "Medium",
		Outcome:          "Fail",
		Reflected:        true,
		ResponseContains: "normal content",
	}

	result := Calculate(input)

	// XSS reflection should set escalation reason
	if result.EscalationReason != "XSS payload reflected" {
		t.Errorf("XSS should be detected, got: %s", result.EscalationReason)
	}

	// Now with pattern - pattern should take precedence (or not?)
	inputWithPattern := Input{
		Severity:         "Medium",
		Outcome:          "Fail",
		Reflected:        true,
		ResponseContains: "AWS_ACCESS_KEY_ID=xxx",
	}

	resultWithPattern := Calculate(inputWithPattern)

	// Pattern is checked first, so pattern reason wins
	if resultWithPattern.EscalationReason == "XSS payload reflected" {
		t.Log("BUG: XSS reason overwriting pattern reason - should pattern win?")
	}
	t.Logf("Combined XSS+Pattern reason: %s", resultWithPattern.EscalationReason)
}

// TestCalculateTimingThresholdBoundary tests exact 5000ms boundary
func TestCalculateTimingThresholdBoundary(t *testing.T) {
	tests := []struct {
		latency int64
		wantHit bool
	}{
		{4999, false}, // Just below threshold
		{5000, false}, // Exactly at threshold - > not >=
		{5001, true},  // Just above threshold
	}

	for _, tt := range tests {
		input := Input{Severity: "High", Outcome: "Fail", LatencyMs: tt.latency}
		result := Calculate(input)

		detected := result.EscalationReason == "Timing differential suggests blind injection"

		if detected != tt.wantHit {
			t.Errorf("Latency %d: detected=%v, want=%v", tt.latency, detected, tt.wantHit)
		}
	}
}

// TestCalculateTimingOnlyOnFail tests timing only triggers on Fail
func TestCalculateTimingOnlyOnFail(t *testing.T) {
	outcomes := []string{"Blocked", "Pass", "Error", ""}

	for _, outcome := range outcomes {
		input := Input{Severity: "High", Outcome: outcome, LatencyMs: 10000}
		result := Calculate(input)

		if result.EscalationReason == "Timing differential suggests blind injection" {
			t.Errorf("Timing attack should only trigger on Fail, not %q", outcome)
		}
	}
}

// TestContainsPatternEdgeCases tests the containsPattern helper
func TestContainsPatternEdgeCases(t *testing.T) {
	tests := []struct {
		text    string
		pattern string
		want    bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello world", "lo wo", true},
		{"hello world", "", false},     // Empty pattern
		{"", "world", false},           // Empty text
		{"", "", false},                // Both empty
		{"ab", "abc", false},           // Pattern longer than text
		{"abc", "abc", true},           // Exact match
		{"aaa", "aa", true},            // Overlapping matches
		{"abc\x00def", "c\x00d", true}, // Null byte in middle
	}

	for _, tt := range tests {
		got := containsPattern(tt.text, tt.pattern)
		if got != tt.want {
			t.Errorf("containsPattern(%q, %q) = %v, want %v",
				tt.text, tt.pattern, got, tt.want)
		}
	}
}

// TestNormalizeBoundaries tests normalize function edge cases
func TestNormalizeBoundaries(t *testing.T) {
	tests := []struct {
		raw  float64
		want float64
	}{
		{-100, 0},   // Very negative
		{-3, 0},     // At formula minimum
		{0, 13.636}, // Around zero (approximately)
		{19, 100},   // At formula maximum
		{100, 100},  // Very positive
	}

	for _, tt := range tests {
		got := normalize(tt.raw)
		if got < 0 || got > 100 {
			t.Errorf("normalize(%.1f) = %.1f, should be 0-100", tt.raw, got)
		}
	}
}

// TestCalculateScoreConsistency tests deterministic scoring
func TestCalculateScoreConsistency(t *testing.T) {
	input := Input{
		Severity:   "High",
		Outcome:    "Fail",
		StatusCode: 200,
		LatencyMs:  100,
		Category:   "sqli",
	}

	// Calculate 100 times - should get same result
	firstResult := Calculate(input)

	for i := 0; i < 100; i++ {
		result := Calculate(input)
		if result.RiskScore != firstResult.RiskScore {
			t.Errorf("Inconsistent scoring: iteration %d got %.1f, first was %.1f",
				i, result.RiskScore, firstResult.RiskScore)
		}
	}
}

// TestCalculateStatusCodeIgnored verifies status code doesn't affect score
func TestCalculateStatusCodeIgnored(t *testing.T) {
	// Status code is in Input but not used in Calculate
	input1 := Input{Severity: "High", Outcome: "Fail", StatusCode: 200}
	input2 := Input{Severity: "High", Outcome: "Fail", StatusCode: 500}
	input3 := Input{Severity: "High", Outcome: "Fail", StatusCode: 0}

	result1 := Calculate(input1)
	result2 := Calculate(input2)
	result3 := Calculate(input3)

	if result1.RiskScore != result2.RiskScore || result2.RiskScore != result3.RiskScore {
		t.Log("NOTE: StatusCode affects scoring - is this intentional?")
	} else {
		t.Log("NOTE: StatusCode is included in Input but NOT used in scoring calculation")
	}
}

// TestCalculateCategoryIgnored verifies category doesn't affect score
func TestCalculateCategoryIgnored(t *testing.T) {
	// Category is in Input but not used in Calculate
	input1 := Input{Severity: "High", Outcome: "Fail", Category: "sqli"}
	input2 := Input{Severity: "High", Outcome: "Fail", Category: "xss"}
	input3 := Input{Severity: "High", Outcome: "Fail", Category: ""}

	result1 := Calculate(input1)
	result2 := Calculate(input2)
	result3 := Calculate(input3)

	if result1.RiskScore != result2.RiskScore || result2.RiskScore != result3.RiskScore {
		t.Log("NOTE: Category affects scoring - is this intentional?")
	} else {
		t.Log("NOTE: Category is included in Input but NOT used in scoring calculation")
	}
}
