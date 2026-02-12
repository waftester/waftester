// Regression tests for benchmark precision, recall, and F1 formula correctness.
package benchmark

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPrecisionFormula_TPDivTPPlusFP verifies precision = TP / (TP + FP).
// Regression: precision was computed as (TP - FP) / TP, producing wrong results
// and even negative values when FP > TP.
func TestPrecisionFormula_TPDivTPPlusFP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		results       []Result
		wantPrecision float64
		wantRecall    float64
		wantF1        float64
	}{
		{
			name: "pure_true_positives",
			results: []Result{
				{TestName: "a1", Category: "sqli", Blocked: true, ExpectedBlock: true},
				{TestName: "a2", Category: "sqli", Blocked: true, ExpectedBlock: true},
			},
			// TP=2, FP=0, FN=0 → Precision=100, Recall=100, F1=100
			wantPrecision: 100.0,
			wantRecall:    100.0,
			wantF1:        100.0,
		},
		{
			name: "with_false_positives",
			results: []Result{
				{TestName: "a1", Category: "sqli", Blocked: true, ExpectedBlock: true},  // TP
				{TestName: "a2", Category: "sqli", Blocked: true, ExpectedBlock: true},  // TP
				{TestName: "b1", Category: "sqli", Blocked: true, ExpectedBlock: false}, // FP
			},
			// TP=2, FP=1, FN=0 → Precision=2/3=66.67, Recall=2/2=100
			wantPrecision: 66.67,
			wantRecall:    100.0,
		},
		{
			name: "fp_exceeds_tp_no_negative_precision",
			results: []Result{
				{TestName: "a1", Category: "sqli", Blocked: true, ExpectedBlock: true},  // TP
				{TestName: "b1", Category: "sqli", Blocked: true, ExpectedBlock: false}, // FP
				{TestName: "b2", Category: "sqli", Blocked: true, ExpectedBlock: false}, // FP
				{TestName: "b3", Category: "sqli", Blocked: true, ExpectedBlock: false}, // FP
			},
			// TP=1, FP=3, FN=0 → Precision=1/4=25 (old bug: would give (1-3)/1 = negative)
			wantPrecision: 25.0,
			wantRecall:    100.0,
		},
		{
			name: "with_false_negatives",
			results: []Result{
				{TestName: "a1", Category: "sqli", Blocked: true, ExpectedBlock: true},  // TP
				{TestName: "a2", Category: "sqli", Blocked: false, ExpectedBlock: true}, // FN
				{TestName: "a3", Category: "sqli", Blocked: false, ExpectedBlock: true}, // FN
			},
			// TP=1, FP=0, FN=2 → Precision=1/1=100, Recall=1/3=33.33
			wantPrecision: 100.0,
			wantRecall:    33.33,
		},
		{
			name: "mixed_realistic",
			results: []Result{
				{TestName: "a1", Category: "sqli", Blocked: true, ExpectedBlock: true},   // TP
				{TestName: "a2", Category: "sqli", Blocked: true, ExpectedBlock: true},   // TP
				{TestName: "a3", Category: "sqli", Blocked: true, ExpectedBlock: true},   // TP
				{TestName: "a4", Category: "sqli", Blocked: false, ExpectedBlock: true},  // FN
				{TestName: "b1", Category: "sqli", Blocked: true, ExpectedBlock: false},  // FP
				{TestName: "b2", Category: "sqli", Blocked: false, ExpectedBlock: false}, // TN
			},
			// TP=3, FP=1, FN=1, TN=1
			// Precision = 3/(3+1) = 75
			// Recall = 3/(3+1) = 75
			// F1 = 2*(75*75)/(75+75) = 75
			wantPrecision: 75.0,
			wantRecall:    75.0,
			wantF1:        75.0,
		},
		{
			name: "all_false_positives_no_attacks",
			results: []Result{
				{TestName: "b1", Category: "sqli", Blocked: true, ExpectedBlock: false}, // FP
				{TestName: "b2", Category: "sqli", Blocked: true, ExpectedBlock: false}, // FP
			},
			// TP=0, FP=2, FN=0 → Precision=0/2=0, Recall=0/0=0 (no attacks)
			wantPrecision: 0.0,
			wantRecall:    0.0,
			wantF1:        0.0,
		},
		{
			name: "all_bypassed",
			results: []Result{
				{TestName: "a1", Category: "sqli", Blocked: false, ExpectedBlock: true}, // FN
				{TestName: "a2", Category: "sqli", Blocked: false, ExpectedBlock: true}, // FN
			},
			// TP=0, FP=0, FN=2 → Precision=N/A (div0), Recall=0/2=0
			wantPrecision: 0.0,
			wantRecall:    0.0,
			wantF1:        0.0,
		},
	}

	scorer := NewScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := scorer.Score(tt.results)

			assert.InDelta(t, tt.wantPrecision, b.Precision, 0.1,
				"Precision: TP/(TP+FP)")

			// Calculate expected recall from the results
			if tt.wantRecall > 0 || tt.name != "" {
				// Compute actual recall: TP / (TP + FN)
				tp := b.TotalBlocked
				fn := b.FalseNegatives
				expectedRecall := 0.0
				if tp+fn > 0 {
					expectedRecall = float64(tp) / float64(tp+fn) * 100
				}
				assert.InDelta(t, tt.wantRecall, expectedRecall, 0.1,
					"Recall should be TP/(TP+FN)")
			}

			if tt.wantF1 > 0 {
				assert.InDelta(t, tt.wantF1, b.F1Score, 0.1,
					"F1 = 2*precision*recall/(precision+recall)")
			}

			// Invariant: precision must NEVER be negative
			if b.Precision < 0 {
				t.Errorf("Precision must not be negative, got %.2f", b.Precision)
			}

			// Invariant: precision must NEVER exceed 100
			if b.Precision > 100.01 {
				t.Errorf("Precision must not exceed 100, got %.2f", b.Precision)
			}
		})
	}
}

// TestRecallIsNotBlockRate verifies recall uses TP/(TP+FN), not TP/TotalTests.
// Regression: F1 used BlockRate (TP/TotalTests) as recall, which is wrong
// whenever non-attack (expected-pass) tests exist.
func TestRecallIsNotBlockRate(t *testing.T) {
	t.Parallel()

	scorer := NewScorer()

	// Scenario: 2 attacks (1 blocked, 1 bypassed) + 8 benign (all correctly allowed)
	results := []Result{
		{TestName: "atk1", Category: "sqli", Blocked: true, ExpectedBlock: true},  // TP
		{TestName: "atk2", Category: "sqli", Blocked: false, ExpectedBlock: true}, // FN
		{TestName: "b1", Category: "sqli", Blocked: false, ExpectedBlock: false},  // TN
		{TestName: "b2", Category: "sqli", Blocked: false, ExpectedBlock: false},  // TN
		{TestName: "b3", Category: "sqli", Blocked: false, ExpectedBlock: false},  // TN
		{TestName: "b4", Category: "sqli", Blocked: false, ExpectedBlock: false},  // TN
		{TestName: "b5", Category: "sqli", Blocked: false, ExpectedBlock: false},  // TN
		{TestName: "b6", Category: "sqli", Blocked: false, ExpectedBlock: false},  // TN
		{TestName: "b7", Category: "sqli", Blocked: false, ExpectedBlock: false},  // TN
		{TestName: "b8", Category: "sqli", Blocked: false, ExpectedBlock: false},  // TN
	}

	b := scorer.Score(results)

	// TP=1, FN=1 → Correct recall = 1/(1+1) = 50%
	// BlockRate = 1/10 = 10% (wrong if used as recall)
	assert.Equal(t, 10.0, b.BlockRate, "BlockRate = TP/TotalTests")

	// F1 should use correct recall (50%), NOT BlockRate (10%)
	// Precision = TP/(TP+FP) = 1/(1+0) = 100%
	// F1 = 2 * (100 * 50) / (100 + 50) = 66.67
	assert.InDelta(t, 66.67, b.F1Score, 0.1,
		"F1 must use recall=TP/(TP+FN), not BlockRate=TP/TotalTests")

	// F1 with wrong recall would be: 2*(100*10)/(100+10) = 18.18
	// This must NOT be the result
	if b.F1Score < 20 {
		t.Errorf("F1 appears to use BlockRate as recall: got %.2f, expected ~66.67", b.F1Score)
	}
}

// TestPrecisionF1_EmptyResults verifies no division by zero on empty input.
func TestPrecisionF1_EmptyResults(t *testing.T) {
	t.Parallel()

	scorer := NewScorer()
	b := scorer.Score([]Result{})

	assert.Equal(t, 0.0, b.Precision)
	assert.Equal(t, 0.0, b.F1Score)
	assert.Equal(t, 0.0, b.BlockRate)
}
