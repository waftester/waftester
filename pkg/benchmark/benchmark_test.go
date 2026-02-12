package benchmark

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScorerBasicScoring(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "sqli_2", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "sqli_3", Category: "sqli", Blocked: false, ExpectedBlock: true}, // Bypass
		{TestName: "xss_1", Category: "xss", Blocked: true, ExpectedBlock: true},
	}

	benchmark := scorer.Score(results)

	assert.Equal(t, 4, benchmark.TotalTests)
	assert.Equal(t, 3, benchmark.TotalBlocked)
	assert.Equal(t, 1, benchmark.TotalBypassed)
	assert.Equal(t, 75.0, benchmark.BlockRate)
}

func TestScorerCategoryScores(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "sqli_2", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "xss_1", Category: "xss", Blocked: true, ExpectedBlock: true},
		{TestName: "xss_2", Category: "xss", Blocked: false, ExpectedBlock: true}, // Bypass
	}

	benchmark := scorer.Score(results)

	// SQLi should be 100%
	sqliScore, ok := benchmark.Categories["sqli"]
	require.True(t, ok)
	assert.Equal(t, 100.0, sqliScore.Score)
	assert.Equal(t, 2, sqliScore.Blocked)
	assert.Equal(t, 0, sqliScore.Bypassed)
	assert.Equal(t, "A+", sqliScore.Grade)

	// XSS should be 50%
	xssScore, ok := benchmark.Categories["xss"]
	require.True(t, ok)
	assert.Equal(t, 50.0, xssScore.Score)
	assert.Equal(t, 1, xssScore.Blocked)
	assert.Equal(t, 1, xssScore.Bypassed)
}

func TestScorerFalsePositives(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "baseline_1", Category: "baseline", Blocked: false, ExpectedBlock: false}, // Correct
		{TestName: "baseline_2", Category: "baseline", Blocked: true, ExpectedBlock: false},  // False positive
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
	}

	benchmark := scorer.Score(results)

	assert.Equal(t, 1, benchmark.FalsePositives)

	baselineScore := benchmark.Categories["baseline"]
	assert.Equal(t, 1, baselineScore.FalsePositives)
	assert.Equal(t, 50.0, baselineScore.Score) // 1 pass, 1 fail
}

func TestScorerFalseNegatives(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "sqli_2", Category: "sqli", Blocked: false, ExpectedBlock: true}, // False negative
	}

	benchmark := scorer.Score(results)

	assert.Equal(t, 1, benchmark.FalseNegatives)
	assert.Equal(t, 1, benchmark.TotalBypassed)
}

func TestScorerGrades(t *testing.T) {
	scorer := NewScorer()

	tests := []struct {
		score    float64
		expected string
	}{
		{100, "A+"},
		{97, "A+"},
		{95, "A"},
		{90, "A-"},
		{87, "B+"},
		{80, "B-"},
		{77, "C+"},
		{70, "C-"},
		{67, "D+"},
		{60, "D-"},
		{50, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			grade := scorer.getGrade(tt.score)
			assert.Equal(t, tt.expected, grade)
		})
	}
}

func TestScorerWeightedScoring(t *testing.T) {
	scorer := NewScorer()

	// Create results where SQLi (weight 1.5) is perfect and XSS (weight 1.3) is 50%
	results := []Result{
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "sqli_2", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "xss_1", Category: "xss", Blocked: true, ExpectedBlock: true},
		{TestName: "xss_2", Category: "xss", Blocked: false, ExpectedBlock: true},
	}

	benchmark := scorer.Score(results)

	// Weighted average: (100 * 1.5 + 50 * 1.3) / (1.5 + 1.3) = 215 / 2.8 = 76.79
	assert.InDelta(t, 76.79, benchmark.OverallScore, 0.1)
}

func TestScorerCustomWeights(t *testing.T) {
	customWeights := map[string]float64{
		"sqli":    2.0, // Double weight
		"xss":     1.0,
		"default": 1.0,
	}

	scorer := NewScorer(WithCategoryWeights(customWeights))

	results := []Result{
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "xss_1", Category: "xss", Blocked: false, ExpectedBlock: true},
	}

	benchmark := scorer.Score(results)

	// Weighted: (100 * 2.0 + 0 * 1.0) / 3.0 = 66.67
	assert.InDelta(t, 66.67, benchmark.OverallScore, 0.1)
}

func TestScorerCustomGrades(t *testing.T) {
	customThresholds := map[string]float64{
		"PASS": 80,
		"FAIL": 0,
	}

	scorer := NewScorer(WithGradeThresholds(customThresholds))

	assert.Equal(t, "PASS", scorer.getGrade(90))
	assert.Equal(t, "PASS", scorer.getGrade(80))
	assert.Equal(t, "FAIL", scorer.getGrade(79))
}

func TestScorerLatencyCalculation(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "test_1", Category: "sqli", Blocked: true, ExpectedBlock: true, ResponseTime: 10 * time.Millisecond},
		{TestName: "test_2", Category: "sqli", Blocked: true, ExpectedBlock: true, ResponseTime: 20 * time.Millisecond},
		{TestName: "test_3", Category: "sqli", Blocked: true, ExpectedBlock: true, ResponseTime: 30 * time.Millisecond},
		{TestName: "test_4", Category: "sqli", Blocked: true, ExpectedBlock: true, ResponseTime: 100 * time.Millisecond},
	}

	benchmark := scorer.Score(results)

	// Avg: (10 + 20 + 30 + 100) / 4 = 40ms
	assert.Equal(t, 40*time.Millisecond, benchmark.AvgLatency)
	// P99: should be close to the max (100ms) for small dataset
	assert.Equal(t, 100*time.Millisecond, benchmark.P99Latency)
}

func TestScorerF1Score(t *testing.T) {
	scorer := NewScorer()

	// Perfect precision and recall
	results := []Result{
		{TestName: "test_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "test_2", Category: "sqli", Blocked: true, ExpectedBlock: true},
	}

	benchmark := scorer.Score(results)

	assert.Equal(t, 100.0, benchmark.Precision)
	assert.Equal(t, 100.0, benchmark.BlockRate)
	assert.Equal(t, 100.0, benchmark.F1Score)
}

func TestBenchmarkCompare(t *testing.T) {
	scorer := NewScorer()

	// Baseline: 50% blocked
	baselineResults := []Result{
		{TestName: "test_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "test_2", Category: "sqli", Blocked: false, ExpectedBlock: true},
	}

	// Current: 100% blocked
	currentResults := []Result{
		{TestName: "test_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "test_2", Category: "sqli", Blocked: true, ExpectedBlock: true},
	}

	baseline := scorer.Score(baselineResults)
	current := scorer.Score(currentResults)

	comparison := Compare(baseline, current)

	assert.True(t, comparison.Improved)
	assert.False(t, comparison.Regressed)
	assert.Equal(t, 50.0, comparison.ScoreDelta)
	assert.Contains(t, comparison.CategoryDeltas, "sqli")
}

func TestBenchmarkCompareRegression(t *testing.T) {
	scorer := NewScorer()

	// Baseline: 100% blocked
	baselineResults := []Result{
		{TestName: "test_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
	}

	// Current: 0% blocked
	currentResults := []Result{
		{TestName: "test_1", Category: "sqli", Blocked: false, ExpectedBlock: true},
	}

	baseline := scorer.Score(baselineResults)
	current := scorer.Score(currentResults)

	comparison := Compare(baseline, current)

	assert.False(t, comparison.Improved)
	assert.True(t, comparison.Regressed)
	assert.Equal(t, -100.0, comparison.ScoreDelta)
}

func TestBenchmarkReport(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true, ResponseTime: 10 * time.Millisecond},
		{TestName: "sqli_2", Category: "sqli", Blocked: true, ExpectedBlock: true, ResponseTime: 20 * time.Millisecond},
		{TestName: "xss_1", Category: "xss", Blocked: true, ExpectedBlock: true, ResponseTime: 15 * time.Millisecond},
	}

	benchmark := scorer.Score(results)
	benchmark.WAFProduct = "ModSecurity"
	benchmark.WAFVersion = "3.0"

	report := benchmark.Report()

	assert.Contains(t, report, "WAF BENCHMARK REPORT")
	assert.Contains(t, report, "ModSecurity")
	assert.Contains(t, report, "sqli")
	assert.Contains(t, report, "xss")
	assert.Contains(t, report, "OVERALL RESULTS")
	assert.Contains(t, report, "CATEGORY BREAKDOWN")
}

func TestGradeFromScore(t *testing.T) {
	assert.Equal(t, "A+", GradeFromScore(100))
	assert.Equal(t, "A", GradeFromScore(95))
	assert.Equal(t, "B", GradeFromScore(85))
	assert.Equal(t, "F", GradeFromScore(30))
}

func TestScoreFromGrade(t *testing.T) {
	assert.Equal(t, 97.0, ScoreFromGrade("A+"))
	assert.Equal(t, 93.0, ScoreFromGrade("A"))
	assert.Equal(t, 83.0, ScoreFromGrade("B"))
	assert.Equal(t, 0.0, ScoreFromGrade("F"))
	assert.Equal(t, 0.0, ScoreFromGrade("INVALID"))
}

func TestScorerEmptyResults(t *testing.T) {
	scorer := NewScorer()

	benchmark := scorer.Score([]Result{})

	assert.Equal(t, 0, benchmark.TotalTests)
	assert.Equal(t, 0.0, benchmark.OverallScore)
	assert.Equal(t, time.Duration(0), benchmark.AvgLatency)
}

func TestScorerCategoryPrecision(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "sqli_2", Category: "sqli", Blocked: true, ExpectedBlock: true},
		{TestName: "baseline_1", Category: "sqli", Blocked: true, ExpectedBlock: false}, // False positive
	}

	benchmark := scorer.Score(results)

	sqliScore := benchmark.Categories["sqli"]
	// Total blocked = 3 (2 TP + 1 FP)
	// True positives (Blocked in score) = 2
	// Precision = TP / (TP + FP) = 2 / 3 = 66.67%
	assert.InDelta(t, 66.67, sqliScore.Precision, 0.1)
}

func TestScorerCategoryCoverage(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "sqli_1", Category: "sqli", Blocked: true, ExpectedBlock: true},     // Attack blocked
		{TestName: "sqli_2", Category: "sqli", Blocked: false, ExpectedBlock: true},    // Attack bypassed
		{TestName: "baseline", Category: "sqli", Blocked: false, ExpectedBlock: false}, // Legitimate
	}

	benchmark := scorer.Score(results)

	sqliScore := benchmark.Categories["sqli"]
	// 2 attack tests, 1 blocked
	// Coverage = 1/2 = 50%
	assert.Equal(t, 50.0, sqliScore.Coverage)
}

func TestPercentileLatencyEdgeCases(t *testing.T) {
	scorer := NewScorer()

	// Empty slice
	result := scorer.percentileLatency([]time.Duration{}, 99)
	assert.Equal(t, time.Duration(0), result)

	// Single element
	result = scorer.percentileLatency([]time.Duration{10 * time.Millisecond}, 99)
	assert.Equal(t, 10*time.Millisecond, result)
}

func TestScorerUncategorizedResults(t *testing.T) {
	scorer := NewScorer()

	results := []Result{
		{TestName: "test_1", Category: "", Blocked: true, ExpectedBlock: true},
	}

	benchmark := scorer.Score(results)

	_, ok := benchmark.Categories["uncategorized"]
	assert.True(t, ok)
}
