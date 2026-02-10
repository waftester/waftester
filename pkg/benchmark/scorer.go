// Package benchmark provides WAF benchmark scoring and grading
package benchmark

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/strutil"
)

// Result represents the outcome of a single test
type Result struct {
	TestName      string        `json:"test_name"`
	Category      string        `json:"category"`
	Payload       string        `json:"payload,omitempty"`
	Blocked       bool          `json:"blocked"`
	StatusCode    int           `json:"status_code"`
	ResponseTime  time.Duration `json:"response_time"`
	ExpectedBlock bool          `json:"expected_block"`
	FalsePositive bool          `json:"false_positive"`
	FalseNegative bool          `json:"false_negative"`
	RuleID        uint          `json:"rule_id,omitempty"`
	ErrorMessage  string        `json:"error,omitempty"`
	ParanoiaLevel int           `json:"paranoia_level,omitempty"`
	Encoder       string        `json:"encoder,omitempty"`
	Placeholder   string        `json:"placeholder,omitempty"`
}

// CategoryScore represents the score for a single category
type CategoryScore struct {
	Category       string  `json:"category"`
	TotalTests     int     `json:"total_tests"`
	Passed         int     `json:"passed"`
	Failed         int     `json:"failed"`
	Blocked        int     `json:"blocked"`
	Bypassed       int     `json:"bypassed"`
	FalsePositives int     `json:"false_positives"`
	FalseNegatives int     `json:"false_negatives"`
	Score          float64 `json:"score"`     // 0-100
	Grade          string  `json:"grade"`     // A+, A, B, C, D, F
	Coverage       float64 `json:"coverage"`  // Percentage of attacks blocked
	Precision      float64 `json:"precision"` // True positives / (True positives + False positives)
}

// Benchmark represents a complete WAF benchmark result
type Benchmark struct {
	Name           string                   `json:"name"`
	Version        string                   `json:"version"`
	WAFProduct     string                   `json:"waf_product,omitempty"`
	WAFVersion     string                   `json:"waf_version,omitempty"`
	Timestamp      time.Time                `json:"timestamp"`
	Duration       time.Duration            `json:"duration"`
	Results        []Result                 `json:"results"`
	Categories     map[string]CategoryScore `json:"categories"`
	OverallScore   float64                  `json:"overall_score"`
	OverallGrade   string                   `json:"overall_grade"`
	TotalTests     int                      `json:"total_tests"`
	TotalBlocked   int                      `json:"total_blocked"`
	TotalBypassed  int                      `json:"total_bypassed"`
	FalsePositives int                      `json:"false_positives"`
	FalseNegatives int                      `json:"false_negatives"`
	BlockRate      float64                  `json:"block_rate"`
	Precision      float64                  `json:"precision"`
	F1Score        float64                  `json:"f1_score"`
	AvgLatency     time.Duration            `json:"avg_latency"`
	P99Latency     time.Duration            `json:"p99_latency"`
}

// Scorer calculates benchmark scores
type Scorer struct {
	categoryWeights map[string]float64
	gradeThresholds []gradeThreshold
}

type gradeThreshold struct {
	grade    string
	minScore float64
}

// ScorerOption configures the scorer
type ScorerOption func(*Scorer)

// WithCategoryWeights sets custom category weights
func WithCategoryWeights(weights map[string]float64) ScorerOption {
	return func(s *Scorer) {
		s.categoryWeights = weights
	}
}

// WithGradeThresholds sets custom grade thresholds
func WithGradeThresholds(thresholds map[string]float64) ScorerOption {
	return func(s *Scorer) {
		s.gradeThresholds = make([]gradeThreshold, 0, len(thresholds))
		for grade, score := range thresholds {
			s.gradeThresholds = append(s.gradeThresholds, gradeThreshold{grade, score})
		}
		// Sort descending by score
		sort.Slice(s.gradeThresholds, func(i, j int) bool {
			return s.gradeThresholds[i].minScore > s.gradeThresholds[j].minScore
		})
	}
}

// NewScorer creates a new benchmark scorer
func NewScorer(opts ...ScorerOption) *Scorer {
	s := &Scorer{
		categoryWeights: defaultCategoryWeights(),
		gradeThresholds: defaultGradeThresholds(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// defaultCategoryWeights returns default weights for each attack category
func defaultCategoryWeights() map[string]float64 {
	return map[string]float64{
		"sqli":         1.5, // SQL injection - critical
		"xss":          1.3, // Cross-site scripting - high
		"lfi":          1.2, // Local file inclusion - high
		"rfi":          1.2, // Remote file inclusion - high
		"rce":          1.5, // Remote code execution - critical
		"ssrf":         1.3, // Server-side request forgery - high
		"xxe":          1.2, // XML external entity - high
		"ssti":         1.3, // Server-side template injection - high
		"ldap":         1.1, // LDAP injection
		"nosql":        1.1, // NoSQL injection
		"cmdinjection": 1.4, // Command injection
		"traversal":    1.1, // Path traversal
		"baseline":     0.5, // Baseline tests (false positive detection)
		"default":      1.0, // Default weight
	}
}

// defaultGradeThresholds returns default grade thresholds
func defaultGradeThresholds() []gradeThreshold {
	return []gradeThreshold{
		{"A+", 97},
		{"A", 93},
		{"A-", 90},
		{"B+", 87},
		{"B", 83},
		{"B-", 80},
		{"C+", 77},
		{"C", 73},
		{"C-", 70},
		{"D+", 67},
		{"D", 63},
		{"D-", 60},
		{"F", 0},
	}
}

// Score calculates the benchmark score from results
func (s *Scorer) Score(results []Result) *Benchmark {
	benchmark := &Benchmark{
		Name:       "WAF Benchmark",
		Version:    "1.0",
		Timestamp:  time.Now(),
		Results:    results,
		Categories: make(map[string]CategoryScore),
	}

	// Group results by category
	categoryResults := make(map[string][]Result)
	for _, r := range results {
		cat := strings.ToLower(r.Category)
		if cat == "" {
			cat = "uncategorized"
		}
		categoryResults[cat] = append(categoryResults[cat], r)
	}

	// Score each category
	var totalWeightedScore float64
	var totalWeight float64
	var allLatencies []time.Duration

	for category, catResults := range categoryResults {
		score := s.scoreCategory(category, catResults)
		benchmark.Categories[category] = score

		weight := s.getCategoryWeight(category)
		totalWeightedScore += score.Score * weight
		totalWeight += weight

		// Aggregate stats
		benchmark.TotalTests += score.TotalTests
		benchmark.TotalBlocked += score.Blocked
		benchmark.TotalBypassed += score.Bypassed
		benchmark.FalsePositives += score.FalsePositives
		benchmark.FalseNegatives += score.FalseNegatives
	}

	// Collect latencies
	for _, r := range results {
		if r.ResponseTime > 0 {
			allLatencies = append(allLatencies, r.ResponseTime)
		}
	}

	// Calculate overall metrics
	if totalWeight > 0 {
		benchmark.OverallScore = totalWeightedScore / totalWeight
	}
	benchmark.OverallGrade = s.getGrade(benchmark.OverallScore)

	if benchmark.TotalTests > 0 {
		benchmark.BlockRate = float64(benchmark.TotalBlocked) / float64(benchmark.TotalTests) * 100
	}

	// Calculate precision and F1 score
	truePositives := benchmark.TotalBlocked - benchmark.FalsePositives
	if truePositives < 0 {
		truePositives = 0
	}

	if benchmark.TotalBlocked > 0 {
		benchmark.Precision = float64(truePositives) / float64(benchmark.TotalBlocked) * 100
	}

	// F1 = 2 * (precision * recall) / (precision + recall)
	recall := benchmark.BlockRate
	if benchmark.Precision+recall > 0 {
		benchmark.F1Score = 2 * (benchmark.Precision * recall) / (benchmark.Precision + recall)
	}

	// Calculate latencies
	if len(allLatencies) > 0 {
		benchmark.AvgLatency = s.avgLatency(allLatencies)
		benchmark.P99Latency = s.percentileLatency(allLatencies, 99)
	}

	return benchmark
}

// scoreCategory calculates the score for a single category
func (s *Scorer) scoreCategory(category string, results []Result) CategoryScore {
	score := CategoryScore{
		Category:   category,
		TotalTests: len(results),
	}

	var totalBlocked int // All requests that were blocked (TP + FP)

	for _, r := range results {
		if r.Blocked {
			totalBlocked++
		}

		if r.Blocked && r.ExpectedBlock {
			score.Passed++
			score.Blocked++ // True positives
		} else if !r.Blocked && !r.ExpectedBlock {
			score.Passed++
		} else if r.Blocked && !r.ExpectedBlock {
			score.Failed++
			score.FalsePositives++
		} else if !r.Blocked && r.ExpectedBlock {
			score.Failed++
			score.Bypassed++
			score.FalseNegatives++
		}
	}

	// Calculate score
	if score.TotalTests > 0 {
		score.Score = float64(score.Passed) / float64(score.TotalTests) * 100
	}

	// Calculate coverage (attacks blocked)
	attackTests := 0
	for _, r := range results {
		if r.ExpectedBlock {
			attackTests++
		}
	}
	if attackTests > 0 {
		score.Coverage = float64(score.Blocked) / float64(attackTests) * 100
	}

	// Calculate precision: TP / (TP + FP) = Blocked / totalBlocked
	if totalBlocked > 0 {
		score.Precision = float64(score.Blocked) / float64(totalBlocked) * 100
	}

	score.Grade = s.getGrade(score.Score)

	return score
}

// getCategoryWeight returns the weight for a category
func (s *Scorer) getCategoryWeight(category string) float64 {
	if weight, ok := s.categoryWeights[strings.ToLower(category)]; ok {
		return weight
	}
	return s.categoryWeights["default"]
}

// getGrade converts a score to a letter grade
func (s *Scorer) getGrade(score float64) string {
	for _, t := range s.gradeThresholds {
		if score >= t.minScore {
			return t.grade
		}
	}
	return "F"
}

// avgLatency calculates average latency
func (s *Scorer) avgLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	return total / time.Duration(len(latencies))
}

// percentileLatency calculates the nth percentile latency
func (s *Scorer) percentileLatency(latencies []time.Duration, percentile float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}

	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	index := int(math.Ceil(percentile/100*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}

	return sorted[index]
}

// Compare compares two benchmarks and returns the difference
func Compare(baseline, current *Benchmark) *BenchmarkComparison {
	comp := &BenchmarkComparison{
		Baseline:       baseline,
		Current:        current,
		ScoreDelta:     current.OverallScore - baseline.OverallScore,
		BlockRateDelta: current.BlockRate - baseline.BlockRate,
		CategoryDeltas: make(map[string]float64),
	}

	// Compare by category
	for cat, currentScore := range current.Categories {
		if baselineScore, ok := baseline.Categories[cat]; ok {
			comp.CategoryDeltas[cat] = currentScore.Score - baselineScore.Score
		} else {
			comp.CategoryDeltas[cat] = currentScore.Score // New category
		}
	}

	// Determine if improvement
	comp.Improved = comp.ScoreDelta > 0
	comp.Regressed = comp.ScoreDelta < -1 // 1% tolerance

	return comp
}

// BenchmarkComparison represents the comparison between two benchmarks
type BenchmarkComparison struct {
	Baseline       *Benchmark         `json:"baseline"`
	Current        *Benchmark         `json:"current"`
	ScoreDelta     float64            `json:"score_delta"`
	BlockRateDelta float64            `json:"block_rate_delta"`
	CategoryDeltas map[string]float64 `json:"category_deltas"`
	Improved       bool               `json:"improved"`
	Regressed      bool               `json:"regressed"`
}

// Report generates a text report from the benchmark
func (b *Benchmark) Report() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("═══════════════════════════════════════════════════════════════════════\n"))
	sb.WriteString(fmt.Sprintf("                         WAF BENCHMARK REPORT\n"))
	sb.WriteString(fmt.Sprintf("═══════════════════════════════════════════════════════════════════════\n\n"))

	sb.WriteString(fmt.Sprintf("WAF Product:     %s %s\n", b.WAFProduct, b.WAFVersion))
	sb.WriteString(fmt.Sprintf("Timestamp:       %s\n", b.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Duration:        %v\n\n", b.Duration))

	sb.WriteString(fmt.Sprintf("───────────────────────────────────────────────────────────────────────\n"))
	sb.WriteString(fmt.Sprintf("                           OVERALL RESULTS\n"))
	sb.WriteString(fmt.Sprintf("───────────────────────────────────────────────────────────────────────\n\n"))

	sb.WriteString(fmt.Sprintf("  Overall Score:     %.1f%% (%s)\n", b.OverallScore, b.OverallGrade))
	sb.WriteString(fmt.Sprintf("  Block Rate:        %.1f%%\n", b.BlockRate))
	sb.WriteString(fmt.Sprintf("  Precision:         %.1f%%\n", b.Precision))
	sb.WriteString(fmt.Sprintf("  F1 Score:          %.1f%%\n\n", b.F1Score))

	sb.WriteString(fmt.Sprintf("  Total Tests:       %d\n", b.TotalTests))
	sb.WriteString(fmt.Sprintf("  Blocked:           %d\n", b.TotalBlocked))
	sb.WriteString(fmt.Sprintf("  Bypassed:          %d\n", b.TotalBypassed))
	sb.WriteString(fmt.Sprintf("  False Positives:   %d\n", b.FalsePositives))
	sb.WriteString(fmt.Sprintf("  False Negatives:   %d\n\n", b.FalseNegatives))

	sb.WriteString(fmt.Sprintf("  Avg Latency:       %v\n", b.AvgLatency))
	sb.WriteString(fmt.Sprintf("  P99 Latency:       %v\n\n", b.P99Latency))

	sb.WriteString(fmt.Sprintf("───────────────────────────────────────────────────────────────────────\n"))
	sb.WriteString(fmt.Sprintf("                          CATEGORY BREAKDOWN\n"))
	sb.WriteString(fmt.Sprintf("───────────────────────────────────────────────────────────────────────\n\n"))

	// Sort categories by name
	var categories []string
	for cat := range b.Categories {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	sb.WriteString(fmt.Sprintf("  %-15s %6s %6s %8s %8s %5s\n", "CATEGORY", "TESTS", "BLOCK", "BYPASS", "SCORE", "GRADE"))
	sb.WriteString(fmt.Sprintf("  %-15s %6s %6s %8s %8s %5s\n", "─────────────", "─────", "─────", "──────", "──────", "─────"))

	for _, cat := range categories {
		score := b.Categories[cat]
		sb.WriteString(fmt.Sprintf("  %-15s %6d %6d %8d %7.1f%% %5s\n",
			strutil.Truncate(cat, 15),
			score.TotalTests,
			score.Blocked,
			score.Bypassed,
			score.Score,
			score.Grade,
		))
	}

	sb.WriteString(fmt.Sprintf("\n═══════════════════════════════════════════════════════════════════════\n"))

	return sb.String()
}



// GradeFromScore converts a numeric score to a letter grade
func GradeFromScore(score float64) string {
	scorer := NewScorer()
	return scorer.getGrade(score)
}

// ScoreFromGrade converts a letter grade to the minimum score
func ScoreFromGrade(grade string) float64 {
	thresholds := defaultGradeThresholds()
	for _, t := range thresholds {
		if t.grade == grade {
			return t.minScore
		}
	}
	return 0
}
