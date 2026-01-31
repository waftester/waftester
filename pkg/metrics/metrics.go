// Package metrics provides enterprise-grade WAF testing metrics.
// Implements quantitative accuracy metrics following industry standards:
// - True Positive Rate (TPR/Recall/Detection Rate)
// - False Positive Rate (FPR)
// - Precision
// - F1 Score
// - F2 Score (recall-weighted)
// - Matthews Correlation Coefficient (MCC)
// - Balanced Accuracy
// - Mutation Potency
// - Bypass Resistance Score
package metrics

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"
)

// ConfusionMatrix holds the fundamental counts for binary classification
type ConfusionMatrix struct {
	TruePositives  int64 `json:"true_positives"`  // Attacks correctly blocked
	TrueNegatives  int64 `json:"true_negatives"`  // Benign correctly allowed
	FalsePositives int64 `json:"false_positives"` // Benign incorrectly blocked
	FalseNegatives int64 `json:"false_negatives"` // Attacks incorrectly allowed
}

// Total returns the total number of tests
func (cm *ConfusionMatrix) Total() int64 {
	return cm.TruePositives + cm.TrueNegatives + cm.FalsePositives + cm.FalseNegatives
}

// EnterpriseMetrics contains all quantitative WAF assessment metrics
type EnterpriseMetrics struct {
	// Timestamp and metadata
	Timestamp  time.Time `json:"timestamp"`
	Duration   float64   `json:"duration_seconds"`
	TargetURL  string    `json:"target_url"`
	WAFVendor  string    `json:"waf_vendor,omitempty"`
	WAFVersion string    `json:"waf_version,omitempty"`

	// Confusion matrix
	Matrix ConfusionMatrix `json:"confusion_matrix"`

	// Primary metrics (0-1 scale, multiply by 100 for percentage)
	DetectionRate     float64 `json:"detection_rate"`      // TPR = TP/(TP+FN) - % of attacks blocked
	FalsePositiveRate float64 `json:"false_positive_rate"` // FPR = FP/(FP+TN) - % of benign blocked
	Precision         float64 `json:"precision"`           // TP/(TP+FP) - accuracy of blocks
	Recall            float64 `json:"recall"`              // Same as DetectionRate (alias)
	Specificity       float64 `json:"specificity"`         // TN/(TN+FP) - true negative rate

	// Balanced metrics
	F1Score          float64 `json:"f1_score"`          // Harmonic mean of precision and recall
	F2Score          float64 `json:"f2_score"`          // Recall-weighted F-score (β=2)
	BalancedAccuracy float64 `json:"balanced_accuracy"` // (TPR + TNR) / 2
	MCC              float64 `json:"mcc"`               // Matthews Correlation Coefficient (-1 to 1)

	// WAF-specific metrics
	BypassResistance float64 `json:"bypass_resistance"` // 1 - (mutations_bypassed / total_mutations)
	MutationPotency  float64 `json:"mutation_potency"`  // Avg bypasses per mutation type
	BlockConsistency float64 `json:"block_consistency"` // Variance in blocking across categories

	// Operational metrics
	AvgLatencyMs  float64 `json:"avg_latency_ms"`
	P50LatencyMs  float64 `json:"p50_latency_ms"`
	P95LatencyMs  float64 `json:"p95_latency_ms"`
	P99LatencyMs  float64 `json:"p99_latency_ms"`
	ErrorRate     float64 `json:"error_rate"`
	TotalRequests int64   `json:"total_requests"`

	// Breakdown by category
	CategoryMetrics map[string]*CategoryMetric `json:"category_metrics,omitempty"`

	// Enterprise grade
	Grade       string `json:"grade"`        // A+, A, B, C, D, F
	GradeReason string `json:"grade_reason"` // Human-readable explanation

	// Recommendations
	Recommendations []string `json:"recommendations,omitempty"`
}

// CategoryMetric holds metrics for a specific attack category
type CategoryMetric struct {
	Category      string  `json:"category"`
	TotalTests    int64   `json:"total_tests"`
	Blocked       int64   `json:"blocked"`
	Bypassed      int64   `json:"bypassed"`
	DetectionRate float64 `json:"detection_rate"`
	Grade         string  `json:"grade"`
}

// AttackResult represents the outcome of a single attack test
type AttackResult struct {
	ID         string        `json:"id"`
	Category   string        `json:"category"`
	Payload    string        `json:"payload,omitempty"`
	Blocked    bool          `json:"blocked"`
	StatusCode int           `json:"status_code"`
	Latency    time.Duration `json:"latency"`
	Error      string        `json:"error,omitempty"`
	Encoder    string        `json:"encoder,omitempty"`
	Mutation   string        `json:"mutation,omitempty"`
	IsMutated  bool          `json:"is_mutated"`
}

// BenignResult represents the outcome of a false-positive test
type BenignResult struct {
	ID         string        `json:"id"`
	Corpus     string        `json:"corpus"`
	Payload    string        `json:"payload,omitempty"`
	Blocked    bool          `json:"blocked"`
	StatusCode int           `json:"status_code"`
	Latency    time.Duration `json:"latency"`
	Error      string        `json:"error,omitempty"`
	Location   string        `json:"location"` // query, body, header
}

// Calculator computes enterprise metrics from test results
type Calculator struct {
	attackResults []AttackResult
	benignResults []BenignResult
	latencies     []float64
	errorCount    int64
}

// NewCalculator creates a new metrics calculator
func NewCalculator() *Calculator {
	return &Calculator{
		attackResults: make([]AttackResult, 0),
		benignResults: make([]BenignResult, 0),
		latencies:     make([]float64, 0),
	}
}

// AddAttackResult records an attack test result
func (c *Calculator) AddAttackResult(r AttackResult) {
	c.attackResults = append(c.attackResults, r)
	if r.Latency > 0 {
		c.latencies = append(c.latencies, float64(r.Latency.Milliseconds()))
	}
	if r.Error != "" {
		c.errorCount++
	}
}

// AddBenignResult records a false-positive test result
func (c *Calculator) AddBenignResult(r BenignResult) {
	c.benignResults = append(c.benignResults, r)
	if r.Latency > 0 {
		c.latencies = append(c.latencies, float64(r.Latency.Milliseconds()))
	}
	if r.Error != "" {
		c.errorCount++
	}
}

// Calculate computes all metrics from recorded results
func (c *Calculator) Calculate(targetURL string, wafVendor string, duration time.Duration) *EnterpriseMetrics {
	m := &EnterpriseMetrics{
		Timestamp:       time.Now(),
		Duration:        duration.Seconds(),
		TargetURL:       targetURL,
		WAFVendor:       wafVendor,
		CategoryMetrics: make(map[string]*CategoryMetric),
		Recommendations: make([]string, 0),
	}

	// Build confusion matrix
	c.buildConfusionMatrix(m)

	// Calculate primary metrics
	c.calculatePrimaryMetrics(m)

	// Calculate balanced metrics
	c.calculateBalancedMetrics(m)

	// Calculate WAF-specific metrics
	c.calculateWAFMetrics(m)

	// Calculate latency metrics
	c.calculateLatencyMetrics(m)

	// Calculate category breakdown
	c.calculateCategoryMetrics(m)

	// Assign grade
	c.assignGrade(m)

	// Generate recommendations
	c.generateRecommendations(m)

	return m
}

func (c *Calculator) buildConfusionMatrix(m *EnterpriseMetrics) {
	for _, r := range c.attackResults {
		if r.Blocked {
			m.Matrix.TruePositives++ // Attack was correctly blocked
		} else {
			m.Matrix.FalseNegatives++ // Attack was incorrectly allowed (bypass)
		}
	}

	for _, r := range c.benignResults {
		if r.Blocked {
			m.Matrix.FalsePositives++ // Benign was incorrectly blocked
		} else {
			m.Matrix.TrueNegatives++ // Benign was correctly allowed
		}
	}

	m.TotalRequests = m.Matrix.Total()
}

func (c *Calculator) calculatePrimaryMetrics(m *EnterpriseMetrics) {
	tp := float64(m.Matrix.TruePositives)
	tn := float64(m.Matrix.TrueNegatives)
	fp := float64(m.Matrix.FalsePositives)
	fn := float64(m.Matrix.FalseNegatives)

	// Detection Rate / Recall / TPR = TP / (TP + FN)
	if tp+fn > 0 {
		m.DetectionRate = tp / (tp + fn)
		m.Recall = m.DetectionRate // Alias
	}

	// False Positive Rate = FP / (FP + TN)
	if fp+tn > 0 {
		m.FalsePositiveRate = fp / (fp + tn)
	}

	// Precision = TP / (TP + FP)
	if tp+fp > 0 {
		m.Precision = tp / (tp + fp)
	}

	// Specificity / TNR = TN / (TN + FP)
	if tn+fp > 0 {
		m.Specificity = tn / (tn + fp)
	}

	// Error rate
	if m.TotalRequests > 0 {
		m.ErrorRate = float64(c.errorCount) / float64(m.TotalRequests)
	}
}

func (c *Calculator) calculateBalancedMetrics(m *EnterpriseMetrics) {
	// F1 Score = 2 * (precision * recall) / (precision + recall)
	if m.Precision+m.Recall > 0 {
		m.F1Score = 2 * (m.Precision * m.Recall) / (m.Precision + m.Recall)
	}

	// F2 Score = (1 + β²) * (precision * recall) / (β² * precision + recall) where β=2
	// F2 weights recall higher than precision
	beta := 2.0
	betaSq := beta * beta
	if betaSq*m.Precision+m.Recall > 0 {
		m.F2Score = (1 + betaSq) * (m.Precision * m.Recall) / (betaSq*m.Precision + m.Recall)
	}

	// Balanced Accuracy = (TPR + TNR) / 2
	m.BalancedAccuracy = (m.DetectionRate + m.Specificity) / 2

	// Matthews Correlation Coefficient
	// MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
	tp := float64(m.Matrix.TruePositives)
	tn := float64(m.Matrix.TrueNegatives)
	fp := float64(m.Matrix.FalsePositives)
	fn := float64(m.Matrix.FalseNegatives)

	denom := math.Sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
	if denom > 0 {
		m.MCC = (tp*tn - fp*fn) / denom
	}
}

func (c *Calculator) calculateWAFMetrics(m *EnterpriseMetrics) {
	// Mutation metrics
	mutatedTotal := 0
	mutatedBypassed := 0
	mutationTypes := make(map[string]struct {
		total    int
		bypassed int
	})

	for _, r := range c.attackResults {
		if r.IsMutated {
			mutatedTotal++
			key := r.Encoder
			if key == "" {
				key = r.Mutation
			}
			if key == "" {
				key = "default"
			}

			stats := mutationTypes[key]
			stats.total++
			if !r.Blocked {
				mutatedBypassed++
				stats.bypassed++
			}
			mutationTypes[key] = stats
		}
	}

	// Bypass Resistance = 1 - (mutations_bypassed / total_mutations)
	if mutatedTotal > 0 {
		m.BypassResistance = 1.0 - float64(mutatedBypassed)/float64(mutatedTotal)
	} else {
		m.BypassResistance = 1.0 // No mutations = no bypasses possible
	}

	// Mutation Potency = average bypass rate per mutation type
	if len(mutationTypes) > 0 {
		totalPotency := 0.0
		for _, stats := range mutationTypes {
			if stats.total > 0 {
				totalPotency += float64(stats.bypassed) / float64(stats.total)
			}
		}
		m.MutationPotency = totalPotency / float64(len(mutationTypes))
	}

	// Block Consistency = 1 - variance in detection rates across categories
	if len(m.CategoryMetrics) > 1 {
		rates := make([]float64, 0, len(m.CategoryMetrics))
		for _, cm := range m.CategoryMetrics {
			rates = append(rates, cm.DetectionRate)
		}
		variance := calculateVariance(rates)
		// Normalize variance (max theoretical variance is 0.25 for rates between 0-1)
		m.BlockConsistency = 1.0 - math.Min(variance/0.25, 1.0)
	} else {
		m.BlockConsistency = 1.0
	}
}

func (c *Calculator) calculateLatencyMetrics(m *EnterpriseMetrics) {
	if len(c.latencies) == 0 {
		return
	}

	// Sort for percentile calculations
	sorted := make([]float64, len(c.latencies))
	copy(sorted, c.latencies)
	sort.Float64s(sorted)

	// Average
	sum := 0.0
	for _, l := range sorted {
		sum += l
	}
	m.AvgLatencyMs = sum / float64(len(sorted))

	// Percentiles
	m.P50LatencyMs = percentile(sorted, 50)
	m.P95LatencyMs = percentile(sorted, 95)
	m.P99LatencyMs = percentile(sorted, 99)
}

func (c *Calculator) calculateCategoryMetrics(m *EnterpriseMetrics) {
	categoryStats := make(map[string]*CategoryMetric)

	for _, r := range c.attackResults {
		cat := r.Category
		if cat == "" {
			cat = "uncategorized"
		}

		cm, exists := categoryStats[cat]
		if !exists {
			cm = &CategoryMetric{Category: cat}
			categoryStats[cat] = cm
		}

		cm.TotalTests++
		if r.Blocked {
			cm.Blocked++
		} else {
			cm.Bypassed++
		}
	}

	// Calculate rates and grades
	for _, cm := range categoryStats {
		if cm.TotalTests > 0 {
			cm.DetectionRate = float64(cm.Blocked) / float64(cm.TotalTests)
			cm.Grade = rateToGrade(cm.DetectionRate)
		}
	}

	m.CategoryMetrics = categoryStats
}

func (c *Calculator) assignGrade(m *EnterpriseMetrics) {
	// Grade based on F1 score (balanced metric) with FPR penalty
	score := m.F1Score * 100

	// Apply FPR penalty: high FPR downgrades
	if m.FalsePositiveRate > 0.05 { // >5% FPR
		score -= (m.FalsePositiveRate - 0.05) * 200 // Heavy penalty
	}

	// Apply MCC bonus/penalty for correlation quality
	score += m.MCC * 5 // MCC ranges -1 to 1, so ±5 points

	switch {
	case score >= 97:
		m.Grade = "A+"
		m.GradeReason = "Excellent detection with minimal false positives"
	case score >= 93:
		m.Grade = "A"
		m.GradeReason = "Very strong WAF performance"
	case score >= 90:
		m.Grade = "A-"
		m.GradeReason = "Strong WAF performance with minor gaps"
	case score >= 87:
		m.Grade = "B+"
		m.GradeReason = "Good WAF performance, some improvements needed"
	case score >= 83:
		m.Grade = "B"
		m.GradeReason = "Acceptable WAF performance"
	case score >= 80:
		m.Grade = "B-"
		m.GradeReason = "Below average, consider tuning rules"
	case score >= 70:
		m.Grade = "C"
		m.GradeReason = "Significant gaps in protection"
	case score >= 60:
		m.Grade = "D"
		m.GradeReason = "Poor protection, major improvements required"
	default:
		m.Grade = "F"
		m.GradeReason = "Critical protection gaps, not production ready"
	}
}

func (c *Calculator) generateRecommendations(m *EnterpriseMetrics) {
	// High FPR recommendation
	if m.FalsePositiveRate > 0.01 {
		m.Recommendations = append(m.Recommendations,
			fmt.Sprintf("False positive rate is %.2f%%. Consider tuning rules or lowering paranoia level.",
				m.FalsePositiveRate*100))
	}

	// Low detection rate
	if m.DetectionRate < 0.95 {
		m.Recommendations = append(m.Recommendations,
			fmt.Sprintf("Detection rate is %.2f%%. Consider increasing paranoia level or adding custom rules.",
				m.DetectionRate*100))
	}

	// Low bypass resistance
	if m.BypassResistance < 0.90 {
		m.Recommendations = append(m.Recommendations,
			fmt.Sprintf("Bypass resistance is %.2f%%. WAF is vulnerable to encoding/evasion techniques.",
				m.BypassResistance*100))
	}

	// Category-specific recommendations
	for _, cm := range m.CategoryMetrics {
		if cm.DetectionRate < 0.90 && cm.TotalTests >= 10 {
			m.Recommendations = append(m.Recommendations,
				fmt.Sprintf("Category '%s' has %.2f%% detection rate. Review rules for this attack type.",
					cm.Category, cm.DetectionRate*100))
		}
	}

	// High latency warning
	if m.P99LatencyMs > 500 {
		m.Recommendations = append(m.Recommendations,
			fmt.Sprintf("P99 latency is %.0fms. Consider optimizing WAF rules or infrastructure.",
				m.P99LatencyMs))
	}
}

// Helper functions

func calculateVariance(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))

	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	return variance / float64(len(values))
}

func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * float64(p) / 100)
	return sorted[idx]
}

func rateToGrade(rate float64) string {
	switch {
	case rate >= 0.97:
		return "A+"
	case rate >= 0.93:
		return "A"
	case rate >= 0.90:
		return "A-"
	case rate >= 0.85:
		return "B+"
	case rate >= 0.80:
		return "B"
	case rate >= 0.75:
		return "B-"
	case rate >= 0.70:
		return "C"
	case rate >= 0.60:
		return "D"
	default:
		return "F"
	}
}

// ToJSON serializes metrics to JSON
func (m *EnterpriseMetrics) ToJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// Summary returns a human-readable summary
func (m *EnterpriseMetrics) Summary() string {
	return fmt.Sprintf(`
WAF ASSESSMENT SUMMARY
═══════════════════════════════════════════════════════
Target:         %s
WAF Vendor:     %s
Grade:          %s (%s)

CONFUSION MATRIX
┌─────────────────────────────────────────────────────┐
│ True Positives:  %-8d  False Positives: %-8d │
│ True Negatives:  %-8d  False Negatives: %-8d │
└─────────────────────────────────────────────────────┘

PRIMARY METRICS
  Detection Rate (TPR):    %6.2f%%
  False Positive Rate:     %6.2f%%
  Precision:               %6.2f%%
  Specificity (TNR):       %6.2f%%

BALANCED METRICS
  F1 Score:                %6.2f%%
  F2 Score (recall-wtd):   %6.2f%%
  Balanced Accuracy:       %6.2f%%
  MCC:                     %+6.3f

WAF-SPECIFIC METRICS
  Bypass Resistance:       %6.2f%%
  Mutation Potency:        %6.3f
  Block Consistency:       %6.2f%%

LATENCY
  Average:                 %6.1f ms
  P50:                     %6.1f ms
  P95:                     %6.1f ms
  P99:                     %6.1f ms
═══════════════════════════════════════════════════════
`,
		m.TargetURL,
		m.WAFVendor,
		m.Grade, m.GradeReason,
		m.Matrix.TruePositives, m.Matrix.FalsePositives,
		m.Matrix.TrueNegatives, m.Matrix.FalseNegatives,
		m.DetectionRate*100,
		m.FalsePositiveRate*100,
		m.Precision*100,
		m.Specificity*100,
		m.F1Score*100,
		m.F2Score*100,
		m.BalancedAccuracy*100,
		m.MCC,
		m.BypassResistance*100,
		m.MutationPotency,
		m.BlockConsistency*100,
		m.AvgLatencyMs,
		m.P50LatencyMs,
		m.P95LatencyMs,
		m.P99LatencyMs,
	)
}
