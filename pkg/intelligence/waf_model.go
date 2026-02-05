// Package intelligence provides adaptive learning capabilities for WAFtester.
// WAFBehaviorModel learns WAF patterns from responses to identify weaknesses and strengths.
package intelligence

import (
	"strings"
	"sync"
	"time"
)

// WAF model constants.
const (
	// MinObservationsForInsight is the minimum observations before generating insights.
	MinObservationsForInsight = 5

	// MinPatternsForWeakness is the minimum pattern occurrences to flag as weakness.
	MinPatternsForWeakness = 3
)

// WAFBehaviorModel learns and tracks WAF behavioral patterns
type WAFBehaviorModel struct {
	mu sync.RWMutex

	// Response patterns
	blockPatterns  map[string]int // Pattern → occurrence count
	bypassPatterns map[string]int

	// Category effectiveness
	categoryBlock  map[string]int // Category → blocks
	categoryBypass map[string]int // Category → bypasses

	// Status code distribution
	statusCodes map[int]int

	// Latency patterns
	avgBlockedLatency time.Duration
	avgBypassLatency  time.Duration
	blockedCount      int
	bypassCount       int

	// Detected weaknesses
	weaknesses []Weakness

	// Detected strengths
	strengths []string
}

// Weakness represents a detected WAF weakness
type Weakness struct {
	Category    string
	Description string
	Confidence  float64
}

// WAFPattern represents a detected behavioral pattern
type WAFPattern struct {
	Name              string
	Description       string
	Priority          int
	Confidence        float64
	RecommendedAction string
}

// NewWAFBehaviorModel creates a new WAF behavioral model
func NewWAFBehaviorModel() *WAFBehaviorModel {
	return &WAFBehaviorModel{
		blockPatterns:  make(map[string]int),
		bypassPatterns: make(map[string]int),
		categoryBlock:  make(map[string]int),
		categoryBypass: make(map[string]int),
		statusCodes:    make(map[int]int),
		weaknesses:     make([]Weakness, 0),
		strengths:      make([]string, 0),
	}
}

// Learn updates the model from a finding.
// Safe to call with nil finding (no-op).
func (w *WAFBehaviorModel) Learn(f *Finding) {
	if f == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	// Track category effectiveness
	if f.Blocked {
		w.categoryBlock[f.Category]++
		w.blockedCount++
		if f.Latency > 0 {
			// Use EMA to avoid integer overflow with large counts
			if w.avgBlockedLatency == 0 {
				w.avgBlockedLatency = f.Latency
			} else {
				w.avgBlockedLatency = time.Duration(float64(w.avgBlockedLatency)*0.9 + float64(f.Latency)*0.1)
			}
		}
	} else {
		w.categoryBypass[f.Category]++
		w.bypassCount++
		if f.Latency > 0 {
			// Use EMA to avoid integer overflow with large counts
			if w.avgBypassLatency == 0 {
				w.avgBypassLatency = f.Latency
			} else {
				w.avgBypassLatency = time.Duration(float64(w.avgBypassLatency)*0.9 + float64(f.Latency)*0.1)
			}
		}
	}

	// Track status codes
	if f.StatusCode > 0 {
		w.statusCodes[f.StatusCode]++
	}

	// Learn patterns from payload
	if f.Payload != "" {
		patterns := extractPatterns(f.Payload)
		for _, p := range patterns {
			if f.Blocked {
				w.blockPatterns[p]++
			} else {
				w.bypassPatterns[p]++
			}
		}
	}

	// Update weaknesses and strengths based on category rates
	w.updateAssessments()
}

// DetectPattern checks if a finding matches a known pattern.
// Returns nil if f is nil or no pattern detected.
func (w *WAFBehaviorModel) DetectPattern(f *Finding) *WAFPattern {
	if f == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Check for timing-based patterns
	if f.Latency > 0 && w.avgBlockedLatency > 0 {
		// If this was blocked but latency differs significantly
		if f.Blocked && f.Latency < w.avgBlockedLatency/2 {
			return &WAFPattern{
				Name:              "Fast Block Pattern",
				Description:       "WAF blocked very quickly - may be using regex/pattern match",
				Priority:          4,
				Confidence:        0.7,
				RecommendedAction: "Try encoding variations to bypass pattern matching",
			}
		}

		// If this bypassed but took long - may have partial match
		if !f.Blocked && f.Latency > w.avgBlockedLatency*2 {
			return &WAFPattern{
				Name:              "Slow Response Pattern",
				Description:       "Response was slow but not blocked - WAF may have partially matched",
				Priority:          3,
				Confidence:        0.6,
				RecommendedAction: "This payload is close to being blocked - try slight variations",
			}
		}
	}

	// Check for category weakness pattern
	if !f.Blocked {
		bypassRate := w.getCategoryBypassRate(f.Category)
		if bypassRate > 0.5 {
			return &WAFPattern{
				Name:              "Category Weakness",
				Description:       "High bypass rate in this category indicates weak rules",
				Priority:          2,
				Confidence:        bypassRate,
				RecommendedAction: "Focus testing on " + f.Category + " category",
			}
		}
	}

	return nil
}

// GetWeaknesses returns detected WAF weaknesses
func (w *WAFBehaviorModel) GetWeaknesses() []Weakness {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]Weakness, len(w.weaknesses))
	copy(result, w.weaknesses)
	return result
}

// GetWeaknessStrings returns weakness descriptions
func (w *WAFBehaviorModel) GetWeaknessStrings() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]string, len(w.weaknesses))
	for i, wk := range w.weaknesses {
		result[i] = wk.Description
	}
	return result
}

// GetStrengths returns detected WAF strengths
func (w *WAFBehaviorModel) GetStrengths() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]string, len(w.strengths))
	copy(result, w.strengths)
	return result
}

func (w *WAFBehaviorModel) getCategoryBypassRate(category string) float64 {
	blocked := w.categoryBlock[category]
	bypassed := w.categoryBypass[category]
	total := blocked + bypassed
	if total == 0 {
		return 0
	}
	return float64(bypassed) / float64(total)
}

func (w *WAFBehaviorModel) updateAssessments() {
	w.weaknesses = make([]Weakness, 0)
	w.strengths = make([]string, 0)

	for category := range w.categoryBlock {
		rate := w.getCategoryBypassRate(category)
		total := w.categoryBlock[category] + w.categoryBypass[category]

		if total < MinObservationsForInsight {
			continue // Not enough data
		}

		if rate > WeakCategoryBypassThreshold {
			w.weaknesses = append(w.weaknesses, Weakness{
				Category:    category,
				Description: category + " rules are weak (>50% bypass rate)",
				Confidence:  rate,
			})
		} else if rate < (1 - StrongCategoryBlockThreshold) {
			w.strengths = append(w.strengths, category+" rules are strong (<10% bypass rate)")
		}
	}

	// Check for bypass patterns
	for pattern, count := range w.bypassPatterns {
		if count >= MinPatternsForWeakness {
			blockCount := w.blockPatterns[pattern]
			if count > blockCount {
				w.weaknesses = append(w.weaknesses, Weakness{
					Category:    "pattern",
					Description: "Pattern '" + pattern + "' frequently bypasses",
					Confidence:  float64(count) / float64(count+blockCount),
				})
			}
		}
	}
}

// extractPatterns extracts key patterns from payloads for learning
func extractPatterns(payload string) []string {
	patterns := make([]string, 0)

	// Encoding patterns
	if strings.Contains(payload, "%") {
		patterns = append(patterns, "url-encoded")
	}
	if strings.Contains(payload, "\\x") || strings.Contains(payload, "\\u") {
		patterns = append(patterns, "unicode-encoded")
	}

	// Comment patterns
	if strings.Contains(payload, "/*") || strings.Contains(payload, "//") || strings.Contains(payload, "--") {
		patterns = append(patterns, "comment-injection")
	}

	// Case patterns
	lower := strings.ToLower(payload)
	if payload != lower && payload != strings.ToUpper(payload) {
		patterns = append(patterns, "mixed-case")
	}

	// Whitespace patterns
	if strings.Contains(payload, "\t") || strings.Contains(payload, "\n") || strings.Contains(payload, "  ") {
		patterns = append(patterns, "whitespace-manipulation")
	}

	// Null byte
	if strings.Contains(payload, "%00") || strings.Contains(payload, "\\x00") {
		patterns = append(patterns, "null-byte")
	}

	return patterns
}

// GetVendor attempts to identify the WAF vendor based on observed behavior
func (w *WAFBehaviorModel) GetVendor() string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Analyze status codes and patterns to identify vendor
	// This is a heuristic based on common WAF behaviors

	// Check status code patterns
	if w.statusCodes[403] > w.statusCodes[406] && w.statusCodes[403] > w.statusCodes[429] {
		// 403 dominant - could be many WAFs
		if w.avgBlockedLatency > 100*time.Millisecond {
			return "cloudflare" // Cloudflare tends to have consistent latency
		}
	}

	if w.statusCodes[406] > 0 && w.statusCodes[406] > w.statusCodes[403]/2 {
		return "modsecurity" // ModSecurity often uses 406
	}

	if w.statusCodes[999] > 0 {
		return "custom" // Custom status codes
	}

	// Default to unknown
	if w.blockedCount > 10 {
		return "unknown"
	}

	return ""
}
