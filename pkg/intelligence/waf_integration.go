// Package intelligence provides adaptive learning capabilities for WAFtester.
// WAFProfiler integrates with the WAF detection package for enhanced fingerprinting.
package intelligence

import (
	"context"
	"sort"
	"sync"
	"time"
)

// WAF profiler constants.
const (
	// MaxLatencyHistory is the maximum number of latency samples to keep.
	MaxLatencyHistory = 100

	// MinObservationsForCategory is the minimum observations before calculating category effectiveness.
	MinObservationsForCategory = 5

	// MinObservationsForEncoding is the minimum observations before calculating encoding effectiveness.
	MinObservationsForEncoding = 3

	// WeakCategoryBypassThreshold is the bypass rate above which a category is considered weak.
	WeakCategoryBypassThreshold = 0.5

	// StrongCategoryBlockThreshold is the block rate above which a category is considered strong.
	// Used as: bypass rate < (1 - StrongCategoryBlockThreshold)
	StrongCategoryBlockThreshold = 0.9
)

// ══════════════════════════════════════════════════════════════════════════════
// WAF INTEGRATION - Enhanced WAF fingerprinting using pkg/waf
// Bridges the gap between detection (pkg/waf) and learning (pkg/intelligence)
// ══════════════════════════════════════════════════════════════════════════════

// WAFFingerprint represents detected WAF information
type WAFFingerprint struct {
	// Primary WAF identification
	Name       string  `json:"name"`
	Vendor     string  `json:"vendor"`
	Type       string  `json:"type"` // cloud, appliance, software, cdn-integrated
	Version    string  `json:"version,omitempty"`
	Confidence float64 `json:"confidence"`

	// Detection evidence
	Evidence []WAFEvidence `json:"evidence"`

	// Known characteristics
	BypassTips   []string `json:"bypass_tips,omitempty"`
	KnownRules   []string `json:"known_rules,omitempty"`
	RulesetInfo  string   `json:"ruleset_info,omitempty"`
	BlockCodes   []int    `json:"block_codes,omitempty"`
	BlockHeaders []string `json:"block_headers,omitempty"`

	// Behavioral characteristics learned
	AvgBlockLatency  time.Duration `json:"avg_block_latency"`
	AvgBypassLatency time.Duration `json:"avg_bypass_latency"`

	// Weaknesses discovered during testing
	Weaknesses []string `json:"weaknesses,omitempty"`
	Strengths  []string `json:"strengths,omitempty"`
}

// WAFEvidence represents evidence of WAF detection
type WAFEvidence struct {
	Type       string  `json:"type"` // header, body, status, behavior, tls, timing
	Source     string  `json:"source"`
	Value      string  `json:"value"`
	Indicates  string  `json:"indicates"`
	Confidence float64 `json:"confidence"`
}

// WAFProfiler profiles WAF behavior and characteristics
type WAFProfiler struct {
	mu sync.RWMutex

	// Detected WAF information
	fingerprint *WAFFingerprint

	// Behavioral observations
	blockPatterns    map[string]int    // Response patterns when blocked
	bypassPatterns   map[string]int    // Response patterns when bypassed
	statusCodeDist   map[int]int       // Status code distribution
	headerSignatures map[string]string // Detected header signatures
	bodyPatterns     []string          // Detected body patterns

	// Response timing analysis
	blockLatencies  []time.Duration
	bypassLatencies []time.Duration

	// Category-specific effectiveness
	categoryBlocks   map[string]int
	categoryBypasses map[string]int

	// Encoding effectiveness
	encodingBlocks   map[string]int
	encodingBypasses map[string]int
}

// NewWAFProfiler creates a new WAF profiler
func NewWAFProfiler() *WAFProfiler {
	return &WAFProfiler{
		blockPatterns:    make(map[string]int),
		bypassPatterns:   make(map[string]int),
		statusCodeDist:   make(map[int]int),
		headerSignatures: make(map[string]string),
		bodyPatterns:     make([]string, 0),
		blockLatencies:   make([]time.Duration, 0),
		bypassLatencies:  make([]time.Duration, 0),
		categoryBlocks:   make(map[string]int),
		categoryBypasses: make(map[string]int),
		encodingBlocks:   make(map[string]int),
		encodingBypasses: make(map[string]int),
	}
}

// SetFingerprint sets the detected WAF fingerprint from pkg/waf detection
func (wp *WAFProfiler) SetFingerprint(fp *WAFFingerprint) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.fingerprint = fp
}

// GetFingerprint returns the current WAF fingerprint
func (wp *WAFProfiler) GetFingerprint() *WAFFingerprint {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	if wp.fingerprint == nil {
		return nil
	}
	// Return a copy
	fp := *wp.fingerprint
	return &fp
}

// LearnFromFinding updates the WAF profile based on a finding
func (wp *WAFProfiler) LearnFromFinding(f *Finding) {
	if f == nil {
		return
	}
	wp.mu.Lock()
	defer wp.mu.Unlock()

	// Track status codes
	if f.StatusCode > 0 {
		wp.statusCodeDist[f.StatusCode]++
	}

	// Track category effectiveness
	if f.Blocked {
		wp.categoryBlocks[f.Category]++
		if f.Latency > 0 {
			wp.blockLatencies = append(wp.blockLatencies, f.Latency)
			// Keep sliding window of last 100 latencies
			if len(wp.blockLatencies) > 100 {
				wp.blockLatencies = wp.blockLatencies[1:]
			}
		}
	} else {
		wp.categoryBypasses[f.Category]++
		if f.Latency > 0 {
			wp.bypassLatencies = append(wp.bypassLatencies, f.Latency)
			if len(wp.bypassLatencies) > 100 {
				wp.bypassLatencies = wp.bypassLatencies[1:]
			}
		}
	}

	// Track encoding effectiveness
	if len(f.Encodings) > 0 {
		for _, enc := range f.Encodings {
			if f.Blocked {
				wp.encodingBlocks[enc]++
			} else {
				wp.encodingBypasses[enc]++
			}
		}
	}
}

// GetCategoryEffectiveness returns the bypass rate for a category
func (wp *WAFProfiler) GetCategoryEffectiveness(category string) float64 {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	blocks := wp.categoryBlocks[category]
	bypasses := wp.categoryBypasses[category]
	total := blocks + bypasses

	if total == 0 {
		return 0.5 // Unknown
	}
	return float64(bypasses) / float64(total)
}

// GetEncodingEffectiveness returns the bypass rate for an encoding
func (wp *WAFProfiler) GetEncodingEffectiveness(encoding string) float64 {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	blocks := wp.encodingBlocks[encoding]
	bypasses := wp.encodingBypasses[encoding]
	total := blocks + bypasses

	if total == 0 {
		return 0.5 // Unknown
	}
	return float64(bypasses) / float64(total)
}

// GetWeakCategories returns categories with high bypass rates
func (wp *WAFProfiler) GetWeakCategories(threshold float64) []string {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.getWeakCategoriesLocked(threshold)
}

// getWeakCategoriesLocked is the internal implementation that assumes lock is held.
func (wp *WAFProfiler) getWeakCategoriesLocked(threshold float64) []string {
	weak := make([]string, 0)
	allCategories := make(map[string]bool)

	for cat := range wp.categoryBlocks {
		allCategories[cat] = true
	}
	for cat := range wp.categoryBypasses {
		allCategories[cat] = true
	}

	for cat := range allCategories {
		blocks := wp.categoryBlocks[cat]
		bypasses := wp.categoryBypasses[cat]
		total := blocks + bypasses

		if total >= MinObservationsForCategory { // Minimum observations
			rate := float64(bypasses) / float64(total)
			if rate >= threshold {
				weak = append(weak, cat)
			}
		}
	}
	return weak
}

// GetStrongCategories returns categories with low bypass rates
func (wp *WAFProfiler) GetStrongCategories(threshold float64) []string {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.getStrongCategoriesLocked(threshold)
}

// getStrongCategoriesLocked is the internal implementation that assumes lock is held.
func (wp *WAFProfiler) getStrongCategoriesLocked(threshold float64) []string {
	strong := make([]string, 0)
	allCategories := make(map[string]bool)

	for cat := range wp.categoryBlocks {
		allCategories[cat] = true
	}
	for cat := range wp.categoryBypasses {
		allCategories[cat] = true
	}

	for cat := range allCategories {
		blocks := wp.categoryBlocks[cat]
		bypasses := wp.categoryBypasses[cat]
		total := blocks + bypasses

		if total >= MinObservationsForCategory { // Minimum observations
			rate := float64(bypasses) / float64(total)
			if rate <= threshold {
				strong = append(strong, cat)
			}
		}
	}
	return strong
}

// GetBestEncodings returns encodings with highest bypass rates
func (wp *WAFProfiler) GetBestEncodings(n int) []EncodingEffectiveness {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.getBestEncodingsLocked(n)
}

// getBestEncodingsLocked is the internal implementation that assumes lock is held.
func (wp *WAFProfiler) getBestEncodingsLocked(n int) []EncodingEffectiveness {
	allEncodings := make(map[string]bool)
	for enc := range wp.encodingBlocks {
		allEncodings[enc] = true
	}
	for enc := range wp.encodingBypasses {
		allEncodings[enc] = true
	}

	results := make([]EncodingEffectiveness, 0)
	for enc := range allEncodings {
		blocks := wp.encodingBlocks[enc]
		bypasses := wp.encodingBypasses[enc]
		total := blocks + bypasses

		if total >= MinObservationsForEncoding { // Minimum observations
			results = append(results, EncodingEffectiveness{
				Encoding:     enc,
				BypassRate:   float64(bypasses) / float64(total),
				Observations: total,
			})
		}
	}

	// Sort by bypass rate descending using standard library sort
	sort.Slice(results, func(i, j int) bool {
		return results[i].BypassRate > results[j].BypassRate
	})

	if len(results) > n {
		return results[:n]
	}
	return results
}

// EncodingEffectiveness tracks encoding bypass effectiveness
type EncodingEffectiveness struct {
	Encoding     string
	BypassRate   float64
	Observations int
}

// GetAverageBlockLatency returns the average latency for blocked requests
func (wp *WAFProfiler) GetAverageBlockLatency() time.Duration {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.getAverageBlockLatencyLocked()
}

// getAverageBlockLatencyLocked is the internal implementation that assumes lock is held.
func (wp *WAFProfiler) getAverageBlockLatencyLocked() time.Duration {
	if len(wp.blockLatencies) == 0 {
		return 0
	}

	var total time.Duration
	for _, l := range wp.blockLatencies {
		total += l
	}
	return total / time.Duration(len(wp.blockLatencies))
}

// GetAverageBypassLatency returns the average latency for bypassed requests
func (wp *WAFProfiler) GetAverageBypassLatency() time.Duration {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.getAverageBypassLatencyLocked()
}

// getAverageBypassLatencyLocked is the internal implementation that assumes lock is held.
func (wp *WAFProfiler) getAverageBypassLatencyLocked() time.Duration {
	if len(wp.bypassLatencies) == 0 {
		return 0
	}

	var total time.Duration
	for _, l := range wp.bypassLatencies {
		total += l
	}
	return total / time.Duration(len(wp.bypassLatencies))
}

// GenerateSummary creates a summary of WAF characteristics
func (wp *WAFProfiler) GenerateSummary() *WAFProfileSummary {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	// Use locked versions to avoid deadlock (RWMutex is NOT reentrant)
	summary := &WAFProfileSummary{
		TotalBlocks:      0,
		TotalBypasses:    0,
		WeakCategories:   wp.getWeakCategoriesLocked(WeakCategoryBypassThreshold),
		StrongCategories: wp.getStrongCategoriesLocked(1 - StrongCategoryBlockThreshold),
		BestEncodings:    wp.getBestEncodingsLocked(5),
		AvgBlockLatency:  wp.getAverageBlockLatencyLocked(),
		AvgBypassLatency: wp.getAverageBypassLatencyLocked(),
		StatusCodeDist:   make(map[int]int),
	}

	for _, count := range wp.categoryBlocks {
		summary.TotalBlocks += count
	}
	for _, count := range wp.categoryBypasses {
		summary.TotalBypasses += count
	}
	for code, count := range wp.statusCodeDist {
		summary.StatusCodeDist[code] = count
	}

	if summary.TotalBlocks+summary.TotalBypasses > 0 {
		summary.OverallBypassRate = float64(summary.TotalBypasses) / float64(summary.TotalBlocks+summary.TotalBypasses)
	}

	if wp.fingerprint != nil {
		summary.WAFName = wp.fingerprint.Name
		summary.WAFVendor = wp.fingerprint.Vendor
		summary.WAFType = wp.fingerprint.Type
		summary.DetectionConfidence = wp.fingerprint.Confidence
	}

	return summary
}

// WAFProfileSummary contains a summary of WAF profiling results
type WAFProfileSummary struct {
	WAFName             string                  `json:"waf_name,omitempty"`
	WAFVendor           string                  `json:"waf_vendor,omitempty"`
	WAFType             string                  `json:"waf_type,omitempty"`
	DetectionConfidence float64                 `json:"detection_confidence"`
	TotalBlocks         int                     `json:"total_blocks"`
	TotalBypasses       int                     `json:"total_bypasses"`
	OverallBypassRate   float64                 `json:"overall_bypass_rate"`
	WeakCategories      []string                `json:"weak_categories"`
	StrongCategories    []string                `json:"strong_categories"`
	BestEncodings       []EncodingEffectiveness `json:"best_encodings"`
	AvgBlockLatency     time.Duration           `json:"avg_block_latency"`
	AvgBypassLatency    time.Duration           `json:"avg_bypass_latency"`
	StatusCodeDist      map[int]int             `json:"status_code_dist"`
}

// Export returns serializable WAFProfiler state
func (wp *WAFProfiler) Export() *WAFProfilerState {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	// Deep-copy the fingerprint so the exported state doesn't share
	// mutable slice fields (Evidence, BypassTips, etc.) with the live profiler.
	var fpCopy *WAFFingerprint
	if wp.fingerprint != nil {
		c := *wp.fingerprint
		c.Evidence = append([]WAFEvidence(nil), wp.fingerprint.Evidence...)
		c.BypassTips = append([]string(nil), wp.fingerprint.BypassTips...)
		c.KnownRules = append([]string(nil), wp.fingerprint.KnownRules...)
		c.BlockCodes = append([]int(nil), wp.fingerprint.BlockCodes...)
		fpCopy = &c
	}

	return &WAFProfilerState{
		Fingerprint:      fpCopy,
		CategoryBlocks:   copyStringIntMap(wp.categoryBlocks),
		CategoryBypasses: copyStringIntMap(wp.categoryBypasses),
		EncodingBlocks:   copyStringIntMap(wp.encodingBlocks),
		EncodingBypasses: copyStringIntMap(wp.encodingBypasses),
		StatusCodeDist:   copyIntIntMap(wp.statusCodeDist),
	}
}

// WAFProfilerState is the serializable form of WAFProfiler
type WAFProfilerState struct {
	Fingerprint      *WAFFingerprint `json:"fingerprint,omitempty"`
	CategoryBlocks   map[string]int  `json:"category_blocks"`
	CategoryBypasses map[string]int  `json:"category_bypasses"`
	EncodingBlocks   map[string]int  `json:"encoding_blocks"`
	EncodingBypasses map[string]int  `json:"encoding_bypasses"`
	StatusCodeDist   map[int]int     `json:"status_code_dist"`
}

// Import restores WAFProfiler from state
func (wp *WAFProfiler) Import(state *WAFProfilerState) {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	wp.fingerprint = state.Fingerprint
	wp.categoryBlocks = copyStringIntMap(state.CategoryBlocks)
	wp.categoryBypasses = copyStringIntMap(state.CategoryBypasses)
	wp.encodingBlocks = copyStringIntMap(state.EncodingBlocks)
	wp.encodingBypasses = copyStringIntMap(state.EncodingBypasses)
	wp.statusCodeDist = copyIntIntMap(state.StatusCodeDist)
}

// Reset clears WAFProfiler state
func (wp *WAFProfiler) Reset() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	wp.fingerprint = nil
	wp.blockPatterns = make(map[string]int)
	wp.bypassPatterns = make(map[string]int)
	wp.statusCodeDist = make(map[int]int)
	wp.headerSignatures = make(map[string]string)
	wp.bodyPatterns = make([]string, 0)
	wp.blockLatencies = make([]time.Duration, 0)
	wp.bypassLatencies = make([]time.Duration, 0)
	wp.categoryBlocks = make(map[string]int)
	wp.categoryBypasses = make(map[string]int)
	wp.encodingBlocks = make(map[string]int)
	wp.encodingBypasses = make(map[string]int)
}

// copyIntIntMap is a helper to copy int→int maps (defined in persistence.go)
// This is a forward declaration for use in this file

// The Engine can integrate with WAFProfiler by adding a field:
// wafProfiler *WAFProfiler
// And calling wp.LearnFromFinding(f) in Learn()

// IntegrateWAFDetection converts pkg/waf DetectionResult to WAFFingerprint
// This bridges the detection package with the intelligence package
func IntegrateWAFDetection(ctx context.Context, result interface{}) *WAFFingerprint {
	// Type assertion for waf.DetectionResult
	// We use interface{} to avoid circular imports
	// Actual integration would cast to *waf.DetectionResult

	// This is a placeholder - actual integration would look like:
	/*
		if dr, ok := result.(*waf.DetectionResult); ok && dr != nil {
			if len(dr.WAFs) > 0 {
				primary := dr.WAFs[0]
				fp := &WAFFingerprint{
					Name:       primary.Name,
					Vendor:     primary.Vendor,
					Type:       primary.Type,
					Version:    primary.Version,
					Confidence: primary.Confidence,
					BypassTips: primary.BypassTips,
					KnownRules: primary.KnownRules,
				}
				for _, e := range dr.Evidence {
					fp.Evidence = append(fp.Evidence, WAFEvidence{
						Type:       e.Type,
						Source:     e.Source,
						Value:      e.Value,
						Indicates:  e.Indicates,
						Confidence: e.Confidence,
					})
				}
				return fp
			}
		}
	*/
	return nil
}
