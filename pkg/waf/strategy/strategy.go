// Package strategy provides intelligent WAF-aware testing strategies.
// It automatically detects the WAF vendor and optimizes testing based on
// the vendor's known weaknesses, recommended encoders, and evasion techniques.
package strategy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/waf/vendors"
)

// Strategy represents an optimized testing strategy based on detected WAF
type Strategy struct {
	// Detection results
	Vendor     vendors.WAFVendor `json:"vendor"`
	VendorName string            `json:"vendor_name"`
	Confidence float64           `json:"confidence"`

	// Prioritized techniques (ordered by effectiveness)
	Encoders   []string `json:"encoders"`    // Priority-ordered encoders
	Evasions   []string `json:"evasions"`    // Priority-ordered evasions
	Locations  []string `json:"locations"`   // Effective injection locations
	BypassTips []string `json:"bypass_tips"` // Vendor-specific hints

	// Rate limiting guidance
	SafeRateLimit   int `json:"safe_rate_limit"`  // Safe requests/second
	BurstRateLimit  int `json:"burst_rate_limit"` // Max burst before throttle
	CooldownSeconds int `json:"cooldown_seconds"` // Wait between bursts

	// Blocking behavior
	BlockStatusCodes []int    `json:"block_status_codes"`
	BlockPatterns    []string `json:"block_patterns"`

	// Testing recommendations
	RecommendedMutationDepth int      `json:"recommended_mutation_depth"` // 1=quick, 2=standard, 3=full
	SkipIneffectiveMutators  []string `json:"skip_ineffective"`           // Mutators to skip for this WAF
	PrioritizeMutators       []string `json:"prioritize_mutators"`        // Mutators to try first
}

// StrategyEngine creates optimized testing strategies based on WAF detection
type StrategyEngine struct {
	detector *vendors.VendorDetector
	cache    map[string]*Strategy
	mu       sync.RWMutex
	timeout  time.Duration
}

// NewStrategyEngine creates a new strategy engine
func NewStrategyEngine(timeout time.Duration) *StrategyEngine {
	if timeout == 0 {
		timeout = httpclient.TimeoutScanning
	}
	return &StrategyEngine{
		detector: vendors.NewVendorDetector(timeout),
		cache:    make(map[string]*Strategy),
		timeout:  timeout,
	}
}

// GetStrategy detects WAF and returns optimized testing strategy
func (e *StrategyEngine) GetStrategy(ctx context.Context, target string) (*Strategy, error) {
	// Check cache first
	e.mu.RLock()
	if cached, ok := e.cache[target]; ok {
		e.mu.RUnlock()
		return cached, nil
	}
	e.mu.RUnlock()

	// Detect WAF
	result, err := e.detector.Detect(ctx, target)
	if err != nil {
		// Return default strategy on error (detection failure is not fatal)
		return e.getDefaultStrategy(), nil //nolint:nilerr // intentional: detection failure returns default strategy
	}

	// Build strategy from detection result
	strategy := e.buildStrategy(result)

	// Cache it
	e.mu.Lock()
	e.cache[target] = strategy
	e.mu.Unlock()

	return strategy, nil
}

// buildStrategy creates an optimized strategy from detection results
func (e *StrategyEngine) buildStrategy(result *vendors.DetectionResult) *Strategy {
	if !result.Detected {
		return e.getDefaultStrategy()
	}

	s := &Strategy{
		Vendor:     result.Vendor,
		VendorName: result.VendorName,
		Confidence: result.Confidence,
		BypassTips: result.BypassHints,
	}

	// Get vendor-specific optimizations
	switch result.Vendor {
	case vendors.VendorCloudflare:
		s.Encoders = []string{"unicode", "overlong_utf8", "utf16le", "double_url", "html_named"}
		s.Evasions = []string{"case_swap", "chunked", "whitespace_alt", "unicode_normalize", "comment_wrap"}
		s.Locations = []string{"body_json", "body_form", "query", "path", "header"}
		s.SafeRateLimit = 100
		s.BurstRateLimit = 1000
		s.CooldownSeconds = 10
		s.BlockStatusCodes = []int{403, 503, 1020}
		s.BlockPatterns = []string{"cloudflare", "ray id", "blocked"}
		s.RecommendedMutationDepth = 2
		s.SkipIneffectiveMutators = []string{"base64_simple"} // CF decodes base64
		s.PrioritizeMutators = []string{"unicode", "case_swap", "overlong_utf8"}

	case vendors.VendorAWSWAF:
		s.Encoders = []string{"double_url", "triple_url", "html_hex", "unicode", "mixed"}
		s.Evasions = []string{"content_type_mismatch", "hpp", "sql_comment", "null_byte"}
		s.Locations = []string{"query", "body_json", "path", "cookie"}
		s.SafeRateLimit = 200
		s.BurstRateLimit = 2000
		s.CooldownSeconds = 5
		s.BlockStatusCodes = []int{403}
		s.BlockPatterns = []string{"request blocked", "aws waf", "forbidden"}
		s.RecommendedMutationDepth = 2
		s.SkipIneffectiveMutators = []string{}
		s.PrioritizeMutators = []string{"double_url", "hpp", "unicode"}

	case vendors.VendorAzureWAF:
		s.Encoders = []string{"unicode", "html_decimal", "base64", "html_hex", "html_named"}
		s.Evasions = []string{"sql_comment", "case_swap", "unicode_normalize", "whitespace_alt"}
		s.Locations = []string{"body_json", "body_xml", "query", "path"}
		s.SafeRateLimit = 150
		s.BurstRateLimit = 1500
		s.CooldownSeconds = 8
		s.BlockStatusCodes = []int{403, 502}
		s.BlockPatterns = []string{"azure", "access restricted", "front door"}
		s.RecommendedMutationDepth = 2
		s.SkipIneffectiveMutators = []string{}
		s.PrioritizeMutators = []string{"unicode", "html_hex", "sql_comment"}

	case vendors.VendorAkamai:
		s.Encoders = []string{"double_url", "unicode", "html_named", "overlong_utf8"}
		s.Evasions = []string{"case_swap", "whitespace_alt", "hpp", "chunked"}
		s.Locations = []string{"query", "path", "body_form", "header"}
		s.SafeRateLimit = 80
		s.BurstRateLimit = 500
		s.CooldownSeconds = 15
		s.BlockStatusCodes = []int{403, 400}
		s.BlockPatterns = []string{"akamai", "reference", "access denied"}
		s.RecommendedMutationDepth = 3 // Akamai is tough, need full coverage
		s.SkipIneffectiveMutators = []string{}
		s.PrioritizeMutators = []string{"double_url", "hpp", "case_swap"}

	case vendors.VendorModSecurity:
		s.Encoders = []string{"double_url", "html_hex", "overlong_utf8", "unicode", "base64"}
		s.Evasions = []string{"sql_comment", "case_swap", "null_byte", "whitespace_alt", "unicode_normalize"}
		s.Locations = []string{"query", "body_form", "body_json", "path", "cookie"}
		s.SafeRateLimit = 300 // Usually no aggressive rate limiting
		s.BurstRateLimit = 5000
		s.CooldownSeconds = 2
		s.BlockStatusCodes = []int{403, 406, 501}
		s.BlockPatterns = []string{"modsecurity", "forbidden", "not acceptable", "owasp"}
		s.RecommendedMutationDepth = 2
		s.SkipIneffectiveMutators = []string{}
		s.PrioritizeMutators = []string{"sql_comment", "unicode", "case_swap"}

	case vendors.VendorImperva:
		s.Encoders = []string{"unicode", "wide_gbk", "overlong_utf8", "double_url", "html_named"}
		s.Evasions = []string{"case_swap", "sql_comment", "whitespace_alt", "chunked", "content_type_mismatch"}
		s.Locations = []string{"query", "body_json", "body_form", "header", "cookie"}
		s.SafeRateLimit = 50 // Imperva is strict
		s.BurstRateLimit = 300
		s.CooldownSeconds = 20
		s.BlockStatusCodes = []int{403, 400, 406}
		s.BlockPatterns = []string{"incapsula", "imperva", "blocked", "incident"}
		s.RecommendedMutationDepth = 3
		s.SkipIneffectiveMutators = []string{"base64_simple"}
		s.PrioritizeMutators = []string{"wide_gbk", "unicode", "overlong_utf8"}

	case vendors.VendorF5BigIP:
		s.Encoders = []string{"double_url", "unicode", "html_hex", "base64"}
		s.Evasions = []string{"hpp", "sql_comment", "case_swap", "chunked", "null_byte"}
		s.Locations = []string{"query", "body_form", "cookie", "path"}
		s.SafeRateLimit = 100
		s.BurstRateLimit = 800
		s.CooldownSeconds = 10
		s.BlockStatusCodes = []int{403, 501}
		s.BlockPatterns = []string{"request rejected", "bigip", "f5", "asm"}
		s.RecommendedMutationDepth = 2
		s.SkipIneffectiveMutators = []string{}
		s.PrioritizeMutators = []string{"hpp", "double_url", "sql_comment"}

	case vendors.VendorFastly:
		s.Encoders = []string{"unicode", "double_url", "html_named", "overlong_utf8"}
		s.Evasions = []string{"case_swap", "whitespace_alt", "chunked", "comment_wrap"}
		s.Locations = []string{"query", "path", "body_json", "header"}
		s.SafeRateLimit = 150
		s.BurstRateLimit = 1200
		s.CooldownSeconds = 8
		s.BlockStatusCodes = []int{403, 503}
		s.BlockPatterns = []string{"fastly", "varnish", "blocked"}
		s.RecommendedMutationDepth = 2
		s.SkipIneffectiveMutators = []string{}
		s.PrioritizeMutators = []string{"unicode", "case_swap", "chunked"}

	case vendors.VendorCloudArmor:
		s.Encoders = []string{"unicode", "double_url", "html_decimal", "html_hex"}
		s.Evasions = []string{"case_swap", "sql_comment", "unicode_normalize", "whitespace_alt"}
		s.Locations = []string{"query", "body_json", "path", "header"}
		s.SafeRateLimit = 120
		s.BurstRateLimit = 1000
		s.CooldownSeconds = 10
		s.BlockStatusCodes = []int{403}
		s.BlockPatterns = []string{"google", "cloud armor", "blocked"}
		s.RecommendedMutationDepth = 2
		s.SkipIneffectiveMutators = []string{}
		s.PrioritizeMutators = []string{"unicode", "html_hex", "sql_comment"}

	default:
		// Use detection result's recommendations if available
		if len(result.RecommendedEncoders) > 0 {
			s.Encoders = result.RecommendedEncoders
		} else {
			s.Encoders = []string{"double_url", "unicode", "html_hex", "base64"}
		}
		if len(result.RecommendedEvasions) > 0 {
			s.Evasions = result.RecommendedEvasions
		} else {
			s.Evasions = []string{"case_swap", "sql_comment", "whitespace_alt"}
		}
		s.Locations = []string{"query", "body_json", "body_form", "path"}
		s.SafeRateLimit = 100
		s.BurstRateLimit = 500
		s.CooldownSeconds = 10
		s.BlockStatusCodes = []int{403, 406, 429, 503}
		s.BlockPatterns = []string{"blocked", "forbidden", "denied", "waf"}
		s.RecommendedMutationDepth = 2
	}

	return s
}

// getDefaultStrategy returns a balanced strategy when WAF is unknown
func (e *StrategyEngine) getDefaultStrategy() *Strategy {
	return &Strategy{
		Vendor:                   vendors.VendorUnknown,
		VendorName:               "Unknown/Generic WAF",
		Confidence:               0,
		Encoders:                 []string{"double_url", "unicode", "html_hex", "base64", "overlong_utf8"},
		Evasions:                 []string{"case_swap", "sql_comment", "whitespace_alt", "null_byte", "chunked"},
		Locations:                []string{"query", "body_json", "body_form", "path", "cookie", "header"},
		SafeRateLimit:            50,
		BurstRateLimit:           300,
		CooldownSeconds:          15,
		BlockStatusCodes:         []int{403, 400, 406, 429, 500, 502, 503},
		BlockPatterns:            []string{"blocked", "forbidden", "denied", "waf", "security", "firewall"},
		RecommendedMutationDepth: 2,
	}
}

// PipelineConfig represents mutation pipeline configuration
type PipelineConfig struct {
	Encoders  []string
	Locations []string
	Evasions  []string
	MaxDepth  int
}

// ToPipelineConfig converts strategy to mutation pipeline configuration
func (s *Strategy) ToPipelineConfig(depth int) *PipelineConfig {
	if depth == 0 {
		depth = s.RecommendedMutationDepth
	}

	config := &PipelineConfig{
		MaxDepth: depth,
	}

	switch depth {
	case 1: // Quick - prioritized only
		config.Encoders = s.prioritize(s.Encoders, 3)
		config.Locations = s.prioritize(s.Locations, 2)
		config.Evasions = []string{} // No evasions in quick mode
	case 2: // Standard - all recommended
		config.Encoders = s.Encoders
		config.Locations = s.prioritize(s.Locations, 4)
		config.Evasions = s.prioritize(s.Evasions, 3)
	case 3: // Full - everything
		config.Encoders = s.expandEncoders()
		config.Locations = s.Locations
		config.Evasions = s.Evasions
	default:
		config.Encoders = s.Encoders
		config.Locations = s.Locations
		config.Evasions = s.Evasions
	}

	return config
}

// prioritize returns top N items from slice
func (s *Strategy) prioritize(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return items[:n]
}

// expandEncoders returns full encoder list with chained encodings
func (s *Strategy) expandEncoders() []string {
	expanded := make([]string, 0, len(s.Encoders)*2)
	expanded = append(expanded, s.Encoders...)

	// Add common chained encodings
	chainedEncodings := []string{
		"double_url",
		"triple_url",
		"unicode_double_url",
		"html_double_url",
	}
	for _, enc := range chainedEncodings {
		found := false
		for _, e := range expanded {
			if e == enc {
				found = true
				break
			}
		}
		if !found {
			expanded = append(expanded, enc)
		}
	}

	return expanded
}

// GetRateLimitConfig returns rate limiting configuration
func (s *Strategy) GetRateLimitConfig() (rateLimit int, burstLimit int, cooldown int) {
	return s.SafeRateLimit, s.BurstRateLimit, s.CooldownSeconds
}

// IsBlocked checks if a response indicates WAF blocking
func (s *Strategy) IsBlocked(statusCode int, body string) bool {
	// Check status code
	for _, code := range s.BlockStatusCodes {
		if statusCode == code {
			// For 403/503, also check body patterns to avoid false positives
			if statusCode == 403 || statusCode == 503 {
				bodyLower := strings.ToLower(body)
				for _, pattern := range s.BlockPatterns {
					if strings.Contains(bodyLower, strings.ToLower(pattern)) {
						return true
					}
				}
				// If status matches but no pattern, might still be WAF block
				return len(body) < 10000 // Short error pages are usually WAF blocks
			}
			return true
		}
	}
	return false
}

// GetBypassHints returns actionable bypass hints for the detected WAF
func (s *Strategy) GetBypassHints() []string {
	return s.BypassTips
}

// String returns a human-readable summary of the strategy
func (s *Strategy) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("WAF Strategy for %s (%.0f%% confidence)\n", s.VendorName, s.Confidence*100))
	sb.WriteString(fmt.Sprintf("  Encoders: %s\n", strings.Join(s.Encoders, ", ")))
	sb.WriteString(fmt.Sprintf("  Evasions: %s\n", strings.Join(s.Evasions, ", ")))
	sb.WriteString(fmt.Sprintf("  Locations: %s\n", strings.Join(s.Locations, ", ")))
	sb.WriteString(fmt.Sprintf("  Rate Limit: %d req/s (burst: %d)\n", s.SafeRateLimit, s.BurstRateLimit))
	return sb.String()
}

// StrategySummary returns a compact summary for display
func (s *Strategy) StrategySummary() string {
	if s.Vendor == vendors.VendorUnknown {
		return "Generic WAF Testing Strategy"
	}
	return fmt.Sprintf("%s-optimized (%d encoders, %d evasions, %d req/s)",
		s.VendorName, len(s.Encoders), len(s.Evasions), s.SafeRateLimit)
}

// MergeStrategies combines multiple strategies (for multi-WAF scenarios)
func MergeStrategies(strategies ...*Strategy) *Strategy {
	if len(strategies) == 0 {
		return nil
	}
	if len(strategies) == 1 {
		return strategies[0]
	}

	merged := &Strategy{
		Vendor:                   vendors.VendorUnknown,
		VendorName:               "Multi-WAF",
		Confidence:               0,
		BlockStatusCodes:         []int{},
		BlockPatterns:            []string{},
		SafeRateLimit:            999999,
		BurstRateLimit:           999999,
		CooldownSeconds:          0,
		RecommendedMutationDepth: 1,
	}

	encoderSet := make(map[string]int) // encoder -> count
	evasionSet := make(map[string]int)
	locationSet := make(map[string]int)

	for _, s := range strategies {
		// Use most restrictive rate limits
		if s.SafeRateLimit < merged.SafeRateLimit {
			merged.SafeRateLimit = s.SafeRateLimit
		}
		if s.BurstRateLimit < merged.BurstRateLimit {
			merged.BurstRateLimit = s.BurstRateLimit
		}
		if s.CooldownSeconds > merged.CooldownSeconds {
			merged.CooldownSeconds = s.CooldownSeconds
		}
		if s.RecommendedMutationDepth > merged.RecommendedMutationDepth {
			merged.RecommendedMutationDepth = s.RecommendedMutationDepth
		}

		// Collect all techniques with frequency
		for _, enc := range s.Encoders {
			encoderSet[enc]++
		}
		for _, eva := range s.Evasions {
			evasionSet[eva]++
		}
		for _, loc := range s.Locations {
			locationSet[loc]++
		}

		// Merge block signatures
		merged.BlockStatusCodes = appendUnique(merged.BlockStatusCodes, s.BlockStatusCodes...)
		merged.BlockPatterns = appendUniqueStr(merged.BlockPatterns, s.BlockPatterns...)
		merged.BypassTips = appendUniqueStr(merged.BypassTips, s.BypassTips...)
	}

	// Sort by frequency (techniques effective against multiple WAFs first)
	merged.Encoders = sortByFrequency(encoderSet)
	merged.Evasions = sortByFrequency(evasionSet)
	merged.Locations = sortByFrequency(locationSet)

	return merged
}

func appendUnique(slice []int, items ...int) []int {
	seen := make(map[int]bool)
	for _, v := range slice {
		seen[v] = true
	}
	for _, item := range items {
		if !seen[item] {
			slice = append(slice, item)
			seen[item] = true
		}
	}
	return slice
}

func appendUniqueStr(slice []string, items ...string) []string {
	seen := make(map[string]bool)
	for _, v := range slice {
		seen[v] = true
	}
	for _, item := range items {
		if !seen[item] {
			slice = append(slice, item)
			seen[item] = true
		}
	}
	return slice
}

func sortByFrequency(freqMap map[string]int) []string {
	type kv struct {
		Key   string
		Value int
	}
	var sorted []kv
	for k, v := range freqMap {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	result := make([]string, len(sorted))
	for i, kv := range sorted {
		result[i] = kv.Key
	}
	return result
}

// ============================================================================
// Tamper Integration
// ============================================================================

// GetTamperEngine creates a tamper engine configured for this WAF strategy
func (s *Strategy) GetTamperEngine(profile tampers.Profile) *tampers.Engine {
	return tampers.NewEngine(&tampers.EngineConfig{
		Profile:       profile,
		WAFVendor:     string(s.Vendor),
		EnableMetrics: true,
	})
}

// GetRecommendedTampers returns tampers recommended for the detected WAF
func (s *Strategy) GetRecommendedTampers() []string {
	return tampers.GetTampersForVendor(string(s.Vendor))
}

// GetTopTampers returns the top N most effective tampers for this WAF
func (s *Strategy) GetTopTampers(n int) []string {
	return tampers.GetTopTampersForVendor(string(s.Vendor), n)
}

// GetTamperRecommendations returns detailed tamper recommendations
func (s *Strategy) GetTamperRecommendations() []tampers.TamperRecommendation {
	return tampers.GetRecommendations(string(s.Vendor))
}

// TamperAwareTransform transforms a payload using WAF-optimized tampers
func (s *Strategy) TamperAwareTransform(payload string, profile tampers.Profile) string {
	engine := s.GetTamperEngine(profile)
	return engine.Transform(payload)
}

// TamperChain returns the recommended tamper chain for this WAF
func (s *Strategy) TamperChain(profile tampers.Profile) []string {
	engine := s.GetTamperEngine(profile)
	return engine.GetSelectedTampers()
}
