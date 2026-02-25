// Package strategy provides intelligent WAF-aware testing strategies.
// This file integrates with the mutation package to provide WAF-optimized pipelines.
package strategy

import (
	"sort"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/mutation"
)

// SmartModes returns the canonical smart-mode names for schema enums.
func SmartModes() []string {
	return []string{"quick", "standard", "full", "bypass", "stealth"}
}

// WAFOptimizedPipeline creates a mutation pipeline optimized for a specific WAF
func WAFOptimizedPipeline(s *Strategy, mode string) *mutation.PipelineConfig {
	if s == nil {
		return mutation.DefaultPipelineConfig()
	}

	config := &mutation.PipelineConfig{
		IncludeRaw: true,
	}

	switch mode {
	case "quick", "fast":
		// Minimal testing - prioritized techniques only
		config.Encoders = s.prioritize(s.Encoders, 3)
		config.Locations = []string{"query_param", "post_json"}
		config.Evasions = []string{}
		config.ChainEncodings = false

	case "standard", "default", "":
		// Balanced testing - recommended techniques
		config.Encoders = s.Encoders
		config.Locations = mapLocationsToMutation(s.Locations)
		config.Evasions = mapEvasionsToMutation(s.prioritize(s.Evasions, 3))
		config.ChainEncodings = false

	case "full", "comprehensive":
		// Full coverage - all recommended + chaining
		config.Encoders = expandEncoders(s.Encoders)
		config.Locations = mapLocationsToMutation(s.Locations)
		config.Evasions = mapEvasionsToMutation(s.Evasions)
		config.ChainEncodings = true
		config.MaxChainDepth = defaults.DepthLow

	case "bypass", "aggressive":
		// Maximum bypass potential - everything + deep chaining
		config.Encoders = getAllEncoders()
		config.Locations = getAllLocations()
		config.Evasions = getAllEvasions()
		config.ChainEncodings = true
		config.MaxChainDepth = defaults.DepthMedium
		config.IncludeRaw = true

	case "stealth", "slow":
		// Low and slow - prioritized but with delays (handled by rate limiting)
		config.Encoders = s.prioritize(s.Encoders, 4)
		config.Locations = []string{"query_param", "post_form", "cookie"}
		config.Evasions = mapEvasionsToMutation(s.prioritize(s.Evasions, 2))
		config.ChainEncodings = false

	default:
		// Use WAF-specific defaults
		config.Encoders = s.Encoders
		config.Locations = mapLocationsToMutation(s.Locations)
		config.Evasions = mapEvasionsToMutation(s.Evasions)
	}

	return config
}

// mapLocationsToMutation converts strategy locations to mutation package names
func mapLocationsToMutation(locations []string) []string {
	mapping := map[string]string{
		"query":     "query_param",
		"body_json": "post_json",
		"body_form": "post_form",
		"body_xml":  "post_xml",
		"path":      "path_segment",
		"header":    "header_custom",
		"cookie":    "cookie",
		"fragment":  "fragment",
		"multipart": "multipart",
	}

	result := make([]string, 0, len(locations))
	for _, loc := range locations {
		if mapped, ok := mapping[loc]; ok {
			result = append(result, mapped)
		} else {
			result = append(result, loc)
		}
	}

	// Ensure we have at least basic locations
	if len(result) == 0 {
		return []string{"query_param", "post_form", "post_json"}
	}

	return result
}

// mapEvasionsToMutation converts strategy evasions to mutation package names
func mapEvasionsToMutation(evasions []string) []string {
	// Map any old/alternate names to actual mutator names
	// Most names should pass through as-is since strategy.go now uses correct names
	mapping := map[string]string{
		// Legacy name mappings (if any old references exist)
		"unicode_normalization": "unicode_normalize",
		"comment_wrapping":      "comment_wrap",
		"content_type":          "content_type_mismatch",
	}

	result := make([]string, 0, len(evasions))
	seen := make(map[string]bool)
	for _, ev := range evasions {
		mapped := ev
		if m, ok := mapping[ev]; ok {
			mapped = m
		}
		if !seen[mapped] {
			result = append(result, mapped)
			seen[mapped] = true
		}
	}

	return result
}

// expandEncoders adds related encoders and chained variants
func expandEncoders(base []string) []string {
	expanded := make([]string, 0, len(base)*2)
	seen := make(map[string]bool)

	for _, enc := range base {
		if !seen[enc] {
			expanded = append(expanded, enc)
			seen[enc] = true
		}

		// Add related encoders
		related := relatedEncoders(enc)
		for _, r := range related {
			if !seen[r] {
				expanded = append(expanded, r)
				seen[r] = true
			}
		}
	}

	return expanded
}

// relatedEncoders returns encoders related to the given one
func relatedEncoders(enc string) []string {
	relations := map[string][]string{
		"url":           {"double_url", "triple_url"},
		"double_url":    {"url", "triple_url"},
		"unicode":       {"utf16le", "utf16be", "overlong_utf8"},
		"html_entities": {"html_decimal", "html_hex", "html_named"},
		"html_decimal":  {"html_hex", "html_named"},
		"base64":        {"base64url"},
		"hex":           {"hex_space", "octal"},
	}

	if related, ok := relations[enc]; ok {
		return related
	}
	return nil
}

// getAllEncoders returns all registered encoder names.
func getAllEncoders() []string {
	return mutation.DefaultRegistry.NamesForCategory("encoder")
}

// getAllLocations returns all registered location names.
func getAllLocations() []string {
	return mutation.DefaultRegistry.NamesForCategory("location")
}

// getAllEvasions returns all registered evasion names.
func getAllEvasions() []string {
	return mutation.DefaultRegistry.NamesForCategory("evasion")
}

// GetOptimalRateLimit returns the recommended rate limit for the WAF
func (s *Strategy) GetOptimalRateLimit(mode string) (rateLimit float64, burstSize int) {
	switch mode {
	case "stealth", "slow":
		return float64(s.SafeRateLimit) / 2, s.SafeRateLimit
	case "fast", "aggressive":
		return float64(s.BurstRateLimit), s.BurstRateLimit * 2
	default:
		return float64(s.SafeRateLimit), s.BurstRateLimit
	}
}

// GetRecommendedConcurrency returns optimal concurrency for the WAF
func (s *Strategy) GetRecommendedConcurrency(mode string) int {
	switch mode {
	case "stealth", "slow":
		return 5
	case "fast", "aggressive":
		return 100
	case "full":
		return 50
	default:
		return 20
	}
}

// CreateOptimizedConfig creates a fully optimized ExecutorConfig based on strategy
func CreateOptimizedConfig(s *Strategy, mode string, targetURL string) *mutation.ExecutorConfig {
	rateLimit, _ := s.GetOptimalRateLimit(mode)
	concurrency := s.GetRecommendedConcurrency(mode)

	return &mutation.ExecutorConfig{
		TargetURL:          targetURL,
		Concurrency:        concurrency,
		RateLimit:          rateLimit,
		Timeout:            10 * 1e9, // 10 seconds
		Retries:            defaults.RetryLow,
		Pipeline:           WAFOptimizedPipeline(s, mode),
		AnalyzeResponses:   true,
		CollectFingerprint: true,
		RealisticMode:      mode != "aggressive",
		AutoCalibrate:      true,
	}
}

// ShouldSkipPayload returns true if this payload type is ineffective against the WAF
func (s *Strategy) ShouldSkipPayload(payloadCategory string) bool {
	// Some WAFs have specific strengths - no point testing what they definitely block
	// This is a heuristic that can be refined based on experience
	return false // By default, test everything
}

// PrioritizePayloads reorders payloads based on WAF-specific knowledge
func (s *Strategy) PrioritizePayloads(payloadCategories []string) []string {
	// WAF-specific category ordering
	// For most WAFs: test injection first, then XSS, then others
	priority := map[string]int{
		"sqli":      1,
		"injection": 1,
		"nosqli":    2,
		"xss":       3,
		"xxe":       4,
		"ssti":      5,
		"ssrf":      6,
		"traversal": 7,
		"lfi":       7,
		"rfi":       8,
		"rce":       9,
		"cmdi":      9,
	}

	// Simple copy and sort by priority
	result := make([]string, len(payloadCategories))
	copy(result, payloadCategories)

	// Sort by priority using efficient O(n log n) sort
	sort.Slice(result, func(i, j int) bool {
		pi := priority[result[i]]
		pj := priority[result[j]]
		if pi == 0 {
			pi = 100
		}
		if pj == 0 {
			pj = 100
		}
		return pi < pj
	})

	return result
}
