// Package tampers provides the TamperEngine - an intelligent payload transformation
// system that automatically selects and chains tamper scripts based on detected WAF.
//
// Features:
//   - WAF-aware tamper selection via Intelligence Matrix
//   - Profile system (stealth/standard/aggressive/bypass)
//   - Adaptive chaining with success feedback
//   - HTTP request-level transformations
//   - Real-time metrics and telemetry
package tampers

import (
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Profile represents a tamper application strategy
type Profile string

const (
	// ProfileStealth uses minimal, low-noise tampers to avoid detection
	ProfileStealth Profile = "stealth"

	// ProfileStandard uses balanced tamper selection for general testing
	ProfileStandard Profile = "standard"

	// ProfileAggressive uses maximum tamper coverage for thorough testing
	ProfileAggressive Profile = "aggressive"

	// ProfileBypass uses WAF-specific optimized chains for bypass research
	ProfileBypass Profile = "bypass"

	// ProfileCustom uses user-specified tampers only
	ProfileCustom Profile = "custom"
)

// Profiles returns all predefined profiles (excludes ProfileCustom).
func Profiles() []Profile {
	return []Profile{
		ProfileStealth,
		ProfileStandard,
		ProfileAggressive,
		ProfileBypass,
	}
}

// ProfileStrings returns profile names as strings, suitable for enum schemas.
// Excludes ProfileCustom since it requires explicit tamper names.
func ProfileStrings() []string {
	ps := Profiles()
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}

// Engine provides intelligent tamper selection and application.
// It integrates with WAF detection to automatically choose optimal tampers.
type Engine struct {
	// Configuration
	profile       Profile
	customTampers []string
	wafVendor     string
	strategyHints []string // WAF strategy-recommended evasion names to boost

	// State
	metrics     *MetricsCollector
	adaptiveMap map[string]float64 // tamper name -> observed effectiveness
	mu          sync.RWMutex
}

// EngineConfig holds configuration for creating a new Engine
type EngineConfig struct {
	Profile       Profile  // Tamper selection profile
	CustomTampers []string // Custom tamper names (for ProfileCustom)
	WAFVendor     string   // Detected WAF vendor (optional, enhances selection)
	StrategyHints []string // Strategy-recommended evasion names (from smart mode detection)
	EnableMetrics bool     // Enable real-time metrics collection
}

// NewEngine creates a new tamper engine with the given configuration
func NewEngine(cfg *EngineConfig) *Engine {
	if cfg == nil {
		cfg = &EngineConfig{Profile: ProfileStandard}
	}

	e := &Engine{
		profile:       cfg.Profile,
		customTampers: cfg.CustomTampers,
		wafVendor:     strings.ToLower(cfg.WAFVendor),
		strategyHints: cfg.StrategyHints,
		adaptiveMap:   make(map[string]float64),
	}

	if cfg.EnableMetrics {
		e.metrics = NewMetricsCollector()
	}

	return e
}

// SetWAFVendor updates the detected WAF vendor for intelligent selection
func (e *Engine) SetWAFVendor(vendor string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wafVendor = strings.ToLower(vendor)
}

// SetProfile changes the active tamper profile
func (e *Engine) SetProfile(p Profile) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.profile = p
}

// GetSelectedTampers returns the list of tampers that will be applied
// based on current profile and WAF detection
func (e *Engine) GetSelectedTampers() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var selected []string
	switch e.profile {
	case ProfileCustom:
		return e.customTampers // Custom profile: user controls everything, no hint merging
	case ProfileStealth:
		selected = e.selectStealthTampers()
	case ProfileAggressive:
		selected = e.selectAggressiveTampers()
	case ProfileBypass:
		selected = e.selectBypassTampers()
	default: // ProfileStandard
		selected = e.selectStandardTampers()
	}

	return e.mergeStrategyHints(selected)
}

// mergeStrategyHints prepends strategy-recommended tampers that are registered
// and not already in the selected list. This ensures WAF-specific evasion
// techniques from smart mode detection get priority.
func (e *Engine) mergeStrategyHints(selected []string) []string {
	if len(e.strategyHints) == 0 {
		return selected
	}

	seen := make(map[string]bool, len(selected))
	for _, name := range selected {
		seen[strings.ToLower(name)] = true
	}

	var prepend []string
	for _, hint := range e.strategyHints {
		lower := strings.ToLower(hint)
		if seen[lower] {
			continue
		}
		// Only include hints that correspond to registered tampers
		if Get(hint) != nil {
			prepend = append(prepend, hint)
			seen[lower] = true
		}
	}

	if len(prepend) == 0 {
		return selected
	}
	return append(prepend, selected...)
}

// selectStealthTampers returns minimal, low-noise tampers
func (e *Engine) selectStealthTampers() []string {
	// If WAF detected, get top 2-3 from matrix, weighted by adaptive feedback
	if e.wafVendor != "" && e.wafVendor != "unknown" {
		recs := GetRecommendations(e.wafVendor)
		if len(recs) > 0 {
			sorted := make([]TamperRecommendation, len(recs))
			copy(sorted, recs)
			sort.Slice(sorted, func(i, j int) bool {
				scoreI := sorted[i].Effectiveness + e.adaptiveMap[sorted[i].Name]
				scoreJ := sorted[j].Effectiveness + e.adaptiveMap[sorted[j].Name]
				return scoreI > scoreJ
			})

			result := make([]string, 0, 3)
			for _, rec := range sorted {
				if len(result) >= 3 {
					break
				}
				// Skip HTTP-modifying tampers in stealth mode
				if !rec.RequiresHTTP {
					result = append(result, rec.Name)
				}
			}
			return result
		}
	}

	// Default stealth set
	return []string{"randomcase", "space2comment"}
}

// selectStandardTampers returns balanced tamper selection
func (e *Engine) selectStandardTampers() []string {
	// If WAF detected, get top 5 from matrix, weighted by adaptive feedback
	if e.wafVendor != "" && e.wafVendor != "unknown" {
		recs := GetRecommendations(e.wafVendor)
		if len(recs) > 0 {
			sorted := make([]TamperRecommendation, len(recs))
			copy(sorted, recs)
			sort.Slice(sorted, func(i, j int) bool {
				scoreI := sorted[i].Effectiveness + e.adaptiveMap[sorted[i].Name]
				scoreJ := sorted[j].Effectiveness + e.adaptiveMap[sorted[j].Name]
				return scoreI > scoreJ
			})

			result := make([]string, 0, 5)
			for i, rec := range sorted {
				if i >= 5 {
					break
				}
				result = append(result, rec.Name)
			}
			return result
		}
	}

	// Default standard set
	return []string{
		"space2comment",
		"randomcase",
		"charencode",
		"between",
		"equaltolike",
	}
}

// selectAggressiveTampers returns full tamper coverage
func (e *Engine) selectAggressiveTampers() []string {
	// If WAF detected, get all from matrix
	if e.wafVendor != "" && e.wafVendor != "unknown" {
		recs := GetRecommendations(e.wafVendor)
		if len(recs) > 0 {
			result := make([]string, 0, len(recs))
			for _, rec := range recs {
				result = append(result, rec.Name)
			}
			return result
		}
	}

	// Default aggressive set - comprehensive coverage
	return []string{
		"space2comment",
		"space2morecomment",
		"space2hash",
		"randomcase",
		"charencode",
		"chardoubleencode",
		"charunicodeencode",
		"between",
		"equaltolike",
		"greatest",
		"least",
		"modsecurityversioned",
		"modsecurityzeroversioned",
		"percentage",
		"unionalltounion",
	}
}

// selectBypassTampers returns WAF-specific optimized chains
func (e *Engine) selectBypassTampers() []string {
	// Must have WAF vendor for bypass mode
	if e.wafVendor != "" && e.wafVendor != "unknown" {
		recs := GetRecommendations(e.wafVendor)
		if len(recs) > 0 {
			// Sort by combined static effectiveness + adaptive feedback scores
			sorted := make([]TamperRecommendation, len(recs))
			copy(sorted, recs)
			sort.Slice(sorted, func(i, j int) bool {
				scoreI := sorted[i].Effectiveness + e.adaptiveMap[sorted[i].Name]
				scoreJ := sorted[j].Effectiveness + e.adaptiveMap[sorted[j].Name]
				return scoreI > scoreJ
			})

			result := make([]string, 0, len(sorted))
			for _, rec := range sorted {
				result = append(result, rec.Name)
			}
			return result
		}
	}

	// Fallback to aggressive if no WAF detected
	return e.selectAggressiveTampers()
}

// Transform applies selected tampers to a payload string
func (e *Engine) Transform(payload string) string {
	tampers := e.GetSelectedTampers()
	return e.TransformWith(payload, tampers...)
}

// TransformWith applies specific tampers to a payload string
func (e *Engine) TransformWith(payload string, tamperNames ...string) string {
	if len(tamperNames) == 0 {
		return payload
	}

	result := payload
	for _, name := range tamperNames {
		t := Get(name)
		if t == nil {
			continue
		}

		transformed := t.Transform(result)
		if e.metrics != nil {
			e.metrics.RecordTransform(name, result, transformed)
		}
		result = transformed
	}

	return result
}

// TransformMultiple applies selected tampers to multiple payloads
func (e *Engine) TransformMultiple(payloads []string) []TransformedResult {
	tampers := e.GetSelectedTampers()
	results := make([]TransformedResult, 0, len(payloads))

	for _, payload := range payloads {
		transformed := e.TransformWith(payload, tampers...)
		results = append(results, TransformedResult{
			Original:    payload,
			Transformed: transformed,
			Tampers:     tampers,
		})
	}

	return results
}

// TransformedResult represents a payload after tamper transformation
type TransformedResult struct {
	Original    string   `json:"original"`
	Transformed string   `json:"transformed"`
	Tampers     []string `json:"tampers"`
}

// TransformRequest applies HTTP-level tamper modifications to a request
func (e *Engine) TransformRequest(req *http.Request) *http.Request {
	tampers := e.GetSelectedTampers()
	return e.TransformRequestWith(req, tampers...)
}

// TransformRequestWith applies specific tampers to an HTTP request
func (e *Engine) TransformRequestWith(req *http.Request, tamperNames ...string) *http.Request {
	if req == nil || len(tamperNames) == 0 {
		return req
	}

	result := req
	for _, name := range tamperNames {
		t := Get(name)
		if t == nil {
			continue
		}

		if modified := t.TransformRequest(result); modified != nil {
			result = modified
		}
	}

	return result
}

// RecordSuccess records a successful bypass for adaptive learning
func (e *Engine) RecordSuccess(tamperNames []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, name := range tamperNames {
		e.adaptiveMap[name] = e.adaptiveMap[name] + 0.1
		if e.adaptiveMap[name] > 1.0 {
			e.adaptiveMap[name] = 1.0
		}
	}

	if e.metrics != nil {
		e.metrics.RecordSuccess(tamperNames)
	}
}

// RecordFailure records a blocked request for adaptive learning
func (e *Engine) RecordFailure(tamperNames []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, name := range tamperNames {
		e.adaptiveMap[name] = e.adaptiveMap[name] - 0.05
		if e.adaptiveMap[name] < 0 {
			e.adaptiveMap[name] = 0
		}
	}

	if e.metrics != nil {
		e.metrics.RecordFailure(tamperNames)
	}
}

// GetMetrics returns the metrics collector if enabled
func (e *Engine) GetMetrics() *MetricsCollector {
	return e.metrics
}

// GetAdaptiveScores returns the adaptive effectiveness scores
func (e *Engine) GetAdaptiveScores() map[string]float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[string]float64, len(e.adaptiveMap))
	for k, v := range e.adaptiveMap {
		result[k] = v
	}
	return result
}

// DescribeTampers returns human-readable descriptions for the selected tampers
func (e *Engine) DescribeTampers() []TamperInfo {
	tampers := e.GetSelectedTampers()
	infos := make([]TamperInfo, 0, len(tampers))

	for _, name := range tampers {
		t := Get(name)
		if t != nil {
			infos = append(infos, TamperInfo{
				Name:        t.Name(),
				Description: t.Description(),
				Category:    string(t.Category()),
			})
		}
	}

	return infos
}

// TamperInfo holds display information about a tamper
type TamperInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// ParseTamperList parses a comma-separated tamper list
func ParseTamperList(input string) []string {
	if input == "" {
		return nil
	}

	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// ValidateTamperNames checks if all tamper names are valid
func ValidateTamperNames(names []string) (valid []string, invalid []string) {
	for _, name := range names {
		if Get(name) != nil {
			valid = append(valid, name)
		} else {
			invalid = append(invalid, name)
		}
	}
	return
}
