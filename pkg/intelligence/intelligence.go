// Package intelligence provides the Intelligence Engine for WAFtester auto mode.
// This transforms auto mode from "automated sequencing" to "adaptive reasoning" by:
// - Learning from results in real-time
// - Correlating findings across phases
// - Building attack chains from low-severity findings
// - Prioritizing high-value targets based on confidence
// - Modeling WAF behavior patterns
// - Optimizing resource allocation
package intelligence

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Engine is the brain of auto mode - learns, adapts, and reasons
type Engine struct {
	mu sync.RWMutex

	// Learning state
	memory       *Memory
	wafModel     *WAFBehaviorModel
	techProfile  *TechProfile
	attackChains []*AttackChain

	// Statistics
	stats *Stats

	// Configuration
	config *Config

	// Callbacks for cross-phase communication
	onInsight func(insight *Insight)
	onChain   func(chain *AttackChain)
}

// Config configures the Intelligence Engine
type Config struct {
	// Learning sensitivity (0.0-1.0) - higher = more aggressive learning
	LearningSensitivity float64

	// Minimum confidence to act on insights
	MinConfidence float64

	// Enable attack chain building
	EnableChains bool

	// Enable WAF behavioral modeling
	EnableWAFModel bool

	// Maximum attack chains to track
	MaxChains int

	// Verbose logging
	Verbose bool
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		LearningSensitivity: 0.7,
		MinConfidence:       0.6,
		EnableChains:        true,
		EnableWAFModel:      true,
		MaxChains:           50,
		Verbose:             false,
	}
}

// NewEngine creates a new Intelligence Engine
func NewEngine(cfg *Config) *Engine {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &Engine{
		memory:       NewMemory(),
		wafModel:     NewWAFBehaviorModel(),
		techProfile:  NewTechProfile(),
		attackChains: make([]*AttackChain, 0),
		stats:        NewStats(),
		config:       cfg,
	}
}

// OnInsight sets a callback for when a new insight is discovered
func (e *Engine) OnInsight(fn func(*Insight)) {
	e.onInsight = fn
}

// OnChain sets a callback for when an attack chain is built
func (e *Engine) OnChain(fn func(*AttackChain)) {
	e.onChain = fn
}

// ══════════════════════════════════════════════════════════════════════════════
// PHASE LEARNING - Absorb findings from each phase
// ══════════════════════════════════════════════════════════════════════════════

// Finding represents a discovery from any phase
type Finding struct {
	Phase      string                 // discovery, js-analysis, leaky-paths, params, waf-testing
	Category   string                 // xss, sqli, ssrf, secret, endpoint, param, etc.
	Severity   string                 // critical, high, medium, low, info
	Path       string                 // URL path or location
	Payload    string                 // Attack payload if applicable
	Evidence   string                 // Supporting evidence
	StatusCode int                    // HTTP status code if applicable
	Latency    time.Duration          // Response latency
	Blocked    bool                   // Was it blocked by WAF?
	Confidence float64                // 0.0-1.0 confidence score
	Metadata   map[string]interface{} // Additional data
	Timestamp  time.Time
}

// LearnFromFinding processes a single finding
func (e *Engine) LearnFromFinding(finding *Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Store in memory
	e.memory.Store(finding)

	// 2. Update WAF behavioral model
	if e.config.EnableWAFModel {
		e.wafModel.Learn(finding)
	}

	// 3. Update technology profile
	e.techProfile.Update(finding)

	// 4. Check for attack chain opportunities
	if e.config.EnableChains {
		e.checkAttackChains(finding)
	}

	// 5. Generate insights
	insights := e.generateInsights(finding)
	for _, insight := range insights {
		if e.onInsight != nil {
			e.onInsight(insight)
		}
	}

	// 6. Update statistics
	e.stats.RecordFinding(finding)
}

// LearnFromPhase processes a batch of findings from a phase
func (e *Engine) LearnFromPhase(phase string, findings []*Finding) {
	for _, f := range findings {
		f.Phase = phase
		e.LearnFromFinding(f)
	}

	// Cross-phase correlation after batch
	e.correlatePhase(phase)
}

// ══════════════════════════════════════════════════════════════════════════════
// INSIGHT GENERATION - Extract actionable intelligence
// ══════════════════════════════════════════════════════════════════════════════

// Insight represents an actionable piece of intelligence
type Insight struct {
	Type        InsightType // pattern, vulnerability, recommendation, chain
	Priority    int         // 1=critical, 2=high, 3=medium, 4=low, 5=info
	Title       string
	Description string
	Action      string // Recommended action
	Confidence  float64
	Source      string // Which finding(s) generated this
	Timestamp   time.Time
}

// InsightType categorizes insights
type InsightType string

const (
	InsightPattern        InsightType = "pattern"        // Recurring pattern detected
	InsightVulnerability  InsightType = "vulnerability"  // Specific vulnerability found
	InsightRecommendation InsightType = "recommendation" // Action recommendation
	InsightChain          InsightType = "chain"          // Attack chain built
	InsightWAFBehavior    InsightType = "waf_behavior"   // WAF behavior pattern
	InsightTechStack      InsightType = "tech_stack"     // Technology detected
)

// generateInsights extracts insights from a finding
func (e *Engine) generateInsights(f *Finding) []*Insight {
	insights := make([]*Insight, 0)

	// Check for WAF behavioral patterns
	if pattern := e.wafModel.DetectPattern(f); pattern != nil {
		insights = append(insights, &Insight{
			Type:        InsightWAFBehavior,
			Priority:    pattern.Priority,
			Title:       pattern.Name,
			Description: pattern.Description,
			Action:      pattern.RecommendedAction,
			Confidence:  pattern.Confidence,
			Source:      f.Phase,
			Timestamp:   time.Now(),
		})
	}

	// Check for technology indicators
	if tech := e.techProfile.Detect(f); tech != nil {
		insights = append(insights, &Insight{
			Type:        InsightTechStack,
			Priority:    5, // Info level
			Title:       fmt.Sprintf("Technology Detected: %s", tech.Name),
			Description: tech.Description,
			Action:      tech.TestingRecommendation,
			Confidence:  tech.Confidence,
			Source:      f.Phase,
			Timestamp:   time.Now(),
		})
	}

	// Check for vulnerability patterns
	if !f.Blocked && f.Confidence >= e.config.MinConfidence {
		severity := severityToPriority(f.Severity)
		insights = append(insights, &Insight{
			Type:        InsightVulnerability,
			Priority:    severity,
			Title:       fmt.Sprintf("%s Bypass Detected", strings.ToUpper(f.Category)),
			Description: fmt.Sprintf("WAF bypassed at %s with %s payload", f.Path, f.Category),
			Action:      fmt.Sprintf("Investigate %s category rules", f.Category),
			Confidence:  f.Confidence,
			Source:      f.Phase,
			Timestamp:   time.Now(),
		})
	}

	return insights
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CHAIN BUILDING - Combine findings into impact chains
// ══════════════════════════════════════════════════════════════════════════════

// AttackChain represents a chain of findings that together have higher impact
type AttackChain struct {
	ID          string
	Name        string
	Impact      string   // critical, high, medium
	Steps       []string // Ordered attack steps
	Findings    []*Finding
	Description string
	CVSS        float64
	Confidence  float64
	Built       time.Time
}

// checkAttackChains looks for opportunities to build attack chains
func (e *Engine) checkAttackChains(f *Finding) {
	// Chain patterns to look for:

	// 1. Secret + Endpoint = Authentication Bypass potential
	if f.Category == "secret" {
		if endpoints := e.memory.GetByCategory("endpoint"); len(endpoints) > 0 {
			chain := e.buildSecretChain(f, endpoints)
			if chain != nil {
				e.addChain(chain)
			}
		}
	}

	// 2. Leaky path + Parameter = Hidden functionality
	if f.Category == "leaky-path" {
		if params := e.memory.GetByCategory("param"); len(params) > 0 {
			chain := e.buildLeakyParamChain(f, params)
			if chain != nil {
				e.addChain(chain)
			}
		}
	}

	// 3. Multiple low-severity bypasses = Pattern exploitation
	if !f.Blocked && f.Severity == "low" {
		similarBypasses := e.memory.GetSimilarBypasses(f, 3)
		if len(similarBypasses) >= 3 {
			chain := e.buildPatternChain(f, similarBypasses)
			if chain != nil {
				e.addChain(chain)
			}
		}
	}

	// 4. SSRF + Cloud URL = Cloud compromise potential
	if f.Category == "ssrf" && !f.Blocked {
		if cloudURLs := e.memory.GetByCategory("cloud-url"); len(cloudURLs) > 0 {
			chain := e.buildCloudChain(f, cloudURLs)
			if chain != nil {
				e.addChain(chain)
			}
		}
	}

	// 5. XSS + DOM Sink = Reliable XSS
	if f.Category == "xss" && !f.Blocked {
		if domSinks := e.memory.GetByCategory("dom-sink"); len(domSinks) > 0 {
			chain := e.buildXSSChain(f, domSinks)
			if chain != nil {
				e.addChain(chain)
			}
		}
	}

	// 6. SQLi + Auth endpoint = Critical auth bypass
	if f.Category == "sqli" && !f.Blocked {
		if authEndpoints := e.memory.GetByPath("/auth", "/login", "/token", "/oauth"); len(authEndpoints) > 0 {
			chain := e.buildAuthBypassChain(f, authEndpoints)
			if chain != nil {
				e.addChain(chain)
			}
		}
	}
}

func (e *Engine) buildSecretChain(secret *Finding, endpoints []*Finding) *AttackChain {
	// Find auth-related endpoints
	for _, ep := range endpoints {
		pathLower := strings.ToLower(ep.Path)
		if strings.Contains(pathLower, "auth") || strings.Contains(pathLower, "login") ||
			strings.Contains(pathLower, "api") || strings.Contains(pathLower, "admin") {
			return &AttackChain{
				ID:     fmt.Sprintf("secret-auth-%d", time.Now().UnixNano()),
				Name:   "Secret + Auth Endpoint Chain",
				Impact: "critical",
				Steps: []string{
					fmt.Sprintf("1. Extract secret: %s", secret.Evidence),
					fmt.Sprintf("2. Target endpoint: %s", ep.Path),
					"3. Attempt authentication with discovered credentials",
				},
				Findings:    []*Finding{secret, ep},
				Description: "Discovered secret can potentially be used against authentication endpoint",
				CVSS:        9.8,
				Confidence:  secret.Confidence * ep.Confidence,
				Built:       time.Now(),
			}
		}
	}
	return nil
}

func (e *Engine) buildLeakyParamChain(leaky *Finding, params []*Finding) *AttackChain {
	// Find params that could expose the leaky path further
	for _, p := range params {
		if strings.Contains(p.Path, "debug") || strings.Contains(p.Path, "admin") ||
			strings.Contains(strings.ToLower(p.Evidence), "debug") {
			return &AttackChain{
				ID:     fmt.Sprintf("leaky-param-%d", time.Now().UnixNano()),
				Name:   "Leaky Path + Hidden Parameter Chain",
				Impact: "high",
				Steps: []string{
					fmt.Sprintf("1. Access leaky path: %s", leaky.Path),
					fmt.Sprintf("2. Add hidden parameter: %s", p.Evidence),
					"3. Explore hidden functionality",
				},
				Findings:    []*Finding{leaky, p},
				Description: "Hidden parameter may expose additional functionality on sensitive path",
				CVSS:        7.5,
				Confidence:  leaky.Confidence * p.Confidence,
				Built:       time.Now(),
			}
		}
	}
	return nil
}

func (e *Engine) buildPatternChain(f *Finding, similar []*Finding) *AttackChain {
	steps := []string{fmt.Sprintf("1. Initial bypass: %s", f.Payload)}
	for i, s := range similar {
		steps = append(steps, fmt.Sprintf("%d. Similar bypass: %s", i+2, s.Payload))
	}
	steps = append(steps, fmt.Sprintf("%d. Pattern indicates WAF rule gap in %s category", len(similar)+2, f.Category))

	return &AttackChain{
		ID:          fmt.Sprintf("pattern-%d", time.Now().UnixNano()),
		Name:        fmt.Sprintf("Pattern Exploitation: %s", f.Category),
		Impact:      "medium",
		Steps:       steps,
		Findings:    append([]*Finding{f}, similar...),
		Description: fmt.Sprintf("Multiple similar bypasses indicate systematic WAF rule weakness in %s", f.Category),
		CVSS:        6.5,
		Confidence:  0.8,
		Built:       time.Now(),
	}
}

func (e *Engine) buildCloudChain(ssrf *Finding, cloudURLs []*Finding) *AttackChain {
	for _, cloud := range cloudURLs {
		return &AttackChain{
			ID:     fmt.Sprintf("ssrf-cloud-%d", time.Now().UnixNano()),
			Name:   "SSRF + Cloud Metadata Chain",
			Impact: "critical",
			Steps: []string{
				fmt.Sprintf("1. SSRF bypass at: %s", ssrf.Path),
				fmt.Sprintf("2. Target cloud service: %s", cloud.Evidence),
				"3. Attempt cloud metadata access (169.254.169.254, etc.)",
				"4. Potential cloud credential theft",
			},
			Findings:    []*Finding{ssrf, cloud},
			Description: "SSRF vulnerability combined with cloud infrastructure could lead to cloud compromise",
			CVSS:        9.8,
			Confidence:  ssrf.Confidence * cloud.Confidence,
			Built:       time.Now(),
		}
	}
	return nil
}

func (e *Engine) buildXSSChain(xss *Finding, domSinks []*Finding) *AttackChain {
	for _, sink := range domSinks {
		return &AttackChain{
			ID:     fmt.Sprintf("xss-dom-%d", time.Now().UnixNano()),
			Name:   "Reflected XSS + DOM Sink Chain",
			Impact: "high",
			Steps: []string{
				fmt.Sprintf("1. XSS bypass payload: %s", xss.Payload),
				fmt.Sprintf("2. Flows to DOM sink: %s", sink.Evidence),
				"3. Reliable JavaScript execution confirmed",
			},
			Findings:    []*Finding{xss, sink},
			Description: "XSS payload reaches DOM sink, confirming reliable exploitation",
			CVSS:        7.5,
			Confidence:  xss.Confidence * sink.Confidence * 1.2,
			Built:       time.Now(),
		}
	}
	return nil
}

func (e *Engine) buildAuthBypassChain(sqli *Finding, authEndpoints []*Finding) *AttackChain {
	for _, auth := range authEndpoints {
		return &AttackChain{
			ID:     fmt.Sprintf("sqli-auth-%d", time.Now().UnixNano()),
			Name:   "SQLi + Authentication Bypass Chain",
			Impact: "critical",
			Steps: []string{
				fmt.Sprintf("1. SQLi bypass payload: %s", sqli.Payload),
				fmt.Sprintf("2. Target auth endpoint: %s", auth.Path),
				"3. Attempt authentication bypass with SQLi",
				"4. Potential complete authentication bypass",
			},
			Findings:    []*Finding{sqli, auth},
			Description: "SQL injection combined with authentication endpoint could lead to auth bypass",
			CVSS:        9.8,
			Confidence:  sqli.Confidence * auth.Confidence,
			Built:       time.Now(),
		}
	}
	return nil
}

func (e *Engine) addChain(chain *AttackChain) {
	// Check for duplicates
	for _, existing := range e.attackChains {
		if existing.Name == chain.Name {
			return
		}
	}

	e.attackChains = append(e.attackChains, chain)

	// Limit chains
	if len(e.attackChains) > e.config.MaxChains {
		// Keep highest impact chains
		sort.Slice(e.attackChains, func(i, j int) bool {
			return e.attackChains[i].CVSS > e.attackChains[j].CVSS
		})
		e.attackChains = e.attackChains[:e.config.MaxChains]
	}

	// Notify
	if e.onChain != nil {
		e.onChain(chain)
	}
}

// GetAttackChains returns all built attack chains
func (e *Engine) GetAttackChains() []*AttackChain {
	e.mu.RLock()
	defer e.mu.RUnlock()

	chains := make([]*AttackChain, len(e.attackChains))
	copy(chains, e.attackChains)
	return chains
}

// ══════════════════════════════════════════════════════════════════════════════
// CROSS-PHASE CORRELATION - Connect findings across phases
// ══════════════════════════════════════════════════════════════════════════════

// correlatePhase performs cross-phase correlation after a phase completes
func (e *Engine) correlatePhase(phase string) {
	// Phase-specific correlations
	switch phase {
	case "discovery":
		// Discovery complete - prepare for JS analysis
		e.prepareJSAnalysis()

	case "js-analysis":
		// JS complete - correlate with discovery
		e.correlateJSWithDiscovery()

	case "leaky-paths":
		// Leaky paths complete - prioritize WAF testing
		e.prioritizeFromLeakyPaths()

	case "params":
		// Params complete - enhance payload targeting
		e.enhancePayloadTargeting()

	case "waf-testing":
		// Testing complete - build final chains
		e.buildFinalChains()
	}
}

func (e *Engine) prepareJSAnalysis() {
	// Identify high-value JS targets from discovery
	endpoints := e.memory.GetByCategory("endpoint")
	for _, ep := range endpoints {
		if strings.HasSuffix(ep.Path, ".js") ||
			strings.Contains(ep.Path, "config") ||
			strings.Contains(ep.Path, "admin") {
			ep.Metadata["priority"] = "high"
		}
	}
}

func (e *Engine) correlateJSWithDiscovery() {
	// Match JS-discovered endpoints with crawled endpoints
	jsEndpoints := e.memory.GetByPhase("js-analysis")
	discoveredEndpoints := e.memory.GetByPhase("discovery")

	for _, js := range jsEndpoints {
		for _, disc := range discoveredEndpoints {
			if js.Path == disc.Path {
				// Endpoint found in both - higher confidence
				js.Confidence *= 1.5
				if js.Confidence > 1.0 {
					js.Confidence = 1.0
				}
			}
		}
	}
}

func (e *Engine) prioritizeFromLeakyPaths() {
	// Leaky paths inform which categories to prioritize
	leaky := e.memory.GetByPhase("leaky-paths")
	for _, l := range leaky {
		if strings.Contains(l.Path, "admin") || strings.Contains(l.Path, "debug") {
			// Found admin/debug paths - prioritize auth testing
			e.memory.SetPriority("auth", "high")
			e.memory.SetPriority("jwt", "high")
		}
		if strings.Contains(l.Path, ".git") || strings.Contains(l.Path, ".env") {
			// Found config exposure - prioritize secret validation
			e.memory.SetPriority("secret", "critical")
		}
	}
}

func (e *Engine) enhancePayloadTargeting() {
	// Use discovered params to enhance payload targeting
	params := e.memory.GetByCategory("param")
	for _, p := range params {
		// Store param names for payload injection
		if p.Metadata == nil {
			p.Metadata = make(map[string]interface{})
		}
		p.Metadata["inject_target"] = true
	}
}

func (e *Engine) buildFinalChains() {
	// After all phases, build any remaining attack chains
	bypasses := e.memory.GetBypasses()
	for _, b := range bypasses {
		e.checkAttackChains(b)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// SMART PAYLOAD SELECTION - Choose payloads based on intelligence
// ══════════════════════════════════════════════════════════════════════════════

// PayloadRecommendation suggests payload categories and priorities
type PayloadRecommendation struct {
	Category   string
	Priority   int
	Reason     string
	Confidence float64
}

// RecommendPayloads returns prioritized payload recommendations
func (e *Engine) RecommendPayloads() []*PayloadRecommendation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	recommendations := make([]*PayloadRecommendation, 0)

	// Based on technology profile
	if e.techProfile.HasFramework("django") || e.techProfile.HasFramework("flask") {
		recommendations = append(recommendations, &PayloadRecommendation{
			Category:   "ssti",
			Priority:   1,
			Reason:     "Python framework detected - SSTI high priority",
			Confidence: 0.9,
		})
	}

	if e.techProfile.HasFramework("express") || e.techProfile.HasFramework("node") {
		recommendations = append(recommendations, &PayloadRecommendation{
			Category:   "prototype-pollution",
			Priority:   1,
			Reason:     "Node.js detected - prototype pollution high priority",
			Confidence: 0.9,
		})
	}

	if e.techProfile.HasDatabase("mongodb") || e.techProfile.HasDatabase("nosql") {
		recommendations = append(recommendations, &PayloadRecommendation{
			Category:   "nosqli",
			Priority:   1,
			Reason:     "NoSQL database detected",
			Confidence: 0.85,
		})
	}

	// Based on WAF behavioral patterns
	if patterns := e.wafModel.GetWeaknesses(); len(patterns) > 0 {
		for _, p := range patterns {
			recommendations = append(recommendations, &PayloadRecommendation{
				Category:   p.Category,
				Priority:   2,
				Reason:     fmt.Sprintf("WAF weakness detected: %s", p.Description),
				Confidence: p.Confidence,
			})
		}
	}

	// Based on bypasses already found
	bypasses := e.memory.GetBypasses()
	categoryBypass := make(map[string]int)
	for _, b := range bypasses {
		categoryBypass[b.Category]++
	}
	for cat, count := range categoryBypass {
		if count >= 2 {
			recommendations = append(recommendations, &PayloadRecommendation{
				Category:   cat,
				Priority:   1,
				Reason:     fmt.Sprintf("%d bypasses found - attack vector viable", count),
				Confidence: 0.95,
			})
		}
	}

	// Sort by priority then confidence
	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].Priority != recommendations[j].Priority {
			return recommendations[i].Priority < recommendations[j].Priority
		}
		return recommendations[i].Confidence > recommendations[j].Confidence
	})

	return recommendations
}

// ══════════════════════════════════════════════════════════════════════════════
// RATE OPTIMIZATION - Allocate resources intelligently
// ══════════════════════════════════════════════════════════════════════════════

// ResourceAllocation recommends how to allocate testing resources
type ResourceAllocation struct {
	Category      string
	AllocationPct float64 // Percentage of total requests
	Reason        string
}

// RecommendResourceAllocation returns resource allocation recommendations
func (e *Engine) RecommendResourceAllocation() []*ResourceAllocation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	allocations := make([]*ResourceAllocation, 0)
	remaining := 100.0

	// High-value categories from bypasses
	bypasses := e.memory.GetBypasses()
	categorySuccess := make(map[string]float64)
	categoryTotal := make(map[string]float64)

	for _, f := range e.memory.GetAll() {
		categoryTotal[f.Category]++
		if !f.Blocked {
			categorySuccess[f.Category]++
		}
	}

	// Calculate success rates
	type catRate struct {
		Category string
		Rate     float64
	}
	rates := make([]catRate, 0)
	for cat, total := range categoryTotal {
		if total >= 3 {
			rate := categorySuccess[cat] / total
			rates = append(rates, catRate{cat, rate})
		}
	}

	// Sort by success rate
	sort.Slice(rates, func(i, j int) bool {
		return rates[i].Rate > rates[j].Rate
	})

	// Allocate based on success rate
	for _, r := range rates {
		alloc := r.Rate * 40 // Max 40% per category
		if alloc > remaining {
			alloc = remaining
		}
		if alloc >= 5 { // Minimum 5% allocation
			allocations = append(allocations, &ResourceAllocation{
				Category:      r.Category,
				AllocationPct: alloc,
				Reason:        fmt.Sprintf("%.0f%% bypass rate", r.Rate*100),
			})
			remaining -= alloc
		}
	}

	// Distribute remaining evenly
	if remaining > 0 && len(bypasses) == 0 {
		// No bypasses yet - even distribution
		allocations = append(allocations, &ResourceAllocation{
			Category:      "all",
			AllocationPct: remaining,
			Reason:        "Initial exploration",
		})
	}

	return allocations
}

// ══════════════════════════════════════════════════════════════════════════════
// SUMMARY AND REPORTING
// ══════════════════════════════════════════════════════════════════════════════

// Summary returns a summary of intelligence gathered
type Summary struct {
	TotalFindings int
	Bypasses      int
	Blocked       int
	AttackChains  int
	Insights      []*Insight
	TopChains     []*AttackChain
	TopCategories []string
	WAFStrengths  []string
	WAFWeaknesses []string
	TechStack     []string
}

// GetSummary returns the intelligence summary
func (e *Engine) GetSummary() *Summary {
	e.mu.RLock()
	defer e.mu.RUnlock()

	summary := &Summary{
		TotalFindings: e.memory.Count(),
		Bypasses:      len(e.memory.GetBypasses()),
		Blocked:       e.memory.CountBlocked(),
		AttackChains:  len(e.attackChains),
		TopChains:     e.getTopChains(5),
		TopCategories: e.stats.TopCategories(5),
		WAFStrengths:  e.wafModel.GetStrengths(),
		WAFWeaknesses: e.wafModel.GetWeaknessStrings(),
		TechStack:     e.techProfile.GetDetected(),
	}

	return summary
}

func (e *Engine) getTopChains(n int) []*AttackChain {
	if len(e.attackChains) <= n {
		return e.attackChains
	}

	sorted := make([]*AttackChain, len(e.attackChains))
	copy(sorted, e.attackChains)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CVSS > sorted[j].CVSS
	})
	return sorted[:n]
}

// ══════════════════════════════════════════════════════════════════════════════
// RUN INTEGRATION - Context-aware execution
// ══════════════════════════════════════════════════════════════════════════════

// StartPhase notifies the engine that a phase is starting
func (e *Engine) StartPhase(ctx context.Context, phase string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.StartPhase(phase)
}

// EndPhase notifies the engine that a phase has ended
func (e *Engine) EndPhase(phase string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.EndPhase(phase)
	e.correlatePhase(phase)
}

// Helper functions

func severityToPriority(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 5
	}
}
