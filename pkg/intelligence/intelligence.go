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

// Engine configuration defaults.
const (
	// DefaultMaxChains is the default maximum number of attack chains to track.
	DefaultMaxChains = 50
)

// Engine is the brain of auto mode - learns, adapts, and reasons
type Engine struct {
	mu sync.RWMutex

	// Learning state
	memory       *Memory
	wafModel     *WAFBehaviorModel
	techProfile  *TechProfile
	attackChains []*AttackChain

	// Advanced cognitive modules
	predictor   *Predictor           // Predicts bypass probability
	mutator     *MutationStrategist  // Suggests mutations when blocked
	clusterer   *EndpointClusterer   // Groups similar endpoints
	anomaly     *AnomalyDetector     // Detects honeypots, silent bans
	pathfinder  *AttackPathOptimizer // Finds optimal attack paths
	wafProfiler *WAFProfiler         // WAF fingerprint profiling

	// Master Brain modules
	banditCategory *BanditSelector      // Thompson Sampling for categories
	banditEncoding *BanditSelector      // Thompson Sampling for encodings
	banditPattern  *BanditSelector      // Thompson Sampling for patterns
	controlLoop    *ControlLoop         // OODA feedback loop
	phaseCtrl      *PhaseController     // Q-learning phase ordering
	calibrator     *ChangePointDetector // CUSUM change-point detection
	influenceGraph *InfluenceGraph      // Cross-phase correlation
	mutationGen    *MutationGenerator   // GA mutation generation

	// Observability
	metrics *Metrics

	// Statistics
	stats *Stats

	// Configuration
	config *Config

	// Callbacks for cross-phase communication
	onInsight func(insight *Insight)
	onChain   func(chain *AttackChain)
	onAnomaly func(anomaly *Anomaly)
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

	// MasterBrainEnabled activates all advanced ML modules.
	// When false, Engine uses the original heuristic-based algorithms.
	MasterBrainEnabled bool
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
		MasterBrainEnabled:  true,
	}
}

// NewEngine creates a new Intelligence Engine
func NewEngine(cfg *Config) *Engine {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	e := &Engine{
		memory:       NewMemory(),
		wafModel:     NewWAFBehaviorModel(),
		techProfile:  NewTechProfile(),
		attackChains: make([]*AttackChain, 0),
		stats:        NewStats(),
		config:       cfg,
		metrics:      NewMetrics(),
		wafProfiler:  NewWAFProfiler(),
		// Advanced cognitive modules
		predictor:  NewPredictor(),
		mutator:    NewMutationStrategist(),
		clusterer:  NewEndpointClusterer(),
		anomaly:    NewAnomalyDetector(),
		pathfinder: NewAttackPathOptimizer(),
	}

	// Initialize Master Brain modules when enabled
	if cfg.MasterBrainEnabled {
		seed := time.Now().UnixNano()
		e.banditCategory = NewBanditSelector(seed)
		e.banditEncoding = NewBanditSelector(seed + 1)
		e.banditPattern = NewBanditSelector(seed + 2)
		e.phaseCtrl = NewPhaseController(
			[]string{"discovery", "js-analysis", "leaky-paths", "params", "waf-testing"},
			DefaultPhaseControllerConfig(),
		)
		e.calibrator = NewChangePointDetector(DefaultCalibratorConfig(), func(metric string, magnitude float64) {
			// Re-calibration callback — triggered when CUSUM detects behavioral shift
			e.recalibrate(metric, magnitude)
		})
		e.influenceGraph = NewInfluenceGraph()
		SeedKnownCorrelations(e.influenceGraph)
		e.mutationGen = NewMutationGenerator(DefaultMutationGeneratorConfig(), seed+4)
		// ControlLoop requires the Engine pointer — set after struct is populated
		e.controlLoop = NewControlLoop(e, DefaultControlLoopConfig())
		// Wire bandits into predictor for Thompson Sampling exploration
		e.predictor.SetBandits(e.banditCategory, e.banditEncoding, e.banditPattern)
		// Wire CUSUM into anomaly detector for change-point detection
		e.anomaly.SetChangeDetector(e.calibrator)
		// Wire influence graph into WAF model for cross-phase correlation
		e.wafModel.SetInfluenceGraph(e.influenceGraph)
		// Wire mutation generator into strategist for GA-based mutations
		e.mutator.SetMutationGenerator(e.mutationGen)
	}

	return e
}

// OnInsight sets a callback for when a new insight is discovered
func (e *Engine) OnInsight(fn func(*Insight)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onInsight = fn
}

// OnChain sets a callback for when an attack chain is built
func (e *Engine) OnChain(fn func(*AttackChain)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onChain = fn
}

// OnAnomaly sets a callback for when an anomaly is detected.
// Note: The callback must not call Engine methods to avoid deadlock.
func (e *Engine) OnAnomaly(fn func(*Anomaly)) {
	e.mu.Lock()
	e.onAnomaly = fn
	anomalyDetector := e.anomaly
	e.mu.Unlock()

	// Set on the anomaly detector after releasing lock to prevent
	// lock ordering issues (Engine.mu -> AnomalyDetector.mu)
	if anomalyDetector != nil {
		anomalyDetector.SetCallback(fn)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ADVANCED COGNITIVE MODULE ACCESSORS
// ══════════════════════════════════════════════════════════════════════════════

// Predictor returns the bypass prediction module
func (e *Engine) Predictor() *Predictor {
	return e.predictor
}

// MutationStrategist returns the mutation strategy module
func (e *Engine) MutationStrategist() *MutationStrategist {
	return e.mutator
}

// EndpointClusterer returns the endpoint clustering module
func (e *Engine) EndpointClusterer() *EndpointClusterer {
	return e.clusterer
}

// AnomalyDetector returns the anomaly detection module
func (e *Engine) AnomalyDetector() *AnomalyDetector {
	return e.anomaly
}

// AttackPathOptimizer returns the attack path optimization module
func (e *Engine) AttackPathOptimizer() *AttackPathOptimizer {
	return e.pathfinder
}

// WAFProfiler returns the WAF profiler module
func (e *Engine) WAFProfiler() *WAFProfiler {
	return e.wafProfiler
}

// Metrics returns the metrics tracker
func (e *Engine) Metrics() *Metrics {
	return e.metrics
}

// ══════════════════════════════════════════════════════════════════════════════
// PHASE LEARNING - Absorb findings from each phase
// ══════════════════════════════════════════════════════════════════════════════

// Finding represents a discovered item from any phase.
// Phases fall into two categories:
//   - Recon phases: discovery, js-analysis, leaky-paths, param-discovery
//   - Testing phases: waf-testing, brain-feedback, mutation-pass
//
// Only testing phases produce meaningful Blocked values. Recon findings
// always have Blocked=false (zero value) because they are HTTP responses,
// not WAF test results. Bypass/block counters must only count testing findings.
type Finding struct {
	Phase           string                 // discovery, js-analysis, leaky-paths, param-discovery, waf-testing, brain-feedback, mutation-pass
	Category        string                 // xss, sqli, ssrf, secret, endpoint, param, etc.
	Severity        string                 // critical, high, medium, low, info
	Path            string                 // URL path or location
	Method          string                 // HTTP method (GET, POST, etc.)
	Payload         string                 // Attack payload if applicable
	OriginalPayload string                 // Pre-mutation payload (set when this is a mutation bypass)
	Evidence        string                 // Supporting evidence
	StatusCode      int                    // HTTP status code if applicable
	Latency         time.Duration          // Response latency
	Blocked         bool                   // Was it blocked by WAF?
	Confidence      float64                // 0.0-1.0 confidence score
	Encodings       []string               // Encodings applied to payload
	Metadata        map[string]interface{} // Additional data
	Timestamp       time.Time
}

// IsTestingPhase returns true if the finding is from a WAF testing phase
// where the Blocked field is meaningful. Recon-phase findings (discovery,
// js-analysis, leaky-paths, param-discovery) have Blocked=false by default
// and must not be counted as bypasses.
func (f *Finding) IsTestingPhase() bool {
	switch f.Phase {
	case "waf-testing", "brain-feedback", "mutation-pass":
		return true
	default:
		return false
	}
}

// LearnFromFinding processes a single finding.
// Safe to call with nil finding (no-op).
func (e *Engine) LearnFromFinding(finding *Finding) {
	if finding == nil {
		return
	}

	// Collect insights, anomalies, and chains while holding lock, invoke callbacks after releasing
	var insights []*Insight
	var anomalies []Anomaly
	var newChains []*AttackChain

	isTesting := finding.IsTestingPhase()

	e.mu.Lock()

	// 0. Record metrics (only count blocked/bypassed for testing phases)
	if e.metrics != nil {
		if isTesting {
			e.metrics.RecordFinding(finding.Blocked)
		} else {
			e.metrics.FindingsProcessed.Add(1)
		}
	}

	// 1. Store in memory (all phases — recon context is valuable)
	e.memory.Store(finding)

	// 2. Update WAF behavioral model (testing phases only —
	// recon findings have Blocked=false which inflates bypass counts)
	if e.config.EnableWAFModel && isTesting {
		e.wafModel.Learn(finding)
	}

	// 3. Update technology profile (all phases — recon detects tech)
	e.techProfile.Update(finding)

	// 4. Update WAF profiler (testing phases only — same bypass inflation risk)
	if e.wafProfiler != nil && isTesting {
		e.wafProfiler.LearnFromFinding(finding)
	}

	// 5. Check for attack chain opportunities (collect for callback)
	if e.config.EnableChains {
		newChains = e.checkAttackChains(finding)
	}

	// 6. Generate insights (collect, don't invoke callback yet)
	insights = e.generateInsights(finding)

	// 7. Update statistics (testing phases only for bypass/block counts)
	e.stats.RecordFinding(finding, isTesting)

	// 8. Feed advanced cognitive modules (returns anomalies for callback)
	anomalies = e.feedAdvancedModules(finding)

	// Get callback references while holding lock
	onInsight := e.onInsight
	// NOTE: onAnomaly is invoked directly by AnomalyDetector.ObserveResponse
	// during feedAdvancedModules, so we don't capture it here to avoid duplicates
	onChain := e.onChain

	e.mu.Unlock()

	// 9. Invoke callbacks AFTER releasing lock to prevent deadlock
	// If callback calls back into Engine, it can safely acquire lock
	for _, insight := range insights {
		if onInsight != nil {
			onInsight(insight)
		}
	}
	// NOTE: Anomaly callbacks are invoked by AnomalyDetector.ObserveResponse
	// during feedAdvancedModules. Do NOT invoke again here to prevent duplicates.
	_ = anomalies // Anomalies already notified via callback in ObserveResponse

	for _, chain := range newChains {
		if onChain != nil {
			onChain(chain)
		}
	}
}

// feedAdvancedModules updates all advanced cognitive modules with a finding.
// Returns any anomalies detected for callback invocation after lock release.
func (e *Engine) feedAdvancedModules(finding *Finding) []Anomaly {
	if finding == nil {
		return nil
	}

	isTesting := finding.IsTestingPhase()

	// Feed the predictor to learn bypass patterns (testing only —
	// recon findings would teach the predictor that everything bypasses)
	if e.predictor != nil && isTesting {
		e.predictor.Learn(finding)
	}

	// Feed mutation strategist with block/bypass outcomes (testing only)
	if e.mutator != nil && isTesting {
		if finding.Blocked {
			e.mutator.LearnBlock(finding.Category, finding.Payload, finding.StatusCode)
		} else if finding.Severity != "info" && finding.Payload != "" && finding.OriginalPayload != "" {
			// Only learn bypass when we know the original blocked payload,
			// so the strategist can detect the actual mutation type applied
			e.mutator.LearnBypass(finding.Category, finding.OriginalPayload, finding.Payload)
		}
	}

	// Feed endpoint clusterer (all phases — recon path data is valuable)
	if e.clusterer != nil && finding.Path != "" {
		e.clusterer.AddEndpoint(finding.Path, finding.Method)
		if isTesting {
			e.clusterer.RecordBehavior(finding.Path, finding.StatusCode, finding.Blocked, finding.Category, float64(finding.Latency.Milliseconds()), finding.Method)
		}
	}

	// Feed anomaly detector (testing only — recon status codes are not anomalies)
	var anomalies []Anomaly
	if e.anomaly != nil && finding.StatusCode > 0 && isTesting {
		responseSize := 0
		if finding.Evidence != "" {
			responseSize = len(finding.Evidence)
		}
		anomalies = e.anomaly.ObserveResponse(
			float64(finding.Latency.Milliseconds()),
			finding.StatusCode,
			responseSize,
			finding.Blocked,
			finding.Category,
			finding.Path,
		)
	}

	// Feed attack path optimizer (testing only)
	if e.pathfinder != nil && isTesting {
		if !finding.Blocked && finding.Severity != "info" && finding.Payload != "" {
			e.pathfinder.LearnFromBypass(finding.Path, finding.Category, finding.Payload)
		} else if finding.Blocked {
			e.pathfinder.LearnFromBlock(finding.Path, finding.Category)
		}
	}

	// Feed Master Brain modules (testing only — all use Blocked as reward signal)
	if e.config.MasterBrainEnabled && isTesting {
		// Thompson Sampling bandits
		if e.banditCategory != nil && finding.Category != "" {
			e.banditCategory.Record(finding.Category, !finding.Blocked)
		}
		if e.banditEncoding != nil && len(finding.Encodings) > 0 {
			for _, enc := range finding.Encodings {
				e.banditEncoding.Record(enc, !finding.Blocked)
			}
		}
		if e.banditPattern != nil && finding.Payload != "" {
			e.banditPattern.Record(finding.Payload, !finding.Blocked)
		}

		// CUSUM change-point detection is handled by AnomalyDetector.ObserveResponse;
		// feeding here as well would double-count every observation, making the
		// detector trigger alarms roughly twice as fast as intended.

		// Influence graph propagation
		if e.influenceGraph != nil && finding.Category != "" {
			signal := 0.5
			if !finding.Blocked {
				signal = 1.0
			}
			e.influenceGraph.Propagate("category:"+finding.Category, signal)
		}
	}

	return anomalies
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

	// Check for vulnerability patterns — only for testing-phase findings with
	// actual HTTP responses. Recon findings always have Blocked=false which
	// would generate spurious "Bypass Detected" insights for every endpoint.
	if !f.Blocked && f.IsTestingPhase() && f.StatusCode > 0 && f.Confidence >= e.config.MinConfidence {
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

// checkAttackChains looks for opportunities to build attack chains.
// Returns newly added chains for callback invocation after lock release.
func (e *Engine) checkAttackChains(f *Finding) []*AttackChain {
	var newChains []*AttackChain

	// Chain patterns to look for:

	// 1. Secret + Endpoint = Authentication Bypass potential
	if f.Category == "secret" {
		if endpoints := e.memory.GetByCategory("endpoint"); len(endpoints) > 0 {
			chain := e.buildSecretChain(f, endpoints)
			if chain != nil {
				if added := e.addChain(chain); added != nil {
					newChains = append(newChains, added)
				}
			}
		}
	}

	// 2. Leaky path + Parameter = Hidden functionality
	if f.Category == "leaky-path" {
		if params := e.memory.GetByCategory("param"); len(params) > 0 {
			chain := e.buildLeakyParamChain(f, params)
			if chain != nil {
				if added := e.addChain(chain); added != nil {
					newChains = append(newChains, added)
				}
			}
		}
	}

	// 3. Multiple low-severity bypasses = Pattern exploitation
	if !f.Blocked && f.Severity == "low" {
		similarBypasses := e.memory.GetSimilarBypasses(f, 3)
		if len(similarBypasses) >= 3 {
			chain := e.buildPatternChain(f, similarBypasses)
			if chain != nil {
				if added := e.addChain(chain); added != nil {
					newChains = append(newChains, added)
				}
			}
		}
	}

	// 4. SSRF + Cloud URL = Cloud compromise potential
	if f.Category == "ssrf" && !f.Blocked {
		if cloudURLs := e.memory.GetByCategory("cloud-url"); len(cloudURLs) > 0 {
			chain := e.buildCloudChain(f, cloudURLs)
			if chain != nil {
				if added := e.addChain(chain); added != nil {
					newChains = append(newChains, added)
				}
			}
		}
	}

	// 5. XSS + DOM Sink = Reliable XSS
	if f.Category == "xss" && !f.Blocked {
		if domSinks := e.memory.GetByCategory("dom-sink"); len(domSinks) > 0 {
			chain := e.buildXSSChain(f, domSinks)
			if chain != nil {
				if added := e.addChain(chain); added != nil {
					newChains = append(newChains, added)
				}
			}
		}
	}

	// 6. SQLi + Auth endpoint = Critical auth bypass
	if f.Category == "sqli" && !f.Blocked {
		if authEndpoints := e.memory.GetByPath("/auth", "/login", "/token", "/oauth"); len(authEndpoints) > 0 {
			chain := e.buildAuthBypassChain(f, authEndpoints)
			if chain != nil {
				if added := e.addChain(chain); added != nil {
					newChains = append(newChains, added)
				}
			}
		}
	}

	return newChains
}

func (e *Engine) buildSecretChain(secret *Finding, endpoints []*Finding) *AttackChain {
	// Find the best auth-related endpoint (highest confidence)
	var best *Finding
	bestScore := 0.0
	for _, ep := range endpoints {
		pathLower := strings.ToLower(ep.Path)
		if strings.Contains(pathLower, "auth") || strings.Contains(pathLower, "login") ||
			strings.Contains(pathLower, "api") || strings.Contains(pathLower, "admin") {
			if ep.Confidence > bestScore {
				bestScore = ep.Confidence
				best = ep
			}
		}
	}
	if best == nil {
		return nil
	}
	return &AttackChain{
		ID:     fmt.Sprintf("secret-auth-%d", time.Now().UnixNano()),
		Name:   "Secret + Auth Endpoint Chain",
		Impact: "critical",
		Steps: []string{
			fmt.Sprintf("1. Extract secret: %s", secret.Evidence),
			fmt.Sprintf("2. Target endpoint: %s", best.Path),
			"3. Attempt authentication with discovered credentials",
		},
		Findings:    []*Finding{secret, best},
		Description: "Discovered secret can potentially be used against authentication endpoint",
		CVSS:        9.8,
		Confidence:  secret.Confidence * best.Confidence,
		Built:       time.Now(),
	}
}

func (e *Engine) buildLeakyParamChain(leaky *Finding, params []*Finding) *AttackChain {
	// Find the best param that could expose the leaky path further (highest confidence)
	var best *Finding
	bestScore := 0.0
	for _, p := range params {
		pathLower := strings.ToLower(p.Path)
		if strings.Contains(pathLower, "debug") || strings.Contains(pathLower, "admin") ||
			strings.Contains(strings.ToLower(p.Evidence), "debug") {
			if p.Confidence > bestScore {
				bestScore = p.Confidence
				best = p
			}
		}
	}
	if best == nil {
		return nil
	}
	return &AttackChain{
		ID:     fmt.Sprintf("leaky-param-%d", time.Now().UnixNano()),
		Name:   "Leaky Path + Hidden Parameter Chain",
		Impact: "high",
		Steps: []string{
			fmt.Sprintf("1. Access leaky path: %s", leaky.Path),
			fmt.Sprintf("2. Add hidden parameter: %s", best.Evidence),
			"3. Explore hidden functionality",
		},
		Findings:    []*Finding{leaky, best},
		Description: "Hidden parameter may expose additional functionality on sensitive path",
		CVSS:        7.5,
		Confidence:  leaky.Confidence * best.Confidence,
		Built:       time.Now(),
	}
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
	// Pick the cloud finding with highest confidence
	var best *Finding
	for _, cloud := range cloudURLs {
		if best == nil || cloud.Confidence > best.Confidence {
			best = cloud
		}
	}
	if best == nil {
		return nil
	}
	return &AttackChain{
		ID:     fmt.Sprintf("ssrf-cloud-%d", time.Now().UnixNano()),
		Name:   "SSRF + Cloud Metadata Chain",
		Impact: "critical",
		Steps: []string{
			fmt.Sprintf("1. SSRF bypass at: %s", ssrf.Path),
			fmt.Sprintf("2. Target cloud service: %s", best.Evidence),
			"3. Attempt cloud metadata access (169.254.169.254, etc.)",
			"4. Potential cloud credential theft",
		},
		Findings:    []*Finding{ssrf, best},
		Description: "SSRF vulnerability combined with cloud infrastructure could lead to cloud compromise",
		CVSS:        9.8,
		Confidence:  ssrf.Confidence * best.Confidence,
		Built:       time.Now(),
	}
}

func (e *Engine) buildXSSChain(xss *Finding, domSinks []*Finding) *AttackChain {
	// Pick the DOM sink with highest confidence
	var best *Finding
	var bestConfidence float64
	for _, sink := range domSinks {
		conf := xss.Confidence * sink.Confidence * 1.2
		if conf > 1.0 {
			conf = 1.0
		}
		if best == nil || conf > bestConfidence {
			best = sink
			bestConfidence = conf
		}
	}
	if best == nil {
		return nil
	}
	return &AttackChain{
		ID:     fmt.Sprintf("xss-dom-%d", time.Now().UnixNano()),
		Name:   "Reflected XSS + DOM Sink Chain",
		Impact: "high",
		Steps: []string{
			fmt.Sprintf("1. XSS bypass payload: %s", xss.Payload),
			fmt.Sprintf("2. Flows to DOM sink: %s", best.Evidence),
			"3. Reliable JavaScript execution confirmed",
		},
		Findings:    []*Finding{xss, best},
		Description: "XSS payload reaches DOM sink, confirming reliable exploitation",
		CVSS:        7.5,
		Confidence:  bestConfidence,
		Built:       time.Now(),
	}
}

func (e *Engine) buildAuthBypassChain(sqli *Finding, authEndpoints []*Finding) *AttackChain {
	// Pick the auth endpoint with highest confidence
	var best *Finding
	for _, auth := range authEndpoints {
		if best == nil || auth.Confidence > best.Confidence {
			best = auth
		}
	}
	if best == nil {
		return nil
	}
	return &AttackChain{
		ID:     fmt.Sprintf("sqli-auth-%d", time.Now().UnixNano()),
		Name:   "SQLi + Authentication Bypass Chain",
		Impact: "critical",
		Steps: []string{
			fmt.Sprintf("1. SQLi bypass payload: %s", sqli.Payload),
			fmt.Sprintf("2. Target auth endpoint: %s", best.Path),
			"3. Attempt authentication bypass with SQLi",
			"4. Potential complete authentication bypass",
		},
		Findings:    []*Finding{sqli, best},
		Description: "SQL injection combined with authentication endpoint could lead to auth bypass",
		CVSS:        9.8,
		Confidence:  sqli.Confidence * best.Confidence,
		Built:       time.Now(),
	}
}

// addChain adds a chain to the engine and returns it if new (for later callback).
// Returns nil if the chain is a duplicate.
func (e *Engine) addChain(chain *AttackChain) *AttackChain {
	// Check for duplicates
	for _, existing := range e.attackChains {
		if existing.Name == chain.Name {
			return nil
		}
	}

	e.attackChains = append(e.attackChains, chain)

	// Limit chains with batched sorting (optimize for frequent additions)
	// Ensure MaxChains is valid to prevent infinite growth
	maxChains := e.config.MaxChains
	if maxChains <= 0 {
		maxChains = DefaultMaxChains
	}
	if len(e.attackChains) > maxChains*2 {
		// Keep highest impact chains
		sort.Slice(e.attackChains, func(i, j int) bool {
			return e.attackChains[i].CVSS > e.attackChains[j].CVSS
		})
		e.attackChains = e.attackChains[:maxChains]
	}

	// Return chain for callback invocation after lock release
	return chain
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
	// Note: GetByCategory returns pointers to shared Findings.
	// We only read from these to avoid data races; priority is stored
	// in Memory's priority map instead of mutating shared Findings.
	endpoints := e.memory.GetByCategory("endpoint")
	for _, ep := range endpoints {
		if strings.HasSuffix(ep.Path, ".js") ||
			strings.Contains(ep.Path, "config") ||
			strings.Contains(ep.Path, "admin") {
			// Store priority safely via Memory's thread-safe method
			e.memory.SetPriority("endpoint:"+ep.Path, "high")
		}
	}
}

func (e *Engine) correlateJSWithDiscovery() {
	// Match JS-discovered endpoints with crawled endpoints
	// Endpoints found in both JS analysis and crawling are higher confidence targets
	jsEndpoints := e.memory.GetByPhase("js-analysis")
	discoveredEndpoints := e.memory.GetByPhase("discovery")

	// Build a set of discovered paths for O(1) lookup
	discoveredPaths := make(map[string]bool)
	for _, disc := range discoveredEndpoints {
		discoveredPaths[disc.Path] = true
	}

	// Boost priority for endpoints found in both phases
	for _, js := range jsEndpoints {
		if discoveredPaths[js.Path] {
			e.memory.SetPriority("endpoint:"+js.Path, "high")
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
	// Use discovered params to prioritize attack categories
	params := e.memory.GetByCategory("param")
	for _, p := range params {
		name := strings.ToLower(p.Evidence)
		switch {
		case strings.Contains(name, "id") || strings.Contains(name, "user"):
			e.memory.SetPriority("sqli", "high")
			e.memory.SetPriority("idor", "high")
		case strings.Contains(name, "url") || strings.Contains(name, "redirect") || strings.Contains(name, "path"):
			e.memory.SetPriority("ssrf", "high")
			e.memory.SetPriority("redirect", "high")
		case strings.Contains(name, "file") || strings.Contains(name, "template"):
			e.memory.SetPriority("lfi", "high")
			e.memory.SetPriority("ssti", "high")
		case strings.Contains(name, "cmd") || strings.Contains(name, "exec") || strings.Contains(name, "command"):
			e.memory.SetPriority("cmdi", "critical")
			e.memory.SetPriority("rce", "critical")
		case strings.Contains(name, "query") || strings.Contains(name, "search"):
			e.memory.SetPriority("sqli", "high")
			e.memory.SetPriority("xss", "high")
		}
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

	// Master Brain: boost with Thompson Sampling rankings
	if e.config.MasterBrainEnabled && e.banditCategory != nil {
		ranked := e.banditCategory.RankAll()
		for _, arm := range ranked {
			if arm.Pulls < 3 {
				continue // Not enough data
			}
			found := false
			for _, rec := range recommendations {
				if rec.Category == arm.Key {
					// Boost confidence with bandit posterior mean
					rec.Confidence = (rec.Confidence + arm.Mean) / 2.0
					found = true
					break
				}
			}
			if !found && arm.Mean > 0.3 {
				recommendations = append(recommendations, &PayloadRecommendation{
					Category:   arm.Key,
					Priority:   2,
					Reason:     fmt.Sprintf("Thompson Sampling: %.0f%% bypass rate (%d trials)", arm.Mean*100, arm.Pulls),
					Confidence: arm.Mean,
				})
			}
		}

		// Re-sort after modifications
		sort.Slice(recommendations, func(i, j int) bool {
			if recommendations[i].Priority != recommendations[j].Priority {
				return recommendations[i].Priority < recommendations[j].Priority
			}
			return recommendations[i].Confidence > recommendations[j].Confidence
		})
	}

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
		// Only consider testing-phase findings for resource allocation.
		// Recon findings have Blocked=false by default, which would give
		// categories like "endpoint" a 100% bypass rate and starve real
		// attack categories of resources.
		if !f.IsTestingPhase() {
			continue
		}
		categoryTotal[f.Category]++
		if !f.Blocked && f.StatusCode > 0 {
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
	e.stats.EndPhase(phase)
	e.correlatePhase(phase)

	// Master Brain: mark phase completed in Q-learning controller
	if e.config.MasterBrainEnabled && e.phaseCtrl != nil {
		e.phaseCtrl.MarkCompleted(phase)
	}

	// Reinforce influence graph edges for confirmed correlations
	if e.config.MasterBrainEnabled && e.influenceGraph != nil {
		bypasses := e.memory.GetBypasses()
		for _, b := range bypasses {
			if b.Phase == phase && b.Category != "" {
				e.influenceGraph.ReinforceEdge("phase:"+phase, "category:"+b.Category, 0.05)
			}
		}
	}

	e.mu.Unlock()

	// Recalculate attack paths at phase boundaries (not on every finding)
	if e.pathfinder != nil {
		e.pathfinder.RecalculateIfDirty()
	}
}

// recalibrate is called when the CUSUM detector detects a behavioral shift.
// It resets predictor baselines using recent observations.
func (e *Engine) recalibrate(metric string, magnitude float64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Decay bandit priors to partially forget old behavior
	if e.banditCategory != nil {
		e.banditCategory.Decay(0.8)
	}
	if e.banditEncoding != nil {
		e.banditEncoding.Decay(0.8)
	}
	if e.banditPattern != nil {
		e.banditPattern.Decay(0.8)
	}

	// Reset CUSUM baselines to recent values
	if e.calibrator != nil {
		state, ok := e.calibrator.GetMetricState(metric)
		if ok {
			e.calibrator.ResetMetric(metric, state.LastValue)
		}
	}

	_ = magnitude // Used for logging in verbose mode if needed
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

// ══════════════════════════════════════════════════════════════════════════════
// ADVANCED COGNITIVE FEATURES - High-level convenience methods
// ══════════════════════════════════════════════════════════════════════════════

// PredictPayloadSuccess predicts the probability of a payload bypassing the WAF
func (e *Engine) PredictPayloadSuccess(category, payload, path string) *Prediction {
	techStack := e.techProfile.GetDetected()
	return e.predictor.Predict(category, payload, path, techStack)
}

// GetTopPayloads returns the payloads most likely to bypass based on learning
func (e *Engine) GetTopPayloads(candidates []PayloadCandidate, n int) []RankedPayload {
	techStack := e.techProfile.GetDetected()
	return e.predictor.GetTopPredictions(candidates, techStack, n)
}

// SuggestMutations suggests mutations when a payload is blocked
func (e *Engine) SuggestMutations(category, blockedPayload string) []MutationSuggestion {
	wafVendor := e.wafModel.GetVendor()
	return e.mutator.SuggestMutations(category, blockedPayload, wafVendor)
}

// GetSmartEndpoints returns endpoints optimized for testing efficiency
func (e *Engine) GetSmartEndpoints(paths []string) []PrioritizedEndpoint {
	return e.clusterer.OptimizeTestOrder(paths)
}

// GetRepresentativeEndpoints returns cluster representatives for efficient testing
func (e *Engine) GetRepresentativeEndpoints() []string {
	return e.clusterer.GetRepresentatives()
}

// InferEndpointBehavior infers behavior for an untested endpoint from similar tested ones
func (e *Engine) InferEndpointBehavior(path string) *InferredBehavior {
	return e.clusterer.InferBehavior(path)
}

// GetAnomalyStatus returns the current anomaly detection status
func (e *Engine) GetAnomalyStatus() AnomalyStats {
	return e.anomaly.GetStats()
}

// ShouldPauseScan returns true if anomalies indicate we should pause
func (e *Engine) ShouldPauseScan() (bool, string) {
	return e.anomaly.ShouldPause()
}

// GetOptimalAttackPath returns the current optimal attack path through the target
func (e *Engine) GetOptimalAttackPath() *AttackPath {
	return e.pathfinder.GetOptimalPath()
}

// GetPriorityTargets returns endpoints prioritized by their attack path value
func (e *Engine) GetPriorityTargets() []EndpointPriority {
	return e.pathfinder.GetPriorityEndpoints()
}

// GetNextHighValueTarget returns the next high-value target to pursue
func (e *Engine) GetNextHighValueTarget() *AttackNode {
	return e.pathfinder.GetNextTarget()
}

// GetAttackGraph exports the attack graph for visualization (DOT format)
func (e *Engine) GetAttackGraph() string {
	return e.pathfinder.ExportGraph()
}

// GetCognitiveSummary returns a summary of all advanced cognitive module states
func (e *Engine) GetCognitiveSummary() *CognitiveSummary {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return &CognitiveSummary{
		Predictor:  e.predictor.GetStats(),
		Mutator:    e.mutator.GetStats(),
		Clusterer:  e.clusterer.GetStats(),
		Anomaly:    e.anomaly.GetStats(),
		Pathfinder: e.pathfinder.GetStats(),
	}
}

// CognitiveSummary contains all advanced module statistics
type CognitiveSummary struct {
	Predictor  PredictorStats
	Mutator    StrategistStats
	Clusterer  ClusteringStats
	Anomaly    AnomalyStats
	Pathfinder AttackPathStats
}
