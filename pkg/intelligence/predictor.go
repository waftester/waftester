// Package intelligence provides advanced cognitive capabilities for WAFtester
// This file implements the Predictive Engine - predicting bypass success before testing
package intelligence

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

// ══════════════════════════════════════════════════════════════════════════════
// PREDICTIVE ENGINE - Predict bypass success before testing
// Uses learned patterns to prioritize most promising payloads
// ══════════════════════════════════════════════════════════════════════════════

// Predictor predicts bypass probability for payloads.
type Predictor struct {
	mu sync.RWMutex

	// Configuration
	config *PredictorConfig

	// Learned patterns from observations
	categorySuccessRate map[string]float64 // Category → bypass rate
	encodingSuccessRate map[string]float64 // Encoding → bypass rate
	patternSuccessRate  map[string]float64 // Payload pattern → bypass rate
	endpointSuccessRate map[string]float64 // Endpoint pattern → bypass rate
	statusCodePatterns  map[int]float64    // Status code → indicates bypass
	latencyThresholds   map[string]float64 // Category → blocking latency threshold
	techVulnerabilities map[string]float64 // Tech → vulnerability likelihood

	// Feature correlations learned
	categoryTechCorr map[string]map[string]float64 // Category → Tech → correlation

	// Observation counts for confidence and UCB1 exploration
	categoryObservations map[string]int
	encodingObservations map[string]int
	patternObservations  map[string]int
	totalObservations    int // Global counter for UCB1 exploration bonus

	// Thompson Sampling bandits (optional, used when UseBandit=true)
	categoryBandit *BanditSelector
	encodingBandit *BanditSelector
	patternBandit  *BanditSelector
}

// NewPredictor creates a new Predictor with default configuration.
func NewPredictor() *Predictor {
	return NewPredictorWithConfig(DefaultPredictorConfig())
}

// NewPredictorWithConfig creates a new Predictor with custom configuration.
func NewPredictorWithConfig(cfg *PredictorConfig) *Predictor {
	if cfg == nil {
		cfg = DefaultPredictorConfig()
	}
	return &Predictor{
		config:               cfg,
		categorySuccessRate:  make(map[string]float64),
		encodingSuccessRate:  make(map[string]float64),
		patternSuccessRate:   make(map[string]float64),
		endpointSuccessRate:  make(map[string]float64),
		statusCodePatterns:   make(map[int]float64),
		latencyThresholds:    make(map[string]float64),
		techVulnerabilities:  make(map[string]float64),
		categoryTechCorr:     make(map[string]map[string]float64),
		categoryObservations: make(map[string]int),
		encodingObservations: make(map[string]int),
		patternObservations:  make(map[string]int),
	}
}

// Prediction represents a bypass probability prediction
type Prediction struct {
	Probability float64 // 0.0-1.0 bypass probability
	Confidence  float64 // 0.0-1.0 confidence in prediction
	Factors     []PredictionFactor
	Ranking     int // Suggested test order (lower = test first)
}

// PredictionFactor explains why a prediction was made
type PredictionFactor struct {
	Factor      string  // What factor influenced prediction
	Weight      float64 // How much it contributed (0.0-1.0)
	Observation string  // What we observed
}

// Learn updates the predictor with a new observation.
// Safe to call with nil finding (no-op).
func (p *Predictor) Learn(finding *Finding) {
	if finding == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.totalObservations++

	success := 0.0
	if !finding.Blocked {
		success = 1.0
	}

	// Learn category success rate (exponential moving average)
	p.updateRate(p.categorySuccessRate, p.categoryObservations, finding.Category, success, 0.1)

	// Learn encoding success rate
	if encoding := p.extractEncoding(finding.Payload); encoding != "" {
		p.updateRate(p.encodingSuccessRate, p.encodingObservations, encoding, success, 0.1)
	}

	// Learn payload pattern success rate
	if pattern := p.extractPattern(finding.Payload); pattern != "" {
		p.updateRate(p.patternSuccessRate, p.patternObservations, pattern, success, 0.1)
	}

	// Learn endpoint pattern success rate
	if endpointPattern := p.extractEndpointPattern(finding.Path); endpointPattern != "" {
		p.updateRate(p.endpointSuccessRate, nil, endpointPattern, success, 0.1)
	}

	// Learn status code patterns
	if finding.StatusCode > 0 {
		if current, ok := p.statusCodePatterns[finding.StatusCode]; ok {
			p.statusCodePatterns[finding.StatusCode] = current*0.9 + success*0.1
		} else {
			p.statusCodePatterns[finding.StatusCode] = success
		}
	}

	// Learn latency patterns (blocked requests often have different latency)
	if finding.Blocked && finding.Latency > 0 {
		key := finding.Category
		if current, ok := p.latencyThresholds[key]; ok {
			p.latencyThresholds[key] = current*0.8 + float64(finding.Latency.Milliseconds())*0.2
		} else {
			p.latencyThresholds[key] = float64(finding.Latency.Milliseconds())
		}
	}
}

// updateRate updates a rate using exponential moving average
func (p *Predictor) updateRate(rates map[string]float64, counts map[string]int, key string, value float64, alpha float64) {
	if key == "" {
		return
	}

	if counts != nil {
		counts[key]++
	}

	if current, ok := rates[key]; ok {
		rates[key] = current*(1-alpha) + value*alpha
	} else {
		rates[key] = value
	}
}

// Predict returns bypass probability for a potential test
func (p *Predictor) Predict(category, payload, path string, techStack []string) *Prediction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.predictLocked(category, payload, path, techStack)
}

// predictLocked performs prediction without acquiring the lock.
// Caller must hold p.mu.RLock() or p.mu.Lock().
func (p *Predictor) predictLocked(category, payload, path string, techStack []string) *Prediction {
	pred := &Prediction{
		Factors: make([]PredictionFactor, 0),
	}

	totalWeight := 0.0
	weightedSum := 0.0

	// Factor 1: Category historical success rate (use config weight)
	if rate, ok := p.categorySuccessRate[category]; ok {
		weight := p.config.CategoryWeight
		confidence := p.getConfidence(p.categoryObservations[category])
		weightedSum += rate * weight * confidence
		totalWeight += weight * confidence
		pred.Factors = append(pred.Factors, PredictionFactor{
			Factor:      "category_history",
			Weight:      weight * confidence,
			Observation: category + " has " + formatPct(rate) + " bypass rate",
		})
	}

	// Factor 2: Encoding success rate (use config weight)
	if encoding := p.extractEncoding(payload); encoding != "" {
		if rate, ok := p.encodingSuccessRate[encoding]; ok {
			weight := p.config.EncodingWeight
			confidence := p.getConfidence(p.encodingObservations[encoding])
			weightedSum += rate * weight * confidence
			totalWeight += weight * confidence
			pred.Factors = append(pred.Factors, PredictionFactor{
				Factor:      "encoding_history",
				Weight:      weight * confidence,
				Observation: encoding + " encoding has " + formatPct(rate) + " bypass rate",
			})
		}
	}

	// Factor 3: Payload pattern success rate (use config weight)
	if pattern := p.extractPattern(payload); pattern != "" {
		if rate, ok := p.patternSuccessRate[pattern]; ok {
			weight := p.config.PayloadWeight
			confidence := p.getConfidence(p.patternObservations[pattern])
			weightedSum += rate * weight * confidence
			totalWeight += weight * confidence
			pred.Factors = append(pred.Factors, PredictionFactor{
				Factor:      "pattern_history",
				Weight:      weight * confidence,
				Observation: "Pattern '" + pattern + "' has " + formatPct(rate) + " success",
			})
		}
	}

	// Factor 4: Endpoint pattern success (use config weight)
	if endpointPattern := p.extractEndpointPattern(path); endpointPattern != "" {
		if rate, ok := p.endpointSuccessRate[endpointPattern]; ok {
			weight := p.config.EndpointWeight
			weightedSum += rate * weight
			totalWeight += weight
			pred.Factors = append(pred.Factors, PredictionFactor{
				Factor:      "endpoint_pattern",
				Weight:      weight,
				Observation: "Endpoint pattern '" + endpointPattern + "' has " + formatPct(rate) + " success",
			})
		}
	}

	// Factor 5: Technology vulnerabilities (use config weight)
	for _, tech := range techStack {
		techLower := strings.ToLower(tech)
		if vuln, ok := p.techVulnerabilities[techLower]; ok {
			weight := p.config.TechStackWeight / float64(len(techStack))
			weightedSum += vuln * weight
			totalWeight += weight
			pred.Factors = append(pred.Factors, PredictionFactor{
				Factor:      "tech_vulnerability",
				Weight:      weight,
				Observation: tech + " has known " + category + " vulnerabilities",
			})
		}
	}

	// Calculate final probability
	if totalWeight > 0 {
		pred.Probability = weightedSum / totalWeight
	} else {
		pred.Probability = 0.5 // No data, assume 50%
	}

	// Calculate confidence based on total observations
	totalObs := 0
	for _, count := range p.categoryObservations {
		totalObs += count
	}
	pred.Confidence = p.getConfidence(totalObs / 10) // Scale down

	return pred
}

// SetBandits injects Thompson Sampling bandits for exploration.
// Called by Engine initialization when MasterBrainEnabled.
func (p *Predictor) SetBandits(category, encoding, pattern *BanditSelector) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.categoryBandit = category
	p.encodingBandit = encoding
	p.patternBandit = pattern
}

// PredictBatch predicts and ranks multiple payloads
func (p *Predictor) PredictBatch(payloads []PayloadCandidate, techStack []string) []RankedPayload {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ranked := make([]RankedPayload, len(payloads))

	for i, payload := range payloads {
		pred := p.predictLocked(payload.Category, payload.Payload, payload.Path, techStack)

		// Exploration bonus: Thompson Sampling if bandits available, else UCB1
		explorationBonus := 0.0
		if p.config.UseBandit && p.categoryBandit != nil {
			// Thompson Sampling: sample from Beta posterior for this category
			explorationBonus = p.categoryBandit.SampleArm(payload.Category)
		} else if p.totalObservations > 0 && p.config.ExplorationWeight > 0 {
			// UCB1 exploration bonus: boost under-tested categories
			// sqrt(2 * ln(totalObs) / categoryObs)
			catObs := p.categoryObservations[payload.Category]
			if catObs == 0 {
				explorationBonus = 1.0
			} else {
				explorationBonus = math.Sqrt(2.0 * math.Log(float64(p.totalObservations)) / float64(catObs))
				if explorationBonus > 1.0 {
					explorationBonus = 1.0
				}
			}
		}

		exploitScore := pred.Probability * pred.Confidence
		exploreScore := explorationBonus * p.config.ExplorationWeight
		ranked[i] = RankedPayload{
			Candidate:  payload,
			Prediction: pred,
			Score:      exploitScore + exploreScore,
		}
	}

	// Sort by score descending (highest probability first)
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].Score > ranked[j].Score
	})

	// Assign rankings
	for i := range ranked {
		ranked[i].Prediction.Ranking = i + 1
	}

	return ranked
}

// PayloadCandidate represents a potential payload to test
type PayloadCandidate struct {
	Category string
	Payload  string
	Path     string
	Encoding string
}

// RankedPayload is a payload with its prediction and ranking
type RankedPayload struct {
	Candidate  PayloadCandidate
	Prediction *Prediction
	Score      float64
}

// GetTopPredictions returns the N payloads most likely to bypass
func (p *Predictor) GetTopPredictions(payloads []PayloadCandidate, techStack []string, n int) []RankedPayload {
	ranked := p.PredictBatch(payloads, techStack)
	if len(ranked) > n {
		return ranked[:n]
	}
	return ranked
}

// extractEncoding identifies encoding type from payload
func (p *Predictor) extractEncoding(payload string) string {
	switch {
	case strings.Contains(payload, "%"):
		if strings.Contains(payload, "%25") {
			return "double-url"
		}
		return "url"
	case strings.Contains(payload, "&#"):
		return "html-entity"
	case strings.Contains(payload, "\\x"):
		return "hex"
	case strings.Contains(payload, "\\u"):
		return "unicode"
	case isBase64Like(payload):
		return "base64"
	default:
		return "plain"
	}
}

// extractPattern extracts attack pattern signature from payload
func (p *Predictor) extractPattern(payload string) string {
	lower := strings.ToLower(payload)

	// SQL injection patterns
	if strings.Contains(lower, "' or ") || strings.Contains(lower, "' and ") {
		return "sqli-or-and"
	}
	if strings.Contains(lower, "union") && strings.Contains(lower, "select") {
		return "sqli-union"
	}
	if strings.Contains(lower, "--") || strings.Contains(lower, "#") {
		return "sqli-comment"
	}

	// XSS patterns
	if strings.Contains(lower, "<script") {
		return "xss-script"
	}
	if strings.Contains(lower, "onerror") || strings.Contains(lower, "onload") {
		return "xss-event"
	}
	if strings.Contains(lower, "javascript:") {
		return "xss-protocol"
	}

	// Command injection patterns
	if strings.Contains(payload, "$(") || strings.Contains(payload, "`") {
		return "cmdi-subshell"
	}
	if strings.Contains(payload, ";") || strings.Contains(payload, "|") || strings.Contains(payload, "&") {
		return "cmdi-chain"
	}

	// Path traversal
	if strings.Contains(payload, "../") || strings.Contains(payload, "..\\") {
		return "traversal"
	}

	// SSRF
	if strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "localhost") {
		return "ssrf-localhost"
	}
	if strings.Contains(lower, "169.254") || strings.Contains(lower, "metadata") {
		return "ssrf-cloud"
	}

	// SSTI patterns
	if strings.Contains(payload, "{{") || strings.Contains(payload, "${") || strings.Contains(payload, "#{") {
		return "ssti-template"
	}
	if strings.Contains(lower, "jinja") || strings.Contains(lower, "twig") || strings.Contains(lower, "freemarker") {
		return "ssti-engine"
	}

	// NoSQL injection
	if strings.Contains(payload, "$gt") || strings.Contains(payload, "$ne") ||
		strings.Contains(payload, "$where") || strings.Contains(payload, "$regex") {
		return "nosqli-operator"
	}
	if strings.Contains(payload, "{'") || strings.Contains(payload, "{\"") {
		return "nosqli-json"
	}

	// PHP deserialization — match format markers, not bare prefixes
	if strings.Contains(payload, "O:4:") || strings.Contains(payload, "O:1:") ||
		strings.Contains(payload, "a:2:{") || strings.Contains(payload, "a:1:{") ||
		strings.Contains(payload, "s:4:") {
		return "deser-php"
	}
	if strings.Contains(lower, "java.lang") || strings.Contains(lower, "rO0") {
		return "deser-java"
	}

	// Prototype pollution
	if strings.Contains(payload, "__proto__") || strings.Contains(payload, "constructor") {
		return "proto-pollution"
	}

	// LDAP injection
	if strings.Contains(payload, "(cn=") || strings.Contains(payload, "(uid=") ||
		strings.Contains(payload, ")(|") || strings.Contains(payload, ")(cn=") {
		return "ldap-injection"
	}

	// XXE
	if strings.Contains(lower, "<!entity") || strings.Contains(lower, "<!doctype") {
		return "xxe"
	}

	return ""
}

// extractEndpointPattern extracts pattern from endpoint path
func (p *Predictor) extractEndpointPattern(path string) string {
	lower := strings.ToLower(path)

	switch {
	case strings.Contains(lower, "/api/"):
		return "api"
	case strings.Contains(lower, "/admin"):
		return "admin"
	case strings.Contains(lower, "/login") || strings.Contains(lower, "/auth"):
		return "auth"
	case strings.Contains(lower, "/search"):
		return "search"
	case strings.Contains(lower, "/upload"):
		return "upload"
	case strings.Contains(lower, "/download"):
		return "download"
	case strings.Contains(lower, "/graphql"):
		return "graphql"
	case strings.Contains(lower, ".php"):
		return "php"
	case strings.Contains(lower, ".asp"):
		return "asp"
	case strings.Contains(lower, ".jsp"):
		return "jsp"
	default:
		return ""
	}
}

// getConfidence returns confidence based on observation count
func (p *Predictor) getConfidence(observations int) float64 {
	if observations == 0 {
		return 0.0
	}
	// Logarithmic confidence curve: approaches 1.0 slowly with more observations.
	// 10 obs ≈ 0.50, 100 obs ≈ 0.67, 1000 obs ≈ 0.83, 10000 obs ≈ 1.0
	return math.Min(1.0, math.Log10(float64(observations)+1)/4)
}

// isBase64Like checks if string looks like base64
func isBase64Like(s string) bool {
	if len(s) < 4 || len(s)%4 != 0 {
		return false
	}
	base64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, c := range s {
		if !strings.ContainsRune(base64Chars, c) {
			return false
		}
	}
	return true
}

// formatPct formats a float as percentage string (e.g., 0.75 → "75%")
func formatPct(f float64) string {
	pct := f * 100
	if pct == float64(int(pct)) {
		return fmt.Sprintf("%.0f%%", pct)
	}
	return fmt.Sprintf("%.1f%%", pct)
}

// GetStats returns predictor statistics
func (p *Predictor) GetStats() PredictorStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := PredictorStats{
		TotalObservations: 0,
		CategoryPatterns:  len(p.categorySuccessRate),
		EncodingPatterns:  len(p.encodingSuccessRate),
		PayloadPatterns:   len(p.patternSuccessRate),
		TopCategories:     make([]CategorySuccess, 0),
		TopEncodings:      make([]EncodingSuccess, 0),
	}

	for _, count := range p.categoryObservations {
		stats.TotalObservations += count
	}

	// Top categories by success rate
	for cat, rate := range p.categorySuccessRate {
		stats.TopCategories = append(stats.TopCategories, CategorySuccess{
			Category:     cat,
			SuccessRate:  rate,
			Observations: p.categoryObservations[cat],
		})
	}
	sort.Slice(stats.TopCategories, func(i, j int) bool {
		return stats.TopCategories[i].SuccessRate > stats.TopCategories[j].SuccessRate
	})
	if len(stats.TopCategories) > 5 {
		stats.TopCategories = stats.TopCategories[:5]
	}

	// Top encodings by success rate
	for enc, rate := range p.encodingSuccessRate {
		stats.TopEncodings = append(stats.TopEncodings, EncodingSuccess{
			Encoding:     enc,
			SuccessRate:  rate,
			Observations: p.encodingObservations[enc],
		})
	}
	sort.Slice(stats.TopEncodings, func(i, j int) bool {
		return stats.TopEncodings[i].SuccessRate > stats.TopEncodings[j].SuccessRate
	})
	if len(stats.TopEncodings) > 5 {
		stats.TopEncodings = stats.TopEncodings[:5]
	}

	return stats
}

// PredictorStats contains predictor statistics
type PredictorStats struct {
	TotalObservations int
	CategoryPatterns  int
	EncodingPatterns  int
	PayloadPatterns   int
	TopCategories     []CategorySuccess
	TopEncodings      []EncodingSuccess
}

// CategorySuccess tracks category bypass success
type CategorySuccess struct {
	Category     string
	SuccessRate  float64
	Observations int
}

// EncodingSuccess tracks encoding bypass success
type EncodingSuccess struct {
	Encoding     string
	SuccessRate  float64
	Observations int
}
