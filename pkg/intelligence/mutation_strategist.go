// Package intelligence provides adaptive learning capabilities for WAFtester.
// MutationStrategist suggests bypass mutations based on learned patterns from WAF responses.
package intelligence

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Mutation strategist constants.
const (
	// MaxMutationSuggestions is the maximum number of mutation suggestions to return.
	MaxMutationSuggestions = 10

	// DefaultEncodingEffectiveness is the initial effectiveness for new encodings.
	DefaultEncodingEffectiveness = 0.7

	// EncodingEMAAlpha is the EMA alpha for updating encoding effectiveness.
	EncodingEMAAlpha = 0.1

	// MaxMutationRecordsPerCategory caps mutation records per category to prevent unbounded growth.
	MaxMutationRecordsPerCategory = 100

	// MaxBlockPatternMutations caps the number of unique block pattern signatures tracked.
	MaxBlockPatternMutations = 500
)

// ══════════════════════════════════════════════════════════════════════════════
// MUTATION STRATEGIST - Suggest specific mutations when blocked
// Learns which mutations bypass specific WAF patterns
// ══════════════════════════════════════════════════════════════════════════════

// MutationStrategist suggests bypass mutations based on learned patterns
type MutationStrategist struct {
	mu sync.RWMutex

	// Configuration
	config *MutatorConfig

	// Learning: what mutations worked for which block patterns
	blockPatternMutations map[string][]MutationRecord // block signature → successful mutations
	categoryMutations     map[string][]MutationRecord // category → successful mutations
	encodingEffectiveness map[string]float64          // encoding → bypass rate

	// WAF-specific knowledge
	wafMutationMap map[string][]string // waf vendor → recommended mutations

	// Observation tracking
	observations int

	// Master Brain: GA-based mutation generator (optional)
	generator *MutationGenerator
}

// MutationRecord tracks a successful mutation
type MutationRecord struct {
	Original     string  // Original blocked payload
	Mutated      string  // Successful mutated payload
	MutationType string  // Type of mutation applied
	SuccessRate  float64 // How often this mutation works
	Uses         int     // Number of times used
	Successes    int     // Number of times it bypassed
}

// MutationSuggestion is a recommended mutation
type MutationSuggestion struct {
	Type        string  // Mutation type to apply
	Description string  // Human-readable description
	Example     string  // Example of the mutation
	Confidence  float64 // Confidence this will work
	Reasoning   string  // Why this is suggested
}

// NewMutationStrategist creates a new MutationStrategist with default configuration.
func NewMutationStrategist() *MutationStrategist {
	return NewMutationStrategistWithConfig(nil)
}

// NewMutationStrategistWithConfig creates a new MutationStrategist with custom configuration.
func NewMutationStrategistWithConfig(cfg *MutatorConfig) *MutationStrategist {
	if cfg == nil {
		cfg = DefaultMutatorConfig()
	}
	ms := &MutationStrategist{
		config:                cfg,
		blockPatternMutations: make(map[string][]MutationRecord),
		categoryMutations:     make(map[string][]MutationRecord),
		encodingEffectiveness: make(map[string]float64),
		wafMutationMap:        make(map[string][]string),
	}

	// Initialize WAF-specific mutation recommendations
	ms.initWAFKnowledge()

	return ms
}

// initWAFKnowledge initializes built-in WAF bypass knowledge
func (ms *MutationStrategist) initWAFKnowledge() {
	// Cloudflare
	ms.wafMutationMap["cloudflare"] = []string{
		"unicode-normalization",
		"double-url-encode",
		"case-variation",
		"null-byte-injection",
		"multipart-boundary",
	}

	// AWS WAF
	ms.wafMutationMap["aws-waf"] = []string{
		"chunked-encoding",
		"parameter-pollution",
		"unicode-escape",
		"comment-injection",
		"whitespace-variation",
	}

	// Akamai
	ms.wafMutationMap["akamai"] = []string{
		"ip-obfuscation",
		"header-injection",
		"protocol-smuggling",
		"encoding-chain",
		"payload-fragmentation",
	}

	// ModSecurity
	ms.wafMutationMap["modsecurity"] = []string{
		"case-variation",
		"comment-injection",
		"whitespace-substitution",
		"null-byte-injection",
		"character-escaping",
	}

	// Imperva/Incapsula
	ms.wafMutationMap["imperva"] = []string{
		"json-unicode",
		"content-type-spoofing",
		"boundary-manipulation",
		"encoding-bypass",
		"request-fragmentation",
	}

	// F5 BIG-IP
	ms.wafMutationMap["f5"] = []string{
		"http-desync",
		"header-smuggling",
		"path-traversal-encoding",
		"multipart-abuse",
		"chunked-te",
	}

	// Generic/Unknown
	ms.wafMutationMap["generic"] = []string{
		"double-url-encode",
		"unicode-normalization",
		"case-variation",
		"comment-injection",
		"whitespace-variation",
	}
}

// SetMutationGenerator attaches a GA-based mutation generator.
// When set, SuggestMutations merges GA-evolved suggestions with heuristic ones.
func (ms *MutationStrategist) SetMutationGenerator(gen *MutationGenerator) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.generator = gen
}

// LearnBlock records a blocked attempt for future mutation suggestions
func (ms *MutationStrategist) LearnBlock(category, payload string, statusCode int) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.observations++

	// Extract block signature for pattern matching
	signature := ms.extractBlockSignature(category, payload, statusCode)

	// Initialize if needed, but cap total signatures to prevent unbounded growth
	if _, ok := ms.blockPatternMutations[signature]; !ok {
		// Only add new signature if under cap
		if len(ms.blockPatternMutations) >= MaxBlockPatternMutations {
			// Evict a random entry (simple LRU-ish behavior)
			for k := range ms.blockPatternMutations {
				delete(ms.blockPatternMutations, k)
				break
			}
		}
		ms.blockPatternMutations[signature] = make([]MutationRecord, 0)
	}

	// Feed GA generator with block outcome
	if ms.generator != nil {
		ms.generator.RecordOutcome(0, TrialResult{Bypassed: false})
	}
}

// LearnBypass records a successful bypass to improve future suggestions
func (ms *MutationStrategist) LearnBypass(category, originalPayload, bypassPayload string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	mutationType := ms.detectMutationType(originalPayload, bypassPayload)
	if mutationType == "" {
		mutationType = "unknown"
	}

	// Update category mutations
	record := MutationRecord{
		Original:     originalPayload,
		Mutated:      bypassPayload,
		MutationType: mutationType,
		SuccessRate:  1.0,
		Uses:         1,
		Successes:    1,
	}

	ms.categoryMutations[category] = append(ms.categoryMutations[category], record)

	// Cap mutations per category to prevent unbounded growth
	if len(ms.categoryMutations[category]) > MaxMutationRecordsPerCategory {
		ms.categoryMutations[category] = ms.categoryMutations[category][len(ms.categoryMutations[category])-MaxMutationRecordsPerCategory:]
	}

	// Update encoding effectiveness using exponential moving average
	encoding := ms.detectEncoding(bypassPayload)
	if encoding != "" {
		if current, ok := ms.encodingEffectiveness[encoding]; ok {
			ms.encodingEffectiveness[encoding] = current*(1-EncodingEMAAlpha) + EncodingEMAAlpha
		} else {
			ms.encodingEffectiveness[encoding] = DefaultEncodingEffectiveness
		}
	}

	// Feed GA generator with bypass outcome
	if ms.generator != nil {
		ms.generator.RecordOutcome(0, TrialResult{Bypassed: true})
	}
}

// SuggestMutations suggests mutations for a blocked payload
func (ms *MutationStrategist) SuggestMutations(category, payload string, wafVendor string) []MutationSuggestion {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	suggestions := make([]MutationSuggestion, 0)

	// 1. WAF-specific suggestions (highest priority)
	wafKey := strings.ToLower(wafVendor)
	if wafKey == "" {
		wafKey = "generic"
	}

	if wafMutations, ok := ms.wafMutationMap[wafKey]; ok {
		for i, mutType := range wafMutations {
			suggestions = append(suggestions, MutationSuggestion{
				Type:        mutType,
				Description: getMutationDescription(mutType),
				Example:     ms.getMutationExample(mutType, payload),
				Confidence:  0.8 - float64(i)*0.1, // Decreasing confidence
				Reasoning:   "Known effective against " + wafVendor,
			})
		}
	}

	// 2. Learned category-specific mutations
	if records, ok := ms.categoryMutations[category]; ok {
		for _, record := range records {
			if record.SuccessRate > 0.5 {
				suggestions = append(suggestions, MutationSuggestion{
					Type:        record.MutationType,
					Description: getMutationDescription(record.MutationType),
					Example:     record.Mutated,
					Confidence:  record.SuccessRate,
					Reasoning:   "Learned from " + category + " bypasses",
				})
			}
		}
	}

	// 3. Encoding-based suggestions
	for encoding, effectiveness := range ms.encodingEffectiveness {
		if effectiveness > 0.5 {
			suggestions = append(suggestions, MutationSuggestion{
				Type:        encoding + "-encode",
				Description: "Apply " + encoding + " encoding",
				Example:     ms.applyEncoding(encoding, payload),
				Confidence:  effectiveness,
				Reasoning:   encoding + " encoding has " + formatPct(effectiveness) + " success rate",
			})
		}
	}

	// 4. GA-evolved mutation suggestions (Master Brain)
	if ms.generator != nil {
		gaChromosomes := ms.generator.SuggestMutations(5)
		for _, chrom := range gaChromosomes {
			if chrom.Fitness < 0.1 {
				continue // Skip low-fitness chromosomes
			}
			geneDesc := make([]string, 0, len(chrom.Genes))
			for _, g := range chrom.Genes {
				geneDesc = append(geneDesc, g.Transform)
			}
			suggestions = append(suggestions, MutationSuggestion{
				Type:        "ga-evolved",
				Description: "GA-evolved transform chain: " + strings.Join(geneDesc, " → "),
				Confidence:  chrom.Fitness,
				Reasoning:   fmt.Sprintf("Evolved through %d generations with %.0f%% bypass fitness", chrom.Age, chrom.Fitness*100),
			})
		}
	}

	// 5. Generic fallback suggestions
	genericSuggestions := []MutationSuggestion{
		{
			Type:        "case-variation",
			Description: "Vary character case to bypass signature matching",
			Example:     ms.applyCaseVariation(payload),
			Confidence:  0.4,
			Reasoning:   "Basic evasion technique",
		},
		{
			Type:        "whitespace-injection",
			Description: "Inject whitespace to break pattern matching",
			Example:     ms.applyWhitespace(payload),
			Confidence:  0.35,
			Reasoning:   "Breaks contiguous pattern matching",
		},
		{
			Type:        "comment-injection",
			Description: "Inject comments to split keywords",
			Example:     ms.applyComments(payload, category),
			Confidence:  0.4,
			Reasoning:   "Splits signature-matched keywords",
		},
	}

	// Add generic suggestions if we don't have enough
	if len(suggestions) < 5 {
		suggestions = append(suggestions, genericSuggestions...)
	}

	// Sort by confidence
	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Confidence > suggestions[j].Confidence
	})

	// Deduplicate by type
	seen := make(map[string]bool)
	unique := make([]MutationSuggestion, 0)
	for _, s := range suggestions {
		if !seen[s.Type] {
			seen[s.Type] = true
			unique = append(unique, s)
		}
	}

	if len(unique) > 10 {
		return unique[:10]
	}
	return unique
}

// extractBlockSignature creates a signature for a block pattern
func (ms *MutationStrategist) extractBlockSignature(category, payload string, statusCode int) string {
	// Normalize payload to create reusable signature
	normalized := strings.ToLower(payload)
	if len([]rune(normalized)) > 50 {
		normalized = string([]rune(normalized)[:50])
	}
	return category + ":" + normalized + ":" + fmt.Sprintf("%d", statusCode)
}

// detectMutationType identifies what mutation was applied
func (ms *MutationStrategist) detectMutationType(original, mutated string) string {
	if original == mutated {
		return ""
	}

	// Check for encoding changes
	if strings.Count(mutated, "%") > strings.Count(original, "%") {
		return "url-encode"
	}
	if strings.Contains(mutated, "\\u") && !strings.Contains(original, "\\u") {
		return "unicode-escape"
	}
	if strings.Contains(mutated, "\\x") && !strings.Contains(original, "\\x") {
		return "hex-encode"
	}

	// Check for case variation
	if strings.EqualFold(original, mutated) && original != mutated {
		return "case-variation"
	}

	// Check for comment injection
	if strings.Contains(mutated, "/*") || strings.Contains(mutated, "<!--") {
		return "comment-injection"
	}

	// Check for whitespace
	if strings.Contains(mutated, "\t") || strings.Contains(mutated, "\n") {
		return "whitespace-injection"
	}

	return "unknown"
}

// detectEncoding identifies the encoding used in a payload
func (ms *MutationStrategist) detectEncoding(payload string) string {
	switch {
	case strings.Contains(payload, "%25"):
		return "double-url"
	case strings.Contains(payload, "%"):
		return "url"
	case strings.Contains(payload, "\\u"):
		return "unicode"
	case strings.Contains(payload, "\\x"):
		return "hex"
	case strings.Contains(payload, "&#"):
		return "html-entity"
	default:
		return ""
	}
}

// getMutationDescription returns a human-readable description
func getMutationDescription(mutType string) string {
	descriptions := map[string]string{
		"unicode-normalization":   "Apply Unicode normalization forms to bypass signature matching",
		"double-url-encode":       "Double URL encode special characters to bypass single-decode filters",
		"case-variation":          "Mix upper/lower case to bypass case-sensitive signatures",
		"null-byte-injection":     "Inject null bytes to terminate string matching early",
		"multipart-boundary":      "Abuse multipart form boundaries to hide payloads",
		"chunked-encoding":        "Use chunked transfer encoding to fragment payloads",
		"parameter-pollution":     "Duplicate parameters to bypass single-value inspection",
		"unicode-escape":          "Use Unicode escape sequences instead of literal characters",
		"comment-injection":       "Inject language-specific comments to split keywords",
		"whitespace-variation":    "Use alternative whitespace characters",
		"ip-obfuscation":          "Obfuscate IP addresses using alternative formats",
		"header-injection":        "Inject payloads via HTTP headers",
		"protocol-smuggling":      "Exploit protocol parsing differences",
		"encoding-chain":          "Chain multiple encodings together",
		"payload-fragmentation":   "Fragment payload across multiple parameters",
		"json-unicode":            "Use JSON Unicode escapes for obfuscation",
		"content-type-spoofing":   "Manipulate Content-Type to bypass inspection",
		"boundary-manipulation":   "Manipulate multipart boundaries",
		"encoding-bypass":         "Use alternative encodings like UTF-7",
		"request-fragmentation":   "Fragment request across TCP packets",
		"http-desync":             "Exploit HTTP parsing discrepancies",
		"header-smuggling":        "Smuggle payloads via header manipulation",
		"path-traversal-encoding": "Encode path traversal sequences",
		"multipart-abuse":         "Abuse multipart form handling",
		"chunked-te":              "Exploit chunked transfer encoding parsing",
		"whitespace-injection":    "Inject whitespace to break patterns",
		"url-encode":              "Apply URL encoding to payload",
		"hex-encode":              "Apply hex encoding to payload",
	}

	if desc, ok := descriptions[mutType]; ok {
		return desc
	}
	return "Apply " + mutType + " transformation"
}

// getMutationExample generates an example of the mutation
func (ms *MutationStrategist) getMutationExample(mutType string, payload string) string {
	switch mutType {
	case "double-url-encode":
		return strings.ReplaceAll(strings.ReplaceAll(payload, "'", "%2527"), "\"", "%2522")
	case "case-variation":
		return ms.applyCaseVariation(payload)
	case "unicode-escape":
		return strings.ReplaceAll(strings.ReplaceAll(payload, "'", "\\u0027"), "<", "\\u003c")
	case "comment-injection":
		return ms.applyComments(payload, "sqli")
	case "whitespace-variation":
		return ms.applyWhitespace(payload)
	default:
		return payload + " (apply " + mutType + ")"
	}
}

// applyEncoding applies specified encoding to payload
func (ms *MutationStrategist) applyEncoding(encoding, payload string) string {
	switch encoding {
	case "url":
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
			payload, "'", "%27"), "\"", "%22"), "<", "%3C")
	case "double-url":
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
			payload, "'", "%2527"), "\"", "%2522"), "<", "%253C")
	case "unicode":
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
			payload, "'", "\\u0027"), "\"", "\\u0022"), "<", "\\u003c")
	case "hex":
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
			payload, "'", "\\x27"), "\"", "\\x22"), "<", "\\x3c")
	case "html-entity":
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
			payload, "'", "&#39;"), "\"", "&#34;"), "<", "&#60;")
	default:
		return payload
	}
}

// applyCaseVariation applies random case variation
func (ms *MutationStrategist) applyCaseVariation(payload string) string {
	result := make([]byte, len(payload))
	for i, c := range []byte(payload) {
		if i%2 == 0 && c >= 'a' && c <= 'z' {
			result[i] = c - 32 // to upper
		} else if i%2 == 1 && c >= 'A' && c <= 'Z' {
			result[i] = c + 32 // to lower
		} else {
			result[i] = c
		}
	}
	return string(result)
}

// applyWhitespace injects alternative whitespace
func (ms *MutationStrategist) applyWhitespace(payload string) string {
	// Inject tabs and newlines at spaces
	return strings.ReplaceAll(strings.ReplaceAll(payload, " ", "\t"), "  ", "\n")
}

// applyComments injects language-specific comments
func (ms *MutationStrategist) applyComments(payload, category string) string {
	switch category {
	case "sqli":
		// SQL comment injection
		return strings.ReplaceAll(strings.ReplaceAll(payload, "SELECT", "SEL/**/ECT"), "UNION", "UNI/**/ON")
	case "xss":
		// HTML comment injection
		return strings.ReplaceAll(payload, "script", "scr<!---->ipt")
	default:
		return payload
	}
}

// GetStats returns strategist statistics
func (ms *MutationStrategist) GetStats() StrategistStats {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	stats := StrategistStats{
		TotalObservations:     ms.observations,
		BlockPatterns:         len(ms.blockPatternMutations),
		LearnedMutations:      0,
		TopMutations:          make([]string, 0),
		EncodingEffectiveness: make(map[string]float64),
	}

	for _, records := range ms.categoryMutations {
		stats.LearnedMutations += len(records)
	}

	for enc, eff := range ms.encodingEffectiveness {
		stats.EncodingEffectiveness[enc] = eff
	}

	return stats
}

// StrategistStats contains strategist statistics
type StrategistStats struct {
	TotalObservations     int
	BlockPatterns         int
	LearnedMutations      int
	TopMutations          []string
	EncodingEffectiveness map[string]float64
}
