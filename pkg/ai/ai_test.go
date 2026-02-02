package ai

import (
	"context"
	"testing"
	"time"
)

func TestProviders(t *testing.T) {
	if ProviderOpenAI != "openai" {
		t.Error("unexpected OpenAI provider value")
	}
	if ProviderAnthropic != "anthropic" {
		t.Error("unexpected Anthropic provider value")
	}
	if ProviderLocal != "local" {
		t.Error("unexpected Local provider value")
	}
	if ProviderOllama != "ollama" {
		t.Error("unexpected Ollama provider value")
	}
}

func TestPayloadTypes(t *testing.T) {
	types := []PayloadType{
		PayloadSQLi, PayloadXSS, PayloadLFI, PayloadRCE,
		PayloadSSRF, PayloadXXE, PayloadSSTI, PayloadNoSQLi,
		PayloadLDAPi, PayloadBypass,
	}
	for _, pt := range types {
		if pt == "" {
			t.Error("payload type should not be empty")
		}
	}
}

func TestNewGenerator(t *testing.T) {
	g := NewGenerator()
	if g == nil {
		t.Fatal("expected non-nil generator")
	}
	if g.cache == nil {
		t.Error("expected non-nil cache")
	}
	if g.rateLimit == nil {
		t.Error("expected non-nil rate limiter")
	}
}

func TestGenerator_RegisterClient(t *testing.T) {
	g := NewGenerator()
	client := NewLocalClient()

	g.RegisterClient(client)

	got, ok := g.GetClient(ProviderLocal)
	if !ok {
		t.Fatal("expected to find local client")
	}
	if got.Provider() != ProviderLocal {
		t.Errorf("expected local, got %s", got.Provider())
	}
}

func TestGenerator_Generate(t *testing.T) {
	g := NewGenerator()
	g.RegisterClient(NewLocalClient())

	ctx := context.Background()
	req := &PayloadRequest{
		Type:         PayloadSQLi,
		Count:        5,
		EvasionLevel: 2,
	}

	payloads, err := g.Generate(ctx, ProviderLocal, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("expected payloads")
	}

	for _, p := range payloads {
		if p.Payload == "" {
			t.Error("expected non-empty payload")
		}
		if p.Type != PayloadSQLi {
			t.Errorf("expected sqli type, got %s", p.Type)
		}
	}
}

func TestGenerator_Generate_UnknownProvider(t *testing.T) {
	g := NewGenerator()

	ctx := context.Background()
	req := &PayloadRequest{Type: PayloadSQLi, Count: 1}

	_, err := g.Generate(ctx, "unknown", req)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestNewOpenAIClient(t *testing.T) {
	client := NewOpenAIClient("sk-test-key", "gpt-4")

	if client.Provider() != ProviderOpenAI {
		t.Errorf("expected openai, got %s", client.Provider())
	}
	if client.Model != "gpt-4" {
		t.Errorf("expected gpt-4, got %s", client.Model)
	}
}

func TestOpenAIClient_Validate(t *testing.T) {
	ctx := context.Background()

	client := NewOpenAIClient("", "")
	if err := client.Validate(ctx); err == nil {
		t.Error("expected error for empty API key")
	}

	client = NewOpenAIClient("sk-test", "")
	if err := client.Validate(ctx); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOpenAIClient_GeneratePayloads(t *testing.T) {
	client := NewOpenAIClient("sk-test", "gpt-4")
	ctx := context.Background()

	req := &PayloadRequest{
		Type:  PayloadXSS,
		Count: 3,
	}

	payloads, err := client.GeneratePayloads(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("expected payloads")
	}
}

func TestOpenAIClient_MutatePayload(t *testing.T) {
	client := NewOpenAIClient("sk-test", "")
	ctx := context.Background()

	payloads, err := client.MutatePayload(ctx, "<script>alert(1)</script>", PayloadXSS, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("expected mutated payloads")
	}
}

func TestOpenAIClient_AnalyzeWAFResponse(t *testing.T) {
	client := NewOpenAIClient("sk-test", "")
	ctx := context.Background()

	analysis, err := client.AnalyzeWAFResponse(ctx, "Request blocked by cloudflare", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !analysis.WAFDetected {
		t.Error("expected WAF to be detected")
	}
	if analysis.WAFName != "cloudflare" {
		t.Errorf("expected cloudflare, got %s", analysis.WAFName)
	}
}

func TestNewAnthropicClient(t *testing.T) {
	client := NewAnthropicClient("sk-test", "claude-3")

	if client.Provider() != ProviderAnthropic {
		t.Errorf("expected anthropic, got %s", client.Provider())
	}
}

func TestAnthropicClient_Validate(t *testing.T) {
	ctx := context.Background()

	client := NewAnthropicClient("", "")
	if err := client.Validate(ctx); err == nil {
		t.Error("expected error for empty API key")
	}
}

func TestNewLocalClient(t *testing.T) {
	client := NewLocalClient()

	if client.Provider() != ProviderLocal {
		t.Errorf("expected local, got %s", client.Provider())
	}
}

func TestLocalClient_Validate(t *testing.T) {
	client := NewLocalClient()
	ctx := context.Background()

	if err := client.Validate(ctx); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLocalClient_GeneratePayloads(t *testing.T) {
	client := NewLocalClient()
	ctx := context.Background()

	testCases := []PayloadType{
		PayloadSQLi, PayloadXSS, PayloadLFI, PayloadRCE, PayloadSSRF,
	}

	for _, pt := range testCases {
		req := &PayloadRequest{
			Type:  pt,
			Count: 3,
		}

		payloads, err := client.GeneratePayloads(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", pt, err)
		}

		if len(payloads) == 0 {
			t.Errorf("expected payloads for %s", pt)
		}
	}
}

func TestNewMutationEngine(t *testing.T) {
	engine := NewMutationEngine()
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestMutationEngine_GetBasePayloads(t *testing.T) {
	engine := NewMutationEngine()

	sqli := engine.GetBasePayloads(PayloadSQLi)
	if len(sqli) == 0 {
		t.Error("expected SQLi base payloads")
	}

	xss := engine.GetBasePayloads(PayloadXSS)
	if len(xss) == 0 {
		t.Error("expected XSS base payloads")
	}

	unknown := engine.GetBasePayloads("unknown")
	if len(unknown) != 0 {
		t.Error("expected empty for unknown type")
	}
}

func TestMutationEngine_Mutate(t *testing.T) {
	engine := NewMutationEngine()

	payload := "' OR '1'='1"
	mutated := engine.Mutate(payload, PayloadSQLi, 3, nil)

	if len(mutated) <= 1 {
		t.Error("expected multiple mutations")
	}

	// Original should be included
	found := false
	for _, m := range mutated {
		if m == payload {
			found = true
			break
		}
	}
	if !found {
		t.Error("original payload should be in results")
	}
}

func TestCaseMutator(t *testing.T) {
	m := &CaseMutator{}

	if m.Name() != "case" {
		t.Errorf("expected 'case', got %s", m.Name())
	}

	results := m.Mutate("SeLeCt")
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

func TestURLEncodeMutator(t *testing.T) {
	m := &URLEncodeMutator{}

	if m.Name() != "url-encode" {
		t.Errorf("expected 'url-encode', got %s", m.Name())
	}

	// Test that alphanumeric chars are NOT encoded
	results := m.Mutate("abc123ABC")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0] != "abc123ABC" {
		t.Errorf("alphanumeric should not be encoded, got %s", results[0])
	}

	// Test that special chars ARE encoded with correct format
	results = m.Mutate("' OR '1'='1")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	expected := "%27%20OR%20%271%27%3D%271"
	if results[0] != expected {
		t.Errorf("expected %q, got %q", expected, results[0])
	}

	// Test single special character
	results = m.Mutate("<")
	if results[0] != "%3C" {
		t.Errorf("expected %%3C for '<', got %q", results[0])
	}

	// Test empty string
	results = m.Mutate("")
	if results[0] != "" {
		t.Errorf("expected empty string, got %q", results[0])
	}
}

func TestDoubleURLEncodeMutator(t *testing.T) {
	m := &DoubleURLEncodeMutator{}

	if m.Name() != "double-url-encode" {
		t.Errorf("expected 'double-url-encode', got %s", m.Name())
	}

	results := m.Mutate("test'")
	if len(results) == 0 {
		t.Error("expected results")
	}
}

func TestUnicodeMutator(t *testing.T) {
	m := &UnicodeMutator{}

	if m.Name() != "unicode" {
		t.Errorf("expected 'unicode', got %s", m.Name())
	}

	results := m.Mutate("<script>")
	if len(results) == 0 {
		t.Error("expected results")
	}
}

func TestCommentMutator(t *testing.T) {
	m := &CommentMutator{}

	if m.Name() != "comment" {
		t.Errorf("expected 'comment', got %s", m.Name())
	}

	results := m.Mutate("UNION SELECT")
	if len(results) == 0 {
		t.Error("expected results")
	}
}

func TestWhitespaceMutator(t *testing.T) {
	m := &WhitespaceMutator{}

	if m.Name() != "whitespace" {
		t.Errorf("expected 'whitespace', got %s", m.Name())
	}

	results := m.Mutate("1 AND 1=1")
	if len(results) != 4 {
		t.Errorf("expected 4 results, got %d", len(results))
	}
}

func TestNullByteMutator(t *testing.T) {
	m := &NullByteMutator{}

	if m.Name() != "null-byte" {
		t.Errorf("expected 'null-byte', got %s", m.Name())
	}

	results := m.Mutate("test.php")
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

func TestNewPayloadCache(t *testing.T) {
	cache := NewPayloadCache(100, time.Hour)
	if cache == nil {
		t.Fatal("expected non-nil cache")
	}
}

func TestPayloadCache_GetSet(t *testing.T) {
	cache := NewPayloadCache(100, time.Hour)

	// Get non-existent
	_, ok := cache.Get("key1")
	if ok {
		t.Error("should not find non-existent key")
	}

	// Set and get
	payloads := []*GeneratedPayload{{Payload: "test"}}
	cache.Set("key1", payloads)

	got, ok := cache.Get("key1")
	if !ok {
		t.Fatal("expected to find key")
	}
	if len(got) != 1 || got[0].Payload != "test" {
		t.Error("unexpected payload")
	}
}

func TestPayloadCache_Expiry(t *testing.T) {
	cache := NewPayloadCache(100, 10*time.Millisecond)

	payloads := []*GeneratedPayload{{Payload: "test"}}
	cache.Set("key1", payloads)

	// Should be found immediately
	_, ok := cache.Get("key1")
	if !ok {
		t.Error("expected to find key")
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	_, ok = cache.Get("key1")
	if ok {
		t.Error("should not find expired key")
	}
}

func TestPayloadCache_Eviction(t *testing.T) {
	cache := NewPayloadCache(2, time.Hour)

	cache.Set("key1", []*GeneratedPayload{{Payload: "1"}})
	cache.Set("key2", []*GeneratedPayload{{Payload: "2"}})
	cache.Set("key3", []*GeneratedPayload{{Payload: "3"}})

	// One should have been evicted
	count := 0
	for _, k := range []string{"key1", "key2", "key3"} {
		if _, ok := cache.Get(k); ok {
			count++
		}
	}
	if count > 2 {
		t.Error("expected at least one eviction")
	}
}

func TestNewRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(10, time.Minute)
	if limiter == nil {
		t.Fatal("expected non-nil limiter")
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	limiter := NewRateLimiter(3, time.Second)

	// First 3 should be allowed
	for i := 0; i < 3; i++ {
		if !limiter.Allow() {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 4th should be denied
	if limiter.Allow() {
		t.Error("4th request should be denied")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	limiter := NewRateLimiter(2, 50*time.Millisecond)

	limiter.Allow()
	limiter.Allow()

	// Should be rate limited
	if limiter.Allow() {
		t.Error("should be rate limited")
	}

	// Wait for reset
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again
	if !limiter.Allow() {
		t.Error("should be allowed after reset")
	}
}

func TestPayloadRequest(t *testing.T) {
	req := &PayloadRequest{
		Type:         PayloadSQLi,
		TargetWAF:    "cloudflare",
		Context:      "parameter",
		Encoding:     []string{"base64", "url"},
		EvasionLevel: 3,
		Count:        10,
		BasePayload:  "' OR '1'='1",
		Constraints: &PayloadConstraints{
			MaxLength:      100,
			AllowedChars:   "a-zA-Z0-9",
			ForbiddenChars: "<>",
			MustContain:    []string{"OR"},
			MustNotContain: []string{"DROP"},
		},
		Custom: map[string]string{"key": "value"},
	}

	if req.Type != PayloadSQLi {
		t.Error("unexpected type")
	}
	if req.EvasionLevel != 3 {
		t.Error("unexpected evasion level")
	}
}

func TestGeneratedPayload(t *testing.T) {
	p := &GeneratedPayload{
		Payload:       "' OR '1'='1",
		Type:          PayloadSQLi,
		Encoding:      "url",
		EvasionLevel:  2,
		Description:   "Basic SQLi payload",
		Confidence:    0.95,
		Tags:          []string{"sqli", "auth-bypass"},
		Mutations:     []string{"url-encode", "case"},
		ParentPayload: "' OR 1=1",
		Metadata:      map[string]string{"source": "mutation"},
	}

	if p.Payload == "" {
		t.Error("expected non-empty payload")
	}
	if p.Confidence < 0 || p.Confidence > 1 {
		t.Error("confidence should be 0-1")
	}
}

func TestWAFAnalysis(t *testing.T) {
	analysis := &WAFAnalysis{
		WAFDetected:       true,
		WAFName:           "cloudflare",
		BlockReason:       "SQL injection detected",
		BypassSuggestions: []string{"Use encoding", "Add comments"},
		EvasionTechniques: []string{"case-switch", "encoding"},
		Confidence:        0.9,
		Metadata:          map[string]string{"rule_id": "942100"},
	}

	if !analysis.WAFDetected {
		t.Error("expected WAF detected")
	}
	if len(analysis.BypassSuggestions) == 0 {
		t.Error("expected bypass suggestions")
	}
}

func TestToggleCase(t *testing.T) {
	result := toggleCase("Hello")
	if result != "hELLO" {
		t.Errorf("expected 'hELLO', got '%s'", result)
	}

	result = toggleCase("ABC123")
	if result != "abc123" {
		t.Errorf("expected 'abc123', got '%s'", result)
	}
}
