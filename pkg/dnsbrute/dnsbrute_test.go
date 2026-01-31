package dnsbrute

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Concurrency != 100 {
		t.Errorf("expected concurrency 100, got %d", config.Concurrency)
	}
	if config.Timeout != 3*time.Second {
		t.Errorf("expected timeout 3s, got %v", config.Timeout)
	}
	if len(config.Resolvers) == 0 {
		t.Error("expected default resolvers")
	}
	if config.Retries != 2 {
		t.Errorf("expected retries 2, got %d", config.Retries)
	}
	if !config.WildcardFilter {
		t.Error("expected wildcard filter enabled")
	}
}

func TestDefaultResolvers(t *testing.T) {
	resolvers := DefaultResolvers()
	if len(resolvers) == 0 {
		t.Error("expected non-empty resolvers")
	}

	// Check format
	for _, r := range resolvers {
		if !containsPort(r) {
			t.Errorf("resolver should include port: %s", r)
		}
	}
}

func containsPort(s string) bool {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

func TestNewBruteforcer(t *testing.T) {
	config := DefaultConfig()
	b := NewBruteforcer(config)

	if b == nil {
		t.Fatal("NewBruteforcer returned nil")
	}
	if len(b.resolvers) != len(config.Resolvers) {
		t.Errorf("expected %d resolvers, got %d", len(config.Resolvers), len(b.resolvers))
	}
}

func TestNewBruteforcer_DefaultValues(t *testing.T) {
	// Test with zero values
	config := Config{}
	b := NewBruteforcer(config)

	if b.config.Concurrency != 100 {
		t.Errorf("expected default concurrency 100, got %d", b.config.Concurrency)
	}
	if b.config.Timeout != 3*time.Second {
		t.Errorf("expected default timeout 3s, got %v", b.config.Timeout)
	}
}

func TestCommonWordlist(t *testing.T) {
	words := CommonWordlist()
	if len(words) == 0 {
		t.Error("expected non-empty common wordlist")
	}

	// Check for common entries
	expected := []string{"www", "mail", "api", "admin"}
	for _, e := range expected {
		found := false
		for _, w := range words {
			if w == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected '%s' in common wordlist", e)
		}
	}
}

func TestBruteforcer_GetStats(t *testing.T) {
	b := NewBruteforcer(DefaultConfig())
	b.startTime = time.Now()

	stats := b.GetStats()
	if stats.Total != 0 {
		t.Errorf("expected total 0, got %d", stats.Total)
	}
}

func TestBruteforcer_GetResults(t *testing.T) {
	b := NewBruteforcer(DefaultConfig())

	results := b.GetResults()
	if results == nil {
		t.Error("expected non-nil results")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestBruteforcer_Stop(t *testing.T) {
	b := NewBruteforcer(DefaultConfig())

	// Should not panic when cancel is nil
	b.Stop()

	// Should work with real context
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	b.Stop()

	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("expected context to be cancelled")
	}
}

func TestBruteforcer_isWildcard(t *testing.T) {
	b := NewBruteforcer(DefaultConfig())

	// No wildcard set
	if b.isWildcard("example.com", []string{"1.2.3.4"}) {
		t.Error("should not be wildcard when none set")
	}

	// Set wildcard
	b.wildcards["example.com"] = []string{"1.2.3.4"}

	if !b.isWildcard("example.com", []string{"1.2.3.4"}) {
		t.Error("should detect wildcard IP match")
	}

	if b.isWildcard("example.com", []string{"5.6.7.8"}) {
		t.Error("should not match different IP")
	}
}

func TestBruteforcer_isWildcardCNAME(t *testing.T) {
	b := NewBruteforcer(DefaultConfig())

	tests := []struct {
		domain   string
		cname    string
		expected bool
	}{
		{"example.com", "wildcard.example.com", true},
		{"example.com", "catch-all.example.com", true},
		{"example.com", "www.example.com", false},
		{"example.com", "api.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.cname, func(t *testing.T) {
			result := b.isWildcardCNAME(tt.domain, tt.cname)
			if result != tt.expected {
				t.Errorf("isWildcardCNAME(%s, %s) = %v, want %v", tt.domain, tt.cname, result, tt.expected)
			}
		})
	}
}

func TestLoadWordlist(t *testing.T) {
	// Create temp wordlist
	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "wordlist.txt")

	content := `www
mail
# comment
api

admin
`
	if err := os.WriteFile(wordlistPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create wordlist: %v", err)
	}

	words, err := loadWordlist(wordlistPath)
	if err != nil {
		t.Fatalf("loadWordlist failed: %v", err)
	}

	expected := []string{"www", "mail", "api", "admin"}
	if len(words) != len(expected) {
		t.Errorf("expected %d words, got %d", len(expected), len(words))
	}

	for i, w := range expected {
		if words[i] != w {
			t.Errorf("word %d: expected %s, got %s", i, w, words[i])
		}
	}
}

func TestLoadWordlist_FileNotFound(t *testing.T) {
	_, err := loadWordlist("/nonexistent/wordlist.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestBruteforcer_RunWithWordlist_NoPath(t *testing.T) {
	config := DefaultConfig()
	config.Wordlist = ""
	b := NewBruteforcer(config)

	_, err := b.RunWithWordlist(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error for missing wordlist path")
	}
}

func TestNewRecursiveBrute(t *testing.T) {
	config := DefaultConfig()
	r := NewRecursiveBrute(config)

	if r == nil {
		t.Fatal("NewRecursiveBrute returned nil")
	}
	if r.maxDepth != 2 {
		t.Errorf("expected default depth 2, got %d", r.maxDepth)
	}
}

func TestNewRecursiveBrute_CustomDepth(t *testing.T) {
	config := DefaultConfig()
	config.RecursionDepth = 5
	r := NewRecursiveBrute(config)

	if r.maxDepth != 5 {
		t.Errorf("expected depth 5, got %d", r.maxDepth)
	}
}

func TestNewPermutationGenerator(t *testing.T) {
	p := NewPermutationGenerator()

	if len(p.prefixes) == 0 {
		t.Error("expected prefixes")
	}
	if len(p.suffixes) == 0 {
		t.Error("expected suffixes")
	}
	if len(p.numbers) == 0 {
		t.Error("expected numbers")
	}
}

func TestPermutationGenerator_Generate(t *testing.T) {
	p := NewPermutationGenerator()

	baseWords := []string{"api", "web"}
	permutations := p.Generate(baseWords)

	if len(permutations) <= len(baseWords) {
		t.Error("expected more permutations than base words")
	}

	// Check for expected permutations
	expectedPatterns := []string{
		"api",
		"web",
		"dev-api",
		"api-backend",
		"api1",
	}

	for _, expected := range expectedPatterns {
		found := false
		for _, perm := range permutations {
			if perm == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected permutation '%s' not found", expected)
		}
	}
}

func TestPermutationGenerator_Generate_NoDuplicates(t *testing.T) {
	p := NewPermutationGenerator()

	baseWords := []string{"api", "api"} // Duplicate input
	permutations := p.Generate(baseWords)

	// Check no duplicates in output
	seen := make(map[string]bool)
	for _, perm := range permutations {
		if seen[perm] {
			t.Errorf("duplicate permutation: %s", perm)
		}
		seen[perm] = true
	}
}

func TestPermutationGenerator_GenerateFromDiscovered(t *testing.T) {
	p := NewPermutationGenerator()

	discovered := []Result{
		{Subdomain: "api"},
		{Subdomain: "admin"},
	}

	permutations := p.GenerateFromDiscovered(discovered)
	if len(permutations) == 0 {
		t.Error("expected permutations from discovered")
	}
}

func TestMergeResults(t *testing.T) {
	set1 := []Result{
		{FQDN: "api.example.com", IPs: []string{"1.1.1.1"}},
		{FQDN: "www.example.com", IPs: []string{"2.2.2.2"}},
	}

	set2 := []Result{
		{FQDN: "api.example.com", IPs: []string{"1.1.1.1", "3.3.3.3"}}, // Overlap
		{FQDN: "mail.example.com", IPs: []string{"4.4.4.4"}},
	}

	merged := MergeResults(set1, set2)

	if len(merged) != 3 {
		t.Errorf("expected 3 unique results, got %d", len(merged))
	}

	// Check api.example.com has merged IPs
	for _, r := range merged {
		if r.FQDN == "api.example.com" {
			if len(r.IPs) != 2 {
				t.Errorf("expected 2 IPs for api.example.com, got %d", len(r.IPs))
			}
		}
	}
}

func TestMergeResults_Empty(t *testing.T) {
	merged := MergeResults()
	if len(merged) != 0 {
		t.Errorf("expected 0 results, got %d", len(merged))
	}
}

func TestMergeResults_Sorted(t *testing.T) {
	set1 := []Result{
		{FQDN: "z.example.com"},
		{FQDN: "a.example.com"},
		{FQDN: "m.example.com"},
	}

	merged := MergeResults(set1)

	if merged[0].FQDN != "a.example.com" {
		t.Error("results should be sorted alphabetically")
	}
	if merged[2].FQDN != "z.example.com" {
		t.Error("results should be sorted alphabetically")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		Subdomain:  "api",
		Domain:     "example.com",
		FQDN:       "api.example.com",
		IPs:        []string{"1.2.3.4"},
		CNAMEs:     []string{"cdn.example.com"},
		IsWildcard: false,
		Resolver:   "8.8.8.8:53",
		Timestamp:  time.Now(),
	}

	if result.Subdomain != "api" {
		t.Error("subdomain field incorrect")
	}
	if result.Domain != "example.com" {
		t.Error("domain field incorrect")
	}
}

func TestStats_Fields(t *testing.T) {
	stats := Stats{
		Total:     100,
		Tested:    50,
		Found:     10,
		Errors:    5,
		Wildcards: 3,
		Duration:  5 * time.Second,
		Rate:      10.0,
	}

	if stats.Total != 100 {
		t.Error("total field incorrect")
	}
	if stats.Rate != 10.0 {
		t.Error("rate field incorrect")
	}
}

func TestBruteforcer_Run_EmptyWordlist(t *testing.T) {
	b := NewBruteforcer(DefaultConfig())

	results, err := b.Run(context.Background(), "example.com", []string{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty wordlist, got %d", len(results))
	}
}

func TestBruteforcer_Run_ContextCancelled(t *testing.T) {
	b := NewBruteforcer(DefaultConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	results, err := b.Run(ctx, "example.com", CommonWordlist())
	// Should complete quickly without error
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Results should be empty or minimal due to cancellation
	_ = results
}

func TestConfig_Wordlist(t *testing.T) {
	config := Config{
		Wordlist: "/path/to/wordlist.txt",
	}

	if config.Wordlist != "/path/to/wordlist.txt" {
		t.Error("wordlist path incorrect")
	}
}

func TestBruteforcer_Run_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	config := DefaultConfig()
	config.Concurrency = 10
	config.Timeout = 2 * time.Second
	b := NewBruteforcer(config)

	// Test with known domain
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	words := []string{"www", "nonexistent12345xyz"}
	results, err := b.Run(ctx, "google.com", words)

	if err != nil {
		t.Logf("run returned error (may be expected): %v", err)
	}

	stats := b.GetStats()
	if stats.Tested == 0 {
		t.Error("expected some words to be tested")
	}

	_ = results
}
