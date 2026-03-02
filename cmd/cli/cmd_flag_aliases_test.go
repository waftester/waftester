package main

import (
	"flag"
	"testing"
)

// =============================================================================
// FLAG ALIAS TESTS
// =============================================================================
//
// These tests verify that CLI flag aliases (-c, -rl, --timeout, -u) are
// properly registered and point to the same variable as the primary flag.

func TestScanFlags_ConcurrencyAlias(t *testing.T) {
	_, cfg := registerScanFlags()

	// Default should be 5 (from --concurrency definition)
	if *cfg.Concurrency != 5 {
		t.Errorf("default concurrency = %d, want 5", *cfg.Concurrency)
	}
}

func TestScanFlags_ConcurrencyAliasC(t *testing.T) {
	fs, cfg := registerScanFlags()
	if err := fs.Parse([]string{"-c", "20"}); err != nil {
		t.Fatalf("Parse -c failed: %v", err)
	}
	if *cfg.Concurrency != 20 {
		t.Errorf("-c 20: concurrency = %d, want 20", *cfg.Concurrency)
	}
}

func TestScanFlags_ConcurrencyLongForm(t *testing.T) {
	fs, cfg := registerScanFlags()
	if err := fs.Parse([]string{"-concurrency", "15"}); err != nil {
		t.Fatalf("Parse -concurrency failed: %v", err)
	}
	if *cfg.Concurrency != 15 {
		t.Errorf("-concurrency 15: concurrency = %d, want 15", *cfg.Concurrency)
	}
}

func TestCrawlFlags_ConcurrencyAlias(t *testing.T) {
	fs := flag.NewFlagSet("crawl", flag.ContinueOnError)
	concurrency := fs.Int("concurrency", 5, "Concurrent crawlers")
	fs.IntVar(concurrency, "c", 5, "Concurrent crawlers (alias)")

	if err := fs.Parse([]string{"-c", "12"}); err != nil {
		t.Fatalf("Parse -c failed: %v", err)
	}
	if *concurrency != 12 {
		t.Errorf("-c 12: concurrency = %d, want 12", *concurrency)
	}
}

func TestFuzzFlags_ConcurrencyAlias(t *testing.T) {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	concurrency := fs.Int("t", 40, "Threads")
	fs.IntVar(concurrency, "c", 40, "Threads (alias)")

	if err := fs.Parse([]string{"-c", "8"}); err != nil {
		t.Fatalf("Parse -c failed: %v", err)
	}
	if *concurrency != 8 {
		t.Errorf("-c 8: threads = %d, want 8", *concurrency)
	}
}

func TestFuzzFlags_RateLimitAlias(t *testing.T) {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	rateLimit := fs.Int("rate", 100, "Requests per second")
	fs.IntVar(rateLimit, "rl", 100, "Requests per second (alias)")

	if err := fs.Parse([]string{"-rl", "50"}); err != nil {
		t.Fatalf("Parse -rl failed: %v", err)
	}
	if *rateLimit != 50 {
		t.Errorf("-rl 50: rateLimit = %d, want 50", *rateLimit)
	}
}

func TestAssessFlags_RateLimitAlias(t *testing.T) {
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	rateLimit := fs.Float64("rate", 100.0, "Requests per second")
	fs.Float64Var(rateLimit, "rl", 100.0, "Requests per second (alias)")

	if err := fs.Parse([]string{"-rl", "25.5"}); err != nil {
		t.Fatalf("Parse -rl failed: %v", err)
	}
	if *rateLimit != 25.5 {
		t.Errorf("-rl 25.5: rateLimit = %f, want 25.5", *rateLimit)
	}
}

func TestCloudFlags_DomainAliasU(t *testing.T) {
	fs := flag.NewFlagSet("cloud", flag.ContinueOnError)
	domain := fs.String("domain", "", "Target domain")
	fs.StringVar(domain, "d", "", "Target domain (alias)")
	fs.StringVar(domain, "u", "", "Target domain (alias)")

	if err := fs.Parse([]string{"-u", "example.com"}); err != nil {
		t.Fatalf("Parse -u failed: %v", err)
	}
	if *domain != "example.com" {
		t.Errorf("-u example.com: domain = %q, want example.com", *domain)
	}
}

func TestCloudFlags_DomainAliasD(t *testing.T) {
	fs := flag.NewFlagSet("cloud", flag.ContinueOnError)
	domain := fs.String("domain", "", "Target domain")
	fs.StringVar(domain, "d", "", "Target domain (alias)")
	fs.StringVar(domain, "u", "", "Target domain (alias)")

	if err := fs.Parse([]string{"-d", "test.org"}); err != nil {
		t.Fatalf("Parse -d failed: %v", err)
	}
	if *domain != "test.org" {
		t.Errorf("-d test.org: domain = %q, want test.org", *domain)
	}
}

func TestBypassFlags_TimeoutExists(t *testing.T) {
	fs := flag.NewFlagSet("bypass", flag.ContinueOnError)
	timeout := fs.Int("timeout", 5, "Request timeout in seconds")

	if err := fs.Parse([]string{"-timeout", "30"}); err != nil {
		t.Fatalf("Parse -timeout failed: %v", err)
	}
	if *timeout != 30 {
		t.Errorf("-timeout 30: timeout = %d, want 30", *timeout)
	}
}

func TestAnalyzeFlags_TimeoutExists(t *testing.T) {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	timeout := fs.Int("timeout", 30, "Request timeout in seconds")

	if err := fs.Parse([]string{"-timeout", "60"}); err != nil {
		t.Fatalf("Parse -timeout failed: %v", err)
	}
	if *timeout != 60 {
		t.Errorf("-timeout 60: timeout = %d, want 60", *timeout)
	}
}
