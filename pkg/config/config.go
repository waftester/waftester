package config

import (
	"flag"
	"fmt"
	"time"

	"github.com/waftester/waftester/pkg/input"
)

// Config holds all CLI configuration options
type Config struct {
	// Target settings
	TargetURL  string
	TargetURLs input.StringSliceFlag // Multi-target support
	ListFile   string                // File containing target URLs

	// Test Plan settings (from learn command)
	PlanFile string // Test plan JSON file from 'learn' command

	// Execution settings (nuclei-style defaults)
	Concurrency int           // Number of parallel workers (default: 25)
	RateLimit   int           // Requests per second (default: 150)
	Timeout     time.Duration // HTTP timeout (default: 5s)
	Retries     int           // Retry count on failure (default: 1)

	// Payload settings
	PayloadDir string // Directory containing payload JSON files
	Category   string // Filter by category (empty = all)
	Severity   string // Filter by minimum severity (empty = all)

	// Mutation settings (WAF bypass)
	MutationMode      string // Mutation mode: none, quick, standard, full (default: none)
	MutationEncoders  string // Comma-separated encoders (empty = all for mode)
	MutationLocations string // Comma-separated locations (empty = default for mode)
	MutationEvasions  string // Comma-separated evasions (empty = none unless full)
	MutationChain     bool   // Enable chained mutations
	MutationMaxChain  int    // Maximum chain depth (default: 2)

	// Match/Filter settings (ffuf-style)
	MatchStatus  string // Match response status codes (e.g., "200,403,500")
	MatchSize    string // Match response size
	MatchWords   string // Match response word count
	MatchLines   string // Match response line count
	MatchRegex   string // Match response body regex
	FilterStatus string // Filter out response status codes
	FilterSize   string // Filter out response size
	FilterWords  string // Filter out response word count
	FilterLines  string // Filter out response line count
	FilterRegex  string // Filter out response body regex

	// Auto-calibration (ffuf-style -ac flag)
	AutoCalibration bool // Automatically detect and filter baseline responses

	// Output settings
	OutputFile       string // Output file path (empty = stdout)
	OutputFormat     string // json, jsonl, console, sarif, csv, md, html
	JSONLines        bool   // Output JSONL (one JSON per line)
	Verbose          bool   // Verbose output
	Silent           bool   // Silent mode (no progress)
	NoColor          bool   // Disable colored output
	DryRun           bool   // List tests without executing
	Stats            bool   // Show statistics during execution
	StatsInterval    int    // Stats update interval in seconds
	Timestamp        bool   // Add timestamp to results (nuclei -ts style)
	StoreResponse    bool   // Store HTTP responses to directory
	StoreResponseDir string // Directory for stored responses

	// Interactive mode (ffuf-style)
	NonInteractive bool // Disable interactive console (ENTER to pause)

	// Advanced settings
	Headers    map[string]string // Custom headers
	Proxy      string            // Proxy URL
	SkipVerify bool              // Skip TLS verification

	// Input settings
	StdinInput bool // Read targets from stdin

	// Realistic mode settings (advanced WAF testing)
	RealisticMode bool     // Use realistic request building and intelligent block detection
	Categories    []string // Parsed category list (internal use)
}

// ParseFlags parses command line arguments and returns Config
func ParseFlags() (*Config, error) {
	cfg := &Config{
		Headers: make(map[string]string),
	}

	// === INPUT ===
	flag.Var(&cfg.TargetURLs, "u", "Target URL(s) - comma-separated or repeated")
	flag.Var(&cfg.TargetURLs, "target", "Target URL(s)")
	flag.StringVar(&cfg.ListFile, "l", "", "File containing target URLs")
	flag.StringVar(&cfg.PlanFile, "plan", "", "Test plan from 'learn' command")
	flag.BoolVar(&cfg.StdinInput, "stdin", false, "Read targets from stdin")

	// === EXECUTION ===
	flag.IntVar(&cfg.Concurrency, "concurrency", 25, "Concurrent workers")
	flag.IntVar(&cfg.Concurrency, "c", 25, "Concurrent workers (alias)")
	flag.IntVar(&cfg.RateLimit, "rate-limit", 150, "Max requests per second")
	flag.IntVar(&cfg.RateLimit, "rl", 150, "Rate limit (alias)")
	timeout := flag.Int("timeout", 5, "HTTP timeout in seconds")
	flag.IntVar(&cfg.Retries, "retries", 1, "Retry count on failure")

	// === PAYLOADS ===
	flag.StringVar(&cfg.PayloadDir, "payloads", "../payloads", "Payload directory")
	flag.StringVar(&cfg.PayloadDir, "p", "../payloads", "Payload dir (alias)")
	flag.StringVar(&cfg.Category, "category", "", "Filter by category")
	flag.StringVar(&cfg.Severity, "severity", "", "Filter by min severity (Critical,High,Medium,Low)")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "List tests without executing")

	// === MUTATION (WAF bypass) ===
	flag.StringVar(&cfg.MutationMode, "mutation", "none", "Mutation mode: none, quick, standard, full")
	flag.StringVar(&cfg.MutationMode, "m", "none", "Mutation mode (alias)")
	flag.StringVar(&cfg.MutationEncoders, "encoders", "", "Comma-separated encoders (e.g., url,double_url,html_hex)")
	flag.StringVar(&cfg.MutationLocations, "locations", "", "Comma-separated locations (e.g., query_param,post_json)")
	flag.StringVar(&cfg.MutationEvasions, "evasions", "", "Comma-separated evasions (e.g., case_swap,sql_comment)")
	flag.BoolVar(&cfg.MutationChain, "chain", false, "Enable chained mutations (encoder → evasion)")
	flag.IntVar(&cfg.MutationMaxChain, "max-chain", 2, "Maximum mutation chain depth")

	// === MATCHERS (what to report) ===
	flag.StringVar(&cfg.MatchStatus, "mc", "", "Match status codes (e.g., 200,403,500)")
	flag.StringVar(&cfg.MatchStatus, "match-code", "", "Match status codes (alias)")
	flag.StringVar(&cfg.MatchSize, "ms", "", "Match response size")
	flag.StringVar(&cfg.MatchSize, "match-size", "", "Match response size (alias)")
	flag.StringVar(&cfg.MatchWords, "mw", "", "Match response word count")
	flag.StringVar(&cfg.MatchWords, "match-words", "", "Match word count (alias)")
	flag.StringVar(&cfg.MatchLines, "ml", "", "Match response line count")
	flag.StringVar(&cfg.MatchLines, "match-lines", "", "Match line count (alias)")
	flag.StringVar(&cfg.MatchRegex, "mr", "", "Match response body regex")
	flag.StringVar(&cfg.MatchRegex, "match-regex", "", "Match regex (alias)")

	// === FILTERS (what to hide) ===
	flag.StringVar(&cfg.FilterStatus, "fc", "", "Filter status codes (e.g., 404,500)")
	flag.StringVar(&cfg.FilterStatus, "filter-code", "", "Filter status codes (alias)")
	flag.StringVar(&cfg.FilterSize, "fs", "", "Filter response size")
	flag.StringVar(&cfg.FilterSize, "filter-size", "", "Filter response size (alias)")
	flag.StringVar(&cfg.FilterWords, "fw", "", "Filter response word count")
	flag.StringVar(&cfg.FilterWords, "filter-words", "", "Filter word count (alias)")
	flag.StringVar(&cfg.FilterLines, "fl", "", "Filter response line count")
	flag.StringVar(&cfg.FilterLines, "filter-lines", "", "Filter line count (alias)")
	flag.StringVar(&cfg.FilterRegex, "fr", "", "Filter response body regex")
	flag.StringVar(&cfg.FilterRegex, "filter-regex", "", "Filter regex (alias)")

	// === AUTO-CALIBRATION (ffuf-style) ===
	flag.BoolVar(&cfg.AutoCalibration, "ac", false, "Auto-calibrate filtering options")
	flag.BoolVar(&cfg.AutoCalibration, "auto-calibrate", false, "Auto-calibrate (alias)")

	// === OUTPUT ===
	flag.StringVar(&cfg.OutputFile, "output", "", "Output file path")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file (alias)")
	flag.StringVar(&cfg.OutputFormat, "format", "console", "Output format: console,json,jsonl,sarif")
	flag.BoolVar(&cfg.JSONLines, "jsonl", false, "JSONL output (one JSON per line)")
	flag.BoolVar(&cfg.JSONLines, "j", false, "JSONL output (alias)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose (alias)")
	flag.BoolVar(&cfg.Silent, "silent", false, "Silent mode - no progress")
	flag.BoolVar(&cfg.Silent, "s", false, "Silent (alias)")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&cfg.NoColor, "nc", false, "No color (alias)")
	flag.BoolVar(&cfg.Stats, "stats", false, "Show statistics during execution")
	flag.IntVar(&cfg.StatsInterval, "stats-interval", 5, "Stats update interval in seconds")
	flag.BoolVar(&cfg.Timestamp, "timestamp", false, "Add timestamp to output")
	flag.BoolVar(&cfg.Timestamp, "ts", false, "Timestamp (alias)")
	flag.BoolVar(&cfg.StoreResponse, "store-response", false, "Store HTTP responses to directory")
	flag.BoolVar(&cfg.StoreResponse, "sr", false, "Store response (alias)")
	flag.StringVar(&cfg.StoreResponseDir, "store-response-dir", "responses", "Directory for stored responses")
	flag.StringVar(&cfg.StoreResponseDir, "srd", "responses", "Store response dir (alias)")

	// === INTERACTIVE MODE ===
	flag.BoolVar(&cfg.NonInteractive, "noninteractive", false, "Disable interactive console")
	flag.BoolVar(&cfg.NonInteractive, "ni", false, "Disable interactive (alias)")

	// === NETWORK ===
	flag.StringVar(&cfg.Proxy, "proxy", "", "HTTP/SOCKS5 proxy URL")
	flag.StringVar(&cfg.Proxy, "x", "", "Proxy (alias)")
	flag.BoolVar(&cfg.SkipVerify, "skip-verify", false, "Skip TLS verification")
	flag.BoolVar(&cfg.SkipVerify, "k", false, "Skip TLS (alias)")

	// === REALISTIC MODE (advanced WAF testing) ===
	flag.BoolVar(&cfg.RealisticMode, "realistic", false, "Use realistic browser-like requests and intelligent block detection")
	flag.BoolVar(&cfg.RealisticMode, "R", false, "Realistic mode (alias)")

	// Parse
	flag.Parse()

	// Convert timeout
	cfg.Timeout = time.Duration(*timeout) * time.Second

	// Handle JSONL format shortcut
	if cfg.JSONLines {
		cfg.OutputFormat = "jsonl"
	}

	// Handle backwards compatibility: if TargetURLs has values, use first one as TargetURL
	if len(cfg.TargetURLs) > 0 && cfg.TargetURL == "" {
		cfg.TargetURL = cfg.TargetURLs[0]
	}

	// Validate - target is required unless using a plan file or stdin or list file
	if cfg.TargetURL == "" && len(cfg.TargetURLs) == 0 && cfg.PlanFile == "" && !cfg.StdinInput && cfg.ListFile == "" {
		return nil, fmt.Errorf("target required: use -u, -l, -plan, or -stdin")
	}

	return cfg, nil
}
