package config

import (
	"flag"
	"os"
	"testing"
	"time"
)

// resetFlags resets the flag package for each test
func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
}

// TestConfigDefaults verifies default values are set correctly
func TestConfigDefaults(t *testing.T) {
	resetFlags()

	// Save and restore os.Args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	// Check defaults
	if cfg.Concurrency != 25 {
		t.Errorf("Concurrency default: got %d, want 25", cfg.Concurrency)
	}
	if cfg.RateLimit != 150 {
		t.Errorf("RateLimit default: got %d, want 150", cfg.RateLimit)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout default: got %v, want 5s", cfg.Timeout)
	}
	if cfg.Retries != 1 {
		t.Errorf("Retries default: got %d, want 1", cfg.Retries)
	}
	if cfg.PayloadDir != "../payloads" {
		t.Errorf("PayloadDir default: got %q, want '../payloads'", cfg.PayloadDir)
	}
	if cfg.OutputFormat != "console" {
		t.Errorf("OutputFormat default: got %q, want 'console'", cfg.OutputFormat)
	}
	if cfg.StatsInterval != 5 {
		t.Errorf("StatsInterval default: got %d, want 5", cfg.StatsInterval)
	}
	if cfg.StoreResponseDir != "responses" {
		t.Errorf("StoreResponseDir default: got %q, want 'responses'", cfg.StoreResponseDir)
	}
}

// TestConfigTargetURL verifies target URL parsing
func TestConfigTargetURL(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://api.example.com"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.TargetURL != "https://api.example.com" {
		t.Errorf("TargetURL: got %q, want 'https://api.example.com'", cfg.TargetURL)
	}
}

// TestConfigTargetAlias verifies -u alias works
func TestConfigTargetAlias(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-u", "https://test.com"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.TargetURL != "https://test.com" {
		t.Errorf("TargetURL via -u: got %q, want 'https://test.com'", cfg.TargetURL)
	}
}

// TestConfigConcurrencyAlias verifies -c alias
func TestConfigConcurrencyAlias(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com", "-c", "50"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.Concurrency != 50 {
		t.Errorf("Concurrency via -c: got %d, want 50", cfg.Concurrency)
	}
}

// TestConfigRateLimitAlias verifies -rl alias
func TestConfigRateLimitAlias(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com", "-rl", "100"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.RateLimit != 100 {
		t.Errorf("RateLimit via -rl: got %d, want 100", cfg.RateLimit)
	}
}

// TestConfigPayloadAliases verifies payload flag aliases
func TestConfigPayloadAliases(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com", "-p", "/custom/payloads"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.PayloadDir != "/custom/payloads" {
		t.Errorf("PayloadDir via -p: got %q, want '/custom/payloads'", cfg.PayloadDir)
	}
}

// TestConfigOutputFlags verifies output flag combinations
func TestConfigOutputFlags(t *testing.T) {
	testCases := []struct {
		name        string
		args        []string
		wantFormat  string
		wantVerbose bool
		wantSilent  bool
	}{
		{
			name:       "json format",
			args:       []string{"cmd", "-target", "https://example.com", "-format", "json"},
			wantFormat: "json",
		},
		{
			name:       "jsonl shortcut",
			args:       []string{"cmd", "-target", "https://example.com", "-jsonl"},
			wantFormat: "jsonl",
		},
		{
			name:       "jsonl alias -j",
			args:       []string{"cmd", "-target", "https://example.com", "-j"},
			wantFormat: "jsonl",
		},
		{
			name:        "verbose with -v",
			args:        []string{"cmd", "-target", "https://example.com", "-v"},
			wantFormat:  "console",
			wantVerbose: true,
		},
		{
			name:       "silent with -s",
			args:       []string{"cmd", "-target", "https://example.com", "-s"},
			wantFormat: "console",
			wantSilent: true,
		},
		{
			name:       "sarif format",
			args:       []string{"cmd", "-target", "https://example.com", "-format", "sarif"},
			wantFormat: "sarif",
		},
		{
			name:       "csv format",
			args:       []string{"cmd", "-target", "https://example.com", "-format", "csv"},
			wantFormat: "csv",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetFlags()
			oldArgs := os.Args
			defer func() { os.Args = oldArgs }()

			os.Args = tc.args

			cfg, err := ParseFlags()
			if err != nil {
				t.Fatalf("ParseFlags failed: %v", err)
			}

			if cfg.OutputFormat != tc.wantFormat {
				t.Errorf("OutputFormat: got %q, want %q", cfg.OutputFormat, tc.wantFormat)
			}
			if cfg.Verbose != tc.wantVerbose {
				t.Errorf("Verbose: got %v, want %v", cfg.Verbose, tc.wantVerbose)
			}
			if cfg.Silent != tc.wantSilent {
				t.Errorf("Silent: got %v, want %v", cfg.Silent, tc.wantSilent)
			}
		})
	}
}

// TestConfigMatchFilter verifies match/filter flags
func TestConfigMatchFilter(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com",
		"-mc", "200,403", "-fc", "404", "-ms", "1000", "-fs", "0"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.MatchStatus != "200,403" {
		t.Errorf("MatchStatus: got %q, want '200,403'", cfg.MatchStatus)
	}
	if cfg.FilterStatus != "404" {
		t.Errorf("FilterStatus: got %q, want '404'", cfg.FilterStatus)
	}
	if cfg.MatchSize != "1000" {
		t.Errorf("MatchSize: got %q, want '1000'", cfg.MatchSize)
	}
	if cfg.FilterSize != "0" {
		t.Errorf("FilterSize: got %q, want '0'", cfg.FilterSize)
	}
}

// TestConfigAutoCalibration verifies auto-calibration flags
func TestConfigAutoCalibration(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com", "-ac"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if !cfg.AutoCalibration {
		t.Error("AutoCalibration should be true with -ac flag")
	}
}

// TestConfigNetworkFlags verifies network-related flags
func TestConfigNetworkFlags(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com",
		"-proxy", "http://localhost:8080", "-k", "-timeout", "10"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.Proxy != "http://localhost:8080" {
		t.Errorf("Proxy: got %q, want 'http://localhost:8080'", cfg.Proxy)
	}
	if !cfg.SkipVerify {
		t.Error("SkipVerify should be true with -k flag")
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout: got %v, want 10s", cfg.Timeout)
	}
}

// TestConfigRequiresTarget verifies target is required
func TestConfigRequiresTarget(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd"}

	_, err := ParseFlags()
	if err == nil {
		t.Error("ParseFlags should fail without target")
	}
	if err != nil && err.Error() != "target required: use -u, -l, -plan, or -stdin" {
		t.Errorf("Wrong error message: %v", err)
	}
}

// TestConfigPlanFileSkipsTarget verifies -plan doesn't require -target
func TestConfigPlanFileSkipsTarget(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-plan", "testplan.json"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags should succeed with -plan: %v", err)
	}

	if cfg.PlanFile != "testplan.json" {
		t.Errorf("PlanFile: got %q, want 'testplan.json'", cfg.PlanFile)
	}
}

// TestConfigStdinSkipsTarget verifies -stdin doesn't require -target
func TestConfigStdinSkipsTarget(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-stdin"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags should succeed with -stdin: %v", err)
	}

	if !cfg.StdinInput {
		t.Error("StdinInput should be true with -stdin flag")
	}
}

// TestConfigDryRun verifies dry-run flag
func TestConfigDryRun(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com", "-dry-run"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if !cfg.DryRun {
		t.Error("DryRun should be true with -dry-run flag")
	}
}

// TestConfigStoreResponse verifies store-response flags
func TestConfigStoreResponse(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com",
		"-sr", "-srd", "/tmp/responses"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if !cfg.StoreResponse {
		t.Error("StoreResponse should be true with -sr flag")
	}
	if cfg.StoreResponseDir != "/tmp/responses" {
		t.Errorf("StoreResponseDir: got %q, want '/tmp/responses'", cfg.StoreResponseDir)
	}
}

// TestConfigNonInteractive verifies non-interactive flag
func TestConfigNonInteractive(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com", "-ni"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if !cfg.NonInteractive {
		t.Error("NonInteractive should be true with -ni flag")
	}
}

// TestConfigCategoryAndSeverity verifies category and severity filters
func TestConfigCategoryAndSeverity(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com",
		"-category", "sqli", "-severity", "High"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.Category != "sqli" {
		t.Errorf("Category: got %q, want 'sqli'", cfg.Category)
	}
	if cfg.Severity != "High" {
		t.Errorf("Severity: got %q, want 'High'", cfg.Severity)
	}
}

// TestConfigTimestamp verifies timestamp flag
func TestConfigTimestamp(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com", "-ts"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if !cfg.Timestamp {
		t.Error("Timestamp should be true with -ts flag")
	}
}

// TestConfigStats verifies stats flags
func TestConfigStats(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com",
		"-stats", "-stats-interval", "10"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if !cfg.Stats {
		t.Error("Stats should be true with -stats flag")
	}
	if cfg.StatsInterval != 10 {
		t.Errorf("StatsInterval: got %d, want 10", cfg.StatsInterval)
	}
}

// TestConfigNoColor verifies no-color flag
func TestConfigNoColor(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com", "-nc"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if !cfg.NoColor {
		t.Error("NoColor should be true with -nc flag")
	}
}

// TestConfigHeadersInitialized verifies Headers map is initialized
func TestConfigHeadersInitialized(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.Headers == nil {
		t.Error("Headers map should be initialized")
	}
}

// TestConfigOutputFile verifies output file flags
func TestConfigOutputFile(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-target", "https://example.com",
		"-o", "results.json", "-format", "json"}

	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.OutputFile != "results.json" {
		t.Errorf("OutputFile: got %q, want 'results.json'", cfg.OutputFile)
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat: got %q, want 'json'", cfg.OutputFormat)
	}
}
