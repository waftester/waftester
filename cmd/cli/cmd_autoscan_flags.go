package main

import (
	"flag"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/ui"
)

// autoscanConfig bundles all flag values for the autoscan command.
type autoscanConfig struct {
	Common CommonFlags
	Smart  SmartModeFlags
	Tamper TamperFlags
	Out    OutputFlags

	// Autoscan-specific flags
	Service     *string
	PayloadDir  *string
	Concurrency *int
	RateLimit   *int
	Depth       *int
	OutputDir   *string
	NoClean     *bool

	// Enterprise assessment
	EnableAssess *bool
	AssessCorpus *string

	// Leaky paths
	EnableLeakyPaths *bool
	LeakyCategories  *string

	// Parameter discovery
	EnableParamDiscovery *bool
	ParamWordlist        *string

	// JA3 fingerprint rotation
	EnableJA3  *bool
	JA3Profile *string

	// Full recon
	EnableFullRecon *bool

	// Browser-based scanning
	EnableBrowserScan *bool
	BrowserHeadless   *bool
	BrowserTimeout    *time.Duration

	// Detection
	NoDetect *bool

	// Checkpoint / resume
	ResumeScan     *bool
	CheckpointFile *string

	// Reporting
	ReportFormats *string

	// Adaptive rate limiting
	AdaptiveRate *bool

	// Brain mode
	EnableBrain  *bool
	BrainVerbose *bool

	// API spec-driven scanning
	SpecFile       *string
	SpecURL        *string
	SpecIntensity  *string
	SpecGroup      *string
	SpecSkipGroup  *string
	SpecDryRun     *bool
	SpecYes        *bool
	ScanConfigPath *string
}

// registerAutoscanFlags creates the FlagSet, registers all autoscan flags,
// and returns both the FlagSet and the populated config.
func registerAutoscanFlags() (*flag.FlagSet, *autoscanConfig) {
	fs := flag.NewFlagSet("auto", flag.ExitOnError)
	cfg := &autoscanConfig{}

	// Output configuration (unified architecture)
	cfg.Out.RegisterFlags(fs)
	cfg.Out.RegisterOutputAliases(fs)
	cfg.Out.Version = ui.Version

	// Common flags
	cfg.Common.Register(fs, 10)

	// Autoscan-specific
	cfg.Service = fs.String("service", "", "Service preset: wordpress, drupal, nextjs, flask, django")
	cfg.PayloadDir = fs.String("payloads", "", "Payload directory (default: auto-detect)")
	cfg.Concurrency = fs.Int("c", 50, "Concurrent workers for testing")
	cfg.RateLimit = fs.Int("rl", 200, "Rate limit (requests per second)")
	cfg.Depth = fs.Int("depth", 3, "Max crawl depth for discovery")
	cfg.OutputDir = fs.String("output-dir", "", "Output directory (default: workspaces/<domain>/<timestamp>)")
	cfg.NoClean = fs.Bool("no-clean", false, "Don't clean previous workspace files")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	cfg.Smart.Register(fs)

	// Tamper scripts (70+ sqlmap-compatible WAF bypass transformations)
	cfg.Tamper.Register(fs)

	// Enterprise assessment with quantitative metrics (NOW DEFAULT for superpower mode)
	cfg.EnableAssess = fs.Bool("assess", true, "Run enterprise assessment with F1/precision/MCC metrics (default: true)")
	cfg.AssessCorpus = fs.String("assess-corpus", "builtin,leipzig", "FP corpus for assessment: builtin,leipzig")

	// Leaky paths scanning
	cfg.EnableLeakyPaths = fs.Bool("leaky-paths", true, "Enable sensitive path scanning (300+ paths)")
	cfg.LeakyCategories = fs.String("leaky-categories", "", "Filter leaky paths: config,debug,vcs,admin,backup,source,api,cloud,ci")

	// Parameter discovery
	cfg.EnableParamDiscovery = fs.Bool("discover-params", true, "Enable Arjun-style parameter discovery")
	cfg.ParamWordlist = fs.String("param-wordlist", "", "Custom parameter wordlist file")

	// JA3 fingerprint rotation
	cfg.EnableJA3 = fs.Bool("ja3-rotate", false, "Enable JA3 fingerprint rotation")
	cfg.JA3Profile = fs.String("ja3-profile", "", "Specific JA3 profile: chrome120,firefox121,safari17,edge120")

	// Full recon mode
	cfg.EnableFullRecon = fs.Bool("full-recon", false, "Run unified reconnaissance (combines leaky-paths, params, JS analysis)")

	// Browser-based authenticated scanning
	cfg.EnableBrowserScan = fs.Bool("browser", true, "Enable authenticated browser scanning (default: true)")
	cfg.BrowserHeadless = fs.Bool("browser-headless", false, "Run browser in headless mode (no visible window)")
	cfg.BrowserTimeout = fs.Duration("browser-timeout", duration.BrowserLogin, "Timeout for user login during browser scan")

	// Detection
	cfg.NoDetect = fs.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	// Auto-resume with checkpoint support
	cfg.ResumeScan = fs.Bool("resume", false, "Resume interrupted scan from checkpoint")
	cfg.CheckpointFile = fs.String("checkpoint", "", "Checkpoint file path (default: <workspace>/checkpoint.json)")

	// Multi-format report generation
	cfg.ReportFormats = fs.String("report-formats", "json,md,html", "Comma-separated report formats: json,md,html,sarif")

	// Adaptive rate limiting
	cfg.AdaptiveRate = fs.Bool("adaptive-rate", true, "Enable adaptive rate limiting (auto-adjust on WAF response)")

	// Brain Mode
	cfg.EnableBrain = fs.Bool("brain", true, "Enable Brain Mode (adaptive learning, attack chains, smart prioritization)")
	cfg.BrainVerbose = fs.Bool("brain-verbose", false, "Show detailed brain insights during scan")

	// API spec-driven scanning
	cfg.SpecFile = fs.String("spec", "", "API spec file path (OpenAPI, Swagger, Postman, HAR)")
	cfg.SpecURL = fs.String("spec-url", "", "API spec URL to fetch and parse")
	cfg.SpecIntensity = fs.String("intensity", "normal", "Spec scan intensity: quick, normal, deep, paranoid")
	cfg.SpecGroup = fs.String("group", "", "Filter spec endpoints by group/tag")
	cfg.SpecSkipGroup = fs.String("skip-group", "", "Exclude spec endpoints by group/tag")
	cfg.SpecDryRun = fs.Bool("dry-run", false, "Show scan plan without executing")
	cfg.SpecYes = fs.Bool("yes", false, "Skip confirmation prompt for spec scans")
	cfg.ScanConfigPath = fs.String("scan-config", "", "Path to .waftester-spec.yaml for per-endpoint overrides")

	return fs, cfg
}

// validate checks that numeric flag values are sane to prevent panics
// (negative channel size) and hangs (zero workers).
func (cfg *autoscanConfig) validate() {
	if *cfg.Concurrency <= 0 {
		exitWithError("--concurrency must be a positive integer")
	}
	if *cfg.RateLimit <= 0 {
		exitWithError("--rl must be a positive integer")
	}
	if cfg.Common.Timeout <= 0 {
		exitWithError("--timeout must be a positive integer")
	}
}
