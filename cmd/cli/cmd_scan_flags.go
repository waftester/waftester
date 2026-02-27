package main

import (
	"flag"
	"time"

	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/defaults"
)

// scanConfig bundles every flag value for the scan command.
// Grouped by concern so callers can reference cfg.Common, cfg.Smart, etc.
type scanConfig struct {
	Common CommonFlags
	Smart  SmartModeFlags
	Tamper TamperFlags
	Out    OutputFlags
	Spec   apispec.SpecFlags

	// Scan-specific flags
	Types       *string
	Concurrency *int
	OutputFile  *string
	JSONOutput  *bool

	// OAuth-specific
	OAuthClientID      *string
	OAuthAuthEndpoint  *string
	OAuthTokenEndpoint *string
	OAuthRedirectURI   *string

	// Rate limiting and throttling
	RateLimit        *int
	RateLimitPerHost *bool
	Delay            *time.Duration
	Jitter           *time.Duration

	// Payload and template directories
	PayloadDir  *string
	TemplateDir *string

	// Output formats (legacy shorthand flags)
	FormatType     *string
	SARIFOutput    *bool
	MarkdownOutput *bool
	HTMLOutput     *bool
	CSVOutput      *bool
	Silent         *bool
	NoColor        *bool

	// Filtering and matching
	MatchSeverity  *string
	FilterSeverity *string
	MatchCategory  *string
	FilterCategory *string

	// Network options
	Proxy       *string
	UserAgent   *string
	RandomAgent *bool
	Headers     headerSlice
	Cookies     *string

	// Retries and error handling
	Retries         *int
	MaxErrors       *int
	StopOnFirstVuln *bool

	// Resume and checkpointing
	Resume         *bool
	CheckpointFile *string

	// Scope control
	ExcludeTypes    *string
	ExcludePatterns *string
	IncludePatterns *string

	// Reporting
	ReportTitle        *string
	ReportAuthor       *string
	IncludeEvidence    *bool
	IncludeRemediation *bool

	// Advanced options
	FollowRedirects *bool
	MaxRedirects    *int
	RespectRobots   *bool
	DryRun          *bool

	// Payload limits
	MaxPayloads *int
	MaxParams   *int

	// Debug and diagnostics
	Debug         *bool
	DebugRequest  *bool
	DebugResponse *bool
	Profile       *bool
	MemProfile    *bool

	// Streaming mode
	StreamMode *bool

	// Timestamp output
	Timestamp *bool

	// Detection control
	NoDetect *bool
}

// registerScanFlags creates the "scan" FlagSet, registers every flag,
// and returns both the FlagSet and the populated scanConfig.
func registerScanFlags() (*flag.FlagSet, *scanConfig) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfg := &scanConfig{}

	// Output configuration (unified architecture - enterprise flags only)
	cfg.Out.RegisterEnterpriseFlags(fs)

	// Common flags (target, timeout, verbose, etc.)
	cfg.Common.Register(fs, 30)

	// API spec scanning flags
	cfg.Spec.Register(fs)

	// Scan types
	cfg.Types = fs.String("types", "all", "Scan types: all, or comma-separated (sqli,xss,traversal,cmdi,nosqli,hpp,crlf,prototype,cors,redirect,hostheader,websocket,cache,upload,deserialize,oauth,ssrf,ssti,xxe,smuggling,graphql,jwt,subtakeover,bizlogic,race,apifuzz,ldap,ssi,xpath,xmlinjection,rfi,lfi,rce,csrf,clickjack,idor,massassignment,wafdetect,waffprint,wafevasion,tlsprobe,httpprobe,secheaders,jsanalyze,apidepth,osint,vhost,techdetect,dnsrecon)")
	fs.StringVar(cfg.Types, "t", "all", "Scan types (alias)")
	cfg.Concurrency = fs.Int("concurrency", 5, "Concurrent scanners")
	cfg.OutputFile = fs.String("output", "", "Output results to JSON file")
	cfg.JSONOutput = fs.Bool("json", false, "Output in JSON format")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	cfg.Smart.Register(fs)

	// Tamper scripts (70+ sqlmap-compatible WAF bypass transformations)
	cfg.Tamper.Register(fs)

	// OAuth-specific flags
	cfg.OAuthClientID = fs.String("oauth-client-id", "", "OAuth client ID for OAuth testing")
	cfg.OAuthAuthEndpoint = fs.String("oauth-auth-endpoint", "", "OAuth authorization endpoint")
	cfg.OAuthTokenEndpoint = fs.String("oauth-token-endpoint", "", "OAuth token endpoint")
	cfg.OAuthRedirectURI = fs.String("oauth-redirect-uri", "", "OAuth redirect URI")

	// Rate limiting and throttling
	cfg.RateLimit = fs.Int("rate-limit", 50, "Max requests per second")
	fs.IntVar(cfg.RateLimit, "rl", 50, "Max requests per second (alias)")

	// Payload and template directories
	cfg.PayloadDir = fs.String("payloads", defaults.PayloadDir, "Payload directory")
	cfg.TemplateDir = fs.String("template-dir", defaults.TemplateDir, "Nuclei template directory")
	cfg.RateLimitPerHost = fs.Bool("rate-limit-per-host", false, "Apply rate limit per host")
	fs.BoolVar(cfg.RateLimitPerHost, "rlph", false, "Rate limit per host (alias)")
	cfg.Delay = fs.Duration("delay", 0, "Delay between requests (e.g., 100ms, 1s)")
	cfg.Jitter = fs.Duration("jitter", 0, "Random jitter to add to delay")

	// Output formats
	cfg.FormatType = fs.String("format", "console", "Output format: console,json,jsonl,sarif,csv,md,html")
	cfg.SARIFOutput = fs.Bool("sarif", false, "Output in SARIF format for CI/CD")
	cfg.MarkdownOutput = fs.Bool("md", false, "Output in Markdown format")
	cfg.HTMLOutput = fs.Bool("html", false, "Output in HTML format")
	cfg.CSVOutput = fs.Bool("csv", false, "Output in CSV format")
	cfg.Silent = fs.Bool("silent", false, "Silent mode - no progress output")
	fs.BoolVar(cfg.Silent, "s", false, "Silent mode (alias)")
	fs.BoolVar(cfg.Silent, "q", false, "Quiet mode (alias)")
	cfg.NoColor = fs.Bool("no-color", false, "Disable colored output")
	fs.BoolVar(cfg.NoColor, "nc", false, "No color (alias)")

	// Filtering and matching
	cfg.MatchSeverity = fs.String("match-severity", "", "Match findings by severity (critical,high,medium,low)")
	fs.StringVar(cfg.MatchSeverity, "msev", "", "Match severity (alias)")
	cfg.FilterSeverity = fs.String("filter-severity", "", "Filter findings by severity")
	fs.StringVar(cfg.FilterSeverity, "fsev", "", "Filter severity (alias)")
	cfg.MatchCategory = fs.String("match-category", "", "Match findings by category")
	fs.StringVar(cfg.MatchCategory, "mcat", "", "Match category (alias)")
	cfg.FilterCategory = fs.String("filter-category", "", "Filter findings by category")
	fs.StringVar(cfg.FilterCategory, "fcat", "", "Filter category (alias)")

	// Network options
	cfg.Proxy = fs.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	fs.StringVar(cfg.Proxy, "x", "", "Proxy (alias)")
	cfg.UserAgent = fs.String("user-agent", "", "Custom User-Agent (default: waftester/VERSION)")
	fs.StringVar(cfg.UserAgent, "ua", "", "User-Agent (alias)")
	cfg.RandomAgent = fs.Bool("random-agent", false, "Use random User-Agent")
	fs.BoolVar(cfg.RandomAgent, "ra", false, "Random agent (alias)")
	fs.Var(&cfg.Headers, "header", "Custom header (Name: Value) — repeatable")
	fs.Var(&cfg.Headers, "H", "Custom header (alias)")
	cfg.Cookies = fs.String("cookie", "", "Cookies to send")
	fs.StringVar(cfg.Cookies, "b", "", "Cookie (alias)")

	// Retries and error handling
	cfg.Retries = fs.Int("retries", 2, "Number of retries on failure")
	fs.IntVar(cfg.Retries, "r", 2, "Retries (alias)")
	cfg.MaxErrors = fs.Int("max-errors", 10, "Max errors before stopping scan")
	fs.IntVar(cfg.MaxErrors, "me", 10, "Max errors (alias)")
	cfg.StopOnFirstVuln = fs.Bool("stop-on-first", false, "Stop scan on first vulnerability")
	fs.BoolVar(cfg.StopOnFirstVuln, "sof", false, "Stop on first (alias)")

	// Resume and checkpointing
	cfg.Resume = fs.Bool("resume", false, "Resume from previous checkpoint")
	cfg.CheckpointFile = fs.String("checkpoint", "", "Checkpoint file for resume")
	fs.StringVar(cfg.CheckpointFile, "cp", "", "Checkpoint (alias)")

	// Scope control
	cfg.ExcludeTypes = fs.String("exclude-types", "", "Exclude scan types (comma-separated)")
	fs.StringVar(cfg.ExcludeTypes, "et", "", "Exclude types (alias)")
	cfg.ExcludePatterns = fs.String("exclude-patterns", "", "Exclude URL patterns (regex)")
	fs.StringVar(cfg.ExcludePatterns, "ep", "", "Exclude patterns (alias)")
	cfg.IncludePatterns = fs.String("include-patterns", "", "Include only matching URL patterns (regex)")
	fs.StringVar(cfg.IncludePatterns, "ip", "", "Include patterns (alias)")

	// Reporting
	cfg.ReportTitle = fs.String("report-title", "", "Custom report title")
	cfg.ReportAuthor = fs.String("report-author", "", "Report author name")
	cfg.IncludeEvidence = fs.Bool("include-evidence", true, "Include evidence in report")
	fs.BoolVar(cfg.IncludeEvidence, "ie", true, "Include evidence (alias)")
	cfg.IncludeRemediation = fs.Bool("include-remediation", true, "Include remediation advice")
	fs.BoolVar(cfg.IncludeRemediation, "ir", true, "Include remediation (alias)")

	// Advanced options
	cfg.FollowRedirects = fs.Bool("follow-redirects", true, "Follow HTTP redirects")
	fs.BoolVar(cfg.FollowRedirects, "fr", true, "Follow redirects (alias)")
	cfg.MaxRedirects = fs.Int("max-redirects", 10, "Max redirects to follow")
	cfg.RespectRobots = fs.Bool("respect-robots", false, "Respect robots.txt")
	fs.BoolVar(cfg.RespectRobots, "rr", false, "Respect robots (alias)")
	cfg.DryRun = fs.Bool("dry-run", false, "Show what would be scanned without scanning")
	fs.BoolVar(cfg.DryRun, "dr", false, "Dry run (alias)")

	// Payload limits (useful for CI/CD and quick validation)
	cfg.MaxPayloads = fs.Int("max-payloads", 0, "Max payloads per parameter per scan type (0 = unlimited)")
	fs.IntVar(cfg.MaxPayloads, "mp", 0, "Max payloads (alias)")
	cfg.MaxParams = fs.Int("max-params", 0, "Max parameters to test per scan type (0 = unlimited)")

	// Debug and diagnostics
	cfg.Debug = fs.Bool("debug", false, "Enable debug output")
	cfg.DebugRequest = fs.Bool("debug-request", false, "Show request details")
	fs.BoolVar(cfg.DebugRequest, "dreq", false, "Debug request (alias)")
	cfg.DebugResponse = fs.Bool("debug-response", false, "Show response details")
	fs.BoolVar(cfg.DebugResponse, "dresp", false, "Debug response (alias)")
	cfg.Profile = fs.Bool("profile", false, "Enable CPU profiling")
	cfg.MemProfile = fs.Bool("mem-profile", false, "Enable memory profiling")

	// Streaming mode (CI-friendly output)
	cfg.StreamMode = fs.Bool("stream", false, "Streaming output mode for CI/scripts")

	// Timestamp output
	cfg.Timestamp = fs.Bool("ts", false, "Add timestamp to vulnerability output")
	fs.BoolVar(cfg.Timestamp, "timestamp", false, "Add timestamp to vulnerability output (alias)")

	// Detection (v2.5.2)
	cfg.NoDetect = fs.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	return fs, cfg
}

// validate checks flag values that must satisfy constraints and exits
// with an error message when a constraint is violated.
func (cfg *scanConfig) validate() {
	if *cfg.Concurrency < 1 {
		exitWithError("--concurrency must be at least 1, got %d", *cfg.Concurrency)
	}
	if *cfg.MaxPayloads < 0 {
		exitWithError("--max-payloads must be non-negative, got %d", *cfg.MaxPayloads)
	}
	if *cfg.MaxParams < 0 {
		exitWithError("--max-params must be non-negative, got %d", *cfg.MaxParams)
	}
	if *cfg.RateLimit < 0 {
		exitWithError("--rate-limit must be non-negative, got %d", *cfg.RateLimit)
	}
	if *cfg.MaxErrors < 1 {
		exitWithError("--max-errors must be at least 1, got %d", *cfg.MaxErrors)
	}
}

// mergeLegacyOutputFlags copies legacy shorthand flags into the unified
// OutputFlags struct for backward compatibility. Legacy flags take
// precedence only when the enterprise equivalent is at its zero value.
func (cfg *scanConfig) mergeLegacyOutputFlags() {
	if cfg.Out.OutputFile == "" && *cfg.OutputFile != "" {
		cfg.Out.OutputFile = *cfg.OutputFile
	}
	if !cfg.Out.JSONMode && *cfg.JSONOutput {
		cfg.Out.JSONMode = true
	}
	if cfg.Out.Format == "console" && *cfg.FormatType != "console" {
		cfg.Out.Format = *cfg.FormatType
	}
	if !cfg.Out.StreamMode && *cfg.StreamMode {
		cfg.Out.StreamMode = true
	}
	if *cfg.SARIFOutput && cfg.Out.SARIFExport == "" {
		cfg.Out.SARIFExport = "results.sarif"
	}
	if *cfg.MarkdownOutput && cfg.Out.MDExport == "" {
		cfg.Out.MDExport = "results.md"
	}
	if *cfg.HTMLOutput && cfg.Out.HTMLExport == "" {
		cfg.Out.HTMLExport = "results.html"
	}
	if *cfg.CSVOutput && cfg.Out.CSVExport == "" {
		cfg.Out.CSVExport = "results.csv"
	}
	if *cfg.Silent {
		cfg.Out.Silent = true
	}
	if *cfg.NoColor {
		cfg.Out.NoColor = true
	}
}
