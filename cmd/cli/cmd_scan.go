package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/waftester/waftester/pkg/api"
	"github.com/waftester/waftester/pkg/apifuzz"
	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/bizlogic"
	"github.com/waftester/waftester/pkg/cache"
	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/clickjack"
	"github.com/waftester/waftester/pkg/cmdi"
	"github.com/waftester/waftester/pkg/cors"
	"github.com/waftester/waftester/pkg/crlf"
	"github.com/waftester/waftester/pkg/csrf"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/deserialize"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/graphql"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/hostheader"
	"github.com/waftester/waftester/pkg/hpp"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/idor"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/jwt"
	"github.com/waftester/waftester/pkg/ldap"
	"github.com/waftester/waftester/pkg/lfi"
	"github.com/waftester/waftester/pkg/massassignment"
	"github.com/waftester/waftester/pkg/nosqli"
	"github.com/waftester/waftester/pkg/oauth"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/probes"
	"github.com/waftester/waftester/pkg/prototype"
	"github.com/waftester/waftester/pkg/race"
	"github.com/waftester/waftester/pkg/ratelimit"
	"github.com/waftester/waftester/pkg/rce"
	"github.com/waftester/waftester/pkg/redirect"
	"github.com/waftester/waftester/pkg/retry"
	"github.com/waftester/waftester/pkg/rfi"
	"github.com/waftester/waftester/pkg/smuggling"
	"github.com/waftester/waftester/pkg/sqli"
	"github.com/waftester/waftester/pkg/ssi"
	"github.com/waftester/waftester/pkg/ssrf"
	"github.com/waftester/waftester/pkg/ssti"
	"github.com/waftester/waftester/pkg/subtakeover"
	"github.com/waftester/waftester/pkg/templateresolver"
	"github.com/waftester/waftester/pkg/traversal"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/upload"
	"github.com/waftester/waftester/pkg/waf"
	"github.com/waftester/waftester/pkg/websocket"
	"github.com/waftester/waftester/pkg/xmlinjection"
	"github.com/waftester/waftester/pkg/xpath"
	"github.com/waftester/waftester/pkg/xss"
	"github.com/waftester/waftester/pkg/xxe"
)

// headerSlice implements flag.Value for repeated -H flags.
// Does not split on commas since header values may contain them.
type headerSlice []string

func (h *headerSlice) String() string { return strings.Join(*h, "; ") }

func (h *headerSlice) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// countingTransport wraps an http.RoundTripper and atomically increments
// a counter on every request. This feeds the LiveProgress rate display
// so it shows real HTTP req/s instead of 0.0/s while scanners run.
type countingTransport struct {
	inner   http.RoundTripper
	counter *int64
}

func (ct *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(ct.counter, 1)
	return ct.inner.RoundTrip(req)
}

// rateLimitTransport enforces a per-request rate limit at the HTTP
// transport level so all scanners share a single token bucket.
// This replaces the per-scanner-launch limiter that only gated scanner
// starts, not actual HTTP traffic.
type rateLimitTransport struct {
	inner   http.RoundTripper
	limiter *rate.Limiter
}

func (rt *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rt.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	return rt.inner.RoundTrip(req)
}

// tamperTransport applies WAF evasion tampers to every outgoing HTTP
// request via the tamper engine's TransformRequest method. This ensures
// all scanners benefit from --tamper/--tamper-auto without individual
// scanner changes.
type tamperTransport struct {
	inner  http.RoundTripper
	engine interface {
		TransformRequest(req *http.Request) *http.Request
	}
}

func (tt *tamperTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return tt.inner.RoundTrip(tt.engine.TransformRequest(req))
}

func runScan() {
	scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)

	// Output configuration (unified architecture - enterprise flags only)
	// Uses RegisterEnterpriseFlags to avoid conflicts with existing legacy flags
	var outFlags OutputFlags
	outFlags.RegisterEnterpriseFlags(scanFlags)
	outFlags.Version = ui.Version

	var cf CommonFlags
	cf.Register(scanFlags, 30)

	// API spec scanning flags
	var sf apispec.SpecFlags
	sf.Register(scanFlags)

	types := scanFlags.String("types", "all", "Scan types: all, or comma-separated (sqli,xss,traversal,cmdi,nosqli,hpp,crlf,prototype,cors,redirect,hostheader,websocket,cache,upload,deserialize,oauth,ssrf,ssti,xxe,smuggling,graphql,jwt,subtakeover,bizlogic,race,apifuzz,ldap,ssi,xpath,xmlinjection,rfi,lfi,rce,csrf,clickjack,idor,massassignment,wafdetect,waffprint,wafevasion,tlsprobe,httpprobe,secheaders,jsanalyze,apidepth,osint,vhost,techdetect,dnsrecon)")
	scanFlags.StringVar(types, "t", "all", "Scan types (alias)")
	concurrency := scanFlags.Int("concurrency", 5, "Concurrent scanners")
	outputFile := scanFlags.String("output", "", "Output results to JSON file")
	jsonOutput := scanFlags.Bool("json", false, "Output in JSON format")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := scanFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := scanFlags.String("smart-mode", "standard", "Smart mode type: quick, standard, full, bypass, stealth")
	smartVerbose := scanFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// Tamper scripts (70+ sqlmap-compatible WAF bypass transformations)
	tamperList := scanFlags.String("tamper", "", "Comma-separated tamper scripts: space2comment,randomcase,charencode")
	tamperAuto := scanFlags.Bool("tamper-auto", false, "Auto-select tampers based on detected WAF")
	tamperProfile := scanFlags.String("tamper-profile", "standard", "Tamper profile: stealth, standard, aggressive, bypass")
	tamperDir := scanFlags.String("tamper-dir", "", "Directory of .tengo script tampers to load")

	// OAuth-specific flags
	oauthClientID := scanFlags.String("oauth-client-id", "", "OAuth client ID for OAuth testing")
	oauthAuthEndpoint := scanFlags.String("oauth-auth-endpoint", "", "OAuth authorization endpoint")
	oauthTokenEndpoint := scanFlags.String("oauth-token-endpoint", "", "OAuth token endpoint")
	oauthRedirectURI := scanFlags.String("oauth-redirect-uri", "", "OAuth redirect URI")

	// === NEW SCAN FLAGS (42+ for 300+ total) ===

	// Rate limiting and throttling
	rateLimit := scanFlags.Int("rate-limit", 50, "Max requests per second")
	scanFlags.IntVar(rateLimit, "rl", 50, "Max requests per second (alias)")

	// Payload and template directories
	payloadDir := scanFlags.String("payloads", defaults.PayloadDir, "Payload directory")
	templateDir := scanFlags.String("template-dir", defaults.TemplateDir, "Nuclei template directory")
	rateLimitPerHost := scanFlags.Bool("rate-limit-per-host", false, "Apply rate limit per host")
	scanFlags.BoolVar(rateLimitPerHost, "rlph", false, "Rate limit per host (alias)")
	delay := scanFlags.Duration("delay", 0, "Delay between requests (e.g., 100ms, 1s)")
	jitter := scanFlags.Duration("jitter", 0, "Random jitter to add to delay")

	// Output formats
	formatType := scanFlags.String("format", "console", "Output format: console,json,jsonl,sarif,csv,md,html")
	sarifOutput := scanFlags.Bool("sarif", false, "Output in SARIF format for CI/CD")
	markdownOutput := scanFlags.Bool("md", false, "Output in Markdown format")
	htmlOutput := scanFlags.Bool("html", false, "Output in HTML format")
	csvOutput := scanFlags.Bool("csv", false, "Output in CSV format")
	silent := scanFlags.Bool("silent", false, "Silent mode - no progress output")
	scanFlags.BoolVar(silent, "s", false, "Silent mode (alias)")
	scanFlags.BoolVar(silent, "q", false, "Quiet mode (alias)")
	noColor := scanFlags.Bool("no-color", false, "Disable colored output")
	scanFlags.BoolVar(noColor, "nc", false, "No color (alias)")

	// Filtering and matching
	matchSeverity := scanFlags.String("match-severity", "", "Match findings by severity (critical,high,medium,low)")
	scanFlags.StringVar(matchSeverity, "msev", "", "Match severity (alias)")
	filterSeverity := scanFlags.String("filter-severity", "", "Filter findings by severity")
	scanFlags.StringVar(filterSeverity, "fsev", "", "Filter severity (alias)")
	matchCategory := scanFlags.String("match-category", "", "Match findings by category")
	scanFlags.StringVar(matchCategory, "mcat", "", "Match category (alias)")
	filterCategory := scanFlags.String("filter-category", "", "Filter findings by category")
	scanFlags.StringVar(filterCategory, "fcat", "", "Filter category (alias)")

	// Network options
	proxy := scanFlags.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	scanFlags.StringVar(proxy, "x", "", "Proxy (alias)")
	userAgent := scanFlags.String("user-agent", "", "Custom User-Agent (default: waftester/VERSION)")
	scanFlags.StringVar(userAgent, "ua", "", "User-Agent (alias)")
	randomAgent := scanFlags.Bool("random-agent", false, "Use random User-Agent")
	scanFlags.BoolVar(randomAgent, "ra", false, "Random agent (alias)")
	var headerFlags headerSlice
	scanFlags.Var(&headerFlags, "header", "Custom header (Name: Value) — repeatable")
	scanFlags.Var(&headerFlags, "H", "Custom header (alias)")
	cookies := scanFlags.String("cookie", "", "Cookies to send")
	scanFlags.StringVar(cookies, "b", "", "Cookie (alias)")

	// Retries and error handling
	retries := scanFlags.Int("retries", 2, "Number of retries on failure")
	scanFlags.IntVar(retries, "r", 2, "Retries (alias)")
	maxErrors := scanFlags.Int("max-errors", 10, "Max errors before stopping scan")
	scanFlags.IntVar(maxErrors, "me", 10, "Max errors (alias)")
	stopOnFirstVuln := scanFlags.Bool("stop-on-first", false, "Stop scan on first vulnerability")
	scanFlags.BoolVar(stopOnFirstVuln, "sof", false, "Stop on first (alias)")

	// Resume and checkpointing
	resume := scanFlags.Bool("resume", false, "Resume from previous checkpoint")
	checkpointFile := scanFlags.String("checkpoint", "", "Checkpoint file for resume")
	scanFlags.StringVar(checkpointFile, "cp", "", "Checkpoint (alias)")

	// Scope control
	excludeTypes := scanFlags.String("exclude-types", "", "Exclude scan types (comma-separated)")
	scanFlags.StringVar(excludeTypes, "et", "", "Exclude types (alias)")
	excludePatterns := scanFlags.String("exclude-patterns", "", "Exclude URL patterns (regex)")
	scanFlags.StringVar(excludePatterns, "ep", "", "Exclude patterns (alias)")
	includePatterns := scanFlags.String("include-patterns", "", "Include only matching URL patterns (regex)")
	scanFlags.StringVar(includePatterns, "ip", "", "Include patterns (alias)")

	// Reporting
	reportTitle := scanFlags.String("report-title", "", "Custom report title")
	reportAuthor := scanFlags.String("report-author", "", "Report author name")
	includeEvidence := scanFlags.Bool("include-evidence", true, "Include evidence in report")
	scanFlags.BoolVar(includeEvidence, "ie", true, "Include evidence (alias)")
	includeRemediation := scanFlags.Bool("include-remediation", true, "Include remediation advice")
	scanFlags.BoolVar(includeRemediation, "ir", true, "Include remediation (alias)")

	// Advanced options
	followRedirects := scanFlags.Bool("follow-redirects", true, "Follow HTTP redirects")
	scanFlags.BoolVar(followRedirects, "fr", true, "Follow redirects (alias)")
	maxRedirects := scanFlags.Int("max-redirects", 10, "Max redirects to follow")
	respectRobots := scanFlags.Bool("respect-robots", false, "Respect robots.txt")
	scanFlags.BoolVar(respectRobots, "rr", false, "Respect robots (alias)")
	dryRun := scanFlags.Bool("dry-run", false, "Show what would be scanned without scanning")
	scanFlags.BoolVar(dryRun, "dr", false, "Dry run (alias)")

	// Payload limits (useful for CI/CD and quick validation)
	maxPayloads := scanFlags.Int("max-payloads", 0, "Max payloads per parameter per scan type (0 = unlimited)")
	scanFlags.IntVar(maxPayloads, "mp", 0, "Max payloads (alias)")
	maxParams := scanFlags.Int("max-params", 0, "Max parameters to test per scan type (0 = unlimited)")

	// Debug and diagnostics
	debug := scanFlags.Bool("debug", false, "Enable debug output")
	debugRequest := scanFlags.Bool("debug-request", false, "Show request details")
	scanFlags.BoolVar(debugRequest, "dreq", false, "Debug request (alias)")
	debugResponse := scanFlags.Bool("debug-response", false, "Show response details")
	scanFlags.BoolVar(debugResponse, "dresp", false, "Debug response (alias)")
	profile := scanFlags.Bool("profile", false, "Enable CPU profiling")
	memProfile := scanFlags.Bool("mem-profile", false, "Enable memory profiling")

	// Streaming mode (CI-friendly output)
	streamMode := scanFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	// Detection (v2.5.2)
	noDetect := scanFlags.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	scanFlags.Parse(os.Args[2:])

	// Resolve nuclei template directory: if the default path doesn't exist
	// on disk, extract embedded templates to a temp directory.
	resolvedTemplateDir, resolveErr := templateresolver.ResolveNucleiDir(*templateDir)
	if resolveErr == nil {
		*templateDir = resolvedTemplateDir
	}

	// Disable detection if requested
	if *noDetect {
		detection.Disable()
	}

	// Merge legacy output flags into outFlags (backward compatibility)
	// Legacy flags take precedence only if outFlags equivalents are empty
	if outFlags.OutputFile == "" && *outputFile != "" {
		outFlags.OutputFile = *outputFile
	}
	if !outFlags.JSONMode && *jsonOutput {
		outFlags.JSONMode = true
	}
	if outFlags.Format == "console" && *formatType != "console" {
		outFlags.Format = *formatType
	}
	if !outFlags.StreamMode && *streamMode {
		outFlags.StreamMode = true
	}
	if *sarifOutput && outFlags.SARIFExport == "" {
		outFlags.SARIFExport = "results.sarif"
	}
	if *markdownOutput && outFlags.MDExport == "" {
		outFlags.MDExport = "results.md"
	}
	if *htmlOutput && outFlags.HTMLExport == "" {
		outFlags.HTMLExport = "results.html"
	}
	if *csvOutput && outFlags.CSVExport == "" {
		outFlags.CSVExport = "results.csv"
	}
	if *silent {
		outFlags.Silent = true
	}
	if *noColor {
		outFlags.NoColor = true
	}

	// Apply UI settings from unified output flags
	outFlags.ApplyUISettings()

	// Check if we're in streaming JSON mode (suppress UI output)
	streamJSON := outFlags.StreamMode && (outFlags.JSONMode || outFlags.Format == "json" || outFlags.Format == "jsonl")

	// Print banner unless in streaming JSON mode or suppressed by outFlags
	if !streamJSON && !outFlags.ShouldSuppressBanner() {
		ui.PrintCompactBanner()
		ui.PrintSection("Deep Vulnerability Scan")
	}

	// Apply debug mode
	if *debug || *debugRequest || *debugResponse {
		cf.Verbose = true // Debug implies verbose
	}

	// Handle CPU profiling
	if *profile {
		f, err := os.Create("cpu.prof")
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Could not create cpu.prof: %v", err))
		} else {
			if err := pprof.StartCPUProfile(f); err != nil {
				ui.PrintWarning(fmt.Sprintf("Could not start CPU profile: %v", err))
				f.Close()
			} else {
				defer func() {
					pprof.StopCPUProfile()
					f.Close()
					ui.PrintInfo("CPU profile written to cpu.prof")
				}()
			}
		}
	}

	// Handle memory profiling
	if *memProfile {
		defer func() {
			f, err := os.Create("mem.prof")
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Could not create mem.prof: %v", err))
				return
			}
			defer f.Close()
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				ui.PrintWarning(fmt.Sprintf("Could not write memory profile: %v", err))
				return
			}
			ui.PrintInfo("Memory profile written to mem.prof")
		}()
	}

	// Handle dry run mode
	if *dryRun {
		ui.PrintWarning("Dry run mode - showing what would be scanned")
	}

	// Handle resume from checkpoint
	if *resume {
		checkpointPath := *checkpointFile
		if checkpointPath == "" {
			checkpointPath = "scan-resume.cfg"
		}
		if _, err := os.Stat(checkpointPath); err == nil {
			ui.PrintInfo(fmt.Sprintf("Resuming from checkpoint: %s", checkpointPath))
		} else {
			ui.PrintWarning("No checkpoint file found, starting fresh")
		}
	}

	// Collect targets using shared TargetSource
	specCfg := sf.ToConfig()
	specMode := specCfg.HasSpec()

	var target string
	if specMode {
		// In spec mode, target comes from spec BaseURL or -u override.
		ts := cf.TargetSource()
		t, terr := ts.GetSingleTarget()
		if terr == nil {
			target = t
			specCfg.TargetOverride = t
		}
		// Target will be resolved from spec if not provided via -u.
	} else {
		ts := cf.TargetSource()
		var terr error
		target, terr = ts.GetSingleTarget()
		if terr != nil {
			ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
			os.Exit(1)
		}
	}

	// Setup context with timeout
	// Overall scan deadline: 60× per-request timeout (e.g., -timeout 30 → 30min scan deadline)
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	ctx, tCancel := context.WithTimeout(ctx, time.Duration(cf.Timeout)*time.Minute)
	defer tCancel()

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	scanID := fmt.Sprintf("scan-%d", time.Now().Unix())
	// Scan builds its own HAR from vulnerability findings via writeScanHAR.
	// Exclude HARExport from the dispatcher so it doesn't open the same file
	// (the dispatcher would write an empty HAR on Close, overwriting the real one).
	scanHARPath := outFlags.HARExport
	outFlags.HARExport = ""
	dispCtx, dispErr := outFlags.InitDispatcher(scanID, target)
	outFlags.HARExport = scanHARPath
	if dispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Output dispatcher warning: %v", dispErr))
	}
	if dispCtx != nil {
		defer dispCtx.Close()
		dispCtx.RegisterDetectionCallbacks(ctx)
		if !streamJSON {
			ui.PrintInfo("Real-time integrations enabled (hooks active)")
		}
		// Emit scan start event to hooks
		_ = dispCtx.EmitStart(ctx, target, 0, *concurrency, nil)
	}

	// Smart Mode: Detect WAF and optimize configuration
	var smartResult *SmartModeResult
	if *smartMode {
		ui.PrintSection("🧠 Smart Mode: WAF Detection & Optimization")
		fmt.Fprintln(os.Stderr)

		smartConfig := &SmartModeConfig{
			DetectionTimeout: time.Duration(cf.Timeout) * time.Second,
			Verbose:          *smartVerbose,
			Mode:             *smartModeType,
		}

		var detectErr error
		smartResult, detectErr = DetectAndOptimize(ctx, target, smartConfig)
		if detectErr != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", detectErr))
		}

		PrintSmartModeInfo(smartResult, *smartVerbose)

		// Apply WAF-optimized rate limit and concurrency
		// Only override if the user didn't explicitly set these flags
		if smartResult != nil && smartResult.WAFDetected {
			userSetRL := false
			userSetConc := false
			scanFlags.Visit(func(f *flag.Flag) {
				if f.Name == "rate-limit" || f.Name == "rl" {
					userSetRL = true
				}
				if f.Name == "concurrency" {
					userSetConc = true
				}
			})

			if !userSetRL && smartResult.RateLimit > 0 {
				ui.PrintInfo(fmt.Sprintf("📊 Rate limit: %.0f req/sec (WAF-optimized for %s)",
					smartResult.RateLimit, smartResult.VendorName))
				*rateLimit = int(smartResult.RateLimit)
			}
			if !userSetConc && smartResult.Concurrency > 0 {
				ui.PrintInfo(fmt.Sprintf("📊 Concurrency: %d workers (WAF-optimized)",
					smartResult.Concurrency))
				*concurrency = smartResult.Concurrency
			}

			// Emit smart mode WAF detection to hooks
			if dispCtx != nil {
				wafDesc := fmt.Sprintf("Smart mode detected: %s (%.0f%% confidence)", smartResult.VendorName, smartResult.Confidence*100)
				_ = dispCtx.EmitBypass(ctx, "smart-waf-detection", "info", target, wafDesc, 0)
				// Emit bypass hints as actionable intelligence
				for _, hint := range smartResult.BypassHints {
					_ = dispCtx.EmitBypass(ctx, "bypass-hint", "info", target, hint, 0)
				}
			}
		}
		fmt.Fprintln(os.Stderr)
	}
	// ═══════════════════════════════════════════════════════════════════════════
	// TAMPER ENGINE INITIALIZATION (Scan Command)
	// ═══════════════════════════════════════════════════════════════════════════
	var tamperEngine *tampers.Engine
	if *tamperList != "" || *tamperAuto || (*smartMode && smartResult != nil && smartResult.WAFDetected) {
		// Determine tamper profile
		profile := tampers.ProfileStandard
		switch *tamperProfile {
		case "stealth":
			profile = tampers.ProfileStealth
		case "aggressive":
			profile = tampers.ProfileAggressive
		case "bypass":
			profile = tampers.ProfileBypass
		}

		// If custom tamper list provided, use custom profile
		if *tamperList != "" {
			profile = tampers.ProfileCustom
		}

		// Get WAF vendor for intelligent selection
		wafVendor := ""
		if smartResult != nil && smartResult.WAFDetected {
			wafVendor = smartResult.VendorName
		}

		// Create tamper engine
		// Load script tampers from directory if specified
		if *tamperDir != "" {
			scripts, errs := tampers.LoadScriptDir(*tamperDir)
			for _, e := range errs {
				ui.PrintWarning(fmt.Sprintf("Script tamper: %v", e))
			}
			for _, st := range scripts {
				tampers.Register(st)
			}
			if len(scripts) > 0 {
				ui.PrintInfo(fmt.Sprintf("Loaded %d script tampers from %s", len(scripts), *tamperDir))
			}
		}

		tamperEngine = tampers.NewEngine(&tampers.EngineConfig{
			Profile:       profile,
			CustomTampers: tampers.ParseTamperList(*tamperList),
			WAFVendor:     wafVendor,
			EnableMetrics: true,
		})

		// Validate custom tampers if specified
		if *tamperList != "" {
			valid, invalid := tampers.ValidateTamperNames(tampers.ParseTamperList(*tamperList))
			if len(invalid) > 0 {
				ui.PrintWarning(fmt.Sprintf("Unknown tampers: %s", strings.Join(invalid, ", ")))
			}
			if len(valid) > 0 {
				ui.PrintInfo(fmt.Sprintf("🔧 Using %d custom tampers: %s", len(valid), strings.Join(valid, ", ")))
			}
		} else if *tamperAuto || (*smartMode && smartResult != nil && smartResult.WAFDetected) {
			selectedTampers := tamperEngine.GetSelectedTampers()
			ui.PrintInfo(fmt.Sprintf("🔧 Auto-selected %d tampers for %s: %s",
				len(selectedTampers), wafVendor, strings.Join(selectedTampers, ", ")))
		}
	}
	// Only print config to stdout if not in streaming JSON mode
	if !streamJSON {
		ui.PrintConfigLine("Target", target)
		ui.PrintConfigLine("Scan Types", *types)
		ui.PrintConfigLine("Timeout", fmt.Sprintf("%ds", cf.Timeout))
		ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
		if *smartMode {
			ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d req/sec (WAF-optimized)", *rateLimit))
		}
		fmt.Fprintln(os.Stderr)

		// Print output configuration if verbose
		if cf.Verbose {
			outFlags.PrintOutputConfig()
		}
	}

	// Parse scan types
	scanAll := *types == "all"
	typeSet := make(map[string]bool)
	if !scanAll {
		for _, t := range strings.Split(*types, ",") {
			typeSet[strings.TrimSpace(strings.ToLower(t))] = true
		}
	}

	// Parse excluded scan types
	excludeSet := make(map[string]bool)
	if *excludeTypes != "" {
		for _, t := range strings.Split(*excludeTypes, ",") {
			excludeSet[strings.TrimSpace(strings.ToLower(t))] = true
		}
	}

	shouldScan := func(name string) bool {
		if excludeSet[name] {
			return false
		}
		return scanAll || typeSet[name]
	}

	// Compile URL include/exclude patterns for scope control
	var includeRe, excludeRe *regexp.Regexp
	if *includePatterns != "" {
		var err error
		includeRe, err = regexp.Compile(*includePatterns)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Invalid --include-patterns regex: %v", err))
			if dispCtx != nil {
				_ = dispCtx.Close()
			}
			os.Exit(1)
		}
	}
	if *excludePatterns != "" {
		var err error
		excludeRe, err = regexp.Compile(*excludePatterns)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Invalid --exclude-patterns regex: %v", err))
			if dispCtx != nil {
				_ = dispCtx.Close()
			}
			os.Exit(1)
		}
	}

	// shouldScanURL returns false if the target URL is excluded by pattern flags.
	shouldScanURL := func(targetURL string) bool {
		if includeRe != nil && !includeRe.MatchString(targetURL) {
			return false
		}
		if excludeRe != nil && excludeRe.MatchString(targetURL) {
			return false
		}
		return true
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// SPEC-DRIVEN SCAN PATH
	// When --spec is provided, load the spec, build a plan, and run scanners
	// against each endpoint. This is a separate flow from the normal scan.
	// Forward generic --dry-run to spec dry-run so both flags work.
	// ═══════════════════════════════════════════════════════════════════════════
	if specMode {
		if *dryRun {
			specCfg.DryRun = true
		}
		runSpecScan(ctx, specCfg, &cf, &outFlags, shouldScan, target, *concurrency, *rateLimit, *proxy, streamJSON, dispCtx)
		return
	}

	// Dry run mode - list what would be scanned and exit
	if *dryRun {
		allScanTypes := []string{"sqli", "xss", "traversal", "cmdi", "nosqli", "hpp", "crlf", "prototype", "cors", "redirect", "hostheader", "websocket", "cache", "upload", "deserialize", "oauth", "ssrf", "ssti", "xxe", "smuggling", "graphql", "jwt", "subtakeover", "bizlogic", "race", "apifuzz", "ldap", "ssi", "xpath", "xmlinjection", "rfi", "lfi", "rce", "csrf", "clickjack", "idor", "massassignment", "wafdetect", "waffprint", "wafevasion", "tlsprobe", "httpprobe", "secheaders", "jsanalyze", "apidepth", "osint", "vhost", "techdetect", "dnsrecon"}

		var selectedScans []string
		for _, t := range allScanTypes {
			if shouldScan(t) {
				selectedScans = append(selectedScans, t)
			}
		}

		ui.PrintSection("Dry Run Mode")
		ui.PrintInfo(fmt.Sprintf("Would execute %d scan types against %s:", len(selectedScans), target))
		fmt.Fprintln(os.Stderr)
		for _, s := range selectedScans {
			fmt.Fprintf(os.Stderr, "  %s %s\n", ui.Icon("•", "-"), s)
		}
		fmt.Fprintln(os.Stderr)
		ui.PrintHelp("Remove -dry-run flag to execute scans")
		if dispCtx != nil {
			_ = dispCtx.Close()
		}
		os.Exit(0)
	}

	// Build HTTP client using shared factory (DNS cache, HTTP/2, sockopt, detection wrapper)
	httpCfg := httpclient.FuzzingConfig()
	httpCfg.InsecureSkipVerify = cf.SkipVerify
	httpCfg.MaxConnsPerHost = *concurrency
	httpCfg.MaxIdleConns = *concurrency * 2
	if *proxy != "" {
		httpCfg.Proxy = *proxy
	}
	httpClient := httpclient.New(httpCfg)
	httpClient.Timeout = time.Duration(cf.Timeout) * time.Second

	// Wrap transport with a request counter so the progress display
	// can show a meaningful per-second rate instead of 0.0/s while
	// a single long-running scanner type is active.
	var httpReqCount int64
	httpClient.Transport = &countingTransport{
		inner:   httpClient.Transport,
		counter: &httpReqCount,
	}

	// Layer rate-limit enforcement at the HTTP transport level so every
	// scanner request obeys --rate-limit, not just scanner launches.
	if *rateLimit > 0 {
		httpClient.Transport = &rateLimitTransport{
			inner:   httpClient.Transport,
			limiter: rate.NewLimiter(rate.Limit(*rateLimit), *rateLimit),
		}
	}

	// Layer tamper engine on the transport so --tamper/--tamper-auto
	// apply WAF evasion transformations to every outgoing request.
	if tamperEngine != nil {
		httpClient.Transport = &tamperTransport{
			inner:  httpClient.Transport,
			engine: tamperEngine,
		}
	}

	// Determine user agent
	effectiveUserAgent := *userAgent
	if effectiveUserAgent == "" {
		effectiveUserAgent = ui.UserAgent()
	}
	if *randomAgent {
		userAgents := []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		}
		effectiveUserAgent = userAgents[time.Now().UnixNano()%int64(len(userAgents))]
	}

	// Build custom headers map
	customHeaders := make(map[string]string)
	for _, h := range headerFlags {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	customHeaders["User-Agent"] = effectiveUserAgent
	if *cookies != "" {
		customHeaders["Cookie"] = *cookies
	}

	// Configure redirect policy
	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if *followRedirects {
			if len(via) >= *maxRedirects {
				return fmt.Errorf("stopped after %d redirects", *maxRedirects)
			}
			return nil
		}
		return http.ErrUseLastResponse
	}
	httpClient.CheckRedirect = redirectPolicy

	result := &ScanResult{
		Target:     target,
		StartTime:  time.Now(),
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
	}

	// Respect robots.txt: fetch disallowed paths and block the scan if the
	// target path is disallowed. We do this once, before launching scanners.
	if *respectRobots {
		es := discovery.NewExternalSources(time.Duration(cf.Timeout)*time.Second, effectiveUserAgent)
		robotsResult, err := es.ParseRobotsTxt(ctx, target)
		if err == nil && robotsResult != nil {
			parsedTarget, _ := url.Parse(target)
			targetPath := "/"
			if parsedTarget != nil && parsedTarget.Path != "" {
				targetPath = parsedTarget.Path
			}
			for _, disallowed := range robotsResult.DisallowedPaths {
				// Path-segment-aware match: /admin must not match
				// /administrator. A disallowed path matches when the
				// target equals it exactly, or is a sub-path (next
				// char is '/').
				if targetPath == disallowed ||
					(strings.HasPrefix(targetPath, disallowed) &&
						(strings.HasSuffix(disallowed, "/") || targetPath[len(disallowed)] == '/')) {
					ui.PrintWarning(fmt.Sprintf("Target path %q is disallowed by robots.txt (matched %q) — skipping scan", targetPath, disallowed))
					if dispCtx != nil {
						_ = dispCtx.Close()
					}
					os.Exit(0)
				}
			}
			if cf.Verbose {
				ui.PrintInfo(fmt.Sprintf("robots.txt: %d disallowed paths checked, target path allowed", len(robotsResult.DisallowedPaths)))
			}
		} else if err != nil && cf.Verbose {
			ui.PrintWarning(fmt.Sprintf("Could not fetch robots.txt: %v (continuing scan)", err))
		}
	}

	// Check URL include/exclude patterns against the target
	if !shouldScanURL(target) {
		ui.PrintWarning("Target URL excluded by --include-patterns / --exclude-patterns")
		if dispCtx != nil {
			_ = dispCtx.Close()
		}
		os.Exit(0)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *concurrency)

	// Clamp rate limit to minimum of 1 (0 or negative would block forever)
	if *rateLimit < 1 {
		*rateLimit = 1
	}

	// Create per-host rate limiter when --rate-limit-per-host is set.
	// Global rate limiting is enforced at the HTTP transport level via
	// rateLimitTransport, so no standalone scanLimiter is needed.
	var perHostLimiter *ratelimit.Limiter
	if *rateLimitPerHost {
		perHostLimiter = ratelimit.New(&ratelimit.Config{
			RequestsPerSecond: *rateLimit,
			PerHost:           true,
			Burst:             *rateLimit,
		})
	}

	// stopOnFirst: shared flag and sync.Once to cancel context on first vuln
	var foundVuln int32 // atomic; 1 = at least one vuln found

	// Progress tracking
	var totalScans int32
	var scanErrors int32
	scanMaxErrors := int32(*maxErrors)
	var scanTimings sync.Map // map[string]time.Duration

	// Count total scans first — must match every runScanner() call below
	allScanTypes := []string{"sqli", "xss", "traversal", "cmdi", "nosqli", "hpp", "crlf", "prototype", "cors", "redirect", "hostheader", "websocket", "cache", "upload", "deserialize", "oauth", "ssrf", "ssti", "xxe", "smuggling", "graphql", "jwt", "subtakeover", "bizlogic", "race", "apifuzz", "ldap", "ssi", "xpath", "xmlinjection", "rfi", "lfi", "rce", "csrf", "clickjack", "idor", "massassignment", "wafdetect", "waffprint", "wafevasion", "tlsprobe", "httpprobe", "secheaders", "jsanalyze", "apidepth", "osint", "vhost", "techdetect", "dnsrecon"}
	for _, t := range allScanTypes {
		if shouldScan(t) {
			atomic.AddInt32(&totalScans, 1)
		}
	}

	// Determine output mode for progress
	outputMode := ui.DefaultOutputMode()
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}
	if *silent {
		outputMode = ui.OutputModeSilent
	}

	// Live progress display using unified LiveProgress
	// Build tips relevant to the scan types being run
	scanTips := buildScanTips(shouldScan)

	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        int(totalScans),
		DisplayLines: 4,
		Title:        "Deep Vulnerability Scan",
		Unit:         "scans",
		Mode:         outputMode,
		RateSource:   &httpReqCount,
		Metrics: []ui.MetricConfig{
			{Name: "vulns", Label: "Vulns", Icon: ui.Icon("🚨", "!"), Highlight: true},
		},
		Tips:           scanTips,
		StreamFormat:   "[PROGRESS] {completed}/{total} ({percent}%) | vulns: {metric:vulns} | active: {status} | {elapsed}",
		StreamInterval: duration.StreamStd,
	})
	progress.Start()
	defer progress.Stop()

	// Streaming JSON event emitter for real-time output
	// Also dispatches to hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
	var eventMu sync.Mutex
	emitEvent := func(eventType string, data interface{}) {
		// Always dispatch to hooks if dispatcher is available
		if dispCtx != nil {
			dataMap, ok := data.(map[string]interface{})
			if ok && eventType == "vulnerability" {
				category, _ := dataMap["category"].(string)
				// Use fmt.Sprintf instead of .(string) type assertion because
				// the map value is finding.Severity (a named string type),
				// and Go type assertions distinguish named types from string.
				severity := fmt.Sprintf("%v", dataMap["severity"])
				// Try payload first, then fallback to type, parameter, or endpoint for description
				payload, _ := dataMap["payload"].(string)
				if payload == "" {
					if vulnType, ok := dataMap["type"].(string); ok {
						payload = vulnType
					}
				}
				if payload == "" {
					if param, ok := dataMap["parameter"].(string); ok {
						payload = "parameter: " + param
					}
				}
				if payload == "" {
					if endpoint, ok := dataMap["endpoint"].(string); ok {
						payload = "endpoint: " + endpoint
					}
				}
				// Dispatch bypass event to all hooks (Slack, Teams, PagerDuty, OTEL, etc.)
				_ = dispCtx.EmitBypass(ctx, category, severity, target, payload, 200)
			}
		}

		// JSON streaming output (only if streamJSON mode)
		if !streamJSON {
			return
		}
		eventMu.Lock()
		defer eventMu.Unlock()
		event := map[string]interface{}{
			"type":      eventType,
			"timestamp": time.Now().Format(time.RFC3339),
			"data":      data,
		}
		eventData, _ := json.Marshal(event)
		fmt.Println(string(eventData)) // debug:keep
	}

	// Emit scan start event
	emitEvent("scan_start", map[string]interface{}{
		"target":      target,
		"scan_types":  allScanTypes,
		"concurrency": *concurrency,
	})

	// Extract host from target URL for detection checks
	targetURL, _ := url.Parse(target)
	targetHost := targetURL.Host

	// checkStopOnFirst cancels the scan context when --stop-on-first is set
	// and vulns have been recorded. Called after each scanner completes.
	checkStopOnFirst := func() {
		if !*stopOnFirstVuln {
			return
		}
		mu.Lock()
		hasVulns := result.TotalVulns > 0
		mu.Unlock()
		if hasVulns {
			if atomic.CompareAndSwapInt32(&foundVuln, 0, 1) {
				emitEvent("scan_stopped", map[string]interface{}{
					"reason": "stop-on-first: vulnerability found",
				})
				cancel()
			}
		}
	}

	// Helper to run a scanner with progress tracking
	runScanner := func(name string, fn func()) {
		if !shouldScan(name) {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Stop-on-first: skip if a vuln was already found
			if *stopOnFirstVuln && atomic.LoadInt32(&foundVuln) == 1 {
				progress.Increment()
				return
			}

			// Enforce per-host rate limit when configured. Global request
			// rate limiting is handled at the HTTP transport level.
			if perHostLimiter != nil {
				if err := perHostLimiter.WaitForHost(ctx, targetHost); err != nil {
					progress.Increment()
					return
				}
			}

			// Apply inter-request delay + jitter if configured
			if *delay > 0 {
				d := *delay
				if *jitter > 0 {
					d += time.Duration(rand.Int63n(int64(*jitter)))
				}
				select {
				case <-ctx.Done():
					progress.Increment()
					return
				case <-time.After(d):
				}
			}

			// Check if host is blocked due to drops/bans or connectivity failures
			if skip, reason := detection.Default().ShouldSkipHost(targetHost); skip {
				emitEvent("scanner_skipped", map[string]interface{}{
					"scanner": name,
					"reason":  reason,
				})
				progress.Increment()
				return
			}
			if hosterrors.Check(target) {
				emitEvent("scanner_skipped", map[string]interface{}{
					"scanner": name,
					"reason":  "host error threshold exceeded",
				})
				progress.Increment()
				return
			}

			scanStart := time.Now()
			progress.SetStatus(name)

			// Wrap scanner execution with retry logic when --retries > 0.
			// Each scanner's fn() is idempotent (creates a fresh tester +
			// records results), so retrying on transient errors is safe.
			// We detect errors by checking if the global error counter
			// increased during the scanner's invocation.
			if *retries > 0 {
				retryCfg := retry.Config{
					MaxAttempts: *retries + 1, // retries flag = retry count, +1 for initial attempt
					InitDelay:   500 * time.Millisecond,
					MaxDelay:    5 * time.Second,
					Strategy:    retry.Exponential,
					Jitter:      true,
				}
				_ = retry.Do(ctx, retryCfg, func() error {
					before := atomic.LoadInt32(&scanErrors)
					fn()
					if atomic.LoadInt32(&scanErrors) > before {
						return fmt.Errorf("%s scan failed", name)
					}
					return nil
				})
			} else {
				fn()
			}

			checkStopOnFirst()

			elapsed := time.Since(scanStart)
			scanTimings.Store(name, elapsed)
			progress.Increment()
		}()
	}

	// scanError is a helper that logs scan errors and increments error counter.
	// Death-spiral protection: if too many scanners error, cancel remaining.
	scanError := func(scanner string, err error) {
		n := atomic.AddInt32(&scanErrors, 1)
		if cf.Verbose {
			ui.PrintWarning(fmt.Sprintf("%s scan error: %v", scanner, err))
		}
		if n >= scanMaxErrors {
			emitEvent("scan_aborted", map[string]interface{}{
				"reason":      fmt.Sprintf("max errors exceeded (%d/%d)", n, scanMaxErrors),
				"errors_seen": n,
			})
			cancel()
		}
	}

	timeoutDur := time.Duration(cf.Timeout) * time.Second

	// Shared callback for real-time vulnerability counting.
	// Scanners that support streaming call this per finding so the
	// progress display updates immediately instead of after Scan() returns.
	onVuln := func() {
		progress.AddMetric("vulns")
	}

	// baseConfig builds an attackconfig.Base with all CLI flags wired.
	// Every scanner using attackconfig.Base should call this instead of
	// constructing Base literals — ensures --user-agent, --header,
	// --cookie, --max-payloads, --max-params, --concurrency all work.
	baseConfig := func() attackconfig.Base {
		return attackconfig.Base{
			Timeout:              timeoutDur,
			UserAgent:            effectiveUserAgent,
			Client:               httpClient,
			MaxPayloads:          *maxPayloads,
			MaxParams:            *maxParams,
			Concurrency:          *concurrency,
			Headers:              customHeaders,
			OnVulnerabilityFound: onVuln,
		}
	}

	// SQL Injection Scanner
	runScanner("sqli", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{
				"scanner": "sqli",
				"vulns":   vulnCount,
			})
		}()

		cfg := &sqli.TesterConfig{
			Base: baseConfig(),
		}
		tester := sqli.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("SQLi", err)
			return
		}
		mu.Lock()
		result.SQLi = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["sqli"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				// Emit real-time event for each vulnerability
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "sqli",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
					"payload":   v.Payload,
				})
			}
		}
		mu.Unlock()
	})

	// XSS Scanner
	runScanner("xss", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "xss", "vulns": vulnCount})
		}()
		cfg := &xss.TesterConfig{
			Base: baseConfig(),
		}
		tester := xss.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("XSS", err)
			return
		}
		mu.Lock()
		result.XSS = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["xss"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "xss",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// Path Traversal Scanner
	runScanner("traversal", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "traversal", "vulns": vulnCount})
		}()
		cfg := &traversal.TesterConfig{
			Base: baseConfig(),
		}
		tester := traversal.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("Traversal", err)
			return
		}
		mu.Lock()
		result.Traversal = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["traversal"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "traversal",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// Command Injection Scanner
	runScanner("cmdi", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "cmdi", "vulns": vulnCount})
		}()
		cfg := &cmdi.TesterConfig{
			Base: baseConfig(),
		}
		tester := cmdi.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("CMDi", err)
			return
		}
		mu.Lock()
		result.CMDI = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["cmdi"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "cmdi",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// NoSQL Injection Scanner
	runScanner("nosqli", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "nosqli", "vulns": vulnCount})
		}()
		cfg := &nosqli.TesterConfig{
			Base: baseConfig(),
		}
		tester := nosqli.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("NoSQLi", err)
			return
		}
		mu.Lock()
		result.NoSQLi = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["nosqli"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "nosqli",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// HTTP Parameter Pollution Scanner
	runScanner("hpp", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "hpp", "vulns": vulnCount})
		}()
		cfg := &hpp.TesterConfig{
			Base: baseConfig(),
		}
		tester := hpp.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("HPP", err)
			return
		}
		mu.Lock()
		result.HPP = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["hpp"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "hpp",
					"severity":  v.Severity,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// CRLF Injection Scanner
	runScanner("crlf", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "crlf", "vulns": vulnCount})
		}()
		cfg := &crlf.TesterConfig{
			Base: baseConfig(),
		}
		tester := crlf.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("CRLF", err)
			return
		}
		mu.Lock()
		result.CRLF = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["crlf"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "crlf",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// Prototype Pollution Scanner
	runScanner("prototype", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "prototype", "vulns": vulnCount})
		}()
		cfg := &prototype.TesterConfig{
			Base: baseConfig(),
		}
		tester := prototype.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("Prototype", err)
			return
		}
		mu.Lock()
		result.Prototype = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["prototype"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "prototype",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// CORS Misconfiguration Scanner
	runScanner("cors", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "cors", "vulns": vulnCount})
		}()
		cfg := &cors.TesterConfig{
			Base: baseConfig(),
		}
		tester := cors.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("CORS", err)
			return
		}
		mu.Lock()
		result.CORS = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["cors"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "cors",
					"severity": v.Severity,
					"type":     v.Type,
					"origin":   v.TestedOrigin,
				})
			}
		}
		mu.Unlock()
	})

	// Open Redirect Scanner
	runScanner("redirect", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "redirect", "vulns": vulnCount})
		}()
		cfg := &redirect.TesterConfig{
			Base: baseConfig(),
		}
		tester := redirect.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("Redirect", err)
			return
		}
		mu.Lock()
		result.Redirect = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["redirect"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "redirect",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// Host Header Injection Scanner
	runScanner("hostheader", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "hostheader", "vulns": vulnCount})
		}()
		cfg := &hostheader.TesterConfig{
			Base: baseConfig(),
		}
		tester := hostheader.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("HostHeader", err)
			return
		}
		mu.Lock()
		result.HostHeader = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["hostheader"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "hostheader",
					"severity": v.Severity,
					"type":     v.Type,
					"header":   v.Header,
				})
			}
		}
		mu.Unlock()
	})

	// WebSocket Security Scanner
	runScanner("websocket", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "websocket", "vulns": vulnCount})
		}()
		cfg := &websocket.TesterConfig{
			Base: baseConfig(),
		}
		tester := websocket.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("WebSocket", err)
			return
		}
		mu.Lock()
		result.WebSocket = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["websocket"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "websocket",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// Cache Poisoning Scanner
	runScanner("cache", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "cache", "vulns": vulnCount})
		}()
		cfg := &cache.TesterConfig{
			Base: baseConfig(),
		}
		tester := cache.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("Cache", err)
			return
		}
		mu.Lock()
		result.Cache = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["cache"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "cache",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// File Upload Scanner - with dedicated timeout to prevent hanging
	runScanner("upload", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "upload", "vulns": vulnCount})
		}()
		// Create a dedicated context with 60s max timeout for upload scanning
		uploadCtx, uploadCancel := context.WithTimeout(ctx, duration.HTTPAPI)
		defer uploadCancel()

		cfg := &upload.TesterConfig{
			Base: baseConfig(),
		}
		tester := upload.NewTester(cfg)
		vulns, err := tester.Scan(uploadCtx, target)
		if err != nil {
			scanError("Upload", err)
			return
		}
		mu.Lock()
		result.Upload = vulns
		vulnCount = len(vulns)
		result.ByCategory["upload"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "upload",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// Deserialization Scanner
	runScanner("deserialize", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "deserialize", "vulns": vulnCount})
		}()
		cfg := &deserialize.TesterConfig{
			Base: baseConfig(),
		}
		tester := deserialize.NewTester(cfg)
		vulns, err := tester.Scan(ctx, target)
		if err != nil {
			scanError("Deserialization", err)
			return
		}
		mu.Lock()
		result.Deserialize = vulns
		vulnCount = len(vulns)
		result.ByCategory["deserialize"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "deserialize",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// OAuth/OIDC Scanner
	runScanner("oauth", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "oauth", "vulns": vulnCount})
		}()
		if *oauthAuthEndpoint == "" {
			if cf.Verbose {
				ui.PrintInfo("OAuth scan skipped: no -oauth-auth-endpoint provided")
			}
			return
		}
		cfg := &oauth.TesterConfig{
			Base: baseConfig(),
		}
		endpoints := &oauth.OAuthEndpoint{
			AuthorizationURL: *oauthAuthEndpoint,
			TokenURL:         *oauthTokenEndpoint,
		}
		oauthCfg := &oauth.OAuthConfig{
			ClientID:    *oauthClientID,
			RedirectURI: *oauthRedirectURI,
		}
		tester := oauth.NewTester(cfg, endpoints, oauthCfg)
		vulns, err := tester.Scan(ctx)
		if err != nil {
			scanError("OAuth", err)
			return
		}
		mu.Lock()
		result.OAuth = vulns
		vulnCount = len(vulns)
		result.ByCategory["oauth"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "oauth",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// SSRF Scanner
	runScanner("ssrf", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "ssrf", "vulns": vulnCount})
		}()
		cfg := ssrf.DefaultConfig()
		cfg.Base = baseConfig()
		detector := ssrf.NewDetector(cfg)
		scanResult, err := detector.Detect(ctx, target, "url")
		if err != nil {
			scanError("SSRF", err)
			return
		}
		mu.Lock()
		result.SSRF = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["ssrf"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "ssrf",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// SSTI Scanner
	runScanner("ssti", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "ssti", "vulns": vulnCount})
		}()
		cfg := &ssti.DetectorConfig{
			Base: baseConfig(),
		}
		detector := ssti.NewDetector(cfg)
		vulns, err := detector.Detect(ctx, target, "input")
		if err != nil {
			scanError("SSTI", err)
			return
		}
		mu.Lock()
		result.SSTI = vulns
		vulnCount = len(vulns)
		result.ByCategory["ssti"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "ssti",
				"severity":  v.Severity,
				"engine":    v.Engine,
				"parameter": v.Parameter,
			})
		}
		mu.Unlock()
	})

	// XXE Scanner
	runScanner("xxe", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "xxe", "vulns": vulnCount})
		}()
		cfg := xxe.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = baseConfig().HTTPHeader()
		detector := xxe.NewDetector(cfg)
		vulns, err := detector.Detect(ctx, target, "POST")
		if err != nil {
			scanError("XXE", err)
			return
		}
		mu.Lock()
		result.XXE = vulns
		vulnCount = len(vulns)
		result.ByCategory["xxe"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "xxe",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// HTTP Request Smuggling Scanner
	runScanner("smuggling", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "smuggling", "vulns": vulnCount})
		}()
		cfg := smuggling.DefaultConfig()
		cfg.Base = baseConfig()
		detector := smuggling.NewDetector(cfg)
		scanResult, err := detector.Detect(ctx, target)
		if err != nil {
			scanError("Smuggling", err)
			return
		}
		mu.Lock()
		result.Smuggling = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["smuggling"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[v.Severity]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "smuggling",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// GraphQL Security Scanner
	runScanner("graphql", func() {
		var vulnCount int
		var foundEndpoint string
		defer func() {
			data := map[string]interface{}{"scanner": "graphql", "vulns": vulnCount}
			if foundEndpoint != "" {
				data["endpoint"] = foundEndpoint
			}
			emitEvent("scan_complete", data)
		}()
		cfg := graphql.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = baseConfig().HTTPHeader()
		// Attempt common GraphQL endpoints
		graphqlEndpoints := []string{
			target + "/graphql",
			target + "/api/graphql",
			target + "/v1/graphql",
			target + "/query",
		}
		for _, endpoint := range graphqlEndpoints {
			tester := graphql.NewTester(endpoint, cfg)
			scanResult, err := tester.FullScan(ctx)
			if err == nil && scanResult != nil && len(scanResult.Vulnerabilities) > 0 {
				mu.Lock()
				result.GraphQL = scanResult
				vulnCount = len(scanResult.Vulnerabilities)
				foundEndpoint = endpoint
				result.ByCategory["graphql"] = vulnCount
				result.TotalVulns += vulnCount
				// Vulns metric updated in real-time via OnVulnerabilityFound callback
				for _, v := range scanResult.Vulnerabilities {
					result.BySeverity[string(v.Severity)]++
					emitEvent("vulnerability", map[string]interface{}{
						"category": "graphql",
						"severity": v.Severity,
						"type":     v.Type,
					})
				}
				mu.Unlock()
				return
			}
		}
		if cf.Verbose {
			ui.PrintInfo("No GraphQL endpoint found or no vulnerabilities detected")
		}
	})

	// JWT Security Scanner
	runScanner("jwt", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "jwt", "vulns": vulnCount})
		}()
		scanner := jwt.NewScanner(jwt.Config{
			Base: baseConfig(),
		})
		scanResult, err := scanner.Scan(ctx, target)
		if err != nil {
			scanError("JWT", err)
			return
		}
		mu.Lock()
		result.JWT = scanResult.Vulnerabilities
		vulnCount = len(scanResult.Vulnerabilities)
		result.ByCategory["jwt"] = vulnCount
		result.TotalVulns += vulnCount
		for _, v := range scanResult.Vulnerabilities {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "jwt",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// Subdomain Takeover Scanner
	runScanner("subtakeover", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "subtakeover", "vulns": vulnCount})
		}()
		cfg := &subtakeover.TesterConfig{
			Base:        baseConfig(),
			CheckHTTP:   true,
			FollowCNAME: true,
		}
		tester := subtakeover.NewTester(cfg)
		// Extract domain from target URL
		u, err := url.Parse(target)
		if err != nil {
			if cf.Verbose {
				ui.PrintWarning(fmt.Sprintf("Subtakeover: invalid URL: %v", err))
			}
			return
		}
		scanResult, err := tester.CheckSubdomain(ctx, u.Host)
		if err != nil {
			scanError("Subtakeover", err)
			return
		}
		mu.Lock()
		if scanResult != nil && scanResult.IsVulnerable {
			result.Subtakeover = append(result.Subtakeover, *scanResult)
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["subtakeover"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "subtakeover",
					"severity": v.Severity,
					"type":     v.Type,
					"domain":   u.Host,
				})
			}
		}
		mu.Unlock()
	})

	// Business Logic Scanner
	runScanner("bizlogic", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "bizlogic", "vulns": vulnCount})
		}()
		cfg := bizlogic.DefaultConfig()
		cfg.Base = baseConfig()
		tester := bizlogic.NewTester(cfg)
		// Test common business logic vulnerabilities
		vulns, err := tester.Scan(ctx, target, []string{"/", "/api", "/admin", "/user", "/account"})
		if err != nil {
			scanError("BizLogic", err)
			return
		}
		mu.Lock()
		result.BizLogic = vulns
		vulnCount = len(vulns)
		result.ByCategory["bizlogic"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "bizlogic",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// Race Condition Scanner
	runScanner("race", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "race", "vulns": vulnCount})
		}()
		cfg := race.DefaultConfig()
		cfg.Base = baseConfig()
		tester := race.NewTester(cfg)
		// Test common race condition scenarios
		reqCfg := &race.RequestConfig{
			Method: "POST",
			URL:    target,
			Body:   "",
		}
		scanResult, err := tester.Scan(ctx, reqCfg)
		if err != nil {
			scanError("Race", err)
			return
		}
		mu.Lock()
		result.Race = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["race"] = vulnCount
			result.TotalVulns += vulnCount
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "race",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// API Fuzzing Scanner
	runScanner("apifuzz", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "apifuzz", "vulns": vulnCount})
		}()
		cfg := apifuzz.DefaultConfig()
		cfg.Base = baseConfig()
		tester := apifuzz.NewTester(cfg)
		// Define basic endpoints to fuzz
		endpoints := []apifuzz.Endpoint{
			{Path: "/api", Method: "GET", Parameters: []apifuzz.Parameter{{Name: "id", Type: apifuzz.ParamString, In: "query"}}},
			{Path: "/api", Method: "POST", RequestBody: &apifuzz.RequestBody{ContentType: defaults.ContentTypeJSON, Required: true}},
		}
		vulns, err := tester.FuzzAPI(ctx, target, endpoints)
		if err != nil {
			scanError("APIFuzz", err)
			return
		}
		mu.Lock()
		result.APIFuzz = vulns
		vulnCount = len(vulns)
		result.ByCategory["apifuzz"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "apifuzz",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// LDAP Injection Scanner
	runScanner("ldap", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "ldap", "vulns": vulnCount})
		}()
		cfg := ldap.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := ldap.NewScanner(cfg)
		// Synthetic params for bare-URL mode (matching SSRF/SSTI pattern)
		params := map[string]string{"search": "test", "user": "admin", "filter": "test"}
		results, err := scanner.Scan(ctx, target, params)
		if err != nil {
			scanError("LDAP", err)
			return
		}
		mu.Lock()
		var vulnResults []ldap.Result
		for _, r := range results {
			if r.Vulnerable {
				vulnResults = append(vulnResults, r)
			}
		}
		result.LDAP = vulnResults
		vulnCount = len(vulnResults)
		result.ByCategory["ldap"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range vulnResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "ldap",
				"severity":  r.Severity,
				"parameter": r.Parameter,
				"payload":   r.Payload,
			})
		}
		mu.Unlock()
	})

	// SSI (Server-Side Include) Injection Scanner
	runScanner("ssi", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "ssi", "vulns": vulnCount})
		}()
		cfg := ssi.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := ssi.NewScanner(cfg)
		params := map[string]string{"input": "test", "page": "index", "file": "test"}
		results, err := scanner.Scan(ctx, target, params)
		if err != nil {
			scanError("SSI", err)
			return
		}
		mu.Lock()
		var vulnResults []ssi.Result
		for _, r := range results {
			if r.Vulnerable {
				vulnResults = append(vulnResults, r)
			}
		}
		result.SSI = vulnResults
		vulnCount = len(vulnResults)
		result.ByCategory["ssi"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range vulnResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "ssi",
				"severity":  r.Severity,
				"parameter": r.Parameter,
				"payload":   r.Payload,
			})
		}
		mu.Unlock()
	})

	// XPath Injection Scanner
	runScanner("xpath", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "xpath", "vulns": vulnCount})
		}()
		cfg := xpath.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := xpath.NewScanner(cfg)
		params := map[string]string{"search": "test", "query": "test", "id": "1"}
		results, err := scanner.Scan(ctx, target, params)
		if err != nil {
			scanError("XPath", err)
			return
		}
		mu.Lock()
		var vulnResults []xpath.Result
		for _, r := range results {
			if r.Vulnerable {
				vulnResults = append(vulnResults, r)
			}
		}
		result.XPath = vulnResults
		vulnCount = len(vulnResults)
		result.ByCategory["xpath"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range vulnResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "xpath",
				"severity":  r.Severity,
				"parameter": r.Parameter,
				"payload":   r.Payload,
			})
		}
		mu.Unlock()
	})

	// XML Injection Scanner
	runScanner("xmlinjection", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "xmlinjection", "vulns": vulnCount})
		}()
		cfg := xmlinjection.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := xmlinjection.NewScanner(cfg)
		results, err := scanner.Scan(ctx, target)
		if err != nil {
			scanError("XMLInjection", err)
			return
		}
		mu.Lock()
		var vulnResults []xmlinjection.Result
		for _, r := range results {
			if r.Vulnerable {
				vulnResults = append(vulnResults, r)
			}
		}
		result.XMLInjection = vulnResults
		vulnCount = len(vulnResults)
		result.ByCategory["xmlinjection"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range vulnResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "xmlinjection",
				"severity": r.Severity,
				"type":     r.PayloadType,
			})
		}
		mu.Unlock()
	})

	// Remote File Inclusion Scanner
	runScanner("rfi", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "rfi", "vulns": vulnCount})
		}()
		cfg := rfi.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := rfi.NewScanner(cfg)
		params := map[string]string{"file": "index", "page": "home", "path": "/tmp/test"}
		results, err := scanner.Scan(ctx, target, params)
		if err != nil {
			scanError("RFI", err)
			return
		}
		mu.Lock()
		var vulnResults []rfi.Result
		for _, r := range results {
			if r.Vulnerable {
				vulnResults = append(vulnResults, r)
			}
		}
		result.RFI = vulnResults
		vulnCount = len(vulnResults)
		result.ByCategory["rfi"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range vulnResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "rfi",
				"severity":  r.Severity,
				"parameter": r.Parameter,
				"payload":   r.Payload,
			})
		}
		mu.Unlock()
	})

	// Local File Inclusion Scanner
	runScanner("lfi", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "lfi", "vulns": vulnCount})
		}()
		cfg := lfi.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := lfi.NewScanner(cfg)
		params := map[string]string{"file": "index", "page": "home", "path": "/tmp/test"}
		results, err := scanner.Scan(ctx, target, params)
		if err != nil {
			scanError("LFI", err)
			return
		}
		mu.Lock()
		var vulnResults []lfi.Result
		for _, r := range results {
			if r.Vulnerable {
				vulnResults = append(vulnResults, r)
			}
		}
		result.LFI = vulnResults
		vulnCount = len(vulnResults)
		result.ByCategory["lfi"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range vulnResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "lfi",
				"severity":  r.Severity,
				"parameter": r.Parameter,
				"payload":   r.Payload,
			})
		}
		mu.Unlock()
	})

	// Remote Code Execution Scanner
	runScanner("rce", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "rce", "vulns": vulnCount})
		}()
		cfg := rce.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := rce.NewScanner(cfg)
		params := map[string]string{"cmd": "test", "exec": "test", "input": "test"}
		results, err := scanner.Scan(ctx, target, params)
		if err != nil {
			scanError("RCE", err)
			return
		}
		mu.Lock()
		var vulnResults []rce.Result
		for _, r := range results {
			if r.Vulnerable {
				vulnResults = append(vulnResults, r)
			}
		}
		result.RCE = vulnResults
		vulnCount = len(vulnResults)
		result.ByCategory["rce"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range vulnResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "rce",
				"severity":  r.Severity,
				"parameter": r.Parameter,
				"type":      r.PayloadType,
			})
		}
		mu.Unlock()
	})

	// CSRF Scanner
	runScanner("csrf", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "csrf", "vulns": vulnCount})
		}()
		cfg := csrf.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := csrf.NewScanner(cfg)
		csrfResult, err := scanner.Scan(ctx, target, "POST")
		if err != nil {
			scanError("CSRF", err)
			return
		}
		mu.Lock()
		if csrfResult.Vulnerable {
			result.CSRF = &csrfResult
			vulnCount = 1
			result.ByCategory["csrf"] = 1
			result.TotalVulns++
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			result.BySeverity[string(csrfResult.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "csrf",
				"severity": csrfResult.Severity,
				"evidence": csrfResult.Evidence,
			})
		}
		mu.Unlock()
	})

	// Clickjacking Scanner
	runScanner("clickjack", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "clickjack", "vulns": vulnCount})
		}()
		cfg := clickjack.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := clickjack.NewScanner(cfg)
		clickResult, err := scanner.Scan(ctx, target)
		if err != nil {
			scanError("Clickjack", err)
			return
		}
		mu.Lock()
		if clickResult.Vulnerable {
			result.Clickjack = &clickResult
			vulnCount = 1
			result.ByCategory["clickjack"] = 1
			result.TotalVulns++
			// Vulns metric updated in real-time via OnVulnerabilityFound callback
			result.BySeverity[string(clickResult.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":        "clickjack",
				"severity":        clickResult.Severity,
				"x_frame_options": clickResult.XFrameOptions,
			})
		}
		mu.Unlock()
	})

	// IDOR Scanner
	runScanner("idor", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "idor", "vulns": vulnCount})
		}()
		cfg := idor.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		cfg.BaseURL = target
		scanner := idor.NewScanner(cfg)
		// Test common endpoints for IDOR
		endpoints := []struct{ path, method string }{
			{"/api/users/1", "GET"},
			{"/api/accounts/1", "GET"},
			{"/api/orders/1", "GET"},
			{"/user/1", "GET"},
			{"/account/1", "GET"},
		}
		var allResults []idor.Result
		for _, ep := range endpoints {
			results, err := scanner.ScanEndpoint(ctx, ep.path, ep.method)
			if err != nil {
				continue
			}
			for _, r := range results {
				if r.Accessible {
					allResults = append(allResults, r)
				}
			}
		}
		mu.Lock()
		result.IDOR = allResults
		vulnCount = len(allResults)
		result.ByCategory["idor"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range allResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "idor",
				"severity": r.Severity,
				"endpoint": r.URL,
				"method":   r.Method,
			})
		}
		mu.Unlock()
	})

	// Mass Assignment Scanner
	runScanner("massassignment", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "massassignment", "vulns": vulnCount})
		}()
		cfg := massassignment.DefaultConfig()
		cfg.Base = baseConfig()
		cfg.Headers = customHeaders
		scanner := massassignment.NewScanner(cfg)
		// Empty baseline — scanner will test with DangerousParameters() against the endpoint
		originalData := map[string]interface{}{"name": "test", "email": "test@example.com"}
		results, err := scanner.Scan(ctx, target, originalData)
		if err != nil {
			scanError("MassAssignment", err)
			return
		}
		mu.Lock()
		var vulnResults []massassignment.Result
		for _, r := range results {
			if r.Vulnerable {
				vulnResults = append(vulnResults, r)
			}
		}
		result.MassAssign = vulnResults
		vulnCount = len(vulnResults)
		result.ByCategory["massassignment"] = vulnCount
		result.TotalVulns += vulnCount
		// Vulns metric updated in real-time via OnVulnerabilityFound callback
		for _, r := range vulnResults {
			result.BySeverity[string(r.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "massassignment",
				"severity":  r.Severity,
				"parameter": r.Parameter,
			})
		}
		mu.Unlock()
	})

	// WAF Detection Scanner
	runScanner("wafdetect", func() {
		var detected bool
		var wafs []waf.WAFInfo
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "wafdetect", "detected": detected, "wafs": wafs})
		}()
		detector := waf.NewDetector(timeoutDur)
		scanResult, err := detector.Detect(ctx, target)
		if err != nil {
			scanError("WAFDetect", err)
			return
		}
		mu.Lock()
		result.WAFDetect = scanResult
		if scanResult != nil && scanResult.Detected {
			detected = scanResult.Detected
			wafs = scanResult.WAFs
			// WAF detection is informational, not a vulnerability
			result.ByCategory["wafdetect"] = len(scanResult.WAFs)
		}
		mu.Unlock()
	})

	// WAF Fingerprinting Scanner
	runScanner("waffprint", func() {
		var hash string
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "waffprint", "hash": hash})
		}()
		fingerprinter := waf.NewFingerprinter(timeoutDur)
		fp, err := fingerprinter.CreateFingerprint(ctx, target)
		if err != nil {
			scanError("WAFFingerprint", err)
			return
		}
		mu.Lock()
		result.WAFFprint = fp
		if fp != nil && fp.Hash != "" {
			hash = fp.Hash
			result.ByCategory["waffprint"] = 1
		}
		mu.Unlock()
	})

	// WAF Evasion Testing Scanner
	runScanner("wafevasion", func() {
		var techniqueCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "wafevasion", "techniques": techniqueCount})
		}()
		evasion := waf.NewEvasion()
		// Load payloads from unified provider (JSON + Nuclei)
		testPayloads := []string{
			"<script>alert(1)</script>",
			"' OR '1'='1",
			"../../../etc/passwd",
		}
		// Attempt to enrich with JSON payload database
		provider := payloadprovider.NewProvider(*payloadDir, *templateDir)
		if err := provider.Load(); err != nil {
			if cf.Verbose {
				ui.PrintInfo(fmt.Sprintf("Payload provider: using fallback payloads (load error: %v)", err))
			}
		} else {
			for _, cat := range []string{"XSS", "SQL-Injection", "Path-Traversal"} {
				catPayloads, catErr := provider.GetByCategory(cat)
				if catErr != nil {
					if cf.Verbose {
						ui.PrintInfo(fmt.Sprintf("Payload provider: skipping %s category: %v", cat, catErr))
					}
					continue
				}
				limit := 5
				if len(catPayloads) < limit {
					limit = len(catPayloads)
				}
				for _, up := range catPayloads[:limit] {
					testPayloads = append(testPayloads, up.Payload)
				}
			}
			// Deduplicate payloads (enrichment may include the hardcoded fallbacks)
			seen := make(map[string]bool, len(testPayloads))
			deduped := make([]string, 0, len(testPayloads))
			for _, p := range testPayloads {
				if !seen[p] {
					seen[p] = true
					deduped = append(deduped, p)
				}
			}
			testPayloads = deduped
		}
		var allTransformed []waf.TransformedPayload
		for _, payload := range testPayloads {
			transformed := evasion.Transform(payload)
			allTransformed = append(allTransformed, transformed...)
		}
		techniqueCount = len(allTransformed)
		if techniqueCount > 0 {
			mu.Lock()
			// Store a sample (first 50) to avoid massive output
			if len(allTransformed) > 50 {
				result.WAFEvasion = allTransformed[:50]
			} else {
				result.WAFEvasion = allTransformed
			}
			result.ByCategory["wafevasion"] = techniqueCount
			mu.Unlock()
		}
	})

	// TLS Security Probe
	runScanner("tlsprobe", func() {
		var vulnFound bool
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "tlsprobe", "vuln_found": vulnFound})
		}()
		parsedURL, err := url.Parse(target)
		if err != nil {
			scanError("TLSProbe", err)
			return
		}
		if parsedURL.Scheme != "https" {
			if cf.Verbose {
				ui.PrintInfo("Skipping TLS probe for non-HTTPS target")
			}
			return
		}
		portStr := parsedURL.Port()
		if portStr == "" {
			portStr = "443"
		}
		portNum := 443
		if n, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil || n != 1 {
			portNum = 443
		}
		prober := probes.NewTLSProber()
		prober.Timeout = timeoutDur
		tlsInfo, err := prober.Probe(ctx, parsedURL.Hostname(), portNum)
		if err != nil {
			scanError("TLSProbe", err)
			return
		}
		mu.Lock()
		result.TLSInfo = tlsInfo
		// TLS issues count as vulnerabilities if there are weaknesses
		if tlsInfo != nil && (tlsInfo.SelfSigned || tlsInfo.Expired || tlsInfo.Mismatched) {
			result.TotalVulns++
			result.BySeverity["medium"]++
			result.ByCategory["tlsprobe"] = 1
			vulnFound = true
			emitEvent("vulnerability", map[string]interface{}{
				"category":    "tlsprobe",
				"severity":    "medium",
				"self_signed": tlsInfo.SelfSigned,
				"expired":     tlsInfo.Expired,
				"mismatched":  tlsInfo.Mismatched,
			})
		}
		mu.Unlock()
	})

	// HTTP Protocol Probe
	runScanner("httpprobe", func() {
		var http2Supported, pipelineSupported bool
		var dangerousMethods int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{
				"scanner":           "httpprobe",
				"http2":             http2Supported,
				"pipeline":          pipelineSupported,
				"dangerous_methods": dangerousMethods,
			})
		}()
		parsedURL, err := url.Parse(target)
		if err != nil {
			scanError("HTTPProbe", err)
			return
		}
		portStr := parsedURL.Port()
		if portStr == "" {
			if parsedURL.Scheme == "https" {
				portStr = "443"
			} else {
				portStr = "80"
			}
		}
		portNum := 80
		if n, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil || n != 1 {
			portNum = 80
		}
		useTLS := parsedURL.Scheme == "https"

		prober := probes.NewHTTPProber()
		httpResult := &probes.HTTPProbeResult{
			Host: parsedURL.Hostname(),
			Port: portNum,
		}

		// Check HTTP/2 support
		if useTLS {
			if h2, proto, err := prober.ProbeHTTP2(ctx, parsedURL.Hostname(), portNum); err == nil {
				httpResult.HTTP2Supported = h2
				httpResult.ALPN = []string{proto}
			}
		} else {
			// Check H2C for non-TLS
			if h2c, err := prober.ProbeH2C(ctx, parsedURL.Hostname(), portNum); err == nil {
				httpResult.H2CSupported = h2c
			}
		}

		// Check HTTP pipelining (potential smuggling vector)
		if pipelining, err := prober.ProbePipeline(ctx, parsedURL.Hostname(), portNum, useTLS); err == nil {
			httpResult.PipelineSupported = pipelining
		}

		// Check allowed methods
		if methods, err := prober.ProbeMethods(ctx, parsedURL.Hostname(), portNum, useTLS, "/"); err == nil {
			httpResult.Methods = methods
		}

		mu.Lock()
		result.HTTPInfo = httpResult
		http2Supported = httpResult.HTTP2Supported
		pipelineSupported = httpResult.PipelineSupported
		// Dangerous methods or pipelining support is informational
		dangerousMethodsList := []string{}
		for _, m := range httpResult.Methods {
			if m == "PUT" || m == "DELETE" || m == "TRACE" || m == "CONNECT" {
				dangerousMethods++
				dangerousMethodsList = append(dangerousMethodsList, m)
			}
		}
		if dangerousMethods > 0 || pipelineSupported {
			result.ByCategory["httpprobe"] = dangerousMethods
			if dangerousMethods > 0 {
				result.TotalVulns += dangerousMethods
				progress.AddMetricBy("vulns", dangerousMethods)
				result.BySeverity["low"] += dangerousMethods
				emitEvent("vulnerability", map[string]interface{}{
					"category": "httpprobe",
					"severity": "low",
					"type":     fmt.Sprintf("Dangerous HTTP methods enabled: %s", strings.Join(dangerousMethodsList, ", ")),
				})
			}
			if pipelineSupported {
				result.TotalVulns++
				progress.AddMetric("vulns")
				result.BySeverity["medium"]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "httpprobe",
					"severity": "medium",
					"type":     "HTTP pipelining supported (potential request smuggling vector)",
				})
			}
		}
		mu.Unlock()
	})

	// Security Headers Probe
	runScanner("secheaders", func() {
		var missingCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "secheaders", "missing_headers": missingCount})
		}()
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			scanError("SecurityHeaders", err)
			return
		}
		req.Header.Set("User-Agent", effectiveUserAgent)
		for k, v := range customHeaders {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			scanError("SecurityHeaders", err)
			return
		}
		defer iohelper.DrainAndClose(resp.Body)
		extractor := probes.NewHeaderExtractor()
		headers := extractor.Extract(resp)
		mu.Lock()
		result.SecHeaders = headers
		// Missing security headers count as informational findings
		if headers != nil {
			missingHeaders := []string{}
			if headers.StrictTransportSecurity == "" {
				missingCount++
				missingHeaders = append(missingHeaders, "Strict-Transport-Security")
			}
			if headers.ContentSecurityPolicy == "" {
				missingCount++
				missingHeaders = append(missingHeaders, "Content-Security-Policy")
			}
			if headers.XFrameOptions == "" {
				missingCount++
				missingHeaders = append(missingHeaders, "X-Frame-Options")
			}
			if headers.XContentTypeOptions == "" {
				missingCount++
				missingHeaders = append(missingHeaders, "X-Content-Type-Options")
			}
			if missingCount > 0 {
				result.TotalVulns += missingCount
				progress.AddMetricBy("vulns", missingCount)
				result.BySeverity["low"] += missingCount
				result.ByCategory["secheaders"] = missingCount
				// Emit missing headers as a vulnerability
				emitEvent("vulnerability", map[string]interface{}{
					"category": "secheaders",
					"severity": "low",
					"type":     fmt.Sprintf("Missing headers: %s", strings.Join(missingHeaders, ", ")),
				})
			}
		}
		mu.Unlock()
	})

	// JavaScript Analysis Scanner
	runScanner("jsanalyze", func() {
		var secretsCount, endpointsCount, domsinksCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{
				"scanner":   "jsanalyze",
				"secrets":   secretsCount,
				"endpoints": endpointsCount,
				"domsinks":  domsinksCount,
			})
		}()
		// Fetch JavaScript from target and analyze
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			scanError("JSAnalyze", err)
			return
		}
		req.Header.Set("User-Agent", effectiveUserAgent)
		for k, v := range customHeaders {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			scanError("JSAnalyze", err)
			return
		}
		defer iohelper.DrainAndClose(resp.Body)
		body, err := iohelper.ReadBodyDefault(resp.Body)
		if err != nil {
			return
		}

		// Analyze any inline JavaScript
		analyzer := js.NewAnalyzer()
		extracted := analyzer.Analyze(string(body))
		if extracted != nil {
			secretsCount = len(extracted.Secrets)
			endpointsCount = len(extracted.Endpoints)
			domsinksCount = len(extracted.DOMSinks)
			if secretsCount > 0 || endpointsCount > 0 || domsinksCount > 0 {
				mu.Lock()
				result.JSAnalysis = extracted
				// Secrets are critical vulnerabilities
				if secretsCount > 0 {
					result.TotalVulns += secretsCount
					progress.AddMetricBy("vulns", secretsCount)
					result.BySeverity["critical"] += secretsCount
					result.ByCategory["jsanalyze"] = secretsCount
					for _, secret := range extracted.Secrets {
						emitEvent("vulnerability", map[string]interface{}{
							"category": "jsanalyze",
							"severity": "critical",
							"type":     secret.Type,
						})
					}
				}
				// DOM sinks are potential XSS vulnerabilities
				if domsinksCount > 0 {
					result.TotalVulns += domsinksCount
					progress.AddMetricBy("vulns", domsinksCount)
					for _, sink := range extracted.DOMSinks {
						result.BySeverity[sink.Severity]++
						emitEvent("vulnerability", map[string]interface{}{
							"category": "dom-xss",
							"severity": sink.Severity,
							"type":     fmt.Sprintf("DOM sink: %s in %s", sink.Sink, sink.Context),
						})
					}
				}
				mu.Unlock()
			}
		}
	})

	// API Route Depth Scanner
	runScanner("apidepth", func() {
		var routeCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "apidepth", "routes": routeCount})
		}()
		depthConfig := api.DefaultDepthScanConfig()
		depthConfig.Timeout = timeoutDur
		depthScanner := api.NewDepthScanner(depthConfig)
		routes := []api.Route{
			{Path: "/api", Method: "GET"},
			{Path: "/v1", Method: "GET"},
			{Path: "/v2", Method: "GET"},
			{Path: "/graphql", Method: "GET"},
			{Path: "/rest", Method: "GET"},
			{Path: "/admin", Method: "GET"},
		}
		results, err := depthScanner.ScanRoutes(ctx, target, routes)
		if err != nil {
			scanError("APIDepth", err)
			return
		}
		routeCount = len(results)
		if routeCount > 0 {
			mu.Lock()
			result.APIRoutes = results
			// API routes exposed is informational
			result.ByCategory["apidepth"] = routeCount
			mu.Unlock()
		}
	})

	// OSINT Scanner - Wayback, CommonCrawl, OTX, VirusTotal
	runScanner("osint", func() {
		var secretCount, endpointCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{
				"scanner":   "osint",
				"endpoints": endpointCount,
				"secrets":   secretCount,
			})
		}()
		// Extract domain from target
		parsedURL, err := url.Parse(target)
		if err != nil {
			if cf.Verbose {
				ui.PrintWarning(fmt.Sprintf("OSINT: Failed to parse target URL: %v", err))
			}
			return
		}
		domain := parsedURL.Hostname()

		sources := discovery.NewExternalSources(timeoutDur, effectiveUserAgent)
		osintResult := sources.GatherAllSources(ctx, target, domain)

		if osintResult != nil && osintResult.TotalUnique > 0 {
			endpointCount = osintResult.TotalUnique
			secretCount = len(osintResult.Secrets)
			mu.Lock()
			result.OSINT = osintResult
			// OSINT findings are informational
			result.ByCategory["osint"] = endpointCount

			// Secrets found via OSINT are critical
			if secretCount > 0 {
				result.TotalVulns += secretCount
				progress.AddMetricBy("vulns", secretCount)
				result.BySeverity["critical"] += secretCount
				for _, secret := range osintResult.Secrets {
					emitEvent("vulnerability", map[string]interface{}{
						"category": "osint",
						"severity": "critical",
						"type":     secret.Type,
					})
				}
			}
			mu.Unlock()

			if cf.Verbose {
				ui.PrintInfo(fmt.Sprintf("OSINT: Found %d unique endpoints from external sources", endpointCount))
			}
		}
	})

	// Virtual Host Scanner
	runScanner("vhost", func() {
		var vhostCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "vhost", "vhosts": vhostCount})
		}()
		// Extract host from target
		parsedURL, err := url.Parse(target)
		if err != nil {
			return
		}

		vhostProber := probes.NewVHostProber()
		vhostProber.Timeout = timeoutDur

		// Common vhost prefixes to test
		wordlist := []string{
			"admin", "api", "app", "beta", "blog", "cdn", "cms", "dev",
			"docs", "internal", "intranet", "jenkins", "jira", "mail",
			"monitor", "mysql", "portal", "private", "prod", "staging",
			"static", "test", "vpn", "www2", "www-dev", "www-staging",
		}

		host := parsedURL.Hostname()
		port := 443
		if parsedURL.Scheme == "http" {
			port = 80
		}
		if parsedURL.Port() != "" {
			fmt.Sscanf(parsedURL.Port(), "%d", &port)
		}

		vhosts, err := vhostProber.ProbeVHosts(ctx, host, port, host, wordlist)
		if err != nil {
			scanError("VHost", err)
			return
		}

		// Filter to only valid (different) vhosts
		var validVHosts []probes.VHostProbeResult
		for _, v := range vhosts {
			if v.Valid {
				validVHosts = append(validVHosts, v)
			}
		}
		vhostCount = len(validVHosts)

		if vhostCount > 0 {
			mu.Lock()
			result.VHosts = validVHosts
			// New vhosts are informational but potentially high risk
			result.ByCategory["vhost"] = vhostCount
			result.TotalVulns += vhostCount
			progress.AddMetricBy("vulns", vhostCount)
			result.BySeverity["low"] += vhostCount
			for _, vh := range validVHosts {
				emitEvent("vulnerability", map[string]interface{}{
					"category": "vhost",
					"severity": "low",
					"vhost":    vh.VHost,
				})
			}
			mu.Unlock()

			if cf.Verbose {
				ui.PrintInfo(fmt.Sprintf("VHost: Found %d virtual hosts", vhostCount))
			}
		}
	})

	// Technology Detection Scanner
	runScanner("techdetect", func() {
		var uniqueTech []string
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "techdetect", "technologies": uniqueTech})
		}()
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", effectiveUserAgent)
		for k, v := range customHeaders {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return
		}
		defer iohelper.DrainAndClose(resp.Body)

		body, _ := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)

		uniqueTech = detectTechStack(resp, body)

		if len(uniqueTech) > 0 {
			mu.Lock()
			result.TechStack = uniqueTech
			result.ByCategory["techdetect"] = len(uniqueTech)
			mu.Unlock()

			if cf.Verbose {
				ui.PrintInfo(fmt.Sprintf("TechDetect: Identified %d technologies: %v", len(uniqueTech), uniqueTech))
			}
		}
	})

	// DNS Reconnaissance Scanner
	runScanner("dnsrecon", func() {
		var totalRecords int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "dnsrecon", "records": totalRecords})
		}()
		parsedURL, err := url.Parse(target)
		if err != nil {
			return
		}
		domain := parsedURL.Hostname()

		dnsResult := performDNSRecon(domain)
		totalRecords = dnsReconTotalRecords(dnsResult)

		if totalRecords > 0 {
			mu.Lock()
			result.DNSInfo = dnsResult
			result.ByCategory["dnsrecon"] = totalRecords
			mu.Unlock()

			if cf.Verbose {
				ui.PrintInfo(fmt.Sprintf("DNSRecon: Found %d DNS records", totalRecords))
			}
		}
	})

	// Wait for all scanners to complete
	wg.Wait()
	result.Duration = time.Since(result.StartTime)

	// Deduplicate findings — group by (parameter, type, technique) and count confirming payloads
	deduplicateAllFindings(result)

	// Apply severity/category filters and strip evidence/remediation if configured
	filters := parseScanFilters(*matchSeverity, *filterSeverity, *matchCategory, *filterCategory, *includeEvidence, *includeRemediation)
	applyFilters(result, filters)

	// Emit summary to all hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
	if dispCtx != nil {
		_ = dispCtx.EmitSummary(ctx, int(totalScans), 0, result.TotalVulns, result.Duration)
	}

	// Emit scan_end event for streaming JSON
	emitEvent("scan_end", map[string]interface{}{
		"target":      target,
		"duration_ms": result.Duration.Milliseconds(),
		"total_vulns": result.TotalVulns,
		"by_severity": result.BySeverity,
		"by_category": result.ByCategory,
	})

	// Stop progress display before printing summary to prevent
	// the deferred Stop() from erasing output with ANSI clear codes.
	progress.Stop()

	// Print scan completion summary to stderr (never pollute stdout used for JSON/structured output)
	if !streamJSON {
		vulnColor := ""
		colorReset := ""
		if ui.StderrIsTerminal() {
			vulnColor = "\033[32m" // Green
			if result.TotalVulns > 0 {
				vulnColor = "\033[33m" // Yellow
			}
			if result.TotalVulns > 5 {
				vulnColor = "\033[31m" // Red
			}
			colorReset = "\033[0m"
		}
		vulnWord := "vulnerabilities"
		if result.TotalVulns == 1 {
			vulnWord = "vulnerability"
		}
		typeWord := "scan types"
		if totalScans == 1 {
			typeWord = "scan type"
		}
		fmt.Fprintln(os.Stderr) // debug:keep
		ui.PrintSuccess(fmt.Sprintf("Scan complete in %s", result.Duration.Round(time.Millisecond)))
		fmt.Fprintf(os.Stderr, "  %s Results: %s%d %s%s across %d %s\n", ui.Icon("📊", "#"), vulnColor, result.TotalVulns, vulnWord, colorReset, totalScans, typeWord) // debug:keep
		if errCount := atomic.LoadInt32(&scanErrors); errCount > 0 {
			ui.PrintWarning(fmt.Sprintf("%d scanner(s) encountered errors (use -verbose for details)", errCount))
		}
		fmt.Fprintln(os.Stderr) // debug:keep
	}

	// Apply report metadata
	if *reportTitle != "" {
		result.ReportTitle = *reportTitle
	}
	if *reportAuthor != "" {
		result.ReportAuthor = *reportAuthor
	}

	// CSV output format
	if *csvOutput {
		printScanCSV(os.Stdout, target, result)
		return
	}

	// Markdown output format
	if *markdownOutput {
		printScanMarkdown(os.Stdout, result)
		return
	}

	// HTML output format
	if *htmlOutput {
		printScanHTML(os.Stdout, result)
		return
	}

	// SARIF output format (for CI/CD integration)
	if *sarifOutput {
		printScanSARIF(os.Stdout, target, result)
		return
	}

	// Check format type flag
	if *formatType != "" && *formatType != "console" {
		switch *formatType {
		case "jsonl":
			printScanJSONL(os.Stdout, target, result)
			return
		}
	}

	// Print summary (skip in stream+json mode - we already emitted events)
	if !*jsonOutput && !streamJSON {
		printScanConsoleSummary(result)
	}

	// Output JSON (skip final blob in stream+json mode - we already emitted events)
	if (*jsonOutput || *outputFile != "") && !streamJSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("JSON encoding error: %v", err)
			ui.PrintError(errMsg)
			if dispCtx != nil {
				_ = dispCtx.EmitError(ctx, "scan", errMsg, true)
				_ = dispCtx.Close()
			}
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				errMsg := fmt.Sprintf("Error writing output: %v", err)
				ui.PrintError(errMsg)
				if dispCtx != nil {
					_ = dispCtx.EmitError(ctx, "scan", errMsg, true)
					_ = dispCtx.Close()
				}
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData)) // debug:keep
		}
	}

	// Still write to file if specified in stream mode
	if *outputFile != "" && streamJSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("JSON encoding error: %v", err)
			ui.PrintError(errMsg)
			if dispCtx != nil {
				_ = dispCtx.EmitError(ctx, "scan", errMsg, true)
				_ = dispCtx.Close()
			}
			os.Exit(1)
		}
		if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
			errMsg := fmt.Sprintf("Error writing output: %v", err)
			ui.PrintError(errMsg)
			if dispCtx != nil {
				_ = dispCtx.EmitError(ctx, "scan", errMsg, true)
			}
		}
	}

	// Enterprise export formats (--json-export, --sarif-export, --html-export, etc.)
	writeScanExports(&outFlags, target, result)

	if result.TotalVulns > 0 {
		if dispCtx != nil {
			_ = dispCtx.Close()
		}
		os.Exit(1) // Exit with error if vulnerabilities found
	}
}
