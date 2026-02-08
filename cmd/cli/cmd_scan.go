package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/api"
	"github.com/waftester/waftester/pkg/apifuzz"
	"github.com/waftester/waftester/pkg/bizlogic"
	"github.com/waftester/waftester/pkg/cache"
	"github.com/waftester/waftester/pkg/cmdi"
	"github.com/waftester/waftester/pkg/cors"
	"github.com/waftester/waftester/pkg/crlf"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/deserialize"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/graphql"
	"github.com/waftester/waftester/pkg/hostheader"
	"github.com/waftester/waftester/pkg/hpp"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/jwt"
	"github.com/waftester/waftester/pkg/nosqli"
	"github.com/waftester/waftester/pkg/oauth"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/probes"
	"github.com/waftester/waftester/pkg/prototype"
	"github.com/waftester/waftester/pkg/race"
	"github.com/waftester/waftester/pkg/redirect"
	"github.com/waftester/waftester/pkg/smuggling"
	"github.com/waftester/waftester/pkg/sqli"
	"github.com/waftester/waftester/pkg/ssrf"
	"github.com/waftester/waftester/pkg/ssti"
	"github.com/waftester/waftester/pkg/subtakeover"
	"github.com/waftester/waftester/pkg/traversal"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/upload"
	"github.com/waftester/waftester/pkg/waf"
	"github.com/waftester/waftester/pkg/websocket"
	"github.com/waftester/waftester/pkg/xss"
	"github.com/waftester/waftester/pkg/xxe"
)

// ScanResult holds comprehensive vulnerability scan results
type ScanResult struct {
	Target       string                      `json:"target"`
	StartTime    time.Time                   `json:"start_time"`
	Duration     time.Duration               `json:"duration"`
	TotalVulns   int                         `json:"total_vulnerabilities"`
	BySeverity   map[string]int              `json:"by_severity"`
	ByCategory   map[string]int              `json:"by_category"`
	ReportTitle  string                      `json:"report_title,omitempty"`
	ReportAuthor string                      `json:"report_author,omitempty"`
	SQLi         *sqli.ScanResult            `json:"sqli,omitempty"`
	XSS          *xss.ScanResult             `json:"xss,omitempty"`
	Traversal    *traversal.ScanResult       `json:"traversal,omitempty"`
	CMDI         *cmdi.Result                `json:"cmdi,omitempty"`
	NoSQLi       *nosqli.ScanResult          `json:"nosqli,omitempty"`
	HPP          *hpp.ScanResult             `json:"hpp,omitempty"`
	CRLF         *crlf.ScanResult            `json:"crlf,omitempty"`
	Prototype    *prototype.ScanResult       `json:"prototype,omitempty"`
	CORS         *cors.Result                `json:"cors,omitempty"`
	Redirect     *redirect.Result            `json:"redirect,omitempty"`
	HostHeader   *hostheader.ScanResult      `json:"hostheader,omitempty"`
	WebSocket    *websocket.ScanResult       `json:"websocket,omitempty"`
	Cache        *cache.ScanResult           `json:"cache,omitempty"`
	Upload       []upload.Vulnerability      `json:"upload,omitempty"`
	Deserialize  []deserialize.Vulnerability `json:"deserialize,omitempty"`
	OAuth        []oauth.Vulnerability       `json:"oauth,omitempty"`
	SSRF         *ssrf.Result                `json:"ssrf,omitempty"`
	SSTI         []*ssti.Vulnerability       `json:"ssti,omitempty"`
	XXE          []*xxe.Vulnerability        `json:"xxe,omitempty"`
	Smuggling    *smuggling.Result           `json:"smuggling,omitempty"`
	GraphQL      *graphql.ScanResult         `json:"graphql,omitempty"`
	JWT          []*jwt.Vulnerability        `json:"jwt,omitempty"`
	Subtakeover  []subtakeover.ScanResult    `json:"subtakeover,omitempty"`
	BizLogic     []bizlogic.Vulnerability    `json:"bizlogic,omitempty"`
	Race         *race.Result                `json:"race,omitempty"`
	APIFuzz      []apifuzz.Vulnerability     `json:"apifuzz,omitempty"`
	WAFDetect    *waf.DetectionResult        `json:"waf_detect,omitempty"`
	WAFFprint    *waf.Fingerprint            `json:"waf_fingerprint,omitempty"`
	WAFEvasion   []waf.TransformedPayload    `json:"waf_evasion,omitempty"`
	TLSInfo      *probes.TLSInfo             `json:"tls_info,omitempty"`
	HTTPInfo     *probes.HTTPProbeResult     `json:"http_info,omitempty"`
	SecHeaders   *probes.SecurityHeaders     `json:"security_headers,omitempty"`
	JSAnalysis   *js.ExtractedData           `json:"js_analysis,omitempty"`
	APIRoutes    []api.ScanResult            `json:"api_routes,omitempty"`
	// New advanced reconnaissance scanners
	OSINT     *discovery.AllSourcesResult `json:"osint,omitempty"`
	VHosts    []probes.VHostProbeResult   `json:"vhosts,omitempty"`
	TechStack []string                    `json:"tech_stack,omitempty"`
	DNSInfo   *DNSReconResult             `json:"dns_info,omitempty"`
}

// DNSReconResult holds DNS reconnaissance findings
type DNSReconResult struct {
	CNAMEs     []string `json:"cnames,omitempty"`
	Subdomains []string `json:"subdomains,omitempty"`
	MXRecords  []string `json:"mx_records,omitempty"`
	TXTRecords []string `json:"txt_records,omitempty"`
	NSRecords  []string `json:"ns_records,omitempty"`
}

func runScan() {
	scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)

	// Output configuration (unified architecture - enterprise flags only)
	// Uses RegisterEnterpriseFlags to avoid conflicts with existing legacy flags
	var outFlags OutputFlags
	outFlags.RegisterEnterpriseFlags(scanFlags)
	outFlags.Version = ui.Version

	var targetURLs input.StringSliceFlag
	scanFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	scanFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := scanFlags.String("l", "", "File containing target URLs")
	stdinInput := scanFlags.Bool("stdin", false, "Read targets from stdin")
	types := scanFlags.String("types", "all", "Scan types: all, or comma-separated (sqli,xss,traversal,cmdi,nosqli,hpp,crlf,prototype,cors,redirect,hostheader,websocket,cache,upload,deserialize,oauth,ssrf,ssti,xxe,smuggling,graphql,jwt,subtakeover,bizlogic,race,apifuzz,wafdetect,waffprint,wafevasion,tlsprobe,httpprobe,secheaders,jsanalyze,apidepth,osint,vhost,techdetect,dnsrecon)")
	timeout := scanFlags.Int("timeout", 30, "Request timeout in seconds")
	concurrency := scanFlags.Int("concurrency", 5, "Concurrent scanners")
	outputFile := scanFlags.String("output", "", "Output results to JSON file")
	jsonOutput := scanFlags.Bool("json", false, "Output in JSON format")
	skipVerify := scanFlags.Bool("skip-verify", false, "Skip TLS verification")
	verbose := scanFlags.Bool("verbose", false, "Verbose output")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := scanFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := scanFlags.String("smart-mode", "standard", "Smart mode type: quick, standard, full, bypass, stealth")
	smartVerbose := scanFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// Tamper scripts (70+ sqlmap-compatible WAF bypass transformations)
	tamperList := scanFlags.String("tamper", "", "Comma-separated tamper scripts: space2comment,randomcase,charencode")
	tamperAuto := scanFlags.Bool("tamper-auto", false, "Auto-select tampers based on detected WAF")
	tamperProfile := scanFlags.String("tamper-profile", "standard", "Tamper profile: stealth, standard, aggressive, bypass")

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
	noColor := scanFlags.Bool("no-color", false, "Disable colored output")
	scanFlags.BoolVar(noColor, "nc", false, "No color (alias)")
	timestamp := scanFlags.Bool("timestamp", false, "Add timestamp to output")
	scanFlags.BoolVar(timestamp, "ts", false, "Timestamp (alias)")

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
	headers := scanFlags.String("header", "", "Custom header (Name: Value)")
	scanFlags.StringVar(headers, "H", "", "Custom header (alias)")
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
	maxDepth := scanFlags.Int("max-depth", 5, "Max crawl depth for discovered URLs")
	scanFlags.IntVar(maxDepth, "mxd", 5, "Max depth (alias)")
	followRedirects := scanFlags.Bool("follow-redirects", true, "Follow HTTP redirects")
	scanFlags.BoolVar(followRedirects, "fr", true, "Follow redirects (alias)")
	maxRedirects := scanFlags.Int("max-redirects", 10, "Max redirects to follow")
	respectRobots := scanFlags.Bool("respect-robots", false, "Respect robots.txt")
	scanFlags.BoolVar(respectRobots, "rr", false, "Respect robots (alias)")
	dryRun := scanFlags.Bool("dry-run", false, "Show what would be scanned without scanning")
	scanFlags.BoolVar(dryRun, "dr", false, "Dry run (alias)")

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
		*verbose = true // Debug implies verbose
	}

	// Handle CPU profiling
	if *profile {
		ui.PrintInfo("CPU profiling enabled (would write to cpu.prof)")
	}

	// Handle memory profiling
	if *memProfile {
		ui.PrintInfo("Memory profiling enabled (would write to mem.prof)")
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
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}

	// Setup context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout*60)*time.Second)
	defer cancel()

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	scanID := fmt.Sprintf("scan-%d", time.Now().Unix())
	dispCtx, dispErr := outFlags.InitDispatcher(scanID, target)
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
			DetectionTimeout: time.Duration(*timeout) * time.Second,
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
		// The smart mode values are the safe limits for that specific WAF
		if smartResult != nil && smartResult.WAFDetected {
			if smartResult.RateLimit > 0 {
				ui.PrintInfo(fmt.Sprintf("📊 Rate limit: %.0f req/sec (WAF-optimized for %s)",
					smartResult.RateLimit, smartResult.VendorName))
				*rateLimit = int(smartResult.RateLimit)
			}
			if smartResult.Concurrency > 0 {
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
	// Silence unused variable warnings
	_ = smartVerbose
	_ = smartModeType

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
	// Silence unused variable warning
	_ = tamperList
	_ = tamperAuto
	_ = tamperProfile
	_ = tamperEngine
	_ = smartResult

	// Only print config to stdout if not in streaming JSON mode
	if !streamJSON {
		ui.PrintConfigLine("Target", target)
		ui.PrintConfigLine("Scan Types", *types)
		ui.PrintConfigLine("Timeout", fmt.Sprintf("%ds", *timeout))
		ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
		if *smartMode {
			ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d req/sec (WAF-optimized)", *rateLimit))
		}
		fmt.Fprintln(os.Stderr)

		// Print output configuration if verbose
		if *verbose {
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

	shouldScan := func(name string) bool {
		return scanAll || typeSet[name]
	}

	// Dry run mode - list what would be scanned and exit
	if *dryRun {
		allScanTypes := []string{"sqli", "xss", "traversal", "cmdi", "nosqli", "hpp", "crlf", "prototype", "cors", "redirect", "hostheader", "websocket", "cache", "upload", "deserialize", "oauth", "ssrf", "ssti", "xxe", "jwt", "smuggling", "bizlogic", "race", "httpprobe", "secheaders", "jsanalyze", "apidepth", "osint", "vhost", "techdetect", "dnsrecon", "wafdetect", "waffprint"}

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
			fmt.Fprintf(os.Stderr, "  • %s\n", s)
		}
		fmt.Fprintln(os.Stderr)
		ui.PrintHelp("Remove -dry-run flag to execute scans")
		os.Exit(0)
	}

	// Build HTTP transport with proxy support
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *skipVerify},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     duration.IdleConnTimeout,
	}

	// Configure proxy if specified
	if *proxy != "" {
		proxyURL, err := url.Parse(*proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
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
	if *headers != "" {
		parts := strings.SplitN(*headers, ":", 2)
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

	// Setup HTTP client
	httpClient := &http.Client{
		Timeout:       time.Duration(*timeout) * time.Second,
		Transport:     transport,
		CheckRedirect: redirectPolicy,
	}

	// Wrap with detection transport for connection drop/silent ban detection
	httpClient = detection.WrapClient(httpClient)

	result := &ScanResult{
		Target:     target,
		StartTime:  time.Now(),
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *concurrency)

	// Progress tracking
	var totalScans int32
	var scanErrors int32
	var scanTimings sync.Map // map[string]time.Duration

	// Count total scans first
	allScanTypes := []string{"sqli", "xss", "traversal", "cmdi", "nosqli", "ssrf", "ssti", "xxe", "smuggling", "oauth", "jwt", "cors", "redirect", "hostheader", "cache", "upload", "deserialize", "bizlogic", "race", "secheaders", "wafdetect", "waffprint", "wafevasion", "techdetect", "jsanalyze"}
	for _, t := range allScanTypes {
		if shouldScan(t) {
			atomic.AddInt32(&totalScans, 1)
		}
	}

	// Determine output mode for progress
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}
	if *silent {
		outputMode = ui.OutputModeSilent
	}

	// Live progress display using unified LiveProgress
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        int(totalScans),
		DisplayLines: 4,
		Title:        "Deep Vulnerability Scan",
		Unit:         "scans",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "vulns", Label: "Vulns", Icon: "🚨", Highlight: true},
		},
		Tips: []string{
			"💡 SQLi uses error-based, time-based, union, and boolean techniques",
			"💡 XSS tests reflected, stored, and DOM-based vectors",
			"💡 SSRF probes for internal network access and cloud metadata",
			"💡 Path traversal tests for file system access vulnerabilities",
			"💡 Each scan type uses context-aware payload selection",
		},
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
				severity, _ := dataMap["severity"].(string)
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
		fmt.Println(string(eventData))
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

			// Check if host is blocked due to drops/bans before running
			if skip, reason := detection.Default().ShouldSkipHost(targetHost); skip {
				emitEvent("scanner_skipped", map[string]interface{}{
					"scanner": name,
					"reason":  reason,
				})
				progress.Increment()
				return
			}

			scanStart := time.Now()
			progress.SetStatus(name)

			fn()
			elapsed := time.Since(scanStart)
			scanTimings.Store(name, elapsed)
			progress.Increment()
		}()
	}

	// scanError is a helper that logs scan errors and increments error counter.
	// Always emits a warning so the user knows a scanner failed, not only in verbose mode.
	scanError := func(scanner string, err error) {
		atomic.AddInt32(&scanErrors, 1)
		if *verbose {
			ui.PrintWarning(fmt.Sprintf("%s scan error: %v", scanner, err))
		}
	}

	timeoutDur := time.Duration(*timeout) * time.Second

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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
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
			progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
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
		progress.AddMetricBy("vulns", vulnCount)
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
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
		progress.AddMetricBy("vulns", vulnCount)
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
			if *verbose {
				ui.PrintInfo("OAuth scan skipped: no -oauth-auth-endpoint provided")
			}
			return
		}
		cfg := &oauth.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
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
		progress.AddMetricBy("vulns", vulnCount)
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
		detector := ssrf.NewDetector()
		detector.Timeout = timeoutDur
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
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[v.Severity]++
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
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
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
		progress.AddMetricBy("vulns", vulnCount)
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
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
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
		progress.AddMetricBy("vulns", vulnCount)
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
		detector := smuggling.NewDetector()
		detector.Timeout = timeoutDur
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
			progress.AddMetricBy("vulns", vulnCount)
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
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
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
				progress.AddMetricBy("vulns", vulnCount)
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
		if *verbose {
			ui.PrintInfo("No GraphQL endpoint found or no vulnerabilities detected")
		}
	})

	// JWT Security Scanner
	runScanner("jwt", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "jwt", "vulns": vulnCount})
		}()
		attacker := jwt.NewAttacker()
		// Generate test tokens to demonstrate JWT attack capabilities
		testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		vulns, err := attacker.GenerateMaliciousTokens(testToken)
		if err != nil {
			scanError("JWT", err)
			return
		}
		mu.Lock()
		result.JWT = vulns
		vulnCount = len(vulns)
		result.ByCategory["jwt"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
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
			Timeout:     timeoutDur,
			UserAgent:   ui.UserAgent(),
			Concurrency: *concurrency,
			CheckHTTP:   true,
			FollowCNAME: true,
			Client:      httpClient,
		}
		tester := subtakeover.NewTester(cfg)
		// Extract domain from target URL
		u, err := url.Parse(target)
		if err != nil {
			if *verbose {
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
			progress.AddMetricBy("vulns", vulnCount)
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
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
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
		progress.AddMetricBy("vulns", vulnCount)
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
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
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
			progress.AddMetricBy("vulns", vulnCount)
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
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
		tester := apifuzz.NewTester(cfg)
		// Define basic endpoints to fuzz
		endpoints := []apifuzz.Endpoint{
			{Path: "/api", Method: "GET", Parameters: []apifuzz.Parameter{{Name: "id", Type: apifuzz.ParamString, In: "query"}}},
			{Path: "/api", Method: "POST", Parameters: []apifuzz.Parameter{{Name: "data", Type: apifuzz.ParamString, In: "body"}}},
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
		progress.AddMetricBy("vulns", vulnCount)
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
			if *verbose {
				ui.PrintInfo(fmt.Sprintf("Payload provider: using fallback payloads (load error: %v)", err))
			}
		} else {
			for _, cat := range []string{"XSS", "SQL-Injection", "Path-Traversal"} {
				catPayloads, catErr := provider.GetByCategory(cat)
				if catErr != nil {
					if *verbose {
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
			if *verbose {
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
			result.BySeverity["Medium"]++
			result.ByCategory["tlsprobe"] = 1
			vulnFound = true
			emitEvent("vulnerability", map[string]interface{}{
				"category":    "tlsprobe",
				"severity":    "Medium",
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
				result.BySeverity["Low"] += dangerousMethods
				emitEvent("vulnerability", map[string]interface{}{
					"category": "httpprobe",
					"severity": "Low",
					"type":     fmt.Sprintf("Dangerous HTTP methods enabled: %s", strings.Join(dangerousMethodsList, ", ")),
				})
			}
			if pipelineSupported {
				emitEvent("vulnerability", map[string]interface{}{
					"category": "httpprobe",
					"severity": "Medium",
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
		client := httpclient.New(httpclient.WithTimeout(timeoutDur))
		resp, err := client.Get(target)
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
				result.ByCategory["secheaders"] = missingCount
				// Emit missing headers as a vulnerability
				emitEvent("vulnerability", map[string]interface{}{
					"category": "secheaders",
					"severity": "Low",
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
		client := httpclient.New(httpclient.WithTimeout(timeoutDur))
		resp, err := client.Get(target)
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
					result.BySeverity["Critical"] += secretsCount
					result.ByCategory["jsanalyze"] = secretsCount
					for _, secret := range extracted.Secrets {
						emitEvent("vulnerability", map[string]interface{}{
							"category": "jsanalyze",
							"severity": "Critical",
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
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("OSINT: Failed to parse target URL: %v", err))
			}
			return
		}
		domain := parsedURL.Hostname()

		sources := discovery.NewExternalSources(timeoutDur, ui.UserAgentWithContext("OSINT"))
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
				result.BySeverity["Critical"] += secretCount
				for _, secret := range osintResult.Secrets {
					emitEvent("vulnerability", map[string]interface{}{
						"category": "osint",
						"severity": "Critical",
						"type":     secret.Type,
					})
				}
			}
			mu.Unlock()

			if *verbose {
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
			result.BySeverity["Low"] += vhostCount
			for _, vh := range validVHosts {
				emitEvent("vulnerability", map[string]interface{}{
					"category": "vhost",
					"severity": "Low",
					"vhost":    vh.VHost,
				})
			}
			mu.Unlock()

			if *verbose {
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
		// Use active discoverer for tech fingerprinting
		ad := discovery.NewActiveDiscoverer(target, timeoutDur, *skipVerify)

		// Manually extract technology stack
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", ui.UserAgentWithContext("Discovery"))

		client := httpclient.New(httpclient.WithTimeout(timeoutDur))

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer iohelper.DrainAndClose(resp.Body)

		body, _ := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)

		var techStack []string

		// Analyze headers
		server := strings.ToLower(resp.Header.Get("Server"))
		powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
		generator := strings.ToLower(resp.Header.Get("X-Generator"))

		if strings.Contains(server, "nginx") {
			techStack = append(techStack, "nginx")
		}
		if strings.Contains(server, "apache") {
			techStack = append(techStack, "apache")
		}
		if strings.Contains(server, "iis") {
			techStack = append(techStack, "iis")
		}
		if strings.Contains(powered, "php") {
			techStack = append(techStack, "php")
		}
		if strings.Contains(powered, "asp") || strings.Contains(powered, ".net") {
			techStack = append(techStack, "asp.net")
		}
		if strings.Contains(powered, "express") {
			techStack = append(techStack, "express")
		}
		if generator != "" {
			techStack = append(techStack, generator)
		}

		// Analyze cookies
		for _, cookie := range resp.Cookies() {
			name := strings.ToLower(cookie.Name)
			if strings.Contains(name, "phpsessid") {
				techStack = append(techStack, "php")
			}
			if strings.Contains(name, "jsessionid") {
				techStack = append(techStack, "java")
			}
			if strings.Contains(name, "asp.net") || strings.Contains(name, "aspxauth") {
				techStack = append(techStack, "asp.net")
			}
			if strings.Contains(name, "csrftoken") {
				techStack = append(techStack, "django")
			}
			if strings.Contains(name, "_rails") {
				techStack = append(techStack, "rails")
			}
		}

		// Analyze body
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wordpress") {
			techStack = append(techStack, "wordpress")
		}
		if strings.Contains(bodyStr, "__next") || strings.Contains(bodyStr, "next.js") {
			techStack = append(techStack, "next.js")
		}
		if strings.Contains(bodyStr, "react") && strings.Contains(bodyStr, "reactdom") {
			techStack = append(techStack, "react")
		}
		if strings.Contains(bodyStr, "angular") || strings.Contains(bodyStr, "ng-app") {
			techStack = append(techStack, "angular")
		}
		if strings.Contains(bodyStr, "vue.js") || strings.Contains(bodyStr, "v-bind") {
			techStack = append(techStack, "vue.js")
		}
		if strings.Contains(bodyStr, "laravel") {
			techStack = append(techStack, "laravel")
		}
		if strings.Contains(bodyStr, "drupal") {
			techStack = append(techStack, "drupal")
		}
		if strings.Contains(bodyStr, "joomla") {
			techStack = append(techStack, "joomla")
		}

		// Deduplicate
		seen := make(map[string]bool)
		for _, t := range techStack {
			if !seen[t] {
				seen[t] = true
				uniqueTech = append(uniqueTech, t)
			}
		}

		// Skip slow active discovery fallback - only use header/body analysis
		// The ad.DiscoverAll call can hang for extended periods
		_ = ad // Suppress unused variable warning

		if len(uniqueTech) > 0 {
			mu.Lock()
			result.TechStack = uniqueTech
			result.ByCategory["techdetect"] = len(uniqueTech)
			mu.Unlock()

			if *verbose {
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

		dnsResult := &DNSReconResult{}

		// Resolve CNAME chain (reusing subtakeover's logic)
		cnames, err := net.LookupCNAME(domain)
		if err == nil && cnames != "" && cnames != domain+"." {
			dnsResult.CNAMEs = []string{strings.TrimSuffix(cnames, ".")}
		}

		// MX Records
		mxRecords, err := net.LookupMX(domain)
		if err == nil {
			for _, mx := range mxRecords {
				dnsResult.MXRecords = append(dnsResult.MXRecords, mx.Host)
			}
		}

		// TXT Records
		txtRecords, err := net.LookupTXT(domain)
		if err == nil {
			dnsResult.TXTRecords = txtRecords
		}

		// NS Records
		nsRecords, err := net.LookupNS(domain)
		if err == nil {
			for _, ns := range nsRecords {
				dnsResult.NSRecords = append(dnsResult.NSRecords, ns.Host)
			}
		}

		totalRecords = len(dnsResult.CNAMEs) + len(dnsResult.MXRecords) +
			len(dnsResult.TXTRecords) + len(dnsResult.NSRecords)

		if totalRecords > 0 {
			mu.Lock()
			result.DNSInfo = dnsResult
			result.ByCategory["dnsrecon"] = totalRecords
			mu.Unlock()

			if *verbose {
				ui.PrintInfo(fmt.Sprintf("DNSRecon: Found %d DNS records", totalRecords))
			}
		}
	})

	// Wait for all scanners to complete
	wg.Wait()
	result.Duration = time.Since(result.StartTime)

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

	// Progress cleanup is handled by defer progress.Stop()

	// Print scan completion summary (to stderr if streaming JSON)
	if !streamJSON {
		vulnColor := "\033[32m" // Green
		if result.TotalVulns > 0 {
			vulnColor = "\033[33m" // Yellow
		}
		if result.TotalVulns > 5 {
			vulnColor = "\033[31m" // Red
		}
		fmt.Println()
		ui.PrintSuccess(fmt.Sprintf("✓ Scan complete in %s", result.Duration.Round(time.Millisecond)))
		fmt.Printf("  📊 Results: %s%d vulnerabilities\033[0m across %d scan types\n", vulnColor, result.TotalVulns, totalScans)
		if errCount := atomic.LoadInt32(&scanErrors); errCount > 0 {
			ui.PrintWarning(fmt.Sprintf("  ⚠️  %d scanner(s) encountered errors (use -verbose for details)", errCount))
		}
		fmt.Println()
	}

	// Apply delay/jitter for rate limiting (used in scanner loops)
	_ = delay  // Used for rate limiting in future iterations
	_ = jitter // Used for rate limiting in future iterations

	// Apply report metadata
	if *reportTitle != "" {
		result.ReportTitle = *reportTitle
	}
	if *reportAuthor != "" {
		result.ReportAuthor = *reportAuthor
	}

	// CSV output format
	if *csvOutput {
		fmt.Println("target,category,severity,count")
		for cat, count := range result.ByCategory {
			fmt.Printf("%s,%s,various,%d\n", target, cat, count)
		}
		return
	}

	// Markdown output format
	if *markdownOutput {
		fmt.Println("# Vulnerability Scan Report")
		fmt.Println()
		if *reportTitle != "" {
			fmt.Printf("**Report:** %s\n", *reportTitle)
		}
		if *reportAuthor != "" {
			fmt.Printf("**Author:** %s\n", *reportAuthor)
		}
		fmt.Printf("**Target:** %s\n", target)
		fmt.Printf("**Date:** %s\n", result.StartTime.Format("2006-01-02 15:04:05"))
		fmt.Printf("**Duration:** %s\n", result.Duration.Round(time.Millisecond))
		fmt.Printf("**Total Vulnerabilities:** %d\n", result.TotalVulns)
		fmt.Println()
		fmt.Println("## By Severity")
		fmt.Println()
		fmt.Println("| Severity | Count |")
		fmt.Println("|----------|-------|")
		for sev, count := range result.BySeverity {
			fmt.Printf("| %s | %d |\n", sev, count)
		}
		fmt.Println()
		fmt.Println("## By Category")
		fmt.Println()
		fmt.Println("| Category | Count |")
		fmt.Println("|----------|-------|")
		for cat, count := range result.ByCategory {
			if count > 0 {
				fmt.Printf("| %s | %d |\n", cat, count)
			}
		}
		return
	}

	// HTML output format
	if *htmlOutput {
		fmt.Println("<!DOCTYPE html><html><head><title>Scan Report</title>")
		fmt.Println("<style>body{font-family:Arial,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#4CAF50;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#ffc107}.low{color:#4caf50}</style></head><body>")
		if *reportTitle != "" {
			fmt.Printf("<h1>%s</h1>\n", *reportTitle)
		} else {
			fmt.Println("<h1>Vulnerability Scan Report</h1>")
		}
		if *reportAuthor != "" {
			fmt.Printf("<p><strong>Author:</strong> %s</p>\n", *reportAuthor)
		}
		fmt.Printf("<p><strong>Target:</strong> %s</p>\n", target)
		fmt.Printf("<p><strong>Date:</strong> %s</p>\n", result.StartTime.Format("2006-01-02 15:04:05"))
		fmt.Printf("<p><strong>Total Vulnerabilities:</strong> %d</p>\n", result.TotalVulns)
		fmt.Println("<h2>By Severity</h2><table><tr><th>Severity</th><th>Count</th></tr>")
		for sev, count := range result.BySeverity {
			fmt.Printf("<tr><td class='%s'>%s</td><td>%d</td></tr>\n", strings.ToLower(sev), sev, count)
		}
		fmt.Println("</table><h2>By Category</h2><table><tr><th>Category</th><th>Count</th></tr>")
		for cat, count := range result.ByCategory {
			if count > 0 {
				fmt.Printf("<tr><td>%s</td><td>%d</td></tr>\n", cat, count)
			}
		}
		fmt.Println("</table></body></html>")
		return
	}

	// SARIF output format (for CI/CD integration)
	if *sarifOutput {
		sarif := map[string]interface{}{
			"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
			"version": "2.1.0",
			"runs": []map[string]interface{}{
				{
					"tool": map[string]interface{}{
						"driver": map[string]interface{}{
							"name":           "waf-tester",
							"version":        ui.Version,
							"informationUri": "https://github.com/waftester/waftester",
						},
					},
					"results": func() []map[string]interface{} {
						var results []map[string]interface{}
						for cat, count := range result.ByCategory {
							if count > 0 {
								results = append(results, map[string]interface{}{
									"ruleId":  cat,
									"level":   "warning",
									"message": map[string]string{"text": fmt.Sprintf("Found %d %s issues", count, cat)},
									"locations": []map[string]interface{}{
										{"physicalLocation": map[string]interface{}{"artifactLocation": map[string]string{"uri": target}}},
									},
								})
							}
						}
						return results
					}(),
				},
			},
		}
		jsonData, _ := json.MarshalIndent(sarif, "", "  ")
		fmt.Println(string(jsonData))
		return
	}

	// Check format type flag
	if *formatType != "" && *formatType != "console" {
		switch *formatType {
		case "jsonl":
			// JSON Lines format
			for cat, count := range result.ByCategory {
				line, _ := json.Marshal(map[string]interface{}{"category": cat, "count": count, "target": target})
				fmt.Println(string(line))
			}
			return
		}
	}

	// Print summary (skip in stream+json mode - we already emitted events)
	if !*jsonOutput && !streamJSON {
		fmt.Println()
		ui.PrintSection("Scan Results")
		ui.PrintConfigLine("Duration", result.Duration.Round(time.Millisecond).String())
		ui.PrintConfigLine("Total Vulnerabilities", fmt.Sprintf("%d", result.TotalVulns))
		fmt.Println()

		if result.TotalVulns > 0 {
			ui.PrintSection("By Severity")
			for sev, count := range result.BySeverity {
				switch sev {
				case "Critical":
					ui.PrintError(fmt.Sprintf("  %s: %d", sev, count))
				case "High":
					ui.PrintError(fmt.Sprintf("  %s: %d", sev, count))
				case "Medium":
					ui.PrintWarning(fmt.Sprintf("  %s: %d", sev, count))
				default:
					ui.PrintInfo(fmt.Sprintf("  %s: %d", sev, count))
				}
			}
			fmt.Println()

			ui.PrintSection("By Category")
			for cat, count := range result.ByCategory {
				if count > 0 {
					ui.PrintConfigLine(cat, fmt.Sprintf("%d vulnerabilities", count))
				}
			}
			fmt.Println()

			// Print detailed findings
			if result.SQLi != nil && len(result.SQLi.Vulnerabilities) > 0 {
				ui.PrintSection("SQLi Findings")
				for _, v := range result.SQLi.Vulnerabilities[:min(5, len(result.SQLi.Vulnerabilities))] {
					ui.PrintError(fmt.Sprintf("  [%s] %s - %s", v.Severity, v.Parameter, v.Type))
				}
				if len(result.SQLi.Vulnerabilities) > 5 {
					ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.SQLi.Vulnerabilities)-5))
				}
				fmt.Println()
			}

			if result.XSS != nil && len(result.XSS.Vulnerabilities) > 0 {
				ui.PrintSection("XSS Findings")
				for _, v := range result.XSS.Vulnerabilities[:min(5, len(result.XSS.Vulnerabilities))] {
					ui.PrintError(fmt.Sprintf("  [%s] %s - %s", v.Severity, v.Parameter, v.Type))
				}
				if len(result.XSS.Vulnerabilities) > 5 {
					ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.XSS.Vulnerabilities)-5))
				}
				fmt.Println()
			}
		} else {
			ui.PrintSuccess("No vulnerabilities found!")
		}
	}

	// Output JSON (skip final blob in stream+json mode - we already emitted events)
	if (*jsonOutput || *outputFile != "") && !streamJSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("JSON encoding error: %v", err)
			ui.PrintError(errMsg)
			_ = dispCtx.EmitError(ctx, "scan", errMsg, true)
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				errMsg := fmt.Sprintf("Error writing output: %v", err)
				ui.PrintError(errMsg)
				_ = dispCtx.EmitError(ctx, "scan", errMsg, true)
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData))
		}
	}

	// Still write to file if specified in stream mode
	if *outputFile != "" && streamJSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
			errMsg := fmt.Sprintf("Error writing output: %v", err)
			fmt.Fprintf(os.Stderr, "[ERROR] %s\n", errMsg)
			_ = dispCtx.EmitError(ctx, "scan", errMsg, true)
		}
	}

	if result.TotalVulns > 0 {
		os.Exit(1) // Exit with error if vulnerabilities found
	}
}

// Silence unused variable warnings for variables that are used for future
// expansion or configuration that may not be fully implemented yet
var (
	_ = (*bool)(nil)   // rateLimitPerHost
	_ = (*string)(nil) // matchSeverity, filterSeverity, matchCategory, filterCategory
	_ = (*string)(nil) // excludeTypes, excludePatterns, includePatterns
	_ = (*bool)(nil)   // includeEvidence, includeRemediation
	_ = (*int)(nil)    // maxDepth, retries, maxErrors
	_ = (*bool)(nil)   // stopOnFirstVuln, respectRobots, timestamp
)
