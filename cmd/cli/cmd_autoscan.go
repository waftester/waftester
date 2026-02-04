package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/waftester/waftester/pkg/assessment"
	"github.com/waftester/waftester/pkg/browser"
	"github.com/waftester/waftester/pkg/calibration"
	"github.com/waftester/waftester/pkg/checkpoint"
	"github.com/waftester/waftester/pkg/core"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/intelligence"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/leakypaths"
	"github.com/waftester/waftester/pkg/learning"
	"github.com/waftester/waftester/pkg/output"
	detectionoutput "github.com/waftester/waftester/pkg/output/detection"
	"github.com/waftester/waftester/pkg/params"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/ratelimit"
	"github.com/waftester/waftester/pkg/recon"
	"github.com/waftester/waftester/pkg/report"
	tlsja3 "github.com/waftester/waftester/pkg/tls"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/waf/vendors"
)

// runAutoScan is the SUPERPOWER command - full automated scan in a single command
// It chains: discover → deep JS analysis → learn → run → comprehensive report
func runAutoScan() {
	startTime := time.Now()

	// Parse flags FIRST so we can determine output mode before printing anything
	autoFlags := flag.NewFlagSet("auto", flag.ExitOnError)

	// Output configuration (unified architecture)
	var outFlags OutputFlags
	outFlags.RegisterFlags(autoFlags)
	outFlags.RegisterOutputAliases(autoFlags)
	outFlags.Version = ui.Version

	var targetURLs input.StringSliceFlag
	autoFlags.Var(&targetURLs, "u", "Target URL(s)")
	autoFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := autoFlags.String("l", "", "File containing target URLs")
	stdinInput := autoFlags.Bool("stdin", false, "Read targets from stdin")
	service := autoFlags.String("service", "", "Service preset: wordpress, drupal, nextjs, flask, django")
	payloadDirFlag := autoFlags.String("payloads", "", "Payload directory (default: auto-detect)")
	concurrency := autoFlags.Int("c", 50, "Concurrent workers for testing")
	rateLimit := autoFlags.Int("rl", 200, "Rate limit (requests per second)")
	timeout := autoFlags.Int("timeout", 10, "HTTP timeout in seconds")
	skipVerify := autoFlags.Bool("skip-verify", false, "Skip TLS verification")
	depth := autoFlags.Int("depth", 3, "Max crawl depth for discovery")
	outputDir := autoFlags.String("output-dir", "", "Output directory (default: workspaces/<domain>/<timestamp>)")
	verbose := autoFlags.Bool("v", false, "Verbose output")
	_ = autoFlags.Bool("no-clean", false, "Don't clean previous workspace files") // Reserved for future use

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := autoFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := autoFlags.String("smart-mode", "standard", "Smart mode type: quick, standard, full, bypass, stealth")
	smartVerbose := autoFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// Tamper scripts (70+ sqlmap-compatible WAF bypass transformations)
	tamperList := autoFlags.String("tamper", "", "Comma-separated tamper scripts: space2comment,randomcase,charencode")
	tamperAuto := autoFlags.Bool("tamper-auto", false, "Auto-select tampers based on detected WAF")
	tamperProfile := autoFlags.String("tamper-profile", "standard", "Tamper profile: stealth, standard, aggressive, bypass")

	// Enterprise assessment with quantitative metrics (NOW DEFAULT for superpower mode)
	enableAssess := autoFlags.Bool("assess", true, "Run enterprise assessment with F1/precision/MCC metrics (default: true)")
	assessCorpus := autoFlags.String("assess-corpus", "builtin,leipzig", "FP corpus for assessment: builtin,leipzig")

	// NEW: Leaky paths scanning (Phase 1.5)
	enableLeakyPaths := autoFlags.Bool("leaky-paths", true, "Enable sensitive path scanning (300+ paths)")
	leakyCategories := autoFlags.String("leaky-categories", "", "Filter leaky paths: config,debug,vcs,admin,backup,source,api,cloud,ci")

	// NEW: Parameter discovery (Phase 2.5)
	enableParamDiscovery := autoFlags.Bool("discover-params", true, "Enable Arjun-style parameter discovery")
	paramWordlist := autoFlags.String("param-wordlist", "", "Custom parameter wordlist file")

	// NEW: JA3 fingerprint rotation
	enableJA3 := autoFlags.Bool("ja3-rotate", false, "Enable JA3 fingerprint rotation")
	ja3Profile := autoFlags.String("ja3-profile", "", "Specific JA3 profile: chrome120,firefox121,safari17,edge120")

	// NEW: Full recon mode using unified recon package
	enableFullRecon := autoFlags.Bool("full-recon", false, "Run unified reconnaissance (combines leaky-paths, params, JS analysis)")

	// NEW: Browser-based authenticated scanning (Phase 7-9)
	enableBrowserScan := autoFlags.Bool("browser", true, "Enable authenticated browser scanning (default: true)")
	browserHeadless := autoFlags.Bool("browser-headless", false, "Run browser in headless mode (no visible window)")
	browserTimeout := autoFlags.Duration("browser-timeout", duration.BrowserLogin, "Timeout for user login during browser scan")

	// Note: stream, json, and -j flags are now registered via outFlags.RegisterFlags()
	// Use outFlags.StreamMode and outFlags.JSONMode instead of local variables

	// Detection (v2.5.2)
	noDetect := autoFlags.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	// NEW v2.6.4: Auto-resume with checkpoint support
	resumeScan := autoFlags.Bool("resume", false, "Resume interrupted scan from checkpoint")
	checkpointFile := autoFlags.String("checkpoint", "", "Checkpoint file path (default: <workspace>/checkpoint.json)")

	// NEW v2.6.4: Multi-format report generation
	reportFormats := autoFlags.String("report-formats", "json,md,html", "Comma-separated report formats: json,md,html,sarif")

	// NEW v2.6.4: Adaptive rate limiting
	adaptiveRate := autoFlags.Bool("adaptive-rate", true, "Enable adaptive rate limiting (auto-adjust on WAF response)")

	// NEW v2.6.4: Intelligence Engine - adaptive learning brain
	enableIntelligence := autoFlags.Bool("intelligence", true, "Enable Intelligence Engine (adaptive learning, attack chains, smart prioritization)")
	intelligenceVerbose := autoFlags.Bool("intelligence-verbose", false, "Show detailed intelligence insights during scan")

	autoFlags.Parse(os.Args[2:])

	// Disable detection if requested
	if *noDetect {
		detection.Disable()
	}

	// Apply unified output settings (silent, color)
	outFlags.ApplyUISettings()

	// Apply silent mode for JSON output - suppress all non-JSON output to stdout
	if outFlags.JSONMode {
		ui.SetSilent(true)
	}

	// Print banner and intro only when not in JSON mode
	if !outFlags.ShouldSuppressBanner() {
		ui.PrintBanner()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, ui.SectionStyle.Render("🚀 SUPERPOWER MODE - Full Automated Security Scan"))
		fmt.Fprintln(os.Stderr)
	}

	// Helper to suppress console output in JSON mode
	// All informational output should use these instead of fmt.Print*
	quietMode := outFlags.JSONMode
	printStatus := func(format string, args ...interface{}) {
		if !quietMode {
			fmt.Fprintf(os.Stderr, format, args...)
		}
	}
	printStatusLn := func(args ...interface{}) {
		if !quietMode {
			fmt.Fprintln(os.Stderr, args...)
		}
	}
	// Silence unused warnings - these will be used throughout
	_ = printStatus
	_ = printStatusLn

	// Auto-detect payload directory if not specified
	payloadDir := *payloadDirFlag
	if payloadDir == "" {
		// Try common locations
		candidates := []string{
			"../payloads",               // When run from waf-tester/
			"payloads",                  // When run from waf-tester/ (alt)
			"tests/payloads",            // When run from repo root
			"tests/waf-tester/payloads", // When run from repo root
			filepath.Join(filepath.Dir(os.Args[0]), "..", "payloads"), // Relative to executable
			filepath.Join(filepath.Dir(os.Args[0]), "payloads"),       // Next to executable
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				payloadDir = candidate
				break
			}
		}
		if payloadDir == "" {
			payloadDir = "../payloads" // Fallback
		}
	}

	// Get target
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use: waf-tester auto -u https://example.com")
		os.Exit(1)
	}

	// Parse domain from target
	parsedURL, err := url.Parse(target)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Invalid target URL: %v", err))
		os.Exit(1)
	}
	domain := parsedURL.Hostname()

	// Create output directory structure
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	workspaceDir := *outputDir
	if workspaceDir == "" {
		// Use project root workspaces directory for consistent output location
		projectRoot := getProjectRoot()
		workspaceDir = filepath.Join(projectRoot, "workspaces", domain, timestamp)
	}
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		ui.PrintError(fmt.Sprintf("Cannot create workspace: %v", err))
		os.Exit(1)
	}

	// Define output files
	discoveryFile := filepath.Join(workspaceDir, "discovery.json")
	jsAnalysisFile := filepath.Join(workspaceDir, "js-analysis.json")
	testPlanFile := filepath.Join(workspaceDir, "testplan.json")
	resultsFile := filepath.Join(workspaceDir, "results.json")
	reportFile := filepath.Join(workspaceDir, "report.md")

	// ═══════════════════════════════════════════════════════════════════════════
	// AUTO-RESUME: Checkpoint Manager Initialization (v2.6.4)
	// ═══════════════════════════════════════════════════════════════════════════
	cpFile := *checkpointFile
	if cpFile == "" {
		cpFile = filepath.Join(workspaceDir, "checkpoint.json")
	}
	cpManager := checkpoint.NewManager(cpFile)

	// Define scan phases for checkpoint tracking
	phaseNames := []string{
		"smart-mode",
		"discovery",
		"leaky-paths",
		"js-analysis",
		"param-discovery",
		"learning",
		"waf-testing",
		"assessment",
		"browser-scan",
	}

	// Initialize checkpoint with phase names as targets
	cpManager.Init("auto", phaseNames, map[string]interface{}{
		"target":      target,
		"workspace":   workspaceDir,
		"concurrency": *concurrency,
		"rate_limit":  *rateLimit,
	})

	// Helper to check if phase is completed (for resume)
	isPhaseCompleted := func(name string) bool {
		return cpManager.IsCompleted(name)
	}

	// Helper to mark phase as completed and save checkpoint
	markPhaseCompleted := func(name string) {
		_ = cpManager.MarkCompleted(name)
	}

	// Check for resume mode
	if *resumeScan && cpManager.Exists() {
		state, err := cpManager.Load()
		if err == nil && state != nil {
			ui.PrintInfo(fmt.Sprintf("Resuming scan from checkpoint (started: %s)", state.StartTime.Format(time.RFC3339)))

			completedCount := state.CompletedTargets
			ui.PrintSuccess(fmt.Sprintf("  Restored %d completed phases, resuming from phase %d", completedCount, completedCount+1))
		}
	}

	// Silence unused variable warnings
	_ = isPhaseCompleted
	_ = markPhaseCompleted
	_ = resumeScan
	_ = checkpointFile

	// ═══════════════════════════════════════════════════════════════════════════
	// INTELLIGENCE ENGINE INITIALIZATION (v2.6.4)
	// The brain of auto mode - learns, adapts, builds attack chains
	// ═══════════════════════════════════════════════════════════════════════════
	var brain *intelligence.Engine
	var insightCount int32
	var chainCount int32

	if *enableIntelligence {
		brain = intelligence.NewEngine(&intelligence.Config{
			LearningSensitivity: 0.7,
			MinConfidence:       0.6,
			EnableChains:        true,
			EnableWAFModel:      true,
			MaxChains:           50,
			Verbose:             *intelligenceVerbose,
		})

		// Register insight callback for real-time intelligence
		brain.OnInsight(func(insight *intelligence.Insight) {
			atomic.AddInt32(&insightCount, 1)
			if *intelligenceVerbose && !quietMode {
				priorityStyle := ui.PassStyle
				switch insight.Priority {
				case 1:
					priorityStyle = ui.SeverityStyle("Critical")
				case 2:
					priorityStyle = ui.SeverityStyle("High")
				case 3:
					priorityStyle = ui.SeverityStyle("Medium")
				}
				fmt.Fprintf(os.Stderr, "  🧠 %s: %s\n", priorityStyle.Render(string(insight.Type)), insight.Title)
			}
		})

		// Register attack chain callback
		brain.OnChain(func(chain *intelligence.AttackChain) {
			atomic.AddInt32(&chainCount, 1)
			if !quietMode {
				impactStyle := ui.SeverityStyle("Critical")
				switch chain.Impact {
				case "high":
					impactStyle = ui.SeverityStyle("High")
				case "medium":
					impactStyle = ui.SeverityStyle("Medium")
				}
				fmt.Fprintf(os.Stderr, "  ⛓️  %s: %s (CVSS %.1f)\n",
					impactStyle.Render("ATTACK CHAIN"), chain.Name, chain.CVSS)
			}
		})

		if !quietMode {
			ui.PrintInfo("🧠 Intelligence Engine enabled (adaptive learning, attack chains)")
		}
	}

	// Silence unused variable warnings
	_ = enableIntelligence
	_ = intelligenceVerbose
	_ = insightCount
	_ = chainCount

	fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("Configuration"))
	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Domain", domain)
	if *service != "" {
		ui.PrintConfigLine("Service", *service)
	}
	ui.PrintConfigLine("Workspace", workspaceDir)
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d req/sec", *rateLimit))
	if *enableLeakyPaths {
		ui.PrintConfigLine("Leaky Paths", "Enabled (300+ sensitive paths)")
	}
	if *enableParamDiscovery {
		ui.PrintConfigLine("Param Discovery", "Enabled (Arjun-style)")
	}
	if *enableJA3 {
		profile := *ja3Profile
		if profile == "" {
			profile = "rotating"
		}
		ui.PrintConfigLine("JA3 Rotation", profile)
	}
	if *enableFullRecon {
		ui.PrintConfigLine("Full Recon", "Enabled (unified reconnaissance)")
	}
	fmt.Fprintln(os.Stderr)

	// Create JA3-aware HTTP client if enabled
	var ja3Client *http.Client
	if *enableJA3 {
		ja3Cfg := &tlsja3.Config{
			RotateEvery: 25,
			Timeout:     time.Duration(*timeout) * time.Second,
			SkipVerify:  *skipVerify,
		}
		if *ja3Profile != "" {
			// Use specific profile
			if profile, err := tlsja3.GetProfileByName(*ja3Profile); err == nil {
				ja3Cfg.Profiles = []*tlsja3.JA3Profile{profile}
			}
		}
		ja3Client = tlsja3.CreateFallbackClient(ja3Cfg) // Use fallback for compatibility
	}
	// Silence if unused (when JA3 not enabled)
	_ = ja3Client

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	autoScanID := fmt.Sprintf("auto-%d", time.Now().Unix())
	autoDispCtx, autoDispErr := outFlags.InitDispatcher(autoScanID, target)
	if autoDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Output dispatcher warning: %v", autoDispErr))
	}
	if autoDispCtx != nil {
		defer autoDispCtx.Close()
		autoDispCtx.RegisterDetectionCallbacks(ctx)
		if !quietMode {
			ui.PrintInfo("Real-time integrations enabled (hooks active)")
		}
		// Emit scan start event to hooks
		_ = autoDispCtx.EmitStart(ctx, target, 0, *concurrency, nil)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr)
		ui.PrintWarning("Interrupt received, shutting down gracefully...")
		cancel()
	}()

	// Determine output mode for LiveProgress
	autoOutputMode := ui.OutputModeInteractive
	if outFlags.JSONMode {
		autoOutputMode = ui.OutputModeSilent
	} else if outFlags.StreamMode {
		autoOutputMode = ui.OutputModeStreaming
	}

	// Use unified LiveProgress for phases
	autoProgress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        7, // 7 major phases: smart mode, discover, JS, learn, run, assess, browser
		DisplayLines: 3,
		Title:        "Auto mode",
		Unit:         "phases",
		Mode:         autoOutputMode,
		Metrics: []ui.MetricConfig{
			{Name: "endpoints", Label: "Endpoints", Icon: "🎯"},
			{Name: "secrets", Label: "Secrets", Icon: "🔑", Highlight: true},
			{Name: "bypasses", Label: "Bypasses", Icon: "⚠️", Highlight: true},
		},
		StreamFormat:   "[PROGRESS] phase {completed}/{total} | {status} | endpoints: {metric:endpoints} | {elapsed}",
		StreamInterval: duration.StreamSlow,
	})
	autoProgress.Start()
	defer autoProgress.Stop()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 0: SMART MODE - WAF DETECTION & STRATEGY OPTIMIZATION (Optional)
	// ═══════════════════════════════════════════════════════════════════════════
	var smartResult *SmartModeResult
	if *smartMode {
		printStatusLn(ui.SectionStyle.Render("PHASE 0: Smart Mode - WAF Detection & Strategy Optimization"))
		printStatusLn()

		ui.PrintInfo("🧠 Detecting WAF vendor from 197+ signatures...")

		smartConfig := &SmartModeConfig{
			DetectionTimeout: time.Duration(*timeout) * time.Second,
			Verbose:          *smartVerbose,
			Mode:             *smartModeType,
		}

		var err error
		smartResult, err = DetectAndOptimize(ctx, target, smartConfig)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", err))
		}

		if !quietMode {
			PrintSmartModeInfo(smartResult, *smartVerbose)
		}

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
			if autoDispCtx != nil {
				wafDesc := fmt.Sprintf("Smart mode detected: %s (%.0f%% confidence)", smartResult.VendorName, smartResult.Confidence*100)
				_ = autoDispCtx.EmitBypass(ctx, "smart-waf-detection", "info", target, wafDesc, 0)
				// Emit bypass hints as actionable intelligence
				for _, hint := range smartResult.BypassHints {
					_ = autoDispCtx.EmitBypass(ctx, "bypass-hint", "info", target, hint, 0)
				}
			}
		}
		printStatusLn()
	}
	// Silence unused variable warning when smart mode not enabled
	_ = smartVerbose
	_ = smartModeType

	// Update progress after smart mode
	autoProgress.SetStatus("Discovery")
	autoProgress.Increment()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 1: DISCOVERY
	// ═══════════════════════════════════════════════════════════════════════════
	printStatusLn(ui.SectionStyle.Render("PHASE 1: Target Discovery & Reconnaissance"))
	printStatusLn()

	discoveryCfg := discovery.DiscoveryConfig{
		Target:      target,
		Service:     *service,
		Timeout:     time.Duration(*timeout) * time.Second,
		Concurrency: *concurrency,
		MaxDepth:    *depth,
		SkipVerify:  *skipVerify,
		Verbose:     *verbose,
		HTTPClient:  ja3Client, // JA3 TLS fingerprint rotation
	}

	discoverer := discovery.NewDiscoverer(discoveryCfg)

	ui.PrintInfo("🔍 Starting endpoint discovery...")
	discResult, err := discoverer.Discover(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("Discovery failed: %v", err)
		ui.PrintError(errMsg)
		_ = autoDispCtx.EmitError(ctx, "auto", errMsg, true)
		os.Exit(1)
	}

	if err := discResult.SaveResult(discoveryFile); err != nil {
		errMsg := fmt.Sprintf("Error saving discovery: %v", err)
		ui.PrintError(errMsg)
		_ = autoDispCtx.EmitError(ctx, "auto", errMsg, true)
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("✓ Discovered %d endpoints", len(discResult.Endpoints)))
	if discResult.WAFDetected {
		ui.PrintInfo(fmt.Sprintf("  WAF Detected: %s", discResult.WAFFingerprint))
	}
	printStatusLn()

	// Update progress after discovery
	autoProgress.SetMetric("endpoints", int64(len(discResult.Endpoints)))
	autoProgress.SetStatus("Leaky paths")
	autoProgress.Increment()

	// Mark discovery phase complete for resume
	markPhaseCompleted("discovery")

	// Feed discovery findings to Intelligence Engine
	if brain != nil {
		brain.StartPhase(ctx, "discovery")
		for _, ep := range discResult.Endpoints {
			brain.LearnFromFinding(&intelligence.Finding{
				Phase:      "discovery",
				Category:   "endpoint",
				Severity:   "info",
				Path:       ep.Path,
				Evidence:   ep.Method + " " + ep.Path,
				Confidence: 0.8,
				Metadata: map[string]interface{}{
					"method":   ep.Method,
					"category": ep.Category,
				},
			})
		}
		if discResult.WAFDetected {
			brain.LearnFromFinding(&intelligence.Finding{
				Phase:      "discovery",
				Category:   "waf",
				Severity:   "info",
				Evidence:   discResult.WAFFingerprint,
				Confidence: 0.9,
			})
		}
		brain.EndPhase("discovery")
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 1.5: LEAKY PATHS SCANNING (NEW - competitive feature from leaky-paths)
	// ═══════════════════════════════════════════════════════════════════════════
	leakyPathsFile := filepath.Join(workspaceDir, "leaky-paths.json")
	var leakyResult *leakypaths.ScanSummary

	if *enableLeakyPaths {
		printStatusLn(ui.SectionStyle.Render("PHASE 1.5: Sensitive Path Scanning (leaky-paths)"))
		printStatusLn()

		// Filter categories if specified
		var categories []string
		if *leakyCategories != "" {
			categories = strings.Split(*leakyCategories, ",")
			ui.PrintInfo(fmt.Sprintf("🔓 Scanning for sensitive paths (categories: %s)...", *leakyCategories))
		} else {
			ui.PrintInfo("🔓 Scanning 1,766+ high-value sensitive paths...")
		}

		// Show what we're looking for
		printStatusLn()
		printStatus("  %s\n", ui.SubtitleStyle.Render("  Targets: .git, .env, admin panels, backups, configs, debug endpoints..."))
		printStatusLn()

		leakyScanner := leakypaths.NewScanner(&leakypaths.Config{
			Timeout:     time.Duration(*timeout) * time.Second,
			Concurrency: *concurrency,
			Verbose:     *verbose,
			HTTPClient:  ja3Client, // JA3 TLS fingerprint rotation
		})

		var err error
		leakyResult, err = leakyScanner.Scan(ctx, target, categories...)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Leaky paths scan warning: %v", err))
		} else {
			// Save results
			leakyData, _ := json.MarshalIndent(leakyResult, "", "  ")
			os.WriteFile(leakyPathsFile, leakyData, 0644)

			// Summary with timing
			ui.PrintSuccess(fmt.Sprintf("✓ Scanned %d paths in %s", leakyResult.TotalPaths, leakyResult.Duration.Round(time.Millisecond)))
			printStatusLn()

			if leakyResult.InterestingHits > 0 && !quietMode {
				// Show severity breakdown in nuclei-style
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("📊 Findings by Severity:"))
				for severity, count := range leakyResult.BySeverity {
					sevStyle := ui.SeverityStyle(severity)
					bar := strings.Repeat("█", min(count, 20))
					fmt.Fprintf(os.Stderr, "    %s %s %d\n", sevStyle.Render(fmt.Sprintf("%-8s", severity)), ui.ProgressFullStyle.Render(bar), count)
				}
				fmt.Fprintln(os.Stderr)

				// Show category breakdown
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("📂 Findings by Category:"))
				for category, count := range leakyResult.ByCategory {
					bar := strings.Repeat("▪", min(count, 20))
					fmt.Fprintf(os.Stderr, "    %-15s %s %d\n", category, ui.StatLabelStyle.Render(bar), count)
				}
				fmt.Fprintln(os.Stderr)

				// Show top findings in nuclei-style bracketed format
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("🎯 Top Findings:"))
				shownCount := 0
				for _, result := range leakyResult.Results {
					if !result.Interesting {
						continue
					}
					if shownCount >= 10 {
						remaining := leakyResult.InterestingHits - 10
						if remaining > 0 {
							fmt.Fprintf(os.Stderr, "    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more findings (see %s)", remaining, leakyPathsFile)))
						}
						break
					}
					// Nuclei-style output: [severity] [category] path [status]
					sevStyle := ui.SeverityStyle(result.Severity)
					statusStyle := ui.StatusCodeStyle(result.StatusCode)
					fmt.Fprintf(os.Stderr, "    %s%s%s %s%s%s %s %s%s%s\n",
						ui.BracketStyle.Render("["),
						sevStyle.Render(strings.ToLower(result.Severity)),
						ui.BracketStyle.Render("]"),
						ui.BracketStyle.Render("["),
						ui.CategoryStyle.Render(result.Category),
						ui.BracketStyle.Render("]"),
						ui.ConfigValueStyle.Render(result.Path),
						ui.BracketStyle.Render("["),
						statusStyle.Render(fmt.Sprintf("%d", result.StatusCode)),
						ui.BracketStyle.Render("]"),
					)
					shownCount++
				}

				// Emit leaky-paths findings to hooks (sensitive path exposure)
				if autoDispCtx != nil {
					for _, result := range leakyResult.Results {
						if result.Interesting {
							leakyDesc := fmt.Sprintf("Sensitive path exposed: %s (%s)", result.Path, result.Category)
							_ = autoDispCtx.EmitBypass(ctx, "sensitive-path-exposure", result.Severity, target, leakyDesc, result.StatusCode)
						}
					}
				}
			} else {
				ui.PrintSuccess("  ✓ No sensitive paths exposed - good security posture!")
			}
		}
		if !quietMode {
			fmt.Fprintln(os.Stderr)
		}
	}
	// Silence unused variable warnings
	_ = enableLeakyPaths
	_ = leakyCategories

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 2: DEEP JAVASCRIPT ANALYSIS
	// ═══════════════════════════════════════════════════════════════════════════
	printStatusLn(ui.SectionStyle.Render("PHASE 2: Deep JavaScript Analysis"))
	printStatusLn()

	ui.PrintInfo("📜 Extracting and analyzing JavaScript files...")

	// Collect all JS files from discovery
	jsFiles := make([]string, 0)
	for _, ep := range discResult.Endpoints {
		if strings.HasSuffix(ep.Path, ".js") {
			jsFiles = append(jsFiles, ep.Path)
		}
	}

	// Also check for common config files
	configPaths := []string{"/config.js", "/admin/config.js", "/app.config.js", "/env.js", "/settings.js"}
	for _, p := range configPaths {
		found := false
		for _, existing := range jsFiles {
			if existing == p {
				found = true
				break
			}
		}
		if !found {
			jsFiles = append(jsFiles, p)
		}
	}

	// Analyze each JS file
	jsAnalyzer := js.NewAnalyzer()
	allJSData := &js.ExtractedData{
		URLs:       make([]js.URLInfo, 0),
		Endpoints:  make([]js.EndpointInfo, 0),
		Secrets:    make([]js.SecretInfo, 0),
		DOMSinks:   make([]js.DOMSinkInfo, 0),
		CloudURLs:  make([]js.CloudURL, 0),
		Subdomains: make([]string, 0),
	}

	// Use JA3-aware client if enabled, otherwise standard client
	var client *http.Client
	if ja3Client != nil {
		client = ja3Client
	} else {
		client = httpclient.New(httpclient.WithTimeout(time.Duration(*timeout) * time.Second))
	}

	jsAnalyzed := 0
	totalJSFiles := len(jsFiles)
	var secretsFound, endpointsFound int32

	// Animated progress for JS analysis
	jsProgressDone := make(chan struct{})
	jsSpinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	jsFrameIdx := 0
	jsStartTime := time.Now()

	if totalJSFiles > 1 && !outFlags.StreamMode && !quietMode {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-jsProgressDone:
					return
				case <-ticker.C:
					analyzed := jsAnalyzed
					secrets := atomic.LoadInt32(&secretsFound)
					endpoints := atomic.LoadInt32(&endpointsFound)
					elapsed := time.Since(jsStartTime)

					spinner := jsSpinnerFrames[jsFrameIdx%len(jsSpinnerFrames)]
					jsFrameIdx++

					percent := float64(0)
					if totalJSFiles > 0 {
						percent = float64(analyzed) / float64(totalJSFiles) * 100
					}

					progressWidth := 25
					fillWidth := int(float64(progressWidth) * percent / 100)
					bar := fmt.Sprintf("[%s%s]",
						strings.Repeat("█", fillWidth),
						strings.Repeat("░", progressWidth-fillWidth))

					secretColor := "\033[32m" // Green
					if secrets > 0 {
						secretColor = "\033[31m" // Red - secrets found!
					}

					fmt.Fprintf(os.Stderr, "\033[2A\033[J")
					fmt.Fprintf(os.Stderr, "  %s %s %.1f%% (%d/%d files)\n", spinner, bar, percent, analyzed, totalJSFiles)
					fmt.Fprintf(os.Stderr, "  📊 Endpoints: %d  %s🔑 Secrets: %d\033[0m  ⏱️  %s\n",
						endpoints, secretColor, secrets, elapsed.Round(time.Second))
				}
			}
		}()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr)
	}

	for _, jsPath := range jsFiles {
		var jsURL string
		if !strings.HasPrefix(jsPath, "http") {
			jsURL = strings.TrimSuffix(target, "/") + jsPath
		} else {
			jsURL = jsPath
		}

		req, err := http.NewRequest("GET", jsURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				iohelper.DrainAndClose(resp.Body) // Drain for connection reuse
			}
			continue
		}

		body, err := iohelper.ReadBody(resp.Body, 5*1024*1024) // 5MB limit
		iohelper.DrainAndClose(resp.Body)                      // Drain for connection reuse
		if err != nil {
			continue
		}

		jsCode := string(body)
		result := jsAnalyzer.Analyze(jsCode)

		// Merge results
		allJSData.URLs = append(allJSData.URLs, result.URLs...)
		allJSData.Endpoints = append(allJSData.Endpoints, result.Endpoints...)
		allJSData.Secrets = append(allJSData.Secrets, result.Secrets...)
		allJSData.DOMSinks = append(allJSData.DOMSinks, result.DOMSinks...)
		allJSData.CloudURLs = append(allJSData.CloudURLs, result.CloudURLs...)
		allJSData.Subdomains = append(allJSData.Subdomains, result.Subdomains...)
		jsAnalyzed++

		// Update atomic counters for progress display
		atomic.AddInt32(&secretsFound, int32(len(result.Secrets)))
		atomic.AddInt32(&endpointsFound, int32(len(result.Endpoints)))

		if *verbose {
			ui.PrintInfo(fmt.Sprintf("  Analyzed: %s (%d URLs, %d endpoints, %d secrets)",
				jsPath, len(result.URLs), len(result.Endpoints), len(result.Secrets)))
		}
	}

	// Stop JS analysis progress display
	if totalJSFiles > 1 {
		close(jsProgressDone)
		time.Sleep(50 * time.Millisecond)
		if !quietMode {
			fmt.Fprintf(os.Stderr, "\033[2A\033[J")
		}
	}

	// Deduplicate subdomains
	subdomainMap := make(map[string]bool)
	for _, sub := range allJSData.Subdomains {
		subdomainMap[sub] = true
	}
	allJSData.Subdomains = make([]string, 0, len(subdomainMap))
	for sub := range subdomainMap {
		allJSData.Subdomains = append(allJSData.Subdomains, sub)
	}

	// Save JS analysis
	jsDataBytes, _ := json.MarshalIndent(allJSData, "", "  ")
	os.WriteFile(jsAnalysisFile, jsDataBytes, 0644)

	ui.PrintSuccess(fmt.Sprintf("✓ Analyzed %d JavaScript files", jsAnalyzed))
	ui.PrintInfo(fmt.Sprintf("  Found: %d URLs, %d endpoints, %d secrets, %d DOM sinks",
		len(allJSData.URLs), len(allJSData.Endpoints), len(allJSData.Secrets), len(allJSData.DOMSinks)))

	// Update progress after JS analysis
	autoProgress.AddMetricN("secrets", int64(len(allJSData.Secrets)))
	autoProgress.SetStatus("Learning")
	autoProgress.Increment()

	// Add JS-discovered endpoints to discovery result
	for _, ep := range allJSData.Endpoints {
		method := ep.Method
		if method == "" {
			// Infer method from path/source
			method = inferHTTPMethod(ep.Path, ep.Source)
		}
		discResult.Endpoints = append(discResult.Endpoints, discovery.Endpoint{
			Path:     ep.Path,
			Method:   method,
			Category: "api",
			Service:  "js-discovery",
		})
	}

	// Also add URLs with inferred methods (these may not match endpoint patterns but have method info)
	seenPaths := make(map[string]bool)
	for _, ep := range discResult.Endpoints {
		seenPaths[ep.Method+":"+ep.Path] = true
	}
	for _, urlInfo := range allJSData.URLs {
		// Only process relative paths that look like API endpoints
		if !strings.HasPrefix(urlInfo.URL, "/") || strings.HasPrefix(urlInfo.URL, "//") {
			continue
		}
		// Skip static files
		if strings.HasSuffix(urlInfo.URL, ".js") || strings.HasSuffix(urlInfo.URL, ".css") ||
			strings.HasSuffix(urlInfo.URL, ".png") || strings.HasSuffix(urlInfo.URL, ".jpg") ||
			strings.HasSuffix(urlInfo.URL, ".svg") || strings.HasSuffix(urlInfo.URL, ".woff") {
			continue
		}
		method := urlInfo.Method
		if method == "" {
			method = "GET"
		}
		key := method + ":" + urlInfo.URL
		if seenPaths[key] {
			continue
		}
		seenPaths[key] = true
		discResult.Endpoints = append(discResult.Endpoints, discovery.Endpoint{
			Path:     urlInfo.URL,
			Method:   method,
			Category: "api",
			Service:  "js-analysis",
		})
	}

	// Print secrets if found
	if len(allJSData.Secrets) > 0 && !quietMode {
		fmt.Fprintln(os.Stderr)
		ui.PrintSection("🔑 Secrets Detected in JavaScript")
		for _, secret := range allJSData.Secrets {
			severity := strings.ToUpper(secret.Confidence)
			if severity == "" {
				severity = "LOW"
			}
			truncated := secret.Value
			if len(truncated) > 50 {
				truncated = truncated[:50] + "..."
			}
			ui.PrintError(fmt.Sprintf("  [%s] %s: %s", severity, secret.Type, truncated))
		}
	}

	// Emit JS secrets to hooks (critical findings)
	if autoDispCtx != nil && len(allJSData.Secrets) > 0 {
		for _, secret := range allJSData.Secrets {
			severity := strings.ToUpper(secret.Confidence)
			if severity == "" {
				severity = "medium"
			}
			secretDesc := fmt.Sprintf("JS secret found: %s", secret.Type)
			_ = autoDispCtx.EmitBypass(ctx, "js-secret-exposure", severity, target, secretDesc, 0)
		}
	}

	// Emit DOM XSS sinks to hooks (potential XSS vulnerabilities)
	if autoDispCtx != nil && len(allJSData.DOMSinks) > 0 {
		for _, sink := range allJSData.DOMSinks {
			sinkDesc := fmt.Sprintf("DOM XSS sink: %s in %s", sink.Sink, sink.Context)
			_ = autoDispCtx.EmitBypass(ctx, "js-dom-xss-sink", sink.Severity, target, sinkDesc, 0)
		}
	}

	// Emit discovered subdomains to hooks (attack surface expansion)
	if autoDispCtx != nil && len(allJSData.Subdomains) > 0 {
		for _, sub := range allJSData.Subdomains {
			subDesc := fmt.Sprintf("Subdomain discovered in JS: %s", sub)
			_ = autoDispCtx.EmitBypass(ctx, "js-subdomain-discovery", "info", target, subDesc, 0)
		}
	}

	// Emit cloud URLs to hooks (potential misconfigurations)
	if autoDispCtx != nil && len(allJSData.CloudURLs) > 0 {
		for _, cloudURL := range allJSData.CloudURLs {
			cloudDesc := fmt.Sprintf("Cloud URL in JS: %s (%s)", cloudURL.URL, cloudURL.Service)
			_ = autoDispCtx.EmitBypass(ctx, "js-cloud-url", "medium", target, cloudDesc, 0)
		}
	}

	if len(allJSData.Subdomains) > 0 && !quietMode {
		fmt.Fprintln(os.Stderr)
		ui.PrintSection("🌐 Subdomains Discovered")
		for _, sub := range allJSData.Subdomains[:min(10, len(allJSData.Subdomains))] {
			ui.PrintInfo("  " + sub)
		}
		if len(allJSData.Subdomains) > 10 {
			ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(allJSData.Subdomains)-10))
		}
	}
	if !quietMode {
		fmt.Fprintln(os.Stderr)
	}

	// Feed JS analysis findings to Intelligence Engine
	if brain != nil {
		brain.StartPhase(ctx, "js-analysis")
		// Secrets - highest priority
		for _, secret := range allJSData.Secrets {
			brain.LearnFromFinding(&intelligence.Finding{
				Phase:      "js-analysis",
				Category:   "secret",
				Severity:   "high",
				Evidence:   secret.Type + ": " + secret.Value[:min(30, len(secret.Value))],
				Confidence: 0.9,
				Metadata:   map[string]interface{}{"type": secret.Type},
			})
		}
		// Endpoints
		for _, ep := range allJSData.Endpoints {
			brain.LearnFromFinding(&intelligence.Finding{
				Phase:      "js-analysis",
				Category:   "endpoint",
				Severity:   "info",
				Path:       ep.Path,
				Evidence:   ep.Method + " " + ep.Path,
				Confidence: 0.7,
			})
		}
		// DOM sinks
		for _, sink := range allJSData.DOMSinks {
			brain.LearnFromFinding(&intelligence.Finding{
				Phase:      "js-analysis",
				Category:   "dom-sink",
				Severity:   sink.Severity,
				Evidence:   sink.Sink + " in " + sink.Context,
				Confidence: 0.8,
			})
		}
		// Cloud URLs
		for _, cloud := range allJSData.CloudURLs {
			brain.LearnFromFinding(&intelligence.Finding{
				Phase:      "js-analysis",
				Category:   "cloud-url",
				Severity:   "medium",
				Path:       cloud.URL,
				Evidence:   cloud.Service,
				Confidence: 0.85,
			})
		}
		brain.EndPhase("js-analysis")
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 2.5: PARAMETER DISCOVERY (NEW - competitive feature from Arjun)
	// ═══════════════════════════════════════════════════════════════════════════
	paramsFile := filepath.Join(workspaceDir, "discovered-params.json")
	var paramResult *params.DiscoveryResult

	if *enableParamDiscovery {
		printStatusLn(ui.SectionStyle.Render("PHASE 2.5: Parameter Discovery (Arjun-style)"))
		printStatusLn()

		ui.PrintInfo("🔍 Discovering hidden API parameters...")
		printStatusLn()
		printStatus("  %s\n", ui.SubtitleStyle.Render("  Technique: Chunked parameter injection (256 params/request)"))
		printStatus("  %s\n", ui.SubtitleStyle.Render("  Wordlist: 1,000+ common parameters (id, key, token, debug, admin...)"))
		printStatusLn()

		paramDiscoverer := params.NewDiscoverer(&params.Config{
			Timeout:     time.Duration(*timeout) * time.Second,
			Concurrency: *concurrency,
			Verbose:     *verbose,
			ChunkSize:   256, // Test 256 params per request for efficiency
			HTTPClient:  ja3Client,
		})

		// Test discovered endpoints for hidden params
		testEndpoints := make([]string, 0, len(discResult.Endpoints))
		for _, ep := range discResult.Endpoints {
			// Skip static files
			if strings.HasSuffix(ep.Path, ".js") || strings.HasSuffix(ep.Path, ".css") ||
				strings.HasSuffix(ep.Path, ".png") || strings.HasSuffix(ep.Path, ".jpg") {
				continue
			}
			fullURL := strings.TrimSuffix(target, "/") + ep.Path
			testEndpoints = append(testEndpoints, fullURL)
		}

		// Limit to first 20 endpoints to avoid too long scan
		if len(testEndpoints) > 20 {
			testEndpoints = testEndpoints[:20]
		}

		if len(testEndpoints) > 0 {
			ui.PrintInfo(fmt.Sprintf("  Testing %d endpoints for hidden parameters...", len(testEndpoints)))
			printStatusLn()

			// Discover params for each endpoint with animated progress display
			allParams := make([]params.DiscoveredParam, 0)
			paramStartTime := time.Now()
			var paramCompleted int32
			var paramsFoundCount int32
			paramProgressDone := make(chan struct{})
			paramSpinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			paramFrameIdx := 0
			totalEndpoints := len(testEndpoints)

			if !outFlags.StreamMode && !quietMode {
				go func() {
					ticker := time.NewTicker(100 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-paramProgressDone:
							return
						case <-ticker.C:
							done := atomic.LoadInt32(&paramCompleted)
							found := atomic.LoadInt32(&paramsFoundCount)
							elapsed := time.Since(paramStartTime)

							spinner := paramSpinnerFrames[paramFrameIdx%len(paramSpinnerFrames)]
							paramFrameIdx++

							percent := float64(done) / float64(totalEndpoints) * 100
							progressWidth := 25
							fillWidth := int(float64(progressWidth) * percent / 100)
							bar := fmt.Sprintf("[%s%s]",
								strings.Repeat("█", fillWidth),
								strings.Repeat("░", progressWidth-fillWidth))

							paramColor := "\033[33m" // Yellow
							if found > 0 {
								paramColor = "\033[32m" // Green - params found!
							}

							fmt.Fprintf(os.Stderr, "\033[2A\033[J")
							fmt.Fprintf(os.Stderr, "  %s %s %.1f%% (%d/%d endpoints)\n", spinner, bar, percent, done, totalEndpoints)
							fmt.Fprintf(os.Stderr, "  %s🔍 Parameters found: %d\033[0m  ⏱️  %s\n",
								paramColor, found, elapsed.Round(time.Second))
						}
					}
				}()
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr)
			} // end if !outFlags.StreamMode

			for _, endpoint := range testEndpoints {
				result, err := paramDiscoverer.Discover(ctx, endpoint)
				if err != nil {
					if *verbose && !quietMode {
						fmt.Fprintln(os.Stderr)
						ui.PrintWarning(fmt.Sprintf("  Warning for %s: %v", endpoint, err))
					}
					atomic.AddInt32(&paramCompleted, 1)
					continue
				}
				allParams = append(allParams, result.Parameters...)
				atomic.AddInt32(&paramsFoundCount, int32(len(result.Parameters)))
				atomic.AddInt32(&paramCompleted, 1)
			}

			// Stop progress display
			close(paramProgressDone)
			time.Sleep(50 * time.Millisecond)
			if !quietMode {
				fmt.Fprintf(os.Stderr, "\033[2A\033[J")
			}

			duration := time.Since(paramStartTime)

			// Create combined result
			paramResult = &params.DiscoveryResult{
				Target:      target,
				TotalTested: len(testEndpoints),
				FoundParams: len(allParams),
				Duration:    duration,
				Parameters:  allParams,
				BySource:    make(map[string]int),
				ByType:      make(map[string]int),
			}
			for _, p := range allParams {
				paramResult.BySource[p.Source]++
				paramResult.ByType[p.Type]++
			}

			// Save results
			paramData, _ := json.MarshalIndent(paramResult, "", "  ")
			os.WriteFile(paramsFile, paramData, 0644)

			ui.PrintSuccess(fmt.Sprintf("✓ Scanned %d endpoints in %s", len(testEndpoints), duration.Round(time.Millisecond)))

			if len(allParams) > 0 && !quietMode {
				fmt.Fprintln(os.Stderr)
				// Show type breakdown
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("📊 Parameters by Type:"))
				for paramType, count := range paramResult.ByType {
					typeStyle := ui.ConfigValueStyle
					switch paramType {
					case "query":
						typeStyle = ui.PassStyle
					case "body":
						typeStyle = ui.BlockedStyle
					case "header":
						typeStyle = ui.ErrorStyle
					}
					bar := strings.Repeat("█", min(count, 20))
					fmt.Fprintf(os.Stderr, "    %s %s %d\n", typeStyle.Render(fmt.Sprintf("%-8s", paramType)), ui.ProgressFullStyle.Render(bar), count)
				}
				fmt.Fprintln(os.Stderr)

				// Show source breakdown
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("🔎 Discovery Sources:"))
				for source, count := range paramResult.BySource {
					bar := strings.Repeat("▪", min(count, 20))
					fmt.Fprintf(os.Stderr, "    %-15s %s %d\n", source, ui.StatLabelStyle.Render(bar), count)
				}
				fmt.Fprintln(os.Stderr)

				// Show top findings in nuclei-style
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("🎯 Discovered Parameters:"))
				for i, p := range allParams {
					if i >= 10 {
						remaining := len(allParams) - 10
						if remaining > 0 {
							fmt.Fprintf(os.Stderr, "    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more parameters (see %s)", remaining, paramsFile)))
						}
						break
					}
					// Nuclei-style output: [type] [source] name [confidence]
					typeStyle := ui.ConfigValueStyle
					switch p.Type {
					case "query":
						typeStyle = ui.PassStyle
					case "body":
						typeStyle = ui.BlockedStyle
					case "header":
						typeStyle = ui.ErrorStyle
					}
					confPercent := int(p.Confidence * 100)
					fmt.Fprintf(os.Stderr, "    %s%s%s %s%s%s %s %s%d%%%s\n",
						ui.BracketStyle.Render("["),
						typeStyle.Render(p.Type),
						ui.BracketStyle.Render("]"),
						ui.BracketStyle.Render("["),
						ui.CategoryStyle.Render(p.Source),
						ui.BracketStyle.Render("]"),
						ui.ConfigValueStyle.Render(p.Name),
						ui.BracketStyle.Render("["),
						confPercent,
						ui.BracketStyle.Render("]"),
					)
				}

				// Emit hidden parameters to hooks (potential attack surface)
				if autoDispCtx != nil {
					for _, p := range allParams {
						paramDesc := fmt.Sprintf("Hidden parameter discovered: %s (%s via %s)", p.Name, p.Type, p.Source)
						_ = autoDispCtx.EmitBypass(ctx, "hidden-parameter", "info", target, paramDesc, 0)
					}
				}
			} else if !quietMode {
				ui.PrintSuccess("  ✓ No hidden parameters discovered - endpoints are well-documented!")
			}
		} else {
			ui.PrintInfo("  ⏭️  No suitable endpoints found for parameter discovery")
			ui.PrintInfo("     (Need API endpoints from Phase 1 to test for hidden params)")
		}
		if !quietMode {
			fmt.Fprintln(os.Stderr)
		}
	}
	// Full Recon Mode - runs unified reconnaissance if enabled
	var fullReconResult *recon.FullReconResult
	if *enableFullRecon {
		printStatusLn(ui.SectionStyle.Render("PHASE 2.7: Unified Reconnaissance (Full Recon)"))
		printStatusLn()

		ui.PrintInfo("🔬 Running comprehensive reconnaissance scan...")
		if !quietMode {
			fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("  Combining: leaky-paths + param-discovery + JS analysis + JA3 rotation"))
			fmt.Fprintln(os.Stderr)
		}

		// Handle empty categories - nil means all categories, not [""] which matches nothing
		var leakyPathCats []string
		if *leakyCategories != "" {
			leakyPathCats = strings.Split(*leakyCategories, ",")
		}

		reconScanner := recon.NewScanner(&recon.Config{
			Timeout:              time.Duration(*timeout) * time.Second,
			Concurrency:          *concurrency,
			Verbose:              *verbose,
			SkipTLSVerify:        *skipVerify,
			HTTPClient:           ja3Client, // JA3 TLS fingerprint rotation
			EnableLeakyPaths:     *enableLeakyPaths,
			EnableParamDiscovery: *enableParamDiscovery,
			EnableJSAnalysis:     true,
			EnableJA3Rotation:    *enableJA3,
			LeakyPathCategories:  leakyPathCats,
			JA3Profile:           *ja3Profile,
			ParamWordlist:        *paramWordlist,
		})

		var err error
		fullReconResult, err = reconScanner.FullScan(ctx, target)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Full recon warning: %v", err))
		} else {
			// Save recon results
			reconFile := filepath.Join(workspaceDir, "full-recon.json")
			reconData, _ := json.MarshalIndent(fullReconResult, "", "  ")
			os.WriteFile(reconFile, reconData, 0644)

			ui.PrintSuccess(fmt.Sprintf("✓ Full reconnaissance completed in %s", fullReconResult.Duration.Round(time.Millisecond)))

			if !quietMode {
				fmt.Fprintln(os.Stderr)

				// Show risk assessment
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("📊 Risk Assessment:"))
				riskStyle := ui.PassStyle
				switch fullReconResult.RiskLevel {
				case "critical":
					riskStyle = ui.SeverityStyle("Critical")
				case "high":
					riskStyle = ui.SeverityStyle("High")
				case "medium":
					riskStyle = ui.SeverityStyle("Medium")
				}
				fmt.Fprintf(os.Stderr, "    Risk Score: %s (%.1f/100)\n", riskStyle.Render(fullReconResult.RiskLevel), fullReconResult.RiskScore)
				fmt.Fprintln(os.Stderr)

				if len(fullReconResult.TopRisks) > 0 {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("⚠️  Top Risks:"))
					for _, risk := range fullReconResult.TopRisks[:min(5, len(fullReconResult.TopRisks))] {
						ui.PrintWarning(fmt.Sprintf("    • %s", risk))
					}
					fmt.Fprintln(os.Stderr)
				}

				// Emit full recon findings to hooks
				if autoDispCtx != nil {
					// Emit risk assessment
					riskDesc := fmt.Sprintf("Full recon risk: %s (%.1f/100)", fullReconResult.RiskLevel, fullReconResult.RiskScore)
					_ = autoDispCtx.EmitBypass(ctx, "recon-risk-assessment", fullReconResult.RiskLevel, target, riskDesc, 0)
					// Emit top risks as individual findings
					for _, risk := range fullReconResult.TopRisks {
						_ = autoDispCtx.EmitBypass(ctx, "recon-top-risk", "high", target, risk, 0)
					}
				}
			}
		}
	}
	_ = fullReconResult // May be unused if full-recon not enabled

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 3: INTELLIGENT LEARNING
	// ═══════════════════════════════════════════════════════════════════════════
	printStatusLn(ui.SectionStyle.Render("PHASE 3: Intelligent Test Plan Generation"))
	printStatusLn()

	ui.PrintInfo("🧠 Analyzing attack surface and generating test plan...")

	learner := learning.NewLearner(discResult, payloadDir)
	testPlan := learner.GenerateTestPlan()

	// Save test plan
	planData, _ := json.MarshalIndent(testPlan, "", "  ")
	os.WriteFile(testPlanFile, planData, 0644)

	ui.PrintSuccess(fmt.Sprintf("✓ Generated test plan with %d tests", testPlan.TotalTests))
	ui.PrintInfo(fmt.Sprintf("  Estimated time: %s", testPlan.EstimatedTime))

	if !quietMode {
		fmt.Fprintln(os.Stderr)

		// Show test categories
		fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("Test Categories:"))
		for _, group := range testPlan.TestGroups {
			fmt.Fprintf(os.Stderr, "    [P%d] %s - %s\n", group.Priority, group.Category, group.Reason)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Update progress after learning phase
	autoProgress.SetStatus("Testing")
	autoProgress.Increment()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 4: WAF SECURITY TESTING
	// ═══════════════════════════════════════════════════════════════════════════
	printStatusLn(ui.SectionStyle.Render("PHASE 4: WAF Security Testing"))
	printStatusLn()

	ui.PrintInfo("⚡ Executing security tests with auto-calibration...")
	printStatusLn()

	// Load payloads
	loader := payloads.NewLoader(payloadDir)
	allPayloads, err := loader.LoadAll()
	if err != nil {
		errMsg := fmt.Sprintf("Error loading payloads: %v", err)
		ui.PrintError(errMsg)
		_ = autoDispCtx.EmitError(ctx, "auto", errMsg, true)
		os.Exit(1)
	}

	// Filter payloads based on test plan categories
	if len(testPlan.RecommendedFlags.Categories) > 0 {
		var filteredPayloads []payloads.Payload
		categorySet := make(map[string]bool)
		for _, cat := range testPlan.RecommendedFlags.Categories {
			categorySet[strings.ToLower(cat)] = true
		}
		for _, p := range allPayloads {
			if categorySet[strings.ToLower(p.Category)] {
				filteredPayloads = append(filteredPayloads, p)
			}
		}
		allPayloads = filteredPayloads
	}

	// Smart payload→endpoint routing based on category matching
	// This ensures XSS goes to HTML endpoints, SQLi to API endpoints, etc.
	if len(discResult.Endpoints) > 0 {
		ui.PrintInfo(fmt.Sprintf("🎯 Smart-routing payloads to %d discovered endpoints...", len(discResult.Endpoints)))

		// Categorize endpoints by type
		apiEndpoints := []discovery.Endpoint{}
		authEndpoints := []discovery.Endpoint{}
		uploadEndpoints := []discovery.Endpoint{}
		graphqlEndpoints := []discovery.Endpoint{}
		otherEndpoints := []discovery.Endpoint{}

		for _, ep := range discResult.Endpoints {
			pathLower := strings.ToLower(ep.Path)
			switch {
			case strings.Contains(pathLower, "graphql"):
				graphqlEndpoints = append(graphqlEndpoints, ep)
			case strings.Contains(pathLower, "upload") || strings.Contains(pathLower, "file"):
				uploadEndpoints = append(uploadEndpoints, ep)
			case strings.Contains(pathLower, "auth") || strings.Contains(pathLower, "login") ||
				strings.Contains(pathLower, "token") || strings.Contains(pathLower, "oauth"):
				authEndpoints = append(authEndpoints, ep)
			case strings.Contains(pathLower, "/api/") || strings.Contains(pathLower, ".json") ||
				ep.ContentType == defaults.ContentTypeJSON:
				apiEndpoints = append(apiEndpoints, ep)
			case strings.HasSuffix(pathLower, ".js") || strings.HasSuffix(pathLower, ".css") ||
				strings.HasSuffix(pathLower, ".png") || strings.HasSuffix(pathLower, ".jpg"):
				// Skip static assets - no security testing needed
			default:
				otherEndpoints = append(otherEndpoints, ep)
			}
		}

		// Route payloads to appropriate endpoints
		for i := range allPayloads {
			var targetEndpoints []discovery.Endpoint
			catLower := strings.ToLower(allPayloads[i].Category)

			switch {
			case strings.Contains(catLower, "sql") || strings.Contains(catLower, "injection"):
				// SQL injection → API endpoints preferentially
				if len(apiEndpoints) > 0 {
					targetEndpoints = apiEndpoints
				}
			case strings.Contains(catLower, "xss") || strings.Contains(catLower, "script"):
				// XSS → non-API endpoints (HTML pages)
				if len(otherEndpoints) > 0 {
					targetEndpoints = otherEndpoints
				}
			case strings.Contains(catLower, "auth") || strings.Contains(catLower, "jwt"):
				// Auth attacks → auth endpoints
				if len(authEndpoints) > 0 {
					targetEndpoints = authEndpoints
				}
			case strings.Contains(catLower, "upload") || strings.Contains(catLower, "file"):
				// File attacks → upload endpoints
				if len(uploadEndpoints) > 0 {
					targetEndpoints = uploadEndpoints
				}
			case strings.Contains(catLower, "graphql"):
				// GraphQL → graphql endpoints
				if len(graphqlEndpoints) > 0 {
					targetEndpoints = graphqlEndpoints
				}
			}

			// Fallback to all endpoints if no specific match
			if len(targetEndpoints) == 0 {
				targetEndpoints = discResult.Endpoints
			}

			// Round-robin within the target category
			endpoint := targetEndpoints[i%len(targetEndpoints)]
			allPayloads[i].TargetPath = endpoint.Path
			// Set method from endpoint if not already specified
			if allPayloads[i].Method == "" && endpoint.Method != "" {
				allPayloads[i].Method = endpoint.Method
			}
		}
	}

	ui.PrintInfo(fmt.Sprintf("Loaded %d payloads for testing", len(allPayloads)))
	printStatusLn()

	// ═══════════════════════════════════════════════════════════════════════════
	// TAMPER ENGINE INITIALIZATION
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

		// Apply tamper transformations to all payloads
		ui.PrintInfo("⚡ Applying tamper transformations to payloads...")
		for i := range allPayloads {
			allPayloads[i].Payload = tamperEngine.Transform(allPayloads[i].Payload)
		}
		ui.PrintSuccess(fmt.Sprintf("✓ Transformed %d payloads with tamper chain", len(allPayloads)))
		printStatusLn()
	}
	// Silence unused variable warning
	_ = tamperList
	_ = tamperAuto
	_ = tamperProfile

	// Auto-calibration
	ui.PrintInfo("Running auto-calibration...")
	cal := calibration.NewCalibratorWithClient(target, time.Duration(*timeout)*time.Second, *skipVerify, ja3Client)
	calResult, calErr := cal.Calibrate(ctx)
	var filterCfg core.FilterConfig
	if calErr == nil && calResult != nil && calResult.Calibrated {
		filterCfg.FilterStatus = calResult.Suggestions.FilterStatus
		filterCfg.FilterSize = calResult.Suggestions.FilterSize
		ui.PrintSuccess(fmt.Sprintf("Calibrated: %s", calResult.Describe()))
	} else if calErr != nil {
		ui.PrintWarning(fmt.Sprintf("Calibration warning: %v", calErr))
	}
	printStatusLn()

	// ═══════════════════════════════════════════════════════════════════════════
	// ADAPTIVE RATE LIMITING (v2.6.4)
	// Auto-adjust rate on WAF detection events (drops, bans, 429s)
	// ═══════════════════════════════════════════════════════════════════════════
	currentRateLimit := *rateLimit
	currentConcurrency := *concurrency
	rateMu := &sync.Mutex{}

	// Create adaptive rate limiter if enabled
	var adaptiveLimiter *ratelimit.Limiter
	if *adaptiveRate {
		adaptiveLimiter = ratelimit.New(&ratelimit.Config{
			RequestsPerSecond: *rateLimit,
			AdaptiveSlowdown:  true,
			SlowdownFactor:    1.5,
			SlowdownMaxDelay:  5 * time.Second,
			RecoveryRate:      0.9,
			Burst:             *concurrency,
		})
		ui.PrintInfo("📊 Adaptive rate limiting enabled (auto-adjusts on WAF response)")
	}

	// Auto-escalation callback: reduce rate when WAF drops/bans detected
	escalationCount := int32(0)
	autoEscalate := func(reason string) {
		count := atomic.AddInt32(&escalationCount, 1)
		if count > 5 {
			// Don't escalate too many times
			return
		}

		rateMu.Lock()
		defer rateMu.Unlock()

		oldRate := currentRateLimit
		oldConc := currentConcurrency

		// Reduce by 50%
		currentRateLimit = currentRateLimit / 2
		if currentRateLimit < 10 {
			currentRateLimit = 10 // Floor
		}
		currentConcurrency = currentConcurrency / 2
		if currentConcurrency < 5 {
			currentConcurrency = 5 // Floor
		}

		ui.PrintWarning(fmt.Sprintf("⚡ Auto-escalation triggered (%s): rate %d→%d, concurrency %d→%d",
			reason, oldRate, currentRateLimit, oldConc, currentConcurrency))

		// Notify adaptive limiter
		if adaptiveLimiter != nil {
			adaptiveLimiter.OnError()
		}

		// Emit to dispatcher
		if autoDispCtx != nil {
			escalateDesc := fmt.Sprintf("Auto-escalation: %s - rate reduced to %d, concurrency to %d",
				reason, currentRateLimit, currentConcurrency)
			_ = autoDispCtx.EmitBypass(ctx, "auto-escalation", "warning", target, escalateDesc, 0)
		}
	}

	// Register detection callbacks for auto-escalation
	detector := detection.Default()
	detector.OnDrop(func(host string, result *detection.DropResult) {
		if result.Consecutive >= 3 {
			autoEscalate(fmt.Sprintf("connection drops (%d consecutive)", result.Consecutive))
		}
	})
	detector.OnBan(func(host string, result *detection.BanResult) {
		if result.Banned {
			autoEscalate(fmt.Sprintf("silent ban detected (%s)", result.Type))
		}
	})

	// Silence unused variable warnings
	_ = adaptiveRate
	_ = adaptiveLimiter
	_ = rateMu

	// Create progress tracker
	progress := ui.NewProgress(ui.ProgressConfig{
		Total:       len(allPayloads),
		Width:       40,
		ShowPercent: true,
		ShowETA:     true,
		ShowRPS:     true,
		Concurrency: currentConcurrency,
		TurboMode:   true,
	})

	// Create output writer for results
	writer, err := output.NewWriterWithOptions(resultsFile, "json", output.WriterOptions{
		Verbose:       *verbose,
		ShowTimestamp: true,
		Silent:        false,
		Target:        target,
	})
	if err != nil {
		errMsg := fmt.Sprintf("Error creating output writer: %v", err)
		ui.PrintError(errMsg)
		_ = autoDispCtx.EmitError(ctx, "auto", errMsg, true)
		os.Exit(1)
	}

	// Print section header
	ui.PrintSection("Executing Tests")
	if !quietMode {
		fmt.Fprintf(os.Stderr, "\n  %s Running with %s parallel workers @ %s req/sec max\n\n",
			ui.SpinnerStyle.Render(">>>"),
			ui.StatValueStyle.Render(fmt.Sprintf("%d", currentConcurrency)),
			ui.StatValueStyle.Render(fmt.Sprintf("%d", currentRateLimit)),
		)
	}

	// Create and run executor (using current adaptive values)
	executor := core.NewExecutor(core.ExecutorConfig{
		TargetURL:     target,
		Concurrency:   currentConcurrency,
		RateLimit:     currentRateLimit,
		Timeout:       time.Duration(*timeout) * time.Second,
		Retries:       defaults.RetryLow,
		Filter:        &filterCfg,
		RealisticMode: true,
		AutoCalibrate: true,
		HTTPClient:    ja3Client, // JA3 TLS fingerprint rotation
		// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
		OnResult: func(result *output.TestResult) {
			// Adaptive rate: call OnError for 429, OnSuccess otherwise
			handleAdaptiveRate(result.StatusCode, result.Outcome, adaptiveLimiter, autoEscalate)

			// Emit every test result for complete telemetry
			if autoDispCtx != nil {
				blocked := result.Outcome == "Blocked"
				_ = autoDispCtx.EmitResult(ctx, result.Category, result.Severity, blocked, result.StatusCode, float64(result.LatencyMs))
			}
			// Additionally emit bypass event for non-blocked results
			if autoDispCtx != nil && result.Outcome != "Blocked" && result.Outcome != "Error" {
				_ = autoDispCtx.EmitBypass(ctx, result.Category, result.Severity, target, result.Payload, result.StatusCode)
			}

			// Feed test result to Intelligence Engine for real-time learning
			if brain != nil {
				brain.LearnFromFinding(&intelligence.Finding{
					Phase:      "waf-testing",
					Category:   result.Category,
					Severity:   result.Severity,
					Path:       result.TargetPath,
					Payload:    result.Payload,
					StatusCode: result.StatusCode,
					Latency:    time.Duration(result.LatencyMs) * time.Millisecond,
					Blocked:    result.Outcome == "Blocked",
					Confidence: 0.95,
					Metadata: map[string]interface{}{
						"outcome": result.Outcome,
						"method":  result.Method,
					},
				})
			}
		},
	})

	progress.Start()
	results := executor.ExecuteWithProgress(ctx, allPayloads, writer, progress)
	progress.Stop()

	writer.Close()

	// Update progress after WAF testing
	autoProgress.AddMetricN("bypasses", int64(results.FailedTests))
	autoProgress.SetStatus("Analysis")
	autoProgress.Increment()

	// Mark WAF testing phase complete for resume
	markPhaseCompleted("waf-testing")

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 4.5: VENDOR-SPECIFIC WAF ANALYSIS (NEW)
	// ═══════════════════════════════════════════════════════════════════════════
	printStatusLn()
	printStatusLn(ui.SectionStyle.Render("PHASE 4.5: Vendor-Specific WAF Analysis"))
	printStatusLn()

	ui.PrintInfo("🔍 Detecting WAF vendor with 150+ signatures...")

	// Vendor detection with comprehensive signature database
	var vendorName string
	var vendorConfidence float64
	var bypassHints []string
	var recommendedEncoders []string
	var recommendedEvasions []string

	// Use the comprehensive vendor detector with 150+ signatures
	vendorDetector := vendors.NewVendorDetectorWithClient(time.Duration(*timeout)*time.Second, ja3Client)
	vendorResult, vendorErr := vendorDetector.Detect(ctx, target)

	if vendorErr == nil && vendorResult.Detected {
		vendorName = vendorResult.VendorName
		vendorConfidence = vendorResult.Confidence
		bypassHints = vendorResult.BypassHints
		recommendedEncoders = vendorResult.RecommendedEncoders
		recommendedEvasions = vendorResult.RecommendedEvasions

		ui.PrintSuccess(fmt.Sprintf("  WAF Vendor: %s (%.0f%% confidence)", vendorName, vendorConfidence*100))

		if !quietMode {
			// Show detection evidence
			if len(vendorResult.Evidence) > 0 {
				for _, ev := range vendorResult.Evidence[:min(3, len(vendorResult.Evidence))] {
					fmt.Fprintf(os.Stderr, "    • %s\n", ev)
				}
			}

			// Show bypass recommendations
			if len(bypassHints) > 0 {
				fmt.Fprintln(os.Stderr)
				ui.PrintInfo("  📋 Bypass Recommendations:")
				for _, hint := range bypassHints[:min(5, len(bypassHints))] {
					fmt.Fprintf(os.Stderr, "    → %s\n", hint)
				}
			}

			// Show recommended encoders/evasions
			if len(recommendedEncoders) > 0 || len(recommendedEvasions) > 0 {
				fmt.Fprintln(os.Stderr)
				ui.PrintInfo("  🔧 Recommended Techniques:")
				if len(recommendedEncoders) > 0 {
					fmt.Fprintf(os.Stderr, "    Encoders: %s\n", strings.Join(recommendedEncoders[:min(4, len(recommendedEncoders))], ", "))
				}
				if len(recommendedEvasions) > 0 {
					fmt.Fprintf(os.Stderr, "    Evasions: %s\n", strings.Join(recommendedEvasions[:min(4, len(recommendedEvasions))], ", "))
				}
			}
		}

		// Emit vendor detection and bypass recommendations to hooks
		if autoDispCtx != nil {
			wafDesc := fmt.Sprintf("WAF vendor detected: %s (%.0f%% confidence)", vendorName, vendorConfidence*100)
			_ = autoDispCtx.EmitBypass(ctx, "waf-vendor-detection", "info", target, wafDesc, 0)
			// Emit bypass hints
			for _, hint := range bypassHints {
				_ = autoDispCtx.EmitBypass(ctx, "bypass-hint", "info", target, hint, 0)
			}
			// Emit recommended techniques
			if len(recommendedEncoders) > 0 {
				encDesc := fmt.Sprintf("Recommended encoders: %s", strings.Join(recommendedEncoders, ", "))
				_ = autoDispCtx.EmitBypass(ctx, "recommended-encoders", "info", target, encDesc, 0)
			}
			if len(recommendedEvasions) > 0 {
				evDesc := fmt.Sprintf("Recommended evasions: %s", strings.Join(recommendedEvasions, ", "))
				_ = autoDispCtx.EmitBypass(ctx, "recommended-evasions", "info", target, evDesc, 0)
			}
		}
	} else if discResult.WAFDetected && discResult.WAFFingerprint != "" {
		// Fallback to discovery result
		vendorName = discResult.WAFFingerprint
		vendorConfidence = 0.6
		ui.PrintInfo(fmt.Sprintf("  WAF Vendor: %s (%.0f%% confidence - from discovery)", vendorName, vendorConfidence*100))
	} else {
		ui.PrintInfo("  No specific WAF vendor detected - using default configuration")
	}
	printStatusLn()

	// End WAF testing phase for Intelligence Engine
	if brain != nil {
		brain.EndPhase("waf-testing")
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// INTELLIGENCE SUMMARY (v2.6.4)
	// Display attack chains, insights, and learned patterns
	// ═══════════════════════════════════════════════════════════════════════════
	if brain != nil && !quietMode {
		summary := brain.GetSummary()

		if summary.AttackChains > 0 || len(summary.WAFWeaknesses) > 0 || len(summary.TechStack) > 0 {
			printStatusLn()
			printStatusLn(ui.SectionStyle.Render("🧠 INTELLIGENCE SUMMARY"))
			printStatusLn()

			// Attack Chains - the crown jewel
			if summary.AttackChains > 0 {
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("⛓️  Attack Chains Built:"))
				for i, chain := range summary.TopChains {
					if i >= 5 {
						fmt.Fprintf(os.Stderr, "    ... and %d more chains\n", summary.AttackChains-5)
						break
					}
					impactStyle := ui.SeverityStyle("Critical")
					switch chain.Impact {
					case "high":
						impactStyle = ui.SeverityStyle("High")
					case "medium":
						impactStyle = ui.SeverityStyle("Medium")
					}
					fmt.Fprintf(os.Stderr, "    %s [%s] %s (CVSS %.1f)\n",
						ui.StatValueStyle.Render(fmt.Sprintf("%d.", i+1)),
						impactStyle.Render(chain.Impact),
						chain.Name,
						chain.CVSS)
					for _, step := range chain.Steps[:min(3, len(chain.Steps))] {
						fmt.Fprintf(os.Stderr, "       %s\n", ui.SubtitleStyle.Render(step))
					}
				}
				fmt.Fprintln(os.Stderr)
			}

			// WAF Behavioral Analysis
			if len(summary.WAFWeaknesses) > 0 {
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("📊 WAF Behavioral Analysis:"))
				fmt.Fprintf(os.Stderr, "    Strengths: %s\n", ui.PassStyle.Render(strings.Join(summary.WAFStrengths[:min(3, len(summary.WAFStrengths))], ", ")))
				fmt.Fprintf(os.Stderr, "    Weaknesses: %s\n", ui.ErrorStyle.Render(strings.Join(summary.WAFWeaknesses[:min(3, len(summary.WAFWeaknesses))], ", ")))
				fmt.Fprintln(os.Stderr)
			}

			// Technology Detection
			if len(summary.TechStack) > 0 {
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("🔧 Technology Stack Detected:"))
				for _, tech := range summary.TechStack[:min(5, len(summary.TechStack))] {
					fmt.Fprintf(os.Stderr, "    • %s\n", tech)
				}
				fmt.Fprintln(os.Stderr)
			}

			// Payload Recommendations
			recs := brain.RecommendPayloads()
			if len(recs) > 0 {
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("🎯 Smart Payload Recommendations:"))
				for _, rec := range recs[:min(5, len(recs))] {
					priorityStyle := ui.PassStyle
					if rec.Priority == 1 {
						priorityStyle = ui.ErrorStyle
					} else if rec.Priority == 2 {
						priorityStyle = ui.SeverityStyle("Medium")
					}
					fmt.Fprintf(os.Stderr, "    [%s] %s - %s\n",
						priorityStyle.Render(fmt.Sprintf("P%d", rec.Priority)),
						ui.StatValueStyle.Render(rec.Category),
						rec.Reason)
				}
				fmt.Fprintln(os.Stderr)
			}

			// Stats summary
			fmt.Fprintf(os.Stderr, "  %s Total findings: %d | Bypasses: %d | Attack chains: %d | Insights: %d\n",
				ui.BracketStyle.Render("📈"),
				summary.TotalFindings, summary.Bypasses, summary.AttackChains, atomic.LoadInt32(&insightCount))
			printStatusLn()
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 5: COMPREHENSIVE REPORT
	// ═══════════════════════════════════════════════════════════════════════════
	printStatusLn()
	printStatusLn(ui.SectionStyle.Render("PHASE 5: Comprehensive Report"))
	printStatusLn()

	// Calculate WAF effectiveness
	wafEffectiveness := float64(0)
	if results.BlockedTests+results.FailedTests > 0 {
		wafEffectiveness = float64(results.BlockedTests) / float64(results.BlockedTests+results.FailedTests) * 100
	}

	scanDuration := time.Since(startTime)

	// Print summary (only in non-JSON mode)
	if !quietMode {
		fmt.Fprintln(os.Stderr, "  ════════════════════════════════════════════════════════════")
		fmt.Fprintln(os.Stderr, "                    SUPERPOWER SCAN COMPLETE")
		fmt.Fprintln(os.Stderr, "  ════════════════════════════════════════════════════════════")
		fmt.Fprintln(os.Stderr)

		ui.PrintConfigLine("Target", target)
		ui.PrintConfigLine("Duration", scanDuration.Round(time.Second).String())
		ui.PrintConfigLine("Workspace", workspaceDir)
		fmt.Fprintln(os.Stderr)

		fmt.Fprintf(os.Stderr, "  +------------------------------------------------+\n")
		fmt.Fprintf(os.Stderr, "  |  Total Endpoints:    %-26d |\n", len(discResult.Endpoints))
		fmt.Fprintf(os.Stderr, "  |  JS Files Analyzed:  %-26d |\n", jsAnalyzed)
		fmt.Fprintf(os.Stderr, "  |  Secrets Found:      %-26d |\n", len(allJSData.Secrets))
		fmt.Fprintf(os.Stderr, "  |  Subdomains Found:   %-26d |\n", len(allJSData.Subdomains))
		// Recon findings from new competitive features
		if leakyResult != nil {
			fmt.Fprintf(os.Stderr, "  |  Leaky Paths Found:  %-26d |\n", leakyResult.InterestingHits)
		}
		if paramResult != nil {
			fmt.Fprintf(os.Stderr, "  |  Hidden Params Found:%-26d |\n", paramResult.FoundParams)
		}
		fmt.Fprintf(os.Stderr, "  +------------------------------------------------+\n")
		fmt.Fprintf(os.Stderr, "  |  Total Tests:        %-26d |\n", results.TotalTests)
		fmt.Fprintf(os.Stderr, "  |  Blocked (WAF):      %-26d |\n", results.BlockedTests)
		fmt.Fprintf(os.Stderr, "  |  Passed:             %-26d |\n", results.PassedTests)
		fmt.Fprintf(os.Stderr, "  |  Failed (Bypass):    %-26d |\n", results.FailedTests)
		fmt.Fprintf(os.Stderr, "  |  Errors:             %-26d |\n", results.ErrorTests)
		fmt.Fprintf(os.Stderr, "  +------------------------------------------------+\n")
		fmt.Fprintln(os.Stderr)

		// WAF Effectiveness
		if wafEffectiveness >= 95 {
			ui.PrintSuccess(fmt.Sprintf("  WAF Effectiveness: %.1f%% - EXCELLENT", wafEffectiveness))
		} else if wafEffectiveness >= 80 {
			ui.PrintWarning(fmt.Sprintf("  WAF Effectiveness: %.1f%% - GOOD (room for improvement)", wafEffectiveness))
		} else {
			ui.PrintError(fmt.Sprintf("  WAF Effectiveness: %.1f%% - NEEDS ATTENTION", wafEffectiveness))
		}
		fmt.Fprintln(os.Stderr)

		// Print summary and enhanced stats
		ui.PrintSummary(ui.Summary{
			TotalTests:     results.TotalTests,
			BlockedTests:   results.BlockedTests,
			PassedTests:    results.PassedTests,
			FailedTests:    results.FailedTests,
			ErrorTests:     results.ErrorTests,
			Duration:       results.Duration,
			RequestsPerSec: results.RequestsPerSec,
			TargetURL:      target,
		})
		output.PrintSummary(results)
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// MULTI-FORMAT REPORT GENERATION (v2.6.4)
	// ═══════════════════════════════════════════════════════════════════════════
	formats := strings.Split(*reportFormats, ",")
	generatedReports := make([]string, 0, len(formats))

	for _, format := range formats {
		format = strings.TrimSpace(strings.ToLower(format))
		switch format {
		case "md", "markdown":
			// Generate markdown report
			generateAutoMarkdownReport(reportFile, target, domain, scanDuration, discResult, allJSData, testPlan, results, wafEffectiveness)
			generatedReports = append(generatedReports, reportFile)
		case "json":
			// JSON is already generated as results.json
			generatedReports = append(generatedReports, resultsFile)
		case "html":
			// HTML enterprise report will be generated after assessment
			htmlFile := filepath.Join(workspaceDir, "report.html")
			if err := report.GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir, domain, scanDuration, htmlFile); err == nil {
				generatedReports = append(generatedReports, htmlFile)
			}
		case "sarif":
			// SARIF format for CI/CD integration (GitHub Code Scanning, etc.)
			sarifFile := filepath.Join(workspaceDir, "report.sarif")
			if err := generateSARIFReport(sarifFile, target, results); err == nil {
				generatedReports = append(generatedReports, sarifFile)
				if !quietMode {
					ui.PrintInfo(fmt.Sprintf("📋 SARIF report generated: %s", sarifFile))
				}
			}
		}
	}

	// Silence unused variable warning
	_ = reportFormats

	// Generate summary.json for CI/CD integration
	summaryFile := filepath.Join(workspaceDir, "summary.json")
	summary := map[string]interface{}{
		"target":            target,
		"domain":            domain,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
		"duration_seconds":  scanDuration.Seconds(),
		"waf_effectiveness": wafEffectiveness,
		"pass":              results.FailedTests == 0,
		"stats": map[string]interface{}{
			"total_tests":   results.TotalTests,
			"blocked":       results.BlockedTests,
			"passed":        results.PassedTests,
			"failed":        results.FailedTests,
			"errors":        results.ErrorTests,
			"requests_sec":  results.RequestsPerSec,
			"endpoints":     len(discResult.Endpoints),
			"js_files":      jsAnalyzed,
			"secrets_found": len(allJSData.Secrets),
		},
		"latency": map[string]interface{}{
			"min_ms": results.LatencyStats.Min,
			"max_ms": results.LatencyStats.Max,
			"avg_ms": results.LatencyStats.Avg,
			"p50_ms": results.LatencyStats.P50,
			"p95_ms": results.LatencyStats.P95,
			"p99_ms": results.LatencyStats.P99,
		},
		"detection": detectionoutput.Stats{
			DropsDetected: results.DropsDetected,
			BansDetected:  results.BansDetected,
			HostsSkipped:  results.HostsSkipped,
		}.ToJSON(),
		"severity_breakdown": results.SeverityBreakdown,
		"category_breakdown": results.CategoryBreakdown,
		"owasp_breakdown":    results.OWASPBreakdown,
		"encoding_stats":     results.EncodingStats,
		"bypass_count":       results.FailedTests,
		"bypass_payloads":    results.BypassPayloads,
		"top_errors":         results.TopErrors,
		"ci_exit_code":       0,
	}
	if results.FailedTests > 0 {
		summary["ci_exit_code"] = 1
		summary["bypass_details"] = results.BypassDetails
	}

	// Add Intelligence Engine data to summary
	if brain != nil {
		intSummary := brain.GetSummary()
		chainData := make([]map[string]interface{}, 0)
		for _, chain := range intSummary.TopChains {
			chainData = append(chainData, map[string]interface{}{
				"name":        chain.Name,
				"impact":      chain.Impact,
				"cvss":        chain.CVSS,
				"description": chain.Description,
				"steps":       chain.Steps,
				"confidence":  chain.Confidence,
			})
		}
		summary["intelligence"] = map[string]interface{}{
			"enabled":        true,
			"total_findings": intSummary.TotalFindings,
			"bypasses":       intSummary.Bypasses,
			"blocked":        intSummary.Blocked,
			"attack_chains":  chainData,
			"waf_strengths":  intSummary.WAFStrengths,
			"waf_weaknesses": intSummary.WAFWeaknesses,
			"tech_stack":     intSummary.TechStack,
			"insights_count": atomic.LoadInt32(&insightCount),
			"chains_count":   atomic.LoadInt32(&chainCount),
		}
	}

	summaryData, _ := json.MarshalIndent(summary, "", "  ")
	os.WriteFile(summaryFile, summaryData, 0644)

	if !quietMode {
		fmt.Fprintln(os.Stderr)
		ui.PrintSuccess(fmt.Sprintf("📊 Full report saved to: %s", reportFile))
		fmt.Fprintln(os.Stderr)

		// Show output files
		fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("Output Files:"))
		fmt.Fprintf(os.Stderr, "    • Discovery:   %s\n", discoveryFile)
		fmt.Fprintf(os.Stderr, "    • JS Analysis: %s\n", jsAnalysisFile)
		fmt.Fprintf(os.Stderr, "    • Test Plan:   %s\n", testPlanFile)
		fmt.Fprintf(os.Stderr, "    • Results:     %s\n", resultsFile)
		fmt.Fprintf(os.Stderr, "    • Summary:     %s\n", summaryFile)
		fmt.Fprintf(os.Stderr, "    • Report:      %s\n", reportFile)
		fmt.Fprintln(os.Stderr)

		fmt.Fprintln(os.Stderr, "  ════════════════════════════════════════════════════════════")
		fmt.Fprintf(os.Stderr, "  🚀 SUPERPOWER SCAN COMPLETE in %s\n", scanDuration.Round(time.Second))
		fmt.Fprintln(os.Stderr, "  ════════════════════════════════════════════════════════════")
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 6: ENTERPRISE ASSESSMENT (NOW DEFAULT)
	// ═══════════════════════════════════════════════════════════════════════════

	// Update progress for assessment phase
	autoProgress.SetStatus("Assessment")
	autoProgress.Increment()

	if *enableAssess {
		printStatusLn()
		printStatusLn(ui.SectionStyle.Render("PHASE 6: Enterprise Assessment (Quantitative Metrics)"))
		printStatusLn()

		ui.PrintInfo("Running enterprise WAF assessment with F1/precision/MCC metrics...")
		printStatusLn()

		assessConfig := &assessment.Config{
			TargetURL:       target,
			Concurrency:     *concurrency,
			RateLimit:       float64(*rateLimit),
			Timeout:         time.Duration(*timeout) * time.Second,
			SkipTLSVerify:   *skipVerify,
			Verbose:         *verbose,
			HTTPClient:      ja3Client, // JA3 TLS fingerprint rotation
			EnableFPTesting: true,
			CorpusSources:   strings.Split(*assessCorpus, ","),
			DetectWAF:       true,
		}

		assess := assessment.New(assessConfig)
		assessCtx, assessCancel := context.WithTimeout(ctx, duration.ContextLong)
		defer assessCancel()

		progressFn := func(completed, total int64, phase string) {
			if !quietMode && (*verbose || completed%25 == 0 || completed == total) {
				pct := float64(0)
				if total > 0 {
					pct = float64(completed) / float64(total) * 100
				}
				fmt.Fprintf(os.Stderr, "\r  %s: %d/%d (%.1f%%)     ", phase, completed, total, pct)
			}
		}

		assessResult, err := assess.Run(assessCtx, progressFn)
		if !quietMode {
			fmt.Fprintln(os.Stderr) // Clear progress line
		}

		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Assessment error: %v", err))
		} else {
			// Emit enterprise assessment results to hooks
			if autoDispCtx != nil {
				// Emit overall grade
				gradeDesc := fmt.Sprintf("Enterprise Assessment: %s - %s", assessResult.Grade, assessResult.GradeReason)
				_ = autoDispCtx.EmitBypass(ctx, "enterprise-grade", assessResult.Grade, target, gradeDesc, 0)

				// Emit weak categories
				for cat, cm := range assessResult.CategoryMetrics {
					if cm.Grade == "D" || cm.Grade == "F" || cm.DetectionRate < 0.6 {
						weakDesc := fmt.Sprintf("Weak category: %s - Detection %.1f%% (%d bypassed) - Grade %s",
							cat, cm.DetectionRate*100, cm.Bypassed, cm.Grade)
						_ = autoDispCtx.EmitBypass(ctx, "enterprise-weak-category", "high", target, weakDesc, 0)
					}
				}

				// Emit recommendations
				for _, rec := range assessResult.Recommendations {
					_ = autoDispCtx.EmitBypass(ctx, "enterprise-recommendation", "info", target, rec, 0)
				}
			}

			// Display assessment results (only in non-JSON mode)
			if !quietMode {
				displayAssessmentResults(assessResult, time.Since(startTime))
			}

			// Save assessment results
			assessFile := filepath.Join(workspaceDir, "assessment.json")
			assessData, _ := json.MarshalIndent(assessResult, "", "  ")
			os.WriteFile(assessFile, assessData, 0644)
			ui.PrintSuccess(fmt.Sprintf("📊 Assessment saved to: %s", assessFile))

			// Generate Enterprise HTML Report now that assessment.json exists
			htmlReportFile := filepath.Join(workspaceDir, "enterprise-report.html")
			if err := report.GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir, domain, scanDuration, htmlReportFile); err != nil {
				ui.PrintWarning(fmt.Sprintf("Enterprise HTML report generation error: %v", err))
			} else if !quietMode {
				fmt.Fprintf(os.Stderr, "    • Enterprise:  %s\n", htmlReportFile)
			}

			// Update summary with enterprise metrics
			summary["enterprise_metrics"] = map[string]interface{}{
				"grade":               assessResult.Grade,
				"grade_reason":        assessResult.GradeReason,
				"f1_score":            assessResult.F1Score,
				"f2_score":            assessResult.F2Score,
				"precision":           assessResult.Precision,
				"recall":              assessResult.DetectionRate,
				"specificity":         assessResult.Specificity,
				"mcc":                 assessResult.MCC,
				"balanced_accuracy":   assessResult.BalancedAccuracy,
				"detection_rate":      assessResult.DetectionRate,
				"false_positive_rate": assessResult.FalsePositiveRate,
				"bypass_resistance":   assessResult.BypassResistance,
			}
			summaryData, _ = json.MarshalIndent(summary, "", "  ")
			os.WriteFile(summaryFile, summaryData, 0644)
		}
		printStatusLn()
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 7-9: AUTHENTICATED BROWSER SCANNING
	// ═══════════════════════════════════════════════════════════════════════════

	// Update progress for browser phase
	autoProgress.SetStatus("Browser scan")
	autoProgress.Increment()

	var browserResult *browser.BrowserScanResult

	if *enableBrowserScan {
		printStatusLn()
		printStatusLn(ui.SectionStyle.Render("PHASE 7: Authenticated Browser Scanning"))
		printStatusLn()

		ui.PrintInfo("🌐 Launching browser for authenticated scanning...")
		printStatusLn()

		if !quietMode {
			fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("  Browser Mode: Authenticated Discovery"))
			fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("  Captures: Routes, Tokens, Storage, Third-Party APIs, Network Traffic"))
			fmt.Fprintln(os.Stderr)
		}

		// Configure browser scanner
		browserConfig := &browser.AuthConfig{
			TargetURL:      target,
			Timeout:        duration.HTTPLongOps,
			WaitForLogin:   *browserTimeout,
			PostLoginDelay: duration.BrowserPostWait,
			CrawlDepth:     *depth,
			ShowBrowser:    !*browserHeadless,
			Verbose:        *verbose,
			ScreenshotDir:  filepath.Join(workspaceDir, "screenshots"),
			EnableScreens:  true,
		}

		scanner := browser.NewAuthenticatedScanner(browserConfig)

		// Progress callback
		browserProgress := func(msg string) {
			if *verbose {
				ui.PrintInfo(fmt.Sprintf("  %s", msg))
			}
		}

		ui.PrintWarning("⏳ Browser will open - please log in when prompted")
		ui.PrintInfo(fmt.Sprintf("   You have %s to complete authentication", browserConfig.WaitForLogin))
		printStatusLn()

		// Run the browser scan
		browserCtx, browserCancel := context.WithTimeout(ctx, browserConfig.Timeout)
		defer browserCancel()

		var err error
		browserResult, err = scanner.Scan(browserCtx, browserProgress)

		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Browser scan warning: %v", err))
		} else {
			// ═══════════════════════════════════════════════════════════════════════════
			// PHASE 8: Browser Findings Analysis
			// ═══════════════════════════════════════════════════════════════════════════
			printStatusLn()
			printStatusLn(ui.SectionStyle.Render("PHASE 8: Browser Findings Analysis"))
			printStatusLn()

			// Save browser results
			browserFile := filepath.Join(workspaceDir, "browser-scan.json")
			if err := browserResult.SaveResult(browserFile); err != nil {
				ui.PrintWarning(fmt.Sprintf("Error saving browser results: %v", err))
			}

			if !quietMode {
				// Display authentication info
				if browserResult.AuthFlowInfo != nil && browserResult.AuthFlowInfo.Provider != "" {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("🔐 Authentication Flow Detected:"))
					fmt.Fprintf(os.Stderr, "    Provider: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.Provider))
					fmt.Fprintf(os.Stderr, "    Flow Type: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.FlowType))
					if browserResult.AuthFlowInfo.LibraryUsed != "" {
						fmt.Fprintf(os.Stderr, "    Library: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.LibraryUsed))
					}
					fmt.Fprintln(os.Stderr)
				}

				// Display discovered routes
				if len(browserResult.DiscoveredRoutes) > 0 {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("🗺️  Discovered Routes:"))
					for i, route := range browserResult.GetSortedRoutes() {
						if i >= 15 {
							remaining := len(browserResult.DiscoveredRoutes) - 15
							fmt.Fprintf(os.Stderr, "    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more routes", remaining)))
							break
						}
						authIcon := "🔓"
						if route.RequiresAuth {
							authIcon = "🔒"
						}
						fmt.Fprintf(os.Stderr, "    %s %s %s\n", authIcon, ui.ConfigValueStyle.Render(route.Path),
							ui.SubtitleStyle.Render(route.PageTitle))
					}
					fmt.Fprintln(os.Stderr)
				}

				// Display exposed tokens (CRITICAL)
				if len(browserResult.ExposedTokens) > 0 {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("⚠️  Exposed Tokens/Secrets:"))
					for _, token := range browserResult.ExposedTokens {
						sevStyle := ui.SeverityStyle(token.Severity)
						fmt.Fprintf(os.Stderr, "    %s%s%s %s in %s\n",
							ui.BracketStyle.Render("["),
							sevStyle.Render(strings.ToUpper(token.Severity)),
							ui.BracketStyle.Render("]"),
							ui.ConfigValueStyle.Render(token.Type),
							ui.SubtitleStyle.Render(token.Location),
						)
						fmt.Fprintf(os.Stderr, "      → %s\n", token.Risk)
					}
					fmt.Fprintln(os.Stderr)
				}

				// Display third-party APIs
				if len(browserResult.ThirdPartyAPIs) > 0 {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("🔗 Third-Party Integrations:"))
					for i, api := range browserResult.ThirdPartyAPIs {
						if i >= 10 {
							remaining := len(browserResult.ThirdPartyAPIs) - 10
							fmt.Fprintf(os.Stderr, "    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more integrations", remaining)))
							break
						}
						sevStyle := ui.SeverityStyle(api.Severity)
						fmt.Fprintf(os.Stderr, "    %s%s%s %s (%s)\n",
							ui.BracketStyle.Render("["),
							sevStyle.Render(api.Severity),
							ui.BracketStyle.Render("]"),
							ui.ConfigValueStyle.Render(api.Name),
							ui.SubtitleStyle.Render(api.RequestType),
						)
					}
					fmt.Fprintln(os.Stderr)
				}

				// Risk Summary
				if browserResult.RiskSummary != nil {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("📊 Browser Scan Risk Summary:"))
					riskStyle := ui.SeverityStyle(browserResult.RiskSummary.OverallRisk)
					fmt.Fprintf(os.Stderr, "    Overall Risk: %s\n", riskStyle.Render(strings.ToUpper(browserResult.RiskSummary.OverallRisk)))
					fmt.Fprintf(os.Stderr, "    Total Findings: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
						browserResult.RiskSummary.TotalFindings,
						browserResult.RiskSummary.CriticalCount,
						browserResult.RiskSummary.HighCount,
						browserResult.RiskSummary.MediumCount,
						browserResult.RiskSummary.LowCount,
					)

					if len(browserResult.RiskSummary.TopRisks) > 0 {
						fmt.Fprintln(os.Stderr)
						fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render("🚨 Top Risks:"))
						for _, risk := range browserResult.RiskSummary.TopRisks {
							ui.PrintWarning(fmt.Sprintf("    • %s", risk))
						}
					}
					fmt.Fprintln(os.Stderr)
				}

				// Emit browser findings to hooks (exposed tokens are critical!)
				if autoDispCtx != nil {
					for _, token := range browserResult.ExposedTokens {
						tokenDesc := fmt.Sprintf("Token exposed in browser: %s at %s - %s", token.Type, token.Location, token.Risk)
						_ = autoDispCtx.EmitBypass(ctx, "browser-token-exposure", token.Severity, target, tokenDesc, 0)
					}
					// Emit third-party API integrations that may leak data
					for _, api := range browserResult.ThirdPartyAPIs {
						if api.Severity == "critical" || api.Severity == "high" {
							apiDesc := fmt.Sprintf("Risky third-party API: %s (%s)", api.Name, api.RequestType)
							_ = autoDispCtx.EmitBypass(ctx, "browser-risky-integration", api.Severity, target, apiDesc, 0)
						}
					}
					// Emit top risks from browser scan
					if browserResult.RiskSummary != nil {
						for _, risk := range browserResult.RiskSummary.TopRisks {
							_ = autoDispCtx.EmitBypass(ctx, "browser-top-risk", "high", target, risk, 0)
						}
						// Emit overall risk level
						if browserResult.RiskSummary.OverallRisk != "" {
							riskDesc := fmt.Sprintf("Browser scan overall risk: %s (Critical:%d, High:%d)",
								browserResult.RiskSummary.OverallRisk, browserResult.RiskSummary.CriticalCount, browserResult.RiskSummary.HighCount)
							_ = autoDispCtx.EmitBypass(ctx, "browser-risk-summary", browserResult.RiskSummary.OverallRisk, target, riskDesc, 0)
						}
					}
				}
			}

			// ═══════════════════════════════════════════════════════════════════════════
			// PHASE 9: Browser Findings Integration
			// ═══════════════════════════════════════════════════════════════════════════
			printStatusLn()
			printStatusLn(ui.SectionStyle.Render("PHASE 9: Browser Findings Integration"))
			printStatusLn()

			ui.PrintInfo("📊 Merging browser findings into enterprise report...")

			// Update summary with browser findings
			browserScanSummary := map[string]interface{}{
				"auth_successful":    browserResult.AuthSuccessful,
				"discovered_routes":  len(browserResult.DiscoveredRoutes),
				"exposed_tokens":     len(browserResult.ExposedTokens),
				"third_party_apis":   len(browserResult.ThirdPartyAPIs),
				"network_requests":   len(browserResult.NetworkRequests),
				"scan_duration_secs": browserResult.ScanDuration.Seconds(),
			}
			// Add risk summary if available
			if browserResult.RiskSummary != nil {
				browserScanSummary["overall_risk"] = browserResult.RiskSummary.OverallRisk
				browserScanSummary["critical_count"] = browserResult.RiskSummary.CriticalCount
				browserScanSummary["high_count"] = browserResult.RiskSummary.HighCount
			}
			summary["browser_scan"] = browserScanSummary

			// Add auth flow info if detected
			if browserResult.AuthFlowInfo != nil {
				summary["auth_flow"] = map[string]interface{}{
					"provider":  browserResult.AuthFlowInfo.Provider,
					"flow_type": browserResult.AuthFlowInfo.FlowType,
					"library":   browserResult.AuthFlowInfo.LibraryUsed,
				}
			}

			// Save updated summary
			summaryData, _ = json.MarshalIndent(summary, "", "  ")
			os.WriteFile(summaryFile, summaryData, 0644)

			// Regenerate enterprise report to include browser findings
			htmlReportFile := filepath.Join(workspaceDir, "enterprise-report.html")
			if err := report.GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir, domain, scanDuration, htmlReportFile); err != nil {
				ui.PrintWarning(fmt.Sprintf("Enterprise report regeneration error: %v", err))
			} else {
				ui.PrintSuccess("✓ Enterprise report updated with browser findings")
			}

			ui.PrintSuccess(fmt.Sprintf("✓ Browser scan completed in %s", browserResult.ScanDuration.Round(time.Millisecond)))
			if !quietMode {
				fmt.Fprintf(os.Stderr, "    • Browser Results: %s\n", browserFile)
				fmt.Fprintln(os.Stderr)
			}
		}
	}
	// Silence unused variable warning
	_ = browserHeadless
	_ = browserTimeout
	_ = enableBrowserScan

	// Output JSON summary to stdout if requested
	if outFlags.JSONMode {
		// Create a comprehensive output structure
		jsonSummary := map[string]interface{}{
			"target":            target,
			"domain":            domain,
			"timestamp":         time.Now().UTC().Format(time.RFC3339),
			"duration_seconds":  scanDuration.Seconds(),
			"waf_effectiveness": wafEffectiveness,
			"success":           results.FailedTests == 0,
			"workspace":         workspaceDir,
			"stats": map[string]interface{}{
				"total_tests":      results.TotalTests,
				"blocked":          results.BlockedTests,
				"passed":           results.PassedTests,
				"failed":           results.FailedTests,
				"errors":           results.ErrorTests,
				"requests_per_sec": results.RequestsPerSec,
			},
			"discovery": map[string]interface{}{
				"endpoints":    len(discResult.Endpoints),
				"waf_detected": discResult.WAFDetected,
				"waf_vendor":   discResult.WAFFingerprint,
			},
			"js_analysis": map[string]interface{}{
				"files_analyzed": jsAnalyzed,
				"secrets_found":  len(allJSData.Secrets),
				"endpoints":      len(allJSData.Endpoints),
				"dom_sinks":      len(allJSData.DOMSinks),
			},
			"latency": map[string]interface{}{
				"min_ms": results.LatencyStats.Min,
				"max_ms": results.LatencyStats.Max,
				"avg_ms": results.LatencyStats.Avg,
				"p50_ms": results.LatencyStats.P50,
				"p95_ms": results.LatencyStats.P95,
				"p99_ms": results.LatencyStats.P99,
			},
			"severity_breakdown": results.SeverityBreakdown,
			"category_breakdown": results.CategoryBreakdown,
			"bypass_count":       results.FailedTests,
			"files": map[string]string{
				"discovery":   discoveryFile,
				"js_analysis": jsAnalysisFile,
				"test_plan":   testPlanFile,
				"results":     resultsFile,
				"summary":     summaryFile,
				"report":      reportFile,
			},
		}

		// Add enterprise metrics if available
		if enterpriseMetrics, ok := summary["enterprise_metrics"]; ok {
			jsonSummary["enterprise_metrics"] = enterpriseMetrics
		}

		// Add browser scan summary if available
		if browserScan, ok := summary["browser_scan"]; ok {
			jsonSummary["browser_scan"] = browserScan
		}

		// Add smart mode info if available
		if smartResult != nil && smartResult.WAFDetected {
			jsonSummary["smart_mode"] = map[string]interface{}{
				"waf_detected": true,
				"vendor":       smartResult.VendorName,
				"confidence":   smartResult.Confidence,
			}
		}

		// Output to stdout
		jsonBytes, _ := json.MarshalIndent(jsonSummary, "", "  ")
		fmt.Println(string(jsonBytes))
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER SUMMARY EMISSION
	// ═══════════════════════════════════════════════════════════════════════════
	// Notify all hooks (Slack, Teams, PagerDuty, OTEL, etc.) that scan is complete
	if autoDispCtx != nil {
		_ = autoDispCtx.EmitSummary(ctx, int(results.TotalTests), int(results.BlockedTests), int(results.FailedTests), scanDuration)
	}

	if results.FailedTests > 0 {
		os.Exit(1)
	}
}

// handleAdaptiveRate processes adaptive rate limiting based on response
func handleAdaptiveRate(statusCode int, outcome string, limiter *ratelimit.Limiter, escalate func(string)) {
	if limiter == nil {
		return
	}
	if statusCode == 429 {
		limiter.OnError()
		escalate("HTTP 429 Too Many Requests")
	} else if outcome != "Error" {
		limiter.OnSuccess()
	}
}

// inferHTTPMethod tries to determine the HTTP method from path and source
func inferHTTPMethod(path, source string) string {
	pathLower := strings.ToLower(path)

	// POST indicators
	if strings.Contains(pathLower, "create") ||
		strings.Contains(pathLower, "add") ||
		strings.Contains(pathLower, "new") ||
		strings.Contains(pathLower, "upload") ||
		strings.Contains(pathLower, "submit") ||
		strings.Contains(pathLower, "login") ||
		strings.Contains(pathLower, "register") ||
		strings.Contains(pathLower, "signup") {
		return "POST"
	}

	// PUT/PATCH indicators
	if strings.Contains(pathLower, "update") ||
		strings.Contains(pathLower, "edit") ||
		strings.Contains(pathLower, "modify") ||
		strings.Contains(pathLower, "save") {
		return "PUT"
	}

	// DELETE indicators
	if strings.Contains(pathLower, "delete") ||
		strings.Contains(pathLower, "remove") ||
		strings.Contains(pathLower, "destroy") {
		return "DELETE"
	}

	// Check source for method hints
	sourceLower := strings.ToLower(source)
	if strings.Contains(sourceLower, "post") {
		return "POST"
	}
	if strings.Contains(sourceLower, "put") {
		return "PUT"
	}
	if strings.Contains(sourceLower, "delete") {
		return "DELETE"
	}
	if strings.Contains(sourceLower, "patch") {
		return "PATCH"
	}

	return "GET"
}

// truncateString truncates a string to max length
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// generateAutoMarkdownReport creates a comprehensive markdown report for auto scan
func generateAutoMarkdownReport(filename, target, domain string, duration time.Duration,
	discResult *discovery.DiscoveryResult, jsData *js.ExtractedData,
	testPlan *learning.TestPlan, results output.ExecutionResults, wafEffectiveness float64) {

	var sb strings.Builder

	sb.WriteString("# 🛡️ WAF Security Assessment Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s  \n", target))
	sb.WriteString(fmt.Sprintf("**Domain:** %s  \n", domain))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", duration.Round(time.Second)))

	sb.WriteString("---\n\n")

	// Executive Summary
	sb.WriteString("## 📋 Executive Summary\n\n")

	if wafEffectiveness >= 95 {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - EXCELLENT** ✅\n\n", wafEffectiveness))
		sb.WriteString("The WAF is performing exceptionally well, blocking virtually all attack attempts.\n\n")
	} else if wafEffectiveness >= 80 {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - GOOD** ⚠️\n\n", wafEffectiveness))
		sb.WriteString("The WAF is performing well but has room for improvement.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - NEEDS ATTENTION** ❌\n\n", wafEffectiveness))
		sb.WriteString("The WAF requires immediate attention. Multiple bypasses detected.\n\n")
	}

	// Key Findings
	sb.WriteString("### Key Findings\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Endpoints Discovered | %d |\n", len(discResult.Endpoints)))
	sb.WriteString(fmt.Sprintf("| JavaScript Files Analyzed | %d |\n", len(jsData.Endpoints)))
	sb.WriteString(fmt.Sprintf("| Secrets Found | %d |\n", len(jsData.Secrets)))
	sb.WriteString(fmt.Sprintf("| Subdomains Discovered | %d |\n", len(jsData.Subdomains)))
	sb.WriteString(fmt.Sprintf("| Total Tests Executed | %d |\n", results.TotalTests))
	sb.WriteString(fmt.Sprintf("| WAF Blocks | %d |\n", results.BlockedTests))
	sb.WriteString(fmt.Sprintf("| Bypasses Detected | %d |\n", results.FailedTests))
	sb.WriteString("\n")

	// Discovery Results
	sb.WriteString("## 🔍 Discovery Results\n\n")

	if discResult.WAFDetected {
		sb.WriteString(fmt.Sprintf("**WAF Detected:** %s\n\n", discResult.WAFFingerprint))
	}

	sb.WriteString("### Attack Surface\n\n")
	surface := discResult.AttackSurface
	if surface.HasAuthEndpoints {
		sb.WriteString("- ✅ Authentication endpoints detected\n")
	}
	if surface.HasAPIEndpoints {
		sb.WriteString("- ✅ API endpoints detected\n")
	}
	if surface.HasFileUpload {
		sb.WriteString("- ✅ File upload functionality detected\n")
	}
	if surface.HasOAuth {
		sb.WriteString("- ✅ OAuth endpoints detected\n")
	}
	if surface.HasGraphQL {
		sb.WriteString("- ✅ GraphQL endpoint detected\n")
	}
	sb.WriteString("\n")

	// Secrets
	if len(jsData.Secrets) > 0 {
		sb.WriteString("## 🔑 Secrets Detected\n\n")
		sb.WriteString("| Type | Confidence | Value (truncated) |\n")
		sb.WriteString("|------|------------|-------------------|\n")
		for _, secret := range jsData.Secrets {
			truncated := secret.Value
			if len(truncated) > 40 {
				truncated = truncated[:40] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | `%s` |\n", secret.Type, secret.Confidence, truncated))
		}
		sb.WriteString("\n")
	}

	// Test Results
	sb.WriteString("## ⚡ Test Results\n\n")

	sb.WriteString("### Summary\n\n")
	sb.WriteString("| Outcome | Count |\n")
	sb.WriteString("|---------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Blocked | %d |\n", results.BlockedTests))
	sb.WriteString(fmt.Sprintf("| Passed | %d |\n", results.PassedTests))
	sb.WriteString(fmt.Sprintf("| Failed (Bypass) | %d |\n", results.FailedTests))
	sb.WriteString(fmt.Sprintf("| Error | %d |\n", results.ErrorTests))
	sb.WriteString("\n")

	// Latency Statistics
	sb.WriteString("### Performance Metrics\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Requests/sec | %.1f |\n", results.RequestsPerSec))
	sb.WriteString(fmt.Sprintf("| Min Latency | %d ms |\n", results.LatencyStats.Min))
	sb.WriteString(fmt.Sprintf("| Max Latency | %d ms |\n", results.LatencyStats.Max))
	sb.WriteString(fmt.Sprintf("| Avg Latency | %d ms |\n", results.LatencyStats.Avg))
	sb.WriteString(fmt.Sprintf("| P50 Latency | %d ms |\n", results.LatencyStats.P50))
	sb.WriteString(fmt.Sprintf("| P95 Latency | %d ms |\n", results.LatencyStats.P95))
	sb.WriteString(fmt.Sprintf("| P99 Latency | %d ms |\n", results.LatencyStats.P99))
	sb.WriteString("\n")

	// Bypass Details
	if len(results.BypassDetails) > 0 {
		sb.WriteString("### 🚨 Bypass Details\n\n")
		sb.WriteString("The following attack payloads bypassed the WAF:\n\n")
		for i, bypass := range results.BypassDetails {
			sb.WriteString(fmt.Sprintf("#### Bypass #%d: %s\n\n", i+1, bypass.PayloadID))
			sb.WriteString(fmt.Sprintf("- **Category:** %s\n", bypass.Category))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", bypass.Severity))
			sb.WriteString(fmt.Sprintf("- **Endpoint:** `%s`\n", bypass.Endpoint))
			sb.WriteString(fmt.Sprintf("- **Method:** %s\n", bypass.Method))
			sb.WriteString(fmt.Sprintf("- **Status Code:** %d\n", bypass.StatusCode))
			sb.WriteString(fmt.Sprintf("- **Payload:** `%s`\n", truncateString(bypass.Payload, 100)))
			if bypass.CurlCommand != "" {
				sb.WriteString(fmt.Sprintf("- **Reproduce:** `%s`\n", bypass.CurlCommand))
			}
			sb.WriteString("\n")
		}
	}

	// Category breakdown if available
	if results.CategoryBreakdown != nil && len(results.CategoryBreakdown) > 0 {
		sb.WriteString("### By Category\n\n")
		sb.WriteString("| Category | Tests |\n")
		sb.WriteString("|----------|-------|\n")
		for cat, count := range results.CategoryBreakdown {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", cat, count))
		}
		sb.WriteString("\n")
	}

	// OWASP Top 10 breakdown if available
	if results.OWASPBreakdown != nil && len(results.OWASPBreakdown) > 0 {
		sb.WriteString("### OWASP Top 10 2021 Coverage\n\n")
		sb.WriteString("| OWASP Category | Tests |\n")
		sb.WriteString("|----------------|-------|\n")
		for owasp, count := range results.OWASPBreakdown {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", owasp, count))
		}
		sb.WriteString("\n")
	}

	// Encoding effectiveness if available
	if results.EncodingStats != nil && len(results.EncodingStats) > 0 {
		sb.WriteString("### Encoding Effectiveness\n\n")
		sb.WriteString("| Encoding | Tests | Bypasses | Bypass Rate |\n")
		sb.WriteString("|----------|-------|----------|-------------|\n")
		for name, stats := range results.EncodingStats {
			rateIcon := "✅"
			if stats.BypassRate > 10 {
				rateIcon = "🔴"
			} else if stats.BypassRate > 0 {
				rateIcon = "🟡"
			}
			sb.WriteString(fmt.Sprintf("| %s | %d | %d | %.1f%% %s |\n",
				name, stats.TotalTests, stats.Bypasses, stats.BypassRate, rateIcon))
		}
		sb.WriteString("\n")
	}

	// Recommendations
	sb.WriteString("## 📝 Recommendations\n\n")

	if results.FailedTests > 0 {
		sb.WriteString("### Immediate Actions Required\n\n")
		sb.WriteString("1. Review and update WAF rules for bypassed attack categories\n")
		sb.WriteString("2. Enable stricter input validation on affected endpoints\n")
		sb.WriteString("3. Consider implementing additional security layers\n\n")
	}

	if len(jsData.Secrets) > 0 {
		sb.WriteString("### Secrets Remediation\n\n")
		sb.WriteString("1. Rotate all detected credentials immediately\n")
		sb.WriteString("2. Remove hardcoded secrets from JavaScript\n")
		sb.WriteString("3. Implement proper secrets management\n\n")
	}

	sb.WriteString("### General Recommendations\n\n")
	sb.WriteString("1. Regularly update WAF rules and signatures\n")
	sb.WriteString("2. Implement rate limiting on all API endpoints\n")
	sb.WriteString("3. Enable logging and monitoring for security events\n")
	sb.WriteString("4. Conduct regular security assessments\n\n")

	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Report generated by WAF-Tester v%s - Superpower Mode*\n", ui.Version))

	os.WriteFile(filename, []byte(sb.String()), 0644)
}

// generateSARIFReport creates a SARIF format report for CI/CD integration
// SARIF (Static Analysis Results Interchange Format) is used by GitHub Code Scanning,
// Azure DevOps, and other security analysis tools.
func generateSARIFReport(filename, target string, results output.ExecutionResults) error {
	// SARIF 2.1.0 schema
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":            "WAFtester",
						"version":         defaults.Version,
						"informationUri":  "https://github.com/waftester/waftester",
						"semanticVersion": defaults.Version,
						"rules":           buildSARIFRules(results),
					},
				},
				"results":    buildSARIFResults(target, results),
				"invocations": []map[string]interface{}{
					{
						"executionSuccessful": true,
						"endTimeUtc":          time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// buildSARIFRules creates rule definitions from categories
func buildSARIFRules(results output.ExecutionResults) []map[string]interface{} {
	rules := make([]map[string]interface{}, 0)
	seenCategories := make(map[string]bool)

	for _, bypass := range results.BypassDetails {
		if seenCategories[bypass.Category] {
			continue
		}
		seenCategories[bypass.Category] = true

		level := "warning"
		switch strings.ToLower(bypass.Severity) {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		case "low", "info":
			level = "note"
		}

		rules = append(rules, map[string]interface{}{
			"id":   bypass.Category,
			"name": bypass.Category,
			"shortDescription": map[string]string{
				"text": fmt.Sprintf("WAF bypass: %s", bypass.Category),
			},
			"fullDescription": map[string]string{
				"text": fmt.Sprintf("WAF bypass detected for %s attack category", bypass.Category),
			},
			"defaultConfiguration": map[string]string{
				"level": level,
			},
			"properties": map[string]interface{}{
				"security-severity": severityToScore(bypass.Severity),
				"tags":              []string{"security", "waf-bypass", bypass.Category},
			},
		})
	}

	return rules
}

// buildSARIFResults creates result entries from bypass details
func buildSARIFResults(target string, results output.ExecutionResults) []map[string]interface{} {
	sarifResults := make([]map[string]interface{}, 0, len(results.BypassDetails))

	for _, bypass := range results.BypassDetails {
		level := "warning"
		switch strings.ToLower(bypass.Severity) {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		case "low", "info":
			level = "note"
		}

		sarifResults = append(sarifResults, map[string]interface{}{
			"ruleId": bypass.Category,
			"level":  level,
			"message": map[string]string{
				"text": fmt.Sprintf("WAF bypass detected: %s payload passed through WAF on endpoint %s (HTTP %d)",
					bypass.Category, bypass.Endpoint, bypass.StatusCode),
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": target + bypass.Endpoint,
						},
					},
					"logicalLocations": []map[string]interface{}{
						{
							"name": bypass.Endpoint,
							"kind": "endpoint",
						},
					},
				},
			},
			"properties": map[string]interface{}{
				"payload":     bypass.Payload,
				"statusCode":  bypass.StatusCode,
				"method":      bypass.Method,
				"curlCommand": bypass.CurlCommand,
			},
		})
	}

	return sarifResults
}

// severityToScore converts severity string to CVSS-like score
func severityToScore(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "3.0"
	default:
		return "1.0"
	}
}
