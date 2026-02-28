package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/assessment"
	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/browser"
	"github.com/waftester/waftester/pkg/calibration"
	"github.com/waftester/waftester/pkg/checkpoint"
	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/core"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/httpclient"
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
	"github.com/waftester/waftester/pkg/strutil"
	"github.com/waftester/waftester/pkg/templateresolver"
	tlsja3 "github.com/waftester/waftester/pkg/tls"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/waf/strategy"
	"github.com/waftester/waftester/pkg/waf/vendors"
)

// smartModeCache is a JSON-serializable snapshot of SmartModeResult for resume.
// All Strategy fields are persisted so resumed scans behave identically to fresh ones.
type smartModeCache struct {
	WAFDetected             bool     `json:"waf_detected"`
	VendorName              string   `json:"vendor_name"`
	Confidence              float64  `json:"confidence"`
	BypassHints             []string `json:"bypass_hints,omitempty"`
	RateLimit               float64  `json:"rate_limit"`
	Concurrency             int      `json:"concurrency"`
	StratVendor             string   `json:"strategy_vendor,omitempty"`
	StratVendorName         string   `json:"strategy_vendor_name,omitempty"`
	StratConfidence         float64  `json:"strategy_confidence,omitempty"`
	StratEncoders           []string `json:"strategy_encoders,omitempty"`
	StratEvasions           []string `json:"strategy_evasions,omitempty"`
	StratLocations          []string `json:"strategy_locations,omitempty"`
	StratSkipIneffective    []string `json:"strategy_skip_ineffective,omitempty"`
	StratPrioritizeMutators []string `json:"strategy_prioritize_mutators,omitempty"`
	StratBypassTips         []string `json:"strategy_bypass_tips,omitempty"`
	StratSafeRateLimit      int      `json:"strategy_safe_rate_limit,omitempty"`
	StratBurstRateLimit     int      `json:"strategy_burst_rate_limit,omitempty"`
	StratCooldownSeconds    int      `json:"strategy_cooldown_seconds,omitempty"`
	StratBlockStatusCodes   []int    `json:"strategy_block_status_codes,omitempty"`
	StratBlockPatterns      []string `json:"strategy_block_patterns,omitempty"`
	StratRecommendedDepth   int      `json:"strategy_recommended_depth,omitempty"`
}

// copyStrings returns an independent copy of a string slice.
func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s...)
}

// copyInts returns an independent copy of an int slice.
func copyInts(s []int) []int {
	if s == nil {
		return nil
	}
	return append([]int(nil), s...)
}

func newSmartModeCache(r *SmartModeResult) smartModeCache {
	c := smartModeCache{
		WAFDetected: r.WAFDetected,
		VendorName:  r.VendorName,
		Confidence:  r.Confidence,
		BypassHints: copyStrings(r.BypassHints),
		RateLimit:   r.RateLimit,
		Concurrency: r.Concurrency,
	}
	if r.Strategy != nil {
		c.StratVendor = string(r.Strategy.Vendor)
		c.StratVendorName = r.Strategy.VendorName
		c.StratConfidence = r.Strategy.Confidence
		c.StratEncoders = copyStrings(r.Strategy.Encoders)
		c.StratEvasions = copyStrings(r.Strategy.Evasions)
		c.StratLocations = copyStrings(r.Strategy.Locations)
		c.StratSkipIneffective = copyStrings(r.Strategy.SkipIneffectiveMutators)
		c.StratPrioritizeMutators = copyStrings(r.Strategy.PrioritizeMutators)
		c.StratBypassTips = copyStrings(r.Strategy.BypassTips)
		c.StratSafeRateLimit = r.Strategy.SafeRateLimit
		c.StratBurstRateLimit = r.Strategy.BurstRateLimit
		c.StratCooldownSeconds = r.Strategy.CooldownSeconds
		c.StratBlockStatusCodes = copyInts(r.Strategy.BlockStatusCodes)
		c.StratBlockPatterns = copyStrings(r.Strategy.BlockPatterns)
		c.StratRecommendedDepth = r.Strategy.RecommendedMutationDepth
	}
	return c
}

func (c *smartModeCache) toSmartModeResult() *SmartModeResult {
	return &SmartModeResult{
		WAFDetected: c.WAFDetected,
		VendorName:  c.VendorName,
		Confidence:  c.Confidence,
		BypassHints: c.BypassHints,
		RateLimit:   c.RateLimit,
		Concurrency: c.Concurrency,
		Strategy: &strategy.Strategy{
			Vendor:                   vendors.WAFVendor(c.StratVendor),
			VendorName:               c.StratVendorName,
			Confidence:               c.StratConfidence,
			Encoders:                 c.StratEncoders,
			Evasions:                 c.StratEvasions,
			Locations:                c.StratLocations,
			SkipIneffectiveMutators:  c.StratSkipIneffective,
			PrioritizeMutators:       c.StratPrioritizeMutators,
			BypassTips:               c.StratBypassTips,
			SafeRateLimit:            c.StratSafeRateLimit,
			BurstRateLimit:           c.StratBurstRateLimit,
			CooldownSeconds:          c.StratCooldownSeconds,
			BlockStatusCodes:         c.StratBlockStatusCodes,
			BlockPatterns:            c.StratBlockPatterns,
			RecommendedMutationDepth: c.StratRecommendedDepth,
		},
	}
}

// runAutoScan is the SUPERPOWER command - full automated scan in a single command
// It chains: discover → deep JS analysis → learn → run → comprehensive report
func runAutoScan() {
	startTime := time.Now()

	autoFlags, cfg := registerAutoscanFlags()
	autoFlags.Parse(os.Args[2:])
	cfg.validate()
	defer cfg.Out.CleanupTemplates()

	// Disable detection if requested
	if *cfg.NoDetect {
		detection.Disable()
	}

	// Apply unified output settings (silent, color)
	cfg.Out.ApplyUISettings()

	// Apply silent mode for JSON output - suppress all non-JSON output to stdout
	if cfg.Out.JSONMode {
		ui.SetSilent(true)
	}

	// Print banner and intro only when not in JSON mode
	if !cfg.Out.ShouldSuppressBanner() {
		ui.PrintBanner()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, ui.SectionStyle.Render(ui.Icon("🚀", ">")+" SUPERPOWER MODE - Full Automated Security Scan"))
		fmt.Fprintln(os.Stderr)
	}

	// Helper to suppress console output in JSON mode
	// All informational output should use these instead of fmt.Print*
	quietMode := cfg.Out.JSONMode
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

	// Auto-detect payload directory if not specified
	payloadDir := *cfg.PayloadDir
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
			payloadDir = defaults.PayloadDir // Fallback
		}
	}

	// Get target. In spec mode, target is optional — the spec's server
	// URLs will be used if -u is not provided.
	specModeActive := *cfg.SpecFile != "" || *cfg.SpecURL != ""
	ts := cfg.Common.TargetSource()
	target, err := ts.GetSingleTarget()
	if err != nil && !specModeActive {
		ui.PrintError("Target URL is required. Use: waf-tester auto -u https://example.com")
		os.Exit(1)
	}

	// Parse domain from target (may be empty in spec mode).
	var domain string
	if target != "" {
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			ui.PrintError(fmt.Sprintf("Invalid target URL: %v", parseErr))
			os.Exit(1)
		}
		domain = parsedURL.Hostname()
	} else {
		domain = "spec-scan"
	}

	// Create output directory structure
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	workspaceDir := *cfg.OutputDir
	if workspaceDir == "" {
		// Use project root workspaces directory for consistent output location
		projectRoot := getProjectRoot()
		workspaceDir = filepath.Join(projectRoot, "workspaces", domain, timestamp)
	}
	// Clean previous workspace files unless --no-clean or --resume is set.
	// Resume needs the existing workspace intact to restore checkpoint state.
	if !*cfg.NoClean && !*cfg.ResumeScan && workspaceDir != "" {
		if info, err := os.Stat(workspaceDir); err == nil && info.IsDir() {
			if removeErr := os.RemoveAll(workspaceDir); removeErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to clean workspace: %v", removeErr))
			}
		}
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
	cpFile := *cfg.CheckpointFile
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
		"full-recon",
		"learning",
		"waf-testing",
		"brain-feedback",
		"mutation-pass",
		"assessment",
		"browser-scan",
		"vendor-detection",
	}

	// Initialize checkpoint with phase names as targets
	cpManager.Init("auto", phaseNames, map[string]interface{}{
		"target":      target,
		"workspace":   workspaceDir,
		"concurrency": *cfg.Concurrency,
		"rate_limit":  *cfg.RateLimit,
	})

	// Helper to mark phase as completed and save checkpoint
	markPhaseCompleted := func(name string) {
		_ = cpManager.MarkCompleted(name)
	}

	// Helper to check if phase should be skipped (resume mode)
	shouldSkipPhase := func(name string) bool {
		if !*cfg.ResumeScan {
			return false
		}
		return cpManager.IsCompleted(name)
	}

	// Check for resume mode
	if *cfg.ResumeScan && cpManager.Exists() {
		state, err := cpManager.Load()
		if err == nil && state != nil {
			ui.PrintInfo(fmt.Sprintf("Resuming scan from checkpoint (started: %s)", state.StartTime.Format(time.RFC3339)))

			completedCount := state.CompletedTargets
			ui.PrintSuccess(fmt.Sprintf("  Restored %d completed phases, resuming from phase %d", completedCount, completedCount+1))
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// BRAIN MODE INITIALIZATION (v2.6.4)
	// Learns, adapts, builds attack chains
	// ═══════════════════════════════════════════════════════════════════════════
	var brain *intelligence.Engine
	var insightCount int32
	var chainCount int32

	// Insight dedup: aggregate repeated titles instead of spamming console
	var insightMu sync.Mutex
	insightSeen := make(map[string]int) // title → count

	if *cfg.EnableBrain {
		brain = intelligence.NewEngine(&intelligence.Config{
			LearningSensitivity: 0.7,
			MinConfidence:       0.6,
			EnableChains:        true,
			EnableWAFModel:      true,
			MaxChains:           50,
			Verbose:             *cfg.BrainVerbose,
		})

		// Register insight callback for real-time brain insights
		brain.OnInsight(func(insight *intelligence.Insight) {
			atomic.AddInt32(&insightCount, 1)
			if *cfg.BrainVerbose && !quietMode {
				insightMu.Lock()
				insightSeen[insight.Title]++
				count := insightSeen[insight.Title]
				insightMu.Unlock()

				// Only print the first occurrence of each insight title;
				// subsequent duplicates are silently counted and summarized later.
				if count > 1 {
					return
				}

				priorityStyle := ui.PassStyle
				switch insight.Priority {
				case 1:
					priorityStyle = ui.SeverityStyle("Critical")
				case 2:
					priorityStyle = ui.SeverityStyle("High")
				case 3:
					priorityStyle = ui.SeverityStyle("Medium")
				}
				// Show description (has URL/path details) for vulnerability insights,
				// fall back to title for others.
				detail := insight.Title
				if insight.Type == intelligence.InsightVulnerability && insight.Description != "" {
					detail = insight.Description
				}
				fmt.Fprintf(os.Stderr, "  %s %s: %s\n", ui.Icon("🧠", "*"), priorityStyle.Render(string(insight.Type)), detail)
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
				fmt.Fprintf(os.Stderr, "  %s  %s: %s (CVSS %.1f)\n",
					ui.Icon("⛓️", ">"),
					impactStyle.Render("ATTACK CHAIN"), chain.Name, chain.CVSS)
			}
		})

		if !quietMode {
			ui.PrintInfo(ui.Icon("🧠", "*") + " Brain Mode enabled (adaptive learning, attack chains)")
		}
	}

	// Brain state persistence for resume support.
	// The engine has Save/Load that persists all cognitive modules
	// (memory, WAF model, tech profile, predictor, mutator, clusterer, pathfinder).
	brainStatePath := filepath.Join(workspaceDir, "brain-state.json")
	saveBrainState := func() {
		if brain == nil {
			return
		}
		if err := brain.Save(brainStatePath); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to save brain state: %v", err))
		}
	}

	// Restore brain state on resume so sub-passes have full intelligence.
	if *cfg.ResumeScan && brain != nil {
		if err := brain.Load(brainStatePath); err == nil {
			ui.PrintInfo("🧠 Brain state restored from checkpoint")
		}
	}

	fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("Configuration"))
	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Domain", domain)
	if *cfg.Service != "" {
		ui.PrintConfigLine("Service", *cfg.Service)
	}
	ui.PrintConfigLine("Workspace", workspaceDir)
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *cfg.Concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d req/sec", *cfg.RateLimit))
	if *cfg.EnableLeakyPaths {
		ui.PrintConfigLine("Leaky Paths", "Enabled (300+ sensitive paths)")
	}
	if *cfg.EnableParamDiscovery {
		ui.PrintConfigLine("Param Discovery", "Enabled (Arjun-style)")
	}
	if *cfg.EnableJA3 {
		profile := *cfg.JA3Profile
		if profile == "" {
			profile = "rotating"
		}
		ui.PrintConfigLine("JA3 Rotation", profile)
	}
	if *cfg.EnableFullRecon {
		ui.PrintConfigLine("Full Recon", "Enabled (unified reconnaissance)")
	}
	fmt.Fprintln(os.Stderr)

	// Create JA3-aware HTTP client if enabled
	var ja3Client *http.Client
	if *cfg.EnableJA3 {
		ja3Cfg := &tlsja3.Config{
			RotateEvery: 25,
			Timeout:     time.Duration(cfg.Common.Timeout) * time.Second,
			SkipVerify:  cfg.Common.SkipVerify,
		}
		if *cfg.JA3Profile != "" {
			// Use specific profile
			if profile, err := tlsja3.GetProfileByName(*cfg.JA3Profile); err == nil {
				ja3Cfg.Profiles = []*tlsja3.JA3Profile{profile}
			}
		}
		ja3Client = tlsja3.CreateFallbackClient(ja3Cfg) // Use fallback for compatibility
	}

	// Setup graceful shutdown
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	autoScanID := fmt.Sprintf("auto-%d", time.Now().Unix())
	autoDispCtx, autoDispErr := cfg.Out.InitDispatcher(autoScanID, target)
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
		_ = autoDispCtx.EmitStart(ctx, target, 0, *cfg.Concurrency, nil)
	}

	// Determine output mode for LiveProgress
	autoOutputMode := ui.DefaultOutputMode()
	if cfg.Out.JSONMode {
		autoOutputMode = ui.OutputModeSilent
	} else if cfg.Out.StreamMode {
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
			{Name: "endpoints", Label: "Endpoints", Icon: ui.Icon("🎯", "@")},
			{Name: "secrets", Label: "Secrets", Icon: ui.Icon("🔑", "*"), Highlight: true},
			{Name: "bypasses", Label: "Bypasses", Icon: ui.Icon("⚠️", "!"), Highlight: true},
		},
		StreamFormat:   "[PROGRESS] phase {completed}/{total} | {status} | endpoints: {metric:endpoints} | {elapsed}",
		StreamInterval: duration.StreamSlow,
	})
	autoProgress.Start()
	defer autoProgress.Stop()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 0: SMART MODE - WAF DETECTION & STRATEGY OPTIMIZATION (Optional)
	// Runs BEFORE spec pipeline so both paths benefit from WAF-tuned settings.
	// ═══════════════════════════════════════════════════════════════════════════
	smartModeFile := filepath.Join(workspaceDir, "smart-mode.json")
	var smartResult *SmartModeResult

	if *cfg.Smart.Enabled && shouldSkipPhase("smart-mode") {
		ui.PrintInfo("⏭️  Skipping smart mode (already completed)")
		// Reload cached smart mode results for downstream phases
		if data, err := os.ReadFile(smartModeFile); err == nil {
			var cached smartModeCache
			if err := json.Unmarshal(data, &cached); err == nil {
				smartResult = cached.toSmartModeResult()
			}
		}
	}

	if *cfg.Smart.Enabled && smartResult == nil && !shouldSkipPhase("smart-mode") {
		printStatusLn(ui.SectionStyle.Render("PHASE 0: Smart Mode - WAF Detection & Strategy Optimization"))
		printStatusLn()

		ui.PrintInfo(ui.Icon("🧠", "*") + " Detecting WAF vendor from 197+ signatures...")

		smartConfig := &SmartModeConfig{
			DetectionTimeout: time.Duration(cfg.Common.Timeout) * time.Second,
			Verbose:          *cfg.Smart.Verbose,
			Mode:             *cfg.Smart.Mode,
		}

		var err error
		smartResult, err = DetectAndOptimize(ctx, target, smartConfig)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", err))
		}

		if !quietMode {
			PrintSmartModeInfo(smartResult, *cfg.Smart.Verbose)
		}

		// Apply WAF-optimized rate limit and concurrency
		// Only override if the user didn't explicitly set these flags
		if smartResult != nil && smartResult.WAFDetected {
			userSetRL := false
			userSetConc := false
			autoFlags.Visit(func(f *flag.Flag) {
				if f.Name == "rl" {
					userSetRL = true
				}
				if f.Name == "c" {
					userSetConc = true
				}
			})

			if !userSetRL && smartResult.RateLimit > 0 {
				ui.PrintInfo(fmt.Sprintf("%s Rate limit: %.0f req/sec (WAF-optimized for %s)",
					ui.Icon("📊", "#"),
					smartResult.RateLimit, smartResult.VendorName))
				*cfg.RateLimit = int(smartResult.RateLimit)
			}
			if !userSetConc && smartResult.Concurrency > 0 {
				ui.PrintInfo(fmt.Sprintf("%s Concurrency: %d workers (WAF-optimized)",
					ui.Icon("📊", "#"),
					smartResult.Concurrency))
				*cfg.Concurrency = smartResult.Concurrency
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
		markPhaseCompleted("smart-mode")

		// Persist smart mode results for resume
		if smartResult != nil {
			cached := newSmartModeCache(smartResult)
			if data, err := json.MarshalIndent(cached, "", "  "); err == nil {
				if werr := os.WriteFile(smartModeFile, data, 0644); werr != nil {
					ui.PrintWarning(fmt.Sprintf("Failed to save smart mode cache: %v", werr))
				}
			}
		}
		printStatusLn()
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// SPEC-DRIVEN PIPELINE: If --spec or --spec-url provided, use intelligence
	// engine instead of discovery+learning.
	// ═══════════════════════════════════════════════════════════════════════════
	if *cfg.SpecFile != "" || *cfg.SpecURL != "" {
		runSpecPipeline(specPipelineConfig{
			specFile:       *cfg.SpecFile,
			specURL:        *cfg.SpecURL,
			target:         target,
			intensity:      *cfg.SpecIntensity,
			group:          *cfg.SpecGroup,
			skipGroup:      *cfg.SpecSkipGroup,
			scanConfigPath: *cfg.ScanConfigPath,
			dryRun:         *cfg.SpecDryRun,
			yes:            *cfg.SpecYes,
			concurrency:    *cfg.Concurrency,
			rateLimit:      *cfg.RateLimit,
			timeout:        cfg.Common.Timeout,
			skipVerify:     cfg.Common.SkipVerify,
			verbose:        cfg.Common.Verbose,
			quietMode:      quietMode,
			outFlags:       &cfg.Out,
			printStatus:    printStatus,
			smartResult:    smartResult,
		})
		return
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// DRY-RUN: Show scan plan without executing (also works for non-spec scans)
	// ═══════════════════════════════════════════════════════════════════════════
	if *cfg.SpecDryRun {
		ui.PrintSection("Auto Scan Plan (dry-run)")
		fmt.Printf("  Target:        %s\n", target)
		fmt.Printf("  Concurrency:   %d\n", *cfg.Concurrency)
		fmt.Printf("  Rate Limit:    %d req/sec\n", *cfg.RateLimit)
		fmt.Printf("  Timeout:       %ds\n", cfg.Common.Timeout)
		fmt.Printf("  Smart Mode:    %v\n", *cfg.Smart.Enabled)
		fmt.Printf("  Brain Mode:    %v\n", *cfg.EnableBrain)
		fmt.Println()
		ui.PrintSection("Phases")
		if *cfg.Smart.Enabled {
			fmt.Println("  0. Smart Mode - WAF Detection & Strategy Optimization")
		}
		fmt.Println("  1. Target Discovery & Reconnaissance")
		fmt.Println("  2. Leaky Path Scanning")
		fmt.Println("  3. Learning Phase - WAF Behavior Analysis")
		fmt.Println("  4. Core Vulnerability Scanning")
		fmt.Println("  5. Tamper Discovery & Bypass Analysis")
		fmt.Println("  6. Enterprise Assessment")
		fmt.Println("  7. Report Generation")
		fmt.Println()
		ui.PrintInfo("No requests sent. Remove --dry-run to execute.")
		return
	}

	// Update progress after smart mode
	autoProgress.SetStatus("Discovery")
	autoProgress.Increment()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 1: DISCOVERY
	// ═══════════════════════════════════════════════════════════════════════════
	var discResult *discovery.DiscoveryResult
	discoveryRanFresh := false

	if shouldSkipPhase("discovery") {
		ui.PrintInfo("⏭️  Skipping discovery (already completed)")
		// Load previous discovery results if available
		if data, err := os.ReadFile(discoveryFile); err == nil {
			var loaded discovery.DiscoveryResult
			if err := json.Unmarshal(data, &loaded); err == nil {
				discResult = &loaded
			}
		}
	}

	if discResult == nil {
		printStatusLn(ui.SectionStyle.Render("PHASE 1: Target Discovery & Reconnaissance"))
		printStatusLn()

		discoveryCfg := discovery.DiscoveryConfig{
			Target:      target,
			Service:     *cfg.Service,
			Timeout:     time.Duration(cfg.Common.Timeout) * time.Second,
			Concurrency: *cfg.Concurrency,
			MaxDepth:    *cfg.Depth,
			SkipVerify:  cfg.Common.SkipVerify,
			Verbose:     cfg.Common.Verbose,
			HTTPClient:  ja3Client, // JA3 TLS fingerprint rotation
		}

		discoverer := discovery.NewDiscoverer(discoveryCfg)

		// Poll endpoint count during discovery so the progress ticker
		// reflects intermediate results instead of staying at 0.
		discDone := make(chan struct{})
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-discDone:
					return
				case <-ticker.C:
					autoProgress.SetMetric("endpoints", int64(discoverer.EndpointCount()))
				}
			}
		}()

		ui.PrintInfo(ui.Icon("🔍", "?") + " Starting endpoint discovery...")
		var err error
		discResult, err = discoverer.Discover(ctx)
		close(discDone)
		if err != nil {
			errMsg := fmt.Sprintf("Discovery failed: %v", err)
			ui.PrintError(errMsg)
			if autoDispCtx != nil {
				_ = autoDispCtx.EmitError(ctx, "auto", errMsg, true)
				_ = autoDispCtx.Close()
			}
			os.Exit(1) // intentional: CLI early exit on fatal error
		}

		if err := discResult.SaveResult(discoveryFile); err != nil {
			errMsg := fmt.Sprintf("Error saving discovery: %v", err)
			ui.PrintError(errMsg)
			if autoDispCtx != nil {
				_ = autoDispCtx.EmitError(ctx, "auto", errMsg, true)
				_ = autoDispCtx.Close()
			}
			os.Exit(1) // intentional: CLI early exit on fatal error
		}

		ui.PrintSuccess(fmt.Sprintf("%s Discovered %d endpoints", ui.Icon("✓", "+"), len(discResult.Endpoints)))
		if discResult.WAFDetected {
			wafLabel := discResult.WAFFingerprint
			// Fall back to smart mode WAF name when discovery fingerprint is empty
			if wafLabel == "" && smartResult != nil && smartResult.VendorName != "" {
				wafLabel = smartResult.VendorName
			}
			if wafLabel != "" {
				ui.PrintInfo(fmt.Sprintf("  WAF Detected: %s", wafLabel))
			}
		}
		printStatusLn()

		// Mark discovery phase complete for resume
		markPhaseCompleted("discovery")
		discoveryRanFresh = true
	}

	// Update progress after discovery
	autoProgress.SetMetric("endpoints", int64(len(discResult.Endpoints)))
	autoProgress.SetStatus("Leaky paths")
	autoProgress.Increment()

	// Feed discovery findings to Brain (only on first run, not resume)
	if brain != nil && discoveryRanFresh {
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

	if *cfg.EnableLeakyPaths && !shouldSkipPhase("leaky-paths") {
		printStatusLn(ui.SectionStyle.Render("PHASE 1.5: Sensitive Path Scanning (leaky-paths)"))
		printStatusLn()

		// Filter categories if specified
		var categories []string
		if *cfg.LeakyCategories != "" {
			categories = strings.Split(*cfg.LeakyCategories, ",")
			ui.PrintInfo(fmt.Sprintf("%s Scanning for sensitive paths (categories: %s)...", ui.Icon("🔓", "?"), *cfg.LeakyCategories))
		} else {
			ui.PrintInfo(ui.Icon("🔓", "?") + " Scanning 1,766+ high-value sensitive paths...")
		}

		// Show what we're looking for
		printStatusLn()
		printStatus("  %s\n", ui.SubtitleStyle.Render("  Targets: .git, .env, admin panels, backups, configs, debug endpoints..."))
		printStatusLn()

		leakyScanner := leakypaths.NewScanner(&leakypaths.Config{
			Base: attackconfig.Base{
				Timeout:     time.Duration(cfg.Common.Timeout) * time.Second,
				Concurrency: *cfg.Concurrency,
			},
			Verbose:    cfg.Common.Verbose,
			HTTPClient: ja3Client, // JA3 TLS fingerprint rotation
		})

		var err error
		leakyResult, err = leakyScanner.Scan(ctx, target, categories...)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Leaky paths scan warning: %v", err))
		} else {
			// Save results
			leakyData, marshalErr := json.MarshalIndent(leakyResult, "", "  ")
			if marshalErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to marshal leaky paths: %v", marshalErr))
			} else if err := os.WriteFile(leakyPathsFile, leakyData, 0644); err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to write leaky paths: %v", err))
			}

			// Summary with timing
			ui.PrintSuccess(fmt.Sprintf("%s Scanned %d paths in %s", ui.Icon("✓", "+"), leakyResult.TotalPaths, leakyResult.Duration.Round(time.Millisecond)))
			printStatusLn()

			if leakyResult.InterestingHits > 0 && !quietMode {
				// Show severity breakdown in nuclei-style
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.Icon("📊", "#")+" Findings by Severity:"))
				leakySevKeys := make([]string, 0, len(leakyResult.BySeverity))
				for sev := range leakyResult.BySeverity {
					leakySevKeys = append(leakySevKeys, sev)
				}
				sort.Strings(leakySevKeys)
				for _, severity := range leakySevKeys {
					count := leakyResult.BySeverity[severity]
					sevStyle := ui.SeverityStyle(severity)
					bar := strings.Repeat(ui.Icon("█", "#"), min(count, 20))
					fmt.Fprintf(os.Stderr, "    %s %s %d\n", sevStyle.Render(fmt.Sprintf("%-8s", severity)), ui.ProgressFullStyle.Render(bar), count)
				}
				fmt.Fprintln(os.Stderr)

				// Show category breakdown
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.Icon("📂", "#")+" Findings by Category:"))
				leakyCatKeys := make([]string, 0, len(leakyResult.ByCategory))
				for cat := range leakyResult.ByCategory {
					leakyCatKeys = append(leakyCatKeys, cat)
				}
				sort.Strings(leakyCatKeys)
				for _, category := range leakyCatKeys {
					count := leakyResult.ByCategory[category]
					bar := strings.Repeat(ui.Icon("▪", "*"), min(count, 20))
					fmt.Fprintf(os.Stderr, "    %-15s %s %d\n", category, ui.StatLabelStyle.Render(bar), count)
				}
				fmt.Fprintln(os.Stderr)

				// Show top findings in nuclei-style bracketed format
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.Icon("🎯", "@")+" Top Findings:"))
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
				ui.PrintSuccess(fmt.Sprintf("  %s No sensitive paths exposed - good security posture!", ui.Icon("✓", "+")))
			}
		}
		if !quietMode {
			fmt.Fprintln(os.Stderr)
		}

		// G2: Feed leaky path URLs into discovery endpoints for attack pipeline
		if leakyResult != nil && leakyResult.InterestingHits > 0 {
			for _, result := range leakyResult.Results {
				if !result.Interesting {
					continue
				}
				discResult.Endpoints = append(discResult.Endpoints, discovery.Endpoint{
					Path:     result.Path,
					Method:   "GET",
					Category: result.Category,
					Service:  "leaky-paths",
				})
			}
		}

		// Update endpoint counter after leaky paths enrichment
		autoProgress.SetMetric("endpoints", int64(len(discResult.Endpoints)))

		// G9: Feed leaky paths findings to Brain
		if brain != nil && leakyResult != nil && leakyResult.InterestingHits > 0 {
			brain.StartPhase(ctx, "leaky-paths")
			for _, result := range leakyResult.Results {
				if !result.Interesting {
					continue
				}
				brain.LearnFromFinding(&intelligence.Finding{
					Phase:      "leaky-paths",
					Category:   result.Category,
					Severity:   result.Severity,
					Path:       result.Path,
					Evidence:   fmt.Sprintf("Exposed: %s (%d)", result.Path, result.StatusCode),
					Confidence: 0.85,
					StatusCode: result.StatusCode,
					Metadata: map[string]interface{}{
						"category":    result.Category,
						"status_code": result.StatusCode,
					},
				})
			}
			brain.EndPhase("leaky-paths")
		}

		markPhaseCompleted("leaky-paths")
	} else if *cfg.EnableLeakyPaths && shouldSkipPhase("leaky-paths") {
		// Resume: reload leaky-paths results for G2/G9 enrichments
		ui.PrintInfo("⏭️  Skipping leaky-paths (already completed)")
		if data, err := os.ReadFile(leakyPathsFile); err == nil {
			var loaded leakypaths.ScanSummary
			if err := json.Unmarshal(data, &loaded); err == nil {
				leakyResult = &loaded
				// G2: Re-inject leaky path endpoints into discovery
				if leakyResult.InterestingHits > 0 {
					for _, result := range leakyResult.Results {
						if !result.Interesting {
							continue
						}
						discResult.Endpoints = append(discResult.Endpoints, discovery.Endpoint{
							Path:     result.Path,
							Method:   "GET",
							Category: result.Category,
							Service:  "leaky-paths",
						})
					}
				}
			}
		}
	}

	// Refresh endpoint counter after leaky-paths resume enrichment
	autoProgress.SetMetric("endpoints", int64(len(discResult.Endpoints)))

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 2: DEEP JAVASCRIPT ANALYSIS
	// ═══════════════════════════════════════════════════════════════════════════

	// Declare JS analysis outputs before skip guard — used in summary and reports
	allJSData := &js.ExtractedData{
		URLs:       make([]js.URLInfo, 0),
		Endpoints:  make([]js.EndpointInfo, 0),
		Secrets:    make([]js.SecretInfo, 0),
		DOMSinks:   make([]js.DOMSinkInfo, 0),
		CloudURLs:  make([]js.CloudURL, 0),
		Subdomains: make([]string, 0),
	}
	var jsAnalyzed int32

	if shouldSkipPhase("js-analysis") {
		ui.PrintInfo("⏭️  Skipping JS analysis (already completed)")
		// Reload JS data from disk for summary/report usage
		if data, err := os.ReadFile(jsAnalysisFile); err == nil {
			var loaded js.ExtractedData
			if err := json.Unmarshal(data, &loaded); err == nil {
				allJSData = &loaded
			}
		}

		// Re-inject JS endpoints into discResult — downstream phases (clustering,
		// test plan, payload routing) depend on these being present.
		for _, ep := range allJSData.Endpoints {
			method := ep.Method
			if method == "" {
				method = inferHTTPMethod(ep.Path, ep.Source)
			}
			discResult.Endpoints = append(discResult.Endpoints, discovery.Endpoint{
				Path:     ep.Path,
				Method:   method,
				Category: "api",
				Service:  "js-discovery",
			})
		}
		seenPaths := make(map[string]bool)
		for _, ep := range discResult.Endpoints {
			seenPaths[ep.Method+":"+ep.Path] = true
		}
		for _, urlInfo := range allJSData.URLs {
			if !strings.HasPrefix(urlInfo.URL, "/") || strings.HasPrefix(urlInfo.URL, "//") {
				continue
			}
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

		// Update counters after JS resume re-injection
		autoProgress.SetMetric("endpoints", int64(len(discResult.Endpoints)))
		autoProgress.AddMetricN("secrets", int64(len(allJSData.Secrets)))
	} else {
		printStatusLn(ui.SectionStyle.Render("PHASE 2: Deep JavaScript Analysis"))
		printStatusLn()

		ui.PrintInfo(ui.Icon("📜", ">") + " Extracting and analyzing JavaScript files...")

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

		// Use JA3-aware client if enabled, otherwise standard client
		var client *http.Client
		if ja3Client != nil {
			client = ja3Client
		} else {
			client = httpclient.New(httpclient.WithTimeout(time.Duration(cfg.Common.Timeout) * time.Second))
		}

		totalJSFiles := len(jsFiles)
		var secretsFound, endpointsFound int32

		// Animated progress for JS analysis
		jsProgressDone := make(chan struct{})
		jsSpinnerFrames := ui.DefaultSpinner().Frames
		jsFrameIdx := 0
		jsStartTime := time.Now()

		if totalJSFiles > 1 && !cfg.Out.StreamMode && !quietMode && ui.StderrIsTerminal() {
			go func() {
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-jsProgressDone:
						return
					case <-ctx.Done():
						return
					case <-ticker.C:
						analyzed := int(atomic.LoadInt32(&jsAnalyzed))
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
							strings.Repeat(ui.Icon("█", "#"), fillWidth),
							strings.Repeat(ui.Icon("░", "."), progressWidth-fillWidth))

						secretColor := "\033[32m" // Green
						if secrets > 0 {
							secretColor = "\033[31m" // Red - secrets found!
						}

						fmt.Fprintf(os.Stderr, "\033[2A\033[J")
						fmt.Fprintf(os.Stderr, "  %s %s %.1f%% (%d/%d files)\n", spinner, bar, percent, analyzed, totalJSFiles)
						fmt.Fprintf(os.Stderr, "  %s Endpoints: %d  %s%s Secrets: %d\033[0m  %s  %s\n",
							ui.Icon("📊", "#"), endpoints, secretColor, ui.Icon("🔑", "*"), secrets, ui.Icon("⏱️", ""), elapsed.Round(time.Second))
					}
				}
			}()
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr)
		}

		for _, jsPath := range jsFiles {
			// Check for cancellation between files
			if ctx.Err() != nil {
				break
			}

			var jsURL string
			if !strings.HasPrefix(jsPath, "http") {
				jsURL = strings.TrimSuffix(target, "/") + jsPath
			} else {
				jsURL = jsPath
			}

			req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
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
			atomic.AddInt32(&jsAnalyzed, 1)

			// Update atomic counters for progress display
			atomic.AddInt32(&secretsFound, int32(len(result.Secrets)))
			atomic.AddInt32(&endpointsFound, int32(len(result.Endpoints)))

			if cfg.Common.Verbose {
				ui.PrintInfo(fmt.Sprintf("  Analyzed: %s (%d URLs, %d endpoints, %d secrets)",
					jsPath, len(result.URLs), len(result.Endpoints), len(result.Secrets)))
			}
		}

		// Stop JS analysis progress display
		if totalJSFiles > 1 {
			close(jsProgressDone)
			select {
			case <-ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
			if !quietMode && ui.StderrIsTerminal() {
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
		sort.Strings(allJSData.Subdomains)

		// Save JS analysis
		jsDataBytes, marshalErr := json.MarshalIndent(allJSData, "", "  ")
		if marshalErr != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to marshal JS analysis: %v", marshalErr))
		} else if err := os.WriteFile(jsAnalysisFile, jsDataBytes, 0644); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to write JS analysis: %v", err))
		}

		ui.PrintSuccess(fmt.Sprintf("✓ Analyzed %d JavaScript files", atomic.LoadInt32(&jsAnalyzed)))
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

		// Update endpoint counter after JS-discovered endpoints
		autoProgress.SetMetric("endpoints", int64(len(discResult.Endpoints)))

		// Print secrets if found
		if len(allJSData.Secrets) > 0 && !quietMode {
			fmt.Fprintln(os.Stderr)
			ui.PrintSection("🔑 Secrets Detected in JavaScript")
			for _, secret := range allJSData.Secrets {
				confidence := strings.ToUpper(secret.Confidence)
				if confidence == "" {
					confidence = "LOW"
				}
				truncated := secret.Value
				if truncRunes := []rune(truncated); len(truncRunes) > 50 {
					truncated = string(truncRunes[:50]) + "..."
				}
				ui.PrintError(fmt.Sprintf("  [%s] %s: %s", confidence, secret.Type, truncated))
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

		// Feed JS analysis findings to Brain
		if brain != nil {
			brain.StartPhase(ctx, "js-analysis")
			// Secrets - highest priority
			for _, secret := range allJSData.Secrets {
				brain.LearnFromFinding(&intelligence.Finding{
					Phase:      "js-analysis",
					Category:   "secret",
					Severity:   "high",
					Evidence:   secret.Type + ": " + strutil.Truncate(secret.Value, 30),
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
	} // end else: js-analysis skip guard
	markPhaseCompleted("js-analysis")

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 2.5: PARAMETER DISCOVERY (NEW - competitive feature from Arjun)
	// ═══════════════════════════════════════════════════════════════════════════
	paramsFile := filepath.Join(workspaceDir, "discovered-params.json")
	var paramResult *params.DiscoveryResult

	if *cfg.EnableParamDiscovery && !shouldSkipPhase("param-discovery") {
		// Clear detection state so discovery-phase connection drops (e.g. from
		// path brute-force) don't block parameter probing.
		if det := detection.Default(); det != nil {
			det.ClearHostErrors(target)
		} else {
			hosterrors.Clear(target)
		}

		printStatusLn(ui.SectionStyle.Render("PHASE 2.5: Parameter Discovery (Arjun-style)"))
		printStatusLn()

		ui.PrintInfo("🔍 Discovering hidden API parameters...")
		printStatusLn()
		printStatus("  %s\n", ui.SubtitleStyle.Render("  Technique: Chunked parameter injection (256 params/request)"))
		printStatus("  %s\n", ui.SubtitleStyle.Render("  Wordlist: 1,000+ common parameters (id, key, token, debug, admin...)"))
		printStatusLn()

		paramDiscoverer := params.NewDiscoverer(&params.Config{
			Base: attackconfig.Base{
				Timeout:     time.Duration(cfg.Common.Timeout) * time.Second,
				Concurrency: *cfg.Concurrency,
			},
			Verbose:      cfg.Common.Verbose,
			ChunkSize:    256, // Test 256 params per request for efficiency
			HTTPClient:   ja3Client,
			WordlistFile: *cfg.ParamWordlist,
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
			paramSpinnerFrames := ui.DefaultSpinner().Frames
			paramFrameIdx := 0
			totalEndpoints := len(testEndpoints)

			if !cfg.Out.StreamMode && !quietMode && ui.StderrIsTerminal() {
				go func() {
					ticker := time.NewTicker(100 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-paramProgressDone:
							return
						case <-ctx.Done():
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
								strings.Repeat(ui.Icon("█", "#"), fillWidth),
								strings.Repeat(ui.Icon("░", "."), progressWidth-fillWidth))

							paramColor := "\033[33m" // Yellow
							if found > 0 {
								paramColor = "\033[32m" // Green - params found!
							}

							fmt.Fprintf(os.Stderr, "\033[2A\033[J")
							fmt.Fprintf(os.Stderr, "  %s %s %.1f%% (%d/%d endpoints)\n", spinner, bar, percent, done, totalEndpoints)
							fmt.Fprintf(os.Stderr, "  %s%s Parameters found: %d\033[0m  %s  %s\n",
								paramColor, ui.Icon("🔍", "?"), found, ui.Icon("⏱️", ""), elapsed.Round(time.Second))
						}
					}
				}()
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr)
			} // end if !cfg.Out.StreamMode

			for _, endpoint := range testEndpoints {
				result, err := paramDiscoverer.Discover(ctx, endpoint)
				if err != nil {
					if cfg.Common.Verbose && !quietMode {
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
			select {
			case <-ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
			if !quietMode && ui.StderrIsTerminal() {
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
			paramData, marshalErr := json.MarshalIndent(paramResult, "", "  ")
			if marshalErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to marshal params: %v", marshalErr))
			} else if err := os.WriteFile(paramsFile, paramData, 0644); err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to write params: %v", err))
			}

			ui.PrintSuccess(fmt.Sprintf("✓ Scanned %d endpoints in %s", len(testEndpoints), duration.Round(time.Millisecond)))

			if len(allParams) > 0 && !quietMode {
				fmt.Fprintln(os.Stderr)
				// Show type breakdown
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("📊 Parameters by Type:")))
				paramTypeKeys := make([]string, 0, len(paramResult.ByType))
			for pt := range paramResult.ByType {
				paramTypeKeys = append(paramTypeKeys, pt)
			}
			sort.Strings(paramTypeKeys)
			for _, paramType := range paramTypeKeys {
				count := paramResult.ByType[paramType]
					typeStyle := ui.ConfigValueStyle
					switch paramType {
					case "query":
						typeStyle = ui.PassStyle
					case "body":
						typeStyle = ui.BlockedStyle
					case "header":
						typeStyle = ui.ErrorStyle
					}
					bar := strings.Repeat(ui.Icon("█", "#"), min(count, 20))
					fmt.Fprintf(os.Stderr, "    %s %s %d\n", typeStyle.Render(fmt.Sprintf("%-8s", paramType)), ui.ProgressFullStyle.Render(bar), count)
				}
				fmt.Fprintln(os.Stderr)

				// Show source breakdown
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("🔎 Discovery Sources:")))
				paramSrcKeys := make([]string, 0, len(paramResult.BySource))
				for src := range paramResult.BySource {
					paramSrcKeys = append(paramSrcKeys, src)
				}
				sort.Strings(paramSrcKeys)
				for _, source := range paramSrcKeys {
					count := paramResult.BySource[source]
					bar := strings.Repeat(ui.Icon("▪", "*"), min(count, 20))
					fmt.Fprintf(os.Stderr, "    %-15s %s %d\n", source, ui.StatLabelStyle.Render(bar), count)
				}
				fmt.Fprintln(os.Stderr)

				// Show top findings in nuclei-style
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("🎯 Discovered Parameters:")))
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

		// G9: Feed discovered params to Brain
		if brain != nil && paramResult != nil && paramResult.FoundParams > 0 {
			brain.StartPhase(ctx, "param-discovery")
			for _, p := range paramResult.Parameters {
				brain.LearnFromFinding(&intelligence.Finding{
					Phase:      "param-discovery",
					Category:   "hidden-parameter",
					Severity:   "medium",
					Path:       target,
					Evidence:   fmt.Sprintf("Hidden param: %s (%s via %s)", p.Name, p.Type, p.Source),
					Confidence: p.Confidence,
					Metadata: map[string]interface{}{
						"param_name": p.Name,
						"param_type": p.Type,
						"source":     p.Source,
					},
				})
			}
			brain.EndPhase("param-discovery")
		}

		markPhaseCompleted("param-discovery")
	} else if *cfg.EnableParamDiscovery && shouldSkipPhase("param-discovery") {
		// Resume: reload param discovery results for G1 enrichment
		ui.PrintInfo("⏭️  Skipping param-discovery (already completed)")
		if data, err := os.ReadFile(paramsFile); err == nil {
			var loaded params.DiscoveryResult
			if err := json.Unmarshal(data, &loaded); err == nil {
				paramResult = &loaded
			}
		}
	}
	// Full Recon Mode - runs unified reconnaissance if enabled
	var fullReconResult *recon.FullReconResult
	if *cfg.EnableFullRecon && !shouldSkipPhase("full-recon") {
		printStatusLn(ui.SectionStyle.Render("PHASE 2.7: Unified Reconnaissance (Full Recon)"))
		printStatusLn()

		ui.PrintInfo("🔬 Running comprehensive reconnaissance scan...")
		if !quietMode {
			fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("  Combining: leaky-paths + param-discovery + JS analysis + JA3 rotation"))
			fmt.Fprintln(os.Stderr)
		}

		// Handle empty categories - nil means all categories, not [""] which matches nothing
		var leakyPathCats []string
		if *cfg.LeakyCategories != "" {
			leakyPathCats = strings.Split(*cfg.LeakyCategories, ",")
		}

		// Skip recon modules whose individual phases already produced results,
		// avoiding redundant network requests when --leaky-paths and --discover-params
		// (both default: true) already ran as separate phases.
		alreadyRanLeaky := leakyResult != nil
		alreadyRanParams := paramResult != nil

		reconScanner := recon.NewScanner(&recon.Config{
			Base: attackconfig.Base{
				Timeout:     time.Duration(cfg.Common.Timeout) * time.Second,
				Concurrency: *cfg.Concurrency,
			},
			Verbose:              cfg.Common.Verbose,
			SkipTLSVerify:        cfg.Common.SkipVerify,
			HTTPClient:           ja3Client, // JA3 TLS fingerprint rotation
			EnableLeakyPaths:     *cfg.EnableLeakyPaths && !alreadyRanLeaky,
			EnableParamDiscovery: *cfg.EnableParamDiscovery && !alreadyRanParams,
			EnableJSAnalysis:     true,
			EnableJA3Rotation:    *cfg.EnableJA3,
			LeakyPathCategories:  leakyPathCats,
			JA3Profile:           *cfg.JA3Profile,
			ParamWordlist:        *cfg.ParamWordlist,
		})

		var err error
		fullReconResult, err = reconScanner.FullScan(ctx, target)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Full recon warning: %v", err))
		} else {
			// Save recon results
			reconFile := filepath.Join(workspaceDir, "full-recon.json")
			reconData, marshalErr := json.MarshalIndent(fullReconResult, "", "  ")
			if marshalErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to marshal recon data: %v", marshalErr))
			} else if err := os.WriteFile(reconFile, reconData, 0644); err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to write recon: %v", err))
			}

			ui.PrintSuccess(fmt.Sprintf("✓ Full reconnaissance completed in %s", fullReconResult.Duration.Round(time.Millisecond)))

			if !quietMode {
				fmt.Fprintln(os.Stderr)

				// Show risk assessment
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("📊 Risk Assessment:")))
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
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("⚠️  Top Risks:")))
					for _, risk := range fullReconResult.TopRisks[:min(5, len(fullReconResult.TopRisks))] {
						ui.PrintWarning(fmt.Sprintf("    %s %s", ui.Icon("•", "-"), risk))
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
		markPhaseCompleted("full-recon")
	} else if *cfg.EnableFullRecon && shouldSkipPhase("full-recon") {
		ui.PrintInfo("⏭️  Skipping full-recon (already completed)")
		reconFile := filepath.Join(workspaceDir, "full-recon.json")
		if data, err := os.ReadFile(reconFile); err == nil {
			var loaded recon.FullReconResult
			if err := json.Unmarshal(data, &loaded); err == nil {
				fullReconResult = &loaded
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 2.8: ENDPOINT CLUSTERING (Brain-powered deduplication)
	// Feeds discovered endpoints into the brain's EndpointClusterer to identify
	// redundant paths (e.g., /api/users/1 ~ /api/users/2) and prioritize unique
	// attack surfaces. This reduces test volume without losing coverage.
	// ═══════════════════════════════════════════════════════════════════════════
	const minEndpointsForClustering = 5 // Below this, clustering overhead exceeds benefit
	if brain != nil && discResult != nil && len(discResult.Endpoints) > minEndpointsForClustering {
		clusterer := brain.EndpointClusterer()
		for _, ep := range discResult.Endpoints {
			clusterer.AddEndpoint(ep.Path)
		}

		representatives := brain.GetRepresentativeEndpoints()
		originalCount := len(discResult.Endpoints)

		if len(representatives) > 0 && len(representatives) < originalCount {
			// Build lookup set for representative endpoints
			repSet := make(map[string]bool, len(representatives))
			for _, r := range representatives {
				repSet[r] = true
			}

			// Filter to representative endpoints only — the clusterer groups
			// similar paths (e.g., /api/v1/users/1, /api/v1/users/42) and picks
			// one representative per cluster. Testing the representative is
			// sufficient because the WAF rule applies uniformly to the cluster.
			var deduped []discovery.Endpoint
			for _, ep := range discResult.Endpoints {
				if repSet[ep.Path] {
					deduped = append(deduped, ep)
				}
			}

			if len(deduped) > 0 {
				discResult.Endpoints = deduped
				ui.PrintSuccess(fmt.Sprintf("🧠 Clustering: %d endpoints → %d representatives (%.0f%% reduction)",
					originalCount, len(deduped), (1-float64(len(deduped))/float64(originalCount))*100))
			}
		}

		// Also optimize test order: high-value targets first
		paths := make([]string, len(discResult.Endpoints))
		for i, ep := range discResult.Endpoints {
			paths[i] = ep.Path
		}
		prioritized := brain.GetSmartEndpoints(paths)
		if len(prioritized) > 0 {
			// Reorder endpoints by brain priority
			pathIdx := make(map[string]int, len(discResult.Endpoints))
			for i, ep := range discResult.Endpoints {
				pathIdx[ep.Path] = i
			}
			reordered := make([]discovery.Endpoint, 0, len(discResult.Endpoints))
			for _, pep := range prioritized {
				if idx, ok := pathIdx[pep.Path]; ok {
					reordered = append(reordered, discResult.Endpoints[idx])
				}
			}
			// Append any that didn't appear in prioritized list
			reorderedSet := make(map[string]bool, len(reordered))
			for _, r := range reordered {
				reorderedSet[r.Path] = true
			}
			for _, ep := range discResult.Endpoints {
				if !reorderedSet[ep.Path] {
					reordered = append(reordered, ep)
				}
			}
			discResult.Endpoints = reordered
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 3: INTELLIGENT LEARNING
	// ═══════════════════════════════════════════════════════════════════════════
	var testPlan *learning.TestPlan

	if shouldSkipPhase("learning") {
		ui.PrintInfo("⏭️  Skipping learning phase (already completed)")
		if data, err := os.ReadFile(testPlanFile); err == nil {
			var loaded learning.TestPlan
			if err := json.Unmarshal(data, &loaded); err == nil {
				testPlan = &loaded
			}
		}
	}

	if testPlan == nil {
		printStatusLn(ui.SectionStyle.Render("PHASE 3: Intelligent Test Plan Generation"))
		printStatusLn()

		ui.PrintInfo("🧠 Analyzing attack surface and generating test plan...")

		learner := learning.NewLearner(discResult, payloadDir)
		testPlan = learner.GenerateTestPlan()

		// Save test plan
		planData, marshalErr := json.MarshalIndent(testPlan, "", "  ")
		if marshalErr != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to marshal test plan: %v", marshalErr))
		} else if err := os.WriteFile(testPlanFile, planData, 0644); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to write test plan: %v", err))
		}

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
		markPhaseCompleted("learning")
	} // end learning skip guard

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 4: WAF SECURITY TESTING
	// ═══════════════════════════════════════════════════════════════════════════
	wafResultsFile := filepath.Join(workspaceDir, "results-summary.json")
	var results output.ExecutionResults

	// ── Shared state for waf-testing, brain-feedback, and mutation-pass ──
	// Hoisted above the skip guard so sub-passes can run independently on resume.
	var allPayloads []payloads.Payload
	var filterCfg core.FilterConfig
	currentRateLimit := *cfg.RateLimit
	currentConcurrency := *cfg.Concurrency
	rateMu := &sync.Mutex{}
	var adaptiveLimiter *ratelimit.Limiter
	var executorRef *core.Executor
	escalationCount := 0
	var lastEscalationTime time.Time
	autoEscalate := func(reason string) {
		rateMu.Lock()
		defer rateMu.Unlock()

		escalationCount++
		if escalationCount > 3 {
			return
		}

		// Cooldown: ignore rapid-fire escalations. Without this, anomaly
		// callbacks fire in burst (all observing the same batch of results)
		// and cascade rate/concurrency down to minimums in one second.
		// 30-second cooldown prevents cascading through all escalation
		// levels from a single burst of anomalies.
		if !lastEscalationTime.IsZero() && time.Since(lastEscalationTime) < 30*time.Second {
			escalationCount-- // don't count suppressed escalation
			return
		}
		lastEscalationTime = time.Now()

		oldRate := currentRateLimit
		oldConc := currentConcurrency

		// Reduce by 25% instead of 50% — gentler ramp-down preserves
		// more scan throughput while still respecting WAF rate limits.
		currentRateLimit = currentRateLimit * 3 / 4
		if currentRateLimit < 10 {
			currentRateLimit = 10
		}
		currentConcurrency = currentConcurrency * 3 / 4
		if currentConcurrency < 5 {
			currentConcurrency = 5
		}

		ui.PrintWarning(fmt.Sprintf("⚡ Auto-escalation triggered (%s): rate %d→%d, concurrency %d→%d (next pass)",
			reason, oldRate, currentRateLimit, oldConc, currentConcurrency))

		// NOTE: adaptiveLimiter.OnError() is NOT called here — handleAdaptiveRate
		// already calls limiter.OnError() on 429s. Calling it again would double
		// the backoff. Non-429 escalations (anomaly detection) call OnError()
		// at their own call site when limiter backoff is needed.
		if executorRef != nil {
			executorRef.SetRateLimit(currentRateLimit)
		}
		if autoDispCtx != nil {
			escalateDesc := fmt.Sprintf("Auto-escalation: %s - rate reduced to %d, concurrency to %d",
				reason, currentRateLimit, currentConcurrency)
			_ = autoDispCtx.EmitBypass(ctx, "auto-escalation", "warning", target, escalateDesc, 0)
		}
	}
	payloadsCheckpoint := filepath.Join(workspaceDir, "payloads-prepared.json")

	// Declare tamperEngine at outer scope so mutation-pass can reuse it on resume.
	var tamperEngine *tampers.Engine

	if shouldSkipPhase("waf-testing") {
		ui.PrintInfo("⏭️  Skipping WAF testing (already completed)")
		if data, err := os.ReadFile(wafResultsFile); err == nil {
			if uerr := json.Unmarshal(data, &results); uerr != nil {
				ui.PrintWarning(fmt.Sprintf("Corrupt results-summary.json, continuing with empty results: %v", uerr))
			}
		} else {
			ui.PrintWarning(fmt.Sprintf("Missing results-summary.json, continuing with empty results: %v", err))
		}

		// Reload prepared payloads for brain-feedback and mutation-pass sub-passes.
		if data, err := os.ReadFile(payloadsCheckpoint); err == nil {
			if uerr := json.Unmarshal(data, &allPayloads); uerr != nil {
				ui.PrintWarning(fmt.Sprintf("Corrupt payloads checkpoint: %v", uerr))
			}
		} else {
			ui.PrintWarning("Payloads checkpoint not found — brain-feedback and mutation-pass will have no payloads")
		}

		// Re-run calibration so sub-pass executors have a valid filter config.
		cal := calibration.NewCalibratorWithClient(target, time.Duration(cfg.Common.Timeout)*time.Second, cfg.Common.SkipVerify, ja3Client)
		if calResult, calErr := cal.Calibrate(ctx); calErr == nil && calResult != nil && calResult.Calibrated {
			filterCfg.FilterStatus = calResult.Suggestions.FilterStatus
			filterCfg.FilterSize = calResult.Suggestions.FilterSize
		} else if calErr != nil {
			ui.PrintWarning(fmt.Sprintf("Resume calibration failed: %v — sub-passes will run without filtering", calErr))
		}

		// Re-init adaptive limiter for sub-passes.
		if *cfg.AdaptiveRate {
			adaptiveLimiter = ratelimit.New(&ratelimit.Config{
				RequestsPerSecond: *cfg.RateLimit,
				AdaptiveSlowdown:  true,
				SlowdownFactor:    1.5,
				SlowdownMaxDelay:  5 * time.Second,
				RecoveryRate:      0.9,
				Burst:             *cfg.Concurrency,
			})
		}
	} else {
		printStatusLn(ui.SectionStyle.Render("PHASE 4: WAF Security Testing"))
		printStatusLn()

		// Clear host error state accumulated during discovery/learning phases.
		// Without this, transient errors in param discovery poison the
		// hosterrors cache and prevent all WAF testing payloads from running.
		// ClearHostErrors clears both detection state AND hosterrors in one call.
		if det := detection.Default(); det != nil {
			det.ClearHostErrors(target)
		} else {
			hosterrors.Clear(target)
		}

		ui.PrintInfo("⚡ Executing security tests with auto-calibration...")
		printStatusLn()

		// Resolve nuclei template directory: if the default path doesn't exist
		// on disk, extract embedded templates to a temp directory.
		templateDir := defaults.TemplateDir
		if resolved, resolveErr := templateresolver.ResolveNucleiDir(templateDir); resolveErr == nil {
			templateDir = resolved
		}

		// Load payloads from unified engine (JSON + Nuclei templates)
		var err error
		allPayloads, _, err = loadUnifiedPayloads(payloadDir, templateDir, cfg.Common.Verbose)
		if err != nil {
			errMsg := fmt.Sprintf("Error loading payloads: %v", err)
			ui.PrintError(errMsg)
			if autoDispCtx != nil {
				_ = autoDispCtx.EmitError(ctx, "auto", errMsg, true)
				_ = autoDispCtx.Close()
			}
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

			// B4: Guard against empty payload set after filtering
			if len(allPayloads) == 0 {
				ui.PrintWarning("No payloads match test plan categories, using full payload set")
				var reloadErr error
				allPayloads, _, reloadErr = loadUnifiedPayloads(payloadDir, templateDir, cfg.Common.Verbose)
				if reloadErr != nil {
					ui.PrintError(fmt.Sprintf("Failed to reload payloads: %v", reloadErr))
					if autoDispCtx != nil {
						_ = autoDispCtx.Close()
					}
					os.Exit(1)
				}
			}
		}

		// G1: Inject discovered params into payload target paths
		// Generates payloads for query params (GET) and body params (POST)
		if paramResult != nil && paramResult.FoundParams > 0 {
			const maxParamPayloads = 200
			var paramPayloads []payloads.Payload
			for _, p := range paramResult.Parameters {
				if len(paramPayloads) >= maxParamPayloads {
					break // Cap total additional payloads across all params
				}

				switch p.Type {
				case "query":
					// Append as query string parameter
					for _, existing := range allPayloads {
						if len(paramPayloads) >= maxParamPayloads {
							break
						}
						clone := existing
						separator := "?"
						if strings.Contains(clone.TargetPath, "?") {
							separator = "&"
						}
						clone.TargetPath = clone.TargetPath + separator + url.QueryEscape(p.Name) + "=" + url.QueryEscape(clone.Payload)
						paramPayloads = append(paramPayloads, clone)
					}

				case "body":
					// Generate POST payloads with the param in form-encoded body
					for _, existing := range allPayloads {
						if len(paramPayloads) >= maxParamPayloads {
							break
						}
						clone := existing
						clone.Method = "POST"
						clone.ContentType = defaults.ContentTypeForm
						clone.Payload = url.QueryEscape(p.Name) + "=" + url.QueryEscape(existing.Payload)
						paramPayloads = append(paramPayloads, clone)
					}

				default:
					// header/cookie params: skip for now (no clean executor support)
					continue
				}
			}
			if len(paramPayloads) > 0 {
				allPayloads = append(allPayloads, paramPayloads...)
				ui.PrintInfo(fmt.Sprintf("🔍 Added %d payloads targeting %d discovered parameters", len(paramPayloads), paramResult.FoundParams))
			}
		}

		// E6: Merge test plan custom payloads into the payload set
		// The learner generates endpoint-specific payloads based on discovered injection points
		for _, set := range testPlan.EndpointTests {
			if len(set.CustomPayloads) > 0 {
				allPayloads = append(allPayloads, set.CustomPayloads...)
			}
		}

		// ── STRATEGY-BASED CATEGORY ORDERING ────────────────────────────────
		// When smart mode detected a WAF, use the strategy's PrioritizePayloads
		// to order payload categories by generic bypass likelihood (e.g., sqli
		// before xss). This provides a good initial ordering even on the first
		// scan when the brain predictor has no training data.
		if smartResult != nil && smartResult.Strategy != nil && len(allPayloads) > 1 {
			// Collect unique categories
			catSet := make(map[string]bool)
			for _, p := range allPayloads {
				catSet[strings.ToLower(p.Category)] = true
			}
			cats := make([]string, 0, len(catSet))
			for c := range catSet {
				cats = append(cats, c)
			}
			prioritized := smartResult.Strategy.PrioritizePayloads(cats)

			// Build category→priority index
			catPriority := make(map[string]int, len(prioritized))
			for i, c := range prioritized {
				catPriority[c] = i
			}

			sort.SliceStable(allPayloads, func(i, j int) bool {
				pi := catPriority[strings.ToLower(allPayloads[i].Category)]
				pj := catPriority[strings.ToLower(allPayloads[j].Category)]
				return pi < pj
			})
		}

		// ── STRATEGY-BASED ENCODING BOOST ───────────────────────────────────
		// Boost payloads whose EncodingUsed matches a recommended encoder.
		// Prefer Pipeline (mode-filtered) over raw Strategy encoders so that
		// quick/stealth modes test fewer encodings while full/bypass test all.
		var boostEncoders []string
		if smartResult != nil && smartResult.Pipeline != nil && len(smartResult.Pipeline.Encoders) > 0 {
			boostEncoders = smartResult.Pipeline.Encoders
		} else if smartResult != nil && smartResult.Strategy != nil && len(smartResult.Strategy.Encoders) > 0 {
			boostEncoders = smartResult.Strategy.Encoders
		}
		if len(boostEncoders) > 0 && len(allPayloads) > 1 {
			recEnc := make(map[string]bool, len(boostEncoders))
			for _, e := range boostEncoders {
				recEnc[strings.ToLower(e)] = true
			}
			sort.SliceStable(allPayloads, func(i, j int) bool {
				iRec := recEnc[strings.ToLower(allPayloads[i].EncodingUsed)]
				jRec := recEnc[strings.ToLower(allPayloads[j].EncodingUsed)]
				return iRec && !jRec
			})
		}

		// ── PREDICTIVE PAYLOAD RANKING ──────────────────────────────────────
		// Use the brain's Predictor to reorder payloads by predicted bypass
		// probability. Payloads most likely to bypass the WAF execute first,
		// giving faster time-to-first-bypass and better brain learning.
		if brain != nil && len(allPayloads) > 10 {
			candidates := payloadsToCandidates(allPayloads)

			ranked := brain.GetTopPayloads(candidates, len(candidates))
			if len(ranked) > 0 {
				// Rebuild payload slice in ranked order
				payloadByKey := make(map[string]int, len(allPayloads))
				for i, p := range allPayloads {
					key := p.Category + "|" + p.Payload + "|" + p.TargetPath + "|" + p.EncodingUsed
					payloadByKey[key] = i
				}

				reordered := make([]payloads.Payload, 0, len(allPayloads))
				used := make(map[int]bool, len(allPayloads))
				for _, rp := range ranked {
					key := rp.Candidate.Category + "|" + rp.Candidate.Payload + "|" + rp.Candidate.Path + "|" + rp.Candidate.Encoding
					if idx, ok := payloadByKey[key]; ok && !used[idx] {
						reordered = append(reordered, allPayloads[idx])
						used[idx] = true
					}
				}
				// Append any unranked payloads at the end
				for i, p := range allPayloads {
					if !used[i] {
						reordered = append(reordered, p)
					}
				}
				allPayloads = reordered

				topScore := ranked[0].Score
				ui.PrintInfo(fmt.Sprintf("🧠 Predictor: reordered %d payloads by bypass probability (top score: %.2f)",
					len(allPayloads), topScore))
			}
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
				// Skip payloads that already have a TargetPath (e.g., G1 param-injected paths)
				if allPayloads[i].TargetPath != "" {
					continue
				}
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

		// Filter out payloads with encodings known to be ineffective against the detected WAF.
		// For example, Cloudflare natively decodes base64, so base64_simple encodings are always caught.
		if smartResult != nil && smartResult.Strategy != nil && len(smartResult.Strategy.SkipIneffectiveMutators) > 0 {
			filtered := make([]payloads.Payload, 0, len(allPayloads))
			skippedCount := 0
			for _, p := range allPayloads {
				if smartResult.Strategy.ShouldSkipPayload(p.EncodingUsed) {
					skippedCount++
					continue
				}
				filtered = append(filtered, p)
			}
			if skippedCount > 0 {
				allPayloads = filtered
				ui.PrintInfo(fmt.Sprintf("Skipped %d payloads with ineffective encodings for %s", skippedCount, smartResult.VendorName))
			}
		}

		printStatusLn()

		// ═══════════════════════════════════════════════════════════════════════════
		// TAMPER ENGINE INITIALIZATION
		// ═══════════════════════════════════════════════════════════════════════════
		if *cfg.Tamper.List != "" || *cfg.Tamper.Auto || (*cfg.Smart.Enabled && smartResult != nil && smartResult.WAFDetected) {
			// Determine tamper profile
			profile := tampers.ProfileStandard
			switch *cfg.Tamper.Profile {
			case "stealth":
				profile = tampers.ProfileStealth
			case "aggressive":
				profile = tampers.ProfileAggressive
			case "bypass":
				profile = tampers.ProfileBypass
			}

			// If custom tamper list provided, use custom profile
			if *cfg.Tamper.List != "" {
				profile = tampers.ProfileCustom
			}

			// Get WAF vendor for intelligent selection
			wafVendor := "unknown"
			if smartResult != nil && smartResult.WAFDetected && smartResult.VendorName != "" {
				wafVendor = smartResult.VendorName
			}

			// Create tamper engine
			// Load script tampers from directory if specified
			if *cfg.Tamper.Dir != "" {
				scripts, errs := tampers.LoadScriptDir(*cfg.Tamper.Dir)
				for _, e := range errs {
					ui.PrintWarning(fmt.Sprintf("Script tamper: %v", e))
				}
				for _, st := range scripts {
					tampers.Register(st)
				}
				if len(scripts) > 0 {
					ui.PrintInfo(fmt.Sprintf("Loaded %d script tampers from %s", len(scripts), *cfg.Tamper.Dir))
				}
			}

			// Collect strategy-recommended evasions AND prioritized mutation techniques
			// as hints for tamper selection. Prefer Pipeline.Evasions (mode-filtered)
			// over raw Strategy.Evasions so quick/stealth modes use fewer evasions.
			var strategyHints []string
			if smartResult != nil && smartResult.Pipeline != nil && len(smartResult.Pipeline.Evasions) > 0 {
				strategyHints = smartResult.Pipeline.Evasions
			} else if smartResult != nil && smartResult.Strategy != nil {
				strategyHints = smartResult.Strategy.Evasions
			}
			// Merge PrioritizeMutators — technique names that the tamper engine's
			// mergeStrategyHints() can match against its registry.
			if smartResult != nil && smartResult.Strategy != nil && len(smartResult.Strategy.PrioritizeMutators) > 0 {
				seen := make(map[string]bool, len(strategyHints))
				for _, h := range strategyHints {
					seen[strings.ToLower(h)] = true
				}
				for _, m := range smartResult.Strategy.PrioritizeMutators {
					if !seen[strings.ToLower(m)] {
						strategyHints = append(strategyHints, m)
					}
				}
			}

			tamperEngine = tampers.NewEngine(&tampers.EngineConfig{
				Profile:       profile,
				CustomTampers: tampers.ParseTamperList(*cfg.Tamper.List),
				WAFVendor:     wafVendor,
				StrategyHints: strategyHints,
				EnableMetrics: true,
			})

			// Validate custom tampers if specified
			if *cfg.Tamper.List != "" {
				valid, invalid := tampers.ValidateTamperNames(tampers.ParseTamperList(*cfg.Tamper.List))
				if len(invalid) > 0 {
					ui.PrintWarning(fmt.Sprintf("Unknown tampers: %s", strings.Join(invalid, ", ")))
				}
				if len(valid) > 0 {
					ui.PrintInfo(fmt.Sprintf("🔧 Using %d custom tampers: %s", len(valid), strings.Join(valid, ", ")))
				}
			} else if *cfg.Tamper.Auto || (*cfg.Smart.Enabled && smartResult != nil && smartResult.WAFDetected) {
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

		// Save prepared payloads so brain-feedback/mutation-pass can resume independently.
		if cpData, cpErr := json.Marshal(allPayloads); cpErr == nil {
			if writeErr := os.WriteFile(payloadsCheckpoint, cpData, 0644); writeErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to save payloads checkpoint: %v", writeErr))
			}
		}

		// Auto-calibration
		ui.PrintInfo("Running auto-calibration...")
		cal := calibration.NewCalibratorWithClient(target, time.Duration(cfg.Common.Timeout)*time.Second, cfg.Common.SkipVerify, ja3Client)
		calResult, calErr := cal.Calibrate(ctx)
		if calErr == nil && calResult != nil && calResult.Calibrated {
			filterCfg.FilterStatus = calResult.Suggestions.FilterStatus
			filterCfg.FilterSize = calResult.Suggestions.FilterSize
			ui.PrintSuccess(fmt.Sprintf("Calibrated: %s", calResult.Describe()))
		} else if calErr != nil {
			ui.PrintWarning(fmt.Sprintf("Calibration warning: %v", calErr))
		}
		printStatusLn()

		// Initialize adaptive rate limiter for the fresh run
		if *cfg.AdaptiveRate {
			adaptiveLimiter = ratelimit.New(&ratelimit.Config{
				RequestsPerSecond: *cfg.RateLimit,
				AdaptiveSlowdown:  true,
				SlowdownFactor:    1.5,
				SlowdownMaxDelay:  5 * time.Second,
				RecoveryRate:      0.9,
				Burst:             *cfg.Concurrency,
			})
			ui.PrintInfo("📊 Adaptive rate limiting enabled (auto-adjusts on WAF response)")
		}

		// NOTE: detection.Default() callbacks are not registered here because
		// core.NewExecutor creates its own detection.New() per executor instance.
		// Registering on Default() would never fire. Drop/ban escalation is
		// handled by the ShouldPauseScan anomaly check in the OnResult callback.

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
			Verbose:       cfg.Common.Verbose,
			ShowTimestamp: true,
			Silent:        false,
			Target:        target,
		})
		if err != nil {
			errMsg := fmt.Sprintf("Error creating output writer: %v", err)
			ui.PrintError(errMsg)
			if autoDispCtx != nil {
				_ = autoDispCtx.EmitError(ctx, "auto", errMsg, true)
				_ = autoDispCtx.Close()
			}
			os.Exit(1) // intentional: CLI early exit on fatal error
		}

		// Print section header
		ui.PrintSection("Executing Tests")
		if !quietMode {
			rateMu.Lock()
			rl := currentRateLimit
			cc := currentConcurrency
			rateMu.Unlock()
			fmt.Fprintf(os.Stderr, "\n  %s Running with %s parallel workers @ %s req/sec max\n\n",
				ui.SpinnerStyle.Render(">>>"),
				ui.StatValueStyle.Render(fmt.Sprintf("%d", cc)),
				ui.StatValueStyle.Render(fmt.Sprintf("%d", rl)),
			)
		}

		// Start waf-testing phase for Brain
		if brain != nil {
			brain.StartPhase(ctx, "waf-testing")
		}

		var anomalyCheckCounter int32 // Rate-limit ShouldPauseScan checks

		// Create and run executor (using current adaptive values)
		executor := core.NewExecutor(core.ExecutorConfig{
			TargetURL:     target,
			Concurrency:   currentConcurrency,
			RateLimit:     currentRateLimit,
			Timeout:       time.Duration(cfg.Common.Timeout) * time.Second,
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
					_ = autoDispCtx.EmitDetailedResult(ctx, result)
				}
				// Emit bypass event only for actual WAF bypasses ("Fail" = expected block but got 2xx)
				if autoDispCtx != nil && result.Outcome == "Fail" {
					_ = autoDispCtx.EmitBypass(ctx, result.Category, result.Severity, target, result.Payload, result.StatusCode)
				}

				// Update live bypass counter in real-time
				if result.Outcome == "Fail" {
					autoProgress.AddMetric("bypasses")
				}

				// Feed test result to Brain for real-time learning
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

					// Anomaly-aware execution: check every 50 results to avoid
					// lock contention from ShouldPauseScan in the hot path.
					if atomic.AddInt32(&anomalyCheckCounter, 1)%50 == 0 {
						if shouldPause, reason := brain.ShouldPauseScan(); shouldPause {
							// Only call OnError if handleAdaptiveRate didn't already
							// (429 responses are already handled above).
							if adaptiveLimiter != nil && result.StatusCode != 429 {
								adaptiveLimiter.OnError()
							}
							autoEscalate(fmt.Sprintf("anomaly: %s", reason))
						}
					}
				}
			},
		})
		rateMu.Lock()
		executorRef = executor
		rateMu.Unlock()
		defer executor.Close()

		progress.Start()
		results = executor.ExecuteWithProgress(ctx, allPayloads, writer, progress)
		progress.Stop()

		writer.Close()

		// Clear executorRef so autoEscalate (called from brain.OnAnomaly)
		// doesn't SetRateLimit on a completed executor between passes.
		rateMu.Lock()
		executorRef = nil
		rateMu.Unlock()

		// Update progress after WAF testing (bypass counter already updated in real-time via OnResult)
		autoProgress.SetStatus("Analysis")
		autoProgress.Increment()

		// Mark WAF testing phase complete for resume
		markPhaseCompleted("waf-testing")

		// Flush results immediately so crash before brain-feedback doesn't
		// lose all waf-testing data. On resume, the skip path reads this file.
		if summaryData, err := json.MarshalIndent(results, "", "  "); err == nil {
			if writeErr := os.WriteFile(wafResultsFile, summaryData, 0644); writeErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to save waf results: %v", writeErr))
			}
		}

		// End WAF testing phase for Brain (only when waf-testing ran fresh)
		if brain != nil {
			brain.EndPhase("waf-testing")
		}
		saveBrainState()
	} // end waf-testing skip guard

	// E5: Wire brain anomaly detection to auto-escalation.
	// Registered outside the skip guard so sub-passes get anomaly callbacks on resume.
	if brain != nil {
		brain.OnAnomaly(func(anomaly *intelligence.Anomaly) {
			autoEscalate(fmt.Sprintf("brain anomaly: %s (confidence %.0f%%)", anomaly.Type, anomaly.Confidence*100))
		})
	}

	// E2: Brain feedback loop — predictor-guided second pass
	// Instead of blindly re-running all payloads from "focus categories",
	// use the Predictor to rank focus payloads by bypass probability
	// and only run the top candidates. This makes the feedback pass
	// both faster and more effective.
	if brain != nil && !shouldSkipPhase("brain-feedback") && ctx.Err() == nil {
		recs := brain.RecommendPayloads()
		if len(recs) > 0 {
			// Collect high-priority categories with bypasses
			focusCategories := make(map[string]bool)
			for _, r := range recs {
				if r.Priority <= 2 && r.Confidence >= 0.7 {
					focusCategories[strings.ToLower(r.Category)] = true
				}
			}

			if len(focusCategories) > 0 {
				var focusPayloads []payloads.Payload
				for _, p := range allPayloads {
					if focusCategories[strings.ToLower(p.Category)] {
						focusPayloads = append(focusPayloads, p)
					}
				}

				// Exclude payloads that already bypassed in the main pass —
				// retesting them inflates FailedTests and duplicates BypassDetails.
				if len(results.BypassDetails) > 0 {
					bypassSet := make(map[string]bool, len(results.BypassDetails))
					for _, bd := range results.BypassDetails {
						bypassSet[strings.ToLower(bd.Category)+"|"+bd.Payload] = true
					}
					filtered := focusPayloads[:0]
					for _, p := range focusPayloads {
						if !bypassSet[strings.ToLower(p.Category)+"|"+p.Payload] {
							filtered = append(filtered, p)
						}
					}
					focusPayloads = filtered
				}

				// Use predictor to rank focus payloads — run only top N
				if len(focusPayloads) > 20 {
					candidates := payloadsToCandidates(focusPayloads)
					topN := len(focusPayloads) / 2 // Take top half by predicted bypass probability
					if topN < 20 {
						topN = 20
					}
					ranked := brain.GetTopPayloads(candidates, topN)
					if len(ranked) > 0 {
						// Rebuild from ranked order
						payIdx := make(map[string]int, len(focusPayloads))
						for i, p := range focusPayloads {
							payIdx[p.Category+"|"+p.Payload+"|"+p.TargetPath+"|"+p.EncodingUsed] = i
						}
						var topPayloads []payloads.Payload
						for _, rp := range ranked {
							key := rp.Candidate.Category + "|" + rp.Candidate.Payload + "|" + rp.Candidate.Path + "|" + rp.Candidate.Encoding
							if idx, ok := payIdx[key]; ok {
								topPayloads = append(topPayloads, focusPayloads[idx])
							}
						}
						if len(topPayloads) > 0 {
							focusPayloads = topPayloads
						}
					}
				}
				if len(focusPayloads) == 0 && len(focusCategories) > 0 {
					ui.PrintWarning("Brain feedback: no payloads available for focus categories (missing checkpoint?)")
				}

				if len(focusPayloads) > 0 && len(focusPayloads) < len(allPayloads) {
					catList := make([]string, 0, len(focusCategories))
					for c := range focusCategories {
						catList = append(catList, c)
					}
					sort.Strings(catList)
					ui.PrintInfo(fmt.Sprintf("🧠 Brain feedback: focused re-test on %d payloads across [%s]",
						len(focusPayloads), strings.Join(catList, ", ")))

					brain.StartPhase(ctx, "brain-feedback")
					feedbackResultsFile := filepath.Join(workspaceDir, "results-feedback.json")
					focusWriter, focusErr := output.NewWriterWithOptions(feedbackResultsFile, "json", output.WriterOptions{
						Verbose:       cfg.Common.Verbose,
						ShowTimestamp: true,
						Target:        target,
					})
					if focusErr != nil {
						ui.PrintWarning(fmt.Sprintf("Brain feedback pass skipped: writer error: %v", focusErr))
						brain.EndPhase("brain-feedback")
					} else {
						focusExec := core.NewExecutor(core.ExecutorConfig{
							TargetURL:     target,
							Concurrency:   currentConcurrency,
							RateLimit:     currentRateLimit,
							Timeout:       time.Duration(cfg.Common.Timeout) * time.Second,
							Retries:       defaults.RetryLow,
							Filter:        &filterCfg,
							RealisticMode: true,
							HTTPClient:    ja3Client,
							// ShouldPauseScan omitted: feedback pass is short (predictor-filtered)
							OnResult: func(result *output.TestResult) {
								handleAdaptiveRate(result.StatusCode, result.Outcome, adaptiveLimiter, autoEscalate)

								// Feed feedback results to brain for continued learning
								if brain != nil {
									brain.LearnFromFinding(&intelligence.Finding{
										Phase:      "brain-feedback",
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
								// Emit feedback results to hooks
								if autoDispCtx != nil {
									_ = autoDispCtx.EmitDetailedResult(ctx, result)
								}
								if autoDispCtx != nil && result.Outcome == "Fail" {
									_ = autoDispCtx.EmitBypass(ctx, result.Category, result.Severity, target, result.Payload, result.StatusCode)
								}
								// Update live bypass counter in real-time
								if result.Outcome == "Fail" {
									autoProgress.AddMetric("bypasses")
								}
							},
						})
						focusProgress := ui.NewProgress(ui.ProgressConfig{
							Total: len(focusPayloads),
						})
						rateMu.Lock()
						executorRef = focusExec
						rateMu.Unlock()
						focusResults := focusExec.ExecuteWithProgress(ctx, focusPayloads, focusWriter, focusProgress)
						focusWriter.Close()
						focusExec.Close()
						rateMu.Lock()
						executorRef = nil
						rateMu.Unlock()

						mergeExecutionResults(&results, focusResults)
						ui.PrintSuccess(fmt.Sprintf("  ✓ Feedback pass: %d additional bypasses found", focusResults.FailedTests))
						brain.EndPhase("brain-feedback")
					}
				}
			}
		}
		markPhaseCompleted("brain-feedback")
		saveBrainState()

		// Save results after brain-feedback merge so crash before mutation-pass
		// doesn't lose feedback bypass discoveries.
		if len(results.Latencies) > 0 {
			recalculateLatencyStats(&results)
		}
		if summaryData, err := json.MarshalIndent(results, "", "  "); err == nil {
			if writeErr := os.WriteFile(wafResultsFile, summaryData, 0644); writeErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to save interim results: %v", writeErr))
			}
		}
	}

	// ── MUTATION PASS ──────────────────────────────────────────────────
	// When payloads are blocked, the MutationStrategist can suggest
	// transformed variants (case variation, comment injection, encoding
	// changes, WAF-specific evasions) that may bypass. This second-pass
	// creates new payloads from blocked ones and runs them.
	if brain != nil && !shouldSkipPhase("mutation-pass") && results.BlockedTests > 0 && ctx.Err() == nil {
		// Collect unique blocked category+payload pairs for mutation.
		// A payload is "blocked" if it was tested but did NOT bypass — we
		// build a set of known bypasses from results.BypassDetails and
		// exclude them.
		type blockedEntry struct {
			category string
			payload  string
			path     string
			method   string
			severity string
		}

		bypassSet := make(map[string]bool, len(results.BypassDetails))
		for _, bd := range results.BypassDetails {
			bypassSet[strings.ToLower(bd.Category)+"|"+bd.Payload] = true
		}

		// NOTE: payloads that errored (timeout, conn refused) are not tracked
		// per-payload — only BypassDetails gives per-payload outcomes. Errored
		// payloads will be included in the mutation input, which is acceptable:
		// mutations may succeed where the original timed out.

		seen := make(map[string]bool)
		var blocked []blockedEntry
		const maxMutationInputs = 50

		for _, p := range allPayloads {
			if len(blocked) >= maxMutationInputs {
				break
			}
			key := strings.ToLower(p.Category) + "|" + p.Payload
			if seen[key] || bypassSet[key] {
				continue // Skip duplicates and payloads that already bypassed
			}
			seen[key] = true
			blocked = append(blocked, blockedEntry{
				category: p.Category,
				payload:  p.Payload,
				path:     p.TargetPath,
				method:   p.Method,
				severity: p.SeverityHint,
			})
		}

		if len(blocked) == 0 && results.BlockedTests > 0 && len(allPayloads) == 0 {
			ui.PrintWarning("Mutation pass: no payload data available for mutation (missing checkpoint?)")
		}

		if len(blocked) > 0 {
			var mutatedPayloads []payloads.Payload
			// Use WAF-tuned mutation depth: prefer Pipeline.MaxChainDepth
			// (mode-filtered), then Strategy.RecommendedMutationDepth, then 3.
			maxMutationsPerPayload := 3
			if smartResult != nil && smartResult.Pipeline != nil && smartResult.Pipeline.MaxChainDepth > 0 {
				maxMutationsPerPayload = smartResult.Pipeline.MaxChainDepth
			} else if smartResult != nil && smartResult.Strategy != nil && smartResult.Strategy.RecommendedMutationDepth > 0 {
				maxMutationsPerPayload = smartResult.Strategy.RecommendedMutationDepth
			}

			for _, b := range blocked {
				suggestions := brain.SuggestMutations(b.category, b.payload)
				for i, s := range suggestions {
					if i >= maxMutationsPerPayload {
						break
					}
					if s.Example == "" || s.Example == b.payload {
						continue // Skip no-op mutations
					}
					mutatedPayloads = append(mutatedPayloads, payloads.Payload{
						ID:              fmt.Sprintf("mutation-%s-%d", b.category, len(mutatedPayloads)),
						Payload:         s.Example,
						Category:        b.category,
						Method:          b.method,
						TargetPath:      b.path,
						ExpectedBlock:   true,
						SeverityHint:    b.severity,
						EncodingUsed:    s.Type,
						MutationType:    "brain-mutation",
						OriginalPayload: b.payload,
					})
				}
			}

			// Apply tamper transforms to mutation payloads so they benefit from
			// the same WAF-specific evasion transforms as the main payload set.
			if tamperEngine != nil && len(mutatedPayloads) > 0 {
				for i := range mutatedPayloads {
					mutatedPayloads[i].Payload = tamperEngine.Transform(mutatedPayloads[i].Payload)
				}
			}

			if len(mutatedPayloads) > 0 {
				brain.StartPhase(ctx, "mutation-pass")
				ui.PrintInfo(fmt.Sprintf("🧬 Mutation pass: %d mutated payloads from %d blocked originals",
					len(mutatedPayloads), len(blocked)))

				mutResultsFile := filepath.Join(workspaceDir, "results-mutations.json")
				mutWriter, mutErr := output.NewWriterWithOptions(mutResultsFile, "json", output.WriterOptions{
					Verbose:       cfg.Common.Verbose,
					ShowTimestamp: true,
					Target:        target,
				})
				if mutErr != nil {
					ui.PrintWarning(fmt.Sprintf("Mutation pass skipped: writer error: %v", mutErr))
					brain.EndPhase("mutation-pass")
				} else {
					mutExec := core.NewExecutor(core.ExecutorConfig{
						TargetURL:     target,
						Concurrency:   currentConcurrency,
						RateLimit:     currentRateLimit,
						Timeout:       time.Duration(cfg.Common.Timeout) * time.Second,
						Retries:       defaults.RetryLow,
						Filter:        &filterCfg,
						RealisticMode: true,
						HTTPClient:    ja3Client,
						// ShouldPauseScan omitted: mutation pass is short (max 150 payloads)
						OnResult: func(result *output.TestResult) {
							handleAdaptiveRate(result.StatusCode, result.Outcome, adaptiveLimiter, autoEscalate)
							if brain != nil {
								brain.LearnFromFinding(&intelligence.Finding{
									Phase:      "mutation-pass",
									Category:   result.Category,
									Severity:   result.Severity,
									Path:       result.TargetPath,
									Payload:    result.Payload,
									StatusCode: result.StatusCode,
									Latency:    time.Duration(result.LatencyMs) * time.Millisecond,
									Blocked:    result.Outcome == "Blocked",
									Confidence: 0.95,
									Metadata: map[string]interface{}{
										"outcome":       result.Outcome,
										"method":        result.Method,
										"mutation_pass": true,
									},
								})
							}
							if autoDispCtx != nil {
								_ = autoDispCtx.EmitDetailedResult(ctx, result)
							}
							if autoDispCtx != nil && result.Outcome == "Fail" {
								_ = autoDispCtx.EmitBypass(ctx, result.Category, result.Severity, target, result.Payload, result.StatusCode)
							}
							// Update live bypass counter in real-time
							if result.Outcome == "Fail" {
								autoProgress.AddMetric("bypasses")
							}
						},
					})
					rateMu.Lock()
					executorRef = mutExec
					rateMu.Unlock()
					mutProgress := ui.NewProgress(ui.ProgressConfig{
						Total: len(mutatedPayloads),
					})
					mutResults := mutExec.ExecuteWithProgress(ctx, mutatedPayloads, mutWriter, mutProgress)
					mutWriter.Close()
					mutExec.Close()
					rateMu.Lock()
					executorRef = nil
					rateMu.Unlock()

					mergeExecutionResults(&results, mutResults)
					ui.PrintSuccess(fmt.Sprintf("  ✓ Mutation pass: %d additional bypasses from %d mutations",
						mutResults.FailedTests, len(mutatedPayloads)))
					brain.EndPhase("mutation-pass")
				}
			}
		}
		markPhaseCompleted("mutation-pass")
		saveBrainState()
	}

	// Recalculate latency percentiles from merged raw latencies so that
	// summary JSON and console output reflect all passes, not just the main one.
	// Only recalculate when raw latencies are available — on resume without
	// sub-passes, Latencies is empty (json:"-") and recalculating would zero
	// out the loaded LatencyStats.
	if len(results.Latencies) > 0 {
		recalculateLatencyStats(&results)
	}

	// Save results summary AFTER feedback merge so resume loads complete data
	if summaryData, err := json.MarshalIndent(results, "", "  "); err == nil {
		if writeErr := os.WriteFile(wafResultsFile, summaryData, 0644); writeErr != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to save results summary: %v", writeErr))
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// VENDOR-SPECIFIC WAF ANALYSIS (runs after testing, before report)
	// ═══════════════════════════════════════════════════════════════════════════

	// Vendor detection with comprehensive signature database
	var vendorName string
	var vendorConfidence float64
	var bypassHints []string
	var recommendedEncoders []string
	var recommendedEvasions []string
	vendorDetectionFile := filepath.Join(workspaceDir, "vendor-detection.json")

	if shouldSkipPhase("vendor-detection") {
		ui.PrintInfo("⏭️  Skipping vendor-detection (already completed)")
		if data, err := os.ReadFile(vendorDetectionFile); err == nil {
			var cached struct {
				VendorName          string   `json:"vendor_name"`
				VendorConfidence    float64  `json:"vendor_confidence"`
				BypassHints         []string `json:"bypass_hints,omitempty"`
				RecommendedEncoders []string `json:"recommended_encoders,omitempty"`
				RecommendedEvasions []string `json:"recommended_evasions,omitempty"`
			}
			if err := json.Unmarshal(data, &cached); err == nil {
				vendorName = cached.VendorName
				vendorConfidence = cached.VendorConfidence
				bypassHints = cached.BypassHints
				recommendedEncoders = cached.RecommendedEncoders
				recommendedEvasions = cached.RecommendedEvasions
			}
		}
	} else {
		printStatusLn()
		printStatusLn(ui.SectionStyle.Render("Vendor-Specific WAF Analysis"))
		printStatusLn()

		ui.PrintInfo("🔍 Detecting WAF vendor with 150+ signatures...")

		// B5: Reuse Phase 0 smart mode results if available to avoid redundant detection
		if smartResult != nil && smartResult.WAFDetected {
			vendorName = smartResult.VendorName
			vendorConfidence = smartResult.Confidence
			bypassHints = smartResult.BypassHints
			if smartResult.Strategy != nil {
				recommendedEncoders = smartResult.Strategy.Encoders
				recommendedEvasions = smartResult.Strategy.Evasions
			}
			ui.PrintSuccess(fmt.Sprintf("  WAF Vendor: %s (%.0f%% confidence, from smart mode)", vendorName, vendorConfidence*100))
		} else {
			// Use the comprehensive vendor detector with 150+ signatures
			vendorDetector := vendors.NewVendorDetectorWithClient(time.Duration(cfg.Common.Timeout)*time.Second, ja3Client)
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
							fmt.Fprintf(os.Stderr, "    %s %s\n", ui.Icon("•", "-"), ev)
						}
					}

					// Show bypass recommendations
					if len(bypassHints) > 0 {
						fmt.Fprintln(os.Stderr)
						ui.PrintInfo("  📋 Bypass Recommendations:")
						for _, hint := range bypassHints[:min(5, len(bypassHints))] {
							fmt.Fprintf(os.Stderr, "    %s %s\n", ui.Icon("→", "->"), hint)
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
		}
		printStatusLn()

		// Save vendor detection results for resume
		vendorCache, marshalErr := json.MarshalIndent(struct {
			VendorName          string   `json:"vendor_name"`
			VendorConfidence    float64  `json:"vendor_confidence"`
			BypassHints         []string `json:"bypass_hints,omitempty"`
			RecommendedEncoders []string `json:"recommended_encoders,omitempty"`
			RecommendedEvasions []string `json:"recommended_evasions,omitempty"`
		}{vendorName, vendorConfidence, bypassHints, recommendedEncoders, recommendedEvasions}, "", "  ")
		if marshalErr != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to marshal vendor detection: %v", marshalErr))
		} else if err := os.WriteFile(vendorDetectionFile, vendorCache, 0644); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to save vendor detection: %v", err))
		}
		markPhaseCompleted("vendor-detection")
	} // end vendor-detection skip guard

	// ═══════════════════════════════════════════════════════════════════════════
	// BRAIN SUMMARY (v2.6.4)
	// Display attack chains, insights, and learned patterns
	// ═══════════════════════════════════════════════════════════════════════════
	// G3: Capture brain recommendations for summary enrichment
	var brainRecommendations []*intelligence.PayloadRecommendation

	// Capture brain recommendations for summary output (works in both JSON and console modes).
	if brain != nil {
		brainRecommendations = brain.RecommendPayloads()
	}

	if brain != nil && !quietMode {
		brainSummary := brain.GetSummary()

		if brainSummary.AttackChains > 0 || len(brainSummary.WAFWeaknesses) > 0 || len(brainSummary.TechStack) > 0 {
			printStatusLn()
			printStatusLn(ui.SectionStyle.Render(ui.SanitizeString("🧠 BRAIN SUMMARY")))
			printStatusLn()

			// Attack Chains - the crown jewel
			if brainSummary.AttackChains > 0 {
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render(ui.SanitizeString("⛓️  Attack Chains Built:")))
				for i, chain := range brainSummary.TopChains {
					if i >= 5 {
						fmt.Fprintf(os.Stderr, "    ... and %d more chains\n", brainSummary.AttackChains-5)
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
			if len(brainSummary.WAFWeaknesses) > 0 {
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render(ui.SanitizeString("📊 WAF Behavioral Analysis:")))
				if len(brainSummary.WAFStrengths) > 0 {
					fmt.Fprintf(os.Stderr, "    Strengths: %s\n", ui.PassStyle.Render(strings.Join(brainSummary.WAFStrengths[:min(3, len(brainSummary.WAFStrengths))], ", ")))
				}
				fmt.Fprintf(os.Stderr, "    Weaknesses: %s\n", ui.ErrorStyle.Render(strings.Join(brainSummary.WAFWeaknesses[:min(3, len(brainSummary.WAFWeaknesses))], ", ")))
				fmt.Fprintln(os.Stderr)
			}

			// Technology Detection
			if len(brainSummary.TechStack) > 0 {
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render(ui.SanitizeString("🔧 Technology Stack Detected:")))
				for _, tech := range brainSummary.TechStack[:min(5, len(brainSummary.TechStack))] {
					fmt.Fprintf(os.Stderr, "    %s %s\n", ui.Icon("•", "-"), tech)
				}
				fmt.Fprintln(os.Stderr)
			}

			// Payload Recommendations display
			if len(brainRecommendations) > 0 {
				fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render(ui.SanitizeString("🎯 Smart Payload Recommendations:")))
				for _, rec := range brainRecommendations[:min(5, len(brainRecommendations))] {
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
				brainSummary.TotalFindings, brainSummary.Bypasses, brainSummary.AttackChains, atomic.LoadInt32(&insightCount))

			// Print aggregated insight counts for repeated types
			if *cfg.BrainVerbose {
				insightMu.Lock()
				for title, count := range insightSeen {
					if count > 1 {
						fmt.Fprintf(os.Stderr, "    %s %s (×%d)\n", ui.Icon("↳", " "), title, count)
					}
				}
				insightMu.Unlock()
			}
			printStatusLn()
		}

		// Cognitive Module Summary — displayed independently of chains/weaknesses
		// since the brain modules collect data even against well-configured WAFs
		// that produce zero bypasses.
		cogSummary := brain.GetCognitiveSummary()
		if cogSummary != nil {
			fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render(ui.SanitizeString("🔬 Cognitive Module Performance:")))
			fmt.Fprintf(os.Stderr, "    Predictor:   %d observations across %d categories, %d encoding patterns\n",
				cogSummary.Predictor.TotalObservations, cogSummary.Predictor.CategoryPatterns, cogSummary.Predictor.EncodingPatterns)
			fmt.Fprintf(os.Stderr, "    Mutator:     %d learned mutations from %d block patterns\n",
				cogSummary.Mutator.LearnedMutations, cogSummary.Mutator.BlockPatterns)
			fmt.Fprintf(os.Stderr, "    Clusterer:   %d clusters from %d endpoints (%.0f%% testing reduction)\n",
				cogSummary.Clusterer.TotalClusters, cogSummary.Clusterer.TotalEndpoints, cogSummary.Clusterer.TestingReduction*100)
			fmt.Fprintf(os.Stderr, "    Anomalies:   %d detected — system health: %s\n",
				cogSummary.Anomaly.TotalAnomalies, cogSummary.Anomaly.OverallHealth)
			fmt.Fprintf(os.Stderr, "    Pathfinder:  %d nodes, %d edges, %d paths found\n",
				cogSummary.Pathfinder.TotalNodes, cogSummary.Pathfinder.TotalEdges, cogSummary.Pathfinder.TotalPaths)
			fmt.Fprintln(os.Stderr)
		}

		// Attack Path — show the optimal path through the target
		attackPath := brain.GetOptimalAttackPath()
		if attackPath != nil && len(attackPath.Nodes) > 0 {
			fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render(ui.SanitizeString("🛤️  Optimal Attack Path:")))
			for i, step := range attackPath.Steps {
				if i >= 5 {
					fmt.Fprintf(os.Stderr, "    ... and %d more steps\n", len(attackPath.Steps)-5)
					break
				}
				fmt.Fprintf(os.Stderr, "    %d. %s %s %s (%.0f%% success)\n",
					i+1, step.From, ui.Icon("→", "->"), step.To, step.SuccessProb*100)
			}
			fmt.Fprintf(os.Stderr, "    Total path value: %.2f | Success probability: %.0f%%\n",
				attackPath.TotalValue, attackPath.SuccessProb*100)
			fmt.Fprintln(os.Stderr)
		}

		// Priority Targets — endpoints the brain thinks are most valuable to attack next
		priorityTargets := brain.GetPriorityTargets()
		if len(priorityTargets) > 0 {
			fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render(ui.SanitizeString("🎯 Priority Targets (for follow-up):")))
			for i, pt := range priorityTargets {
				if i >= 5 {
					break
				}
				reachable := "reachable"
				if !pt.Reachable {
					reachable = "blocked"
				}
				fmt.Fprintf(os.Stderr, "    %d. %s (value: %.2f, paths: %d, %s)\n",
					i+1, pt.Path, pt.Value, pt.PathCount, reachable)
			}
			fmt.Fprintln(os.Stderr)
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 5: COMPREHENSIVE REPORT
	// ═══════════════════════════════════════════════════════════════════════════
	printStatusLn()
	printStatusLn(ui.SectionStyle.Render("PHASE 5: Comprehensive Report"))
	printStatusLn()

	// Calculate WAF effectiveness.
	// The denominator includes blocked + failed + skipped tests so that hosts
	// which were unreachable (silent-banned / connection-dropped) are not
	// silently excluded — otherwise a scan where 90% of tests were skipped
	// could report "100% effectiveness."
	wafEffectiveness := float64(0)
	skippedTests := results.TotalTests - results.BlockedTests - results.PassedTests - results.FailedTests - results.ErrorTests
	if skippedTests < 0 {
		skippedTests = 0
	}
	denominator := results.BlockedTests + results.FailedTests + skippedTests
	if denominator > 0 {
		wafEffectiveness = float64(results.BlockedTests) / float64(denominator) * 100
	}

	scanDuration := time.Since(startTime)

	// Print summary (only in non-JSON mode)
	if !quietMode {
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat(ui.Icon("═", "="), 60))
		fmt.Fprintln(os.Stderr, "                    SUPERPOWER SCAN COMPLETE")
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat(ui.Icon("═", "="), 60))
		fmt.Fprintln(os.Stderr)

		ui.PrintConfigLine("Target", target)
		ui.PrintConfigLine("Duration", scanDuration.Round(time.Second).String())
		ui.PrintConfigLine("Workspace", workspaceDir)
		fmt.Fprintln(os.Stderr)

		fmt.Fprintf(os.Stderr, "  +------------------------------------------------+\n")
		fmt.Fprintf(os.Stderr, "  |  Total Endpoints:    %-26d |\n", len(discResult.Endpoints))
		fmt.Fprintf(os.Stderr, "  |  JS Files Analyzed:  %-26d |\n", atomic.LoadInt32(&jsAnalyzed))
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
		if skippedTests > 0 {
			fmt.Fprintf(os.Stderr, "  |  Skipped (dropped):  %-26d |\n", skippedTests)
		}
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
	formats := strings.Split(*cfg.ReportFormats, ",")
	generatedReports := make([]string, 0, len(formats))

	for _, format := range formats {
		format = strings.TrimSpace(strings.ToLower(format))
		switch format {
		case "md", "markdown":
			// Generate markdown report
			generateAutoMarkdownReport(reportFile, target, domain, scanDuration, discResult, allJSData, testPlan, results, wafEffectiveness, leakyResult, paramResult, vendorName, vendorConfidence)
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
			"skipped":       skippedTests,
			"requests_sec":  results.RequestsPerSec,
			"endpoints":     len(discResult.Endpoints),
			"js_files":      atomic.LoadInt32(&jsAnalyzed),
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
	// Also fail CI when WAF effectiveness is critically low (the WAF is
	// functionally absent even if nothing was explicitly "bypassed" because
	// most tests were skipped) or when all tests errored out (complete scan
	// failure — denominator=0 but tests existed).
	if wafEffectiveness < 50 && denominator > 0 {
		summary["ci_exit_code"] = 1
	}
	if results.TotalTests > 0 && results.BlockedTests == 0 && results.FailedTests == 0 && results.PassedTests == 0 && denominator == 0 {
		summary["ci_exit_code"] = 1
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
		// Note: intSummary.Bypasses counts non-blocked brain observations
		// (including skipped tests where status_code=0). This differs from
		// results.FailedTests which counts actual WAF bypasses. Use
		// bypass_count (from results.FailedTests) as the authoritative count.
		summary["intelligence"] = map[string]interface{}{
			"enabled":         true,
			"total_findings":  intSummary.TotalFindings,
			"bypasses":        results.FailedTests, // authoritative: actual WAF bypasses
			"brain_unblocked": intSummary.Bypasses, // brain's count (includes skipped)
			"blocked":         intSummary.Blocked,
			"attack_chains":   chainData,
			"waf_strengths":   intSummary.WAFStrengths,
			"waf_weaknesses":  intSummary.WAFWeaknesses,
			"tech_stack":      intSummary.TechStack,
			"insights_count":  atomic.LoadInt32(&insightCount),
			"chains_count":    atomic.LoadInt32(&chainCount),
		}
	}

	// G3: Add brain recommendations to summary output
	if len(brainRecommendations) > 0 {
		recData := make([]map[string]interface{}, 0, len(brainRecommendations))
		for _, rec := range brainRecommendations {
			recData = append(recData, map[string]interface{}{
				"category":   rec.Category,
				"priority":   rec.Priority,
				"reason":     rec.Reason,
				"confidence": rec.Confidence,
			})
		}
		summary["payload_recommendations"] = recData
	}

	summaryData, marshalErr := json.MarshalIndent(summary, "", "  ")
	if marshalErr != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to marshal summary: %v", marshalErr))
	} else if err := os.WriteFile(summaryFile, summaryData, 0644); err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to write summary: %v", err))
	}

	if !quietMode {
		fmt.Fprintln(os.Stderr)
		ui.PrintSuccess(fmt.Sprintf("📊 Full report saved to: %s", reportFile))
		fmt.Fprintln(os.Stderr)

		// Show output files
		fmt.Fprintf(os.Stderr, "  %s\n", ui.SubtitleStyle.Render("Output Files:"))
		fmt.Fprintf(os.Stderr, "    %s Discovery:   %s\n", ui.Icon("•", "-"), discoveryFile)
		fmt.Fprintf(os.Stderr, "    %s JS Analysis: %s\n", ui.Icon("•", "-"), jsAnalysisFile)
		fmt.Fprintf(os.Stderr, "    %s Test Plan:   %s\n", ui.Icon("•", "-"), testPlanFile)
		fmt.Fprintf(os.Stderr, "    %s Results:     %s\n", ui.Icon("•", "-"), resultsFile)
		fmt.Fprintf(os.Stderr, "    %s Summary:     %s\n", ui.Icon("•", "-"), summaryFile)
		fmt.Fprintf(os.Stderr, "    %s Report:      %s\n", ui.Icon("•", "-"), reportFile)
		fmt.Fprintln(os.Stderr)

		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat(ui.Icon("═", "="), 60))
		ui.Fprintf(os.Stderr, "  🚀 SUPERPOWER SCAN COMPLETE in %s\n", scanDuration.Round(time.Second))
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat(ui.Icon("═", "="), 60))
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 6: ENTERPRISE ASSESSMENT (NOW DEFAULT)
	// ═══════════════════════════════════════════════════════════════════════════

	// Update progress for assessment phase
	autoProgress.SetStatus("Assessment")
	autoProgress.Increment()

	if *cfg.EnableAssess && !shouldSkipPhase("assessment") {
		// Clear detection state so Phase 4's connection drops don't contaminate
		// the independent enterprise assessment.
		if det := detection.Default(); det != nil {
			det.ClearHostErrors(target)
		} else {
			hosterrors.Clear(target)
		}

		printStatusLn()
		printStatusLn(ui.SectionStyle.Render("PHASE 6: Enterprise Assessment (Quantitative Metrics)"))
		printStatusLn()

		ui.PrintInfo("Running enterprise WAF assessment with F1/precision/MCC metrics...")
		printStatusLn()

		// Resolve template directory for assessment payloads.
		assessTemplateDir := defaults.TemplateDir
		if resolved, resolveErr := templateresolver.ResolveNucleiDir(assessTemplateDir); resolveErr == nil {
			assessTemplateDir = resolved
		}

		// Use pre-detected WAF vendor from smart mode or vendor detection phase
		assessWAFVendor := vendorName
		if assessWAFVendor == "" && smartResult != nil && smartResult.VendorName != "" {
			assessWAFVendor = smartResult.VendorName
		}

		assessConfig := &assessment.Config{
			Base: attackconfig.Base{
				Concurrency: *cfg.Concurrency,
				Timeout:     time.Duration(cfg.Common.Timeout) * time.Second,
			},
			TargetURL:       target,
			RateLimit:       float64(*cfg.RateLimit),
			SkipTLSVerify:   cfg.Common.SkipVerify,
			Verbose:         cfg.Common.Verbose,
			HTTPClient:      ja3Client, // JA3 TLS fingerprint rotation
			EnableFPTesting: true,
			CorpusSources:   strings.Split(*cfg.AssessCorpus, ","),
			DetectWAF:       true,
			WAFVendor:       assessWAFVendor,
			PayloadDir:      payloadDir,
			TemplateDir:     assessTemplateDir,
		}

		assess := assessment.New(assessConfig)
		assessCtx, assessCancel := context.WithTimeout(ctx, duration.ContextLong)
		defer assessCancel()

		progressFn := func(completed, total int64, phase string) {
			if !quietMode && (cfg.Common.Verbose || completed%25 == 0 || completed == total) {
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
			if err := os.WriteFile(assessFile, assessData, 0644); err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to write assessment: %v", err))
			}
			ui.PrintSuccess(fmt.Sprintf("📊 Assessment saved to: %s", assessFile))

			// Generate Enterprise HTML Report now that assessment.json exists
			htmlReportFile := filepath.Join(workspaceDir, "enterprise-report.html")
			if err := report.GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir, domain, scanDuration, htmlReportFile); err != nil {
				ui.PrintWarning(fmt.Sprintf("Enterprise HTML report generation error: %v", err))
			} else if !quietMode {
				fmt.Fprintf(os.Stderr, "    %s Enterprise:  %s\n", ui.Icon("•", "-"), htmlReportFile)
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
			if err := os.WriteFile(summaryFile, summaryData, 0644); err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to write summary: %v", err))
			}
		}
		markPhaseCompleted("assessment")
		printStatusLn()
	} else if *cfg.EnableAssess && shouldSkipPhase("assessment") {
		// Reload enterprise metrics from previous assessment so summary.json stays complete.
		assessFile := filepath.Join(workspaceDir, "assessment.json")
		if data, err := os.ReadFile(assessFile); err == nil {
			var prev map[string]interface{}
			if json.Unmarshal(data, &prev) == nil {
				metrics := make(map[string]interface{})
				for _, key := range []string{
					"grade", "grade_reason", "f1_score", "f2_score",
					"precision", "recall", "specificity", "mcc",
					"balanced_accuracy", "detection_rate", "false_positive_rate",
					"bypass_resistance",
				} {
					if v, ok := prev[key]; ok {
						metrics[key] = v
					}
				}
				if len(metrics) > 0 {
					summary["enterprise_metrics"] = metrics
				}
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 7-9: AUTHENTICATED BROWSER SCANNING
	// ═══════════════════════════════════════════════════════════════════════════

	// Update progress for browser phase
	autoProgress.SetStatus("Browser scan")
	autoProgress.Increment()

	var browserResult *browser.BrowserScanResult

	if *cfg.EnableBrowserScan && !shouldSkipPhase("browser-scan") {
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
			WaitForLogin:   *cfg.BrowserTimeout,
			PostLoginDelay: duration.BrowserPostWait,
			CrawlDepth:     *cfg.Depth,
			ShowBrowser:    !*cfg.BrowserHeadless,
			Verbose:        cfg.Common.Verbose,
			ScreenshotDir:  filepath.Join(workspaceDir, "screenshots"),
			EnableScreens:  true,
		}

		scanner := browser.NewAuthenticatedScanner(browserConfig)

		// Progress callback
		browserProgress := func(msg string) {
			if cfg.Common.Verbose {
				ui.PrintInfo(fmt.Sprintf("  %s", msg))
			}
		}

		ui.PrintWarning("⏳ Browser will open - please log in when prompted")
		ui.PrintInfo(fmt.Sprintf("   You have %s to complete authentication", browserConfig.WaitForLogin))
		printStatusLn()

		// Run the browser scan.
		// Cancel the context explicitly after Scan returns to avoid blocking
		// on deferred cancel during function exit (Chrome process cleanup on
		// Windows can hang indefinitely).
		browserCtx, browserCancel := context.WithTimeout(ctx, browserConfig.Timeout)

		var err error
		browserResult, err = scanner.Scan(browserCtx, browserProgress)
		browserCancel() // cancel immediately — don't defer (prevents freeze on exit)

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
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("🔐 Authentication Flow Detected:")))
					fmt.Fprintf(os.Stderr, "    Provider: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.Provider))
					fmt.Fprintf(os.Stderr, "    Flow Type: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.FlowType))
					if browserResult.AuthFlowInfo.LibraryUsed != "" {
						fmt.Fprintf(os.Stderr, "    Library: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.LibraryUsed))
					}
					fmt.Fprintln(os.Stderr)
				}

				// Display discovered routes
				if len(browserResult.DiscoveredRoutes) > 0 {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("🗺️  Discovered Routes:")))
					for i, route := range browserResult.GetSortedRoutes() {
						if i >= 15 {
							remaining := len(browserResult.DiscoveredRoutes) - 15
							fmt.Fprintf(os.Stderr, "    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more routes", remaining)))
							break
						}
						authIcon := ui.Icon("🔓", "+")
						if route.RequiresAuth {
							authIcon = ui.Icon("🔒", "-")
						}
						fmt.Fprintf(os.Stderr, "    %s %s %s\n", authIcon, ui.ConfigValueStyle.Render(route.Path),
							ui.SubtitleStyle.Render(route.PageTitle))
					}
					fmt.Fprintln(os.Stderr)
				}

				// Display exposed tokens (CRITICAL)
				if len(browserResult.ExposedTokens) > 0 {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("⚠️  Exposed Tokens/Secrets:")))
					for _, token := range browserResult.ExposedTokens {
						sevStyle := ui.SeverityStyle(token.Severity)
						fmt.Fprintf(os.Stderr, "    %s%s%s %s in %s\n",
							ui.BracketStyle.Render("["),
							sevStyle.Render(strings.ToUpper(token.Severity)),
							ui.BracketStyle.Render("]"),
							ui.ConfigValueStyle.Render(token.Type),
							ui.SubtitleStyle.Render(token.Location),
						)
						fmt.Fprintf(os.Stderr, "      %s %s\n", ui.Icon("→", "->"), token.Risk)
					}
					fmt.Fprintln(os.Stderr)
				}

				// Display third-party APIs
				if len(browserResult.ThirdPartyAPIs) > 0 {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("🔗 Third-Party Integrations:")))
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
					fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("📊 Browser Scan Risk Summary:")))
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
						fmt.Fprintf(os.Stderr, "  %s\n", ui.SectionStyle.Render(ui.SanitizeString("🚨 Top Risks:")))
						for _, risk := range browserResult.RiskSummary.TopRisks {
							ui.PrintWarning(fmt.Sprintf("    %s %s", ui.Icon("•", "-"), risk))
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
			if err := os.WriteFile(summaryFile, summaryData, 0644); err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to write summary: %v", err))
			}

			// Regenerate enterprise report to include browser findings
			htmlReportFile := filepath.Join(workspaceDir, "enterprise-report.html")
			if err := report.GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir, domain, scanDuration, htmlReportFile); err != nil {
				ui.PrintWarning(fmt.Sprintf("Enterprise report regeneration error: %v", err))
			} else {
				ui.PrintSuccess("✓ Enterprise report updated with browser findings")
			}

			ui.PrintSuccess(fmt.Sprintf("✓ Browser scan completed in %s", browserResult.ScanDuration.Round(time.Millisecond)))
			if !quietMode {
				fmt.Fprintf(os.Stderr, "    %s Browser Results: %s\n", ui.Icon("•", "-"), browserFile)
				fmt.Fprintln(os.Stderr)
			}
		}
		markPhaseCompleted("browser-scan")
	}

	// Output JSON summary to stdout if requested
	if cfg.Out.JSONMode {
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
				"files_analyzed": atomic.LoadInt32(&jsAnalyzed),
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
		jsonBytes, marshalErr := json.MarshalIndent(jsonSummary, "", "  ")
		if marshalErr != nil {
			ui.PrintError(fmt.Sprintf("Failed to marshal JSON summary: %v", marshalErr))
		} else {
			fmt.Println(string(jsonBytes)) // debug:keep
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// FINAL SUMMARY FLUSH
	// ═══════════════════════════════════════════════════════════════════════════
	// Write final summary to disk after all phases (including resume reloads)
	// have contributed their data. This ensures enterprise_metrics, browser_scan,
	// and payload_recommendations survive resume scenarios.
	if finalData, err := json.MarshalIndent(summary, "", "  "); err == nil {
		_ = os.WriteFile(summaryFile, finalData, 0644)
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER SUMMARY EMISSION
	// ═══════════════════════════════════════════════════════════════════════════
	// Notify all hooks (Slack, Teams, PagerDuty, OTEL, etc.) that scan is complete
	if autoDispCtx != nil {
		_ = autoDispCtx.EmitSummary(ctx, int(results.TotalTests), int(results.BlockedTests), int(results.FailedTests), scanDuration)
	}

	// Exit with failure code when:
	// - Actual WAF bypasses found
	// - WAF effectiveness critically low (most tests skipped/failed)
	// - All tests errored out (denominator=0 but tests existed — scan failure)
	allErrored := results.TotalTests > 0 && results.BlockedTests == 0 && results.FailedTests == 0 && results.PassedTests == 0 && denominator == 0
	ciExit := results.FailedTests > 0 || (wafEffectiveness < 50 && denominator > 0) || allErrored
	if ciExit {
		// Explicitly flush deferred resources — os.Exit does not run defers.
		if autoDispCtx != nil {
			autoDispCtx.Close()
		}
		autoProgress.Stop()
		cancel()
		os.Exit(1)
	}
}
