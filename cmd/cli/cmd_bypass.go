package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// BYPASS FINDER COMMAND
// =============================================================================

func runBypassFinder() {
	ui.PrintCompactBanner()
	ui.PrintSection("WAF Bypass Finder")

	bypassFlags := flag.NewFlagSet("bypass", flag.ExitOnError)

	target := bypassFlags.String("target", "", "Target URL")
	targetShort := bypassFlags.String("u", "", "Target URL (shorthand)")
	payloadDir := bypassFlags.String("payloads", defaults.PayloadDir, "Payload directory")
	category := bypassFlags.String("category", "injection", "Payload category to test")
	concurrency := bypassFlags.Int("c", 10, "Concurrency")
	rateLimit := bypassFlags.Float64("rl", 30, "Rate limit")
	outputFile := bypassFlags.String("o", "bypasses.json", "Output file for bypass results")
	skipVerify := bypassFlags.Bool("k", false, "Skip TLS verification")

	// Streaming mode (CI-friendly output)
	streamMode := bypassFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	// Realistic mode (intelligent block detection)
	realisticMode := bypassFlags.Bool("realistic", false, "Use intelligent block detection + realistic headers")
	realisticShort := bypassFlags.Bool("R", false, "Realistic mode (shorthand)")
	autoCalibrate := bypassFlags.Bool("ac", false, "Auto-calibrate baseline before testing")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := bypassFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := bypassFlags.String("smart-mode", "bypass", "Smart mode type: quick, standard, full, bypass, stealth")
	smartVerbose := bypassFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// Enterprise output flags (unified output configuration)
	var outputFlags OutputFlags
	outputFlags.RegisterBypassEnterpriseFlags(bypassFlags)

	// Detection (v2.5.2)
	noDetect := bypassFlags.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	bypassFlags.Parse(os.Args[2:])

	// Disable detection if requested
	if *noDetect {
		detection.Disable()
	}

	// Apply UI settings from output flags
	outputFlags.ApplyUISettings()

	// Sync legacy flags to outputFlags for unified handling
	outputFlags.OutputFile = *outputFile
	outputFlags.StreamMode = *streamMode

	targetURL := *target
	if targetURL == "" {
		targetURL = *targetShort
	}
	if targetURL == "" {
		ui.PrintError("Target URL required")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", targetURL)
	ui.PrintConfigLine("Category", *category)
	if *smartMode {
		ui.PrintConfigLine("Mode", fmt.Sprintf("Smart Bypass Hunter (%s mode)", *smartModeType))
	} else {
		ui.PrintConfigLine("Mode", "Bypass Hunter (all evasions enabled)")
	}
	fmt.Println()

	// Setup context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	bypassScanID := fmt.Sprintf("bypass-%d", time.Now().Unix())
	bypassDispCtx, bypassDispErr := outputFlags.InitDispatcher(bypassScanID, targetURL)
	if bypassDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Output dispatcher warning: %v", bypassDispErr))
	}
	if bypassDispCtx != nil {
		defer bypassDispCtx.Close()
		bypassDispCtx.RegisterDetectionCallbacks(ctx)
	}
	bypassCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if bypassDispCtx != nil {
		_ = bypassDispCtx.EmitStart(bypassCtx, targetURL, 0, *concurrency, nil)
	}

	// Smart Mode: Detect WAF and optimize configuration
	var smartResult *SmartModeResult
	if *smartMode {
		ui.PrintSection("🧠 Smart Mode: WAF Detection & Optimization")
		fmt.Println()

		smartConfig := &SmartModeConfig{
			DetectionTimeout: duration.HTTPScanning,
			Verbose:          *smartVerbose,
			Mode:             *smartModeType,
		}

		var err error
		smartResult, err = DetectAndOptimize(ctx, targetURL, smartConfig)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", err))
		}

		PrintSmartModeInfo(smartResult, *smartVerbose)

		// Emit smart mode WAF detection to hooks
		if bypassDispCtx != nil && smartResult != nil && smartResult.WAFDetected {
			wafDesc := fmt.Sprintf("Smart mode detected: %s (%.0f%% confidence)", smartResult.VendorName, smartResult.Confidence*100)
			_ = bypassDispCtx.EmitBypass(ctx, "smart-waf-detection", "info", targetURL, wafDesc, 0)
			// Emit bypass hints as actionable intelligence
			for _, hint := range smartResult.BypassHints {
				_ = bypassDispCtx.EmitBypass(ctx, "bypass-hint", "info", targetURL, hint, 0)
			}
		}
	}

	// Load payloads from unified engine (JSON + Nuclei templates)
	allPayloads, _, err := loadUnifiedPayloads(*payloadDir, defaults.TemplateDir, *smartVerbose)
	if err != nil {
		errMsg := fmt.Sprintf("Cannot load payloads: %v", err)
		ui.PrintError(errMsg)
		if bypassDispCtx != nil {
			_ = bypassDispCtx.EmitError(ctx, "bypass", errMsg, true)
		}
		os.Exit(1)
	}

	filtered := payloads.Filter(allPayloads, *category, "")
	var testPayloads []string
	for _, p := range filtered {
		testPayloads = append(testPayloads, p.Payload)
	}

	ui.PrintConfigLine("Payloads", fmt.Sprintf("%d", len(testPayloads)))

	// Configure for maximum bypass detection
	cfg := mutation.DefaultExecutorConfig()
	cfg.TargetURL = targetURL
	cfg.Concurrency = *concurrency
	cfg.RateLimit = *rateLimit
	cfg.SkipVerify = *skipVerify
	cfg.RealisticMode = *realisticMode || *realisticShort || *smartMode
	cfg.AutoCalibrate = *autoCalibrate || *smartMode

	// Apply smart mode optimizations
	if *smartMode && smartResult != nil {
		ApplySmartConfig(cfg, smartResult)
		ui.PrintInfo(fmt.Sprintf("📊 WAF-optimized: %d encoders, %d evasions, %.0f req/sec",
			len(cfg.Pipeline.Encoders), len(cfg.Pipeline.Evasions), cfg.RateLimit))
	} else {
		cfg.Pipeline = mutation.FullCoveragePipelineConfig()
	}

	executor := mutation.NewExecutor(cfg)

	// Count combinations
	expectedTests := executor.CountCombinations(len(testPayloads))
	ui.PrintConfigLine("Expected Tests", fmt.Sprintf("%d", expectedTests))
	fmt.Fprintln(os.Stderr)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Generate tasks for progress tracking
	tasks := executor.GenerateTasks(testPayloads, nil)

	// Progress tracking
	var bypassMu sync.Mutex
	var bypassPayloads []*mutation.TestResult

	// Determine WAF name for manifest display
	wafName := "Unknown WAF"
	if smartResult != nil && smartResult.WAFDetected {
		wafName = smartResult.VendorName
	}

	// Tips for bypass hunting
	tips := []string{
		"Chunked encoding can split payloads to evade pattern matching",
		"Most WAFs can't properly normalize Unicode in all contexts",
		"Encoders combined with evasions multiply your test coverage",
		"Parameter pollution bypasses 30%+ of WAFs",
		"Case variations alone find bypasses in 1 out of 5 WAFs",
	}

	// Determine output mode
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Display execution manifest BEFORE running (only in interactive mode)
	if !*streamMode {
		manifest := ui.NewExecutionManifest("BYPASS HUNT MANIFEST")
		manifest.SetDescription("Hunting for WAF bypass vectors")
		manifest.AddWithIcon("🎯", "Target", targetURL)
		manifest.AddWithIcon("🛡️", "WAF", wafName)
		manifest.AddEmphasis("📦", "Payloads", fmt.Sprintf("%d base payloads", len(testPayloads)))
		manifest.AddEmphasis("🔀", "Mutations", fmt.Sprintf("%d test combinations", len(tasks)))
		manifest.AddWithIcon("🏷️", "Category", *category)
		if *smartMode {
			manifest.AddWithIcon("🧠", "Mode", fmt.Sprintf("Smart (%s)", *smartModeType))
		} else {
			manifest.AddWithIcon("⚔️", "Mode", "Bypass Hunter (all evasions)")
		}
		manifest.AddConcurrency(*concurrency, *rateLimit)
		manifest.AddEstimate(len(tasks), *rateLimit)
		manifest.Print()
	} else {
		fmt.Printf("[INFO] Starting bypass hunt: target=%s waf=%s payloads=%d mutations=%d\n",
			targetURL, wafName, len(testPayloads), len(tasks))
	}

	// Track execution time for summary
	bypassStartTime := time.Now()

	// Use unified LiveProgress component
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        len(tasks),
		DisplayLines: 3,
		Title:        "Hunting for bypasses",
		Unit:         "tests",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "bypasses", Label: "Bypasses", Icon: "🎯", Highlight: true},
			{Name: "blocked", Label: "Blocked", Icon: "🛡️"},
			{Name: "errors", Label: "Errors", Icon: "⚠️"},
		},
		Tips:        tips,
		TipInterval: duration.TipRotate,
	})

	progress.Start()

	// Execute mutation tests with callback
	executor.Execute(ctx, tasks, func(r *mutation.TestResult) {
		progress.Increment()

		// Emit every test result for complete telemetry
		if bypassDispCtx != nil {
			category := "bypass-hunt"
			if r.EvasionUsed != "" {
				category = "bypass-hunt-" + r.EvasionUsed
			}
			_ = bypassDispCtx.EmitResult(ctx, category, "high", r.Blocked, r.StatusCode, float64(r.LatencyMs))
		}

		if r.Blocked {
			progress.AddMetric("blocked")
		} else if r.ErrorMessage != "" {
			progress.AddMetric("errors")
		} else {
			progress.AddMetric("bypasses")
			// Record bypass
			bypassMu.Lock()
			bypassPayloads = append(bypassPayloads, r)
			bypassMu.Unlock()

			// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
			// Emit each bypass as it's found for immediate alerting
			if bypassDispCtx != nil {
				// Build category from encoder/evasion used
				category := "waf-bypass"
				if r.EvasionUsed != "" {
					category = "waf-bypass-" + r.EvasionUsed
				}
				_ = bypassDispCtx.EmitBypass(ctx, category, "high", r.URL, r.MutatedPayload, r.StatusCode)
			}
		}
	})

	progress.Stop()

	// Build result
	totalTested := progress.GetCompleted()
	bypassRate := float64(0)
	if totalTested > 0 {
		bypassRate = float64(len(bypassPayloads)) / float64(totalTested) * 100
	}

	ui.PrintSection("Bypass Hunt Results")
	fmt.Printf("  Total Tested:    %d\n", totalTested)
	fmt.Printf("  Bypasses Found:  %d\n", len(bypassPayloads))
	fmt.Printf("  Bypass Rate:     %.2f%%\n", bypassRate)
	fmt.Println()

	if len(bypassPayloads) > 0 {
		ui.PrintWarning(fmt.Sprintf("🚨 Found %d WAF bypasses!", len(bypassPayloads)))
		fmt.Println()

		// Show top bypasses
		ui.PrintSection("Top Bypasses")
		shown := 0
		for _, bp := range bypassPayloads {
			if shown >= 10 {
				fmt.Printf("  ... and %d more (see %s)\n", len(bypassPayloads)-10, *outputFile)
				break
			}
			fmt.Printf("  [%d] %s | %s | %s\n",
				bp.StatusCode, bp.EncoderUsed, bp.LocationUsed, bp.EvasionUsed)
			fmt.Printf("      Payload: %.60s...\n", bp.MutatedPayload)
			fmt.Println()
			shown++
		}

		// Save to file
		if *outputFile != "" {
			f, err := os.Create(*outputFile)
			if err != nil {
				ui.PrintError(fmt.Sprintf("Cannot create output file %s: %v", *outputFile, err))
			} else {
				defer f.Close()
				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				// Create result structure for JSON output
				result := &mutation.WAFBypassResult{
					Found:          true,
					BypassPayloads: bypassPayloads,
					TotalTested:    totalTested,
					BypassRate:     bypassRate,
				}
				if err := enc.Encode(result); err != nil {
					ui.PrintError(fmt.Sprintf("Error encoding results: %v", err))
				} else {
					ui.PrintSuccess(fmt.Sprintf("Full results saved to %s", *outputFile))
				}
			}
		}
	} else {
		ui.PrintSuccess("✓ No bypasses found - WAF held strong!")
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER SUMMARY EMISSION
	// ═══════════════════════════════════════════════════════════════════════════
	// Notify all hooks (Slack, Teams, PagerDuty, OTEL, etc.) that bypass hunt is complete
	if bypassDispCtx != nil {
		blocked := int(totalTested) - len(bypassPayloads)
		_ = bypassDispCtx.EmitSummary(ctx, int(totalTested), blocked, len(bypassPayloads), time.Since(bypassStartTime))
	}
}
