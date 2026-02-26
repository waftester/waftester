package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/templateresolver"
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
	var smartFlags SmartModeFlags
	smartFlags.RegisterBypass(bypassFlags)

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
	if *smartFlags.Enabled {
		ui.PrintConfigLine("Mode", fmt.Sprintf("Smart Bypass Hunter (%s mode)", *smartFlags.Mode))
	} else {
		ui.PrintConfigLine("Mode", "Bypass Hunter (all evasions enabled)")
	}
	fmt.Println()

	// Setup context
	ctx, cancel := cli.SignalContext(30 * time.Second)
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
	if *smartFlags.Enabled {
		ui.PrintSection("🧠 Smart Mode: WAF Detection & Optimization")
		fmt.Println()

		smartConfig := &SmartModeConfig{
			DetectionTimeout: duration.HTTPScanning,
			Verbose:          *smartFlags.Verbose,
			Mode:             *smartFlags.Mode,
		}

		var err error
		smartResult, err = DetectAndOptimize(ctx, targetURL, smartConfig)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", err))
		}

		PrintSmartModeInfo(smartResult, *smartFlags.Verbose)

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

	// Resolve template directory (extracts embedded templates if needed)
	templateDir := defaults.TemplateDir
	if resolved, resolveErr := templateresolver.ResolveNucleiDir(templateDir); resolveErr == nil {
		templateDir = resolved
	}

	// Load payloads from unified engine (JSON + Nuclei templates)
	allPayloads, _, err := loadUnifiedPayloads(*payloadDir, templateDir, *smartFlags.Verbose)
	if err != nil {
		errMsg := fmt.Sprintf("Cannot load payloads: %v", err)
		ui.PrintError(errMsg)
		if bypassDispCtx != nil {
			_ = bypassDispCtx.EmitError(ctx, "bypass", errMsg, true)
			_ = bypassDispCtx.Close()
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
	cfg.RealisticMode = *realisticMode || *realisticShort || *smartFlags.Enabled
	cfg.AutoCalibrate = *autoCalibrate || *smartFlags.Enabled

	// Apply smart mode optimizations
	if *smartFlags.Enabled && smartResult != nil {
		// Preserve user-explicit flags (same pattern as scan/autoscan)
		userSetRL := false
		userSetConc := false
		bypassFlags.Visit(func(f *flag.Flag) {
			if f.Name == "rl" {
				userSetRL = true
			}
			if f.Name == "c" {
				userSetConc = true
			}
		})
		ApplySmartConfig(cfg, smartResult)
		// Restore user-set values after smart config
		if userSetRL {
			cfg.RateLimit = *rateLimit
		}
		if userSetConc {
			cfg.Concurrency = *concurrency
		}
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
		if *smartFlags.Enabled {
			manifest.AddWithIcon("🧠", "Mode", fmt.Sprintf("Smart (%s)", *smartFlags.Mode))
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
			{Name: "bypasses", Label: "Bypasses", Icon: ui.Icon("🎯", "*"), Highlight: true},
			{Name: "blocked", Label: "Blocked", Icon: ui.Icon("🛡️", "#")},
			{Name: "errors", Label: "Errors", Icon: ui.Icon("⚠️", "!")},
		},
		Tips:        tips,
		TipInterval: duration.TipRotate,
	})

	progress.Start()

	// Execute mutation tests with callback
	executor.Execute(ctx, tasks, func(r *mutation.TestResult) {
		progress.Increment()

		// Emit full result for HAR export and telemetry
		if bypassDispCtx != nil {
			cat := "bypass-hunt"
			if r.EvasionUsed != "" {
				cat = "bypass-hunt-" + r.EvasionUsed
			}
			outcome := r.Outcome
			if outcome == "" {
				outcome = "Passed"
				if r.Blocked {
					outcome = "Blocked"
				}
			}
			tr := &output.TestResult{
				ID:                  r.ID,
				Category:            cat,
				Severity:            "high",
				Outcome:             outcome,
				StatusCode:          r.StatusCode,
				LatencyMs:           r.LatencyMs,
				Payload:             r.MutatedPayload,
				OriginalPayload:     r.OriginalPayload,
				Method:              r.Method,
				RequestURL:          r.URL,
				ContentLength:       r.ContentLength,
				ResponseHeaders:     r.ResponseHeaders,
				ResponseBodySnippet: r.ResponseSnippet,
				EncodingUsed:        r.EncoderUsed,
				ErrorMessage:        r.ErrorMessage,
			}
			_ = bypassDispCtx.EmitDetailedResult(ctx, tr)
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
				remaining := len(bypassPayloads) - 10
				if *outputFile != "" {
					fmt.Printf("  ... and %d more (see %s)\n", remaining, *outputFile)
				} else {
					fmt.Printf("  ... and %d more (use -o <file> to export all)\n", remaining)
				}
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

	// Write enterprise export files (--json-export, --sarif-export, etc.)
	writeBypassExports(&outputFlags, targetURL, bypassPayloads, totalTested, bypassRate)

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER SUMMARY EMISSION
	// ═══════════════════════════════════════════════════════════════════════════
	// Notify all hooks (Slack, Teams, PagerDuty, OTEL, etc.) that bypass hunt is complete
	if bypassDispCtx != nil {
		blocked := int(totalTested) - len(bypassPayloads)
		_ = bypassDispCtx.EmitSummary(ctx, int(totalTested), blocked, len(bypassPayloads), time.Since(bypassStartTime))
	}
}

// writeBypassExports writes bypass results to enterprise export files (--json-export, --sarif-export, etc.).
func writeBypassExports(outFlags *OutputFlags, target string, bypasses []*mutation.TestResult, totalTested int64, bypassRate float64) {
	result := &mutation.WAFBypassResult{
		Found:          len(bypasses) > 0,
		BypassPayloads: bypasses,
		TotalTested:    totalTested,
		BypassRate:     bypassRate,
	}

	if outFlags.JSONExport != "" {
		if err := writeJSONFile(outFlags.JSONExport, result); err != nil {
			ui.PrintError(fmt.Sprintf("JSON export: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("JSON export saved to %s", outFlags.JSONExport))
		}
	}

	if outFlags.JSONLExport != "" {
		f, err := os.Create(outFlags.JSONLExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("JSONL export: %v", err))
		} else {
			enc := json.NewEncoder(f)
			for _, bp := range bypasses {
				_ = enc.Encode(bp)
			}
			f.Close()
			ui.PrintSuccess(fmt.Sprintf("JSONL export saved to %s", outFlags.JSONLExport))
		}
	}

	if outFlags.CSVExport != "" {
		f, err := os.Create(outFlags.CSVExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("CSV export: %v", err))
		} else {
			fmt.Fprintln(f, "status_code,payload,encoder,evasion,location,latency_ms,url")
			for _, bp := range bypasses {
				fmt.Fprintf(f, "%d,%q,%s,%s,%s,%d,%s\n",
					bp.StatusCode, bp.MutatedPayload, bp.EncoderUsed, bp.EvasionUsed, bp.LocationUsed, bp.LatencyMs, bp.URL)
			}
			f.Close()
			ui.PrintSuccess(fmt.Sprintf("CSV export saved to %s", outFlags.CSVExport))
		}
	}

	if outFlags.SARIFExport != "" {
		if err := writeJSONFile(outFlags.SARIFExport, buildBypassSARIF(target, bypasses)); err != nil {
			ui.PrintError(fmt.Sprintf("SARIF export: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("SARIF export saved to %s", outFlags.SARIFExport))
		}
	}

	if outFlags.HTMLExport != "" {
		f, err := os.Create(outFlags.HTMLExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("HTML export: %v", err))
		} else {
			fmt.Fprintf(f, "<html><head><title>WAF Bypass Results</title></head><body>\n")
			fmt.Fprintf(f, "<h1>WAF Bypass Results</h1>\n")
			fmt.Fprintf(f, "<p>Target: %s | Total: %d | Bypasses: %d | Rate: %.2f%%</p>\n",
				html.EscapeString(target), totalTested, len(bypasses), bypassRate)
			if len(bypasses) > 0 {
				fmt.Fprintf(f, "<table border='1'><tr><th>Status</th><th>Payload</th><th>Encoder</th><th>Evasion</th><th>Location</th></tr>\n")
				for _, bp := range bypasses {
					fmt.Fprintf(f, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
						bp.StatusCode, html.EscapeString(bp.MutatedPayload), html.EscapeString(bp.EncoderUsed), html.EscapeString(bp.EvasionUsed), html.EscapeString(bp.LocationUsed))
				}
				fmt.Fprintf(f, "</table>\n")
			}
			fmt.Fprintf(f, "</body></html>\n")
			f.Close()
			ui.PrintSuccess(fmt.Sprintf("HTML export saved to %s", outFlags.HTMLExport))
		}
	}

	if outFlags.MDExport != "" {
		f, err := os.Create(outFlags.MDExport)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Markdown export: %v", err))
		} else {
			fmt.Fprintf(f, "# WAF Bypass Results\n\n")
			fmt.Fprintf(f, "- **Target:** %s\n- **Total Tested:** %d\n- **Bypasses:** %d\n- **Bypass Rate:** %.2f%%\n\n",
				target, totalTested, len(bypasses), bypassRate)
			if len(bypasses) > 0 {
				fmt.Fprintf(f, "| Status | Payload | Encoder | Evasion | Location |\n")
				fmt.Fprintf(f, "|--------|---------|---------|---------|----------|\n")
				for _, bp := range bypasses {
					fmt.Fprintf(f, "| %d | %s | %s | %s | %s |\n",
						bp.StatusCode, bp.MutatedPayload, bp.EncoderUsed, bp.EvasionUsed, bp.LocationUsed)
				}
			}
			f.Close()
			ui.PrintSuccess(fmt.Sprintf("Markdown export saved to %s", outFlags.MDExport))
		}
	}
}

// writeJSONFile marshals v to a JSON file with indentation.
func writeJSONFile(path string, v interface{}) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// buildBypassSARIF creates a minimal SARIF 2.1.0 structure for bypass findings.
func buildBypassSARIF(target string, bypasses []*mutation.TestResult) map[string]interface{} {
	results := make([]map[string]interface{}, 0, len(bypasses))
	for _, bp := range bypasses {
		results = append(results, map[string]interface{}{
			"ruleId":  "waf-bypass",
			"level":   "warning",
			"message": map[string]string{"text": fmt.Sprintf("WAF bypass found: %s via %s/%s", bp.MutatedPayload, bp.EncoderUsed, bp.EvasionUsed)},
			"locations": []map[string]interface{}{
				{"physicalLocation": map[string]interface{}{
					"artifactLocation": map[string]string{"uri": bp.URL},
				}},
			},
		})
	}
	return map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "WAFtester",
						"version": defaults.Version,
					},
				},
				"results": results,
			},
		},
	}
}
