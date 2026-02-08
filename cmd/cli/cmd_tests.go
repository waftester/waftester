package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/waftester/waftester/pkg/calibration"
	"github.com/waftester/waftester/pkg/config"
	"github.com/waftester/waftester/pkg/core"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/interactive"
	"github.com/waftester/waftester/pkg/learning"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/output/baseline"
	"github.com/waftester/waftester/pkg/output/policy"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/ui"
)

// runTests executes the main WAF testing workflow
func runTests() {
	// Register enterprise output flags on global flag.CommandLine BEFORE config.ParseFlags()
	// This allows enterprise features without modifying the config package
	var outputFlags OutputFlags
	outputFlags.RegisterRunEnterpriseFlags(flag.CommandLine)

	// Parse CLI flags first to check for silent mode
	cfg, err := config.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Sync OutputFlags with config settings (config.ParseFlags defines some overlapping flags)
	outputFlags.OutputFile = cfg.OutputFile
	outputFlags.Format = cfg.OutputFormat
	outputFlags.Silent = cfg.Silent
	outputFlags.NoColor = cfg.NoColor
	outputFlags.ShowStats = cfg.Stats
	outputFlags.StatsInterval = cfg.StatsInterval

	// Disable detection if user requested
	if !cfg.EnableDetection {
		detection.Disable()
	}

	// Load policy and baseline for CI/CD gating
	pol, err := outputFlags.LoadPolicy()
	if err != nil {
		ui.PrintError(fmt.Sprintf("Error loading policy: %v", err))
		os.Exit(1)
	}
	bl, err := outputFlags.LoadBaseline()
	if err != nil {
		ui.PrintError(fmt.Sprintf("Error loading baseline: %v", err))
		os.Exit(1)
	}

	// Print banner (unless silent)
	if !cfg.Silent {
		ui.PrintBanner()
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     cfg.TargetURLs,
		ListFile: cfg.ListFile,
		Stdin:    cfg.StdinInput,
	}
	targets, err := ts.GetTargets()
	if err != nil {
		ui.PrintError(fmt.Sprintf("Error reading targets: %v", err))
		os.Exit(1)
	}
	if len(targets) == 0 && cfg.PlanFile == "" {
		// Only require target if not using a test plan (plan can provide target)
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}
	// For multi-target support, we'll iterate through targets later
	// Set the first target as primary for now (used by test plan loading, etc.)
	if len(targets) > 0 {
		cfg.TargetURL = targets[0]
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	runScanID := fmt.Sprintf("run-%d", time.Now().Unix())
	runDispCtx, runDispErr := outputFlags.InitDispatcher(runScanID, cfg.TargetURL)
	if runDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Output dispatcher warning: %v", runDispErr))
	}
	if runDispCtx != nil {
		defer runDispCtx.Close()
		if !cfg.Silent {
			ui.PrintInfo("Real-time integrations enabled (hooks active)")
		}
		// Emit scan start event to hooks
		_ = runDispCtx.EmitStart(ctx, cfg.TargetURL, 0, cfg.Concurrency, cfg.Categories)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr)
		ui.PrintWarning("Interrupt received, shutting down gracefully...")
		cancel()
	}()

	// Check if using a test plan from 'learn' command
	var plan *learning.TestPlan
	if cfg.PlanFile != "" {
		if !cfg.Silent {
			ui.PrintInfo(fmt.Sprintf("Loading test plan from %s...", cfg.PlanFile))
		}
		plan, err = learning.LoadPlan(cfg.PlanFile)
		if err != nil {
			errMsg := fmt.Sprintf("Error loading test plan: %v", err)
			ui.PrintError(errMsg)
			ui.PrintHelp("Run 'waf-tester learn -discovery <file>' first to generate a test plan")
			_ = runDispCtx.EmitError(ctx, "run", errMsg, true)
			os.Exit(1)
		}

		// Apply plan settings if not overridden by CLI
		if cfg.TargetURL == "" {
			cfg.TargetURL = plan.Target
		}
		if cfg.Concurrency == 25 { // default value
			cfg.Concurrency = plan.RecommendedFlags.Concurrency
		}
		if cfg.RateLimit == 150 { // default value
			cfg.RateLimit = plan.RecommendedFlags.RateLimit
		}
		if cfg.Category == "" && len(plan.RecommendedFlags.Categories) > 0 {
			cfg.Category = plan.RecommendedFlags.Categories[0]
		}

		if !cfg.Silent {
			ui.PrintSuccess(fmt.Sprintf("Loaded test plan: %d tests across %d categories",
				plan.TotalTests, len(plan.TestGroups)))
			fmt.Println()
		}
	}

	// Print configuration (ffuf-style) - skip if silent
	if !cfg.Silent {
		configOptions := map[string]string{
			"Target":      cfg.TargetURL,
			"Payload Dir": cfg.PayloadDir,
			"Concurrency": fmt.Sprintf("%d", cfg.Concurrency),
			"Rate Limit":  fmt.Sprintf("%d req/sec", cfg.RateLimit),
			"Timeout":     fmt.Sprintf("%v", cfg.Timeout),
		}
		if cfg.PlanFile != "" {
			configOptions["Test Plan"] = cfg.PlanFile
		}
		if cfg.Category != "" {
			configOptions["Category"] = cfg.Category
		}
		if cfg.Severity != "" {
			configOptions["Min Severity"] = cfg.Severity + "+"
		}
		if cfg.MatchStatus != "" {
			configOptions["Match Codes"] = cfg.MatchStatus
		}
		if cfg.MatchWords != "" {
			configOptions["Match Words"] = cfg.MatchWords
		}
		if cfg.MatchLines != "" {
			configOptions["Match Lines"] = cfg.MatchLines
		}
		if cfg.MatchRegex != "" {
			configOptions["Match Regex"] = cfg.MatchRegex
		}
		if cfg.FilterStatus != "" {
			configOptions["Filter Codes"] = cfg.FilterStatus
		}
		if cfg.FilterWords != "" {
			configOptions["Filter Words"] = cfg.FilterWords
		}
		if cfg.FilterLines != "" {
			configOptions["Filter Lines"] = cfg.FilterLines
		}
		if cfg.FilterRegex != "" {
			configOptions["Filter Regex"] = cfg.FilterRegex
		}
		if cfg.Proxy != "" {
			configOptions["Proxy"] = cfg.Proxy
		}
		if cfg.OutputFile != "" {
			configOptions["Output"] = cfg.OutputFile
			configOptions["Format"] = cfg.OutputFormat
		}
		if cfg.AutoCalibration {
			configOptions["Calibration"] = "enabled"
		}
		ui.PrintConfigBanner(configOptions)
	}

	// Auto-calibration (like ffuf -ac)
	if cfg.AutoCalibration {
		if !cfg.Silent {
			ui.PrintInfo("Running auto-calibration...")
		}
		cal := calibration.NewCalibrator(cfg.TargetURL, cfg.Timeout, cfg.SkipVerify)
		calResult, calErr := cal.Calibrate(ctx)
		if calErr != nil {
			if !cfg.Silent {
				ui.PrintWarning(fmt.Sprintf("Calibration failed: %v (continuing without filtering)", calErr))
			}
		} else if calResult != nil && calResult.Calibrated {
			// Apply calibration results as filters
			if len(calResult.Suggestions.FilterStatus) > 0 && cfg.FilterStatus == "" {
				codes := make([]string, len(calResult.Suggestions.FilterStatus))
				for i, c := range calResult.Suggestions.FilterStatus {
					codes[i] = fmt.Sprintf("%d", c)
				}
				cfg.FilterStatus = strings.Join(codes, ",")
			}
			if len(calResult.Suggestions.FilterSize) > 0 && cfg.FilterSize == "" {
				sizes := make([]string, len(calResult.Suggestions.FilterSize))
				for i, s := range calResult.Suggestions.FilterSize {
					sizes[i] = fmt.Sprintf("%d", s)
				}
				cfg.FilterSize = strings.Join(sizes, ",")
			}
			if !cfg.Silent {
				ui.PrintSuccess(fmt.Sprintf("Calibrated: %s", calResult.Describe()))
			}
		}
		if !cfg.Silent {
			fmt.Println()
		}
	}

	// Initialize interactive handler (ffuf-style)
	var interactiveHandler *interactive.Handler
	if !cfg.NonInteractive && !cfg.Silent {
		interactiveState := interactive.NewState(cfg.RateLimit)
		interactiveHandler = interactive.NewHandler(interactiveState)
		go interactiveHandler.Start()
		defer interactiveHandler.Stop()
	}
	_ = interactiveHandler // Handler provides pause/resume during execution via background goroutine

	// Load payloads from unified engine (JSON + Nuclei templates)
	if !cfg.Silent {
		ui.PrintInfo("Loading payloads...")
	}
	allPayloads, _, err := loadUnifiedPayloads(cfg.PayloadDir, defaults.TemplateDir, cfg.Verbose)
	if err != nil {
		errMsg := fmt.Sprintf("Error loading payloads: %v", err)
		ui.PrintError(errMsg)
		_ = runDispCtx.EmitError(ctx, "run", errMsg, true)
		os.Exit(1)
	}

	// Apply filters from test plan or CLI
	if plan != nil && len(plan.RecommendedFlags.Categories) > 0 {
		// When using a test plan, filter to ANY of its recommended categories
		var filteredPayloads []payloads.Payload
		categorySet := make(map[string]bool)
		for _, cat := range plan.RecommendedFlags.Categories {
			categorySet[strings.ToLower(cat)] = true
		}
		for _, p := range allPayloads {
			if categorySet[strings.ToLower(p.Category)] {
				filteredPayloads = append(filteredPayloads, p)
			}
		}
		allPayloads = filteredPayloads
		if !cfg.Silent {
			ui.PrintInfo(fmt.Sprintf("Filtered to %d categories from test plan: %v", len(plan.RecommendedFlags.Categories), plan.RecommendedFlags.Categories))
		}
	} else if cfg.Category != "" || cfg.Severity != "" {
		allPayloads = payloads.Filter(allPayloads, cfg.Category, cfg.Severity)
	}

	if !cfg.Silent {
		ui.PrintSuccess(fmt.Sprintf("Loaded %d payloads", len(allPayloads)))
	}

	// Apply mutations if enabled
	if cfg.MutationMode != "" && cfg.MutationMode != "none" {
		allPayloads = applyMutations(cfg, allPayloads)
		if !cfg.Silent {
			ui.PrintSuccess(fmt.Sprintf("Expanded to %d payloads after mutation", len(allPayloads)))
		}
	}

	// Dry run mode - just list payloads
	if cfg.DryRun {
		// Force sync stderr before printing to stdout
		os.Stderr.Sync()

		ui.PrintSection("Dry Run Mode")
		ui.PrintInfo(fmt.Sprintf("Would execute %d tests:", len(allPayloads)))

		// Sync stderr before switching to stdout for results
		os.Stderr.Sync()

		for _, p := range allPayloads {
			ui.PrintBracketedInfo(
				ui.SeverityBracket(p.SeverityHint),
				ui.CategoryBracket(p.Category),
				ui.TextBracket(p.ID),
			)
		}

		// Sync stdout before switching back to stderr
		os.Stdout.Sync()
		fmt.Fprintln(os.Stderr)
		ui.PrintHelp("Remove -dry-run flag to execute tests")
		os.Exit(0)
	}

	// Determine which targets to test
	// If targets is empty (using plan file), use plan.Target
	if len(targets) == 0 && plan != nil && plan.Target != "" {
		targets = []string{plan.Target}
	}

	// Multi-target support: run tests against each target
	var aggregatedResults output.ExecutionResults
	totalTargets := len(targets)

	if totalTargets > 1 && !cfg.Silent {
		ui.PrintSection(fmt.Sprintf("Multi-Target Mode: Testing %d targets", totalTargets))
		fmt.Println()
	}

	for targetIdx, currentTarget := range targets {
		// Update config for this target
		cfg.TargetURL = currentTarget

		if totalTargets > 1 && !cfg.Silent {
			ui.PrintSection(fmt.Sprintf("Target %d/%d: %s", targetIdx+1, totalTargets, currentTarget))
			fmt.Println()
		}

		// Create output writer with verbose, timestamp, and silent options
		// For multi-target, append target index to filename
		outputFile := cfg.OutputFile
		if totalTargets > 1 && cfg.OutputFile != "" {
			ext := filepath.Ext(cfg.OutputFile)
			base := strings.TrimSuffix(cfg.OutputFile, ext)
			// Extract domain for clearer filenames
			domain := ""
			if u, err := url.Parse(currentTarget); err == nil && u != nil {
				domain = u.Host
			}
			if domain == "" {
				domain = fmt.Sprintf("target-%d", targetIdx+1)
			}
			domain = strings.ReplaceAll(domain, ":", "_")
			outputFile = fmt.Sprintf("%s-%s%s", base, domain, ext)
		}

		writer, err := output.NewWriterWithOptions(outputFile, cfg.OutputFormat, output.WriterOptions{
			Verbose:       cfg.Verbose,
			ShowTimestamp: cfg.Timestamp,
			Silent:        cfg.Silent,
			Target:        currentTarget,
		})
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error creating output for %s: %v", currentTarget, err))
			continue
		}

		// Create progress tracker with turbo mode
		progress := ui.NewProgress(ui.ProgressConfig{
			Total:       len(allPayloads),
			Width:       40,
			ShowPercent: true,
			ShowETA:     true,
			ShowRPS:     true,
			Concurrency: cfg.Concurrency,
			TurboMode:   true,
		})

		// Print section header
		if !cfg.Silent {
			ui.PrintSection("Executing Tests")
			fmt.Printf("\n  %s Running with %s parallel workers @ %s req/sec max\n\n",
				ui.SpinnerStyle.Render(">>>"),
				ui.StatValueStyle.Render(fmt.Sprintf("%d", cfg.Concurrency)),
				ui.StatValueStyle.Render(fmt.Sprintf("%d", cfg.RateLimit)),
			)
		}

		// Create and run executor with UI callbacks
		executor := core.NewExecutor(core.ExecutorConfig{
			TargetURL:     currentTarget,
			Concurrency:   cfg.Concurrency,
			RateLimit:     cfg.RateLimit,
			Timeout:       cfg.Timeout,
			Retries:       cfg.Retries,
			Filter:        buildFilterConfig(cfg),
			RealisticMode: cfg.RealisticMode,
			AutoCalibrate: cfg.RealisticMode && cfg.AutoCalibration,
			// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
			OnResult: func(result *output.TestResult) {
				// Emit every test result for complete telemetry
				if runDispCtx != nil {
					blocked := result.Outcome == "Blocked"
					_ = runDispCtx.EmitResult(ctx, result.Category, result.Severity, blocked, result.StatusCode, float64(result.LatencyMs))
				}
				// Additionally emit bypass event for non-blocked results
				// Skip "Skipped" payloads — they're host-unreachable, not bypasses
				if runDispCtx != nil && result.Outcome != "Blocked" && result.Outcome != "Error" && result.Outcome != "Skipped" {
					_ = runDispCtx.EmitBypass(ctx, result.Category, result.Severity, result.RequestURL, result.Payload, result.StatusCode)
				}
			},
		})

		// Start progress display (skip if silent)
		if !cfg.Silent {
			progress.Start()
		}

		results := executor.ExecuteWithProgress(ctx, allPayloads, writer, progress)

		// Stop progress display
		if !cfg.Silent {
			progress.Stop()
		}

		// Print summary (skip if silent)
		if !cfg.Silent {
			ui.PrintSummary(ui.Summary{
				TotalTests:     results.TotalTests,
				BlockedTests:   results.BlockedTests,
				PassedTests:    results.PassedTests,
				FailedTests:    results.FailedTests,
				ErrorTests:     results.ErrorTests,
				HostsSkipped:   results.HostsSkipped,
				Duration:       results.Duration,
				RequestsPerSec: results.RequestsPerSec,
				TargetURL:      currentTarget,
				Category:       cfg.Category,
				Severity:       cfg.Severity,
			})

			// Print enhanced stats (nuclei-style status codes, severity breakdown)
			output.PrintSummary(results)
		}

		// Close writer to flush output
		writer.Close()

		// Save results if output file specified
		if outputFile != "" && !cfg.Silent {
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", outputFile))
		}

		// Aggregate results
		aggregatedResults.TotalTests += results.TotalTests
		aggregatedResults.BlockedTests += results.BlockedTests
		aggregatedResults.PassedTests += results.PassedTests
		aggregatedResults.FailedTests += results.FailedTests
		aggregatedResults.ErrorTests += results.ErrorTests
		aggregatedResults.HostsSkipped += results.HostsSkipped
		aggregatedResults.Duration += results.Duration

		// Add spacing between targets
		if totalTargets > 1 && targetIdx < totalTargets-1 && !cfg.Silent {
			fmt.Fprintln(os.Stderr)
		}
	}

	// Print aggregated summary for multi-target
	if totalTargets > 1 && !cfg.Silent {
		fmt.Fprintln(os.Stderr)
		ui.PrintSection("Aggregated Results (All Targets)")
		aggregatedResults.RequestsPerSec = float64(aggregatedResults.TotalTests) / aggregatedResults.Duration.Seconds()
		ui.PrintSummary(ui.Summary{
			TotalTests:     aggregatedResults.TotalTests,
			BlockedTests:   aggregatedResults.BlockedTests,
			PassedTests:    aggregatedResults.PassedTests,
			FailedTests:    aggregatedResults.FailedTests,
			ErrorTests:     aggregatedResults.ErrorTests,
			HostsSkipped:   aggregatedResults.HostsSkipped,
			Duration:       aggregatedResults.Duration,
			RequestsPerSec: aggregatedResults.RequestsPerSec,
			TargetURL:      fmt.Sprintf("%d targets", totalTargets),
			Category:       cfg.Category,
			Severity:       cfg.Severity,
		})
		output.PrintSummary(aggregatedResults)
	}

	// Handle enterprise exports if configured
	if outputFlags.HasEnterpriseExports() {
		if !cfg.Silent {
			outputFlags.PrintOutputConfig()
		}
		if err := outputFlags.WriteEnterpriseExports(aggregatedResults); err != nil {
			ui.PrintError(fmt.Sprintf("Error writing enterprise exports: %v", err))
		}
	}

	// Determine exit code using policy and baseline (CI/CD gating)
	exitCode := 0

	// Policy evaluation takes precedence
	if pol != nil {
		// Build SummaryData from aggregated results
		summaryData := policy.SummaryData{
			TotalBypasses:      aggregatedResults.PassedTests, // Bypasses = passed tests (WAF didn't block)
			TotalTests:         aggregatedResults.TotalTests,
			TotalErrors:        aggregatedResults.ErrorTests,
			BypassesBySeverity: aggregatedResults.SeverityBreakdown,
			BypassesByCategory: aggregatedResults.CategoryBreakdown,
			Effectiveness:      float64(aggregatedResults.BlockedTests) / float64(aggregatedResults.TotalTests) * 100,
			ErrorRate:          float64(aggregatedResults.ErrorTests) / float64(aggregatedResults.TotalTests) * 100,
		}
		policyResult := pol.Evaluate(summaryData)
		if !policyResult.Pass {
			if !cfg.Silent {
				ui.PrintError(fmt.Sprintf("Policy violations: %v", policyResult.Failures))
			}
			// Emit policy violations to hooks
			if runDispCtx != nil {
				for _, failure := range policyResult.Failures {
					_ = runDispCtx.EmitBypass(ctx, "policy-violation", "critical", cfg.TargetURL, failure, 0)
				}
			}
			exitCode = policyResult.ExitCode
		} else if !cfg.Silent {
			ui.PrintSuccess("Policy check passed")
		}
	}

	// Baseline regression detection
	if bl != nil && exitCode == 0 {
		// Convert bypass details to baseline entries for comparison
		currentBypasses := make([]baseline.BypassEntry, len(aggregatedResults.BypassDetails))
		for i, d := range aggregatedResults.BypassDetails {
			currentBypasses[i] = baseline.BypassEntry{
				ID:          d.PayloadID,
				Category:    d.Category,
				Severity:    d.Severity,
				TargetPath:  d.Endpoint,
				PayloadHash: d.Payload, // Use payload as hash for comparison
			}
		}
		comparison := bl.Compare(currentBypasses)
		if comparison.HasNewBypasses {
			if !cfg.Silent {
				ui.PrintError(fmt.Sprintf("Baseline regression: %d new bypass(es) detected", len(comparison.NewBypasses)))
				for _, r := range comparison.NewBypasses {
					ui.PrintWarning(fmt.Sprintf("  - %s (%s)", r.ID, r.Category))
				}
			}
			// Emit baseline regression events to hooks
			if runDispCtx != nil {
				for _, r := range comparison.NewBypasses {
					regDesc := fmt.Sprintf("Baseline regression: new bypass %s (%s)", r.ID, r.Category)
					_ = runDispCtx.EmitBypass(ctx, "baseline-regression", "critical", cfg.TargetURL, regDesc, 0)
				}
			}
			exitCode = 2 // Different exit code for regressions
		} else if !cfg.Silent {
			ui.PrintSuccess(fmt.Sprintf("No baseline regressions: %s", comparison.Summary))
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER SUMMARY EMISSION
	// ═══════════════════════════════════════════════════════════════════════════
	// Notify all hooks (Slack, Teams, PagerDuty, OTEL, etc.) that test run is complete
	if runDispCtx != nil {
		_ = runDispCtx.EmitSummary(ctx, int(aggregatedResults.TotalTests), int(aggregatedResults.BlockedTests), int(aggregatedResults.FailedTests), aggregatedResults.Duration)
	}

	// Default exit logic if no policy/baseline configured
	if pol == nil && bl == nil && aggregatedResults.FailedTests > 0 {
		exitCode = 1
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
