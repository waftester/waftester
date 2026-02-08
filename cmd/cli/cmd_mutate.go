package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
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
// MUTATION ENGINE COMMAND
// =============================================================================

func runMutate() {
	ui.PrintCompactBanner()
	ui.PrintSection("Mutation Engine - Full Coverage WAF Testing")

	mutateFlags := flag.NewFlagSet("mutate", flag.ExitOnError)

	// Target
	target := mutateFlags.String("target", "", "Target URL to test")
	targetShort := mutateFlags.String("u", "", "Target URL (shorthand)")

	// Payload source
	payloadDir := mutateFlags.String("payloads", defaults.PayloadDir, "Payload directory")
	category := mutateFlags.String("category", "", "Filter payload category (sqli, xss, etc.)")
	payloadFile := mutateFlags.String("payload-file", "", "Single payload file to use")
	rawPayload := mutateFlags.String("payload", "", "Single raw payload to test")

	// Mutation settings
	mode := mutateFlags.String("mode", "quick", "Mutation mode: quick, standard, full, bypass")
	encoders := mutateFlags.String("encoders", "", "Comma-separated encoders (url,double_url,utf7,...)")
	locations := mutateFlags.String("locations", "", "Comma-separated locations (query_param,post_json,...)")
	evasions := mutateFlags.String("evasions", "", "Comma-separated evasions (case_swap,sql_comment,...)")
	chainEncodings := mutateFlags.Bool("chain", false, "Chain multiple encodings together")

	// Execution
	concurrency := mutateFlags.Int("c", 10, "Concurrency")
	rateLimit := mutateFlags.Float64("rl", 50, "Rate limit (requests/sec)")
	timeout := mutateFlags.Int("timeout", 10, "Timeout in seconds")
	skipVerify := mutateFlags.Bool("k", false, "Skip TLS verification")

	// Realistic mode (intelligent block detection)
	realisticMode := mutateFlags.Bool("realistic", false, "Use intelligent block detection + realistic headers")
	realisticShort := mutateFlags.Bool("R", false, "Realistic mode (shorthand)")
	autoCalibrate := mutateFlags.Bool("ac", false, "Auto-calibrate baseline before testing")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := mutateFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := mutateFlags.String("smart-mode", "", "Override mutation mode with smart optimization: quick, standard, full, bypass, stealth")
	smartVerbose := mutateFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// Output
	outputFile := mutateFlags.String("o", "", "Output file (JSON)")
	verbose := mutateFlags.Bool("v", false, "Verbose output")
	showStats := mutateFlags.Bool("stats", false, "Show mutation registry stats only")
	dryRun := mutateFlags.Bool("dry-run", false, "Show what would be tested without executing")

	// Streaming mode (CI-friendly output)
	streamMode := mutateFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	// Enterprise hook flags (Slack, Teams, PagerDuty, OTEL, etc.)
	slackWebhook := mutateFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	teamsWebhook := mutateFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	pagerdutyKey := mutateFlags.String("pagerduty-key", "", "PagerDuty routing key")
	otelEndpoint := mutateFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	webhookURL := mutateFlags.String("webhook-url", "", "Generic webhook URL")

	// Detection (v2.5.2)
	noDetect := mutateFlags.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	mutateFlags.Parse(os.Args[2:])

	// Disable detection if requested
	if *noDetect {
		detection.Disable()
	}

	// Resolve target
	targetURL := *target
	if targetURL == "" {
		targetURL = *targetShort
	}

	// Show stats only
	if *showStats {
		printMutationStats()
		return
	}

	if targetURL == "" && !*dryRun {
		ui.PrintError("Target URL required. Use -target or -u")
		os.Exit(1)
	}

	// Setup context for smart mode detection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Smart Mode: Detect WAF and optimize configuration
	var smartResult *SmartModeResult
	effectiveMode := *mode
	if *smartMode && targetURL != "" {
		ui.PrintSection("🧠 Smart Mode: WAF Detection & Optimization")
		fmt.Println()

		smartModeValue := *smartModeType
		if smartModeValue == "" {
			smartModeValue = *mode // Use the -mode flag value if smart-mode not specified
		}

		smartConfig := &SmartModeConfig{
			DetectionTimeout: time.Duration(*timeout) * time.Second,
			Verbose:          *smartVerbose,
			Mode:             smartModeValue,
		}

		var err error
		smartResult, err = DetectAndOptimize(ctx, targetURL, smartConfig)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", err))
		}

		PrintSmartModeInfo(smartResult, *smartVerbose)
		effectiveMode = "smart:" + smartModeValue
	}
	// Silence unused variable warnings
	_ = smartVerbose
	_ = smartModeType

	// Configure executor
	cfg := mutation.DefaultExecutorConfig()
	cfg.TargetURL = targetURL
	cfg.Concurrency = *concurrency
	cfg.RateLimit = *rateLimit
	cfg.Timeout = time.Duration(*timeout) * time.Second
	cfg.SkipVerify = *skipVerify
	cfg.RealisticMode = *realisticMode || *realisticShort || *smartMode
	cfg.AutoCalibrate = *autoCalibrate || *smartMode

	// Apply smart mode optimizations first
	if *smartMode && smartResult != nil {
		ApplySmartConfig(cfg, smartResult)
		ui.PrintInfo(fmt.Sprintf("📊 WAF-optimized: %d encoders, %d evasions, %.0f req/sec",
			len(cfg.Pipeline.Encoders), len(cfg.Pipeline.Evasions), cfg.RateLimit))
		fmt.Println()
	} else {
		// Configure pipeline based on mode (only if not using smart mode)
		switch *mode {
		case "quick":
			cfg.Pipeline = &mutation.PipelineConfig{
				Encoders:   []string{"raw", "url", "double_url"},
				Locations:  []string{"query_param", "post_form", "post_json"},
				Evasions:   []string{},
				IncludeRaw: true,
			}
		case "standard":
			cfg.Pipeline = mutation.DefaultPipelineConfig()
		case "full":
			cfg.Pipeline = mutation.FullCoveragePipelineConfig()
		case "bypass":
			cfg.Pipeline = &mutation.PipelineConfig{
				Encoders: []string{
					"raw", "url", "double_url", "triple_url",
					"overlong_utf8", "wide_gbk", "utf7",
					"html_decimal", "html_hex", "mixed",
				},
				Locations: []string{
					"query_param", "post_form", "post_json",
					"header_xforward", "cookie", "path_segment",
				},
				Evasions: []string{
					"case_swap", "sql_comment", "whitespace_alt",
					"null_byte", "hpp", "unicode_normalize",
				},
				ChainEncodings: true,
				MaxChainDepth:  2,
				IncludeRaw:     true,
			}
		}
	} // End of else block for non-smart mode

	// Override with explicit settings
	if *encoders != "" {
		cfg.Pipeline.Encoders = strings.Split(*encoders, ",")
	}
	if *locations != "" {
		cfg.Pipeline.Locations = strings.Split(*locations, ",")
	}
	if *evasions != "" {
		cfg.Pipeline.Evasions = strings.Split(*evasions, ",")
	}
	if *chainEncodings {
		cfg.Pipeline.ChainEncodings = true
	}

	// Print config
	ui.PrintConfigLine("Target", targetURL)
	ui.PrintConfigLine("Mode", effectiveMode)
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", cfg.Concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%.0f req/sec", cfg.RateLimit))
	fmt.Println()

	// Load payloads
	var testPayloads []string
	if *rawPayload != "" {
		testPayloads = []string{*rawPayload}
		ui.PrintConfigLine("Payload", "Single raw payload")
	} else if *payloadFile != "" {
		// Load from specific file
		content, err := os.ReadFile(*payloadFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot read payload file: %v", err))
			os.Exit(1)
		}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				testPayloads = append(testPayloads, line)
			}
		}
		ui.PrintConfigLine("Payload File", *payloadFile)
		ui.PrintConfigLine("Payloads Loaded", fmt.Sprintf("%d", len(testPayloads)))
	} else {
		// Load from unified payload engine (JSON + Nuclei templates)
		allPayloads, _, err := loadUnifiedPayloads(*payloadDir, defaults.TemplateDir, *verbose)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot load payloads: %v", err))
			os.Exit(1)
		}

		// Filter by category if specified
		if *category != "" {
			filtered := payloads.Filter(allPayloads, *category, "")
			for _, p := range filtered {
				testPayloads = append(testPayloads, p.Payload)
			}
			ui.PrintConfigLine("Category", *category)
		} else {
			for _, p := range allPayloads {
				testPayloads = append(testPayloads, p.Payload)
			}
		}
		ui.PrintConfigLine("Payloads Dir", *payloadDir)
		ui.PrintConfigLine("Payloads Loaded", fmt.Sprintf("%d", len(testPayloads)))
	}

	// Create executor
	executor := mutation.NewExecutor(cfg)

	// Generate tasks
	tasks := executor.GenerateTasks(testPayloads, nil)
	ui.PrintConfigLine("Total Mutations", fmt.Sprintf("%d", len(tasks)))
	fmt.Println()

	// Dry run - just show what would be tested
	if *dryRun {
		ui.PrintSection("Dry Run - Sample Mutations")
		shown := 0
		for _, task := range tasks {
			if shown >= 20 {
				fmt.Printf("  ... and %d more\n", len(tasks)-20)
				break
			}
			evasion := ""
			if task.Evasion != nil {
				evasion = " + " + task.Evasion.MutatorName
			}
			fmt.Printf("  [%s] [%s]%s: %.50s...\n",
				task.EncodedPayload.MutatorName,
				task.Location.MutatorName,
				evasion,
				task.EncodedPayload.Mutated)
			shown++
		}
		return
	}

	// Context already created for smart mode detection above

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\n\nInterrupted, shutting down...")
		cancel()
	}()

	// Output writer
	var writer *json.Encoder
	var outputFh *os.File
	if *outputFile != "" {
		var err error
		outputFh, err = os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot create output file: %v", err))
			os.Exit(1)
		}
		defer outputFh.Close()
		writer = json.NewEncoder(outputFh)
	}

	// Initialize dispatcher for hooks (Slack, Teams, PagerDuty, OTEL, etc.)
	mutateOutputFlags := OutputFlags{
		SlackWebhook: *slackWebhook,
		TeamsWebhook: *teamsWebhook,
		PagerDutyKey: *pagerdutyKey,
		OTelEndpoint: *otelEndpoint,
		WebhookURL:   *webhookURL,
	}
	mutateScanID := fmt.Sprintf("mutate-%d", time.Now().Unix())
	mutateDispCtx, mutateDispErr := mutateOutputFlags.InitDispatcher(mutateScanID, targetURL)
	if mutateDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", mutateDispErr))
	}
	if mutateDispCtx != nil {
		defer mutateDispCtx.Close()
		mutateDispCtx.RegisterDetectionCallbacks(ctx)
	}
	mutateStartTime := time.Now()

	// Emit start event for scan lifecycle hooks
	if mutateDispCtx != nil {
		_ = mutateDispCtx.EmitStart(ctx, targetURL, 0, *concurrency, nil)
	}

	// Emit smart mode WAF detection to hooks (after dispatcher is initialized)
	if mutateDispCtx != nil && smartResult != nil && smartResult.WAFDetected {
		wafDesc := fmt.Sprintf("Smart mode detected: %s (%.0f%% confidence)", smartResult.VendorName, smartResult.Confidence*100)
		_ = mutateDispCtx.EmitBypass(ctx, "smart-waf-detection", "info", targetURL, wafDesc, 0)
		// Emit bypass hints as actionable intelligence
		for _, hint := range smartResult.BypassHints {
			_ = mutateDispCtx.EmitBypass(ctx, "bypass-hint", "info", targetURL, hint, 0)
		}
	}

	// Run tests with live progress
	ui.PrintSection("🔥 WAF Bypass Hunt")

	// Determine WAF name for display
	wafName := "Unknown WAF"
	if smartResult != nil && smartResult.WAFDetected {
		wafName = smartResult.VendorName
	}
	fmt.Printf("  Target: %s (%s)\n", targetURL, wafName)
	fmt.Printf("  Mutations: %d | Mode: %s\n\n", len(tasks), effectiveMode)

	// Determine output mode for progress
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Use unified LiveProgress
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        len(tasks),
		DisplayLines: 4,
		Title:        "Mutation testing",
		Unit:         "mutations",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "bypasses", Label: "Bypasses", Icon: "🔓", Highlight: true},
			{Name: "blocked", Label: "Blocked", Icon: "🛡️"},
			{Name: "errors", Label: "Errors", Icon: "⚠️"},
		},
		Tips: []string{
			"💡 Chunked encoding can split payloads to evade pattern matching",
			"💡 Most WAFs can't properly normalize Unicode in all contexts",
			"💡 Encoders combined with evasions multiply your test coverage",
			"💡 Parameter pollution bypasses 30%+ of WAFs",
			"💡 Case variations alone find bypasses in 1 out of 5 WAFs",
			"💡 SQL comments /**/ can hide entire payload chunks",
		},
		StreamFormat:   "[PROGRESS] {completed}/{total} ({percent}%) | bypasses: {metric:bypasses} | blocked: {metric:blocked} | {status} | {elapsed}",
		StreamInterval: duration.StreamStd,
	})
	progress.Start()
	defer progress.Stop()

	// Execute mutation tests
	stats := executor.Execute(ctx, tasks, func(r *mutation.TestResult) {
		// Update progress and metrics
		progress.Increment()

		// Emit every test result for complete telemetry
		if mutateDispCtx != nil {
			category := "mutation"
			if r.EvasionUsed != "" {
				category = "mutation-" + r.EvasionUsed
			}
			_ = mutateDispCtx.EmitResult(ctx, category, "high", r.Blocked, r.StatusCode, float64(r.LatencyMs))
		}

		if r.Blocked {
			progress.AddMetric("blocked")
		} else if r.ErrorMessage != "" {
			progress.AddMetric("errors")
		} else {
			progress.AddMetric("bypasses")
			// Update status with last bypass info
			encoder := r.EncoderUsed
			if r.EvasionUsed != "" {
				encoder += "+" + r.EvasionUsed
			}
			progress.SetStatus(fmt.Sprintf("bypass: %s", encoder))

			// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
			if mutateDispCtx != nil {
				category := "mutation-bypass"
				if r.EvasionUsed != "" {
					category = "mutation-bypass-" + r.EvasionUsed
				}
				_ = mutateDispCtx.EmitBypass(ctx, category, "high", r.URL, r.MutatedPayload, r.StatusCode)
			}
		}

		// Write to output file
		if writer != nil {
			writer.Encode(r)
		}

		// Verbose output
		if *verbose {
			status := "✓"
			if r.Blocked {
				status = "✗"
			} else if r.ErrorMessage != "" {
				status = "!"
			}
			fmt.Printf("  [%s] %s | %s | %s | %dms\n",
				status, r.EncoderUsed, r.LocationUsed, r.EvasionUsed, r.LatencyMs)
		}
	})

	// Print final results with celebration or commiseration
	fmt.Println()
	fmt.Println("  ═══════════════════════════════════════════════════════════")

	if stats.Passed > 0 {
		if stats.Passed > 20 {
			fmt.Printf("  🏆 \033[1;33mLEGENDARY! %d BYPASSES FOUND!\033[0m 🏆\n", stats.Passed)
		} else if stats.Passed > 10 {
			fmt.Printf("  🔥 \033[1;33mON FIRE! %d BYPASSES FOUND!\033[0m 🔥\n", stats.Passed)
		} else if stats.Passed > 5 {
			fmt.Printf("  ⚡ \033[1;33mNICE! %d BYPASSES FOUND!\033[0m ⚡\n", stats.Passed)
		} else {
			fmt.Printf("  🎯 \033[1;32m%d BYPASS(ES) FOUND!\033[0m\n", stats.Passed)
		}
	} else {
		fmt.Printf("  🛡️ \033[1;36mWAF held strong - no bypasses found\033[0m\n")
	}

	fmt.Println("  ═══════════════════════════════════════════════════════════")
	fmt.Println()

	fmt.Printf("  📊 \033[1mFinal Stats:\033[0m\n")
	fmt.Printf("     • Total Tests:   %d\n", stats.TotalTests)
	fmt.Printf("     • Bypasses:      \033[32m%d\033[0m (%.1f%%)\n", stats.Passed, float64(stats.Passed)/float64(stats.TotalTests)*100)
	fmt.Printf("     • Blocked:       \033[31m%d\033[0m (%.1f%%)\n", stats.Blocked, float64(stats.Blocked)/float64(stats.TotalTests)*100)
	fmt.Printf("     • Errors:        %d\n", stats.Errors)
	fmt.Printf("     • Duration:      %s\n", stats.Duration.Round(time.Millisecond))
	fmt.Printf("     • Throughput:    %.1f req/s\n", stats.RequestsPerSec)
	fmt.Println()

	// Top encoders if bypasses found
	if stats.Passed > 0 && len(stats.ByEncoder) > 0 {
		fmt.Printf("  🎯 \033[1mEffective Encoders:\033[0m\n")
		for enc, count := range stats.ByEncoder {
			if count > 0 {
				fmt.Printf("     • %-20s %d hits\n", enc, count)
			}
		}
		fmt.Println()
	}

	if *outputFile != "" {
		ui.PrintSuccess(fmt.Sprintf("Results written to %s", *outputFile))
	}

	// Emit summary to hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
	if mutateDispCtx != nil {
		_ = mutateDispCtx.EmitSummary(ctx, int(stats.TotalTests), int(stats.Blocked), int(stats.Passed), time.Since(mutateStartTime))
	}

	// Final message
	if stats.Passed > 0 {
		ui.PrintWarning(fmt.Sprintf("⚠️  %d potential WAF bypasses need investigation!", stats.Passed))
	} else {
		ui.PrintSuccess("✓ WAF blocked all mutation attempts")
	}
}

// formatETA formats a duration for ETA display
func formatETA(d time.Duration) string {
	if d <= 0 {
		return "calculating..."
	}
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

// sanitizeForDisplay removes newlines and control characters for single-line display
func sanitizeForDisplay(s string) string {
	// Replace common problematic characters
	s = strings.ReplaceAll(s, "\r\n", "↵")
	s = strings.ReplaceAll(s, "\n", "↵")
	s = strings.ReplaceAll(s, "\r", "↵")
	s = strings.ReplaceAll(s, "\t", "→")
	s = strings.ReplaceAll(s, "\x00", "∅")

	// Remove other control characters
	var result strings.Builder
	for _, r := range s {
		if r >= 32 || r == '↵' || r == '→' || r == '∅' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// printMutationStats displays mutation registry statistics
func printMutationStats() {
	ui.PrintSection("Mutation Registry Statistics")

	// Create temporary executor to get stats
	executor := mutation.NewExecutor(nil)
	stats := executor.GetStats()

	fmt.Printf("  Encoders:   %d registered\n", stats["encoders"])
	fmt.Printf("  Locations:  %d registered\n", stats["locations"])
	fmt.Printf("  Evasions:   %d registered\n", stats["evasions"])
	fmt.Printf("  Protocols:  %d registered\n", stats["protocols"])
	fmt.Printf("  Total:      %d mutators\n", stats["total"])
	fmt.Println()

	// List all registered mutators
	reg := mutation.DefaultRegistry
	categories := reg.Categories()

	for _, cat := range categories {
		ui.PrintSection(strings.Title(cat) + " Mutators")
		mutators := reg.GetByCategory(cat)
		for _, m := range mutators {
			fmt.Printf("  %-25s %s\n", m.Name(), m.Description())
		}
		fmt.Println()
	}

	// Show example combinations
	ui.PrintSection("Example Coverage Calculation")
	fmt.Println("  For 100 payloads with default pipeline:")
	fmt.Printf("    Quick mode:    ~%d tests\n", 100*3*3)
	fmt.Printf("    Standard mode: ~%d tests\n", 100*stats["encoders"]*3)
	fmt.Printf("    Full mode:     ~%d tests\n", 100*stats["encoders"]*stats["locations"]*(1+stats["evasions"]))
}
