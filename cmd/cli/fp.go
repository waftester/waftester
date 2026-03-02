// cmd/cli/fp.go - False Positive Testing Command
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/fp"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/strutil"
	"github.com/waftester/waftester/pkg/ui"
)

// runFP executes the false positive testing command
func runFP() {
	ui.PrintCompactBanner()
	ui.PrintSection("False Positive Testing")

	fpFlags := flag.NewFlagSet("fp", flag.ExitOnError)

	// Required
	target := fpFlags.String("u", "", "Target URL to test")

	// Optional
	concurrency := fpFlags.Int("c", 5, "Number of concurrent workers")
	rateLimit := fpFlags.Float64("rate", 10.0, "Requests per second limit")
	timeout := fpFlags.Int("timeout", 10, "Request timeout in seconds")
	paranoiaLevel := fpFlags.Int("pl", 2, "OWASP CRS paranoia level (1-4)")

	// Corpus options
	corpusSources := fpFlags.String("corpus", "all", "Corpus sources: all,leipzig,edge,forms,api,tech,intl")
	dynamicCorpus := fpFlags.String("dynamic", "", "File with dynamic corpus (extracted from target)")

	// Output
	output := fpFlags.String("output", "", "Output file for results (JSON)")
	verbose := fpFlags.Bool("v", false, "Verbose output")
	streamMode := fpFlags.Bool("stream", false, "Streaming output mode (for CI/scripts)")

	// Local WAF testing
	localTest := fpFlags.Bool("local", false, "Run local WAF simulation test")

	// Enterprise hook flags
	fpSlack := fpFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	fpTeams := fpFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	fpPagerDuty := fpFlags.String("pagerduty-key", "", "PagerDuty routing key")
	fpOtel := fpFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	fpWebhook := fpFlags.String("webhook-url", "", "Generic webhook URL")

	fpFlags.Parse(os.Args[2:])

	// Validate required args
	if *target == "" && !*localTest {
		ui.PrintError("Target URL required. Use -u <url> or -local for local testing.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage: waf-tester fp -u <url> [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -u <url>        Target URL to test")
		fmt.Fprintln(os.Stderr, "  -c <n>          Concurrency (default: 5)")
		fmt.Fprintln(os.Stderr, "  -rate <n>       Rate limit requests/sec (default: 10)")
		fmt.Fprintln(os.Stderr, "  -pl <1-4>       Paranoia level (default: 2)")
		fmt.Fprintln(os.Stderr, "  -corpus <src>   Corpus sources (default: all)")
		fmt.Fprintln(os.Stderr, "  -dynamic <file> Dynamic corpus file")
		fmt.Fprintln(os.Stderr, "  -output <file>  Output results to JSON")
		fmt.Fprintln(os.Stderr, "  -stream         Streaming output (for CI/scripts)")
		fmt.Fprintln(os.Stderr, "  -local          Run local WAF simulation only")
		fmt.Fprintln(os.Stderr, "  -v              Verbose output")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", *target)
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%.1f req/s", *rateLimit))
	ui.PrintConfigLine("Paranoia Level", fmt.Sprintf("%d", *paranoiaLevel))
	ui.PrintConfigLine("Corpus", *corpusSources)
	fmt.Fprintln(os.Stderr)

	// Local WAF test
	if *localTest {
		runLocalFPTest(*paranoiaLevel, *verbose)
		return
	}

	// Build configuration
	config := &fp.Config{
		Base: attackconfig.Base{
			Concurrency: *concurrency,
			Timeout:     time.Duration(*timeout) * time.Second,
		},
		TargetURL:     *target,
		RateLimit:     *rateLimit,
		ParanoiaLevel: *paranoiaLevel,
		CorpusSources: parseCorpusSources(*corpusSources),
		Verbose:       *verbose,
	}

	// Create tester
	tester := fp.NewTester(config)

	// Load dynamic corpus if provided
	if *dynamicCorpus != "" {
		ui.PrintInfo("Loading dynamic corpus from " + *dynamicCorpus)
		if err := loadDynamicCorpus(tester, *dynamicCorpus); err != nil {
			ui.PrintWarning(fmt.Sprintf("Could not load dynamic corpus: %v", err))
		}
	}

	// Get corpus count for manifest display
	corpusCount := tester.GetCorpus().Count()

	// Display execution manifest BEFORE running (only in interactive mode)
	if !*streamMode {
		manifest := ui.NewExecutionManifest("FALSE POSITIVE TEST MANIFEST")
		manifest.SetDescription("Testing benign content against WAF rules")
		manifest.AddWithIcon("🎯", "Target", *target)
		manifest.AddEmphasis("📦", "Test Cases", fmt.Sprintf("%d benign payloads", corpusCount))
		manifest.AddWithIcon("🏷️", "Corpus", *corpusSources)
		manifest.AddWithIcon("🔒", "Paranoia Level", fmt.Sprintf("PL%d", *paranoiaLevel))
		manifest.AddWithIcon("⚡", "Concurrency", fmt.Sprintf("%d workers", *concurrency))
		manifest.AddWithIcon("🚦", "Rate Limit", fmt.Sprintf("%.0f req/s", *rateLimit))
		manifest.AddEstimate(corpusCount, *rateLimit)
		manifest.Print()
	} else {
		// Streaming mode: simple line output for CI/scripts
		fmt.Fprintf(os.Stderr, "[INFO] Starting false positive test: target=%s payloads=%d concurrency=%d rate=%.0f\n",
			*target, corpusCount, *concurrency, *rateLimit)
	}

	// Initialize dispatcher for hooks
	fpOutputFlags := OutputFlags{
		SlackWebhook: *fpSlack,
		TeamsWebhook: *fpTeams,
		PagerDutyKey: *fpPagerDuty,
		OTelEndpoint: *fpOtel,
		WebhookURL:   *fpWebhook,
	}
	fpScanID := fmt.Sprintf("fp-%d", time.Now().Unix())
	fpDispCtx, fpDispErr := fpOutputFlags.InitDispatcher(fpScanID, *target)
	if fpDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", fpDispErr))
	}
	if fpDispCtx != nil {
		defer fpDispCtx.Close()
	}
	fpCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if fpDispCtx != nil {
		_ = fpDispCtx.EmitStart(fpCtx, *target, corpusCount, *concurrency, nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration.ContextMax)
	defer cancel()

	// Determine output mode
	outputMode := ui.DefaultOutputMode()
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Use unified LiveProgress component
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        corpusCount,
		DisplayLines: 2,
		Title:        "Testing false positives",
		Unit:         "tests",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "fps", Label: "FPs", Icon: ui.Icon("⚠️", "!"), Highlight: true},
		},
		StreamFormat: "[PROGRESS] {completed}/{total} ({percent}%) - {metrics} - {elapsed} elapsed",
	})

	progress.Start()

	// Wire progress callback so LiveProgress updates in real time
	tester.ProgressFn = func(completed, total int) {
		progress.SetTotal(total)
		progress.SetCompleted(completed)
	}

	// Run tests
	result, err := tester.Run(ctx)

	// Stop progress display
	progress.Stop()

	if err != nil {
		// Emit error to hooks
		if fpDispCtx != nil {
			_ = fpDispCtx.EmitError(fpCtx, "fp", fmt.Sprintf("FP test error: %v", err), true)
			_ = fpDispCtx.Close()
		}
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	// Show completion summary
	elapsed := progress.GetElapsed()
	if *streamMode {
		fmt.Fprintf(os.Stderr, "[COMPLETE] %d tests in %s, FPs=%d\n", result.TotalTests, duration.FormatCompact(elapsed), result.FalsePositives)
	} else {
		ui.Printf("  %s Completed %d tests in %s\n", ui.Icon("\u2705", "+"), result.TotalTests, duration.FormatCompact(elapsed))
		if result.FalsePositives > 0 {
			if ui.StdoutIsTerminal() {
				ui.Printf("  %s  \033[31m%d false positives detected\033[0m\n", ui.Icon("\u26a0\ufe0f", "!"), result.FalsePositives)
			} else {
				ui.Printf("  %s  %d false positives detected\n", ui.Icon("\u26a0\ufe0f", "!"), result.FalsePositives)
			}
		} else {
			if ui.StdoutIsTerminal() {
				ui.Printf("  %s \033[32mNo false positives detected\033[0m\n", ui.Icon("\u2728", "+"))
			} else {
				ui.Printf("  %s No false positives detected\n", ui.Icon("\u2728", "+"))
			}
		}
		fmt.Fprintln(os.Stderr)

		// Display results
		displayFPResults(result)
	}

	// Save to file if requested
	if *output != "" {
		if err := iohelper.WriteAtomicJSON(*output, result, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Error saving output: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *output))
		}
	}

	// Emit FP findings and summary to hooks
	if fpDispCtx != nil {
		if result.FalsePositives > 0 {
			fpDesc := fmt.Sprintf("%d false positives detected at PL%d", result.FalsePositives, *paranoiaLevel)
			_ = fpDispCtx.EmitBypass(fpCtx, "false-positive-detected", "medium", *target, fpDesc, 0)

			// Emit individual FP details
			for _, fpDetail := range result.FalsePositiveDetails {
				detailDesc := fmt.Sprintf("False positive: %s blocked at %s (rule %d)",
					strutil.Truncate(fpDetail.Payload, 80), fpDetail.Location, fpDetail.RuleID)
				_ = fpDispCtx.EmitBypass(fpCtx, "false-positive-detail", "medium", *target, detailDesc, fpDetail.StatusCode)
			}
		}

		// Emit FP rating (critical if >10%)
		if result.FPRatio >= 0.10 {
			ratingDesc := fmt.Sprintf("CRITICAL FP rate: %.1f%% (>10%%) - significant tuning required", result.FPRatio*100)
			_ = fpDispCtx.EmitBypass(fpCtx, "fp-rating-critical", "critical", *target, ratingDesc, 0)
		} else if result.FPRatio >= 0.05 {
			ratingDesc := fmt.Sprintf("POOR FP rate: %.1f%% (5-10%%) - needs tuning", result.FPRatio*100)
			_ = fpDispCtx.EmitBypass(fpCtx, "fp-rating-poor", "high", *target, ratingDesc, 0)
		}

		_ = fpDispCtx.EmitSummary(fpCtx, int(result.TotalTests), int(result.FalsePositives), int(result.TotalTests-result.FalsePositives), elapsed)
	}
}

func parseCorpusSources(sources string) []string {
	if sources == "all" {
		return []string{"leipzig", "edge", "forms", "api", "tech", "intl"}
	}
	return strutil.SplitTrimmed(sources, ",")
}

func loadDynamicCorpus(tester *fp.Tester, filename string) error {
	var payloads []string
	if err := iohelper.ReadJSON(filename, &payloads); err != nil {
		// Not valid JSON array — try line-by-line text format
		data, readErr := os.ReadFile(filename)
		if readErr != nil {
			return fmt.Errorf("read corpus %s: %w", filename, readErr)
		}
		payloads = strutil.SplitTrimmed(string(data), "\n")
	}

	tester.GetCorpus().AddDynamicCorpus(payloads)
	return nil
}

func displayFPResults(result *fp.Result) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, ui.SectionStyle.Render("FALSE POSITIVE ANALYSIS RESULTS"))
	fmt.Fprintln(os.Stderr)

	// Summary box
	if ui.UnicodeTerminal() {
		fmt.Fprintln(os.Stderr, "╔══════════════════════════════════════════════════════════════╗")
		fmt.Fprintln(os.Stderr, "║                    FP TESTING SUMMARY                        ║")
		fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════════════════════╣")
		fmt.Fprintf(os.Stderr, "║  Total Tests:        %-40d ║\n", result.TotalTests)
		fmt.Fprintf(os.Stderr, "║  False Positives:    %-40d ║\n", result.FalsePositives)
		fmt.Fprintf(os.Stderr, "║  FP Rate:            %-40.2f ║\n", result.FPRatio*100)
		fmt.Fprintf(os.Stderr, "║  True Negatives:     %-40d ║\n", result.TrueNegatives)
		fmt.Fprintf(os.Stderr, "║  Errors:             %-40d ║\n", result.Errors)
		fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════════════════════╝")
	} else {
		fmt.Fprintln(os.Stderr, "+--------------------------------------------------------------+")
		fmt.Fprintln(os.Stderr, "|                    FP TESTING SUMMARY                        |")
		fmt.Fprintln(os.Stderr, "+--------------------------------------------------------------+")
		fmt.Fprintf(os.Stderr, "|  Total Tests:        %-40d |\n", result.TotalTests)
		fmt.Fprintf(os.Stderr, "|  False Positives:    %-40d |\n", result.FalsePositives)
		fmt.Fprintf(os.Stderr, "|  FP Rate:            %-40.2f |\n", result.FPRatio*100)
		fmt.Fprintf(os.Stderr, "|  True Negatives:     %-40d |\n", result.TrueNegatives)
		fmt.Fprintf(os.Stderr, "|  Errors:             %-40d |\n", result.Errors)
		fmt.Fprintln(os.Stderr, "+--------------------------------------------------------------+")
	}
	fmt.Fprintln(os.Stderr)

	// Rating
	var rating string
	switch {
	case result.FPRatio == 0:
		rating = "EXCELLENT - No false positives detected"
	case result.FPRatio < 0.01:
		rating = "GOOD - Less than 1% FP rate"
	case result.FPRatio < 0.05:
		rating = "ACCEPTABLE - Less than 5% FP rate"
	case result.FPRatio < 0.10:
		rating = "POOR - 5-10% FP rate, needs tuning"
	default:
		rating = "CRITICAL - >10% FP rate, significant tuning required"
	}
	fmt.Fprintf(os.Stderr, "Rating: %s\n\n", rating)

	// By corpus
	if len(result.ByCorpus) > 0 {
		fmt.Fprintln(os.Stderr, ui.SectionStyle.Render("FP BY CORPUS SOURCE"))
		for corpus, count := range result.ByCorpus {
			fmt.Fprintf(os.Stderr, "  %-20s %d FPs\n", corpus, count)
		}
		fmt.Fprintln(os.Stderr)
	}

	// By location
	if len(result.ByLocation) > 0 {
		fmt.Fprintln(os.Stderr, ui.SectionStyle.Render("FP BY INJECTION LOCATION"))
		for location, count := range result.ByLocation {
			fmt.Fprintf(os.Stderr, "  %-20s %d FPs\n", location, count)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Top FP details (max 10)
	if len(result.FalsePositiveDetails) > 0 {
		fmt.Fprintln(os.Stderr, ui.SectionStyle.Render("FALSE POSITIVE DETAILS"))
		maxItems := 10
		if len(result.FalsePositiveDetails) < maxItems {
			maxItems = len(result.FalsePositiveDetails)
		}
		for i := 0; i < maxItems; i++ {
			fpDetail := result.FalsePositiveDetails[i]
			fmt.Fprintf(os.Stderr, "  [%d] Payload: %s\n", i+1, strutil.Truncate(fpDetail.Payload, 60))
			fmt.Fprintf(os.Stderr, "      Location: %s | Status: %d | Rule: %d\n",
				fpDetail.Location, fpDetail.StatusCode, fpDetail.RuleID)
		}
		if len(result.FalsePositiveDetails) > maxItems {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(result.FalsePositiveDetails)-maxItems)
		}
		fmt.Fprintln(os.Stderr)
	}
}

func runLocalFPTest(paranoiaLevel int, verbose bool) {
	ui.PrintInfo("Running local WAF FP simulation...")
	fmt.Fprintln(os.Stderr)

	waf := fp.NewLocalWAF(paranoiaLevel)
	stats := waf.TestCorpus(verbose)

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, fp.FormatLocalFPReport(stats))
}

// Helper functions for progress display
func repeatChar(char string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += char
	}
	return result
}
