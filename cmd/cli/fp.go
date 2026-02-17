// cmd/cli/fp.go - False Positive Testing Command
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/fp"
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
		fmt.Println(ui.ErrorStyle.Render("Error: Target URL required. Use -u <url> or -local for local testing."))
		fmt.Println()
		fmt.Println("Usage: waf-tester fp -u <url> [options]")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -u <url>        Target URL to test")
		fmt.Println("  -c <n>          Concurrency (default: 5)")
		fmt.Println("  -rate <n>       Rate limit requests/sec (default: 10)")
		fmt.Println("  -pl <1-4>       Paranoia level (default: 2)")
		fmt.Println("  -corpus <src>   Corpus sources (default: all)")
		fmt.Println("  -dynamic <file> Dynamic corpus file")
		fmt.Println("  -output <file>  Output results to JSON")
		fmt.Println("  -stream         Streaming output (for CI/scripts)")
		fmt.Println("  -local          Run local WAF simulation only")
		fmt.Println("  -v              Verbose output")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", *target)
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%.1f req/s", *rateLimit))
	ui.PrintConfigLine("Paranoia Level", fmt.Sprintf("%d", *paranoiaLevel))
	ui.PrintConfigLine("Corpus", *corpusSources)
	fmt.Println()

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
			fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Warning: Could not load dynamic corpus: %v", err)))
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
		fmt.Printf("[INFO] Starting false positive test: target=%s payloads=%d concurrency=%d rate=%.0f\n",
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
	outputMode := ui.OutputModeInteractive
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
			{Name: "fps", Label: "FPs", Icon: "⚠️", Highlight: true},
		},
		StreamFormat: "[PROGRESS] {completed}/{total} ({percent}%) - {metrics} - {elapsed} elapsed",
	})

	progress.Start()

	// Run tests
	result, err := tester.Run(ctx)

	// Stop progress display
	progress.Stop()

	if err != nil {
		// Emit error to hooks
		if fpDispCtx != nil {
			_ = fpDispCtx.EmitError(fpCtx, "fp", fmt.Sprintf("FP test error: %v", err), true)
		}
		fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Show completion summary
	elapsed := progress.GetElapsed()
	if *streamMode {
		fmt.Printf("[COMPLETE] %d tests in %s, FPs=%d\n", result.TotalTests, formatElapsed(elapsed), result.FalsePositives)
	} else {
		fmt.Printf("  ✅ Completed %d tests in %s\n", result.TotalTests, formatElapsed(elapsed))
		if result.FalsePositives > 0 {
			fmt.Printf("  ⚠️  \033[31m%d false positives detected\033[0m\n", result.FalsePositives)
		} else {
			fmt.Printf("  ✨ \033[32mNo false positives detected\033[0m\n")
		}
		fmt.Println()

		// Display results
		displayFPResults(result)
	}

	// Save to file if requested
	if *output != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Error marshaling results: %v", err)))
		} else if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Error saving output: %v", err)))
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

		_ = fpDispCtx.EmitSummary(fpCtx, int(result.TotalTests), int(result.TotalTests-result.FalsePositives), int(result.FalsePositives), elapsed)
	}
}

func parseCorpusSources(sources string) []string {
	if sources == "all" {
		return []string{"leipzig", "edge", "forms", "api", "tech", "intl"}
	}
	return splitAndTrim(sources, ",")
}

func splitAndTrim(s string, sep string) []string {
	parts := make([]string, 0)
	for _, p := range splitString(s, sep) {
		p = trimString(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitString(s, sep string) []string {
	if s == "" {
		return nil
	}
	result := make([]string, 0)
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimString(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func loadDynamicCorpus(tester *fp.Tester, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read corpus %s: %w", filename, err)
	}

	var payloads []string
	if err := json.Unmarshal(data, &payloads); err != nil {
		// Try line-by-line format
		lines := splitString(string(data), "\n")
		for _, line := range lines {
			line = trimString(line)
			if line != "" {
				payloads = append(payloads, line)
			}
		}
	}

	tester.GetCorpus().AddDynamicCorpus(payloads)
	return nil
}

func displayFPResults(result *fp.Result) {
	fmt.Println()
	fmt.Println(ui.SectionStyle.Render("FALSE POSITIVE ANALYSIS RESULTS"))
	fmt.Println()

	// Summary box
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    FP TESTING SUMMARY                        ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Total Tests:        %-40d ║\n", result.TotalTests)
	fmt.Printf("║  False Positives:    %-40d ║\n", result.FalsePositives)
	fmt.Printf("║  FP Rate:            %-40.2f ║\n", result.FPRatio*100)
	fmt.Printf("║  True Negatives:     %-40d ║\n", result.TrueNegatives)
	fmt.Printf("║  Errors:             %-40d ║\n", result.Errors)
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

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
	fmt.Printf("Rating: %s\n\n", rating)

	// By corpus
	if len(result.ByCorpus) > 0 {
		fmt.Println(ui.SectionStyle.Render("FP BY CORPUS SOURCE"))
		for corpus, count := range result.ByCorpus {
			fmt.Printf("  %-20s %d FPs\n", corpus, count)
		}
		fmt.Println()
	}

	// By location
	if len(result.ByLocation) > 0 {
		fmt.Println(ui.SectionStyle.Render("FP BY INJECTION LOCATION"))
		for location, count := range result.ByLocation {
			fmt.Printf("  %-20s %d FPs\n", location, count)
		}
		fmt.Println()
	}

	// Top FP details (max 10)
	if len(result.FalsePositiveDetails) > 0 {
		fmt.Println(ui.SectionStyle.Render("FALSE POSITIVE DETAILS"))
		maxItems := 10
		if len(result.FalsePositiveDetails) < maxItems {
			maxItems = len(result.FalsePositiveDetails)
		}
		for i := 0; i < maxItems; i++ {
			fpDetail := result.FalsePositiveDetails[i]
			fmt.Printf("  [%d] Payload: %.60s...\n", i+1, strutil.Truncate(fpDetail.Payload, 60))
			fmt.Printf("      Location: %s | Status: %d | Rule: %d\n",
				fpDetail.Location, fpDetail.StatusCode, fpDetail.RuleID)
		}
		if len(result.FalsePositiveDetails) > maxItems {
			fmt.Printf("  ... and %d more\n", len(result.FalsePositiveDetails)-maxItems)
		}
		fmt.Println()
	}
}



func runLocalFPTest(paranoiaLevel int, verbose bool) {
	ui.PrintInfo("Running local WAF FP simulation...")
	fmt.Println()

	waf := fp.NewLocalWAF(paranoiaLevel)
	stats := waf.TestCorpus(verbose)

	fmt.Println()
	fmt.Println(fp.FormatLocalFPReport(stats))
}

// Helper functions for progress display
func repeatChar(char string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += char
	}
	return result
}

func formatElapsed(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", mins, secs)
}
