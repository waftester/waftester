// cmd/cli/assess.go - Enterprise WAF Assessment Command
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/assessment"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/metrics"
	"github.com/waftester/waftester/pkg/ui"
)

// runAssess executes the enterprise WAF assessment command
func runAssess() {
	ui.PrintCompactBanner()
	ui.PrintSection("Enterprise WAF Assessment")
	fmt.Println()
	fmt.Println("  🏢 Comprehensive security assessment with enterprise-grade metrics")
	fmt.Println("     Combines attack testing + false positive testing + quantitative analysis")
	fmt.Println()

	assessFlags := flag.NewFlagSet("assess", flag.ExitOnError)

	// Required
	target := assessFlags.String("u", "", "Target URL to assess")

	// Performance
	concurrency := assessFlags.Int("c", 25, "Number of concurrent workers")
	rateLimit := assessFlags.Float64("rate", 100.0, "Requests per second limit")
	timeout := assessFlags.Int("timeout", 10, "Request timeout in seconds")

	// Attack testing
	categories := assessFlags.String("categories", "", "Attack categories to test (comma-separated, empty=all)")

	// FP testing
	enableFP := assessFlags.Bool("fp", true, "Enable false positive testing")
	corpus := assessFlags.String("corpus", "builtin", "FP corpus sources: builtin,leipzig (comma-separated)")
	customCorpus := assessFlags.String("custom-corpus", "", "Path to custom corpus file")

	// WAF detection
	detectWAF := assessFlags.Bool("detect-waf", true, "Detect WAF vendor before testing")

	// Output
	output := assessFlags.String("o", "", "Output file for results")
	format := assessFlags.String("format", "console", "Output format: console, json")
	verbose := assessFlags.Bool("v", false, "Verbose output")
	streamMode := assessFlags.Bool("stream", false, "Streaming output mode (for CI/scripts)")

	// TLS
	skipVerify := assessFlags.Bool("k", false, "Skip TLS certificate verification")

	assessFlags.Parse(os.Args[2:])

	// Validate
	if *target == "" {
		fmt.Println(ui.ErrorStyle.Render("Error: Target URL required. Use -u <url>"))
		fmt.Println()
		fmt.Println("Usage: waf-tester assess -u <url> [options]")
		fmt.Println()
		fmt.Println("Enterprise WAF Assessment - combines attack testing with FP testing")
		fmt.Println("and produces quantitative metrics (F1 score, precision, recall, etc.)")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -u <url>              Target URL to assess (required)")
		fmt.Println("  -c <n>                Concurrency (default: 25)")
		fmt.Println("  -rate <n>             Rate limit requests/sec (default: 100)")
		fmt.Println("  -timeout <n>          Request timeout in seconds (default: 10)")
		fmt.Println("  -categories <list>    Attack categories (default: all)")
		fmt.Println("  -fp                   Enable false positive testing (default: true)")
		fmt.Println("  -corpus <sources>     FP corpus: builtin,leipzig (default: builtin)")
		fmt.Println("  -custom-corpus <file> Path to custom corpus file")
		fmt.Println("  -detect-waf           Auto-detect WAF vendor (default: true)")
		fmt.Println("  -o <file>             Output results to file")
		fmt.Println("  -format <fmt>         Output format: console, json (default: console)")
		fmt.Println("  -v                    Verbose output")
		fmt.Println("  -k                    Skip TLS verification")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  waf-tester assess -u https://example.com")
		fmt.Println("  waf-tester assess -u https://example.com -corpus builtin,leipzig -o report.json -format json")
		fmt.Println("  waf-tester assess -u https://example.com -categories sqli,xss -c 50")
		os.Exit(1)
	}

	// Print configuration
	ui.PrintConfigLine("Target", *target)
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%.0f req/s", *rateLimit))
	ui.PrintConfigLine("Timeout", fmt.Sprintf("%ds", *timeout))
	if *categories != "" {
		ui.PrintConfigLine("Categories", *categories)
	} else {
		ui.PrintConfigLine("Categories", "all")
	}
	ui.PrintConfigLine("FP Testing", fmt.Sprintf("%v", *enableFP))
	ui.PrintConfigLine("Corpus", *corpus)
	ui.PrintConfigLine("WAF Detection", fmt.Sprintf("%v", *detectWAF))
	fmt.Println()

	// Build configuration
	config := &assessment.Config{
		TargetURL:        *target,
		Concurrency:      *concurrency,
		RateLimit:        *rateLimit,
		Timeout:          time.Duration(*timeout) * time.Second,
		SkipTLSVerify:    *skipVerify,
		Verbose:          *verbose,
		EnableFPTesting:  *enableFP,
		CorpusSources:    parseCorpusSourcesAssess(*corpus),
		CustomCorpusFile: *customCorpus,
		DetectWAF:        *detectWAF,
		OutputFormat:     *format,
		OutputFile:       *output,
	}

	if *categories != "" {
		config.Categories = strings.Split(*categories, ",")
	}

	// Create assessment
	assess := assessment.New(config)

	// Setup context with timeout (30 min max)
	ctx, cancel := context.WithTimeout(context.Background(), duration.ContextMax)
	defer cancel()

	// Display execution manifest BEFORE running (only in interactive mode)
	if !*streamMode {
		manifest := ui.NewExecutionManifest("ENTERPRISE WAF ASSESSMENT")
		manifest.SetDescription("Attack testing + FP testing + quantitative metrics")
		manifest.AddWithIcon("🎯", "Target", *target)
		if *categories != "" {
			manifest.AddWithIcon("🏷️", "Categories", *categories)
		} else {
			manifest.AddWithIcon("🏷️", "Categories", "all")
		}
		manifest.AddWithIcon("🧪", "FP Testing", fmt.Sprintf("%v", *enableFP))
		manifest.AddWithIcon("⚡", "Concurrency", fmt.Sprintf("%d workers", *concurrency))
		manifest.AddWithIcon("🚦", "Rate Limit", fmt.Sprintf("%.0f req/s", *rateLimit))
		manifest.AddWithIcon("🔍", "WAF Detection", fmt.Sprintf("%v", *detectWAF))
		manifest.Print()
	} else {
		fmt.Printf("[INFO] Starting enterprise assessment: target=%s concurrency=%d rate=%.0f\n",
			*target, *concurrency, *rateLimit)
	}

	// Determine output mode
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Use unified LiveProgress component
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        0, // Will be set dynamically by callback
		DisplayLines: 4,
		Title:        "Enterprise assessment",
		Unit:         "tests",
		Mode:         outputMode,
		Tips: []string{
			"💡 Enterprise assessment combines attack testing with FP testing",
			"💡 F1 score balances precision and recall for accurate grading",
			"💡 Quantitative metrics provide objective WAF evaluation",
		},
		StreamFormat: "[PROGRESS] {completed}/{total} ({percent}%) - {status} - {elapsed} elapsed",
	})

	// Progress callback - updates LiveProgress
	progressFn := func(completed, total int64, phase string) {
		progress.SetTotal(int(total))
		progress.SetCompleted(int(completed))
		progress.SetStatus(phase)
	}

	progress.Start()

	// Run assessment
	result, err := assess.Run(ctx, progressFn)

	// Stop progress display
	progress.Stop()
	elapsed := progress.GetElapsed()

	if err != nil {
		fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Assessment error: %v", err)))
		os.Exit(1)
	}

	// Show completion summary
	if *streamMode {
		fmt.Printf("[COMPLETE] Assessment in %s, Grade=%s\n", formatElapsedAssess(elapsed), result.Grade)
	} else {
		fmt.Printf("  ✅ Assessment completed in %s\n", formatElapsedAssess(elapsed))
		fmt.Println()
	}

	// Display results (only in interactive mode)
	if !*streamMode {
		displayAssessmentResults(result, elapsed)
	}

	// Save to file if requested
	if *output != "" {
		var data []byte
		switch strings.ToLower(*format) {
		case "json":
			data, _ = json.MarshalIndent(result, "", "  ")
		default:
			data = []byte(result.Summary())
		}

		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Error saving output: %v", err)))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *output))
		}
	}

	// Exit code based on grade
	if result.Grade == "F" || result.Grade == "D" || result.Grade == "D-" {
		os.Exit(1)
	}
}

func parseCorpusSourcesAssess(sources string) []string {
	parts := strings.Split(sources, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func displayAssessmentResults(m *metrics.EnterpriseMetrics, duration time.Duration) {
	fmt.Println()
	fmt.Println(ui.SectionStyle.Render("ENTERPRISE WAF ASSESSMENT RESULTS"))
	fmt.Println()

	// Grade banner
	gradeColor := getGradeColor(m.Grade)
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  %-64s ║\n", fmt.Sprintf("Grade: %s%s%s  -  %s", gradeColor, m.Grade, "\033[0m", m.GradeReason))
	fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  %-64s ║\n", fmt.Sprintf("Target: %s", assessTruncateString(m.TargetURL, 50)))
	fmt.Printf("║  %-64s ║\n", fmt.Sprintf("WAF: %s", m.WAFVendor))
	fmt.Printf("║  %-64s ║\n", fmt.Sprintf("Duration: %.2fs | Tests: %d", duration.Seconds(), m.TotalRequests))
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Confusion Matrix
	fmt.Println(ui.SectionStyle.Render("CONFUSION MATRIX"))
	fmt.Println()
	fmt.Println("              │  Predicted  │  Predicted  │")
	fmt.Println("              │   Blocked   │   Allowed   │")
	fmt.Println("  ────────────┼─────────────┼─────────────┤")
	fmt.Printf("  Attack      │  %9d  │  %9d  │ (TP, FN)\n", m.Matrix.TruePositives, m.Matrix.FalseNegatives)
	fmt.Printf("  Benign      │  %9d  │  %9d  │ (FP, TN)\n", m.Matrix.FalsePositives, m.Matrix.TrueNegatives)
	fmt.Println()

	// Primary Metrics
	fmt.Println(ui.SectionStyle.Render("PRIMARY METRICS"))
	fmt.Println()
	fmt.Printf("  %-28s %s\n", "Detection Rate (TPR/Recall):", formatMetric(m.DetectionRate*100, "%"))
	fmt.Printf("  %-28s %s\n", "False Positive Rate (FPR):", formatMetric(m.FalsePositiveRate*100, "%"))
	fmt.Printf("  %-28s %s\n", "Precision:", formatMetric(m.Precision*100, "%"))
	fmt.Printf("  %-28s %s\n", "Specificity (TNR):", formatMetric(m.Specificity*100, "%"))
	fmt.Println()

	// Balanced Metrics
	fmt.Println(ui.SectionStyle.Render("BALANCED METRICS"))
	fmt.Println()
	fmt.Printf("  %-28s %s\n", "F1 Score:", formatMetric(m.F1Score*100, "%"))
	fmt.Printf("  %-28s %s\n", "F2 Score (recall-weighted):", formatMetric(m.F2Score*100, "%"))
	fmt.Printf("  %-28s %s\n", "Balanced Accuracy:", formatMetric(m.BalancedAccuracy*100, "%"))
	fmt.Printf("  %-28s %s\n", "MCC:", formatMCC(m.MCC))
	fmt.Println()

	// WAF-Specific Metrics
	fmt.Println(ui.SectionStyle.Render("WAF-SPECIFIC METRICS"))
	fmt.Println()
	fmt.Printf("  %-28s %s\n", "Bypass Resistance:", formatMetric(m.BypassResistance*100, "%"))
	fmt.Printf("  %-28s %.4f\n", "Mutation Potency:", m.MutationPotency)
	fmt.Printf("  %-28s %s\n", "Block Consistency:", formatMetric(m.BlockConsistency*100, "%"))
	fmt.Println()

	// Latency
	if m.AvgLatencyMs > 0 {
		fmt.Println(ui.SectionStyle.Render("LATENCY"))
		fmt.Println()
		fmt.Printf("  %-28s %.1f ms\n", "Average:", m.AvgLatencyMs)
		fmt.Printf("  %-28s %.1f ms\n", "P50:", m.P50LatencyMs)
		fmt.Printf("  %-28s %.1f ms\n", "P95:", m.P95LatencyMs)
		fmt.Printf("  %-28s %.1f ms\n", "P99:", m.P99LatencyMs)
		fmt.Println()
	}

	// Category Breakdown
	if len(m.CategoryMetrics) > 0 {
		fmt.Println(ui.SectionStyle.Render("CATEGORY BREAKDOWN"))
		fmt.Println()
		fmt.Println("  Category          │ Tests │ Blocked │ Detection │ Grade")
		fmt.Println("  ──────────────────┼───────┼─────────┼───────────┼──────")
		for cat, cm := range m.CategoryMetrics {
			fmt.Printf("  %-18s│ %5d │ %7d │   %5.1f%%  │   %s\n",
				assessTruncateString(cat, 18), cm.TotalTests, cm.Blocked, cm.DetectionRate*100, cm.Grade)
		}
		fmt.Println()
	}

	// Recommendations
	if len(m.Recommendations) > 0 {
		fmt.Println(ui.SectionStyle.Render("RECOMMENDATIONS"))
		fmt.Println()
		for i, rec := range m.Recommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
		fmt.Println()
	}
}

func getGradeColor(grade string) string {
	if len(grade) == 0 {
		return ""
	}
	switch grade[0] {
	case 'A':
		return "\033[32m" // Green
	case 'B':
		return "\033[33m" // Yellow
	case 'C':
		return "\033[35m" // Magenta
	case 'D', 'F':
		return "\033[31m" // Red
	default:
		return ""
	}
}

func formatMetric(value float64, suffix string) string {
	color := ""
	reset := "\033[0m"

	if suffix == "%" {
		if value >= 95 {
			color = "\033[32m" // Green
		} else if value >= 80 {
			color = "\033[33m" // Yellow
		} else if value >= 60 {
			color = "\033[35m" // Magenta
		} else {
			color = "\033[31m" // Red
		}
	}

	return fmt.Sprintf("%s%.2f%s%s", color, value, suffix, reset)
}

func formatMCC(value float64) string {
	color := ""
	reset := "\033[0m"

	if value >= 0.8 {
		color = "\033[32m" // Green
	} else if value >= 0.5 {
		color = "\033[33m" // Yellow
	} else if value >= 0 {
		color = "\033[35m" // Magenta
	} else {
		color = "\033[31m" // Red
	}

	return fmt.Sprintf("%s%+.4f%s", color, value, reset)
}

func assessTruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Helper functions for animated progress
func repeatCharAssess(char string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += char
	}
	return result
}

func formatElapsedAssess(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", mins, secs)
}
