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
	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/metrics"
	detectionoutput "github.com/waftester/waftester/pkg/output/detection"
	"github.com/waftester/waftester/pkg/templateresolver"
	"github.com/waftester/waftester/pkg/ui"
)

// runAssess executes the enterprise WAF assessment command
func runAssess() {
	ui.PrintCompactBanner()
	ui.PrintSection("Enterprise WAF Assessment")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, ui.SanitizeString("  🏢 Comprehensive security assessment with enterprise-grade metrics"))
	fmt.Fprintln(os.Stderr, "     Combines attack testing + false positive testing + quantitative analysis")
	fmt.Fprintln(os.Stderr)

	assessFlags := flag.NewFlagSet("assess", flag.ExitOnError)

	// Required
	target := assessFlags.String("u", "", "Target URL to assess")

	// Performance
	concurrency := assessFlags.Int("c", 25, "Number of concurrent workers")
	rateLimit := assessFlags.Float64("rate", 100.0, "Requests per second limit")
	timeout := assessFlags.Int("timeout", 10, "Request timeout in seconds")

	// Attack testing
	categories := assessFlags.String("categories", "", "Attack categories to test (comma-separated, empty=all)")
	payloadDir := assessFlags.String("payloads", defaults.PayloadDir, "Payload directory")

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

	// Detection (v2.5.2)
	noDetect := assessFlags.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	// Enterprise output flags (SARIF, JUnit, webhooks, policy, etc.)
	var outputFlags OutputFlags
	outputFlags.RegisterEnterpriseFlags(assessFlags)

	assessFlags.Parse(os.Args[2:])

	// Disable detection if requested
	if *noDetect {
		detection.Disable()
	}

	// Apply UI settings from output flags
	outputFlags.ApplyUISettings()

	// Validate
	if *target == "" {
		ui.PrintError("Target URL required. Use -u <url>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage: waf-tester assess -u <url> [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Enterprise WAF Assessment - combines attack testing with FP testing")
		fmt.Fprintln(os.Stderr, "and produces quantitative metrics (F1 score, precision, recall, etc.)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -u <url>              Target URL to assess (required)")
		fmt.Fprintln(os.Stderr, "  -c <n>                Concurrency (default: 25)")
		fmt.Fprintln(os.Stderr, "  -rate <n>             Rate limit requests/sec (default: 100)")
		fmt.Fprintln(os.Stderr, "  -timeout <n>          Request timeout in seconds (default: 10)")
		fmt.Fprintln(os.Stderr, "  -categories <list>    Attack categories (default: all)")
		fmt.Fprintln(os.Stderr, "  -fp                   Enable false positive testing (default: true)")
		fmt.Fprintln(os.Stderr, "  -corpus <sources>     FP corpus: builtin,leipzig (default: builtin)")
		fmt.Fprintln(os.Stderr, "  -custom-corpus <file> Path to custom corpus file")
		fmt.Fprintln(os.Stderr, "  -detect-waf           Auto-detect WAF vendor (default: true)")
		fmt.Fprintln(os.Stderr, "  -o <file>             Output results to file")
		fmt.Fprintln(os.Stderr, "  -format <fmt>         Output format: console, json (default: console)")
		fmt.Fprintln(os.Stderr, "  -v                    Verbose output")
		fmt.Fprintln(os.Stderr, "  -k                    Skip TLS verification")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "CI/CD Integration:")
		fmt.Fprintln(os.Stderr, "  -sarif-export <file>  Export SARIF for GitHub/Azure DevOps")
		fmt.Fprintln(os.Stderr, "  -junit-export <file>  Export JUnit XML for CI systems")
		fmt.Fprintln(os.Stderr, "  -policy <file>        Policy YAML for exit code rules")
		fmt.Fprintln(os.Stderr, "  -baseline <file>      Baseline JSON for regression detection")
		fmt.Fprintln(os.Stderr, "  -github-output        Enable GitHub Actions output")
		fmt.Fprintln(os.Stderr, "  -github-summary       Add to GitHub Actions job summary")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  waf-tester assess -u https://example.com")
		fmt.Fprintln(os.Stderr, "  waf-tester assess -u https://example.com -corpus builtin,leipzig -o report.json -format json")
		fmt.Fprintln(os.Stderr, "  waf-tester assess -u https://example.com -categories sqli,xss -c 50")
		os.Exit(1)
	}

	// Configuration is displayed via execution manifest below
	fmt.Println()

	// Resolve template directory (extracts embedded templates if needed)
	templateDir := defaults.TemplateDir
	if resolved, resolveErr := templateresolver.ResolveNucleiDir(templateDir); resolveErr == nil {
		templateDir = resolved
	}

	// Build configuration
	config := &assessment.Config{
		Base: attackconfig.Base{
			Concurrency: *concurrency,
			Timeout:     time.Duration(*timeout) * time.Second,
		},
		TargetURL:        *target,
		RateLimit:        *rateLimit,
		SkipTLSVerify:    *skipVerify,
		Verbose:          *verbose,
		EnableFPTesting:  *enableFP,
		CorpusSources:    parseCorpusSourcesAssess(*corpus),
		CustomCorpusFile: *customCorpus,
		DetectWAF:        *detectWAF,
		OutputFormat:     *format,
		OutputFile:       *output,
		PayloadDir:       *payloadDir,
		TemplateDir:      templateDir,
	}

	if *categories != "" {
		config.Categories = strings.Split(*categories, ",")
	}

	// Create assessment
	assess := assessment.New(config)

	// Setup context with timeout (30 min max)
	ctx, cancel := context.WithTimeout(context.Background(), duration.ContextMax)
	defer cancel()

	// Initialize dispatcher for hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
	scanID := fmt.Sprintf("assess-%d", time.Now().Unix())
	dispCtx, dispErr := outputFlags.InitDispatcher(scanID, *target)
	if dispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Output dispatcher warning: %v", dispErr))
	}
	if dispCtx != nil {
		defer dispCtx.Close()
		// Register detection callbacks to emit drop/ban events
		dispCtx.RegisterDetectionCallbacks(ctx)
		if !*streamMode {
			ui.PrintInfo("Real-time integrations enabled (hooks active)")
		}
	}

	// Emit start event for scan lifecycle hooks
	if dispCtx != nil {
		var cats []string
		if *categories != "" {
			cats = strings.Split(*categories, ",")
		}
		_ = dispCtx.EmitStart(ctx, *target, 0, *concurrency, cats)
	}

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
			"Enterprise assessment combines attack testing with FP testing",
			"F1 score balances precision and recall for accurate grading",
			"Quantitative metrics provide objective WAF evaluation",
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
		// Emit error to hooks
		if dispCtx != nil {
			_ = dispCtx.EmitError(ctx, "assess", fmt.Sprintf("Assessment error: %v", err), true)
			_ = dispCtx.Close()
		}
		ui.PrintError(fmt.Sprintf("Assessment error: %v", err))
		os.Exit(1)
	}

	// Show completion summary
	if *streamMode {
		fmt.Printf("[COMPLETE] Assessment in %s, Grade=%s\n", formatElapsedAssess(elapsed), result.Grade)
	} else {
		ui.Printf("  %s Assessment completed in %s\n", ui.Icon("✅", "+"), formatElapsedAssess(elapsed))
		fmt.Println()
	}

	// Emit findings to all hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
	if dispCtx != nil {
		// Emit overall grade as a result event
		gradeDesc := fmt.Sprintf("Enterprise Assessment Grade: %s - %s", result.Grade, result.GradeReason)
		_ = dispCtx.EmitBypass(ctx, "assess-grade", result.Grade, *target, gradeDesc, 0)

		// Emit weak categories (low detection rate or poor grades)
		for cat, cm := range result.CategoryMetrics {
			if cm.Grade == "D" || cm.Grade == "F" || cm.DetectionRate < 0.6 {
				weakDesc := fmt.Sprintf("Weak category: %s - Detection %.1f%% (%d bypassed) - Grade %s",
					cat, cm.DetectionRate*100, cm.Bypassed, cm.Grade)
				_ = dispCtx.EmitBypass(ctx, "assess-weak-category", "high", *target, weakDesc, 0)
			}
		}

		// Emit recommendations
		for _, rec := range result.Recommendations {
			_ = dispCtx.EmitBypass(ctx, "assess-recommendation", "info", *target, rec, 0)
		}

		// Emit summary
		_ = dispCtx.EmitSummary(ctx, int(result.TotalRequests),
			int(result.Matrix.TruePositives+result.Matrix.TrueNegatives),
			int(result.Matrix.FalseNegatives), elapsed)
	}

	// Display results (only in interactive mode)
	if !*streamMode {
		displayAssessmentResults(result, elapsed)
	}

	// Write enterprise export files (--json-export, --sarif-export, etc.)
	writeAssessExports(&outputFlags, result, elapsed)

	// Save to file if requested
	if *output != "" {
		var data []byte
		var marshalErr error
		switch strings.ToLower(*format) {
		case "json":
			data, marshalErr = json.MarshalIndent(result, "", "  ")
		default:
			data = []byte(result.Summary())
		}

		if marshalErr != nil {
			ui.PrintError(fmt.Sprintf("Error encoding output: %v", marshalErr))
			if dispCtx != nil {
				_ = dispCtx.Close()
			}
			os.Exit(1)
		}

		if err := os.WriteFile(*output, data, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Error saving output: %v", err))
			if dispCtx != nil {
				_ = dispCtx.Close()
			}
			os.Exit(1)
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *output))
		}
	}

	// Exit code based on grade
	if result.Grade == "F" || result.Grade == "D" || result.Grade == "D-" {
		if dispCtx != nil {
			_ = dispCtx.Close()
		}
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
	if ui.UnicodeTerminal() {
		fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
		fmt.Printf("║  %-64s ║\n", fmt.Sprintf("Grade: %s%s%s  -  %s", gradeColor, m.Grade, "\033[0m", m.GradeReason))
		fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
		fmt.Printf("║  %-64s ║\n", fmt.Sprintf("Target: %s", assessTruncateString(m.TargetURL, 50)))
		fmt.Printf("║  %-64s ║\n", fmt.Sprintf("WAF: %s", m.WAFVendor))
		fmt.Printf("║  %-64s ║\n", fmt.Sprintf("Duration: %.2fs | Tests: %d", duration.Seconds(), m.TotalRequests))
		fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	} else {
		fmt.Println("+------------------------------------------------------------------+")
		fmt.Printf("|  %-64s |\n", fmt.Sprintf("Grade: %s%s%s  -  %s", gradeColor, m.Grade, "\033[0m", m.GradeReason))
		fmt.Println("+------------------------------------------------------------------+")
		fmt.Printf("|  %-64s |\n", fmt.Sprintf("Target: %s", assessTruncateString(m.TargetURL, 50)))
		fmt.Printf("|  %-64s |\n", fmt.Sprintf("WAF: %s", m.WAFVendor))
		fmt.Printf("|  %-64s |\n", fmt.Sprintf("Duration: %.2fs | Tests: %d", duration.Seconds(), m.TotalRequests))
		fmt.Println("+------------------------------------------------------------------+")
	}
	fmt.Println()

	// Confusion Matrix
	fmt.Println(ui.SectionStyle.Render("CONFUSION MATRIX"))
	fmt.Println()
	if ui.UnicodeTerminal() {
		fmt.Println("              │  Predicted  │  Predicted  │")
		fmt.Println("              │   Blocked   │   Allowed   │")
		fmt.Println("  ────────────┼─────────────┼─────────────┤")
		fmt.Printf("  Attack      │  %9d  │  %9d  │ (TP, FN)\n", m.Matrix.TruePositives, m.Matrix.FalseNegatives)
		fmt.Printf("  Benign      │  %9d  │  %9d  │ (FP, TN)\n", m.Matrix.FalsePositives, m.Matrix.TrueNegatives)
	} else {
		fmt.Println("              |  Predicted  |  Predicted  |")
		fmt.Println("              |   Blocked   |   Allowed   |")
		fmt.Println("  ------------+-------------+-------------|")
		fmt.Printf("  Attack      |  %9d  |  %9d  | (TP, FN)\n", m.Matrix.TruePositives, m.Matrix.FalseNegatives)
		fmt.Printf("  Benign      |  %9d  |  %9d  | (FP, TN)\n", m.Matrix.FalsePositives, m.Matrix.TrueNegatives)
	}
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

	// Detection Stats (v2.5.2 - using unified detection output package)
	detStats := detectionoutput.FromDetector()
	if detStats.HasData() {
		fmt.Println(ui.SectionStyle.Render("DETECTION STATS"))
		detStats.PrintConsole()
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
