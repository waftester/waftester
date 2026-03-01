package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/headless"
	"github.com/waftester/waftester/pkg/race"
	"github.com/waftester/waftester/pkg/smuggling"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/workflow"
)

// =============================================================================
// SMUGGLE COMMAND - HTTP Request Smuggling Detection
// =============================================================================

func runSmuggle() {
	ui.PrintCompactBanner()
	ui.PrintSection("HTTP Request Smuggling Detection")

	fs := flag.NewFlagSet("smuggle", flag.ExitOnError)

	// Target options
	targetURL := fs.String("u", "", "Target URL")
	fs.StringVar(targetURL, "target", "", "Target URL")
	targetFile := fs.String("l", "", "File containing target URLs")

	// Detection options
	safeMode := fs.Bool("safe", true, "Safe mode - timing only, no payload injection")
	timeout := fs.Int("timeout", 10, "Request timeout in seconds")
	delay := fs.Int("delay", 1000, "Delay between requests in milliseconds")
	retries := fs.Int("retries", 3, "Number of retries per technique")

	// Output options
	outputFile := fs.String("o", "", "Output file (JSON)")
	jsonOutput := fs.Bool("json", false, "JSON output to stdout")
	verbose := fs.Bool("v", false, "Verbose output")
	streamMode := fs.Bool("stream", false, "Streaming output mode for CI/scripts")

	// Enterprise hook flags (Slack, Teams, PagerDuty, OTEL, etc.)
	smuggleSlack := fs.String("slack-webhook", "", "Slack webhook URL for notifications")
	smuggleTeams := fs.String("teams-webhook", "", "Teams webhook URL for notifications")
	smugglePagerDuty := fs.String("pagerduty-key", "", "PagerDuty routing key")
	smuggleOtel := fs.String("otel-endpoint", "", "OpenTelemetry endpoint")
	smuggleWebhook := fs.String("webhook-url", "", "Generic webhook URL")

	fs.Parse(os.Args[2:])

	// Collect targets
	targets := []string{}

	if *targetURL != "" {
		targets = append(targets, strings.Split(*targetURL, ",")...)
	}

	if *targetFile != "" {
		file, err := os.Open(*targetFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to open target file: %v", err))
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to read target file: %v", err))
			os.Exit(1)
		}
	}

	if len(targets) == 0 {
		ui.PrintError("No targets specified. Use -u or -l")
		os.Exit(1)
	}

	// Create detector
	cfg := smuggling.DefaultConfig()
	cfg.Timeout = time.Duration(*timeout) * time.Second
	cfg.SafeMode = *safeMode
	cfg.DelayMs = *delay
	cfg.MaxRetries = *retries
	detector := smuggling.NewDetector(cfg)

	if *verbose {
		fmt.Printf("  Mode: %s\n", map[bool]string{true: "Safe (timing only)", false: "Full (payload injection)"}[*safeMode])
		fmt.Printf("  Timeout: %ds\n", *timeout)
		fmt.Printf("  Delay: %dms\n", *delay)
		fmt.Println()
	}

	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()
	allResults := []*smuggling.Result{}
	smuggleStartTime := time.Now()

	// Initialize dispatcher for hooks (Slack, Teams, PagerDuty, OTEL, etc.)
	smuggleOutputFlags := OutputFlags{
		SlackWebhook: *smuggleSlack,
		TeamsWebhook: *smuggleTeams,
		PagerDutyKey: *smugglePagerDuty,
		OTelEndpoint: *smuggleOtel,
		WebhookURL:   *smuggleWebhook,
	}
	smuggleScanID := fmt.Sprintf("smuggle-%d", time.Now().Unix())
	firstTarget := ""
	if len(targets) > 0 {
		firstTarget = targets[0]
	}
	smuggleDispCtx, smuggleDispErr := smuggleOutputFlags.InitDispatcher(smuggleScanID, firstTarget)
	if smuggleDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", smuggleDispErr))
	}
	if smuggleDispCtx != nil {
		defer smuggleDispCtx.Close()
	}
	smugglerCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if smuggleDispCtx != nil {
		_ = smuggleDispCtx.EmitStart(smugglerCtx, firstTarget, len(targets), 1, nil)
	}

	// Determine output mode
	outputMode := ui.DefaultOutputMode()
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Display execution manifest BEFORE running (multi-target only, interactive mode)
	var progress *ui.LiveProgress
	if len(targets) > 1 {
		if !*streamMode {
			manifest := ui.NewExecutionManifest("HTTP SMUGGLING DETECTION")
			manifest.SetDescription("Testing for request smuggling vulnerabilities")
			manifest.AddEmphasis("🎯", "Targets", fmt.Sprintf("%d URLs", len(targets)))
			manifest.AddWithIcon("🛡️", "Mode", map[bool]string{true: "Safe (timing only)", false: "Full (payload injection)"}[*safeMode])
			manifest.AddWithIcon("⏱️", "Timeout", fmt.Sprintf("%ds per target", *timeout))
			manifest.Print()
		} else {
			fmt.Printf("[INFO] Starting smuggle detection: targets=%d mode=%s\n",
				len(targets), map[bool]string{true: "safe", false: "full"}[*safeMode])
		}

		// Use unified LiveProgress component
		progress = ui.NewLiveProgress(ui.LiveProgressConfig{
			Total:        len(targets),
			DisplayLines: 2,
			Title:        "Testing for request smuggling",
			Unit:         "targets",
			Mode:         outputMode,
			Metrics: []ui.MetricConfig{
				{Name: "vulns", Label: "Vulnerabilities", Icon: ui.Icon("🚨", "!"), Highlight: true},
			},
		})
		progress.Start()
	}

	for _, target := range targets {
		if len(targets) == 1 {
			ui.PrintInfo(fmt.Sprintf("Testing: %s", target))
		}

		result, err := detector.Detect(ctx, target)
		if err != nil {
			if len(targets) == 1 {
				ui.PrintError(fmt.Sprintf("  Error: %v", err))
			}
			// Emit error to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
			if smuggleDispCtx != nil {
				_ = smuggleDispCtx.EmitError(ctx, "smuggle", fmt.Sprintf("Detection error for %s: %v", target, err), false)
			}
			if progress != nil {
				progress.Increment()
			}
			continue
		}

		allResults = append(allResults, result)
		if progress != nil {
			progress.Increment()
			progress.AddMetricBy("vulns", len(result.Vulnerabilities))
		}

		// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
		if smuggleDispCtx != nil && len(result.Vulnerabilities) > 0 {
			for _, vuln := range result.Vulnerabilities {
				vulnDesc := fmt.Sprintf("%s: %s", vuln.Type, vuln.Description)
				_ = smuggleDispCtx.EmitBypass(ctx, "request-smuggling", vuln.Severity, target, vulnDesc, 0)
			}
		}

		if len(targets) == 1 {
			if len(result.Vulnerabilities) > 0 {
				for _, vuln := range result.Vulnerabilities {
					severity := ui.SeverityStyle(vuln.Severity)
					fmt.Printf("  [%s] %s - %s\n", severity.Render(vuln.Severity), vuln.Type, vuln.Description)
					if *verbose {
						fmt.Printf("    Confidence: %.0f%%\n", vuln.Confidence*100)
						fmt.Printf("    Exploitable: %v\n", vuln.Exploitable)
					}
				}
			} else {
				ui.PrintSuccess("  No smuggling vulnerabilities detected")
			}

			fmt.Printf("  Tested: %s in %v\n", strings.Join(result.TestedTechniques, ", "), result.Duration.Round(time.Millisecond))
			fmt.Println()
		}
	}

	// Stop progress
	if progress != nil {
		progress.Stop()
	}

	// Summary
	totalVulns := 0
	for _, r := range allResults {
		totalVulns += len(r.Vulnerabilities)
	}

	ui.PrintSection("Summary")
	fmt.Printf("  Targets tested: %d\n", len(allResults))
	fmt.Printf("  Vulnerabilities found: %d\n", totalVulns)

	// Emit summary to hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
	if smuggleDispCtx != nil {
		_ = smuggleDispCtx.EmitSummary(ctx, len(allResults), len(allResults)-totalVulns, totalVulns, time.Since(smuggleStartTime))
	}

	// Output
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(allResults); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to encode JSON: %v", err))
		}
	}

	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create output file: %v", err))
		} else {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			encErr := enc.Encode(allResults)
			closeErr := f.Close()
			if encErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to encode results: %v", encErr))
			} else if closeErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to close output file: %v", closeErr))
			} else {
				ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
			}
		}
	}
}

// =============================================================================
// RACE COMMAND - Race Condition Testing
// =============================================================================

func runRace() {
	ui.PrintCompactBanner()
	ui.PrintSection("Race Condition Testing")

	fs := flag.NewFlagSet("race", flag.ExitOnError)

	// Target options
	targetURL := fs.String("u", "", "Target URL")
	fs.StringVar(targetURL, "target", "", "Target URL")
	method := fs.String("method", "POST", "HTTP method (GET, POST, PUT)")
	body := fs.String("body", "", "Request body")
	headers := fs.String("H", "", "Headers (format: 'Header: Value' comma-separated)")

	// Attack options
	attackType := fs.String("attack", "double_submit", "Attack type: double_submit, token_reuse, limit_bypass, toctou")
	concurrency := fs.Int("c", 50, "Concurrent requests")
	iterations := fs.Int("n", 1, "Number of iterations")
	timeout := fs.Int("timeout", 30, "Request timeout in seconds")

	// Output options
	outputFile := fs.String("o", "", "Output file (JSON)")
	jsonOutput := fs.Bool("json", false, "JSON output to stdout")
	verbose := fs.Bool("v", false, "Verbose output")

	// Enterprise hook flags (Slack, Teams, PagerDuty, OTEL, etc.)
	raceSlack := fs.String("slack-webhook", "", "Slack webhook URL for notifications")
	raceTeams := fs.String("teams-webhook", "", "Teams webhook URL for notifications")
	racePagerDuty := fs.String("pagerduty-key", "", "PagerDuty routing key")
	raceOtel := fs.String("otel-endpoint", "", "OpenTelemetry endpoint")
	raceWebhook := fs.String("webhook-url", "", "Generic webhook URL")

	fs.Parse(os.Args[2:])

	if *targetURL == "" {
		ui.PrintError("Target URL required. Use -u <url>")
		os.Exit(1)
	}

	// Parse headers
	headerMap := http.Header{}
	if *headers != "" {
		for _, h := range strings.Split(*headers, ",") {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				headerMap.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	// Create tester
	config := race.DefaultConfig()
	config.MaxConcurrency = *concurrency
	config.Iterations = *iterations
	config.Timeout = time.Duration(*timeout) * time.Second

	tester := race.NewTester(config)

	if *verbose {
		fmt.Printf("  Target: %s\n", *targetURL)
		fmt.Printf("  Attack: %s\n", *attackType)
		fmt.Printf("  Concurrency: %d\n", *concurrency)
		fmt.Printf("  Iterations: %d\n", *iterations)
		fmt.Println()
	}

	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()
	var vulns []*race.Vulnerability
	raceStartTime := time.Now()

	// Initialize dispatcher for hooks (Slack, Teams, PagerDuty, OTEL, etc.)
	raceOutputFlags := OutputFlags{
		SlackWebhook: *raceSlack,
		TeamsWebhook: *raceTeams,
		PagerDutyKey: *racePagerDuty,
		OTelEndpoint: *raceOtel,
		WebhookURL:   *raceWebhook,
	}
	raceScanID := fmt.Sprintf("race-%d", time.Now().Unix())
	raceDispCtx, raceDispErr := raceOutputFlags.InitDispatcher(raceScanID, *targetURL)
	if raceDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", raceDispErr))
	}
	if raceDispCtx != nil {
		defer raceDispCtx.Close()
	}
	raceCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if raceDispCtx != nil {
		_ = raceDispCtx.EmitStart(raceCtx, *targetURL, 0, *concurrency, nil)
	}

	// Create request config
	reqConfig := &race.RequestConfig{
		Method:  *method,
		URL:     *targetURL,
		Body:    *body,
		Headers: headerMap,
	}

	ui.PrintInfo(fmt.Sprintf("Testing %s attack...", *attackType))

	var vuln *race.Vulnerability
	var err error

	switch race.AttackType(*attackType) {
	case race.AttackDoubleSubmit:
		vuln, err = tester.TestDoubleSubmit(ctx, reqConfig, *concurrency)
	case race.AttackTokenReuse:
		vuln, err = tester.TestTokenReuse(ctx, reqConfig, *concurrency)
	case race.AttackLimitBypass:
		vuln, err = tester.TestLimitBypass(ctx, reqConfig, *concurrency, 10) // Default expected limit of 10
	default:
		// For other attack types, use generic concurrent test
		requests := make([]*race.RequestConfig, *concurrency)
		for i := 0; i < *concurrency; i++ {
			requests[i] = reqConfig
		}
		responses := tester.SendConcurrent(ctx, requests)

		// Analyze responses
		statusCounts := make(map[int]int)
		for _, r := range responses {
			if r.Error == nil {
				statusCounts[r.StatusCode]++
			}
		}

		if *verbose {
			fmt.Println("  Response distribution:")
			sortedStatuses := make([]int, 0, len(statusCounts))
			for status := range statusCounts {
				sortedStatuses = append(sortedStatuses, status)
			}
			sort.Ints(sortedStatuses)
			for _, status := range sortedStatuses {
				fmt.Printf("    HTTP %d: %d responses\n", status, statusCounts[status])
			}
		}
	}

	if err != nil {
		ui.PrintError(fmt.Sprintf("Test failed: %v", err))
		// Emit error to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
		if raceDispCtx != nil {
			_ = raceDispCtx.EmitError(ctx, "race", fmt.Sprintf("Race test failed: %v", err), true)
		}
	} else if vuln != nil {
		vulns = append(vulns, vuln)
		severity := ui.SeverityStyle(string(vuln.Severity))
		fmt.Printf("  [%s] %s\n", severity.Render(string(vuln.Severity)), vuln.Description)
		if *verbose {
			fmt.Printf("    Evidence: %s\n", vuln.Evidence)
			fmt.Printf("    Remediation: %s\n", vuln.Remediation)
		}

		// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
		if raceDispCtx != nil {
			vulnDesc := fmt.Sprintf("%s: %s", *attackType, vuln.Description)
			_ = raceDispCtx.EmitBypass(ctx, "race-condition", string(vuln.Severity), *targetURL, vulnDesc, 0)
		}
	} else {
		ui.PrintSuccess("  No race condition vulnerability detected")
	}

	// Summary
	ui.PrintSection("Summary")
	fmt.Printf("  Vulnerabilities found: %d\n", len(vulns))

	// Emit summary to hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
	if raceDispCtx != nil {
		blocked := 1
		if len(vulns) > 0 {
			blocked = 0
		}
		_ = raceDispCtx.EmitSummary(ctx, 1, blocked, len(vulns), time.Since(raceStartTime))
	}

	// Output
	if *jsonOutput && len(vulns) > 0 {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(vulns); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to encode JSON: %v", err))
		}
	}

	if *outputFile != "" && len(vulns) > 0 {
		f, err := os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create output file: %v", err))
		} else {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			encErr := enc.Encode(vulns)
			closeErr := f.Close()
			if encErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to encode results: %v", encErr))
			} else if closeErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to close output file: %v", closeErr))
			} else {
				ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
			}
		}
	}
}

// =============================================================================
// WORKFLOW COMMAND - Attack Workflow Execution
// =============================================================================

func runWorkflow() {
	ui.PrintCompactBanner()
	ui.PrintSection("Workflow Execution")

	fs := flag.NewFlagSet("workflow", flag.ExitOnError)

	// Workflow file
	workflowFile := fs.String("f", "", "Workflow file (YAML or JSON)")
	fs.StringVar(workflowFile, "file", "", "Workflow file (YAML or JSON)")

	// Input variables
	inputVars := fs.String("var", "", "Input variables (format: 'name=value' comma-separated)")

	// Execution options
	dryRun := fs.Bool("dry-run", false, "Show what would be executed without running")
	_ = fs.Bool("continue-on-error", false, "Continue workflow on step failure (reserved for future use)")
	timeout := fs.Int("timeout", 300, "Workflow timeout in seconds")

	// Output options
	outputFile := fs.String("o", "", "Output file (JSON)")
	jsonOutput := fs.Bool("json", false, "JSON output to stdout")
	verbose := fs.Bool("v", false, "Verbose output")

	// Enterprise hook flags (Slack, Teams, PagerDuty, OTEL, etc.)
	workflowSlack := fs.String("slack-webhook", "", "Slack webhook URL for notifications")
	workflowTeams := fs.String("teams-webhook", "", "Teams webhook URL for notifications")
	workflowPagerDuty := fs.String("pagerduty-key", "", "PagerDuty routing key")
	workflowOtel := fs.String("otel-endpoint", "", "OpenTelemetry endpoint")
	workflowWebhook := fs.String("webhook-url", "", "Generic webhook URL")

	fs.Parse(os.Args[2:])

	if *workflowFile == "" {
		ui.PrintError("Workflow file required. Use -f <file.yaml>")
		os.Exit(1)
	}

	// Parse input variables
	inputs := make(map[string]string)
	if *inputVars != "" {
		for _, v := range strings.Split(*inputVars, ",") {
			parts := strings.SplitN(strings.TrimSpace(v), "=", 2)
			if len(parts) == 2 {
				inputs[parts[0]] = parts[1]
			}
		}
	}

	// Load workflow
	wf, err := workflow.LoadWorkflow(*workflowFile)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to load workflow: %v", err))
		os.Exit(1)
	}

	// Initialize dispatcher for hooks (Slack, Teams, PagerDuty, OTEL, etc.)
	workflowOutputFlags := OutputFlags{
		SlackWebhook: *workflowSlack,
		TeamsWebhook: *workflowTeams,
		PagerDutyKey: *workflowPagerDuty,
		OTelEndpoint: *workflowOtel,
		WebhookURL:   *workflowWebhook,
	}
	workflowScanID := fmt.Sprintf("workflow-%d", time.Now().Unix())
	workflowDispCtx, workflowDispErr := workflowOutputFlags.InitDispatcher(workflowScanID, wf.Name)
	if workflowDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", workflowDispErr))
	}
	if workflowDispCtx != nil {
		defer workflowDispCtx.Close()
	}
	workflowCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if workflowDispCtx != nil {
		_ = workflowDispCtx.EmitStart(workflowCtx, wf.Name, len(wf.Steps), 1, nil)
	}

	if *verbose {
		fmt.Printf("  Workflow: %s\n", wf.Name)
		if wf.Description != "" {
			fmt.Printf("  Description: %s\n", wf.Description)
		}
		fmt.Printf("  Steps: %d\n", len(wf.Steps))
		fmt.Println()
	}

	// Create engine
	engine := workflow.NewEngine()
	engine.DryRun = *dryRun
	engine.Verbose = *verbose

	// Execute workflow with timeout
	timeoutDuration := time.Duration(*timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	ui.PrintInfo(fmt.Sprintf("Executing workflow: %s", wf.Name))
	if *dryRun {
		ui.PrintInfo("(dry-run mode - no commands will be executed)")
	}
	fmt.Println()

	result, err := engine.Execute(ctx, wf, inputs)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Workflow failed: %v", err))
		// Emit error to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
		if workflowDispCtx != nil {
			_ = workflowDispCtx.EmitError(workflowCtx, "workflow", fmt.Sprintf("Workflow '%s' failed: %v", *workflowFile, err), true)
		}
	}

	// Print step results
	for _, sr := range result.Steps {
		statusIcon := "✓"
		if sr.Status == "failed" {
			statusIcon = "✗"
			// Emit step failure to hooks
			if workflowDispCtx != nil {
				failDesc := fmt.Sprintf("Step '%s' failed", sr.StepName)
				_ = workflowDispCtx.EmitBypass(workflowCtx, "workflow-step-failure", "high", wf.Name, failDesc, 0)
			}
		} else if sr.Status == "skipped" {
			statusIcon = "○"
			// Emit step skipped to hooks
			if workflowDispCtx != nil {
				skipDesc := fmt.Sprintf("Step '%s' skipped", sr.StepName)
				_ = workflowDispCtx.EmitBypass(workflowCtx, "workflow-step-skipped", "info", wf.Name, skipDesc, 0)
			}
		} else if sr.Status == "success" {
			// Emit step success to hooks
			if workflowDispCtx != nil {
				successDesc := fmt.Sprintf("Step '%s' completed in %v", sr.StepName, sr.Duration.Round(time.Millisecond))
				_ = workflowDispCtx.EmitBypass(workflowCtx, "workflow-step-success", "info", wf.Name, successDesc, 0)
			}
		}

		fmt.Printf("  %s %s (%s) - %v\n", statusIcon, sr.StepName, sr.Status, sr.Duration.Round(time.Millisecond))
		if *verbose && sr.Output != "" {
			lines := strings.Split(sr.Output, "\n")
			for i, line := range lines {
				if i < 5 { // Show first 5 lines
					fmt.Printf("    %s\n", line)
				}
			}
			if len(lines) > 5 {
				fmt.Printf("    ... (%d more lines)\n", len(lines)-5)
			}
		}
	}

	// Summary
	fmt.Println()
	ui.PrintSection("Summary")
	fmt.Printf("  Status: %s\n", result.Status)
	fmt.Printf("  Duration: %v\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("  Steps: %d total, %d succeeded, %d failed, %d skipped\n",
		len(result.Steps),
		countStepStatus(result.Steps, "success"),
		countStepStatus(result.Steps, "failed"),
		countStepStatus(result.Steps, "skipped"))

	// Output
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to encode JSON: %v", err))
		}
	}

	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create output file: %v", err))
		} else {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			encErr := enc.Encode(result)
			closeErr := f.Close()
			if encErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to encode results: %v", encErr))
			} else if closeErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to close output file: %v", closeErr))
			} else {
				ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
			}
		}
	}

	if result.Status == "failed" {
		// Emit summary for failed workflow
		if workflowDispCtx != nil {
			failedCount := countStepStatus(result.Steps, "failed")
			_ = workflowDispCtx.EmitSummary(workflowCtx, len(result.Steps), len(result.Steps)-failedCount, failedCount, result.Duration)
			_ = workflowDispCtx.Close()
		}
		os.Exit(1)
	}

	// Emit summary for successful workflow
	if workflowDispCtx != nil {
		_ = workflowDispCtx.EmitSummary(workflowCtx, len(result.Steps), len(result.Steps), 0, result.Duration)
	}
}

func countStepStatus(results []workflow.StepResult, status string) int {
	count := 0
	for _, r := range results {
		if r.Status == status {
			count++
		}
	}
	return count
}

// =============================================================================
// HEADLESS COMMAND - Headless Browser Testing
// =============================================================================

func runHeadless() {
	ui.PrintCompactBanner()
	ui.PrintSection("Headless Browser Testing")

	fs := flag.NewFlagSet("headless", flag.ExitOnError)

	// Target options
	targetURL := fs.String("u", "", "Target URL")
	fs.StringVar(targetURL, "target", "", "Target URL")
	targetFile := fs.String("l", "", "File containing target URLs")

	// Browser options
	chromePath := fs.String("chrome", "", "Path to Chrome/Chromium executable")
	headlessMode := fs.Bool("headless", true, "Run in headless mode")
	timeout := fs.Int("timeout", 30, "Page load timeout in seconds")
	waitTime := fs.Int("wait", 2, "Wait time after page load in seconds")

	// Action options
	screenshot := fs.Bool("screenshot", false, "Take screenshots")
	screenshotDir := fs.String("screenshot-dir", "screenshots", "Screenshot output directory")
	extractURLs := fs.Bool("extract-urls", true, "Extract URLs from page")
	executeJS := fs.String("js", "", "JavaScript to execute on page")

	// Output options
	outputFile := fs.String("o", "", "Output file (JSON)")
	jsonOutput := fs.Bool("json", false, "JSON output to stdout")
	verbose := fs.Bool("v", false, "Verbose output")
	streamMode := fs.Bool("stream", false, "Streaming output mode for CI/scripts")

	// Event crawl options
	eventCrawl := fs.Bool("event-crawl", false, "Run DOM event crawling to discover hidden endpoints")
	maxClicks := fs.Int("max-clicks", 50, "Maximum elements to click during event crawl")
	clickTimeout := fs.Int("click-timeout", 5, "Timeout per click in seconds")

	// Enterprise hook flags (Slack, Teams, PagerDuty, OTEL, etc.)
	headlessSlack := fs.String("slack-webhook", "", "Slack webhook URL for notifications")
	headlessTeams := fs.String("teams-webhook", "", "Teams webhook URL for notifications")
	headlessPagerDuty := fs.String("pagerduty-key", "", "PagerDuty routing key")
	headlessOtel := fs.String("otel-endpoint", "", "OpenTelemetry endpoint")
	headlessWebhook := fs.String("webhook-url", "", "Generic webhook URL")

	fs.Parse(os.Args[2:])

	// Collect targets
	targets := []string{}

	if *targetURL != "" {
		targets = append(targets, strings.Split(*targetURL, ",")...)
	}

	if *targetFile != "" {
		file, err := os.Open(*targetFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to open target file: %v", err))
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to read target file: %v", err))
			os.Exit(1)
		}
	}

	if len(targets) == 0 {
		ui.PrintError("No targets specified. Use -u or -l")
		os.Exit(1)
	}

	// Create browser config
	config := headless.DefaultConfig()
	config.ShowBrowser = !*headlessMode // ShowBrowser is inverted from headless flag
	config.PageTimeout = time.Duration(*timeout) * time.Second
	config.IdleTimeout = time.Duration(*waitTime) * time.Second
	if *chromePath != "" {
		config.ChromiumPath = *chromePath
	}
	if *screenshot {
		config.ScreenshotEnabled = true
		config.ScreenshotDir = *screenshotDir
	}
	if *executeJS != "" {
		config.PostLoadJS = *executeJS
	}

	if *verbose {
		fmt.Printf("  Headless: %v\n", *headlessMode)
		fmt.Printf("  Timeout: %ds\n", *timeout)
		fmt.Printf("  Wait: %ds\n", *waitTime)
		fmt.Println()
	}

	// Create browser
	browser, err := headless.NewBrowser(config)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to create browser: %v", err))
		ui.PrintInfo("Make sure Chrome/Chromium is installed or specify path with -chrome")
		os.Exit(1)
	}
	defer browser.Close()

	// Create screenshot directory if needed
	if *screenshot {
		if err := os.MkdirAll(*screenshotDir, 0755); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create screenshot directory: %v", err))
		}
	}

	// Initialize dispatcher for hooks (Slack, Teams, PagerDuty, OTEL, etc.)
	headlessOutputFlags := OutputFlags{
		SlackWebhook: *headlessSlack,
		TeamsWebhook: *headlessTeams,
		PagerDutyKey: *headlessPagerDuty,
		OTelEndpoint: *headlessOtel,
		WebhookURL:   *headlessWebhook,
	}
	headlessScanID := fmt.Sprintf("headless-%d", time.Now().Unix())
	headlessTarget := targets[0]
	if len(targets) > 1 {
		headlessTarget = fmt.Sprintf("%d targets", len(targets))
	}
	headlessDispCtx, headlessDispErr := headlessOutputFlags.InitDispatcher(headlessScanID, headlessTarget)
	if headlessDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", headlessDispErr))
	}
	if headlessDispCtx != nil {
		defer headlessDispCtx.Close()
	}
	headlessStartTime := time.Now()

	ctx := context.Background()

	// Emit start event for scan lifecycle hooks
	if headlessDispCtx != nil {
		_ = headlessDispCtx.EmitStart(ctx, headlessTarget, len(targets), 1, nil)
	}

	allResults := []*headless.PageResult{}

	// Determine output mode
	outputMode := ui.DefaultOutputMode()
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Display execution manifest and progress for multi-target
	var progress *ui.LiveProgress
	if len(targets) > 1 {
		if !*streamMode {
			manifest := ui.NewExecutionManifest("HEADLESS BROWSER TESTING")
			manifest.SetDescription("Visiting pages with headless browser")
			manifest.AddEmphasis("🎯", "Targets", fmt.Sprintf("%d URLs", len(targets)))
			manifest.AddWithIcon("🌐", "Headless", fmt.Sprintf("%v", *headlessMode))
			manifest.AddWithIcon("⏱️", "Timeout", fmt.Sprintf("%ds", *timeout))
			if *screenshot {
				manifest.AddWithIcon("📸", "Screenshots", *screenshotDir)
			}
			manifest.Print()
		} else {
			fmt.Printf("[INFO] Starting headless browsing: targets=%d headless=%v\n",
				len(targets), *headlessMode)
		}

		// Use unified LiveProgress component
		progress = ui.NewLiveProgress(ui.LiveProgressConfig{
			Total:        len(targets),
			DisplayLines: 2,
			Title:        "Browsing pages",
			Unit:         "pages",
			Mode:         outputMode,
			Metrics: []ui.MetricConfig{
				{Name: "urls", Label: "URLs Found", Icon: ui.Icon("🔗", "~")},
			},
		})
		progress.Start()
	}

	for _, target := range targets {
		if len(targets) == 1 {
			ui.PrintInfo(fmt.Sprintf("Visiting: %s", target))
		}

		result, err := browser.Visit(ctx, target)
		if err != nil {
			if len(targets) == 1 {
				ui.PrintError(fmt.Sprintf("  Error: %v", err))
			}
			// Emit error to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
			if headlessDispCtx != nil {
				_ = headlessDispCtx.EmitError(ctx, "headless", fmt.Sprintf("Visit error for %s: %v", target, err), false)
			}
			if progress != nil {
				progress.Increment()
			}
			continue
		}

		allResults = append(allResults, result)
		if progress != nil {
			progress.Increment()
			progress.AddMetricBy("urls", len(result.FoundURLs))
		}

		if len(targets) == 1 {
			fmt.Printf("  Status: %d\n", result.StatusCode)
			fmt.Printf("  Title: %s\n", result.Title)

			if *extractURLs && len(result.FoundURLs) > 0 {
				fmt.Printf("  URLs found: %d\n", len(result.FoundURLs))
				if *verbose {
					for i, u := range result.FoundURLs {
						if i < 10 {
							fmt.Printf("    - %s\n", u.URL)
						}
					}
					if len(result.FoundURLs) > 10 {
						fmt.Printf("    ... and %d more\n", len(result.FoundURLs)-10)
					}
				}
			}

			if *screenshot && result.ScreenshotPath != "" {
				fmt.Printf("  Screenshot: %s\n", result.ScreenshotPath)
			}

			fmt.Println()
		}
	}

	// Stop progress
	if progress != nil {
		progress.Stop()
	}

	// Event crawl: use chromedp to click interactive elements and discover hidden endpoints
	var eventCrawlResults []headless.EventCrawlResult
	if *eventCrawl && len(targets) > 0 {
		ui.PrintSection("DOM Event Crawling")

		eventConfig := headless.DefaultEventCrawlConfig()
		eventConfig.MaxClicks = *maxClicks
		eventConfig.ClickTimeout = time.Duration(*clickTimeout) * time.Second

		// Create a chromedp context for event crawling
		allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", *headlessMode),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
		)
		if *chromePath != "" {
			allocOpts = append(allocOpts, chromedp.ExecPath(*chromePath))
		}

		allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
		defer allocCancel()

		browserCtx, browserCancel := chromedp.NewContext(allocCtx)
		defer browserCancel()

		for _, target := range targets {
			ui.PrintInfo(fmt.Sprintf("Event crawling: %s", target))

			results, err := headless.EventCrawl(browserCtx, target, eventConfig)
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Event crawl failed for %s: %v", target, err))
				continue
			}

			eventCrawlResults = append(eventCrawlResults, results...)

			// Collect discovered URLs
			discoveredURLs := headless.CollectDiscoveredURLs(results, target, true)
			if len(discoveredURLs) > 0 {
				ui.PrintSuccess(fmt.Sprintf("Discovered %d hidden endpoints via DOM events", len(discoveredURLs)))
				if *verbose {
					for i, u := range discoveredURLs {
						if i >= 10 {
							fmt.Printf("    ... and %d more\n", len(discoveredURLs)-10)
							break
						}
						fmt.Printf("    - %s\n", u)
					}
				}
			}

			// Count XHR/API calls found
			xhrCount := 0
			for _, r := range results {
				xhrCount += len(r.XHRRequests)
			}
			if xhrCount > 0 {
				ui.PrintInfo(fmt.Sprintf("Captured %d XHR/API requests", xhrCount))
			}
		}
	}

	// Summary
	ui.PrintSection("Summary")
	fmt.Printf("  Pages visited: %d\n", len(allResults))
	totalURLs := 0
	for _, r := range allResults {
		totalURLs += len(r.FoundURLs)
	}
	fmt.Printf("  URLs extracted: %d\n", totalURLs)
	if len(eventCrawlResults) > 0 {
		eventURLs := 0
		eventXHR := 0
		for _, r := range eventCrawlResults {
			eventURLs += len(r.DiscoveredURLs)
			eventXHR += len(r.XHRRequests)
		}
		fmt.Printf("  Event crawl clicks: %d\n", len(eventCrawlResults))
		fmt.Printf("  Event crawl URLs: %d\n", eventURLs)
		fmt.Printf("  Event crawl XHR: %d\n", eventXHR)
	}

	// Output
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(allResults); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to encode JSON: %v", err))
		}
	}

	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create output file: %v", err))
		} else {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			encErr := enc.Encode(allResults)
			closeErr := f.Close()
			if encErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to encode results: %v", encErr))
			} else if closeErr != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to close output file: %v", closeErr))
			} else {
				ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
			}
		}
	}

	// Emit summary to hooks
	if headlessDispCtx != nil {
		headlessDuration := time.Since(headlessStartTime)
		_ = headlessDispCtx.EmitSummary(ctx, len(allResults), 0, totalURLs, headlessDuration)
		// Emit individual page results with extracted URLs
		for _, result := range allResults {
			// Emit the page visit as a result
			pageDesc := fmt.Sprintf("Page visited: %s (status: %d, title: %s, URLs: %d)",
				result.URL, result.StatusCode, result.Title, len(result.FoundURLs))
			_ = headlessDispCtx.EmitBypass(ctx, "headless-page", "info", result.URL, pageDesc, result.StatusCode)
			// Emit interesting URLs discovered (API endpoints, XHR, etc.)
			for _, foundURL := range result.FoundURLs {
				if foundURL.Source == "xhr" || foundURL.Source == "action" || foundURL.Source == "js" {
					urlDesc := fmt.Sprintf("Discovered %s URL: %s", foundURL.Source, foundURL.URL)
					_ = headlessDispCtx.EmitBypass(ctx, "headless-discovered-url", "info", foundURL.URL, urlDesc, 0)
				}
			}
		}
	}
}
