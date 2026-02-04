package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/learning"
	"github.com/waftester/waftester/pkg/ui"
)

func runLearn() {
	ui.PrintCompactBanner()
	ui.PrintSection("Test Plan Generation")

	learnFlags := flag.NewFlagSet("learn", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	learnFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	learnFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := learnFlags.String("l", "", "File containing target URLs")
	stdinInput := learnFlags.Bool("stdin", false, "Read targets from stdin")
	discoveryFile := learnFlags.String("discovery", "discovery.json", "Discovery results file")
	payloadDir := learnFlags.String("payloads", "../payloads", "Payload directory")
	outputPlan := learnFlags.String("output", "testplan.json", "Output test plan file")
	outputPayloads := learnFlags.String("custom-payloads", "", "Output file for generated custom payloads")
	verbose := learnFlags.Bool("verbose", false, "Show detailed test plan")

	// Enterprise hook flags
	learnSlack := learnFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	learnTeams := learnFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	learnPagerDuty := learnFlags.String("pagerduty-key", "", "PagerDuty routing key")
	learnOtel := learnFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	learnWebhook := learnFlags.String("webhook-url", "", "Generic webhook URL")

	learnFlags.Parse(os.Args[2:])

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Discovery File", *discoveryFile)
	ui.PrintConfigLine("Payload Dir", *payloadDir)
	ui.PrintConfigLine("Output Plan", *outputPlan)
	fmt.Println()

	// Initialize dispatcher for hooks
	learnOutputFlags := OutputFlags{
		SlackWebhook: *learnSlack,
		TeamsWebhook: *learnTeams,
		PagerDutyKey: *learnPagerDuty,
		OTelEndpoint: *learnOtel,
		WebhookURL:   *learnWebhook,
	}
	learnScanID := fmt.Sprintf("learn-%d", time.Now().Unix())
	learnDispCtx, learnDispErr := learnOutputFlags.InitDispatcher(learnScanID, target)
	if learnDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", learnDispErr))
	}
	if learnDispCtx != nil {
		defer learnDispCtx.Close()
	}
	learnStartTime := time.Now()
	learnCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if learnDispCtx != nil {
		_ = learnDispCtx.EmitStart(learnCtx, target, 0, 1, nil)
	}

	// Load discovery results
	ui.PrintInfo("Loading discovery results...")
	disc, err := discovery.LoadResult(*discoveryFile)
	if err != nil {
		errMsg := fmt.Sprintf("Error loading discovery file: %v", err)
		ui.PrintError(errMsg)
		ui.PrintHelp("Run 'waf-tester discover' first to generate discovery.json")
		_ = learnDispCtx.EmitError(learnCtx, "learn", errMsg, true)
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("Loaded discovery for %s (%d endpoints)", disc.Target, len(disc.Endpoints)))
	fmt.Println()

	// Generate test plan
	ui.PrintInfo("Analyzing attack surface and generating test plan...")
	learner := learning.NewLearner(disc, *payloadDir)
	plan := learner.GenerateTestPlan()

	// Emit test plan to hooks (attack categories identified for testing)
	if learnDispCtx != nil {
		for _, group := range plan.TestGroups {
			groupDesc := fmt.Sprintf("Test plan: [P%d] %s - %s", group.Priority, group.Category, group.Reason)
			severity := "info"
			if group.Priority == 1 {
				severity = "high"
			} else if group.Priority == 2 {
				severity = "medium"
			}
			_ = learnDispCtx.EmitBypass(learnCtx, "test-plan-category", severity, plan.Target, groupDesc, 0)
		}
	}

	// Display plan summary
	ui.PrintSection("Test Plan Summary")
	ui.PrintConfigLine("Target", plan.Target)
	if plan.Service != "" {
		ui.PrintConfigLine("Service", plan.Service)
	}
	ui.PrintConfigLine("Total Tests", fmt.Sprintf("%d", plan.TotalTests))
	ui.PrintConfigLine("Estimated Time", plan.EstimatedTime)
	fmt.Println()

	// Show test groups
	ui.PrintSection("Test Categories (by priority)")
	for _, group := range plan.TestGroups {
		fmt.Printf("  [P%d] %s - %s\n",
			group.Priority,
			ui.StatValueStyle.Render(group.Category),
			group.Reason,
		)
	}
	fmt.Println()

	// Show endpoint-specific tests if verbose
	if *verbose {
		ui.PrintSection("Endpoint-Specific Tests")
		for _, set := range plan.EndpointTests {
			fmt.Printf("  %s %s\n", set.Endpoint.Method, set.Endpoint.Path)
			fmt.Printf("    Attack Categories: %v\n", set.AttackCategories)
			fmt.Printf("    Injection Points: %d\n", len(set.InjectPoints))
			fmt.Printf("    Custom Payloads: %d\n", len(set.CustomPayloads))
		}
		fmt.Println()
	}

	// Show recommended config
	ui.PrintSection("Recommended Configuration")
	cfg := plan.RecommendedFlags
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", cfg.Concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d req/sec", cfg.RateLimit))
	ui.PrintConfigLine("Categories", fmt.Sprintf("%v", cfg.Categories))
	if len(cfg.FocusAreas) > 0 {
		ui.PrintConfigLine("Focus Areas", fmt.Sprintf("%v", cfg.FocusAreas))
	}
	fmt.Println()

	// Save test plan
	if err := plan.SavePlan(*outputPlan); err != nil {
		errMsg := fmt.Sprintf("Error saving test plan: %v", err)
		ui.PrintError(errMsg)
		_ = learnDispCtx.EmitError(learnCtx, "learn", errMsg, true)
		os.Exit(1)
	}
	ui.PrintSuccess(fmt.Sprintf("Test plan saved to %s", *outputPlan))

	// Save custom payloads if requested
	if *outputPayloads != "" {
		if err := plan.GeneratePayloadFile(*outputPayloads); err != nil {
			errMsg := fmt.Sprintf("Error saving custom payloads: %v", err)
			ui.PrintError(errMsg)
			_ = learnDispCtx.EmitError(learnCtx, "learn", errMsg, true)
			os.Exit(1)
		}
		ui.PrintSuccess(fmt.Sprintf("Custom payloads saved to %s", *outputPayloads))
	}

	fmt.Println()

	// Build the run command
	categories := ""
	if len(cfg.Categories) > 0 {
		categories = cfg.Categories[0]
	}

	runCmd := fmt.Sprintf("waf-tester run -target %s -c %d -rate %d",
		plan.Target, cfg.Concurrency, cfg.RateLimit)
	if categories != "" {
		runCmd += " -category " + categories
	}
	if *outputPayloads != "" {
		runCmd += " -payloads " + *outputPayloads
	}

	ui.PrintHelp("Next step: " + runCmd)

	// Emit success summary
	if learnDispCtx != nil {
		_ = learnDispCtx.EmitSummary(learnCtx, plan.TotalTests, plan.TotalTests, 0, time.Since(learnStartTime))
	}
}
