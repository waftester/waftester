package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/ui"
)

func runDiscover() {
	ui.PrintCompactBanner()
	ui.PrintSection("Target Discovery")

	discoverFlags := flag.NewFlagSet("discover", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	discoverFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	discoverFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := discoverFlags.String("l", "", "File containing target URLs")
	stdinInput := discoverFlags.Bool("stdin", false, "Read targets from stdin")
	service := discoverFlags.String("service", "", "Service type: wordpress, drupal, nextjs, flask, django")
	outputFile := discoverFlags.String("output", "discovery.json", "Output file for discovery results")
	timeout := discoverFlags.Int("timeout", 10, "HTTP request timeout in seconds")
	concurrency := discoverFlags.Int("concurrency", 10, "Number of parallel discovery workers")
	maxDepth := discoverFlags.Int("depth", 3, "Maximum crawl depth")
	skipVerify := discoverFlags.Bool("skip-verify", false, "Skip TLS certificate verification")
	verbose := discoverFlags.Bool("verbose", false, "Show detailed discovery output")

	// Enterprise hook flags (Slack, Teams, PagerDuty, OTEL, etc.)
	discoverSlack := discoverFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	discoverTeams := discoverFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	discoverPagerDuty := discoverFlags.String("pagerduty-key", "", "PagerDuty routing key")
	discoverOtel := discoverFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	discoverWebhook := discoverFlags.String("webhook-url", "", "Generic webhook URL")

	discoverFlags.Parse(os.Args[2:])

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
	if *service != "" {
		ui.PrintConfigLine("Service", *service)
	}
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	ui.PrintConfigLine("Max Depth", fmt.Sprintf("%d", *maxDepth))
	ui.PrintConfigLine("Output", *outputFile)
	fmt.Fprintln(os.Stderr)

	// Initialize dispatcher for hooks (Slack, Teams, PagerDuty, OTEL, etc.)
	discoverOutputFlags := OutputFlags{
		SlackWebhook: *discoverSlack,
		TeamsWebhook: *discoverTeams,
		PagerDutyKey: *discoverPagerDuty,
		OTelEndpoint: *discoverOtel,
		WebhookURL:   *discoverWebhook,
	}
	discoverScanID := fmt.Sprintf("discover-%d", time.Now().Unix())
	discoverDispCtx, discoverDispErr := discoverOutputFlags.InitDispatcher(discoverScanID, target)
	if discoverDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", discoverDispErr))
	}
	if discoverDispCtx != nil {
		defer discoverDispCtx.Close()
		_ = discoverDispCtx.EmitStart(context.Background(), target, 0, *concurrency, nil)
	}

	// Create discoverer
	cfg := discovery.DiscoveryConfig{
		Target:      target,
		Service:     *service,
		Timeout:     time.Duration(*timeout) * time.Second,
		Concurrency: *concurrency,
		MaxDepth:    *maxDepth,
		SkipVerify:  *skipVerify,
	}

	discoverer := discovery.NewDiscoverer(cfg)

	// Setup context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), duration.ContextMedium)
	defer cancel()

	// Run discovery
	ui.PrintInfo("Starting endpoint discovery...")
	fmt.Fprintln(os.Stderr)

	result, err := discoverer.Discover(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("Discovery error: %v", err)
		ui.PrintError(errMsg)
		if discoverDispCtx != nil {
			_ = discoverDispCtx.EmitError(ctx, "discover", errMsg, true)
			_ = discoverDispCtx.Close()
		}
		os.Exit(1)
	}

	// Display results
	ui.PrintSection("Discovery Results")
	ui.PrintConfigLine("Endpoints Found", fmt.Sprintf("%d", result.Statistics.TotalEndpoints))
	ui.PrintConfigLine("Parameters Found", fmt.Sprintf("%d", result.Statistics.TotalParameters))
	ui.PrintConfigLine("WAF Detected", fmt.Sprintf("%v", result.WAFDetected))
	if result.WAFFingerprint != "" {
		ui.PrintConfigLine("WAF Type", result.WAFFingerprint)
	}
	ui.PrintConfigLine("Duration", result.Duration.String())
	fmt.Fprintln(os.Stderr)

	// Emit security findings to hooks in real-time
	discoverCtx := context.Background()
	if discoverDispCtx != nil {
		// Emit WAF detection
		if result.WAFDetected {
			wafDesc := fmt.Sprintf("WAF detected: %s", result.WAFFingerprint)
			_ = discoverDispCtx.EmitBypass(discoverCtx, "waf-detection", "info", target, wafDesc, 0)
		}
		// Emit secrets found during discovery
		for path, secrets := range result.Secrets {
			for _, s := range secrets {
				secretDesc := fmt.Sprintf("%s found at %s", s.Type, path)
				_ = discoverDispCtx.EmitBypass(discoverCtx, "secret-exposure", s.Severity, target, secretDesc, 0)
			}
		}
		// Emit S3 buckets (potential cloud misconfigurations)
		for _, bucket := range result.S3Buckets {
			bucketDesc := fmt.Sprintf("S3 bucket discovered: %s", bucket)
			_ = discoverDispCtx.EmitBypass(discoverCtx, "s3-bucket-discovery", "medium", target, bucketDesc, 0)
		}
		// Emit subdomains
		for _, sub := range result.Subdomains {
			subDesc := fmt.Sprintf("Subdomain discovered: %s", sub)
			_ = discoverDispCtx.EmitBypass(discoverCtx, "subdomain-discovery", "info", target, subDesc, 0)
		}
		// Emit high-risk attack surface features
		surface := result.AttackSurface
		if surface.HasFileUpload {
			_ = discoverDispCtx.EmitBypass(discoverCtx, "attack-surface-upload", "high", target, "File upload endpoints detected", 0)
		}
		if surface.HasGraphQL {
			_ = discoverDispCtx.EmitBypass(discoverCtx, "attack-surface-graphql", "medium", target, "GraphQL endpoint detected", 0)
		}
		if surface.HasWebSockets {
			_ = discoverDispCtx.EmitBypass(discoverCtx, "attack-surface-websocket", "medium", target, "WebSocket endpoints detected", 0)
		}
		if surface.HasOAuth {
			_ = discoverDispCtx.EmitBypass(discoverCtx, "attack-surface-oauth", "medium", target, "OAuth endpoints detected", 0)
		}
		if surface.HasSAML {
			_ = discoverDispCtx.EmitBypass(discoverCtx, "attack-surface-saml", "medium", target, "SAML endpoints detected", 0)
		}
		if surface.HasAuthEndpoints {
			_ = discoverDispCtx.EmitBypass(discoverCtx, "attack-surface-auth", "high", target, "Authentication endpoints detected", 0)
		}

		// Emit discovered endpoints (attack surface inventory)
		for _, ep := range result.Endpoints {
			epMethod := ep.Method
			if epMethod == "" {
				epMethod = "GET"
			}
			epDesc := fmt.Sprintf("Endpoint discovered: %s %s (category: %s, status: %d)", epMethod, ep.Path, ep.Category, ep.StatusCode)
			_ = discoverDispCtx.EmitBypass(discoverCtx, "endpoint-discovery", "info", target, epDesc, ep.StatusCode)
		}
	}

	// Show attack surface
	ui.PrintSection("Attack Surface Analysis")
	surface := result.AttackSurface
	if surface.HasAuthEndpoints {
		ui.PrintInfo(ui.Icon("✓", "+") + " Authentication endpoints detected")
	}
	if surface.HasOAuth {
		ui.PrintInfo(ui.Icon("✓", "+") + " OAuth endpoints detected")
	}
	if surface.HasSAML {
		ui.PrintInfo(ui.Icon("✓", "+") + " SAML endpoints detected")
	}
	if surface.HasAPIEndpoints {
		ui.PrintInfo(ui.Icon("✓", "+") + " API endpoints detected")
	}
	if surface.HasFileUpload {
		ui.PrintInfo(ui.Icon("✓", "+") + " File upload endpoints detected")
	}
	if surface.HasGraphQL {
		ui.PrintInfo(ui.Icon("✓", "+") + " GraphQL endpoint detected")
	}
	if surface.HasWebSockets {
		ui.PrintInfo(ui.Icon("✓", "+") + " WebSocket endpoints detected")
	}
	fmt.Fprintln(os.Stderr)

	ui.PrintConfigLine("Relevant Categories", fmt.Sprintf("%v", surface.RelevantCategories))
	fmt.Fprintln(os.Stderr)

	// Show enhanced discovery findings
	if len(result.Secrets) > 0 {
		ui.PrintSection(ui.Icon("🔑", "*") + " Secrets Detected")
		for path, secrets := range result.Secrets {
			for _, s := range secrets {
				ui.PrintError(fmt.Sprintf("[%s] %s in %s", s.Severity, s.Type, path))
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	if len(result.S3Buckets) > 0 {
		ui.PrintSection(ui.Icon("☁️", "~") + "  S3 Buckets Found")
		for _, bucket := range result.S3Buckets {
			ui.PrintInfo("  " + bucket)
		}
		fmt.Fprintln(os.Stderr)
	}

	if len(result.Subdomains) > 0 {
		ui.PrintSection(ui.Icon("🌐", ">") + " Subdomains Discovered")
		for _, sub := range result.Subdomains {
			ui.PrintInfo("  " + sub)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Show endpoints if verbose
	if *verbose {
		ui.PrintSection("Discovered Endpoints")
		for _, ep := range result.Endpoints {
			fmt.Fprintf(os.Stderr, "  [%s] %s %s (%s)\n",
				ui.StatusBracket(ep.StatusCode),
				ep.Method,
				ep.Path,
				ep.Category,
			)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Save results
	if err := result.SaveResult(*outputFile); err != nil {
		errMsg := fmt.Sprintf("Error saving results: %v", err)
		ui.PrintError(errMsg)
		if discoverDispCtx != nil {
			_ = discoverDispCtx.EmitError(discoverCtx, "discover", errMsg, true)
			_ = discoverDispCtx.Close()
		}
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("Discovery results saved to %s", *outputFile))
	fmt.Fprintln(os.Stderr)
	ui.PrintHelp("Next step: waf-tester learn -discovery " + *outputFile)

	// Emit summary to hooks
	if discoverDispCtx != nil {
		totalSecrets := 0
		for _, secrets := range result.Secrets {
			totalSecrets += len(secrets)
		}
		totalFindings := result.Statistics.TotalEndpoints + result.Statistics.TotalParameters + totalSecrets
		_ = discoverDispCtx.EmitSummary(discoverCtx, totalFindings, 0, totalFindings, result.Duration)
	}
}
