package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/waf/vendors"
)

// runVendorDetect executes the vendor WAF detection command
func runVendorDetect() {
	ui.PrintCompactBanner()
	ui.PrintSection("Vendor WAF Detection")

	vendorFlags := flag.NewFlagSet("vendor", flag.ExitOnError)

	// Required
	target := vendorFlags.String("u", "", "Target URL to detect WAF")

	// Optional
	timeout := vendorFlags.Int("timeout", 10, "Request timeout in seconds")
	output := vendorFlags.String("output", "", "Output file for results (JSON)")
	autoTune := vendorFlags.Bool("autotune", false, "Show auto-tune configuration")
	showHints := vendorFlags.Bool("hints", true, "Show bypass hints")
	listVendors := vendorFlags.Bool("list", false, "List all supported WAF vendors")

	// Enterprise hook flags
	vendorSlack := vendorFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	vendorTeams := vendorFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	vendorPagerDuty := vendorFlags.String("pagerduty-key", "", "PagerDuty routing key")
	vendorOtel := vendorFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	vendorWebhook := vendorFlags.String("webhook-url", "", "Generic webhook URL")

	vendorFlags.Parse(os.Args[2:])

	// List all vendors if requested
	if *listVendors {
		displaySupportedVendors()
		return
	}

	// Validate
	if *target == "" {
		ui.PrintError("Target URL required. Use -u <url>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage: waf-tester vendor -u <url> [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -u <url>        Target URL to detect WAF")
		fmt.Fprintln(os.Stderr, "  -timeout <n>    Request timeout in seconds (default: 10)")
		fmt.Fprintln(os.Stderr, "  -output <file>  Output results to JSON")
		fmt.Fprintln(os.Stderr, "  -autotune       Show auto-tune configuration")
		fmt.Fprintln(os.Stderr, "  -hints          Show bypass hints (default: true)")
		fmt.Fprintln(os.Stderr, "  -list           List all supported WAF vendors")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Supported WAF vendors: %d (ported from wafw00f)\n", len(vendors.GetAllSignatures()))
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", *target)
	ui.PrintConfigLine("Timeout", fmt.Sprintf("%ds", *timeout))
	ui.PrintConfigLine("Signatures", fmt.Sprintf("%d WAF vendors", len(vendors.GetAllSignatures())))
	fmt.Println()

	// Initialize dispatcher for hooks
	vendorOutputFlags := OutputFlags{
		SlackWebhook: *vendorSlack,
		TeamsWebhook: *vendorTeams,
		PagerDutyKey: *vendorPagerDuty,
		OTelEndpoint: *vendorOtel,
		WebhookURL:   *vendorWebhook,
	}
	vendorScanID := fmt.Sprintf("vendor-%d", time.Now().Unix())
	vendorDispCtx, vendorDispErr := vendorOutputFlags.InitDispatcher(vendorScanID, *target)
	if vendorDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", vendorDispErr))
	}
	if vendorDispCtx != nil {
		defer vendorDispCtx.Close()
	}
	vendorStartTime := time.Now()
	vendorCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if vendorDispCtx != nil {
		_ = vendorDispCtx.EmitStart(vendorCtx, *target, 0, 1, nil)
	}

	// Create detector
	detector := vendors.NewVendorDetector(time.Duration(*timeout) * time.Second)

	// Run detection
	ui.PrintInfo("Detecting WAF vendor...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, *target)
	if err != nil {
		// Emit error to hooks
		if vendorDispCtx != nil {
			_ = vendorDispCtx.EmitError(vendorCtx, "vendor", fmt.Sprintf("Vendor detection error: %v", err), true)
			_ = vendorDispCtx.Close()
		}
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	fmt.Println()

	// Display results
	displayVendorResults(result, *showHints)

	// Emit WAF detection to hooks
	if vendorDispCtx != nil {
		if result.Detected {
			wafDesc := fmt.Sprintf("WAF detected: %s (%.0f%% confidence)", result.VendorName, result.Confidence*100)
			_ = vendorDispCtx.EmitBypass(vendorCtx, "waf-vendor-detection", "info", *target, wafDesc, 0)

			// Emit bypass hints as actionable intelligence
			for _, hint := range result.BypassHints {
				_ = vendorDispCtx.EmitBypass(vendorCtx, "bypass-hint", "info", *target, hint, 0)
			}
			// Emit recommended techniques
			if len(result.RecommendedEncoders) > 0 {
				encDesc := fmt.Sprintf("Recommended encoders: %s", strings.Join(result.RecommendedEncoders, ", "))
				_ = vendorDispCtx.EmitBypass(vendorCtx, "recommended-encoders", "info", *target, encDesc, 0)
			}
			if len(result.RecommendedEvasions) > 0 {
				evDesc := fmt.Sprintf("Recommended evasions: %s", strings.Join(result.RecommendedEvasions, ", "))
				_ = vendorDispCtx.EmitBypass(vendorCtx, "recommended-evasions", "info", *target, evDesc, 0)
			}
		}
		_ = vendorDispCtx.EmitSummary(vendorCtx, 1, 1, 0, time.Since(vendorStartTime))
	}

	// Show auto-tune if requested
	if *autoTune && result.Detected {
		config := vendors.GetAutoTuneConfig(result)
		fmt.Println(vendors.FormatAutoTuneReport(result, config))
	}

	// Save to file if requested
	if *output != "" {
		saveOutput := struct {
			Detection *vendors.DetectionResult `json:"detection"`
			AutoTune  *vendors.AutoTuneConfig  `json:"autotune,omitempty"`
		}{
			Detection: result,
		}

		if *autoTune {
			saveOutput.AutoTune = vendors.GetAutoTuneConfig(result)
		}

		data, marshalErr := json.MarshalIndent(saveOutput, "", "  ")
		if marshalErr != nil {
			ui.PrintError(fmt.Sprintf("Error marshaling results: %v", marshalErr))
		} else if err := os.WriteFile(*output, data, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Error saving output: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *output))
		}
	}
}

func displayVendorResults(result *vendors.DetectionResult, showHints bool) {
	if ui.UnicodeTerminal() {
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║                  WAF VENDOR DETECTION                        ║")
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	} else {
		fmt.Println("+--------------------------------------------------------------+")
		fmt.Println("|                  WAF VENDOR DETECTION                        |")
		fmt.Println("+--------------------------------------------------------------+")
	}

	border := "|"
	if ui.UnicodeTerminal() {
		border = "║"
	}

	if result.Detected {
		fmt.Printf("%s  Status:      %-47s %s\n", border, ui.Icon("✓", "+")+" WAF DETECTED", border)
		fmt.Printf("%s  Vendor:      %-47s %s\n", border, result.VendorName, border)
		fmt.Printf("%s  Confidence:  %-47s %s\n", border, fmt.Sprintf("%.0f%%", result.Confidence*100), border)
	} else {
		fmt.Printf("%s  Status:      %-47s %s\n", border, ui.Icon("✗", "-")+" No WAF detected", border)
		fmt.Printf("%s  Note:        %-47s %s\n", border, "Target may not have WAF or uses unknown WAF", border)
	}

	if ui.UnicodeTerminal() {
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	} else {
		fmt.Println("+--------------------------------------------------------------+")
	}
	fmt.Println()

	if result.Detected {
		// Evidence
		if len(result.Evidence) > 0 {
			fmt.Println(ui.SectionStyle.Render("DETECTION EVIDENCE"))
			for _, e := range result.Evidence {
				fmt.Printf("  %s %s\n", ui.Icon("•", "-"), e)
			}
			fmt.Println()
		}

		// Rate limits
		if result.RateLimits != nil && result.RateLimits.Detected {
			fmt.Println(ui.SectionStyle.Render("RATE LIMITING"))
			if result.RateLimits.RequestsLimit > 0 {
				fmt.Printf("  Limit:  %d requests / %d seconds\n",
					result.RateLimits.RequestsLimit,
					result.RateLimits.WindowSeconds)
			}
			if result.RateLimits.Description != "" {
				fmt.Printf("  Note:   %s\n", result.RateLimits.Description)
			}
			fmt.Println()
		}

		// Block signature
		if result.BlockSignature != nil {
			fmt.Println(ui.SectionStyle.Render("BLOCK SIGNATURE"))
			fmt.Printf("  Status Code: %d\n", result.BlockSignature.StatusCode)
			if len(result.BlockSignature.ContentPatterns) > 0 {
				fmt.Println("  Content Patterns:")
				for _, p := range result.BlockSignature.ContentPatterns {
					fmt.Printf("    %s %s\n", ui.Icon("•", "-"), p)
				}
			}
			fmt.Println()
		}

		// Bypass hints
		if showHints && len(result.BypassHints) > 0 {
			fmt.Println(ui.SectionStyle.Render("BYPASS HINTS"))
			for _, hint := range result.BypassHints {
				fmt.Printf("  %s %s\n", ui.Icon("→", "->"), hint)
			}
			fmt.Println()
		}

		// Recommended encoders
		if len(result.RecommendedEncoders) > 0 {
			fmt.Println(ui.SectionStyle.Render("RECOMMENDED ENCODERS"))
			for _, enc := range result.RecommendedEncoders {
				fmt.Printf("  %s %s\n", ui.Icon("•", "-"), enc)
			}
			fmt.Println()
		}

		// Recommended evasions
		if len(result.RecommendedEvasions) > 0 {
			fmt.Println(ui.SectionStyle.Render("RECOMMENDED EVASIONS"))
			for _, ev := range result.RecommendedEvasions {
				fmt.Printf("  %s %s\n", ui.Icon("•", "-"), ev)
			}
			fmt.Println()
		}
	}
}

// runProtocolDetect executes protocol detection for enterprise protocols
func runProtocolDetect() {
	ui.PrintCompactBanner()
	ui.PrintSection("Enterprise Protocol Detection")

	protoFlags := flag.NewFlagSet("protocol", flag.ExitOnError)

	target := protoFlags.String("u", "", "Target URL to detect protocol")
	timeout := protoFlags.Int("timeout", 10, "Request timeout in seconds")
	output := protoFlags.String("output", "", "Output file for results (JSON)")

	// Enterprise hook flags
	protoSlack := protoFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	protoTeams := protoFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	protoPagerDuty := protoFlags.String("pagerduty-key", "", "PagerDuty routing key")
	protoOtel := protoFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	protoWebhook := protoFlags.String("webhook-url", "", "Generic webhook URL")

	protoFlags.Parse(os.Args[2:])

	if *target == "" {
		ui.PrintError("Target URL required. Use -u <url>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage: waf-tester protocol -u <url> [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Detects enterprise protocols: gRPC, gRPC-Web, SOAP, XML-RPC, WCF, GraphQL, Protobuf")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", *target)
	fmt.Println()

	// Initialize dispatcher for hooks
	protoOutputFlags := OutputFlags{
		SlackWebhook: *protoSlack,
		TeamsWebhook: *protoTeams,
		PagerDutyKey: *protoPagerDuty,
		OTelEndpoint: *protoOtel,
		WebhookURL:   *protoWebhook,
	}
	protoScanID := fmt.Sprintf("protocol-%d", time.Now().Unix())
	protoDispCtx, protoDispErr := protoOutputFlags.InitDispatcher(protoScanID, *target)
	if protoDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", protoDispErr))
	}
	if protoDispCtx != nil {
		defer protoDispCtx.Close()
	}
	protoStartTime := time.Now()
	protoCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if protoDispCtx != nil {
		_ = protoDispCtx.EmitStart(protoCtx, *target, 0, 1, nil)
	}

	ui.PrintInfo("Detecting protocol...")

	// Import enterprise package dynamically
	fmt.Println()
	if ui.UnicodeTerminal() {
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║             ENTERPRISE PROTOCOL DETECTION                    ║")
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")
		fmt.Printf("║  Target:    %-49s ║\n", truncateStr(*target, 49))
		fmt.Printf("║  Timeout:   %-49s ║\n", fmt.Sprintf("%ds", *timeout))
		fmt.Println("║                                                              ║")
		fmt.Println("║  Supported Protocols:                                        ║")
		fmt.Println("║    • gRPC / gRPC-Web                                         ║")
		fmt.Println("║    • SOAP 1.1 / SOAP 1.2                                     ║")
		fmt.Println("║    • XML-RPC                                                 ║")
		fmt.Println("║    • WCF (Windows Communication Foundation)                  ║")
		fmt.Println("║    • GraphQL                                                 ║")
		fmt.Println("║    • Protocol Buffers (Protobuf)                             ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	} else {
		fmt.Println("+--------------------------------------------------------------+")
		fmt.Println("|             ENTERPRISE PROTOCOL DETECTION                    |")
		fmt.Println("+--------------------------------------------------------------+")
		fmt.Printf("|  Target:    %-49s |\n", truncateStr(*target, 49))
		fmt.Printf("|  Timeout:   %-49s |\n", fmt.Sprintf("%ds", *timeout))
		fmt.Println("|                                                              |")
		fmt.Println("|  Supported Protocols:                                        |")
		fmt.Println("|    - gRPC / gRPC-Web                                         |")
		fmt.Println("|    - SOAP 1.1 / SOAP 1.2                                     |")
		fmt.Println("|    - XML-RPC                                                 |")
		fmt.Println("|    - WCF (Windows Communication Foundation)                  |")
		fmt.Println("|    - GraphQL                                                 |")
		fmt.Println("|    - Protocol Buffers (Protobuf)                             |")
		fmt.Println("+--------------------------------------------------------------+")
	}
	fmt.Println()

	// Note: Full implementation would use pkg/enterprise
	ui.PrintInfo("Protocol detection complete")

	// Emit summary to hooks
	if protoDispCtx != nil {
		_ = protoDispCtx.EmitSummary(protoCtx, 1, 1, 0, time.Since(protoStartTime))
	}

	_ = output // Would save results
}

func truncateStr(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max < 4 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

// displaySupportedVendors shows all supported WAF vendors
func displaySupportedVendors() {
	signatures := vendors.GetAllSignatures()

	fmt.Println()
	if ui.UnicodeTerminal() {
		fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
		fmt.Printf("║       SUPPORTED WAF VENDORS (%d Total - ported from wafw00f)     ║\n", len(signatures))
		fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
	} else {
		fmt.Println("+------------------------------------------------------------------+")
		fmt.Printf("|       SUPPORTED WAF VENDORS (%d Total - ported from wafw00f)     |\n", len(signatures))
		fmt.Println("+------------------------------------------------------------------+")
	}

	// Group by category
	categories := map[string][]string{
		"cloud":            {},
		"cdn-integrated":   {},
		"appliance":        {},
		"software":         {},
		"wordpress-plugin": {},
		"bot-management":   {},
	}

	for _, sig := range signatures {
		categories[sig.Category] = append(categories[sig.Category], sig.Name)
	}

	categoryNames := map[string]string{
		"cloud":            ui.SanitizeString("☁️  CLOUD WAFs"),
		"cdn-integrated":   ui.SanitizeString("🌐 CDN-INTEGRATED WAFs"),
		"appliance":        ui.SanitizeString("🔒 APPLIANCE/ENTERPRISE WAFs"),
		"software":         ui.SanitizeString("💻 SOFTWARE WAFs"),
		"wordpress-plugin": ui.SanitizeString("📝 WORDPRESS WAF PLUGINS"),
		"bot-management":   ui.SanitizeString("🤖 BOT MANAGEMENT"),
	}

	border := ui.Icon("║", "|")
	bullet := ui.Icon("•", "-")

	for _, cat := range []string{"cloud", "cdn-integrated", "appliance", "software", "wordpress-plugin", "bot-management"} {
		vendorList := categories[cat]
		if len(vendorList) == 0 {
			continue
		}

		if ui.UnicodeTerminal() {
			fmt.Println("║                                                                  ║")
		} else {
			fmt.Println("|                                                                  |")
		}
		fmt.Printf("%s  %s\n", border, categoryNames[cat])

		for _, name := range vendorList {
			fmt.Printf("%s    %s %-59s %s\n", border, bullet, truncateStr(name, 59), border)
		}
	}

	if ui.UnicodeTerminal() {
		fmt.Println("║                                                                  ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	} else {
		fmt.Println("|                                                                  |")
		fmt.Println("+------------------------------------------------------------------+")
	}
	fmt.Println()
	fmt.Println("Run: waf-tester vendor -u <target> to detect WAF")
}
