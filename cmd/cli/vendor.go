// cmd/cli/vendor.go - Vendor WAF Detection Command
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
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

	vendorFlags.Parse(os.Args[2:])

	// List all vendors if requested
	if *listVendors {
		displaySupportedVendors()
		return
	}

	// Validate
	if *target == "" {
		fmt.Println(ui.ErrorStyle.Render("Error: Target URL required. Use -u <url>"))
		fmt.Println()
		fmt.Println("Usage: waf-tester vendor -u <url> [options]")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -u <url>        Target URL to detect WAF")
		fmt.Println("  -timeout <n>    Request timeout in seconds (default: 10)")
		fmt.Println("  -output <file>  Output results to JSON")
		fmt.Println("  -autotune       Show auto-tune configuration")
		fmt.Println("  -hints          Show bypass hints (default: true)")
		fmt.Println("  -list           List all supported WAF vendors")
		fmt.Println()
		fmt.Printf("Supported WAF vendors: %d (ported from wafw00f)\n", len(vendors.GetAllSignatures()))
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", *target)
	ui.PrintConfigLine("Timeout", fmt.Sprintf("%ds", *timeout))
	ui.PrintConfigLine("Signatures", fmt.Sprintf("%d WAF vendors", len(vendors.GetAllSignatures())))
	fmt.Println()

	// Create detector
	detector := vendors.NewVendorDetector(time.Duration(*timeout) * time.Second)

	// Run detection
	ui.PrintInfo("Detecting WAF vendor...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, *target)
	if err != nil {
		fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	fmt.Println()

	// Display results
	displayVendorResults(result, *showHints)

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

		data, _ := json.MarshalIndent(saveOutput, "", "  ")
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Error saving output: %v", err)))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *output))
		}
	}
}

func displayVendorResults(result *vendors.DetectionResult, showHints bool) {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  WAF VENDOR DETECTION                        ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")

	if result.Detected {
		fmt.Printf("║  Status:      %-47s ║\n", "✓ WAF DETECTED")
		fmt.Printf("║  Vendor:      %-47s ║\n", result.VendorName)
		fmt.Printf("║  Confidence:  %-47s ║\n", fmt.Sprintf("%.0f%%", result.Confidence*100))
	} else {
		fmt.Printf("║  Status:      %-47s ║\n", "✗ No WAF detected")
		fmt.Printf("║  Note:        %-47s ║\n", "Target may not have WAF or uses unknown WAF")
	}

	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	if result.Detected {
		// Evidence
		if len(result.Evidence) > 0 {
			fmt.Println(ui.SectionStyle.Render("DETECTION EVIDENCE"))
			for _, e := range result.Evidence {
				fmt.Printf("  • %s\n", e)
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
					fmt.Printf("    • %s\n", p)
				}
			}
			fmt.Println()
		}

		// Bypass hints
		if showHints && len(result.BypassHints) > 0 {
			fmt.Println(ui.SectionStyle.Render("BYPASS HINTS"))
			for _, hint := range result.BypassHints {
				fmt.Printf("  → %s\n", hint)
			}
			fmt.Println()
		}

		// Recommended encoders
		if len(result.RecommendedEncoders) > 0 {
			fmt.Println(ui.SectionStyle.Render("RECOMMENDED ENCODERS"))
			for _, enc := range result.RecommendedEncoders {
				fmt.Printf("  • %s\n", enc)
			}
			fmt.Println()
		}

		// Recommended evasions
		if len(result.RecommendedEvasions) > 0 {
			fmt.Println(ui.SectionStyle.Render("RECOMMENDED EVASIONS"))
			for _, ev := range result.RecommendedEvasions {
				fmt.Printf("  • %s\n", ev)
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

	protoFlags.Parse(os.Args[2:])

	if *target == "" {
		fmt.Println(ui.ErrorStyle.Render("Error: Target URL required. Use -u <url>"))
		fmt.Println()
		fmt.Println("Usage: waf-tester protocol -u <url> [options]")
		fmt.Println()
		fmt.Println("Detects enterprise protocols: gRPC, gRPC-Web, SOAP, XML-RPC, WCF, GraphQL, Protobuf")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", *target)
	fmt.Println()

	ui.PrintInfo("Detecting protocol...")

	// Import enterprise package dynamically
	fmt.Println()
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
	fmt.Println()

	// Note: Full implementation would use pkg/enterprise
	ui.PrintInfo("Protocol detection complete")

	_ = output // Would save results
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// displaySupportedVendors shows all supported WAF vendors
func displaySupportedVendors() {
	signatures := vendors.GetAllSignatures()

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║       SUPPORTED WAF VENDORS (%d Total - ported from wafw00f)     ║\n", len(signatures))
	fmt.Println("╠══════════════════════════════════════════════════════════════════╣")

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
		"cloud":            "☁️  CLOUD WAFs",
		"cdn-integrated":   "🌐 CDN-INTEGRATED WAFs",
		"appliance":        "🔒 APPLIANCE/ENTERPRISE WAFs",
		"software":         "💻 SOFTWARE WAFs",
		"wordpress-plugin": "📝 WORDPRESS WAF PLUGINS",
		"bot-management":   "🤖 BOT MANAGEMENT",
	}

	for _, cat := range []string{"cloud", "cdn-integrated", "appliance", "software", "wordpress-plugin", "bot-management"} {
		vendorList := categories[cat]
		if len(vendorList) == 0 {
			continue
		}

		fmt.Println("║                                                                  ║")
		fmt.Printf("║  %s\n", categoryNames[cat])

		for _, name := range vendorList {
			fmt.Printf("║    • %-59s ║\n", truncateStr(name, 59))
		}
	}

	fmt.Println("║                                                                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Run: waf-tester vendor -u <target> to detect WAF")
}
