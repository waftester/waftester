// cmd/cli/fp.go - False Positive Testing Command
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/fp"
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

	// Local WAF testing
	localTest := fpFlags.Bool("local", false, "Run local WAF simulation test")

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
		TargetURL:     *target,
		Concurrency:   *concurrency,
		RateLimit:     *rateLimit,
		Timeout:       time.Duration(*timeout) * time.Second,
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

	// Run tests
	ui.PrintInfo("Running false positive tests...")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	result, err := tester.Run(ctx)
	if err != nil {
		fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Display results
	displayFPResults(result)

	// Save to file if requested
	if *output != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Println(ui.ErrorStyle.Render(fmt.Sprintf("Error saving output: %v", err)))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *output))
		}
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
		return err
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
			fmt.Printf("  [%d] Payload: %.60s...\n", i+1, truncate(fpDetail.Payload, 60))
			fmt.Printf("      Location: %s | Status: %d | Rule: %d\n",
				fpDetail.Location, fpDetail.StatusCode, fpDetail.RuleID)
		}
		if len(result.FalsePositiveDetails) > maxItems {
			fmt.Printf("  ... and %d more\n", len(result.FalsePositiveDetails)-maxItems)
		}
		fmt.Println()
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func runLocalFPTest(paranoiaLevel int, verbose bool) {
	ui.PrintInfo("Running local WAF FP simulation...")
	fmt.Println()

	waf := fp.NewLocalWAF(paranoiaLevel)
	stats := waf.TestCorpus(verbose)

	fmt.Println()
	fmt.Println(fp.FormatLocalFPReport(stats))
}
