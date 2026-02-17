package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/ui"
)

// runTampers handles the tampers subcommand
func runTampers() {
	ui.PrintCompactBanner()
	ui.PrintSection("Tamper Scripts (70+ sqlmap-compatible)")

	tamperFlags := flag.NewFlagSet("tampers", flag.ExitOnError)
	listAll := tamperFlags.Bool("list", false, "List all available tampers")
	category := tamperFlags.String("category", "", "Filter by category: encoding,space,sql,mysql,mssql,waf,http,obfuscation")
	forWAF := tamperFlags.String("for-waf", "", "Show recommended tampers for a WAF vendor")
	test := tamperFlags.String("test", "", "Test payload to transform")
	tamperNames := tamperFlags.String("tamper", "", "Comma-separated tampers to apply (for --test)")
	showMatrix := tamperFlags.Bool("matrix", false, "Show WAF intelligence matrix")
	jsonOutput := tamperFlags.Bool("json", false, "Output as JSON")
	discover := tamperFlags.Bool("discover", false, "Auto-discover WAF bypass tampers against a live target")
	discoverTarget := tamperFlags.String("target", "", "Target URL for bypass discovery (use with --discover)")
	discoverConcurrency := tamperFlags.Int("concurrency", 5, "Parallel tamper tests for discovery")
	discoverTopN := tamperFlags.Int("top-n", 5, "Top tampers to combine during discovery")
	discoverConfirm := tamperFlags.Int("confirm", 2, "Confirmation payloads per potential bypass")

	// Enterprise hook flags
	tampersSlack := tamperFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	tampersTeams := tamperFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	tampersPagerDuty := tamperFlags.String("pagerduty-key", "", "PagerDuty routing key")
	tampersOtel := tamperFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	tampersWebhook := tamperFlags.String("webhook-url", "", "Generic webhook URL")

	tamperFlags.Parse(os.Args[2:])

	// If no flags, show list
	if !*listAll && *category == "" && *forWAF == "" && *test == "" && !*showMatrix && !*discover {
		*listAll = true
	}

	// Initialize dispatcher for hooks (only for --for-waf mode which is actionable)
	var tampersDispCtx *DispatcherContext
	if *forWAF != "" {
		tampersOutputFlags := OutputFlags{
			SlackWebhook: *tampersSlack,
			TeamsWebhook: *tampersTeams,
			PagerDutyKey: *tampersPagerDuty,
			OTelEndpoint: *tampersOtel,
			WebhookURL:   *tampersWebhook,
		}
		tampersScanID := fmt.Sprintf("tampers-%d", time.Now().Unix())
		var tampersDispErr error
		tampersDispCtx, tampersDispErr = tampersOutputFlags.InitDispatcher(tampersScanID, *forWAF)
		if tampersDispErr != nil {
			ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", tampersDispErr))
		}
		if tampersDispCtx != nil {
			defer tampersDispCtx.Close()
		}
	}
	tampersStartTime := time.Now()
	tampersCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if tampersDispCtx != nil {
		_ = tampersDispCtx.EmitStart(tampersCtx, *forWAF, 0, 1, nil)
	}

	// List all tampers
	if *listAll {
		listTampers(*category, *jsonOutput)
		return
	}

	// Show tampers for a WAF vendor
	if *forWAF != "" {
		showTampersForWAF(*forWAF, *jsonOutput)
		// Emit tamper recommendations to hooks
		if tampersDispCtx != nil {
			recs := tampers.GetRecommendations(strings.ToLower(*forWAF))
			tamperDesc := fmt.Sprintf("%d tampers recommended for %s", len(recs), *forWAF)
			_ = tampersDispCtx.EmitBypass(tampersCtx, "tamper-recommendation", "info", *forWAF, tamperDesc, 0)
			_ = tampersDispCtx.EmitSummary(tampersCtx, len(recs), len(recs), 0, time.Since(tampersStartTime))
		}
		return
	}

	// Test a payload transformation
	if *test != "" {
		testTamperTransformation(*test, *tamperNames)
		return
	}

	// Show WAF intelligence matrix
	if *showMatrix {
		showWAFMatrix(*jsonOutput)
		return
	}

	// Bypass discovery mode
	if *discover {
		runBypassDiscovery(*discoverTarget, *forWAF, *discoverConcurrency, *discoverTopN, *discoverConfirm, *jsonOutput)
		return
	}
}

// listTampers lists all available tampers
func listTampers(category string, jsonOut bool) {
	allTampers := tampers.All()

	// Filter by category if specified
	if category != "" {
		cat := tampers.Category(category)
		filtered := make([]tampers.Tamper, 0)
		for _, t := range allTampers {
			if t.Category() == cat {
				filtered = append(filtered, t)
			}
		}
		allTampers = filtered
	}

	// Sort by name
	sort.Slice(allTampers, func(i, j int) bool {
		return allTampers[i].Name() < allTampers[j].Name()
	})

	if jsonOut {
		type tamperJSON struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Category    string   `json:"category"`
			Tags        []string `json:"tags,omitempty"`
		}

		result := make([]tamperJSON, 0, len(allTampers))
		for _, t := range allTampers {
			result = append(result, tamperJSON{
				Name:        t.Name(),
				Description: t.Description(),
				Category:    string(t.Category()),
				Tags:        t.Tags(),
			})
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	// Print formatted list
	ui.PrintInfo(fmt.Sprintf("Available Tampers: %d", len(allTampers)))
	fmt.Println()

	// Group by category
	byCategory := make(map[tampers.Category][]tampers.Tamper)
	for _, t := range allTampers {
		byCategory[t.Category()] = append(byCategory[t.Category()], t)
	}

	// Print categories in order
	categories := tampers.Categories()
	for _, cat := range categories {
		tampersInCat := byCategory[cat]
		if len(tampersInCat) == 0 {
			continue
		}

		fmt.Printf("  %s (%d)\n", ui.SectionStyle.Render(string(cat)), len(tampersInCat))
		for _, t := range tampersInCat {
			fmt.Printf("    %-30s %s\n",
				ui.ConfigLabelStyle.Render(t.Name()),
				ui.HelpStyle.Render(t.Description()))
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("Usage examples:")
	fmt.Println("  waf-tester scan -u https://target.com --tamper=space2comment,randomcase")
	fmt.Println("  waf-tester auto -u https://target.com --tamper-auto")
	fmt.Println("  waf-tester tampers --for-waf=cloudflare")
	fmt.Println("  waf-tester tampers --test \"' OR 1=1--\" --tamper=space2comment")
}

// showTampersForWAF shows recommended tampers for a specific WAF
func showTampersForWAF(wafVendor string, jsonOut bool) {
	vendor := strings.ToLower(wafVendor)
	recs := tampers.GetRecommendations(vendor)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]interface{}{
			"vendor":          vendor,
			"recommendations": recs,
		})
		return
	}

	if !tampers.HasVendor(vendor) {
		ui.PrintWarning(fmt.Sprintf("WAF vendor '%s' not found in matrix, showing defaults", wafVendor))
		fmt.Println()
		fmt.Println("Known vendors:")
		for _, v := range tampers.GetAllVendors() {
			fmt.Printf("  - %s\n", v)
		}
		fmt.Println()
	}

	ui.PrintSuccess(fmt.Sprintf("Recommended Tampers for %s", wafVendor))
	fmt.Println()

	fmt.Printf("  %-5s %-25s %-12s %s\n",
		ui.HelpStyle.Render("#"),
		ui.ConfigLabelStyle.Render("TAMPER"),
		ui.HelpStyle.Render("EFFECTIVENESS"),
		ui.HelpStyle.Render("NOTES"))
	fmt.Println("  " + strings.Repeat(ui.Icon("─", "-"), 70))

	for i, rec := range recs {
		effectBar := strings.Repeat(ui.Icon("█", "#"), int(rec.Effectiveness*10))
		effectBar += strings.Repeat(ui.Icon("░", "-"), 10-int(rec.Effectiveness*10))

		notes := rec.Notes
		if notes == "" {
			notes = "-"
		}

		fmt.Printf("  %-5d %-25s %s %.0f%%  %s\n",
			i+1,
			ui.StatValueStyle.Render(rec.Name),
			ui.PassStyle.Render(effectBar),
			rec.Effectiveness*100,
			ui.HelpStyle.Render(notes))
	}

	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  waf-tester scan -u https://target.com --tamper=%s\n",
		strings.Join(tampers.GetTopTampersForVendor(vendor, 3), ","))
	fmt.Printf("  waf-tester auto -u https://target.com --smart --tamper-auto\n")
}

// testTamperTransformation tests payload transformation
func testTamperTransformation(payload, tamperList string) {
	ui.PrintInfo(fmt.Sprintf("Original payload: %s", payload))
	fmt.Println()

	var tamperNames []string
	if tamperList != "" {
		tamperNames = tampers.ParseTamperList(tamperList)
	} else {
		// Use default set if none specified
		tamperNames = []string{"space2comment", "randomcase"}
	}

	// Validate tampers
	valid, invalid := tampers.ValidateTamperNames(tamperNames)
	if len(invalid) > 0 {
		ui.PrintWarning(fmt.Sprintf("Unknown tampers: %s", strings.Join(invalid, ", ")))
	}

	if len(valid) == 0 {
		ui.PrintError("No valid tampers specified")
		return
	}

	fmt.Printf("  Applying tampers: %s\n\n", strings.Join(valid, ui.Icon(" → ", " -> ")))

	// Show step-by-step transformation
	current := payload
	for i, name := range valid {
		t := tampers.Get(name)
		if t == nil {
			continue
		}

		transformed := t.Transform(current)
		fmt.Printf("  Step %d: %s\n", i+1, ui.ConfigLabelStyle.Render(name))
		fmt.Printf("    In:  %s\n", ui.HelpStyle.Render(current))
		fmt.Printf("    Out: %s\n", ui.StatValueStyle.Render(transformed))
		fmt.Println()

		current = transformed
	}

	fmt.Println("  " + strings.Repeat(ui.Icon("─", "-"), 50))
	fmt.Printf("  Final: %s\n", ui.PassStyle.Render(current))
}

// showWAFMatrix shows the full WAF intelligence matrix
func showWAFMatrix(jsonOut bool) {
	vendors := tampers.GetAllVendors()
	sort.Strings(vendors)

	if jsonOut {
		matrix := make(map[string][]tampers.TamperRecommendation)
		for _, v := range vendors {
			matrix[v] = tampers.GetRecommendations(v)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(matrix)
		return
	}

	ui.PrintSection("WAF Intelligence Matrix")
	fmt.Printf("  Supported vendors: %d\n\n", len(vendors))

	for _, vendor := range vendors {
		recs := tampers.GetRecommendations(vendor)
		topTampers := make([]string, 0, 3)
		for i := 0; i < min(3, len(recs)); i++ {
			topTampers = append(topTampers, recs[i].Name)
		}

		fmt.Printf("  %-20s Top: %s\n",
			ui.ConfigLabelStyle.Render(vendor),
			ui.HelpStyle.Render(strings.Join(topTampers, ", ")))
	}

	fmt.Println()
	fmt.Println("For detailed recommendations, use: waf-tester tampers --for-waf=<vendor>")
}

// runBypassDiscovery runs automated bypass discovery against a live target
func runBypassDiscovery(targetURL, wafVendor string, concurrency, topN, confirmCount int, jsonOut bool) {
	if targetURL == "" {
		ui.PrintError("--target is required with --discover")
		fmt.Println("Usage: waf-tester tampers --discover --target https://target.com")
		os.Exit(1)
	}

	ui.PrintSection("Bypass Discovery")
	ui.PrintInfo(fmt.Sprintf("Target: %s", targetURL))
	if wafVendor != "" {
		ui.PrintInfo(fmt.Sprintf("WAF vendor filter: %s", wafVendor))
	}
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cfg := tampers.BypassDiscoveryConfig{
		TargetURL:    targetURL,
		WAFVendor:    wafVendor,
		Concurrency:  concurrency,
		TopN:         topN,
		ConfirmCount: confirmCount,
		OnProgress: func(tamperName, result string) {
			switch result {
			case "bypassed":
				ui.PrintSuccess(fmt.Sprintf("%-30s BYPASS", tamperName))
			case "blocked":
				ui.PrintInfo(fmt.Sprintf("%-30s blocked", tamperName))
			case "error":
				ui.PrintWarning(fmt.Sprintf("%-30s error", tamperName))
			}
		},
	}

	result, err := tampers.DiscoverBypasses(ctx, cfg)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Discovery failed: %v", err))
		os.Exit(1)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	fmt.Println()
	ui.PrintSection("Discovery Results")
	fmt.Printf("  Tampers tested: %d\n", result.TotalTampers)
	fmt.Printf("  Bypasses found: %d\n", result.TotalBypasses)
	fmt.Printf("  Duration:       %s\n", result.Duration.Round(time.Millisecond))
	fmt.Println()

	if !result.BaselineBlocked {
		ui.PrintWarning("Raw payloads were not blocked — target may not have WAF protection")
		return
	}

	if len(result.TopBypasses) > 0 {
		ui.PrintSuccess("Top Bypasses")
		fmt.Println()
		for i, b := range result.TopBypasses {
			fmt.Printf("  %d. %s (%.0f%% success, confidence: %s)\n",
				i+1, ui.StatValueStyle.Render(b.TamperName),
				b.SuccessRate*100, b.Confidence)
			if b.SampleOutput != "" {
				fmt.Printf("     Sample: %s\n", ui.HelpStyle.Render(b.SampleOutput))
			}
		}
	}

	if len(result.Combinations) > 0 {
		fmt.Println()
		ui.PrintSuccess("Effective Combinations")
		fmt.Println()
		for i, c := range result.Combinations {
			fmt.Printf("  %d. %s (%.0f%% success)\n",
				i+1, ui.StatValueStyle.Render(strings.Join(c.TamperNames, " + ")),
				c.SuccessRate*100)
		}
	}

	if result.TotalBypasses == 0 {
		fmt.Println()
		ui.PrintInfo("No bypasses found. The WAF effectively blocks all tested tamper techniques.")
	}
}
