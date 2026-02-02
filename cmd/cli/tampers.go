package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

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

	tamperFlags.Parse(os.Args[2:])

	// If no flags, show list
	if !*listAll && *category == "" && *forWAF == "" && *test == "" && !*showMatrix {
		*listAll = true
	}

	// List all tampers
	if *listAll {
		listTampers(*category, *jsonOutput)
		return
	}

	// Show tampers for a WAF vendor
	if *forWAF != "" {
		showTampersForWAF(*forWAF, *jsonOutput)
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
	fmt.Println("  " + strings.Repeat("─", 70))

	for i, rec := range recs {
		effectBar := strings.Repeat("█", int(rec.Effectiveness*10))
		effectBar += strings.Repeat("░", 10-int(rec.Effectiveness*10))

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

	fmt.Printf("  Applying tampers: %s\n\n", strings.Join(valid, " → "))

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

	fmt.Println("  " + strings.Repeat("─", 50))
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
