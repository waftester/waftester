package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/nuclei"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// TEMPLATE COMMAND - Nuclei Template Engine
// =============================================================================

func runTemplate() {
	ui.PrintCompactBanner()
	ui.PrintSection("Template Scanner (Nuclei-Compatible)")

	templateFlags := flag.NewFlagSet("template", flag.ExitOnError)

	// Target options
	target := templateFlags.String("target", "", "Target URL")
	targetShort := templateFlags.String("u", "", "Target URL (shorthand)")
	targetList := templateFlags.String("l", "", "File containing target URLs")

	// Template options
	templateFile := templateFlags.String("t", "", "Path to template file or directory")
	templateDir := templateFlags.String("templates", "", "Template directory (alias)")
	tags := templateFlags.String("tags", "", "Filter templates by tags (comma-separated)")
	severity := templateFlags.String("severity", "", "Filter by severity: critical,high,medium,low,info")
	excludeTags := templateFlags.String("exclude-tags", "", "Exclude templates by tags")

	// Execution options
	concurrency := templateFlags.Int("c", 25, "Concurrency level")
	rateLimit := templateFlags.Int("rl", 150, "Requests per second")
	timeout := templateFlags.Int("timeout", 10, "Request timeout in seconds")
	retries := templateFlags.Int("retries", 1, "Number of retries")

	// Output options
	outputFile := templateFlags.String("o", "", "Output file (JSON)")
	jsonOutput := templateFlags.Bool("json", false, "Output in JSON format")
	silent := templateFlags.Bool("silent", false, "Silent mode - only show results")
	verbose := templateFlags.Bool("v", false, "Verbose output")

	// Validation only
	validateOnly := templateFlags.Bool("validate", false, "Only validate templates, don't run")

	// Payload bridge options
	enrichPayloads := templateFlags.Bool("enrich", false, "Enrich templates with JSON payload database")
	payloadDir := templateFlags.String("payloads", defaults.PayloadDir, "Directory containing JSON payloads")

	templateFlags.Parse(os.Args[2:])

	// Get target URL
	targetURL := *target
	if targetURL == "" {
		targetURL = *targetShort
	}

	// Get template path
	templatePath := *templateFile
	if templatePath == "" {
		templatePath = *templateDir
	}

	// Validation mode
	if *validateOnly {
		if templatePath == "" {
			ui.PrintError("Template path required for validation")
			os.Exit(1)
		}
		runTemplateValidation(templatePath, *verbose)
		return
	}

	// Normal execution requires target
	if targetURL == "" && *targetList == "" {
		ui.PrintError("Target URL or target list required")
		fmt.Println()
		fmt.Println("Usage: waf-tester template -u <target> -t <templates>")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  waf-tester template -u https://example.com -t templates/")
		fmt.Println("  waf-tester template -u https://example.com -t sqli.yaml")
		fmt.Println("  waf-tester template -l targets.txt -t templates/ --tags waf")
		os.Exit(1)
	}

	if templatePath == "" {
		templatePath = "templates"
	}

	if !*silent {
		ui.PrintConfigLine("Target", targetURL)
		ui.PrintConfigLine("Templates", templatePath)
		if *tags != "" {
			ui.PrintConfigLine("Tags", *tags)
		}
		if *severity != "" {
			ui.PrintConfigLine("Severity", *severity)
		}
		ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
		ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d/s", *rateLimit))
		fmt.Println()
	}

	// Setup context with cancellation
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	// Create engine
	engine := nuclei.NewEngine()
	engine.Verbose = *verbose

	// Load templates
	var templates []*nuclei.Template
	var loadErr error

	info, err := os.Stat(templatePath)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Cannot access templates: %v", err))
		os.Exit(1)
	}

	if info.IsDir() {
		templates, loadErr = nuclei.LoadDirectory(templatePath)
	} else {
		tmpl, err := nuclei.LoadTemplate(templatePath)
		if err != nil {
			loadErr = err
		} else {
			templates = []*nuclei.Template{tmpl}
		}
	}

	if loadErr != nil {
		ui.PrintError(fmt.Sprintf("Failed to load templates: %v", loadErr))
		os.Exit(1)
	}

	// Filter templates
	if *tags != "" || *severity != "" || *excludeTags != "" {
		templates = nuclei.FilterTemplates(templates, nuclei.FilterOptions{
			Tags:        *tags,
			Severity:    *severity,
			ExcludeTags: *excludeTags,
		})
	}

	if !*silent {
		ui.PrintSuccess(fmt.Sprintf("Loaded %d templates", len(templates)))
		fmt.Println()
	}

	// Enrich templates with JSON payload database
	if *enrichPayloads {
		// Enrichment only needs JSON payloads, not a second load of nuclei templates.
		provider := payloadprovider.NewProvider(*payloadDir, "")
		if err := provider.Load(); err != nil {
			if !*silent {
				ui.PrintWarning(fmt.Sprintf("Could not load payload database for enrichment: %v", err))
			}
		} else {
			totalAdded := 0
			for i, tmpl := range templates {
				enriched, added, err := provider.EnrichTemplate(tmpl)
				if err != nil {
					if *verbose {
						ui.PrintWarning(fmt.Sprintf("Could not enrich %s: %v", tmpl.ID, err))
					}
					continue
				}
				templates[i] = enriched
				totalAdded += added
			}
			if !*silent && totalAdded > 0 {
				ui.PrintSuccess(fmt.Sprintf("Enriched templates with %d additional payloads from JSON database", totalAdded))
			}
		}
	}

	if len(templates) == 0 {
		ui.PrintWarning("No templates match the specified filters")
		os.Exit(0)
	}

	// Collect targets
	targets := []string{}
	if targetURL != "" {
		targets = append(targets, targetURL)
	}
	if *targetList != "" {
		listTargets, err := readTargetsFromFile(*targetList)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to read target list: %v", err))
			os.Exit(1)
		}
		targets = append(targets, listTargets...)
	}

	// Execute templates
	var results []*nuclei.Result
	matched := 0
	total := len(templates) * len(targets)
	processed := 0

	_ = *concurrency
	_ = *rateLimit
	_ = *timeout
	_ = *retries

	for _, tgt := range targets {
		for _, tmpl := range templates {
			select {
			case <-ctx.Done():
				goto done
			default:
			}

			result, err := engine.Execute(ctx, tmpl, tgt)
			processed++

			if err != nil {
				if *verbose {
					ui.PrintError(fmt.Sprintf("[%s] %s: %v", tmpl.ID, tgt, err))
				}
				continue
			}

			results = append(results, result)

			if result.Matched {
				matched++
				if *jsonOutput {
					jsonBytes, _ := json.Marshal(result)
					fmt.Println(string(jsonBytes))
				} else {
					severityColor := getSeverityColor(result.Severity)
					fmt.Printf("%s[%s]%s %s - %s\n",
						severityColor, result.Severity, ui.Reset,
						result.TemplateName, tgt)
				}
			}

			if !*silent && !*jsonOutput && processed%10 == 0 {
				fmt.Printf("\r[%d/%d] Processed, %d matches found", processed, total, matched)
			}
		}
	}

done:
	if !*silent && !*jsonOutput {
		fmt.Println()
		fmt.Println()
		ui.PrintSection("Results")
		ui.PrintConfigLine("Templates", fmt.Sprintf("%d", len(templates)))
		ui.PrintConfigLine("Targets", fmt.Sprintf("%d", len(targets)))
		ui.PrintConfigLine("Matches", fmt.Sprintf("%d", matched))
	}

	// Write output file
	if *outputFile != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(*outputFile, data, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to write output: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results written to %s", *outputFile))
		}
	}
}

func runTemplateValidation(templatePath string, verbose bool) {
	ui.PrintSection("Template Validation")

	info, err := os.Stat(templatePath)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Cannot access path: %v", err))
		os.Exit(1)
	}

	var files []string
	if info.IsDir() {
		err := filepath.Walk(templatePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to walk directory: %v", err))
			os.Exit(1)
		}
	} else {
		files = []string{templatePath}
	}

	ui.PrintConfigLine("Files", fmt.Sprintf("%d", len(files)))
	fmt.Println()

	valid := 0
	invalid := 0

	for _, file := range files {
		_, err := nuclei.LoadTemplate(file)
		if err != nil {
			invalid++
			ui.PrintError(fmt.Sprintf("%s: %v", file, err))
		} else {
			valid++
			if verbose {
				ui.PrintSuccess(fmt.Sprintf("%s: valid", file))
			}
		}
	}

	fmt.Println()
	ui.PrintSection("Summary")
	ui.PrintConfigLine("Valid", fmt.Sprintf("%d", valid))
	if invalid > 0 {
		ui.PrintConfigLine("Invalid", fmt.Sprintf("%d", invalid))
		os.Exit(1)
	}
	ui.PrintSuccess("All templates are valid!")
}

func readTargetsFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets, nil
}



func getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return ui.BoldRed
	case "high":
		return ui.Red
	case "medium":
		return ui.Yellow
	case "low":
		return ui.Blue
	case "info":
		return ui.Cyan
	default:
		return ui.Reset
	}
}

// Unused but kept for interface compatibility
var _ = time.Now
