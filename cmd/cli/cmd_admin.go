package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/report"
	"github.com/waftester/waftester/pkg/templatevalidator"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/update"
	"github.com/waftester/waftester/pkg/validate"
)

func runValidate() {
	ui.PrintCompactBanner()

	validateFlags := flag.NewFlagSet("validate", flag.ExitOnError)
	specPath := validateFlags.String("spec", "", "API spec file to validate (OpenAPI, Swagger, Postman, HAR)")
	specURL := validateFlags.String("spec-url", "", "API spec URL to validate")
	allowInternal := validateFlags.Bool("allow-internal", false, "Allow internal/private server URLs in spec validation")
	payloadDir := validateFlags.String("payloads", defaults.PayloadDir, "Directory containing payload JSON files")
	failFast := validateFlags.Bool("fail-fast", false, "Abort on first error")
	verbose := validateFlags.Bool("verbose", false, "Show detailed validation output")
	outputJSON := validateFlags.String("output", "", "Output results to JSON file")

	// Enterprise hook flags
	validateSlack := validateFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	validateTeams := validateFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	validatePagerDuty := validateFlags.String("pagerduty-key", "", "PagerDuty routing key")
	validateOtel := validateFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	validateWebhook := validateFlags.String("webhook-url", "", "Generic webhook URL")

	validateFlags.Parse(os.Args[2:])

	// Route to spec validation if --spec or --spec-url provided.
	if *specPath != "" || *specURL != "" {
		runValidateSpec(*specPath, *specURL, *allowInternal, *verbose, *outputJSON)
		return
	}

	ui.PrintSection("Payload Validation")
	ui.PrintConfigLine("Payload Dir", *payloadDir)
	ui.PrintConfigLine("Fail Fast", fmt.Sprintf("%v", *failFast))
	fmt.Println() // debug:keep

	// Initialize dispatcher for hooks
	validateOutputFlags := OutputFlags{
		SlackWebhook: *validateSlack,
		TeamsWebhook: *validateTeams,
		PagerDutyKey: *validatePagerDuty,
		OTelEndpoint: *validateOtel,
		WebhookURL:   *validateWebhook,
	}
	validateScanID := fmt.Sprintf("validate-%d", time.Now().Unix())
	validateDispCtx, validateDispErr := validateOutputFlags.InitDispatcher(validateScanID, *payloadDir)
	if validateDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", validateDispErr))
	}
	if validateDispCtx != nil {
		defer validateDispCtx.Close()
	}
	validateStartTime := time.Now()
	validateCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if validateDispCtx != nil {
		_ = validateDispCtx.EmitStart(validateCtx, *payloadDir, 0, 1, nil)
	}

	result, err := validate.ValidatePayloads(*payloadDir, *failFast, *verbose)
	if err != nil {
		if validateDispCtx != nil {
			_ = validateDispCtx.EmitError(validateCtx, "validate", fmt.Sprintf("Validation error: %v", err), true)
		}
		ui.PrintError(fmt.Sprintf("Validation error: %v", err))
		os.Exit(1)
	}

	if *outputJSON != "" {
		// Write JSON output
		f, err := os.Create(*outputJSON)
		if err != nil {
			if validateDispCtx != nil {
				_ = validateDispCtx.EmitError(validateCtx, "validate", fmt.Sprintf("Cannot create output file: %v", err), true)
			}
			ui.PrintError(fmt.Sprintf("Cannot create output file: %v", err))
			os.Exit(1)
		}
		defer f.Close()
		fmt.Fprintf(f, "%+v\n", result)
		ui.PrintSuccess(fmt.Sprintf("Results written to %s", *outputJSON))
	}

	if !result.Valid {
		// Emit validation failure
		if validateDispCtx != nil {
			_ = validateDispCtx.EmitBypass(validateCtx, "payload-validation-failure", "high", *payloadDir, "Payload validation failed", 0)
			_ = validateDispCtx.EmitSummary(validateCtx, 1, 0, 1, time.Since(validateStartTime))
		}
		ui.PrintError("Validation failed!")
		os.Exit(1)
	}

	// Emit success
	if validateDispCtx != nil {
		_ = validateDispCtx.EmitSummary(validateCtx, 1, 1, 0, time.Since(validateStartTime))
	}
	ui.PrintSuccess("All payloads validated successfully!")
}

// runValidateSpec validates an API spec file for correctness, security
// concerns (SSRF, credentials), and completeness.
func runValidateSpec(specPath, specURL string, allowInternal, verbose bool, outputFile string) {
	ui.PrintSection("API Spec Validation")

	source := specPath
	if source == "" {
		source = specURL
	}
	ui.PrintConfigLine("Spec", source)
	fmt.Println() // debug:keep

	result, err := apispec.ValidateSpec(source, allowInternal)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Spec validation error: %v", err))
		os.Exit(1)
	}

	// Print errors.
	for _, issue := range result.Errors {
		path := ""
		if issue.Path != "" {
			path = fmt.Sprintf(" (%s)", issue.Path)
		}
		ui.PrintError(fmt.Sprintf("[%s]%s %s", issue.Code, path, issue.Message))
	}

	// Print warnings.
	for _, issue := range result.Warnings {
		path := ""
		if issue.Path != "" {
			path = fmt.Sprintf(" (%s)", issue.Path)
		}
		ui.PrintWarning(fmt.Sprintf("[%s]%s %s", issue.Code, path, issue.Message))
	}

	// Print spec summary if parsed successfully.
	if result.Spec != nil {
		fmt.Println() // debug:keep
		ui.PrintConfigLine("Format", string(result.Spec.Format))
		ui.PrintConfigLine("Title", result.Spec.Title)
		if result.Spec.Version != "" {
			ui.PrintConfigLine("Version", result.Spec.Version)
		}
		ui.PrintConfigLine("Endpoints", fmt.Sprintf("%d", len(result.Spec.Endpoints)))
		if len(result.Spec.AuthSchemes) > 0 {
			ui.PrintConfigLine("Auth Schemes", fmt.Sprintf("%d", len(result.Spec.AuthSchemes)))
		}

		if verbose {
			fmt.Println() // debug:keep
			for _, ep := range result.Spec.Endpoints {
				fmt.Fprintf(os.Stderr, "  %s %s", ep.Method, ep.Path)
				if len(ep.Parameters) > 0 {
					fmt.Fprintf(os.Stderr, " (%d params)", len(ep.Parameters))
				}
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	// Write JSON output if requested.
	if outputFile != "" {
		data, marshalErr := json.MarshalIndent(result, "", "  ")
		if marshalErr != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to marshal results: %v", marshalErr))
		} else if writeErr := os.WriteFile(outputFile, data, 0o644); writeErr != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to write output: %v", writeErr))
		} else {
			ui.PrintInfo(fmt.Sprintf("Results written to %s", outputFile))
		}
	}

	fmt.Println() // debug:keep
	if result.Valid {
		ui.PrintSuccess(fmt.Sprintf("Spec validation passed (%d warnings)", len(result.Warnings)))
	} else {
		ui.PrintError(fmt.Sprintf("Spec validation failed (%d errors, %d warnings)", len(result.Errors), len(result.Warnings)))
		os.Exit(1)
	}
}

func runValidateTemplates() {
	ui.PrintCompactBanner()
	ui.PrintSection("Template Validation")

	validateFlags := flag.NewFlagSet("validate-templates", flag.ExitOnError)
	templateDir := validateFlags.String("templates", defaults.TemplateDir, "Directory containing nuclei template YAML files")
	strict := validateFlags.Bool("strict", false, "Enable strict validation mode (warnings become errors)")
	verbose := validateFlags.Bool("verbose", false, "Show detailed validation output")
	outputJSON := validateFlags.String("output", "", "Output results to JSON file")

	// Enterprise hook flags
	vtSlack := validateFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	vtTeams := validateFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	vtPagerDuty := validateFlags.String("pagerduty-key", "", "PagerDuty routing key")
	vtOtel := validateFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	vtWebhook := validateFlags.String("webhook-url", "", "Generic webhook URL")

	validateFlags.Parse(os.Args[2:])

	ui.PrintConfigLine("Template Dir", *templateDir)
	ui.PrintConfigLine("Strict Mode", fmt.Sprintf("%v", *strict))
	fmt.Println() // debug:keep

	// Initialize dispatcher for hooks
	vtOutputFlags := OutputFlags{
		SlackWebhook: *vtSlack,
		TeamsWebhook: *vtTeams,
		PagerDutyKey: *vtPagerDuty,
		OTelEndpoint: *vtOtel,
		WebhookURL:   *vtWebhook,
	}
	vtScanID := fmt.Sprintf("validate-templates-%d", time.Now().Unix())
	vtDispCtx, vtDispErr := vtOutputFlags.InitDispatcher(vtScanID, *templateDir)
	if vtDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", vtDispErr))
	}
	if vtDispCtx != nil {
		defer vtDispCtx.Close()
	}
	vtStartTime := time.Now()
	vtCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if vtDispCtx != nil {
		_ = vtDispCtx.EmitStart(vtCtx, *templateDir, 0, 1, nil)
	}

	validator := templatevalidator.NewValidator(*strict)
	summary, err := validator.ValidateDirectory(*templateDir)
	if err != nil {
		if vtDispCtx != nil {
			_ = vtDispCtx.EmitError(vtCtx, "validate-templates", fmt.Sprintf("Validation error: %v", err), true)
		}
		ui.PrintError(fmt.Sprintf("Validation error: %v", err))
		os.Exit(1)
	}

	// Print summary
	ui.PrintSection("Validation Summary")
	ui.PrintConfigLine("Total Files", fmt.Sprintf("%d", summary.TotalFiles))
	ui.PrintConfigLine("Valid", fmt.Sprintf("%d", summary.ValidFiles))
	ui.PrintConfigLine("Invalid", fmt.Sprintf("%d", summary.InvalidFiles))
	ui.PrintConfigLine("Total Errors", fmt.Sprintf("%d", summary.TotalErrors))
	ui.PrintConfigLine("Total Warnings", fmt.Sprintf("%d", summary.TotalWarnings))
	fmt.Println() // debug:keep

	// Print detailed results if verbose
	if *verbose {
		for _, result := range summary.Results {
			if !result.Valid || len(result.Warnings) > 0 {
				fmt.Printf("\n%s\n", result.File) // debug:keep
				for _, e := range result.Errors {
					ui.PrintError(fmt.Sprintf("  ERROR: %s", e))
				}
				for _, w := range result.Warnings {
					ui.PrintWarning(fmt.Sprintf("  WARNING: %s", w))
				}
			}
		}
	}

	// Emit individual validation errors to hooks
	if vtDispCtx != nil {
		for _, result := range summary.Results {
			if !result.Valid {
				for _, e := range result.Errors {
					errDesc := fmt.Sprintf("Template error in %s: %s", result.File, e)
					_ = vtDispCtx.EmitBypass(vtCtx, "template-error", "high", result.File, errDesc, 0)
				}
			}
			if *strict {
				for _, w := range result.Warnings {
					warnDesc := fmt.Sprintf("Template warning in %s: %s", result.File, w)
					_ = vtDispCtx.EmitBypass(vtCtx, "template-warning", "medium", result.File, warnDesc, 0)
				}
			}
		}
	}

	if *outputJSON != "" {
		// Write JSON output
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			if vtDispCtx != nil {
				_ = vtDispCtx.EmitError(vtCtx, "validate-templates", fmt.Sprintf("Cannot marshal results: %v", err), true)
			}
			ui.PrintError(fmt.Sprintf("Cannot marshal results: %v", err))
			os.Exit(1)
		}
		if err := os.WriteFile(*outputJSON, data, 0644); err != nil {
			if vtDispCtx != nil {
				_ = vtDispCtx.EmitError(vtCtx, "validate-templates", fmt.Sprintf("Cannot create output file: %v", err), true)
			}
			ui.PrintError(fmt.Sprintf("Cannot create output file: %v", err))
			os.Exit(1)
		}
		ui.PrintSuccess(fmt.Sprintf("Results written to %s", *outputJSON))
	}

	if summary.InvalidFiles > 0 {
		// Emit validation failures
		if vtDispCtx != nil {
			failDesc := fmt.Sprintf("%d invalid templates found", summary.InvalidFiles)
			_ = vtDispCtx.EmitBypass(vtCtx, "template-validation-failure", "high", *templateDir, failDesc, 0)
			_ = vtDispCtx.EmitSummary(vtCtx, summary.TotalFiles, summary.ValidFiles, summary.InvalidFiles, time.Since(vtStartTime))
		}
		ui.PrintError(fmt.Sprintf("Validation failed! %d invalid templates found.", summary.InvalidFiles))
		os.Exit(1)
	}

	// Emit success
	if vtDispCtx != nil {
		_ = vtDispCtx.EmitSummary(vtCtx, summary.TotalFiles, summary.ValidFiles, 0, time.Since(vtStartTime))
	}
	ui.PrintSuccess(fmt.Sprintf("All %d templates validated successfully!", summary.TotalFiles))
}

func runEnterpriseReport() {
	ui.PrintCompactBanner()
	ui.PrintSection("Enterprise HTML Report Generator")

	reportFlags := flag.NewFlagSet("report", flag.ExitOnError)
	workspaceDir := reportFlags.String("workspace", "", "Path to workspace directory containing results.json and assessment.json")
	outputFile := reportFlags.String("output", "", "Output HTML report file path (default: workspace/enterprise-report.html)")
	targetName := reportFlags.String("target", "", "Target name for the report header")

	// Enterprise hook flags
	reportSlack := reportFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	reportTeams := reportFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	reportPagerDuty := reportFlags.String("pagerduty-key", "", "PagerDuty routing key")
	reportOtel := reportFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	reportWebhook := reportFlags.String("webhook-url", "", "Generic webhook URL")

	reportFlags.Parse(os.Args[2:])

	// Validate workspace directory
	if *workspaceDir == "" {
		ui.PrintError("Workspace directory is required. Use -workspace <path>")
		fmt.Println()                                                                               // debug:keep
		fmt.Println("Usage: waf-tester report -workspace <path> [-output <file>] [-target <name>]") // debug:keep
		fmt.Println()                                                                               // debug:keep
		fmt.Println("Options:")                                                                     // debug:keep
		fmt.Println("  -workspace <path>  Path to workspace directory containing results.json")     // debug:keep
		fmt.Println("  -output <file>     Output HTML file (default: workspace/enterprise-report.html) // debug:keep")
		fmt.Println("  -target <name>     Target name for report header") // debug:keep
		os.Exit(1)
	}

	// Check workspace exists
	if _, err := os.Stat(*workspaceDir); os.IsNotExist(err) {
		ui.PrintError(fmt.Sprintf("Workspace directory not found: %s", *workspaceDir))
		os.Exit(1)
	}

	// Check results.json exists
	resultsPath := filepath.Join(*workspaceDir, "results.json")
	if _, err := os.Stat(resultsPath); os.IsNotExist(err) {
		ui.PrintError(fmt.Sprintf("results.json not found in workspace: %s", *workspaceDir))
		os.Exit(1)
	}

	// Determine target name
	target := *targetName
	if target == "" {
		// Try to extract from workspace path
		target = filepath.Base(filepath.Dir(*workspaceDir))
		if target == "." || target == "" {
			target = "WAF Security Assessment"
		}
	}

	// Determine output file
	output := *outputFile
	if output == "" {
		output = filepath.Join(*workspaceDir, "enterprise-report.html")
	}

	ui.PrintConfigLine("Workspace", *workspaceDir)
	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Output", output)
	fmt.Println() // debug:keep

	// Initialize dispatcher for hooks
	reportOutputFlags := OutputFlags{
		SlackWebhook: *reportSlack,
		TeamsWebhook: *reportTeams,
		PagerDutyKey: *reportPagerDuty,
		OTelEndpoint: *reportOtel,
		WebhookURL:   *reportWebhook,
	}
	reportScanID := fmt.Sprintf("report-%d", time.Now().Unix())
	reportDispCtx, reportDispErr := reportOutputFlags.InitDispatcher(reportScanID, target)
	if reportDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", reportDispErr))
	}
	if reportDispCtx != nil {
		defer reportDispCtx.Close()
	}
	reportStartTime := time.Now()
	reportCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if reportDispCtx != nil {
		_ = reportDispCtx.EmitStart(reportCtx, target, 0, 1, nil)
	}

	// Generate report
	if err := report.GenerateEnterpriseHTMLReportFromWorkspace(*workspaceDir, target, 0, output); err != nil {
		// Emit failure
		if reportDispCtx != nil {
			_ = reportDispCtx.EmitBypass(reportCtx, "report-generation-failure", "medium", target, err.Error(), 0)
			_ = reportDispCtx.EmitSummary(reportCtx, 1, 0, 1, time.Since(reportStartTime))
		}
		ui.PrintError(fmt.Sprintf("Report generation failed: %v", err))
		os.Exit(1)
	}

	// Emit success
	if reportDispCtx != nil {
		_ = reportDispCtx.EmitSummary(reportCtx, 1, 1, 0, time.Since(reportStartTime))
	}
	ui.PrintSuccess(fmt.Sprintf("Enterprise HTML report saved to: %s", output))
}

func runUpdate() {
	ui.PrintCompactBanner()
	ui.PrintSection("Payload Update")

	updateFlags := flag.NewFlagSet("update", flag.ExitOnError)
	payloadDir := updateFlags.String("payloads", defaults.PayloadDir, "Directory containing payload JSON files")
	source := updateFlags.String("source", "OWASP", "Payload source: OWASP, GitHub, Manual")
	dryRun := updateFlags.Bool("dry-run", false, "Preview changes without modifying files")
	autoApply := updateFlags.Bool("auto-apply", false, "Automatically apply non-destructive updates")
	skipDestructive := updateFlags.Bool("skip-destructive", false, "Skip potentially destructive payloads")
	versionBump := updateFlags.String("version-bump", "minor", "Version bump type: major, minor, patch")
	outputFile := updateFlags.String("output", "payload-update-report.json", "Output report file")

	// Enterprise hook flags
	updateSlack := updateFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	updateTeams := updateFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	updatePagerDuty := updateFlags.String("pagerduty-key", "", "PagerDuty routing key")
	updateOtel := updateFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	updateWebhook := updateFlags.String("webhook-url", "", "Generic webhook URL")

	updateFlags.Parse(os.Args[2:])

	ui.PrintConfigLine("Source", *source)
	ui.PrintConfigLine("Payload Dir", *payloadDir)
	ui.PrintConfigLine("Dry Run", fmt.Sprintf("%v", *dryRun))
	ui.PrintConfigLine("Auto Apply", fmt.Sprintf("%v", *autoApply))
	fmt.Println() // debug:keep

	// Initialize dispatcher for hooks
	updateOutputFlags := OutputFlags{
		SlackWebhook: *updateSlack,
		TeamsWebhook: *updateTeams,
		PagerDutyKey: *updatePagerDuty,
		OTelEndpoint: *updateOtel,
		WebhookURL:   *updateWebhook,
	}
	updateScanID := fmt.Sprintf("update-%d", time.Now().Unix())
	updateDispCtx, updateDispErr := updateOutputFlags.InitDispatcher(updateScanID, *payloadDir)
	if updateDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", updateDispErr))
	}
	if updateDispCtx != nil {
		defer updateDispCtx.Close()
	}
	updateStartTime := time.Now()
	updateCtx := context.Background()

	// Emit start event for scan lifecycle hooks
	if updateDispCtx != nil {
		_ = updateDispCtx.EmitStart(updateCtx, *payloadDir, 0, 1, nil)
	}

	cfg := &update.UpdateConfig{
		PayloadDir:      *payloadDir,
		Source:          *source,
		DryRun:          *dryRun,
		AutoApply:       *autoApply,
		SkipDestructive: *skipDestructive,
		VersionBump:     *versionBump,
		OutputFile:      *outputFile,
	}

	_, err := update.UpdatePayloads(cfg)
	if err != nil {
		// Emit failure
		if updateDispCtx != nil {
			_ = updateDispCtx.EmitBypass(updateCtx, "payload-update-failure", "medium", *payloadDir, err.Error(), 0)
			_ = updateDispCtx.EmitSummary(updateCtx, 1, 0, 1, time.Since(updateStartTime))
		}
		ui.PrintError(fmt.Sprintf("Update error: %v", err))
		os.Exit(1)
	}

	// Emit success
	if updateDispCtx != nil {
		_ = updateDispCtx.EmitSummary(updateCtx, 1, 1, 0, time.Since(updateStartTime))
	}

	if *dryRun {
		ui.PrintInfo("Dry run complete - no changes applied")
	} else {
		ui.PrintSuccess("Payloads updated successfully!")
	}
}
