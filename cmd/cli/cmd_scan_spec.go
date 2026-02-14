package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/ui"
)

// runSpecScan handles the --spec scan path: loads the spec, builds a plan,
// iterates endpoints, and runs the requested scan types against each.
func runSpecScan(
	ctx context.Context,
	cfg *apispec.SpecConfig,
	cf *CommonFlags,
	outFlags *OutputFlags,
	shouldScan func(string) bool,
	targetOverride string,
	concurrency int,
	rateLimit int,
	proxy string,
	streamJSON bool,
	dispCtx *DispatcherContext,
) {
	// Load and parse the spec.
	source := cfg.Source()
	if !streamJSON {
		ui.PrintSection("API Spec Scan")
		ui.PrintConfigLine("Spec", source)
	}

	spec, err := apispec.ParseContext(ctx, source)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to parse spec: %v", err))
		os.Exit(1)
	}

	// Apply environment file if specified.
	if cfg.EnvFile != "" {
		envVars, envErr := apispec.LoadPostmanEnvironment(cfg.EnvFile)
		if envErr != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to load environment file: %v", envErr))
		} else {
			apispec.ResolveVariables(spec, cfg.Variables, envVars)
		}
	} else if len(cfg.Variables) > 0 {
		// Apply variable overrides from --var flags only.
		apispec.ResolveVariables(spec, cfg.Variables, nil)
	}

	// Resolve base URL: CLI -u overrides spec BaseURL.
	baseURL := spec.BaseURL()
	if targetOverride != "" {
		baseURL = targetOverride
	}
	if baseURL == "" {
		ui.PrintError("No base URL found in spec and no -u flag provided")
		os.Exit(1)
	}

	// Substitute variables in the base URL.
	baseURL = apispec.SubstituteVariables(baseURL, spec.Variables)

	if !streamJSON {
		ui.PrintConfigLine("Base URL", baseURL)
		ui.PrintConfigLine("Format", string(spec.Format))
		ui.PrintConfigLine("Endpoints", fmt.Sprintf("%d total", len(spec.Endpoints)))
	}

	// Filter endpoints based on --group, --skip-group, --path.
	endpoints := cfg.FilterEndpoints(spec.Endpoints)
	if len(endpoints) == 0 {
		ui.PrintWarning("No endpoints match the current filters")
		os.Exit(0)
	}

	if !streamJSON && len(endpoints) != len(spec.Endpoints) {
		ui.PrintConfigLine("Filtered", fmt.Sprintf("%d endpoints", len(endpoints)))
	}

	// Show spec auth schemes.
	if !streamJSON && len(spec.AuthSchemes) > 0 {
		descs := apispec.DescribeSpecAuth(spec.AuthSchemes)
		for _, d := range descs {
			ui.PrintInfo(fmt.Sprintf("Auth required: %s", d))
		}
		if !cfg.Auth.HasAuth() {
			ui.PrintWarning("No auth credentials provided. Use --bearer, --api-key, or --auth-header")
		}
	}

	// Build scan plan.
	plan := apispec.BuildSimplePlan(spec, cfg)
	if plan == nil || len(plan.Entries) == 0 {
		ui.PrintWarning("No scan plan entries generated")
		os.Exit(0)
	}

	if !streamJSON {
		ui.PrintConfigLine("Plan", fmt.Sprintf("%d entries, ~%d tests", len(plan.Entries), plan.TotalTests))
		ui.PrintConfigLine("Est. Duration", plan.EstimatedDuration.Truncate(time.Second).String())
		fmt.Fprintln(os.Stderr)
	}

	// Spec dry-run: show plan and exit.
	if cfg.DryRun {
		runSpecDryRun(plan, endpoints, streamJSON)
		return
	}

	// Resolve auth.
	authFn := apispec.ResolveAuth(spec.AuthSchemes, cfg.Auth)

	// Execute the plan.
	result := &apispec.SpecScanResult{
		SpecSource: source,
		StartedAt:  time.Now(),
	}

	executor := &apispec.SimpleExecutor{
		BaseURL:     baseURL,
		Concurrency: concurrency,
		AuthFn:      authFn,
		ScanFn: func(ctx context.Context, name string, targetURL string, ep apispec.Endpoint) ([]apispec.SpecFinding, error) {
			if !shouldScan(name) {
				return nil, nil
			}

			// Run the scanner for this category against the endpoint URL.
			findings, scanErr := runScannerForSpec(ctx, name, targetURL, ep, cf, proxy)
			return findings, scanErr
		},
		OnEndpointStart: func(ep apispec.Endpoint, scanType string) {
			if !streamJSON {
				ui.PrintInfo(fmt.Sprintf("Scanning %s %s [%s]", ep.Method, ep.Path, scanType))
			}
		},
		OnEndpointComplete: func(ep apispec.Endpoint, scanType string, findingCount int, err error) {
			if err != nil && cf.Verbose {
				ui.PrintWarning(fmt.Sprintf("%s %s [%s]: %v", ep.Method, ep.Path, scanType, err))
			}
		},
		OnFinding: func(f apispec.SpecFinding) {
			result.AddFinding(f)
			if streamJSON {
				data, _ := json.Marshal(map[string]interface{}{
					"type":      "spec_finding",
					"timestamp": time.Now().Format(time.RFC3339),
					"data":      f,
				})
				fmt.Println(string(data))
			} else {
				ui.PrintWarning(fmt.Sprintf("[%s] %s %s — %s: %s (param: %s)",
					strings.ToUpper(f.Severity), f.Method, f.Path, f.Category, f.Title, f.Parameter))
			}
		},
	}

	session, execErr := executor.Execute(ctx, plan)
	if execErr != nil {
		ui.PrintError(fmt.Sprintf("Spec scan execution error: %v", execErr))
	}

	result.Finalize()

	// Print summary.
	if !streamJSON {
		fmt.Fprintln(os.Stderr)
		ui.PrintSection("Spec Scan Results")
		ui.PrintConfigLine("Spec", source)
		ui.PrintConfigLine("Endpoints", fmt.Sprintf("%d", session.TotalEndpoints))
		ui.PrintConfigLine("Tests", fmt.Sprintf("%d", session.TotalTests))
		ui.PrintConfigLine("Findings", fmt.Sprintf("%d", result.TotalFindings()))
		ui.PrintConfigLine("Duration", result.Duration.Truncate(time.Millisecond).String())

		bySev := result.BySeverity()
		if len(bySev) > 0 {
			var sevParts []string
			for sev, count := range bySev {
				sevParts = append(sevParts, fmt.Sprintf("%s: %d", sev, count))
			}
			ui.PrintConfigLine("By Severity", strings.Join(sevParts, ", "))
		}

		byCat := result.ByCategory()
		if len(byCat) > 0 {
			var catParts []string
			for cat, count := range byCat {
				catParts = append(catParts, fmt.Sprintf("%s: %d", cat, count))
			}
			ui.PrintConfigLine("By Category", strings.Join(catParts, ", "))
		}
	}

	// Dispatch completion event.
	if dispCtx != nil {
		_ = dispCtx.EmitSummary(ctx, session.TotalEndpoints, result.TotalFindings(), 0, result.Duration)
	}

	// Write output if configured.
	if outFlags.OutputFile != "" {
		writeSpecOutput(result, outFlags)
	}
}

// runSpecDryRun outputs the spec scan plan and exits.
func runSpecDryRun(plan *apispec.ScanPlan, endpoints []apispec.Endpoint, streamJSON bool) {
	if streamJSON {
		data, _ := json.Marshal(plan)
		fmt.Println(string(data))
		os.Exit(0)
	}

	ui.PrintSection("Spec Scan Plan (Dry Run)")
	ui.PrintConfigLine("Total Entries", fmt.Sprintf("%d", len(plan.Entries)))
	ui.PrintConfigLine("Total Tests", fmt.Sprintf("%d", plan.TotalTests))
	ui.PrintConfigLine("Est. Duration", plan.EstimatedDuration.Truncate(time.Second).String())
	fmt.Fprintln(os.Stderr)

	// Group entries by endpoint for readable output.
	type epKey struct{ method, path string }
	seen := make(map[epKey][]string)
	var order []epKey

	for _, entry := range plan.Entries {
		k := epKey{entry.Endpoint.Method, entry.Endpoint.Path}
		if _, ok := seen[k]; !ok {
			order = append(order, k)
		}
		seen[k] = append(seen[k], entry.Attack.Category)
	}

	for _, k := range order {
		scanTypes := seen[k]
		fmt.Fprintf(os.Stderr, "  %s %s\n", k.method, k.path)
		fmt.Fprintf(os.Stderr, "    Scans: %s\n", strings.Join(unique(scanTypes), ", "))
	}

	fmt.Fprintln(os.Stderr)
	ui.PrintConfigLine("Endpoints", fmt.Sprintf("%d", len(endpoints)))
	ui.PrintHelp("Remove --spec-dry-run to execute")
	os.Exit(0)
}

// unique deduplicates a string slice preserving order.
func unique(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// runScannerForSpec runs a single scanner type against a spec endpoint URL.
// This bridges the gap between spec-driven scanning and the existing
// scanner Scan(ctx, targetURL) contract.
func runScannerForSpec(
	ctx context.Context,
	scanType string,
	targetURL string,
	ep apispec.Endpoint,
	cf *CommonFlags,
	proxy string,
) ([]apispec.SpecFinding, error) {
	// Each scanner follows the pattern: NewTester(cfg) → Scan(ctx, target) → result.
	// We call the appropriate scanner and convert its findings to SpecFinding.
	// Only the core injection scanners are wired here; meta scanners (cors, etc.)
	// are handled separately since they don't inject per-parameter.

	tag := ep.CorrelationTag
	if tag == "" {
		tag = apispec.CorrelationTag(ep.Method, ep.Path)
	}

	// For now, return nil — the scanner wiring is implemented incrementally.
	// Each scanner type will be added as we verify it works with spec endpoints.
	_ = ctx
	_ = targetURL
	_ = cf
	_ = proxy
	_ = tag

	return nil, nil
}

// writeSpecOutput writes spec scan results to the configured output file.
func writeSpecOutput(result *apispec.SpecScanResult, outFlags *OutputFlags) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to marshal spec results: %v", err))
		return
	}

	if writeErr := os.WriteFile(outFlags.OutputFile, data, 0o644); writeErr != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to write output file: %v", writeErr))
		return
	}

	ui.PrintInfo(fmt.Sprintf("Results written to %s", outFlags.OutputFile))
}
