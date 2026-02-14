package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/ui"
)

// specPipelineConfig holds the spec-driven scan configuration.
type specPipelineConfig struct {
	specFile    string
	specURL     string
	target      string
	intensity   string
	group       string
	skipGroup   string
	dryRun      bool
	yes         bool
	concurrency int
	rateLimit   int
	timeout     int
	skipVerify  bool
	verbose     bool
	quietMode   bool
	outFlags    *OutputFlags
	printStatus func(format string, args ...interface{})
}

// runSpecPipeline runs the spec-driven scan pipeline:
// parse spec -> intelligence engine -> preview -> execute.
func runSpecPipeline(cfg specPipelineConfig) {
	startTime := time.Now()

	// Determine spec source.
	source := cfg.specFile
	if source == "" {
		source = cfg.specURL
	}

	if !cfg.quietMode {
		ui.PrintSection("API Spec-Driven Scan")
		ui.PrintConfigLine("Spec Source", source)
		ui.PrintConfigLine("Target", cfg.target)
		ui.PrintConfigLine("Intensity", cfg.intensity)
		if cfg.group != "" {
			ui.PrintConfigLine("Group", cfg.group)
		}
		if cfg.skipGroup != "" {
			ui.PrintConfigLine("Skip Group", cfg.skipGroup)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Phase 1: Parse spec.
	cfg.printStatus("  Parsing API specification...\n")

	spec, err := apispec.Parse(source)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to parse spec: %v", err))
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("Parsed %s spec: %s v%s (%d endpoints)",
		spec.Format, spec.Title, spec.Version, len(spec.Endpoints)))

	// Apply group filters.
	if cfg.group != "" {
		filtered := spec.EndpointsByGroup(cfg.group)
		ui.PrintInfo(fmt.Sprintf("  Filtered to group %q: %d endpoints", cfg.group, len(filtered)))
		spec.Endpoints = filtered
	}
	if cfg.skipGroup != "" {
		groups := strings.Split(cfg.skipGroup, ",")
		kept := make([]apispec.Endpoint, 0, len(spec.Endpoints))
		for _, ep := range spec.Endpoints {
			skip := false
			for _, g := range groups {
				g = strings.TrimSpace(g)
				for _, tag := range ep.Tags {
					if strings.EqualFold(tag, g) {
						skip = true
						break
					}
				}
				if skip {
					break
				}
			}
			if !skip {
				kept = append(kept, ep)
			}
		}
		ui.PrintInfo(fmt.Sprintf("  After skip-group: %d endpoints", len(kept)))
		spec.Endpoints = kept
	}

	if len(spec.Endpoints) == 0 {
		ui.PrintWarning("No endpoints to scan after filtering.")
		return
	}

	// Phase 2: Intelligence engine.
	cfg.printStatus("  Running intelligence engine (8-layer analysis)...\n")

	intensityMap := map[string]apispec.Intensity{
		"quick":    apispec.IntensityQuick,
		"normal":   apispec.IntensityNormal,
		"deep":     apispec.IntensityDeep,
		"paranoid": apispec.IntensityParanoid,
	}
	intensity, ok := intensityMap[cfg.intensity]
	if !ok {
		intensity = apispec.IntensityNormal
	}

	plan := apispec.BuildIntelligentPlan(spec, apispec.IntelligenceOptions{
		Intensity: intensity,
	})

	ui.PrintSuccess(fmt.Sprintf("Generated scan plan: %d tests across %d endpoint-attack pairs",
		plan.TotalTests, len(plan.Entries)))

	// Phase 3: Preview.
	if !cfg.quietMode {
		fmt.Fprintln(os.Stderr)
		var buf bytes.Buffer
		apispec.RenderPreview(&buf, plan, spec, apispec.PreviewConfig{
			MaxEndpoints: 50,
			ShowReasons:  cfg.verbose,
		})
		fmt.Fprint(os.Stderr, buf.String())
		fmt.Fprintln(os.Stderr)
	}

	// Dry run: output plan JSON and exit.
	if cfg.dryRun {
		type dryRunOutput struct {
			DryRun    bool              `json:"dry_run"`
			Target    string            `json:"target"`
			SpecFile  string            `json:"spec_file"`
			Intensity string            `json:"intensity"`
			Plan      *apispec.ScanPlan `json:"plan"`
		}
		data, _ := json.MarshalIndent(dryRunOutput{
			DryRun:    true,
			Target:    cfg.target,
			SpecFile:  source,
			Intensity: cfg.intensity,
			Plan:      plan,
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Confirmation prompt (unless --yes).
	if !cfg.yes && !cfg.quietMode {
		fmt.Fprintf(os.Stderr, "Proceed with scan? [Y/n] ")
		var answer string
		fmt.Scanln(&answer)
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "" && answer != "y" && answer != "yes" {
			ui.PrintInfo("Scan cancelled.")
			return
		}
	}

	// Resolve target URL.
	scanTarget := cfg.target
	if scanTarget == "" && spec.BaseURL() != "" {
		scanTarget = spec.BaseURL()
	}
	if scanTarget == "" {
		ui.PrintError("No target URL. Provide -u or ensure the spec has a server URL.")
		os.Exit(1)
	}

	// Phase 4: Execute.
	cfg.printStatus("  Executing spec-driven scan...\n")

	result := &apispec.SpecScanResult{
		SpecSource: source,
		StartedAt:  time.Now(),
	}

	executor := &apispec.SimpleExecutor{
		BaseURL:     scanTarget,
		Concurrency: cfg.concurrency,
		ScanFn: func(_ context.Context, name string, targetURL string, ep apispec.Endpoint) ([]apispec.SpecFinding, error) {
			// Bridge to existing scanner infrastructure.
			// Full implementation in P4 (adaptive executor).
			return nil, nil
		},
		OnEndpointStart: func(ep apispec.Endpoint, scanType string) {
			cfg.printStatus("  Testing %s %s (%s)...\n", ep.Method, ep.Path, scanType)
		},
		OnFinding: func(f apispec.SpecFinding) {
			result.AddFinding(f)
			if !cfg.quietMode {
				severity := f.Severity
				if severity == "" {
					severity = "info"
				}
				fmt.Fprintf(os.Stderr, "  [%s] %s %s: %s\n",
					strings.ToUpper(severity), f.Method, f.Path, f.Title)
			}
		},
	}

	if _, execErr := executor.Execute(nil, plan); execErr != nil {
		result.AddError(fmt.Sprintf("execution error: %v", execErr))
	}

	result.Finalize()

	// Phase 5: Output results.
	elapsed := time.Since(startTime).Round(time.Millisecond)

	type scanOutput struct {
		Target   string                  `json:"target"`
		SpecFile string                  `json:"spec_file"`
		Duration string                  `json:"duration"`
		Result   *apispec.SpecScanResult `json:"result"`
	}
	data, _ := json.MarshalIndent(scanOutput{
		Target:   scanTarget,
		SpecFile: source,
		Duration: elapsed.String(),
		Result:   result,
	}, "", "  ")

	if cfg.outFlags.JSONMode {
		fmt.Println(string(data))
	} else {
		ui.PrintSuccess(fmt.Sprintf("Scan complete in %s", elapsed))
		totalFindings := result.TotalFindings()
		if totalFindings > 0 {
			ui.PrintInfo(fmt.Sprintf("  Findings: %d total", totalFindings))
			for sev, count := range result.BySeverity() {
				fmt.Fprintf(os.Stderr, "    %s: %d\n", sev, count)
			}
		} else {
			ui.PrintInfo("  No findings detected.")
		}
	}
}
