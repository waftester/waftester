package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/plugin"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// PLUGIN COMMAND - Plugin Management
// =============================================================================

func runPlugin() {
	ui.PrintCompactBanner()
	ui.PrintSection("Plugin Manager")

	pluginFlags := flag.NewFlagSet("plugin", flag.ExitOnError)

	// Commands
	listPlugins := pluginFlags.Bool("list", false, "List installed plugins")
	load := pluginFlags.String("load", "", "Load a plugin file (.so)")
	run := pluginFlags.String("run", "", "Run a specific plugin scanner")
	info := pluginFlags.String("info", "", "Show plugin information")

	// Plugin directory
	pluginDir := pluginFlags.String("dir", "./plugins", "Plugin directory")

	// Target options (for run)
	target := pluginFlags.String("target", "", "Target URL")
	targetShort := pluginFlags.String("u", "", "Target URL (shorthand)")

	// Plugin config
	configFile := pluginFlags.String("config", "", "Plugin configuration file (JSON)")
	configJSON := pluginFlags.String("config-json", "", "Plugin configuration (inline JSON)")

	// Output options
	outputFile := pluginFlags.String("o", "", "Output file (JSON)")
	jsonOutput := pluginFlags.Bool("json", false, "Output in JSON format")
	verbose := pluginFlags.Bool("v", false, "Verbose output")

	pluginFlags.Parse(os.Args[2:])

	// Create plugin manager
	manager := plugin.NewManager(*pluginDir)

	// Load builtin plugins
	if err := manager.LoadBuiltins(); err != nil && *verbose {
		ui.PrintWarning(fmt.Sprintf("Failed to load builtins: %v", err))
	}

	// Load plugins from directory
	if err := manager.LoadFromDirectory(*pluginDir); err != nil && *verbose {
		ui.PrintWarning(fmt.Sprintf("Failed to load plugins from %s: %v", *pluginDir, err))
	}

	switch {
	case *listPlugins:
		runPluginList(manager, *jsonOutput)

	case *load != "":
		runPluginLoad(manager, *load, *verbose)

	case *info != "":
		runPluginInfo(manager, *info, *jsonOutput)

	case *run != "":
		targetURL := *target
		if targetURL == "" {
			targetURL = *targetShort
		}
		if targetURL == "" {
			ui.PrintError("Target URL required for running plugin")
			os.Exit(1)
		}
		runPluginRun(manager, *run, targetURL, *configFile, *configJSON, *outputFile, *jsonOutput, *verbose)

	default:
		// Default to listing plugins
		runPluginList(manager, *jsonOutput)
	}
}

func runPluginList(manager *plugin.Manager, jsonOutput bool) {
	plugins := manager.Info()

	if jsonOutput {
		type pluginInfo struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
			Builtin     bool   `json:"builtin"`
		}

		var infos []pluginInfo
		for _, p := range plugins {
			infos = append(infos, pluginInfo{
				Name:        p.Name,
				Version:     p.Version,
				Description: p.Description,
				Builtin:     manager.IsBuiltin(p.Name),
			})
		}

		data, _ := json.MarshalIndent(map[string]interface{}{
			"plugins": infos,
			"count":   len(infos),
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	if len(plugins) == 0 {
		ui.PrintWarning("No plugins installed")
		fmt.Println()
		fmt.Println("Plugin directory: ./plugins")
		fmt.Println()
		fmt.Println("To install a plugin, place the .so file in the plugins directory")
		return
	}

	ui.PrintSection("Installed Plugins")
	for _, p := range plugins {
		builtinTag := ""
		if manager.IsBuiltin(p.Name) {
			builtinTag = " [builtin]"
		}
		fmt.Printf("  • %s v%s%s\n", p.Name, p.Version, builtinTag)
		fmt.Printf("    %s\n", p.Description)
		fmt.Println()
	}
	ui.PrintSuccess(fmt.Sprintf("Total: %d plugins", len(plugins)))
}

func runPluginLoad(manager *plugin.Manager, path string, verbose bool) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Invalid path: %v", err))
		os.Exit(1)
	}

	if verbose {
		ui.PrintConfigLine("Loading", absPath)
	}

	if err := manager.LoadPlugin(absPath); err != nil {
		ui.PrintError(fmt.Sprintf("Failed to load plugin: %v", err))
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("Loaded plugin from %s", path))
}

func runPluginInfo(manager *plugin.Manager, name string, jsonOutput bool) {
	scanner, ok := manager.Get(name)
	if !ok {
		ui.PrintError(fmt.Sprintf("Plugin not found: %s", name))
		os.Exit(1)
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"name":        scanner.Name(),
			"version":     scanner.Version(),
			"description": scanner.Description(),
			"builtin":     manager.IsBuiltin(name),
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	ui.PrintSection(fmt.Sprintf("Plugin: %s", scanner.Name()))
	ui.PrintConfigLine("Version", scanner.Version())
	ui.PrintConfigLine("Description", scanner.Description())
	if manager.IsBuiltin(name) {
		ui.PrintConfigLine("Type", "Built-in")
	} else {
		ui.PrintConfigLine("Type", "External")
	}
}

func runPluginRun(manager *plugin.Manager, name, targetURL, configFile, configJSON, outputFile string, jsonOutput, verbose bool) {
	scanner, ok := manager.Get(name)
	if !ok {
		ui.PrintError(fmt.Sprintf("Plugin not found: %s", name))
		os.Exit(1)
	}

	if !jsonOutput {
		ui.PrintConfigLine("Plugin", scanner.Name())
		ui.PrintConfigLine("Target", targetURL)
		fmt.Println()
	}

	// Parse configuration
	config := make(map[string]interface{})
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to read config file: %v", err))
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &config); err != nil {
			ui.PrintError(fmt.Sprintf("Invalid config file: %v", err))
			os.Exit(1)
		}
	} else if configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
			ui.PrintError(fmt.Sprintf("Invalid config JSON: %v", err))
			os.Exit(1)
		}
	}

	// Initialize scanner
	if err := scanner.Init(config); err != nil {
		ui.PrintError(fmt.Sprintf("Failed to initialize scanner: %v", err))
		os.Exit(1)
	}
	defer scanner.Cleanup()

	// Setup context
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	// Create target
	target := &plugin.Target{
		URL: targetURL,
	}

	// Run scan
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Scan failed: %v", err))
		os.Exit(1)
	}

	// Output results
	if outputFile != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to write output: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results written to %s", outputFile))
		}
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Print findings
	if len(result.Findings) > 0 {
		ui.PrintSection("Findings")
		for _, finding := range result.Findings {
			severityColor := getSeverityColor(finding.Severity)
			fmt.Printf("  %s[%s]%s %s\n", severityColor, finding.Severity, ui.Reset, finding.Title)
			if verbose && finding.Description != "" {
				fmt.Printf("    %s\n", finding.Description)
			}
			if finding.Evidence != "" {
				fmt.Printf("    Evidence: %s\n", truncatePayload(finding.Evidence, 80))
			}
			fmt.Println()
		}
	}

	// Print info items
	if len(result.Info) > 0 && verbose {
		ui.PrintSection("Information")
		for _, info := range result.Info {
			fmt.Printf("  • %s: %s\n", info.Title, info.Value)
		}
		fmt.Println()
	}

	// Summary
	ui.PrintSection("Summary")
	ui.PrintConfigLine("Findings", fmt.Sprintf("%d", len(result.Findings)))
	ui.PrintConfigLine("Duration", fmt.Sprintf("%dms", result.DurationMs))

	// Count by severity
	sevCounts := make(map[string]int)
	for _, f := range result.Findings {
		sevCounts[f.Severity]++
	}
	for sev, count := range sevCounts {
		ui.PrintConfigLine(fmt.Sprintf("  %s", sev), fmt.Sprintf("%d", count))
	}
}
