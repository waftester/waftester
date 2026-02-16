package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/config"
	"github.com/waftester/waftester/pkg/core"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/mutation"
	_ "github.com/waftester/waftester/pkg/mutation/encoder"
	_ "github.com/waftester/waftester/pkg/mutation/evasion"
	_ "github.com/waftester/waftester/pkg/mutation/location"
	_ "github.com/waftester/waftester/pkg/mutation/protocol"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// rejectSpecFlags exits with an error if os.Args contains --spec or --spec-url.
// This lives here (not in pkg/) because os.Exit belongs in the CLI entry point.
func rejectSpecFlags(command string) {
	if err := apispec.CheckSpecFlagsRejected(command, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// getProjectRoot returns the project root directory (coraza-caddy).
// It navigates up from the executable location (tests/waf-tester) to the project root.
// Falls back to current working directory if executable path cannot be determined.
func getProjectRoot() string {
	// Try to get executable path first
	exePath, err := os.Executable()
	if err == nil {
		// Resolve symlinks
		exePath, err = filepath.EvalSymlinks(exePath)
		if err == nil {
			// Executable is in tests/waf-tester, go up 2 levels to project root
			exeDir := filepath.Dir(exePath)
			projectRoot := filepath.Join(exeDir, "..", "..")
			projectRoot, err = filepath.Abs(projectRoot)
			if err == nil {
				// Verify this looks like the project root (has workspaces dir or can create it)
				workspacesDir := filepath.Join(projectRoot, "workspaces")
				if _, statErr := os.Stat(workspacesDir); statErr == nil || os.IsNotExist(statErr) {
					return projectRoot
				}
			}
		}
	}

	// Fallback: use current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func main() {
	// Register detection transport wrapper globally
	// This ensures ALL httpclient.New() calls get detection capabilities
	httpclient.RegisterTransportWrapper(detection.WrapRoundTripper)

	// Check for subcommands
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "auto", "superpower", "sp":
		runAutoScan()
	case "discover":
		runDiscover()
	case "learn":
		runLearn()
	case "probe":
		runProbe()
	case "crawl":
		runCrawl()
	case "scan":
		runScan()
	case "fuzz":
		rejectSpecFlags("fuzz")
		runFuzz()
	case "analyze":
		runAnalyze()
	case "validate":
		runValidate()
	case "validate-templates":
		runValidateTemplates()
	case "update":
		runUpdate()
	case "mutate":
		runMutate()
	case "bypass":
		rejectSpecFlags("bypass")
		runBypassFinder()
	case "smuggle":
		rejectSpecFlags("smuggle")
		runSmuggle()
	case "race":
		rejectSpecFlags("race")
		runRace()
	case "workflow":
		runWorkflow()
	case "headless":
		rejectSpecFlags("headless")
		runHeadless()
	case "fp", "falsepositive", "false-positive":
		rejectSpecFlags("fp")
		runFP()
	case "assess", "assessment", "benchmark":
		rejectSpecFlags("assess")
		runAssess()
	case "vendor", "waf-detect", "detect-waf":
		runVendorDetect()
	case "tampers", "tamper":
		runTampers()
	case "protocol", "proto":
		runProtocolDetect()
	case "run":
		// Remove "run" from args and continue with normal execution
		os.Args = append(os.Args[:1], os.Args[2:]...)
		runTests()
	case "report", "html-report", "enterprise-report":
		runEnterpriseReport()
	case "template", "templates", "nuclei":
		if !runTemplateManager() {
			runTemplate()
		}
	case "grpc", "grpc-test":
		runGRPC()
	case "soap", "wsdl":
		runSOAP()
	case "openapi", "openapi-fuzz", "swagger":
		runOpenAPI()
	case "cicd", "ci-cd", "pipeline":
		runCICD()
	case "plugin", "plugins":
		runPlugin()
	case "cloud", "cloud-discover":
		runCloud()
	case "mcp", "mcp-server":
		runMCP()
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	case "docs", "doc", "man", "manual":
		printDetailedDocs()
		os.Exit(0)
	case "-v", "--version", "version":
		ui.PrintMiniBanner()
		os.Exit(0)
	default:
		// Assume it's a flag for the default "run" command
		runTests()
	}
}

// runProbe is in cmd_probe.go

// runCrawl is in cmd_crawl.go

// runFuzz is in cmd_fuzz.go

// runAnalyze is in cmd_analyze.go

// applyMutations expands payloads using the mutation engine based on config
func applyMutations(cfg *config.Config, originalPayloads []payloads.Payload) []payloads.Payload {
	var pipelineCfg *mutation.PipelineConfig

	switch cfg.MutationMode {
	case "quick":
		// Quick mode: just URL encoding variants
		pipelineCfg = &mutation.PipelineConfig{
			Encoders:       []string{"raw", "url", "double_url"},
			Locations:      []string{"query_param"},
			Evasions:       []string{},
			ChainEncodings: false,
			IncludeRaw:     true,
		}
	case "standard":
		// Standard mode: common encodings and locations
		pipelineCfg = &mutation.PipelineConfig{
			Encoders:       []string{"raw", "url", "double_url", "html_hex", "unicode"},
			Locations:      []string{"query_param", "post_form", "post_json"},
			Evasions:       []string{},
			ChainEncodings: false,
			IncludeRaw:     true,
		}
	case "full":
		// Full mode: all mutators
		pipelineCfg = mutation.FullCoveragePipelineConfig()
	default:
		// Use default config
		pipelineCfg = mutation.DefaultPipelineConfig()
	}

	// Override with CLI flags if specified
	if cfg.MutationEncoders != "" {
		pipelineCfg.Encoders = strings.Split(cfg.MutationEncoders, ",")
	}
	if cfg.MutationLocations != "" {
		pipelineCfg.Locations = strings.Split(cfg.MutationLocations, ",")
	}
	if cfg.MutationEvasions != "" {
		pipelineCfg.Evasions = strings.Split(cfg.MutationEvasions, ",")
	}
	if cfg.MutationChain {
		pipelineCfg.ChainEncodings = true
	}
	if cfg.MutationMaxChain > 0 {
		pipelineCfg.MaxChainDepth = cfg.MutationMaxChain
	}

	// Get mutators by category
	encoders := mutation.DefaultRegistry.GetByCategory("encoder")
	evasions := mutation.DefaultRegistry.GetByCategory("evasion")

	// Filter encoders by config
	var selectedEncoders []mutation.Mutator
	if len(pipelineCfg.Encoders) > 0 {
		encoderSet := make(map[string]bool)
		for _, name := range pipelineCfg.Encoders {
			encoderSet[strings.TrimSpace(name)] = true
		}
		for _, enc := range encoders {
			if encoderSet[enc.Name()] {
				selectedEncoders = append(selectedEncoders, enc)
			}
		}
	} else {
		selectedEncoders = encoders
	}

	// Filter evasions by config
	var selectedEvasions []mutation.Mutator
	if len(pipelineCfg.Evasions) > 0 {
		evasionSet := make(map[string]bool)
		for _, name := range pipelineCfg.Evasions {
			evasionSet[strings.TrimSpace(name)] = true
		}
		for _, eva := range evasions {
			if evasionSet[eva.Name()] {
				selectedEvasions = append(selectedEvasions, eva)
			}
		}
	}

	// Expand payloads
	var mutatedPayloads []payloads.Payload
	seen := make(map[string]bool)

	for _, p := range originalPayloads {
		// Always include original if IncludeRaw
		if pipelineCfg.IncludeRaw {
			mutatedPayloads = append(mutatedPayloads, p)
			seen[p.ID+":"+p.Payload] = true
		}

		// Apply encoders
		for _, enc := range selectedEncoders {
			results := enc.Mutate(p.Payload)
			for _, r := range results {
				key := p.ID + ":" + r.Mutated
				if !seen[key] && r.Mutated != p.Payload {
					seen[key] = true
					mutated := p // Copy original
					mutated.Payload = r.Mutated
					mutated.ID = fmt.Sprintf("%s_%s", p.ID, enc.Name())
					mutatedPayloads = append(mutatedPayloads, mutated)
				}
			}
		}

		// Apply evasions (only if configured)
		for _, eva := range selectedEvasions {
			results := eva.Mutate(p.Payload)
			for _, r := range results {
				key := p.ID + ":" + r.Mutated
				if !seen[key] && r.Mutated != p.Payload {
					seen[key] = true
					mutated := p
					mutated.Payload = r.Mutated
					mutated.ID = fmt.Sprintf("%s_%s", p.ID, eva.Name())
					mutatedPayloads = append(mutatedPayloads, mutated)
				}
			}
		}

		// Chain mutations if enabled (encoder → evasion)
		if pipelineCfg.ChainEncodings && len(selectedEvasions) > 0 {
			for _, enc := range selectedEncoders {
				encResults := enc.Mutate(p.Payload)
				for _, encR := range encResults {
					for _, eva := range selectedEvasions {
						evaResults := eva.Mutate(encR.Mutated)
						for _, evaR := range evaResults {
							key := p.ID + ":" + evaR.Mutated
							if !seen[key] && evaR.Mutated != p.Payload {
								seen[key] = true
								mutated := p
								mutated.Payload = evaR.Mutated
								mutated.ID = fmt.Sprintf("%s_%s_%s", p.ID, enc.Name(), eva.Name())
								mutatedPayloads = append(mutatedPayloads, mutated)
							}
						}
					}
				}
			}
		}
	}

	return mutatedPayloads
}

// buildFilterConfig creates a FilterConfig from CLI flags
func buildFilterConfig(cfg *config.Config) *core.FilterConfig {
	fc := &core.FilterConfig{}
	hasAny := false

	// Parse match status codes (e.g., "200,403,500")
	if cfg.MatchStatus != "" {
		fc.MatchStatus = parseIntList(cfg.MatchStatus)
		hasAny = true
	}

	// Parse filter status codes
	if cfg.FilterStatus != "" {
		fc.FilterStatus = parseIntList(cfg.FilterStatus)
		hasAny = true
	}

	// Parse match size
	if cfg.MatchSize != "" {
		fc.MatchSize = parseIntList(cfg.MatchSize)
		hasAny = true
	}

	// Parse filter size
	if cfg.FilterSize != "" {
		fc.FilterSize = parseIntList(cfg.FilterSize)
		hasAny = true
	}

	// Parse match words
	if cfg.MatchWords != "" {
		fc.MatchWords = parseIntList(cfg.MatchWords)
		hasAny = true
	}

	// Parse filter words
	if cfg.FilterWords != "" {
		fc.FilterWords = parseIntList(cfg.FilterWords)
		hasAny = true
	}

	// Parse match lines
	if cfg.MatchLines != "" {
		fc.MatchLines = parseIntList(cfg.MatchLines)
		hasAny = true
	}

	// Parse filter lines
	if cfg.FilterLines != "" {
		fc.FilterLines = parseIntList(cfg.FilterLines)
		hasAny = true
	}

	// Parse match regex
	if cfg.MatchRegex != "" {
		if re, err := regexcache.Get(cfg.MatchRegex); err == nil {
			fc.MatchRegex = re
			hasAny = true
		}
	}

	// Parse filter regex
	if cfg.FilterRegex != "" {
		if re, err := regexcache.Get(cfg.FilterRegex); err == nil {
			fc.FilterRegex = re
			hasAny = true
		}
	}

	if !hasAny {
		return nil
	}
	return fc
}

// parseIntList parses comma-separated integers (e.g., "200,403,500")
func parseIntList(s string) []int {
	var result []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			result = append(result, n)
		}
	}
	return result
}
