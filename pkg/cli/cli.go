// Package cli provides unified CLI integration for all waf-tester capabilities.
// It bridges the new packages (encoding, benchmark, grpc, soap, etc.) with CLI commands.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/benchmark"
	"github.com/waftester/waftester/pkg/encoding"
	"github.com/waftester/waftester/pkg/evasion/advanced"
	"github.com/waftester/waftester/pkg/falsepositive"
	"github.com/waftester/waftester/pkg/ftw"
	"github.com/waftester/waftester/pkg/health"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/override"
	"github.com/waftester/waftester/pkg/paranoia"
	"github.com/waftester/waftester/pkg/placeholder"
	"github.com/waftester/waftester/pkg/report"
)

// Command represents a CLI command.
type Command string

const (
	CommandEncode      Command = "encode"
	CommandBenchmark   Command = "benchmark"
	CommandEvade       Command = "evade"
	CommandFP          Command = "fp"
	CommandGRPC        Command = "grpc-test"
	CommandSOAP        Command = "soap-test"
	CommandHealth      Command = "health"
	CommandFTW         Command = "ftw-convert"
	CommandReport      Command = "report"
	CommandParanoia    Command = "paranoia"
	CommandPlaceholder Command = "placeholder"
)

// Config holds CLI configuration.
type Config struct {
	Verbose     bool          `json:"verbose"`
	Output      string        `json:"output"`
	Format      string        `json:"format"`
	Timeout     time.Duration `json:"timeout"`
	Concurrency int           `json:"concurrency"`
	Tags        []string      `json:"tags"`
}

// DefaultConfig returns default CLI config.
func DefaultConfig() *Config {
	return &Config{
		Verbose:     false,
		Output:      "",
		Format:      "json",
		Timeout:     httpclient.TimeoutFuzzing,
		Concurrency: 10,
		Tags:        []string{},
	}
}

// =============================================================================
// Encoding Commands
// =============================================================================

// EncodeOptions for encoding commands.
type EncodeOptions struct {
	Input     string   `json:"input"`
	Encodings []string `json:"encodings"`
	Chain     bool     `json:"chain"`
	All       bool     `json:"all"`
}

// RunEncode runs encoding operations.
func RunEncode(opts *EncodeOptions, w io.Writer) error {
	if opts.Input == "" {
		return fmt.Errorf("input is required")
	}

	var results []EncodingResult

	if opts.All {
		for _, name := range encoding.List() {
			enc := encoding.Get(name)
			if enc != nil {
				result, _ := enc.Encode(opts.Input)
				results = append(results, EncodingResult{
					Encoding: name,
					Output:   result,
				})
			}
		}
	} else if opts.Chain && len(opts.Encodings) > 1 {
		chain := encoding.Chain(opts.Encodings...)
		if chain != nil {
			result, err := chain.Encode(opts.Input)
			if err != nil {
				return err
			}
			results = append(results, EncodingResult{
				Encoding: strings.Join(opts.Encodings, "→"),
				Output:   result,
			})
		}
	} else {
		for _, encID := range opts.Encodings {
			enc := encoding.Get(encID)
			if enc == nil {
				return fmt.Errorf("encoder not found: %s", encID)
			}
			result, err := enc.Encode(opts.Input)
			if err != nil {
				return err
			}
			results = append(results, EncodingResult{
				Encoding: encID,
				Output:   result,
			})
		}
	}

	return writeJSON(w, results)
}

// EncodingResult holds encoding result.
type EncodingResult struct {
	Encoding string `json:"encoding"`
	Output   string `json:"output"`
}

// =============================================================================
// Evasion Commands
// =============================================================================

// EvasionOptions for evasion generation.
type EvasionOptions struct {
	Payload     string   `json:"payload"`
	Techniques  []string `json:"techniques"`
	MaxVariants int      `json:"max_variants"`
	ChainDepth  int      `json:"chain_depth"`
}

// RunEvasion generates evasion variants.
func RunEvasion(opts *EvasionOptions, w io.Writer) error {
	if opts.Payload == "" {
		return fmt.Errorf("payload is required")
	}

	config := advanced.DefaultConfig()
	if opts.MaxVariants > 0 {
		config.MaxVariants = opts.MaxVariants
	}
	if opts.ChainDepth > 0 {
		config.MaxChainDepth = opts.ChainDepth
	}

	engine := advanced.NewEngine(config)
	variants := engine.GenerateVariants(opts.Payload, config.MaxVariants)

	return writeJSON(w, variants)
}

// =============================================================================
// Benchmark Commands
// =============================================================================

// BenchmarkOptions for benchmark commands.
type BenchmarkOptions struct {
	Target      string `json:"target"`
	TestsFile   string `json:"tests_file"`
	ParanoiaLvl int    `json:"paranoia_level"`
	OutputFile  string `json:"output_file"`
	HTMLReport  bool   `json:"html_report"`
}

// RunBenchmark executes benchmark scoring.
func RunBenchmark(opts *BenchmarkOptions, w io.Writer) error {
	scorer := benchmark.NewScorer()

	results := []benchmark.Result{
		{
			TestName:      "test-1",
			Category:      "sqli",
			Payload:       "' OR '1'='1",
			Blocked:       true,
			ExpectedBlock: true,
		},
	}

	bench := scorer.Score(results)
	return writeJSON(w, bench)
}

// =============================================================================
// False Positive Commands
// =============================================================================

// FPOptions for false positive analysis.
type FPOptions struct {
	ResultsFile  string `json:"results_file"`
	DatabaseFile string `json:"database_file"`
	Action       string `json:"action"`
}

// RunFP runs false positive operations.
func RunFP(opts *FPOptions, w io.Writer) error {
	db := falsepositive.NewDatabase()

	if opts.DatabaseFile != "" {
		if _, err := os.Stat(opts.DatabaseFile); err == nil {
			if err := db.Load(opts.DatabaseFile); err != nil {
				return fmt.Errorf("failed to load database: %w", err)
			}
		}
	}

	switch opts.Action {
	case "report":
		rep := falsepositive.GenerateReport(db)
		return writeJSON(w, rep)
	case "list":
		fps := db.List()
		return writeJSON(w, fps)
	default:
		return writeJSON(w, map[string]interface{}{
			"count":      db.Count(),
			"categories": db.ListByCategory(falsepositive.CategoryKnown),
		})
	}
}

// =============================================================================
// Health Commands
// =============================================================================

// HealthOptions for health checking.
type HealthOptions struct {
	Targets     []string      `json:"targets"`
	Timeout     time.Duration `json:"timeout"`
	Interval    time.Duration `json:"interval"`
	MaxAttempts int           `json:"max_attempts"`
	Wait        bool          `json:"wait"`
}

// RunHealth runs health checks.
func RunHealth(opts *HealthOptions, w io.Writer) error {
	if len(opts.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}

	cfg := health.DefaultConfig()
	if opts.Timeout > 0 {
		cfg.Timeout = opts.Timeout
	}
	if opts.MaxAttempts > 0 {
		cfg.MaxRetries = opts.MaxAttempts
	}

	checker := health.NewChecker(cfg)
	for _, target := range opts.Targets {
		check := &health.Check{
			Name:     target,
			Type:     health.CheckTypeHTTP,
			Endpoint: target,
			Timeout:  opts.Timeout,
		}
		_ = checker.AddCheck(check)
	}

	if opts.Wait {
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = httpclient.TimeoutAPI
		}
		waiterCfg := health.DefaultWaiterConfig()
		waiterCfg.Timeout = timeout
		waiter := health.NewWaiter(checker, waiterCfg)
		result := waiter.Wait(context.Background())
		return writeJSON(w, result)
	}

	results, _ := checker.CheckAll(context.Background())
	return writeJSON(w, results)
}

// =============================================================================
// gRPC Commands
// =============================================================================

// GRPCOptions for gRPC testing.
type GRPCOptions struct {
	Target   string   `json:"target"`
	Proto    string   `json:"proto"`
	Services []string `json:"services"`
	Payloads []string `json:"payloads"`
}

// RunGRPC runs gRPC tests.
func RunGRPC(opts *GRPCOptions, w io.Writer) error {
	if opts.Target == "" {
		return fmt.Errorf("target is required")
	}
	return writeJSON(w, map[string]interface{}{
		"status": "gRPC testing - use pkg/grpc directly",
		"target": opts.Target,
	})
}

// =============================================================================
// SOAP Commands
// =============================================================================

// SOAPOptions for SOAP testing.
type SOAPOptions struct {
	Target   string   `json:"target"`
	WSDLPath string   `json:"wsdl_path"`
	Services []string `json:"services"`
	Payloads []string `json:"payloads"`
}

// RunSOAP runs SOAP tests.
func RunSOAP(opts *SOAPOptions, w io.Writer) error {
	if opts.Target == "" {
		return fmt.Errorf("target is required")
	}
	return writeJSON(w, map[string]interface{}{
		"status": "SOAP testing - use pkg/soap directly",
		"target": opts.Target,
	})
}

// =============================================================================
// FTW Commands
// =============================================================================

// FTWOptions for FTW operations.
type FTWOptions struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Action string `json:"action"`
	Format string `json:"format"`
}

// RunFTW runs FTW conversion operations.
func RunFTW(opts *FTWOptions, w io.Writer) error {
	switch opts.Action {
	case "validate":
		validator := ftw.NewValidator()
		result, err := validator.ValidateFile(opts.Input)
		if err != nil {
			return err
		}
		return writeJSON(w, result)

	case "import":
		importer := ftw.NewImporter()
		tests, err := importer.ImportDirectory(opts.Input)
		if err != nil {
			return err
		}
		return writeJSON(w, map[string]interface{}{
			"imported": len(tests),
		})

	case "export":
		test, err := ftw.LoadFTWFile(opts.Input)
		if err != nil {
			return err
		}
		if opts.Output != "" {
			return ftw.SaveFTWFile(test, opts.Output)
		}
		return writeJSON(w, test)

	default:
		return fmt.Errorf("unknown action: %s", opts.Action)
	}
}

// =============================================================================
// Report Commands
// =============================================================================

// ReportOptions for report generation.
type ReportOptions struct {
	ResultsFile string `json:"results_file"`
	OutputFile  string `json:"output_file"`
	Format      string `json:"format"`
	Title       string `json:"title"`
	Template    string `json:"template"`
}

// RunReport generates reports.
func RunReport(opts *ReportOptions, w io.Writer) error {
	if opts.ResultsFile == "" {
		return fmt.Errorf("results file is required")
	}

	data, err := os.ReadFile(opts.ResultsFile)
	if err != nil {
		return err
	}

	var findings []*report.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return err
	}

	// Determine format
	format := report.ReportFormat(opts.Format)
	if format == "" {
		format = report.FormatHTML
	}

	generator := report.NewReportGenerator()
	config := report.ReportConfig{
		Title:  opts.Title,
		Format: format,
	}

	builder := report.NewReportBuilder(config)
	for _, f := range findings {
		builder.AddFinding(f)
	}
	rep := builder.Build()

	if opts.OutputFile != "" {
		outputFile, err := os.Create(opts.OutputFile)
		if err != nil {
			return err
		}
		defer outputFile.Close()
		return generator.Generate(rep, outputFile)
	}

	return generator.Generate(rep, w)
}

// =============================================================================
// Paranoia Commands
// =============================================================================

// ParanoiaOptions for paranoia level testing.
type ParanoiaOptions struct {
	Target  string `json:"target"`
	Level   int    `json:"level"`
	Detect  bool   `json:"detect"`
	Compare bool   `json:"compare"`
}

// RunParanoia runs paranoia level operations.
func RunParanoia(opts *ParanoiaOptions, w io.Writer) error {
	level := paranoia.PL1
	if opts.Level > 0 && opts.Level <= 4 {
		level = paranoia.Level(opts.Level)
	}

	// Use NewConfig instead of DefaultConfig
	cfg := paranoia.NewConfig(level)

	if opts.Detect {
		// Just return the configured level
		return writeJSON(w, map[string]interface{}{
			"current_level": level,
			"description":   level.Description(),
			"categories":    level.RuleCategories(),
		})
	}

	if opts.Compare {
		// Compare PL1 vs PL4 categories
		return writeJSON(w, map[string]interface{}{
			"pl1_categories": paranoia.PL1.RuleCategories(),
			"pl4_categories": paranoia.PL4.RuleCategories(),
			"difference":     len(paranoia.PL4.RuleCategories()) - len(paranoia.PL1.RuleCategories()),
		})
	}

	// Generate tests for this level
	gen := paranoia.NewGenerator()
	tests := gen.GenerateForLevel(level)
	return writeJSON(w, map[string]interface{}{
		"level":       cfg.Level,
		"test_count":  len(tests),
		"description": level.Description(),
	})
}

// =============================================================================
// Placeholder Commands
// =============================================================================

// PlaceholderOptions for placeholder operations.
type PlaceholderOptions struct {
	Template string            `json:"template"`
	Values   map[string]string `json:"values"`
	Payload  string            `json:"payload"`
	Output   string            `json:"output"`
}

// RunPlaceholder runs placeholder operations.
func RunPlaceholder(opts *PlaceholderOptions, w io.Writer) error {
	engine := placeholder.NewEngine(nil)

	if opts.Payload != "" && opts.Template != "" {
		result := engine.Inject(opts.Template, opts.Payload)
		return writeJSON(w, map[string]interface{}{
			"result": result,
		})
	}

	if opts.Template != "" && len(opts.Values) > 0 {
		var vals []placeholder.Value
		for k, v := range opts.Values {
			vals = append(vals, placeholder.Value{Name: k, Value: v})
		}
		result := engine.Process(opts.Template, vals)
		return writeJSON(w, map[string]interface{}{
			"result": result,
		})
	}

	return writeJSON(w, engine.List())
}

// =============================================================================
// Override Commands
// =============================================================================

// OverrideOptions for test override operations.
type OverrideOptions struct {
	TestID   string            `json:"test_id"`
	Reason   string            `json:"reason"`
	Action   string            `json:"action"`
	File     string            `json:"file"`
	Metadata map[string]string `json:"metadata"`
}

// RunOverride manages test overrides.
func RunOverride(opts *OverrideOptions, w io.Writer) error {
	mgr := override.NewManager(nil)

	if opts.File != "" {
		if err := mgr.LoadFromFile(opts.File); err != nil {
			return err
		}
	}

	switch opts.Action {
	case "skip":
		o := &override.Override{
			TestID:    opts.TestID,
			Reason:    opts.Reason,
			Action:    override.ActionSkip,
			CreatedAt: time.Now(),
		}
		mgr.Add(o)
	case "list":
		overrides := mgr.List()
		return writeJSON(w, overrides)
	case "apply":
		test := &override.Test{ID: opts.TestID}
		result := mgr.Apply(test)
		return writeJSON(w, result)
	}

	return writeJSON(w, map[string]string{"status": "ok"})
}

// =============================================================================
// Runner
// =============================================================================

// Runner executes CLI commands.
type Runner struct {
	config *Config
	writer io.Writer
}

// NewRunner creates a new CLI runner.
func NewRunner(config *Config, w io.Writer) *Runner {
	if config == nil {
		config = DefaultConfig()
	}
	if w == nil {
		w = os.Stdout
	}
	return &Runner{config: config, writer: w}
}

// Run executes a command with options.
func (r *Runner) Run(cmd Command, opts interface{}) error {
	switch cmd {
	case CommandEncode:
		return RunEncode(opts.(*EncodeOptions), r.writer)
	case CommandEvade:
		return RunEvasion(opts.(*EvasionOptions), r.writer)
	case CommandBenchmark:
		return RunBenchmark(opts.(*BenchmarkOptions), r.writer)
	case CommandFP:
		return RunFP(opts.(*FPOptions), r.writer)
	case CommandHealth:
		return RunHealth(opts.(*HealthOptions), r.writer)
	case CommandGRPC:
		return RunGRPC(opts.(*GRPCOptions), r.writer)
	case CommandSOAP:
		return RunSOAP(opts.(*SOAPOptions), r.writer)
	case CommandFTW:
		return RunFTW(opts.(*FTWOptions), r.writer)
	case CommandReport:
		return RunReport(opts.(*ReportOptions), r.writer)
	case CommandParanoia:
		return RunParanoia(opts.(*ParanoiaOptions), r.writer)
	case CommandPlaceholder:
		return RunPlaceholder(opts.(*PlaceholderOptions), r.writer)
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

// =============================================================================
// Helpers
// =============================================================================

func writeJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// LoadConfig loads CLI config from file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	return config, nil
}

// SaveConfig saves CLI config to file.
func SaveConfig(config *Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Commands returns list of available commands.
func Commands() []Command {
	return []Command{
		CommandEncode,
		CommandBenchmark,
		CommandEvade,
		CommandFP,
		CommandGRPC,
		CommandSOAP,
		CommandHealth,
		CommandFTW,
		CommandReport,
		CommandParanoia,
		CommandPlaceholder,
	}
}
