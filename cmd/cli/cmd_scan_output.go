package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/ui"
)

// scanOutputConfig bundles all output-related parameters so
// finalizeScanOutput can be a standalone, testable function
// instead of inlined at the end of a 3000-line god function.
type scanOutputConfig struct {
	Target     string
	StreamJSON bool

	TotalScans  int32
	ScanErrors  *int32 // atomic pointer — caller owns
	CSVOutput   bool
	MDOutput    bool
	HTMLOutput  bool
	SARIFOutput bool
	JSONOutput  bool
	FormatType  string
	OutputFile  string

	ReportTitle  string
	ReportAuthor string

	OutFlags *OutputFlags
	DispCtx  *DispatcherContext
}

// finalizeScanOutput handles everything after wg.Wait(): the console
// summary, format-specific exports, file output, and enterprise exports.
// Extracted from the tail of runScan() to keep the orchestrator focused
// on scanner dispatch.
func finalizeScanOutput(ctx context.Context, result *ScanResult, cfg scanOutputConfig) {
	// Print scan completion summary to stderr (never pollute stdout)
	if !cfg.StreamJSON {
		printScanCompletionBanner(result, cfg.TotalScans, cfg.ScanErrors)
	}

	// Apply report metadata
	if cfg.ReportTitle != "" {
		result.ReportTitle = cfg.ReportTitle
	}
	if cfg.ReportAuthor != "" {
		result.ReportAuthor = cfg.ReportAuthor
	}

	// CSV output format
	if cfg.CSVOutput {
		printScanCSV(os.Stdout, cfg.Target, result)
		return
	}

	// Markdown output format
	if cfg.MDOutput {
		printScanMarkdown(os.Stdout, result)
		return
	}

	// HTML output format
	if cfg.HTMLOutput {
		printScanHTML(os.Stdout, result)
		return
	}

	// SARIF output format (for CI/CD integration)
	if cfg.SARIFOutput {
		printScanSARIF(os.Stdout, cfg.Target, result)
		return
	}

	// Check format type flag
	if cfg.FormatType != "" && cfg.FormatType != "console" {
		switch cfg.FormatType {
		case "jsonl":
			printScanJSONL(os.Stdout, cfg.Target, result)
			return
		}
	}

	// Print summary (skip in stream+json mode)
	if !cfg.JSONOutput && !cfg.StreamJSON {
		printScanConsoleSummary(result)
	}

	// Output JSON (skip final blob in stream+json mode)
	if (cfg.JSONOutput || cfg.OutputFile != "") && !cfg.StreamJSON {
		writeScanJSON(ctx, result, cfg)
	}

	// Write to file in stream mode
	if cfg.OutputFile != "" && cfg.StreamJSON {
		writeScanJSON(ctx, result, cfg)
	}

	// Enterprise export formats (--json-export, --sarif-export, --html-export, etc.)
	writeScanExports(cfg.OutFlags, cfg.Target, result)

	if result.TotalVulns > 0 {
		if cfg.DispCtx != nil {
			_ = cfg.DispCtx.Close()
		}
		os.Exit(1)
	}
}

// printScanCompletionBanner writes the color-coded completion summary to stderr.
func printScanCompletionBanner(result *ScanResult, totalScans int32, scanErrors *int32) {
	vulnColor := ""
	colorReset := ""
	if ui.StderrIsTerminal() {
		vulnColor = "\033[32m" // Green
		if result.TotalVulns > 0 {
			vulnColor = "\033[33m" // Yellow
		}
		if result.TotalVulns > 5 {
			vulnColor = "\033[31m" // Red
		}
		colorReset = "\033[0m"
	}
	vulnWord := "vulnerabilities"
	if result.TotalVulns == 1 {
		vulnWord = "vulnerability"
	}
	typeWord := "scan types"
	if totalScans == 1 {
		typeWord = "scan type"
	}
	fmt.Fprintln(os.Stderr)                                                                                                                                       // debug:keep
	ui.PrintSuccess(fmt.Sprintf("Scan complete in %s", result.Duration.Round(time.Millisecond)))                                                                  // debug:keep
	fmt.Fprintf(os.Stderr, "  %s Results: %s%d %s%s across %d %s\n", ui.Icon("📊", "#"), vulnColor, result.TotalVulns, vulnWord, colorReset, totalScans, typeWord) // debug:keep
	if scanErrors != nil {
		if errCount := atomic.LoadInt32(scanErrors); errCount > 0 {
			ui.PrintWarning(fmt.Sprintf("%d scanner(s) encountered errors (use -verbose for details)", errCount))
		}
	}
	fmt.Fprintln(os.Stderr) // debug:keep
}

// writeScanJSON marshals results to JSON and writes to file and/or stdout.
func writeScanJSON(ctx context.Context, result *ScanResult, cfg scanOutputConfig) {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		errMsg := fmt.Sprintf("JSON encoding error: %v", err)
		ui.PrintError(errMsg)
		if cfg.DispCtx != nil {
			_ = cfg.DispCtx.EmitError(ctx, "scan", errMsg, true)
			_ = cfg.DispCtx.Close()
		}
		os.Exit(1)
	}

	if cfg.OutputFile != "" {
		if err := os.WriteFile(cfg.OutputFile, jsonData, 0644); err != nil {
			errMsg := fmt.Sprintf("Error writing output: %v", err)
			ui.PrintError(errMsg)
			if cfg.DispCtx != nil {
				_ = cfg.DispCtx.EmitError(ctx, "scan", errMsg, true)
				_ = cfg.DispCtx.Close()
			}
			os.Exit(1)
		}
		ui.PrintSuccess(fmt.Sprintf("Results saved to %s", cfg.OutputFile))
	}

	if cfg.JSONOutput && !cfg.StreamJSON {
		fmt.Println(string(jsonData)) // debug:keep
	}
}
