package main

// WAF-Aware Strategy Integration
// This file provides helper functions to integrate WAF detection with all testing modes.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/waf/strategy"
	"github.com/waftester/waftester/pkg/waf/vendors"
)

// SmartModeConfig holds configuration for WAF-aware testing
type SmartModeConfig struct {
	// Detection settings
	DetectionTimeout time.Duration
	Verbose          bool

	// Override settings (empty = use WAF-specific defaults)
	ForceEncoders  []string
	ForceEvasions  []string
	ForceRateLimit float64

	// Mode: quick, standard, full, bypass, stealth
	Mode string
}

// DefaultSmartModeConfig returns sensible defaults for smart mode
func DefaultSmartModeConfig() *SmartModeConfig {
	return &SmartModeConfig{
		DetectionTimeout: duration.HTTPScanning,
		Verbose:          false,
		Mode:             "standard",
	}
}

// SmartModeResult holds the result of WAF detection and strategy generation
type SmartModeResult struct {
	// Detection results
	WAFDetected    bool
	VendorName     string
	Vendor         vendors.WAFVendor
	Confidence     float64
	Evidence       []string
	BypassHints    []string
	DetectionError error

	// Generated strategy
	Strategy *strategy.Strategy

	// Optimized configuration
	Pipeline    *mutation.PipelineConfig
	RateLimit   float64
	Concurrency int
}

// DetectAndOptimize performs WAF detection and generates an optimized testing strategy
func DetectAndOptimize(ctx context.Context, targetURL string, config *SmartModeConfig) (*SmartModeResult, error) {
	if config == nil {
		config = DefaultSmartModeConfig()
	}

	result := &SmartModeResult{}

	// Create strategy engine
	engine := strategy.NewStrategyEngine(config.DetectionTimeout)

	// Get optimized strategy (includes WAF detection)
	strat, err := engine.GetStrategy(ctx, targetURL)
	if err != nil {
		result.DetectionError = err
		// Use default strategy on error
		strat = &strategy.Strategy{
			Vendor:                   vendors.VendorUnknown,
			VendorName:               "Unknown/Generic",
			Confidence:               0,
			Encoders:                 []string{"double_url", "unicode", "html_hex", "base64"},
			Evasions:                 []string{"case_swap", "sql_comment", "whitespace_alt"},
			Locations:                []string{"query", "body_json", "body_form", "path"},
			SafeRateLimit:            50,
			BurstRateLimit:           300,
			CooldownSeconds:          10,
			RecommendedMutationDepth: 2,
		}
	}

	result.Strategy = strat
	result.WAFDetected = strat.Vendor != vendors.VendorUnknown
	result.VendorName = strat.VendorName
	result.Vendor = strat.Vendor
	result.Confidence = strat.Confidence
	result.BypassHints = strat.BypassTips

	// Generate optimized pipeline
	result.Pipeline = strategy.WAFOptimizedPipeline(strat, config.Mode)

	// Apply overrides if specified
	if len(config.ForceEncoders) > 0 {
		result.Pipeline.Encoders = config.ForceEncoders
	}
	if len(config.ForceEvasions) > 0 {
		result.Pipeline.Evasions = config.ForceEvasions
	}

	// Get optimal rate limit and concurrency
	result.RateLimit, _ = strat.GetOptimalRateLimit(config.Mode)
	if config.ForceRateLimit > 0 {
		result.RateLimit = config.ForceRateLimit
	}
	result.Concurrency = strat.GetRecommendedConcurrency(config.Mode)

	return result, nil
}

// PrintSmartModeInfo prints the smart mode detection and configuration info
func PrintSmartModeInfo(result *SmartModeResult, verbose bool) {
	// Respect silent mode for JSON output
	if ui.IsSilent() {
		return
	}

	if result.WAFDetected {
		ui.PrintSuccess(fmt.Sprintf("🎯 WAF Detected: %s (%.0f%% confidence)", result.VendorName, result.Confidence*100))

		if verbose {
			// Show evidence
			if len(result.Evidence) > 0 {
				fmt.Fprintln(os.Stderr, "   Evidence:")
				for _, ev := range result.Evidence[:min(3, len(result.Evidence))] {
					fmt.Fprintf(os.Stderr, "     • %s\n", ev)
				}
			}

			// Show optimized config
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "   📋 WAF-Optimized Configuration:")
			fmt.Fprintf(os.Stderr, "     Rate Limit: %.0f req/sec (safe for %s)\n", result.RateLimit, result.VendorName)
			fmt.Fprintf(os.Stderr, "     Concurrency: %d workers\n", result.Concurrency)

			if len(result.Pipeline.Encoders) > 0 {
				fmt.Fprintf(os.Stderr, "     Encoders: %d prioritized\n", len(result.Pipeline.Encoders))
				if len(result.Pipeline.Encoders) <= 5 {
					fmt.Fprintf(os.Stderr, "       → %v\n", result.Pipeline.Encoders)
				}
			}
			if len(result.Pipeline.Evasions) > 0 {
				fmt.Fprintf(os.Stderr, "     Evasions: %d selected\n", len(result.Pipeline.Evasions))
			}
		}

		// Show bypass hints
		if len(result.BypassHints) > 0 {
			fmt.Fprintln(os.Stderr)
			ui.PrintInfo("   💡 Bypass Hints:")
			for i, hint := range result.BypassHints {
				if i >= 3 {
					fmt.Fprintf(os.Stderr, "     ... and %d more\n", len(result.BypassHints)-3)
					break
				}
				fmt.Fprintf(os.Stderr, "     → %s\n", hint)
			}
		}

		// Show template recommendations
		recommendations := GetTemplateRecommendations(result)
		if len(recommendations) > 0 {
			fmt.Fprintln(os.Stderr)
			ui.PrintInfo("   📋 Recommended Templates:")
			for _, rec := range recommendations {
				fmt.Fprintf(os.Stderr, "     → %s\n", rec)
			}
		}
	} else {
		ui.PrintInfo("🔍 No specific WAF detected - using generic testing configuration")
		if verbose {
			fmt.Fprintf(os.Stderr, "     Rate Limit: %.0f req/sec\n", result.RateLimit)
			fmt.Fprintf(os.Stderr, "     Concurrency: %d workers\n", result.Concurrency)
		}
	}
	fmt.Fprintln(os.Stderr)
}

// ApplySmartConfig applies the smart mode result to an ExecutorConfig
func ApplySmartConfig(cfg *mutation.ExecutorConfig, result *SmartModeResult) {
	if cfg == nil || result == nil {
		return
	}

	// Apply pipeline configuration
	if result.Pipeline != nil {
		cfg.Pipeline = result.Pipeline
	}

	// Apply WAF-optimized rate limit (override user default if smart mode found a safe rate)
	// The smart mode rate limit is the safe maximum for that specific WAF, so we use it
	// unless the user explicitly set a custom rate limit via CLI flag
	if result.RateLimit > 0 {
		cfg.RateLimit = result.RateLimit
	}

	// Apply WAF-optimized concurrency
	if result.Concurrency > 0 {
		cfg.Concurrency = result.Concurrency
	}

	// Enable realistic mode for better detection
	cfg.RealisticMode = true
	cfg.AutoCalibrate = true
}

// GetSmartModeHelp returns help text for the --smart flag
func GetSmartModeHelp() string {
	return `
SMART MODE (--smart)
====================

Smart mode automatically detects the WAF vendor (from 197+ signatures) and
optimizes testing based on known WAF characteristics:

  1. WAF Detection     - Identifies the exact WAF vendor with confidence score
  2. Rate Optimization - Adjusts rate limit to avoid triggering rate blocks
  3. Encoder Priority  - Prioritizes encoders known to bypass that specific WAF
  4. Evasion Selection - Enables evasion techniques effective against that WAF
  5. Bypass Hints      - Shows specific bypass tips for the detected WAF

Smart Mode Options:
  --smart             Enable WAF-aware testing (auto-detect and optimize)
  --smart-mode=MODE   Set optimization level: quick, standard, full, bypass, stealth
  --smart-verbose     Show detailed WAF detection and optimization info

Examples:
  waf-tester bypass -u https://target.com --smart
  waf-tester auto -u https://target.com --smart --smart-mode=full
  waf-tester scan -u https://target.com --smart --smart-verbose
`
}

// Note: min() function is defined in main.go, no need to redeclare here

// GetTemplateRecommendations returns recommended template paths based on detected WAF vendor.
func GetTemplateRecommendations(result *SmartModeResult) []string {
	if result == nil || !result.WAFDetected {
		return []string{
			"templates/nuclei/http/waf-bypass/   (all bypass templates)",
			"templates/policies/standard.yaml    (standard grading policy)",
			"payloads/community/waf-bypass/      (133 bypass payloads from JSON DB)",
		}
	}

	recommendations := make([]string, 0, 8)

	vendorLower := strings.ToLower(result.VendorName)

	// WAF-specific detection templates
	switch {
	case strings.Contains(vendorLower, "cloudflare"):
		recommendations = append(recommendations,
			"templates/nuclei/http/waf-detection/cloudflare-detect.yaml",
			"payloads/community/waf-bypass/cloudflare-bypass.json (20 vendor-specific bypasses)",
		)
	case strings.Contains(vendorLower, "aws"), strings.Contains(vendorLower, "amazon"):
		recommendations = append(recommendations, "templates/nuclei/http/waf-detection/aws-waf-detect.yaml")
	case strings.Contains(vendorLower, "akamai"):
		recommendations = append(recommendations, "templates/nuclei/http/waf-detection/akamai-detect.yaml")
	case strings.Contains(vendorLower, "azure"), strings.Contains(vendorLower, "microsoft"):
		recommendations = append(recommendations, "templates/nuclei/http/waf-detection/azure-waf-detect.yaml")
	case strings.Contains(vendorLower, "modsecurity"), strings.Contains(vendorLower, "coraza"):
		recommendations = append(recommendations,
			"templates/nuclei/http/waf-detection/modsecurity-detect.yaml",
			"templates/overrides/crs-tuning.yaml  (CRS paranoia level tuning)",
			"payloads/community/waf-bypass/modsecurity-crs.json (20 CRS-specific bypasses)",
		)
	}

	// Always recommend bypass templates + unified payload access
	recommendations = append(recommendations,
		"templates/nuclei/http/waf-bypass/   (all bypass templates)",
		"templates/policies/standard.yaml    (standard grading policy)",
		"templates/overrides/false-positive-suppression.yaml (reduce noise)",
		"Use --enrich flag with template command to inject 2800+ JSON payloads into Nuclei templates",
	)

	return recommendations
}
