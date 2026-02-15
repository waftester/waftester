package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/leakypaths"
	"github.com/waftester/waftester/pkg/learning"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/params"
	"github.com/waftester/waftester/pkg/ui"
)

// generateAutoMarkdownReport creates a comprehensive markdown report for auto scan
func generateAutoMarkdownReport(filename, target, domain string, duration time.Duration,
	discResult *discovery.DiscoveryResult, jsData *js.ExtractedData,
	testPlan *learning.TestPlan, results output.ExecutionResults, wafEffectiveness float64,
	leakyResult *leakypaths.ScanSummary, paramResult *params.DiscoveryResult,
	vendorName string, vendorConfidence float64) {

	var sb strings.Builder

	sb.WriteString("# 🛡️ WAF Security Assessment Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s  \n", target))
	sb.WriteString(fmt.Sprintf("**Domain:** %s  \n", domain))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", duration.Round(time.Second)))

	sb.WriteString("---\n\n")

	// Executive Summary
	sb.WriteString("## 📋 Executive Summary\n\n")

	if wafEffectiveness >= 95 {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - EXCELLENT** ✅\n\n", wafEffectiveness))
		sb.WriteString("The WAF is performing exceptionally well, blocking virtually all attack attempts.\n\n")
	} else if wafEffectiveness >= 80 {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - GOOD** ⚠️\n\n", wafEffectiveness))
		sb.WriteString("The WAF is performing well but has room for improvement.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - NEEDS ATTENTION** ❌\n\n", wafEffectiveness))
		sb.WriteString("The WAF requires immediate attention. Multiple bypasses detected.\n\n")
	}

	// Key Findings
	sb.WriteString("### Key Findings\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Endpoints Discovered | %d |\n", len(discResult.Endpoints)))
	sb.WriteString(fmt.Sprintf("| JavaScript Files Analyzed | %d |\n", len(jsData.Endpoints)))
	sb.WriteString(fmt.Sprintf("| Secrets Found | %d |\n", len(jsData.Secrets)))
	sb.WriteString(fmt.Sprintf("| Subdomains Discovered | %d |\n", len(jsData.Subdomains)))
	sb.WriteString(fmt.Sprintf("| Total Tests Executed | %d |\n", results.TotalTests))
	sb.WriteString(fmt.Sprintf("| WAF Blocks | %d |\n", results.BlockedTests))
	sb.WriteString(fmt.Sprintf("| Bypasses Detected | %d |\n", results.FailedTests))
	sb.WriteString("\n")

	// Discovery Results
	sb.WriteString("## 🔍 Discovery Results\n\n")

	if discResult.WAFDetected {
		sb.WriteString(fmt.Sprintf("**WAF Detected:** %s\n\n", discResult.WAFFingerprint))
	}

	sb.WriteString("### Attack Surface\n\n")
	surface := discResult.AttackSurface
	if surface.HasAuthEndpoints {
		sb.WriteString("- ✅ Authentication endpoints detected\n")
	}
	if surface.HasAPIEndpoints {
		sb.WriteString("- ✅ API endpoints detected\n")
	}
	if surface.HasFileUpload {
		sb.WriteString("- ✅ File upload functionality detected\n")
	}
	if surface.HasOAuth {
		sb.WriteString("- ✅ OAuth endpoints detected\n")
	}
	if surface.HasGraphQL {
		sb.WriteString("- ✅ GraphQL endpoint detected\n")
	}
	sb.WriteString("\n")

	// Vendor Detection
	if vendorName != "" {
		sb.WriteString("### WAF Vendor Detection\n\n")
		sb.WriteString(fmt.Sprintf("**Vendor:** %s (%.0f%% confidence)\n\n", vendorName, vendorConfidence*100))
	}

	// Leaky Paths
	if leakyResult != nil && leakyResult.InterestingHits > 0 {
		sb.WriteString("### Sensitive Path Findings\n\n")
		sb.WriteString(fmt.Sprintf("Scanned %d paths, found **%d exposed** sensitive endpoints.\n\n", leakyResult.PathsScanned, leakyResult.InterestingHits))
		sb.WriteString("| Path | Status | Category |\n")
		sb.WriteString("|------|--------|----------|\n")
		limit := len(leakyResult.Results)
		if limit > 20 {
			limit = 20
		}
		for _, r := range leakyResult.Results[:limit] {
			sb.WriteString(fmt.Sprintf("| `%s` | %d | %s |\n", r.Path, r.StatusCode, r.Category))
		}
		if len(leakyResult.Results) > 20 {
			sb.WriteString(fmt.Sprintf("| ... | ... | *%d more* |\n", len(leakyResult.Results)-20))
		}
		sb.WriteString("\n")
	}

	// Discovered Parameters
	if paramResult != nil && paramResult.FoundParams > 0 {
		sb.WriteString("### Discovered Parameters\n\n")
		sb.WriteString(fmt.Sprintf("Found **%d hidden parameters** (tested %d candidates).\n\n", paramResult.FoundParams, paramResult.TotalTested))
		sb.WriteString("| Parameter | Type | Source |\n")
		sb.WriteString("|-----------|------|--------|\n")
		limit := len(paramResult.Parameters)
		if limit > 20 {
			limit = 20
		}
		for _, p := range paramResult.Parameters[:limit] {
			sb.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", p.Name, p.Type, p.Source))
		}
		if len(paramResult.Parameters) > 20 {
			sb.WriteString(fmt.Sprintf("| ... | ... | *%d more* |\n", len(paramResult.Parameters)-20))
		}
		sb.WriteString("\n")
	}

	// Secrets
	if len(jsData.Secrets) > 0 {
		sb.WriteString("## 🔑 Secrets Detected\n\n")
		sb.WriteString("| Type | Confidence | Value (redacted) |\n")
		sb.WriteString("|------|------------|------------------|\n")
		for _, secret := range jsData.Secrets {
			// Redact secret values — show only first 4 chars to confirm identity
			redacted := "****"
			if len(secret.Value) >= 4 {
				redacted = secret.Value[:4] + "****"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | `%s` |\n", secret.Type, secret.Confidence, redacted))
		}
		sb.WriteString("\n")
	}

	// Test Results
	sb.WriteString("## ⚡ Test Results\n\n")

	sb.WriteString("### Summary\n\n")
	sb.WriteString("| Outcome | Count |\n")
	sb.WriteString("|---------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Blocked | %d |\n", results.BlockedTests))
	sb.WriteString(fmt.Sprintf("| Passed | %d |\n", results.PassedTests))
	sb.WriteString(fmt.Sprintf("| Failed (Bypass) | %d |\n", results.FailedTests))
	sb.WriteString(fmt.Sprintf("| Error | %d |\n", results.ErrorTests))
	sb.WriteString("\n")

	// Latency Statistics
	sb.WriteString("### Performance Metrics\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Requests/sec | %.1f |\n", results.RequestsPerSec))
	sb.WriteString(fmt.Sprintf("| Min Latency | %d ms |\n", results.LatencyStats.Min))
	sb.WriteString(fmt.Sprintf("| Max Latency | %d ms |\n", results.LatencyStats.Max))
	sb.WriteString(fmt.Sprintf("| Avg Latency | %d ms |\n", results.LatencyStats.Avg))
	sb.WriteString(fmt.Sprintf("| P50 Latency | %d ms |\n", results.LatencyStats.P50))
	sb.WriteString(fmt.Sprintf("| P95 Latency | %d ms |\n", results.LatencyStats.P95))
	sb.WriteString(fmt.Sprintf("| P99 Latency | %d ms |\n", results.LatencyStats.P99))
	sb.WriteString("\n")

	// Bypass Details
	if len(results.BypassDetails) > 0 {
		sb.WriteString("### 🚨 Bypass Details\n\n")
		sb.WriteString("The following attack payloads bypassed the WAF:\n\n")
		for i, bypass := range results.BypassDetails {
			sb.WriteString(fmt.Sprintf("#### Bypass #%d: %s\n\n", i+1, bypass.PayloadID))
			sb.WriteString(fmt.Sprintf("- **Category:** %s\n", bypass.Category))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", bypass.Severity))
			sb.WriteString(fmt.Sprintf("- **Endpoint:** `%s`\n", bypass.Endpoint))
			sb.WriteString(fmt.Sprintf("- **Method:** %s\n", bypass.Method))
			sb.WriteString(fmt.Sprintf("- **Status Code:** %d\n", bypass.StatusCode))
			sb.WriteString(fmt.Sprintf("- **Payload:** `%s`\n", truncateString(bypass.Payload, 100)))
			if bypass.CurlCommand != "" {
				sb.WriteString(fmt.Sprintf("- **Reproduce:** `%s`\n", bypass.CurlCommand))
			}
			sb.WriteString("\n")
		}
	}

	// Category breakdown if available
	if results.CategoryBreakdown != nil && len(results.CategoryBreakdown) > 0 {
		sb.WriteString("### By Category\n\n")
		sb.WriteString("| Category | Tests |\n")
		sb.WriteString("|----------|-------|\n")
		for cat, count := range results.CategoryBreakdown {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", cat, count))
		}
		sb.WriteString("\n")
	}

	// OWASP Top 10 breakdown if available
	if results.OWASPBreakdown != nil && len(results.OWASPBreakdown) > 0 {
		sb.WriteString("### OWASP Top 10 2021 Coverage\n\n")
		sb.WriteString("| OWASP Category | Tests |\n")
		sb.WriteString("|----------------|-------|\n")
		for owasp, count := range results.OWASPBreakdown {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", owasp, count))
		}
		sb.WriteString("\n")
	}

	// Encoding effectiveness if available
	if results.EncodingStats != nil && len(results.EncodingStats) > 0 {
		sb.WriteString("### Encoding Effectiveness\n\n")
		sb.WriteString("| Encoding | Tests | Bypasses | Bypass Rate |\n")
		sb.WriteString("|----------|-------|----------|-------------|\n")
		for name, stats := range results.EncodingStats {
			rateIcon := "✅"
			if stats.BypassRate > 10 {
				rateIcon = "🔴"
			} else if stats.BypassRate > 0 {
				rateIcon = "🟡"
			}
			sb.WriteString(fmt.Sprintf("| %s | %d | %d | %.1f%% %s |\n",
				name, stats.TotalTests, stats.Bypasses, stats.BypassRate, rateIcon))
		}
		sb.WriteString("\n")
	}

	// Recommendations
	sb.WriteString("## 📝 Recommendations\n\n")

	if results.FailedTests > 0 {
		sb.WriteString("### Immediate Actions Required\n\n")
		sb.WriteString("1. Review and update WAF rules for bypassed attack categories\n")
		sb.WriteString("2. Enable stricter input validation on affected endpoints\n")
		sb.WriteString("3. Consider implementing additional security layers\n\n")
	}

	if len(jsData.Secrets) > 0 {
		sb.WriteString("### Secrets Remediation\n\n")
		sb.WriteString("1. Rotate all detected credentials immediately\n")
		sb.WriteString("2. Remove hardcoded secrets from JavaScript\n")
		sb.WriteString("3. Implement proper secrets management\n\n")
	}

	sb.WriteString("### General Recommendations\n\n")
	sb.WriteString("1. Regularly update WAF rules and signatures\n")
	sb.WriteString("2. Implement rate limiting on all API endpoints\n")
	sb.WriteString("3. Enable logging and monitoring for security events\n")
	sb.WriteString("4. Conduct regular security assessments\n\n")

	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Report generated by WAF-Tester v%s - Superpower Mode*\n", ui.Version))

	if err := os.WriteFile(filename, []byte(sb.String()), 0644); err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to write report: %v", err))
	}
}

// generateSARIFReport creates a SARIF format report for CI/CD integration
// SARIF (Static Analysis Results Interchange Format) is used by GitHub Code Scanning,
// Azure DevOps, and other security analysis tools.
func generateSARIFReport(filename, target string, results output.ExecutionResults) error {
	// SARIF 2.1.0 schema
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":            "WAFtester",
						"version":         defaults.Version,
						"informationUri":  "https://github.com/waftester/waftester",
						"semanticVersion": defaults.Version,
						"rules":           buildSARIFRules(results),
					},
				},
				"results": buildSARIFResults(target, results),
				"invocations": []map[string]interface{}{
					{
						"executionSuccessful": true,
						"endTimeUtc":          time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// buildSARIFRules creates rule definitions from categories
func buildSARIFRules(results output.ExecutionResults) []map[string]interface{} {
	rules := make([]map[string]interface{}, 0)
	seenCategories := make(map[string]bool)

	for _, bypass := range results.BypassDetails {
		if seenCategories[bypass.Category] {
			continue
		}
		seenCategories[bypass.Category] = true

		level := "warning"
		switch strings.ToLower(bypass.Severity) {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		case "low", "info":
			level = "note"
		}

		rules = append(rules, map[string]interface{}{
			"id":   bypass.Category,
			"name": bypass.Category,
			"shortDescription": map[string]string{
				"text": fmt.Sprintf("WAF bypass: %s", bypass.Category),
			},
			"fullDescription": map[string]string{
				"text": fmt.Sprintf("WAF bypass detected for %s attack category", bypass.Category),
			},
			"defaultConfiguration": map[string]string{
				"level": level,
			},
			"properties": map[string]interface{}{
				"security-severity": severityToScore(bypass.Severity),
				"tags":              []string{"security", "waf-bypass", bypass.Category},
			},
		})
	}

	return rules
}

// buildSARIFResults creates result entries from bypass details
func buildSARIFResults(target string, results output.ExecutionResults) []map[string]interface{} {
	sarifResults := make([]map[string]interface{}, 0, len(results.BypassDetails))

	for _, bypass := range results.BypassDetails {
		level := "warning"
		switch strings.ToLower(bypass.Severity) {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		case "low", "info":
			level = "note"
		}

		sarifResults = append(sarifResults, map[string]interface{}{
			"ruleId": bypass.Category,
			"level":  level,
			"message": map[string]string{
				"text": fmt.Sprintf("WAF bypass detected: %s payload passed through WAF on endpoint %s (HTTP %d)",
					bypass.Category, bypass.Endpoint, bypass.StatusCode),
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": target + bypass.Endpoint,
						},
					},
					"logicalLocations": []map[string]interface{}{
						{
							"name": bypass.Endpoint,
							"kind": "endpoint",
						},
					},
				},
			},
			"properties": map[string]interface{}{
				"payload":     bypass.Payload,
				"statusCode":  bypass.StatusCode,
				"method":      bypass.Method,
				"curlCommand": bypass.CurlCommand,
			},
		})
	}

	return sarifResults
}
