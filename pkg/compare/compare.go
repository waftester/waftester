// Package compare provides scan result comparison logic for WAFtester.
// It loads scan result JSON files and computes structured diffs between them.
// Supports both regular scan output (waf-tester scan --json) and autoscan
// summary output (waf-tester auto --json).
package compare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ErrNotScanResult is returned when a JSON file doesn't contain scan result data.
var ErrNotScanResult = errors.New("file does not contain scan result data")

// SeverityWeights maps severity names to numeric weights for risk scoring.
// Used to detect severity shifts even when total vulnerability count is unchanged.
var SeverityWeights = map[string]int{
	"critical": 10,
	"high":     5,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// ScanSummary is the minimal data extracted from a scan result JSON for comparison.
type ScanSummary struct {
	Target     string         `json:"target"`
	StartTime  time.Time      `json:"start_time"`
	Duration   time.Duration  `json:"duration"`
	TotalVulns int            `json:"total_vulnerabilities"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
	WAFVendor  string         `json:"waf_vendor,omitempty"`
	WAFVendors []string       `json:"waf_vendors,omitempty"`
	TechStack  []string       `json:"tech_stack,omitempty"`
	FilePath   string         `json:"-"` // source file path, not serialized
}

// Result holds the full comparison output.
type Result struct {
	Before          *ScanSummary   `json:"before"`
	After           *ScanSummary   `json:"after"`
	VulnDelta       int            `json:"vuln_delta"`
	SeverityDeltas  map[string]int `json:"severity_deltas"`
	CategoryDeltas  map[string]int `json:"category_deltas"`
	NewCategories   []string       `json:"new_categories"`
	FixedCategories []string       `json:"fixed_categories"`
	WAFChanged      bool           `json:"waf_changed"`
	Improved        bool           `json:"improved"`
	Verdict         string         `json:"verdict"`
	WeightedBefore  int            `json:"weighted_before"`
	WeightedAfter   int            `json:"weighted_after"`
	WeightedDelta   int            `json:"weighted_delta"`
}

// rawSummary is an intermediate struct for unmarshaling scan result JSON.
// It handles both regular scan output and autoscan summary.json formats.
type rawSummary struct {
	// === Regular scan output fields (waf-tester scan --json) ===
	Target     string          `json:"target"`
	StartTime  time.Time       `json:"start_time"`
	Duration   json.RawMessage `json:"duration"` // int64 nanoseconds or string
	TotalVulns int             `json:"total_vulnerabilities"`
	BySeverity map[string]int  `json:"by_severity"`
	ByCategory map[string]int  `json:"by_category"`
	TechStack  []string        `json:"tech_stack"`
	WAFDetect  *struct {
		Vendor string `json:"vendor"` // legacy: direct vendor field
		WAFs   []struct {
			Vendor string `json:"vendor"`
			Name   string `json:"name"`
		} `json:"wafs"` // real format: array of detected WAFs
	} `json:"waf_detect"`

	// === Autoscan summary.json fallback fields ===
	Timestamp         string         `json:"timestamp"`          // RFC3339 (fallback for start_time)
	DurationSeconds   *float64       `json:"duration_seconds"`   // seconds float (fallback for duration)
	SeverityBreakdown map[string]int `json:"severity_breakdown"` // fallback for by_severity
	CategoryBreakdown map[string]int `json:"category_breakdown"` // fallback for by_category
	BypassCount       int            `json:"bypass_count"`       // fallback for total_vulnerabilities
	Stats             *struct {
		TotalTests int `json:"total_tests"`
		Blocked    int `json:"blocked"`
		Failed     int `json:"failed"`
	} `json:"stats"`
	Discovery *struct {
		WAFVendor   string `json:"waf_vendor"`
		WAFDetected bool   `json:"waf_detected"`
	} `json:"discovery"`
	SmartMode *struct {
		Vendor string `json:"vendor"`
	} `json:"smart_mode"`
	Intelligence *struct {
		TechStack []string `json:"tech_stack"`
	} `json:"intelligence"`
}

// LoadSummary reads a JSON file and extracts a ScanSummary.
// It auto-detects the format: regular scan output or autoscan summary.
func LoadSummary(path string) (*ScanSummary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return parseSummary(data, path)
}

// parseSummary parses JSON bytes into a ScanSummary.
// The path is used for error messages and stored in FilePath.
func parseSummary(data []byte, path string) (*ScanSummary, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("file is empty: %s", path)
	}

	// Detect JSON arrays early with a helpful error message.
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, fmt.Errorf("file contains a JSON array, not a scan result object: %s", path)
	}

	var raw rawSummary
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	s := &ScanSummary{
		Target:     raw.Target,
		StartTime:  raw.StartTime,
		TotalVulns: raw.TotalVulns,
		BySeverity: raw.BySeverity,
		ByCategory: raw.ByCategory,
		TechStack:  raw.TechStack,
		FilePath:   path,
	}

	// Duration: parse from raw JSON (nanoseconds int or string), or fall back to duration_seconds.
	s.Duration = parseDuration(raw.Duration, raw.DurationSeconds)

	// Start time: fall back to autoscan "timestamp" field.
	if s.StartTime.IsZero() && raw.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, raw.Timestamp); err == nil {
			s.StartTime = t
		}
	}

	// Severity/category: fall back to autoscan field names.
	if s.BySeverity == nil && raw.SeverityBreakdown != nil {
		s.BySeverity = raw.SeverityBreakdown
	}
	if s.ByCategory == nil && raw.CategoryBreakdown != nil {
		s.ByCategory = raw.CategoryBreakdown
	}

	// Total vulns: try bypass_count, stats.failed, then sum by_severity.
	if s.TotalVulns == 0 && raw.BypassCount > 0 {
		s.TotalVulns = raw.BypassCount
	}
	if s.TotalVulns == 0 && raw.Stats != nil && raw.Stats.Failed > 0 {
		s.TotalVulns = raw.Stats.Failed
	}
	if s.TotalVulns == 0 && len(s.BySeverity) > 0 {
		for _, count := range s.BySeverity {
			s.TotalVulns += count
		}
	}

	// WAF vendors: extract from all possible sources (scan, autoscan, smart mode).
	s.WAFVendors = extractWAFVendors(raw)
	if len(s.WAFVendors) > 0 {
		s.WAFVendor = s.WAFVendors[0]
	}

	// Tech stack: fall back to intelligence.tech_stack.
	if len(s.TechStack) == 0 && raw.Intelligence != nil {
		s.TechStack = raw.Intelligence.TechStack
	}

	// Validate: at least one field must be populated to confirm this is scan data.
	if s.Target == "" && s.TotalVulns == 0 && len(s.BySeverity) == 0 && len(s.ByCategory) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotScanResult, path)
	}

	return s, nil
}

// parseDuration extracts a duration from a JSON raw message or duration_seconds float.
// Handles: int64 nanoseconds (Go default), string like "5m30s", and float64 seconds fallback.
func parseDuration(raw json.RawMessage, durationSeconds *float64) time.Duration {
	if len(raw) > 0 && string(raw) != "null" && string(raw) != "0" {
		// Try int64 nanoseconds first (standard Go time.Duration JSON).
		var ns int64
		if err := json.Unmarshal(raw, &ns); err == nil && ns != 0 {
			return time.Duration(ns)
		}
		// Try string format like "5m30s".
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && s != "" {
			if d, err := time.ParseDuration(s); err == nil {
				return d
			}
		}
	}
	// Fall back to duration_seconds (autoscan format).
	if durationSeconds != nil && *durationSeconds > 0 {
		return time.Duration(*durationSeconds * float64(time.Second))
	}
	return 0
}

// extractWAFVendors collects WAF vendor names from all possible JSON sources,
// deduplicates them, and returns a sorted slice.
func extractWAFVendors(raw rawSummary) []string {
	seen := make(map[string]bool)
	var vendors []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			vendors = append(vendors, v)
		}
	}

	// Source 1: waf_detect.wafs[] (regular scan output).
	if raw.WAFDetect != nil {
		for _, w := range raw.WAFDetect.WAFs {
			add(w.Vendor)
		}
		// Legacy fallback: direct vendor field.
		if len(vendors) == 0 {
			add(raw.WAFDetect.Vendor)
		}
	}

	// Source 2: discovery.waf_vendor (autoscan JSON mode).
	if raw.Discovery != nil {
		add(raw.Discovery.WAFVendor)
	}

	// Source 3: smart_mode.vendor (autoscan smart detection).
	if raw.SmartMode != nil {
		add(raw.SmartMode.Vendor)
	}

	sort.Strings(vendors)
	return vendors
}

// Compare compares two scan summaries and returns a structured result.
// Nil summaries are treated as empty (zero vulnerabilities).
func Compare(before, after *ScanSummary) *Result {
	if before == nil {
		before = &ScanSummary{}
	}
	if after == nil {
		after = &ScanSummary{}
	}
	r := &Result{
		Before:         before,
		After:          after,
		VulnDelta:      after.TotalVulns - before.TotalVulns,
		SeverityDeltas: computeDeltas(before.BySeverity, after.BySeverity),
		CategoryDeltas: computeDeltas(before.ByCategory, after.ByCategory),
	}

	// WAF comparison: use full vendor sets for accurate change detection.
	r.WAFChanged = !stringSlicesEqual(before.WAFVendors, after.WAFVendors)
	// Fallback for summaries without WAFVendors populated (e.g., manually constructed).
	if len(before.WAFVendors) == 0 && len(after.WAFVendors) == 0 {
		r.WAFChanged = before.WAFVendor != after.WAFVendor
	}

	r.NewCategories = findNew(before.ByCategory, after.ByCategory)
	r.FixedCategories = findNew(after.ByCategory, before.ByCategory)

	// Compute severity-weighted risk scores.
	r.WeightedBefore = computeWeightedScore(before.BySeverity)
	r.WeightedAfter = computeWeightedScore(after.BySeverity)
	r.WeightedDelta = r.WeightedAfter - r.WeightedBefore

	// Verdict: total count first, severity weight as tiebreaker.
	switch {
	case r.VulnDelta < 0:
		r.Verdict = "improved"
		r.Improved = true
	case r.VulnDelta > 0:
		r.Verdict = "regressed"
	case r.WeightedDelta < 0:
		// Same total vulns, but severity shifted down (e.g., critical→low).
		r.Verdict = "improved"
		r.Improved = true
	case r.WeightedDelta > 0:
		// Same total vulns, but severity shifted up (e.g., low→critical).
		r.Verdict = "regressed"
	default:
		r.Verdict = "unchanged"
	}

	return r
}

// computeWeightedScore calculates a severity-weighted risk score.
func computeWeightedScore(severity map[string]int) int {
	score := 0
	for sev, count := range severity {
		weight, ok := SeverityWeights[strings.ToLower(sev)]
		if !ok {
			weight = 1 // default weight for unknown severities
		}
		score += count * weight
	}
	return score
}

// stringSlicesEqual compares two sorted string slices.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// computeDeltas returns (after[key] - before[key]) for all keys in both maps.
func computeDeltas(before, after map[string]int) map[string]int {
	deltas := make(map[string]int)
	for k, v := range before {
		deltas[k] = -v
	}
	for k, v := range after {
		deltas[k] += v
	}
	return deltas
}

// findNew returns sorted keys present in after (with count > 0) but absent or zero in before.
// A category with count 0 in before is treated as not present.
func findNew(before, after map[string]int) []string {
	var result []string
	for k, v := range after {
		if v > 0 {
			if bv, exists := before[k]; !exists || bv == 0 {
				result = append(result, k)
			}
		}
	}
	sort.Strings(result)
	return result
}
