// Package compare provides scan result comparison logic for WAFtester.
// It loads scan result JSON files and computes structured diffs between them.
package compare

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// ErrNotScanResult is returned when a JSON file doesn't contain scan result data.
var ErrNotScanResult = errors.New("file does not contain scan result data")

// ScanSummary is the minimal data extracted from a scan result JSON for comparison.
type ScanSummary struct {
	Target     string         `json:"target"`
	StartTime  time.Time      `json:"start_time"`
	Duration   time.Duration  `json:"duration"`
	TotalVulns int            `json:"total_vulnerabilities"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
	WAFVendor  string         `json:"waf_vendor,omitempty"`
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
}

// rawSummary is an intermediate struct for unmarshaling scan result JSON.
// It handles the nested waf_detect field which contains a wafs array.
type rawSummary struct {
	Target     string         `json:"target"`
	StartTime  time.Time      `json:"start_time"`
	Duration   time.Duration  `json:"duration"`
	TotalVulns int            `json:"total_vulnerabilities"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
	TechStack  []string       `json:"tech_stack"`
	WAFDetect  *struct {
		Vendor string `json:"vendor"` // legacy: direct vendor field
		WAFs   []struct {
			Vendor string `json:"vendor"`
			Name   string `json:"name"`
		} `json:"wafs"` // real format: array of detected WAFs
	} `json:"waf_detect"`
}

// LoadSummary reads a JSON file and extracts a ScanSummary.
func LoadSummary(path string) (*ScanSummary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw rawSummary
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	s := &ScanSummary{
		Target:     raw.Target,
		StartTime:  raw.StartTime,
		Duration:   raw.Duration,
		TotalVulns: raw.TotalVulns,
		BySeverity: raw.BySeverity,
		ByCategory: raw.ByCategory,
		TechStack:  raw.TechStack,
		FilePath:   path,
	}

	if raw.WAFDetect != nil {
		// Prefer wafs[0].vendor (real scan output format), fall back to direct vendor field.
		if len(raw.WAFDetect.WAFs) > 0 && raw.WAFDetect.WAFs[0].Vendor != "" {
			s.WAFVendor = raw.WAFDetect.WAFs[0].Vendor
		} else if raw.WAFDetect.Vendor != "" {
			s.WAFVendor = raw.WAFDetect.Vendor
		}
	}

	// If total_vulnerabilities is 0 but by_severity has entries, sum them.
	if s.TotalVulns == 0 && len(s.BySeverity) > 0 {
		for _, count := range s.BySeverity {
			s.TotalVulns += count
		}
	}

	// Validate: at least one field must be populated to confirm this is scan data.
	if s.Target == "" && s.TotalVulns == 0 && len(s.BySeverity) == 0 && len(s.ByCategory) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotScanResult, path)
	}

	return s, nil
}

// Compare compares two scan summaries and returns a structured result.
// Both before and after must be non-nil.
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
		WAFChanged:     before.WAFVendor != after.WAFVendor,
	}

	r.NewCategories = findNew(before.ByCategory, after.ByCategory)
	r.FixedCategories = findNew(after.ByCategory, before.ByCategory)

	switch {
	case r.VulnDelta < 0:
		r.Verdict = "improved"
		r.Improved = true
	case r.VulnDelta > 0:
		r.Verdict = "regressed"
	default:
		r.Verdict = "unchanged"
	}

	return r
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

// findNew returns sorted keys present in after (with count > 0) but not in before.
func findNew(before, after map[string]int) []string {
	var result []string
	for k, v := range after {
		if v > 0 {
			if _, exists := before[k]; !exists {
				result = append(result, k)
			}
		}
	}
	sort.Strings(result)
	return result
}
