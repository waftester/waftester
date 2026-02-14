package apispec

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ComparisonStatus classifies a finding relative to a baseline.
type ComparisonStatus string

const (
	StatusFixed     ComparisonStatus = "fixed"
	StatusRegressed ComparisonStatus = "regressed"
	StatusNew       ComparisonStatus = "new"
	StatusUnchanged ComparisonStatus = "unchanged"
)

// ComparedFinding wraps a finding with its comparison status.
type ComparedFinding struct {
	Finding SpecFinding      `json:"finding"`
	Status  ComparisonStatus `json:"status"`
}

// ComparisonResult holds the diff between a baseline and current scan.
type ComparisonResult struct {
	Fixed         []SpecFinding `json:"fixed"`
	Regressed     []SpecFinding `json:"regressed"`
	New           []SpecFinding `json:"new"`
	Unchanged     []SpecFinding `json:"unchanged"`
	BaselineCount int           `json:"baseline_count"`
	CurrentCount  int           `json:"current_count"`
}

// Baseline stores findings for later comparison.
type Baseline struct {
	Findings   []SpecFinding `json:"findings"`
	SpecSource string        `json:"spec_source"`
	CreatedAt  string        `json:"created_at"`
}

// SaveBaseline writes current findings to a JSON file.
func SaveBaseline(path string, findings []SpecFinding, specSource string) error {
	bl := Baseline{
		Findings:   findings,
		SpecSource: specSource,
		CreatedAt:  timeNowStr(),
	}

	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}

	return nil
}

// LoadBaseline reads a baseline from a JSON file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}

	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}

	return &bl, nil
}

// CompareFindings diffs current findings against a baseline.
// Matching is by endpoint (method+path) + category + parameter, not by timestamp.
func CompareFindings(baseline, current []SpecFinding) ComparisonResult {
	baselineKeys := make(map[string]SpecFinding, len(baseline))
	for _, f := range baseline {
		key := findingKey(f)
		baselineKeys[key] = f
	}

	currentKeys := make(map[string]SpecFinding, len(current))
	for _, f := range current {
		key := findingKey(f)
		currentKeys[key] = f
	}

	result := ComparisonResult{
		BaselineCount: len(baseline),
		CurrentCount:  len(current),
	}

	// Fixed: in baseline but not in current.
	for key, f := range baselineKeys {
		if _, exists := currentKeys[key]; !exists {
			result.Fixed = append(result.Fixed, f)
		}
	}

	// New / Regressed / Unchanged.
	for key, f := range currentKeys {
		if _, exists := baselineKeys[key]; !exists {
			result.New = append(result.New, f)
		} else {
			// Present in both — check if severity changed (regressed = worse).
			baseF := baselineKeys[key]
			if severityRank(f.Severity) > severityRank(baseF.Severity) {
				result.Regressed = append(result.Regressed, f)
			} else {
				result.Unchanged = append(result.Unchanged, f)
			}
		}
	}

	return result
}

// findingKey generates a stable key for matching findings across scans.
// Independent of timestamp — uses method+path+category+parameter.
func findingKey(f SpecFinding) string {
	return f.Method + "|" + f.Path + "|" + f.Category + "|" + f.Parameter
}

// severityRank maps severity strings to numeric rank (higher = worse).
func severityRank(severity string) int {
	switch severity {
	case "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	default:
		return 0
	}
}

// timeNowStr returns the current time as an RFC3339 string.
func timeNowStr() string {
	return time.Now().Format("2006-01-02T15:04:05Z07:00")
}
