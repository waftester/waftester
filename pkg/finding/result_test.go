package finding

import (
	"encoding/json"
	"testing"
	"time"
)

func TestScanResult_JSONRoundtrip(t *testing.T) {
	t.Parallel()

	start := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	original := ScanResult{
		Target:       "https://example.com",
		TestedParams: 42,
		StartTime:    start,
		Duration:     5 * time.Second,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Target != original.Target {
		t.Errorf("Target = %q, want %q", decoded.Target, original.Target)
	}
	if decoded.TestedParams != original.TestedParams {
		t.Errorf("TestedParams = %d, want %d", decoded.TestedParams, original.TestedParams)
	}
	if !decoded.StartTime.Equal(original.StartTime) {
		t.Errorf("StartTime = %v, want %v", decoded.StartTime, original.StartTime)
	}
	if decoded.Duration != original.Duration {
		t.Errorf("Duration = %v, want %v", decoded.Duration, original.Duration)
	}
}

func TestScanResult_ZeroValue(t *testing.T) {
	t.Parallel()

	var r ScanResult
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal zero value: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// target always present
	if _, ok := m["target"]; !ok {
		t.Error("target must be present even when empty")
	}
}

func TestScanResult_EmbeddingPattern(t *testing.T) {
	t.Parallel()

	// Demonstrates embedding for attack-specific results
	type SQLiResult struct {
		ScanResult
		Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	}

	r := SQLiResult{
		ScanResult: ScanResult{
			Target:       "https://example.com",
			TestedParams: 10,
			Duration:     2 * time.Second,
		},
		Vulnerabilities: []Vulnerability{
			{URL: "https://example.com/search", Severity: High},
		},
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Base fields
	if m["target"] != "https://example.com" {
		t.Errorf("target = %v", m["target"])
	}

	// Extension fields
	vulns, ok := m["vulnerabilities"].([]any)
	if !ok || len(vulns) != 1 {
		t.Errorf("vulnerabilities = %v", m["vulnerabilities"])
	}
}
