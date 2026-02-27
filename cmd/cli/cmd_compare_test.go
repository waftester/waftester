package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/waftester/waftester/pkg/compare"
)

// writeCompareTestFile creates a scan result JSON file for compare tests.
func writeCompareTestFile(t *testing.T, dir, name string, data map[string]interface{}) string {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCompare_LoadAndCompare_Integration(t *testing.T) {
	dir := t.TempDir()

	beforePath := writeCompareTestFile(t, dir, "before.json", map[string]interface{}{
		"target":                "https://example.com",
		"total_vulnerabilities": 20,
		"by_severity":           map[string]int{"critical": 5, "high": 10, "medium": 5},
		"by_category":           map[string]int{"sqli": 10, "xss": 8, "cmdi": 2},
		"waf_detect":            map[string]string{"vendor": "Cloudflare"},
	})

	afterPath := writeCompareTestFile(t, dir, "after.json", map[string]interface{}{
		"target":                "https://example.com",
		"total_vulnerabilities": 8,
		"by_severity":           map[string]int{"critical": 0, "high": 3, "medium": 5},
		"by_category":           map[string]int{"sqli": 3, "xss": 5},
		"waf_detect":            map[string]string{"vendor": "Cloudflare"},
	})

	before, err := compare.LoadSummary(beforePath)
	if err != nil {
		t.Fatal(err)
	}
	after, err := compare.LoadSummary(afterPath)
	if err != nil {
		t.Fatal(err)
	}

	result := compare.Compare(before, after)
	if result.Verdict != "improved" {
		t.Errorf("Verdict = %q, want %q", result.Verdict, "improved")
	}
	if result.VulnDelta != -12 {
		t.Errorf("VulnDelta = %d, want -12", result.VulnDelta)
	}
	if len(result.FixedCategories) != 1 || result.FixedCategories[0] != "cmdi" {
		t.Errorf("FixedCategories = %v, want [cmdi]", result.FixedCategories)
	}
	if result.WAFChanged {
		t.Error("WAFChanged should be false for same vendor")
	}
}

func TestCompare_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	beforePath := writeCompareTestFile(t, dir, "before.json", map[string]interface{}{
		"target":                "https://example.com",
		"total_vulnerabilities": 5,
		"by_severity":           map[string]int{"medium": 5},
		"by_category":           map[string]int{"xss": 5},
	})

	afterPath := writeCompareTestFile(t, dir, "after.json", map[string]interface{}{
		"target":                "https://example.com",
		"total_vulnerabilities": 5,
		"by_severity":           map[string]int{"medium": 5},
		"by_category":           map[string]int{"xss": 5},
	})

	before, err := compare.LoadSummary(beforePath)
	if err != nil {
		t.Fatal(err)
	}
	after, err := compare.LoadSummary(afterPath)
	if err != nil {
		t.Fatal(err)
	}

	result := compare.Compare(before, after)

	// Verify JSON serialization round-trips correctly
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}

	var decoded compare.Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Verdict != "unchanged" {
		t.Errorf("decoded Verdict = %q, want %q", decoded.Verdict, "unchanged")
	}
	if decoded.VulnDelta != 0 {
		t.Errorf("decoded VulnDelta = %d, want 0", decoded.VulnDelta)
	}
}

func TestCompare_MissingFile(t *testing.T) {
	_, err := compare.LoadSummary("/nonexistent/before.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCompare_InvalidJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := compare.LoadSummary(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCompare_FormatDelta(t *testing.T) {
	tests := []struct {
		delta int
		want  string
	}{
		{5, "+5 \u25b2"},
		{-3, "-3 \u25bc"},
		{0, "0 ="},
	}
	for _, tt := range tests {
		got := formatDelta(tt.delta)
		if got != tt.want {
			t.Errorf("formatDelta(%d) = %q, want %q", tt.delta, got, tt.want)
		}
	}
}

func TestCompare_CollectSeverityKeys_Order(t *testing.T) {
	r := &compare.Result{
		Before: &compare.ScanSummary{
			BySeverity: map[string]int{"low": 1, "critical": 2},
		},
		After: &compare.ScanSummary{
			BySeverity: map[string]int{"medium": 3, "high": 4, "info": 1},
		},
	}
	keys := collectSeverityKeys(r)
	expected := []string{"critical", "high", "medium", "low", "info"}
	if len(keys) != len(expected) {
		t.Fatalf("got %v, want %v", keys, expected)
	}
	for i, k := range keys {
		if k != expected[i] {
			t.Errorf("keys[%d] = %q, want %q", i, k, expected[i])
		}
	}
}
