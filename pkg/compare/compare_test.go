package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testParse marshals v to JSON and parses it via parseSummary, skipping filesystem I/O.
func testParse(t *testing.T, v interface{}) *ScanSummary {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseSummary(data, "test.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// testParseErr marshals v and returns the parseSummary error.
func testParseErr(t *testing.T, v interface{}) error {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseSummary(data, "test.json")
	return err
}

// --- LoadSummary / parseSummary tests ---

func TestLoadSummary_FullScanResult(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":                "https://example.com",
		"total_vulnerabilities": 12,
		"by_severity":           map[string]int{"critical": 2, "high": 5, "medium": 3, "low": 2},
		"by_category":           map[string]int{"sqli": 4, "xss": 5, "cmdi": 3},
		"tech_stack":            []string{"nginx", "php"},
		"waf_detect":            map[string]string{"vendor": "Cloudflare"},
	})
	if s.Target != "https://example.com" {
		t.Errorf("Target = %q, want %q", s.Target, "https://example.com")
	}
	if s.TotalVulns != 12 {
		t.Errorf("TotalVulns = %d, want 12", s.TotalVulns)
	}
	if s.WAFVendor != "Cloudflare" {
		t.Errorf("WAFVendor = %q, want %q", s.WAFVendor, "Cloudflare")
	}
	if len(s.BySeverity) != 4 {
		t.Errorf("BySeverity has %d entries, want 4", len(s.BySeverity))
	}
	if len(s.TechStack) != 2 {
		t.Errorf("TechStack has %d entries, want 2", len(s.TechStack))
	}
}

func TestLoadSummary_MinimalJSON(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target": "https://minimal.example.com",
	})
	if s.Target != "https://minimal.example.com" {
		t.Errorf("Target = %q, want %q", s.Target, "https://minimal.example.com")
	}
	if s.TotalVulns != 0 {
		t.Errorf("TotalVulns = %d, want 0", s.TotalVulns)
	}
}

func TestLoadSummary_FileNotFound(t *testing.T) {
	t.Parallel()
	_, err := LoadSummary("/nonexistent/path/file.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadSummary_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := parseSummary([]byte("{invalid json!!!"), "bad.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadSummary_EmptyObject(t *testing.T) {
	t.Parallel()
	err := testParseErr(t, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected ErrNotScanResult for empty object")
	}
}

func TestLoadSummary_WAFDetectNested(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":     "https://waf.example.com",
		"waf_detect": map[string]string{"vendor": "AWS WAF"},
	})
	if s.WAFVendor != "AWS WAF" {
		t.Errorf("WAFVendor = %q, want %q", s.WAFVendor, "AWS WAF")
	}
}

func TestLoadSummary_ZeroTotalButSeverityPopulated(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":                "https://example.com",
		"total_vulnerabilities": 0,
		"by_severity":           map[string]int{"high": 3, "medium": 7},
	})
	if s.TotalVulns != 10 {
		t.Errorf("TotalVulns = %d, want 10 (summed from by_severity)", s.TotalVulns)
	}
}

func TestLoadSummary_NoWAFDetect(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":                "https://nowaf.example.com",
		"total_vulnerabilities": 5,
	})
	if s.WAFVendor != "" {
		t.Errorf("WAFVendor = %q, want empty", s.WAFVendor)
	}
}

// --- Compare tests ---

func TestCompare_Identical(t *testing.T) {
	t.Parallel()
	a := &ScanSummary{
		Target:     "https://example.com",
		TotalVulns: 10,
		BySeverity: map[string]int{"high": 5, "medium": 5},
		ByCategory: map[string]int{"sqli": 5, "xss": 5},
		WAFVendor:  "Cloudflare",
	}
	b := &ScanSummary{
		Target:     "https://example.com",
		TotalVulns: 10,
		BySeverity: map[string]int{"high": 5, "medium": 5},
		ByCategory: map[string]int{"sqli": 5, "xss": 5},
		WAFVendor:  "Cloudflare",
	}
	r := Compare(a, b)
	if r.Verdict != "unchanged" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "unchanged")
	}
	if r.VulnDelta != 0 {
		t.Errorf("VulnDelta = %d, want 0", r.VulnDelta)
	}
	if r.Improved {
		t.Error("Improved should be false for unchanged")
	}
	if r.WAFChanged {
		t.Error("WAFChanged should be false for identical WAF vendor")
	}
	if len(r.NewCategories) != 0 {
		t.Errorf("NewCategories = %v, want empty", r.NewCategories)
	}
	if len(r.FixedCategories) != 0 {
		t.Errorf("FixedCategories = %v, want empty", r.FixedCategories)
	}
}

func TestCompare_Improved(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 20, BySeverity: map[string]int{"critical": 5, "high": 10, "medium": 5}, ByCategory: map[string]int{"sqli": 10, "xss": 10}},
		&ScanSummary{TotalVulns: 8, BySeverity: map[string]int{"critical": 0, "high": 3, "medium": 5}, ByCategory: map[string]int{"sqli": 3, "xss": 5}},
	)
	if r.Verdict != "improved" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "improved")
	}
	if r.VulnDelta != -12 {
		t.Errorf("VulnDelta = %d, want -12", r.VulnDelta)
	}
	if !r.Improved {
		t.Error("Improved should be true")
	}
}

func TestCompare_Regressed(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, BySeverity: map[string]int{"medium": 5}, ByCategory: map[string]int{"xss": 5}},
		&ScanSummary{TotalVulns: 15, BySeverity: map[string]int{"critical": 3, "medium": 12}, ByCategory: map[string]int{"xss": 8, "sqli": 7}},
	)
	if r.Verdict != "regressed" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "regressed")
	}
	if r.VulnDelta != 10 {
		t.Errorf("VulnDelta = %d, want 10", r.VulnDelta)
	}
	if r.Improved {
		t.Error("Improved should be false")
	}
}

func TestCompare_NewCategories(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, ByCategory: map[string]int{"sqli": 5}},
		&ScanSummary{TotalVulns: 10, ByCategory: map[string]int{"sqli": 5, "xss": 3, "cmdi": 2}},
	)
	if len(r.NewCategories) != 2 {
		t.Fatalf("NewCategories = %v, want 2 entries", r.NewCategories)
	}
	if r.NewCategories[0] != "cmdi" || r.NewCategories[1] != "xss" {
		t.Errorf("NewCategories = %v, want [cmdi, xss]", r.NewCategories)
	}
}

func TestCompare_FixedCategories(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 10, ByCategory: map[string]int{"sqli": 5, "cmdi": 3, "xxe": 2}},
		&ScanSummary{TotalVulns: 5, ByCategory: map[string]int{"sqli": 5}},
	)
	if len(r.FixedCategories) != 2 {
		t.Fatalf("FixedCategories = %v, want 2 entries", r.FixedCategories)
	}
	if r.FixedCategories[0] != "cmdi" || r.FixedCategories[1] != "xxe" {
		t.Errorf("FixedCategories = %v, want [cmdi, xxe]", r.FixedCategories)
	}
}

func TestCompare_MixedSeverityDeltas(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 10, BySeverity: map[string]int{"critical": 2, "high": 5, "medium": 3}},
		&ScanSummary{TotalVulns: 10, BySeverity: map[string]int{"critical": 0, "high": 3, "medium": 5, "low": 2}},
	)
	for sev, want := range map[string]int{"critical": -2, "high": -2, "medium": 2, "low": 2} {
		if r.SeverityDeltas[sev] != want {
			t.Errorf("%s delta = %d, want %d", sev, r.SeverityDeltas[sev], want)
		}
	}
}

func TestCompare_WAFChanged(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, WAFVendor: "Cloudflare", ByCategory: map[string]int{"sqli": 5}},
		&ScanSummary{TotalVulns: 3, WAFVendor: "AWS WAF", ByCategory: map[string]int{"sqli": 3}},
	)
	if !r.WAFChanged {
		t.Error("WAFChanged should be true")
	}
}

func TestCompare_WAFAppeared(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 10, WAFVendor: "", ByCategory: map[string]int{"sqli": 10}},
		&ScanSummary{TotalVulns: 3, WAFVendor: "Imperva", ByCategory: map[string]int{"sqli": 3}},
	)
	if !r.WAFChanged {
		t.Error("WAFChanged should be true when WAF vendor appears")
	}
}

func TestCompare_BothNilMaps(t *testing.T) {
	t.Parallel()
	r := Compare(&ScanSummary{TotalVulns: 0}, &ScanSummary{TotalVulns: 0})
	if r.Verdict != "unchanged" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "unchanged")
	}
	if len(r.SeverityDeltas) != 0 {
		t.Errorf("SeverityDeltas = %v, want empty", r.SeverityDeltas)
	}
	if len(r.CategoryDeltas) != 0 {
		t.Errorf("CategoryDeltas = %v, want empty", r.CategoryDeltas)
	}
}

func TestCompare_OneNilOnePopulated(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 0, BySeverity: nil, ByCategory: nil},
		&ScanSummary{TotalVulns: 5, BySeverity: map[string]int{"high": 3, "medium": 2}, ByCategory: map[string]int{"sqli": 3, "xss": 2}},
	)
	if r.VulnDelta != 5 {
		t.Errorf("VulnDelta = %d, want 5", r.VulnDelta)
	}
	if r.SeverityDeltas["high"] != 3 {
		t.Errorf("high delta = %d, want 3", r.SeverityDeltas["high"])
	}
	if len(r.NewCategories) != 2 {
		t.Errorf("NewCategories = %v, want 2 entries", r.NewCategories)
	}
}

func TestCompare_BothZeroVulns(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 0, ByCategory: map[string]int{}},
		&ScanSummary{TotalVulns: 0, ByCategory: map[string]int{}},
	)
	if r.Verdict != "unchanged" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "unchanged")
	}
	if r.VulnDelta != 0 {
		t.Errorf("VulnDelta = %d, want 0", r.VulnDelta)
	}
}

func TestLoadSummary_RealWAFDetectFormat(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":                "https://protected.example.com",
		"total_vulnerabilities": 5,
		"waf_detect": map[string]interface{}{
			"detected":   true,
			"confidence": 0.95,
			"wafs": []map[string]interface{}{
				{"name": "Cloudflare", "vendor": "Cloudflare", "confidence": 0.98},
			},
		},
	})
	if s.WAFVendor != "Cloudflare" {
		t.Errorf("WAFVendor = %q, want %q (from wafs[0].vendor)", s.WAFVendor, "Cloudflare")
	}
}

func TestLoadSummary_RealWAFDetectMultipleWAFs(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":                "https://multi.example.com",
		"total_vulnerabilities": 3,
		"waf_detect": map[string]interface{}{
			"detected": true,
			"wafs": []map[string]interface{}{
				{"name": "AWS WAF", "vendor": "AWS", "confidence": 0.90},
				{"name": "Cloudflare", "vendor": "Cloudflare", "confidence": 0.50},
			},
		},
	})
	if s.WAFVendor != "AWS" {
		t.Errorf("WAFVendor = %q, want %q (first WAF)", s.WAFVendor, "AWS")
	}
}

func TestCompare_NilBeforeSummary(t *testing.T) {
	t.Parallel()
	r := Compare(nil, &ScanSummary{TotalVulns: 5, BySeverity: map[string]int{"high": 5}})
	if r.VulnDelta != 5 {
		t.Errorf("VulnDelta = %d, want 5", r.VulnDelta)
	}
	if r.Verdict != "regressed" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "regressed")
	}
}

func TestCompare_NilAfterSummary(t *testing.T) {
	t.Parallel()
	r := Compare(&ScanSummary{TotalVulns: 10, BySeverity: map[string]int{"high": 10}}, nil)
	if r.VulnDelta != -10 {
		t.Errorf("VulnDelta = %d, want -10", r.VulnDelta)
	}
	if r.Verdict != "improved" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "improved")
	}
}

func TestCompare_BothNilSummaries(t *testing.T) {
	t.Parallel()
	r := Compare(nil, nil)
	if r.Verdict != "unchanged" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "unchanged")
	}
}

func TestCompare_CategoryWithZeroCountNotNew(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, ByCategory: map[string]int{"xss": 5}},
		&ScanSummary{TotalVulns: 5, ByCategory: map[string]int{"xss": 5, "sqli": 0}},
	)
	if len(r.NewCategories) != 0 {
		t.Errorf("NewCategories = %v, want empty (sqli has count 0)", r.NewCategories)
	}
}

func TestCompare_CategoryWithZeroCountNotFixed(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, ByCategory: map[string]int{"xss": 5, "cmdi": 0}},
		&ScanSummary{TotalVulns: 5, ByCategory: map[string]int{"xss": 5}},
	)
	if len(r.FixedCategories) != 0 {
		t.Errorf("FixedCategories = %v, want empty (cmdi had count 0)", r.FixedCategories)
	}
}

func TestCompare_CategoryChurnUnchangedTotal(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 10, ByCategory: map[string]int{"sqli": 10}},
		&ScanSummary{TotalVulns: 10, ByCategory: map[string]int{"xss": 10}},
	)
	if r.Verdict != "unchanged" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "unchanged")
	}
	if len(r.NewCategories) != 1 || r.NewCategories[0] != "xss" {
		t.Errorf("NewCategories = %v, want [xss]", r.NewCategories)
	}
	if len(r.FixedCategories) != 1 || r.FixedCategories[0] != "sqli" {
		t.Errorf("FixedCategories = %v, want [sqli]", r.FixedCategories)
	}
}

func TestCompare_LargeDeltaValues(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 100000, BySeverity: map[string]int{"critical": 50000, "high": 50000}},
		&ScanSummary{TotalVulns: 1, BySeverity: map[string]int{"low": 1}},
	)
	if r.VulnDelta != -99999 {
		t.Errorf("VulnDelta = %d, want -99999", r.VulnDelta)
	}
	if !r.Improved {
		t.Error("Improved should be true for large reduction")
	}
	if r.SeverityDeltas["critical"] != -50000 {
		t.Errorf("critical delta = %d, want -50000", r.SeverityDeltas["critical"])
	}
}

// --- Autoscan format tests ---

func TestLoadSummary_AutoscanFormat(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":             "https://auto.example.com",
		"timestamp":          "2026-02-28T10:00:00Z",
		"duration_seconds":   45.5,
		"bypass_count":       12,
		"severity_breakdown": map[string]int{"critical": 2, "high": 5, "medium": 3, "low": 2},
		"category_breakdown": map[string]int{"sqli": 6, "xss": 4, "cmdi": 2},
		"discovery":          map[string]interface{}{"waf_vendor": "Cloudflare", "waf_detected": true},
		"intelligence":       map[string]interface{}{"tech_stack": []string{"nginx", "react"}},
	})
	if s.Target != "https://auto.example.com" {
		t.Errorf("Target = %q, want %q", s.Target, "https://auto.example.com")
	}
	if s.TotalVulns != 12 {
		t.Errorf("TotalVulns = %d, want 12 (from bypass_count)", s.TotalVulns)
	}
	if len(s.BySeverity) != 4 {
		t.Errorf("BySeverity has %d entries, want 4 (from severity_breakdown)", len(s.BySeverity))
	}
	if len(s.ByCategory) != 3 {
		t.Errorf("ByCategory has %d entries, want 3 (from category_breakdown)", len(s.ByCategory))
	}
	if s.WAFVendor != "Cloudflare" {
		t.Errorf("WAFVendor = %q, want %q (from discovery)", s.WAFVendor, "Cloudflare")
	}
	if len(s.TechStack) != 2 {
		t.Errorf("TechStack has %d entries, want 2 (from intelligence)", len(s.TechStack))
	}
	if s.StartTime.IsZero() {
		t.Error("StartTime should be parsed from timestamp field")
	}
	if s.Duration == 0 {
		t.Error("Duration should be parsed from duration_seconds")
	}
	if s.Duration.Seconds() < 45 || s.Duration.Seconds() > 46 {
		t.Errorf("Duration = %v, want ~45.5s", s.Duration)
	}
}

func TestLoadSummary_AutoscanStatsFallback(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target": "https://stats.example.com",
		"stats":  map[string]interface{}{"total_tests": 100, "blocked": 80, "failed": 20},
	})
	if s.TotalVulns != 20 {
		t.Errorf("TotalVulns = %d, want 20 (from stats.failed)", s.TotalVulns)
	}
}

func TestLoadSummary_SmartModeVendor(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":     "https://smart.example.com",
		"smart_mode": map[string]interface{}{"vendor": "Imperva"},
	})
	if s.WAFVendor != "Imperva" {
		t.Errorf("WAFVendor = %q, want %q (from smart_mode)", s.WAFVendor, "Imperva")
	}
}

// --- Duration parsing tests ---

func TestLoadSummary_DurationNanoseconds(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":   "https://ns.example.com",
		"duration": 5000000000, // 5 seconds
	})
	if s.Duration.Seconds() < 4.9 || s.Duration.Seconds() > 5.1 {
		t.Errorf("Duration = %v, want ~5s (from nanoseconds int64)", s.Duration)
	}
}

func TestLoadSummary_DurationString(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":   "https://str.example.com",
		"duration": "5m30s",
	})
	if got := int(s.Duration.Seconds()); got != 330 {
		t.Errorf("Duration = %v (%ds), want 330s (from string \"5m30s\")", s.Duration, got)
	}
}

// --- Empty file and JSON array tests (require filesystem) ---

func TestLoadSummary_EmptyFile(t *testing.T) {
	t.Parallel()
	_, err := parseSummary([]byte(""), "empty.json")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q, want mention of 'empty'", err.Error())
	}
}

func TestLoadSummary_JSONArray(t *testing.T) {
	t.Parallel()
	_, err := parseSummary([]byte(`[{"target":"x"}]`), "array.json")
	if err == nil {
		t.Fatal("expected error for JSON array")
	}
	if !strings.Contains(err.Error(), "array") {
		t.Errorf("error = %q, want mention of 'array'", err.Error())
	}
}

// --- Severity-weighted verdict tests ---

func TestCompare_SeverityShiftRegression(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 10, BySeverity: map[string]int{"low": 10}},
		&ScanSummary{TotalVulns: 10, BySeverity: map[string]int{"critical": 10}},
	)
	if r.Verdict != "regressed" {
		t.Errorf("Verdict = %q, want %q (severity shifted up)", r.Verdict, "regressed")
	}
	if r.VulnDelta != 0 {
		t.Errorf("VulnDelta = %d, want 0", r.VulnDelta)
	}
	if r.WeightedDelta != 90 {
		t.Errorf("WeightedDelta = %d, want 90", r.WeightedDelta)
	}
}

func TestCompare_SeverityShiftImprovement(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 10, BySeverity: map[string]int{"critical": 10}},
		&ScanSummary{TotalVulns: 10, BySeverity: map[string]int{"low": 10}},
	)
	if r.Verdict != "improved" {
		t.Errorf("Verdict = %q, want %q (severity shifted down)", r.Verdict, "improved")
	}
	if !r.Improved {
		t.Error("Improved should be true for severity downshift")
	}
	if r.WeightedDelta != -90 {
		t.Errorf("WeightedDelta = %d, want -90", r.WeightedDelta)
	}
}

func TestCompare_WeightedScores(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, BySeverity: map[string]int{"critical": 1, "high": 2, "medium": 1, "low": 1}},
		&ScanSummary{TotalVulns: 5, BySeverity: map[string]int{"medium": 3, "low": 2}},
	)
	// Before: 1*10 + 2*5 + 1*2 + 1*1 = 23
	if r.WeightedBefore != 23 {
		t.Errorf("WeightedBefore = %d, want 23", r.WeightedBefore)
	}
	// After: 3*2 + 2*1 = 8
	if r.WeightedAfter != 8 {
		t.Errorf("WeightedAfter = %d, want 8", r.WeightedAfter)
	}
	if r.WeightedDelta != -15 {
		t.Errorf("WeightedDelta = %d, want -15", r.WeightedDelta)
	}
}

// --- Multi-WAF comparison tests ---

func TestCompare_MultiWAFChanged(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, WAFVendor: "Cloudflare", WAFVendors: []string{"Cloudflare"}},
		&ScanSummary{TotalVulns: 5, WAFVendor: "AWS", WAFVendors: []string{"AWS", "Cloudflare"}},
	)
	if !r.WAFChanged {
		t.Error("WAFChanged should be true when vendor set differs")
	}
}

func TestCompare_MultiWAFSameSet(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, WAFVendor: "AWS", WAFVendors: []string{"AWS", "Cloudflare"}},
		&ScanSummary{TotalVulns: 5, WAFVendor: "AWS", WAFVendors: []string{"AWS", "Cloudflare"}},
	)
	if r.WAFChanged {
		t.Error("WAFChanged should be false when vendor sets are identical")
	}
}

func TestLoadSummary_MultipleWAFVendorSources(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target": "https://multi.example.com",
		"waf_detect": map[string]interface{}{
			"wafs": []map[string]interface{}{
				{"vendor": "Cloudflare", "name": "Cloudflare"},
			},
		},
		"discovery": map[string]interface{}{
			"waf_vendor":   "Imperva",
			"waf_detected": true,
		},
	})
	if len(s.WAFVendors) != 2 {
		t.Fatalf("WAFVendors = %v, want 2 vendors", s.WAFVendors)
	}
	if s.WAFVendors[0] != "Cloudflare" || s.WAFVendors[1] != "Imperva" {
		t.Errorf("WAFVendors = %v, want [Cloudflare, Imperva]", s.WAFVendors)
	}
}

func TestLoadSummary_DeduplicatesWAFVendors(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target": "https://dedup.example.com",
		"waf_detect": map[string]interface{}{
			"wafs": []map[string]interface{}{
				{"vendor": "Cloudflare", "name": "Cloudflare"},
			},
		},
		"discovery": map[string]interface{}{
			"waf_vendor":   "Cloudflare",
			"waf_detected": true,
		},
		"smart_mode": map[string]interface{}{
			"vendor": "Cloudflare",
		},
	})
	if len(s.WAFVendors) != 1 {
		t.Errorf("WAFVendors = %v, want [Cloudflare] (deduplicated)", s.WAFVendors)
	}
}

// --- parseDuration unit tests ---

func TestParseDuration_NanosecondsInt(t *testing.T) {
	t.Parallel()
	d := parseDuration(json.RawMessage(`5000000000`), nil) // 5 seconds
	if d.Seconds() < 4.9 || d.Seconds() > 5.1 {
		t.Errorf("parseDuration(5000000000) = %v, want ~5s", d)
	}
}

func TestParseDuration_StringFormat(t *testing.T) {
	t.Parallel()
	d := parseDuration(json.RawMessage(`"2m30s"`), nil)
	if d.Seconds() != 150 {
		t.Errorf("parseDuration(\"2m30s\") = %v, want 2m30s", d)
	}
}

func TestParseDuration_DurationSecondsFallback(t *testing.T) {
	t.Parallel()
	sec := 45.5
	d := parseDuration(nil, &sec)
	if d.Seconds() < 45 || d.Seconds() > 46 {
		t.Errorf("parseDuration(nil, 45.5) = %v, want ~45.5s", d)
	}
}

func TestParseDuration_NullJSON(t *testing.T) {
	t.Parallel()
	d := parseDuration(json.RawMessage(`null`), nil)
	if d != 0 {
		t.Errorf("parseDuration(null) = %v, want 0", d)
	}
}

func TestParseDuration_ZeroJSON(t *testing.T) {
	t.Parallel()
	d := parseDuration(json.RawMessage(`0`), nil)
	if d != 0 {
		t.Errorf("parseDuration(0) = %v, want 0", d)
	}
}

// --- computeWeightedScore tests ---

func TestComputeWeightedScore_AllSeverities(t *testing.T) {
	t.Parallel()
	sev := map[string]int{"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
	// 1*10 + 2*5 + 3*2 + 4*1 + 5*0 = 30
	if got := computeWeightedScore(sev); got != 30 {
		t.Errorf("computeWeightedScore = %d, want 30", got)
	}
}

func TestComputeWeightedScore_UnknownSeverity(t *testing.T) {
	t.Parallel()
	if got := computeWeightedScore(map[string]int{"custom": 5}); got != 5 {
		t.Errorf("computeWeightedScore = %d, want 5 (5 * default weight 1)", got)
	}
}

func TestComputeWeightedScore_NilMap(t *testing.T) {
	t.Parallel()
	if got := computeWeightedScore(nil); got != 0 {
		t.Errorf("computeWeightedScore(nil) = %d, want 0", got)
	}
}

// --- extractWAFVendors tests ---

func TestExtractWAFVendors_EmptyWhitespace(t *testing.T) {
	t.Parallel()
	raw := rawSummary{
		Discovery: &struct {
			WAFVendor   string `json:"waf_vendor"`
			WAFDetected bool   `json:"waf_detected"`
		}{
			WAFVendor: "  ",
		},
	}
	if vendors := extractWAFVendors(raw); len(vendors) != 0 {
		t.Errorf("extractWAFVendors = %v, want empty (whitespace-only vendor)", vendors)
	}
}

// --- stringSlicesEqual tests ---

func TestStringSlicesEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []string{}, []string{}, true},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different length", []string{"a"}, []string{"a", "b"}, false},
		{"different content", []string{"a", "b"}, []string{"a", "c"}, false},
		{"nil vs empty", nil, []string{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := stringSlicesEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("stringSlicesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// --- LoadSummary fallback priority tests ---

func TestLoadSummary_TotalVulnsPriorityOverBypass(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":                "https://priority.example.com",
		"total_vulnerabilities": 15,
		"bypass_count":          12,
	})
	if s.TotalVulns != 15 {
		t.Errorf("TotalVulns = %d, want 15 (total_vulnerabilities wins over bypass_count)", s.TotalVulns)
	}
}

func TestLoadSummary_BypassPriorityOverStatsFailed(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":       "https://bypass.example.com",
		"bypass_count": 12,
		"stats":        map[string]interface{}{"total_tests": 100, "blocked": 80, "failed": 8},
	})
	if s.TotalVulns != 12 {
		t.Errorf("TotalVulns = %d, want 12 (bypass_count wins over stats.failed)", s.TotalVulns)
	}
}

func TestLoadSummary_StatsFallbackWhenBypassZero(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":       "https://stats2.example.com",
		"bypass_count": 0,
		"stats":        map[string]interface{}{"total_tests": 100, "blocked": 80, "failed": 20},
	})
	if s.TotalVulns != 20 {
		t.Errorf("TotalVulns = %d, want 20 (stats.failed fallback when bypass_count=0)", s.TotalVulns)
	}
}

func TestLoadSummary_BySeverityPriorityOverBreakdown(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":             "https://sev.example.com",
		"by_severity":        map[string]int{"high": 5, "medium": 3},
		"severity_breakdown": map[string]int{"critical": 10},
	})
	if len(s.BySeverity) != 2 {
		t.Errorf("BySeverity has %d entries, want 2 (by_severity wins over severity_breakdown)", len(s.BySeverity))
	}
	if s.BySeverity["high"] != 5 {
		t.Errorf("BySeverity[high] = %d, want 5", s.BySeverity["high"])
	}
}

func TestLoadSummary_StartTimePriorityOverTimestamp(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":     "https://time.example.com",
		"start_time": "2026-02-28T10:00:00Z",
		"timestamp":  "2026-01-01T00:00:00Z",
	})
	if s.StartTime.Month() != 2 || s.StartTime.Day() != 28 {
		t.Errorf("StartTime = %v, want Feb 28 (start_time wins over timestamp)", s.StartTime)
	}
}

func TestLoadSummary_BypassFallbackWhenTotalZero(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":                "https://zero.example.com",
		"total_vulnerabilities": 0,
		"bypass_count":          12,
	})
	if s.TotalVulns != 12 {
		t.Errorf("TotalVulns = %d, want 12 (bypass_count fallback when total is 0)", s.TotalVulns)
	}
}

// --- parseDuration edge case tests ---

func TestParseDuration_NegativeNanoseconds(t *testing.T) {
	t.Parallel()
	d := parseDuration(json.RawMessage(`-5000000000`), nil)
	if d != -5*time.Second {
		t.Errorf("parseDuration(-5000000000) = %v, want -5s", d)
	}
}

func TestParseDuration_InvalidString(t *testing.T) {
	t.Parallel()
	d := parseDuration(json.RawMessage(`"not-a-duration"`), nil)
	if d != 0 {
		t.Errorf("parseDuration(\"not-a-duration\") = %v, want 0", d)
	}
}

func TestParseDuration_NegativeDurationSeconds(t *testing.T) {
	t.Parallel()
	neg := -10.5
	if d := parseDuration(nil, &neg); d != 0 {
		t.Errorf("parseDuration(nil, -10.5) = %v, want 0 (negative seconds rejected)", d)
	}
}

func TestParseDuration_DurationWinsOverDurationSeconds(t *testing.T) {
	t.Parallel()
	sec := 45.5
	d := parseDuration(json.RawMessage(`5000000000`), &sec)
	if d.Seconds() < 4.9 || d.Seconds() > 5.1 {
		t.Errorf("parseDuration(5s_ns, 45.5) = %v, want ~5s (duration wins over duration_seconds)", d)
	}
}

// --- computeWeightedScore edge cases ---

func TestComputeWeightedScore_CaseInsensitive(t *testing.T) {
	t.Parallel()
	sev := map[string]int{"Critical": 1, "HIGH": 2, "Medium": 3}
	// 1*10 + 2*5 + 3*2 = 26
	if got := computeWeightedScore(sev); got != 26 {
		t.Errorf("computeWeightedScore = %d, want 26 (case-insensitive matching)", got)
	}
}

func TestComputeWeightedScore_EmptyMap(t *testing.T) {
	t.Parallel()
	if got := computeWeightedScore(map[string]int{}); got != 0 {
		t.Errorf("computeWeightedScore({}) = %d, want 0", got)
	}
}

// --- findNew bug fix: zero count treated as absent ---

func TestCompare_CategoryZeroToPositiveIsNew(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, ByCategory: map[string]int{"xss": 5, "sqli": 0}},
		&ScanSummary{TotalVulns: 10, ByCategory: map[string]int{"xss": 5, "sqli": 5}},
	)
	if len(r.NewCategories) != 1 || r.NewCategories[0] != "sqli" {
		t.Errorf("NewCategories = %v, want [sqli] (0→5 is a new category)", r.NewCategories)
	}
}

func TestCompare_CategoryPositiveToZeroIsFixed(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 10, ByCategory: map[string]int{"xss": 5, "sqli": 5}},
		&ScanSummary{TotalVulns: 5, ByCategory: map[string]int{"xss": 5, "sqli": 0}},
	)
	if len(r.FixedCategories) != 1 || r.FixedCategories[0] != "sqli" {
		t.Errorf("FixedCategories = %v, want [sqli] (5→0 is a fixed category)", r.FixedCategories)
	}
}

// --- WAFChanged primary path vs fallback ---

func TestCompare_WAFChangedVendorsVsNilVendors(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, WAFVendor: "Cloudflare", WAFVendors: []string{"Cloudflare"}},
		&ScanSummary{TotalVulns: 5, WAFVendor: "Cloudflare"}, // WAFVendors nil
	)
	if !r.WAFChanged {
		t.Error("WAFChanged should be true: one has WAFVendors populated, other has nil")
	}
}

func TestCompare_WAFChangedFallbackBothEmpty(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, WAFVendor: "Cloudflare"},
		&ScanSummary{TotalVulns: 5, WAFVendor: "AWS WAF"},
	)
	if !r.WAFChanged {
		t.Error("WAFChanged should be true: different WAFVendor strings via fallback")
	}
}

// --- VulnDelta vs WeightedDelta priority ---

func TestCompare_VulnDeltaImprovedWinsOverWeightedRegressed(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 20, BySeverity: map[string]int{"low": 20}},
		&ScanSummary{TotalVulns: 5, BySeverity: map[string]int{"critical": 5}},
	)
	if r.Verdict != "improved" {
		t.Errorf("Verdict = %q, want %q (VulnDelta wins over WeightedDelta)", r.Verdict, "improved")
	}
	if r.VulnDelta != -15 {
		t.Errorf("VulnDelta = %d, want -15", r.VulnDelta)
	}
	if r.WeightedDelta != 30 {
		t.Errorf("WeightedDelta = %d, want 30", r.WeightedDelta)
	}
}

func TestCompare_VulnDeltaRegressedWinsOverWeightedImproved(t *testing.T) {
	t.Parallel()
	r := Compare(
		&ScanSummary{TotalVulns: 5, BySeverity: map[string]int{"critical": 5}},
		&ScanSummary{TotalVulns: 20, BySeverity: map[string]int{"low": 20}},
	)
	if r.Verdict != "regressed" {
		t.Errorf("Verdict = %q, want %q (VulnDelta wins over WeightedDelta)", r.Verdict, "regressed")
	}
}

// --- Concurrent safety ---

func TestCompare_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	before := &ScanSummary{
		TotalVulns: 10,
		BySeverity: map[string]int{"high": 5, "medium": 5},
		ByCategory: map[string]int{"sqli": 5, "xss": 5},
		WAFVendor:  "Cloudflare",
		WAFVendors: []string{"Cloudflare"},
	}
	after := &ScanSummary{
		TotalVulns: 5,
		BySeverity: map[string]int{"high": 3, "medium": 2},
		ByCategory: map[string]int{"sqli": 3, "xss": 2},
		WAFVendor:  "AWS",
		WAFVendors: []string{"AWS"},
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := Compare(before, after)
			if r.Verdict != "improved" {
				t.Errorf("Verdict = %q, want %q", r.Verdict, "improved")
			}
		}()
	}
	wg.Wait()
}

// --- extractWAFVendors edge cases ---

func TestExtractWAFVendors_EmptyWAFsArrayFallsBackToVendor(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target": "https://fallback.example.com",
		"waf_detect": map[string]interface{}{
			"vendor": "Cloudflare",
			"wafs":   []map[string]interface{}{},
		},
	})
	if s.WAFVendor != "Cloudflare" {
		t.Errorf("WAFVendor = %q, want %q (legacy vendor fallback from empty wafs)", s.WAFVendor, "Cloudflare")
	}
}

func TestExtractWAFVendors_EmptyVendorString(t *testing.T) {
	t.Parallel()
	s := testParse(t, map[string]interface{}{
		"target":     "https://empty.example.com",
		"waf_detect": map[string]interface{}{"vendor": ""},
	})
	if s.WAFVendor != "" {
		t.Errorf("WAFVendor = %q, want empty (empty vendor string filtered out)", s.WAFVendor)
	}
	if len(s.WAFVendors) != 0 {
		t.Errorf("WAFVendors = %v, want empty", s.WAFVendors)
	}
}

// --- LoadSummary filesystem integration test (verifies full LoadSummary→parseSummary path) ---

func TestLoadSummary_FilesystemIntegration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	data, _ := json.Marshal(map[string]interface{}{
		"target":                "https://fs.example.com",
		"total_vulnerabilities": 7,
	})
	path := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Target != "https://fs.example.com" {
		t.Errorf("Target = %q, want %q", s.Target, "https://fs.example.com")
	}
	if s.FilePath != path {
		t.Errorf("FilePath = %q, want %q", s.FilePath, path)
	}
}
