package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTestJSON writes a JSON file to the given path and returns the path.
func writeTestJSON(t *testing.T, dir, name string, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- LoadSummary tests ---

func TestLoadSummary_FullScanResult(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]interface{}{
		"target":                "https://example.com",
		"total_vulnerabilities": 12,
		"by_severity":           map[string]int{"critical": 2, "high": 5, "medium": 3, "low": 2},
		"by_category":           map[string]int{"sqli": 4, "xss": 5, "cmdi": 3},
		"tech_stack":            []string{"nginx", "php"},
		"waf_detect":            map[string]string{"vendor": "Cloudflare"},
	}
	path := writeTestJSON(t, dir, "full.json", raw)

	s, err := LoadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
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
	if s.FilePath != path {
		t.Errorf("FilePath = %q, want %q", s.FilePath, path)
	}
}

func TestLoadSummary_MinimalJSON(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]interface{}{
		"target": "https://minimal.example.com",
	}
	path := writeTestJSON(t, dir, "minimal.json", raw)

	s, err := LoadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Target != "https://minimal.example.com" {
		t.Errorf("Target = %q, want %q", s.Target, "https://minimal.example.com")
	}
	if s.TotalVulns != 0 {
		t.Errorf("TotalVulns = %d, want 0", s.TotalVulns)
	}
}

func TestLoadSummary_FileNotFound(t *testing.T) {
	_, err := LoadSummary("/nonexistent/path/file.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadSummary_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid json!!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSummary(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadSummary_EmptyObject(t *testing.T) {
	dir := t.TempDir()
	path := writeTestJSON(t, dir, "empty.json", map[string]interface{}{})

	_, err := LoadSummary(path)
	if err == nil {
		t.Fatal("expected ErrNotScanResult for empty object")
	}
}

func TestLoadSummary_WAFDetectNested(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]interface{}{
		"target":     "https://waf.example.com",
		"waf_detect": map[string]string{"vendor": "AWS WAF"},
	}
	path := writeTestJSON(t, dir, "waf.json", raw)

	s, err := LoadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.WAFVendor != "AWS WAF" {
		t.Errorf("WAFVendor = %q, want %q", s.WAFVendor, "AWS WAF")
	}
}

func TestLoadSummary_ZeroTotalButSeverityPopulated(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]interface{}{
		"target":                "https://example.com",
		"total_vulnerabilities": 0,
		"by_severity":           map[string]int{"high": 3, "medium": 7},
	}
	path := writeTestJSON(t, dir, "zero_total.json", raw)

	s, err := LoadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.TotalVulns != 10 {
		t.Errorf("TotalVulns = %d, want 10 (summed from by_severity)", s.TotalVulns)
	}
}

func TestLoadSummary_NoWAFDetect(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]interface{}{
		"target":                "https://nowaf.example.com",
		"total_vulnerabilities": 5,
	}
	path := writeTestJSON(t, dir, "nowaf.json", raw)

	s, err := LoadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.WAFVendor != "" {
		t.Errorf("WAFVendor = %q, want empty", s.WAFVendor)
	}
}

// --- Compare tests ---

func TestCompare_Identical(t *testing.T) {
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
	before := &ScanSummary{
		TotalVulns: 20,
		BySeverity: map[string]int{"critical": 5, "high": 10, "medium": 5},
		ByCategory: map[string]int{"sqli": 10, "xss": 10},
	}
	after := &ScanSummary{
		TotalVulns: 8,
		BySeverity: map[string]int{"critical": 0, "high": 3, "medium": 5},
		ByCategory: map[string]int{"sqli": 3, "xss": 5},
	}
	r := Compare(before, after)
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
	before := &ScanSummary{
		TotalVulns: 5,
		BySeverity: map[string]int{"medium": 5},
		ByCategory: map[string]int{"xss": 5},
	}
	after := &ScanSummary{
		TotalVulns: 15,
		BySeverity: map[string]int{"critical": 3, "medium": 12},
		ByCategory: map[string]int{"xss": 8, "sqli": 7},
	}
	r := Compare(before, after)
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
	before := &ScanSummary{
		TotalVulns: 5,
		ByCategory: map[string]int{"sqli": 5},
	}
	after := &ScanSummary{
		TotalVulns: 10,
		ByCategory: map[string]int{"sqli": 5, "xss": 3, "cmdi": 2},
	}
	r := Compare(before, after)
	if len(r.NewCategories) != 2 {
		t.Fatalf("NewCategories = %v, want 2 entries", r.NewCategories)
	}
	// Sorted: cmdi, xss
	if r.NewCategories[0] != "cmdi" || r.NewCategories[1] != "xss" {
		t.Errorf("NewCategories = %v, want [cmdi, xss]", r.NewCategories)
	}
}

func TestCompare_FixedCategories(t *testing.T) {
	before := &ScanSummary{
		TotalVulns: 10,
		ByCategory: map[string]int{"sqli": 5, "cmdi": 3, "xxe": 2},
	}
	after := &ScanSummary{
		TotalVulns: 5,
		ByCategory: map[string]int{"sqli": 5},
	}
	r := Compare(before, after)
	if len(r.FixedCategories) != 2 {
		t.Fatalf("FixedCategories = %v, want 2 entries", r.FixedCategories)
	}
	// Sorted: cmdi, xxe
	if r.FixedCategories[0] != "cmdi" || r.FixedCategories[1] != "xxe" {
		t.Errorf("FixedCategories = %v, want [cmdi, xxe]", r.FixedCategories)
	}
}

func TestCompare_MixedSeverityDeltas(t *testing.T) {
	before := &ScanSummary{
		TotalVulns: 10,
		BySeverity: map[string]int{"critical": 2, "high": 5, "medium": 3},
	}
	after := &ScanSummary{
		TotalVulns: 10,
		BySeverity: map[string]int{"critical": 0, "high": 3, "medium": 5, "low": 2},
	}
	r := Compare(before, after)
	if r.SeverityDeltas["critical"] != -2 {
		t.Errorf("critical delta = %d, want -2", r.SeverityDeltas["critical"])
	}
	if r.SeverityDeltas["high"] != -2 {
		t.Errorf("high delta = %d, want -2", r.SeverityDeltas["high"])
	}
	if r.SeverityDeltas["medium"] != 2 {
		t.Errorf("medium delta = %d, want 2", r.SeverityDeltas["medium"])
	}
	if r.SeverityDeltas["low"] != 2 {
		t.Errorf("low delta = %d, want 2", r.SeverityDeltas["low"])
	}
}

func TestCompare_WAFChanged(t *testing.T) {
	before := &ScanSummary{
		TotalVulns: 5,
		WAFVendor:  "Cloudflare",
		ByCategory: map[string]int{"sqli": 5},
	}
	after := &ScanSummary{
		TotalVulns: 3,
		WAFVendor:  "AWS WAF",
		ByCategory: map[string]int{"sqli": 3},
	}
	r := Compare(before, after)
	if !r.WAFChanged {
		t.Error("WAFChanged should be true")
	}
}

func TestCompare_WAFAppeared(t *testing.T) {
	before := &ScanSummary{
		TotalVulns: 10,
		WAFVendor:  "",
		ByCategory: map[string]int{"sqli": 10},
	}
	after := &ScanSummary{
		TotalVulns: 3,
		WAFVendor:  "Imperva",
		ByCategory: map[string]int{"sqli": 3},
	}
	r := Compare(before, after)
	if !r.WAFChanged {
		t.Error("WAFChanged should be true when WAF vendor appears")
	}
}

func TestCompare_BothNilMaps(t *testing.T) {
	before := &ScanSummary{TotalVulns: 0}
	after := &ScanSummary{TotalVulns: 0}
	r := Compare(before, after)
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
	before := &ScanSummary{
		TotalVulns: 0,
		BySeverity: nil,
		ByCategory: nil,
	}
	after := &ScanSummary{
		TotalVulns: 5,
		BySeverity: map[string]int{"high": 3, "medium": 2},
		ByCategory: map[string]int{"sqli": 3, "xss": 2},
	}
	r := Compare(before, after)
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
	before := &ScanSummary{
		TotalVulns: 0,
		ByCategory: map[string]int{},
	}
	after := &ScanSummary{
		TotalVulns: 0,
		ByCategory: map[string]int{},
	}
	r := Compare(before, after)
	if r.Verdict != "unchanged" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "unchanged")
	}
	if r.VulnDelta != 0 {
		t.Errorf("VulnDelta = %d, want 0", r.VulnDelta)
	}
}

func TestLoadSummary_RealWAFDetectFormat(t *testing.T) {
	dir := t.TempDir()
	// Real scan output format: waf_detect has a wafs array, not a direct vendor field.
	raw := map[string]interface{}{
		"target":                "https://protected.example.com",
		"total_vulnerabilities": 5,
		"waf_detect": map[string]interface{}{
			"detected":   true,
			"confidence": 0.95,
			"wafs": []map[string]interface{}{
				{"name": "Cloudflare", "vendor": "Cloudflare", "confidence": 0.98},
			},
		},
	}
	path := writeTestJSON(t, dir, "real_waf.json", raw)

	s, err := LoadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.WAFVendor != "Cloudflare" {
		t.Errorf("WAFVendor = %q, want %q (from wafs[0].vendor)", s.WAFVendor, "Cloudflare")
	}
}

func TestLoadSummary_RealWAFDetectMultipleWAFs(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]interface{}{
		"target":                "https://multi.example.com",
		"total_vulnerabilities": 3,
		"waf_detect": map[string]interface{}{
			"detected": true,
			"wafs": []map[string]interface{}{
				{"name": "AWS WAF", "vendor": "AWS", "confidence": 0.90},
				{"name": "Cloudflare", "vendor": "Cloudflare", "confidence": 0.50},
			},
		},
	}
	path := writeTestJSON(t, dir, "multi_waf.json", raw)

	s, err := LoadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	// Should pick the first WAF in the array
	if s.WAFVendor != "AWS" {
		t.Errorf("WAFVendor = %q, want %q (first WAF)", s.WAFVendor, "AWS")
	}
}

func TestCompare_NilBeforeSummary(t *testing.T) {
	after := &ScanSummary{
		TotalVulns: 5,
		BySeverity: map[string]int{"high": 5},
	}
	// Should not panic
	r := Compare(nil, after)
	if r.VulnDelta != 5 {
		t.Errorf("VulnDelta = %d, want 5", r.VulnDelta)
	}
	if r.Verdict != "regressed" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "regressed")
	}
}

func TestCompare_NilAfterSummary(t *testing.T) {
	before := &ScanSummary{
		TotalVulns: 10,
		BySeverity: map[string]int{"high": 10},
	}
	// Should not panic
	r := Compare(before, nil)
	if r.VulnDelta != -10 {
		t.Errorf("VulnDelta = %d, want -10", r.VulnDelta)
	}
	if r.Verdict != "improved" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "improved")
	}
}

func TestCompare_BothNilSummaries(t *testing.T) {
	// Should not panic
	r := Compare(nil, nil)
	if r.Verdict != "unchanged" {
		t.Errorf("Verdict = %q, want %q", r.Verdict, "unchanged")
	}
}

func TestCompare_CategoryWithZeroCountNotNew(t *testing.T) {
	before := &ScanSummary{
		TotalVulns: 5,
		ByCategory: map[string]int{"xss": 5},
	}
	after := &ScanSummary{
		TotalVulns: 5,
		ByCategory: map[string]int{"xss": 5, "sqli": 0},
	}
	r := Compare(before, after)
	if len(r.NewCategories) != 0 {
		t.Errorf("NewCategories = %v, want empty (sqli has count 0)", r.NewCategories)
	}
}

func TestCompare_CategoryWithZeroCountNotFixed(t *testing.T) {
	before := &ScanSummary{
		TotalVulns: 5,
		ByCategory: map[string]int{"xss": 5, "cmdi": 0},
	}
	after := &ScanSummary{
		TotalVulns: 5,
		ByCategory: map[string]int{"xss": 5},
	}
	r := Compare(before, after)
	if len(r.FixedCategories) != 0 {
		t.Errorf("FixedCategories = %v, want empty (cmdi had count 0)", r.FixedCategories)
	}
}

func TestCompare_CategoryChurnUnchangedTotal(t *testing.T) {
	// Same total vulns, but completely different categories — verdict is "unchanged"
	// but NewCategories/FixedCategories should capture the shift
	before := &ScanSummary{
		TotalVulns: 10,
		ByCategory: map[string]int{"sqli": 10},
	}
	after := &ScanSummary{
		TotalVulns: 10,
		ByCategory: map[string]int{"xss": 10},
	}
	r := Compare(before, after)
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
	before := &ScanSummary{
		TotalVulns: 100000,
		BySeverity: map[string]int{"critical": 50000, "high": 50000},
	}
	after := &ScanSummary{
		TotalVulns: 1,
		BySeverity: map[string]int{"low": 1},
	}
	r := Compare(before, after)
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
