// Regression test for bug: BuildFromMetrics panicked on empty grade string.
//
// Before the fix, when catMap["grade"] was present but empty (""),
// the code did `g[0]` to extract the first character for CSSClassSuffix,
// causing an index-out-of-range panic. The fix adds `len(g) > 0` guard.
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildFromMetrics_EmptyGrade_NoPanic(t *testing.T) {
	t.Parallel()

	// Construct metrics with an empty grade string — this triggered the panic.
	metrics := map[string]interface{}{
		"category_metrics": map[string]interface{}{
			"sqli": map[string]interface{}{
				"detection_rate": 0.85,
				"total_tests":    100.0,
				"blocked":        85.0,
				"bypassed":       15.0,
				"grade":          "", // empty string — the bug trigger
			},
		},
		"overall_detection_rate": 0.85,
	}

	// Must not panic.
	report, err := BuildFromMetrics(metrics, "test.example.com", 0)
	if err != nil {
		t.Fatalf("BuildFromMetrics error: %v", err)
	}
	if report == nil {
		t.Fatal("BuildFromMetrics returned nil")
	}

	// Empty grade should be ignored; grade should come from detection_rate instead.
	for _, cr := range report.CategoryResults {
		if cr.Category == "sqli" {
			if cr.Grade.Mark == "" {
				// Grade should have been computed from detection_rate since
				// the empty string grade was skipped.
				t.Error("grade.Mark is empty even though detection_rate was provided")
			}
		}
	}
}

func TestBuildFromMetrics_ValidGrade_Applied(t *testing.T) {
	t.Parallel()

	metrics := map[string]interface{}{
		"category_metrics": map[string]interface{}{
			"xss": map[string]interface{}{
				"detection_rate": 0.90,
				"total_tests":    50.0,
				"blocked":        45.0,
				"bypassed":       5.0,
				"grade":          "A",
			},
		},
		"overall_detection_rate": 0.90,
	}

	report, err := BuildFromMetrics(metrics, "test.example.com", 0)
	if err != nil {
		t.Fatalf("BuildFromMetrics error: %v", err)
	}
	if report == nil {
		t.Fatal("BuildFromMetrics returned nil")
	}

	for _, cr := range report.CategoryResults {
		if cr.Category == "xss" {
			if cr.Grade.Mark != "A" {
				t.Errorf("grade.Mark = %q; want %q", cr.Grade.Mark, "A")
			}
			if cr.Grade.CSSClassSuffix != "a" {
				t.Errorf("grade.CSSClassSuffix = %q; want %q", cr.Grade.CSSClassSuffix, "a")
			}
			return
		}
	}
	t.Error("xss category not found in report")
}

// Regression test: LoadAllResultsFromFile must not overwrite assessment counts.
//
// Before the fix, LoadAllResultsFromFile replaced TotalRequests/BlockedRequests/
// PassedRequests with counts from the results.json entries only. This caused the
// stats grid to show 55 total instead of 367, and 6 blocked instead of 117.
func TestLoadAllResultsFromFile_DoesNotOverwriteAssessmentCounts(t *testing.T) {
	t.Parallel()

	// Build a report with assessment-level counts (from confusion matrix).
	report := &EnterpriseReport{
		TotalRequests:   367,
		BlockedRequests: 117,
		PassedRequests:  250,
		ErrorRequests:   0,
	}

	// Write a small results.json with fewer entries.
	results := []map[string]interface{}{
		{"id": "test-1", "outcome": "Blocked", "status_code": 403.0},
		{"id": "test-2", "outcome": "Blocked", "status_code": 403.0},
		{"id": "test-3", "outcome": "Pass", "status_code": 200.0},
		{"id": "test-4", "outcome": "Skipped", "status_code": 0.0, "error_message": "silent_ban"},
		{"id": "test-5", "outcome": "Error", "status_code": 0.0},
	}
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tmpDir := t.TempDir()
	resultsPath := filepath.Join(tmpDir, "results.json")
	if err := os.WriteFile(resultsPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Load results.
	if err := report.LoadAllResultsFromFile(resultsPath); err != nil {
		t.Fatalf("LoadAllResultsFromFile: %v", err)
	}

	// Assessment-level counts must be preserved.
	if report.TotalRequests != 367 {
		t.Errorf("TotalRequests = %d; want 367 (must not be overwritten)", report.TotalRequests)
	}
	if report.BlockedRequests != 117 {
		t.Errorf("BlockedRequests = %d; want 117 (must not be overwritten)", report.BlockedRequests)
	}
	if report.PassedRequests != 250 {
		t.Errorf("PassedRequests = %d; want 250 (must not be overwritten)", report.PassedRequests)
	}

	// Per-result counts should reflect the actual results.json entries.
	if report.ResultsBlockedCount != 2 {
		t.Errorf("ResultsBlockedCount = %d; want 2", report.ResultsBlockedCount)
	}
	if report.ResultsPassedCount != 1 {
		t.Errorf("ResultsPassedCount = %d; want 1", report.ResultsPassedCount)
	}
	if report.ResultsSkippedCount != 1 {
		t.Errorf("ResultsSkippedCount = %d; want 1", report.ResultsSkippedCount)
	}
	if report.ResultsErrorCount != 1 {
		t.Errorf("ResultsErrorCount = %d; want 1", report.ResultsErrorCount)
	}

	// AllResults should have all 5 entries.
	if len(report.AllResults) != 5 {
		t.Errorf("len(AllResults) = %d; want 5", len(report.AllResults))
	}
}

// Regression test: BuildRadarChartData returns nil for fewer than 3 categories.
func TestBuildRadarChartData_LessThan3Categories(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		categories []CategoryResult
		wantNil    bool
	}{
		{"zero", nil, true},
		{"one", []CategoryResult{{Category: "sqli", DetectionRate: 0.9}}, true},
		{"two", []CategoryResult{
			{Category: "sqli", DetectionRate: 0.9},
			{Category: "xss", DetectionRate: 0.8},
		}, true},
		{"three", []CategoryResult{
			{Category: "sqli", DetectionRate: 0.9},
			{Category: "xss", DetectionRate: 0.8},
			{Category: "lfi", DetectionRate: 0.7},
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := BuildRadarChartData(tc.categories)
			if tc.wantNil && got != nil {
				t.Errorf("BuildRadarChartData with %d categories should return nil", len(tc.categories))
			}
			if !tc.wantNil && got == nil {
				t.Error("BuildRadarChartData with 3 categories should not return nil")
			}
		})
	}
}

// Regression test: parseBrowserFindings deduplicates routes and filters empty API names.
func TestParseBrowserFindings_DedupAndFilter(t *testing.T) {
	t.Parallel()

	data := map[string]interface{}{
		"discovered_routes": []interface{}{
			map[string]interface{}{"path": "/api/data", "requires_auth": true},
			map[string]interface{}{"path": "/api/data", "requires_auth": true}, // duplicate
			map[string]interface{}{"path": "/api/users", "requires_auth": false},
			map[string]interface{}{"path": "", "requires_auth": false}, // empty path
		},
		"third_party_apis": []interface{}{
			map[string]interface{}{"name": "Google Analytics", "request_type": "script", "severity": "low"},
			map[string]interface{}{"name": "", "request_type": "xhr", "severity": "medium"}, // empty name
			map[string]interface{}{"name": "Google Analytics", "request_type": "img", "severity": "low"},
		},
	}

	findings := parseBrowserFindings(data)

	// Routes should be deduplicated and empty paths filtered.
	if len(findings.DiscoveredRoutes) != 2 {
		t.Errorf("DiscoveredRoutes = %d; want 2 (deduped, empty filtered)", len(findings.DiscoveredRoutes))
	}

	// Third-party APIs should have empty names filtered.
	if len(findings.ThirdPartyAPIs) != 2 {
		t.Errorf("ThirdPartyAPIs = %d; want 2 (empty name filtered)", len(findings.ThirdPartyAPIs))
	}

	// Grouped third-party should have 1 entry (both Google Analytics merged).
	if len(findings.GroupedThirdParty) != 1 {
		t.Errorf("GroupedThirdParty = %d; want 1 (grouped)", len(findings.GroupedThirdParty))
	}
	if len(findings.GroupedThirdParty) > 0 && findings.GroupedThirdParty[0].Count != 2 {
		t.Errorf("GroupedThirdParty[0].Count = %d; want 2", findings.GroupedThirdParty[0].Count)
	}
}

// Regression test: Executive summary is generated and non-empty.
func TestBuildFromMetrics_HasExecutiveSummary(t *testing.T) {
	t.Parallel()

	metrics := map[string]interface{}{
		"detection_rate":          0.85,
		"false_positive_rate":     0.02,
		"bypass_resistance":      0.90,
		"grade":                  "B",
		"waf_vendor":             "ModSecurity",
		"total_requests":         367.0,
		"overall_detection_rate": 0.85,
		"confusion_matrix": map[string]interface{}{
			"true_positives":  117.0,
			"false_positives": 0.0,
			"true_negatives":  29.0,
			"false_negatives": 221.0,
		},
		"category_metrics": map[string]interface{}{
			"sqli": map[string]interface{}{
				"detection_rate": 0.90,
				"total_tests":    50.0,
				"blocked":        45.0,
				"bypassed":       5.0,
			},
			"xss": map[string]interface{}{
				"detection_rate": 0.80,
				"total_tests":    40.0,
				"blocked":        32.0,
				"bypassed":       8.0,
			},
			"lfi": map[string]interface{}{
				"detection_rate": 0.60,
				"total_tests":    30.0,
				"blocked":        18.0,
				"bypassed":       12.0,
			},
		},
	}

	report, err := BuildFromMetrics(metrics, "test.example.com", 0)
	if err != nil {
		t.Fatalf("BuildFromMetrics error: %v", err)
	}
	if report.ExecutiveSummary == "" {
		t.Error("ExecutiveSummary should not be empty")
	}
	// Should mention the target
	if !contains(report.ExecutiveSummary, "test.example.com") {
		t.Errorf("ExecutiveSummary should mention target, got: %s", report.ExecutiveSummary)
	}
	// Should mention the WAF vendor
	if !contains(report.ExecutiveSummary, "ModSecurity") {
		t.Errorf("ExecutiveSummary should mention WAF vendor, got: %s", report.ExecutiveSummary)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
