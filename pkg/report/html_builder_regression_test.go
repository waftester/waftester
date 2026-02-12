// Regression test for bug: BuildFromMetrics panicked on empty grade string.
//
// Before the fix, when catMap["grade"] was present but empty (""),
// the code did `g[0]` to extract the first character for CSSClassSuffix,
// causing an index-out-of-range panic. The fix adds `len(g) > 0` guard.
package report

import (
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
