// Package testutil provides reusable test helpers for output writer testing.
package testutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/output/testfixtures"
)

// ============================================================================
// WRITER TEST SCAFFOLDING
// ============================================================================

// WriterTestCase defines a test case for output writers.
type WriterTestCase struct {
	Name       string
	Format     string
	Results    []*output.TestResult
	Options    output.WriterOptions
	Validate   func(t *testing.T, content []byte)
	ShouldFail bool
}

// RunWriterTest runs a standard writer test case.
func RunWriterTest(t *testing.T, tc WriterTestCase) {
	t.Helper()
	t.Run(tc.Name, func(t *testing.T) {
		tmpDir := t.TempDir()
		ext := tc.Format
		if ext == "markdown" {
			ext = "md"
		}
		path := filepath.Join(tmpDir, "output."+ext)

		w, err := output.NewWriterWithOptions(path, tc.Format, tc.Options)
		if err != nil {
			if tc.ShouldFail {
				return // Expected failure
			}
			t.Fatalf("failed to create writer: %v", err)
		}
		defer w.Close()

		for _, result := range tc.Results {
			if err := w.Write(result); err != nil {
				t.Fatalf("failed to write result: %v", err)
			}
		}

		if err := w.Close(); err != nil {
			t.Fatalf("failed to close writer: %v", err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		if tc.Validate != nil {
			tc.Validate(t, content)
		}
	})
}

// RunWriterTests runs multiple writer test cases.
func RunWriterTests(t *testing.T, cases []WriterTestCase) {
	t.Helper()
	for _, tc := range cases {
		RunWriterTest(t, tc)
	}
}

// ============================================================================
// FORMAT VALIDATORS
// ============================================================================

// ValidateJSON checks if content is valid JSON.
func ValidateJSON(t *testing.T, content []byte) {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal(content, &v); err != nil {
		t.Errorf("invalid JSON: %v\nContent: %s", err, string(content[:min(500, len(content))]))
	}
}

// ValidateJSONArray checks if content is a valid JSON array.
func ValidateJSONArray(t *testing.T, content []byte) {
	t.Helper()
	var v []interface{}
	if err := json.Unmarshal(content, &v); err != nil {
		t.Errorf("invalid JSON array: %v", err)
	}
}

// ValidateJSONL checks if content is valid JSONL (one JSON object per line).
func ValidateJSONL(t *testing.T, content []byte) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		var v interface{}
		if err := json.Unmarshal(line, &v); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
	}
}

// ValidateHTML checks if content is valid HTML structure.
func ValidateHTML(t *testing.T, content []byte) {
	t.Helper()
	str := string(content)

	required := []string{
		"<!DOCTYPE html>",
		"<html",
		"<head>",
		"</head>",
		"<body",
		"</body>",
		"</html>",
	}

	for _, tag := range required {
		if !strings.Contains(str, tag) {
			t.Errorf("missing required HTML element: %s", tag)
		}
	}
}

// ValidateSARIF checks if content is valid SARIF format.
func ValidateSARIF(t *testing.T, content []byte) {
	t.Helper()

	var sarif struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(content, &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarif.Version)
	}

	if len(sarif.Runs) == 0 {
		t.Error("SARIF must have at least one run")
	}
}

// ValidateMarkdown checks if content is valid Markdown structure.
func ValidateMarkdown(t *testing.T, content []byte) {
	t.Helper()
	str := string(content)

	// Check for title
	if !regexp.MustCompile(`^#\s+\w+`).MatchString(str) {
		t.Error("Markdown should start with a title (# heading)")
	}

	// Check for table structure if expected
	if !strings.Contains(str, "|") {
		t.Log("Note: Markdown contains no tables")
	}
}

// ValidateCSV checks if content is valid CSV structure.
func ValidateCSV(t *testing.T, content []byte) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))

	if len(lines) == 0 {
		t.Error("CSV should have at least a header row")
		return
	}

	headerCols := bytes.Count(lines[0], []byte(",")) + 1

	for i, line := range lines[1:] {
		cols := bytes.Count(line, []byte(",")) + 1
		if cols != headerCols {
			t.Errorf("line %d has %d columns, expected %d", i+2, cols, headerCols)
		}
	}
}

// ============================================================================
// ASSERTION HELPERS
// ============================================================================

// AssertContains checks if content contains all expected strings.
func AssertContains(t *testing.T, content []byte, expected []string) {
	t.Helper()
	str := string(content)
	for _, exp := range expected {
		if !strings.Contains(str, exp) {
			t.Errorf("content missing expected string: %q", exp)
		}
	}
}

// AssertNotContains checks if content does NOT contain any forbidden strings.
func AssertNotContains(t *testing.T, content []byte, forbidden []string) {
	t.Helper()
	str := string(content)
	for _, f := range forbidden {
		if strings.Contains(str, f) {
			t.Errorf("content contains forbidden string: %q", f)
		}
	}
}

// AssertJSONEqual checks if two JSON values are semantically equal.
func AssertJSONEqual(t *testing.T, expected, actual []byte) {
	t.Helper()

	var expVal, actVal interface{}
	if err := json.Unmarshal(expected, &expVal); err != nil {
		t.Fatalf("expected JSON is invalid: %v", err)
	}
	if err := json.Unmarshal(actual, &actVal); err != nil {
		t.Fatalf("actual JSON is invalid: %v", err)
	}

	expNorm, _ := json.Marshal(expVal)
	actNorm, _ := json.Marshal(actVal)

	if !bytes.Equal(expNorm, actNorm) {
		t.Errorf("JSON mismatch:\nExpected: %s\nActual: %s", expNorm, actNorm)
	}
}

// AssertResultCount checks that the expected number of results are in output.
func AssertResultCount(t *testing.T, content []byte, format string, expected int) {
	t.Helper()

	var actual int

	switch format {
	case "json":
		var results []interface{}
		if err := json.Unmarshal(content, &results); err != nil {
			t.Fatalf("failed to parse JSON array: %v", err)
		}
		actual = len(results)

	case "jsonl":
		lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
		for _, line := range lines {
			if len(line) > 0 {
				actual++
			}
		}

	case "csv":
		lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
		actual = len(lines) - 1 // Subtract header

	default:
		t.Fatalf("unsupported format for result count: %s", format)
	}

	if actual != expected {
		t.Errorf("expected %d results, got %d", expected, actual)
	}
}

// ============================================================================
// TEMP FILE HELPERS
// ============================================================================

// WithTempFile creates a temp file and passes its path to the function.
func WithTempFile(t *testing.T, ext string, fn func(path string)) {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test."+ext)
	fn(path)
}

// WithTempDir creates a temp directory and passes its path to the function.
func WithTempDir(t *testing.T, fn func(dir string)) {
	t.Helper()
	fn(t.TempDir())
}

// ============================================================================
// GOLDEN FILE COMPARISON
// ============================================================================

// GoldenDir returns the path to the golden files directory.
func GoldenDir() string {
	return filepath.Join("testdata", "golden")
}

// CompareWithGolden compares output with a golden file.
// Set UPDATE_GOLDEN=true to update golden files.
func CompareWithGolden(t *testing.T, name string, actual []byte) {
	t.Helper()

	goldenPath := filepath.Join(GoldenDir(), name)

	if os.Getenv("UPDATE_GOLDEN") == "true" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0755); err != nil {
			t.Fatalf("failed to create golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, actual, 0644); err != nil {
			t.Fatalf("failed to update golden file: %v", err)
		}
		t.Logf("Updated golden file: %s", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file %s: %v\nRun with UPDATE_GOLDEN=true to create it", goldenPath, err)
	}

	if !bytes.Equal(expected, actual) {
		t.Errorf("output does not match golden file %s\n--- Expected:\n%s\n--- Actual:\n%s",
			name,
			string(expected[:min(1000, len(expected))]),
			string(actual[:min(1000, len(actual))]))
	}
}

// ============================================================================
// REALISTIC SCENARIO HELPERS
// ============================================================================

// StandardWriterTests returns a standard set of test cases for any format.
func StandardWriterTests(format string, validateFn func(t *testing.T, content []byte)) []WriterTestCase {
	return []WriterTestCase{
		{
			Name:    "empty results",
			Format:  format,
			Results: []*output.TestResult{},
			Validate: func(t *testing.T, content []byte) {
				if len(content) == 0 {
					t.Error("output should not be empty even with no results")
				}
			},
		},
		{
			Name:     "single result",
			Format:   format,
			Results:  []*output.TestResult{testfixtures.MakeTestResult("test-1", "sqli", "High", "Blocked", 403)},
			Validate: validateFn,
		},
		{
			Name:     "multiple results",
			Format:   format,
			Results:  testfixtures.MakeSampleResults(10),
			Validate: validateFn,
		},
		{
			Name:     "realistic scan",
			Format:   format,
			Results:  testfixtures.MakeRealisticScan(100),
			Validate: validateFn,
		},
		{
			Name:   "bypass scenario",
			Format: format,
			Results: []*output.TestResult{
				testfixtures.MakeBlockedResult("blocked-1", "sqli", "High"),
				testfixtures.MakeBypassResult("bypass-1", "sqli", "Critical", []string{"charunicodeencode"}),
				testfixtures.MakeErrorResult("error-1", "connection", "timeout"),
			},
			Validate: validateFn,
		},
	}
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// FormatBytes returns a human-readable byte size.
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
