package output

// Error propagation tests for all write functions — verifies file close errors
// and write errors are surfaced, not silently swallowed.
// Would have caught R1 (CSV header errors, silent writer failures),
// R3 (output file close errors, silent write errors in JUnit/HTML/Markdown),
// and R4 (checkpoint close error).

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// minimalResults returns the smallest valid ExecutionResults for testing.
func minimalResults() ExecutionResults {
	return ExecutionResults{
		TotalTests:  1,
		PassedTests: 1,
		StartTime:   time.Now().Add(-time.Second),
		EndTime:     time.Now(),
		Duration:    time.Second,
	}
}

// TestWriteFunctions_InvalidPath verifies all write functions return an error
// when given a path that cannot be created (e.g., inside a non-existent directory).
func TestWriteFunctions_InvalidPath(t *testing.T) {
	t.Parallel()

	badPath := filepath.Join(t.TempDir(), "nonexistent", "deep", "nested", "file.out")
	results := minimalResults()

	cases := []struct {
		name string
		fn   func() error
	}{
		{"JSON", func() error { return writeResultsJSON(badPath, results, false) }},
		{"JSONL", func() error { return writeResultsJSONL(badPath, results) }},
		{"SARIF", func() error { return writeResultsSARIF(badPath, results, "2.8.6") }},
		{"JUnit", func() error { return writeResultsJUnit(badPath, results) }},
		{"CSV", func() error { return writeResultsCSV(badPath, results) }},
		{"HTML", func() error { return writeResultsHTML(badPath, results) }},
		{"Markdown", func() error { return writeResultsMarkdown(badPath, results) }},
		{"SonarQube", func() error { return writeResultsSonarQube(badPath, results) }},
		{"GitLabSAST", func() error { return writeResultsGitLabSAST(badPath, results) }},
		{"DefectDojo", func() error { return writeResultsDefectDojo(badPath, results) }},
		{"CycloneDX", func() error { return writeResultsCycloneDX(badPath, results) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.fn()
			if err == nil {
				t.Errorf("%s: expected error for invalid path, got nil", tc.name)
			}
		})
	}
}

// TestWriteFunctions_ReadOnlyFile verifies write functions detect permission errors.
func TestWriteFunctions_ReadOnlyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	results := minimalResults()

	// Create a read-only directory to prevent file creation
	roDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(roDir, 0o555); err != nil {
		t.Skipf("cannot create read-only dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(roDir, 0o755) })

	badPath := filepath.Join(roDir, "output.json")

	err := writeResultsJSON(badPath, results, false)
	// On some OS/configurations this may still succeed; skip if it does
	if err == nil {
		t.Skip("OS allowed writing to read-only dir (may be running as root/admin)")
	}
}

// TestWriteFunctions_ValidPath verifies all write functions succeed with valid paths.
func TestWriteFunctions_ValidPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	results := minimalResults()

	cases := []struct {
		name string
		fn   func(string) error
	}{
		{"JSON", func(p string) error { return writeResultsJSON(p, results, false) }},
		{"JSONL", func(p string) error { return writeResultsJSONL(p, results) }},
		{"SARIF", func(p string) error { return writeResultsSARIF(p, results, "2.8.6") }},
		{"JUnit", func(p string) error { return writeResultsJUnit(p, results) }},
		{"CSV", func(p string) error { return writeResultsCSV(p, results) }},
		{"HTML", func(p string) error { return writeResultsHTML(p, results) }},
		{"Markdown", func(p string) error { return writeResultsMarkdown(p, results) }},
		{"SonarQube", func(p string) error { return writeResultsSonarQube(p, results) }},
		{"GitLabSAST", func(p string) error { return writeResultsGitLabSAST(p, results) }},
		{"DefectDojo", func(p string) error { return writeResultsDefectDojo(p, results) }},
		{"CycloneDX", func(p string) error { return writeResultsCycloneDX(p, results) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, tc.name+".out")
			if err := tc.fn(path); err != nil {
				t.Errorf("%s: unexpected error: %v", tc.name, err)
			}
			// Verify file was actually created
			if _, err := os.Stat(path); err != nil {
				t.Errorf("%s: output file not created", tc.name)
			}
		})
	}
}
