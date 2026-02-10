package output_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/output/testfixtures"
	"github.com/waftester/waftester/pkg/output/testutil"
)

// ============================================================================
// REALISTIC INTEGRATION TESTS
// ============================================================================
//
// These tests simulate real-world usage scenarios, not just unit behavior.
// Each test represents a complete workflow that a user might perform.
// ============================================================================

// TestRealisticWAFScanReport simulates a complete WAF scan with report generation.
// This is what happens when a user runs: waf-tester scan -u target.com -format html -o report.html
func TestRealisticWAFScanReport(t *testing.T) {
	// Generate realistic scan data: 70% blocked, 20% bypass, 10% errors
	results := testfixtures.MakeRealisticScan(100)

	formats := []struct {
		name     string
		format   string
		ext      string
		validate func(t *testing.T, content []byte)
	}{
		{
			name:   "JSON report",
			format: "json",
			ext:    "json",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateJSONArray(t, content)
				testutil.AssertResultCount(t, content, "json", 100)
			},
		},
		{
			name:   "JSONL streaming",
			format: "jsonl",
			ext:    "jsonl",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateJSONL(t, content)
				testutil.AssertResultCount(t, content, "jsonl", 100)
			},
		},
		{
			name:   "HTML stakeholder report",
			format: "html",
			ext:    "html",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateHTML(t, content)
				testutil.AssertContains(t, content, []string{
					"WAF Security Test Report",
					"blocked-", // Should contain blocked results
					"bypass-",  // Should contain bypass results
				})
			},
		},
		{
			name:   "SARIF for CI/CD",
			format: "sarif",
			ext:    "sarif",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateSARIF(t, content)
				// SARIF only includes Fail/Error outcomes
				var sarif struct {
					Runs []struct {
						Results []interface{} `json:"results"`
					} `json:"runs"`
				}
				json.Unmarshal(content, &sarif)
				// Should have bypass + error results (20 + 10 = 30)
				if len(sarif.Runs) > 0 && len(sarif.Runs[0].Results) < 20 {
					t.Errorf("expected at least 20 SARIF results (bypasses + errors), got %d", len(sarif.Runs[0].Results))
				}
			},
		},
		{
			name:   "Markdown documentation",
			format: "md",
			ext:    "md",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateMarkdown(t, content)
				testutil.AssertContains(t, content, []string{
					"# WAF Security Test Report",
					"## Summary",
					"## Results",
				})
			},
		},
		{
			name:   "CSV for Excel",
			format: "csv",
			ext:    "csv",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateCSV(t, content)
				testutil.AssertResultCount(t, content, "csv", 100)
			},
		},
	}

	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "report."+tc.ext)

			w, err := output.NewWriter(path, tc.format)
			if err != nil {
				t.Fatalf("failed to create %s writer: %v", tc.format, err)
			}

			for _, result := range results {
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

			tc.validate(t, content)
		})
	}
}

// TestRealisticBypassDiscovery simulates bypass hunting workflow.
// This is what happens when a user runs: waf-tester bypass -u target.com --smart -json
func TestRealisticBypassDiscovery(t *testing.T) {
	// Create results that simulate bypass discovery
	results := []*output.TestResult{
		// First, WAF blocks most attacks
		testfixtures.MakeBlockedResult("sqli-001", "sqli", "Critical"),
		testfixtures.MakeBlockedResult("sqli-002", "sqli", "Critical"),
		testfixtures.MakeBlockedResult("sqli-003", "sqli", "Critical"),
		testfixtures.MakeBlockedResult("xss-001", "xss", "High"),
		testfixtures.MakeBlockedResult("xss-002", "xss", "High"),
		// Then, tamper chains find bypasses
		testfixtures.MakeBypassResult("sqli-bypass-001", "sqli", "Critical", []string{"charunicodeencode", "space2comment"}),
		testfixtures.MakeBypassResult("xss-bypass-001", "xss", "High", []string{"randomcase", "htmlencode"}),
		// Some errors during aggressive testing
		testfixtures.MakeErrorResult("timeout-001", "connection", "connection reset by peer"),
	}

	t.Run("JSON output captures bypass details", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "bypasses.json")

		w, err := output.NewWriter(path, "json")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		for _, result := range results {
			w.Write(result)
		}
		w.Close()

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		// Parse and verify structure
		var parsed []output.TestResult
		if err := json.Unmarshal(content, &parsed); err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}

		// Count bypasses (Outcome == "Fail" with StatusCode 200)
		bypasses := 0
		for _, r := range parsed {
			if r.Outcome == "Fail" && r.StatusCode == 200 {
				bypasses++
			}
		}

		if bypasses != 2 {
			t.Errorf("expected 2 bypasses, got %d", bypasses)
		}

		// Verify bypass details are captured
		testutil.AssertContains(t, content, []string{
			"encoding_used",
			"double_url",
			"evidence_markers",
			"curl_command",
			"bypass-payload-",
		})
	})

	t.Run("SARIF captures only vulnerabilities", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "bypasses.sarif")

		w, err := output.NewWriter(path, "sarif")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		for _, result := range results {
			w.Write(result)
		}
		w.Close()

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		var sarif struct {
			Runs []struct {
				Results []struct {
					RuleID string `json:"ruleId"`
					Level  string `json:"level"`
				} `json:"results"`
			} `json:"runs"`
		}

		if err := json.Unmarshal(content, &sarif); err != nil {
			t.Fatalf("failed to parse SARIF: %v", err)
		}

		// SARIF should only contain bypasses and errors (Fail/Error outcomes)
		if len(sarif.Runs) == 0 {
			t.Fatal("SARIF should have at least one run")
		}

		// We should have 3 results: 2 bypasses + 1 error
		resultCount := len(sarif.Runs[0].Results)
		if resultCount != 3 {
			t.Errorf("expected 3 SARIF results (2 bypasses + 1 error), got %d", resultCount)
		}
	})
}

// TestRealisticEnterpriseAssessment simulates enterprise assessment workflow.
// This is what happens when a user runs: waf-tester assess -u target.com -fp -o assessment.json
func TestRealisticEnterpriseAssessment(t *testing.T) {
	// Simulate an enterprise assessment with metrics
	// This would normally include TPR, FPR, F1, MCC calculations

	// Create a mix of true positives (blocked), false negatives (bypassed), and clean results
	results := make([]*output.TestResult, 0)

	// True Positives: Attacks correctly blocked
	for i := 0; i < 50; i++ {
		results = append(results, testfixtures.MakeBlockedResult(
			"tp-"+string(rune('0'+i%10)),
			[]string{"sqli", "xss", "rce", "ssrf", "xxe"}[i%5],
			[]string{"Critical", "High", "Medium"}[i%3],
		))
	}

	// False Negatives: Attacks that bypassed
	for i := 0; i < 5; i++ {
		results = append(results, testfixtures.MakeBypassResult(
			"fn-"+string(rune('0'+i)),
			"sqli",
			"Critical",
			[]string{"charunicodeencode"},
		))
	}

	// True Negatives: Benign requests that passed (simulated as Pass outcome)
	for i := 0; i < 45; i++ {
		results = append(results, testfixtures.MakeTestResult(
			"tn-"+string(rune('0'+i%10)),
			"benign",
			"None",
			"Pass",
			200,
		))
	}

	t.Run("JSON assessment output", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "assessment.json")

		w, err := output.NewWriter(path, "json")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		for _, result := range results {
			w.Write(result)
		}
		w.Close()

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		testutil.ValidateJSONArray(t, content)
		testutil.AssertResultCount(t, content, "json", 100)

		// Verify category distribution
		var parsed []output.TestResult
		json.Unmarshal(content, &parsed)

		blocked := 0
		bypassed := 0
		passed := 0
		for _, r := range parsed {
			switch r.Outcome {
			case "Blocked":
				blocked++
			case "Fail":
				bypassed++
			case "Pass":
				passed++
			}
		}

		if blocked != 50 {
			t.Errorf("expected 50 blocked, got %d", blocked)
		}
		if bypassed != 5 {
			t.Errorf("expected 5 bypassed, got %d", bypassed)
		}
		if passed != 45 {
			t.Errorf("expected 45 passed, got %d", passed)
		}
	})

	t.Run("HTML assessment report", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "assessment.html")

		w, err := output.NewWriter(path, "html")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		for _, result := range results {
			w.Write(result)
		}
		w.Close()

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		testutil.ValidateHTML(t, content)
		testutil.AssertContains(t, content, []string{
			"WAF Security Test Report",
			"WAF Effectiveness", // Should calculate and display metrics
		})
	})
}

// TestRealisticCICDPipeline simulates CI/CD integration workflow.
// This is what happens in: GitHub Actions, GitLab CI, Azure DevOps
func TestRealisticCICDPipeline(t *testing.T) {
	results := testfixtures.MakeSampleResults(25)

	t.Run("SARIF for GitHub Security Tab", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "results.sarif")

		w, err := output.NewWriter(path, "sarif")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		for _, result := range results {
			w.Write(result)
		}
		w.Close()

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		testutil.ValidateSARIF(t, content)

		// Verify SARIF structure for GitHub
		var sarif struct {
			Schema  string `json:"$schema"`
			Version string `json:"version"`
			Runs    []struct {
				Tool struct {
					Driver struct {
						Name           string `json:"name"`
						InformationUri string `json:"informationUri"`
						Rules          []struct {
							ID string `json:"id"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
			} `json:"runs"`
		}

		json.Unmarshal(content, &sarif)

		if !strings.Contains(sarif.Schema, "sarif") {
			t.Error("SARIF schema should reference sarif")
		}
		if sarif.Version != "2.1.0" {
			t.Errorf("SARIF version should be 2.1.0, got %s", sarif.Version)
		}
	})

	t.Run("JSONL for streaming processing", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "events.jsonl")

		w, err := output.NewWriter(path, "jsonl")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		for _, result := range results {
			w.Write(result)
		}
		w.Close()

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		testutil.ValidateJSONL(t, content)

		// Each line should be parseable individually (streaming requirement)
		lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
		for i, line := range lines {
			var result output.TestResult
			if err := json.Unmarshal(line, &result); err != nil {
				t.Errorf("line %d is not a valid TestResult: %v", i+1, err)
			}
			if result.ID == "" {
				t.Errorf("line %d result has no ID", i+1)
			}
		}
	})
}

// TestRealisticLargeScale simulates large-scale scanning (2800+ payloads).
func TestRealisticLargeScale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-scale test in short mode")
	}

	// Simulate full payload set execution
	results := testfixtures.MakeRealisticScan(2800)

	formats := []string{"json", "jsonl", "csv"}

	for _, format := range formats {
		t.Run(format+" handles 2800 results", func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "results."+format)

			w, err := output.NewWriter(path, format)
			if err != nil {
				t.Fatalf("failed to create writer: %v", err)
			}

			for _, result := range results {
				if err := w.Write(result); err != nil {
					t.Fatalf("failed to write result: %v", err)
				}
			}

			if err := w.Close(); err != nil {
				t.Fatalf("failed to close writer: %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("failed to stat output: %v", err)
			}

			// Should produce reasonable file size
			if info.Size() == 0 {
				t.Error("output file is empty")
			}

			t.Logf("%s output: %s", format, testutil.FormatBytes(info.Size()))
		})
	}
}

// TestWriterOptionsInteraction tests that writer options work correctly together.
func TestWriterOptionsInteraction(t *testing.T) {
	results := testfixtures.MakeSampleResults(5)

	t.Run("verbose mode includes extra details", func(t *testing.T) {
		w, err := output.NewWriterWithOptions("", "console", output.WriterOptions{
			Verbose: true,
		})
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		// Note: ConsoleWriter writes to os.Stdout by default, this tests creation
		_ = w
	})

	t.Run("silent mode suppresses output", func(t *testing.T) {
		w, err := output.NewWriterWithOptions("", "console", output.WriterOptions{
			Silent: true,
		})
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		for _, result := range results {
			w.Write(result)
		}
		w.Close()

		// Silent mode should not produce output
	})
}

// TestOWASPCategoryMapping verifies OWASP mappings use centralized defaults data.
func TestOWASPCategoryMapping(t *testing.T) {
	// Verify all categories in OWASPMapping use centralized OWASP data correctly
	for cat, mapping := range output.OWASPMapping {
		// Each mapping should have a valid OWASP category
		if mapping.OWASP == "" {
			t.Errorf("category %s has empty OWASP mapping", cat)
			continue
		}

		// OWASP should start with "A" followed by digits (e.g., "A03:2021 - Injection", "A10:2021 - SSRF")
		if len(mapping.OWASP) < 3 || mapping.OWASP[0] != 'A' {
			t.Errorf("category %s: OWASP mapping %q doesn't look like OWASP Top 10 format", cat, mapping.OWASP)
		}

		// Each mapping should have at least one CWE
		if len(mapping.CWE) == 0 {
			t.Errorf("category %s has no CWE mappings", cat)
		}
	}
}

// TestAllCategoriesHaveValidOutput verifies all attack categories produce valid output.
func TestAllCategoriesHaveValidOutput(t *testing.T) {
	categories := testfixtures.AllCategories()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "all-categories.json")

	w, err := output.NewWriter(path, "json")
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	for i, cat := range categories {
		result := testfixtures.MakeTestResult(
			"cat-test-"+cat,
			cat,
			"High",
			"Blocked",
			403,
		)
		if err := w.Write(result); err != nil {
			t.Errorf("failed to write category %s: %v", cat, err)
		}
		_ = i
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	testutil.ValidateJSONArray(t, content)
	testutil.AssertResultCount(t, content, "json", len(categories))
}

// ============================================================================
// MULTI-WRITER INTEGRATION TESTS
// ============================================================================
//
// These tests verify that multiple writers can work simultaneously,
// which is a common scenario when users want multiple output formats at once.
// ============================================================================

// TestMultiWriterScenario_JSONAndSARIF verifies writing to JSON and SARIF simultaneously.
// This simulates: waf-tester scan -u target.com -format json,sarif -o results
func TestMultiWriterScenario_JSONAndSARIF(t *testing.T) {
	results := testfixtures.MakeRealisticScan(50)

	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "results.json")
	sarifPath := filepath.Join(tmpDir, "results.sarif")

	// Create both writers
	jsonWriter, err := output.NewWriter(jsonPath, "json")
	if err != nil {
		t.Fatalf("failed to create JSON writer: %v", err)
	}

	sarifWriter, err := output.NewWriter(sarifPath, "sarif")
	if err != nil {
		t.Fatalf("failed to create SARIF writer: %v", err)
	}

	// Write to both simultaneously
	for _, result := range results {
		if err := jsonWriter.Write(result); err != nil {
			t.Fatalf("failed to write to JSON: %v", err)
		}
		if err := sarifWriter.Write(result); err != nil {
			t.Fatalf("failed to write to SARIF: %v", err)
		}
	}

	// Close both writers
	if err := jsonWriter.Close(); err != nil {
		t.Fatalf("failed to close JSON writer: %v", err)
	}
	if err := sarifWriter.Close(); err != nil {
		t.Fatalf("failed to close SARIF writer: %v", err)
	}

	// Verify JSON output
	jsonContent, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}
	testutil.ValidateJSONArray(t, jsonContent)
	testutil.AssertResultCount(t, jsonContent, "json", 50)

	// Verify SARIF output
	sarifContent, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed to read SARIF output: %v", err)
	}
	testutil.ValidateSARIF(t, sarifContent)

	// Verify file sizes are reasonable
	jsonInfo, _ := os.Stat(jsonPath)
	sarifInfo, _ := os.Stat(sarifPath)

	if jsonInfo.Size() == 0 {
		t.Error("JSON output file is empty")
	}
	if sarifInfo.Size() == 0 {
		t.Error("SARIF output file is empty")
	}

	t.Logf("JSON output: %s, SARIF output: %s",
		testutil.FormatBytes(jsonInfo.Size()),
		testutil.FormatBytes(sarifInfo.Size()))
}

// TestMultiWriterScenario_AllFormats verifies writing to all formats simultaneously.
// This simulates: waf-tester scan -u target.com -format json,sarif,csv,md,html -o results
func TestMultiWriterScenario_AllFormats(t *testing.T) {
	results := testfixtures.MakeRealisticScan(50)

	tmpDir := t.TempDir()

	// Define all formats to test
	formats := []struct {
		format   string
		ext      string
		validate func(t *testing.T, content []byte)
	}{
		{
			format: "json",
			ext:    "json",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateJSONArray(t, content)
				testutil.AssertResultCount(t, content, "json", 50)
			},
		},
		{
			format: "sarif",
			ext:    "sarif",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateSARIF(t, content)
			},
		},
		{
			format: "csv",
			ext:    "csv",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateCSV(t, content)
				testutil.AssertResultCount(t, content, "csv", 50)
			},
		},
		{
			format: "md",
			ext:    "md",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateMarkdown(t, content)
				testutil.AssertContains(t, content, []string{
					"# WAF Security Test Report",
					"## Summary",
				})
			},
		},
		{
			format: "html",
			ext:    "html",
			validate: func(t *testing.T, content []byte) {
				testutil.ValidateHTML(t, content)
				testutil.AssertContains(t, content, []string{
					"WAF Security Test Report",
				})
			},
		},
	}

	// Create all writers
	writers := make(map[string]output.ResultWriter)
	paths := make(map[string]string)

	for _, f := range formats {
		path := filepath.Join(tmpDir, "results."+f.ext)
		paths[f.format] = path

		w, err := output.NewWriter(path, f.format)
		if err != nil {
			t.Fatalf("failed to create %s writer: %v", f.format, err)
		}
		writers[f.format] = w
	}

	// Write to all writers simultaneously
	for _, result := range results {
		for format, w := range writers {
			if err := w.Write(result); err != nil {
				t.Fatalf("failed to write to %s: %v", format, err)
			}
		}
	}

	// Close all writers
	for format, w := range writers {
		if err := w.Close(); err != nil {
			t.Fatalf("failed to close %s writer: %v", format, err)
		}
	}

	// Verify each output
	for _, f := range formats {
		t.Run(f.format+" output valid", func(t *testing.T) {
			path := paths[f.format]

			// Verify file exists and has content
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("%s output file does not exist: %v", f.format, err)
			}
			if info.Size() == 0 {
				t.Fatalf("%s output file is empty", f.format)
			}

			// Read and validate content
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read %s output: %v", f.format, err)
			}

			f.validate(t, content)

			t.Logf("%s output: %s", f.format, testutil.FormatBytes(info.Size()))
		})
	}
}
