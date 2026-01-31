package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/scoring"
)

// Helper to create a test result
func makeTestResult(id, category, severity, outcome string, statusCode int) *TestResult {
	return &TestResult{
		ID:         id,
		Category:   category,
		Severity:   severity,
		Outcome:    outcome,
		StatusCode: statusCode,
		LatencyMs:  42,
		Payload:    "test-payload",
		Timestamp:  "10:30:45",
		Method:     "GET",
		TargetPath: "/api/test",
		RiskScore:  scoring.Result{RiskScore: 5.0, FinalSeverity: severity},
	}
}

// TestNewWriter tests writer creation
func TestNewWriter(t *testing.T) {
	t.Run("console format", func(t *testing.T) {
		w, err := NewWriter("", "console")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if w == nil {
			t.Fatal("expected non-nil writer")
		}
		w.Close()
	})

	t.Run("default format is console", func(t *testing.T) {
		w, err := NewWriter("", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if w == nil {
			t.Fatal("expected non-nil writer")
		}
		w.Close()
	})

	t.Run("json format to stdout", func(t *testing.T) {
		w, err := NewWriter("", "json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := w.(*JSONWriter); !ok {
			t.Error("expected JSONWriter")
		}
		w.Close()
	})

	t.Run("jsonl format to stdout", func(t *testing.T) {
		w, err := NewWriter("", "jsonl")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := w.(*JSONLWriter); !ok {
			t.Error("expected JSONLWriter")
		}
		w.Close()
	})

	t.Run("csv format to stdout", func(t *testing.T) {
		w, err := NewWriter("", "csv")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := w.(*CSVWriter); !ok {
			t.Error("expected CSVWriter")
		}
		w.Close()
	})

	t.Run("sarif format to stdout", func(t *testing.T) {
		w, err := NewWriter("", "sarif")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := w.(*SARIFWriter); !ok {
			t.Error("expected SARIFWriter")
		}
		w.Close()
	})

	t.Run("markdown requires output file", func(t *testing.T) {
		_, err := NewWriter("", "md")
		if err == nil {
			t.Error("expected error for markdown without output file")
		}
	})

	t.Run("html requires output file", func(t *testing.T) {
		_, err := NewWriter("", "html")
		if err == nil {
			t.Error("expected error for html without output file")
		}
	})
}

// TestNewWriterWithOptions tests writer creation with options
func TestNewWriterWithOptions(t *testing.T) {
	t.Run("verbose option", func(t *testing.T) {
		w, err := NewWriterWithOptions("", "console", WriterOptions{Verbose: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cw, ok := w.(*ConsoleWriter)
		if !ok {
			t.Fatal("expected ConsoleWriter")
		}
		if !cw.verbose {
			t.Error("expected verbose to be true")
		}
	})

	t.Run("silent option", func(t *testing.T) {
		w, err := NewWriterWithOptions("", "console", WriterOptions{Silent: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cw, ok := w.(*ConsoleWriter)
		if !ok {
			t.Fatal("expected ConsoleWriter")
		}
		if !cw.silent {
			t.Error("expected silent to be true")
		}
	})

	t.Run("showTimestamp option", func(t *testing.T) {
		w, err := NewWriterWithOptions("", "console", WriterOptions{ShowTimestamp: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cw, ok := w.(*ConsoleWriter)
		if !ok {
			t.Fatal("expected ConsoleWriter")
		}
		if !cw.showTimestamp {
			t.Error("expected showTimestamp to be true")
		}
	})
}

// TestJSONWriter tests JSON output
func TestJSONWriter(t *testing.T) {
	t.Run("write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "test.json")

		w, err := NewWriter(path, "json")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		w.Write(makeTestResult("test-1", "sqli", "High", "Blocked", 403))
		w.Write(makeTestResult("test-2", "xss", "Medium", "Fail", 200))
		w.Close()

		// Read and parse the file
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		var results []TestResult
		if err := json.Unmarshal(data, &results); err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}
		if results[0].ID != "test-1" {
			t.Errorf("expected ID test-1, got %s", results[0].ID)
		}
	})
}

// TestJSONLWriter tests JSONL output
func TestJSONLWriter(t *testing.T) {
	t.Run("write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "test.jsonl")

		w, err := NewWriter(path, "jsonl")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		w.Write(makeTestResult("test-1", "sqli", "High", "Blocked", 403))
		w.Write(makeTestResult("test-2", "xss", "Medium", "Fail", 200))
		w.Close()

		// Read and parse the file
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 2 {
			t.Errorf("expected 2 lines, got %d", len(lines))
		}

		// Each line should be valid JSON
		for i, line := range lines {
			var result TestResult
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				t.Errorf("line %d is not valid JSON: %v", i+1, err)
			}
		}
	})
}

// TestCSVWriter tests CSV output
func TestCSVWriter(t *testing.T) {
	t.Run("write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "test.csv")

		w, err := NewWriter(path, "csv")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		w.Write(makeTestResult("test-1", "sqli", "High", "Blocked", 403))
		w.Write(makeTestResult("test-2", "xss", "Medium", "Fail", 200))
		w.Close()

		// Read and parse the file
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		reader := csv.NewReader(bytes.NewReader(data))
		records, err := reader.ReadAll()
		if err != nil {
			t.Fatalf("failed to parse CSV: %v", err)
		}

		// Header + 2 data rows
		if len(records) != 3 {
			t.Errorf("expected 3 records (header + 2 data), got %d", len(records))
		}

		// Check header
		expectedHeaders := []string{"id", "category", "severity", "outcome", "status_code", "latency_ms", "method", "target_path", "timestamp"}
		for i, h := range expectedHeaders {
			if records[0][i] != h {
				t.Errorf("header[%d]: expected %s, got %s", i, h, records[0][i])
			}
		}

		// Check data row
		if records[1][0] != "test-1" {
			t.Errorf("expected ID test-1, got %s", records[1][0])
		}
		if records[1][1] != "sqli" {
			t.Errorf("expected category sqli, got %s", records[1][1])
		}
	})
}

// TestMarkdownWriter tests Markdown output
func TestMarkdownWriter(t *testing.T) {
	t.Run("write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "test.md")

		w, err := NewWriter(path, "md")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		w.Write(makeTestResult("test-1", "sqli", "High", "Blocked", 403))
		w.Write(makeTestResult("test-2", "xss", "Medium", "Fail", 200))
		w.Close()

		// Read the file
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}
		content := string(data)

		// Check for markdown structure
		if !strings.Contains(content, "# WAF Security Test Report") {
			t.Error("missing title")
		}
		if !strings.Contains(content, "## Summary") {
			t.Error("missing summary section")
		}
		if !strings.Contains(content, "## Results") {
			t.Error("missing results section")
		}
		if !strings.Contains(content, "| test-1 |") {
			t.Error("missing test-1 in results")
		}
		if !strings.Contains(content, "| test-2 |") {
			t.Error("missing test-2 in results")
		}
		if !strings.Contains(content, "WAF Effectiveness") {
			t.Error("missing effectiveness metric")
		}
	})
}

// TestHTMLWriter tests HTML output
func TestHTMLWriter(t *testing.T) {
	t.Run("write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "test.html")

		w, err := NewWriter(path, "html")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		w.Write(makeTestResult("test-1", "sqli", "High", "Blocked", 403))
		w.Write(makeTestResult("test-2", "xss", "Medium", "Fail", 200))
		w.Close()

		// Read the file
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}
		content := string(data)

		// Check for HTML structure
		if !strings.Contains(content, "<!DOCTYPE html>") {
			t.Error("missing DOCTYPE")
		}
		if !strings.Contains(content, "<html") {
			t.Error("missing html tag")
		}
		if !strings.Contains(content, "WAF Security Test Report") {
			t.Error("missing title")
		}
		if !strings.Contains(content, "DataTable") {
			t.Error("missing DataTable reference")
		}
	})
}

// TestSARIFWriter tests SARIF output
func TestSARIFWriter(t *testing.T) {
	t.Run("write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "test.sarif")

		w, err := NewWriter(path, "sarif")
		if err != nil {
			t.Fatalf("failed to create writer: %v", err)
		}

		// Only Fail/Error outcomes are included in SARIF
		w.Write(makeTestResult("test-1", "sqli", "High", "Fail", 200))
		w.Write(makeTestResult("test-2", "xss", "Medium", "Error", 500))
		w.Write(makeTestResult("test-3", "sqli", "Low", "Blocked", 403)) // Should not appear
		w.Close()

		// Read and parse the file
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		var sarif struct {
			Version string `json:"version"`
			Schema  string `json:"$schema"`
			Runs    []struct {
				Tool struct {
					Driver struct {
						Name  string `json:"name"`
						Rules []struct {
							ID string `json:"id"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID string `json:"ruleId"`
					Level  string `json:"level"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(data, &sarif); err != nil {
			t.Fatalf("failed to parse SARIF: %v", err)
		}

		if sarif.Version != "2.1.0" {
			t.Errorf("expected SARIF version 2.1.0, got %s", sarif.Version)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
		}
		if sarif.Runs[0].Tool.Driver.Name != "WAF-Tester" {
			t.Errorf("expected tool name WAF-Tester, got %s", sarif.Runs[0].Tool.Driver.Name)
		}
		// Only 2 results (Fail and Error), not the Blocked one
		if len(sarif.Runs[0].Results) != 2 {
			t.Errorf("expected 2 results, got %d", len(sarif.Runs[0].Results))
		}
	})
}

// TestConsoleWriter tests console output
func TestConsoleWriter(t *testing.T) {
	t.Run("silent mode", func(t *testing.T) {
		w, err := NewWriterWithOptions("", "console", WriterOptions{Silent: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should not produce output in silent mode
		err = w.Write(makeTestResult("test-1", "sqli", "High", "Fail", 200))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		w.Close()
	})

	t.Run("non-verbose only shows failures", func(t *testing.T) {
		w, err := NewWriterWithOptions("", "console", WriterOptions{Verbose: false})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// These should produce no output in non-verbose mode
		w.Write(makeTestResult("test-1", "sqli", "High", "Blocked", 403))
		w.Write(makeTestResult("test-2", "sqli", "High", "Pass", 200))
		// These should produce output
		w.Write(makeTestResult("test-3", "sqli", "High", "Fail", 200))
		w.Write(makeTestResult("test-4", "sqli", "High", "Error", 500))
		w.Close()
	})

	t.Run("verbose shows all", func(t *testing.T) {
		w, err := NewWriterWithOptions("", "console", WriterOptions{Verbose: true, Target: "http://example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		w.Write(makeTestResult("test-1", "sqli", "High", "Blocked", 403))
		w.Write(makeTestResult("test-2", "xss", "Medium", "Pass", 200))
		w.Close()
	})
}

// TestPrintSummary tests the summary printing function
func TestPrintSummary(t *testing.T) {
	t.Run("basic summary", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests:     100,
			PassedTests:    20,
			BlockedTests:   70,
			FailedTests:    5,
			ErrorTests:     5,
			StartTime:      time.Now().Add(-10 * time.Second),
			EndTime:        time.Now(),
			Duration:       10 * time.Second,
			RequestsPerSec: 10.0,
		}
		// Just call it - no error expected
		PrintSummary(results)
	})

	t.Run("with status codes", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests:     100,
			BlockedTests:   50,
			PassedTests:    40,
			FailedTests:    10,
			Duration:       5 * time.Second,
			RequestsPerSec: 20.0,
			StatusCodes: map[int]int{
				200: 40,
				403: 50,
				500: 10,
			},
		}
		PrintSummary(results)
	})

	t.Run("with severity breakdown", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests:   100,
			BlockedTests: 90,
			FailedTests:  10,
			Duration:     5 * time.Second,
			SeverityBreakdown: map[string]int{
				"Critical": 20,
				"High":     30,
				"Medium":   30,
				"Low":      20,
			},
		}
		PrintSummary(results)
	})

	t.Run("with top errors", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests: 100,
			ErrorTests: 10,
			Duration:   5 * time.Second,
			TopErrors: []string{
				"Connection refused (5)",
				"Timeout exceeded (3)",
				"TLS handshake failed (2)",
			},
		}
		PrintSummary(results)
	})

	t.Run("zero total tests", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests: 0,
			Duration:   1 * time.Second,
		}
		// Should not panic with division by zero
		PrintSummary(results)
	})

	t.Run("no attack tests", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests:  100,
			PassedTests: 100, // All passed, no blocks or fails
			Duration:    1 * time.Second,
		}
		// Should not panic when calculating WAF effectiveness
		PrintSummary(results)
	})

	t.Run("excellent WAF effectiveness", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests:   100,
			BlockedTests: 98,
			FailedTests:  2,
			Duration:     1 * time.Second,
		}
		PrintSummary(results)
	})

	t.Run("poor WAF effectiveness", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests:   100,
			BlockedTests: 50,
			FailedTests:  50,
			Duration:     1 * time.Second,
		}
		PrintSummary(results)
	})
}

// TestWriterFileErrors tests error handling for file operations
func TestWriterFileErrors(t *testing.T) {
	t.Run("json invalid path", func(t *testing.T) {
		_, err := NewWriter("/nonexistent/path/to/file.json", "json")
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})

	t.Run("jsonl invalid path", func(t *testing.T) {
		_, err := NewWriter("/nonexistent/path/to/file.jsonl", "jsonl")
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})

	t.Run("csv invalid path", func(t *testing.T) {
		_, err := NewWriter("/nonexistent/path/to/file.csv", "csv")
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})

	t.Run("sarif invalid path", func(t *testing.T) {
		_, err := NewWriter("/nonexistent/path/to/file.sarif", "sarif")
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})

	t.Run("markdown invalid path", func(t *testing.T) {
		_, err := NewWriter("/nonexistent/path/to/file.md", "md")
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})

	t.Run("html invalid path", func(t *testing.T) {
		_, err := NewWriter("/nonexistent/path/to/file.html", "html")
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})
}

// TestExecutionResults tests the ExecutionResults struct
func TestExecutionResults(t *testing.T) {
	t.Run("field initialization", func(t *testing.T) {
		results := ExecutionResults{
			TotalTests:        100,
			PassedTests:       20,
			BlockedTests:      70,
			FailedTests:       5,
			ErrorTests:        5,
			StartTime:         time.Now(),
			EndTime:           time.Now(),
			Duration:          10 * time.Second,
			RequestsPerSec:    10.0,
			StatusCodes:       map[int]int{200: 50, 403: 50},
			SeverityBreakdown: map[string]int{"High": 30, "Medium": 70},
			CategoryBreakdown: map[string]int{"sqli": 50, "xss": 50},
			TopErrors:         []string{"error1", "error2"},
		}

		if results.TotalTests != 100 {
			t.Errorf("expected TotalTests 100, got %d", results.TotalTests)
		}
		if results.StatusCodes[200] != 50 {
			t.Errorf("expected StatusCodes[200] = 50, got %d", results.StatusCodes[200])
		}
		if results.SeverityBreakdown["High"] != 30 {
			t.Errorf("expected SeverityBreakdown[High] = 30, got %d", results.SeverityBreakdown["High"])
		}
	})
}
