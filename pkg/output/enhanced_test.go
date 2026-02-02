package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/scoring"
)

func TestEJSONWriter(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "test.ejson.json")

	metadata := &ExecutionMetadata{
		StartTime:   time.Now(),
		Target:      "http://example.com",
		CommandLine: "waf-tester -u http://example.com",
		Version:     defaults.Version,
	}

	writer, err := NewEJSONWriter(outPath, metadata)
	if err != nil {
		t.Fatalf("failed to create EJSONWriter: %v", err)
	}

	// Write test results
	results := []*TestResult{
		{
			ID:         "test-1",
			Category:   "sqli",
			Severity:   "High",
			Outcome:    "Blocked",
			StatusCode: 403,
			LatencyMs:  50,
			RiskScore:  scoring.Result{RiskScore: 2.1},
		},
		{
			ID:         "test-2",
			Category:   "xss",
			Severity:   "Medium",
			Outcome:    "Pass",
			StatusCode: 200,
			LatencyMs:  100,
			RiskScore:  scoring.Result{RiskScore: 0.5},
		},
		{
			ID:         "test-3",
			Category:   "rce",
			Severity:   "Critical",
			Outcome:    "Fail",
			StatusCode: 200,
			LatencyMs:  200,
			RiskScore:  scoring.Result{RiskScore: 15.0},
		},
	}

	for _, r := range results {
		if err := writer.Write(r); err != nil {
			t.Fatalf("failed to write result: %v", err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	// Read and verify output
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var output EJSONOutput
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("failed to parse EJSON output: %v", err)
	}

	// Verify metadata
	if output.Metadata.Target != "http://example.com" {
		t.Errorf("expected target http://example.com, got %s", output.Metadata.Target)
	}
	if output.Metadata.TotalRequests != 3 {
		t.Errorf("expected 3 total requests, got %d", output.Metadata.TotalRequests)
	}

	// Verify results
	if len(output.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(output.Results))
	}

	// Verify summary
	if output.Summary.Total != 3 {
		t.Errorf("expected total 3, got %d", output.Summary.Total)
	}
	if output.Summary.Blocked != 1 {
		t.Errorf("expected 1 blocked, got %d", output.Summary.Blocked)
	}
	if output.Summary.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", output.Summary.Passed)
	}
	if output.Summary.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", output.Summary.Failed)
	}

	// Verify category breakdown
	if output.Summary.ByCategory["sqli"] != 1 {
		t.Errorf("expected 1 sqli, got %d", output.Summary.ByCategory["sqli"])
	}
}

func TestECSVWriter(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "test.ecsv.csv")

	writer, err := NewECSVWriter(outPath)
	if err != nil {
		t.Fatalf("failed to create ECSVWriter: %v", err)
	}

	result := &TestResult{
		ID:          "csv-test-1",
		Category:    "sqli",
		Severity:    "High",
		Outcome:     "Blocked",
		StatusCode:  403,
		LatencyMs:   50,
		Method:      "POST",
		TargetPath:  "/api/login",
		ContentType: "application/json",
		Payload:     "' OR 1=1--",
		Timestamp:   "2024-01-01T12:00:00Z",
		RiskScore:   scoring.Result{RiskScore: 2.1},
	}

	if err := writer.Write(result); err != nil {
		t.Fatalf("failed to write result: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	content := string(data)

	// Check header
	if !strings.Contains(content, "id,category,severity,outcome,status_code") {
		t.Error("missing CSV header")
	}

	// Check data
	if !strings.Contains(content, "csv-test-1") {
		t.Error("missing test ID in CSV")
	}
	if !strings.Contains(content, "403") {
		t.Error("missing status code in CSV")
	}
}

func TestTaggedWriter(t *testing.T) {
	// Use a mock writer
	mock := &mockWriter{results: make([]*TestResult, 0)}
	tagged := NewTaggedWriter(mock, "wayback")

	result := &TestResult{
		ID:       "test-1",
		Category: "sqli",
	}

	if err := tagged.Write(result); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if err := tagged.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	// Verify tag was added
	if len(mock.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(mock.results))
	}
	if !strings.Contains(mock.results[0].ID, "[wayback]") {
		t.Errorf("expected tagged ID, got %s", mock.results[0].ID)
	}
}

// mockWriter for testing
type mockWriter struct {
	results []*TestResult
	closed  bool
}

func (m *mockWriter) Write(result *TestResult) error {
	m.results = append(m.results, result)
	return nil
}

func (m *mockWriter) Close() error {
	m.closed = true
	return nil
}

func TestTemplateWriter(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "template.txt")

	writer, err := NewTemplateWriter(outPath, TemplateSimple)
	if err != nil {
		t.Fatalf("failed to create TemplateWriter: %v", err)
	}

	result := &TestResult{
		ID:         "tmpl-test",
		Category:   "xss",
		Outcome:    "Blocked",
		StatusCode: 403,
		LatencyMs:  75,
	}

	if err := writer.Write(result); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "Blocked") {
		t.Error("missing Blocked in output")
	}
	if !strings.Contains(content, "403") {
		t.Error("missing status code in output")
	}
	if !strings.Contains(content, "75ms") {
		t.Error("missing latency in output")
	}
}

func TestTemplateKatanaStyle(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "katana.txt")

	writer, err := NewTemplateWriter(outPath, TemplateKatanaStyle)
	if err != nil {
		t.Fatalf("failed to create TemplateWriter: %v", err)
	}

	result := &TestResult{
		Category:   "sqli",
		Outcome:    "Fail",
		TargetPath: "/api/users?id=1",
	}

	if err := writer.Write(result); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	writer.Close()

	data, _ := os.ReadFile(outPath)
	content := string(data)

	// Should be: [Fail] [sqli] /api/users?id=1
	if !strings.Contains(content, "[Fail]") {
		t.Error("missing [Fail] tag")
	}
	if !strings.Contains(content, "[sqli]") {
		t.Error("missing [sqli] tag")
	}
	if !strings.Contains(content, "/api/users?id=1") {
		t.Error("missing target path")
	}
}

func TestTemplateNucleiStyle(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "nuclei.txt")

	writer, err := NewTemplateWriter(outPath, TemplateNucleiStyle)
	if err != nil {
		t.Fatalf("failed to create TemplateWriter: %v", err)
	}

	result := &TestResult{
		ID:         "CVE-2024-1234",
		Category:   "rce",
		Severity:   "Critical",
		TargetPath: "/admin/shell",
		StatusCode: 200,
	}

	if err := writer.Write(result); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	writer.Close()

	data, _ := os.ReadFile(outPath)
	content := string(data)

	// Should be: [Critical] [rce] [CVE-2024-1234] /admin/shell [200]
	if !strings.Contains(content, "[Critical]") {
		t.Error("missing [Critical] tag")
	}
	if !strings.Contains(content, "[rce]") {
		t.Error("missing [rce] tag")
	}
	if !strings.Contains(content, "[CVE-2024-1234]") {
		t.Error("missing ID tag")
	}
}

func TestMultiWriter(t *testing.T) {
	mock1 := &mockWriter{results: make([]*TestResult, 0)}
	mock2 := &mockWriter{results: make([]*TestResult, 0)}
	mock3 := &mockWriter{results: make([]*TestResult, 0)}

	multi := NewMultiWriter(mock1, mock2, mock3)

	result := &TestResult{
		ID:       "multi-test",
		Category: "sqli",
	}

	if err := multi.Write(result); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// All writers should have the result
	if len(mock1.results) != 1 {
		t.Error("mock1 missing result")
	}
	if len(mock2.results) != 1 {
		t.Error("mock2 missing result")
	}
	if len(mock3.results) != 1 {
		t.Error("mock3 missing result")
	}

	if err := multi.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	if !mock1.closed || !mock2.closed || !mock3.closed {
		t.Error("not all writers closed")
	}
}

func TestEJSONWriterWithNilMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "nil-meta.ejson.json")

	// Should create default metadata
	writer, err := NewEJSONWriter(outPath, nil)
	if err != nil {
		t.Fatalf("failed to create writer with nil metadata: %v", err)
	}

	result := &TestResult{
		ID:       "test",
		Category: "test",
		Outcome:  "Pass",
	}
	writer.Write(result)
	writer.Close()

	data, _ := os.ReadFile(outPath)
	var output EJSONOutput
	json.Unmarshal(data, &output)

	if output.Metadata == nil {
		t.Error("metadata should not be nil")
	}
	if output.Metadata.Version != defaults.Version {
		t.Errorf("expected version %s, got %s", defaults.Version, output.Metadata.Version)
	}
}

func TestSummaryStatsComputation(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "summary.ejson.json")

	writer, _ := NewEJSONWriter(outPath, nil)

	// Write various outcomes
	outcomes := []string{"Pass", "Pass", "Blocked", "Blocked", "Blocked", "Fail", "Error"}
	for i, outcome := range outcomes {
		writer.Write(&TestResult{
			ID:         string(rune('a' + i)),
			Outcome:    outcome,
			Category:   "test",
			Severity:   "Medium",
			StatusCode: 200,
		})
	}
	writer.Close()

	data, _ := os.ReadFile(outPath)
	var output EJSONOutput
	json.Unmarshal(data, &output)

	if output.Summary.Passed != 2 {
		t.Errorf("expected 2 passed, got %d", output.Summary.Passed)
	}
	if output.Summary.Blocked != 3 {
		t.Errorf("expected 3 blocked, got %d", output.Summary.Blocked)
	}
	if output.Summary.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", output.Summary.Failed)
	}
	if output.Summary.Errors != 1 {
		t.Errorf("expected 1 error, got %d", output.Summary.Errors)
	}
}

func TestECSVWriterMultipleRows(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "multi.ecsv.csv")

	writer, _ := NewECSVWriter(outPath)

	for i := 0; i < 5; i++ {
		writer.Write(&TestResult{
			ID:         string(rune('a' + i)),
			Category:   "sqli",
			StatusCode: 403,
			RiskScore:  scoring.Result{RiskScore: float64(i)},
		})
	}
	writer.Close()

	data, _ := os.ReadFile(outPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	// Should have 1 header + 5 data rows
	if len(lines) != 6 {
		t.Errorf("expected 6 lines (1 header + 5 data), got %d", len(lines))
	}
}

func TestTemplateInvalidTemplate(t *testing.T) {
	_, err := NewTemplateWriter("", "{{.Invalid")
	if err == nil {
		t.Error("expected error for invalid template")
	}
}

func TestEJSONWriterStdout(t *testing.T) {
	// Empty path should write to stdout
	writer, err := NewEJSONWriter("", nil)
	if err != nil {
		t.Fatalf("failed to create stdout writer: %v", err)
	}
	if writer.file != os.Stdout {
		t.Error("expected stdout file")
	}
	// Don't close stdout
}

func TestECSVWriterStdout(t *testing.T) {
	writer, err := NewECSVWriter("")
	if err != nil {
		t.Fatalf("failed to create stdout writer: %v", err)
	}
	if writer.file != os.Stdout {
		t.Error("expected stdout file")
	}
}

func TestTemplateWriterStdout(t *testing.T) {
	writer, err := NewTemplateWriter("", TemplateSimple)
	if err != nil {
		t.Fatalf("failed to create stdout writer: %v", err)
	}
	if writer.file != os.Stdout {
		t.Error("expected stdout file")
	}
}
