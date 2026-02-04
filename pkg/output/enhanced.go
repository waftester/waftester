package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
)

// EJSONWriter writes enhanced JSON with execution metadata
// Based on ffuf's ejson format
type EJSONWriter struct {
	file     *os.File
	results  []*TestResult
	metadata *ExecutionMetadata
	mu       sync.Mutex
}

// ExecutionMetadata holds execution context for enhanced output
type ExecutionMetadata struct {
	StartTime     time.Time         `json:"start_time"`
	EndTime       time.Time         `json:"end_time"`
	Duration      time.Duration     `json:"duration_ms"`
	Target        string            `json:"target"`
	CommandLine   string            `json:"command_line,omitempty"`
	Version       string            `json:"version"`
	TotalRequests int               `json:"total_requests"`
	Config        map[string]string `json:"config,omitempty"`
	
	// Network configuration (v2.6.3)
	Proxy       string `json:"proxy,omitempty"`
	ReplayProxy string `json:"replay_proxy,omitempty"`
	SNI         string `json:"sni,omitempty"`
}

// EJSONOutput represents the enhanced JSON output structure
type EJSONOutput struct {
	Metadata *ExecutionMetadata `json:"metadata"`
	Results  []*TestResult      `json:"results"`
	Summary  *SummaryStats      `json:"summary"`
}

// SummaryStats provides aggregate statistics
type SummaryStats struct {
	Total      int            `json:"total"`
	Passed     int            `json:"passed"`
	Blocked    int            `json:"blocked"`
	Failed     int            `json:"failed"`
	Errors     int            `json:"errors"`
	ByCategory map[string]int `json:"by_category"`
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[int]int    `json:"by_status"`
}

// NewEJSONWriter creates a new enhanced JSON writer
func NewEJSONWriter(path string, metadata *ExecutionMetadata) (*EJSONWriter, error) {
	if metadata == nil {
		metadata = &ExecutionMetadata{
			StartTime: time.Now(),
			Version:   defaults.Version,
		}
	}
	if path == "" {
		return &EJSONWriter{file: os.Stdout, metadata: metadata}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &EJSONWriter{
		file:     file,
		results:  make([]*TestResult, 0),
		metadata: metadata,
	}, nil
}

func (w *EJSONWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, result)
	return nil
}

func (w *EJSONWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.metadata.EndTime = time.Now()
	w.metadata.Duration = w.metadata.EndTime.Sub(w.metadata.StartTime)
	w.metadata.TotalRequests = len(w.results)

	output := EJSONOutput{
		Metadata: w.metadata,
		Results:  w.results,
		Summary:  w.computeSummary(),
	}

	encoder := json.NewEncoder(w.file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return err
	}

	if w.file != os.Stdout {
		return w.file.Close()
	}
	return nil
}

func (w *EJSONWriter) computeSummary() *SummaryStats {
	stats := &SummaryStats{
		ByCategory: make(map[string]int),
		BySeverity: make(map[string]int),
		ByStatus:   make(map[int]int),
	}

	for _, r := range w.results {
		stats.Total++
		switch r.Outcome {
		case "Pass":
			stats.Passed++
		case "Blocked":
			stats.Blocked++
		case "Fail":
			stats.Failed++
		case "Error":
			stats.Errors++
		}
		stats.ByCategory[r.Category]++
		stats.BySeverity[r.Severity]++
		stats.ByStatus[r.StatusCode]++
	}

	return stats
}

// ECSVWriter writes enhanced CSV with additional columns
// Based on ffuf's ecsv format
type ECSVWriter struct {
	file      *os.File
	writer    *csv.Writer
	mu        sync.Mutex
	hasHeader bool
}

// NewECSVWriter creates a new enhanced CSV writer
func NewECSVWriter(path string) (*ECSVWriter, error) {
	if path == "" {
		return &ECSVWriter{file: os.Stdout, writer: csv.NewWriter(os.Stdout)}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &ECSVWriter{file: file, writer: csv.NewWriter(file)}, nil
}

func (w *ECSVWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Write header on first result
	if !w.hasHeader {
		header := []string{
			"id", "category", "severity", "outcome", "status_code",
			"latency_ms", "method", "target_path", "content_type",
			"payload", "error_message", "timestamp", "risk_score",
		}
		if err := w.writer.Write(header); err != nil {
			return err
		}
		w.hasHeader = true
	}

	record := []string{
		result.ID,
		result.Category,
		result.Severity,
		result.Outcome,
		fmt.Sprintf("%d", result.StatusCode),
		fmt.Sprintf("%d", result.LatencyMs),
		result.Method,
		result.TargetPath,
		result.ContentType,
		result.Payload,
		result.ErrorMessage,
		result.Timestamp,
		fmt.Sprintf("%.2f", result.RiskScore.RiskScore),
	}

	return w.writer.Write(record)
}

func (w *ECSVWriter) Close() error {
	w.writer.Flush()
	if w.file != os.Stdout {
		return w.file.Close()
	}
	return nil
}

// TaggedWriter wraps another writer and adds source tags (gospider-style)
type TaggedWriter struct {
	inner  Writer
	source string
}

// NewTaggedWriter creates a writer that prefixes output with source tags
func NewTaggedWriter(inner Writer, source string) *TaggedWriter {
	return &TaggedWriter{
		inner:  inner,
		source: source,
	}
}

func (w *TaggedWriter) Write(result *TestResult) error {
	// Add source prefix to payload or ID
	if w.source != "" {
		result.ID = fmt.Sprintf("[%s] %s", w.source, result.ID)
	}
	return w.inner.Write(result)
}

func (w *TaggedWriter) Close() error {
	return w.inner.Close()
}

// TemplateWriter uses Go templates for custom output format (katana-style)
type TemplateWriter struct {
	file     *os.File
	template *template.Template
	mu       sync.Mutex
}

// NewTemplateWriter creates a writer using a custom Go template
func NewTemplateWriter(path string, templateStr string) (*TemplateWriter, error) {
	tmpl, err := template.New("output").Parse(templateStr)
	if err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}

	var file *os.File
	if path == "" {
		file = os.Stdout
	} else {
		file, err = os.Create(path)
		if err != nil {
			return nil, err
		}
	}

	return &TemplateWriter{file: file, template: tmpl}, nil
}

func (w *TemplateWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var buf bytes.Buffer
	if err := w.template.Execute(&buf, result); err != nil {
		return err
	}

	_, err := fmt.Fprintln(w.file, buf.String())
	return err
}

func (w *TemplateWriter) Close() error {
	if w.file != os.Stdout {
		return w.file.Close()
	}
	return nil
}

// MultiWriter writes to multiple outputs simultaneously
type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter creates a writer that outputs to all formats
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (w *MultiWriter) Write(result *TestResult) error {
	var lastErr error
	for _, writer := range w.writers {
		if err := writer.Write(result); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (w *MultiWriter) Close() error {
	var lastErr error
	for _, writer := range w.writers {
		if err := writer.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// NewAllFormatsWriter creates writers for all supported formats
func NewAllFormatsWriter(basePath string, metadata *ExecutionMetadata) (*MultiWriter, error) {
	if basePath == "" {
		basePath = "output"
	}

	// Remove extension if present
	basePath = strings.TrimSuffix(basePath, ".json")
	basePath = strings.TrimSuffix(basePath, ".csv")
	basePath = strings.TrimSuffix(basePath, ".html")
	basePath = strings.TrimSuffix(basePath, ".md")

	writers := make([]Writer, 0)

	// JSON
	if w, err := newJSONWriter(basePath + ".json"); err == nil {
		writers = append(writers, w)
	}

	// EJSON
	if w, err := NewEJSONWriter(basePath+".ejson.json", metadata); err == nil {
		writers = append(writers, w)
	}

	// CSV
	if w, err := newCSVWriter(basePath + ".csv"); err == nil {
		writers = append(writers, w)
	}

	// ECSV
	if w, err := NewECSVWriter(basePath + ".ecsv.csv"); err == nil {
		writers = append(writers, w)
	}

	// HTML
	if w, err := newHTMLWriter(basePath + ".html"); err == nil {
		writers = append(writers, w)
	}

	// Markdown
	if w, err := newMarkdownWriter(basePath + ".md"); err == nil {
		writers = append(writers, w)
	}

	if len(writers) == 0 {
		return nil, fmt.Errorf("failed to create any output writers")
	}

	return NewMultiWriter(writers...), nil
}

// Common templates for quick use
const (
	// TemplateSimple outputs just the essential info
	TemplateSimple = "{{.Outcome}}: {{.Category}}/{{.ID}} [{{.StatusCode}}] {{.LatencyMs}}ms"

	// TemplateURLOnly outputs just the target path
	TemplateURLOnly = "{{.TargetPath}}"

	// TemplateKatanaStyle mimics katana's output format
	TemplateKatanaStyle = "[{{.Outcome}}] [{{.Category}}] {{.TargetPath}}"

	// TemplateNucleiStyle mimics nuclei's output format
	TemplateNucleiStyle = "[{{.Severity}}] [{{.Category}}] [{{.ID}}] {{.TargetPath}} [{{.StatusCode}}]"

	// TemplateFfufStyle mimics ffuf's output format
	TemplateFfufStyle = "{{.TargetPath}} [Status: {{.StatusCode}}, Size: 0, Words: 0, Lines: 0]"
)
