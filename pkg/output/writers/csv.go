// Package writers provides output writers for various formats.
package writers

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*CSVWriter)(nil)

// UTF-8 BOM for Excel compatibility.
const utf8BOM = "\xEF\xBB\xBF"

// Default timestamp format (RFC3339).
const defaultTimestampFormat = "2006-01-02T15:04:05Z07:00"

// CSVWriter writes events as CSV rows.
// Each row represents a single test result, making it ideal for
// data analysis in tools like Excel, pandas, or database imports.
//
// Features:
//   - Gold-standard 20 column format for security analysts
//   - Excel compatibility with UTF-8 BOM
//   - CSV injection prevention (formula sanitization)
//   - Summary row support
type CSVWriter struct {
	w             io.Writer
	csvWriter     *csv.Writer
	mu            sync.Mutex
	opts          CSVOptions
	headerWritten bool
	summary       *events.SummaryEvent // Store summary for Close()
}

// CSVOptions configures the CSV writer behavior.
type CSVOptions struct {
	// IncludeHeader includes a header row with column names.
	IncludeHeader bool

	// Delimiter sets the field delimiter character.
	// Default is comma when zero value.
	Delimiter rune

	// ExcelCompatible adds UTF-8 BOM for Excel compatibility.
	// This ensures proper display of Unicode characters in Excel.
	ExcelCompatible bool

	// SanitizeFormulas prevents CSV injection by prefixing dangerous characters.
	// Dangerous characters: = + - @ TAB CR
	SanitizeFormulas bool

	// TimestampFormat sets the timestamp format (default: RFC3339).
	TimestampFormat string

	// TruncateAt limits field length (0 = no limit).
	TruncateAt int
}

// csvColumns defines the gold-standard CSV column headers.
// Order optimized for security analyst workflow.
var csvColumns = []string{
	// Core Identification
	"id",        // Unique finding ID
	"timestamp", // ISO 8601 timestamp (RFC3339)

	// Classification
	"severity",   // CRITICAL/HIGH/MEDIUM/LOW/INFO
	"confidence", // HIGH/MEDIUM/LOW
	"category",   // Attack type (SQL Injection, XSS, etc.)
	"rule_id",    // Internal rule identifier
	"cwe_id",     // CWE-89, CWE-79, etc.
	"cvss_score", // CVSS score if available

	// Test Result
	"outcome",     // BLOCKED/BYPASS/ERROR/TIMEOUT
	"status_code", // HTTP status code
	"latency_ms",  // Response latency

	// Target Info
	"target_url", // Full URL
	"method",     // HTTP method
	"parameter",  // Injection point/parameter name

	// Evidence
	"payload",  // Attack payload used
	"evidence", // Detection evidence (response pattern)

	// Metadata
	"owasp",       // OWASP category codes
	"remediation", // Fix guidance
	"test_group",  // Test grouping for filtering
	"description", // Human-readable finding description
}

// sanitizeForCSV prevents CSV injection by prefixing dangerous characters.
// This is a SECURITY feature to prevent formula execution in spreadsheets.
func sanitizeForCSV(s string) string {
	if len(s) == 0 {
		return s
	}
	// Characters that can trigger formula execution in spreadsheets
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s // Prefix with single quote
	}
	return s
}

// truncateField truncates a field to the specified length.
func truncateField(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen > 3 {
		return string(runes[:maxLen-3]) + "..."
	}
	return string(runes[:maxLen])
}

// NewCSVWriter creates a new CSV writer with gold-standard features.
// If IncludeHeader is true, a header row is written immediately.
// If ExcelCompatible is true, a UTF-8 BOM is written for proper Excel display.
// The writer is safe for concurrent use.
func NewCSVWriter(w io.Writer, opts CSVOptions) *CSVWriter {
	// Set defaults
	if opts.TimestampFormat == "" {
		opts.TimestampFormat = defaultTimestampFormat
	}

	// Write UTF-8 BOM for Excel compatibility
	if opts.ExcelCompatible {
		_, _ = w.Write([]byte(utf8BOM))
	}

	csvWriter := csv.NewWriter(w)
	if opts.Delimiter != 0 {
		csvWriter.Comma = opts.Delimiter
	}

	cw := &CSVWriter{
		w:         w,
		csvWriter: csvWriter,
		opts:      opts,
	}

	// Write header by default
	if opts.IncludeHeader {
		_ = csvWriter.Write(csvColumns)
		csvWriter.Flush()
		cw.headerWritten = true
	}

	return cw
}

// Write writes a result event as a CSV row with all gold-standard columns.
// Summary events are captured for output on Close().
// Other event types are silently skipped.
func (cw *CSVWriter) Write(event events.Event) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	switch e := event.(type) {
	case *events.ResultEvent:
		return cw.writeResult(e)
	case *events.SummaryEvent:
		cw.summary = e
		return nil
	default:
		return nil // Skip other event types
	}
}

// writeResult writes a single result event as a CSV row.
func (cw *CSVWriter) writeResult(re *events.ResultEvent) error {
	// Extract evidence fields
	payload := ""
	evidence := ""
	if re.Evidence != nil {
		payload = re.Evidence.Payload
		evidence = re.Evidence.ResponsePreview
		if len([]rune(evidence)) > 500 {
			evidence = string([]rune(evidence)[:500]) + "..."
		}
	}

	// Build CWE string
	cweStr := ""
	if len(re.Test.CWE) > 0 {
		cwes := make([]string, len(re.Test.CWE))
		for i, cwe := range re.Test.CWE {
			cwes[i] = fmt.Sprintf("CWE-%d", cwe)
		}
		cweStr = strings.Join(cwes, ";")
	}

	// Build OWASP string
	owaspStr := ""
	if len(re.Test.OWASP) > 0 {
		owaspStr = strings.Join(re.Test.OWASP, ";")
	}

	// Determine confidence based on status code patterns
	confidence := "MEDIUM"
	if re.Result.StatusCode == 403 || re.Result.StatusCode == 406 ||
		re.Result.StatusCode == 429 || re.Result.StatusCode == 503 {
		confidence = "HIGH"
	} else if re.Result.StatusCode >= 500 {
		confidence = "LOW"
	}

	// Build row with all columns (matches csvColumns order)
	row := []string{
		re.Test.ID, // id
		re.Timestamp().Format(cw.opts.TimestampFormat), // timestamp
		strings.ToUpper(string(re.Test.Severity)),      // severity
		confidence,       // confidence
		re.Test.Category, // category
		re.Test.ID,       // rule_id (same as id for now)
		cweStr,           // cwe_id
		"",               // cvss_score (not available)
		strings.ToUpper(string(re.Result.Outcome)),           // outcome
		strconv.Itoa(re.Result.StatusCode),                   // status_code
		strconv.FormatFloat(re.Result.LatencyMs, 'f', 2, 64), // latency_ms
		re.Target.URL,       // target_url
		re.Target.Method,    // method
		re.Target.Parameter, // parameter
		payload,             // payload
		evidence,            // evidence
		owaspStr,            // owasp
		"",                  // remediation (not available)
		re.Test.Category,    // test_group
		re.Test.Name,        // description
	}

	// Apply sanitization and truncation
	for i, field := range row {
		if cw.opts.SanitizeFormulas {
			field = sanitizeForCSV(field)
		}
		if cw.opts.TruncateAt > 0 {
			field = truncateField(field, cw.opts.TruncateAt)
		}
		row[i] = field
	}

	return cw.csvWriter.Write(row)
}

// Flush flushes the CSV writer's internal buffer.
func (cw *CSVWriter) Flush() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.csvWriter.Flush()
	return cw.csvWriter.Error()
}

// Close flushes the CSV writer and writes summary if available.
// If the underlying writer implements io.Closer, it will be closed.
func (cw *CSVWriter) Close() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	// Write summary if available
	if cw.summary != nil {
		cw.writeSummaryLocked()
	}

	cw.csvWriter.Flush()
	if err := cw.csvWriter.Error(); err != nil {
		return fmt.Errorf("csv: flush: %w", err)
	}

	if closer, ok := cw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// writeSummaryLocked writes a summary section at the end of the CSV.
// Must be called with mu held.
func (cw *CSVWriter) writeSummaryLocked() {
	if cw.summary == nil {
		return
	}

	// Write blank row as separator
	_ = cw.csvWriter.Write([]string{})

	// Write summary rows
	_ = cw.csvWriter.Write([]string{"# SUMMARY"})
	_ = cw.csvWriter.Write([]string{"Total Tests", strconv.Itoa(cw.summary.Totals.Tests)})
	_ = cw.csvWriter.Write([]string{"Blocked", strconv.Itoa(cw.summary.Totals.Blocked)})
	_ = cw.csvWriter.Write([]string{"Bypasses", strconv.Itoa(cw.summary.Totals.Bypasses)})
	_ = cw.csvWriter.Write([]string{"Block Rate", fmt.Sprintf("%.1f%%", cw.summary.Effectiveness.BlockRatePct)})
	_ = cw.csvWriter.Write([]string{"Grade", cw.summary.Effectiveness.Grade})
}

// SupportsEvent returns true for result and summary events.
// CSV format supports tabular result data and summary statistics.
func (cw *CSVWriter) SupportsEvent(eventType events.EventType) bool {
	return eventType == events.EventTypeResult || eventType == events.EventTypeSummary
}
