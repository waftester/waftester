// Package writers provides output writers for various formats.
package writers

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*XMLWriter)(nil)

// XMLWriter writes events in XML format for legacy compliance systems.
// Output conforms to a DTD-style structure compatible with enterprise SIEM
// and vulnerability management platforms.
type XMLWriter struct {
	w      io.Writer
	mu     sync.Mutex
	opts   XMLOptions
	buffer []events.Event
}

// XMLOptions configures XML writer behavior.
type XMLOptions struct {
	// CreatorName identifies the scanning tool
	CreatorName string

	// CreatorVersion is the tool version
	CreatorVersion string

	// IncludeEvidence includes request/response data
	IncludeEvidence bool

	// SchemaURL is the DTD/XSD schema URL for validation
	SchemaURL string

	// PrettyPrint enables indented output
	PrettyPrint bool
}

// xmlDocument is the root XML element.
type xmlDocument struct {
	XMLName     xml.Name     `xml:"waftester-report"`
	Version     string       `xml:"version,attr"`
	GeneratedAt string       `xml:"generatedAt,attr"`
	SchemaURL   string       `xml:"schemaLocation,attr,omitempty"`
	Generator   xmlGenerator `xml:"generator"`
	Target      xmlTarget    `xml:"target"`
	Summary     xmlSummary   `xml:"summary"`
	Results     xmlResults   `xml:"results"`
}

// xmlGenerator identifies the tool that created the report.
type xmlGenerator struct {
	Name    string `xml:"name"`
	Version string `xml:"version"`
	URL     string `xml:"url,omitempty"`
}

// xmlTarget describes the scan target.
type xmlTarget struct {
	URL       string `xml:"url"`
	WAFVendor string `xml:"wafVendor,omitempty"`
}

// xmlSummary contains aggregate scan statistics.
type xmlSummary struct {
	TotalTests     int     `xml:"totalTests"`
	BlockedTests   int     `xml:"blockedTests"`
	PassedTests    int     `xml:"passedTests"`
	ErrorTests     int     `xml:"errorTests"`
	DetectionRate  float64 `xml:"detectionRate"`
	BypassCount    int     `xml:"bypassCount"`
	TotalLatencyMs int64   `xml:"totalLatencyMs"`
	StartTime      string  `xml:"startTime,omitempty"`
	EndTime        string  `xml:"endTime,omitempty"`
}

// xmlResults contains all test results.
type xmlResults struct {
	Result []xmlResult `xml:"result"`
}

// xmlResult represents a single test result.
type xmlResult struct {
	ID         string         `xml:"id,attr"`
	Category   string         `xml:"category"`
	Severity   string         `xml:"severity"`
	Outcome    string         `xml:"outcome"`
	Confidence string         `xml:"confidence,omitempty"`
	StatusCode int            `xml:"statusCode"`
	LatencyMs  float64        `xml:"latencyMs"`
	Target     xmlReqTarget   `xml:"target"`
	Evidence   *xmlEvidence   `xml:"evidence,omitempty"`
	Compliance *xmlCompliance `xml:"compliance,omitempty"`
}

// xmlReqTarget describes the request target.
type xmlReqTarget struct {
	URL    string `xml:"url"`
	Method string `xml:"method"`
}

// xmlEvidence contains forensic evidence.
type xmlEvidence struct {
	Payload         string `xml:"payload,omitempty"`
	ResponsePreview string `xml:"responsePreview,omitempty"`
	WAFSignature    string `xml:"wafSignature,omitempty"`
}

// xmlCompliance maps to security standards.
type xmlCompliance struct {
	CWE  string `xml:"cwe,omitempty"`
	CVE  string `xml:"cve,omitempty"`
	WASC string `xml:"wasc,omitempty"`
}

// NewXMLWriter creates a new XML writer.
func NewXMLWriter(w io.Writer, opts XMLOptions) *XMLWriter {
	if opts.CreatorName == "" {
		opts.CreatorName = defaults.ToolName
	}
	if opts.CreatorVersion == "" {
		opts.CreatorVersion = defaults.Version
	}

	return &XMLWriter{
		w:      w,
		opts:   opts,
		buffer: make([]events.Event, 0),
	}
}

// SupportsEvent returns true for result events.
func (xw *XMLWriter) SupportsEvent(eventType events.EventType) bool {
	return eventType == events.EventTypeResult
}

// Write buffers an event for later XML output.
func (xw *XMLWriter) Write(event events.Event) error {
	xw.mu.Lock()
	defer xw.mu.Unlock()

	if _, ok := event.(*events.ResultEvent); ok {
		xw.buffer = append(xw.buffer, event)
	}
	return nil
}

// Flush is a no-op for XML writer.
func (xw *XMLWriter) Flush() error {
	return nil
}

// Close writes the complete XML document and closes the writer.
func (xw *XMLWriter) Close() error {
	xw.mu.Lock()
	defer xw.mu.Unlock()

	doc := xw.buildDocument()

	// Write XML header
	if _, err := xw.w.Write([]byte(xml.Header)); err != nil {
		return fmt.Errorf("xml: write header: %w", err)
	}

	// Write document
	encoder := xml.NewEncoder(xw.w)
	if xw.opts.PrettyPrint {
		encoder.Indent("", "  ")
	}

	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("xml: encode: %w", err)
	}

	// Close underlying writer if applicable
	if closer, ok := xw.w.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// buildDocument creates the XML document from buffered events.
func (xw *XMLWriter) buildDocument() xmlDocument {
	doc := xmlDocument{
		Version:     "1.0",
		GeneratedAt: time.Now().Format(time.RFC3339),
		SchemaURL:   xw.opts.SchemaURL,
		Generator: xmlGenerator{
			Name:    xw.opts.CreatorName,
			Version: xw.opts.CreatorVersion,
			URL:     "https://github.com/waftester/waftester",
		},
		Results: xmlResults{
			Result: make([]xmlResult, 0, len(xw.buffer)),
		},
	}

	// Track summary statistics
	var totalTests, blocked, passed, errors int
	var totalLatency float64
	var targetURL, wafVendor string
	var bypasses int

	for _, event := range xw.buffer {
		re, ok := event.(*events.ResultEvent)
		if !ok {
			continue
		}

		totalTests++
		totalLatency += re.Result.LatencyMs

		// Set target from first result
		if targetURL == "" {
			targetURL = re.Target.URL
		}
		if wafVendor == "" && re.Result.WAFSignature != "" {
			wafVendor = re.Result.WAFSignature
		}

		// Count outcomes
		switch re.Result.Outcome {
		case events.OutcomeBlocked:
			blocked++
		case events.OutcomeBypass:
			passed++
			bypasses++
		case events.OutcomePass:
			passed++
		case events.OutcomeError:
			errors++
		}

		// Build result element
		result := xmlResult{
			ID:         re.Test.ID,
			Category:   re.Test.Category,
			Severity:   string(re.Test.Severity),
			Outcome:    string(re.Result.Outcome),
			Confidence: string(re.Result.Confidence),
			StatusCode: re.Result.StatusCode,
			LatencyMs:  re.Result.LatencyMs,
			Target: xmlReqTarget{
				URL:    re.Target.URL,
				Method: re.Target.Method,
			},
		}

		// Add evidence if requested
		if xw.opts.IncludeEvidence && re.Evidence != nil {
			result.Evidence = &xmlEvidence{
				Payload:         re.Evidence.Payload,
				ResponsePreview: re.Evidence.ResponsePreview,
				WAFSignature:    re.Result.WAFSignature,
			}
		}

		// Add compliance mapping if available
		wascID := defaults.GetWASCID(re.Test.Category)
		if len(re.Test.CWE) > 0 || wascID != "" {
			result.Compliance = &xmlCompliance{
				CWE:  formatCWEList(re.Test.CWE),
				WASC: wascID,
			}
		}

		doc.Results.Result = append(doc.Results.Result, result)
	}

	// Set target info
	doc.Target = xmlTarget{
		URL:       targetURL,
		WAFVendor: wafVendor,
	}

	// Calculate detection rate
	var detectionRate float64
	if totalTests > 0 {
		detectionRate = float64(blocked) / float64(totalTests) * 100
	}

	doc.Summary = xmlSummary{
		TotalTests:     totalTests,
		BlockedTests:   blocked,
		PassedTests:    passed,
		ErrorTests:     errors,
		DetectionRate:  detectionRate,
		BypassCount:    bypasses,
		TotalLatencyMs: int64(totalLatency),
	}

	return doc
}

// formatCWEList converts a slice of CWE IDs to a comma-separated string.
func formatCWEList(cweIDs []int) string {
	if len(cweIDs) == 0 {
		return ""
	}
	result := ""
	for i, id := range cweIDs {
		if i > 0 {
			result += ","
		}
		result += "CWE-" + strconv.Itoa(id)
	}
	return result
}
