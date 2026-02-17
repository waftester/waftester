// Package writers provides output writers for various formats.
package writers

import (
	"encoding/xml"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*JUnitWriter)(nil)

// JUnitWriter writes events in JUnit XML format.
// JUnit XML is a standard format for CI/CD systems including Jenkins,
// GitLab CI, GitHub Actions, Azure DevOps, and CircleCI.
// Results are buffered and written as a complete JUnit document on Close.
// The writer is safe for concurrent use.
type JUnitWriter struct {
	w         io.Writer
	mu        sync.Mutex
	opts      JUnitOptions
	results   []junitTestCase
	startTime time.Time
}

// JUnitOptions configures the JUnit XML writer.
type JUnitOptions struct {
	// SuiteName is the name of the test suite (default: "waftester").
	SuiteName string

	// Package is the package name for test cases (used as classname prefix).
	Package string

	// Hostname is the hostname for the test suite.
	Hostname string
}

// JUnit XML structures.

type junitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	TestSuites []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      float64         `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	Hostname  string          `xml:"hostname,attr,omitempty"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitError   `xml:"error,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

type junitError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// NewJUnitWriter creates a new JUnit XML writer that writes to w.
// The writer buffers all results and writes a complete JUnit document on Close.
// The writer is safe for concurrent use.
func NewJUnitWriter(w io.Writer, opts JUnitOptions) *JUnitWriter {
	if opts.SuiteName == "" {
		opts.SuiteName = defaults.ToolName
	}
	if opts.Package == "" {
		opts.Package = defaults.ToolName
	}
	return &JUnitWriter{
		w:         w,
		opts:      opts,
		results:   make([]junitTestCase, 0),
		startTime: time.Now(),
	}
}

// Write converts a result event to a JUnit test case.
// Only result events are processed; other event types are ignored.
// Mapping:
//   - blocked outcome → Success (no child element)
//   - pass outcome → Success (no child element)
//   - bypass outcome → <failure> with bypass details
//   - error outcome → <error> with error message
//   - timeout outcome → <error type="timeout">
func (jw *JUnitWriter) Write(event events.Event) error {
	jw.mu.Lock()
	defer jw.mu.Unlock()

	re, ok := event.(*events.ResultEvent)
	if !ok {
		return nil // Skip non-result events
	}

	testCase := junitTestCase{
		Name:      re.Test.ID,
		ClassName: jw.opts.Package + "." + re.Test.Category,
		Time:      re.Result.LatencyMs / 1000.0, // Convert ms to seconds
	}

	switch re.Result.Outcome {
	case events.OutcomeBypass:
		payload := ""
		if re.Evidence != nil {
			payload = re.Evidence.Payload
		}
		testCase.Failure = &junitFailure{
			Message: "WAF bypass detected",
			Type:    "bypass",
			Content: formatBypassDetails(re, payload),
		}
	case events.OutcomeError:
		testCase.Error = &junitError{
			Message: "Test execution error",
			Type:    "error",
			Content: "Error executing test",
		}
	case events.OutcomeTimeout:
		testCase.Error = &junitError{
			Message: "Request timeout",
			Type:    "timeout",
			Content: "Request timed out",
		}
		// OutcomeBlocked and OutcomePass are successes - no child elements
	}

	jw.results = append(jw.results, testCase)
	return nil
}

// formatBypassDetails formats the bypass information for the failure content.
func formatBypassDetails(re *events.ResultEvent, payload string) string {
	return fmt.Sprintf(`Bypass Details:
- Category: %s
- Severity: %s
- Status Code: %d
- Payload: %s`,
		re.Test.Category,
		re.Test.Severity,
		re.Result.StatusCode,
		payload,
	)
}

// Flush is a no-op for JUnit writer.
// All results are written as a single document on Close.
func (jw *JUnitWriter) Flush() error {
	return nil
}

// Close writes all buffered results as a complete JUnit XML document.
// If the underlying writer implements io.Closer, it will be closed.
func (jw *JUnitWriter) Close() error {
	jw.mu.Lock()
	defer jw.mu.Unlock()

	// Calculate totals
	failures := 0
	errors := 0
	for _, tc := range jw.results {
		if tc.Failure != nil {
			failures++
		}
		if tc.Error != nil {
			errors++
		}
	}

	// Calculate elapsed time
	elapsed := time.Since(jw.startTime).Seconds()

	suite := junitTestSuite{
		Name:      jw.opts.SuiteName,
		Tests:     len(jw.results),
		Failures:  failures,
		Errors:    errors,
		Time:      elapsed,
		Timestamp: jw.startTime.Format(time.RFC3339),
		Hostname:  jw.opts.Hostname,
		TestCases: jw.results,
	}

	doc := junitTestSuites{
		TestSuites: []junitTestSuite{suite},
	}

	// Write XML header
	if _, err := jw.w.Write([]byte(xml.Header)); err != nil {
		return fmt.Errorf("junit: write header: %w", err)
	}

	// Encode the document
	encoder := xml.NewEncoder(jw.w)
	encoder.Indent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("junit: encode: %w", err)
	}

	if closer, ok := jw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SupportsEvent returns true only for result events.
// JUnit XML is designed for test results, not progress or summary events.
func (jw *JUnitWriter) SupportsEvent(eventType events.EventType) bool {
	return eventType == events.EventTypeResult
}
