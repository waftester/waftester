// Package writers provides output writers for various formats.
package writers

import (
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*HARWriter)(nil)

// HARWriter writes events as HAR 1.2 (HTTP Archive) format.
// HAR is widely supported by browser developer tools and HTTP analysis tools.
// Events are buffered and written as a complete HAR document on Close.
type HARWriter struct {
	w      io.Writer
	mu     sync.Mutex
	opts   HAROptions
	buffer []events.Event
}

// HAROptions configures the HAR writer behavior.
type HAROptions struct {
	// CreatorName is the name of the tool creating the HAR file.
	// Defaults to "waftester" if empty.
	CreatorName string

	// CreatorVersion is the version of the tool creating the HAR file.
	CreatorVersion string

	// OnlyBypasses filters output to only include bypass events.
	// When true, only events with EventTypeBypass or ResultEvents
	// with OutcomeBypass are included.
	OnlyBypasses bool
}

// harDocument represents the root HAR 1.2 structure.
type harDocument struct {
	Log harLog `json:"log"`
}

// harLog represents the HAR log object.
type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}

// harCreator represents the HAR creator object.
type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// harEntry represents a single HAR entry.
type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           harCache    `json:"cache"`
	Timings         harTimings  `json:"timings"`
	Comment         string      `json:"comment,omitempty"`
}

// harRequest represents a HAR request object.
type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	QueryString []harNameValue `json:"queryString"`
	Cookies     []harCookie    `json:"cookies"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int            `json:"bodySize"`
	PostData    *harPostData   `json:"postData,omitempty"`
}

// harResponse represents a HAR response object.
type harResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	Cookies     []harCookie    `json:"cookies"`
	Content     harContent     `json:"content"`
	RedirectURL string         `json:"redirectURL"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int            `json:"bodySize"`
}

// harContent represents a HAR content object.
type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

// harCache represents a HAR cache object.
type harCache struct{}

// harTimings represents a HAR timings object.
type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// harNameValue represents a HAR name-value pair.
type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// harCookie represents a HAR cookie object.
type harCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

// harPostData represents HAR post data.
type harPostData struct {
	MimeType string         `json:"mimeType"`
	Text     string         `json:"text,omitempty"`
	Params   []harNameValue `json:"params,omitempty"`
}

// NewHARWriter creates a new HAR writer that writes to w.
// The writer buffers all events and writes them as a HAR document on Close.
// The writer is safe for concurrent use.
func NewHARWriter(w io.Writer, opts HAROptions) *HARWriter {
	if opts.CreatorName == "" {
		opts.CreatorName = defaults.ToolName
	}
	return &HARWriter{
		w:      w,
		opts:   opts,
		buffer: make([]events.Event, 0),
	}
}

// Write buffers an event for later HAR output.
// The event is stored in memory until Close is called.
func (hw *HARWriter) Write(event events.Event) error {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	// Only process result events
	re, ok := event.(*events.ResultEvent)
	if !ok {
		return nil
	}

	// Filter: only bypasses if requested
	if hw.opts.OnlyBypasses {
		if re.Result.Outcome != events.OutcomeBypass {
			return nil
		}
	}

	hw.buffer = append(hw.buffer, event)
	return nil
}

// Flush is a no-op for HAR writer.
// All events are written as a single document on Close.
func (hw *HARWriter) Flush() error {
	return nil
}

// Close writes all buffered events as a HAR document and closes the writer.
// If the underlying writer implements io.Closer, it will be closed.
func (hw *HARWriter) Close() error {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	doc := harDocument{
		Log: harLog{
			Version: "1.2",
			Creator: harCreator{
				Name:    hw.opts.CreatorName,
				Version: hw.opts.CreatorVersion,
			},
			Entries: make([]harEntry, 0, len(hw.buffer)),
		},
	}

	for _, event := range hw.buffer {
		if re, ok := event.(*events.ResultEvent); ok {
			entry := hw.resultToEntry(re)
			doc.Log.Entries = append(doc.Log.Entries, entry)
		}
	}

	encoder := json.NewEncoder(hw.w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return err
	}

	if closer, ok := hw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SupportsEvent returns true for result and bypass events.
// HAR is focused on HTTP request/response pairs from test results.
func (hw *HARWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeBypass:
		return true
	default:
		return false
	}
}

// resultToEntry converts a ResultEvent to a HAR entry.
func (hw *HARWriter) resultToEntry(re *events.ResultEvent) harEntry {
	// Parse URL for query string extraction
	queryParams := extractQueryParams(re.Target.URL)

	// Build comment from test info and outcome
	comment := buildComment(re)

	// Calculate body size from evidence if available
	bodySize := -1
	if re.Evidence != nil && re.Evidence.Payload != "" {
		bodySize = len(re.Evidence.Payload)
	}

	// Build request headers from evidence
	reqHeaders := make([]harNameValue, 0)
	if re.Evidence != nil && re.Evidence.RequestHeaders != nil {
		for name, value := range re.Evidence.RequestHeaders {
			reqHeaders = append(reqHeaders, harNameValue{Name: name, Value: value})
		}
	}

	// Build post data if method supports it and we have a payload
	var postData *harPostData
	if re.Evidence != nil && re.Evidence.Payload != "" && methodHasBody(re.Target.Method) {
		postData = &harPostData{
			MimeType: "application/x-www-form-urlencoded",
			Text:     re.Evidence.Payload,
		}
	}

	return harEntry{
		StartedDateTime: re.Time.Format(time.RFC3339Nano),
		Time:            re.Result.LatencyMs,
		Request: harRequest{
			Method:      re.Target.Method,
			URL:         re.Target.URL,
			HTTPVersion: "HTTP/1.1",
			Headers:     reqHeaders,
			QueryString: queryParams,
			Cookies:     []harCookie{},
			HeadersSize: -1,
			BodySize:    bodySize,
			PostData:    postData,
		},
		Response: harResponse{
			Status:      re.Result.StatusCode,
			StatusText:  statusText(re.Result.StatusCode),
			HTTPVersion: "HTTP/1.1",
			Headers:     []harNameValue{},
			Cookies:     []harCookie{},
			Content: harContent{
				Size:     re.Result.ContentLength,
				MimeType: "text/html",
			},
			RedirectURL: "",
			HeadersSize: -1,
			BodySize:    re.Result.ContentLength,
		},
		Cache: harCache{},
		Timings: harTimings{
			Send:    -1,
			Wait:    re.Result.LatencyMs,
			Receive: -1,
		},
		Comment: comment,
	}
}

// extractQueryParams parses a URL and extracts query parameters.
func extractQueryParams(rawURL string) []harNameValue {
	params := make([]harNameValue, 0)
	u, err := url.Parse(rawURL)
	if err != nil {
		return params
	}
	for key, values := range u.Query() {
		for _, value := range values {
			params = append(params, harNameValue{Name: key, Value: value})
		}
	}
	return params
}

// buildComment creates a descriptive comment for the HAR entry.
func buildComment(re *events.ResultEvent) string {
	var parts []string

	if re.Result.Outcome == events.OutcomeBypass {
		parts = append(parts, "WAF bypass")
	} else {
		parts = append(parts, string(re.Result.Outcome))
	}

	parts = append(parts, re.Test.ID)

	if re.Test.Category != "" {
		parts = append(parts, "["+re.Test.Category+"]")
	}

	return strings.Join(parts, ": ")
}

// methodHasBody returns true if the HTTP method typically has a body.
func methodHasBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// statusText returns the standard HTTP status text for a status code.
func statusText(code int) string {
	texts := map[int]string{
		200: "OK",
		201: "Created",
		204: "No Content",
		301: "Moved Permanently",
		302: "Found",
		304: "Not Modified",
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		405: "Method Not Allowed",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
	}
	if text, ok := texts[code]; ok {
		return text
	}
	return "Status " + strconv.Itoa(code)
}
