// Package writers provides output writers for various formats.
package writers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

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
	closed bool
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
	Pages   []any      `json:"pages"`
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
	if opts.CreatorVersion == "" {
		opts.CreatorVersion = defaults.Version
	}
	return &HARWriter{
		w:      w,
		opts:   opts,
		buffer: make([]events.Event, 0),
	}
}

// Write buffers an event for later HAR output.
// Accepts both ResultEvent and BypassEvent (converted to a synthetic ResultEvent).
// The event is stored in memory until Close is called.
func (hw *HARWriter) Write(event events.Event) error {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	if hw.closed {
		return nil
	}

	switch e := event.(type) {
	case *events.ResultEvent:
		if hw.opts.OnlyBypasses && e.Result.Outcome != events.OutcomeBypass {
			return nil
		}
		hw.buffer = append(hw.buffer, e)
	case *events.BypassEvent:
		re := bypassToResult(e)
		hw.buffer = append(hw.buffer, re)
	default:
		// Unknown event type — ignore per convention.
	}
	return nil
}

// Flush is a no-op for HAR writer.
// All events are written as a single document on Close.
func (hw *HARWriter) Flush() error {
	return nil
}

// Close writes all buffered events as a HAR document and closes the writer.
// The underlying writer is always closed if it implements io.Closer,
// even when encoding fails (to avoid leaking file handles).
func (hw *HARWriter) Close() error {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	if hw.closed {
		return nil
	}
	hw.closed = true

	doc := harDocument{
		Log: harLog{
			Version: "1.2",
			Creator: harCreator{
				Name:    hw.opts.CreatorName,
				Version: hw.opts.CreatorVersion,
			},
			Pages:   []any{},
			Entries: make([]harEntry, 0, len(hw.buffer)),
		},
	}

	for _, event := range hw.buffer {
		if re, ok := event.(*events.ResultEvent); ok {
			entry := hw.resultToEntry(re)
			doc.Log.Entries = append(doc.Log.Entries, entry)
		}
	}

	// Release buffer memory early.
	hw.buffer = nil

	// Encode to buffer first so a mid-write I/O failure doesn't leave
	// a corrupt (truncated) HAR file on disk.
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")

	var encodeErr error
	if err := encoder.Encode(doc); err != nil {
		encodeErr = fmt.Errorf("har: encode: %w", err)
	} else if _, err := buf.WriteTo(hw.w); err != nil {
		encodeErr = fmt.Errorf("har: write: %w", err)
	}

	if closer, ok := hw.w.(io.Closer); ok {
		if closeErr := closer.Close(); closeErr != nil && encodeErr == nil {
			return fmt.Errorf("har: close: %w", closeErr)
		}
	}
	return encodeErr
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

// harMillisecondFormat provides consistent 3-decimal-place timestamps
// for HAR compatibility (some tools expect fixed millisecond precision).
const harMillisecondFormat = "2006-01-02T15:04:05.000Z07:00"

// resultToEntry converts a ResultEvent to a HAR entry.
func (hw *HARWriter) resultToEntry(re *events.ResultEvent) harEntry {
	// Default empty method to GET for spec compliance, consistent with
	// bypassToResult which does the same.
	method := re.Target.Method
	if method == "" {
		method = "GET"
	}

	queryParams := extractQueryParams(re.Target.URL)
	comment := buildComment(re)

	// Prefer the wire payload (EncodedPayload) over the raw payload for
	// accurate representation of what was actually sent.
	wirePayload := effectivePayload(re.Evidence)

	bodySize := -1
	if wirePayload != "" {
		bodySize = len(wirePayload)
	}

	reqHeaders := buildSortedHeaders(re.Evidence)
	reqCookies := buildRequestCookies(re.Evidence)

	// Build response content from evidence.
	respContent := buildResponseContent(re)

	var postData *harPostData
	if wirePayload != "" && methodHasBody(method) {
		mimeType := "application/x-www-form-urlencoded"
		if re.Evidence != nil {
			if ct := headerValue(re.Evidence.RequestHeaders, "Content-Type"); ct != "" {
				mimeType = ct
			}
		}
		postData = &harPostData{
			MimeType: mimeType,
			Text:     wirePayload,
			Params:   buildFormParams(mimeType, wirePayload),
		}
	}

	return harEntry{
		StartedDateTime: re.Time.Format(harMillisecondFormat),
		Time:            re.Result.LatencyMs,
		Request: harRequest{
			Method:      method,
			URL:         re.Target.URL,
			HTTPVersion: "HTTP/1.1",
			Headers:     reqHeaders,
			QueryString: queryParams,
			Cookies:     reqCookies,
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
			Content:     respContent,
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

// extractQueryParams parses a URL and extracts query parameters in sorted order.
// Empty-key params (from trailing "?") are filtered out.
func extractQueryParams(rawURL string) []harNameValue {
	params := make([]harNameValue, 0)
	u, err := url.Parse(rawURL)
	if err != nil {
		return params
	}
	for key, values := range u.Query() {
		if key == "" {
			continue
		}
		for _, value := range values {
			params = append(params, harNameValue{Name: key, Value: value})
		}
	}
	sortNameValues(params)
	return params
}

// buildComment creates a descriptive comment for the HAR entry.
// Empty fields are filtered to avoid dangling separators.
// Includes evasion context (encoding, tamper, technique) when available.
func buildComment(re *events.ResultEvent) string {
	var parts []string

	if re.Result.Outcome == events.OutcomeBypass {
		parts = append(parts, "WAF bypass")
	} else if re.Result.Outcome != "" {
		parts = append(parts, string(re.Result.Outcome))
	}

	if re.Test.ID != "" {
		parts = append(parts, re.Test.ID)
	}

	if re.Test.Category != "" {
		parts = append(parts, "["+re.Test.Category+"]")
	}

	if ctx := buildContextTag(re.Context); ctx != "" {
		parts = append(parts, ctx)
	}

	return strings.Join(parts, ": ")
}

// buildContextTag formats evasion context fields into a parenthesized tag
// for the HAR comment, e.g. "(encoding: unicode, tamper: case-swap)".
func buildContextTag(ctx *events.ContextInfo) string {
	if ctx == nil {
		return ""
	}
	var fields []string
	if ctx.Encoding != "" {
		fields = append(fields, "encoding: "+ctx.Encoding)
	}
	if ctx.Tamper != "" {
		fields = append(fields, "tamper: "+ctx.Tamper)
	}
	if ctx.EvasionTechnique != "" {
		fields = append(fields, "evasion: "+ctx.EvasionTechnique)
	}
	if len(fields) == 0 {
		return ""
	}
	return "(" + strings.Join(fields, ", ") + ")"
}

// methodHasBody returns true if the HTTP method can carry a request body.
func methodHasBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// statusText returns the standard HTTP status text for a status code.
// Delegates to net/http.StatusText which covers all IANA-registered codes.
func statusText(code int) string {
	if text := http.StatusText(code); text != "" {
		return text
	}
	return fmt.Sprintf("Status %d", code)
}

// bypassToResult converts a BypassEvent into a synthetic ResultEvent
// so it can be rendered as a HAR entry (HTTP request/response pair).
// Defaults Method to GET when unset to satisfy HAR spec requirements.
// Propagates WAFDetected from AlertContext to WAFSignature for forensics.
func bypassToResult(be *events.BypassEvent) *events.ResultEvent {
	method := be.Details.Method
	if method == "" {
		method = "GET"
	}

	return &events.ResultEvent{
		BaseEvent: be.BaseEvent,
		Test: events.TestInfo{
			ID:       be.Details.TestID,
			Category: be.Details.Category,
			Severity: be.Details.Severity,
			OWASP:    be.Details.OWASP,
			CWE:      be.Details.CWE,
		},
		Target: events.TargetInfo{
			URL:    be.Details.Endpoint,
			Method: method,
		},
		Result: events.ResultInfo{
			Outcome:      events.OutcomeBypass,
			StatusCode:   be.Details.StatusCode,
			WAFSignature: be.Context.WAFDetected,
		},
		Evidence: &events.Evidence{
			Payload:     be.Details.Payload,
			CurlCommand: be.Details.Curl,
		},
		Context: &events.ContextInfo{
			Encoding: be.Details.Encoding,
			Tamper:   be.Details.Tamper,
		},
	}
}

// buildSortedHeaders extracts request headers from evidence in deterministic
// (sorted by name) order, safe for diff-based comparison.
func buildSortedHeaders(ev *events.Evidence) []harNameValue {
	headers := make([]harNameValue, 0)
	if ev == nil || ev.RequestHeaders == nil {
		return headers
	}
	for name, value := range ev.RequestHeaders {
		headers = append(headers, harNameValue{Name: name, Value: value})
	}
	sortNameValues(headers)
	return headers
}

// sortNameValues sorts a slice of harNameValue by Name for deterministic output.
func sortNameValues(nv []harNameValue) {
	slices.SortFunc(nv, func(a, b harNameValue) int {
		return strings.Compare(a.Name, b.Name)
	})
}

// buildRequestCookies parses the Cookie request header into individual
// harCookie entries per HAR spec section 5.2.
// Uses case-insensitive header lookup for HTTP/2 compatibility.
func buildRequestCookies(ev *events.Evidence) []harCookie {
	if ev == nil {
		return []harCookie{}
	}
	cookieHeader := headerValue(ev.RequestHeaders, "Cookie")
	if cookieHeader == "" {
		return []harCookie{}
	}
	return parseCookieHeader(cookieHeader)
}

// parseCookieHeader splits a Cookie header value ("name1=val1; name2=val2")
// into individual harCookie entries.
func parseCookieHeader(header string) []harCookie {
	cookies := make([]harCookie, 0)
	for _, pair := range strings.Split(header, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		cookies = append(cookies, harCookie{
			Name:  name,
			Value: strings.TrimSpace(value),
		})
	}
	return cookies
}

// buildFormParams parses URL-encoded form data into HAR params when the
// MIME type is application/x-www-form-urlencoded. Returns nil otherwise.
// Uses base MIME type comparison to handle Content-Type parameters
// like "; charset=utf-8".
func buildFormParams(mimeType, body string) []harNameValue {
	if baseMIMEType(mimeType) != "application/x-www-form-urlencoded" {
		return nil
	}
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil
	}
	params := make([]harNameValue, 0, len(values))
	for key, vals := range values {
		for _, val := range vals {
			params = append(params, harNameValue{Name: key, Value: val})
		}
	}
	sortNameValues(params)
	return params
}

// effectivePayload returns the wire-format payload from evidence.
// Prefers EncodedPayload (the evasion-encoded form actually sent) over
// the raw Payload. Returns empty string when no evidence is available.
func effectivePayload(ev *events.Evidence) string {
	if ev == nil {
		return ""
	}
	if ev.EncodedPayload != "" {
		return ev.EncodedPayload
	}
	return ev.Payload
}

// buildResponseContent constructs the HAR response content object.
// Maps ResponsePreview to content.text when available, and infers
// the MIME type from the preview content rather than guessing from
// request headers.
// Size always reflects ContentLength from the actual HTTP response;
// ResponsePreview is a truncated snippet and its length would misrepresent
// the true response size.
func buildResponseContent(re *events.ResultEvent) harContent {
	c := harContent{
		Size:     re.Result.ContentLength,
		MimeType: "text/html",
	}

	if re.Evidence != nil && re.Evidence.ResponsePreview != "" {
		c.Text = re.Evidence.ResponsePreview
		c.MimeType = inferMIMEFromContent(re.Evidence.ResponsePreview)
	}

	return c
}

// headerValue returns the value of a header by name using case-insensitive
// comparison. HTTP/2 normalizes header names to lowercase, but HTTP/1.1
// preserves original casing — this handles both.
func headerValue(headers map[string]string, name string) string {
	if headers == nil {
		return ""
	}
	// Fast path: exact match (common for HTTP/1.1 canonical headers).
	if v, ok := headers[name]; ok {
		return v
	}
	// Slow path: case-insensitive scan for HTTP/2 lowercase headers.
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// baseMIMEType extracts the base MIME type from a Content-Type header value,
// stripping parameters like "; charset=utf-8".
func baseMIMEType(contentType string) string {
	base, _, _ := strings.Cut(contentType, ";")
	return strings.TrimSpace(base)
}

// inferMIMEFromContent makes a best-effort guess at MIME type from content.
// Inspects the first non-whitespace character for JSON ({/[) or XML (<) markers.
func inferMIMEFromContent(content string) string {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return "text/html"
	}
	switch trimmed[0] {
	case '{', '[':
		return "application/json"
	case '<':
		if strings.HasPrefix(trimmed, "<?xml") {
			return "application/xml"
		}
		return "text/html"
	default:
		return "text/plain"
	}
}
