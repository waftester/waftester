// Package realistic provides realistic HTTP request generation for WAF testing
// This package transforms test payloads into requests that look like real traffic
package realistic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// Note: Go 1.20+ auto-seeds the global random source, no init() needed

// InjectionLocation specifies where to inject the payload
type InjectionLocation string

const (
	LocationQuery      InjectionLocation = "query"      // URL query parameter
	LocationPath       InjectionLocation = "path"       // URL path segment
	LocationBody       InjectionLocation = "body"       // Request body (form)
	LocationJSON       InjectionLocation = "json"       // JSON body field
	LocationHeader     InjectionLocation = "header"     // Custom header
	LocationCookie     InjectionLocation = "cookie"     // Cookie value
	LocationUserAgent  InjectionLocation = "useragent"  // User-Agent header
	LocationReferer    InjectionLocation = "referer"    // Referer header
	LocationXForwarded InjectionLocation = "xforwarded" // X-Forwarded-For header
	LocationFragment   InjectionLocation = "fragment"   // URL fragment
	LocationMultipart  InjectionLocation = "multipart"  // Multipart form data
)

// RequestTemplate defines how to build a realistic request
type RequestTemplate struct {
	Method         string
	Path           string
	QueryParams    map[string]string      // Legitimate query params
	InjectionParam string                 // Which param to inject payload into
	Headers        map[string]string      // Additional headers
	Cookies        map[string]string      // Cookies to include
	FormData       map[string]string      // Form body data
	JSONData       map[string]interface{} // JSON body template
	InjectionField string                 // Which JSON field to inject into
	ContentType    string
	InjectionLoc   InjectionLocation
}

// Builder creates realistic HTTP requests from payloads
type Builder struct {
	BaseURL     string
	UserAgents  []string
	Referers    []string
	SessionID   string
	RandomizeUA bool
	AddJitter   bool
	JitterMaxMs int
}

// NewBuilder creates a new request builder
func NewBuilder(baseURL string) *Builder {
	return &Builder{
		BaseURL:     strings.TrimSuffix(baseURL, "/"),
		UserAgents:  DefaultUserAgents,
		Referers:    []string{},
		RandomizeUA: true,
		AddJitter:   false,
		JitterMaxMs: 100,
	}
}

// BuildRequest creates a realistic HTTP request with payload injected
func (b *Builder) BuildRequest(payload string, template *RequestTemplate) (*http.Request, error) {
	if template == nil {
		template = DefaultTemplate(payload)
	}

	var req *http.Request
	var err error

	// Build URL
	targetURL := b.BaseURL + template.Path

	switch template.InjectionLoc {
	case LocationQuery, "":
		req, err = b.buildQueryRequest(targetURL, payload, template)
	case LocationBody:
		req, err = b.buildFormRequest(targetURL, payload, template)
	case LocationJSON:
		req, err = b.buildJSONRequest(targetURL, payload, template)
	case LocationHeader:
		req, err = b.buildHeaderRequest(targetURL, payload, template)
	case LocationCookie:
		req, err = b.buildCookieRequest(targetURL, payload, template)
	case LocationXForwarded:
		req, err = b.buildXForwardedRequest(targetURL, payload, template)
	case LocationPath:
		req, err = b.buildPathRequest(targetURL, payload, template)
	case LocationMultipart:
		req, err = b.buildMultipartRequest(targetURL, payload, template)
	case LocationUserAgent, LocationReferer, LocationFragment:
		// These locations use header injection or are client-side only
		req, err = b.buildQueryRequest(targetURL, payload, template)
	}

	if err != nil {
		return nil, err
	}

	// Add realistic headers
	b.addRealisticHeaders(req, template)

	return req, nil
}

// buildQueryRequest injects payload into URL query parameter
func (b *Builder) buildQueryRequest(targetURL, payload string, template *RequestTemplate) (*http.Request, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()

	// Add legitimate params first
	for k, v := range template.QueryParams {
		if k != template.InjectionParam {
			q.Set(k, v)
		}
	}

	// Add payload param
	injParam := template.InjectionParam
	if injParam == "" {
		injParam = randomParam()
	}
	q.Set(injParam, payload)

	u.RawQuery = q.Encode()

	method := template.Method
	if method == "" {
		method = "GET"
	}

	return http.NewRequest(method, u.String(), nil)
}

// buildFormRequest injects payload into form body
func (b *Builder) buildFormRequest(targetURL, payload string, template *RequestTemplate) (*http.Request, error) {
	form := url.Values{}

	// Add legitimate fields
	for k, v := range template.FormData {
		if k != template.InjectionParam {
			form.Set(k, v)
		}
	}

	// Add payload field
	injParam := template.InjectionParam
	if injParam == "" {
		injParam = randomParam()
	}
	form.Set(injParam, payload)

	method := template.Method
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// buildJSONRequest injects payload into JSON body field
func (b *Builder) buildJSONRequest(targetURL, payload string, template *RequestTemplate) (*http.Request, error) {
	data := make(map[string]interface{})

	// Copy template data
	for k, v := range template.JSONData {
		data[k] = v
	}

	// Inject payload
	injField := template.InjectionField
	if injField == "" {
		injField = "data"
	}
	data[injField] = payload

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	method := template.Method
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, targetURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// buildHeaderRequest injects payload into a custom header
func (b *Builder) buildHeaderRequest(targetURL, payload string, template *RequestTemplate) (*http.Request, error) {
	method := template.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, err
	}

	headerName := template.InjectionParam
	if headerName == "" {
		headerName = "X-Custom-Data"
	}
	req.Header.Set(headerName, payload)

	return req, nil
}

// buildCookieRequest injects payload into a cookie
func (b *Builder) buildCookieRequest(targetURL, payload string, template *RequestTemplate) (*http.Request, error) {
	method := template.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, err
	}

	// Add legitimate cookies
	for name, value := range template.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	// Add payload cookie
	cookieName := template.InjectionParam
	if cookieName == "" {
		cookieName = "session_data"
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: payload})

	return req, nil
}

// buildXForwardedRequest injects payload into X-Forwarded-For
func (b *Builder) buildXForwardedRequest(targetURL, payload string, template *RequestTemplate) (*http.Request, error) {
	method := template.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, err
	}

	// Add payload in X-Forwarded-For (commonly used for IP spoofing attacks)
	req.Header.Set("X-Forwarded-For", payload)
	req.Header.Set("X-Real-IP", payload)

	return req, nil
}

// buildPathRequest injects payload into URL path
func (b *Builder) buildPathRequest(targetURL, payload string, template *RequestTemplate) (*http.Request, error) {
	// Replace placeholder in path or append
	path := template.Path
	if strings.Contains(path, "{payload}") {
		path = strings.Replace(path, "{payload}", url.PathEscape(payload), 1)
	} else {
		path = path + "/" + url.PathEscape(payload)
	}

	fullURL := b.BaseURL + path

	method := template.Method
	if method == "" {
		method = "GET"
	}

	return http.NewRequest(method, fullURL, nil)
}

// buildMultipartRequest creates multipart form with payload
func (b *Builder) buildMultipartRequest(targetURL, payload string, template *RequestTemplate) (*http.Request, error) {
	var buf bytes.Buffer

	boundary := fmt.Sprintf("----WebKitFormBoundary%s", randomString(16))

	// Add legitimate fields
	for name, value := range template.FormData {
		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		buf.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"%s\"\r\n\r\n", name))
		buf.WriteString(value + "\r\n")
	}

	// Add payload field
	injField := template.InjectionParam
	if injField == "" {
		injField = "file"
	}
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"%s\"; filename=\"test.txt\"\r\n", injField))
	buf.WriteString("Content-Type: text/plain\r\n\r\n")
	buf.WriteString(payload + "\r\n")
	buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	method := template.Method
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, targetURL, &buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	return req, nil
}

// addRealisticHeaders adds headers that make the request look legitimate
func (b *Builder) addRealisticHeaders(req *http.Request, template *RequestTemplate) {
	// User-Agent
	if b.RandomizeUA && len(b.UserAgents) > 0 {
		req.Header.Set("User-Agent", b.UserAgents[rand.Intn(len(b.UserAgents))])
	} else {
		req.Header.Set("User-Agent", DefaultUserAgents[0])
	}

	// Standard browser headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	// Origin/Referer for POST requests
	if req.Method == "POST" || req.Method == "PUT" {
		if len(b.Referers) > 0 {
			req.Header.Set("Referer", b.Referers[rand.Intn(len(b.Referers))])
		} else {
			req.Header.Set("Referer", b.BaseURL)
		}
		req.Header.Set("Origin", b.BaseURL)
	}

	// AJAX indicator for API-like requests
	if strings.Contains(req.URL.Path, "/api") {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}

	// Add template-specific headers
	for k, v := range template.Headers {
		req.Header.Set(k, v)
	}

	// Add cookies
	for name, value := range template.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	// Add session if configured
	if b.SessionID != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: b.SessionID})
	}
}

// GetRotatingUA returns a random User-Agent string for realistic traffic simulation
func (b *Builder) GetRotatingUA() string {
	if b.RandomizeUA && len(b.UserAgents) > 0 {
		return b.UserAgents[rand.Intn(len(b.UserAgents))]
	}
	if len(DefaultUserAgents) > 0 {
		return DefaultUserAgents[0]
	}
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

// DefaultTemplate creates a default request template for simple payload injection
func DefaultTemplate(payload string) *RequestTemplate {
	return &RequestTemplate{
		Method: "GET",
		Path:   "/",
		QueryParams: map[string]string{
			"id":   fmt.Sprintf("%d", rand.Intn(10000)),
			"page": "1",
			"sort": "asc",
		},
		InjectionParam: randomParam(),
		InjectionLoc:   LocationQuery,
	}
}

// APITemplate creates a template for API endpoint testing
func APITemplate(endpoint, method string) *RequestTemplate {
	return &RequestTemplate{
		Method: method,
		Path:   endpoint,
		JSONData: map[string]interface{}{
			"timestamp": time.Now().Unix(),
			"version":   "1.0",
		},
		InjectionField: "data",
		InjectionLoc:   LocationJSON,
	}
}

// FormTemplate creates a template for form submission testing
func FormTemplate(action string) *RequestTemplate {
	return &RequestTemplate{
		Method: "POST",
		Path:   action,
		FormData: map[string]string{
			"csrf_token": randomString(32),
			"submit":     "true",
		},
		InjectionParam: "input",
		InjectionLoc:   LocationBody,
	}
}

// SearchTemplate creates a template for search functionality testing
func SearchTemplate() *RequestTemplate {
	return &RequestTemplate{
		Method: "GET",
		Path:   "/search",
		QueryParams: map[string]string{
			"page":    "1",
			"limit":   "20",
			"sort":    "relevance",
			"filters": "all",
		},
		InjectionParam: "q",
		InjectionLoc:   LocationQuery,
	}
}

// LoginTemplate creates a template for login form testing
func LoginTemplate() *RequestTemplate {
	return &RequestTemplate{
		Method: "POST",
		Path:   "/login",
		FormData: map[string]string{
			"remember": "true",
			"redirect": "/dashboard",
		},
		InjectionParam: "username",
		InjectionLoc:   LocationBody,
	}
}

// Helper functions

func randomParam() string {
	params := []string{"q", "search", "query", "id", "name", "value", "data", "input", "text", "filter", "term"}
	return params[rand.Intn(len(params))]
}

func randomString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// CloneRequest creates a deep copy of an HTTP request
func CloneRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())

	if req.Body != nil {
		bodyBytes, err := iohelper.ReadBodyDefault(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		clone.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	return clone, nil
}

// DefaultUserAgents is a list of common real browser User-Agent strings
var DefaultUserAgents = []string{
	// Chrome on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	// Chrome on Mac
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	// Firefox on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	// Firefox on Mac
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	// Safari on Mac
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	// Edge on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	// Chrome on Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	// Mobile Chrome on Android
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
	// Mobile Safari on iPhone
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}
