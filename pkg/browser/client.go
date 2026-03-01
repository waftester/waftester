// Package browser provides browser-like HTTP client capabilities for realistic WAF testing
package browser

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Profile represents a browser fingerprint profile
type Profile struct {
	Name      string
	UserAgent string
	Headers   map[string]string
	TLSConfig *tls.Config
}

// Common browser profiles
var (
	Chrome = &Profile{
		Name:      "Chrome",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Windows"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		},
	}

	Firefox = &Profile{
		Name:      "Firefox",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Accept-Encoding":           "gzip, deflate, br",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
		},
	}

	Safari = &Profile{
		Name:      "Safari",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Upgrade-Insecure-Requests": "1",
		},
	}

	Edge = &Profile{
		Name:      "Edge",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Windows"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		},
	}

	Mobile = &Profile{
		Name:      "Mobile",
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
		},
	}

	Bot = &Profile{
		Name:      "Googlebot",
		UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		Headers: map[string]string{
			"Accept":          "*/*",
			"Accept-Encoding": "gzip, deflate",
		},
	}
)

// AllProfiles returns all available browser profiles
func AllProfiles() []*Profile {
	return []*Profile{Chrome, Firefox, Safari, Edge, Mobile, Bot}
}

// Client is a browser-like HTTP client
type Client struct {
	http        *http.Client
	profile     *Profile
	cookieJar   http.CookieJar
	baseURL     string
	timeout     time.Duration
	retries     int
	retryDelay  time.Duration
	followRedir bool
	maxRedirs   int
	proxy       string

	mu      sync.Mutex
	history []*Request
	referer string
}

// Option configures the client
type Option func(*Client)

// WithProfile sets the browser profile
func WithProfile(p *Profile) Option {
	return func(c *Client) {
		c.profile = p
	}
}

// WithTimeout sets the request timeout
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithRetries sets the number of retries
func WithRetries(n int) Option {
	return func(c *Client) {
		c.retries = n
	}
}

// WithRetryDelay sets the delay between retries
func WithRetryDelay(d time.Duration) Option {
	return func(c *Client) {
		c.retryDelay = d
	}
}

// WithFollowRedirects enables/disables redirect following
func WithFollowRedirects(follow bool) Option {
	return func(c *Client) {
		c.followRedir = follow
	}
}

// WithMaxRedirects sets the maximum number of redirects
func WithMaxRedirects(n int) Option {
	return func(c *Client) {
		c.maxRedirs = n
	}
}

// WithProxy sets a proxy URL
func WithProxy(proxyURL string) Option {
	return func(c *Client) {
		c.proxy = proxyURL
	}
}

// WithBaseURL sets the base URL for relative paths
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// NewClient creates a new browser-like client
func NewClient(opts ...Option) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	c := &Client{
		profile:     Chrome,
		cookieJar:   jar,
		timeout:     duration.BrowserPage,
		retries:     0,
		retryDelay:  time.Second,
		followRedir: true,
		maxRedirs:   10,
		history:     make([]*Request, 0),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Build client via httpclient.Config for centralized transport management
	cfg := httpclient.Config{
		Timeout:             c.timeout,
		MaxIdleConns:        100,
		IdleConnTimeout:     duration.IdleConnTimeout,
		TLSHandshakeTimeout: duration.TLSHandshake,
		Proxy:               c.proxy,
	}
	if c.profile.TLSConfig != nil {
		cfg.TLSConfig = c.profile.TLSConfig
	}
	c.http = httpclient.New(cfg)
	c.http.Jar = jar

	if c.followRedir {
		c.http.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= c.maxRedirs {
				return fmt.Errorf("stopped after %d redirects", c.maxRedirs)
			}
			return nil
		}
	} else {
		c.http.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return c, nil
}

// Request represents an HTTP request with browser-like features
type Request struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        io.Reader
	BodyString  string
	ContentType string
	Referer     string
	Origin      string
	XHR         bool // XMLHttpRequest style request
}

// Response represents an HTTP response
type Response struct {
	StatusCode    int
	Status        string
	Headers       http.Header
	Body          []byte
	ContentType   string
	ContentLength int64
	Latency       time.Duration
	RedirectCount int
	FinalURL      string
	Cookies       []*http.Cookie
	Blocked       bool
	Request       *Request
}

// Do executes a request
func (c *Client) Do(req *Request) (*Response, error) {
	return c.DoWithContext(context.Background(), req)
}

// DoWithContext executes a request with context
func (c *Client) DoWithContext(ctx context.Context, req *Request) (*Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			time.Sleep(c.retryDelay)
		}

		resp, err := c.doOnce(ctx, req)
		if err != nil {
			lastErr = err
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.retries+1, lastErr)
}

func (c *Client) doOnce(ctx context.Context, req *Request) (*Response, error) {
	// Build URL
	targetURL := req.URL
	if c.baseURL != "" && !strings.HasPrefix(req.URL, "http") {
		targetURL = strings.TrimSuffix(c.baseURL, "/") + "/" + strings.TrimPrefix(req.URL, "/")
	}

	// Create HTTP request
	var body io.Reader = req.Body
	if body == nil && req.BodyString != "" {
		body = strings.NewReader(req.BodyString)
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply browser profile headers (snapshot under lock to avoid race with SetProfile)
	c.mu.Lock()
	profile := c.profile
	c.mu.Unlock()
	httpReq.Header.Set("User-Agent", profile.UserAgent)
	for k, v := range profile.Headers {
		httpReq.Header.Set(k, v)
	}

	// Apply request-specific headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Content type
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	// Referer
	if req.Referer != "" {
		httpReq.Header.Set("Referer", req.Referer)
	} else {
		c.mu.Lock()
		ref := c.referer
		c.mu.Unlock()
		if ref != "" {
			httpReq.Header.Set("Referer", ref)
		}
	}

	// Origin
	if req.Origin != "" {
		httpReq.Header.Set("Origin", req.Origin)
	}

	// XHR headers
	if req.XHR {
		httpReq.Header.Set("X-Requested-With", "XMLHttpRequest")
		httpReq.Header.Set("Sec-Fetch-Dest", "empty")
		httpReq.Header.Set("Sec-Fetch-Mode", "cors")
	}

	// Execute request
	start := time.Now()
	httpResp, err := c.http.Do(httpReq)
	latency := time.Since(start)

	if err != nil {
		return &Response{
			Latency: latency,
			Blocked: true,
			Request: req,
		}, fmt.Errorf("request failed: %w", err)
	}
	defer iohelper.DrainAndClose(httpResp.Body)

	// Read body
	var respBody []byte
	if httpResp.Header.Get("Content-Encoding") == "gzip" {
		gzr, gzErr := gzip.NewReader(httpResp.Body)
		if gzErr == nil {
			defer gzr.Close() // Ensure closure even on panic
			respBody, gzErr = iohelper.ReadBodyDefault(gzr)
			if gzErr != nil {
				respBody = nil // Don't use partially decompressed data
			}
		}
	}
	if len(respBody) == 0 {
		respBody, _ = iohelper.ReadBodyDefault(httpResp.Body)
	}

	// Build response
	resp := &Response{
		StatusCode:    httpResp.StatusCode,
		Status:        httpResp.Status,
		Headers:       httpResp.Header,
		Body:          respBody,
		ContentType:   httpResp.Header.Get("Content-Type"),
		ContentLength: httpResp.ContentLength,
		Latency:       latency,
		FinalURL:      httpResp.Request.URL.String(),
		Request:       req,
	}

	// Get cookies
	parsedURL, _ := url.Parse(targetURL)
	if parsedURL != nil {
		resp.Cookies = c.cookieJar.Cookies(parsedURL)
	}

	// Check if blocked
	resp.Blocked = isBlockedResponse(httpResp)

	// Update history and referer
	c.mu.Lock()
	c.history = append(c.history, req)
	c.referer = targetURL
	c.mu.Unlock()

	return resp, nil
}

func isBlockedResponse(resp *http.Response) bool {
	// Common WAF block status codes
	if resp.StatusCode == 403 || resp.StatusCode == 406 ||
		resp.StatusCode == 418 || resp.StatusCode == 429 ||
		resp.StatusCode >= 500 {
		return true
	}
	return false
}

// Get performs a GET request
func (c *Client) Get(urlStr string) (*Response, error) {
	return c.Do(&Request{Method: "GET", URL: urlStr})
}

// Post performs a POST request with form data
func (c *Client) Post(urlStr string, data url.Values) (*Response, error) {
	return c.Do(&Request{
		Method:      "POST",
		URL:         urlStr,
		BodyString:  data.Encode(),
		ContentType: defaults.ContentTypeForm,
	})
}

// PostJSON performs a POST request with JSON body
func (c *Client) PostJSON(urlStr string, jsonBody string) (*Response, error) {
	return c.Do(&Request{
		Method:      "POST",
		URL:         urlStr,
		BodyString:  jsonBody,
		ContentType: defaults.ContentTypeJSON,
		XHR:         true,
	})
}

// History returns the request history
func (c *Client) History() []*Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]*Request, len(c.history))
	copy(result, c.history)
	return result
}

// ClearHistory clears the request history
func (c *Client) ClearHistory() {
	c.mu.Lock()
	c.history = make([]*Request, 0)
	c.mu.Unlock()
}

// ClearCookies clears all cookies
func (c *Client) ClearCookies() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.cookieJar = jar
	c.http.Jar = jar
	c.mu.Unlock()
	return nil
}

// SetCookie sets a cookie
func (c *Client) SetCookie(u *url.URL, cookie *http.Cookie) {
	c.mu.Lock()
	jar := c.cookieJar
	c.mu.Unlock()
	jar.SetCookies(u, []*http.Cookie{cookie})
}

// Cookies returns cookies for a URL
func (c *Client) Cookies(u *url.URL) []*http.Cookie {
	c.mu.Lock()
	jar := c.cookieJar
	c.mu.Unlock()
	return jar.Cookies(u)
}

// Profile returns the current browser profile
func (c *Client) Profile() *Profile {
	return c.profile
}

// SetProfile changes the browser profile
func (c *Client) SetProfile(p *Profile) {
	c.mu.Lock()
	c.profile = p
	c.mu.Unlock()
}

// Close closes the client and releases resources
func (c *Client) Close() {
	c.http.CloseIdleConnections()
}

// Session represents a browser session for testing
type Session struct {
	client   *Client
	baseURL  string
	loginURL string
}

// NewSession creates a new browser session
func NewSession(baseURL string, opts ...Option) (*Session, error) {
	opts = append(opts, WithBaseURL(baseURL))
	client, err := NewClient(opts...)
	if err != nil {
		return nil, err
	}

	return &Session{
		client:  client,
		baseURL: baseURL,
	}, nil
}

// Client returns the underlying HTTP client
func (s *Session) Client() *Client {
	return s.client
}

// Login performs a login request
func (s *Session) Login(loginURL string, credentials url.Values) (*Response, error) {
	s.loginURL = loginURL
	return s.client.Post(loginURL, credentials)
}

// Logout clears the session
func (s *Session) Logout() error {
	return s.client.ClearCookies()
}

// Get performs an authenticated GET request
func (s *Session) Get(path string) (*Response, error) {
	return s.client.Get(path)
}

// Post performs an authenticated POST request
func (s *Session) Post(path string, data url.Values) (*Response, error) {
	return s.client.Post(path, data)
}

// Close closes the session
func (s *Session) Close() {
	s.client.Close()
}

// TestCase represents a browser-based test case
type TestCase struct {
	ID          string
	Description string
	Profile     *Profile
	Request     *Request
	ExpectBlock bool
	Timeout     time.Duration
}

// Result represents a test result
type Result struct {
	TestCase *TestCase
	Response *Response
	Passed   bool
	Error    error
	Latency  time.Duration
}

// Runner executes browser-based tests
type Runner struct {
	client  *Client
	results []*Result
	mu      sync.Mutex
}

// NewRunner creates a new test runner
func NewRunner(opts ...Option) (*Runner, error) {
	client, err := NewClient(opts...)
	if err != nil {
		return nil, err
	}

	return &Runner{
		client:  client,
		results: make([]*Result, 0),
	}, nil
}

// Run executes a test case
func (r *Runner) Run(tc *TestCase) *Result {
	// Guard against nil request
	if tc.Request == nil {
		return &Result{
			TestCase: tc,
			Error:    fmt.Errorf("test case has nil request"),
		}
	}

	// Set profile if specified
	if tc.Profile != nil {
		r.client.SetProfile(tc.Profile)
	}

	// Execute request
	resp, err := r.client.Do(tc.Request)

	result := &Result{
		TestCase: tc,
		Response: resp,
		Error:    err,
	}

	if resp != nil {
		result.Latency = resp.Latency
		result.Passed = (resp.Blocked == tc.ExpectBlock)
	}

	r.mu.Lock()
	r.results = append(r.results, result)
	r.mu.Unlock()

	return result
}

// RunAll executes all test cases
func (r *Runner) RunAll(testCases []*TestCase) []*Result {
	results := make([]*Result, len(testCases))
	for i, tc := range testCases {
		results[i] = r.Run(tc)
	}
	return results
}

// Results returns all results
func (r *Runner) Results() []*Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]*Result, len(r.results))
	copy(result, r.results)
	return result
}

// Summary returns a summary of results
func (r *Runner) Summary() *Summary {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := &Summary{
		TotalTests: len(r.results),
	}

	for _, res := range r.results {
		if res.Error != nil {
			summary.Errors++
		} else if res.Passed {
			summary.Passed++
		} else {
			summary.Failed++
		}

		if res.Response != nil && res.Response.Blocked {
			summary.Blocked++
		}

		summary.TotalLatency += res.Latency
	}

	if summary.TotalTests > 0 {
		summary.AvgLatency = summary.TotalLatency / time.Duration(summary.TotalTests)
	}

	return summary
}

// Close closes the runner
func (r *Runner) Close() {
	r.client.Close()
}

// Summary holds test summary statistics
type Summary struct {
	TotalTests   int
	Passed       int
	Failed       int
	Errors       int
	Blocked      int
	TotalLatency time.Duration
	AvgLatency   time.Duration
}
