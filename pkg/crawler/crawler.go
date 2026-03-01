// Package crawler provides web crawling capabilities
// Based on katana/gospider's crawling features with scope control and recursion
package crawler

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// CrawlResult represents a crawled page result
type CrawlResult struct {
	URL           string            `json:"url"`
	FinalURL      string            `json:"final_url,omitempty"` // After redirects
	Depth         int               `json:"depth"`
	StatusCode    int               `json:"status_code"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int               `json:"content_length"`
	Title         string            `json:"title,omitempty"`
	Links         []string          `json:"links,omitempty"`
	Forms         []FormInfo        `json:"forms,omitempty"`
	Scripts       []string          `json:"scripts,omitempty"`
	Stylesheets   []string          `json:"stylesheets,omitempty"`
	Images        []string          `json:"images,omitempty"`
	Comments      []string          `json:"comments,omitempty"`
	Meta          map[string]string `json:"meta,omitempty"`
	Headers       http.Header       `json:"headers,omitempty"`
	RedirectChain []string          `json:"redirect_chain,omitempty"` // Full redirect history
	Error         string            `json:"error,omitempty"`
	APIEndpoints  []APIEndpointInfo `json:"api_endpoints,omitempty"`
	Subdomains    []string          `json:"subdomains,omitempty"` // Discovered subdomains
	Emails        []string          `json:"emails,omitempty"`     // Extracted email addresses
	Parameters    []string          `json:"parameters,omitempty"` // Discovered parameter names
	Secrets       []SecretFinding   `json:"secrets,omitempty"`    // Potential secrets/tokens
	Timestamp     time.Time         `json:"timestamp"`
}

// FormInfo represents an HTML form
type FormInfo struct {
	Action    string      `json:"action"`
	Method    string      `json:"method"`
	ID        string      `json:"id,omitempty"`
	Name      string      `json:"name,omitempty"`
	Inputs    []InputInfo `json:"inputs,omitempty"`
	Enctype   string      `json:"enctype,omitempty"`
	HasUpload bool        `json:"has_upload,omitempty"` // Contains file input
}

// InputInfo represents a form input
type InputInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value,omitempty"`
	ID          string `json:"id,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// CrawlStats holds crawl progress and summary statistics.
type CrawlStats struct {
	PagesCrawled int   `json:"pages_crawled"`
	PagesQueued  int   `json:"pages_queued"`
	PagesDropped int64 `json:"pages_dropped"`
	Errors       int   `json:"errors"`
}

// Config holds crawler configuration
type Config struct {
	// Crawl limits
	MaxDepth       int           `json:"max_depth"`
	MaxPages       int           `json:"max_pages"`
	MaxConcurrency int           `json:"max_concurrency"`
	Timeout        time.Duration `json:"timeout"`
	Delay          time.Duration `json:"delay"`

	// Scope control
	IncludeScope      []string `json:"include_scope,omitempty"` // Regex patterns to include
	ExcludeScope      []string `json:"exclude_scope,omitempty"` // Regex patterns to exclude
	IncludeSubdomains bool     `json:"include_subdomains"`
	SameDomain        bool     `json:"same_domain"`
	SamePort          bool     `json:"same_port"`

	// Feature flags
	ExtractForms    bool `json:"extract_forms"`
	ExtractScripts  bool `json:"extract_scripts"`
	ExtractLinks    bool `json:"extract_links"`
	ExtractComments bool `json:"extract_comments"`
	ExtractMeta     bool `json:"extract_meta"`
	FollowRobots    bool `json:"follow_robots"`

	// Additional extraction options
	ExtractEmails    bool `json:"extract_emails"`
	ExtractEndpoints bool `json:"extract_endpoints"`
	ExtractParams    bool `json:"extract_params"`
	ExtractSecrets   bool `json:"extract_secrets"`

	// Advanced crawling options
	PathClimbing    bool `json:"path_climbing"`     // Crawl parent paths (/a/b/c → /a/b/, /a/)
	FormFilling     bool `json:"form_filling"`      // Auto-fill and submit forms
	CrossDomainJS   bool `json:"cross_domain_js"`   // Analyze JS files from CDNs outside scope
	SkipJSLibraries bool `json:"skip_js_libraries"` // Skip analysis of jQuery/React/Angular/etc.

	// Request options
	UserAgent  string            `json:"user_agent"`
	Headers    map[string]string `json:"headers,omitempty"`
	Cookies    []*http.Cookie    `json:"cookies,omitempty"`
	Proxy      string            `json:"proxy,omitempty"`
	SkipVerify bool              `json:"skip_verify"`

	// JavaScript/Headless options (not yet implemented — flags are parsed but ignored)
	JSRendering bool          `json:"js_rendering"`
	JSTimeout   time.Duration `json:"js_timeout"`
	WaitFor     string        `json:"wait_for,omitempty"` // CSS selector to wait for

	// Retry options
	MaxRetries int           `json:"max_retries"` // Retries on transient errors (default: 2)
	RetryDelay time.Duration `json:"retry_delay"` // Base delay between retries (default: 500ms)

	// Robots.txt disallowed paths (populated at crawl start when FollowRobots is true)
	RobotsDisallowed []string `json:"robots_disallowed,omitempty"`

	// Debug options
	Debug   bool `json:"debug"`
	Verbose bool `json:"verbose"`

	// Progress callback (optional) — called periodically with crawl stats
	OnProgress func(stats CrawlStats) `json:"-"`

	// Extensions to crawl
	AllowedExtensions    []string `json:"allowed_extensions,omitempty"`
	DisallowedExtensions []string `json:"disallowed_extensions,omitempty"`
}

// DefaultConfig returns default crawler configuration
func DefaultConfig() *Config {
	return &Config{
		MaxDepth:          defaults.DepthMedium,
		MaxPages:          defaults.CrawlMaxPages,
		MaxConcurrency:    defaults.ConcurrencyMedium,
		Timeout:           httpclient.TimeoutFuzzing,
		Delay:             duration.CrawlDelay,
		MaxRetries:        defaults.RetryLow,
		RetryDelay:        duration.RetryBaseBackoff,
		ExtractForms:      true,
		ExtractScripts:    true,
		ExtractLinks:      true,
		ExtractComments:   false,
		ExtractMeta:       true,
		ExtractEndpoints:  true,
		FollowRobots:      true,
		SameDomain:        true,
		IncludeSubdomains: true,
		PathClimbing:      true,
		FormFilling:       true,
		CrossDomainJS:     true,
		SkipJSLibraries:   true,
		UserAgent:         ui.UserAgentWithContext("crawler"),
		DisallowedExtensions: []string{
			".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
			".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm",
			".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
			".zip", ".tar", ".gz", ".rar", ".7z",
			".woff", ".woff2", ".ttf", ".eot", ".otf",
		},
	}
}

// Crawler performs web crawling
type Crawler struct {
	config        *Config
	client        *http.Client
	visited       map[string]bool
	visitedMu     sync.RWMutex
	contentSeen   map[string]bool // SHA-256 body hashes for content dedup
	contentSeenMu sync.Mutex
	soft404Hash   string // Body hash of a known-nonexistent path
	queue         chan *crawlTask
	results       chan *CrawlResult
	includeRE     []*regexp.Regexp
	excludeRE     []*regexp.Regexp
	baseDomain    string
	baseHostname  string // hostname without port
	basePort      string // port (or default for scheme)
	jsAnalyzer    *js.Analyzer
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	pageCount     int
	pageMu        sync.Mutex
	inFlight      atomic.Int64 // tracks tasks in-flight for graceful shutdown
	closeOnce     sync.Once    // guards c.queue close to prevent double-close panic
	droppedCount  atomic.Int64 // URLs dropped because queue was full
	errorCount    atomic.Int64 // requests that resulted in errors
}

type crawlTask struct {
	URL   string
	Depth int
}

// NewCrawler creates a new crawler
func NewCrawler(config *Config) *Crawler {
	if config == nil {
		config = DefaultConfig()
	}

	if config.JSRendering {
		slog.Warn("[crawl] --js/--javascript flag is not yet implemented; headless rendering is unavailable. Use the event_crawl MCP tool for SPA crawling.")
	}

	// Build HTTP client — always use a custom client for crawling so we get
	// cookie jar + redirect following.
	cfg := httpclient.DefaultConfig()
	cfg.Timeout = config.Timeout
	cfg.InsecureSkipVerify = config.SkipVerify
	cfg.CookieJar = true // Persist server-set cookies across the crawl session
	cfg.RetryCount = config.MaxRetries
	cfg.RetryDelay = config.RetryDelay
	if config.Proxy != "" {
		cfg.Proxy = config.Proxy
	}

	// Override CheckRedirect: we need to follow redirects ourselves to track the chain
	// and validate each hop against scope. The default httpclient uses ErrUseLastResponse.
	client := httpclient.New(cfg)
	client.CheckRedirect = nil // Use Go default: follow up to 10 redirects

	c := &Crawler{
		config:      config,
		visited:     make(map[string]bool),
		contentSeen: make(map[string]bool),
		queue:       make(chan *crawlTask, defaults.ChannelLarge),
		results:     make(chan *CrawlResult, defaults.ChannelMedium),
		client:      client,
		jsAnalyzer:  js.NewAnalyzer(),
	}

	// Compile include patterns
	for _, pattern := range config.IncludeScope {
		if re, err := regexcache.Get(pattern); err == nil {
			c.includeRE = append(c.includeRE, re)
		}
	}

	// Compile exclude patterns
	for _, pattern := range config.ExcludeScope {
		if re, err := regexcache.Get(pattern); err == nil {
			c.excludeRE = append(c.excludeRE, re)
		}
	}

	return c
}

// Crawl starts crawling from the given URL
func (c *Crawler) Crawl(ctx context.Context, startURL string) (<-chan *CrawlResult, error) {
	parsed, err := url.Parse(startURL)
	if err != nil {
		return nil, err
	}

	c.baseDomain = parsed.Host
	c.baseHostname = parsed.Hostname()
	c.basePort = parsed.Port()
	if c.basePort == "" {
		if parsed.Scheme == "https" {
			c.basePort = "443"
		} else {
			c.basePort = "80"
		}
	}
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Establish soft-404 baseline: request a known-nonexistent path and hash the body
	c.detectSoft404(parsed)

	// Enforce robots.txt: check disallowed paths and extract Allow/Sitemap URLs
	if c.config.FollowRobots {
		c.loadRobotsTxt(parsed)
	}

	// Fetch sitemap.xml for additional crawl targets
	c.loadSitemaps(parsed)

	// Add start URL to queue BEFORE starting workers to avoid a race where
	// workers find an empty queue and exit before the seed is enqueued.
	c.inFlight.Add(1)
	c.queue <- &crawlTask{URL: startURL, Depth: 0}

	// Start workers
	for i := 0; i < c.config.MaxConcurrency; i++ {
		c.wg.Add(1)
		go c.worker()
	}

	// Monitor and close results when done
	go func() {
		c.wg.Wait()
		c.cancel() // Release context resources on normal completion
		close(c.results)
	}()

	// Start progress reporter if callback is set
	if c.config.OnProgress != nil {
		go c.progressReporter()
	}

	return c.results, nil
}

// Stop stops the crawler
func (c *Crawler) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

// Stats returns the current crawl statistics.
func (c *Crawler) Stats() CrawlStats {
	c.pageMu.Lock()
	pages := c.pageCount
	c.pageMu.Unlock()

	c.visitedMu.RLock()
	queued := len(c.visited)
	c.visitedMu.RUnlock()

	return CrawlStats{
		PagesCrawled: pages,
		PagesQueued:  queued,
		PagesDropped: c.droppedCount.Load(),
		Errors:       int(c.errorCount.Load()),
	}
}

func (c *Crawler) progressReporter() {
	ticker := time.NewTicker(duration.StreamStd)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			// Fire one final progress update
			if c.config.OnProgress != nil {
				c.config.OnProgress(c.Stats())
			}
			return
		case <-ticker.C:
			if c.config.OnProgress != nil {
				c.config.OnProgress(c.Stats())
			}
		}
	}
}

func (c *Crawler) worker() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case task, ok := <-c.queue:
			if !ok {
				return
			}

			// Check page limit
			c.pageMu.Lock()
			if c.pageCount >= c.config.MaxPages {
				c.pageMu.Unlock()
				if c.inFlight.Add(-1) == 0 {
					c.closeOnce.Do(func() { close(c.queue) })
				}
				continue
			}
			c.pageCount++
			c.pageMu.Unlock()

			// Process the task
			result := c.crawlURL(task.URL, task.Depth)

			if result.Error != "" {
				c.errorCount.Add(1)
			}

			select {
			case c.results <- result:
			case <-c.ctx.Done():
				c.inFlight.Add(-1)
				return
			}

			// Add delay (context-aware)
			if c.config.Delay > 0 {
				select {
				case <-c.ctx.Done():
					return
				case <-time.After(c.config.Delay):
				}
			}

			// Queue new URLs if within depth
			if task.Depth < c.config.MaxDepth && result.Error == "" {
				for _, link := range result.Links {
					c.queueURL(link, task.Depth+1)
				}
				// Also queue form action URLs as crawl targets
				for _, form := range result.Forms {
					if form.Action != "" {
						c.queueURL(form.Action, task.Depth+1)
					}
				}
				// Queue external script URLs for JS endpoint extraction
				for _, script := range result.Scripts {
					c.queueURL(script, task.Depth+1)
					// .min.js → .js source fallback: source files have better variable names
					if strings.HasSuffix(strings.ToLower(script), ".min.js") {
						base := script[:len(script)-len(".min.js")]
						c.queueURL(base+".js", task.Depth+1)
						c.queueURL(base+".js.map", task.Depth+1)
					}
				}
				// Queue discovered API endpoints
				for _, ep := range result.APIEndpoints {
					if ep.Path != "" {
						if taskParsed, parseErr := url.Parse(task.URL); parseErr == nil {
							if resolved := resolveURL(ep.Path, taskParsed); resolved != "" {
								c.queueURL(resolved, task.Depth+1)
							}
						}
					}
				}

				// Path climbing: crawl parent paths to discover directory listings
				if c.config.PathClimbing {
					c.climbPaths(task.URL, task.Depth+1)
				}

				// Queue discovered subdomains
				for _, sub := range result.Subdomains {
					subURL := fmt.Sprintf("https://%s/", sub)
					c.queueURL(subURL, task.Depth+1)
				}
			}

			// Mark this task done; if no more in-flight tasks, close queue
			if c.inFlight.Add(-1) == 0 {
				c.closeOnce.Do(func() { close(c.queue) })
			}
		}
	}
}

// isRetryableStatus returns true for HTTP status codes that indicate a transient error.
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

func (c *Crawler) crawlURL(rawURL string, depth int) *CrawlResult {
	result := &CrawlResult{
		URL:       rawURL,
		Depth:     depth,
		Timestamp: time.Now(),
		Meta:      make(map[string]string),
	}

	// Parse URL
	parsed, err := url.Parse(rawURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Create request
	req, err := http.NewRequestWithContext(c.ctx, "GET", rawURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", c.config.UserAgent)
	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}

	// Add cookies
	for _, cookie := range c.config.Cookies {
		req.AddCookie(cookie)
	}

	// Make request with retry for transient failures.
	// The httpclient retryTransport handles transport-level retries. Here we add
	// application-level retry for HTTP status codes (429, 502, 503, 504).
	var resp *http.Response
	maxAttempts := c.config.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := c.config.RetryDelay * time.Duration(1<<(attempt-1)) // Exponential backoff
			select {
			case <-time.After(delay):
			case <-c.ctx.Done():
				result.Error = c.ctx.Err().Error()
				return result
			}

			// Recreate request for retry (body may have been consumed)
			req, err = http.NewRequestWithContext(c.ctx, "GET", rawURL, nil)
			if err != nil {
				result.Error = err.Error()
				return result
			}
			req.Header.Set("User-Agent", c.config.UserAgent)
			for k, v := range c.config.Headers {
				req.Header.Set(k, v)
			}
			for _, cookie := range c.config.Cookies {
				req.AddCookie(cookie)
			}
		}

		resp, err = c.client.Do(req)
		if err != nil {
			if attempt < maxAttempts-1 {
				continue // Retry on transport error
			}
			result.Error = err.Error()
			return result
		}

		if !isRetryableStatus(resp.StatusCode) || attempt == maxAttempts-1 {
			break // Success or final attempt
		}

		// Respect Retry-After header if present
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, parseErr := time.ParseDuration(ra + "s"); parseErr == nil && secs > 0 && secs <= duration.RetryAfterMax {
				select {
				case <-time.After(secs):
				case <-c.ctx.Done():
					iohelper.DrainAndClose(resp.Body)
					result.Error = c.ctx.Err().Error()
					return result
				}
			}
		}
		iohelper.DrainAndClose(resp.Body)
	}
	defer iohelper.DrainAndClose(resp.Body)

	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.Headers = resp.Header

	// Track redirect chain: if the final URL differs from the original, record the chain
	finalURL := resp.Request.URL.String()
	if finalURL != rawURL {
		result.FinalURL = finalURL
		// Build chain from the redirect history in resp.Request
		result.RedirectChain = buildRedirectChain(resp)
	}

	// Read body
	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.ContentLength = len(body)

	// Extract URLs from response headers regardless of content type.
	// Link, CSP, Location, Content-Location, and Set-Cookie headers reveal
	// application structure even for non-HTML responses.
	if c.config.ExtractLinks {
		headerLinks, headerEPs := extractFromResponseHeaders(resp.Header, parsed)
		result.Links = append(result.Links, headerLinks...)
		result.APIEndpoints = append(result.APIEndpoints, headerEPs...)
	}

	// Handle JSON API responses — extract URLs/paths from JSON values.
	if strings.Contains(result.ContentType, "application/json") || strings.Contains(result.ContentType, "text/json") {
		if c.config.ExtractEndpoints {
			jsonLinks, jsonEPs := extractFromJSONResponse(body, parsed)
			result.Links = append(result.Links, jsonLinks...)
			result.APIEndpoints = append(result.APIEndpoints, jsonEPs...)
			// LinkFinder catches additional paths in JSON string values
			lfLinks, lfEPs := extractWithLinkFinder(string(body), parsed)
			result.Links = append(result.Links, lfLinks...)
			result.APIEndpoints = append(result.APIEndpoints, lfEPs...)
		}
		if c.config.ExtractSecrets {
			result.Secrets = extractSecrets(string(body), rawURL)
		}
		return result
	}

	// Handle JavaScript file responses — extract URLs and endpoints.
	if strings.Contains(result.ContentType, "javascript") {
		if c.config.ExtractEndpoints {
			// Skip analysis of common JS libraries (jQuery, React, etc.) — they only produce noise
			if c.config.SkipJSLibraries && isCommonJSLibrary(rawURL) {
				return result
			}
			jsLinks, jsEPs := extractFromJSFile(body, parsed, c.jsAnalyzer)
			result.Links = append(result.Links, jsLinks...)
			result.APIEndpoints = append(result.APIEndpoints, jsEPs...)
			// LinkFinder regex as fallback — catches things the AST parser misses
			lfLinks, lfEPs := extractWithLinkFinder(string(body), parsed)
			result.Links = append(result.Links, lfLinks...)
			result.APIEndpoints = append(result.APIEndpoints, lfEPs...)
		}
		// Secrets commonly leak in JS bundles
		if c.config.ExtractSecrets {
			result.Secrets = extractSecrets(string(body), rawURL)
		}
		return result
	}

	// Handle XML responses (sitemap, RSS, etc.) — extract with LinkFinder
	if strings.Contains(result.ContentType, "text/xml") || strings.Contains(result.ContentType, "application/xml") {
		if c.config.ExtractEndpoints {
			lfLinks, lfEPs := extractWithLinkFinder(string(body), parsed)
			result.Links = append(result.Links, lfLinks...)
			result.APIEndpoints = append(result.APIEndpoints, lfEPs...)
		}
		return result
	}

	// Only full HTML parsing for text/html content
	if !strings.Contains(result.ContentType, "text/html") {
		return result
	}

	// Content-hash dedup: skip extraction if we've already seen identical content
	bodyHash := hashBody(body)
	if c.isContentDuplicate(bodyHash) {
		return result // Return the result but skip link extraction to avoid loops
	}

	// Soft-404 detection: if response matches the baseline, skip extraction
	if c.soft404Hash != "" && bodyHash == c.soft404Hash {
		return result
	}

	htmlStr := string(body)

	// Detect <base> tag for URL resolution
	base := detectBaseTag(htmlStr, parsed)

	// Extract title (use regex — title is simple enough and tokenizer overhead is unnecessary)
	result.Title = extractTitle(htmlStr)

	// Extract links using HTML tokenizer
	if c.config.ExtractLinks {
		result.Links = extractLinksTokenizer(htmlStr, base)
	}

	// Extract forms using HTML tokenizer
	if c.config.ExtractForms {
		result.Forms = extractFormsTokenizer(htmlStr, base)
	}

	// Extract scripts using HTML tokenizer
	if c.config.ExtractScripts {
		result.Scripts = extractScriptsTokenizer(htmlStr, base)
	}

	// Extract stylesheets
	result.Stylesheets = extractStylesheetsTokenizer(htmlStr, base)

	// Extract images
	result.Images = extractImagesTokenizer(htmlStr, base)

	// Extract comments using HTML tokenizer
	if c.config.ExtractComments {
		result.Comments = extractCommentsTokenizer(htmlStr)
	}

	// Extract meta tags
	if c.config.ExtractMeta {
		result.Meta = extractMetaTokenizer(htmlStr)
	}

	// Extract URLs from inline <script> tags — critical for SPAs.
	// React/Vue/Angular/Next.js define routes in inline bundles.
	if c.config.ExtractScripts {
		inlineLinks, inlineEPs := extractInlineJSTokenizer(htmlStr, base, c.jsAnalyzer)
		result.Links = append(result.Links, inlineLinks...)
		result.APIEndpoints = append(result.APIEndpoints, inlineEPs...)
	}

	// Extract URLs from media elements (iframe, embed, object, video, audio, source)
	if c.config.ExtractLinks {
		result.Links = append(result.Links, extractMediaElementsTokenizer(htmlStr, base)...)
	}

	// Extract URLs from CSS url() in inline styles
	result.Links = append(result.Links, extractCSSURLsTokenizer(htmlStr, base)...)

	// LinkFinder regex as body-wide fallback — catches URLs in inline JS,
	// JSON-LD, data attributes, and anywhere else the structured parsers miss.
	if c.config.ExtractEndpoints {
		lfLinks, lfEPs := extractWithLinkFinder(htmlStr, base)
		result.Links = append(result.Links, lfLinks...)
		result.APIEndpoints = append(result.APIEndpoints, lfEPs...)
	}

	// Add form actions to links so they get crawled
	for i := range result.Forms {
		if result.Forms[i].Action != "" {
			result.Links = append(result.Links, result.Forms[i].Action)
		}
		// Flag upload forms (high-value WAF testing targets)
		for _, input := range result.Forms[i].Inputs {
			if strings.EqualFold(input.Type, "file") {
				result.Forms[i].HasUpload = true
				break
			}
		}
	}

	// Subdomain discovery from response body
	if c.config.IncludeSubdomains && c.baseDomain != "" {
		result.Subdomains = extractSubdomains(htmlStr, c.baseDomain)
	}

	// Cross-domain JS analysis: analyze out-of-scope scripts for endpoints
	if c.config.CrossDomainJS && c.config.ExtractEndpoints {
		c.analyzeCrossDomainScripts(result.Scripts, base, result)
	}

	// Auto-fill and submit forms to discover POST-based endpoints
	if c.config.FormFilling {
		for _, form := range result.Forms {
			if filledReq := fillForm(form, base); filledReq != nil {
				// Add the filled form URL to links for crawling
				result.Links = append(result.Links, filledReq.URL)
				result.APIEndpoints = append(result.APIEndpoints, APIEndpointInfo{
					Path:   filledReq.URL,
					Method: filledReq.Method,
					Source: "form-fill",
				})
			}
		}
	}

	// Email extraction from page content
	if c.config.ExtractEmails {
		result.Emails = extractEmails(htmlStr)
	}

	// Parameter extraction from discovered URLs
	if c.config.ExtractParams {
		result.Parameters = extractParameters(result.Links)
	}

	// Secret detection in page source
	if c.config.ExtractSecrets {
		result.Secrets = extractSecrets(htmlStr, rawURL)
	}

	return result
}

func (c *Crawler) queueURL(rawURL string, depth int) {
	// Normalize URL
	normalized := c.normalizeURL(rawURL)
	if normalized == "" {
		return
	}

	// Check scope, extension, and robots BEFORE marking as visited to avoid
	// unbounded memory growth from out-of-scope URLs polluting the visited map.
	if !c.inScope(normalized) {
		return
	}
	if !c.allowedExtension(normalized) {
		return
	}
	if c.config.FollowRobots && c.isRobotsDisallowed(normalized) {
		return
	}

	// Check if already visited (after scope filtering)
	c.visitedMu.Lock()
	if c.visited[normalized] {
		c.visitedMu.Unlock()
		return
	}
	c.visited[normalized] = true
	c.visitedMu.Unlock()

	// Add to queue (non-blocking)
	c.inFlight.Add(1)
	select {
	case c.queue <- &crawlTask{URL: normalized, Depth: depth}:
	default:
		// Queue full — track the drop
		c.inFlight.Add(-1)
		c.droppedCount.Add(1)
		if c.config.Verbose {
			slog.Debug("[crawl] queue full, dropped", "url", normalized)
		}
	}
}

func (c *Crawler) normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" || rawURL == "#" {
		return ""
	}

	// Skip javascript:, mailto:, tel:, etc.
	lower := strings.ToLower(rawURL)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Remove fragment
	parsed.Fragment = ""

	// Normalize path
	if parsed.Path == "" {
		parsed.Path = "/"
	}

	// Strip tracking parameters and sort query params for dedup
	if parsed.RawQuery != "" {
		params := parsed.Query()
		for key := range params {
			if isTrackingParam(key) {
				params.Del(key)
			}
		}
		// Sort query parameters for consistent dedup
		parsed.RawQuery = sortedQueryString(params)
	}

	return parsed.String()
}

// trackingParams are query parameters that don't affect page content.
// Stripping them improves crawl dedup efficiency.
var trackingParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true,
	"utm_term": true, "utm_content": true, "utm_id": true,
	"fbclid": true, "gclid": true, "gclsrc": true, "dclid": true,
	"msclkid": true, "twclid": true, "li_fat_id": true,
	"mc_cid": true, "mc_eid": true, "igshid": true,
	"_ga": true, "_gl": true, "_gid": true,
	"ref": true, "ref_src": true, "ref_url": true,
	"yclid": true, "ymclid": true, "ysclid": true,
	"_hsenc": true, "_hsmi": true, "hsa_cam": true,
}

func isTrackingParam(key string) bool {
	return trackingParams[strings.ToLower(key)]
}

// sortedQueryString produces a deterministic query string with params sorted by key.
func sortedQueryString(params url.Values) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		vals := params[k]
		sort.Strings(vals)
		for j, v := range vals {
			if i > 0 || j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

// commonJSLibraryRE matches URLs of common JS libraries that should be skipped
// during endpoint analysis (they produce only false positives).
var commonJSLibraryRE = regexp.MustCompile(`(?i)(?:` +
	`jquery|angular(?:js)?|react(?:-dom)?|vue(?:\.runtime)?|backbone|ember|` +
	`bootstrap|foundation|materialize|bulma|semantic(?:-ui)?|` +
	`lodash|underscore|moment|dayjs|luxon|date-fns|` +
	`d3(?:\.v\d)?|chart\.?js|three(?:\.min)?|leaflet|mapbox|` +
	`webpack|polyfill|babel|core-js|regenerator|tslib|` +
	`google.*analytics|gtag|ga\.js|segment|mixpanel|amplitude|hotjar|` +
	`stripe|paypal|braintree|recaptcha|turnstile|hcaptcha|` +
	`socket\.io|sockjs|signalr|` +
	`tinymce|ckeditor|quill|codemirror|ace-editor|monaco|` +
	`swiper|slick|owl\.?carousel|lightbox|fancybox|photoswipe|` +
	`gsap|anime|velocity|wow|scroll|parallax|` +
	`font-?awesome|ionicons|material-icons|` +
	`popper|tippy|floating-ui|` +
	`highlight\.?js|prism(?:\.min)?|` +
	`sentry|bugsnag|datadog|newrelic|rollbar` +
	`)`)

// isCommonJSLibrary checks if a script URL is a known JS library that
// should be skipped during endpoint analysis.
func isCommonJSLibrary(scriptURL string) bool {
	// Extract just the filename/path portion for matching
	if parsed, err := url.Parse(scriptURL); err == nil {
		return commonJSLibraryRE.MatchString(parsed.Path)
	}
	return commonJSLibraryRE.MatchString(scriptURL)
}

func (c *Crawler) inScope(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname() // stripped of port

	// Domain check (only when SameDomain is true, which is the default)
	if c.config.SameDomain {
		if host == c.baseHostname {
			// Same domain, OK
		} else if c.config.IncludeSubdomains && strings.HasSuffix(host, "."+c.baseHostname) {
			// Subdomain, OK if allowed
		} else if len(c.includeRE) > 0 {
			// Check include patterns
			matched := false
			for _, re := range c.includeRE {
				if re.MatchString(rawURL) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		} else {
			return false
		}
	}

	// Port check (only when SamePort is true)
	if c.config.SamePort {
		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		if port != c.basePort {
			return false
		}
	}

	// Check exclude patterns
	for _, re := range c.excludeRE {
		if re.MatchString(rawURL) {
			return false
		}
	}

	return true
}

func (c *Crawler) allowedExtension(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}

	path := strings.ToLower(parsed.Path)

	// Check disallowed extensions
	for _, ext := range c.config.DisallowedExtensions {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}

	// If allowed extensions specified, check them
	if len(c.config.AllowedExtensions) > 0 {
		for _, ext := range c.config.AllowedExtensions {
			if strings.HasSuffix(path, ext) {
				return true
			}
		}
		// No extension match - allow if no extension
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash >= 0 {
			filename := path[lastSlash+1:]
			if !strings.Contains(filename, ".") {
				return true // No extension, allow
			}
		}
		return false
	}

	return true
}

// ---------- Soft-404 and content dedup ----------

// detectSoft404 requests a known-nonexistent path and stores the body hash
// to identify soft-404 pages during the crawl.
// It also fetches the real root page to avoid false positives on catch-all servers
// that serve the same content for all paths (e.g., Go's DefaultServeMux).
func (c *Crawler) detectSoft404(base *url.URL) {
	probe := *base
	probe.Path = "/waftester-nonexistent-" + fmt.Sprintf("%d", time.Now().UnixNano())

	req, err := http.NewRequestWithContext(c.ctx, "GET", probe.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Only calibrate against 200 responses (actual 404s don't need filtering)
	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return
	}

	probeHash := hashBody(body)

	// Fetch the real root page to compare — if they match, the server is a
	// catch-all (serves same content for any path) and the hash is useless.
	rootReq, err := http.NewRequestWithContext(c.ctx, "GET", base.String(), nil)
	if err != nil {
		return
	}
	rootReq.Header.Set("User-Agent", c.config.UserAgent)

	rootResp, err := c.client.Do(rootReq)
	if err != nil {
		c.soft404Hash = probeHash // Can't verify, use it anyway
		return
	}
	defer iohelper.DrainAndClose(rootResp.Body)

	rootBody, err := iohelper.ReadBodyDefault(rootResp.Body)
	if err != nil {
		c.soft404Hash = probeHash
		return
	}

	rootHash := hashBody(rootBody)
	if probeHash != rootHash {
		// Different content means the server has a distinct soft-404 page
		c.soft404Hash = probeHash
	}
	// If hashes match, server is a catch-all — don't set soft404Hash
}

func hashBody(body []byte) string {
	h := sha256.Sum256(body)
	return fmt.Sprintf("%x", h[:8]) // First 8 bytes is enough for dedup
}

func (c *Crawler) isContentDuplicate(hash string) bool {
	c.contentSeenMu.Lock()
	defer c.contentSeenMu.Unlock()

	if c.contentSeen[hash] {
		return true
	}
	c.contentSeen[hash] = true
	return false
}

// ---------- Robots.txt enforcement ----------

func (c *Crawler) loadRobotsTxt(base *url.URL) {
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", base.Scheme, base.Host)

	req, err := http.NewRequestWithContext(c.ctx, "GET", robotsURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return
	}

	robotsStr := string(body)
	disallowed := parseRobotsDisallowed(robotsStr)
	c.config.RobotsDisallowed = disallowed

	// Extract Allow and Sitemap paths for crawling
	allowedPaths := parseRobotsAllowAndSitemaps(robotsStr, base)
	for _, p := range allowedPaths {
		c.queueURL(p, 1)
	}
}

// parseRobotsDisallowed extracts Disallow paths from robots.txt for * user-agent.
func parseRobotsDisallowed(body string) []string {
	var disallowed []string
	inWildcard := false

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "user-agent:") {
			agent := strings.TrimSpace(line[len("user-agent:"):])
			inWildcard = agent == "*"
			continue
		}

		if inWildcard && strings.HasPrefix(lower, "disallow:") {
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" {
				disallowed = append(disallowed, path)
			}
		}
	}

	return disallowed
}

// parseRobotsAllowAndSitemaps extracts Allow paths and Sitemap URLs from robots.txt.
func parseRobotsAllowAndSitemaps(body string, base *url.URL) []string {
	var urls []string
	inWildcard := false

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lower := strings.ToLower(line)

		// Sitemap directives are global (not user-agent specific)
		if strings.HasPrefix(lower, "sitemap:") {
			sitemapURL := strings.TrimSpace(line[len("sitemap:"):])
			if sitemapURL != "" {
				urls = append(urls, sitemapURL)
			}
			continue
		}

		if strings.HasPrefix(lower, "user-agent:") {
			agent := strings.TrimSpace(line[len("user-agent:"):])
			inWildcard = agent == "*"
			continue
		}

		if inWildcard && strings.HasPrefix(lower, "allow:") {
			path := strings.TrimSpace(line[len("allow:"):])
			if path != "" && path != "/" {
				if resolved := resolveURL(path, base); resolved != "" {
					urls = append(urls, resolved)
				}
			}
		}
	}

	return urls
}

func (c *Crawler) isRobotsDisallowed(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	path := parsed.Path
	for _, disallowed := range c.config.RobotsDisallowed {
		if strings.HasPrefix(path, disallowed) {
			return true
		}
	}
	return false
}

// ---------- Sitemap.xml parsing ----------

// sitemapPaths lists common sitemap locations to probe (same set as gospider).
var sitemapPaths = []string{
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/sitemap-index.xml",
	"/sitemapindex.xml",
	"/sitemap_news.xml",
	"/sitemap-news.xml",
	"/post-sitemap.xml",
	"/page-sitemap.xml",
	"/portfolio-sitemap.xml",
	"/category-sitemap.xml",
	"/author-sitemap.xml",
}

// loadSitemaps fetches sitemap.xml files and queues discovered URLs for crawling.
func (c *Crawler) loadSitemaps(base *url.URL) {
	for _, path := range sitemapPaths {
		sitemapURL := fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, path)
		c.parseSitemapURL(sitemapURL, base, 0)
	}
}

// parseSitemapURL fetches and parses a single sitemap URL. Handles sitemap indexes
// recursively (up to depth 2 to prevent infinite loops).
func (c *Crawler) parseSitemapURL(sitemapURL string, base *url.URL, depth int) {
	if depth > 2 {
		return
	}

	req, err := http.NewRequestWithContext(c.ctx, "GET", sitemapURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return
	}

	// Extract URLs using a simple regex — handles both <loc> and <sitemap> entries
	locRE := regexcache.MustGet(`<loc>\s*([^<]+?)\s*</loc>`)
	for _, match := range locRE.FindAllSubmatch(body, -1) {
		if len(match) < 2 {
			continue
		}
		loc := strings.TrimSpace(string(match[1]))
		if loc == "" {
			continue
		}

		// If the located URL is itself a sitemap, parse it recursively
		lower := strings.ToLower(loc)
		if strings.HasSuffix(lower, ".xml") || strings.Contains(lower, "sitemap") {
			c.parseSitemapURL(loc, base, depth+1)
		}

		// Queue as crawl target
		c.queueURL(loc, 1)
	}
}

// ---------- Path climbing ----------

// climbPaths extracts parent paths from a URL and queues them for crawling.
// Given /a/b/c/page, it queues /a/b/c/, /a/b/, /a/ to discover directory listings.
func (c *Crawler) climbPaths(rawURL string, depth int) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	path := parsed.Path
	// Strip trailing filename
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash <= 0 {
		return
	}
	path = path[:lastSlash]

	// Walk up directory tree
	for path != "" && path != "/" {
		parent := *parsed
		parent.Path = path + "/"
		parent.RawQuery = ""
		c.queueURL(parent.String(), depth)

		lastSlash = strings.LastIndex(path, "/")
		if lastSlash <= 0 {
			break
		}
		path = path[:lastSlash]
	}
}

// ---------- Subdomain discovery ----------

// extractSubdomains finds subdomains of baseDomain mentioned in text content.
func extractSubdomains(text, baseDomain string) []string {
	// Build a regex that matches *.baseDomain
	escaped := regexp.QuoteMeta(baseDomain)
	re, err := regexp.Compile(`(?i)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.` + escaped + `)`)
	if err != nil {
		return nil
	}

	matches := re.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(matches))
	var result []string
	for _, m := range matches {
		lower := strings.ToLower(m)
		if lower == baseDomain || seen[lower] {
			continue
		}
		seen[lower] = true
		result = append(result, lower)
	}
	return result
}

// ---------- Cross-domain JS analysis ----------

// analyzeCrossDomainScripts fetches and analyzes JS files that are outside the
// crawl scope (e.g., CDN-hosted application JS). Discovered endpoints are added
// back to the result only if they resolve to in-scope URLs.
func (c *Crawler) analyzeCrossDomainScripts(scripts []string, base *url.URL, result *CrawlResult) {
	for _, script := range scripts {
		if !c.inScope(script) && !isCommonJSLibrary(script) {
			c.analyzeExternalJS(script, base, result)
		}
	}
}

func (c *Crawler) analyzeExternalJS(jsURL string, base *url.URL, result *CrawlResult) {
	req, err := http.NewRequestWithContext(c.ctx, "GET", jsURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil || len(body) == 0 {
		return
	}

	jsParsed, _ := url.Parse(jsURL)
	if jsParsed == nil {
		jsParsed = base
	}

	// Run both AST analyzer and LinkFinder
	jsLinks, jsEPs := extractFromJSFile(body, jsParsed, c.jsAnalyzer)
	lfLinks, lfEPs := extractWithLinkFinder(string(body), jsParsed)

	// Only keep endpoints that resolve to in-scope URLs
	for _, link := range append(jsLinks, lfLinks...) {
		if c.inScope(link) {
			result.Links = append(result.Links, link)
		}
	}
	for _, ep := range append(jsEPs, lfEPs...) {
		if resolved := resolveURL(ep.Path, base); resolved != "" && c.inScope(resolved) {
			ep.Source = "crossdomain-" + ep.Source
			result.APIEndpoints = append(result.APIEndpoints, ep)
		}
	}
}

// ---------- Form filling ----------

// FilledFormRequest represents a form that has been auto-filled for submission.
type FilledFormRequest struct {
	URL         string
	Method      string
	ContentType string
	Body        string
}

// formFillDefaults provides type-aware default values for form inputs.
var formFillDefaults = map[string]string{
	"email":    "test@example.org",
	"password": "TestP@ssw0rd1!",
	"tel":      "2124567890",
	"number":   "1",
	"range":    "50",
	"color":    "#e66465",
	"date":     "2025-01-15",
	"time":     "12:00",
	"url":      "https://example.com",
	"search":   "test",
	"month":    "2025-01",
	"week":     "2025-W03",
}

// fillForm generates a filled form request for submission.
// Hidden input values are preserved (CSRF tokens, etc.).
// Returns nil if the form cannot be filled.
func fillForm(form FormInfo, base *url.URL) *FilledFormRequest {
	if form.Action == "" && len(form.Inputs) == 0 {
		return nil
	}

	params := url.Values{}
	for _, input := range form.Inputs {
		if input.Name == "" {
			continue
		}

		val := input.Value
		if val == "" {
			// Don't overwrite hidden inputs — they contain CSRF tokens, etc.
			if strings.EqualFold(input.Type, "hidden") {
				continue
			}

			// Use placeholder if available
			if input.Placeholder != "" {
				val = input.Placeholder
			} else if def, ok := formFillDefaults[strings.ToLower(input.Type)]; ok {
				val = def
			} else {
				val = "test"
			}
		}
		params.Set(input.Name, val)
	}

	if len(params) == 0 {
		return nil
	}

	method := strings.ToUpper(form.Method)
	if method == "" {
		method = "GET"
	}

	actionURL := form.Action
	if actionURL == "" && base != nil {
		actionURL = base.String()
	}

	result := &FilledFormRequest{
		Method: method,
	}

	if method == "GET" {
		// Append params to URL
		parsed, err := url.Parse(actionURL)
		if err != nil {
			return nil
		}
		existing := parsed.Query()
		for k, vs := range params {
			for _, v := range vs {
				existing.Set(k, v)
			}
		}
		parsed.RawQuery = existing.Encode()
		result.URL = parsed.String()
		result.ContentType = ""
	} else {
		result.URL = actionURL
		result.ContentType = "application/x-www-form-urlencoded"
		result.Body = params.Encode()
	}

	return result
}

// ---------- Redirect chain tracking ----------

func buildRedirectChain(resp *http.Response) []string {
	if resp == nil || resp.Request == nil {
		return nil
	}

	// Walk backwards through the request chain
	var chain []string
	for r := resp.Request; r != nil; {
		chain = append(chain, r.URL.String())
		if r.Response == nil {
			break
		}
		r = r.Response.Request
	}

	// Reverse to get chronological order
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	return chain
}

// ---------- <base> tag detection ----------

// detectBaseTag scans for <base href="..."> and returns it as the resolution base.
// Falls back to the page URL if no <base> tag is found.
func detectBaseTag(htmlStr string, pageURL *url.URL) *url.URL {
	baseRE := regexcache.MustGet(`(?i)<base[^>]+href\s*=\s*["']([^"']+)["']`)
	if match := baseRE.FindStringSubmatch(htmlStr); len(match) > 1 {
		if parsed, err := url.Parse(match[1]); err == nil {
			return pageURL.ResolveReference(parsed)
		}
	}
	return pageURL
}

// ---------- HTML tokenizer-based extraction ----------

// getAttr returns the value of the named attribute from a token, or "".
func getAttr(t html.Token, name string) string {
	for _, a := range t.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

// extractLinksTokenizer extracts links using the HTML tokenizer.
// It finds href, data-href, data-url attributes on any element,
// meta refresh URLs, and srcset values.
func extractLinksTokenizer(htmlStr string, base *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	addLink := func(href string) {
		resolved := resolveURL(href, base)
		if resolved != "" && !seen[resolved] {
			seen[resolved] = true
			links = append(links, resolved)
		}
	}

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()
			tag := t.Data

			// Standard href attribute (a, area, link, base)
			if href := getAttr(t, "href"); href != "" {
				addLink(href)
			}

			// a[ping], area[ping] — tracking URLs
			if tag == "a" || tag == "area" {
				if ping := getAttr(t, "ping"); ping != "" {
					addLink(ping)
				}
			}

			// src attribute (script, img, frame, iframe, embed, input, audio, video, source, track)
			if src := getAttr(t, "src"); src != "" {
				switch tag {
				case "script", "frame", "iframe", "embed", "video", "audio", "source", "track":
					addLink(src)
				case "img":
					if !strings.HasPrefix(src, "data:") {
						addLink(src)
					}
				case "input":
					// input[type='image'] src
					if strings.EqualFold(getAttr(t, "type"), "image") {
						addLink(src)
					}
				}
			}

			// data-href, data-url, data-src attributes (lazy-loading / SPAs)
			if dh := getAttr(t, "data-href"); dh != "" {
				addLink(dh)
			}
			if du := getAttr(t, "data-url"); du != "" {
				addLink(du)
			}
			if ds := getAttr(t, "data-src"); ds != "" {
				addLink(ds)
			}

			// button[formaction]
			if tag == "button" {
				if fa := getAttr(t, "formaction"); fa != "" {
					addLink(fa)
				}
			}

			// blockquote[cite]
			if tag == "blockquote" {
				if cite := getAttr(t, "cite"); cite != "" {
					addLink(cite)
				}
			}

			// body[background], table[background], td[background]
			if tag == "body" || tag == "table" || tag == "td" {
				if bg := getAttr(t, "background"); bg != "" {
					addLink(bg)
				}
			}

			// img — dynsrc, longdesc, lowsrc, srcset
			if tag == "img" {
				for _, attr := range []string{"dynsrc", "longdesc", "lowsrc"} {
					if v := getAttr(t, attr); v != "" {
						addLink(v)
					}
				}
			}

			// video[poster]
			if tag == "video" {
				if poster := getAttr(t, "poster"); poster != "" {
					addLink(poster)
				}
			}

			// object[data], object[codebase]
			if tag == "object" {
				if data := getAttr(t, "data"); data != "" {
					addLink(data)
				}
				if cb := getAttr(t, "codebase"); cb != "" {
					addLink(cb)
				}
			}

			// applet[archive], applet[codebase]
			if tag == "applet" {
				if archive := getAttr(t, "archive"); archive != "" {
					addLink(archive)
				}
				if cb := getAttr(t, "codebase"); cb != "" {
					addLink(cb)
				}
			}

			// isindex[action]
			if tag == "isindex" {
				if action := getAttr(t, "action"); action != "" {
					addLink(action)
				}
			}

			// import[implementation]
			if tag == "import" {
				if impl := getAttr(t, "implementation"); impl != "" {
					addLink(impl)
				}
			}

			// html[manifest]
			if tag == "html" {
				if manifest := getAttr(t, "manifest"); manifest != "" {
					addLink(manifest)
				}
			}

			// meta http-equiv="refresh" content="0;url=..."
			if tag == "meta" {
				equiv := strings.ToLower(getAttr(t, "http-equiv"))
				if equiv == "refresh" {
					content := getAttr(t, "content")
					if u := parseMetaRefreshURL(content); u != "" {
						addLink(u)
					}
				}
				// Also extract URLs from meta content (og:url, etc.)
				if content := getAttr(t, "content"); content != "" {
					if looksLikeURL(content) {
						addLink(content)
					}
				}
			}

			// srcset on img/source — extract each URL
			if srcset := getAttr(t, "srcset"); srcset != "" {
				for _, entry := range strings.Split(srcset, ",") {
					parts := strings.Fields(strings.TrimSpace(entry))
					if len(parts) > 0 {
						addLink(parts[0])
					}
				}
			}

			// htmx attributes: hx-get, hx-post, hx-put, hx-delete, hx-patch
			for _, attr := range t.Attr {
				switch attr.Key {
				case "hx-get", "hx-post", "hx-put", "hx-delete", "hx-patch":
					if attr.Val != "" {
						addLink(attr.Val)
					}
				}
			}
		}
	}

	return links
}

// parseMetaRefreshURL extracts the URL from a meta refresh content value.
// Format: "5;url=https://example.com" or "0; URL=https://example.com"
func parseMetaRefreshURL(content string) string {
	lower := strings.ToLower(content)
	idx := strings.Index(lower, "url=")
	if idx < 0 {
		return ""
	}
	u := strings.TrimSpace(content[idx+4:])
	// Remove surrounding quotes if present
	u = strings.Trim(u, "'\"")
	return u
}

// extractFormsTokenizer extracts forms using the HTML tokenizer.
func extractFormsTokenizer(htmlStr string, base *url.URL) []FormInfo {
	var forms []FormInfo

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	var currentForm *FormInfo
	inForm := false

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()

			if t.Data == "form" {
				form := FormInfo{Method: "GET"}

				if action := getAttr(t, "action"); action != "" {
					form.Action = resolveURL(action, base)
				}
				if method := getAttr(t, "method"); method != "" {
					form.Method = strings.ToUpper(method)
				}
				form.ID = getAttr(t, "id")
				form.Name = getAttr(t, "name")
				form.Enctype = getAttr(t, "enctype")

				currentForm = &form
				inForm = true
			}

			if inForm && currentForm != nil {
				switch t.Data {
				case "input":
					input := InputInfo{Type: "text"}
					input.Name = getAttr(t, "name")
					input.Type = getAttr(t, "type")
					if input.Type == "" {
						input.Type = "text"
					}
					input.Value = getAttr(t, "value")
					input.ID = getAttr(t, "id")
					input.Placeholder = getAttr(t, "placeholder")
					for _, a := range t.Attr {
						if a.Key == "required" {
							input.Required = true
							break
						}
					}
					if strings.EqualFold(input.Type, "file") {
						currentForm.HasUpload = true
					}
					if input.Name != "" {
						currentForm.Inputs = append(currentForm.Inputs, input)
					}

				case "textarea":
					input := InputInfo{Type: "textarea"}
					input.Name = getAttr(t, "name")
					input.ID = getAttr(t, "id")
					// Read textarea content
					z.Next()
					input.Value = string(z.Text())
					if input.Name != "" {
						currentForm.Inputs = append(currentForm.Inputs, input)
					}

				case "select":
					input := InputInfo{Type: "select"}
					input.Name = getAttr(t, "name")
					input.ID = getAttr(t, "id")
					if input.Name != "" {
						currentForm.Inputs = append(currentForm.Inputs, input)
					}
				}
			}

		case html.EndTagToken:
			t := z.Token()
			if t.Data == "form" && inForm && currentForm != nil {
				forms = append(forms, *currentForm)
				currentForm = nil
				inForm = false
			}
		}
	}

	// Handle unclosed form (common in malformed HTML)
	if inForm && currentForm != nil {
		forms = append(forms, *currentForm)
	}

	return forms
}

// extractScriptsTokenizer extracts external script URLs using the HTML tokenizer.
func extractScriptsTokenizer(htmlStr string, base *url.URL) []string {
	var scripts []string
	seen := make(map[string]bool)

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()
			if t.Data == "script" {
				if src := getAttr(t, "src"); src != "" {
					resolved := resolveURL(src, base)
					if resolved != "" && !seen[resolved] {
						seen[resolved] = true
						scripts = append(scripts, resolved)
					}
				}
			}
		}
	}

	return scripts
}

// extractStylesheetsTokenizer extracts stylesheet URLs using the HTML tokenizer.
func extractStylesheetsTokenizer(htmlStr string, base *url.URL) []string {
	var stylesheets []string
	seen := make(map[string]bool)

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()
			if t.Data == "link" {
				rel := strings.ToLower(getAttr(t, "rel"))
				href := getAttr(t, "href")
				if href == "" {
					continue
				}
				if rel == "stylesheet" || strings.HasSuffix(strings.ToLower(href), ".css") {
					resolved := resolveURL(href, base)
					if resolved != "" && !seen[resolved] {
						seen[resolved] = true
						stylesheets = append(stylesheets, resolved)
					}
				}
			}
		}
	}

	return stylesheets
}

// extractImagesTokenizer extracts image URLs using the HTML tokenizer.
func extractImagesTokenizer(htmlStr string, base *url.URL) []string {
	var images []string
	seen := make(map[string]bool)

	addImage := func(src string) {
		resolved := resolveURL(src, base)
		if resolved != "" && !seen[resolved] {
			seen[resolved] = true
			images = append(images, resolved)
		}
	}

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()
			if t.Data == "img" {
				if src := getAttr(t, "src"); src != "" {
					addImage(src)
				}
				if ds := getAttr(t, "data-src"); ds != "" {
					addImage(ds)
				}
				// srcset handled by link extraction
			}
		}
	}

	return images
}

// extractCommentsTokenizer extracts HTML comments using the HTML tokenizer.
func extractCommentsTokenizer(htmlStr string) []string {
	var comments []string

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.CommentToken {
			comment := strings.TrimSpace(string(z.Text()))
			if comment != "" && len(comment) > 3 { // Skip tiny comments
				comments = append(comments, comment)
			}
		}
	}

	return comments
}

// extractMetaTokenizer extracts meta tags using the HTML tokenizer.
func extractMetaTokenizer(htmlStr string) map[string]string {
	meta := make(map[string]string)

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()
			if t.Data == "meta" {
				name := getAttr(t, "name")
				property := getAttr(t, "property")
				content := getAttr(t, "content")

				if name != "" && content != "" {
					meta[name] = content
				}
				if property != "" && content != "" {
					meta[property] = content
				}
			}
		}
	}

	return meta
}

// ---------- Legacy regex-based extraction (kept for backward compatibility in tests) ----------

func extractTitle(htmlStr string) string {
	titleRE := regexcache.MustGet(`(?i)<title[^>]*>([^<]*)</title>`)
	if match := titleRE.FindStringSubmatch(htmlStr); len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

// extractForms is the legacy function (kept for tests, delegates to tokenizer).
func extractForms(htmlStr string, base *url.URL) []FormInfo {
	return extractFormsTokenizer(htmlStr, base)
}

// extractInputs extracts form inputs from a form body string.
func extractInputs(formBody string) []InputInfo {
	var inputs []InputInfo

	z := html.NewTokenizer(strings.NewReader(formBody))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()

			switch t.Data {
			case "input":
				input := InputInfo{Type: "text"}
				input.Name = getAttr(t, "name")
				input.Type = getAttr(t, "type")
				if input.Type == "" {
					input.Type = "text"
				}
				input.Value = getAttr(t, "value")
				input.ID = getAttr(t, "id")
				input.Placeholder = getAttr(t, "placeholder")
				for _, a := range t.Attr {
					if a.Key == "required" {
						input.Required = true
						break
					}
				}
				if input.Name != "" {
					inputs = append(inputs, input)
				}

			case "textarea":
				input := InputInfo{Type: "textarea"}
				input.Name = getAttr(t, "name")
				z.Next()
				input.Value = string(z.Text())
				if input.Name != "" {
					inputs = append(inputs, input)
				}

			case "select":
				input := InputInfo{Type: "select"}
				input.Name = getAttr(t, "name")
				if input.Name != "" {
					inputs = append(inputs, input)
				}
			}
		}
	}

	return inputs
}

// extractScripts is the legacy function (now delegates to tokenizer).
func extractScripts(htmlStr string, base *url.URL) []string {
	return extractScriptsTokenizer(htmlStr, base)
}

// extractStylesheets is the legacy function (now delegates to tokenizer).
func extractStylesheets(htmlStr string, base *url.URL) []string {
	return extractStylesheetsTokenizer(htmlStr, base)
}

// extractImages is the legacy function (now delegates to tokenizer).
func extractImages(htmlStr string, base *url.URL) []string {
	return extractImagesTokenizer(htmlStr, base)
}

// extractComments is the legacy function (now delegates to tokenizer).
func extractComments(htmlStr string) []string {
	return extractCommentsTokenizer(htmlStr)
}

// extractMeta is the legacy function (now delegates to tokenizer).
func extractMeta(htmlStr string) map[string]string {
	return extractMetaTokenizer(htmlStr)
}

func resolveURL(href string, base *url.URL) string {
	href = strings.TrimSpace(href)
	if href == "" || href == "#" || strings.HasPrefix(href, "#") {
		return ""
	}

	// Skip special URLs
	lower := strings.ToLower(href)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") {
		return ""
	}

	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(parsed)
	resolved.Fragment = "" // Remove fragment

	return resolved.String()
}

// GetVisited returns all visited URLs
func (c *Crawler) GetVisited() []string {
	c.visitedMu.RLock()
	defer c.visitedMu.RUnlock()

	urls := make([]string, 0, len(c.visited))
	for u := range c.visited {
		urls = append(urls, u)
	}

	sort.Strings(urls)
	return urls
}

// GetPageCount returns the number of pages crawled
func (c *Crawler) GetPageCount() int {
	c.pageMu.Lock()
	defer c.pageMu.Unlock()
	return c.pageCount
}

// GetDroppedCount returns the number of URLs dropped because the queue was full.
func (c *Crawler) GetDroppedCount() int64 {
	return c.droppedCount.Load()
}
