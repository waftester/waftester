// Package crawler provides web crawling capabilities
// Based on katana/gospider's crawling features with scope control and recursion
package crawler

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
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
	Timestamp     time.Time         `json:"timestamp"`
}

// FormInfo represents an HTML form
type FormInfo struct {
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	ID      string      `json:"id,omitempty"`
	Name    string      `json:"name,omitempty"`
	Inputs  []InputInfo `json:"inputs,omitempty"`
	Enctype string      `json:"enctype,omitempty"`
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
		FollowRobots:      true,
		IncludeSubdomains: true,
		UserAgent:         ui.UserAgentWithContext("crawler"),
		DisallowedExtensions: []string{
			".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
			".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm",
			".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
			".zip", ".tar", ".gz", ".rar", ".7z",
			".woff", ".woff2", ".ttf", ".eot", ".otf",
			".css", // Often not useful for crawling
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
		log.Printf("[crawl] WARNING: --js/--javascript flag is not yet implemented; headless rendering is unavailable. Use the event_crawl MCP tool for SPA crawling.")
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
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Establish soft-404 baseline: request a known-nonexistent path and hash the body
	c.detectSoft404(parsed)

	// Enforce robots.txt: check disallowed paths
	if c.config.FollowRobots {
		c.loadRobotsTxt(parsed)
	}

	// Start workers
	for i := 0; i < c.config.MaxConcurrency; i++ {
		c.wg.Add(1)
		go c.worker()
	}

	// Add start URL to queue
	c.inFlight.Add(1)
	c.queue <- &crawlTask{URL: startURL, Depth: 0}

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

			// Add delay
			if c.config.Delay > 0 {
				time.Sleep(c.config.Delay)
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

	// Only parse HTML content
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

	return result
}

func (c *Crawler) queueURL(rawURL string, depth int) {
	// Normalize URL
	normalized := c.normalizeURL(rawURL)
	if normalized == "" {
		return
	}

	// Check if already visited
	c.visitedMu.Lock()
	if c.visited[normalized] {
		c.visitedMu.Unlock()
		return
	}
	c.visited[normalized] = true
	c.visitedMu.Unlock()

	// Check scope
	if !c.inScope(normalized) {
		return
	}

	// Check extension
	if !c.allowedExtension(normalized) {
		return
	}

	// Enforce robots.txt disallowed paths
	if c.config.FollowRobots && c.isRobotsDisallowed(normalized) {
		return
	}

	// Add to queue (non-blocking)
	c.inFlight.Add(1)
	select {
	case c.queue <- &crawlTask{URL: normalized, Depth: depth}:
	default:
		// Queue full — track the drop
		c.inFlight.Add(-1)
		c.droppedCount.Add(1)
		if c.config.Verbose {
			log.Printf("[crawl] queue full, dropped: %s", normalized)
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

	return parsed.String()
}

func (c *Crawler) inScope(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Check if same domain or subdomain
	host := parsed.Host
	if host == c.baseDomain {
		// Same domain, OK
	} else if c.config.IncludeSubdomains && strings.HasSuffix(host, "."+c.baseDomain) {
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

	disallowed := parseRobotsDisallowed(string(body))
	c.config.RobotsDisallowed = disallowed
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

// ---------- Redirect chain tracking ----------

func buildRedirectChain(resp *http.Response) []string {
	if resp == nil || resp.Request == nil {
		return nil
	}

	// Walk backwards through the request chain
	var chain []string
	for r := resp.Request; r != nil; r = r.Response.Request {
		chain = append(chain, r.URL.String())
		if r.Response == nil {
			break
		}
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

			// Standard href attribute (a, area, link)
			if href := getAttr(t, "href"); href != "" {
				addLink(href)
			}

			// data-href, data-url attributes (common in lazy-loading / SPAs)
			if dh := getAttr(t, "data-href"); dh != "" {
				addLink(dh)
			}
			if du := getAttr(t, "data-url"); du != "" {
				addLink(du)
			}

			// meta http-equiv="refresh" content="0;url=..."
			if t.Data == "meta" {
				equiv := strings.ToLower(getAttr(t, "http-equiv"))
				if equiv == "refresh" {
					content := getAttr(t, "content")
					if u := parseMetaRefreshURL(content); u != "" {
						addLink(u)
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
