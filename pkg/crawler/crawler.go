// Package crawler provides web crawling capabilities
// Based on katana/gospider's crawling features with scope control and recursion
package crawler

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// CrawlResult represents a crawled page result
type CrawlResult struct {
	URL           string            `json:"url"`
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

	// JavaScript/Headless options
	JSRendering bool          `json:"js_rendering"`
	JSTimeout   time.Duration `json:"js_timeout"`
	WaitFor     string        `json:"wait_for,omitempty"` // CSS selector to wait for

	// Debug options
	Debug bool `json:"debug"`

	// Extensions to crawl
	AllowedExtensions    []string `json:"allowed_extensions,omitempty"`
	DisallowedExtensions []string `json:"disallowed_extensions,omitempty"`
}

// DefaultConfig returns default crawler configuration
func DefaultConfig() *Config {
	return &Config{
		MaxDepth:          3,
		MaxPages:          100,
		MaxConcurrency:    10,
		Timeout:           30 * time.Second,
		Delay:             100 * time.Millisecond,
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
	config     *Config
	client     *http.Client
	visited    map[string]bool
	visitedMu  sync.RWMutex
	queue      chan *crawlTask
	results    chan *CrawlResult
	includeRE  []*regexp.Regexp
	excludeRE  []*regexp.Regexp
	baseDomain string
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	pageCount  int
	pageMu     sync.Mutex
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

	// Build transport with proxy and TLS options
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.SkipVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Configure proxy if specified
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	c := &Crawler{
		config:  config,
		visited: make(map[string]bool),
		queue:   make(chan *crawlTask, 10000),
		results: make(chan *CrawlResult, 1000),
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
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

	// Start workers
	for i := 0; i < c.config.MaxConcurrency; i++ {
		c.wg.Add(1)
		go c.worker()
	}

	// Add start URL to queue
	c.queue <- &crawlTask{URL: startURL, Depth: 0}

	// Monitor and close results when done
	go func() {
		c.wg.Wait()
		close(c.results)
	}()

	return c.results, nil
}

// Stop stops the crawler
func (c *Crawler) Stop() {
	if c.cancel != nil {
		c.cancel()
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
				continue
			}
			c.pageCount++
			c.pageMu.Unlock()

			// Process the task
			result := c.crawlURL(task.URL, task.Depth)

			select {
			case c.results <- result:
			case <-c.ctx.Done():
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
			}
		default:
			// No more tasks, check if queue is empty
			select {
			case <-time.After(100 * time.Millisecond):
				// Give other workers time
			case <-c.ctx.Done():
				return
			}
		}
	}
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

	// Make request
	resp, err := c.client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.Headers = resp.Header

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

	html := string(body)

	// Extract title
	result.Title = extractTitle(html)

	// Extract links
	if c.config.ExtractLinks {
		result.Links = c.extractLinks(html, parsed)
	}

	// Extract forms
	if c.config.ExtractForms {
		result.Forms = extractForms(html, parsed)
	}

	// Extract scripts
	if c.config.ExtractScripts {
		result.Scripts = extractScripts(html, parsed)
	}

	// Extract stylesheets
	result.Stylesheets = extractStylesheets(html, parsed)

	// Extract images
	result.Images = extractImages(html, parsed)

	// Extract comments
	if c.config.ExtractComments {
		result.Comments = extractComments(html)
	}

	// Extract meta tags
	if c.config.ExtractMeta {
		result.Meta = extractMeta(html)
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

	// Add to queue (non-blocking)
	select {
	case c.queue <- &crawlTask{URL: normalized, Depth: depth}:
	default:
		// Queue full, skip
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

func (c *Crawler) extractLinks(html string, base *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	// Extract href attributes
	hrefRE := regexcache.MustGet(`href\s*=\s*["']([^"']+)["']`)
	matches := hrefRE.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		href := match[1]
		resolved := resolveURL(href, base)
		if resolved != "" && !seen[resolved] {
			seen[resolved] = true
			links = append(links, resolved)
		}
	}

	return links
}

func extractForms(html string, base *url.URL) []FormInfo {
	var forms []FormInfo

	// Simple form extraction
	formRE := regexcache.MustGet(`(?is)<form([^>]*)>(.*?)</form>`)
	formMatches := formRE.FindAllStringSubmatch(html, -1)

	for _, match := range formMatches {
		if len(match) < 3 {
			continue
		}

		attrs := match[1]
		body := match[2]

		form := FormInfo{
			Method: "GET", // Default
		}

		// Extract action
		if actionMatch := regexcache.MustGet(`action\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(actionMatch) > 1 {
			form.Action = resolveURL(actionMatch[1], base)
		}

		// Extract method
		if methodMatch := regexcache.MustGet(`(?i)method\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		// Extract id
		if idMatch := regexcache.MustGet(`id\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(idMatch) > 1 {
			form.ID = idMatch[1]
		}

		// Extract name
		if nameMatch := regexcache.MustGet(`name\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(nameMatch) > 1 {
			form.Name = nameMatch[1]
		}

		// Extract enctype
		if encMatch := regexcache.MustGet(`enctype\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(encMatch) > 1 {
			form.Enctype = encMatch[1]
		}

		// Extract inputs
		form.Inputs = extractInputs(body)

		forms = append(forms, form)
	}

	return forms
}

func extractInputs(formBody string) []InputInfo {
	var inputs []InputInfo

	// Input tags
	inputRE := regexcache.MustGet(`(?i)<input([^>]+)>`)
	inputMatches := inputRE.FindAllStringSubmatch(formBody, -1)

	for _, match := range inputMatches {
		if len(match) < 2 {
			continue
		}

		attrs := match[1]
		input := InputInfo{
			Type: "text", // Default
		}

		// Extract attributes
		if nameMatch := regexcache.MustGet(`name\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(nameMatch) > 1 {
			input.Name = nameMatch[1]
		}
		if typeMatch := regexcache.MustGet(`type\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(typeMatch) > 1 {
			input.Type = typeMatch[1]
		}
		if valueMatch := regexcache.MustGet(`value\s*=\s*["']([^"']*?)["']`).FindStringSubmatch(attrs); len(valueMatch) > 1 {
			input.Value = valueMatch[1]
		}
		if idMatch := regexcache.MustGet(`id\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(idMatch) > 1 {
			input.ID = idMatch[1]
		}
		if phMatch := regexcache.MustGet(`placeholder\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(phMatch) > 1 {
			input.Placeholder = phMatch[1]
		}
		if strings.Contains(strings.ToLower(attrs), "required") {
			input.Required = true
		}

		if input.Name != "" {
			inputs = append(inputs, input)
		}
	}

	// Textarea tags
	textareaRE := regexcache.MustGet(`(?i)<textarea([^>]*)>([^<]*)</textarea>`)
	taMatches := textareaRE.FindAllStringSubmatch(formBody, -1)

	for _, match := range taMatches {
		if len(match) < 2 {
			continue
		}

		attrs := match[1]
		input := InputInfo{
			Type: "textarea",
		}

		if nameMatch := regexcache.MustGet(`name\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(nameMatch) > 1 {
			input.Name = nameMatch[1]
		}
		if len(match) > 2 {
			input.Value = match[2]
		}

		if input.Name != "" {
			inputs = append(inputs, input)
		}
	}

	// Select tags
	selectRE := regexcache.MustGet(`(?i)<select([^>]*)>`)
	selMatches := selectRE.FindAllStringSubmatch(formBody, -1)

	for _, match := range selMatches {
		if len(match) < 2 {
			continue
		}

		attrs := match[1]
		input := InputInfo{
			Type: "select",
		}

		if nameMatch := regexcache.MustGet(`name\s*=\s*["']([^"']+)["']`).FindStringSubmatch(attrs); len(nameMatch) > 1 {
			input.Name = nameMatch[1]
		}

		if input.Name != "" {
			inputs = append(inputs, input)
		}
	}

	return inputs
}

func extractScripts(html string, base *url.URL) []string {
	var scripts []string
	seen := make(map[string]bool)

	srcRE := regexcache.MustGet(`<script[^>]+src\s*=\s*["']([^"']+)["']`)
	matches := srcRE.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		src := resolveURL(match[1], base)
		if src != "" && !seen[src] {
			seen[src] = true
			scripts = append(scripts, src)
		}
	}

	return scripts
}

func extractStylesheets(html string, base *url.URL) []string {
	var stylesheets []string
	seen := make(map[string]bool)

	hrefRE := regexcache.MustGet(`<link[^>]+href\s*=\s*["']([^"']+)["'][^>]*>`)
	matches := hrefRE.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		// Check if it's a stylesheet
		full := strings.ToLower(match[0])
		if !strings.Contains(full, "stylesheet") && !strings.HasSuffix(strings.ToLower(match[1]), ".css") {
			continue
		}

		href := resolveURL(match[1], base)
		if href != "" && !seen[href] {
			seen[href] = true
			stylesheets = append(stylesheets, href)
		}
	}

	return stylesheets
}

func extractImages(html string, base *url.URL) []string {
	var images []string
	seen := make(map[string]bool)

	srcRE := regexcache.MustGet(`<img[^>]+src\s*=\s*["']([^"']+)["']`)
	matches := srcRE.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		src := resolveURL(match[1], base)
		if src != "" && !seen[src] {
			seen[src] = true
			images = append(images, src)
		}
	}

	return images
}

func extractComments(html string) []string {
	var comments []string

	commentRE := regexcache.MustGet(`<!--(.*?)-->`)
	matches := commentRE.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		comment := strings.TrimSpace(match[1])
		if comment != "" && len(comment) > 3 { // Skip tiny comments
			comments = append(comments, comment)
		}
	}

	return comments
}

func extractMeta(html string) map[string]string {
	meta := make(map[string]string)

	// Name-content pairs
	nameRE := regexcache.MustGet(`<meta[^>]+name\s*=\s*["']([^"']+)["'][^>]+content\s*=\s*["']([^"']*)["']`)
	matches := nameRE.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			meta[match[1]] = match[2]
		}
	}

	// Content-name pairs (reversed order in HTML)
	contentRE := regexcache.MustGet(`<meta[^>]+content\s*=\s*["']([^"']*)["'][^>]+name\s*=\s*["']([^"']+)["']`)
	matches = contentRE.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			meta[match[2]] = match[1]
		}
	}

	// Property-content (Open Graph)
	propRE := regexcache.MustGet(`<meta[^>]+property\s*=\s*["']([^"']+)["'][^>]+content\s*=\s*["']([^"']*)["']`)
	matches = propRE.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			meta[match[1]] = match[2]
		}
	}

	return meta
}

func extractTitle(html string) string {
	titleRE := regexcache.MustGet(`(?i)<title[^>]*>([^<]*)</title>`)
	if match := titleRE.FindStringSubmatch(html); len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	return ""
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
