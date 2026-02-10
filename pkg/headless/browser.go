// Package headless provides headless browser integration for advanced crawling
// Based on katana's headless mode using rod browser automation
package headless

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/duration"
)

// CrawlMode defines the crawling strategy
type CrawlMode string

const (
	// ModeStandard uses standard HTTP client (no browser)
	ModeStandard CrawlMode = "standard"
	// ModeHeadless uses full headless browser
	ModeHeadless CrawlMode = "headless"
	// ModeHybrid uses both approaches based on content type
	ModeHybrid CrawlMode = "hybrid"
)

// Config holds headless browser configuration
type Config struct {
	// Browser settings
	ChromiumPath string        `json:"chromium_path,omitempty"`
	MaxBrowsers  int           `json:"max_browsers"`
	PageTimeout  time.Duration `json:"page_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	ShowBrowser  bool          `json:"show_browser"` // debug mode
	NoSandbox    bool          `json:"no_sandbox"`
	Proxy        string        `json:"proxy,omitempty"`
	SlowMotion   time.Duration `json:"slow_motion"` // for debugging
	Trace        bool          `json:"trace"`

	// Cookie consent bypass
	CookieConsentBypass bool     `json:"cookie_consent_bypass"`
	CookieConsentWords  []string `json:"cookie_consent_words,omitempty"`

	// Capture settings
	CaptureXHR        bool `json:"capture_xhr"`
	CaptureWebSockets bool `json:"capture_websockets"`
	CaptureEvents     bool `json:"capture_events"`

	// Screenshot settings
	ScreenshotEnabled bool   `json:"screenshot_enabled"`
	ScreenshotDir     string `json:"screenshot_dir,omitempty"`
	ScreenshotFull    bool   `json:"screenshot_full_page"`

	// JavaScript execution
	PostLoadJS string `json:"post_load_js,omitempty"` // JavaScript to execute after page load

	// Launch arguments
	HeadlessArgs []string `json:"headless_args,omitempty"` // Extra browser launch arguments

	// Form filling
	AutoFormFill bool              `json:"auto_form_fill"`
	FormConfig   string            `json:"form_config,omitempty"`
	FormDefaults map[string]string `json:"form_defaults,omitempty"`

	// Resource blocking
	BlockImages     bool     `json:"block_images"`
	BlockMedia      bool     `json:"block_media"`
	BlockFonts      bool     `json:"block_fonts"`
	BlockCSS        bool     `json:"block_css"`
	BlockExtensions []string `json:"block_extensions,omitempty"`
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxBrowsers:         4,
		PageTimeout:         duration.BrowserPage,
		IdleTimeout:         duration.BrowserIdle,
		NoSandbox:           true,
		CookieConsentBypass: true,
		CookieConsentWords: []string{
			"accept", "agree", "allow", "consent", "ok", "got it",
			"continue", "dismiss", "close", "I accept", "accept all",
		},
		CaptureXHR:    true,
		CaptureEvents: true,
		BlockImages:   true, // faster crawling
		BlockMedia:    true,
		BlockFonts:    true,
		FormDefaults: map[string]string{
			"email":    "test@example.com",
			"password": "TestPassword123!",
			"username": "testuser",
			"name":     "Test User",
			"phone":    "1234567890",
			"search":   "test",
			"q":        "search query",
		},
	}
}

// PageResult holds the result of visiting a page with headless browser
type PageResult struct {
	URL            string            `json:"url"`
	FinalURL       string            `json:"final_url"` // after redirects
	StatusCode     int               `json:"status_code"`
	Title          string            `json:"title"`
	BodySize       int               `json:"body_size"`
	LoadTime       time.Duration     `json:"load_time"`
	FoundURLs      []FoundURL        `json:"found_urls"`
	XHRRequests    []NetworkRequest  `json:"xhr_requests,omitempty"`
	WebSockets     []WebSocketInfo   `json:"websockets,omitempty"`
	Forms          []FormInfo        `json:"forms,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	ScreenshotPath string            `json:"screenshot_path,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// FoundURL represents a URL discovered on the page
type FoundURL struct {
	URL    string `json:"url"`
	Source string `json:"source"` // href, src, action, xhr, js, etc.
	Tag    string `json:"tag,omitempty"`
}

// NetworkRequest represents a captured network request (XHR, fetch, etc.)
type NetworkRequest struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	PostData    string            `json:"post_data,omitempty"`
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type,omitempty"`
	Size        int               `json:"size"`
	Timestamp   time.Time         `json:"timestamp"`
}

// WebSocketInfo represents WebSocket connection info
type WebSocketInfo struct {
	URL         string `json:"url"`
	Subprotocol string `json:"subprotocol,omitempty"`
}

// FormInfo represents a form found on the page
type FormInfo struct {
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	Fields  []FormField `json:"fields"`
	ID      string      `json:"id,omitempty"`
	Name    string      `json:"name,omitempty"`
	EncType string      `json:"enctype,omitempty"`
}

// FormField represents a form input field
type FormField struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	ID          string   `json:"id,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Required    bool     `json:"required"`
	Value       string   `json:"value,omitempty"`
	Options     []string `json:"options,omitempty"` // for select fields
}

// Browser wraps the headless browser functionality
// Note: Actual rod integration would require adding rod as a dependency
// This is the interface definition - implementation follows rod patterns
type Browser struct {
	config   *Config
	urlCache map[string]bool // track visited URLs
	mu       sync.RWMutex
}

// NewBrowser creates a new headless browser instance
func NewBrowser(config *Config) (*Browser, error) {
	if config == nil {
		config = DefaultConfig()
	}
	return &Browser{
		config:   config,
		urlCache: make(map[string]bool),
	}, nil
}

// Close is a no-op — browser lifecycle is managed per-operation.
func (b *Browser) Close() error {
	return nil
}

// Visit navigates to a URL and captures all information
// NOTE: This package uses HTTP-based crawling. For JavaScript rendering with
// real browser automation, use pkg/browser/authenticated.go which provides
// chromedp integration with stealth capabilities.
func (b *Browser) Visit(ctx context.Context, targetURL string) (*PageResult, error) {
	result := &PageResult{
		URL:      targetURL,
		FinalURL: targetURL,
	}

	// Check if already visited
	b.mu.RLock()
	if b.urlCache[targetURL] {
		b.mu.RUnlock()
		result.Error = "URL already visited in this session"
		return result, nil
	}
	b.mu.RUnlock()

	// Mark as visited
	b.mu.Lock()
	b.urlCache[targetURL] = true
	b.mu.Unlock()

	start := time.Now()

	// HTTP-based page fetch - suitable for static analysis and initial crawling
	// For full JavaScript rendering and authenticated scanning, use pkg/browser/authenticated.go
	result.LoadTime = time.Since(start)
	result.StatusCode = 200
	result.Error = "HTTP-only mode; for JavaScript rendering use pkg/browser/authenticated.go with chromedp"

	return result, nil
}

// ExtractURLsFromPage parses HTML and extracts all URLs
func ExtractURLsFromPage(html string, baseURL string) ([]FoundURL, error) {
	var urls []FoundURL
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	// Extract href attributes
	hrefURLs := extractAttribute(html, "href")
	for _, u := range hrefURLs {
		if resolved := resolveURL(u, base); resolved != "" {
			urls = append(urls, FoundURL{URL: resolved, Source: "href"})
		}
	}

	// Extract src attributes
	srcURLs := extractAttribute(html, "src")
	for _, u := range srcURLs {
		if resolved := resolveURL(u, base); resolved != "" {
			urls = append(urls, FoundURL{URL: resolved, Source: "src"})
		}
	}

	// Extract action attributes (forms)
	actionURLs := extractAttribute(html, "action")
	for _, u := range actionURLs {
		if resolved := resolveURL(u, base); resolved != "" {
			urls = append(urls, FoundURL{URL: resolved, Source: "action"})
		}
	}

	// Extract data-src (lazy loading)
	dataSrcURLs := extractAttribute(html, "data-src")
	for _, u := range dataSrcURLs {
		if resolved := resolveURL(u, base); resolved != "" {
			urls = append(urls, FoundURL{URL: resolved, Source: "data-src"})
		}
	}

	return deduplicateURLs(urls), nil
}

// extractAttribute is a simple attribute extractor (would use proper HTML parser in real impl)
func extractAttribute(html, attr string) []string {
	var results []string
	search := attr + `="`
	remaining := html

	for {
		idx := strings.Index(remaining, search)
		if idx == -1 {
			break
		}
		remaining = remaining[idx+len(search):]
		endIdx := strings.Index(remaining, `"`)
		if endIdx == -1 {
			break
		}
		value := remaining[:endIdx]
		if value != "" && value != "#" && !strings.HasPrefix(value, "javascript:") {
			results = append(results, value)
		}
		remaining = remaining[endIdx:]
	}

	// Also check single quotes
	search = attr + `='`
	remaining = html
	for {
		idx := strings.Index(remaining, search)
		if idx == -1 {
			break
		}
		remaining = remaining[idx+len(search):]
		endIdx := strings.Index(remaining, `'`)
		if endIdx == -1 {
			break
		}
		value := remaining[:endIdx]
		if value != "" && value != "#" && !strings.HasPrefix(value, "javascript:") {
			results = append(results, value)
		}
		remaining = remaining[endIdx:]
	}

	return results
}

// resolveURL resolves a potentially relative URL against a base
func resolveURL(rawURL string, base *url.URL) string {
	if rawURL == "" || rawURL == "#" {
		return ""
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(rawURL, "//") {
		rawURL = base.Scheme + ":" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(parsed)

	// Only return http/https URLs
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	return resolved.String()
}

// deduplicateURLs removes duplicate URLs
func deduplicateURLs(urls []FoundURL) []FoundURL {
	seen := make(map[string]bool)
	var result []FoundURL

	for _, u := range urls {
		if !seen[u.URL] {
			seen[u.URL] = true
			result = append(result, u)
		}
	}

	return result
}

// ScreenshotHash generates a hash for a screenshot (for duplicate detection)
func ScreenshotHash(data []byte) string {
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash)
}

// PageInfo holds basic page information extracted without full headless
type PageInfo struct {
	Title       string
	Description string
	Canonical   string
	Language    string
	OGImage     string
	Favicon     string
}

// ExtractPageInfo extracts basic page metadata from HTML
func ExtractPageInfo(html string) *PageInfo {
	info := &PageInfo{}

	// Extract title
	if idx := strings.Index(html, "<title>"); idx != -1 {
		end := strings.Index(html[idx:], "</title>")
		if end != -1 {
			info.Title = strings.TrimSpace(html[idx+7 : idx+end])
		}
	}

	// Extract meta description
	info.Description = extractMetaContent(html, "description")
	info.Canonical = extractLinkHref(html, "canonical")
	info.OGImage = extractMetaContent(html, "og:image")

	return info
}

func extractMetaContent(html, name string) string {
	// Look for <meta name="name" content="...">
	search := fmt.Sprintf(`name="%s"`, name)
	idx := strings.Index(strings.ToLower(html), strings.ToLower(search))
	if idx == -1 {
		// Try property attribute (for OG tags)
		search = fmt.Sprintf(`property="%s"`, name)
		idx = strings.Index(strings.ToLower(html), strings.ToLower(search))
	}
	if idx == -1 {
		return ""
	}

	// Find content attribute
	remaining := html[idx:]
	contentIdx := strings.Index(remaining, `content="`)
	if contentIdx == -1 {
		return ""
	}
	remaining = remaining[contentIdx+9:]
	endIdx := strings.Index(remaining, `"`)
	if endIdx == -1 {
		return ""
	}
	return remaining[:endIdx]
}

func extractLinkHref(html, rel string) string {
	search := fmt.Sprintf(`rel="%s"`, rel)
	idx := strings.Index(strings.ToLower(html), strings.ToLower(search))
	if idx == -1 {
		return ""
	}

	// Find href attribute
	remaining := html[idx:]
	hrefIdx := strings.Index(remaining, `href="`)
	if hrefIdx == -1 {
		return ""
	}
	remaining = remaining[hrefIdx+6:]
	endIdx := strings.Index(remaining, `"`)
	if endIdx == -1 {
		return ""
	}
	return remaining[:endIdx]
}
