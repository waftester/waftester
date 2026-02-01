// Package discovery - External sources for endpoint discovery
// Inspired by gospider's OtherSources and katana's known-files features
package discovery

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

// ExternalSources provides methods to discover endpoints from external sources
type ExternalSources struct {
	httpClient *http.Client
	userAgent  string
}

// NewExternalSources creates a new external sources discoverer
func NewExternalSources(timeout time.Duration, userAgent string) *ExternalSources {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if userAgent == "" {
		userAgent = "WAF-Tester-Discovery/1.0"
	}
	return &ExternalSources{
		httpClient: &http.Client{Timeout: timeout},
		userAgent:  userAgent,
	}
}

// ==================== ROBOTS.TXT PARSING ====================

// RobotsResult contains parsed robots.txt data
type RobotsResult struct {
	AllowedPaths    []string `json:"allowed_paths"`
	DisallowedPaths []string `json:"disallowed_paths"`
	Sitemaps        []string `json:"sitemaps"`
	CrawlDelay      int      `json:"crawl_delay,omitempty"`
}

// ParseRobotsTxt fetches and parses robots.txt
func (es *ExternalSources) ParseRobotsTxt(ctx context.Context, targetURL string) (*RobotsResult, error) {
	robotsURL := strings.TrimRight(targetURL, "/") + "/robots.txt"

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", es.userAgent)

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch robots.txt: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("robots.txt not found (status %d)", resp.StatusCode)
	}

	body, err := iohelper.ReadBody(resp.Body, iohelper.DefaultMaxBodySize) // 1MB limit
	if err != nil {
		return nil, err
	}

	return parseRobotsContent(string(body)), nil
}

func parseRobotsContent(content string) *RobotsResult {
	result := &RobotsResult{
		AllowedPaths:    make([]string, 0),
		DisallowedPaths: make([]string, 0),
		Sitemaps:        make([]string, 0),
	}

	allowRe := regexcache.MustGet(`(?i)^\s*Allow:\s*(.+)$`)
	disallowRe := regexcache.MustGet(`(?i)^\s*Disallow:\s*(.+)$`)
	sitemapRe := regexcache.MustGet(`(?i)^\s*Sitemap:\s*(.+)$`)
	crawlDelayRe := regexcache.MustGet(`(?i)^\s*Crawl-delay:\s*(\d+)`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := allowRe.FindStringSubmatch(line); len(match) > 1 {
			path := strings.TrimSpace(match[1])
			if path != "" && path != "/" {
				result.AllowedPaths = append(result.AllowedPaths, path)
			}
		}

		if match := disallowRe.FindStringSubmatch(line); len(match) > 1 {
			path := strings.TrimSpace(match[1])
			if path != "" && path != "/" {
				result.DisallowedPaths = append(result.DisallowedPaths, path)
			}
		}

		if match := sitemapRe.FindStringSubmatch(line); len(match) > 1 {
			sitemap := strings.TrimSpace(match[1])
			if sitemap != "" {
				result.Sitemaps = append(result.Sitemaps, sitemap)
			}
		}

		if match := crawlDelayRe.FindStringSubmatch(line); len(match) > 1 {
			if delay, err := strconv.Atoi(match[1]); err == nil {
				result.CrawlDelay = delay
			}
		}
	}

	return result
}

// ==================== SITEMAP.XML PARSING ====================

// SitemapURL represents a URL entry in a sitemap
type SitemapURL struct {
	Loc        string `xml:"loc" json:"loc"`
	LastMod    string `xml:"lastmod,omitempty" json:"lastmod,omitempty"`
	ChangeFreq string `xml:"changefreq,omitempty" json:"changefreq,omitempty"`
	Priority   string `xml:"priority,omitempty" json:"priority,omitempty"`
}

// Sitemap represents a sitemap or sitemap index
type Sitemap struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []SitemapURL `xml:"url"`
}

// SitemapIndex represents a sitemap index file
type SitemapIndex struct {
	XMLName  xml.Name `xml:"sitemapindex"`
	Sitemaps []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod,omitempty"`
	} `xml:"sitemap"`
}

// SitemapResult contains all discovered sitemap URLs
type SitemapResult struct {
	URLs       []SitemapURL `json:"urls"`
	TotalFound int          `json:"total_found"`
}

// ParseSitemaps fetches and parses sitemap.xml and common variants
func (es *ExternalSources) ParseSitemaps(ctx context.Context, targetURL string) (*SitemapResult, error) {
	baseURL := strings.TrimRight(targetURL, "/")

	// Common sitemap locations (like gospider/katana)
	sitemapPaths := []string{
		"/sitemap.xml",
		"/sitemap_index.xml",
		"/sitemap-index.xml",
		"/sitemapindex.xml",
		"/sitemap_news.xml",
		"/sitemap-news.xml",
		"/post-sitemap.xml",
		"/page-sitemap.xml",
		"/sitemap1.xml",
	}

	result := &SitemapResult{
		URLs: make([]SitemapURL, 0),
	}

	seen := make(map[string]bool)

	for _, path := range sitemapPaths {
		sitemapURL := baseURL + path
		urls, err := es.fetchSitemap(ctx, sitemapURL, seen)
		if err != nil {
			continue // Silently skip missing sitemaps
		}
		result.URLs = append(result.URLs, urls...)
	}

	result.TotalFound = len(result.URLs)
	return result, nil
}

func (es *ExternalSources) fetchSitemap(ctx context.Context, sitemapURL string, seen map[string]bool) ([]SitemapURL, error) {
	if seen[sitemapURL] {
		return nil, nil
	}
	seen[sitemapURL] = true

	req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", es.userAgent)

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("sitemap not found")
	}

	body, err := iohelper.ReadBody(resp.Body, iohelper.LargeMaxBodySize) // 10MB limit
	if err != nil {
		return nil, err
	}

	// Try parsing as sitemap index first
	var sitemapIndex SitemapIndex
	if err := xml.Unmarshal(body, &sitemapIndex); err == nil && len(sitemapIndex.Sitemaps) > 0 {
		var allURLs []SitemapURL
		for _, sm := range sitemapIndex.Sitemaps {
			if !seen[sm.Loc] {
				urls, _ := es.fetchSitemap(ctx, sm.Loc, seen)
				allURLs = append(allURLs, urls...)
			}
		}
		return allURLs, nil
	}

	// Parse as regular sitemap
	var sitemap Sitemap
	if err := xml.Unmarshal(body, &sitemap); err != nil {
		return nil, err
	}

	return sitemap.URLs, nil
}

// ==================== JAVASCRIPT LINKFINDER ====================

// LinkFinderRegex is the regex pattern used by gospider for finding URLs in JavaScript
// This is the famous LinkFinder regex pattern
var LinkFinderRegex = regexcache.MustGet(`(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`)

// Pre-compiled regex for title extraction (used in fingerprinting)
var titleExtractRegex = regexcache.MustGet(`(?i)<title>([^<]+)</title>`)

// FindLinksInJS extracts URLs and paths from JavaScript content
func FindLinksInJS(content string) []string {
	var links []string
	seen := make(map[string]bool)

	// Handle very large files by adding newlines
	if len(content) > 1000000 {
		content = strings.ReplaceAll(content, ";", ";\n")
		content = strings.ReplaceAll(content, ",", ",\n")
	}

	// Decode URL-encoded and unicode-escaped content
	content = decodeJSContent(content)

	// Standard LinkFinder regex
	matches := LinkFinderRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			link := strings.TrimSpace(match[1])
			link = filterNewlines(link)
			if link != "" && !seen[link] {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	// Additional API route patterns for modern SPAs
	apiPatterns := []*regexp.Regexp{
		// fetch("/api/...") or fetch('/api/...')
		regexcache.MustGet(`fetch\s*\(\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// axios.get("/api/..."), axios.post(...), etc.
		regexcache.MustGet(`axios\.\w+\s*\(\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// $.ajax({ url: "/api/..." }) or $.get("/api/...")
		regexcache.MustGet(`\$\.(?:ajax|get|post)\s*\(\s*(?:\{[^}]*url\s*:\s*)?["'\x60](/[^"'\x60]+)["'\x60]`),
		// apiEndpoint: "/api/v1/users" or API_URL = "/api"
		regexcache.MustGet(`(?:api|API|endpoint|ENDPOINT|url|URL|path|PATH|route|ROUTE)\s*[=:]\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// path("/api/v1/users") in router definitions
		regexcache.MustGet(`path\s*\(\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// Route definitions: <Route path="/users" or route: "/users"
		regexcache.MustGet(`[Rr]oute[^=]*(?:path|to)\s*[=:]\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// createAsyncThunk or API functions: "/api/users"
		regexcache.MustGet(`(?:createAsyncThunk|useMutation|useQuery)\s*\([^,]+,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{?[^}]*["'\x60](/api[^"'\x60]+)["'\x60]`),
		// Template strings with API paths: `${baseUrl}/api/users`
		regexcache.MustGet(`\x60\$\{[^}]+\}(/api[^$\x60]+)\x60`),
		// /v1/, /v2/, /v3/ versioned APIs
		regexcache.MustGet(`["'\x60](/v[1-3]/[^"'\x60]+)["'\x60]`),
		// REST patterns: /users/:id, /posts/{id}
		regexcache.MustGet(`["'\x60](/(?:api/)?(?:users|posts|items|products|orders|auth|login|register|admin|settings|profile|upload|files|documents|media|search|reports|analytics|notifications|messages|comments|reviews|categories|tags)[^"'\x60]*)["'\x60]`),
	}

	for _, pattern := range apiPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				link := strings.TrimSpace(match[1])
				link = filterNewlines(link)
				// Clean up template string artifacts
				link = strings.ReplaceAll(link, "${", "")
				link = strings.ReplaceAll(link, "}", "")
				if link != "" && !seen[link] && strings.HasPrefix(link, "/") {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	return links
}

// Pre-compiled replacer and regex for decodeJSContent and filterNewlines
var (
	jsUnicodeReplacer = strings.NewReplacer(
		`\u002f`, "/",
		`\u002F`, "/",
		`\u0026`, "&",
		`\u003d`, "=",
		`\u003D`, "=",
		`\u003f`, "?",
		`\u003F`, "?",
	)
	filterNewlinesRegex = regexcache.MustGet(`[\t\r\n]+`)
)

// Content-hash based caches for expensive extraction functions
var (
	s3BucketsCache     sync.Map // map[string][]string (hash -> buckets)
	detectSecretsCache sync.Map // map[string][]Secret (hash -> secrets)
	jsURLsCache        sync.Map // map[string][]JSURLMatch (hash -> matches)
)

// contentHash generates a fast hash for cache keys
func contentHash(content string) string {
	h := md5.Sum([]byte(content))
	return string(h[:])
}

func decodeJSContent(s string) string {
	// URL decode
	if decoded, err := url.QueryUnescape(s); err == nil {
		s = decoded
	}

	// Unicode escape sequences (using pre-compiled replacer)
	return jsUnicodeReplacer.Replace(s)
}

func filterNewlines(s string) string {
	return filterNewlinesRegex.ReplaceAllString(strings.TrimSpace(s), " ")
}

// ==================== WAYBACK MACHINE ====================

// WaybackURL represents a URL from the Wayback Machine
type WaybackURL struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
}

// FetchWaybackURLs retrieves historical URLs from the Wayback Machine
func (es *ExternalSources) FetchWaybackURLs(ctx context.Context, domain string, includeSubs bool) ([]WaybackURL, error) {
	subsWildcard := ""
	if includeSubs {
		subsWildcard = "*."
	}

	waybackURL := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey&limit=5000",
		subsWildcard, domain,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", waybackURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", es.userAgent)

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback machine request failed: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback machine returned status %d", resp.StatusCode)
	}

	body, err := iohelper.ReadBody(resp.Body, iohelper.LargeMaxBodySize)
	if err != nil {
		return nil, err
	}

	var wrapper [][]string
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}

	result := make([]WaybackURL, 0, len(wrapper))
	skip := true
	for _, urls := range wrapper {
		// First row is headers
		if skip {
			skip = false
			continue
		}
		if len(urls) >= 3 {
			result = append(result, WaybackURL{
				Timestamp: urls[1],
				URL:       urls[2],
			})
		}
	}

	return result, nil
}

// ==================== COMMONCRAWL ====================

// FetchCommonCrawlURLs retrieves URLs from CommonCrawl
func (es *ExternalSources) FetchCommonCrawlURLs(ctx context.Context, domain string, includeSubs bool) ([]string, error) {
	subsWildcard := ""
	if includeSubs {
		subsWildcard = "*."
	}

	// Using a recent CommonCrawl index
	ccURL := fmt.Sprintf(
		"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=%s%s/*&output=json&limit=1000",
		subsWildcard, domain,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", ccURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", es.userAgent)

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl request failed: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("commoncrawl returned status %d", resp.StatusCode)
	}

	var urls []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var entry struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			if entry.URL != "" && !seen[entry.URL] {
				seen[entry.URL] = true
				urls = append(urls, entry.URL)
			}
		}
	}

	return urls, nil
}

// ==================== FORM EXTRACTION ====================

// FormField represents a form input field
type FormField struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // text, password, email, file, hidden, etc.
	ID          string `json:"id,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Value       string `json:"value,omitempty"`
}

// Form represents an HTML form
type Form struct {
	Action   string      `json:"action"`
	Method   string      `json:"method"`
	ID       string      `json:"id,omitempty"`
	Fields   []FormField `json:"fields"`
	HasFile  bool        `json:"has_file_upload"`
	IsLogin  bool        `json:"is_login_form"`
	IsSearch bool        `json:"is_search_form"`
}

// ExtractForms extracts forms from HTML content
func ExtractForms(htmlContent, baseURL string) []Form {
	var forms []Form

	// Simple regex-based form extraction
	formRe := regexcache.MustGet(`(?is)<form[^>]*>(.*?)</form>`)
	actionRe := regexcache.MustGet(`(?i)action=["']([^"']+)["']`)
	methodRe := regexcache.MustGet(`(?i)method=["']([^"']+)["']`)
	formIDRe := regexcache.MustGet(`(?i)id=["']([^"']+)["']`)

	inputRe := regexcache.MustGet(`(?i)<input[^>]*>`)
	inputNameRe := regexcache.MustGet(`(?i)name=["']([^"']+)["']`)
	inputTypeRe := regexcache.MustGet(`(?i)type=["']([^"']+)["']`)
	inputIDRe := regexcache.MustGet(`(?i)id=["']([^"']+)["']`)
	inputValueRe := regexcache.MustGet(`(?i)value=["']([^"']+)["']`)
	inputPlaceholderRe := regexcache.MustGet(`(?i)placeholder=["']([^"']+)["']`)
	inputRequiredRe := regexcache.MustGet(`(?i)\brequired\b`)

	textareaRe := regexcache.MustGet(`(?i)<textarea[^>]*`)
	selectRe := regexcache.MustGet(`(?i)<select[^>]*`)

	formMatches := formRe.FindAllStringSubmatch(htmlContent, -1)
	for _, formMatch := range formMatches {
		if len(formMatch) < 2 {
			continue
		}

		formTag := formMatch[0]
		formBody := formMatch[1]

		form := Form{
			Method: "GET", // Default
			Fields: make([]FormField, 0),
		}

		// Extract action
		if match := actionRe.FindStringSubmatch(formTag); len(match) > 1 {
			form.Action = resolveURL(match[1], baseURL)
		}

		// Extract method
		if match := methodRe.FindStringSubmatch(formTag); len(match) > 1 {
			form.Method = strings.ToUpper(match[1])
		}

		// Extract form ID
		if match := formIDRe.FindStringSubmatch(formTag); len(match) > 1 {
			form.ID = match[1]
		}

		// Extract input fields
		inputs := inputRe.FindAllString(formBody, -1)
		for _, input := range inputs {
			field := FormField{Type: "text"} // Default

			if match := inputNameRe.FindStringSubmatch(input); len(match) > 1 {
				field.Name = match[1]
			}
			if match := inputTypeRe.FindStringSubmatch(input); len(match) > 1 {
				field.Type = strings.ToLower(match[1])
			}
			if match := inputIDRe.FindStringSubmatch(input); len(match) > 1 {
				field.ID = match[1]
			}
			if match := inputValueRe.FindStringSubmatch(input); len(match) > 1 {
				field.Value = match[1]
			}
			if match := inputPlaceholderRe.FindStringSubmatch(input); len(match) > 1 {
				field.Placeholder = match[1]
			}
			if inputRequiredRe.MatchString(input) {
				field.Required = true
			}

			if field.Name != "" {
				form.Fields = append(form.Fields, field)

				// Check for file upload
				if field.Type == "file" {
					form.HasFile = true
				}
			}
		}

		// Check for textareas
		textareas := textareaRe.FindAllString(formBody, -1)
		for _, textarea := range textareas {
			field := FormField{Type: "textarea"}
			if match := inputNameRe.FindStringSubmatch(textarea); len(match) > 1 {
				field.Name = match[1]
			}
			if field.Name != "" {
				form.Fields = append(form.Fields, field)
			}
		}

		// Check for selects
		selects := selectRe.FindAllString(formBody, -1)
		for _, sel := range selects {
			field := FormField{Type: "select"}
			if match := inputNameRe.FindStringSubmatch(sel); len(match) > 1 {
				field.Name = match[1]
			}
			if field.Name != "" {
				form.Fields = append(form.Fields, field)
			}
		}

		// Determine form type
		form.IsLogin = isLoginForm(form)
		form.IsSearch = isSearchForm(form)

		if len(form.Fields) > 0 {
			forms = append(forms, form)
		}
	}

	return forms
}

func isLoginForm(form Form) bool {
	hasPassword := false
	hasUsername := false

	for _, field := range form.Fields {
		if field.Type == "password" {
			hasPassword = true
		}
		name := strings.ToLower(field.Name)
		if strings.Contains(name, "user") || strings.Contains(name, "email") || strings.Contains(name, "login") {
			hasUsername = true
		}
	}

	return hasPassword && hasUsername
}

func isSearchForm(form Form) bool {
	for _, field := range form.Fields {
		name := strings.ToLower(field.Name)
		if strings.Contains(name, "search") || strings.Contains(name, "query") || strings.Contains(name, "q") {
			return true
		}
	}
	return false
}

func resolveURL(link, baseURL string) string {
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return link
	}
	if strings.HasPrefix(link, "//") {
		return "https:" + link
	}
	if strings.HasPrefix(link, "/") {
		base, _ := url.Parse(baseURL)
		return base.Scheme + "://" + base.Host + link
	}
	return baseURL + "/" + link
}

// ==================== OTX ALIENVAULT ====================
// From gospider - excellent source for historical URLs

// OTXURLResult represents a URL from AlienVault OTX
type OTXURLResult struct {
	URL      string `json:"url"`
	Domain   string `json:"domain"`
	Hostname string `json:"hostname"`
	HTTPCode int    `json:"httpcode"`
}

// FetchOTXURLs retrieves URLs from AlienVault OTX
func (es *ExternalSources) FetchOTXURLs(ctx context.Context, domain string) ([]OTXURLResult, error) {
	var allURLs []OTXURLResult
	page := 0
	maxPages := 10 // Limit to prevent infinite loops

	for page < maxPages {
		otxURL := fmt.Sprintf(
			"https://otx.alienvault.com/api/v1/indicators/hostname/%s/url_list?limit=50&page=%d",
			domain, page,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", otxURL, nil)
		if err != nil {
			return allURLs, err
		}
		req.Header.Set("User-Agent", es.userAgent)

		resp, err := es.httpClient.Do(req)
		if err != nil {
			return allURLs, fmt.Errorf("OTX request failed: %w", err)
		}

		body, err := iohelper.ReadBody(resp.Body, 5*1024*1024)
		iohelper.DrainAndClose(resp.Body)
		if err != nil {
			return allURLs, err
		}

		if resp.StatusCode != 200 {
			return allURLs, fmt.Errorf("OTX returned status %d", resp.StatusCode)
		}

		var wrapper struct {
			HasNext bool `json:"has_next"`
			URLList []struct {
				URL      string `json:"url"`
				Domain   string `json:"domain"`
				Hostname string `json:"hostname"`
				HTTPCode int    `json:"httpcode"`
			} `json:"url_list"`
		}

		if err := json.Unmarshal(body, &wrapper); err != nil {
			return allURLs, err
		}

		for _, u := range wrapper.URLList {
			allURLs = append(allURLs, OTXURLResult{
				URL:      u.URL,
				Domain:   u.Domain,
				Hostname: u.Hostname,
				HTTPCode: u.HTTPCode,
			})
		}

		if !wrapper.HasNext {
			break
		}
		page++
	}

	return allURLs, nil
}

// ==================== VIRUSTOTAL ====================
// From gospider - URLs detected by VirusTotal (requires API key)

// FetchVirusTotalURLs retrieves URLs from VirusTotal
// Requires VT_API_KEY environment variable
func (es *ExternalSources) FetchVirusTotalURLs(ctx context.Context, domain string, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not provided")
	}

	vtURL := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		apiKey, domain,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", vtURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", es.userAgent)

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VirusTotal request failed: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VirusTotal returned status %d", resp.StatusCode)
	}

	body, err := iohelper.ReadBody(resp.Body, iohelper.LargeMaxBodySize)
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		DetectedURLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}

	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}

	var urls []string
	for _, u := range wrapper.DetectedURLs {
		urls = append(urls, u.URL)
	}

	return urls, nil
}

// ==================== AWS S3 BUCKET EXTRACTION ====================
// From gospider - finds S3 buckets in responses

// S3 bucket regex patterns
var (
	// Match S3 bucket URLs and references
	s3BucketPatterns = []*regexp.Regexp{
		regexcache.MustGet(`[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com`),
		regexcache.MustGet(`[a-zA-Z0-9.\-_]+\.s3-[a-z0-9-]+\.amazonaws\.com`),
		regexcache.MustGet(`[a-zA-Z0-9.\-_]+\.s3\.[a-z0-9-]+\.amazonaws\.com`),
		regexcache.MustGet(`s3\.amazonaws\.com/[a-zA-Z0-9.\-_]+`),
		regexcache.MustGet(`s3-[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.\-_]+`),
		regexcache.MustGet(`s3\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.\-_]+`),
		regexcache.MustGet(`//[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com`),
		regexcache.MustGet(`arn:aws:s3:::[a-zA-Z0-9.\-_]+`),
	}
)

// ExtractS3Buckets finds AWS S3 bucket references in content
func ExtractS3Buckets(content string) []string {
	// Check cache first
	hash := contentHash(content)
	if cached, ok := s3BucketsCache.Load(hash); ok {
		return cached.([]string)
	}

	seen := make(map[string]bool, 16)
	buckets := make([]string, 0, 16)

	for _, pattern := range s3BucketPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Clean up the match
			match = strings.TrimPrefix(match, "//")
			match = strings.TrimPrefix(match, "arn:aws:s3:::")
			if !seen[match] {
				seen[match] = true
				buckets = append(buckets, match)
			}
		}
	}

	// Cache the result
	s3BucketsCache.Store(hash, buckets)
	return buckets
}

// ==================== SUBDOMAIN EXTRACTION ====================
// From gospider - finds subdomains in responses

// ExtractSubdomains finds subdomains of the target domain in content
func ExtractSubdomains(content string, baseDomain string) []string {
	seen := make(map[string]bool)
	var subdomains []string

	// Escape dots in domain for regex
	escapedDomain := strings.ReplaceAll(baseDomain, ".", `\.`)

	// Pattern to match subdomains
	subdomainRe := regexcache.MustGet(`(?i)([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+` + escapedDomain)

	matches := subdomainRe.FindAllString(content, -1)
	for _, match := range matches {
		match = strings.ToLower(match)
		// Skip if it's just the base domain
		if match == baseDomain {
			continue
		}
		if !seen[match] {
			seen[match] = true
			subdomains = append(subdomains, match)
		}
	}

	return subdomains
}

// ==================== DIRECTORY LISTING DETECTION ====================
// From feroxbuster - detects directory listings and extracts links

// DirectoryListing represents a detected directory listing
type DirectoryListing struct {
	URL     string   `json:"url"`
	Type    string   `json:"type"` // apache, nginx, iis, python, etc.
	Entries []string `json:"entries"`
}

// Directory listing detection patterns
var directoryListingPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"apache", regexcache.MustGet(`(?i)<title>Index of /`)},
	{"nginx", regexcache.MustGet(`(?i)<title>Index of /`)},
	{"nginx-autoindex", regexcache.MustGet(`(?i)autoindex on`)},
	{"lighttpd", regexcache.MustGet(`(?i)<title>Index of /`)},
	{"iis", regexcache.MustGet(`(?i)<title>.*- /</title>`)},
	{"python-http", regexcache.MustGet(`(?i)Directory listing for /`)},
	{"tomcat", regexcache.MustGet(`(?i)<title>Directory Listing For /`)},
	{"webdav", regexcache.MustGet(`(?i)<D:multistatus`)},
}

// Link extraction patterns for directory listings
var directoryLinkPatterns = []*regexp.Regexp{
	regexcache.MustGet(`<a\s+href="([^"?]+)"`),
	regexcache.MustGet(`<a\s+href='([^'?]+)'`),
}

// DetectDirectoryListing checks if content is a directory listing and extracts entries
func DetectDirectoryListing(content string, baseURL string) *DirectoryListing {
	// First check for sorting query params (strong indicator of directory listing)
	hasSorting := HasSortingQueryParams(content)

	for _, pattern := range directoryListingPatterns {
		if pattern.Pattern.MatchString(content) {
			listing := &DirectoryListing{
				URL:     baseURL,
				Type:    pattern.Name,
				Entries: make([]string, 0),
			}

			// Extract links
			seen := make(map[string]bool)
			for _, linkPattern := range directoryLinkPatterns {
				matches := linkPattern.FindAllStringSubmatch(content, -1)
				for _, match := range matches {
					if len(match) > 1 {
						link := match[1]
						// Skip parent directory and common non-file links
						if link == "../" || link == "./" || link == "/" ||
							strings.HasPrefix(link, "?") || strings.HasPrefix(link, "#") {
							continue
						}
						if !seen[link] {
							seen[link] = true
							listing.Entries = append(listing.Entries, link)
						}
					}
				}
			}

			return listing
		}
	}

	// If we have sorting params but no pattern match, it might still be a directory listing
	if hasSorting {
		listing := &DirectoryListing{
			URL:     baseURL,
			Type:    "unknown-with-sorting",
			Entries: make([]string, 0),
		}

		// Extract any links as potential directory entries
		seen := make(map[string]bool)
		for _, linkPattern := range directoryLinkPatterns {
			matches := linkPattern.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) > 1 {
					link := match[1]
					if link == "../" || link == "./" || link == "/" ||
						strings.HasPrefix(link, "?") || strings.HasPrefix(link, "#") {
						continue
					}
					if !seen[link] {
						seen[link] = true
						listing.Entries = append(listing.Entries, link)
					}
				}
			}
		}

		if len(listing.Entries) > 0 {
			return listing
		}
	}

	return nil
}

// HasSortingQueryParams checks for directory listing sorting parameters
// From feroxbuster heuristics
func HasSortingQueryParams(content string) bool {
	sortPatterns := []string{
		"?C=N", "?C=M", "?C=S", "?C=D", // Apache mod_autoindex
		"?O=A", "?O=D", // Order
		"?N=A", "?N=D", // Name
		"?M=A", "?M=D", // Modified
		"?S=A", "?S=D", // Size
	}

	for _, pattern := range sortPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}

// ==================== ENHANCED JAVASCRIPT PARSING ====================
// From jsluice - smarter extraction of URLs from JavaScript

// JSURLMatch represents a URL found in JavaScript with context
type JSURLMatch struct {
	URL         string            `json:"url"`
	Method      string            `json:"method,omitempty"`
	Type        string            `json:"type"` // fetch, xhr, jquery, location, etc.
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams []string          `json:"query_params,omitempty"`
	BodyParams  []string          `json:"body_params,omitempty"`
}

// Enhanced JavaScript URL extraction patterns
var (
	// fetch() calls - fetch('/api/users', { method: 'POST' })
	fetchPattern = regexcache.MustGet(`fetch\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*\{([^}]+)\})?`)

	// XMLHttpRequest.open() - xhr.open('POST', '/api/data')
	xhrOpenPattern = regexcache.MustGet(`\.open\s*\(\s*['"]([A-Z]+)['"]\s*,\s*['"]([^'"]+)['"]`)

	// jQuery AJAX - $.ajax({ url: '/api', method: 'POST' })
	jqueryAjaxPattern = regexcache.MustGet(`\$\.ajax\s*\(\s*\{([^}]+)\}`)

	// jQuery shortcuts - $.get('/api'), $.post('/api')
	jqueryGetPattern  = regexcache.MustGet(`\$\.get\s*\(\s*['"]([^'"]+)['"]`)
	jqueryPostPattern = regexcache.MustGet(`\$\.post\s*\(\s*['"]([^'"]+)['"]`)

	// Location assignments - location.href = '/path'
	locationPattern = regexcache.MustGet(`(?:location\.href|window\.location|document\.location)\s*=\s*['"]([^'"]+)['"]`)

	// location.replace() - location.replace('/path')
	locationReplacePattern = regexcache.MustGet(`location\.replace\s*\(\s*['"]([^'"]+)['"]`)

	// window.open() - window.open('/popup')
	windowOpenPattern = regexcache.MustGet(`window\.open\s*\(\s*['"]([^'"]+)['"]`)

	// src/href assignments - element.src = '/image.png'
	srcHrefPattern = regexcache.MustGet(`\.(src|href)\s*=\s*['"]([^'"]+)['"]`)

	// API endpoint patterns - const API_URL = '/api/v1'
	apiConstPattern = regexcache.MustGet(`(?:API_URL|API_ENDPOINT|BASE_URL|apiUrl|apiEndpoint|baseUrl)\s*[=:]\s*['"]([^'"]+)['"]`)

	// Route definitions - '/users/:id'
	routePattern = regexcache.MustGet(`['"](/[a-zA-Z0-9_/-]+/:[a-zA-Z0-9_]+(?:/[a-zA-Z0-9_/-]*)*)['"]`)

	// Helper patterns for extracting method/url from options
	methodExtractPattern = regexcache.MustGet(`(?i)(?:method|type)\s*:\s*['"]([A-Z]+)['"]`)
	urlExtractPattern    = regexcache.MustGet(`(?i)url\s*:\s*['"]([^'"]+)['"]`)
)

// ExtractJSURLsEnhanced performs smart JavaScript URL extraction
func ExtractJSURLsEnhanced(content string) []JSURLMatch {
	// Check cache first
	hash := contentHash(content)
	if cached, ok := jsURLsCache.Load(hash); ok {
		return cached.([]JSURLMatch)
	}

	// Pre-allocate with estimated capacity
	matches := make([]JSURLMatch, 0, 64)
	seen := make(map[string]bool, 64)

	// Decode escaped content first
	content = decodeJSContent(content)

	// fetch() calls
	for _, match := range fetchPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "fetch:" + url
			if !seen[key] {
				seen[key] = true
				m := JSURLMatch{URL: url, Type: "fetch", Method: "GET"}
				if len(match) > 2 && match[2] != "" {
					m.Method = extractMethodFromOptions(match[2])
				}
				matches = append(matches, m)
			}
		}
	}

	// XHR.open()
	for _, match := range xhrOpenPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 2 {
			method := strings.ToUpper(match[1])
			url := match[2]
			key := "xhr:" + method + ":" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: method, Type: "xhr"})
			}
		}
	}

	// jQuery AJAX
	for _, match := range jqueryAjaxPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			options := match[1]
			url := extractURLFromOptions(options)
			if url != "" {
				key := "jquery:" + url
				if !seen[key] {
					seen[key] = true
					method := extractMethodFromOptions(options)
					if method == "" {
						method = "GET"
					}
					matches = append(matches, JSURLMatch{URL: url, Method: method, Type: "jquery.ajax"})
				}
			}
		}
	}

	// jQuery $.get
	for _, match := range jqueryGetPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "jget:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: "jquery.get"})
			}
		}
	}

	// jQuery $.post
	for _, match := range jqueryPostPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "jpost:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "POST", Type: "jquery.post"})
			}
		}
	}

	// location assignments
	for _, match := range locationPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "location:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: "location"})
			}
		}
	}

	// location.replace()
	for _, match := range locationReplacePattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "replace:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: "location.replace"})
			}
		}
	}

	// window.open()
	for _, match := range windowOpenPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "open:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: "window.open"})
			}
		}
	}

	// src/href assignments
	for _, match := range srcHrefPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 2 {
			url := match[2]
			key := "src:" + url
			if !seen[key] && isValidURLPath(url) {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: match[1] + "_assignment"})
			}
		}
	}

	// API constants
	for _, match := range apiConstPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "api:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Type: "api_constant"})
			}
		}
	}

	// Route definitions
	for _, match := range routePattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "route:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Type: "route"})
			}
		}
	}

	// Also run the original LinkFinder regex
	basicLinks := FindLinksInJS(content)
	for _, link := range basicLinks {
		key := "link:" + link
		if !seen[key] {
			seen[key] = true
			matches = append(matches, JSURLMatch{URL: link, Type: "linkfinder"})
		}
	}

	// Cache the result
	jsURLsCache.Store(hash, matches)
	return matches
}

func extractMethodFromOptions(options string) string {
	if match := methodExtractPattern.FindStringSubmatch(options); len(match) > 1 {
		return strings.ToUpper(match[1])
	}
	return "GET"
}

func extractURLFromOptions(options string) string {
	if match := urlExtractPattern.FindStringSubmatch(options); len(match) > 1 {
		return match[1]
	}
	return ""
}

func isValidURLPath(s string) bool {
	// Filter out data: URLs, javascript:, etc.
	if strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "javascript:") ||
		strings.HasPrefix(s, "mailto:") || strings.HasPrefix(s, "tel:") {
		return false
	}
	// Should start with /, //, http, or be a relative path
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "http") ||
		(len(s) > 1 && !strings.ContainsAny(s[:1], " (){}[]<>"))
}

// ==================== SECRET DETECTION ====================
// From jsluice - finds secrets in JavaScript/responses

// Secret represents a detected secret
type Secret struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Context  string `json:"context,omitempty"`
	Severity string `json:"severity"` // info, low, medium, high
}

// Secret detection patterns
var secretPatterns = []struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}{
	// AWS
	{"aws_access_key", regexcache.MustGet(`AKIA[0-9A-Z]{16}`), "high"},
	{"aws_secret_key", regexcache.MustGet(`(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]`), "high"},

	// Google
	{"google_api_key", regexcache.MustGet(`AIza[0-9A-Za-z\-_]{35}`), "medium"},
	{"google_oauth", regexcache.MustGet(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), "medium"},

	// GitHub
	{"github_token", regexcache.MustGet(`gh[pousr]_[A-Za-z0-9_]{36,255}`), "high"},
	{"github_oauth", regexcache.MustGet(`gho_[A-Za-z0-9]{36}`), "high"},

	// Slack
	{"slack_token", regexcache.MustGet(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`), "high"},
	{"slack_webhook", regexcache.MustGet(`https://hooks\.slack\.com/services/[A-Za-z0-9+/]+`), "medium"},

	// JWT
	{"jwt_token", regexcache.MustGet(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`), "medium"},

	// Private keys
	{"private_key", regexcache.MustGet(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "high"},

	// Generic API keys
	{"api_key", regexcache.MustGet(`(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]`), "medium"},
	{"secret_key", regexcache.MustGet(`(?i)(?:secret[_-]?key|secretkey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]`), "medium"},
	{"auth_token", regexcache.MustGet(`(?i)(?:auth[_-]?token|access[_-]?token)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]`), "medium"},

	// Firebase
	{"firebase_config", regexcache.MustGet(`(?i)firebase[a-zA-Z]*\.json`), "low"},

	// Database URLs
	{"database_url", regexcache.MustGet(`(?i)(?:mongodb|postgres|mysql|redis)://[^\s'"]+`), "high"},

	// Stripe
	{"stripe_key", regexcache.MustGet(`sk_live_[0-9a-zA-Z]{24}`), "high"},
	{"stripe_publishable", regexcache.MustGet(`pk_live_[0-9a-zA-Z]{24}`), "low"},

	// Twilio
	{"twilio_sid", regexcache.MustGet(`AC[a-zA-Z0-9_\-]{32}`), "medium"},
	{"twilio_auth", regexcache.MustGet(`SK[a-zA-Z0-9_\-]{32}`), "high"},

	// SendGrid
	{"sendgrid_key", regexcache.MustGet(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`), "high"},

	// Mailgun
	{"mailgun_key", regexcache.MustGet(`key-[0-9a-zA-Z]{32}`), "high"},

	// Square
	{"square_token", regexcache.MustGet(`sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}`), "high"},

	// Heroku
	{"heroku_key", regexcache.MustGet(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), "low"},
}

// DetectSecrets finds secrets in content
func DetectSecrets(content string) []Secret {
	// Check cache first
	hash := contentHash(content)
	if cached, ok := detectSecretsCache.Load(hash); ok {
		return cached.([]Secret)
	}

	secrets := make([]Secret, 0, 8)
	seen := make(map[string]bool, 16)

	for _, sp := range secretPatterns {
		matches := sp.Pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Create a unique key to avoid duplicates
			key := sp.Name + ":" + match
			if !seen[key] {
				seen[key] = true
				secrets = append(secrets, Secret{
					Type:     sp.Name,
					Value:    truncateSecret(match),
					Severity: sp.Severity,
				})
			}
		}
	}

	// Cache the result
	detectSecretsCache.Store(hash, secrets)
	return secrets
}

func truncateSecret(s string) string {
	// Show first 10 and last 4 chars for secrets
	if len(s) > 20 {
		return s[:10] + "..." + s[len(s)-4:]
	}
	return s
}

// ==================== RESPONSE FINGERPRINTING ====================
// From feroxbuster - detect similar/duplicate responses

// ResponseFingerprint represents a response's unique characteristics
type ResponseFingerprint struct {
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	WordCount     int    `json:"word_count"`
	LineCount     int    `json:"line_count"`
	ContentType   string `json:"content_type"`
	TitleHash     string `json:"title_hash,omitempty"`
}

// CalculateFingerprint creates a fingerprint from response data
func CalculateFingerprint(statusCode int, body []byte, contentType string) ResponseFingerprint {
	content := string(body)

	// Count words (simple split on whitespace)
	words := strings.Fields(content)
	wordCount := len(words)

	// Count lines
	lineCount := strings.Count(content, "\n") + 1

	// Extract title hash (using pre-compiled regex)
	titleHash := ""
	if match := titleExtractRegex.FindStringSubmatch(content); len(match) > 1 {
		titleHash = fmt.Sprintf("%x", simpleHash(match[1]))
	}

	return ResponseFingerprint{
		StatusCode:    statusCode,
		ContentLength: int64(len(body)),
		WordCount:     wordCount,
		LineCount:     lineCount,
		ContentType:   contentType,
		TitleHash:     titleHash,
	}
}

// IsSimilar checks if two fingerprints are similar (for filtering duplicates)
func (f ResponseFingerprint) IsSimilar(other ResponseFingerprint, threshold float64) bool {
	// Status codes must match
	if f.StatusCode != other.StatusCode {
		return false
	}

	// Content type should match
	if f.ContentType != other.ContentType {
		return false
	}

	// Calculate similarity score (0-1)
	var score float64

	// Content length similarity
	if f.ContentLength > 0 && other.ContentLength > 0 {
		lenDiff := float64(abs64(f.ContentLength-other.ContentLength)) / float64(max64(f.ContentLength, other.ContentLength))
		if lenDiff < 0.1 { // Within 10%
			score += 0.4
		}
	}

	// Word count similarity
	if f.WordCount > 0 && other.WordCount > 0 {
		wordDiff := float64(absInt(f.WordCount-other.WordCount)) / float64(maxInt(f.WordCount, other.WordCount))
		if wordDiff < 0.1 {
			score += 0.3
		}
	}

	// Line count similarity
	if f.LineCount > 0 && other.LineCount > 0 {
		lineDiff := float64(absInt(f.LineCount-other.LineCount)) / float64(maxInt(f.LineCount, other.LineCount))
		if lineDiff < 0.1 {
			score += 0.2
		}
	}

	// Title match
	if f.TitleHash != "" && f.TitleHash == other.TitleHash {
		score += 0.1
	}

	return score >= threshold
}

func simpleHash(s string) uint32 {
	var h uint32
	for _, c := range s {
		h = h*31 + uint32(c)
	}
	return h
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ==================== WILDCARD/404 DETECTION ====================
// From feroxbuster - detect wildcard/soft-404 responses

// WildcardDetector helps detect wildcard responses
type WildcardDetector struct {
	baselineFingerprints map[string]ResponseFingerprint // method -> fingerprint
}

// NewWildcardDetector creates a new wildcard detector
func NewWildcardDetector() *WildcardDetector {
	return &WildcardDetector{
		baselineFingerprints: make(map[string]ResponseFingerprint),
	}
}

// AddBaseline adds a baseline response for a method
func (w *WildcardDetector) AddBaseline(method string, fp ResponseFingerprint) {
	w.baselineFingerprints[method] = fp
}

// IsWildcard checks if a response matches the wildcard pattern
func (w *WildcardDetector) IsWildcard(method string, fp ResponseFingerprint) bool {
	baseline, exists := w.baselineFingerprints[method]
	if !exists {
		return false
	}
	return fp.IsSimilar(baseline, 0.7)
}

// ==================== ALL SOURCES COMBINED ====================

// AllSourcesResult combines all external source results
type AllSourcesResult struct {
	RobotsPaths    []string       `json:"robots_paths"`
	SitemapURLs    []string       `json:"sitemap_urls"`
	WaybackURLs    []string       `json:"wayback_urls"`
	CommonCrawl    []string       `json:"commoncrawl_urls"`
	OTXURLs        []string       `json:"otx_urls"`
	VirusTotalURLs []string       `json:"virustotal_urls,omitempty"`
	JSLinks        []string       `json:"js_links"`
	S3Buckets      []string       `json:"s3_buckets,omitempty"`
	Subdomains     []string       `json:"subdomains,omitempty"`
	Secrets        []Secret       `json:"secrets,omitempty"`
	Forms          []Form         `json:"forms"`
	TotalUnique    int            `json:"total_unique"`
	SourceCounts   map[string]int `json:"source_counts"`
}

// GatherAllSources collects endpoints from all external sources
// GatherAllSources collects endpoints from all available external sources
// Enhanced with OTX, VirusTotal, CommonCrawl, and more
func (es *ExternalSources) GatherAllSources(ctx context.Context, targetURL string, domain string) *AllSourcesResult {
	result := &AllSourcesResult{
		SourceCounts: make(map[string]int),
	}
	seen := make(map[string]bool)

	// Robots.txt
	if robots, err := es.ParseRobotsTxt(ctx, targetURL); err == nil {
		for _, path := range robots.AllowedPaths {
			if !seen[path] {
				seen[path] = true
				result.RobotsPaths = append(result.RobotsPaths, path)
			}
		}
		for _, path := range robots.DisallowedPaths {
			if !seen[path] {
				seen[path] = true
				result.RobotsPaths = append(result.RobotsPaths, path)
			}
		}
		result.SourceCounts["robots.txt"] = len(result.RobotsPaths)
	}

	// Sitemaps
	if sitemap, err := es.ParseSitemaps(ctx, targetURL); err == nil {
		for _, u := range sitemap.URLs {
			parsed, _ := url.Parse(u.Loc)
			if parsed != nil && !seen[parsed.Path] {
				seen[parsed.Path] = true
				result.SitemapURLs = append(result.SitemapURLs, parsed.Path)
			}
		}
		result.SourceCounts["sitemap.xml"] = len(result.SitemapURLs)
	}

	// Wayback Machine (with timeout context)
	waybackCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if wayback, err := es.FetchWaybackURLs(waybackCtx, domain, false); err == nil {
		for _, w := range wayback {
			parsed, _ := url.Parse(w.URL)
			if parsed != nil && !seen[parsed.Path] {
				seen[parsed.Path] = true
				result.WaybackURLs = append(result.WaybackURLs, parsed.Path)
			}
		}
		result.SourceCounts["wayback"] = len(result.WaybackURLs)
	}
	cancel()

	// CommonCrawl
	ccCtx, ccCancel := context.WithTimeout(ctx, 30*time.Second)
	if cc, err := es.FetchCommonCrawlURLs(ccCtx, domain, false); err == nil {
		for _, u := range cc {
			parsed, _ := url.Parse(u)
			if parsed != nil && !seen[parsed.Path] {
				seen[parsed.Path] = true
				result.CommonCrawl = append(result.CommonCrawl, parsed.Path)
			}
		}
		result.SourceCounts["commoncrawl"] = len(result.CommonCrawl)
	}
	ccCancel()

	// OTX AlienVault
	otxCtx, otxCancel := context.WithTimeout(ctx, 30*time.Second)
	if otx, err := es.FetchOTXURLs(otxCtx, domain); err == nil {
		for _, o := range otx {
			parsed, _ := url.Parse(o.URL)
			if parsed != nil && !seen[parsed.Path] {
				seen[parsed.Path] = true
				result.OTXURLs = append(result.OTXURLs, parsed.Path)
			}
		}
		result.SourceCounts["otx"] = len(result.OTXURLs)
	}
	otxCancel()

	// VirusTotal (only if API key is available)
	vtAPIKey := getEnvWithDefault("VT_API_KEY", "")
	if vtAPIKey != "" {
		vtCtx, vtCancel := context.WithTimeout(ctx, 30*time.Second)
		if vt, err := es.FetchVirusTotalURLs(vtCtx, domain, vtAPIKey); err == nil {
			for _, u := range vt {
				parsed, _ := url.Parse(u)
				if parsed != nil && !seen[parsed.Path] {
					seen[parsed.Path] = true
					result.VirusTotalURLs = append(result.VirusTotalURLs, parsed.Path)
				}
			}
			result.SourceCounts["virustotal"] = len(result.VirusTotalURLs)
		}
		vtCancel()
	}

	result.TotalUnique = len(seen)
	return result
}

// GatherAllSourcesWithContent extends GatherAllSources to also analyze fetched content
// for S3 buckets, subdomains, secrets, JS links, and forms
func (es *ExternalSources) GatherAllSourcesWithContent(ctx context.Context, targetURL string, domain string, responses []ResponseWithBody) *AllSourcesResult {
	// Start with basic sources
	result := es.GatherAllSources(ctx, targetURL, domain)

	seenS3 := make(map[string]bool)
	seenSub := make(map[string]bool)
	seenJS := make(map[string]bool)
	seenFormAction := make(map[string]bool)

	// Analyze responses for additional data
	for _, resp := range responses {
		// Extract S3 buckets
		buckets := ExtractS3Buckets(resp.Body)
		for _, b := range buckets {
			if !seenS3[b] {
				seenS3[b] = true
				result.S3Buckets = append(result.S3Buckets, b)
			}
		}

		// Extract subdomains
		subs := ExtractSubdomains(resp.Body, domain)
		for _, s := range subs {
			if !seenSub[s] {
				seenSub[s] = true
				result.Subdomains = append(result.Subdomains, s)
			}
		}

		// Detect secrets
		secrets := DetectSecrets(resp.Body)
		result.Secrets = append(result.Secrets, secrets...)

		// Extract JS links from HTML/JS content
		jsMatches := ExtractJSURLsEnhanced(resp.Body)
		for _, match := range jsMatches {
			if !seenJS[match.URL] {
				seenJS[match.URL] = true
				result.JSLinks = append(result.JSLinks, match.URL)
			}
		}

		// Extract forms from HTML content
		forms := ExtractForms(resp.Body, resp.URL)
		for _, form := range forms {
			actionKey := form.Action + "|" + form.Method
			if !seenFormAction[actionKey] {
				seenFormAction[actionKey] = true
				result.Forms = append(result.Forms, form)
			}
		}
	}

	result.SourceCounts["s3_buckets"] = len(result.S3Buckets)
	result.SourceCounts["subdomains"] = len(result.Subdomains)
	result.SourceCounts["secrets"] = len(result.Secrets)
	result.SourceCounts["js_links"] = len(result.JSLinks)
	result.SourceCounts["forms"] = len(result.Forms)

	// Update TotalUnique to include new sources
	result.TotalUnique += len(result.JSLinks)

	return result
}

// ResponseWithBody holds a response body for analysis
type ResponseWithBody struct {
	URL  string
	Body string
}

// Helper to get environment variable with default
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
