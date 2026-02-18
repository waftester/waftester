// Package discovery - External sources for endpoint discovery
// Inspired by gospider's OtherSources and katana's known-files features
package discovery

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// ExternalSources provides methods to discover endpoints from external sources
type ExternalSources struct {
	httpClient *http.Client
	userAgent  string
}

// NewExternalSources creates a new external sources discoverer
func NewExternalSources(timeout time.Duration, userAgent string) *ExternalSources {
	if timeout == 0 {
		timeout = httpclient.TimeoutScanning
	}
	if userAgent == "" {
		userAgent = ui.UserAgentWithContext("Discovery")
	}
	return &ExternalSources{
		httpClient: httpclient.New(httpclient.WithTimeout(timeout)),
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

	body, err := iohelper.ReadBody(resp.Body, iohelper.DefaultMaxBodySize)
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

// ==================== SITEMAP PARSING ====================

// SitemapURL represents a URL from sitemap.xml
type SitemapURL struct {
	Loc        string `xml:"loc" json:"loc"`
	LastMod    string `xml:"lastmod,omitempty" json:"lastmod,omitempty"`
	ChangeFreq string `xml:"changefreq,omitempty" json:"changefreq,omitempty"`
	Priority   string `xml:"priority,omitempty" json:"priority,omitempty"`
}

// SitemapResult contains all discovered sitemap URLs
type SitemapResult struct {
	URLs       []SitemapURL `json:"urls"`
	TotalFound int          `json:"total_found"`
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

// ParseSitemaps fetches and parses sitemap.xml (including sitemap indexes)
func (es *ExternalSources) ParseSitemaps(ctx context.Context, targetURL string) (*SitemapResult, error) {
	sitemapURL := strings.TrimRight(targetURL, "/") + "/sitemap.xml"
	seen := make(map[string]bool)
	urls, err := es.fetchSitemap(ctx, sitemapURL, seen)
	if err != nil {
		return &SitemapResult{URLs: make([]SitemapURL, 0)}, nil
	}
	result := &SitemapResult{URLs: urls}
	result.TotalFound = len(result.URLs)
	return result, nil
}

func (es *ExternalSources) fetchSitemap(ctx context.Context, sitemapURL string, seen map[string]bool) ([]SitemapURL, error) {
	return es.fetchSitemapRecursive(ctx, sitemapURL, seen, 0)
}

const maxSitemapDepth = 5

func (es *ExternalSources) fetchSitemapRecursive(ctx context.Context, sitemapURL string, seen map[string]bool, depth int) ([]SitemapURL, error) {
	if depth > maxSitemapDepth || seen[sitemapURL] {
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
		return nil, nil
	}

	body, err := iohelper.ReadBody(resp.Body, iohelper.LargeMaxBodySize)
	if err != nil {
		return nil, err
	}

	// Try parsing as sitemap index first
	var index SitemapIndex
	if err := xml.Unmarshal(body, &index); err == nil && len(index.Sitemaps) > 0 {
		var allURLs []SitemapURL
		for _, sm := range index.Sitemaps {
			urls, _ := es.fetchSitemapRecursive(ctx, sm.Loc, seen, depth+1)
			allURLs = append(allURLs, urls...)
		}
		return allURLs, nil
	}

	// Parse as regular urlset
	var sitemap Sitemap
	if err := xml.Unmarshal(body, &sitemap); err != nil {
		return nil, err
	}

	return sitemap.URLs, nil
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
	Secrets        []Secret       `json:"secrets,omitempty"` // Secrets found in external source responses
	Forms          []Form         `json:"forms"`
	SourceCounts   map[string]int `json:"source_counts"`
	TotalUnique    int            `json:"total_unique"`
}

// GatherAllSources fetches from all external sources in parallel-ish fashion
func (es *ExternalSources) GatherAllSources(ctx context.Context, targetURL string, domain string) *AllSourcesResult {
	result := &AllSourcesResult{
		SourceCounts: make(map[string]int),
	}

	// Use sync.WaitGroup for parallel fetching
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Track unique URLs
	seen := make(map[string]bool)
	addUnique := func(source string, urls []string) {
		mu.Lock()
		defer mu.Unlock()
		var unique []string
		for _, u := range urls {
			// Extract path from absolute URL
			parsed, err := url.Parse(u)
			if err != nil {
				continue
			}
			path := parsed.Path
			if path == "" || path == "/" {
				continue
			}
			if !seen[path] {
				seen[path] = true
				unique = append(unique, path)
			}
		}
		result.SourceCounts[source] = len(unique)
		switch source {
		case "robots.txt":
			result.RobotsPaths = append(result.RobotsPaths, unique...)
		case "sitemap.xml":
			result.SitemapURLs = append(result.SitemapURLs, unique...)
		case "wayback":
			result.WaybackURLs = append(result.WaybackURLs, unique...)
		case "commoncrawl":
			result.CommonCrawl = append(result.CommonCrawl, unique...)
		case "otx":
			result.OTXURLs = append(result.OTXURLs, unique...)
		case "virustotal":
			result.VirusTotalURLs = append(result.VirusTotalURLs, unique...)
		}
	}

	// Robots.txt
	wg.Add(1)
	go func() {
		defer wg.Done()
		robots, err := es.ParseRobotsTxt(ctx, targetURL)
		if err != nil {
			return
		}
		var allPaths []string
		allPaths = append(allPaths, robots.DisallowedPaths...)
		allPaths = append(allPaths, robots.AllowedPaths...)
		addUnique("robots.txt", allPaths)

		// If robots.txt has sitemaps, fetch those too
		for _, sm := range robots.Sitemaps {
			smSeen := make(map[string]bool)
			urls, err := es.fetchSitemap(ctx, sm, smSeen)
			if err == nil {
				var sitemapPaths []string
				for _, u := range urls {
					sitemapPaths = append(sitemapPaths, u.Loc)
				}
				addUnique("sitemap.xml", sitemapPaths)
			}
		}
	}()

	// Sitemap.xml (default location)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sitemaps, err := es.ParseSitemaps(ctx, targetURL)
		if err != nil || sitemaps == nil {
			return
		}
		var urls []string
		for _, u := range sitemaps.URLs {
			urls = append(urls, u.Loc)
		}
		addUnique("sitemap.xml", urls)
	}()

	// Wayback Machine
	wg.Add(1)
	go func() {
		defer wg.Done()
		waybackURLs, err := es.FetchWaybackURLs(ctx, domain, true)
		if err != nil {
			return
		}
		var urls []string
		for _, wu := range waybackURLs {
			urls = append(urls, wu.URL)
		}
		addUnique("wayback", urls)
	}()

	// CommonCrawl
	wg.Add(1)
	go func() {
		defer wg.Done()
		ccURLs, err := es.FetchCommonCrawlURLs(ctx, domain, true)
		if err != nil {
			return
		}
		addUnique("commoncrawl", ccURLs)
	}()

	// OTX
	wg.Add(1)
	go func() {
		defer wg.Done()
		otxURLs, err := es.FetchOTXURLs(ctx, domain)
		if err != nil {
			return
		}
		var urls []string
		for _, ou := range otxURLs {
			urls = append(urls, ou.URL)
		}
		addUnique("otx", urls)
	}()

	// VirusTotal (if API key available)
	vtKey := getEnvWithDefault("VT_API_KEY", "")
	if vtKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vtURLs, err := es.FetchVirusTotalURLs(ctx, domain, vtKey)
			if err != nil {
				return
			}
			addUnique("virustotal", vtURLs)
		}()
	}

	wg.Wait()
	result.TotalUnique = len(seen)

	return result
}

// GatherAllSourcesWithContent fetches from all sources and also analyzes response content
func (es *ExternalSources) GatherAllSourcesWithContent(ctx context.Context, targetURL string, domain string, responses []ResponseWithBody) *AllSourcesResult {
	// Start with regular gathering
	result := es.GatherAllSources(ctx, targetURL, domain)

	// Analyze response content for additional findings
	var allSecrets []Secret
	var allS3Buckets []string
	var allSubdomains []string
	s3Seen := make(map[string]bool)
	subSeen := make(map[string]bool)

	for _, resp := range responses {
		content := string(resp.Body)

		// Extract secrets
		if secrets := DetectSecrets(content); len(secrets) > 0 {
			allSecrets = append(allSecrets, secrets...)
		}

		// Extract S3 buckets
		if buckets := ExtractS3Buckets(content); len(buckets) > 0 {
			for _, b := range buckets {
				if !s3Seen[b] {
					s3Seen[b] = true
					allS3Buckets = append(allS3Buckets, b)
				}
			}
		}

		// Extract subdomains
		if subs := ExtractSubdomains(content, domain); len(subs) > 0 {
			for _, s := range subs {
				if !subSeen[s] {
					subSeen[s] = true
					allSubdomains = append(allSubdomains, s)
				}
			}
		}

		// Extract JS links from HTML/JS content
		if strings.Contains(resp.ContentType, "html") || strings.Contains(resp.ContentType, "javascript") {
			jsMatches := ExtractJSURLsEnhanced(content)
			for _, m := range jsMatches {
				result.JSLinks = append(result.JSLinks, m.URL)
			}
		}
	}

	result.Secrets = allSecrets
	result.S3Buckets = allS3Buckets
	result.Subdomains = allSubdomains

	return result
}

// ResponseWithBody represents a response with its body for content analysis
type ResponseWithBody struct {
	URL         string
	StatusCode  int
	ContentType string
	Body        []byte
}

// getEnvWithDefault returns env var or default
func getEnvWithDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
