// Package discovery - JavaScript analysis for endpoint discovery
package discovery

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/regexcache"
)

// discoverFromJavaScript extracts links from JavaScript files using LinkFinder
func (d *Discoverer) discoverFromJavaScript(ctx context.Context, result *DiscoveryResult) {
	// Find JavaScript files from already discovered endpoints
	var jsURLs []string
	for _, ep := range d.endpoints {
		if strings.HasSuffix(ep.Path, ".js") {
			jsURLs = append(jsURLs, d.config.Target+ep.Path)
		}
	}

	// Extract JS bundle URLs from homepage HTML (critical for SPAs)
	homepageJS := d.extractJSFromHomepage(ctx)
	jsURLs = append(jsURLs, homepageJS...)

	// Also check common JS paths
	commonJSPaths := []string{
		"/static/js/main.js",
		"/assets/js/app.js",
		"/js/bundle.js",
		"/dist/main.js",
		"/build/bundle.js",
	}
	for _, path := range commonJSPaths {
		jsURLs = append(jsURLs, d.config.Target+path)
	}

	// Dedupe JS URLs
	seenJS := make(map[string]bool)
	uniqueJS := make([]string, 0)
	for _, u := range jsURLs {
		if !seenJS[u] {
			seenJS[u] = true
			uniqueJS = append(uniqueJS, u)
		}
	}

	// Create JS analyzer for method inference
	jsAnalyzer := js.NewAnalyzer()

	// Fetch and analyze each JS file
	for _, jsURL := range uniqueJS {
		// Check context cancellation between JS files to enable prompt shutdown
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.config.UserAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				iohelper.DrainAndClose(resp.Body)
			}
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 2*1024*1024) // 2MB limit
		iohelper.DrainAndClose(resp.Body)

		jsCode := string(body)

		// Use JS analyzer for proper method inference
		jsData := jsAnalyzer.Analyze(jsCode)

		// Add endpoints from JS analyzer (fetch/axios/xhr patterns)
		for _, ep := range jsData.Endpoints {
			epPath := normalizeJSPath(ep.Path)
			if epPath == "" || isStaticFile(epPath) {
				continue
			}
			path := extractPath(epPath)
			if path != "" && !d.isExcluded(path) {
				method := ep.Method
				if method == "" {
					method = "GET"
				}
				d.probeEndpointWithMethod(ctx, path, method, result)
			}
		}

		// Add URLs with inferred methods
		for _, urlInfo := range jsData.URLs {
			urlPath := normalizeJSPath(urlInfo.URL)
			if urlPath == "" || isStaticFile(urlPath) {
				continue
			}
			path := extractPath(urlPath)
			if path != "" && !d.isExcluded(path) {
				method := urlInfo.Method
				if method == "" {
					method = "GET"
				}
				d.probeEndpointWithMethod(ctx, path, method, result)
			}
		}
	}
}

// extractJSFromHomepage fetches homepage and extracts all JavaScript bundle URLs
func (d *Discoverer) extractJSFromHomepage(ctx context.Context) []string {
	req, err := http.NewRequestWithContext(ctx, "GET", d.config.Target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", d.config.UserAgent)

	resp, err := d.httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			iohelper.DrainAndClose(resp.Body)
		}
		return nil
	}

	body, _ := iohelper.ReadBody(resp.Body, 512*1024) // 512KB limit for HTML
	iohelper.DrainAndClose(resp.Body)

	html := string(body)
	var jsURLs []string

	// Extract script src attributes
	// Pattern: <script ... src="..." ...>
	scriptPattern := regexcache.MustGet(`<script[^>]*\ssrc=["']([^"']+)["']`)
	matches := scriptPattern.FindAllStringSubmatch(html, -1)
	baseURL := d.config.Target
	// Ensure base URL ends without trailing slash for clean concatenation
	baseURL = strings.TrimRight(baseURL, "/")

	for _, match := range matches {
		if len(match) > 1 {
			src := match[1]
			// Skip data URIs and empty sources
			if src == "" || strings.HasPrefix(src, "data:") {
				continue
			}
			// Convert to absolute URL
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				// Check if same domain. Guard against empty hostname — in Go,
				// strings.Contains(s, "") is always true, which would match
				// every third-party CDN URL.
				hostname := d.getHostname()
				srcURL, parseErr := url.Parse(src)
				if parseErr == nil && hostname != "" && srcURL.Hostname() == hostname {
					jsURLs = append(jsURLs, src)
				}
			} else if strings.HasPrefix(src, "//") {
				// Protocol-relative URL — inherit scheme from target
				scheme := "https:"
				if strings.HasPrefix(baseURL, "http://") {
					scheme = "http:"
				}
				fullURL := scheme + src
				hostname := d.getHostname()
				srcURL, parseErr := url.Parse(fullURL)
				if parseErr == nil && hostname != "" && srcURL.Hostname() == hostname {
					jsURLs = append(jsURLs, fullURL)
				}
			} else if strings.HasPrefix(src, "/") {
				// Absolute path
				jsURLs = append(jsURLs, baseURL+src)
			} else {
				// Relative path (e.g., "js/app.js", "./bundle.js")
				// Strip leading "./" before resolving against base URL
				cleanSrc := strings.TrimPrefix(src, "./")
				parsedBase, parseErr := url.Parse(baseURL)
				if parseErr == nil {
					dir := parsedBase.Path
					if idx := strings.LastIndex(dir, "/"); idx >= 0 {
						dir = dir[:idx]
					}
					parsedBase.Path = dir + "/" + cleanSrc
					jsURLs = append(jsURLs, parsedBase.String())
				} else {
					jsURLs = append(jsURLs, baseURL+"/"+cleanSrc)
				}
			}
		}
	}

	// Also check for dynamic imports in inline scripts
	// Pattern: import("...") or require("...")
	importPattern := regexcache.MustGet(`(?:import|require)\s*\(\s*["']([^"']+\.js[^"']*)["']`)
	importMatches := importPattern.FindAllStringSubmatch(html, -1)
	for _, match := range importMatches {
		if len(match) > 1 {
			src := match[1]
			if strings.HasPrefix(src, "/") {
				jsURLs = append(jsURLs, baseURL+src)
			}
		}
	}

	return jsURLs
}

// normalizeJSPath converts a JS-extracted path to an absolute path.
// Absolute paths ("/api/users") pass through. Relative paths ("api/users",
// "./config") get a "/" prefix. Protocol-relative ("//cdn.example.com") and
// full URLs ("https://...") are rejected (return "").
// Parent-directory traversals ("../secret") are rejected to avoid probing
// nonsensical paths that could trigger WAF rules on the target.
func normalizeJSPath(p string) string {
	if p == "" || p == "." || p == ".." {
		return ""
	}
	// Reject protocol-relative and full URLs
	if strings.HasPrefix(p, "//") || strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return ""
	}
	// Reject parent-directory traversals
	if strings.HasPrefix(p, "../") {
		return ""
	}
	// Already absolute
	if strings.HasPrefix(p, "/") {
		// Reject traversal in absolute paths
		if strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
			return ""
		}
		return p
	}
	// Relative path — strip "./" prefix and make absolute
	p = strings.TrimPrefix(p, "./")
	if p == "" || p == "." || p == ".." {
		return ""
	}
	// Reject traversal after stripping ./
	if strings.HasPrefix(p, "../") {
		return ""
	}
	// Also reject mid-path traversal (e.g., "foo/../bar")
	if strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return ""
	}
	return "/" + p
}

// isStaticFile returns true if the path ends with a known static file extension.
// Used to skip probing static assets that are not API endpoints.
func isStaticFile(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".css") ||
		strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") ||
		strings.HasSuffix(lower, ".jpeg") || strings.HasSuffix(lower, ".gif") ||
		strings.HasSuffix(lower, ".svg") || strings.HasSuffix(lower, ".woff") ||
		strings.HasSuffix(lower, ".woff2") || strings.HasSuffix(lower, ".ttf") ||
		strings.HasSuffix(lower, ".eot") || strings.HasSuffix(lower, ".ico") ||
		strings.HasSuffix(lower, ".map") || strings.HasSuffix(lower, ".webp") ||
		strings.HasSuffix(lower, ".mp4") || strings.HasSuffix(lower, ".webm")
}

// getHostname extracts hostname from target URL
func (d *Discoverer) getHostname() string {
	u, err := url.Parse(d.config.Target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
