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
			if strings.HasPrefix(ep.Path, "/") && !strings.HasPrefix(ep.Path, "//") {
				path := extractPath(ep.Path)
				if path != "" && !d.isExcluded(path) {
					method := ep.Method
					if method == "" {
						method = "GET"
					}
					d.probeEndpointWithMethod(ctx, path, method, result)
				}
			}
		}

		// Add URLs with inferred methods
		for _, urlInfo := range jsData.URLs {
			if strings.HasPrefix(urlInfo.URL, "/") && !strings.HasPrefix(urlInfo.URL, "//") {
				// Skip static files
				if strings.HasSuffix(urlInfo.URL, ".js") || strings.HasSuffix(urlInfo.URL, ".css") ||
					strings.HasSuffix(urlInfo.URL, ".png") || strings.HasSuffix(urlInfo.URL, ".jpg") ||
					strings.HasSuffix(urlInfo.URL, ".svg") || strings.HasSuffix(urlInfo.URL, ".woff") {
					continue
				}
				path := extractPath(urlInfo.URL)
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
	for _, match := range matches {
		if len(match) > 1 {
			src := match[1]
			// Convert to absolute URL
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				// Check if same domain
				if strings.Contains(src, d.getHostname()) {
					jsURLs = append(jsURLs, src)
				}
			} else if strings.HasPrefix(src, "//") {
				// Protocol-relative URL
				jsURLs = append(jsURLs, "https:"+src)
			} else if strings.HasPrefix(src, "/") {
				// Absolute path
				jsURLs = append(jsURLs, d.config.Target+src)
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
				jsURLs = append(jsURLs, d.config.Target+src)
			}
		}
	}

	return jsURLs
}

// getHostname extracts hostname from target URL
func (d *Discoverer) getHostname() string {
	u, err := url.Parse(d.config.Target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
