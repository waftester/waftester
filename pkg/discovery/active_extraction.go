// Package discovery - Response extraction, parameter discovery, and enhanced getters
package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

// extractFromResponses extracts additional paths from found pages (legacy wrapper)
func (ad *ActiveDiscoverer) extractFromResponses(ctx context.Context) {
	ad.extractFromResponsesWithProgress(ctx, 10, nil)
}

// extractFromResponsesWithProgress crawls found pages to discover new links using worker pool
func (ad *ActiveDiscoverer) extractFromResponsesWithProgress(ctx context.Context, concurrency int, progress func(done, total int)) {
	// Collect HTML pages only (skip static assets)
	var htmlPaths []string
	ad.found.Range(func(key, value interface{}) bool {
		path := key.(string)
		if !isStaticAsset(path) {
			htmlPaths = append(htmlPaths, path)
		}
		return true
	})

	// Limit to 50 pages max for performance
	if len(htmlPaths) > 50 {
		htmlPaths = htmlPaths[:50]
	}

	if len(htmlPaths) == 0 {
		if progress != nil {
			progress(1, 1)
		}
		return
	}

	total := len(htmlPaths)
	var done int64

	// Worker pool
	work := make(chan string, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case path, ok := <-work:
					if !ok {
						return
					}
					ad.extractLinksFromPage(ctx, path)
					if progress != nil {
						current := atomic.AddInt64(&done, 1)
						progress(int(current), total)
					}
				}
			}
		}()
	}

htmlLoop:
	for _, path := range htmlPaths {
		select {
		case <-ctx.Done():
			break htmlLoop
		case work <- path:
		}
	}
	close(work)
	wg.Wait()
}

// extractLinksFromPage fetches a page and extracts links using all enhanced extractors
func (ad *ActiveDiscoverer) extractLinksFromPage(ctx context.Context, path string) {
	fullURL := ad.target + path
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", ad.userAgent)

	resp, err := ad.client.Do(req)
	if err != nil {
		return
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)
	bodyStr := string(body)
	contentType := resp.Header.Get("Content-Type")

	// Collect all discovered links
	allLinks := make(map[string]bool)

	// 1. Standard HTML link extraction
	for _, link := range extractLinks(bodyStr, ad.target) {
		allLinks[link] = true
	}

	// 2. Enhanced JavaScript URL extraction (fetch, XHR, jQuery, etc.)
	jsMatches := ExtractJSURLsEnhanced(bodyStr)
	for _, match := range jsMatches {
		if resolved := resolveURL(match.URL, ad.target); resolved != "" {
			allLinks[resolved] = true
		}
	}

	// 3. Directory listing detection - extract all entries if detected
	if listing := DetectDirectoryListing(bodyStr, fullURL); listing != nil {
		for _, entry := range listing.Entries {
			// Build full path from listing entry
			var entryPath string
			if strings.HasPrefix(entry, "/") {
				entryPath = entry
			} else {
				entryPath = strings.TrimSuffix(path, "/") + "/" + entry
			}
			allLinks[entryPath] = true
		}
	}

	// 4. Secret detection - store for later reporting (don't probe)
	if secrets := DetectSecrets(bodyStr); len(secrets) > 0 {
		ad.mu.Lock()
		if ad.discoveredSecrets == nil {
			ad.discoveredSecrets = make(map[string][]Secret)
		}
		ad.discoveredSecrets[path] = append(ad.discoveredSecrets[path], secrets...)
		ad.mu.Unlock()
	}

	// 5. S3 bucket extraction - store for later reporting
	if buckets := ExtractS3Buckets(bodyStr); len(buckets) > 0 {
		ad.mu.Lock()
		if ad.discoveredS3Buckets == nil {
			ad.discoveredS3Buckets = make(map[string]bool)
		}
		for _, bucket := range buckets {
			ad.discoveredS3Buckets[bucket] = true
		}
		ad.mu.Unlock()
	}

	// 6. Subdomain extraction - store for later reporting
	if domain := extractDomainFromURL(ad.target); domain != "" {
		if subs := ExtractSubdomains(bodyStr, domain); len(subs) > 0 {
			ad.mu.Lock()
			if ad.discoveredSubdomains == nil {
				ad.discoveredSubdomains = make(map[string]bool)
			}
			for _, sub := range subs {
				ad.discoveredSubdomains[sub] = true
			}
			ad.mu.Unlock()
		}
	}

	// Probe discovered links (limit to prevent explosion)
	count := 0
	maxProbes := 20 // Increased from 10 due to better quality links
	for link := range allLinks {
		if count >= maxProbes {
			break
		}
		if _, exists := ad.found.Load(link); !exists {
			// Skip static assets
			if isStaticAsset(link) {
				continue
			}
			ad.probeSinglePath(ctx, link)
			count++
		}
	}

	// For JavaScript files, do deeper extraction
	if strings.Contains(contentType, "javascript") || strings.HasSuffix(path, ".js") {
		ad.extractFromJavaScript(ctx, bodyStr)
	}
}

// extractFromJavaScript performs deep extraction from JavaScript content
func (ad *ActiveDiscoverer) extractFromJavaScript(ctx context.Context, jsContent string) {
	matches := ExtractJSURLsEnhanced(jsContent)

	count := 0
	for _, match := range matches {
		if count >= 15 {
			break
		}
		resolved := resolveURL(match.URL, ad.target)
		if resolved == "" || isStaticAsset(resolved) {
			continue
		}
		if _, exists := ad.found.Load(resolved); !exists {
			ad.probeSinglePath(ctx, resolved)
			count++
		}
	}
}

// extractDomainFromURL extracts the domain from a URL
func extractDomainFromURL(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// isStaticAsset checks if path is a static asset
func isStaticAsset(path string) bool {
	lower := strings.ToLower(path)
	exts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// isHighValueEndpoint checks if endpoint is worth deep testing
func isHighValueEndpoint(ep Endpoint) bool {
	switch ep.Category {
	case "api", "auth", "admin", "upload", "protected":
		return true
	}
	path := strings.ToLower(ep.Path)
	highValue := []string{"/api", "/rest", "/graphql", "/admin", "/auth", "/login", "/user", "/webhook", "/upload"}
	for _, hv := range highValue {
		if strings.Contains(path, hv) {
			return true
		}
	}
	return false
}

// discoverParameters finds hidden parameters in endpoints (legacy wrapper)
func (ad *ActiveDiscoverer) discoverParameters(ctx context.Context) {
	ad.discoverParametersWithProgress(ctx, 10, nil)
}

// discoverParametersWithProgress tests common parameters on high-value endpoints using worker pool
func (ad *ActiveDiscoverer) discoverParametersWithProgress(ctx context.Context, concurrency int, progress func(done, total int)) {
	commonParams := []string{
		"id", "page", "search", "q", "query",
		"user", "file", "path", "url", "redirect",
		"debug", "token", "key", "format", "callback",
	}

	// Get high-value endpoints only
	ad.mu.Lock()
	var highValue []int // indices
	for i, ep := range ad.results {
		if isHighValueEndpoint(ep) && len(ep.Parameters) == 0 && ep.Method == "GET" {
			highValue = append(highValue, i)
		}
	}
	ad.mu.Unlock()

	// Limit to 30 endpoints max
	if len(highValue) > 30 {
		highValue = highValue[:30]
	}

	if len(highValue) == 0 {
		if progress != nil {
			progress(1, 1)
		}
		return
	}

	total := len(highValue)
	var done int64

	// Worker pool
	work := make(chan int, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case idx, ok := <-work:
					if !ok {
						return
					}
					ad.mu.Lock()
					ep := ad.results[idx]
					ad.mu.Unlock()

					foundParams := ad.probeParameters(ctx, ep.Path, commonParams)
					if len(foundParams) > 0 {
						ad.mu.Lock()
						if idx < len(ad.results) {
							ad.results[idx].Parameters = foundParams
						}
						ad.mu.Unlock()
					}

					if progress != nil {
						current := atomic.AddInt64(&done, 1)
						progress(int(current), total)
					}
				}
			}
		}()
	}

paramLoop:
	for _, idx := range highValue {
		select {
		case <-ctx.Done():
			break paramLoop
		case work <- idx:
		}
	}
	close(work)
	wg.Wait()
}

// probeParameters tests common parameters on an endpoint
func (ad *ActiveDiscoverer) probeParameters(ctx context.Context, path string, params []string) []Parameter {
	var found []Parameter

	// Get baseline response
	baseURL := ad.target + path
	baseReq, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return found
	}
	baseReq.Header.Set("User-Agent", ad.userAgent)
	baseResp, err := ad.client.Do(baseReq)
	if err != nil {
		return found
	}
	baseBody, _ := iohelper.ReadBodyDefault(baseResp.Body)
	iohelper.DrainAndClose(baseResp.Body)
	baseLen := len(baseBody)

	// Try each parameter
	for _, param := range params {
		testURL := fmt.Sprintf("%s?%s=test123", baseURL, param)
		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", ad.userAgent)

		resp, err := ad.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)

		// If response differs significantly, parameter is likely processed
		if abs(len(body)-baseLen) > 50 || resp.StatusCode != baseResp.StatusCode {
			found = append(found, Parameter{
				Name:     param,
				Location: "query",
				Type:     "string",
			})
		}
	}

	return found
}

// ==================== HELPER FUNCTIONS ====================

func isInterestingStatus(code int) bool {
	switch code {
	case 200, 201, 204, 206, 301, 302, 303, 307, 308, 401, 403, 405:
		return true
	}
	return false
}

func categorizeByStatus(path string, statusCode int) string {
	pathLower := strings.ToLower(path)

	if statusCode == 401 || statusCode == 403 {
		return "protected"
	}
	if strings.Contains(pathLower, "login") || strings.Contains(pathLower, "auth") ||
		strings.Contains(pathLower, "signin") || strings.Contains(pathLower, "sso") {
		return "auth"
	}
	if strings.Contains(pathLower, "api") || strings.Contains(pathLower, "rest") ||
		strings.Contains(pathLower, "graphql") {
		return "api"
	}
	if strings.Contains(pathLower, "admin") || strings.Contains(pathLower, "manage") ||
		strings.Contains(pathLower, "dashboard") {
		return "admin"
	}
	if strings.Contains(pathLower, "upload") || strings.Contains(pathLower, "file") {
		return "upload"
	}
	if strings.Contains(pathLower, "health") || strings.Contains(pathLower, "status") ||
		strings.Contains(pathLower, "ping") {
		return "health"
	}
	if strings.HasSuffix(pathLower, ".js") || strings.HasSuffix(pathLower, ".css") ||
		strings.HasSuffix(pathLower, ".png") || strings.HasSuffix(pathLower, ".jpg") {
		return "static"
	}
	return "page"
}

func extractParamsFromResponse(body, path string) []Parameter {
	var params []Parameter
	seen := make(map[string]bool)

	// Extract from URL query strings in body
	urlRe := regexcache.MustGet(`[?&]([a-zA-Z_][a-zA-Z0-9_]*)=`)
	matches := urlRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			params = append(params, Parameter{
				Name:     m[1],
				Location: "query",
				Type:     "string",
			})
		}
	}

	// Extract from form inputs
	inputRe := regexcache.MustGet(`<input[^>]*name=["']([^"']+)["']`)
	matches = inputRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			params = append(params, Parameter{
				Name:     m[1],
				Location: "body",
				Type:     "string",
			})
		}
	}

	return params
}

func extractLinks(body, target string) []string {
	var links []string
	seen := make(map[string]bool)

	parsed, _ := url.Parse(target)
	targetHost := ""
	if parsed != nil {
		targetHost = parsed.Host
	}

	// Extract href and src attributes
	linkRe := regexcache.MustGet(`(?:href|src|action)=["']([^"']+)["']`)
	matches := linkRe.FindAllStringSubmatch(body, -1)

	for _, m := range matches {
		if len(m) > 1 {
			link := m[1]

			// Skip external links, data URLs, anchors, mailto
			if strings.HasPrefix(link, "http") {
				linkParsed, err := url.Parse(link)
				if err != nil || linkParsed.Host != targetHost {
					continue
				}
				link = linkParsed.Path
			}
			if strings.HasPrefix(link, "data:") || strings.HasPrefix(link, "javascript:") ||
				strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "#") {
				continue
			}

			// Normalize path
			if !strings.HasPrefix(link, "/") {
				link = "/" + link
			}

			if !seen[link] {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	return links
}

func hasExtension(path string) bool {
	// Check if path has a file extension
	// Get the last path segment (strings.Split always returns at least one element)
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	return strings.Contains(last, ".")
}

func dedupe(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ==================== ENHANCED DISCOVERY GETTERS ====================

// GetDiscoveredSecrets returns all secrets found during discovery
func (ad *ActiveDiscoverer) GetDiscoveredSecrets() map[string][]Secret {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	if ad.discoveredSecrets == nil {
		return make(map[string][]Secret)
	}
	// Return a copy
	result := make(map[string][]Secret)
	for k, v := range ad.discoveredSecrets {
		result[k] = append([]Secret{}, v...)
	}
	return result
}

// GetDiscoveredS3Buckets returns all S3 buckets found during discovery
func (ad *ActiveDiscoverer) GetDiscoveredS3Buckets() []string {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	if ad.discoveredS3Buckets == nil {
		return nil
	}
	result := make([]string, 0, len(ad.discoveredS3Buckets))
	for bucket := range ad.discoveredS3Buckets {
		result = append(result, bucket)
	}
	return result
}

// GetDiscoveredSubdomains returns all subdomains found during discovery
func (ad *ActiveDiscoverer) GetDiscoveredSubdomains() []string {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	if ad.discoveredSubdomains == nil {
		return nil
	}
	result := make([]string, 0, len(ad.discoveredSubdomains))
	for sub := range ad.discoveredSubdomains {
		result = append(result, sub)
	}
	return result
}

// EnhancedDiscoveryResults contains all extra findings from enhanced discovery
type EnhancedDiscoveryResults struct {
	Secrets      map[string][]Secret `json:"secrets,omitempty"`
	S3Buckets    []string            `json:"s3_buckets,omitempty"`
	Subdomains   []string            `json:"subdomains,omitempty"`
	Technologies []string            `json:"technologies,omitempty"`
}

// GetEnhancedResults returns all enhanced discovery findings
func (ad *ActiveDiscoverer) GetEnhancedResults() EnhancedDiscoveryResults {
	return EnhancedDiscoveryResults{
		Secrets:      ad.GetDiscoveredSecrets(),
		S3Buckets:    ad.GetDiscoveredS3Buckets(),
		Subdomains:   ad.GetDiscoveredSubdomains(),
		Technologies: ad.GetDetectedTechnologies(),
	}
}

// GetDetectedTechnologies returns the detected technology stack
func (ad *ActiveDiscoverer) GetDetectedTechnologies() []string {
	return ad.detectedTechnologies
}
