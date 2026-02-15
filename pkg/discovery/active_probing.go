// Package discovery - Active path probing and method enumeration
package discovery

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/waftester/waftester/pkg/discovery/wordlists"
	"github.com/waftester/waftester/pkg/iohelper"
)

// fingerprintTechnology detects the technology stack and sets up wildcard detection
func (ad *ActiveDiscoverer) fingerprintTechnology(ctx context.Context) []string {
	var detected []string

	// Initialize wildcard detector
	ad.wildcardDetector = NewWildcardDetector()

	req, err := http.NewRequestWithContext(ctx, "GET", ad.target, nil)
	if err != nil {
		return detected
	}
	req.Header.Set("User-Agent", ad.userAgent)

	resp, err := ad.client.Do(req)
	if err != nil {
		return detected
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Check headers for technology hints
	headers := resp.Header

	// Server header
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "apache") || strings.Contains(server, "php") {
		detected = append(detected, "php")
	}
	if strings.Contains(server, "nginx") {
		detected = append(detected, "nginx")
	}
	if strings.Contains(server, "iis") || strings.Contains(server, "asp") {
		detected = append(detected, "aspnet")
	}

	// X-Powered-By
	powered := strings.ToLower(headers.Get("X-Powered-By"))
	if strings.Contains(powered, "php") {
		detected = append(detected, "php")
	}
	if strings.Contains(powered, "asp") || strings.Contains(powered, ".net") {
		detected = append(detected, "aspnet")
	}
	if strings.Contains(powered, "express") || strings.Contains(powered, "node") {
		detected = append(detected, "node")
	}

	// Check cookies
	cookies := headers.Values("Set-Cookie")
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)
		if strings.Contains(cookieLower, "phpsessid") {
			detected = append(detected, "php")
		}
		if strings.Contains(cookieLower, "asp.net") || strings.Contains(cookieLower, "aspxauth") {
			detected = append(detected, "aspnet")
		}
		if strings.Contains(cookieLower, "jsessionid") {
			detected = append(detected, "java")
		}
		if strings.Contains(cookieLower, "csrftoken") || strings.Contains(cookieLower, "django") {
			detected = append(detected, "python")
		}
		if strings.Contains(cookieLower, "_rails") || strings.Contains(cookieLower, "rack.session") {
			detected = append(detected, "ruby")
		}
	}

	// Check response body for hints
	body, _ := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)
	bodyStr := strings.ToLower(string(body))

	if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wordpress") {
		detected = append(detected, "php")
	}
	if strings.Contains(bodyStr, "next.js") || strings.Contains(bodyStr, "__next") {
		detected = append(detected, "node")
	}
	if strings.Contains(bodyStr, "react") || strings.Contains(bodyStr, "reactdom") {
		detected = append(detected, "node")
	}
	if strings.Contains(bodyStr, "angular") || strings.Contains(bodyStr, "ng-") {
		detected = append(detected, "node")
	}

	// Detect wildcard/404 baseline by requesting random non-existent paths
	ad.detectWildcardBaseline(ctx)

	return dedupe(detected)
}

// detectWildcardBaseline probes random paths to establish 404/wildcard baseline
func (ad *ActiveDiscoverer) detectWildcardBaseline(ctx context.Context) {
	randomPaths := []string{
		"/asd8f7asdf8a7sdf8a7sdf", // random gibberish
		"/nonexistent-path-12345",
		"/this-page-does-not-exist-xyz",
	}

	for _, method := range []string{"GET", "POST"} {
		for _, path := range randomPaths {
			req, err := http.NewRequestWithContext(ctx, method, ad.target+path, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", ad.userAgent)

			resp, err := ad.client.Do(req)
			if err != nil {
				continue
			}

			body, _ := iohelper.ReadBody(resp.Body, 50*1024)
			iohelper.DrainAndClose(resp.Body)

			fp := CalculateFingerprint(resp.StatusCode, body, resp.Header.Get("Content-Type"))
			if ad.wildcardDetector != nil {
				ad.wildcardDetector.AddBaseline(method, fp)
			}
			break // One successful baseline per method is enough
		}
	}
}

// buildWordlist creates a comprehensive wordlist based on detected technology
func (ad *ActiveDiscoverer) buildWordlist(tech []string) []string {
	seen := make(map[string]bool)
	var paths []string

	// Load framework-specific wordlists based on detected technologies
	frameworks := wordlists.DetectFrameworks(tech)
	fwRoutes, err := wordlists.LoadMultiple(frameworks)
	if err != nil {
		// DetectFrameworks only returns known names, so this should never happen.
		// Fall through to common paths below.
		fwRoutes = nil
	}
	for _, p := range fwRoutes {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	// Add legacy common paths (for routes not in framework wordlists)
	for _, p := range commonPaths {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	// Add technology-specific paths from inline map
	for _, t := range tech {
		if techSpecific, ok := techPaths[t]; ok {
			for _, p := range techSpecific {
				if !seen[p] {
					seen[p] = true
					paths = append(paths, p)
				}
			}
		}
	}

	// Add permutations
	permutations := ad.generatePermutations(paths)
	for _, p := range permutations {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	return paths
}

// generatePermutations creates variations of paths
func (ad *ActiveDiscoverer) generatePermutations(paths []string) []string {
	var perms []string

	// Extensions to try
	extensions := []string{".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".html", ".htm", ".txt", ".bak", ".old"}

	// Only add extensions to paths without them
	for _, p := range paths {
		if !hasExtension(p) && !strings.HasSuffix(p, "/") {
			for _, ext := range extensions {
				perms = append(perms, p+ext)
			}
			// Also try with trailing slash (directory listing)
			perms = append(perms, p+"/")
		}
	}

	return perms
}

// probePaths checks paths in parallel with proper context cancellation
// Uses a worker pool pattern to avoid spawning too many goroutines
func (ad *ActiveDiscoverer) probePaths(ctx context.Context, paths []string, concurrency int) {
	ad.probePathsWithPhaseProgress(ctx, paths, concurrency, nil)
}

// probePathsWithPhaseProgress checks paths with worker pool and progress
func (ad *ActiveDiscoverer) probePathsWithPhaseProgress(ctx context.Context, paths []string, concurrency int, progress func(done, total int)) {
	if len(paths) == 0 {
		return
	}

	total := len(paths)
	var done int64

	// Create a channel to send work to workers
	work := make(chan string, concurrency)
	var wg sync.WaitGroup

	// Start fixed number of workers
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
						return // channel closed
					}
					ad.probeSinglePath(ctx, path)

					// Report progress
					if progress != nil {
						current := atomic.AddInt64(&done, 1)
						progress(int(current), total)
					}
				}
			}
		}()
	}

	// Send work to workers
pathLoop:
	for _, path := range paths {
		select {
		case <-ctx.Done():
			break pathLoop
		case work <- path:
			// sent
		}
	}

	// Close work channel to signal workers to exit
	close(work)

	// Wait for all workers to finish
	wg.Wait()
}

// probeSinglePath probes a single path and records if found
func (ad *ActiveDiscoverer) probeSinglePath(ctx context.Context, path string) {
	// Skip if already found
	if _, exists := ad.found.Load(path); exists {
		return
	}

	fullURL := ad.target + path
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", ad.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := ad.client.Do(req)
	if err != nil {
		return
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Read body for analysis
	body, _ := iohelper.ReadBody(resp.Body, 50*1024)
	contentType := resp.Header.Get("Content-Type")

	// Check if this is a wildcard/soft-404 response using fingerprinting
	if ad.wildcardDetector != nil {
		fp := CalculateFingerprint(resp.StatusCode, body, contentType)
		if ad.wildcardDetector.IsWildcard("GET", fp) {
			// This is a wildcard response (soft-404), skip it
			return
		}
	}

	// Consider interesting: 200, 201, 204, 301, 302, 307, 308, 401, 403, 405
	// Skip: 404 (not found), 500+ (server errors)
	interesting := isInterestingStatus(resp.StatusCode)

	if interesting {
		ad.found.Store(path, true)

		ep := Endpoint{
			Path:        path,
			Method:      "GET",
			StatusCode:  resp.StatusCode,
			ContentType: contentType,
			Category:    categorizeByStatus(path, resp.StatusCode),
		}

		// Extract parameters from response
		ep.Parameters = extractParamsFromResponse(string(body), path)

		ad.mu.Lock()
		ad.results = append(ad.results, ep)
		ad.mu.Unlock()
	}

	// Content-type probing: many API endpoints return 404 for GET but accept POST with JSON/form/XML.
	// Try alternate methods+content-types before giving up on this path.
	if resp.StatusCode == 404 || resp.StatusCode == 405 {
		ad.probeContentTypes(ctx, path)
		ad.probeOptions(ctx, path)
	}
}

// contentTypeProbe defines a POST probe with a specific content type.
type contentTypeProbe struct {
	contentType string
	body        string
}

// defaultContentTypeProbes returns the standard content-type probes for API discovery.
func defaultContentTypeProbes() []contentTypeProbe {
	return []contentTypeProbe{
		{"application/json", "{}"},
		{"application/x-www-form-urlencoded", "test=1"},
		{"application/xml", "<root/>"},
	}
}

// probeContentTypes tries POST with common content types on paths that returned 404/405 for GET.
// Many API endpoints only accept specific methods/content types.
func (ad *ActiveDiscoverer) probeContentTypes(ctx context.Context, path string) {
	fullURL := ad.target + path

	for _, probe := range defaultContentTypeProbes() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "POST", fullURL, strings.NewReader(probe.body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", probe.contentType)
		req.Header.Set("User-Agent", ad.userAgent)

		resp, err := ad.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		// Non-404/405 means this endpoint exists for POST with this content type
		if resp.StatusCode != 404 && resp.StatusCode != 405 {
			ad.found.Store(path, true)
			ep := Endpoint{
				Path:        path,
				Method:      "POST",
				StatusCode:  resp.StatusCode,
				ContentType: probe.contentType,
				Category:    categorizeByStatus(path, resp.StatusCode),
			}
			ad.mu.Lock()
			ad.results = append(ad.results, ep)
			ad.mu.Unlock()
			return // Found a working content type, stop probing
		}
	}
}

// probeOptions sends an OPTIONS request to discover allowed methods via the Allow header.
func (ad *ActiveDiscoverer) probeOptions(ctx context.Context, path string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	fullURL := ad.target + path
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", fullURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", ad.userAgent)

	resp, err := ad.client.Do(req)
	if err != nil {
		return
	}
	iohelper.DrainAndClose(resp.Body)

	allow := resp.Header.Get("Allow")
	if allow == "" {
		return
	}

	for _, method := range strings.Split(allow, ",") {
		method = strings.TrimSpace(method)
		if method == "" || method == "GET" || method == "OPTIONS" || method == "HEAD" {
			continue
		}
		ad.found.Store(path, true)
		ep := Endpoint{
			Path:       path,
			Method:     method,
			StatusCode: resp.StatusCode,
			Category:   categorizeByStatus(path, resp.StatusCode),
		}
		ad.mu.Lock()
		ad.results = append(ad.results, ep)
		ad.mu.Unlock()
	}
}

// enumerateMethods tests HTTP methods on endpoints (legacy wrapper)
func (ad *ActiveDiscoverer) enumerateMethods(ctx context.Context) {
	ad.enumerateMethodsWithProgress(ctx, 10, nil)
}

// enumerateMethodsWithProgress tests HTTP methods on high-value endpoints using worker pool
func (ad *ActiveDiscoverer) enumerateMethodsWithProgress(ctx context.Context, concurrency int, progress func(done, total int)) {
	methods := []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"}

	// Get high-value endpoints only
	ad.mu.Lock()
	var highValue []Endpoint
	for _, ep := range ad.results {
		if isHighValueEndpoint(ep) && ep.Method == "GET" {
			highValue = append(highValue, ep)
		}
	}
	ad.mu.Unlock()

	// Limit to 40 endpoints max
	if len(highValue) > 40 {
		highValue = highValue[:40]
	}

	if len(highValue) == 0 {
		if progress != nil {
			progress(1, 1)
		}
		return
	}

	// Total work items = endpoints * methods
	total := len(highValue) * len(methods)
	var done int64

	type methodWork struct {
		ep     Endpoint
		method string
	}

	work := make(chan methodWork, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case mw, ok := <-work:
					if !ok {
						return
					}
					ad.probeMethod(ctx, mw.ep, mw.method)
					if progress != nil {
						current := atomic.AddInt64(&done, 1)
						progress(int(current), total)
					}
				}
			}
		}()
	}

methodLoop:
	for _, ep := range highValue {
		for _, method := range methods {
			select {
			case <-ctx.Done():
				break methodLoop
			case work <- methodWork{ep: ep, method: method}:
			}
		}
	}
	close(work)
	wg.Wait()
}

// probeMethod tests a single HTTP method on an endpoint
func (ad *ActiveDiscoverer) probeMethod(ctx context.Context, ep Endpoint, method string) {
	fullURL := ad.target + ep.Path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", ad.userAgent)

	resp, err := ad.client.Do(req)
	if err != nil {
		return
	}
	iohelper.DrainAndClose(resp.Body)

	// Method is supported if not 405 Method Not Allowed
	if resp.StatusCode != 405 && resp.StatusCode != 501 {
		newEp := Endpoint{
			Path:        ep.Path,
			Method:      method,
			StatusCode:  resp.StatusCode,
			ContentType: ep.ContentType,
			Category:    ep.Category,
		}
		ad.mu.Lock()
		ad.results = append(ad.results, newEp)
		ad.mu.Unlock()
	}
}
