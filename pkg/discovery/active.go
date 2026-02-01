// Package discovery - Active endpoint discovery through intelligent probing
// This doesn't rely on robots.txt or sitemaps - it actively finds endpoints
package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

// ActiveDiscoverer performs aggressive endpoint discovery
type ActiveDiscoverer struct {
	client    *http.Client
	target    string
	userAgent string
	found     sync.Map
	mu        sync.Mutex
	results   []Endpoint

	// Enhanced discovery results
	discoveredSecrets    map[string][]Secret // path -> secrets found
	discoveredS3Buckets  map[string]bool     // unique S3 buckets
	discoveredSubdomains map[string]bool     // unique subdomains
	detectedTechnologies []string            // detected tech stack

	// Wildcard/404 detection
	wildcardDetector *WildcardDetector
}

// NewActiveDiscoverer creates an active discovery engine
func NewActiveDiscoverer(target string, timeout time.Duration, skipVerify bool) *ActiveDiscoverer {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipVerify,
		},
	}

	return &ActiveDiscoverer{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		target:    strings.TrimRight(target, "/"),
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		results:   make([]Endpoint, 0),
	}
}

// ==================== COMMON PATHS WORDLIST ====================
// Curated from SecLists, Dirsearch, and real-world pentests

var commonPaths = []string{
	// Authentication & Admin
	"/admin", "/administrator", "/admin.php", "/admin.html",
	"/login", "/signin", "/sign-in", "/auth", "/authenticate",
	"/logout", "/signout", "/sign-out",
	"/register", "/signup", "/sign-up", "/join",
	"/forgot-password", "/reset-password", "/password-reset",
	"/account", "/profile", "/user", "/users", "/me",
	"/dashboard", "/panel", "/console", "/portal",
	"/manage", "/manager", "/management",
	"/settings", "/preferences", "/config", "/configuration",

	// API Endpoints
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/rest", "/graphql", "/graphiql",
	"/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
	"/openapi", "/openapi.json", "/openapi.yaml",
	"/api-docs", "/apidocs", "/docs", "/documentation",
	"/health", "/healthz", "/healthcheck", "/health-check",
	"/status", "/ping", "/version", "/info",
	"/metrics", "/prometheus", "/actuator", "/actuator/health",

	// Common Web Frameworks
	// WordPress
	"/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
	"/wp-json", "/wp-json/wp/v2", "/xmlrpc.php",
	// Drupal
	"/node", "/admin/content", "/user/login", "/core",
	// Joomla
	"/administrator", "/components", "/modules", "/plugins",
	// Laravel
	"/telescope", "/horizon", "/nova", "/_debugbar",
	// Django
	"/admin", "/static", "/media", "/__debug__",
	// Spring Boot
	"/actuator", "/actuator/env", "/actuator/mappings", "/actuator/beans",
	"/actuator/configprops", "/actuator/heapdump",
	// Express/Node
	"/socket.io", "/webpack", "/__webpack_hmr",

	// Development & Debug
	"/debug", "/test", "/testing", "/dev", "/development",
	"/staging", "/stage", "/demo", "/sandbox",
	"/.git", "/.git/config", "/.git/HEAD",
	"/.env", "/.env.local", "/.env.production",
	"/.htaccess", "/.htpasswd",
	"/phpinfo.php", "/info.php", "/test.php",
	"/server-status", "/server-info",
	"/trace", "/trace.axd", "/elmah.axd",
	"/error", "/errors", "/error_log", "/debug.log",
	"/console", "/shell", "/cmd", "/command",

	// Files & Backups
	"/backup", "/backups", "/bak", "/old", "/archive",
	"/upload", "/uploads", "/files", "/documents", "/docs",
	"/download", "/downloads", "/assets", "/static",
	"/images", "/img", "/css", "/js", "/scripts",
	"/media", "/resources", "/public", "/private",
	"/temp", "/tmp", "/cache", "/logs", "/log",
	"/data", "/db", "/database", "/sql",
	"/backup.sql", "/backup.zip", "/backup.tar.gz",
	"/dump.sql", "/database.sql", "/db.sql",

	// E-commerce
	"/cart", "/checkout", "/order", "/orders",
	"/product", "/products", "/shop", "/store",
	"/payment", "/pay", "/invoice", "/invoices",

	// OAuth & SSO
	"/oauth", "/oauth2", "/oauth/authorize", "/oauth/token",
	"/sso", "/saml", "/saml2", "/cas", "/oidc",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",

	// Specific Services (authentik, n8n, immich)
	// Authentik
	"/if/flow", "/api/v3", "/outpost", "/-/health/ready",
	"/application/o", "/if/admin",
	// n8n
	"/rest/workflows", "/webhook", "/webhooks",
	"/rest/credentials", "/rest/executions",
	// Immich
	"/api/server-info", "/api/auth", "/api/asset",
	"/api/album", "/api/user", "/api/search",

	// Mobile API
	"/mobile", "/app", "/ios", "/android",
	"/api/mobile", "/v1/mobile", "/m",

	// WebSocket
	"/ws", "/wss", "/websocket", "/socket", "/realtime",

	// Misc
	"/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
	"/favicon.ico", "/crossdomain.xml", "/clientaccesspolicy.xml",
	"/security.txt", "/.well-known/security.txt",
	"/humans.txt", "/ads.txt",
}

// Technology-specific paths based on detected stack
var techPaths = map[string][]string{
	"php": {
		"/index.php", "/admin.php", "/login.php", "/config.php",
		"/wp-admin", "/wp-login.php", "/phpmyadmin", "/pma",
	},
	"aspnet": {
		"/web.config", "/default.aspx", "/login.aspx", "/admin.aspx",
		"/elmah.axd", "/trace.axd", "/ScriptResource.axd",
	},
	"java": {
		"/manager/html", "/manager/status", "/jmx-console",
		"/invoker/JMXInvokerServlet", "/admin-console",
		"/actuator", "/jolokia", "/console",
	},
	"python": {
		"/admin", "/api", "/static", "/media",
		"/__debug__", "/graphql", "/docs",
	},
	"node": {
		"/package.json", "/node_modules", "/.npmrc",
		"/graphql", "/socket.io", "/api",
	},
	"ruby": {
		"/rails/info", "/rails/mailers", "/sidekiq",
		"/admin", "/api", "/assets",
	},
}

// ==================== ACTIVE DISCOVERY METHODS ====================

// PhaseProgress reports progress for a specific discovery phase
type PhaseProgress struct {
	Phase     int    // Current phase number (1-6)
	PhaseName string // Human-readable phase name
	Done      int    // Items completed in this phase
	Total     int    // Total items in this phase
}

// DiscoverAll runs all active discovery techniques
func (ad *ActiveDiscoverer) DiscoverAll(ctx context.Context, concurrency int) []Endpoint {
	return ad.DiscoverAllWithProgress(ctx, concurrency, nil)
}

// DiscoverAllWithProgress runs all 6 discovery phases with detailed progress
// Phase 1: Technology fingerprinting
// Phase 2: Path brute-force (wordlist)
// Phase 3: Link extraction from responses
// Phase 4: Parameter discovery (high-value endpoints only)
// Phase 5: HTTP method enumeration (high-value endpoints only)
// Phase 6: Final deduplication
func (ad *ActiveDiscoverer) DiscoverAllWithProgress(ctx context.Context, concurrency int, progress func(done, total int)) []Endpoint {
	return ad.DiscoverAllWithPhaseProgress(ctx, concurrency, func(p PhaseProgress) {
		if progress != nil {
			progress(p.Done, p.Total)
		}
	})
}

// DiscoverAllWithPhaseProgress runs all phases with per-phase progress reporting
func (ad *ActiveDiscoverer) DiscoverAllWithPhaseProgress(ctx context.Context, concurrency int, progress func(PhaseProgress)) []Endpoint {
	if concurrency <= 0 {
		concurrency = 20
	}

	report := func(phase int, name string, done, total int) {
		if progress != nil {
			progress(PhaseProgress{Phase: phase, PhaseName: name, Done: done, Total: total})
		}
	}

	// ===== PHASE 1: Technology Fingerprinting =====
	select {
	case <-ctx.Done():
		return ad.results
	default:
	}
	report(1, "fingerprint", 0, 1)
	tech := ad.fingerprintTechnology(ctx)
	ad.detectedTechnologies = tech // Store for later retrieval
	report(1, "fingerprint", 1, 1)

	// ===== PHASE 2: Path Brute-Force =====
	select {
	case <-ctx.Done():
		return ad.results
	default:
	}
	paths := ad.buildWordlist(tech)
	ad.probePathsWithPhaseProgress(ctx, paths, concurrency, func(done, total int) {
		report(2, "path-bruteforce", done, total)
	})

	// ===== PHASE 3: Link Extraction =====
	select {
	case <-ctx.Done():
		return ad.results
	default:
	}
	ad.extractFromResponsesWithProgress(ctx, concurrency, func(done, total int) {
		report(3, "link-extraction", done, total)
	})

	// ===== PHASE 4: Parameter Discovery (high-value only) =====
	select {
	case <-ctx.Done():
		return ad.results
	default:
	}
	ad.discoverParametersWithProgress(ctx, concurrency, func(done, total int) {
		report(4, "param-discovery", done, total)
	})

	// ===== PHASE 5: Method Enumeration (high-value only) =====
	select {
	case <-ctx.Done():
		return ad.results
	default:
	}
	ad.enumerateMethodsWithProgress(ctx, concurrency, func(done, total int) {
		report(5, "method-enum", done, total)
	})

	// ===== PHASE 6: Deduplication =====
	report(6, "dedupe", 0, 1)
	ad.deduplicateResults()
	report(6, "dedupe", 1, 1)

	return ad.results
}

// deduplicateResults removes duplicate path+method combinations and filters SPA route duplicates
func (ad *ActiveDiscoverer) deduplicateResults() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Phase 1: Remove exact duplicates
	seen := make(map[string]bool)
	unique := make([]Endpoint, 0, len(ad.results))
	for _, ep := range ad.results {
		key := ep.Method + ":" + ep.Path
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ep)
		}
	}

	// Phase 2: Filter SPA route duplicates
	// Group paths by their base (e.g., /admin, /admin.php, /admin.bak all have base "/admin")
	// If multiple paths with different extensions have same status, they're likely SPA routing
	spaFiltered := ad.filterSPADuplicates(unique)

	ad.results = spaFiltered
}

// filterSPADuplicates removes paths that are likely SPA routing artifacts or bruteforce noise
// e.g., if /admin, /admin.php, /admin.bak all return 200, keep only /admin or /admin/
// Also filters bruteforce artifact paths that get WAF-blocked (403) and don't have a clean version
func (ad *ActiveDiscoverer) filterSPADuplicates(endpoints []Endpoint) []Endpoint {
	// Common file extensions that indicate bruteforce artifacts
	bruteExtensions := []string{".php", ".asp", ".aspx", ".jsp", ".bak", ".old", ".txt", ".xml", ".json", ".htm", ".html", ".sql"}

	// First, identify which paths are bruteforce artifacts
	isBruteforceArtifact := func(path string) (bool, string) {
		lower := strings.ToLower(path)
		for _, ext := range bruteExtensions {
			if strings.HasSuffix(lower, ext) {
				base := path[:len(path)-len(ext)]
				if len(base) > 0 && base[len(base)-1] != '/' {
					return true, base
				}
			}
		}
		return false, ""
	}

	// Group endpoints by status code category
	realEndpoints := make([]Endpoint, 0)    // 200-299 responses
	blockedEndpoints := make([]Endpoint, 0) // 403 responses (potential WAF blocks)
	otherEndpoints := make([]Endpoint, 0)   // Other status codes

	for _, ep := range endpoints {
		switch {
		case ep.StatusCode >= 200 && ep.StatusCode < 300:
			realEndpoints = append(realEndpoints, ep)
		case ep.StatusCode == 403:
			blockedEndpoints = append(blockedEndpoints, ep)
		default:
			otherEndpoints = append(otherEndpoints, ep)
		}
	}

	// Build a set of known real paths (from 200 responses)
	realPaths := make(map[string]bool)
	for _, ep := range realEndpoints {
		realPaths[ep.Path] = true
	}

	// Filter real endpoints (200) - remove extension variants when clean path exists
	filteredReal := make([]Endpoint, 0)
	for _, ep := range realEndpoints {
		isArtifact, base := isBruteforceArtifact(ep.Path)
		if isArtifact {
			// Check if clean version exists
			if realPaths[base] || realPaths[base+"/"] {
				continue // Skip - clean version exists
			}
		}
		filteredReal = append(filteredReal, ep)
	}

	// Filter blocked endpoints (403) - only keep if likely real (not bruteforce artifact)
	filteredBlocked := make([]Endpoint, 0)
	for _, ep := range blockedEndpoints {
		isArtifact, _ := isBruteforceArtifact(ep.Path)
		if isArtifact {
			// This is a bruteforce artifact that got blocked - likely noise, skip it
			// Real endpoints don't have extensions like .php, .bak on modern apps
			continue
		}
		// Clean path that got blocked - might be real (e.g., /admin blocked by WAF)
		filteredBlocked = append(filteredBlocked, ep)
	}

	// Combine results
	result := make([]Endpoint, 0, len(filteredReal)+len(filteredBlocked)+len(otherEndpoints))
	seen := make(map[string]bool)

	// Add filtered real endpoints
	for _, ep := range filteredReal {
		key := ep.Method + ":" + ep.Path
		if !seen[key] {
			seen[key] = true
			result = append(result, ep)
		}
	}

	// Add filtered blocked endpoints
	for _, ep := range filteredBlocked {
		key := ep.Method + ":" + ep.Path
		if !seen[key] {
			seen[key] = true
			result = append(result, ep)
		}
	}

	// Add other endpoints (redirects, errors, etc.)
	for _, ep := range otherEndpoints {
		key := ep.Method + ":" + ep.Path
		if !seen[key] {
			seen[key] = true
			result = append(result, ep)
		}
	}

	return result
}

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
	defer resp.Body.Close()

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
			ad.wildcardDetector.AddBaseline(method, fp)
			break // One successful baseline per method is enough
		}
	}
}

// buildWordlist creates a comprehensive wordlist based on detected technology
func (ad *ActiveDiscoverer) buildWordlist(tech []string) []string {
	paths := make([]string, 0, len(commonPaths)+500)
	seen := make(map[string]bool)

	// Add common paths
	for _, p := range commonPaths {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	// Add technology-specific paths
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
	defer resp.Body.Close()

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
}

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
	defer resp.Body.Close()

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
	baseResp.Body.Close()
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
