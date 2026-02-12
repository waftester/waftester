// Package discovery - Active endpoint discovery through intelligent probing
// This doesn't rely on robots.txt or sitemaps - it actively finds endpoints
package discovery

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
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
	// Use shared pooled client with custom timeout if needed
	var client *http.Client
	if timeout != httpclient.TimeoutFuzzing {
		cfg := httpclient.WithTimeout(timeout)
		cfg.InsecureSkipVerify = skipVerify
		client = httpclient.New(cfg)
	} else {
		client = httpclient.Default()
	}

	return &ActiveDiscoverer{
		client:               client,
		target:               strings.TrimRight(target, "/"),
		userAgent:            defaults.UAChrome,
		results:              make([]Endpoint, 0),
		discoveredSecrets:    make(map[string][]Secret),
		discoveredS3Buckets:  make(map[string]bool),
		discoveredSubdomains: make(map[string]bool),
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
		concurrency = defaults.ConcurrencyHigh
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
