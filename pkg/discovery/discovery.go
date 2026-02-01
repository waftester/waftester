// Package discovery implements target application learning and endpoint enumeration
package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/regexcache"
)

// Endpoint represents a discovered API endpoint
type Endpoint struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	ContentType string            `json:"content_type,omitempty"`
	Parameters  []Parameter       `json:"parameters,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	StatusCode  int               `json:"status_code"`
	Service     string            `json:"service,omitempty"`
	Category    string            `json:"category,omitempty"` // auth, api, static, health, etc.
	RiskFactors []string          `json:"risk_factors,omitempty"`
}

// Parameter represents a discovered parameter
type Parameter struct {
	Name     string `json:"name"`
	Location string `json:"location"` // query, body, path, header
	Type     string `json:"type"`     // string, number, boolean, array, object
	Example  string `json:"example,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// DiscoveryResult contains all discovered information about the target
type DiscoveryResult struct {
	Target         string              `json:"target"`
	Service        string              `json:"service,omitempty"`
	DiscoveredAt   time.Time           `json:"discovered_at"`
	Duration       time.Duration       `json:"duration"`
	Endpoints      []Endpoint          `json:"endpoints"`
	Technologies   []string            `json:"technologies,omitempty"`
	WAFDetected    bool                `json:"waf_detected"`
	WAFFingerprint string              `json:"waf_fingerprint,omitempty"`
	AttackSurface  AttackSurface       `json:"attack_surface"`
	Statistics     DiscoveryStatistics `json:"statistics"`
	// Enhanced discovery findings
	Secrets    map[string][]Secret `json:"secrets,omitempty"`    // path -> secrets found
	S3Buckets  []string            `json:"s3_buckets,omitempty"` // S3 bucket names discovered
	Subdomains []string            `json:"subdomains,omitempty"` // Subdomains discovered
}

// AttackSurface summarizes what attack categories are relevant
type AttackSurface struct {
	HasAuthEndpoints   bool     `json:"has_auth_endpoints"`
	HasAPIEndpoints    bool     `json:"has_api_endpoints"`
	HasFileUpload      bool     `json:"has_file_upload"`
	HasOAuth           bool     `json:"has_oauth"`
	HasSAML            bool     `json:"has_saml"`
	HasGraphQL         bool     `json:"has_graphql"`
	HasWebSockets      bool     `json:"has_websockets"`
	AcceptsJSON        bool     `json:"accepts_json"`
	AcceptsXML         bool     `json:"accepts_xml"`
	AcceptsFormData    bool     `json:"accepts_form_data"`
	RelevantCategories []string `json:"relevant_categories"`
}

// DiscoveryStatistics tracks discovery progress
type DiscoveryStatistics struct {
	TotalEndpoints  int            `json:"total_endpoints"`
	ByMethod        map[string]int `json:"by_method"`
	ByCategory      map[string]int `json:"by_category"`
	TotalParameters int            `json:"total_parameters"`
	CrawlDepth      int            `json:"crawl_depth"`
	RequestsMade    int            `json:"requests_made"`
}

// DiscoveryConfig holds discovery settings
type DiscoveryConfig struct {
	Target        string
	Timeout       time.Duration
	MaxDepth      int
	Concurrency   int
	SkipVerify    bool
	UserAgent     string
	Service       string // Optional: authentik, n8n, immich, agreementpulse
	IncludePaths  []string
	ExcludePaths  []string
	DisableActive bool         // Skip active path brute-forcing (useful for testing)
	Verbose       bool         // Enable verbose logging
	HTTPClient    *http.Client // Optional custom HTTP client (e.g., JA3-aware)
}

// Discoverer crawls and learns about the target application
type Discoverer struct {
	config     DiscoveryConfig
	httpClient *http.Client
	visited    sync.Map
	endpoints  []Endpoint
	mu         sync.Mutex
}

// NewDiscoverer creates a new discovery instance
func NewDiscoverer(cfg DiscoveryConfig) *Discoverer {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 3
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 10
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "WAF-Tester-Discovery/1.0"
	}

	// Use provided HTTPClient (e.g., JA3-aware) or create default
	var client *http.Client
	if cfg.HTTPClient != nil {
		client = cfg.HTTPClient
	} else {
		transport := &http.Transport{
			MaxIdleConns:        cfg.Concurrency * 2,
			MaxIdleConnsPerHost: cfg.Concurrency,
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipVerify,
			},
		}

		client = &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		}
	}

	return &Discoverer{
		config:     cfg,
		httpClient: client,
		endpoints:  make([]Endpoint, 0),
	}
}

// Discover runs the discovery process
func (d *Discoverer) Discover(ctx context.Context) (*DiscoveryResult, error) {
	start := time.Now()
	result := &DiscoveryResult{
		Target:       d.config.Target,
		Service:      d.config.Service,
		DiscoveredAt: start,
		Endpoints:    make([]Endpoint, 0),
		Statistics: DiscoveryStatistics{
			ByMethod:   make(map[string]int),
			ByCategory: make(map[string]int),
		},
	}

	// Helper for animated phase execution
	spinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	runPhaseWithSpinner := func(phaseNum int, phaseName string, work func()) int {
		beforeCount := len(d.endpoints)
		done := make(chan struct{})

		go func() {
			frame := 0
			for {
				select {
				case <-done:
					return
				default:
					fmt.Printf("\r  [%d/9] %s %s ", phaseNum, spinnerFrames[frame%len(spinnerFrames)], phaseName)
					frame++
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()

		work()
		close(done)

		added := len(d.endpoints) - beforeCount
		fmt.Printf("\r  [%d/9] ✅ %s +%d\033[K\n", phaseNum, phaseName, added)
		return added
	}

	// Phase 1: Detect WAF
	fmt.Print("  [1/9] ⠋ Detecting WAF... ")
	d.detectWAF(ctx, result)
	if result.WAFDetected {
		fmt.Printf("\r  [1/9] ✅ WAF detected: %s\033[K\n", result.WAFFingerprint)
	} else {
		fmt.Print("\r  [1/9] ✅ No WAF detected\033[K\n")
	}

	// Phase 2: ACTIVE DISCOVERY - Comprehensive path brute-forcing with tech fingerprinting
	// This is the primary discovery method - doesn't rely on robots.txt/sitemap
	// Skip if DisableActive is set (useful for testing)
	if !d.config.DisableActive {
		fmt.Print("  [2/9] ⠋ Active discovery (path brute-force)... ")
		d.discoverActiveEndpoints(ctx, result)
		fmt.Printf("\r  [2/9] ✅ Active discovery: %d endpoints\033[K\n", len(d.endpoints))
	}

	// Phase 3: External Sources
	runPhaseWithSpinner(3, "External sources", func() {
		d.discoverFromExternalSources(ctx, result)
	})

	// Phase 4: Service-specific endpoint probing
	runPhaseWithSpinner(4, "Service-specific probing", func() {
		d.probeKnownEndpoints(ctx, result)
	})

	// Phase 5: JavaScript link extraction
	runPhaseWithSpinner(5, "JavaScript analysis", func() {
		d.discoverFromJavaScript(ctx, result)
	})

	// Phase 6: API Spec Parsing (OpenAPI/Swagger/GraphQL introspection)
	runPhaseWithSpinner(6, "API spec parsing", func() {
		d.parseAPISpecs(ctx, result)
	})

	// Phase 7: Form extraction
	runPhaseWithSpinner(7, "Form extraction", func() {
		d.discoverForms(ctx, result)
	})

	// Phase 8: Crawl discovered endpoints (recursive link following)
	runPhaseWithSpinner(8, "Crawling links", func() {
		d.crawlEndpoints(ctx, result)
	})

	// Phase 9: Analyze and categorize
	fmt.Print("  [9/9] ⠋ Analyzing attack surface... ")
	d.analyzeAttackSurface(result)
	fmt.Print("\r  [9/9] ✅ Attack surface analyzed\033[K\n")

	result.Duration = time.Since(start)
	result.Endpoints = d.endpoints
	result.Statistics.TotalEndpoints = len(d.endpoints)

	return result, nil
}

// discoverActiveEndpoints performs comprehensive 6-phase path brute-forcing
func (d *Discoverer) discoverActiveEndpoints(ctx context.Context, result *DiscoveryResult) {
	active := NewActiveDiscoverer(d.config.Target, d.config.Timeout, d.config.SkipVerify)

	// Phase-aware progress callback with mutex for thread-safe access
	var progressMu sync.Mutex
	currentPhase := ""
	progress := func(p PhaseProgress) {
		phaseName := p.PhaseName
		percent := 0
		if p.Total > 0 {
			percent = (p.Done * 100) / p.Total
		}

		// Only update display when phase changes or on significant progress
		progressMu.Lock()
		phaseChanged := phaseName != currentPhase
		if phaseChanged {
			currentPhase = phaseName
		}
		progressMu.Unlock()

		if phaseChanged || percent%10 == 0 || p.Done == p.Total {
			switch phaseName {
			case "fingerprint":
				fmt.Printf("\r  [2/9] Active discovery: fingerprinting... ")
			case "path-bruteforce":
				fmt.Printf("\r  [2/9] Active discovery: path brute-force %d%%   ", percent)
			case "link-extraction":
				fmt.Printf("\r  [2/9] Active discovery: extracting links %d%%   ", percent)
			case "param-discovery":
				fmt.Printf("\r  [2/9] Active discovery: finding params %d%%    ", percent)
			case "method-enum":
				fmt.Printf("\r  [2/9] Active discovery: testing methods %d%%   ", percent)
			case "dedupe":
				// silent
			}
		}
	}

	endpoints := active.DiscoverAllWithPhaseProgress(ctx, d.config.Concurrency, progress)

	// Merge into main results
	d.mu.Lock()
	for _, ep := range endpoints {
		d.endpoints = append(d.endpoints, ep)
		result.Statistics.ByMethod[ep.Method]++
		result.Statistics.ByCategory[ep.Category]++
	}
	d.mu.Unlock()

	// Merge enhanced discovery findings (secrets, S3 buckets, subdomains, technologies)
	enhanced := active.GetEnhancedResults()
	if len(enhanced.Secrets) > 0 {
		result.Secrets = enhanced.Secrets
	}
	if len(enhanced.S3Buckets) > 0 {
		result.S3Buckets = enhanced.S3Buckets
	}
	if len(enhanced.Subdomains) > 0 {
		result.Subdomains = enhanced.Subdomains
	}
	if len(enhanced.Technologies) > 0 {
		result.Technologies = enhanced.Technologies
	}

	result.Statistics.RequestsMade += len(endpoints) * 2 // Estimate
}

// discoverFromExternalSources fetches endpoints from robots.txt, sitemap.xml, and Wayback Machine
func (d *Discoverer) discoverFromExternalSources(ctx context.Context, result *DiscoveryResult) {
	sources := NewExternalSources(d.config.Timeout, d.config.UserAgent)

	// Parse target URL to get domain
	parsed, err := url.Parse(d.config.Target)
	if err != nil {
		return
	}

	// Gather from all sources
	allSources := sources.GatherAllSources(ctx, d.config.Target, parsed.Host)

	// Probe robots.txt paths
	for _, path := range allSources.RobotsPaths {
		d.probeEndpoint(ctx, path, result)
	}

	// Probe sitemap URLs
	for _, path := range allSources.SitemapURLs {
		d.probeEndpoint(ctx, path, result)
	}

	// Probe Wayback URLs (limit to avoid overwhelming)
	maxWayback := 100
	for i, path := range allSources.WaybackURLs {
		if i >= maxWayback {
			break
		}
		d.probeEndpoint(ctx, path, result)
	}

	// Probe CommonCrawl URLs (limit)
	maxCC := 50
	for i, path := range allSources.CommonCrawl {
		if i >= maxCC {
			break
		}
		d.probeEndpoint(ctx, path, result)
	}

	// Probe OTX URLs (limit)
	maxOTX := 50
	for i, path := range allSources.OTXURLs {
		if i >= maxOTX {
			break
		}
		d.probeEndpoint(ctx, path, result)
	}

	// Probe VirusTotal URLs if available (limit)
	maxVT := 25
	for i, path := range allSources.VirusTotalURLs {
		if i >= maxVT {
			break
		}
		d.probeEndpoint(ctx, path, result)
	}

	// Merge S3 buckets from external sources into result
	if len(allSources.S3Buckets) > 0 {
		if result.S3Buckets == nil {
			result.S3Buckets = allSources.S3Buckets
		} else {
			seen := make(map[string]bool)
			for _, b := range result.S3Buckets {
				seen[b] = true
			}
			for _, b := range allSources.S3Buckets {
				if !seen[b] {
					result.S3Buckets = append(result.S3Buckets, b)
				}
			}
		}
	}

	// Merge subdomains from external sources into result
	if len(allSources.Subdomains) > 0 {
		if result.Subdomains == nil {
			result.Subdomains = allSources.Subdomains
		} else {
			seen := make(map[string]bool)
			for _, s := range result.Subdomains {
				seen[s] = true
			}
			for _, s := range allSources.Subdomains {
				if !seen[s] {
					result.Subdomains = append(result.Subdomains, s)
				}
			}
		}
	}

	// Merge secrets from external sources into result
	if len(allSources.Secrets) > 0 {
		if result.Secrets == nil {
			result.Secrets = make(map[string][]Secret)
		}
		for _, secret := range allSources.Secrets {
			result.Secrets["external"] = append(result.Secrets["external"], secret)
		}
	}

	// Probe JS-extracted links (limit to avoid overwhelming)
	// Note: JSLinks and Forms from allSources are not populated by GatherAllSources
	// These are handled by discoverFromJavaScript and discoverForms phases instead

	// Log source counts for debugging/observability
	if len(allSources.SourceCounts) > 0 && d.config.Verbose {
		fmt.Printf("  External sources: robots=%d sitemap=%d wayback=%d commoncrawl=%d otx=%d virustotal=%d (total unique: %d)\n",
			allSources.SourceCounts["robots.txt"],
			allSources.SourceCounts["sitemap.xml"],
			allSources.SourceCounts["wayback"],
			allSources.SourceCounts["commoncrawl"],
			allSources.SourceCounts["otx"],
			allSources.SourceCounts["virustotal"],
			allSources.TotalUnique)
	}
}

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
	resp.Body.Close()

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

// discoverForms extracts and analyzes HTML forms
func (d *Discoverer) discoverForms(ctx context.Context, result *DiscoveryResult) {
	// Analyze HTML responses for forms
	for _, ep := range d.endpoints {
		if !strings.Contains(ep.ContentType, "html") {
			continue
		}

		fullURL := d.config.Target + ep.Path
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
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

		body, _ := iohelper.ReadBody(resp.Body, iohelper.DefaultMaxBodySize) // 1MB limit
		iohelper.DrainAndClose(resp.Body)

		forms := ExtractForms(string(body), d.config.Target)
		for _, form := range forms {
			// Add form action as an endpoint
			if form.Action != "" {
				formPath := extractPath(form.Action)
				if formPath != "" && !d.isExcluded(formPath) {
					// Create endpoint for form target
					formEndpoint := Endpoint{
						Path:       formPath,
						Method:     form.Method,
						StatusCode: 0, // Unknown until probed
						Service:    d.config.Service,
						Category:   "form",
					}

					// Add form fields as parameters
					for _, field := range form.Fields {
						formEndpoint.Parameters = append(formEndpoint.Parameters, Parameter{
							Name:     field.Name,
							Location: "body",
							Type:     field.Type,
							Required: field.Required,
						})
					}

					// Add risk factors
					if form.HasFile {
						formEndpoint.RiskFactors = append(formEndpoint.RiskFactors, "file_upload")
						result.AttackSurface.HasFileUpload = true
					}
					if form.IsLogin {
						formEndpoint.RiskFactors = append(formEndpoint.RiskFactors, "authentication")
						result.AttackSurface.HasAuthEndpoints = true
					}

					d.mu.Lock()
					d.endpoints = append(d.endpoints, formEndpoint)
					result.Statistics.ByCategory["form"]++
					d.mu.Unlock()
				}
			}
		}
	}
}

// detectWAF checks if a WAF is present
func (d *Discoverer) detectWAF(ctx context.Context, result *DiscoveryResult) {
	// Send a simple SQL injection to detect WAF
	testPayloads := []string{
		"?id=1' OR '1'='1",
		"?q=<script>alert(1)</script>",
		"?file=../../../etc/passwd",
	}

	for _, payload := range testPayloads {
		req, err := http.NewRequestWithContext(ctx, "GET", d.config.Target+payload, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.config.UserAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for WAF signatures
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 418 {
			result.WAFDetected = true

			// Try to fingerprint
			server := resp.Header.Get("Server")
			if strings.Contains(strings.ToLower(server), "modsecurity") {
				result.WAFFingerprint = "ModSecurity"
			} else if strings.Contains(strings.ToLower(server), "coraza") {
				result.WAFFingerprint = "Coraza"
			} else if resp.Header.Get("X-CDN") != "" {
				result.WAFFingerprint = "CDN WAF (Cloudflare/AWS WAF)"
			}
			break
		}
	}
}

// probeKnownEndpoints tests service-specific endpoints
func (d *Discoverer) probeKnownEndpoints(ctx context.Context, result *DiscoveryResult) {
	var endpoints []string

	// Common endpoints for all services
	common := []string{
		"/",
		"/health",
		"/healthz",
		"/api/health",
		"/.well-known/security.txt",
		"/robots.txt",
		"/favicon.ico",
	}
	endpoints = append(endpoints, common...)

	// Service-specific endpoints
	switch strings.ToLower(d.config.Service) {
	case "authentik":
		endpoints = append(endpoints, getAuthentikEndpoints()...)
		result.AttackSurface.HasAuthEndpoints = true
		result.AttackSurface.HasOAuth = true
		result.AttackSurface.HasSAML = true
	case "n8n":
		endpoints = append(endpoints, getN8nEndpoints()...)
		result.AttackSurface.HasAPIEndpoints = true
		result.AttackSurface.HasWebSockets = true
	case "immich":
		endpoints = append(endpoints, getImmichEndpoints()...)
		result.AttackSurface.HasFileUpload = true
		result.AttackSurface.HasAPIEndpoints = true
	case "agreementpulse":
		endpoints = append(endpoints, getAgreementPulseEndpoints()...)
		result.AttackSurface.HasAPIEndpoints = true
	case "onehub":
		endpoints = append(endpoints, getOnehubEndpoints()...)
		result.AttackSurface.HasAPIEndpoints = true
		result.AttackSurface.AcceptsJSON = true
	default:
		// Generic probing
		endpoints = append(endpoints, getGenericEndpoints()...)
	}

	// Probe each endpoint using worker pool pattern
	// (avoids goroutine leak from semaphore pattern)
	if len(endpoints) == 0 {
		return
	}

	concurrency := d.config.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

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
						return
					}
					d.probeEndpoint(ctx, path, result)
				}
			}
		}()
	}

	// Send work to workers
sendLoop:
	for _, path := range endpoints {
		select {
		case <-ctx.Done():
			break sendLoop
		case work <- path:
		}
	}
	close(work)
	wg.Wait()
}

// probeEndpoint tests a single endpoint
func (d *Discoverer) probeEndpoint(ctx context.Context, path string, result *DiscoveryResult) {
	// Skip if already visited
	if _, exists := d.visited.LoadOrStore(path, true); exists {
		return
	}

	methods := []string{"GET", "POST", "OPTIONS"}

	for _, method := range methods {
		fullURL := d.config.Target + path
		req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", d.config.UserAgent)
		req.Header.Set("Accept", "application/json, text/html, */*")

		resp, err := d.httpClient.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 4096)
		iohelper.DrainAndClose(resp.Body)

		// Skip 404s and errors
		if resp.StatusCode == 404 || resp.StatusCode >= 500 {
			continue
		}

		endpoint := Endpoint{
			Path:        path,
			Method:      method,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Service:     d.config.Service,
			Category:    categorizeEndpoint(path, method),
			Headers:     make(map[string]string),
		}

		// Extract parameters from response
		endpoint.Parameters = extractParameters(path, string(body), resp.Header.Get("Content-Type"))

		// Identify risk factors
		endpoint.RiskFactors = identifyRiskFactors(path, method, string(body))

		d.mu.Lock()
		d.endpoints = append(d.endpoints, endpoint)
		result.Statistics.ByMethod[method]++
		result.Statistics.ByCategory[endpoint.Category]++
		result.Statistics.RequestsMade++
		d.mu.Unlock()

		// Only continue with GET for now to avoid side effects
		if method == "GET" {
			break
		}
	}
}

// probeEndpointWithMethod probes an endpoint with a specific HTTP method (used for JS-inferred methods)
func (d *Discoverer) probeEndpointWithMethod(ctx context.Context, path, method string, result *DiscoveryResult) {
	// Create a unique key for method+path to avoid duplicates
	visitKey := method + ":" + path
	if _, exists := d.visited.LoadOrStore(visitKey, true); exists {
		return
	}

	fullURL := d.config.Target + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return
	}

	body, _ := iohelper.ReadBody(resp.Body, 4096)
	resp.Body.Close()

	// Skip 404s and errors
	if resp.StatusCode == 404 || resp.StatusCode >= 500 {
		return
	}

	endpoint := Endpoint{
		Path:        path,
		Method:      method,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Service:     d.config.Service,
		Category:    categorizeEndpoint(path, method),
		Headers:     make(map[string]string),
	}

	// Extract parameters from response
	endpoint.Parameters = extractParameters(path, string(body), resp.Header.Get("Content-Type"))

	// Identify risk factors
	endpoint.RiskFactors = identifyRiskFactors(path, method, string(body))

	d.mu.Lock()
	d.endpoints = append(d.endpoints, endpoint)
	result.Statistics.ByMethod[method]++
	result.Statistics.ByCategory[endpoint.Category]++
	result.Statistics.RequestsMade++
	d.mu.Unlock()
}

// parseAPISpecs discovers endpoints from OpenAPI/Swagger specs and GraphQL introspection
func (d *Discoverer) parseAPISpecs(ctx context.Context, result *DiscoveryResult) {
	// Common OpenAPI/Swagger spec locations
	specPaths := []string{
		"/openapi.json",
		"/swagger.json",
		"/api/openapi.json",
		"/api/swagger.json",
		"/v1/openapi.json",
		"/v2/openapi.json",
		"/v3/openapi.json",
		"/api-docs",
		"/api-docs.json",
		"/docs/openapi.json",
		"/api/v1/swagger.json",
		"/api/v2/swagger.json",
		"/swagger/v1/swagger.json",
	}

	// Try to fetch and parse OpenAPI specs
	for _, specPath := range specPaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		endpoints := d.parseOpenAPISpec(ctx, specPath)
		for _, ep := range endpoints {
			d.addEndpointIfNew(ep, result)
		}
	}

	// GraphQL introspection
	graphqlPaths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}
	for _, gqlPath := range graphqlPaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		endpoints := d.introspectGraphQL(ctx, gqlPath)
		for _, ep := range endpoints {
			d.addEndpointIfNew(ep, result)
		}
	}
}

// parseOpenAPISpec fetches and parses an OpenAPI/Swagger specification
func (d *Discoverer) parseOpenAPISpec(ctx context.Context, specPath string) []Endpoint {
	var endpoints []Endpoint

	fullURL := d.config.Target + specPath
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return endpoints
	}
	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			iohelper.DrainAndClose(resp.Body)
		}
		return endpoints
	}

	// Check content-type - must be JSON, not HTML
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		iohelper.DrainAndClose(resp.Body)
		return endpoints
	}

	body, err := iohelper.ReadBody(resp.Body, 5*1024*1024) // 5MB limit
	resp.Body.Close()
	if err != nil {
		return endpoints
	}

	// Verify body looks like JSON (starts with { or [) - handles SPA 200 responses
	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 || (trimmedBody[0] != '{' && trimmedBody[0] != '[') {
		return endpoints
	}

	// Parse as JSON
	var spec map[string]interface{}
	if err := json.Unmarshal(body, &spec); err != nil {
		return endpoints
	}

	// Verify it's an OpenAPI/Swagger spec (has paths or openapi/swagger key)
	_, hasOpenAPI := spec["openapi"]
	_, hasSwagger := spec["swagger"]
	_, hasPaths := spec["paths"]
	if !hasOpenAPI && !hasSwagger && !hasPaths {
		return endpoints
	}

	// Check for OpenAPI 3.x or Swagger 2.x
	basePath := ""
	if bp, ok := spec["basePath"].(string); ok {
		basePath = bp
	}

	// Handle OpenAPI 3.x servers
	if servers, ok := spec["servers"].([]interface{}); ok && len(servers) > 0 {
		if server, ok := servers[0].(map[string]interface{}); ok {
			if serverURL, ok := server["url"].(string); ok {
				// Extract path from server URL if relative
				if strings.HasPrefix(serverURL, "/") {
					basePath = serverURL
				} else if u, err := url.Parse(serverURL); err == nil {
					basePath = u.Path
				}
			}
		}
	}

	// Extract paths
	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		return endpoints
	}

	for path, methods := range paths {
		methodMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		fullPath := basePath + path
		// Normalize path - replace {param} with placeholder
		fullPath = regexcache.MustGet(`\{[^}]+\}`).ReplaceAllString(fullPath, "1")

		for method, details := range methodMap {
			method = strings.ToUpper(method)
			if method == "PARAMETERS" || method == "SERVERS" {
				continue // Skip non-HTTP method keys
			}

			ep := Endpoint{
				Path:     fullPath,
				Method:   method,
				Category: "api",
			}

			// Extract parameters
			if detailMap, ok := details.(map[string]interface{}); ok {
				ep.Parameters = d.extractOpenAPIParameters(detailMap)

				// Extract operation info for categorization
				if opID, ok := detailMap["operationId"].(string); ok {
					opLower := strings.ToLower(opID)
					if strings.Contains(opLower, "auth") || strings.Contains(opLower, "login") {
						ep.Category = "auth"
					} else if strings.Contains(opLower, "upload") || strings.Contains(opLower, "file") {
						ep.Category = "upload"
					} else if strings.Contains(opLower, "admin") {
						ep.Category = "admin"
					}
				}

				// Check for file upload (multipart/form-data)
				if requestBody, ok := detailMap["requestBody"].(map[string]interface{}); ok {
					if content, ok := requestBody["content"].(map[string]interface{}); ok {
						if _, hasMultipart := content["multipart/form-data"]; hasMultipart {
							ep.Category = "upload"
							ep.RiskFactors = append(ep.RiskFactors, "file_upload")
						}
					}
				}
			}

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// extractOpenAPIParameters extracts parameters from an OpenAPI operation
func (d *Discoverer) extractOpenAPIParameters(operation map[string]interface{}) []Parameter {
	var params []Parameter

	// Extract from 'parameters' array
	if paramList, ok := operation["parameters"].([]interface{}); ok {
		for _, p := range paramList {
			paramMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}

			param := Parameter{}
			if name, ok := paramMap["name"].(string); ok {
				param.Name = name
			}
			if in, ok := paramMap["in"].(string); ok {
				param.Location = in
			}
			if required, ok := paramMap["required"].(bool); ok {
				param.Required = required
			}

			// Get type from schema
			if schema, ok := paramMap["schema"].(map[string]interface{}); ok {
				if t, ok := schema["type"].(string); ok {
					param.Type = t
				}
				if ex, ok := schema["example"]; ok {
					param.Example = fmt.Sprintf("%v", ex)
				}
			}

			if param.Name != "" {
				params = append(params, param)
			}
		}
	}

	// Extract from requestBody (for POST/PUT/PATCH)
	if requestBody, ok := operation["requestBody"].(map[string]interface{}); ok {
		if content, ok := requestBody["content"].(map[string]interface{}); ok {
			for contentType, mediaType := range content {
				mediaMap, ok := mediaType.(map[string]interface{})
				if !ok {
					continue
				}

				if schema, ok := mediaMap["schema"].(map[string]interface{}); ok {
					bodyParams := d.extractSchemaProperties(schema, contentType)
					params = append(params, bodyParams...)
				}
			}
		}
	}

	return params
}

// extractSchemaProperties extracts parameters from a JSON schema
func (d *Discoverer) extractSchemaProperties(schema map[string]interface{}, contentType string) []Parameter {
	var params []Parameter

	location := "body"
	if strings.Contains(contentType, "form") {
		location = "form"
	}

	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		requiredFields := make(map[string]bool)
		if req, ok := schema["required"].([]interface{}); ok {
			for _, r := range req {
				if name, ok := r.(string); ok {
					requiredFields[name] = true
				}
			}
		}

		for name, prop := range properties {
			propMap, ok := prop.(map[string]interface{})
			if !ok {
				continue
			}

			param := Parameter{
				Name:     name,
				Location: location,
				Required: requiredFields[name],
			}

			if t, ok := propMap["type"].(string); ok {
				param.Type = t
			}
			if ex, ok := propMap["example"]; ok {
				param.Example = fmt.Sprintf("%v", ex)
			}

			params = append(params, param)
		}
	}

	return params
}

// introspectGraphQL performs GraphQL schema introspection
func (d *Discoverer) introspectGraphQL(ctx context.Context, gqlPath string) []Endpoint {
	var endpoints []Endpoint

	fullURL := d.config.Target + gqlPath

	// Standard introspection query
	introspectionQuery := `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name kind } } } } } } }"}`

	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, strings.NewReader(introspectionQuery))
	if err != nil {
		return endpoints
	}
	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 400) {
		if resp != nil {
			iohelper.DrainAndClose(resp.Body)
		}
		return endpoints
	}

	// Check content-type - must be JSON, not HTML (handles SPAs)
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		iohelper.DrainAndClose(resp.Body)
		return endpoints
	}

	body, err := iohelper.ReadBody(resp.Body, 2*1024*1024) // 2MB limit
	resp.Body.Close()
	if err != nil {
		return endpoints
	}

	// Verify body looks like JSON (starts with {)
	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 || trimmedBody[0] != '{' {
		return endpoints
	}

	// Parse the introspection response
	var gqlResp map[string]interface{}
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return endpoints
	}

	// Check for errors (introspection might be disabled)
	if _, hasErrors := gqlResp["errors"]; hasErrors {
		// Introspection disabled, but we know GraphQL exists
		// Add basic GraphQL endpoint
		endpoints = append(endpoints, Endpoint{
			Path:        gqlPath,
			Method:      "POST",
			Category:    "api",
			RiskFactors: []string{"graphql"},
		})
		return endpoints
	}

	data, ok := gqlResp["data"].(map[string]interface{})
	if !ok {
		return endpoints
	}

	schema, ok := data["__schema"].(map[string]interface{})
	if !ok {
		return endpoints
	}

	// Extract query and mutation types
	types, ok := schema["types"].([]interface{})
	if !ok {
		return endpoints
	}

	for _, t := range types {
		typeMap, ok := t.(map[string]interface{})
		if !ok {
			continue
		}

		typeName, _ := typeMap["name"].(string)
		// Skip internal types
		if strings.HasPrefix(typeName, "__") {
			continue
		}

		kind, _ := typeMap["kind"].(string)
		if kind != "OBJECT" {
			continue
		}

		// Only process Query and Mutation types
		if typeName != "Query" && typeName != "Mutation" && typeName != "Subscription" {
			continue
		}

		fields, ok := typeMap["fields"].([]interface{})
		if !ok {
			continue
		}

		for _, f := range fields {
			fieldMap, ok := f.(map[string]interface{})
			if !ok {
				continue
			}

			fieldName, _ := fieldMap["name"].(string)
			if fieldName == "" {
				continue
			}

			// Create endpoint for each field
			ep := Endpoint{
				Path:        gqlPath,
				Method:      "POST",
				Category:    "api",
				RiskFactors: []string{"graphql", strings.ToLower(typeName)},
			}

			// Add field name as a pseudo-parameter for testing
			ep.Parameters = append(ep.Parameters, Parameter{
				Name:     "operation",
				Location: "body",
				Type:     "string",
				Example:  fieldName,
			})

			// Extract arguments
			if args, ok := fieldMap["args"].([]interface{}); ok {
				for _, arg := range args {
					argMap, ok := arg.(map[string]interface{})
					if !ok {
						continue
					}

					argName, _ := argMap["name"].(string)
					if argName == "" {
						continue
					}

					param := Parameter{
						Name:     argName,
						Location: "body",
						Type:     "string", // Default type
					}

					// Try to get actual type
					if argType, ok := argMap["type"].(map[string]interface{}); ok {
						if typeName, ok := argType["name"].(string); ok && typeName != "" {
							param.Type = strings.ToLower(typeName)
						} else if kind, ok := argType["kind"].(string); ok {
							param.Type = strings.ToLower(kind)
						}
					}

					ep.Parameters = append(ep.Parameters, param)
				}
			}

			// Categorize based on field name
			fieldLower := strings.ToLower(fieldName)
			if strings.Contains(fieldLower, "login") || strings.Contains(fieldLower, "auth") ||
				strings.Contains(fieldLower, "register") || strings.Contains(fieldLower, "password") {
				ep.Category = "auth"
			} else if strings.Contains(fieldLower, "upload") || strings.Contains(fieldLower, "file") {
				ep.Category = "upload"
				ep.RiskFactors = append(ep.RiskFactors, "file_upload")
			} else if strings.Contains(fieldLower, "admin") || strings.Contains(fieldLower, "user") {
				ep.Category = "admin"
			}

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// addEndpointIfNew adds an endpoint only if it doesn't already exist
func (d *Discoverer) addEndpointIfNew(ep Endpoint, result *DiscoveryResult) {
	key := ep.Method + ":" + ep.Path

	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if already exists
	if _, exists := d.visited.Load(key); exists {
		return
	}
	d.visited.Store(key, true)

	d.endpoints = append(d.endpoints, ep)
	result.Statistics.ByMethod[ep.Method]++
	result.Statistics.ByCategory[ep.Category]++
}

// crawlEndpoints performs deeper crawling of discovered content
func (d *Discoverer) crawlEndpoints(ctx context.Context, result *DiscoveryResult) {
	// Extract links from responses and add to queue
	// This is a simplified implementation
	linkPatterns := []*regexp.Regexp{
		regexcache.MustGet(`href=["']([^"']+)["']`),
		regexcache.MustGet(`action=["']([^"']+)["']`),
		regexcache.MustGet(`"path"\s*:\s*"([^"]+)"`),
	}

	for _, endpoint := range d.endpoints {
		if endpoint.StatusCode != 200 {
			continue
		}

		fullURL := d.config.Target + endpoint.Path
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.config.UserAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 65536)
		iohelper.DrainAndClose(resp.Body)

		for _, pattern := range linkPatterns {
			matches := pattern.FindAllStringSubmatch(string(body), -1)
			for _, match := range matches {
				if len(match) > 1 {
					link := match[1]
					if isInternalLink(link, d.config.Target) {
						parsedPath := extractPath(link)
						if parsedPath != "" && !d.isExcluded(parsedPath) {
							d.probeEndpoint(ctx, parsedPath, result)
						}
					}
				}
			}
		}
	}
}

// analyzeAttackSurface determines which attack categories are relevant
func (d *Discoverer) analyzeAttackSurface(result *DiscoveryResult) {
	surface := &result.AttackSurface
	categories := make(map[string]bool)

	for _, ep := range d.endpoints {
		path := strings.ToLower(ep.Path)

		// Check for auth endpoints
		if strings.Contains(path, "login") || strings.Contains(path, "auth") ||
			strings.Contains(path, "signin") || strings.Contains(path, "token") {
			surface.HasAuthEndpoints = true
			categories["auth"] = true
		}

		// Check for API endpoints
		if strings.Contains(path, "/api/") || strings.Contains(path, "/v1/") ||
			strings.Contains(path, "/v2/") {
			surface.HasAPIEndpoints = true
			categories["injection"] = true
		}

		// Check for file upload
		if strings.Contains(path, "upload") || strings.Contains(path, "import") ||
			strings.Contains(path, "asset") {
			surface.HasFileUpload = true
			categories["media"] = true
			categories["traversal"] = true
		}

		// Check for OAuth
		if strings.Contains(path, "oauth") || strings.Contains(path, "authorize") ||
			strings.Contains(path, "callback") {
			surface.HasOAuth = true
			categories["auth"] = true
		}

		// Check for SAML
		if strings.Contains(path, "saml") || strings.Contains(path, "sso") {
			surface.HasSAML = true
			categories["auth"] = true
		}

		// Check for GraphQL
		if strings.Contains(path, "graphql") {
			surface.HasGraphQL = true
			categories["graphql"] = true
		}

		// Check content types
		if strings.Contains(ep.ContentType, "json") {
			surface.AcceptsJSON = true
			categories["injection"] = true
		}
		if strings.Contains(ep.ContentType, "xml") {
			surface.AcceptsXML = true
			categories["injection"] = true
		}
		if strings.Contains(ep.ContentType, "form") || strings.Contains(ep.ContentType, "urlencoded") ||
			strings.Contains(ep.ContentType, "multipart") {
			surface.AcceptsFormData = true
			categories["injection"] = true
		}

		// Forms indicate form data acceptance
		if ep.Method == "POST" && (strings.Contains(path, "login") || strings.Contains(path, "submit") ||
			strings.Contains(path, "register") || strings.Contains(path, "form")) {
			surface.AcceptsFormData = true
		}

		// Add risk factor categories
		for _, risk := range ep.RiskFactors {
			switch risk {
			case "parameter_injection":
				categories["injection"] = true
			case "file_access":
				categories["traversal"] = true
			case "command_execution":
				categories["injection"] = true
			case "redirect":
				categories["ssrf"] = true
			}
		}
	}

	// Build relevant categories list
	for cat := range categories {
		surface.RelevantCategories = append(surface.RelevantCategories, cat)
	}

	// Always include these baseline categories
	baseline := []string{"xss", "waf-validation", "protocol"}
	for _, b := range baseline {
		if !contains(surface.RelevantCategories, b) {
			surface.RelevantCategories = append(surface.RelevantCategories, b)
		}
	}
}

// isExcluded checks if a path should be skipped
func (d *Discoverer) isExcluded(path string) bool {
	for _, exc := range d.config.ExcludePaths {
		if strings.Contains(path, exc) {
			return true
		}
	}
	return false
}

// SaveResult saves discovery result to a JSON file
func (r *DiscoveryResult) SaveResult(filename string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filename, data)
}

// LoadResult loads a discovery result from a JSON file
func LoadResult(filename string) (*DiscoveryResult, error) {
	data, err := readFile(filename)
	if err != nil {
		return nil, err
	}
	var result DiscoveryResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// Helper functions

func getAuthentikEndpoints() []string {
	return []string{
		"/-/health/ready/",
		"/-/health/live/",
		"/api/v3/core/applications/",
		"/api/v3/core/groups/",
		"/api/v3/core/users/",
		"/api/v3/core/tokens/",
		"/api/v3/flows/executor/",
		"/api/v3/policies/",
		"/application/o/authorize/",
		"/application/o/token/",
		"/application/o/userinfo/",
		"/source/saml/",
		"/source/oauth/",
		"/if/flow/default-authentication-flow/",
		"/if/admin/",
		"/if/user/",
		"/ws/",
	}
}

func getN8nEndpoints() []string {
	return []string{
		"/healthz",
		"/rest/workflows",
		"/rest/credentials",
		"/rest/executions",
		"/rest/settings",
		"/rest/users",
		"/rest/oauth2-credential/",
		"/webhook/",
		"/webhook-test/",
		"/api/v1/",
		"/push",
	}
}

func getImmichEndpoints() []string {
	return []string{
		"/api/server/ping",
		"/api/server-info/",
		"/api/auth/login",
		"/api/auth/signup",
		"/api/users/",
		"/api/albums/",
		"/api/assets/",
		"/api/assets/upload",
		"/api/search/",
		"/api/faces/",
		"/api/people/",
	}
}

func getAgreementPulseEndpoints() []string {
	return []string{
		"/api/health",
		"/api/auth/login",
		"/api/auth/register",
		"/api/agreements/",
		"/api/documents/",
		"/api/users/",
		"/api/notifications/",
	}
}

// getOnehubEndpoints returns known endpoints for ADNOC OneHub (.NET/Azure-based)
// Updated with deep JavaScript analysis findings from config.js, foundation.js, and remote entries
func getOnehubEndpoints() []string {
	baseAPI := "/vms/onehub/LiteAppApi.2.0/api"
	return []string{
		// === BASE LITEAPP API ===
		baseAPI,
		baseAPI + "/",
		baseAPI + "/values",
		baseAPI + "/users",
		baseAPI + "/user",
		baseAPI + "/account",
		baseAPI + "/auth",
		baseAPI + "/login",
		baseAPI + "/token",
		baseAPI + "/refresh",
		baseAPI + "/logout",
		baseAPI + "/profile",
		// Document management
		baseAPI + "/documents",
		baseAPI + "/document",
		baseAPI + "/files",
		baseAPI + "/file",
		baseAPI + "/upload",
		baseAPI + "/download",
		baseAPI + "/attachments",
		// Content management
		baseAPI + "/content",
		baseAPI + "/pages",
		baseAPI + "/posts",
		baseAPI + "/news",
		baseAPI + "/articles",
		baseAPI + "/announcements",
		// Enterprise features
		baseAPI + "/departments",
		baseAPI + "/organizations",
		baseAPI + "/groups",
		baseAPI + "/teams",
		baseAPI + "/roles",
		baseAPI + "/permissions",
		// Search & lookup
		baseAPI + "/search",
		baseAPI + "/lookup",
		baseAPI + "/autocomplete",
		baseAPI + "/suggest",
		// Workflow & tasks
		baseAPI + "/workflows",
		baseAPI + "/tasks",
		baseAPI + "/approvals",
		baseAPI + "/requests",
		// Notifications
		baseAPI + "/notifications",
		baseAPI + "/alerts",
		baseAPI + "/messages",
		// Admin & config
		baseAPI + "/admin",
		baseAPI + "/settings",
		baseAPI + "/config",
		baseAPI + "/configuration",
		// Analytics & reporting
		baseAPI + "/analytics",
		baseAPI + "/reports",
		baseAPI + "/dashboard",
		baseAPI + "/stats",
		// Health
		baseAPI + "/health",
		baseAPI + "/ping",
		baseAPI + "/status",
		// Swagger/OpenAPI
		"/vms/onehub/LiteAppApi.2.0/swagger",
		"/vms/onehub/LiteAppApi.2.0/swagger/v1/swagger.json",
		"/vms/onehub/api",
		"/vms/onehub/LiteAppApi/api",
		"/vms/onehub/LiteAppApi.1.0/api",

		// === SITECORE CMS APIs (from config.js) ===
		"/sitecore/onehub/api/events/UpcomingEventsWidget",
		"/sitecore/onehub/api/news/GetAllNewsByDate",
		"/sitecore/onehub/api/news/GetNewsWidgetData",
		"/sitecore/onehub/api/WhatsNew/GetWhatsNewWidgetData",
		"/sitecore/onehub/api",

		// === SERVICENOW INTEGRATION (from config.js) ===
		"/servicenow/onehub/integration",
		"/servicenow/onehub/integration/incidents",
		"/servicenow/onehub/integration/requests",
		"/servicenow/onehub/integration/tickets",

		// === CORPORATE BI / ENTERPRISE SEARCH (from config.js) ===
		"/corporatebi/onehub/multi-api/kpi-insights/enterprise-search",
		"/corporatebi/onehub/multi-api",
		"/corporatebi/onehub",

		// === ONETALENT HR SYSTEM (from config.js) ===
		"/onetalent/v1",
		"/onetalent/v1/employees",
		"/onetalent/v1/profile",
		"/onetalent/v1/leave",
		"/onetalent/v1/attendance",

		// === RECOGNITION SYSTEM (from config.js) ===
		"/recognition/v1",
		"/recognition/v1/badges",
		"/recognition/v1/awards",
		"/recognition/v1/nominations",

		// === YAMMER INTEGRATION (from config.js) ===
		"/yammer/v1",
		"/yammer/v1/messages",
		"/yammer/v1/groups",
		"/yammer/v1/users",

		// === DELEGATION OF AUTHORITY (from config.js) ===
		"/doa",
		"/doa/api",
		"/doa/delegations",
		"/doa/authorities",

		// === DOC360 / POLICY SEARCH (from config.js) ===
		"/doc360/onehub/onehub/policy/search",
		"/doc360/onehub/policies",
		"/doc360/onehub/documents",

		// === BMS - BUILDING MANAGEMENT (from config.js) ===
		"/tbms/onehub",
		"/tbms/onehub/facilities",
		"/tbms/onehub/bookings",

		// === ACTION HUB (from config.js) ===
		"/onehubmf/actionhub",
		"/onehubmf/actionhub/actions",
		"/onehubmf/actionhub/tracking",

		// === CTS - CORRESPONDENCE TRACKING (from config.js) ===
		"/cts/api",
		"/cts/api/correspondence",
		"/cts/api/signatures",
		"/cts/api/workflows",

		// === POWERBI INTEGRATION (from foundation.js) ===
		"/powerbi/api/App",
		"/powerbi/api/Capacity",
		"/powerbi/api/Dashboard",
		"/powerbi/api/Dataset",
		"/powerbi/api/Report",
		"/powerbi/api/Workspace",

		// === CONFIG APIs (from foundation.js) ===
		"/api/config/v0",
		"/api/config/v0/icons",
		"/e-service-item/employee-photo",

		// === VMS - VISITOR MANAGEMENT (from remote_vms.js) ===
		"/container/entry/visitor_management_system",
		"/vms/details",
		"/vms/service",
		"/vms/visitors",
		"/vms/visits",
		"/vms/badges",
		"/vms/checkpoints",

		// === STANDARD ENDPOINTS ===
		"/api",
		"/api/v1",
		"/api/v2",
		"/admin",
		"/admin/",
		"/admin/content",
		"/admin/config.js",
		"/config.js",
		"/administrator",

		// === AZURE AD / AUTH ===
		"/signin-oidc",
		"/signout-callback-oidc",
		"/.auth/login",
		"/.auth/logout",
		"/.auth/me",

		// === SHAREPOINT/GRAPH STYLE ===
		"/_api",
		"/_api/web",
		"/_api/lists",
		"/_layouts",
		"/_vti_bin",

		// === MICRO-FRONTEND REMOTE ENTRIES (from config.js) ===
		"/onehub/blob/static-onehub-prod/vms/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/service-now/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/profile/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/search/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/meera/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/insights/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/cts/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/bms/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/shorts/remoteEntry.js",
		"/onehub/blob/static-ai-prd/ai-marketplace/remoteEntry.js",

		// === WALKME (from config.js) ===
		"/walkme/onehub/prdwalkme",

		// === STATIC ASSETS ===
		"/static/fonts/fonts.css",
		"/static/fonts/adnoc-sans-w-rg/adnoc-sans-w-rg.woff2",
		"/js/main-98bd4238fcc42dfb79df.js",
		"/js/foundation-98bd4238fcc42dfb79df.js",
		"/js/microsoft-98bd4238fcc42dfb79df.js",
		"/js/packages-98bd4238fcc42dfb79df.js",
	}
}

func getGenericEndpoints() []string {
	return []string{
		"/api/",
		"/api/v1/",
		"/api/v2/",
		"/login",
		"/logout",
		"/register",
		"/signup",
		"/admin/",
		"/dashboard/",
		"/settings/",
		"/profile/",
		"/users/",
		"/search",
		"/upload",
		"/download",
		"/graphql",
		"/swagger.json",
		"/openapi.json",
		"/.env",
		"/config",
	}
}

func categorizeEndpoint(path, method string) string {
	path = strings.ToLower(path)

	if strings.Contains(path, "health") || strings.Contains(path, "ping") {
		return "health"
	}
	if strings.Contains(path, "login") || strings.Contains(path, "auth") || strings.Contains(path, "oauth") {
		return "auth"
	}
	if strings.Contains(path, "api") {
		return "api"
	}
	if strings.Contains(path, "admin") {
		return "admin"
	}
	if strings.Contains(path, "upload") || strings.Contains(path, "asset") {
		return "upload"
	}
	if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".png") {
		return "static"
	}
	if strings.Contains(path, "webhook") {
		return "webhook"
	}
	return "general"
}

func extractParameters(path, body, contentType string) []Parameter {
	params := make([]Parameter, 0)

	// Extract query parameters from path
	if idx := strings.Index(path, "?"); idx != -1 {
		query := path[idx+1:]
		for _, pair := range strings.Split(query, "&") {
			if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
				params = append(params, Parameter{
					Name:     kv[0],
					Location: "query",
					Type:     "string",
					Example:  kv[1],
				})
			}
		}
	}

	// Extract JSON body parameters
	if strings.Contains(contentType, "json") && len(body) > 0 {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
			for key, val := range jsonData {
				params = append(params, Parameter{
					Name:     key,
					Location: "body",
					Type:     inferType(val),
				})
			}
		}
	}

	return params
}

func identifyRiskFactors(path, method string, body string) []string {
	risks := make([]string, 0)
	path = strings.ToLower(path)
	body = strings.ToLower(body)

	// Check for injection points
	if strings.Contains(path, "?") || strings.Contains(path, "id=") || strings.Contains(path, "query=") {
		risks = append(risks, "parameter_injection")
	}

	// Check for file access
	if strings.Contains(path, "file") || strings.Contains(path, "path") || strings.Contains(path, "download") {
		risks = append(risks, "file_access")
	}

	// Check for command execution hints
	if strings.Contains(body, "exec") || strings.Contains(body, "command") || strings.Contains(body, "shell") {
		risks = append(risks, "command_execution")
	}

	// Check for redirect
	if strings.Contains(path, "redirect") || strings.Contains(path, "url=") || strings.Contains(path, "next=") {
		risks = append(risks, "redirect")
	}

	return risks
}

func inferType(val interface{}) string {
	switch val.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

func isInternalLink(link, target string) bool {
	if strings.HasPrefix(link, "/") && !strings.HasPrefix(link, "//") {
		return true
	}
	targetURL, err := url.Parse(target)
	if err != nil || targetURL == nil {
		return false
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return false
	}
	return linkURL.Host == "" || linkURL.Host == targetURL.Host
}

func extractPath(link string) string {
	if strings.HasPrefix(link, "/") {
		// Remove query string and fragment
		if idx := strings.Index(link, "?"); idx != -1 {
			link = link[:idx]
		}
		if idx := strings.Index(link, "#"); idx != -1 {
			link = link[:idx]
		}
		return link
	}
	parsed, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// File I/O helpers (platform-independent)
func writeFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

func readFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
