// Package discovery implements target application learning and endpoint enumeration
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
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
		cfg.Timeout = httpclient.TimeoutProbing
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = defaults.DepthMedium
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = defaults.ConcurrencyMedium
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = ui.UserAgentWithContext("Discovery")
	}

	// Use provided HTTPClient (e.g., JA3-aware) or create default
	var client *http.Client
	if cfg.HTTPClient != nil {
		client = cfg.HTTPClient
	} else {
		// Use shared pooled client with custom timeout if needed
		if cfg.Timeout != httpclient.TimeoutFuzzing {
			httpCfg := httpclient.WithTimeout(cfg.Timeout)
			httpCfg.InsecureSkipVerify = cfg.SkipVerify
			client = httpclient.New(httpCfg)
		} else {
			client = httpclient.Default()
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

	// spinWhile runs work() while showing an animated spinner on stderr.
	// The spinner goroutine is fully stopped before this function returns,
	// so the caller can safely write the completion line without a race.
	// Spinner animation is suppressed when stderr is not a terminal.
	spinnerFrames := ui.DefaultSpinner().Frames
	stderrTTY := ui.StderrIsTerminal()
	spinWhile := func(phaseNum int, phaseName string, work func()) {
		done := make(chan struct{})
		stopped := make(chan struct{})

		go func() {
			defer close(stopped)
			if !stderrTTY {
				<-done
				return
			}
			frame := 0
			for {
				select {
				case <-done:
					return
				default:
					fmt.Fprintf(os.Stderr, "\r  [%d/9] %s %s ", phaseNum, spinnerFrames[frame%len(spinnerFrames)], phaseName)
					frame++
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()

		work()
		close(done)
		<-stopped
	}

	// clearEOL returns the ANSI "erase to end of line" code when stderr is
	// a terminal, empty string otherwise.
	clearEOL := ""
	if ui.StderrIsTerminal() {
		clearEOL = "\033[K"
	}

	// runPhase runs a phase with spinner and prints a standard "+N" completion line.
	runPhase := func(phaseNum int, phaseName string, work func()) int {
		beforeCount := len(d.endpoints)
		spinWhile(phaseNum, phaseName, work)
		added := len(d.endpoints) - beforeCount
		fmt.Fprintf(os.Stderr, "\r  [%d/9] %s %s +%d%s\n", phaseNum, ui.Icon("✅", "+"), phaseName, added, clearEOL)
		return added
	}

	// Phase 1: Detect WAF
	spinWhile(1, "Detecting WAF...", func() {
		d.detectWAF(ctx, result)
	})
	if result.WAFDetected {
		fmt.Fprintf(os.Stderr, "\r  [1/9] %s WAF detected: %s%s\n", ui.Icon("✅", "+"), result.WAFFingerprint, clearEOL)
	} else {
		fmt.Fprintf(os.Stderr, "\r  [1/9] %s No WAF detected%s\n", ui.Icon("✅", "+"), clearEOL)
	}

	// Phase 2: Active discovery — comprehensive path brute-forcing
	if !d.config.DisableActive {
		spinWhile(2, "Active discovery (path brute-force)...", func() {
			d.discoverActiveEndpoints(ctx, result)
		})
		fmt.Fprintf(os.Stderr, "\r  [2/9] %s Active discovery: %d endpoints%s\n", ui.Icon("✅", "+"), len(d.endpoints), clearEOL)
	}

	// Phase 3: External Sources
	runPhase(3, "External sources", func() {
		d.discoverFromExternalSources(ctx, result)
	})

	// Phase 4: Service-specific endpoint probing
	runPhase(4, "Service-specific probing", func() {
		d.probeKnownEndpoints(ctx, result)
	})

	// Phase 5: JavaScript link extraction
	runPhase(5, "JavaScript analysis", func() {
		d.discoverFromJavaScript(ctx, result)
	})

	// Phase 6: API Spec Parsing (OpenAPI/Swagger/GraphQL introspection)
	runPhase(6, "API spec parsing", func() {
		d.parseAPISpecs(ctx, result)
	})

	// Phase 7: Form extraction
	runPhase(7, "Form extraction", func() {
		d.discoverForms(ctx, result)
	})

	// Phase 8: Crawl discovered endpoints (recursive link following)
	runPhase(8, "Crawling links", func() {
		d.crawlEndpoints(ctx, result)
	})

	// Phase 9: Analyze and categorize
	spinWhile(9, "Analyzing attack surface...", func() {
		d.analyzeAttackSurface(result)
	})
	fmt.Fprintf(os.Stderr, "\r  [9/9] %s Attack surface analyzed%s\n", ui.Icon("✅", "+"), clearEOL)

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
				fmt.Fprintf(os.Stderr, "\r  [2/9] Active discovery: fingerprinting... ")
			case "path-bruteforce":
				fmt.Fprintf(os.Stderr, "\r  [2/9] Active discovery: path brute-force %d%%   ", percent)
			case "link-extraction":
				fmt.Fprintf(os.Stderr, "\r  [2/9] Active discovery: extracting links %d%%   ", percent)
			case "param-discovery":
				fmt.Fprintf(os.Stderr, "\r  [2/9] Active discovery: finding params %d%%    ", percent)
			case "method-enum":
				fmt.Fprintf(os.Stderr, "\r  [2/9] Active discovery: testing methods %d%%   ", percent)
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
		fmt.Fprintf(os.Stderr, "  External sources: robots=%d sitemap=%d wayback=%d commoncrawl=%d otx=%d virustotal=%d (total unique: %d)\n",
			allSources.SourceCounts["robots.txt"],
			allSources.SourceCounts["sitemap.xml"],
			allSources.SourceCounts["wayback"],
			allSources.SourceCounts["commoncrawl"],
			allSources.SourceCounts["otx"],
			allSources.SourceCounts["virustotal"],
			allSources.TotalUnique)
	}
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
		// Check for context cancellation before each iteration
		select {
		case <-ctx.Done():
			return
		default:
		}

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
		if !slices.Contains(surface.RelevantCategories, b) {
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
		return fmt.Errorf("marshal discovery result: %w", err)
	}
	if err := writeFile(filename, data); err != nil {
		return fmt.Errorf("write discovery result: %w", err)
	}
	return nil
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

// File I/O helpers (platform-independent)
func writeFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

func readFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
