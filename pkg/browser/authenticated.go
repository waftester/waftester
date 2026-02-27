// Package browser provides authenticated browser scanning capabilities
// Uses chromedp for real browser automation with network capture
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/waftester/waftester/pkg/duration"
)

// AuthenticatedScanner provides authenticated browser-based discovery
type AuthenticatedScanner struct {
	config *AuthConfig
	mu     sync.RWMutex // RWMutex: RLock for read-only paths, Lock for writes

	// Compiled ignore patterns for performance
	ignorePatterns []*regexp.Regexp
}

// AuthConfig configures authenticated browser scanning
type AuthConfig struct {
	TargetURL      string            `json:"target_url"`
	Timeout        time.Duration     `json:"timeout"`
	WaitForLogin   time.Duration     `json:"wait_for_login"` // Max time to wait for user login
	PostLoginDelay time.Duration     `json:"post_login_delay"`
	CrawlDepth     int               `json:"crawl_depth"`
	ShowBrowser    bool              `json:"show_browser"` // Headless false = show browser
	Verbose        bool              `json:"verbose"`
	ScreenshotDir  string            `json:"screenshot_dir,omitempty"`
	EnableScreens  bool              `json:"enable_screenshots"`
	UserDataDir    string            `json:"user_data_dir,omitempty"`  // For session persistence
	IgnorePatterns []string          `json:"ignore_patterns"`          // URL patterns to ignore
	FocusPatterns  []string          `json:"focus_patterns"`           // URL patterns to prioritize
	Proxy          string            `json:"proxy,omitempty"`          // HTTP/SOCKS5 proxy URL for browser traffic
	CustomHeaders  map[string]string `json:"custom_headers,omitempty"` // Custom headers to inject (e.g., X-Bug-Bounty)
	StealthMode    bool              `json:"stealth_mode"`             // Enable anti-bot detection evasion
}

// DefaultAuthConfig returns sensible defaults for authenticated scanning
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		Timeout:        duration.HTTPLongOps,
		WaitForLogin:   duration.BrowserLogin, // User has 3 minutes to log in
		PostLoginDelay: duration.BrowserPostWait,
		CrawlDepth:     3,
		ShowBrowser:    true, // Show browser for manual login
		Verbose:        true,
		StealthMode:    true, // Enable stealth by default for WAF testing
		IgnorePatterns: []string{
			`\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css)$`,
			`fonts\.googleapis\.com`,
			`google-analytics\.com`,
			`googletagmanager\.com`,
			`facebook\.com/tr`,
			`doubleclick\.net`,
		},
	}
}

// NetworkRequest represents a captured HTTP request
type NetworkRequest struct {
	RequestID     string            `json:"request_id,omitempty"` // Chrome DevTools request ID for correlation
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	Headers       map[string]string `json:"headers,omitempty"`
	PostData      string            `json:"post_data,omitempty"`
	ResponseCode  int               `json:"response_code"`
	ResponseType  string            `json:"response_type,omitempty"`
	Size          int64             `json:"size"`
	Timestamp     time.Time         `json:"timestamp"`
	Duration      time.Duration     `json:"duration"`
	IsXHR         bool              `json:"is_xhr"`
	IsFetch       bool              `json:"is_fetch"`
	IsAPI         bool              `json:"is_api"`
	IsThirdParty  bool              `json:"is_third_party"`
	SecurityFlags []string          `json:"security_flags,omitempty"`
}

// DiscoveredRoute represents an application route found during browsing
type DiscoveredRoute struct {
	Path          string   `json:"path"`
	FullURL       string   `json:"full_url"`
	Method        string   `json:"method"`
	RequiresAuth  bool     `json:"requires_auth"`
	ContentType   string   `json:"content_type,omitempty"`
	Parameters    []string `json:"parameters,omitempty"`
	Category      string   `json:"category"` // admin, api, user, public
	DiscoveredVia string   `json:"discovered_via"`
	PageTitle     string   `json:"page_title,omitempty"`
}

// ExposedToken represents a token/secret found in browser storage or network
type ExposedToken struct {
	Type        string    `json:"type"`     // jwt, api_key, oauth, session, bearer
	Location    string    `json:"location"` // localStorage, sessionStorage, cookie, header, url
	Key         string    `json:"key"`      // Storage key or header name
	Value       string    `json:"value"`    // The actual token (may be truncated for display)
	FullValue   string    `json:"-"`        // Full value (not serialized)
	Severity    string    `json:"severity"` // critical, high, medium, low
	Risk        string    `json:"risk"`     // Description of the risk
	Timestamp   time.Time `json:"timestamp"`
	Expires     string    `json:"expires,omitempty"`     // For JWTs
	IssuedBy    string    `json:"issued_by,omitempty"`   // Token issuer
	Permissions []string  `json:"permissions,omitempty"` // Extracted permissions/scopes
}

// ThirdPartyAPI represents an external API integration found
type ThirdPartyAPI struct {
	Name        string   `json:"name"`
	BaseURL     string   `json:"base_url"`
	Endpoints   []string `json:"endpoints"`
	RequestType string   `json:"request_type"` // oauth, api, webhook, tracking
	AuthMethod  string   `json:"auth_method,omitempty"`
	DataSent    []string `json:"data_sent,omitempty"` // Types of data sent
	Severity    string   `json:"severity"`            // based on data exposure
}

// AuthFlowInfo captures authentication flow details
type AuthFlowInfo struct {
	Provider       string            `json:"provider"` // microsoft, google, okta, auth0, custom
	FlowType       string            `json:"flow_type"`
	LoginURL       string            `json:"login_url"`
	TokenEndpoint  string            `json:"token_endpoint,omitempty"`
	AuthorizeURL   string            `json:"authorize_url,omitempty"`
	RedirectURI    string            `json:"redirect_uri,omitempty"`
	ClientID       string            `json:"client_id,omitempty"` // Public, ok to expose
	Scopes         []string          `json:"scopes,omitempty"`
	TenantID       string            `json:"tenant_id,omitempty"` // For Azure AD
	LibraryUsed    string            `json:"library_used,omitempty"`
	SecurityIssues []string          `json:"security_issues,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// StorageData captures browser storage contents
type StorageData struct {
	LocalStorage   map[string]string `json:"local_storage"`
	SessionStorage map[string]string `json:"session_storage"`
	Cookies        []CookieInfo      `json:"cookies"`
	IndexedDB      []string          `json:"indexed_db_databases,omitempty"`
}

// CookieInfo represents a browser cookie
type CookieInfo struct {
	Name     string    `json:"name"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Secure   bool      `json:"secure"`
	HTTPOnly bool      `json:"http_only"`
	SameSite string    `json:"same_site"`
	Expires  time.Time `json:"expires,omitempty"`
	Size     int       `json:"size"`
}

// BrowserScanResult contains all findings from an authenticated browser scan
type BrowserScanResult struct {
	TargetURL        string            `json:"target_url"`
	Domain           string            `json:"domain"`
	ScanDuration     time.Duration     `json:"scan_duration"`
	Timestamp        time.Time         `json:"timestamp"`
	AuthSuccessful   bool              `json:"auth_successful"`
	AuthFlowInfo     *AuthFlowInfo     `json:"auth_flow_info,omitempty"`
	DiscoveredRoutes []DiscoveredRoute `json:"discovered_routes"`
	ExposedTokens    []ExposedToken    `json:"exposed_tokens"`
	ThirdPartyAPIs   []ThirdPartyAPI   `json:"third_party_apis"`
	NetworkRequests  []NetworkRequest  `json:"network_requests"`
	StorageData      *StorageData      `json:"storage_data,omitempty"`
	RiskSummary      *RiskSummary      `json:"risk_summary"`
	Screenshots      []string          `json:"screenshots,omitempty"`

	// Internal maps for O(1) operations (not serialized)
	routeMap        map[string]bool `json:"-"` // Route deduplication
	requestIndexMap map[string]int  `json:"-"` // RequestID → NetworkRequests index for O(1) response matching
}

// RiskSummary provides an overview of security risks found
type RiskSummary struct {
	OverallRisk     string   `json:"overall_risk"` // critical, high, medium, low
	CriticalCount   int      `json:"critical_count"`
	HighCount       int      `json:"high_count"`
	MediumCount     int      `json:"medium_count"`
	LowCount        int      `json:"low_count"`
	TotalFindings   int      `json:"total_findings"`
	TopRisks        []string `json:"top_risks"`
	Recommendations []string `json:"recommendations"`
}

// NewAuthenticatedScanner creates a new authenticated browser scanner
func NewAuthenticatedScanner(config *AuthConfig) *AuthenticatedScanner {
	if config == nil {
		config = DefaultAuthConfig()
	}

	// Pre-compile ignore patterns for performance
	var compiledPatterns []*regexp.Regexp
	for _, pattern := range config.IgnorePatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			compiledPatterns = append(compiledPatterns, re)
		}
		// Silently skip invalid patterns
	}

	return &AuthenticatedScanner{
		config:         config,
		ignorePatterns: compiledPatterns,
	}
}

// Scan performs an authenticated browser scan
// This is the main entry point - it opens a browser, waits for user login,
// then captures all network activity and storage data
func (s *AuthenticatedScanner) Scan(ctx context.Context, progressFn func(string)) (*BrowserScanResult, error) {
	// Apply configured timeout only if parent context has no deadline
	if s.config.Timeout > 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, s.config.Timeout)
			defer cancel()
		}
	}

	startTime := time.Now()

	parsed, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	domain := parsed.Hostname()

	result := &BrowserScanResult{
		TargetURL:        s.config.TargetURL,
		Domain:           domain,
		Timestamp:        startTime,
		DiscoveredRoutes: make([]DiscoveredRoute, 0),
		ExposedTokens:    make([]ExposedToken, 0),
		ThirdPartyAPIs:   make([]ThirdPartyAPI, 0),
		NetworkRequests:  make([]NetworkRequest, 0),
		Screenshots:      make([]string, 0),
	}

	// Phase 1: Check if chromedp is available
	if progressFn != nil {
		progressFn("Initializing browser automation...")
	}

	// Try to use chromedp if available
	chromedpAvailable := s.checkChromedpAvailable()

	if chromedpAvailable {
		// Use real browser with chromedp
		if err := s.runChromedpScan(ctx, result, progressFn); err != nil {
			// Fall back to simulation if chromedp fails
			if progressFn != nil {
				progressFn(fmt.Sprintf("Browser automation error: %v - using simulation mode", err))
			}
			// Reset result fields that may have been partially populated
			// to avoid inconsistent state mixing real and simulated data
			result.DiscoveredRoutes = make([]DiscoveredRoute, 0)
			result.ExposedTokens = make([]ExposedToken, 0)
			result.ThirdPartyAPIs = make([]ThirdPartyAPI, 0)
			result.NetworkRequests = make([]NetworkRequest, 0)
			result.StorageData = nil
			result.AuthFlowInfo = nil
			result.AuthSuccessful = false
			result.routeMap = nil        // Reset O(1) dedup map
			result.requestIndexMap = nil // Reset O(1) response lookup map
			s.runSimulatedScan(ctx, result, progressFn)
		}
	} else {
		// Use simulated scan (demonstrates the data structure)
		if progressFn != nil {
			progressFn("chromedp not available - using HTTP-based scanning with browser simulation")
		}
		s.runSimulatedScan(ctx, result, progressFn)
	}

	// Calculate risk summary
	result.RiskSummary = s.calculateRiskSummary(result)
	result.ScanDuration = time.Since(startTime)

	return result, nil
}

// checkChromedpAvailable checks if chromedp package is available
func (s *AuthenticatedScanner) checkChromedpAvailable() bool {
	// First, try exec.LookPath for dynamic browser detection (most reliable)
	browserNames := []string{"chrome", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable"}
	for _, name := range browserNames {
		if path, err := exec.LookPath(name); err == nil && path != "" {
			return true
		}
	}

	// Fallback: check well-known paths for systems where PATH isn't configured
	chromePaths := []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		os.Getenv("LOCALAPPDATA") + `\Google\Chrome\Application\chrome.exe`,
		`/usr/bin/google-chrome`,
		`/usr/bin/chromium-browser`,
		`/usr/bin/chromium`,
		`/snap/bin/chromium`,
		`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
		`/Applications/Chromium.app/Contents/MacOS/Chromium`,
	}

	for _, path := range chromePaths {
		if path != "" {
			if _, err := os.Stat(path); err == nil {
				return true
			}
		}
	}
	return false
}

// stealthScript is injected to hide automation detection markers
const stealthScript = `
(function() {
    // Remove webdriver property
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true
    });
    
    // Mock chrome object for non-Chrome environments
    if (!window.chrome) {
        window.chrome = {
            runtime: {},
            loadTimes: function() {},
            csi: function() {},
            app: {}
        };
    }
    
    // Override permissions query
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
    );
    
    // Mock plugins array
    Object.defineProperty(navigator, 'plugins', {
        get: () => [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
            { name: 'Native Client', filename: 'internal-nacl-plugin' }
        ],
        configurable: true
    });
    
    // Mock languages
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
        configurable: true
    });
    
    // Hide automation-related properties
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
})();
`

// runChromedpScan runs the actual browser scan using chromedp
func (s *AuthenticatedScanner) runChromedpScan(ctx context.Context, result *BrowserScanResult, progressFn func(string)) error {
	// Build browser options - must handle headless mode carefully
	// DefaultExecAllocatorOptions includes chromedp.Headless which adds --headless
	// For visible browser, we MUST start fresh without that option
	var opts []chromedp.ExecAllocatorOption

	if s.config.ShowBrowser {
		// VISIBLE BROWSER MODE - Use defaults but skip Headless option
		if progressFn != nil {
			progressFn("Launching visible browser window")
		}

		// chromedp.DefaultExecAllocatorOptions is an array like:
		//   [0] NoFirstRun
		//   [1] NoDefaultBrowserCheck
		//   [2] Headless  ← We need to SKIP this one!
		//   [3...] Various flags
		// Copy all options except Headless to get visible browser
		defaultOpts := chromedp.DefaultExecAllocatorOptions[:]
		opts = make([]chromedp.ExecAllocatorOption, 0, len(defaultOpts)-1)

		// Copy all except Headless (skip index 2)
		opts = append(opts, defaultOpts[0]) // NoFirstRun
		opts = append(opts, defaultOpts[1]) // NoDefaultBrowserCheck
		// Skip index 2 (Headless) - this is the critical change!
		opts = append(opts, defaultOpts[3:]...) // All remaining flags

		// Add visible window options
		opts = append(opts,
			chromedp.Flag("start-maximized", true),
		)

		if progressFn != nil {
			progressFn("Browser options configured for visible mode")
		}
	} else {
		// HEADLESS MODE - Use defaults which include headless
		opts = append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
		)
	}

	// Add common stealth and appearance options
	opts = append(opts,
		// Stealth flags - hide automation detection
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-component-extensions-with-background-pages", true),
		// Additional anti-detection flags
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		// Realistic browser appearance
		chromedp.Flag("window-size", "1920,1080"),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	if s.config.UserDataDir != "" {
		opts = append(opts, chromedp.UserDataDir(s.config.UserDataDir))
	}

	// Add proxy support if configured
	if s.config.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(s.config.Proxy))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	// NOTE: allocCancel and browserCancel are called explicitly below with a
	// timeout to prevent the process freeze on Windows where Chrome child
	// processes (GPU, renderer) can block indefinitely during cleanup.

	if progressFn != nil {
		progressFn("Browser allocator initialized")
	}

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	// cancelBrowser is a helper that cancels chromedp contexts with a timeout.
	// On Windows, chromedp's allocator cancel can block waiting for Chrome
	// child processes (GPU, renderer) to exit. This wrapper ensures cleanup
	// completes within 5 seconds, then force-kills the browser process tree.
	cancelBrowser := func() {
		// Capture the browser process BEFORE cancelling contexts — after
		// cancel the process reference may be nil.
		var proc *os.Process
		if c := chromedp.FromContext(browserCtx); c != nil && c.Browser != nil {
			proc = c.Browser.Process()
		}

		done := make(chan struct{})
		go func() {
			browserCancel()
			allocCancel()
			close(done)
		}()
		select {
		case <-done:
			// Clean shutdown
		case <-time.After(5 * time.Second):
			// Graceful cancel blocked — force-kill the Chrome process tree.
			if proc != nil {
				_ = proc.Kill()
			}
			if progressFn != nil {
				progressFn("Browser cleanup timed out — force-killed Chrome process")
			}
		}
	}
	defer cancelBrowser()

	if progressFn != nil {
		progressFn("Browser context created, launching...")
	}

	// Initialize storage data early
	result.StorageData = &StorageData{
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
		Cookies:        make([]CookieInfo, 0),
	}

	// Set up network event listeners to capture all requests
	chromedp.ListenTarget(browserCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			s.handleNetworkRequest(e, result)
		case *network.EventResponseReceived:
			s.handleNetworkResponse(e, result)
		}
	})

	// Navigate to target and wait for user login
	if progressFn != nil {
		progressFn("Opening browser - please log in within " + s.config.WaitForLogin.String())
	}

	// Inject stealth script before navigation to hide automation markers
	// This runs on every page load via AddScriptToEvaluateOnNewDocument
	err := chromedp.Run(browserCtx,
		network.Enable(),
		// Inject custom headers (e.g., X-Bug-Bounty for researcher identification)
		chromedp.ActionFunc(func(ctx context.Context) error {
			if len(s.config.CustomHeaders) > 0 {
				headers := make(network.Headers)
				for k, v := range s.config.CustomHeaders {
					headers[k] = v
				}
				return network.SetExtraHTTPHeaders(headers).Do(ctx)
			}
			return nil
		}),
		// Inject stealth script to run on every new document (including navigations)
		// Only inject if StealthMode is enabled (hides automation markers from WAFs)
		chromedp.ActionFunc(func(ctx context.Context) error {
			if s.config.StealthMode {
				_, err := page.AddScriptToEvaluateOnNewDocument(stealthScript).Do(ctx)
				return err
			}
			return nil
		}),
		chromedp.Navigate(s.config.TargetURL),
	)
	if err != nil {
		return fmt.Errorf("navigation failed: %w", err)
	}

	// Detect auth flow from initial page
	result.AuthFlowInfo = s.detectAuthFlow(s.config.TargetURL)

	// Wait for authentication (detect login success)
	loginCtx, loginCancel := context.WithTimeout(browserCtx, s.config.WaitForLogin)
	defer loginCancel()

	if progressFn != nil {
		progressFn("Waiting for user authentication...")
		progressFn(">>> LOG IN NOW - browser will continue after detecting auth tokens <<<")
	}

	// Minimum wait before checking auth - prevents false positives from initial page load
	// User needs time to actually log in, and SPAs can briefly show target URL during redirect
	minWaitTime := duration.BrowserMinWait
	startTime := time.Now()

	// Poll for login indicators
	authenticated := false
	checkCount := 0
	for !authenticated {
		select {
		case <-loginCtx.Done():
			return fmt.Errorf("login timeout - user did not authenticate within %s", s.config.WaitForLogin)
		default:
			checkCount++
			// Only start auth detection after minimum wait time
			elapsed := time.Since(startTime)
			if elapsed < minWaitTime {
				// Still in minimum wait period - just wait
				time.Sleep(duration.RetryFast)
				continue
			}

			// Collect current storage/cookies for auth detection
			var localStorageData, sessionStorageData string
			_ = chromedp.Run(browserCtx,
				chromedp.Evaluate(`JSON.stringify(Object.fromEntries(Object.entries(localStorage)))`, &localStorageData),
				chromedp.Evaluate(`JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))`, &sessionStorageData),
			)
			s.mu.Lock()
			s.parseStorageData(localStorageData, sessionStorageData, result)
			s.mu.Unlock()

			// Get current cookies
			_ = chromedp.Run(browserCtx, chromedp.ActionFunc(func(ctx context.Context) error {
				cookies, err := storage.GetCookies().Do(ctx)
				if err != nil {
					return err
				}
				s.mu.Lock()
				defer s.mu.Unlock()
				result.StorageData.Cookies = make([]CookieInfo, 0, len(cookies))
				for _, c := range cookies {
					result.StorageData.Cookies = append(result.StorageData.Cookies, CookieInfo{
						Name:     c.Name,
						Domain:   c.Domain,
						Path:     c.Path,
						Secure:   c.Secure,
						HTTPOnly: c.HTTPOnly,
						SameSite: c.SameSite.String(),
					})
				}
				return nil
			}))

			// After min wait, check for auth success indicators
			var currentURL string
			if err := chromedp.Run(browserCtx, chromedp.Location(&currentURL)); err == nil {
				if s.isAuthenticationComplete(currentURL, result) {
					result.AuthSuccessful = true
					authenticated = true
					if progressFn != nil {
						progressFn("Authentication detected - beginning authenticated scan")
					}
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Post-login delay
	time.Sleep(s.config.PostLoginDelay)

	// Extract storage data
	if progressFn != nil {
		progressFn("Extracting browser storage (localStorage, sessionStorage, cookies)...")
	}

	var localStorageData, sessionStorageData string
	_ = chromedp.Run(browserCtx,
		chromedp.Evaluate(`JSON.stringify(Object.fromEntries(Object.entries(localStorage)))`, &localStorageData),
		chromedp.Evaluate(`JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))`, &sessionStorageData),
	)

	// Parse and analyze storage (with lock for concurrent safety)
	s.mu.Lock()
	s.parseStorageData(localStorageData, sessionStorageData, result)
	s.mu.Unlock()

	// Get cookies
	_ = chromedp.Run(browserCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		cookies, err := storage.GetCookies().Do(ctx)
		if err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, c := range cookies {
			result.StorageData.Cookies = append(result.StorageData.Cookies, CookieInfo{
				Name:     c.Name,
				Domain:   c.Domain,
				Path:     c.Path,
				Secure:   c.Secure,
				HTTPOnly: c.HTTPOnly,
				SameSite: string(c.SameSite),
				Size:     len(c.Value),
			})
			// Analyze cookie for security issues
			s.analyzeCookie(c, result)
		}
		return nil
	}))

	// Crawl authenticated pages with depth-based recursive discovery
	if progressFn != nil {
		progressFn(fmt.Sprintf("Crawling authenticated pages (depth: %d)...", s.config.CrawlDepth))
	}

	visited := make(map[string]bool)
	visited[s.config.TargetURL] = true
	maxLinks := 50 // Total limit to prevent excessive crawling
	visitedCount := 0

	targetParsed, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	targetHost := targetParsed.Host

	// Recursive crawl helper function
	var crawlPage func(pageURL string, currentDepth int)
	crawlPage = func(pageURL string, currentDepth int) {
		if currentDepth > s.config.CrawlDepth || visitedCount >= maxLinks {
			return
		}

		// CHROME: extract links from DOM
		var rawLinks []string
		_ = chromedp.Run(browserCtx,
			chromedp.Evaluate(`Array.from(document.querySelectorAll('a[href]')).map(a => a.href)`, &rawLinks),
		)

		// PURE: filter and sort
		filtered := s.filterCrawlLinks(rawLinks, targetHost, visited, maxLinks-visitedCount)

		for _, link := range filtered {
			if visitedCount >= maxLinks {
				if progressFn != nil {
					progressFn(fmt.Sprintf("Reached max link limit (%d), stopping crawl", maxLinks))
				}
				return
			}

			visited[link] = true
			visitedCount++

			// CHROME: navigate to link
			err := chromedp.Run(browserCtx,
				chromedp.Navigate(link),
				chromedp.Sleep(duration.RetryFast),
			)
			if err != nil {
				if s.config.Verbose && progressFn != nil {
					progressFn(fmt.Sprintf("Failed to navigate to %s: %v", extractPath(link), err))
				}
				continue
			}

			var title string
			_ = chromedp.Run(browserCtx, chromedp.Title(&title))

			// Take screenshot if enabled (useful for visual evidence in pentests)
			if s.config.EnableScreens && s.config.ScreenshotDir != "" {
				// Ensure screenshot directory exists
				if err := os.MkdirAll(s.config.ScreenshotDir, 0755); err == nil {
					var buf []byte
					if err := chromedp.Run(browserCtx, chromedp.FullScreenshot(&buf, 90)); err == nil {
						safeName := strings.ReplaceAll(extractPath(link), "/", "_")
						screenshotPath := fmt.Sprintf("%s/%s_%d.png", s.config.ScreenshotDir, safeName, time.Now().UnixNano())
						if err := os.WriteFile(screenshotPath, buf, 0644); err == nil {
							result.Screenshots = append(result.Screenshots, screenshotPath)
						}
					}
				}
			}

			// PURE: build route
			route := buildDiscoveredRoute(link, title, currentDepth)
			s.mu.Lock()
			result.DiscoveredRoutes = append(result.DiscoveredRoutes, route)
			s.mu.Unlock()

			// Recursively crawl this page for more links
			if currentDepth < s.config.CrawlDepth {
				crawlPage(link, currentDepth+1)
			}
		}
	}

	// Start recursive crawl from depth 1
	crawlPage(s.config.TargetURL, 1)

	if progressFn != nil {
		s.mu.Lock()
		routeCount := len(result.DiscoveredRoutes)
		tokenCount := len(result.ExposedTokens)
		apiCount := len(result.ThirdPartyAPIs)
		s.mu.Unlock()
		progressFn(formatScanSummary(routeCount, tokenCount, apiCount))
	}

	return nil
}

// analyzeCookie checks a cookie for security issues
func (s *AuthenticatedScanner) analyzeCookie(c *network.Cookie, result *BrowserScanResult) {
	// Check for session tokens in cookies without proper flags
	nameLower := strings.ToLower(c.Name)
	isSessionCookie := strings.Contains(nameLower, "session") ||
		strings.Contains(nameLower, "token") ||
		strings.Contains(nameLower, "auth") ||
		strings.Contains(nameLower, "jwt")

	if isSessionCookie {
		var issues []string
		if !c.Secure {
			issues = append(issues, "Missing Secure flag")
		}
		if !c.HTTPOnly {
			issues = append(issues, "Missing HttpOnly flag")
		}
		if c.SameSite == "" || c.SameSite == "None" {
			issues = append(issues, "SameSite not set or None")
		}

		if len(issues) > 0 {
			result.addTokenIfUnique(ExposedToken{
				Type:     "Session Cookie",
				Key:      c.Name,
				Location: fmt.Sprintf("Cookie (domain: %s)", c.Domain),
				Severity: "medium",
				Risk:     strings.Join(issues, "; "),
			})
		}
	}
}

// runSimulatedScan provides URL-based auth flow detection without real browser
// Note: No actual HTTP requests are made - only URL pattern analysis
func (s *AuthenticatedScanner) runSimulatedScan(ctx context.Context, result *BrowserScanResult, progressFn func(string)) {
	if progressFn != nil {
		progressFn("Running URL-based auth flow detection (no browser available)...")
	}

	// Detect auth flow from URL patterns (no HTTP requests)
	result.AuthFlowInfo = s.detectAuthFlow(s.config.TargetURL)

	// Initialize empty storage data
	result.StorageData = &StorageData{
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
		Cookies:        make([]CookieInfo, 0),
	}

	if progressFn != nil {
		progressFn("Note: Full browser scanning requires Chrome/Chromium installed")
		progressFn("Only URL pattern analysis performed - no network requests made")
	}

	// Mark as requiring manual verification since no browser was available
	result.AuthSuccessful = false
}

// detectAuthFlow analyzes a URL to detect authentication flow patterns
func (s *AuthenticatedScanner) detectAuthFlow(targetURL string) *AuthFlowInfo {
	info := &AuthFlowInfo{
		Metadata: make(map[string]string),
	}

	urlLower := strings.ToLower(targetURL)

	// Microsoft/Azure AD patterns
	if strings.Contains(urlLower, "login.microsoftonline.com") ||
		strings.Contains(urlLower, "login.microsoft.com") ||
		strings.Contains(urlLower, "aad") ||
		strings.Contains(urlLower, "azure") {
		info.Provider = "Microsoft Azure AD"
		info.FlowType = "OAuth 2.0 / OIDC"
		info.LibraryUsed = "MSAL.js (likely)"
		info.AuthorizeURL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
		info.TokenEndpoint = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
	}

	// Google patterns
	if strings.Contains(urlLower, "accounts.google.com") {
		info.Provider = "Google"
		info.FlowType = "OAuth 2.0"
		info.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	}

	// Okta patterns
	if strings.Contains(urlLower, "okta.com") || strings.Contains(urlLower, "oktapreview.com") {
		info.Provider = "Okta"
		info.FlowType = "OAuth 2.0 / OIDC"
	}

	// Auth0 patterns
	if strings.Contains(urlLower, "auth0.com") {
		info.Provider = "Auth0"
		info.FlowType = "OAuth 2.0 / OIDC"
	}

	// Keycloak patterns
	if strings.Contains(urlLower, "keycloak") {
		info.Provider = "Keycloak"
		info.FlowType = "OAuth 2.0 / OIDC"
	}

	// Default
	if info.Provider == "" {
		info.Provider = "Custom/Unknown"
		info.FlowType = "Unknown"
	}

	return info
}

// analyzeToken examines a token value and returns classification
func (s *AuthenticatedScanner) analyzeToken(key, value, location string) *ExposedToken {
	token := &ExposedToken{
		Key:       key,
		Location:  location,
		Timestamp: time.Now(),
		FullValue: value,
	}

	// Truncate for display
	if len(value) > 50 {
		token.Value = value[:25] + "..." + value[len(value)-15:]
	} else {
		token.Value = value
	}

	// JWT detection
	if strings.Count(value, ".") == 2 && len(value) > 50 {
		token.Type = "jwt"
		token.Severity = "critical"
		token.Risk = "JWT stored in " + location + " - vulnerable to XSS token theft"

		// Try to decode JWT header/payload (not signature)
		parts := strings.Split(value, ".")
		if len(parts) >= 2 {
			// Could decode and extract claims here
			token.Permissions = []string{"(decode JWT to see permissions)"}
		}
		return token
	}

	// Bearer token patterns
	keyLower := strings.ToLower(key)
	if strings.Contains(keyLower, "bearer") || strings.Contains(keyLower, "access_token") ||
		strings.Contains(keyLower, "accesstoken") {
		token.Type = "bearer"
		token.Severity = "critical"
		token.Risk = "Bearer/access token exposed in " + location
		return token
	}

	// API key patterns
	if strings.Contains(keyLower, "api_key") || strings.Contains(keyLower, "apikey") ||
		strings.Contains(keyLower, "api-key") || strings.Contains(keyLower, "x-api-key") {
		token.Type = "api_key"
		token.Severity = "high"
		token.Risk = "API key exposed in " + location
		return token
	}

	// Session token patterns
	if strings.Contains(keyLower, "session") || strings.Contains(keyLower, "sid") {
		token.Type = "session"
		token.Severity = "high"
		token.Risk = "Session token exposed in " + location
		return token
	}

	// OAuth tokens
	if strings.Contains(keyLower, "oauth") || strings.Contains(keyLower, "refresh") {
		token.Type = "oauth"
		token.Severity = "critical"
		token.Risk = "OAuth token exposed in " + location
		return token
	}

	// CSRF tokens (lower severity, expected behavior)
	if strings.Contains(keyLower, "csrf") || strings.Contains(keyLower, "xsrf") {
		token.Type = "csrf"
		token.Severity = "low"
		token.Risk = "CSRF token in " + location + " (expected, verify secure usage)"
		return token
	}

	// Generic sensitive patterns
	if strings.Contains(keyLower, "token") || strings.Contains(keyLower, "secret") ||
		strings.Contains(keyLower, "password") || strings.Contains(keyLower, "credential") {
		token.Type = "sensitive"
		token.Severity = "medium"
		token.Risk = "Potentially sensitive value in " + location
		return token
	}

	return nil // Not a token of interest
}

// classifyThirdPartyAPI analyzes a URL and returns third-party API info if applicable
func (s *AuthenticatedScanner) classifyThirdPartyAPI(requestURL, targetDomain string) *ThirdPartyAPI {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return nil
	}

	reqDomain := parsed.Hostname()

	// Skip same-domain requests - use proper subdomain matching
	// "api.example.com" and "example.com" -> reqDomain should end with "."+targetDomain or be equal
	if reqDomain == targetDomain ||
		strings.HasSuffix(reqDomain, "."+targetDomain) ||
		strings.HasSuffix(targetDomain, "."+reqDomain) {
		return nil
	}

	api := &ThirdPartyAPI{
		BaseURL:   parsed.Scheme + "://" + parsed.Host,
		Endpoints: []string{parsed.Path},
	}

	// Classify known services
	domainLower := strings.ToLower(reqDomain)

	// Microsoft Graph API
	if strings.Contains(domainLower, "graph.microsoft.com") {
		api.Name = "Microsoft Graph API"
		api.RequestType = "api"
		api.AuthMethod = "OAuth 2.0"
		api.Severity = "medium"
		return api
	}

	// Azure services
	if strings.Contains(domainLower, "azure") || strings.Contains(domainLower, "microsoft") {
		api.Name = "Microsoft/Azure Services"
		api.RequestType = "api"
		api.Severity = "medium"
		return api
	}

	// SAP
	if strings.Contains(domainLower, "sap.com") || strings.Contains(domainLower, "sapcloud") {
		api.Name = "SAP"
		api.RequestType = "api"
		api.Severity = "high"
		api.DataSent = []string{"business data"}
		return api
	}

	// ServiceNow
	if strings.Contains(domainLower, "servicenow") || strings.Contains(domainLower, "service-now") {
		api.Name = "ServiceNow"
		api.RequestType = "api"
		api.Severity = "medium"
		return api
	}

	// SharePoint
	if strings.Contains(domainLower, "sharepoint") {
		api.Name = "SharePoint"
		api.RequestType = "api"
		api.Severity = "medium"
		return api
	}

	// Analytics/Tracking
	if strings.Contains(domainLower, "analytics") || strings.Contains(domainLower, "tracking") ||
		strings.Contains(domainLower, "telemetry") || strings.Contains(domainLower, "segment") ||
		strings.Contains(domainLower, "mixpanel") || strings.Contains(domainLower, "amplitude") {
		api.Name = "Analytics/Telemetry"
		api.RequestType = "tracking"
		api.Severity = "low"
		return api
	}

	// Google services
	if strings.Contains(domainLower, "googleapis.com") || strings.Contains(domainLower, "google.com") {
		api.Name = "Google Services"
		api.RequestType = "api"
		api.Severity = "low"
		return api
	}

	// AWS
	if strings.Contains(domainLower, "amazonaws.com") || strings.Contains(domainLower, "aws.") {
		api.Name = "AWS"
		api.RequestType = "api"
		api.Severity = "medium"
		return api
	}

	// CDNs (low priority)
	if strings.Contains(domainLower, "cdn") || strings.Contains(domainLower, "cloudfront") ||
		strings.Contains(domainLower, "akamai") || strings.Contains(domainLower, "cloudflare") {
		return nil // Ignore CDNs
	}

	// Unknown third party
	api.Name = "Unknown: " + reqDomain
	api.RequestType = "unknown"
	api.Severity = "low"
	return api
}

// filterCrawlLinks filters raw page links for crawling: removes visited,
// ignored, and cross-origin links, then sorts by focus pattern priority.
// Returns at most maxRemaining links.
func (s *AuthenticatedScanner) filterCrawlLinks(
	rawLinks []string,
	targetHost string,
	visited map[string]bool,
	maxRemaining int,
) []string {
	if len(rawLinks) == 0 || maxRemaining <= 0 {
		return nil
	}

	// Sort links to prioritize FocusPatterns (e.g., /api/, /admin/)
	if len(s.config.FocusPatterns) > 0 {
		sort.SliceStable(rawLinks, func(i, j int) bool {
			iPriority := s.matchesFocusPattern(rawLinks[i])
			jPriority := s.matchesFocusPattern(rawLinks[j])
			return iPriority && !jPriority
		})
	}

	seen := make(map[string]bool)
	var result []string
	for _, link := range rawLinks {
		if len(result) >= maxRemaining {
			break
		}
		if seen[link] || visited[link] || s.shouldIgnoreURL(link) {
			continue
		}
		linkParsed, err := url.Parse(link)
		if err != nil {
			continue
		}
		if linkParsed.Host != targetHost {
			continue
		}
		seen[link] = true
		result = append(result, link)
	}
	return result
}

// buildDiscoveredRoute creates a DiscoveredRoute from crawl data.
func buildDiscoveredRoute(link, title string, depth int) DiscoveredRoute {
	return DiscoveredRoute{
		FullURL:       link,
		Path:          extractPath(link),
		Method:        "GET",
		RequiresAuth:  true,
		PageTitle:     title,
		DiscoveredVia: fmt.Sprintf("browser_crawl_depth_%d", depth),
	}
}

// formatScanSummary creates the final scan progress message.
func formatScanSummary(routeCount, tokenCount, apiCount int) string {
	return fmt.Sprintf("Discovered %d routes, %d tokens, %d third-party APIs",
		routeCount, tokenCount, apiCount)
}

// handleNetworkRequest processes network request events from chromedp
func (s *AuthenticatedScanner) handleNetworkRequest(e *network.EventRequestWillBeSent, result *BrowserScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req := NetworkRequest{
		RequestID: string(e.RequestID), // Use RequestID for proper correlation
		URL:       e.Request.URL,
		Method:    e.Request.Method,
		Headers:   make(map[string]string),
		Timestamp: time.Now(),
		IsXHR:     e.Type == network.ResourceTypeXHR,
		IsFetch:   e.Type == network.ResourceTypeFetch,
	}

	// Populate PostData if present
	if e.Request.HasPostData && len(e.Request.PostDataEntries) > 0 {
		var postDataParts []string
		for _, entry := range e.Request.PostDataEntries {
			if entry.Bytes != "" {
				postDataParts = append(postDataParts, entry.Bytes)
			}
		}
		req.PostData = strings.Join(postDataParts, "")
	}

	// Copy headers
	for k, v := range e.Request.Headers {
		if str, ok := v.(string); ok {
			req.Headers[k] = str
		}
	}

	// Check if it's an API call
	if strings.Contains(e.Request.URL, "/api/") || req.IsXHR || req.IsFetch {
		req.IsAPI = true
	}

	// Check if it's a third-party request using Hostname() (excludes port)
	parsed, err := url.Parse(e.Request.URL)
	if err == nil {
		targetParsed, _ := url.Parse(s.config.TargetURL)
		if targetParsed != nil {
			reqHostname := parsed.Hostname()
			targetHostname := targetParsed.Hostname()

			// Use Hostname() for proper same-origin check (ignores port)
			if reqHostname != targetHostname &&
				!strings.HasSuffix(reqHostname, "."+targetHostname) &&
				!strings.HasSuffix(targetHostname, "."+reqHostname) {
				req.IsThirdParty = true

				// Classify third-party API
				if api := s.classifyThirdPartyAPI(e.Request.URL, targetHostname); api != nil {
					// Check if already added
					found := false
					for _, existing := range result.ThirdPartyAPIs {
						if existing.Name == api.Name {
							found = true
							break
						}
					}
					if !found {
						result.ThirdPartyAPIs = append(result.ThirdPartyAPIs, *api)
					}
				}
			}
		}
	}

	// Look for tokens in headers
	for name, value := range req.Headers {
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, "authorization") ||
			strings.Contains(nameLower, "x-api-key") ||
			strings.Contains(nameLower, "x-auth-token") {
			if token := s.analyzeToken(name, value, "Request Header: "+e.Request.URL); token != nil {
				result.addTokenIfUnique(*token)
			}
		}
	}

	// Limit network requests with smart filtering - drop low-value assets first
	const maxNetworkRequests = 1000
	if len(result.NetworkRequests) < maxNetworkRequests {
		// Filter out low-value static assets to preserve capacity for important requests
		if !isLowValueAsset(e.Request.URL) {
			// Initialize request index map for O(1) response matching
			if result.requestIndexMap == nil {
				result.requestIndexMap = make(map[string]int)
			}
			// Store index by RequestID for proper correlation (handles duplicate URLs)
			result.requestIndexMap[string(e.RequestID)] = len(result.NetworkRequests)
			result.NetworkRequests = append(result.NetworkRequests, req)
		}
	}

	// Add as discovered route if it's an API on the same domain
	if req.IsAPI && !req.IsThirdParty && !s.shouldIgnoreURL(e.Request.URL) {
		path := extractPath(e.Request.URL)
		routeKey := req.Method + ":" + path

		// Initialize map if needed
		if result.routeMap == nil {
			result.routeMap = make(map[string]bool)
		}

		// O(1) deduplication using map
		if !result.routeMap[routeKey] {
			result.routeMap[routeKey] = true
			result.DiscoveredRoutes = append(result.DiscoveredRoutes, DiscoveredRoute{
				Path:          path,
				FullURL:       e.Request.URL,
				Method:        req.Method,
				RequiresAuth:  true,
				DiscoveredVia: "network_capture",
				Category:      "api",
			})
		}
	}
}

// handleNetworkResponse processes network response events from chromedp
func (s *AuthenticatedScanner) handleNetworkResponse(e *network.EventResponseReceived, result *BrowserScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// O(1) lookup using RequestID for proper correlation (handles duplicate URLs)
	requestID := string(e.RequestID)
	if result.requestIndexMap != nil {
		if idx, exists := result.requestIndexMap[requestID]; exists && idx < len(result.NetworkRequests) {
			req := &result.NetworkRequests[idx]
			req.ResponseCode = int(e.Response.Status)
			req.ResponseType = e.Response.MimeType
			req.Size = int64(e.Response.EncodedDataLength)

			// Calculate duration from Timing if available
			if e.Response.Timing != nil {
				// Timing.ReceiveHeadersEnd is the time to receive response headers
				req.Duration = time.Duration(e.Response.Timing.ReceiveHeadersEnd) * time.Millisecond
			}
			return
		}
	}

	// Fallback to linear search by RequestID (shouldn't happen if map is properly maintained)
	for i := range result.NetworkRequests {
		if result.NetworkRequests[i].RequestID == requestID {
			result.NetworkRequests[i].ResponseCode = int(e.Response.Status)
			result.NetworkRequests[i].ResponseType = e.Response.MimeType
			result.NetworkRequests[i].Size = int64(e.Response.EncodedDataLength)
			if e.Response.Timing != nil {
				result.NetworkRequests[i].Duration = time.Duration(e.Response.Timing.ReceiveHeadersEnd) * time.Millisecond
			}
			break
		}
	}
}

// isAuthenticationComplete checks if user has completed login
func (s *AuthenticatedScanner) isAuthenticationComplete(currentURL string, result *BrowserScanResult) bool {
	// External IdP domains that indicate we're still authenticating
	loginDomains := []string{
		"microsoftonline.com", "accounts.google.com", "okta.com",
		"auth0.com", "login.microsoft.com", "login.live.com",
	}

	currentLower := strings.ToLower(currentURL)

	// Check if still on external IdP domain - definitely not authenticated yet
	for _, idpDomain := range loginDomains {
		if strings.Contains(currentLower, idpDomain) {
			return false // Still on IdP, not authenticated yet
		}
	}

	// IMPORTANT: We no longer use URL-based detection alone (too many false positives with SPAs)
	// Instead, we require actual authentication evidence: tokens in storage or auth cookies

	// Check if we've captured any authentication tokens (with lock for concurrent safety)
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check for real auth tokens
	if len(result.ExposedTokens) > 0 {
		for _, token := range result.ExposedTokens {
			// Match lowercase types set by analyzeToken()
			if token.Type == "jwt" || token.Type == "bearer" || token.Type == "session" || token.Type == "oauth" {
				return true
			}
		}
	}

	// Check for session cookies that indicate successful authentication
	if result.StorageData != nil {
		for _, cookie := range result.StorageData.Cookies {
			cookieNameLower := strings.ToLower(cookie.Name)
			// These cookie patterns strongly indicate authenticated session
			if strings.Contains(cookieNameLower, "session") ||
				strings.Contains(cookieNameLower, "authtoken") ||
				strings.Contains(cookieNameLower, "accesstoken") ||
				strings.Contains(cookieNameLower, "id_token") ||
				strings.Contains(cookieNameLower, "msal") { // Microsoft Auth Library
				return true
			}
		}

		// Check localStorage/sessionStorage for auth tokens
		authStorageKeys := []string{"token", "accesstoken", "id_token", "msal", "auth"}
		for key := range result.StorageData.LocalStorage {
			keyLower := strings.ToLower(key)
			for _, authKey := range authStorageKeys {
				if strings.Contains(keyLower, authKey) {
					return true
				}
			}
		}
		for key := range result.StorageData.SessionStorage {
			keyLower := strings.ToLower(key)
			for _, authKey := range authStorageKeys {
				if strings.Contains(keyLower, authKey) {
					return true
				}
			}
		}
	}

	return false
}

// parseStorageData parses localStorage and sessionStorage JSON strings
func (s *AuthenticatedScanner) parseStorageData(localStorageJSON, sessionStorageJSON string, result *BrowserScanResult) {
	if result.StorageData == nil {
		result.StorageData = &StorageData{
			LocalStorage:   make(map[string]string),
			SessionStorage: make(map[string]string),
			Cookies:        make([]CookieInfo, 0),
		}
	}

	// Parse localStorage
	if localStorageJSON != "" && localStorageJSON != "{}" {
		var localStorage map[string]string
		if err := json.Unmarshal([]byte(localStorageJSON), &localStorage); err == nil {
			result.StorageData.LocalStorage = localStorage

			// Analyze each item for sensitive data
			for key, value := range localStorage {
				if token := s.analyzeToken(key, value, "localStorage"); token != nil {
					result.addTokenIfUnique(*token)
				}
			}
		}
	}

	// Parse sessionStorage
	if sessionStorageJSON != "" && sessionStorageJSON != "{}" {
		var sessionStorage map[string]string
		if err := json.Unmarshal([]byte(sessionStorageJSON), &sessionStorage); err == nil {
			result.StorageData.SessionStorage = sessionStorage

			// Analyze each item for sensitive data
			for key, value := range sessionStorage {
				if token := s.analyzeToken(key, value, "sessionStorage"); token != nil {
					result.addTokenIfUnique(*token)
				}
			}
		}
	}
}

// shouldIgnoreURL checks if a URL should be ignored based on config patterns
func (s *AuthenticatedScanner) shouldIgnoreURL(urlStr string) bool {
	// Use pre-compiled patterns for better performance
	for _, re := range s.ignorePatterns {
		if re.MatchString(urlStr) {
			return true
		}
	}
	return false
}

// matchesFocusPattern checks if a URL matches any configured focus patterns
// Focus patterns prioritize interesting endpoints like /api/, /admin/, /graphql
func (s *AuthenticatedScanner) matchesFocusPattern(urlStr string) bool {
	for _, pattern := range s.config.FocusPatterns {
		if strings.Contains(urlStr, pattern) {
			return true
		}
	}
	return false
}

// calculateRiskSummary computes overall risk from findings
func (s *AuthenticatedScanner) calculateRiskSummary(result *BrowserScanResult) *RiskSummary {
	summary := &RiskSummary{
		TopRisks:        make([]string, 0),
		Recommendations: make([]string, 0),
	}

	// Count by severity
	for _, token := range result.ExposedTokens {
		switch token.Severity {
		case "critical":
			summary.CriticalCount++
			summary.TopRisks = append(summary.TopRisks, fmt.Sprintf("CRITICAL: %s - %s", token.Type, token.Risk))
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	for _, api := range result.ThirdPartyAPIs {
		switch api.Severity {
		case "high":
			summary.HighCount++
			summary.TopRisks = append(summary.TopRisks, fmt.Sprintf("HIGH: Third-party API %s may expose sensitive data", api.Name))
		case "medium":
			summary.MediumCount++
		}
	}

	summary.TotalFindings = summary.CriticalCount + summary.HighCount + summary.MediumCount + summary.LowCount

	// Determine overall risk
	if summary.CriticalCount > 0 {
		summary.OverallRisk = "critical"
	} else if summary.HighCount > 0 {
		summary.OverallRisk = "high"
	} else if summary.MediumCount > 0 {
		summary.OverallRisk = "medium"
	} else {
		summary.OverallRisk = "low"
	}

	// Generate recommendations
	if summary.CriticalCount > 0 {
		summary.Recommendations = append(summary.Recommendations,
			"URGENT: Review all critical findings immediately",
			"Consider moving tokens from localStorage to httpOnly cookies",
		)
	}

	if len(result.ThirdPartyAPIs) > 5 {
		summary.Recommendations = append(summary.Recommendations,
			"Review third-party integrations - "+fmt.Sprintf("%d detected", len(result.ThirdPartyAPIs)),
		)
	}

	// Limit top risks
	if len(summary.TopRisks) > 5 {
		summary.TopRisks = summary.TopRisks[:5]
	}

	return summary
}

// SaveResult saves the browser scan result to a JSON file
func (r *BrowserScanResult) SaveResult(filepath string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	// Use 0600 permissions - scan results may contain sensitive token info
	return os.WriteFile(filepath, data, 0600)
}

// GetSortedRoutes returns routes sorted by path
func (r *BrowserScanResult) GetSortedRoutes() []DiscoveredRoute {
	routes := make([]DiscoveredRoute, len(r.DiscoveredRoutes))
	copy(routes, r.DiscoveredRoutes)
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Path < routes[j].Path
	})
	return routes
}

// GetCriticalTokens returns only critical severity tokens
func (r *BrowserScanResult) GetCriticalTokens() []ExposedToken {
	critical := make([]ExposedToken, 0)
	for _, t := range r.ExposedTokens {
		if t.Severity == "critical" {
			critical = append(critical, t)
		}
	}
	return critical
}

// extractPath extracts the path from a full URL
func extractPath(fullURL string) string {
	parsed, err := url.Parse(fullURL)
	if err != nil {
		return fullURL
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	return path
}

// isLowValueAsset checks if a URL points to a static asset with low security value
// These are filtered to preserve network request capacity for API calls
func isLowValueAsset(urlStr string) bool {
	urlLower := strings.ToLower(urlStr)

	// File extensions that are low-value for security testing
	lowValueExtensions := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".css", ".map",
		".mp3", ".mp4", ".webm", ".ogg", ".wav",
		".pdf",
	}

	for _, ext := range lowValueExtensions {
		if strings.HasSuffix(urlLower, ext) {
			return true
		}
	}

	// Common third-party analytics/tracking domains
	trackingDomains := []string{
		"google-analytics.com", "googletagmanager.com",
		"facebook.com/tr", "doubleclick.net",
		"fonts.googleapis.com", "fonts.gstatic.com",
		"cdn.jsdelivr.net", "cdnjs.cloudflare.com",
		"unpkg.com", "gravatar.com",
	}

	for _, domain := range trackingDomains {
		if strings.Contains(urlLower, domain) {
			return true
		}
	}

	return false
}

// addTokenIfUnique adds a token to the result only if it's not a duplicate
// Deduplication is based on Type + Key + Location combination
func (r *BrowserScanResult) addTokenIfUnique(token ExposedToken) bool {
	for _, existing := range r.ExposedTokens {
		if existing.Type == token.Type &&
			existing.Key == token.Key &&
			existing.Location == token.Location {
			return false // Duplicate
		}
	}
	r.ExposedTokens = append(r.ExposedTokens, token)
	return true
}
