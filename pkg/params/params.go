// Package params implements intelligent parameter discovery inspired by Arjun
// (https://github.com/s0md3v/Arjun). Discovers hidden API parameters through
// heuristic analysis, wordlists, and passive source mining.
package params

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

// Discoverer handles parameter discovery operations
type Discoverer struct {
	client       *http.Client
	timeout      time.Duration
	concurrency  int
	userAgent    string
	verbose      bool
	wordlistFile string
	positions    []string
}

// DiscoveredParam represents a discovered parameter
type DiscoveredParam struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"` // query, body, header, cookie
	Value      string   `json:"value,omitempty"`
	Confidence float64  `json:"confidence"` // 0.0 - 1.0
	Source     string   `json:"source"`     // wordlist, heuristic, passive, reflection
	Methods    []string `json:"methods,omitempty"`
}

// DiscoveryResult contains all discovered parameters
type DiscoveryResult struct {
	Target          string            `json:"target"`
	TotalTested     int               `json:"total_tested"`
	FoundParams     int               `json:"found_params"`
	Duration        time.Duration     `json:"duration"`
	Parameters      []DiscoveredParam `json:"parameters"`
	BySource        map[string]int    `json:"by_source"`
	ByType          map[string]int    `json:"by_type"`
	ReflectedParams []string          `json:"reflected_params"`
}

// Config configures the discoverer
type Config struct {
	attackconfig.Base
	Verbose       bool
	ChunkSize     int      // Number of params to test per request (Arjun-style)
	Methods       []string // HTTP methods to test
	CustomParams  []string // Additional params to test
	Positions     []string // Discovery positions: "query", "body", "json", "header", "cookie" (default: all)
	SkipTLSVerify bool
	WordlistFile  string       // Custom wordlist file path (empty = built-in)
	HTTPClient    *http.Client // Optional custom HTTP client (e.g., JA3-aware)
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyMedium,
			Timeout:     duration.DialTimeout,
			UserAgent:   defaults.UAChrome,
		},
		ChunkSize: 256, // Arjun default is 256
		Methods:   []string{"GET", "POST"},
		Positions: []string{"query", "body", "json", "header", "cookie"},
	}
}

// NewDiscoverer creates a new parameter discoverer
func NewDiscoverer(cfg *Config) *Discoverer {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaults.ConcurrencyMedium
	}

	// Use provided HTTPClient (e.g., JA3-aware) or create default
	var client *http.Client
	if cfg.HTTPClient != nil {
		client = cfg.HTTPClient
	} else {
		client = httpclient.New(httpclient.WithTimeout(cfg.Timeout))
	}

	positions := cfg.Positions
	if len(positions) == 0 {
		positions = []string{"query", "body", "json", "header", "cookie"}
	}

	return &Discoverer{
		client:       client,
		timeout:      cfg.Timeout,
		concurrency:  cfg.Concurrency,
		userAgent:    cfg.UserAgent,
		verbose:      cfg.Verbose,
		wordlistFile: cfg.WordlistFile,
		positions:    positions,
	}
}

// Discover performs comprehensive parameter discovery on a target
func (d *Discoverer) Discover(ctx context.Context, targetURL string, methods ...string) (*DiscoveryResult, error) {
	start := time.Now()

	if len(methods) == 0 {
		methods = []string{"GET", "POST"}
	}

	result := &DiscoveryResult{
		Target:     targetURL,
		Parameters: make([]DiscoveredParam, 0),
		BySource:   make(map[string]int),
		ByType:     make(map[string]int),
	}

	// Get baseline response for comparison
	baseline, err := d.getBaseline(ctx, targetURL, methods[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Phase 1: Passive discovery from HTML/JS
	passiveParams := d.passiveDiscovery(ctx, targetURL)
	for _, p := range passiveParams {
		p.Source = "passive"
		result.Parameters = append(result.Parameters, p)
		result.BySource["passive"]++
		result.ByType[p.Type]++
	}

	// Phase 2: Wordlist-based discovery with chunking (Arjun-style)
	wordlistParams := d.wordlistDiscovery(ctx, targetURL, methods, baseline)
	for _, p := range wordlistParams {
		result.Parameters = append(result.Parameters, p)
		result.BySource[p.Source]++
		result.ByType[p.Type]++
	}

	// Phase 2b: JSON body discovery
	if containsPosition(d.positions, "json") {
		jsonParams := d.jsonBodyDiscovery(ctx, targetURL, baseline)
		for _, p := range jsonParams {
			result.Parameters = append(result.Parameters, p)
			result.BySource[p.Source]++
			result.ByType[p.Type]++
		}
	}

	// Phase 2c: Header discovery
	if containsPosition(d.positions, "header") {
		headerParams := d.headerDiscovery(ctx, targetURL, baseline)
		for _, p := range headerParams {
			result.Parameters = append(result.Parameters, p)
			result.BySource[p.Source]++
			result.ByType[p.Type]++
		}
	}

	// Phase 2d: Cookie discovery
	if containsPosition(d.positions, "cookie") {
		cookieParams := d.cookieDiscovery(ctx, targetURL, baseline)
		for _, p := range cookieParams {
			result.Parameters = append(result.Parameters, p)
			result.BySource[p.Source]++
			result.ByType[p.Type]++
		}
	}

	// Phase 3: Reflection testing
	reflectedParams := d.testReflection(ctx, targetURL, result.Parameters)
	result.ReflectedParams = reflectedParams

	// Deduplicate and sort by confidence
	result.Parameters = d.deduplicate(result.Parameters)
	sort.Slice(result.Parameters, func(i, j int) bool {
		return result.Parameters[i].Confidence > result.Parameters[j].Confidence
	})

	result.FoundParams = len(result.Parameters)
	result.Duration = time.Since(start)

	return result, nil
}

// getBaseline gets a baseline response for comparison
func (d *Discoverer) getBaseline(ctx context.Context, targetURL string, method string) (*baselineResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", d.userAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)

	return &baselineResponse{
		StatusCode:    resp.StatusCode,
		ContentLength: len(body),
		ContentHash:   fmt.Sprintf("%x", md5.Sum(body)),
		Headers:       resp.Header,
	}, nil
}

type baselineResponse struct {
	StatusCode    int
	ContentLength int
	ContentHash   string
	Headers       http.Header
}

// passiveDiscovery extracts parameters from HTML/JS without active probing
func (d *Discoverer) passiveDiscovery(ctx context.Context, targetURL string) []DiscoveredParam {
	var params []DiscoveredParam

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return params
	}
	req.Header.Set("User-Agent", d.userAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		return params
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	content := string(body)

	// Extract from HTML forms
	formParams := extractFormParams(content)
	params = append(params, formParams...)

	// Extract from JavaScript
	jsParams := extractJSParams(content)
	params = append(params, jsParams...)

	// Extract from URLs in page
	urlParams := extractURLParams(content)
	params = append(params, urlParams...)

	return params
}

// extractFormParams extracts parameters from HTML forms
func extractFormParams(content string) []DiscoveredParam {
	var params []DiscoveredParam

	// Input fields
	inputRe := regexcache.MustGet(`<input[^>]+name=["']([^"']+)["'][^>]*>`)
	for _, match := range inputRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			params = append(params, DiscoveredParam{
				Name:       match[1],
				Type:       "body",
				Confidence: 0.9,
				Source:     "passive-form",
			})
		}
	}

	// Select fields
	selectRe := regexcache.MustGet(`<select[^>]+name=["']([^"']+)["'][^>]*>`)
	for _, match := range selectRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			params = append(params, DiscoveredParam{
				Name:       match[1],
				Type:       "body",
				Confidence: 0.9,
				Source:     "passive-form",
			})
		}
	}

	// Textarea fields
	textareaRe := regexcache.MustGet(`<textarea[^>]+name=["']([^"']+)["'][^>]*>`)
	for _, match := range textareaRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			params = append(params, DiscoveredParam{
				Name:       match[1],
				Type:       "body",
				Confidence: 0.9,
				Source:     "passive-form",
			})
		}
	}

	return params
}

// extractJSParams extracts parameters from JavaScript code
func extractJSParams(content string) []DiscoveredParam {
	var params []DiscoveredParam
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{
		// Object property access patterns
		regexcache.MustGet(`(?:params|query|data|body|payload|request)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)`),
		regexcache.MustGet(`(?:params|query|data|body|payload|request)\s*\[\s*["']([^"']+)["']\s*\]`),

		// URLSearchParams
		regexcache.MustGet(`(?:searchParams|urlParams|params)\s*\.(?:get|set|append|has)\s*\(\s*["']([^"']+)["']\s*\)`),

		// FormData
		regexcache.MustGet(`(?:formData|form)\s*\.(?:append|set|get)\s*\(\s*["']([^"']+)["']\s*`),

		// $.ajax/axios data objects
		regexcache.MustGet(`(?:data|params)\s*:\s*\{[^}]*["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*:`),

		// fetch body JSON
		regexcache.MustGet(`JSON\.stringify\s*\(\s*\{[^}]*["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*:`),

		// GraphQL variables
		regexcache.MustGet(`variables\s*:\s*\{[^}]*["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*:`),

		// Direct assignments
		regexcache.MustGet(`["']([a-zA-Z_][a-zA-Z0-9_]*)["']\s*:\s*(?:req\.|this\.|data\.)`),
	}

	for _, re := range patterns {
		for _, match := range re.FindAllStringSubmatch(content, -1) {
			if len(match) > 1 && !seen[match[1]] {
				seen[match[1]] = true
				params = append(params, DiscoveredParam{
					Name:       match[1],
					Type:       "query", // Could be body too
					Confidence: 0.7,
					Source:     "passive-js",
				})
			}
		}
	}

	return params
}

// extractURLParams extracts parameters from URLs in the content
func extractURLParams(content string) []DiscoveredParam {
	var params []DiscoveredParam
	seen := make(map[string]bool)

	// Find URLs with query strings
	urlRe := regexcache.MustGet(`[?&]([a-zA-Z_][a-zA-Z0-9_]*)=`)
	for _, match := range urlRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			params = append(params, DiscoveredParam{
				Name:       match[1],
				Type:       "query",
				Confidence: 0.8,
				Source:     "passive-url",
			})
		}
	}

	return params
}

// wordlistDiscovery tests parameters from the wordlist using chunking (Arjun-style)
func (d *Discoverer) wordlistDiscovery(ctx context.Context, targetURL string, methods []string, baseline *baselineResponse) []DiscoveredParam {
	var params []DiscoveredParam
	var mu sync.Mutex

	chunkSize := 256 // Arjun default
	words := d.getWordlist()

	// Create chunks
	var chunks [][]string
	for i := 0; i < len(words); i += chunkSize {
		end := i + chunkSize
		if end > len(words) {
			end = len(words)
		}
		chunks = append(chunks, words[i:end])
	}

	// Process chunks concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, d.concurrency)

	for _, method := range methods {
		for _, chunk := range chunks {
			wg.Add(1)
			go func(m string, c []string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				found := d.testParamChunk(ctx, targetURL, m, c, baseline)
				if len(found) > 0 {
					mu.Lock()
					params = append(params, found...)
					mu.Unlock()
				}
			}(method, chunk)
		}
	}

	wg.Wait()
	return params
}

// testParamChunk tests a chunk of parameters in a single request
func (d *Discoverer) testParamChunk(ctx context.Context, targetURL string, method string, chunk []string, baseline *baselineResponse) []DiscoveredParam {
	var found []DiscoveredParam

	// Build URL with all params in chunk
	u, err := url.Parse(targetURL)
	if err != nil {
		return found
	}

	q := u.Query()
	canary := generateCanary()

	for _, param := range chunk {
		q.Set(param, canary+param)
	}

	var req *http.Request
	if method == "GET" {
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, method, u.String(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, targetURL, strings.NewReader(q.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", defaults.ContentTypeForm)
		}
	}
	if err != nil {
		return found
	}

	req.Header.Set("User-Agent", d.userAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		return found
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	content := string(body)
	newHash := fmt.Sprintf("%x", md5.Sum(body))

	// Check if response differs from baseline
	differs := resp.StatusCode != baseline.StatusCode ||
		len(body) != baseline.ContentLength ||
		newHash != baseline.ContentHash

	if !differs {
		return found // No change, params not processed
	}

	// Binary search to find which params caused the change
	if len(chunk) > 1 {
		// Split chunk and recursively test
		mid := len(chunk) / 2
		left := d.testParamChunk(ctx, targetURL, method, chunk[:mid], baseline)
		right := d.testParamChunk(ctx, targetURL, method, chunk[mid:], baseline)
		found = append(found, left...)
		found = append(found, right...)
	} else if len(chunk) == 1 {
		// Single param - confirmed valid
		param := chunk[0]
		confidence := 0.8

		// Check for reflection
		if strings.Contains(content, canary+param) {
			confidence = 0.95
		}

		// Map HTTP method to parameter position type
		paramType := "query"
		if strings.EqualFold(method, "POST") {
			paramType = "body"
		}

		found = append(found, DiscoveredParam{
			Name:       param,
			Type:       paramType,
			Confidence: confidence,
			Source:     "wordlist",
			Methods:    []string{method},
		})
	}

	return found
}

// testReflection tests if parameters are reflected in responses
func (d *Discoverer) testReflection(ctx context.Context, targetURL string, params []DiscoveredParam) []string {
	var reflected []string

	for _, param := range params {
		canary := generateCanary()
		v := url.Values{}
		v.Set(param.Name, canary)
		testURL := fmt.Sprintf("%s?%s", targetURL, v.Encode())

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)

		if strings.Contains(string(body), canary) {
			reflected = append(reflected, param.Name)
		}
	}

	return reflected
}

// deduplicate removes duplicate parameters, keeping highest confidence
func (d *Discoverer) deduplicate(params []DiscoveredParam) []DiscoveredParam {
	seen := make(map[string]*DiscoveredParam)

	for i := range params {
		p := &params[i]
		existing, exists := seen[p.Name]
		if !exists || p.Confidence > existing.Confidence {
			seen[p.Name] = p
		}
	}

	var result []DiscoveredParam
	for _, p := range seen {
		result = append(result, *p)
	}
	return result
}

// canaryCounter provides unique canary values across concurrent goroutines.
var canaryCounter uint64

// generateCanary creates a unique string for reflection testing
func generateCanary() string {
	return fmt.Sprintf("waft%d", atomic.AddUint64(&canaryCounter, 1))
}

// getWordlist returns the wordlist to use - custom file if specified, otherwise built-in
func (d *Discoverer) getWordlist() []string {
	if d.wordlistFile != "" {
		words, err := loadWordlistFromFile(d.wordlistFile)
		if err != nil {
			if d.verbose {
				fmt.Printf("[!] Failed to load custom wordlist %s: %v, using built-in\n", d.wordlistFile, err)
			}
			return getParamWordlist()
		}
		if d.verbose {
			fmt.Printf("[*] Using custom wordlist: %s (%d words)\n", d.wordlistFile, len(words))
		}
		return words
	}
	return getParamWordlist()
}

// loadWordlistFromFile loads parameter names from a file (one per line)
func loadWordlistFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var words []string
	for _, line := range strings.Split(string(data), "\n") {
		word := strings.TrimSpace(line)
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, nil
}

// getParamWordlist returns the deduplicated parameter discovery wordlist.
// Based on Arjun's params.txt and additional research.
func getParamWordlist() []string {
	raw := []string{
		// Common authentication/session
		"id", "user", "username", "userid", "user_id", "uid", "login", "email", "mail",
		"password", "passwd", "pass", "pwd", "secret", "token", "auth", "key", "apikey",
		"api_key", "apiKey", "access_token", "accessToken", "refresh_token", "refreshToken",
		"session", "sessionid", "session_id", "sid", "jwt", "bearer", "oauth", "oauth_token",

		// Common identifiers
		"id", "Id", "ID", "uuid", "guid", "ref", "reference", "num", "number", "no",
		"code", "key", "pk", "sk", "fk", "idx", "index", "hash", "checksum",

		// Pagination/filtering
		"page", "p", "pg", "offset", "limit", "size", "pageSize", "page_size", "pageNum",
		"page_num", "perPage", "per_page", "count", "start", "end", "from", "to",
		"sort", "sortBy", "sort_by", "order", "orderBy", "order_by", "asc", "desc",
		"filter", "filters", "search", "q", "query", "keyword", "keywords", "term", "terms",

		// Common CRUD parameters
		"action", "act", "do", "cmd", "command", "op", "operation", "type", "method",
		"mode", "state", "status", "flag", "step", "stage", "phase",
		"create", "read", "update", "delete", "add", "edit", "remove", "modify",

		// Content/data
		"data", "body", "content", "text", "message", "msg", "value", "val", "values",
		"input", "output", "result", "results", "response", "request", "payload",
		"json", "xml", "html", "format", "encoding", "charset",

		// File operations
		"file", "filename", "file_name", "fileName", "path", "filepath", "file_path",
		"dir", "directory", "folder", "upload", "download", "attachment", "doc", "document",
		"image", "img", "photo", "picture", "video", "audio", "media",
		"url", "uri", "link", "href", "src", "source", "dest", "destination", "target",

		// URLs and routing
		"url", "uri", "link", "href", "redirect", "redirectUrl", "redirect_url", "returnUrl",
		"return_url", "next", "nextUrl", "next_url", "callback", "callbackUrl", "callback_url",
		"continue", "continueUrl", "continue_url", "goto", "forward", "redir",

		// API specific
		"version", "v", "ver", "api", "api_version", "apiVersion", "endpoint",
		"resource", "resources", "method", "methods", "fields", "include", "exclude",
		"expand", "embed", "projection", "select", "columns",

		// Common names
		"name", "title", "label", "description", "desc", "summary", "details",
		"first_name", "firstName", "last_name", "lastName", "full_name", "fullName",
		"display_name", "displayName", "nickname", "alias",

		// Contact info
		"email", "mail", "e_mail", "phone", "telephone", "tel", "mobile", "cell",
		"fax", "address", "addr", "street", "city", "state", "country", "zip", "postal",

		// Boolean flags
		"enabled", "disabled", "active", "inactive", "visible", "hidden", "public", "private",
		"admin", "debug", "test", "dev", "prod", "production", "verbose", "quiet",
		"force", "confirm", "preview", "draft", "live",

		// Date/time
		"date", "time", "datetime", "timestamp", "ts", "created", "updated", "modified",
		"start_date", "startDate", "end_date", "endDate", "from_date", "fromDate",
		"to_date", "toDate", "year", "month", "day", "hour", "minute", "second",

		// Numeric
		"amount", "price", "cost", "total", "subtotal", "tax", "discount", "quantity",
		"qty", "count", "number", "num", "min", "max", "avg", "sum", "length", "width",
		"height", "size", "weight", "rate", "ratio", "percent", "percentage",

		// Categories/tags
		"category", "categories", "cat", "type", "types", "tag", "tags", "class", "classes",
		"group", "groups", "topic", "topics", "subject", "label", "labels",

		// Location/geo
		"lat", "latitude", "lng", "longitude", "location", "loc", "geo", "region",
		"area", "zone", "position", "coordinates", "coords",

		// Security/permissions
		"role", "roles", "permission", "permissions", "scope", "scopes", "grant", "grants",
		"access", "level", "privilege", "privileges", "capability", "capabilities",

		// Settings/config
		"setting", "settings", "config", "configuration", "option", "options",
		"preference", "preferences", "pref", "prefs", "param", "params", "parameter",

		// Misc common
		"lang", "language", "locale", "currency", "timezone", "tz", "theme", "color",
		"template", "layout", "view", "render", "partial", "component",
		"callback", "handler", "listener", "hook", "event", "trigger",
		"cache", "refresh", "reload", "reset", "clear", "flush",
		"backup", "restore", "export", "import", "sync", "async",

		// Error handling
		"error", "errors", "err", "exception", "message", "msg", "code",
		"reason", "cause", "stack", "trace", "debug",

		// Testing
		"test", "testing", "demo", "sample", "example", "mock", "fake", "stub",
		"fixture", "seed", "dummy",

		// Version control
		"version", "revision", "rev", "build", "release", "branch", "commit", "sha",

		// Headers often passed as params
		"x_forwarded_for", "x_real_ip", "origin", "referer", "referrer",
		"user_agent", "userAgent", "accept", "content_type", "contentType",
		"authorization", "auth", "cookie", "cookies",

		// JSONP/CORS
		"callback", "jsonp", "cb", "jsonpcallback",

		// Format selection
		"format", "fmt", "output", "accept", "content_type", "_format",
		".json", ".xml", ".html", ".csv", ".pdf",

		// Framework specific
		"_token", "_csrf", "csrf_token", "csrfToken", "authenticity_token",
		"_method", "_action", "__RequestVerificationToken",

		// AWS specific
		"Action", "Version", "X-Amz-Algorithm", "X-Amz-Credential",

		// GraphQL
		"query", "mutation", "variables", "operationName", "extensions",

		// Common vulnerable parameters
		"template", "include", "require", "file", "document", "root", "path",
		"pg", "style", "pdf", "show", "doc", "site", "type", "view", "content",
		"dir", "read", "fetch", "load", "cat", "article", "page", "class",
		"parser", "php_path", "conf", "menu", "lang", "language", "locale",
	}

	// Deduplicate: the wordlist is organized by category so entries
	// intentionally appear in multiple sections for readability.
	seen := make(map[string]struct{}, len(raw))
	deduped := make([]string, 0, len(raw))
	for _, w := range raw {
		if _, dup := seen[w]; !dup {
			seen[w] = struct{}{}
			deduped = append(deduped, w)
		}
	}
	return deduped
}

// DiscoverFromJSON extracts parameters from a JSON API response
func DiscoverFromJSON(data []byte) []DiscoveredParam {
	var params []DiscoveredParam

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return params
	}

	extractKeys(obj, "", &params)
	return params
}

func extractKeys(obj map[string]interface{}, prefix string, params *[]DiscoveredParam) {
	for key, value := range obj {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		*params = append(*params, DiscoveredParam{
			Name:       fullKey,
			Type:       "body",
			Confidence: 0.85,
			Source:     "json-schema",
		})

		if nested, ok := value.(map[string]interface{}); ok {
			extractKeys(nested, fullKey, params)
		}
	}
}
