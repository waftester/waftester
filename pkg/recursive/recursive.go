// Package recursive provides recursive fuzzing for deep content discovery
package recursive

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures recursive fuzzing
type Config struct {
	MaxDepth     int           // Maximum recursion depth
	Concurrency  int           // Worker count
	Timeout      time.Duration // Request timeout
	MaxResults   int           // Max results per level
	Wordlist     []string      // Words to fuzz
	Extensions   []string      // File extensions to try
	ExcludeRegex string        // Exclude URLs matching regex
	IncludeRegex string        // Only include URLs matching regex
	FollowLinks  bool          // Extract and follow links
	Delay        time.Duration // Delay between requests
	UserAgent    string        // Custom user agent
	Headers      http.Header   // Custom headers
	SuccessCodes []int         // Status codes to consider success
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		MaxDepth:     3,
		Concurrency:  10,
		Timeout:      10 * time.Second,
		MaxResults:   1000,
		Extensions:   []string{"", ".html", ".php", ".asp", ".aspx", ".jsp", ".json", ".xml"},
		FollowLinks:  true,
		Delay:        100 * time.Millisecond,
		UserAgent:    "Mozilla/5.0 (compatible; FuzzBot/1.0)",
		SuccessCodes: []int{200, 201, 204, 301, 302, 307, 308, 401, 403},
	}
}

// Result represents a discovered endpoint
type Result struct {
	URL         string            `json:"url"`
	Path        string            `json:"path"`
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type"`
	Length      int64             `json:"length"`
	Depth       int               `json:"depth"`
	FoundIn     string            `json:"found_in,omitempty"` // Parent URL
	Method      string            `json:"method"`
	Redirect    string            `json:"redirect,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Tags        []string          `json:"tags,omitempty"`
}

// Stats tracks fuzzing statistics
type Stats struct {
	TotalRequests int64         `json:"total_requests"`
	Found         int64         `json:"found"`
	Errors        int64         `json:"errors"`
	CurrentDepth  int32         `json:"current_depth"`
	Duration      time.Duration `json:"duration"`
	Rate          float64       `json:"requests_per_second"`
}

// Fuzzer performs recursive fuzzing
type Fuzzer struct {
	config       Config
	httpClient   *http.Client
	results      []Result
	visited      map[string]bool
	queue        chan fuzzerTask
	stats        Stats
	mu           sync.RWMutex
	startTime    time.Time
	cancel       context.CancelFunc
	excludeRegex *regexp.Regexp
	includeRegex *regexp.Regexp
}

type fuzzerTask struct {
	url       string
	path      string
	depth     int
	parentURL string
}

// NewFuzzer creates a recursive fuzzer
func NewFuzzer(config Config) (*Fuzzer, error) {
	if config.MaxDepth <= 0 {
		config.MaxDepth = 3
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if len(config.SuccessCodes) == 0 {
		config.SuccessCodes = DefaultConfig().SuccessCodes
	}

	f := &Fuzzer{
		config:  config,
		results: make([]Result, 0),
		visited: make(map[string]bool),
		queue:   make(chan fuzzerTask, 10000),
		httpClient: &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	if config.ExcludeRegex != "" {
		regex, err := regexp.Compile(config.ExcludeRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude regex: %w", err)
		}
		f.excludeRegex = regex
	}

	if config.IncludeRegex != "" {
		regex, err := regexp.Compile(config.IncludeRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid include regex: %w", err)
		}
		f.includeRegex = regex
	}

	return f, nil
}

// Run starts recursive fuzzing
func (f *Fuzzer) Run(ctx context.Context, baseURL string) ([]Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	f.cancel = cancel
	f.startTime = time.Now()

	// Normalize base URL
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < f.config.Concurrency; i++ {
		wg.Add(1)
		go f.worker(ctx, &wg)
	}

	// Seed initial tasks
	f.seedTasks(baseURL, 0)

	// Wait for completion
	go func() {
		wg.Wait()
		close(f.queue)
	}()

	// Process queue until empty
	for task := range f.queue {
		if ctx.Err() != nil {
			break
		}
		f.processTask(ctx, task)
	}

	f.stats.Duration = time.Since(f.startTime)
	if f.stats.Duration.Seconds() > 0 {
		f.stats.Rate = float64(f.stats.TotalRequests) / f.stats.Duration.Seconds()
	}

	return f.results, nil
}

// seedTasks adds initial fuzzing tasks
func (f *Fuzzer) seedTasks(baseURL string, depth int) {
	for _, word := range f.config.Wordlist {
		for _, ext := range f.config.Extensions {
			path := word + ext
			f.addTask(baseURL, path, depth, "")
		}
	}
}

// addTask adds a task to the queue
func (f *Fuzzer) addTask(baseURL, path string, depth int, parentURL string) bool {
	fullURL := baseURL + path

	f.mu.Lock()
	if f.visited[fullURL] {
		f.mu.Unlock()
		return false
	}
	f.visited[fullURL] = true
	f.mu.Unlock()

	// Apply filters
	if f.excludeRegex != nil && f.excludeRegex.MatchString(fullURL) {
		return false
	}
	if f.includeRegex != nil && !f.includeRegex.MatchString(fullURL) {
		return false
	}

	select {
	case f.queue <- fuzzerTask{
		url:       baseURL,
		path:      path,
		depth:     depth,
		parentURL: parentURL,
	}:
		return true
	default:
		return false
	}
}

// worker processes tasks from the queue
func (f *Fuzzer) worker(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-f.queue:
			if !ok {
				return
			}
			f.processTask(ctx, task)
		}
	}
}

// processTask processes a single fuzzing task
func (f *Fuzzer) processTask(ctx context.Context, task fuzzerTask) {
	if task.depth > f.config.MaxDepth {
		return
	}

	atomic.StoreInt32(&f.stats.CurrentDepth, int32(task.depth))

	fullURL := task.url + task.path
	result, err := f.request(ctx, fullURL)
	if err != nil {
		atomic.AddInt64(&f.stats.Errors, 1)
		return
	}

	atomic.AddInt64(&f.stats.TotalRequests, 1)

	// Check if successful
	if f.isSuccess(result.StatusCode) {
		result.Depth = task.depth
		result.FoundIn = task.parentURL
		result.Path = task.path

		f.mu.Lock()
		if len(f.results) < f.config.MaxResults {
			f.results = append(f.results, result)
			atomic.AddInt64(&f.stats.Found, 1)
		}
		f.mu.Unlock()

		// Recursively fuzz discovered directories
		if f.isDirectory(result) && task.depth < f.config.MaxDepth {
			newBase := fullURL
			if !strings.HasSuffix(newBase, "/") {
				newBase += "/"
			}
			f.seedTasks(newBase, task.depth+1)
		}

		// Extract and follow links if enabled
		if f.config.FollowLinks && result.StatusCode == 200 {
			// Would extract links from body here
		}
	}

	// Apply delay
	if f.config.Delay > 0 {
		time.Sleep(f.config.Delay)
	}
}

// request makes an HTTP request
func (f *Fuzzer) request(ctx context.Context, targetURL string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return Result{}, err
	}

	// Set headers
	if f.config.UserAgent != "" {
		req.Header.Set("User-Agent", f.config.UserAgent)
	}
	for key, values := range f.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Read body to get length
	body, _ := iohelper.ReadBody(resp.Body, iohelper.LargeMaxBodySize) // Max 1MB

	result := Result{
		URL:         targetURL,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Length:      int64(len(body)),
		Method:      "GET",
		Timestamp:   time.Now(),
	}

	// Capture redirect
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.Redirect = resp.Header.Get("Location")
	}

	// Capture interesting headers
	result.Headers = make(map[string]string)
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if v := resp.Header.Get(h); v != "" {
			result.Headers[h] = v
		}
	}

	return result, nil
}

// isSuccess checks if status code is successful
func (f *Fuzzer) isSuccess(code int) bool {
	for _, c := range f.config.SuccessCodes {
		if c == code {
			return true
		}
	}
	return false
}

// isDirectory checks if result represents a directory
func (f *Fuzzer) isDirectory(result Result) bool {
	// Redirects to trailing slash indicate directory
	if result.StatusCode == 301 || result.StatusCode == 302 {
		if strings.HasSuffix(result.Redirect, "/") {
			return true
		}
	}

	// Check content type
	ct := strings.ToLower(result.ContentType)
	if strings.Contains(ct, "text/html") {
		return true
	}

	return false
}

// Stop stops the fuzzer
func (f *Fuzzer) Stop() {
	if f.cancel != nil {
		f.cancel()
	}
}

// GetStats returns current statistics
func (f *Fuzzer) GetStats() Stats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	stats := f.stats
	stats.Duration = time.Since(f.startTime)
	if stats.Duration.Seconds() > 0 {
		stats.Rate = float64(stats.TotalRequests) / stats.Duration.Seconds()
	}
	return stats
}

// GetResults returns found results
func (f *Fuzzer) GetResults() []Result {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.results
}

// LinkExtractor extracts links from HTML content
type LinkExtractor struct {
	baseURL *url.URL
}

// NewLinkExtractor creates a link extractor
func NewLinkExtractor(baseURL string) (*LinkExtractor, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &LinkExtractor{baseURL: parsed}, nil
}

// Extract extracts links from HTML content
func (e *LinkExtractor) Extract(content string) []string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`href=["']([^"']+)["']`),
		regexp.MustCompile(`src=["']([^"']+)["']`),
		regexp.MustCompile(`action=["']([^"']+)["']`),
	}

	seen := make(map[string]bool)
	var links []string

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				link := e.normalizeLink(match[1])
				if link != "" && !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	return links
}

// normalizeLink normalizes a relative/absolute link
func (e *LinkExtractor) normalizeLink(link string) string {
	// Skip external protocols
	if strings.HasPrefix(link, "javascript:") ||
		strings.HasPrefix(link, "mailto:") ||
		strings.HasPrefix(link, "data:") ||
		strings.HasPrefix(link, "#") {
		return ""
	}

	parsed, err := url.Parse(link)
	if err != nil {
		return ""
	}

	// Resolve relative URL
	resolved := e.baseURL.ResolveReference(parsed)

	// Only return same-origin links
	if resolved.Host != e.baseURL.Host {
		return ""
	}

	return resolved.String()
}

// CommonWordlists provides built-in wordlists
var CommonWordlists = map[string][]string{
	"common": {
		"admin", "administrator", "backup", "config", "console", "dashboard",
		"data", "db", "debug", "dev", "download", "error", "files", "home",
		"img", "images", "include", "js", "css", "lib", "log", "login",
		"media", "old", "private", "public", "script", "scripts", "secret",
		"secure", "server", "static", "system", "temp", "test", "tmp",
		"upload", "uploads", "user", "users", "web", "api", "v1", "v2",
	},
	"api": {
		"api", "v1", "v2", "v3", "graphql", "rest", "swagger", "openapi",
		"docs", "documentation", "users", "user", "auth", "login", "logout",
		"register", "token", "oauth", "health", "status", "info", "admin",
		"settings", "config", "webhook", "webhooks", "callback", "notify",
		"search", "query", "upload", "download", "export", "import",
	},
	"backup": {
		"backup", "bak", "old", "orig", "original", "copy", "temp", "tmp",
		".backup", ".bak", ".old", ".orig", ".save", ".swp", ".swo",
	},
}

// ResultAnalyzer analyzes fuzzing results
type ResultAnalyzer struct {
	results []Result
}

// NewResultAnalyzer creates a result analyzer
func NewResultAnalyzer(results []Result) *ResultAnalyzer {
	return &ResultAnalyzer{results: results}
}

// GroupByStatusCode groups results by status code
func (a *ResultAnalyzer) GroupByStatusCode() map[int][]Result {
	groups := make(map[int][]Result)
	for _, r := range a.results {
		groups[r.StatusCode] = append(groups[r.StatusCode], r)
	}
	return groups
}

// GroupByContentType groups results by content type
func (a *ResultAnalyzer) GroupByContentType() map[string][]Result {
	groups := make(map[string][]Result)
	for _, r := range a.results {
		ct := r.ContentType
		if idx := strings.Index(ct, ";"); idx > 0 {
			ct = ct[:idx]
		}
		groups[ct] = append(groups[ct], r)
	}
	return groups
}

// FindInteresting identifies interesting findings
func (a *ResultAnalyzer) FindInteresting() []Result {
	var interesting []Result

	interestingPatterns := []string{
		"backup", "config", "admin", "debug", ".git", ".env",
		"secret", "private", "internal", "swagger", "api/v",
	}

	for _, r := range a.results {
		for _, pattern := range interestingPatterns {
			if strings.Contains(strings.ToLower(r.Path), pattern) {
				interesting = append(interesting, r)
				break
			}
		}
	}

	return interesting
}

// Summary generates a summary of results
func (a *ResultAnalyzer) Summary() map[string]any {
	byCode := a.GroupByStatusCode()
	byType := a.GroupByContentType()
	interesting := a.FindInteresting()

	codeStats := make(map[int]int)
	for code, results := range byCode {
		codeStats[code] = len(results)
	}

	typeStats := make(map[string]int)
	for ct, results := range byType {
		typeStats[ct] = len(results)
	}

	return map[string]any{
		"total":           len(a.results),
		"by_status_code":  codeStats,
		"by_content_type": typeStats,
		"interesting":     len(interesting),
	}
}

// SortByLength sorts results by content length
func (a *ResultAnalyzer) SortByLength() []Result {
	sorted := make([]Result, len(a.results))
	copy(sorted, a.results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Length > sorted[j].Length
	})
	return sorted
}

// Filter filters results by predicate
func (a *ResultAnalyzer) Filter(predicate func(Result) bool) []Result {
	var filtered []Result
	for _, r := range a.results {
		if predicate(r) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
