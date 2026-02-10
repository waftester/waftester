// Package fuzz provides directory and content fuzzing capabilities
// Similar to ffuf, gobuster, and dirsearch
package fuzz

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/bufpool"
	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
	"golang.org/x/time/rate"
)

// Config holds fuzzing configuration
type Config struct {
	attackconfig.Base

	// Target
	TargetURL string // URL with FUZZ keyword

	// Wordlist
	Words []string // Words to fuzz

	// Execution
	RateLimit  int  // Requests per second
	SkipVerify bool // Skip TLS verification

	// HTTP
	Method      string            // HTTP method (default: GET)
	Headers     map[string]string // Custom headers
	Data        string            // POST data (can contain FUZZ)
	Cookies     string            // Cookies to send
	FollowRedir bool              // Follow redirects

	// Network options
	Proxy   string        // HTTP/SOCKS5 proxy URL
	Retries int           // Number of retries on failure
	Delay   time.Duration // Delay between requests
	Jitter  time.Duration // Random jitter for delay

	// Extensions
	Extensions []string // Extensions to append (e.g., .php, .html)

	// Filters (exclude if matched)
	FilterStatus []int          // Status codes to exclude
	FilterSize   []int          // Content lengths to exclude
	FilterWords  []int          // Word counts to exclude
	FilterLines  []int          // Line counts to exclude
	FilterRegex  *regexp.Regexp // Body regex to exclude

	// Matchers (show only if matched)
	MatchStatus []int          // Status codes to include
	MatchSize   []int          // Content lengths to include
	MatchWords  []int          // Word counts to include
	MatchLines  []int          // Line counts to include
	MatchRegex  *regexp.Regexp // Body regex to include

	// Recursion
	Recursive      bool // Enable recursive scanning
	RecursionDepth int  // Max recursion depth

	// Mode and advanced options
	Mode          string // Fuzzing mode: sniper, pitchfork, clusterbomb
	ExtractRegex  string // Regex to extract from responses
	ExtractPreset string // Preset extraction: emails, urls, ips, secrets

	// Response storage
	StoreResponses bool   // Store HTTP responses
	StoreDir       string // Directory for stored responses
	StoreMatches   bool   // Store only matching responses

	// Debug and output
	Debug   bool // Debug mode
	Verbose bool // Verbose output
}

// Result represents a single fuzz result
type Result struct {
	Input         string        `json:"input"`
	URL           string        `json:"url"`
	StatusCode    int           `json:"status_code"`
	ContentLength int           `json:"content_length"`
	WordCount     int           `json:"word_count"`
	LineCount     int           `json:"line_count"`
	ResponseTime  time.Duration `json:"response_time"`
	Redirected    bool          `json:"redirected,omitempty"`
	RedirectURL   string        `json:"redirect_url,omitempty"`
	Error         string        `json:"error,omitempty"`
	Filtered      bool          `json:"-"`
}

// Stats holds execution statistics
type Stats struct {
	TotalRequests   int64
	Matches         int64
	Filtered        int64
	Errors          int64
	StartTime       time.Time
	Duration        time.Duration
	RequestsPerSec  float64
	StatusBreakdown map[int]int
}

// Fuzzer executes fuzzing operations
type Fuzzer struct {
	config     *Config
	httpClient *http.Client
	limiter    *rate.Limiter
	detector   *detection.Detector // Connection drop and silent ban detection (v2.5.2)
}

// NewFuzzer creates a new fuzzer instance
func NewFuzzer(cfg *Config) *Fuzzer {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaults.ConcurrencyVeryHigh
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 100
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = httpclient.TimeoutProbing
	}
	if cfg.Method == "" {
		cfg.Method = "GET"
	}

	// Build HTTP client with appropriate configuration
	var clientCfg httpclient.Config
	if cfg.Proxy != "" {
		clientCfg = httpclient.WithProxy(cfg.Proxy)
	} else {
		clientCfg = httpclient.WithTimeout(cfg.Timeout)
	}
	clientCfg.Timeout = cfg.Timeout
	clientCfg.InsecureSkipVerify = cfg.SkipVerify
	clientCfg.MaxConnsPerHost = cfg.Concurrency
	clientCfg.MaxIdleConns = cfg.Concurrency * 2

	client := httpclient.New(clientCfg)

	// Override redirect policy if following redirects is enabled
	if cfg.FollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)

	fuzzer := &Fuzzer{
		config:     cfg,
		httpClient: client,
		limiter:    limiter,
	}

	// Initialize detection system (v2.5.2)
	fuzzer.detector = detection.Default()

	return fuzzer
}

// ResultCallback is called for each matching result
type ResultCallback func(result *Result)

// Run executes the fuzzing operation
func (f *Fuzzer) Run(ctx context.Context, callback ResultCallback) *Stats {
	stats := &Stats{
		StartTime:       time.Now(),
		StatusBreakdown: make(map[int]int),
	}

	// Expand words with extensions
	words := f.expandWords()

	// Create work channel
	tasks := make(chan string, f.config.Concurrency*2)
	results := make(chan *Result, f.config.Concurrency*2)

	// Track stats atomically
	var totalReqs, matches, filtered, errors int64

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < f.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
					f.limiter.Wait(ctx)
					result := f.fuzz(ctx, word)
					atomic.AddInt64(&totalReqs, 1)

					if result.Error != "" {
						atomic.AddInt64(&errors, 1)
					} else if result.Filtered {
						atomic.AddInt64(&filtered, 1)
					} else {
						atomic.AddInt64(&matches, 1)
						results <- result
					}
				}
			}
		}()
	}

	// Result collector
	var collectorWg sync.WaitGroup
	statusMu := sync.Mutex{}
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for result := range results {
			if callback != nil {
				callback(result)
			}
			statusMu.Lock()
			stats.StatusBreakdown[result.StatusCode]++
			statusMu.Unlock()
		}
	}()

	// Send words to workers
wordLoop:
	for _, word := range words {
		select {
		case <-ctx.Done():
			break wordLoop
		case tasks <- word:
		}
	}
	close(tasks)

	// Wait for workers
	wg.Wait()
	close(results)

	// Wait for collector
	collectorWg.Wait()

	// Final stats
	stats.TotalRequests = atomic.LoadInt64(&totalReqs)
	stats.Matches = atomic.LoadInt64(&matches)
	stats.Filtered = atomic.LoadInt64(&filtered)
	stats.Errors = atomic.LoadInt64(&errors)
	stats.Duration = time.Since(stats.StartTime)
	if stats.Duration.Seconds() > 0 {
		stats.RequestsPerSec = float64(stats.TotalRequests) / stats.Duration.Seconds()
	}

	return stats
}

// expandWords expands the word list with extensions
func (f *Fuzzer) expandWords() []string {
	if len(f.config.Extensions) == 0 {
		return f.config.Words
	}

	expanded := make([]string, 0, len(f.config.Words)*(len(f.config.Extensions)+1))
	for _, word := range f.config.Words {
		expanded = append(expanded, word) // Original word
		for _, ext := range f.config.Extensions {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			expanded = append(expanded, word+ext)
		}
	}
	return expanded
}

// fuzz executes a single fuzz request
func (f *Fuzzer) fuzz(ctx context.Context, word string) *Result {
	result := &Result{
		Input: word,
	}

	// Replace FUZZ keyword in URL
	targetURL := strings.ReplaceAll(f.config.TargetURL, "FUZZ", url.PathEscape(word))
	result.URL = targetURL

	// Check if host should be skipped (v2.5.2)
	if f.detector != nil {
		if skip, _ := f.detector.ShouldSkipHost(targetURL); skip {
			result.Filtered = true
			return result
		}
	}

	// Prepare request body if POST
	var body io.Reader
	if f.config.Data != "" {
		bodyData := strings.ReplaceAll(f.config.Data, "FUZZ", word)
		body = strings.NewReader(bodyData)
	}

	req, err := http.NewRequestWithContext(ctx, f.config.Method, targetURL, body)
	if err != nil {
		result.Error = err.Error()
		result.Filtered = true
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", ui.UserAgent())
	for key, val := range f.config.Headers {
		val = strings.ReplaceAll(val, "FUZZ", word)
		req.Header.Set(key, val)
	}
	if f.config.Cookies != "" {
		req.Header.Set("Cookie", strings.ReplaceAll(f.config.Cookies, "FUZZ", word))
	}

	// Execute request
	start := time.Now()
	resp, err := f.httpClient.Do(req)
	result.ResponseTime = time.Since(start)

	if err != nil {
		// Record error for detection (v2.5.2)
		if f.detector != nil {
			f.detector.RecordError(targetURL, err)
		}
		result.Error = err.Error()
		result.Filtered = true
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	result.StatusCode = resp.StatusCode

	// Read body using pooled buffers for better performance
	buf := bufpool.GetSlice(32 * 1024)
	defer bufpool.PutSlice(buf)

	bodyBytes := make([]byte, 0, 64*1024) // Start smaller, grow as needed
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			bodyBytes = append(bodyBytes, buf[:n]...)
			if len(bodyBytes) >= 1024*1024 {
				break
			}
		}
		if readErr != nil {
			break
		}
	}

	result.ContentLength = len(bodyBytes)
	// Count words and lines directly from bytes to avoid string allocation
	result.WordCount = countWords(bodyBytes)
	result.LineCount = bytes.Count(bodyBytes, []byte{'\n'}) + 1
	if len(bodyBytes) == 0 {
		result.LineCount = 0
	}

	// Convert to string only when needed for filtering
	var bodyStr string
	if f.needsBodyString() {
		bodyStr = string(bodyBytes)
	}

	// Record response for detection (v2.5.2)
	if f.detector != nil {
		f.detector.RecordResponse(targetURL, resp, result.ResponseTime, result.ContentLength)
	}

	// Check for redirect
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.Redirected = true
		result.RedirectURL = resp.Header.Get("Location")
	}

	// Apply filters
	result.Filtered = !f.shouldShow(result, bodyStr)

	return result
}

// shouldShow applies filter/match logic
func (f *Fuzzer) shouldShow(result *Result, body string) bool {
	cfg := f.config

	// === FILTER CHECKS ===
	if len(cfg.FilterStatus) > 0 {
		for _, code := range cfg.FilterStatus {
			if result.StatusCode == code {
				return false
			}
		}
	}

	if len(cfg.FilterSize) > 0 {
		for _, size := range cfg.FilterSize {
			if result.ContentLength == size {
				return false
			}
		}
	}

	if len(cfg.FilterWords) > 0 {
		for _, wc := range cfg.FilterWords {
			if result.WordCount == wc {
				return false
			}
		}
	}

	if len(cfg.FilterLines) > 0 {
		for _, lc := range cfg.FilterLines {
			if result.LineCount == lc {
				return false
			}
		}
	}

	if cfg.FilterRegex != nil && cfg.FilterRegex.MatchString(body) {
		return false
	}

	// === MATCH CHECKS ===
	hasMatchCriteria := len(cfg.MatchStatus) > 0 || len(cfg.MatchSize) > 0 ||
		len(cfg.MatchWords) > 0 || len(cfg.MatchLines) > 0 || cfg.MatchRegex != nil

	if !hasMatchCriteria {
		return true
	}

	// Check if ANY match criterion is satisfied
	if len(cfg.MatchStatus) > 0 {
		for _, code := range cfg.MatchStatus {
			if result.StatusCode == code {
				return true
			}
		}
	}

	if len(cfg.MatchSize) > 0 {
		for _, size := range cfg.MatchSize {
			if result.ContentLength == size {
				return true
			}
		}
	}

	if len(cfg.MatchWords) > 0 {
		for _, wc := range cfg.MatchWords {
			if result.WordCount == wc {
				return true
			}
		}
	}

	if len(cfg.MatchLines) > 0 {
		for _, lc := range cfg.MatchLines {
			if result.LineCount == lc {
				return true
			}
		}
	}

	if cfg.MatchRegex != nil && cfg.MatchRegex.MatchString(body) {
		return true
	}

	return false
}

// Calibration holds auto-calibration data
type Calibration struct {
	BaselineSize   int
	BaselineWords  int
	BaselineLines  int
	BaselineStatus int
	Threshold      float64 // Similarity threshold (0.0-1.0)
}

// Calibrate performs auto-calibration by sending random requests
func (f *Fuzzer) Calibrate(ctx context.Context) *Calibration {
	cal := &Calibration{
		Threshold: 0.95, // 95% similarity threshold
	}

	// Send 3 random calibration requests
	randomWords := []string{
		"waftester_calibration_" + randomString(8),
		"random_path_" + randomString(12),
		"nonexistent_" + randomString(10),
	}

	var sizes, words, lines []int
	var status int

	for _, word := range randomWords {
		result := f.fuzz(ctx, word)
		if result.StatusCode > 0 {
			sizes = append(sizes, result.ContentLength)
			words = append(words, result.WordCount)
			lines = append(lines, result.LineCount)
			status = result.StatusCode
		}
	}

	if len(sizes) > 0 {
		// Use median values
		cal.BaselineSize = median(sizes)
		cal.BaselineWords = median(words)
		cal.BaselineLines = median(lines)
		cal.BaselineStatus = status
	}

	return cal
}

// ShouldFilter returns true if the result matches the baseline (should be filtered)
func (c *Calibration) ShouldFilter(result *Result) bool {
	if c == nil || c.BaselineSize == 0 {
		return false
	}

	// Check status code first
	if result.StatusCode != c.BaselineStatus {
		return false // Different status = interesting
	}

	// Check size similarity
	sizeDiff := abs(result.ContentLength - c.BaselineSize)
	sizeThreshold := int(float64(c.BaselineSize) * (1 - c.Threshold))
	if sizeDiff > sizeThreshold {
		return false // Different enough = interesting
	}

	// Check word count similarity
	wordDiff := abs(result.WordCount - c.BaselineWords)
	if wordDiff > 5 { // Allow 5 word difference
		return false
	}

	// Matches baseline - should filter
	return true
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func median(nums []int) int {
	if len(nums) == 0 {
		return 0
	}
	// Make a copy to avoid modifying original
	sorted := make([]int, len(nums))
	copy(sorted, nums)

	// Efficient O(n log n) sort
	sort.Ints(sorted)

	// Return middle element (for even length, return lower middle)
	return sorted[len(sorted)/2]
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// countWords counts words in a byte slice without allocating a string.
// A word is a sequence of non-whitespace characters.
func countWords(b []byte) int {
	count := 0
	inWord := false
	for _, c := range b {
		isSpace := c == ' ' || c == '\t' || c == '\n' || c == '\r'
		if isSpace {
			inWord = false
		} else if !inWord {
			count++
			inWord = true
		}
	}
	return count
}

// needsBodyString returns true if filtering requires the body as a string.
func (f *Fuzzer) needsBodyString() bool {
	cfg := f.config
	return cfg.MatchRegex != nil || cfg.FilterRegex != nil
}
