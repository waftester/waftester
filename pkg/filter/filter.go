// Package filter implements smart filtering and matching for HTTP responses
// Modeled after ffuf's powerful filter/matcher system
package filter

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config holds all filter and matcher configuration
// Based on ffuf and httpx filter systems
type Config struct {
	// Match criteria (show ONLY responses matching these)
	MatchStatus    []int             // HTTP status codes to match
	MatchSize      []Range           // Content-Length ranges
	MatchWords     []Range           // Word count ranges
	MatchLines     []Range           // Line count ranges
	MatchRegex     []*regexp.Regexp  // Body content regex patterns
	MatchString    []string          // Body contains string
	MatchTime      time.Duration     // Response time threshold (match if slower)
	MatchCDN       []string          // CDN provider names
	MatchFavicon   []string          // Favicon hashes (mmh3)
	MatchHeaders   map[string]string // Header key-value matches
	MatchCondition string            // DSL expression

	// Filter criteria (EXCLUDE responses matching these)
	FilterStatus     []int
	FilterSize       []Range
	FilterWords      []Range
	FilterLines      []Range
	FilterRegex      []*regexp.Regexp
	FilterString     []string
	FilterTime       time.Duration // Exclude if slower than
	FilterCDN        []string
	FilterDuplicates bool // Simhash-based duplicate detection
	FilterErrorPage  bool // Detect and exclude error pages
	FilterHeaders    map[string]string

	// Modes
	MatchMode  Mode // "and" | "or" - how to combine match criteria
	FilterMode Mode // "and" | "or" - how to combine filter criteria
}

// Mode defines how multiple criteria are combined
type Mode string

const (
	ModeAnd Mode = "and" // ALL criteria must match
	ModeOr  Mode = "or"  // ANY criterion can match
)

// Range represents a numeric range for filtering
type Range struct {
	Min int
	Max int
}

// Response holds the data needed for filtering decisions
type Response struct {
	StatusCode    int
	ContentLength int
	Body          []byte
	Headers       map[string][]string
	ResponseTime  time.Duration
	CDNProvider   string
	FaviconHash   string
	Simhash       uint64
}

// Filter evaluates responses against configured criteria
type Filter struct {
	config     *Config
	seenHashes map[uint64]bool // For duplicate detection
}

// NewFilter creates a new filter with the given configuration
func NewFilter(cfg *Config) *Filter {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.MatchMode == "" {
		cfg.MatchMode = ModeOr // Default: match if ANY criterion matches
	}
	if cfg.FilterMode == "" {
		cfg.FilterMode = ModeOr // Default: filter if ANY criterion matches
	}
	return &Filter{
		config:     cfg,
		seenHashes: make(map[uint64]bool),
	}
}

// ShouldShow returns true if the response should be shown (passed filtering)
func (f *Filter) ShouldShow(resp *Response) bool {
	// First check filters (exclusions) - if ANY filter matches, exclude
	if f.matchesFilter(resp) {
		return false
	}

	// If no match criteria defined, show by default
	if !f.hasMatchCriteria() {
		return true
	}

	// Check match criteria
	return f.matchesMatcher(resp)
}

// hasMatchCriteria returns true if any match criteria is configured
func (f *Filter) hasMatchCriteria() bool {
	c := f.config
	return len(c.MatchStatus) > 0 ||
		len(c.MatchSize) > 0 ||
		len(c.MatchWords) > 0 ||
		len(c.MatchLines) > 0 ||
		len(c.MatchRegex) > 0 ||
		len(c.MatchString) > 0 ||
		c.MatchTime > 0 ||
		len(c.MatchCDN) > 0 ||
		len(c.MatchFavicon) > 0 ||
		len(c.MatchHeaders) > 0 ||
		c.MatchCondition != ""
}

// matchesMatcher checks if response matches configured match criteria
func (f *Filter) matchesMatcher(resp *Response) bool {
	c := f.config
	results := make([]bool, 0)

	// Status code matching
	if len(c.MatchStatus) > 0 {
		results = append(results, containsInt(c.MatchStatus, resp.StatusCode))
	}

	// Size matching
	if len(c.MatchSize) > 0 {
		results = append(results, matchesAnyRange(c.MatchSize, resp.ContentLength))
	}

	// Word count matching
	if len(c.MatchWords) > 0 {
		wordCount := countWords(resp.Body)
		results = append(results, matchesAnyRange(c.MatchWords, wordCount))
	}

	// Line count matching
	if len(c.MatchLines) > 0 {
		lineCount := countLines(resp.Body)
		results = append(results, matchesAnyRange(c.MatchLines, lineCount))
	}

	// Regex matching
	if len(c.MatchRegex) > 0 {
		matched := false
		for _, re := range c.MatchRegex {
			if re.Match(resp.Body) {
				matched = true
				break
			}
		}
		results = append(results, matched)
	}

	// String matching
	if len(c.MatchString) > 0 {
		matched := false
		bodyStr := string(resp.Body)
		for _, s := range c.MatchString {
			if strings.Contains(bodyStr, s) {
				matched = true
				break
			}
		}
		results = append(results, matched)
	}

	// Response time matching
	if c.MatchTime > 0 {
		results = append(results, resp.ResponseTime >= c.MatchTime)
	}

	// CDN matching
	if len(c.MatchCDN) > 0 {
		matched := false
		for _, cdn := range c.MatchCDN {
			if strings.EqualFold(resp.CDNProvider, cdn) {
				matched = true
				break
			}
		}
		results = append(results, matched)
	}

	// Favicon hash matching
	if len(c.MatchFavicon) > 0 {
		matched := false
		for _, hash := range c.MatchFavicon {
			if resp.FaviconHash == hash {
				matched = true
				break
			}
		}
		results = append(results, matched)
	}

	// Header matching
	if len(c.MatchHeaders) > 0 {
		matched := matchesHeaders(c.MatchHeaders, resp.Headers)
		results = append(results, matched)
	}

	// Combine results based on mode
	return combineResults(results, c.MatchMode)
}

// matchesFilter checks if response should be filtered out
func (f *Filter) matchesFilter(resp *Response) bool {
	c := f.config
	results := make([]bool, 0)

	// Duplicate detection (check first for efficiency)
	if c.FilterDuplicates && resp.Simhash > 0 {
		if f.seenHashes[resp.Simhash] {
			return true // Already seen, filter out
		}
		f.seenHashes[resp.Simhash] = true
	}

	// Status code filtering
	if len(c.FilterStatus) > 0 {
		results = append(results, containsInt(c.FilterStatus, resp.StatusCode))
	}

	// Size filtering
	if len(c.FilterSize) > 0 {
		results = append(results, matchesAnyRange(c.FilterSize, resp.ContentLength))
	}

	// Word count filtering
	if len(c.FilterWords) > 0 {
		wordCount := countWords(resp.Body)
		results = append(results, matchesAnyRange(c.FilterWords, wordCount))
	}

	// Line count filtering
	if len(c.FilterLines) > 0 {
		lineCount := countLines(resp.Body)
		results = append(results, matchesAnyRange(c.FilterLines, lineCount))
	}

	// Regex filtering
	if len(c.FilterRegex) > 0 {
		for _, re := range c.FilterRegex {
			if re.Match(resp.Body) {
				results = append(results, true)
				break
			}
		}
	}

	// String filtering
	if len(c.FilterString) > 0 {
		bodyStr := string(resp.Body)
		for _, s := range c.FilterString {
			if strings.Contains(bodyStr, s) {
				results = append(results, true)
				break
			}
		}
	}

	// Response time filtering
	if c.FilterTime > 0 {
		results = append(results, resp.ResponseTime >= c.FilterTime)
	}

	// CDN filtering
	if len(c.FilterCDN) > 0 {
		for _, cdn := range c.FilterCDN {
			if strings.EqualFold(resp.CDNProvider, cdn) {
				results = append(results, true)
				break
			}
		}
	}

	// Header filtering
	if len(c.FilterHeaders) > 0 {
		results = append(results, matchesHeaders(c.FilterHeaders, resp.Headers))
	}

	// Error page detection
	if c.FilterErrorPage && isErrorPage(resp) {
		return true
	}

	// If no filter results, don't filter
	if len(results) == 0 {
		return false
	}

	// Combine results based on mode
	return combineResults(results, c.FilterMode)
}

// Helper functions

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func matchesAnyRange(ranges []Range, val int) bool {
	for _, r := range ranges {
		if val >= r.Min && val <= r.Max {
			return true
		}
	}
	return false
}

func countWords(body []byte) int {
	return len(strings.Fields(string(body)))
}

func countLines(body []byte) int {
	return len(strings.Split(string(body), "\n"))
}

func matchesHeaders(want map[string]string, have map[string][]string) bool {
	for k, v := range want {
		vals, ok := have[k]
		if !ok {
			return false
		}
		found := false
		for _, hv := range vals {
			if strings.Contains(hv, v) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func combineResults(results []bool, mode Mode) bool {
	if len(results) == 0 {
		return false
	}
	if mode == ModeAnd {
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	}
	// ModeOr
	for _, r := range results {
		if r {
			return true
		}
	}
	return false
}

// isErrorPage detects common error page patterns
func isErrorPage(resp *Response) bool {
	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		return true
	}
	bodyStr := strings.ToLower(string(resp.Body))
	errorPatterns := []string{
		"not found",
		"page not found",
		"404 error",
		"access denied",
		"forbidden",
		"unauthorized",
		"internal server error",
		"service unavailable",
		"bad gateway",
	}
	for _, pattern := range errorPatterns {
		if strings.Contains(bodyStr, pattern) {
			return true
		}
	}
	return false
}

// ParseRange parses a range string like "100-200" or "100" into a Range
func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		min, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return Range{}, err
		}
		max, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return Range{}, err
		}
		return Range{Min: min, Max: max}, nil
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return Range{}, err
	}
	return Range{Min: val, Max: val}, nil
}

// ParseRanges parses multiple range specifications
// Supports formats: "100-200", "100,200,300", "100-200,300-400"
func ParseRanges(s string) ([]Range, error) {
	var ranges []Range
	parts := strings.Split(s, ",")
	for _, part := range parts {
		r, err := ParseRange(part)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	return ranges, nil
}

// ParseStatusCodes parses status code specifications
// Supports: "200", "200,301,302", "2xx" (all 2xx), "200-299"
func ParseStatusCodes(s string) ([]int, error) {
	var codes []int
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Handle wildcards like "2xx"
		if strings.HasSuffix(part, "xx") {
			prefix, err := strconv.Atoi(strings.TrimSuffix(part, "xx"))
			if err != nil {
				return nil, err
			}
			for i := prefix * 100; i < (prefix+1)*100; i++ {
				codes = append(codes, i)
			}
			continue
		}

		// Handle ranges like "200-299"
		if strings.Contains(part, "-") {
			subParts := strings.SplitN(part, "-", 2)
			min, err := strconv.Atoi(strings.TrimSpace(subParts[0]))
			if err != nil {
				return nil, err
			}
			max, err := strconv.Atoi(strings.TrimSpace(subParts[1]))
			if err != nil {
				return nil, err
			}
			for i := min; i <= max; i++ {
				codes = append(codes, i)
			}
			continue
		}

		// Single value
		val, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		codes = append(codes, val)
	}
	return codes, nil
}
