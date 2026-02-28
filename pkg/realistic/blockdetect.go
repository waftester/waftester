package realistic

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// BlockDetector analyzes HTTP responses to determine if a request was blocked
type BlockDetector struct {
	// StatusCodes that indicate blocking
	BlockStatusCodes []int

	// Keywords in response body indicating block
	BlockKeywords []string

	// Patterns in response body indicating block
	BlockPatterns []*regexp.Regexp

	// Keywords in headers indicating block (e.g., WAF headers)
	BlockHeaders map[string][]string

	// Baseline response for comparison
	Baseline *BaselineResponse

	// Similarity threshold for baseline comparison (0.0-1.0)
	SimilarityThreshold float64
}

// BaselineResponse stores characteristics of a normal (non-blocked) response
type BaselineResponse struct {
	StatusCode    int
	ContentLength int64
	ContentType   string
	BodyHash      string
	Headers       map[string]string
	ResponseTime  time.Duration
}

// BlockResult contains detailed information about block detection
type BlockResult struct {
	IsBlocked       bool
	Confidence      float64  // 0.0-1.0 confidence that it was blocked
	Reason          string   // Human-readable reason
	MatchedPatterns []string // Which patterns matched
	StatusCode      int
	ResponseTime    time.Duration
}

// NewBlockDetector creates a detector with sensible defaults
func NewBlockDetector() *BlockDetector {
	return &BlockDetector{
		BlockStatusCodes:    []int{403, 406, 429, 503},
		BlockKeywords:       DefaultBlockKeywords,
		BlockPatterns:       compilePatterns(DefaultBlockPatterns),
		BlockHeaders:        DefaultBlockHeaders,
		SimilarityThreshold: 0.7,
	}
}

// DetectBlock analyzes an HTTP response to determine if it indicates blocking
func (d *BlockDetector) DetectBlock(resp *http.Response, responseTime time.Duration) (*BlockResult, error) {
	result := &BlockResult{
		IsBlocked:       false,
		Confidence:      0.0,
		StatusCode:      resp.StatusCode,
		ResponseTime:    responseTime,
		MatchedPatterns: []string{},
	}

	var reasons []string
	var totalConfidence float64

	// 1. Check status code
	if d.isBlockedStatusCode(resp.StatusCode) {
		totalConfidence += 0.4
		reasons = append(reasons, fmt.Sprintf("status_code:%d", resp.StatusCode))
		result.MatchedPatterns = append(result.MatchedPatterns, "status_code")
	}

	// 2. Check WAF headers
	headerMatches := d.checkBlockHeaders(resp.Header)
	if len(headerMatches) > 0 {
		totalConfidence += 0.3
		reasons = append(reasons, headerMatches...)
		result.MatchedPatterns = append(result.MatchedPatterns, headerMatches...)
	}

	// 3. Read and analyze body (limit to 100KB for block pages)
	bodyBytes, err := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)
	if err != nil && err != io.EOF {
		return result, err
	}
	body := string(bodyBytes)

	// 4. Check body keywords - weight based on number of matches
	keywordMatches := d.checkBlockKeywords(body)
	if len(keywordMatches) > 0 {
		// More matches = higher confidence
		keywordConfidence := 0.15 * float64(len(keywordMatches))
		if keywordConfidence > 0.4 {
			keywordConfidence = 0.4
		}
		totalConfidence += keywordConfidence
		reasons = append(reasons, keywordMatches...)
		result.MatchedPatterns = append(result.MatchedPatterns, keywordMatches...)
	}

	// 5. Check body patterns - weight based on number of matches
	patternMatches := d.checkBlockPatterns(body)
	if len(patternMatches) > 0 {
		patternConfidence := 0.15 * float64(len(patternMatches))
		if patternConfidence > 0.4 {
			patternConfidence = 0.4
		}
		totalConfidence += patternConfidence
		reasons = append(reasons, patternMatches...)
		result.MatchedPatterns = append(result.MatchedPatterns, patternMatches...)
	}

	// 6. Compare to baseline if available
	if d.Baseline != nil {
		baselineConfidence := d.compareToBaseline(resp, body, responseTime)
		if baselineConfidence > 0 {
			totalConfidence += baselineConfidence * 0.3
			reasons = append(reasons, "baseline_deviation")
		}
	}

	// Normalize confidence
	if totalConfidence > 1.0 {
		totalConfidence = 1.0
	}

	result.Confidence = totalConfidence
	result.IsBlocked = totalConfidence >= 0.3 // Threshold for considering blocked
	result.Reason = strings.Join(reasons, ", ")

	return result, nil
}

// isBlockedStatusCode checks if status indicates blocking
func (d *BlockDetector) isBlockedStatusCode(code int) bool {
	for _, blocked := range d.BlockStatusCodes {
		if code == blocked {
			return true
		}
	}
	return false
}

// checkBlockHeaders looks for WAF-specific headers
func (d *BlockDetector) checkBlockHeaders(headers http.Header) []string {
	var matches []string

	for headerName, blockedValues := range d.BlockHeaders {
		headerValue := headers.Get(headerName)
		if headerValue == "" {
			continue
		}

		headerValueLower := strings.ToLower(headerValue)
		for _, blockedVal := range blockedValues {
			if strings.Contains(headerValueLower, strings.ToLower(blockedVal)) {
				matches = append(matches, "header:"+headerName+"="+blockedVal)
			}
		}
	}

	return matches
}

// checkBlockKeywords looks for blocking keywords in body
func (d *BlockDetector) checkBlockKeywords(body string) []string {
	var matches []string
	bodyLower := strings.ToLower(body)

	for _, keyword := range d.BlockKeywords {
		if strings.Contains(bodyLower, strings.ToLower(keyword)) {
			matches = append(matches, "keyword:"+keyword)
		}
	}

	return matches
}

// checkBlockPatterns uses regex to find block indicators
func (d *BlockDetector) checkBlockPatterns(body string) []string {
	var matches []string

	for i, pattern := range d.BlockPatterns {
		if pattern.MatchString(body) {
			matches = append(matches, "pattern:"+DefaultBlockPatterns[i])
		}
	}

	return matches
}

// compareToBaseline compares response to baseline
func (d *BlockDetector) compareToBaseline(resp *http.Response, body string, responseTime time.Duration) float64 {
	if d.Baseline == nil {
		return 0
	}

	var deviation float64

	// Status code change is significant
	if resp.StatusCode != d.Baseline.StatusCode {
		deviation += 0.5
	}

	// Content length change
	if d.Baseline.ContentLength > 0 {
		lengthDiff := float64(int64(len(body))-d.Baseline.ContentLength) / float64(d.Baseline.ContentLength)
		if lengthDiff < -0.5 || lengthDiff > 0.5 {
			deviation += 0.3
		}
	}

	// Content type change
	currentCT := resp.Header.Get("Content-Type")
	if d.Baseline.ContentType != "" && !strings.HasPrefix(currentCT, d.Baseline.ContentType) {
		deviation += 0.2
	}

	// Response time anomaly (e.g., blocked responses are often faster)
	if d.Baseline.ResponseTime > 0 {
		timeDiff := float64(responseTime) / float64(d.Baseline.ResponseTime)
		if timeDiff < 0.3 { // Response 70%+ faster than baseline
			deviation += 0.2
		}
	}

	if deviation > 1.0 {
		deviation = 1.0
	}

	return deviation
}

// CaptureBaseline records a normal response for comparison
func (d *BlockDetector) CaptureBaseline(resp *http.Response, responseTime time.Duration) error {
	bodyBytes, err := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)
	if err != nil && err != io.EOF {
		return err
	}

	d.Baseline = &BaselineResponse{
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(bodyBytes)),
		ContentType:   strings.Split(resp.Header.Get("Content-Type"), ";")[0],
		BodyHash:      simpleHash(string(bodyBytes)),
		Headers:       headerMap(resp.Header),
		ResponseTime:  responseTime,
	}

	return nil
}

// Helper functions

func compilePatterns(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile("(?i)" + p) // case-insensitive
	}
	return compiled
}

func simpleHash(s string) string {
	// Simple FNV-1a hash for comparison
	var hash uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= 16777619
	}
	return fmt.Sprintf("%08x", hash)
}

func headerMap(h http.Header) map[string]string {
	m := make(map[string]string)
	for k := range h {
		m[k] = h.Get(k)
	}
	return m
}

// DefaultBlockKeywords are common phrases indicating WAF blocks
var DefaultBlockKeywords = []string{
	// Generic WAF
	"access denied",
	"request blocked",
	"forbidden",
	"not allowed",
	"security policy",
	"blocked by",
	"request rejected",
	"violation",
	"malicious",

	// Cloudflare
	"attention required",
	"ray id",
	"cloudflare",
	"ddos protection",
	"checking your browser",

	// AWS WAF
	"aws waf",
	"request could not be satisfied",
	"amazon web services",

	// Akamai
	"akamai",
	"ghost",
	"access denied - akamai",

	// Imperva/Incapsula
	"incapsula",
	"imperva",
	"incident id",

	// ModSecurity
	"modsecurity",
	"mod_security",
	"owasp",
	"core rule set",

	// Nginx
	"nginx",
	"openresty",

	// F5 BIG-IP
	"big-ip",
	"f5",
	"asm",

	// Sucuri
	"sucuri",
	"website firewall",

	// Wordfence
	"wordfence",
	"generated by wordfence",

	// Generic errors
	"suspicious activity",
	"unusual traffic",
	"security check",
	"your request has been blocked",
	"please contact",
}

// DefaultBlockPatterns are regex patterns for block detection
var DefaultBlockPatterns = []string{
	// Error IDs
	`(?:error|incident|request|reference|ray)[\s_-]?id[:\s]+[a-z0-9-]+`,

	// IP mentions in errors
	`your\s+ip\s+(?:address\s+)?(?:has\s+been|was|is)\s+(?:blocked|banned|flagged)`,

	// Captcha pages
	`(?:captcha|recaptcha|hcaptcha|challenge)`,

	// Common WAF block page patterns
	`<title>[^<]*(?:blocked|denied|forbidden|error|security)[^<]*</title>`,

	// Support contact patterns
	`contact\s+(?:support|administrator|webmaster)`,

	// Time-based blocks
	`try\s+again\s+(?:later|in\s+\d+)`,

	// JavaScript challenges
	`javascript\s+(?:challenge|verification|required)`,

	// Cookie/session issues from WAFs
	`enable\s+cookies`,
}

// DefaultBlockHeaders maps header names to values indicating blocks
var DefaultBlockHeaders = map[string][]string{
	// Server identification
	"Server": {
		"cloudflare",
		"awselb",
		"akamai",
		"imperva",
		"incapsula",
		"sucuri",
		"barracuda",
		"f5 big-ip",
	},

	// WAF-specific headers
	"X-CDN":          {"Incapsula"},
	"X-Iinfo":        {""}, // Presence indicates Incapsula
	"CF-RAY":         {""}, // Presence indicates Cloudflare
	"X-Sucuri-ID":    {""},
	"X-Sucuri-Cache": {""},

	// Custom WAF headers
	"X-WAF-Event-Info": {""},
	"X-Request-ID":     {"blocked"},

	// Rate limiting headers
	"Retry-After":           {""},
	"X-RateLimit-Remaining": {"0"},
}
