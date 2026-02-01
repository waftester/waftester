// Package cache provides web cache poisoning detection capabilities.
// It tests for cache key manipulation, unkeyed header injection,
// web cache deception, and other cache-related vulnerabilities.
package cache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of cache vulnerability
type VulnerabilityType string

const (
	VulnUnkeyedHeader     VulnerabilityType = "unkeyed-header"
	VulnUnkeyedCookie     VulnerabilityType = "unkeyed-cookie"
	VulnUnkeyedParameter  VulnerabilityType = "unkeyed-parameter"
	VulnPathNormalization VulnerabilityType = "path-normalization"
	VulnCacheDeception    VulnerabilityType = "cache-deception"
	VulnParameterCloaking VulnerabilityType = "parameter-cloaking"
	VulnFatGET            VulnerabilityType = "fat-get"
	VulnResponseSplitting VulnerabilityType = "response-splitting"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Vulnerability represents a detected cache poisoning vulnerability
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	URL         string            `json:"url"`
	Evidence    string            `json:"evidence"`
	Remediation string            `json:"remediation"`
	CVSS        float64           `json:"cvss"`
	Header      string            `json:"header,omitempty"`
	Parameter   string            `json:"parameter,omitempty"`
	CacheBuster string            `json:"cache_buster,omitempty"`
}

// ScanResult contains the results of a cache security scan
type ScanResult struct {
	URL             string            `json:"url"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time"`
	Duration        time.Duration     `json:"duration"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	CacheDetected   bool              `json:"cache_detected"`
	CacheHeaders    map[string]string `json:"cache_headers"`
	TestedHeaders   int               `json:"tested_headers"`
	TestedParams    int               `json:"tested_params"`
}

// TesterConfig configures the cache poisoning tester
type TesterConfig struct {
	Timeout      time.Duration
	UserAgent    string
	Concurrency  int
	CacheBusters []string // Custom cache busters
	TestHeaders  []string // Headers to test for unkeyed behavior
	TestParams   []string // Parameters to test
	Client       *http.Client
	VerifyCache  bool // Whether to verify caching behavior
}

// Tester performs cache poisoning tests
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:     30 * time.Second,
		UserAgent:   ui.UserAgent(),
		Concurrency: 5,
		VerifyCache: true,
		TestHeaders: []string{
			// Standard headers
			"X-Forwarded-Host",
			"X-Forwarded-Scheme",
			"X-Forwarded-Proto",
			"X-Forwarded-Port",
			"X-Forwarded-Path",
			"X-Original-URL",
			"X-Rewrite-URL",
			"X-Forwarded-Server",
			"X-HTTP-Host-Override",
			"X-Host",
			"X-Custom-IP-Authorization",
			"X-Original-Host",
			"X-Forwarded-For",
			"X-Client-IP",
			"X-Real-IP",
			"True-Client-IP",
			"Forwarded",
			"X-WAP-Profile",
			"Profile",
			// Less common
			"X-Backend-Host",
			"X-Originating-IP",
			"CF-Connecting-IP",
			"Fastly-Client-IP",
			"X-Azure-ClientIP",
			"X-Akamai-Proxy",
			// Content negotiation
			"Accept",
			"Accept-Language",
			"Accept-Encoding",
			// Custom application headers
			"X-Debug",
			"X-Test",
			"X-Inject",
			"X-Canary",
		},
		TestParams: []string{
			"_",
			"cache",
			"cb",
			"bust",
			"random",
			"utm_source",
			"utm_campaign",
			"utm_content",
			"utm_medium",
			"utm_term",
			"ref",
			"source",
			"track",
			"clickid",
			"gclid",
			"fbclid",
		},
	}
}

// NewTester creates a new cache poisoning tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &Tester{
		config: config,
		client: client,
	}
}

// generateCacheBuster creates a unique cache buster value
func generateCacheBuster() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// addCacheBuster appends a cache buster to the URL
func addCacheBuster(targetURL, buster string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("cb", buster)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// DetectCache checks if the target uses caching
func (t *Tester) DetectCache(ctx context.Context, targetURL string) (bool, map[string]string, error) {
	cacheHeaders := make(map[string]string)

	buster := generateCacheBuster()
	bustedURL, err := addCacheBuster(targetURL, buster)
	if err != nil {
		return false, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", bustedURL, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return false, nil, err
	}
	iohelper.DrainAndClose(resp.Body)

	// Collect cache-related headers
	cacheIndicators := []string{
		"X-Cache",
		"X-Cache-Status",
		"X-Varnish",
		"X-CDN",
		"X-Edge-Location",
		"Age",
		"Cache-Control",
		"Via",
		"X-Served-By",
		"X-Cache-Hits",
		"X-Timer",
		"CF-Cache-Status",
		"X-Drupal-Cache",
		"X-Proxy-Cache",
		"Fastly-Debug",
		"X-Rack-Cache",
		"X-Magento-Cache",
	}

	cacheDetected := false
	for _, h := range cacheIndicators {
		if v := resp.Header.Get(h); v != "" {
			cacheHeaders[h] = v
			cacheDetected = true
		}
	}

	// Also check if Age > 0
	if age := resp.Header.Get("Age"); age != "" && age != "0" {
		cacheDetected = true
	}

	return cacheDetected, cacheHeaders, nil
}

// TestUnkeyedHeader tests if a header is reflected but not included in cache key
func (t *Tester) TestUnkeyedHeader(ctx context.Context, targetURL string, header string) (*Vulnerability, error) {
	// Generate unique canary value
	canary := "waftester" + generateCacheBuster()
	buster := generateCacheBuster()

	bustedURL, err := addCacheBuster(targetURL, buster)
	if err != nil {
		return nil, err
	}

	// First request: Poison with header
	req1, err := http.NewRequestWithContext(ctx, "GET", bustedURL, nil)
	if err != nil {
		return nil, err
	}
	req1.Header.Set("User-Agent", t.config.UserAgent)
	req1.Header.Set(header, canary)

	resp1, err := t.client.Do(req1)
	if err != nil {
		return nil, err
	}

	body1 := readBodyLimit(resp1, 100*1024)
	iohelper.DrainAndClose(resp1.Body)

	// Check if canary is reflected in first response
	if !strings.Contains(body1, canary) {
		return nil, nil // Header not reflected
	}

	// Second request: Without the header (should get cached poisoned response)
	req2, err := http.NewRequestWithContext(ctx, "GET", bustedURL, nil)
	if err != nil {
		return nil, err
	}
	req2.Header.Set("User-Agent", t.config.UserAgent)

	resp2, err := t.client.Do(req2)
	if err != nil {
		return nil, err
	}

	body2 := readBodyLimit(resp2, 100*1024)
	iohelper.DrainAndClose(resp2.Body)

	// If canary appears in second response without header, cache is poisoned
	if strings.Contains(body2, canary) {
		return &Vulnerability{
			Type:        VulnUnkeyedHeader,
			Description: fmt.Sprintf("Header '%s' is reflected but not keyed in cache", header),
			Severity:    SeverityHigh,
			URL:         targetURL,
			Evidence:    fmt.Sprintf("Canary '%s' appeared in cached response", canary),
			Remediation: GetUnkeyedHeaderRemediation(),
			CVSS:        7.5,
			Header:      header,
			CacheBuster: buster,
		}, nil
	}

	return nil, nil
}

// TestUnkeyedParameter tests if a parameter is reflected but not included in cache key
func (t *Tester) TestUnkeyedParameter(ctx context.Context, targetURL string, param string) (*Vulnerability, error) {
	canary := "waftester" + generateCacheBuster()
	buster := generateCacheBuster()

	// Build URL with cache buster and test param
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("cb", buster)
	q.Set(param, canary)
	u.RawQuery = q.Encode()
	poisonedURL := u.String()

	// Build URL with only cache buster
	q2 := u.Query()
	q2.Set("cb", buster)
	q2.Del(param)
	u.RawQuery = q2.Encode()
	normalURL := u.String()

	// First request: With param
	req1, err := http.NewRequestWithContext(ctx, "GET", poisonedURL, nil)
	if err != nil {
		return nil, err
	}
	req1.Header.Set("User-Agent", t.config.UserAgent)

	resp1, err := t.client.Do(req1)
	if err != nil {
		return nil, err
	}

	body1 := readBodyLimit(resp1, 100*1024)
	iohelper.DrainAndClose(resp1.Body)

	if !strings.Contains(body1, canary) {
		return nil, nil // Param not reflected
	}

	// Second request: Without param
	req2, err := http.NewRequestWithContext(ctx, "GET", normalURL, nil)
	if err != nil {
		return nil, err
	}
	req2.Header.Set("User-Agent", t.config.UserAgent)

	resp2, err := t.client.Do(req2)
	if err != nil {
		return nil, err
	}

	body2 := readBodyLimit(resp2, 100*1024)
	iohelper.DrainAndClose(resp2.Body)

	if strings.Contains(body2, canary) {
		return &Vulnerability{
			Type:        VulnUnkeyedParameter,
			Description: fmt.Sprintf("Parameter '%s' is reflected but not keyed in cache", param),
			Severity:    SeverityHigh,
			URL:         targetURL,
			Evidence:    fmt.Sprintf("Canary '%s' appeared in cached response without param", canary),
			Remediation: GetUnkeyedParamRemediation(),
			CVSS:        7.5,
			Parameter:   param,
			CacheBuster: buster,
		}, nil
	}

	return nil, nil
}

// TestCacheDeception tests for web cache deception attacks
func (t *Tester) TestCacheDeception(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Extensions that caches commonly store
	cacheableExtensions := []string{
		"/test.css",
		"/test.js",
		"/test.png",
		"/test.jpg",
		"/test.gif",
		"/test.ico",
		"/test.svg",
		"/test.woff",
		"/test.woff2",
		"/style.css",
		"/script.js",
	}

	// Path delimiters that may trick path parsing
	pathDelimiters := []string{
		"/",
		";",
		"%2f",
		"%3b",
		"%00",
		"?",
		"#",
		"/./",
		"/../",
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	basePath := strings.TrimSuffix(u.Path, "/")
	if basePath == "" {
		basePath = "/"
	}

	// First, get the original response for comparison
	buster := generateCacheBuster()
	bustedURL, _ := addCacheBuster(targetURL, buster)

	req, err := http.NewRequestWithContext(ctx, "GET", bustedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}

	originalBody := readBodyLimit(resp, 100*1024)
	iohelper.DrainAndClose(resp.Body)

	// Try each extension with delimiter
	for _, ext := range cacheableExtensions {
		for _, delim := range pathDelimiters {
			testPath := basePath + delim + ext
			u.Path = testPath

			newBuster := generateCacheBuster()
			q := u.Query()
			q.Set("cb", newBuster)
			u.RawQuery = q.Encode()

			testURL := u.String()

			req2, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			req2.Header.Set("User-Agent", t.config.UserAgent)

			resp2, err := t.client.Do(req2)
			if err != nil {
				continue
			}

			testBody := readBodyLimit(resp2, 100*1024)

			// Check cache headers
			cacheStatus := resp2.Header.Get("X-Cache")
			cfCache := resp2.Header.Get("CF-Cache-Status")
			iohelper.DrainAndClose(resp2.Body)

			// If responses are similar and it's being cached, it's vulnerable
			if (cacheStatus == "HIT" || cfCache == "HIT" || cfCache == "DYNAMIC") &&
				similarity(originalBody, testBody) > 0.8 {
				vulns = append(vulns, Vulnerability{
					Type:        VulnCacheDeception,
					Description: fmt.Sprintf("Cache deception via path: %s%s", delim, ext),
					Severity:    SeverityHigh,
					URL:         testURL,
					Evidence:    fmt.Sprintf("Response cached with static extension, Cache-Status: %s%s", cacheStatus, cfCache),
					Remediation: GetCacheDeceptionRemediation(),
					CVSS:        7.1,
				})
			}
		}
	}

	return vulns, nil
}

// TestPathNormalization tests for cache key normalization issues
func (t *Tester) TestPathNormalization(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Path variations that might normalize differently
	pathVariations := []struct {
		pattern string
		desc    string
	}{
		{"/./", "dot segment"},
		{"/../parent/", "parent traversal"},
		{"/;/", "semicolon delimiter"},
		{"/%2e/", "encoded dot"},
		{"/%2e%2e/", "encoded double dot"},
		{"/..%2f", "mixed encoding traversal"},
		{"//", "double slash"},
		{"/./../../", "complex traversal"},
		{"%00", "null byte"},
		{"%0a", "newline"},
		{"%0d", "carriage return"},
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	originalPath := u.Path

	for _, variation := range pathVariations {
		testPath := originalPath + variation.pattern + "test"
		u.Path = testPath

		buster := generateCacheBuster()
		q := u.Query()
		q.Set("cb", buster)
		u.RawQuery = q.Encode()

		testURL := u.String()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", t.config.UserAgent)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		// Check if response was cached
		cacheStatus := resp.Header.Get("X-Cache")
		age := resp.Header.Get("Age")
		iohelper.DrainAndClose(resp.Body)

		// Check for cache hit on first request (shouldn't happen normally)
		if strings.Contains(cacheStatus, "HIT") || (age != "" && age != "0") {
			vulns = append(vulns, Vulnerability{
				Type:        VulnPathNormalization,
				Description: fmt.Sprintf("Path normalization issue with %s", variation.desc),
				Severity:    SeverityMedium,
				URL:         testURL,
				Evidence:    fmt.Sprintf("Cache hit on path with %s: %s", variation.desc, variation.pattern),
				Remediation: GetPathNormalizationRemediation(),
				CVSS:        5.3,
			})
		}
	}

	return vulns, nil
}

// TestFatGET tests for fat GET request vulnerabilities
func (t *Tester) TestFatGET(ctx context.Context, targetURL string) (*Vulnerability, error) {
	canary := "waftester" + generateCacheBuster()
	buster := generateCacheBuster()

	bustedURL, err := addCacheBuster(targetURL, buster)
	if err != nil {
		return nil, err
	}

	// Create GET request with body (fat GET)
	req, err := http.NewRequestWithContext(ctx, "GET", bustedURL, strings.NewReader(fmt.Sprintf("inject=%s", canary)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}

	body := readBodyLimit(resp, 100*1024)
	iohelper.DrainAndClose(resp.Body)

	if strings.Contains(body, canary) {
		return &Vulnerability{
			Type:        VulnFatGET,
			Description: "Server processes body in GET requests (Fat GET)",
			Severity:    SeverityMedium,
			URL:         targetURL,
			Evidence:    fmt.Sprintf("GET request body was processed, canary reflected: %s", canary),
			Remediation: GetFatGETRemediation(),
			CVSS:        5.3,
		}, nil
	}

	return nil, nil
}

// TestParameterCloaking tests for parameter cloaking vulnerabilities
func (t *Tester) TestParameterCloaking(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	canary := "waftester" + generateCacheBuster()

	// Different parameter pollution patterns
	patterns := []struct {
		query string
		desc  string
	}{
		{"test=%s&test=normal", "duplicate parameter"},
		{"test[]=normal&test[]=%s", "array parameter"},
		{"test=normal;inject=%s", "semicolon delimiter"},
		{"test=normal%%26inject=%s", "encoded ampersand"},
		{"test=normal%00inject=%s", "null byte injection"},
	}

	for _, pattern := range patterns {
		buster := generateCacheBuster()

		u, err := url.Parse(targetURL)
		if err != nil {
			continue
		}

		q := u.Query()
		q.Set("cb", buster)
		u.RawQuery = q.Encode() + "&" + fmt.Sprintf(pattern.query, canary)

		testURL := u.String()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", t.config.UserAgent)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body := readBodyLimit(resp, 100*1024)
		iohelper.DrainAndClose(resp.Body)

		if strings.Contains(body, canary) {
			vulns = append(vulns, Vulnerability{
				Type:        VulnParameterCloaking,
				Description: fmt.Sprintf("Parameter cloaking via %s", pattern.desc),
				Severity:    SeverityMedium,
				URL:         testURL,
				Evidence:    fmt.Sprintf("Hidden parameter processed: %s", pattern.desc),
				Remediation: GetParameterCloakingRemediation(),
				CVSS:        5.3,
			})
		}
	}

	return vulns, nil
}

// Scan performs a comprehensive cache poisoning scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:          targetURL,
		StartTime:    startTime,
		CacheHeaders: make(map[string]string),
	}

	// First, detect if caching is in use
	cacheDetected, cacheHeaders, err := t.DetectCache(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	result.CacheDetected = cacheDetected
	result.CacheHeaders = cacheHeaders

	// Test unkeyed headers
	for _, header := range t.config.TestHeaders {
		vuln, err := t.TestUnkeyedHeader(ctx, targetURL, header)
		if err != nil {
			continue
		}
		if vuln != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
		}
		result.TestedHeaders++
	}

	// Test unkeyed parameters
	for _, param := range t.config.TestParams {
		vuln, err := t.TestUnkeyedParameter(ctx, targetURL, param)
		if err != nil {
			continue
		}
		if vuln != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
		}
		result.TestedParams++
	}

	// Test cache deception
	vulns, err := t.TestCacheDeception(ctx, targetURL)
	if err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	// Test path normalization
	vulns, err = t.TestPathNormalization(ctx, targetURL)
	if err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	// Test Fat GET
	vuln, err := t.TestFatGET(ctx, targetURL)
	if err == nil && vuln != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
	}

	// Test parameter cloaking
	vulns, err = t.TestParameterCloaking(ctx, targetURL)
	if err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	return result, nil
}

// Helper functions

func readBodyLimit(resp *http.Response, limit int64) string {
	buf := make([]byte, limit)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Simple length-based similarity for performance
	shorter := len(a)
	longer := len(b)
	if shorter > longer {
		shorter, longer = longer, shorter
	}

	if longer == 0 {
		return 1.0
	}

	// Find matching characters
	matches := 0
	minLen := shorter
	if minLen > 1000 {
		minLen = 1000
	}

	for i := 0; i < minLen; i++ {
		if i < len(a) && i < len(b) && a[i] == b[i] {
			matches++
		}
	}

	return float64(matches) / float64(minLen)
}

// Remediation guidance

// GetUnkeyedHeaderRemediation returns remediation for unkeyed header issues
func GetUnkeyedHeaderRemediation() string {
	return `To fix unkeyed header vulnerabilities:
1. Configure cache to include relevant headers in the cache key
2. Strip potentially dangerous headers before caching
3. Use Vary header to specify which headers affect response
4. Implement header validation at the edge
5. Consider using signed headers for critical values`
}

// GetUnkeyedParamRemediation returns remediation for unkeyed parameter issues
func GetUnkeyedParamRemediation() string {
	return `To fix unkeyed parameter vulnerabilities:
1. Include all parameters in the cache key
2. Whitelist which parameters should be keyed
3. Strip unknown parameters before caching
4. Normalize parameter order in cache key
5. Use consistent parameter parsing`
}

// GetCacheDeceptionRemediation returns remediation for cache deception
func GetCacheDeceptionRemediation() string {
	return `To fix web cache deception vulnerabilities:
1. Set proper Cache-Control headers (no-store for sensitive pages)
2. Configure cache to ignore path extensions for dynamic content
3. Use consistent path parsing between cache and origin
4. Validate that cached responses don't contain sensitive data
5. Use SameSite cookies and other session protections`
}

// GetPathNormalizationRemediation returns remediation for path normalization issues
func GetPathNormalizationRemediation() string {
	return `To fix path normalization vulnerabilities:
1. Normalize paths consistently at the edge and origin
2. Reject requests with encoded path traversal sequences
3. Use strict path matching rules
4. Configure cache to normalize paths before keying
5. Reject paths containing null bytes or unusual characters`
}

// GetFatGETRemediation returns remediation for Fat GET vulnerabilities
func GetFatGETRemediation() string {
	return `To fix Fat GET vulnerabilities:
1. Ignore request bodies for GET/HEAD methods
2. Configure web server to reject GET requests with bodies
3. Ensure cache doesn't key on GET request body
4. Use POST for operations that require request body`
}

// GetParameterCloakingRemediation returns remediation for parameter cloaking
func GetParameterCloakingRemediation() string {
	return `To fix parameter cloaking vulnerabilities:
1. Use consistent parameter parsing across all layers
2. Reject requests with duplicate parameters
3. Normalize parameter encoding before processing
4. Reject requests with null bytes in parameters
5. Use explicit parameter whitelisting`
}

// AllVulnerabilityTypes returns all vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnUnkeyedHeader,
		VulnUnkeyedCookie,
		VulnUnkeyedParameter,
		VulnPathNormalization,
		VulnCacheDeception,
		VulnParameterCloaking,
		VulnFatGET,
		VulnResponseSplitting,
	}
}

// CommonCacheHeaders returns common cache-related headers
func CommonCacheHeaders() []string {
	return []string{
		"X-Cache",
		"X-Cache-Status",
		"X-Varnish",
		"Age",
		"Cache-Control",
		"Via",
		"X-Served-By",
		"CF-Cache-Status",
		"X-CDN",
		"X-Edge-Location",
	}
}

// IsValidCacheStatus checks if a cache status indicates caching
func IsValidCacheStatus(status string) bool {
	status = strings.ToUpper(status)
	cacheStatuses := []string{"HIT", "MISS", "EXPIRED", "STALE", "DYNAMIC"}
	for _, s := range cacheStatuses {
		if strings.Contains(status, s) {
			return true
		}
	}
	return false
}

// ParseCacheControl parses Cache-Control header
func ParseCacheControl(header string) map[string]string {
	result := make(map[string]string)

	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx != -1 {
			key := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			result[key] = value
		} else {
			result[part] = ""
		}
	}

	return result
}

// IsCacheable determines if a response is cacheable
func IsCacheable(resp *http.Response) bool {
	// Check Cache-Control
	cc := resp.Header.Get("Cache-Control")
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}

	// Check for caching headers
	if resp.Header.Get("X-Cache") != "" || resp.Header.Get("Age") != "" {
		return true
	}

	// Check status code (only certain codes are typically cached)
	cacheableCodes := map[int]bool{200: true, 203: true, 204: true, 300: true, 301: true, 304: true, 404: true, 410: true}
	if cacheableCodes[resp.StatusCode] {
		return true
	}

	return false
}

// ExtractCanaryPattern returns a regex for finding canary values
func ExtractCanaryPattern() *regexp.Regexp {
	return regexp.MustCompile(`waftester[a-f0-9]{16}`)
}
