// Package idor provides Insecure Direct Object Reference testing
package idor

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures IDOR testing
type Config struct {
	attackconfig.Base
	BaseURL      string
	Headers      map[string]string
	AuthTokens   []string // Multiple auth tokens for comparison
	IDPatterns   []string // Patterns to identify IDs in responses
	NumericRange [2]int   // Range for numeric ID enumeration
	UUIDWordlist []string // UUIDs to test
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyMedium,
			Timeout:     httpclient.TimeoutProbing,
		},
		NumericRange: [2]int{1, 100},
		IDPatterns: []string{
			`"id"\s*:\s*(\d+)`,
			`"user_id"\s*:\s*(\d+)`,
			`"account_id"\s*:\s*(\d+)`,
			`/users/(\d+)`,
			`/accounts/(\d+)`,
			`/orders/(\d+)`,
		},
	}
}

// Result represents an IDOR test result
type Result struct {
	URL           string
	Method        string
	OriginalID    string
	TestedID      string
	StatusCode    int
	Accessible    bool
	ResponseSize  int
	AuthToken     string
	Vulnerability string
	Severity      string
	Timestamp     time.Time
}

// Scanner performs IDOR testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new IDOR scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyMedium
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutProbing
	}

	return &Scanner{
		config:  config,
		client:  httpclient.Default(),
		results: make([]Result, 0),
	}
}

// ScanEndpoint tests an endpoint for IDOR vulnerabilities
func (s *Scanner) ScanEndpoint(ctx context.Context, endpoint string, method string) ([]Result, error) {
	results := make([]Result, 0)

	// Extract IDs from endpoint
	ids := s.extractIDs(endpoint)
	if len(ids) == 0 {
		return results, nil
	}

	// Test each ID with enumeration
	for _, originalID := range ids {
		testIDs := s.generateTestIDs(originalID)
		for _, testID := range testIDs {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			default:
			}

			testURL := strings.Replace(endpoint, originalID, testID, 1)
			result := s.testAccess(ctx, testURL, method, originalID, testID)
			if result.Accessible {
				results = append(results, result)
				s.config.NotifyVulnerabilityFound()
			}
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// extractIDs extracts potential IDs from a URL
func (s *Scanner) extractIDs(url string) []string {
	ids := make([]string, 0)
	seen := make(map[string]bool)

	for _, pattern := range s.config.IDPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue // Skip invalid patterns
		}
		matches := re.FindAllStringSubmatch(url, -1)
		for _, match := range matches {
			if len(match) > 1 && !seen[match[1]] {
				ids = append(ids, match[1])
				seen[match[1]] = true
			}
		}
	}

	// Also extract numeric segments from path
	parts := strings.Split(url, "/")
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err == nil && !seen[part] {
			ids = append(ids, part)
			seen[part] = true
		}
	}

	return ids
}

// generateTestIDs generates test IDs based on original
func (s *Scanner) generateTestIDs(original string) []string {
	testIDs := make([]string, 0)

	// Try numeric enumeration
	if num, err := strconv.Atoi(original); err == nil {
		// Test adjacent values
		for i := -5; i <= 5; i++ {
			if i != 0 {
				testIDs = append(testIDs, strconv.Itoa(num+i))
			}
		}
		// Test common IDs
		for _, common := range []int{1, 2, 0, 999, 1000, 9999} {
			if common != num {
				testIDs = append(testIDs, strconv.Itoa(common))
			}
		}
	}

	// Add UUID wordlist if available
	testIDs = append(testIDs, s.config.UUIDWordlist...)

	return testIDs
}

// accessDeniedPatterns are common response body indicators that access was denied
// even when the HTTP status code is 2xx.
var accessDeniedPatterns = []string{
	"access denied",
	"unauthorized",
	"forbidden",
	"not authorized",
	"permission denied",
	"not allowed",
	"invalid token",
	"login required",
	"authentication required",
	"you do not have permission",
	"insufficient privileges",
	"requires authentication",
}

// testAccess tests if an ID is accessible
func (s *Scanner) testAccess(ctx context.Context, url, method, originalID, testID string) Result {
	result := Result{
		URL:        url,
		Method:     method,
		OriginalID: originalID,
		TestedID:   testID,
		Timestamp:  time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return result
	}

	// Add headers
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	result.StatusCode = resp.StatusCode

	// Read the actual response body to verify access
	body, _ := iohelper.ReadBodyDefault(resp.Body)
	result.ResponseSize = len(body)

	// Only consider 2xx responses as potentially accessible
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Verify the response isn't an access-denied page disguised as 200
		bodyLower := strings.ToLower(string(body))
		accessDenied := false
		for _, pattern := range accessDeniedPatterns {
			if strings.Contains(bodyLower, pattern) {
				accessDenied = true
				break
			}
		}

		// Also reject empty/trivially small responses as likely non-data
		if !accessDenied && result.ResponseSize > 0 {
			result.Accessible = true
			result.Vulnerability = "IDOR - Unauthorized Access"
			result.Severity = s.determineSeverity(url, method)
		}
	}

	return result
}

// determineSeverity determines severity based on endpoint type
func (s *Scanner) determineSeverity(url, method string) string {
	urlLower := strings.ToLower(url)

	// High severity patterns
	highPatterns := []string{"admin", "password", "secret", "payment", "billing", "credit"}
	for _, p := range highPatterns {
		if strings.Contains(urlLower, p) {
			return "HIGH"
		}
	}

	// Write methods are higher severity
	if method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH" {
		return "HIGH"
	}

	// Medium by default for read access
	return "MEDIUM"
}

// HorizontalPrivilegeTest tests for horizontal privilege escalation
func (s *Scanner) HorizontalPrivilegeTest(ctx context.Context, endpoint string, tokens []string) []Result {
	results := make([]Result, 0)

	if len(tokens) < 2 {
		return results
	}

	// Test with first token and capture response body
	firstResult, firstBody := s.testWithTokenBody(ctx, endpoint, tokens[0])

	// Test same endpoint with other tokens and compare bodies
	for i := 1; i < len(tokens); i++ {
		otherResult, otherBody := s.testWithTokenBody(ctx, endpoint, tokens[i])

		// Both must return 200 AND response bodies must be similar,
		// indicating the second token can access the first token's data.
		if firstResult.StatusCode == 200 && otherResult.StatusCode == 200 &&
			len(firstBody) > 0 && len(otherBody) > 0 &&
			responseSimilar(firstBody, otherBody) {
			result := Result{
				URL:           endpoint,
				Method:        "GET",
				AuthToken:     tokens[i],
				Accessible:    true,
				Vulnerability: "Horizontal Privilege Escalation",
				Severity:      "high",
				Timestamp:     time.Now(),
			}
			results = append(results, result)
		}
	}

	return results
}

// testWithToken tests endpoint with specific auth token
func (s *Scanner) testWithToken(ctx context.Context, endpoint, token string) Result {
	result, _ := s.testWithTokenBody(ctx, endpoint, token)
	return result
}

// testWithTokenBody tests endpoint with specific auth token and returns the response body.
func (s *Scanner) testWithTokenBody(ctx context.Context, endpoint, token string) (Result, []byte) {
	result := Result{
		URL:       endpoint,
		AuthToken: token,
		Timestamp: time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return result, nil
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.client.Do(req)
	if err != nil {
		return result, nil
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)
	return result, body
}

// responseSimilar checks if two response bodies are similar enough to indicate
// the same data is being returned (suggesting unauthorized access to another user's data).
func responseSimilar(a, b []byte) bool {
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return false
	}

	// If lengths differ by more than 20%, responses are likely different content
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	larger := la
	if lb > la {
		larger = lb
	}
	if float64(diff)/float64(larger) > 0.2 {
		return false
	}

	// Exact match is a strong indicator
	if la == lb && string(a) == string(b) {
		return true
	}

	// Compare a sample of content to detect actual overlap
	// Check prefix and suffix regions for similarity
	checkLen := la
	if lb < checkLen {
		checkLen = lb
	}
	if checkLen > 256 {
		checkLen = 256
	}
	matching := 0
	for i := 0; i < checkLen; i++ {
		if a[i] == b[i] {
			matching++
		}
	}
	// Require at least 80% byte-level similarity in the sample
	return float64(matching)/float64(checkLen) >= 0.8
}

// VerticalPrivilegeTest tests for vertical privilege escalation
func (s *Scanner) VerticalPrivilegeTest(ctx context.Context, adminEndpoints []string, userToken string) []Result {
	results := make([]Result, 0)

	for _, endpoint := range adminEndpoints {
		result := s.testWithToken(ctx, endpoint, userToken)
		if result.StatusCode >= 200 && result.StatusCode < 300 {
			result.Vulnerability = "Vertical Privilege Escalation"
			result.Severity = "critical"
			result.Accessible = true
			results = append(results, result)
		}
	}

	return results
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// GeneratePayloads generates IDOR test payloads
func GeneratePayloads() []string {
	return []string{
		"../user/1",
		"../user/2",
		"?user_id=1",
		"?id=1",
		"?account=admin",
		"/api/v1/users/1",
		"/api/v1/users/0",
		"/api/v1/users/-1",
		"/api/v1/users/999999",
		"1' OR '1'='1",
		"1; DROP TABLE users--",
	}
}

// CommonEndpoints returns common IDOR-prone endpoints
func CommonEndpoints() []string {
	return []string{
		"/api/users/{id}",
		"/api/accounts/{id}",
		"/api/orders/{id}",
		"/api/invoices/{id}",
		"/api/documents/{id}",
		"/api/files/{id}",
		"/api/messages/{id}",
		"/api/profile/{id}",
		"/api/settings/{id}",
		"/admin/users/{id}",
	}
}
