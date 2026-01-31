// Package apiabuse provides API abuse testing capabilities
package apiabuse

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures API abuse testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	RateLimit   int // requests per second limit to test
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: 5,
		Timeout:     10 * time.Second,
		RateLimit:   100,
	}
}

// Result represents an API abuse test result
type Result struct {
	URL          string
	TestType     string
	Method       string
	StatusCode   int
	ResponseTime time.Duration
	RateLimited  bool
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs API abuse testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new API abuse scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = 5
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.RateLimit <= 0 {
		config.RateLimit = 100
	}

	return &Scanner{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		results: make([]Result, 0),
	}
}

// TestRateLimiting tests if rate limiting is properly implemented
func (s *Scanner) TestRateLimiting(ctx context.Context, targetURL string, requests int) (Result, error) {
	result := Result{
		URL:       targetURL,
		TestType:  "rate_limiting",
		Method:    "GET",
		Timestamp: time.Now(),
	}

	successCount := 0
	var lastStatusCode int
	var totalTime time.Duration

	for i := 0; i < requests; i++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		for k, v := range s.config.Headers {
			req.Header.Set(k, v)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()

		totalTime += time.Since(start)
		lastStatusCode = resp.StatusCode

		if resp.StatusCode == 429 {
			result.RateLimited = true
			break
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}
	}

	result.StatusCode = lastStatusCode
	result.ResponseTime = totalTime / time.Duration(requests)

	if !result.RateLimited && successCount == requests {
		result.Vulnerable = true
		result.Evidence = "No rate limiting detected after " + string(rune(requests)) + " requests"
		result.Severity = "MEDIUM"
	}

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	return result, nil
}

// TestResourceExhaustion tests for resource exhaustion vulnerabilities
func (s *Scanner) TestResourceExhaustion(ctx context.Context, targetURL string) ([]Result, error) {
	results := make([]Result, 0)

	for _, payload := range ResourceExhaustionPayloads() {
		result := s.testResourcePayload(ctx, targetURL, payload)
		results = append(results, result)
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// ResourcePayload represents a resource exhaustion payload
type ResourcePayload struct {
	Name        string
	Payload     interface{}
	ContentType string
	Method      string
}

func (s *Scanner) testResourcePayload(ctx context.Context, targetURL string, payload ResourcePayload) Result {
	result := Result{
		URL:       targetURL,
		TestType:  "resource_exhaustion",
		Method:    payload.Method,
		Timestamp: time.Now(),
	}

	var body io.Reader
	if payload.Payload != nil {
		jsonData, _ := json.Marshal(payload.Payload)
		body = strings.NewReader(string(jsonData))
	}

	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, payload.Method, targetURL, body)
	if payload.ContentType != "" {
		req.Header.Set("Content-Type", payload.ContentType)
	}
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	io.ReadAll(resp.Body)
	result.ResponseTime = time.Since(start)
	result.StatusCode = resp.StatusCode

	// Check for slow response (potential DoS)
	if result.ResponseTime > 5*time.Second {
		result.Vulnerable = true
		result.Evidence = "Slow response: " + result.ResponseTime.String()
		result.Severity = "HIGH"
	}

	return result
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// ResourceExhaustionPayloads returns payloads for resource exhaustion testing
func ResourceExhaustionPayloads() []ResourcePayload {
	return []ResourcePayload{
		// Deep nesting JSON
		{
			Name:        "deep_nesting",
			Payload:     generateDeepJSON(50),
			ContentType: "application/json",
			Method:      "POST",
		},
		// Large array
		{
			Name:        "large_array",
			Payload:     generateLargeArray(10000),
			ContentType: "application/json",
			Method:      "POST",
		},
		// Long string
		{
			Name:        "long_string",
			Payload:     map[string]string{"data": strings.Repeat("A", 100000)},
			ContentType: "application/json",
			Method:      "POST",
		},
	}
}

func generateDeepJSON(depth int) interface{} {
	if depth <= 0 {
		return "leaf"
	}
	return map[string]interface{}{
		"nested": generateDeepJSON(depth - 1),
	}
}

func generateLargeArray(size int) []interface{} {
	arr := make([]interface{}, size)
	for i := range arr {
		arr[i] = i
	}
	return arr
}

// BruteForcePayloads returns common brute force attack payloads
func BruteForcePayloads() map[string][]string {
	return map[string][]string{
		"username": {
			"admin", "administrator", "root", "user", "test",
			"guest", "info", "adm", "mysql", "postgres",
		},
		"password": {
			"password", "123456", "admin", "12345678", "qwerty",
			"password123", "letmein", "welcome", "monkey", "dragon",
		},
	}
}

// CommonAPIEndpoints returns common API endpoints to test
func CommonAPIEndpoints() []string {
	return []string{
		"/api/v1/users",
		"/api/v1/admin",
		"/api/login",
		"/api/register",
		"/api/users/me",
		"/api/config",
		"/api/settings",
		"/graphql",
		"/api/debug",
		"/api/internal",
	}
}
