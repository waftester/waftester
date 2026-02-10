// Package cachepoisoning provides Web Cache Poisoning testing
package cachepoisoning

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures cache poisoning testing
type Config struct {
	attackconfig.Base
	Headers        map[string]string
	CallbackDomain string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyLow,
			Timeout:     httpclient.TimeoutScanning,
		},
	}
}

// Result represents a cache poisoning test result
type Result struct {
	URL          string
	Technique    string
	Header       string
	Payload      string
	IsCached     bool
	CacheHeaders map[string]string
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs cache poisoning testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new cache poisoning scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyLow
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutScanning
	}

	return &Scanner{
		config:  config,
		client:  httpclient.Scanning(),
		results: make([]Result, 0),
	}
}

// Scan tests a URL for cache poisoning vulnerabilities
func (s *Scanner) Scan(ctx context.Context, targetURL string) ([]Result, error) {
	results := make([]Result, 0)

	// Test unkeyed headers
	for _, header := range UnkeyedHeaders() {
		result := s.testUnkeyedHeader(ctx, targetURL, header)
		if result.Vulnerable {
			results = append(results, result)
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// testUnkeyedHeader tests if a header is reflected in cached response
func (s *Scanner) testUnkeyedHeader(ctx context.Context, targetURL, header string) Result {
	cacheBuster := generateCacheBuster()
	var testURL string
	if strings.Contains(targetURL, "?") {
		testURL = targetURL + "&cb=" + cacheBuster
	} else {
		testURL = targetURL + "?cb=" + cacheBuster
	}

	result := Result{
		URL:       testURL,
		Technique: "Unkeyed Header",
		Header:    header,
		Timestamp: time.Now(),
	}

	// Generate unique payload
	payload := "POISON_" + cacheBuster

	// First request with poisoned header
	req1, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return result
	}
	req1.Header.Set(header, payload)
	for k, v := range s.config.Headers {
		req1.Header.Set(k, v)
	}

	resp1, err := s.client.Do(req1)
	if err != nil {
		return result
	}
	body1, _ := iohelper.ReadBodyDefault(resp1.Body)
	iohelper.DrainAndClose(resp1.Body)

	result.CacheHeaders = extractCacheHeaders(resp1.Header)
	result.IsCached = isCacheableResponse(resp1.Header)
	result.Payload = payload

	// Check if payload reflected in first response
	if strings.Contains(string(body1), payload) {
		// Second request without poisoned header
		req2, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			return result
		}
		for k, v := range s.config.Headers {
			req2.Header.Set(k, v)
		}

		resp2, err := s.client.Do(req2)
		if err != nil {
			return result
		}
		body2, _ := iohelper.ReadBodyDefault(resp2.Body)
		iohelper.DrainAndClose(resp2.Body)

		// Check if poison persisted in cache
		if strings.Contains(string(body2), payload) {
			result.Vulnerable = true
			result.Evidence = "Unkeyed header " + header + " poisoned cache"
			result.Severity = "HIGH"
		}
	}

	return result
}

// extractCacheHeaders extracts cache-related headers
func extractCacheHeaders(headers http.Header) map[string]string {
	cacheHeaders := make(map[string]string)
	keys := []string{
		"Cache-Control",
		"Age",
		"X-Cache",
		"X-Cache-Hit",
		"CF-Cache-Status",
		"X-Varnish",
		"X-Served-By",
		"Vary",
	}
	for _, key := range keys {
		if val := headers.Get(key); val != "" {
			cacheHeaders[key] = val
		}
	}
	return cacheHeaders
}

// isCacheableResponse checks if response appears to be cached
func isCacheableResponse(headers http.Header) bool {
	// Check for cache hit indicators
	if strings.Contains(strings.ToLower(headers.Get("X-Cache")), "hit") {
		return true
	}
	if headers.Get("CF-Cache-Status") == "HIT" {
		return true
	}
	if headers.Get("Age") != "" {
		return true
	}
	return false
}

func generateCacheBuster() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// UnkeyedHeaders returns headers commonly not included in cache keys
func UnkeyedHeaders() []string {
	return []string{
		"X-Forwarded-Host",
		"X-Forwarded-Scheme",
		"X-Forwarded-Proto",
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-Host",
		"X-Forwarded-Server",
		"Forwarded",
		"Origin",
		"X-Custom-IP-Authorization",
		"X-Original-Host",
		"Pragma",
		"Cache-Control",
		"X-Requested-With",
		"Accept-Language",
		"Accept-Encoding",
		"X-Forwarded-For",
		"X-Real-IP",
		"True-Client-IP",
	}
}

// FatGetPayloads returns payloads for fat GET cache poisoning
func FatGetPayloads() map[string]string {
	return map[string]string{
		"callback": "alert(1)",
		"jsonp":    "alert",
		"cb":       "malicious",
	}
}

// ParameterClobberingPayloads returns payloads for parameter clobbering
func ParameterClobberingPayloads() []string {
	return []string{
		"utm_source=evil&utm_medium=cache",
		"fb_action_ids=evil",
		"_ga=poison",
	}
}
