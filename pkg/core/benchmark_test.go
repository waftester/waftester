package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
)

// --- Sample data for benchmarks ---

// sampleBody1KB is a realistic 1KB HTML response body.
var sampleBody1KB = strings.Repeat("<html><body><h1>Welcome</h1><p>This is a test page with sample content.</p></body></html>", 10)

// sampleBody10KB is a 10KB response body with realistic content that exercises evidence pattern matching.
var sampleBody10KB = strings.Repeat(
	"<html><body>\n"+
		"<h1>Application Dashboard</h1>\n"+
		"<p>Welcome to the application. Server version v2.3.1 running on nginx/1.21.0</p>\n"+
		"<div>Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"+
		"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n"+
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.</div>\n"+
		"<footer>Powered by Apache/2.4.51 (Ubuntu) PHP/8.1.2</footer>\n"+
		"</body></html>\n", 15)

// sampleHeaders simulates WAF-related response headers.
var sampleHeaders = http.Header{
	"Server":                    {"cloudflare"},
	"Cf-Ray":                    {"abc123def456-IAD"},
	"Cf-Cache-Status":           {"DYNAMIC"},
	"Content-Type":              {"text/html; charset=utf-8"},
	"X-Content-Type-Options":    {"nosniff"},
	"X-Frame-Options":           {"DENY"},
	"X-Request-Id":              {"req-abcdef-123456"},
	"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
	"X-Powered-By":              {"Express"},
	"Cache-Control":             {"no-cache, no-store, must-revalidate"},
}

// BenchmarkExecuteTest benchmarks a single executeTest call against an httptest server.
func BenchmarkExecuteTest(b *testing.B) {
	body := sampleBody1KB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	cfg := ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100000, // High limit to avoid throttling benchmarks
		Timeout:     5 * time.Second,
		Retries:     0,
		SkipVerify:  true,
	}
	executor := NewExecutor(cfg)
	defer executor.Close()

	payload := payloads.Payload{
		ID:            "bench-sqli-1",
		Payload:       "' OR '1'='1'--",
		Category:      "sqli",
		ExpectedBlock: true,
		SeverityHint:  "high",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = executor.executeTest(ctx, payload)
	}
}

// BenchmarkEvidencePatternMatching benchmarks all 9 pre-compiled evidence pattern regexes
// against a realistic 10KB response body.
func BenchmarkEvidencePatternMatching(b *testing.B) {
	body := sampleBody10KB

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ep := range evidencePatterns {
			_ = ep.pattern.MatchString(body)
		}
	}
}

// BenchmarkEvidencePatternMatching_NoMatch benchmarks evidence patterns against a body
// with zero matches (worst-case full scan).
func BenchmarkEvidencePatternMatching_NoMatch(b *testing.B) {
	// Body with no evidence markers at all
	body := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 250)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ep := range evidencePatterns {
			_ = ep.pattern.MatchString(body)
		}
	}
}

// BenchmarkFilterConfig_Match benchmarks the shouldShowResult filter matching logic
// with status code, content length, and word count filters.
func BenchmarkFilterConfig_Match(b *testing.B) {
	filter := &FilterConfig{
		MatchStatus: []int{200, 301, 403},
		FilterSize:  []int{0, 42},
		FilterWords: []int{1, 2},
		MatchLines:  []int{10, 20, 30, 40, 50},
	}

	cfg := ExecutorConfig{
		TargetURL:   "http://example.com",
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
		Filter:      filter,
	}
	executor := NewExecutor(cfg)
	defer executor.Close()

	result := &output.TestResult{
		StatusCode:    200,
		ContentLength: 1024,
		WordCount:     150,
		LineCount:     20,
	}
	body := sampleBody1KB

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = executor.shouldShowResult(result, body)
	}
}

// BenchmarkFilterConfig_FilterRegex benchmarks filter matching with regex filter.
func BenchmarkFilterConfig_FilterRegex(b *testing.B) {
	filter := &FilterConfig{
		FilterRegex: regexp.MustCompile("(?i)access denied|forbidden|blocked"),
		MatchStatus: []int{200, 403},
	}

	cfg := ExecutorConfig{
		TargetURL:   "http://example.com",
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
		Filter:      filter,
	}
	executor := NewExecutor(cfg)
	defer executor.Close()

	result := &output.TestResult{
		StatusCode:    200,
		ContentLength: 1024,
		WordCount:     150,
		LineCount:     20,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = executor.shouldShowResult(result, sampleBody10KB)
	}
}

// BenchmarkBuildTargetURL benchmarks URL construction with payload injection.
func BenchmarkBuildTargetURL(b *testing.B) {
	baseURLs := []string{
		"http://example.com",
		"https://api.example.com/v1",
		"https://target.example.com/search",
	}
	testPayloads := []string{
		"' OR '1'='1'--",
		"<script>alert(document.cookie)</script>",
		"{{7*7}}",
		"../../../etc/passwd",
		"; cat /etc/passwd",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base := baseURLs[i%len(baseURLs)]
		p := testPayloads[i%len(testPayloads)]
		_ = fmt.Sprintf("%s?test=%s", base, url.QueryEscape(p))
	}
}

// BenchmarkResponseHashing benchmarks SHA256 hashing of response bodies
// (the ResponseBodyHash computation used in captureResponseEvidence).
func BenchmarkResponseHashing(b *testing.B) {
	bodies := [][]byte{
		[]byte(sampleBody1KB),
		[]byte(sampleBody10KB),
		[]byte(strings.Repeat("x", 100*1024)), // 100KB body
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body := bodies[i%len(bodies)]
		hash := sha256.Sum256(body)
		_ = hex.EncodeToString(hash[:8])
	}
}

// BenchmarkResponseHashing_1KB benchmarks SHA256 hashing of 1KB response body.
func BenchmarkResponseHashing_1KB(b *testing.B) {
	body := []byte(sampleBody1KB)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256(body)
		_ = hex.EncodeToString(hash[:8])
	}
}

// BenchmarkCaptureResponseEvidence benchmarks the full captureResponseEvidence function.
func BenchmarkCaptureResponseEvidence(b *testing.B) {
	bodyStr := sampleBody10KB
	bodyBytes := []byte(bodyStr)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := &output.TestResult{
			ResponseHeaders: make(map[string]string),
		}
		captureResponseEvidence(result, bodyStr, bodyBytes)
	}
}

// BenchmarkSanitizeForJSON benchmarks the sanitizeForJSON function with realistic input.
func BenchmarkSanitizeForJSON(b *testing.B) {
	// Input with some control characters mixed in
	input := "Normal text\x00with\x01control\x02chars\nand newlines\tand tabs " + sampleBody1KB[:200]

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeForJSON(input)
	}
}

// BenchmarkCategorizeError benchmarks error categorization.
func BenchmarkCategorizeError(b *testing.B) {
	errors := []error{
		fmt.Errorf("dial tcp: lookup example.com: no such host"),
		fmt.Errorf("TLS handshake timeout"),
		fmt.Errorf("connection refused"),
		fmt.Errorf("context deadline exceeded"),
		fmt.Errorf("unexpected EOF"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = categorizeError(errors[i%len(errors)])
	}
}
