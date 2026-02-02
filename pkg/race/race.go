// Package race provides race condition vulnerability testing.
// It supports detection of TOCTOU, session fixation, double-submit,
// and other concurrency vulnerabilities.
package race

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// AttackType represents different race condition attack types
type AttackType string

const (
	AttackTOCTOU          AttackType = "toctou"           // Time-of-check to time-of-use
	AttackDoubleSubmit    AttackType = "double_submit"    // Form/payment double submission
	AttackSessionFixation AttackType = "session_fixation" // Session race condition
	AttackTokenReuse      AttackType = "token_reuse"      // Nonce/token reuse
	AttackResourceExhaust AttackType = "resource_exhaust" // Resource exhaustion via concurrency
	AttackLimitBypass     AttackType = "limit_bypass"     // Rate limit bypass via race
)

// Severity represents the severity of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// RequestConfig represents a request to be sent in a race
type RequestConfig struct {
	Method  string
	URL     string
	Body    string
	Headers http.Header
	Cookies []*http.Cookie
}

// Response represents a response from a race request
type Response struct {
	StatusCode   int
	Body         string
	Headers      http.Header
	ResponseTime time.Duration
	Error        error
	RequestIndex int
}

// Vulnerability represents a detected race condition vulnerability
type Vulnerability struct {
	Type        AttackType  `json:"type"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	Evidence    string      `json:"evidence"`
	URL         string      `json:"url"`
	Remediation string      `json:"remediation"`
	Responses   []*Response `json:"responses"`
}

// TesterConfig configures the race condition tester
type TesterConfig struct {
	Timeout        time.Duration
	UserAgent      string
	MaxConcurrency int           // Maximum concurrent requests
	Iterations     int           // Number of iterations
	DelayBetween   time.Duration // Delay between request batches
}

// DefaultConfig returns a default tester configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:        duration.HTTPFuzzing,
		UserAgent:      defaults.UAChrome,
		MaxConcurrency: 50,
		Iterations:     1,
		DelayBetween:   0,
	}
}

// Tester performs race condition testing
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// NewTester creates a new race condition tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	return &Tester{
		config: config,
		client: httpclient.Default(),
	}
}

// SendConcurrent sends multiple requests concurrently and returns all responses
func (t *Tester) SendConcurrent(ctx context.Context, requests []*RequestConfig) []*Response {
	// Limit to max concurrency
	requestsToSend := requests
	if len(requests) > t.config.MaxConcurrency {
		requestsToSend = requests[:t.config.MaxConcurrency]
	}

	responses := make([]*Response, len(requestsToSend))
	var wg sync.WaitGroup

	// Use a channel to synchronize start
	startChan := make(chan struct{})

	for i, reqConfig := range requestsToSend {
		wg.Add(1)
		go func(idx int, rc *RequestConfig) {
			defer wg.Done()

			// Wait for start signal
			<-startChan

			start := time.Now()
			resp, err := t.sendRequest(ctx, rc)
			elapsed := time.Since(start)

			responses[idx] = &Response{
				ResponseTime: elapsed,
				RequestIndex: idx,
				Error:        err,
			}

			if resp != nil {
				defer iohelper.DrainAndClose(resp.Body)
				body, _ := iohelper.ReadBodyDefault(resp.Body)
				responses[idx].StatusCode = resp.StatusCode
				responses[idx].Body = string(body)
				responses[idx].Headers = resp.Header
			}
		}(i, reqConfig)
	}

	// Signal all goroutines to start simultaneously
	close(startChan)

	wg.Wait()
	return responses
}

func (t *Tester) sendRequest(ctx context.Context, rc *RequestConfig) (*http.Response, error) {
	var body io.Reader
	if rc.Body != "" {
		body = strings.NewReader(rc.Body)
	}

	req, err := http.NewRequestWithContext(ctx, rc.Method, rc.URL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", t.config.UserAgent)

	for key, values := range rc.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	for _, cookie := range rc.Cookies {
		req.AddCookie(cookie)
	}

	return t.client.Do(req)
}

// TestDoubleSubmit tests for double-submit vulnerabilities (e.g., payment duplication)
func (t *Tester) TestDoubleSubmit(ctx context.Context, request *RequestConfig, numRequests int) (*Vulnerability, error) {
	requests := make([]*RequestConfig, numRequests)
	for i := 0; i < numRequests; i++ {
		requests[i] = request
	}

	responses := t.SendConcurrent(ctx, requests)

	// Analyze responses for double-submit vulnerability
	successCount := 0
	var successResponses []*Response

	for _, resp := range responses {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
			successResponses = append(successResponses, resp)
		}
	}

	// If more than one request succeeded, potential vulnerability
	if successCount > 1 {
		return &Vulnerability{
			Type:        AttackDoubleSubmit,
			Description: fmt.Sprintf("Double-submit vulnerability: %d out of %d concurrent requests succeeded", successCount, numRequests),
			Severity:    SeverityCritical,
			Evidence:    fmt.Sprintf("Multiple successful responses from concurrent identical requests"),
			URL:         request.URL,
			Remediation: "Implement idempotency tokens, database locks, or optimistic locking to prevent duplicate submissions",
			Responses:   successResponses,
		}, nil
	}

	return nil, nil
}

// TestTokenReuse tests for token/nonce reuse vulnerabilities
func (t *Tester) TestTokenReuse(ctx context.Context, request *RequestConfig, numRequests int) (*Vulnerability, error) {
	requests := make([]*RequestConfig, numRequests)
	for i := 0; i < numRequests; i++ {
		requests[i] = request
	}

	responses := t.SendConcurrent(ctx, requests)

	// Count successful and failed requests
	successCount := 0
	failCount := 0

	for _, resp := range responses {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		} else if resp.StatusCode >= 400 {
			failCount++
		}
	}

	// If multiple requests succeed with same token, vulnerability exists
	if successCount > 1 {
		return &Vulnerability{
			Type:        AttackTokenReuse,
			Description: fmt.Sprintf("Token reuse vulnerability: same token accepted %d times", successCount),
			Severity:    SeverityHigh,
			Evidence:    "Token/nonce accepted multiple times in concurrent requests",
			URL:         request.URL,
			Remediation: "Implement atomic token validation and invalidation using database transactions",
			Responses:   responses,
		}, nil
	}

	return nil, nil
}

// TestLimitBypass tests for rate limit bypass via race condition
func (t *Tester) TestLimitBypass(ctx context.Context, request *RequestConfig, numRequests int, expectedLimit int) (*Vulnerability, error) {
	requests := make([]*RequestConfig, numRequests)
	for i := 0; i < numRequests; i++ {
		requests[i] = request
	}

	responses := t.SendConcurrent(ctx, requests)

	successCount := 0
	rateLimitedCount := 0

	for _, resp := range responses {
		if resp.StatusCode == 429 {
			rateLimitedCount++
		} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}
	}

	// If we got more successes than the limit allows, bypass detected
	if successCount > expectedLimit {
		return &Vulnerability{
			Type:        AttackLimitBypass,
			Description: fmt.Sprintf("Rate limit bypass: %d requests succeeded, expected limit was %d", successCount, expectedLimit),
			Severity:    SeverityMedium,
			Evidence:    fmt.Sprintf("Concurrent requests bypassed rate limit: %d succeeded vs %d limit", successCount, expectedLimit),
			URL:         request.URL,
			Remediation: "Use atomic counters with database transactions or distributed locks for rate limiting",
			Responses:   responses,
		}, nil
	}

	return nil, nil
}

// TestSequential tests sequential access for TOCTOU vulnerabilities
func (t *Tester) TestSequential(ctx context.Context, checkRequest *RequestConfig, useRequest *RequestConfig, numAttempts int) (*Vulnerability, error) {
	// This simulates TOCTOU by rapidly alternating between check and use
	var successCount int32
	var wg sync.WaitGroup

	for i := 0; i < numAttempts; i++ {
		wg.Add(2)

		// Check request
		go func() {
			defer wg.Done()
			resp, _ := t.sendRequest(ctx, checkRequest)
			if resp != nil && resp.Body != nil {
				iohelper.DrainAndClose(resp.Body)
			}
		}()

		// Use request (slightly delayed)
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond)
			resp, err := t.sendRequest(ctx, useRequest)
			if err == nil && resp != nil {
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					atomic.AddInt32(&successCount, 1)
				}
				iohelper.DrainAndClose(resp.Body)
			}
		}()
	}

	wg.Wait()

	// If use succeeded multiple times while checks were happening, TOCTOU may exist
	if successCount > int32(numAttempts/2) {
		return &Vulnerability{
			Type:        AttackTOCTOU,
			Description: fmt.Sprintf("Potential TOCTOU: %d uses succeeded during concurrent checks", successCount),
			Severity:    SeverityHigh,
			Evidence:    "Multiple 'use' operations succeeded while 'check' was in progress",
			URL:         useRequest.URL,
			Remediation: "Use atomic operations or database transactions to combine check and use into single atomic operation",
		}, nil
	}

	return nil, nil
}

// Result represents a race condition scan result
type Result struct {
	URL             string           `json:"url"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	TotalRequests   int              `json:"total_requests"`
	Duration        time.Duration    `json:"duration"`
}

// AnalyzeResponses analyzes a set of responses for anomalies indicating race conditions
func AnalyzeResponses(responses []*Response) *RaceAnalysis {
	analysis := &RaceAnalysis{
		TotalResponses: len(responses),
	}

	if len(responses) == 0 {
		return analysis
	}

	statusCounts := make(map[int]int)
	var responseTimes []time.Duration
	uniqueBodies := make(map[string]int)

	for _, r := range responses {
		statusCounts[r.StatusCode]++
		responseTimes = append(responseTimes, r.ResponseTime)

		// Hash or truncate body for comparison
		bodyKey := r.Body
		if len(bodyKey) > 500 {
			bodyKey = bodyKey[:500]
		}
		uniqueBodies[bodyKey]++
	}

	analysis.StatusDistribution = statusCounts
	analysis.UniqueBodyCount = len(uniqueBodies)

	// Calculate timing statistics
	if len(responseTimes) > 0 {
		var total time.Duration
		min := responseTimes[0]
		max := responseTimes[0]

		for _, t := range responseTimes {
			total += t
			if t < min {
				min = t
			}
			if t > max {
				max = t
			}
		}

		analysis.AvgResponseTime = total / time.Duration(len(responseTimes))
		analysis.MinResponseTime = min
		analysis.MaxResponseTime = max
		analysis.TimeVariance = max - min
	}

	// Detect anomalies
	analysis.HasAnomaly = analysis.UniqueBodyCount > 1 || len(statusCounts) > 1

	return analysis
}

// RaceAnalysis contains analysis of race condition test responses
type RaceAnalysis struct {
	TotalResponses     int           `json:"total_responses"`
	StatusDistribution map[int]int   `json:"status_distribution"`
	UniqueBodyCount    int           `json:"unique_body_count"`
	AvgResponseTime    time.Duration `json:"avg_response_time"`
	MinResponseTime    time.Duration `json:"min_response_time"`
	MaxResponseTime    time.Duration `json:"max_response_time"`
	TimeVariance       time.Duration `json:"time_variance"`
	HasAnomaly         bool          `json:"has_anomaly"`
}

// CreateBurst creates multiple identical request configs for burst testing
func CreateBurst(baseRequest *RequestConfig, count int) []*RequestConfig {
	requests := make([]*RequestConfig, count)
	for i := 0; i < count; i++ {
		requests[i] = &RequestConfig{
			Method:  baseRequest.Method,
			URL:     baseRequest.URL,
			Body:    baseRequest.Body,
			Headers: baseRequest.Headers.Clone(),
			Cookies: append([]*http.Cookie{}, baseRequest.Cookies...),
		}
	}
	return requests
}

// AllAttackTypes returns all race condition attack types
func AllAttackTypes() []AttackType {
	return []AttackType{
		AttackTOCTOU,
		AttackDoubleSubmit,
		AttackSessionFixation,
		AttackTokenReuse,
		AttackResourceExhaust,
		AttackLimitBypass,
	}
}

// CommonTargets returns common endpoints vulnerable to race conditions
func CommonTargets() []string {
	return []string{
		"/api/checkout",
		"/api/payment",
		"/api/transfer",
		"/api/redeem",
		"/api/coupon",
		"/api/discount",
		"/api/vote",
		"/api/like",
		"/api/follow",
		"/api/register",
		"/api/verify",
		"/api/password-reset",
		"/api/email-verify",
		"/api/activate",
		"/api/withdraw",
		"/api/deposit",
		"/api/claim",
		"/api/referral",
	}
}

// Scan performs a comprehensive race condition scan
func (t *Tester) Scan(ctx context.Context, request *RequestConfig) (*Result, error) {
	start := time.Now()

	result := &Result{
		URL: request.URL,
	}

	var vulns []*Vulnerability

	// Test double-submit (10 concurrent requests)
	vuln, err := t.TestDoubleSubmit(ctx, request, 10)
	if err != nil {
		return nil, err
	}
	if vuln != nil {
		vulns = append(vulns, vuln)
	}
	result.TotalRequests += 10

	// Test token reuse (5 concurrent requests)
	vuln, err = t.TestTokenReuse(ctx, request, 5)
	if err != nil {
		return nil, err
	}
	if vuln != nil {
		vulns = append(vulns, vuln)
	}
	result.TotalRequests += 5

	result.Vulnerabilities = vulns
	result.Duration = time.Since(start)

	return result, nil
}

// GetRemediation returns remediation advice for an attack type
func GetRemediation(attackType AttackType) string {
	remediations := map[AttackType]string{
		AttackTOCTOU:          "Use atomic operations combining check and use into single database transaction. Implement row-level locking.",
		AttackDoubleSubmit:    "Implement idempotency keys, use database constraints, or apply optimistic/pessimistic locking.",
		AttackSessionFixation: "Regenerate session IDs after authentication. Use secure session management.",
		AttackTokenReuse:      "Invalidate tokens atomically before processing. Use database transactions for token validation.",
		AttackResourceExhaust: "Implement proper resource pooling with atomic acquisition. Use semaphores or distributed locks.",
		AttackLimitBypass:     "Use atomic counters with Redis or database. Implement sliding window rate limiting.",
	}

	if r, ok := remediations[attackType]; ok {
		return r
	}
	return "Implement proper concurrency controls using atomic operations, locks, or transactions."
}
