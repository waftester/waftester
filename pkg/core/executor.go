package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/realistic"
	"github.com/waftester/waftester/pkg/scoring"
	"github.com/waftester/waftester/pkg/ui"
	"golang.org/x/time/rate"
)

// FilterConfig holds match/filter settings (ffuf-style)
type FilterConfig struct {
	// Match criteria (show ONLY responses matching these)
	MatchStatus []int          // HTTP status codes to match
	MatchSize   []int          // Content length values to match
	MatchWords  []int          // Word count values to match
	MatchLines  []int          // Line count values to match
	MatchRegex  *regexp.Regexp // Body regex pattern to match

	// Filter criteria (EXCLUDE responses matching these)
	FilterStatus []int          // HTTP status codes to exclude
	FilterSize   []int          // Content length values to exclude
	FilterWords  []int          // Word count values to exclude
	FilterLines  []int          // Line count values to exclude
	FilterRegex  *regexp.Regexp // Body regex pattern to exclude
}

// ExecutorConfig holds execution settings
type ExecutorConfig struct {
	TargetURL     string
	Concurrency   int
	RateLimit     int
	Timeout       time.Duration
	Retries       int
	Proxy         string
	SkipVerify    bool
	Filter        *FilterConfig // Optional filter configuration
	RealisticMode bool          // Use realistic request building and block detection
	AutoCalibrate bool          // Auto-calibrate before testing
	HTTPClient    *http.Client  // Optional custom HTTP client (e.g., JA3-aware)
}

// Executor runs security tests in parallel
type Executor struct {
	config     ExecutorConfig
	httpClient *http.Client
	limiter    *rate.Limiter
	enhancer   *realistic.ExecutorEnhancer // Realistic mode enhancer
}

// NewExecutor creates a new parallel executor
func NewExecutor(cfg ExecutorConfig) *Executor {
	// Validate and apply defaults for invalid config values
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1 // Default to 1 worker
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 100 // Default to 100 requests/sec
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second // Default 30 second timeout
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0 // No negative retries
	}

	// Use provided HTTPClient (e.g., JA3-aware) or create default
	var client *http.Client
	if cfg.HTTPClient != nil {
		client = cfg.HTTPClient
	} else {
		// Create HTTP client with connection pooling
		transport := &http.Transport{
			MaxIdleConns:        cfg.Concurrency * 2,
			MaxIdleConnsPerHost: cfg.Concurrency,
			MaxConnsPerHost:     cfg.Concurrency,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipVerify,
			},
		}

		// Add proxy if configured
		if cfg.Proxy != "" {
			proxyURL, err := url.Parse(cfg.Proxy)
			if err == nil && proxyURL != nil {
				transport.Proxy = http.ProxyURL(proxyURL)
			}
			// Silently ignore malformed proxy URLs - continue without proxy
		}

		client = &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}
	}

	// Create rate limiter (token bucket)
	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)

	executor := &Executor{
		config:     cfg,
		httpClient: client,
		limiter:    limiter,
	}

	// Initialize realistic mode enhancer if enabled
	if cfg.RealisticMode {
		executor.enhancer = realistic.NewExecutorEnhancer(cfg.TargetURL)
	}

	return executor
}

// Execute runs all payloads with worker pool pattern
func (e *Executor) Execute(ctx context.Context, allPayloads []payloads.Payload, writer output.Writer) output.ExecutionResults {
	results := output.ExecutionResults{
		TotalTests: len(allPayloads),
		StartTime:  time.Now(),
	}

	// Auto-calibrate if realistic mode is enabled
	if e.enhancer != nil && e.config.AutoCalibrate {
		if err := e.enhancer.Calibrate(ctx); err != nil {
			// Log calibration failure but continue
			fmt.Printf("Warning: Auto-calibration failed: %v\n", err)
		}
	}

	// Create channels for work distribution
	tasks := make(chan payloads.Payload, e.config.Concurrency*2)
	resultsChan := make(chan *output.TestResult, e.config.Concurrency*2)

	// Atomic counters for progress
	var completed int64
	var blocked, passed, failed, errored int64

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for payload := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
					// Rate limit
					e.limiter.Wait(ctx)

					// Execute test
					result := e.executeTest(ctx, payload)
					resultsChan <- result

					// Update counters
					atomic.AddInt64(&completed, 1)
					switch result.Outcome {
					case "Blocked":
						atomic.AddInt64(&blocked, 1)
					case "Pass":
						atomic.AddInt64(&passed, 1)
					case "Fail":
						atomic.AddInt64(&failed, 1)
					case "Error":
						atomic.AddInt64(&errored, 1)
					}
				}
			}
		}(i)
	}

	// Result collector goroutine
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for result := range resultsChan {
			writer.Write(result)
		}
	}()

	// Progress display goroutine
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				done := atomic.LoadInt64(&completed)
				elapsed := time.Since(results.StartTime).Seconds()
				rps := float64(done) / elapsed
				fmt.Printf("\r[*] Progress: %d/%d (%.1f/sec) | Blocked: %d | Pass: %d | Fail: %d | Error: %d",
					done, results.TotalTests, rps,
					atomic.LoadInt64(&blocked),
					atomic.LoadInt64(&passed),
					atomic.LoadInt64(&failed),
					atomic.LoadInt64(&errored))
			case <-progressDone:
				return
			}
		}
	}()

	// Send all payloads to workers
sendLoop:
	for _, payload := range allPayloads {
		select {
		case <-ctx.Done():
			break sendLoop
		case tasks <- payload:
		}
	}
	close(tasks)

	// Wait for workers to complete
	wg.Wait()
	close(resultsChan)

	// Wait for collector
	collectorWg.Wait()
	close(progressDone)

	// Final stats
	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	results.BlockedTests = int(atomic.LoadInt64(&blocked))
	results.PassedTests = int(atomic.LoadInt64(&passed))
	results.FailedTests = int(atomic.LoadInt64(&failed))
	results.ErrorTests = int(atomic.LoadInt64(&errored))
	if results.Duration.Seconds() > 0 {
		results.RequestsPerSec = float64(results.TotalTests) / results.Duration.Seconds()
	}

	fmt.Println() // New line after progress
	return results
}

// executeTest runs a single payload test
func (e *Executor) executeTest(ctx context.Context, payload payloads.Payload) *output.TestResult {
	// Determine HTTP method (default to GET for standard payloads)
	method := payload.Method
	if method == "" {
		method = "GET"
	}

	result := &output.TestResult{
		ID:              payload.ID,
		Category:        payload.Category,
		Severity:        payload.SeverityHint,
		Payload:         payload.Payload,
		Timestamp:       time.Now().Format("15:04:05"),
		Method:          method,
		TargetPath:      payload.TargetPath,
		ContentType:     payload.ContentType,
		ResponseHeaders: make(map[string]string),
		// Copy encoding info from payload for effectiveness tracking
		EncodingUsed:    payload.EncodingUsed,
		MutationType:    payload.MutationType,
		OriginalPayload: payload.OriginalPayload,
	}

	var req *http.Request
	var err error

	// Determine target URL (use TargetPath if specified, otherwise use base URL)
	targetURL := e.config.TargetURL
	if payload.TargetPath != "" {
		// Parse base URL and append target path
		baseURL, parseErr := url.Parse(e.config.TargetURL)
		if parseErr == nil {
			baseURL.Path = payload.TargetPath
			targetURL = baseURL.String()
		}
	}
	result.RequestURL = targetURL

	// Build request using realistic mode or legacy mode
	if e.enhancer != nil && e.config.RealisticMode {
		// Use realistic request builder with rotating templates
		template := e.enhancer.RotateTemplate()

		// Override template path if payload specifies target
		if payload.TargetPath != "" {
			template.Path = payload.TargetPath
		}

		// Handle method override
		if method != "" {
			template.Method = method
		}

		req, err = e.enhancer.BuildRequestWithTemplate(payload.Payload, template)
		if err == nil {
			req = req.WithContext(ctx)
		}
	} else if method == "POST" && payload.ContentType != "" {
		// Legacy: For POST with body (custom payloads from 'learn' command)
		// The payload IS the body (e.g., JSON like {"message": "' OR '1'='1"})
		body := strings.NewReader(payload.Payload)
		req, err = http.NewRequestWithContext(ctx, method, targetURL, body)
		if err == nil {
			req.Header.Set("Content-Type", payload.ContentType)
		}
	} else {
		// Legacy: For GET or simple payloads, inject in URL parameter
		targetWithPayload := fmt.Sprintf("%s?test=%s", targetURL, url.QueryEscape(payload.Payload))
		req, err = http.NewRequestWithContext(ctx, method, targetWithPayload, nil)
	}

	if err != nil {
		result.Outcome = "Error"
		result.ErrorMessage = err.Error()
		// Calculate risk score for error case
		result.RiskScore = scoring.Calculate(scoring.Input{
			Severity: payload.SeverityHint,
			Outcome:  result.Outcome,
			Category: payload.Category,
		})
		return result
	}

	// Only set static User-Agent if not using realistic mode
	if e.enhancer == nil || !e.config.RealisticMode {
		req.Header.Set("User-Agent", ui.UserAgent())
	}

	start := time.Now()

	// Execute with retry
	var resp *http.Response
	for attempt := 0; attempt <= e.config.Retries; attempt++ {
		resp, err = e.httpClient.Do(req)
		if err == nil {
			break
		}
		if attempt < e.config.Retries {
			time.Sleep(100 * time.Millisecond)
		}
	}

	result.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Outcome = "Error"
		// Categorize the error for better analysis
		result.ErrorMessage = categorizeError(err)
		// Calculate risk score for error case
		result.RiskScore = scoring.Calculate(scoring.Input{
			Severity: payload.SeverityHint,
			Outcome:  result.Outcome,
			Category: payload.Category,
		})
		return result
	}
	defer resp.Body.Close()

	// Capture important response headers (WAF-related)
	wafHeaders := []string{
		"X-Waf-Rule", "X-Mod-Security-Message", "X-Coraza-Rule",
		"X-Block-Reason", "X-Denied-Reason", "X-Request-Id",
		"Server", "X-Powered-By", "X-Content-Type-Options",
		"X-Modsecurity-Rule-Id", "X-Waf-Event-Id",
	}
	for _, h := range wafHeaders {
		if v := resp.Header.Get(h); v != "" {
			result.ResponseHeaders[h] = v
		}
	}

	// Extract WAF rule ID from common headers/patterns
	for _, h := range []string{"X-Waf-Rule", "X-Mod-Security-Message", "X-Coraza-Rule", "X-Modsecurity-Rule-Id"} {
		if v := resp.Header.Get(h); v != "" {
			result.WAFRuleID = v
			break
		}
	}

	// Read response body for filtering (limited to 1MB)
	bodyBytes := make([]byte, 0, 1024*1024)
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			bodyBytes = append(bodyBytes, buf[:n]...)
			if len(bodyBytes) >= 1024*1024 {
				break // Limit to 1MB
			}
		}
		if readErr != nil {
			break
		}
	}
	bodyStr := string(bodyBytes)

	// Calculate word and line counts for filtering
	result.WordCount = len(strings.Fields(bodyStr))
	result.LineCount = strings.Count(bodyStr, "\n") + 1
	if len(bodyStr) == 0 {
		result.LineCount = 0
	}
	result.ContentLength = len(bodyBytes)

	result.StatusCode = resp.StatusCode

	// Apply filters if configured
	if e.config.Filter != nil {
		if !e.shouldShowResult(result, bodyStr) {
			result.Filtered = true
			return result
		}
	}

	// Determine outcome using realistic block detection or legacy method
	var isBlocked bool
	var blockConfidence float64

	if e.enhancer != nil && e.config.RealisticMode {
		// Use intelligent block detection
		blockResult, detectErr := e.enhancer.AnalyzeResponse(
			&http.Response{
				StatusCode: resp.StatusCode,
				Body:       io.NopCloser(strings.NewReader(bodyStr)),
				Header:     resp.Header,
			},
			time.Duration(result.LatencyMs)*time.Millisecond,
		)
		if detectErr == nil {
			isBlocked = blockResult.IsBlocked
			blockConfidence = blockResult.Confidence
		} else {
			// Fall back to status code check
			isBlocked = resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429
		}
	} else {
		// Legacy: Simple status code check
		isBlocked = resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429
	}

	// Store block confidence as numeric value
	result.BlockConfidence = blockConfidence

	// Determine outcome based on detection and expectations
	if isBlocked {
		result.Outcome = "Blocked"
		if blockConfidence > 0 {
			result.ErrorMessage = fmt.Sprintf("Block confidence: %.0f%%", blockConfidence*100)
		}
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if payload.ExpectedBlock {
			result.Outcome = "Fail" // Should have been blocked!
			// Generate curl command for bypass reproduction
			result.CurlCommand = generateCurlCommand(req)

			// Capture response evidence for bypass analysis
			captureResponseEvidence(result, bodyStr, bodyBytes)
		} else {
			result.Outcome = "Pass"
		}
	} else if resp.StatusCode == 404 {
		result.Outcome = "Pass" // Endpoint doesn't exist
	} else {
		result.Outcome = "Error"
		result.ErrorMessage = fmt.Sprintf("Unexpected status: %d", resp.StatusCode)
	}

	// Check for XSS reflection (payload appears in response)
	reflected := false
	if payload.Category == "xss" || payload.Category == "XSS" {
		// Check if key parts of payload are reflected
		payloadCheck := payload.Payload
		if len(payloadCheck) > 20 {
			payloadCheck = payloadCheck[:20] // Check first 20 chars
		}
		reflected = strings.Contains(bodyStr, payloadCheck)
	}

	// Calculate risk score with full context
	result.RiskScore = scoring.Calculate(scoring.Input{
		Severity:         payload.SeverityHint,
		Outcome:          result.Outcome,
		StatusCode:       result.StatusCode,
		LatencyMs:        result.LatencyMs,
		Category:         payload.Category,
		ResponseContains: bodyStr, // Pass response body for pattern detection
		Reflected:        reflected,
	})

	return result
}

// generateCurlCommand creates a curl command to reproduce the request
func generateCurlCommand(req *http.Request) string {
	if req == nil {
		return ""
	}
	cmd := fmt.Sprintf("curl -X %s '%s'", req.Method, req.URL.String())
	for k, v := range req.Header {
		if len(v) > 0 && k != "User-Agent" {
			cmd += fmt.Sprintf(" -H '%s: %s'", k, v[0])
		}
	}
	return cmd
}

// captureResponseEvidence captures response body evidence for bypass analysis
func captureResponseEvidence(result *output.TestResult, bodyStr string, bodyBytes []byte) {
	// Capture snippet (first 300 chars, sanitized)
	snippet := bodyStr
	if len(snippet) > 300 {
		snippet = snippet[:300] + "..."
	}
	result.ResponseBodySnippet = sanitizeForJSON(snippet)

	// Hash for deduplication (first 16 hex chars of SHA256)
	hash := sha256.Sum256(bodyBytes)
	result.ResponseBodyHash = hex.EncodeToString(hash[:8])

	// Look for evidence markers indicating vulnerability exploitation
	evidencePatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"sql_error", regexp.MustCompile(`(?i)(mysql|postgresql|oracle|sqlite|sql syntax|query failed|ORA-\d+)`)},
		{"stack_trace", regexp.MustCompile(`(?i)(stack trace|at line \d+|exception|Traceback|panic:)`)},
		{"debug_info", regexp.MustCompile(`(?i)(debug|internal error|undefined variable|Notice:)`)},
		{"path_disclosure", regexp.MustCompile(`[A-Z]:\\|/var/www/|/home/\w+|/usr/local/`)},
		{"version_disclosure", regexp.MustCompile(`(?i)(version|v\d+\.\d+\.\d+|PHP/|Apache/|nginx/)`)},
		{"sensitive_data", regexp.MustCompile(`(?i)(password|secret|api.?key|token|credential)`)},
		{"command_output", regexp.MustCompile(`(?i)(uid=\d+|root:|/bin/bash|command not found)`)},
		{"xml_error", regexp.MustCompile(`(?i)(xml parsing|entity|DTD|<!ENTITY)`)},
		{"template_injection", regexp.MustCompile(`(?i)(\{\{.*\}\}|\$\{.*\}|<%.*%>)`)},
	}

	for _, ep := range evidencePatterns {
		if ep.pattern.MatchString(bodyStr) {
			result.EvidenceMarkers = append(result.EvidenceMarkers, ep.name)
		}
	}
}

// sanitizeForJSON removes control characters and null bytes
func sanitizeForJSON(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			sb.WriteRune(r)
		} else if r == '\n' || r == '\t' {
			sb.WriteRune(' ')
		}
	}
	return sb.String()
}

// categorizeError classifies errors for better analysis
func categorizeError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	switch {
	case strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline exceeded"):
		return fmt.Sprintf("[TIMEOUT] %s", errStr)
	case strings.Contains(errLower, "no such host") || strings.Contains(errLower, "dns"):
		return fmt.Sprintf("[DNS] %s", errStr)
	case strings.Contains(errLower, "certificate") || strings.Contains(errLower, "tls") ||
		strings.Contains(errLower, "x509"):
		return fmt.Sprintf("[TLS] %s", errStr)
	case strings.Contains(errLower, "connection refused") || strings.Contains(errLower, "connection reset"):
		return fmt.Sprintf("[CONNECTION] %s", errStr)
	case strings.Contains(errLower, "rate limit") || strings.Contains(errLower, "too many"):
		return fmt.Sprintf("[RATE_LIMIT] %s", errStr)
	case strings.Contains(errLower, "invalid") || strings.Contains(errLower, "malformed"):
		return fmt.Sprintf("[INVALID_REQUEST] %s", errStr)
	default:
		return errStr
	}
}

// ExecuteWithProgress runs all payloads with UI progress display
func (e *Executor) ExecuteWithProgress(ctx context.Context, allPayloads []payloads.Payload, writer output.Writer, progress *ui.Progress) output.ExecutionResults {
	results := output.ExecutionResults{
		TotalTests:        len(allPayloads),
		StartTime:         time.Now(),
		StatusCodes:       make(map[int]int),
		SeverityBreakdown: make(map[string]int),
		CategoryBreakdown: make(map[string]int),
		TopErrors:         make([]string, 0),
		EncodingStats:     make(map[string]*output.EncodingEffectiveness),
		OWASPBreakdown:    make(map[string]int),
	}

	// Maps for collecting stats (thread-safe with mutex)
	var statsMu sync.Mutex
	errorCounts := make(map[string]int)

	// Create channels for work distribution
	tasks := make(chan payloads.Payload, e.config.Concurrency*2)
	resultsChan := make(chan *output.TestResult, e.config.Concurrency*2)

	// Atomic counters
	var blocked, passed, failed, errored int64

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for payload := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
					// Rate limit
					e.limiter.Wait(ctx)

					// Execute test
					result := e.executeTest(ctx, payload)
					resultsChan <- result

					// Update progress
					progress.Increment(result.Outcome)

					// Update atomic counters for final stats
					switch result.Outcome {
					case "Blocked":
						atomic.AddInt64(&blocked, 1)
					case "Pass":
						atomic.AddInt64(&passed, 1)
					case "Fail":
						atomic.AddInt64(&failed, 1)
					case "Error":
						atomic.AddInt64(&errored, 1)
					}
				}
			}
		}(i)
	}

	// Result collector goroutine - also collects stats
	var collectorWg sync.WaitGroup
	var filteredCount int64
	var latencies []int64
	var bypassDetails []output.BypassDetail
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for result := range resultsChan {
			// Skip filtered results (don't write to output)
			if result.Filtered {
				atomic.AddInt64(&filteredCount, 1)
				continue
			}

			writer.Write(result)

			// Collect stats (thread-safe)
			statsMu.Lock()
			results.StatusCodes[result.StatusCode]++
			results.SeverityBreakdown[result.Severity]++
			results.CategoryBreakdown[result.Category]++
			if result.ErrorMessage != "" {
				errorCounts[result.ErrorMessage]++
			}
			// Collect latencies for percentile calculation
			latencies = append(latencies, result.LatencyMs)

			// Track encoding effectiveness
			encoding := result.EncodingUsed
			if encoding == "" {
				encoding = "raw" // Default for unencoded payloads
			}
			if results.EncodingStats[encoding] == nil {
				results.EncodingStats[encoding] = &output.EncodingEffectiveness{Name: encoding}
			}
			stats := results.EncodingStats[encoding]
			stats.TotalTests++
			if result.Outcome == "Fail" {
				stats.Bypasses++
			} else if result.Outcome == "Blocked" {
				stats.BlockedTests++
			}

			// Track OWASP category
			category := strings.ToLower(result.Category)
			if mapping, ok := output.OWASPMapping[category]; ok {
				results.OWASPBreakdown[mapping.OWASP]++
			}

			// Track bypasses (Fail = attack got through)
			if result.Outcome == "Fail" {
				bypassDetails = append(bypassDetails, output.BypassDetail{
					PayloadID:   result.ID,
					Payload:     result.Payload,
					Endpoint:    result.TargetPath,
					Method:      result.Method,
					StatusCode:  result.StatusCode,
					CurlCommand: result.CurlCommand,
					Category:    result.Category,
					Severity:    result.Severity,
				})
			}
			statsMu.Unlock()
		}
	}()

	// Send all payloads to workers
sendLoop2:
	for _, payload := range allPayloads {
		select {
		case <-ctx.Done():
			break sendLoop2
		case tasks <- payload:
		}
	}
	close(tasks)

	// Wait for workers to complete
	wg.Wait()
	close(resultsChan)

	// Wait for collector
	collectorWg.Wait()

	// Calculate latency percentiles
	if len(latencies) > 0 {
		// Sort latencies for percentile calculation
		sortedLatencies := make([]int64, len(latencies))
		copy(sortedLatencies, latencies)
		// Efficient O(n log n) sort
		sort.Slice(sortedLatencies, func(i, j int) bool {
			return sortedLatencies[i] < sortedLatencies[j]
		})

		results.LatencyStats.Min = sortedLatencies[0]
		results.LatencyStats.Max = sortedLatencies[len(sortedLatencies)-1]

		// Calculate average
		var sum int64
		for _, l := range sortedLatencies {
			sum += l
		}
		results.LatencyStats.Avg = sum / int64(len(sortedLatencies))

		// Percentiles
		results.LatencyStats.P50 = sortedLatencies[len(sortedLatencies)*50/100]
		results.LatencyStats.P95 = sortedLatencies[len(sortedLatencies)*95/100]
		p99Idx := len(sortedLatencies) * 99 / 100
		if p99Idx >= len(sortedLatencies) {
			p99Idx = len(sortedLatencies) - 1
		}
		results.LatencyStats.P99 = sortedLatencies[p99Idx]
	}

	// Calculate encoding bypass rates
	for _, stats := range results.EncodingStats {
		if stats.TotalTests > 0 {
			stats.BypassRate = float64(stats.Bypasses) / float64(stats.TotalTests) * 100
		}
	}

	// Store bypass details
	results.BypassDetails = bypassDetails
	for _, bypass := range bypassDetails {
		results.BypassPayloads = append(results.BypassPayloads, bypass.Payload)
	}

	// Final stats
	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	results.BlockedTests = int(atomic.LoadInt64(&blocked))
	results.PassedTests = int(atomic.LoadInt64(&passed))
	results.FailedTests = int(atomic.LoadInt64(&failed))
	results.ErrorTests = int(atomic.LoadInt64(&errored))
	if results.Duration.Seconds() > 0 {
		results.RequestsPerSec = float64(results.TotalTests) / results.Duration.Seconds()
	}

	// Populate top errors (sorted by frequency)
	type errCount struct {
		msg   string
		count int
	}
	errList := make([]errCount, 0, len(errorCounts))
	for msg, count := range errorCounts {
		errList = append(errList, errCount{msg, count})
	}
	// Sort by count descending using efficient O(n log n) sort
	sort.Slice(errList, func(i, j int) bool {
		return errList[i].count > errList[j].count
	})
	// Take top 5
	for i := 0; i < len(errList) && i < 5; i++ {
		results.TopErrors = append(results.TopErrors, fmt.Sprintf("%s (%d)", errList[i].msg, errList[i].count))
	}

	return results
}

// shouldShowResult applies filter/match logic (ffuf-style)
// Returns true if the result should be shown, false if filtered out
func (e *Executor) shouldShowResult(result *output.TestResult, body string) bool {
	f := e.config.Filter
	if f == nil {
		return true
	}

	// === FILTER CHECKS (if ANY matches, exclude the result) ===

	// Filter by status code
	if len(f.FilterStatus) > 0 {
		for _, code := range f.FilterStatus {
			if result.StatusCode == code {
				return false
			}
		}
	}

	// Filter by content length
	if len(f.FilterSize) > 0 {
		for _, size := range f.FilterSize {
			if result.ContentLength == size {
				return false
			}
		}
	}

	// Filter by word count
	if len(f.FilterWords) > 0 {
		for _, wc := range f.FilterWords {
			if result.WordCount == wc {
				return false
			}
		}
	}

	// Filter by line count
	if len(f.FilterLines) > 0 {
		for _, lc := range f.FilterLines {
			if result.LineCount == lc {
				return false
			}
		}
	}

	// Filter by regex
	if f.FilterRegex != nil {
		if f.FilterRegex.MatchString(body) {
			return false
		}
	}

	// === MATCH CHECKS (if configured, at least ONE must match) ===

	// If no match criteria configured, show the result
	hasMatchCriteria := len(f.MatchStatus) > 0 || len(f.MatchSize) > 0 ||
		len(f.MatchWords) > 0 || len(f.MatchLines) > 0 || f.MatchRegex != nil

	if !hasMatchCriteria {
		return true
	}

	// Check if ANY match criterion is satisfied
	matched := false

	// Match by status code
	if len(f.MatchStatus) > 0 {
		for _, code := range f.MatchStatus {
			if result.StatusCode == code {
				matched = true
				break
			}
		}
	}

	// Match by content length
	if !matched && len(f.MatchSize) > 0 {
		for _, size := range f.MatchSize {
			if result.ContentLength == size {
				matched = true
				break
			}
		}
	}

	// Match by word count
	if !matched && len(f.MatchWords) > 0 {
		for _, wc := range f.MatchWords {
			if result.WordCount == wc {
				matched = true
				break
			}
		}
	}

	// Match by line count
	if !matched && len(f.MatchLines) > 0 {
		for _, lc := range f.MatchLines {
			if result.LineCount == lc {
				matched = true
				break
			}
		}
	}

	// Match by regex
	if !matched && f.MatchRegex != nil {
		if f.MatchRegex.MatchString(body) {
			matched = true
		}
	}

	return matched
}
