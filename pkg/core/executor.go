package core

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/realistic"
	"github.com/waftester/waftester/pkg/scoring"
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

// ResultCallback is called for each test result during execution.
// Use this for real-time streaming to hooks (Slack, Teams, OTEL, etc.)
type ResultCallback func(result *output.TestResult)

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

	// OnResult is called for each test result (optional).
	// Use for real-time streaming to webhooks, Slack, Teams, PagerDuty, OTEL, etc.
	OnResult ResultCallback
}

// Executor runs security tests in parallel
type Executor struct {
	config     ExecutorConfig
	httpClient *http.Client
	limiter    *rate.Limiter
	enhancer   *realistic.ExecutorEnhancer // Realistic mode enhancer
	detector   *detection.Detector         // Connection drop and silent ban detection
	logger     *slog.Logger
}

// ExecutorOption configures an Executor.
type ExecutorOption func(*Executor)

// WithLogger sets a custom structured logger for the executor.
func WithLogger(l *slog.Logger) ExecutorOption {
	return func(e *Executor) { e.logger = l }
}

// NewExecutor creates a new parallel executor
func NewExecutor(cfg ExecutorConfig, opts ...ExecutorOption) *Executor {
	// Validate and apply defaults for invalid config values
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaults.ConcurrencyMinimal // Default to 1 worker
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 100 // Default to 100 requests/sec
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = httpclient.TimeoutFuzzing // Default fuzzing timeout
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0 // No negative retries
	}

	// Use provided HTTPClient (e.g., JA3-aware) or create default using shared httpclient factory
	var client *http.Client
	if cfg.HTTPClient != nil {
		client = cfg.HTTPClient
	} else {
		// Start from FuzzingConfig preset and override with executor-specific settings
		httpCfg := httpclient.FuzzingConfig()
		httpCfg.Timeout = cfg.Timeout
		httpCfg.InsecureSkipVerify = cfg.SkipVerify
		httpCfg.Proxy = cfg.Proxy
		// Scale connection pool to concurrency level
		httpCfg.MaxConnsPerHost = cfg.Concurrency
		httpCfg.MaxIdleConns = cfg.Concurrency * 2
		client = httpclient.New(httpCfg)
	}

	// Create rate limiter (token bucket)
	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)

	executor := &Executor{
		config:     cfg,
		httpClient: client,
		limiter:    limiter,
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(executor)
	}

	// Initialize realistic mode enhancer if enabled
	if cfg.RealisticMode {
		executor.enhancer = realistic.NewExecutorEnhancer(cfg.TargetURL)
	}

	// Each executor gets its own detector so concurrent scans don't
	// cross-contaminate detection state (drops, bans, baselines).
	executor.detector = detection.New()

	// Wire the same detector into the transport wrapper so the transport
	// layer and executor layer share one consistent view.
	// If the transport isn't a detection.Transport (e.g., user-provided
	// HTTPClient or transport wrapper not registered), detection still
	// works via executor.detector.ShouldSkipHost in the worker loop.
	// When using a user-provided HTTPClient, shallow-copy the transport to
	// avoid mutating shared state across concurrent executors.
	if dt, ok := client.Transport.(*detection.Transport); ok {
		if cfg.HTTPClient != nil {
			// User-provided client — shallow copy the transport wrapper
			// so we don't mutate their transport's Detector field.
			dtCopy := *dt
			dtCopy.Detector = executor.detector
			client.Transport = &dtCopy
		} else {
			dt.Detector = executor.detector
		}
	}

	return executor
}

// Execute runs all payloads with worker pool pattern
func (e *Executor) Execute(ctx context.Context, allPayloads []payloads.Payload, writer output.ResultWriter) output.ExecutionResults {
	results := output.ExecutionResults{
		TotalTests: len(allPayloads),
		StartTime:  time.Now(),
	}

	// Auto-calibrate if realistic mode is enabled
	if e.enhancer != nil && e.config.AutoCalibrate {
		if err := e.enhancer.Calibrate(ctx); err != nil {
			// Log calibration failure but continue
			e.logger.Warn("auto-calibration failed", slog.String("error", err.Error()))
		}
	}

	// Create channels for work distribution
	tasks := make(chan payloads.Payload, e.config.Concurrency*2)
	resultsChan := make(chan *output.TestResult, e.config.Concurrency*2)

	// Atomic counters for progress
	var completed int64
	var blocked, passed, failed, errored int64
	var skipped, drops, bans int64

	// Death spiral detection: if >deathSpiralRatioThreshold of the first
	// batch are skipped, the host is unreachable and continuing wastes time.
	const (
		deathSpiralMinSamples     = 50  // Check after this many completions
		deathSpiralRatioThreshold = 0.8 // Abort if skip ratio exceeds this
	)
	var deathSpiralOnce sync.Once
	deathSpiralCtx, deathSpiralCancel := context.WithCancel(ctx)
	defer deathSpiralCancel()

	checkDeathSpiral := func() {
		done := atomic.LoadInt64(&completed)
		if done < deathSpiralMinSamples {
			return
		}
		skip := atomic.LoadInt64(&skipped)
		if float64(skip)/float64(done) > deathSpiralRatioThreshold {
			deathSpiralOnce.Do(func() {
				e.logger.Error("scan death spiral detected, aborting",
					slog.Int64("skipped", skip),
					slog.Int64("completed", done))
				deathSpiralCancel()
			})
		}
	}

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for payload := range tasks {
				select {
				case <-deathSpiralCtx.Done():
					return
				default:
					// Check skip conditions BEFORE rate limiter to avoid
					// wasting rate-limit tokens on payloads that will be skipped.
					if hosterrors.Check(e.config.TargetURL) {
						result := e.buildSkippedResult(payload, "[HOST_FAILED] Host has exceeded error threshold")
						resultsChan <- result
						atomic.AddInt64(&completed, 1)
						atomic.AddInt64(&skipped, 1)
						checkDeathSpiral()
						continue
					}
					if e.detector != nil {
						if skip, reason := e.detector.ShouldSkipHost(e.config.TargetURL); skip {
							result := e.buildSkippedResult(payload, fmt.Sprintf("[DETECTION] %s", reason))
							resultsChan <- result
							atomic.AddInt64(&completed, 1)
							atomic.AddInt64(&skipped, 1)
							checkDeathSpiral()
							continue
						}
					}

					// Rate limit
					if err := e.limiter.Wait(deathSpiralCtx); err != nil {
						return // context cancelled
					}

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
					case "Skipped":
						atomic.AddInt64(&skipped, 1)
					}
					// Track detection events
					if result.DropDetected {
						atomic.AddInt64(&drops, 1)
					}
					if result.BanDetected {
						atomic.AddInt64(&bans, 1)
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

			// Call OnResult callback for real-time streaming to hooks
			if e.config.OnResult != nil {
				e.config.OnResult(result)
			}
		}
	}()

	// Progress display goroutine
	var progressWg sync.WaitGroup
	progressDone := make(chan struct{})
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				done := atomic.LoadInt64(&completed)
				elapsed := time.Since(results.StartTime).Seconds()
				rps := float64(done) / elapsed
				fmt.Printf("\r[*] Progress: %d/%d (%.1f/sec) | Blocked: %d | Pass: %d | Fail: %d | Error: %d", // debug:keep
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
		case <-deathSpiralCtx.Done():
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
	progressWg.Wait()

	// Final stats
	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	results.BlockedTests = int(atomic.LoadInt64(&blocked))
	results.PassedTests = int(atomic.LoadInt64(&passed))
	results.FailedTests = int(atomic.LoadInt64(&failed))
	results.ErrorTests = int(atomic.LoadInt64(&errored))
	results.HostsSkipped = int(atomic.LoadInt64(&skipped))
	results.DropsDetected = int(atomic.LoadInt64(&drops))
	results.BansDetected = int(atomic.LoadInt64(&bans))
	if results.Duration.Seconds() > 0 {
		results.RequestsPerSec = float64(results.TotalTests) / results.Duration.Seconds()
	}

	// Capture detection statistics from detector
	if e.detector != nil {
		detStats := e.detector.Stats()
		results.DetectionStats = detStats
		// Override drops count from detector if available (more accurate)
		if connmonDrops, ok := detStats["connmon_total_drops"]; ok && connmonDrops > results.DropsDetected {
			results.DropsDetected = connmonDrops
		}
	}

	fmt.Println() // debug:keep — newline after progress
	return results
}

// Close releases resources held by the executor, including idle HTTP
// connections and detection state for the target URL.
func (e *Executor) Close() {
	if e.detector != nil {
		e.detector.ClearAll()
	}
	if e.httpClient == nil {
		return
	}
	type idleCloser interface {
		CloseIdleConnections()
	}
	if ic, ok := e.httpClient.Transport.(idleCloser); ok {
		ic.CloseIdleConnections()
	}
}

// SetRateLimit dynamically updates the rate limiter's throughput.
// Safe to call concurrently while the executor is running.
func (e *Executor) SetRateLimit(requestsPerSec int) {
	if requestsPerSec <= 0 {
		return
	}
	e.limiter.SetLimit(rate.Limit(requestsPerSec))
	e.limiter.SetBurst(requestsPerSec)
}

// buildSkippedResult creates a TestResult for a payload that was skipped
// due to host errors or detection system recommendations. Used by the
// worker pool to skip payloads without going through the rate limiter.
func (e *Executor) buildSkippedResult(payload payloads.Payload, reason string) *output.TestResult {
	method := payload.Method
	if method == "" {
		method = "GET"
	}
	return &output.TestResult{
		ID:              payload.ID,
		Category:        payload.Category,
		Severity:        payload.SeverityHint,
		Payload:         payload.Payload,
		Timestamp:       time.Now().Format("15:04:05"),
		Method:          method,
		Outcome:         "Skipped",
		ErrorMessage:    reason,
		ResponseHeaders: make(map[string]string),
		RiskScore:       scoring.Result{RiskScore: 0},
	}
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
