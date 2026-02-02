// Package mutation provides an enhanced executor that integrates all mutation plugins.
// This is the core engine that generates and tests all payload variants.
package mutation

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/realistic"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/waf"
	"golang.org/x/time/rate"
)

// ExecutorConfig configures the mutation executor
type ExecutorConfig struct {
	TargetURL   string
	Concurrency int
	RateLimit   float64
	Timeout     time.Duration
	Retries     int
	UserAgent   string

	// Mutation settings
	Pipeline *PipelineConfig

	// Response analysis
	AnalyzeResponses   bool
	CollectFingerprint bool

	// Realistic mode (intelligent block detection, rotating UA, realistic headers)
	RealisticMode bool
	AutoCalibrate bool
	SkipVerify    bool // Skip TLS verification
}

// DefaultExecutorConfig returns sensible defaults
func DefaultExecutorConfig() *ExecutorConfig {
	return &ExecutorConfig{
		Concurrency:        10,
		RateLimit:          50,
		Timeout:            duration.DialTimeout,
		Retries:            2,
		UserAgent:          ui.UserAgentWithContext("Mutation Engine"),
		Pipeline:           DefaultPipelineConfig(),
		AnalyzeResponses:   true,
		CollectFingerprint: false,
	}
}

// TestResult represents a single test result
type TestResult struct {
	ID              string `json:"id"`
	OriginalPayload string `json:"original_payload"`
	MutatedPayload  string `json:"mutated_payload"`
	EncoderUsed     string `json:"encoder_used"`
	LocationUsed    string `json:"location_used"`
	EvasionUsed     string `json:"evasion_used,omitempty"`

	Method        string `json:"method"`
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	LatencyMs     int64  `json:"latency_ms"`

	Outcome      string `json:"outcome"` // Blocked, Passed, Error
	Blocked      bool   `json:"blocked"`
	ErrorMessage string `json:"error_message,omitempty"`

	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseSnippet string            `json:"response_snippet,omitempty"`
}

// ExecutionStats tracks overall execution statistics
type ExecutionStats struct {
	TotalTests     int64         `json:"total_tests"`
	Blocked        int64         `json:"blocked"`
	Passed         int64         `json:"passed"`
	Errors         int64         `json:"errors"`
	Duration       time.Duration `json:"duration"`
	RequestsPerSec float64       `json:"requests_per_sec"`

	// Breakdown by category
	ByEncoder    map[string]int64 `json:"by_encoder"`
	ByLocation   map[string]int64 `json:"by_location"`
	ByEvasion    map[string]int64 `json:"by_evasion"`
	ByStatusCode map[int]int64    `json:"by_status_code"`

	// WAF fingerprint (collected if CollectFingerprint is enabled)
	WAFFingerprint *waf.Fingerprint `json:"waf_fingerprint,omitempty"`
}

// Executor runs mutation-based WAF tests
type Executor struct {
	config        *ExecutorConfig
	httpClient    *http.Client
	limiter       *rate.Limiter
	registry      *Registry
	blockDetector *realistic.BlockDetector // Intelligent block detection
	builder       *realistic.Builder       // Realistic request building
	fingerprinter *waf.Fingerprinter       // WAF fingerprinting (if CollectFingerprint enabled)
}

// NewExecutor creates a new mutation executor
func NewExecutor(config *ExecutorConfig) *Executor {
	if config == nil {
		config = DefaultExecutorConfig()
	}

	exec := &Executor{
		config:     config,
		httpClient: httpclient.Default(),
		limiter:    rate.NewLimiter(rate.Limit(config.RateLimit), int(config.RateLimit)),
		registry:   DefaultRegistry,
	}

	// Initialize realistic mode components
	if config.RealisticMode {
		exec.blockDetector = realistic.NewBlockDetector()
		exec.builder = realistic.NewBuilder(config.TargetURL)
		exec.builder.RandomizeUA = true

		// Auto-calibrate if requested
		if config.AutoCalibrate && config.TargetURL != "" {
			calibrator := realistic.NewCalibrator(config.TargetURL)
			ctx, cancel := context.WithTimeout(context.Background(), duration.ContextShort)
			result, err := calibrator.Calibrate(ctx)
			cancel()
			if err == nil && result.Success {
				exec.blockDetector.Baseline = calibrator.Detector.Baseline
			}
		}
	}

	// Initialize WAF fingerprinter if enabled
	if config.CollectFingerprint {
		exec.fingerprinter = waf.NewFingerprinter(config.Timeout)
	}

	return exec
}

// MutationTask represents a single test to execute
type MutationTask struct {
	OriginalPayload string
	Category        string
	EncodedPayload  MutatedPayload
	Location        MutatedPayload
	Evasion         *MutatedPayload // Optional
}

// GenerateTasks creates all mutation combinations for a set of payloads
func (e *Executor) GenerateTasks(payloads []string, categories []string) []MutationTask {
	var tasks []MutationTask

	cfg := e.config.Pipeline
	encoders := e.registry.GetByCategory("encoder")
	locations := e.registry.GetByCategory("location")
	evasions := e.registry.GetByCategory("evasion")

	// Filter by config
	if len(cfg.Encoders) > 0 {
		encoders = e.filterMutators(encoders, cfg.Encoders)
	}
	if len(cfg.Locations) > 0 {
		locations = e.filterMutators(locations, cfg.Locations)
	}
	if len(cfg.Evasions) > 0 {
		evasions = e.filterMutators(evasions, cfg.Evasions)
	}

	for i, payload := range payloads {
		category := ""
		if i < len(categories) {
			category = categories[i]
		}

		// Add raw payload first if configured
		if cfg.IncludeRaw {
			for _, loc := range locations {
				locResults := loc.Mutate(payload)
				for _, locResult := range locResults {
					tasks = append(tasks, MutationTask{
						OriginalPayload: payload,
						Category:        category,
						EncodedPayload: MutatedPayload{
							Original:    payload,
							Mutated:     payload,
							MutatorName: "raw",
							Category:    "encoder",
						},
						Location: locResult,
					})
				}
			}
		}

		// Apply each encoder
		for _, enc := range encoders {
			encResults := enc.Mutate(payload)
			for _, encResult := range encResults {
				// Apply each location
				for _, loc := range locations {
					locResults := loc.Mutate(encResult.Mutated)
					for _, locResult := range locResults {
						// Without evasion
						tasks = append(tasks, MutationTask{
							OriginalPayload: payload,
							Category:        category,
							EncodedPayload:  encResult,
							Location:        locResult,
						})

						// With each evasion (if configured)
						for _, ev := range evasions {
							evResults := ev.Mutate(locResult.Mutated)
							for _, evResult := range evResults {
								tasks = append(tasks, MutationTask{
									OriginalPayload: payload,
									Category:        category,
									EncodedPayload:  encResult,
									Location:        locResult,
									Evasion:         &evResult,
								})
							}
						}
					}
				}
			}
		}
	}

	return tasks
}

func (e *Executor) filterMutators(mutators []Mutator, names []string) []Mutator {
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}

	var filtered []Mutator
	for _, m := range mutators {
		if nameSet[m.Name()] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

// ResultHandler is called for each test result
type ResultHandler func(*TestResult)

// Execute runs all mutation tests with progress tracking
func (e *Executor) Execute(ctx context.Context, tasks []MutationTask, handler ResultHandler) *ExecutionStats {
	stats := &ExecutionStats{
		TotalTests:   int64(len(tasks)),
		ByEncoder:    make(map[string]int64),
		ByLocation:   make(map[string]int64),
		ByEvasion:    make(map[string]int64),
		ByStatusCode: make(map[int]int64),
	}

	var statsMu sync.Mutex
	startTime := time.Now()

	// Task channel
	taskChan := make(chan MutationTask, e.config.Concurrency*2)

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Rate limit
				e.limiter.Wait(ctx)

				// Execute test
				result := e.executeTask(ctx, task)

				// Update stats
				statsMu.Lock()
				if result.Blocked {
					atomic.AddInt64(&stats.Blocked, 1)
				} else if result.ErrorMessage != "" {
					atomic.AddInt64(&stats.Errors, 1)
				} else {
					atomic.AddInt64(&stats.Passed, 1)
				}
				stats.ByEncoder[result.EncoderUsed]++
				stats.ByLocation[result.LocationUsed]++
				if result.EvasionUsed != "" {
					stats.ByEvasion[result.EvasionUsed]++
				}
				stats.ByStatusCode[result.StatusCode]++
				statsMu.Unlock()

				// Call handler
				if handler != nil {
					handler(result)
				}
			}
		}()
	}

	// Send tasks
sendLoop:
	for _, task := range tasks {
		select {
		case <-ctx.Done():
			break sendLoop
		case taskChan <- task:
		}
	}
	close(taskChan)

	// Wait for completion
	wg.Wait()

	stats.Duration = time.Since(startTime)
	if stats.Duration.Seconds() > 0 {
		stats.RequestsPerSec = float64(stats.TotalTests) / stats.Duration.Seconds()
	}

	// Collect WAF fingerprint if enabled
	if e.fingerprinter != nil && e.config.TargetURL != "" {
		fpCtx, fpCancel := context.WithTimeout(ctx, duration.ContextShort)
		fingerprint, err := e.fingerprinter.CreateFingerprint(fpCtx, e.config.TargetURL)
		fpCancel()
		if err == nil {
			stats.WAFFingerprint = fingerprint
		}
	}

	return stats
}

// executeTask runs a single mutation test
func (e *Executor) executeTask(ctx context.Context, task MutationTask) *TestResult {
	result := &TestResult{
		ID:              fmt.Sprintf("%s_%s_%s", task.EncodedPayload.MutatorName, task.Location.MutatorName, task.Category),
		OriginalPayload: task.OriginalPayload,
		MutatedPayload:  task.EncodedPayload.Mutated,
		EncoderUsed:     task.EncodedPayload.MutatorName,
		LocationUsed:    task.Location.MutatorName,
	}

	if task.Evasion != nil {
		result.EvasionUsed = task.Evasion.MutatorName
		result.MutatedPayload = task.Evasion.Mutated
	}

	// Build request based on location
	req, err := e.buildRequest(ctx, task)
	if err != nil {
		result.Outcome = "Error"
		result.ErrorMessage = err.Error()
		return result
	}

	result.Method = req.Method
	result.URL = req.URL.String()

	// Execute with retries
	start := time.Now()
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
		result.ErrorMessage = err.Error()
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Read response
	bodyBytes, _ := iohelper.ReadBody(resp.Body, iohelper.SmallMaxBodySize)
	result.StatusCode = resp.StatusCode
	result.ContentLength = len(bodyBytes)

	// Collect response headers if analyzing
	if e.config.AnalyzeResponses {
		result.ResponseHeaders = make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				result.ResponseHeaders[k] = v[0]
			}
		}
		// First 200 chars of response
		if len(bodyBytes) > 200 {
			result.ResponseSnippet = string(bodyBytes[:200])
		} else {
			result.ResponseSnippet = string(bodyBytes)
		}
	}

	// Determine outcome using intelligent block detection or legacy method
	if e.blockDetector != nil && e.config.RealisticMode {
		// Use intelligent multi-signal block detection
		// Create a new reader from body bytes for detector
		blockResult, detectErr := e.blockDetector.DetectBlock(
			&http.Response{
				StatusCode: resp.StatusCode,
				Body:       io.NopCloser(strings.NewReader(string(bodyBytes))),
				Header:     resp.Header,
			},
			time.Duration(result.LatencyMs)*time.Millisecond,
		)
		if detectErr == nil {
			result.Blocked = blockResult.IsBlocked
			if blockResult.IsBlocked {
				result.Outcome = "Blocked"
				// Store additional detection info in response snippet if not already set
				if result.ResponseSnippet == "" && blockResult.Reason != "" {
					result.ResponseSnippet = fmt.Sprintf("[Block detected: %s (confidence: %.2f)]",
						blockResult.Reason, blockResult.Confidence)
				}
			} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				result.Outcome = "Passed"
			} else {
				result.Outcome = "Error"
				result.ErrorMessage = fmt.Sprintf("Unexpected status: %d", resp.StatusCode)
			}
		} else {
			// Fallback to legacy detection on error
			result.Blocked = resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429
			if result.Blocked {
				result.Outcome = "Blocked"
			} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				result.Outcome = "Passed"
			} else {
				result.Outcome = "Error"
				result.ErrorMessage = fmt.Sprintf("Unexpected status: %d", resp.StatusCode)
			}
		}
	} else {
		// Legacy: status-code-only detection
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
			result.Outcome = "Blocked"
			result.Blocked = true
		} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			result.Outcome = "Passed"
			result.Blocked = false
		} else {
			result.Outcome = "Error"
			result.ErrorMessage = fmt.Sprintf("Unexpected status: %d", resp.StatusCode)
		}
	}

	return result
}

// buildRequest constructs an HTTP request based on the mutation task
func (e *Executor) buildRequest(ctx context.Context, task MutationTask) (*http.Request, error) {
	locName := task.Location.MutatorName
	payload := task.Location.Mutated

	// Handle evasion-modified payload
	if task.Evasion != nil {
		payload = task.Evasion.Mutated
	}

	targetURL := e.config.TargetURL
	method := "GET"
	var body io.Reader
	headers := make(map[string]string)

	// Route based on location type
	switch {
	case strings.HasPrefix(locName, "query_param"):
		// Payload is already formatted as ?param=value
		if strings.HasPrefix(payload, "?") {
			targetURL = targetURL + payload
		} else {
			targetURL = targetURL + "?test=" + url.QueryEscape(payload)
		}

	case strings.HasPrefix(locName, "post_form"):
		method = "POST"
		body = strings.NewReader(payload)
		headers["Content-Type"] = "application/x-www-form-urlencoded"

	case strings.HasPrefix(locName, "post_json"):
		method = "POST"
		body = strings.NewReader(payload)
		headers["Content-Type"] = "application/json"

	case strings.HasPrefix(locName, "post_xml"):
		method = "POST"
		body = strings.NewReader(payload)
		headers["Content-Type"] = "application/xml"

	case strings.HasPrefix(locName, "header_"):
		// Payload format: "Header-Name: value"
		parts := strings.SplitN(payload, ": ", 2)
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}

	case strings.HasPrefix(locName, "cookie"):
		// Payload format: "Cookie: name=value"
		parts := strings.SplitN(payload, ": ", 2)
		if len(parts) == 2 {
			headers["Cookie"] = parts[1]
		}

	case strings.HasPrefix(locName, "path_segment"):
		// Payload is a path
		baseURL, err := url.Parse(e.config.TargetURL)
		if err == nil {
			baseURL.Path = payload
			targetURL = baseURL.String()
		}

	case strings.HasPrefix(locName, "multipart"):
		method = "POST"
		body = strings.NewReader(payload)
		headers["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"

	case strings.HasPrefix(locName, "fragment"):
		// Fragment is client-side only, but we can still send it
		targetURL = targetURL + payload

	case strings.HasPrefix(locName, "basic_auth"):
		// Payload format: "Authorization: Basic xxx"
		parts := strings.SplitN(payload, ": ", 2)
		if len(parts) == 2 {
			headers["Authorization"] = parts[1]
		}

	default:
		// Generic: try as query param
		targetURL = targetURL + "?test=" + url.QueryEscape(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, body)
	if err != nil {
		return nil, err
	}

	// Set headers - use realistic mode if available
	if e.builder != nil && e.config.RealisticMode {
		// Rotate User-Agent for realistic traffic
		ua := e.builder.GetRotatingUA()
		req.Header.Set("User-Agent", ua)

		// Add browser-like headers
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		// Add Sec-Fetch headers for modern browser simulation
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
	} else {
		// Legacy: static User-Agent
		req.Header.Set("User-Agent", e.config.UserAgent)
	}

	// Set location-specific headers (may override some of the above)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

// QuickScan runs a fast scan with common encodings and locations
func (e *Executor) QuickScan(ctx context.Context, payloads []string, handler ResultHandler) *ExecutionStats {
	// Use minimal configuration for speed
	e.config.Pipeline = &PipelineConfig{
		Encoders:   []string{"raw", "url", "double_url"},
		Locations:  []string{"query_param", "post_form", "post_json"},
		Evasions:   []string{},
		IncludeRaw: true,
	}

	tasks := e.GenerateTasks(payloads, nil)
	return e.Execute(ctx, tasks, handler)
}

// FullScan runs a comprehensive scan with all mutations
func (e *Executor) FullScan(ctx context.Context, payloads []string, handler ResultHandler) *ExecutionStats {
	e.config.Pipeline = FullCoveragePipelineConfig()
	tasks := e.GenerateTasks(payloads, nil)
	return e.Execute(ctx, tasks, handler)
}

// StreamResults writes results to a channel for streaming output
func (e *Executor) StreamResults(ctx context.Context, tasks []MutationTask) (<-chan *TestResult, *ExecutionStats) {
	resultChan := make(chan *TestResult, 100)

	var stats *ExecutionStats
	go func() {
		defer close(resultChan)
		stats = e.Execute(ctx, tasks, func(r *TestResult) {
			select {
			case resultChan <- r:
			case <-ctx.Done():
			}
		})
	}()

	return resultChan, stats
}

// CountCombinations returns the expected number of test combinations
func (e *Executor) CountCombinations(payloadCount int) int {
	cfg := e.config.Pipeline

	encoderCount := len(e.registry.GetByCategory("encoder"))
	locationCount := len(e.registry.GetByCategory("location"))
	var evasionCount int

	if len(cfg.Encoders) > 0 {
		encoderCount = len(cfg.Encoders)
	}
	if len(cfg.Locations) > 0 {
		locationCount = len(cfg.Locations)
	}
	if len(cfg.Evasions) > 0 {
		evasionCount = len(cfg.Evasions)
	} else {
		evasionCount = 0 // No evasions by default
	}

	// Formula: payloads × encoders × locations × (1 + evasions)
	multiplier := 1
	if evasionCount > 0 {
		multiplier = 1 + evasionCount
	}

	rawPayloads := 0
	if cfg.IncludeRaw {
		rawPayloads = payloadCount * locationCount
	}

	return rawPayloads + (payloadCount * encoderCount * locationCount * multiplier)
}

// GetStats returns current registry statistics
func (e *Executor) GetStats() map[string]int {
	return map[string]int{
		"encoders":  len(e.registry.GetByCategory("encoder")),
		"locations": len(e.registry.GetByCategory("location")),
		"evasions":  len(e.registry.GetByCategory("evasion")),
		"protocols": len(e.registry.GetByCategory("protocol")),
		"total":     len(e.registry.All()),
	}
}

// WAFBypassResult contains bypass detection results
type WAFBypassResult struct {
	Found          bool          `json:"found"`
	BypassPayloads []*TestResult `json:"bypass_payloads"`
	TotalTested    int64         `json:"total_tested"`
	BypassRate     float64       `json:"bypass_rate"`
}

// FindBypasses runs tests and collects any that bypass the WAF
func (e *Executor) FindBypasses(ctx context.Context, payloads []string) *WAFBypassResult {
	result := &WAFBypassResult{
		BypassPayloads: make([]*TestResult, 0),
	}
	var bypassMu sync.Mutex

	tasks := e.GenerateTasks(payloads, nil)
	result.TotalTested = int64(len(tasks))

	e.Execute(ctx, tasks, func(r *TestResult) {
		if !r.Blocked && r.ErrorMessage == "" {
			bypassMu.Lock()
			result.BypassPayloads = append(result.BypassPayloads, r)
			bypassMu.Unlock()
		}
	})

	result.Found = len(result.BypassPayloads) > 0
	if result.TotalTested > 0 {
		result.BypassRate = float64(len(result.BypassPayloads)) / float64(result.TotalTested) * 100
	}

	return result
}
