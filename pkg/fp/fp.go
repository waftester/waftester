// Package fp provides false positive testing capabilities for WAF validation.
// It tests benign payloads that should NOT trigger WAF rules, identifying
// overly aggressive configurations that block legitimate traffic.
package fp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/ui"
	"golang.org/x/time/rate"
)

// Config holds false positive testing configuration
type Config struct {
	TargetURL     string
	Concurrency   int
	RateLimit     float64
	Timeout       time.Duration
	SkipVerify    bool
	Verbose       bool
	ParanoiaLevel int      // CRS paranoia level 1-4 (for local testing)
	CorpusSources []string // Which corpus sources to use
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Concurrency:   20,
		RateLimit:     50,
		Timeout:       10 * time.Second,
		ParanoiaLevel: 2,
		CorpusSources: []string{"leipzig", "edgecases", "forms", "api"},
	}
}

// Result represents the overall FP testing result
type Result struct {
	TargetURL            string           `json:"target_url"`
	TotalTests           int64            `json:"total_tests"`
	FalsePositives       int64            `json:"false_positives"`
	TrueNegatives        int64            `json:"true_negatives"`
	Errors               int64            `json:"errors"`
	FPRatio              float64          `json:"fp_ratio"`
	Duration             time.Duration    `json:"duration"`
	StartTime            time.Time        `json:"start_time"`
	EndTime              time.Time        `json:"end_time"`
	ByCorpus             map[string]int64 `json:"by_corpus"`
	ByLocation           map[string]int64 `json:"by_location"`
	FalsePositiveDetails []FPDetail       `json:"false_positive_details"`
}

// FPDetail contains details about a specific false positive
type FPDetail struct {
	Payload       string `json:"payload"`
	Corpus        string `json:"corpus"`
	Location      string `json:"location"`
	StatusCode    int    `json:"status_code"`
	ResponseBody  string `json:"response_body,omitempty"`
	RuleID        int    `json:"rule_id,omitempty"` // If detected from logs
	ParanoiaLevel int    `json:"paranoia_level,omitempty"`
}

// Tester performs false positive testing
type Tester struct {
	config     *Config
	httpClient *http.Client
	limiter    *rate.Limiter
	corpus     *Corpus
}

// NewTester creates a new FP tester
func NewTester(cfg *Config) *Tester {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	transport := &http.Transport{
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		},
	}

	return &Tester{
		config: cfg,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), int(cfg.RateLimit)),
		corpus:  NewCorpus(),
	}
}

// GetCorpus returns the corpus used by this tester
func (t *Tester) GetCorpus() *Corpus {
	return t.corpus
}

// TestTask represents a single FP test
type TestTask struct {
	Payload  string
	Corpus   string
	Location string // query_param, post_form, post_json, header
}

// Run executes false positive testing against the target
func (t *Tester) Run(ctx context.Context) (*Result, error) {
	result := &Result{
		TargetURL:            t.config.TargetURL,
		StartTime:            time.Now(),
		ByCorpus:             make(map[string]int64),
		ByLocation:           make(map[string]int64),
		FalsePositiveDetails: make([]FPDetail, 0),
	}

	// Load corpus
	if err := t.corpus.Load(t.config.CorpusSources); err != nil {
		return nil, fmt.Errorf("failed to load corpus: %w", err)
	}

	// Generate test tasks
	tasks := t.generateTasks()
	result.TotalTests = int64(len(tasks))

	if t.config.Verbose {
		fmt.Printf("  Generated %d FP test tasks\n", len(tasks))
	}

	// Task channel
	taskChan := make(chan TestTask, t.config.Concurrency*2)

	// Results tracking
	var fpMu sync.Mutex
	var blocked, passed, errors int64

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < t.config.Concurrency; i++ {
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
				t.limiter.Wait(ctx)

				// Execute test
				isBlocked, statusCode, respBody, err := t.executeTest(ctx, task)

				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}

				if isBlocked {
					// This is a FALSE POSITIVE - benign content was blocked
					atomic.AddInt64(&blocked, 1)
					fpMu.Lock()
					result.FalsePositiveDetails = append(result.FalsePositiveDetails, FPDetail{
						Payload:      task.Payload,
						Corpus:       task.Corpus,
						Location:     task.Location,
						StatusCode:   statusCode,
						ResponseBody: truncate(respBody, 200),
					})
					result.ByCorpus[task.Corpus]++
					result.ByLocation[task.Location]++
					fpMu.Unlock()
				} else {
					// TRUE NEGATIVE - benign content was correctly allowed
					atomic.AddInt64(&passed, 1)
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

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.FalsePositives = blocked
	result.TrueNegatives = passed
	result.Errors = errors

	if result.TotalTests > 0 {
		result.FPRatio = float64(result.FalsePositives) / float64(result.TotalTests) * 100
	}

	return result, nil
}

// generateTasks creates all test tasks from corpus
func (t *Tester) generateTasks() []TestTask {
	tasks := make([]TestTask, 0)
	locations := []string{"query_param", "post_form", "post_json", "header_custom"}

	for _, source := range t.config.CorpusSources {
		payloads := t.corpus.Get(source)
		for _, payload := range payloads {
			for _, location := range locations {
				tasks = append(tasks, TestTask{
					Payload:  payload,
					Corpus:   source,
					Location: location,
				})
			}
		}
	}

	return tasks
}

// executeTest runs a single FP test
func (t *Tester) executeTest(ctx context.Context, task TestTask) (blocked bool, statusCode int, respBody string, err error) {
	targetURL := t.config.TargetURL
	method := "GET"
	var body io.Reader
	headers := make(map[string]string)

	switch task.Location {
	case "query_param":
		targetURL = targetURL + "?test=" + url.QueryEscape(task.Payload)

	case "post_form":
		method = "POST"
		body = strings.NewReader("data=" + url.QueryEscape(task.Payload))
		headers["Content-Type"] = "application/x-www-form-urlencoded"

	case "post_json":
		method = "POST"
		jsonBody, _ := json.Marshal(map[string]string{"input": task.Payload})
		body = strings.NewReader(string(jsonBody))
		headers["Content-Type"] = "application/json"

	case "header_custom":
		headers["X-Custom-Input"] = task.Payload
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, body)
	if err != nil {
		return false, 0, "", err
	}

	req.Header.Set("User-Agent", ui.UserAgentWithContext("FP-Test"))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	respBody = string(bodyBytes)
	statusCode = resp.StatusCode

	// Check if blocked - these status codes indicate WAF block
	blocked = statusCode == 403 || statusCode == 406 || statusCode == 429 ||
		statusCode == 418 || statusCode == 503

	return blocked, statusCode, respBody, nil
}

// SaveResult saves the FP test result to a file
func (r *Result) SaveResult(filepath string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}

// truncate limits string length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
