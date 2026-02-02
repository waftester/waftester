// Package health provides health checking and wait functionality for WAF endpoints
package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Common errors
var (
	ErrTimeout      = errors.New("health check timed out")
	ErrMaxRetries   = errors.New("maximum retries exceeded")
	ErrUnhealthy    = errors.New("endpoint is unhealthy")
	ErrNoEndpoints  = errors.New("no endpoints configured")
	ErrAllUnhealthy = errors.New("all endpoints are unhealthy")
)

// Status represents the health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// CheckType defines the type of health check
type CheckType string

const (
	CheckTypeHTTP CheckType = "http"
	CheckTypeTCP  CheckType = "tcp"
	CheckTypeExec CheckType = "exec"
	CheckTypeGRPC CheckType = "grpc"
)

// Result represents a health check result
type Result struct {
	Endpoint   string        `json:"endpoint"`
	Status     Status        `json:"status"`
	StatusCode int           `json:"status_code,omitempty"`
	Latency    time.Duration `json:"latency"`
	Message    string        `json:"message,omitempty"`
	CheckedAt  time.Time     `json:"checked_at"`
	Attempts   int           `json:"attempts"`
	Body       string        `json:"body,omitempty"`
}

// IsHealthy returns true if the result indicates healthy status
func (r *Result) IsHealthy() bool {
	return r.Status == StatusHealthy
}

// Check defines a health check configuration
type Check struct {
	Name            string            `json:"name" yaml:"name"`
	Endpoint        string            `json:"endpoint" yaml:"endpoint"`
	Type            CheckType         `json:"type" yaml:"type"`
	Method          string            `json:"method,omitempty" yaml:"method,omitempty"`
	Headers         map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body            string            `json:"body,omitempty" yaml:"body,omitempty"`
	ExpectedStatus  []int             `json:"expected_status,omitempty" yaml:"expected_status,omitempty"`
	ExpectedBody    string            `json:"expected_body,omitempty" yaml:"expected_body,omitempty"`
	ExpectedPattern string            `json:"expected_pattern,omitempty" yaml:"expected_pattern,omitempty"`
	Timeout         time.Duration     `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Interval        time.Duration     `json:"interval,omitempty" yaml:"interval,omitempty"`
}

// Validate validates the check configuration
func (c *Check) Validate() error {
	if c.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	if c.Type == "" {
		c.Type = CheckTypeHTTP
	}
	if c.Method == "" {
		c.Method = "GET"
	}
	if c.Timeout == 0 {
		c.Timeout = httpclient.TimeoutProbing
	}
	if c.Interval == 0 {
		c.Interval = duration.RetryFast
	}
	if len(c.ExpectedStatus) == 0 {
		c.ExpectedStatus = []int{200}
	}
	return nil
}

// Config contains health checker configuration
type Config struct {
	Checks      []*Check      `json:"checks" yaml:"checks"`
	Timeout     time.Duration `json:"timeout" yaml:"timeout"`
	MaxRetries  int           `json:"max_retries" yaml:"max_retries"`
	RetryDelay  time.Duration `json:"retry_delay" yaml:"retry_delay"`
	FailFast    bool          `json:"fail_fast" yaml:"fail_fast"`
	Concurrency int           `json:"concurrency" yaml:"concurrency"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Checks:      make([]*Check, 0),
		Timeout:     httpclient.TimeoutFuzzing,
		MaxRetries:  defaults.RetryMax,
		RetryDelay:  duration.RetryFast,
		FailFast:    false,
		Concurrency: 5,
	}
}

// Checker performs health checks
type Checker struct {
	config     *Config
	httpClient *http.Client
}

// NewChecker creates a new health checker
func NewChecker(config *Config) *Checker {
	if config == nil {
		config = DefaultConfig()
	}
	return &Checker{
		config:     config,
		httpClient: httpclient.Default(),
	}
}

// AddCheck adds a health check
func (c *Checker) AddCheck(check *Check) error {
	if err := check.Validate(); err != nil {
		return fmt.Errorf("invalid check: %w", err)
	}
	c.config.Checks = append(c.config.Checks, check)
	return nil
}

// CheckOne performs a single health check
func (c *Checker) CheckOne(ctx context.Context, check *Check) (*Result, error) {
	if err := check.Validate(); err != nil {
		return nil, err
	}

	result := &Result{
		Endpoint:  check.Endpoint,
		Status:    StatusUnknown,
		CheckedAt: time.Now(),
		Attempts:  1,
	}

	switch check.Type {
	case CheckTypeHTTP:
		return c.checkHTTP(ctx, check, result)
	case CheckTypeTCP:
		return c.checkTCP(ctx, check, result)
	default:
		return nil, fmt.Errorf("unsupported check type: %s", check.Type)
	}
}

func (c *Checker) checkHTTP(ctx context.Context, check *Check, result *Result) (*Result, error) {
	start := time.Now()

	var body io.Reader
	if check.Body != "" {
		body = strings.NewReader(check.Body)
	}

	req, err := http.NewRequestWithContext(ctx, check.Method, check.Endpoint, body)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("failed to create request: %v", err)
		result.Latency = time.Since(start)
		return result, nil
	}

	for k, v := range check.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("request failed: %v", err)
		result.Latency = time.Since(start)
		return result, nil
	}
	defer iohelper.DrainAndClose(resp.Body)

	result.StatusCode = resp.StatusCode
	result.Latency = time.Since(start)

	// Read body for comparison
	bodyBytes, _ := iohelper.ReadBodyDefault(resp.Body)
	result.Body = string(bodyBytes)

	// Check status code
	statusOK := false
	for _, expected := range check.ExpectedStatus {
		if resp.StatusCode == expected {
			statusOK = true
			break
		}
	}

	if !statusOK {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("unexpected status code: %d, expected: %v", resp.StatusCode, check.ExpectedStatus)
		return result, nil
	}

	// Check expected body
	if check.ExpectedBody != "" {
		if !strings.Contains(result.Body, check.ExpectedBody) {
			result.Status = StatusUnhealthy
			result.Message = fmt.Sprintf("body does not contain expected string: %s", check.ExpectedBody)
			return result, nil
		}
	}

	// Check expected pattern
	if check.ExpectedPattern != "" {
		re, err := regexp.Compile(check.ExpectedPattern)
		if err != nil {
			result.Status = StatusUnhealthy
			result.Message = fmt.Sprintf("invalid pattern: %v", err)
			return result, nil
		}
		if !re.MatchString(result.Body) {
			result.Status = StatusUnhealthy
			result.Message = fmt.Sprintf("body does not match pattern: %s", check.ExpectedPattern)
			return result, nil
		}
	}

	result.Status = StatusHealthy
	result.Message = "OK"
	return result, nil
}

func (c *Checker) checkTCP(ctx context.Context, check *Check, result *Result) (*Result, error) {
	start := time.Now()

	// TCP check - just verify the endpoint format for now
	// Full TCP implementation would use net.Dial
	if !strings.Contains(check.Endpoint, ":") {
		result.Status = StatusUnhealthy
		result.Message = "invalid TCP endpoint format (expected host:port)"
		result.Latency = time.Since(start)
		return result, nil
	}

	result.Status = StatusHealthy
	result.Message = "TCP endpoint format valid"
	result.Latency = time.Since(start)
	return result, nil
}

// CheckAll performs all configured health checks
func (c *Checker) CheckAll(ctx context.Context) ([]*Result, error) {
	if len(c.config.Checks) == 0 {
		return nil, ErrNoEndpoints
	}

	results := make([]*Result, 0, len(c.config.Checks))
	var mu sync.Mutex

	// Use semaphore for concurrency control
	sem := make(chan struct{}, c.config.Concurrency)
	var wg sync.WaitGroup

	for _, check := range c.config.Checks {
		wg.Add(1)
		go func(chk *Check) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, _ := c.CheckOne(ctx, chk)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(check)
	}

	wg.Wait()
	return results, nil
}

// AllHealthy returns true if all checks are healthy
func (c *Checker) AllHealthy(results []*Result) bool {
	for _, r := range results {
		if !r.IsHealthy() {
			return false
		}
	}
	return true
}

// Waiter waits for health checks to pass
type Waiter struct {
	checker *Checker
	config  *WaiterConfig
}

// WaiterConfig configures the waiter
type WaiterConfig struct {
	Timeout       time.Duration `json:"timeout" yaml:"timeout"`
	CheckInterval time.Duration `json:"check_interval" yaml:"check_interval"`
	MinChecks     int           `json:"min_checks" yaml:"min_checks"`
	FailFast      bool          `json:"fail_fast" yaml:"fail_fast"`
	OnProgress    func(attempt int, result *Result)
}

// DefaultWaiterConfig returns default waiter configuration
func DefaultWaiterConfig() *WaiterConfig {
	return &WaiterConfig{
		Timeout:       httpclient.TimeoutAPI,
		CheckInterval: duration.HealthCheck,
		MinChecks:     1,
		FailFast:      false,
	}
}

// NewWaiter creates a new waiter
func NewWaiter(checker *Checker, config *WaiterConfig) *Waiter {
	if config == nil {
		config = DefaultWaiterConfig()
	}
	return &Waiter{
		checker: checker,
		config:  config,
	}
}

// WaitResult contains the wait operation result
type WaitResult struct {
	Success     bool          `json:"success"`
	Duration    time.Duration `json:"duration"`
	Attempts    int           `json:"attempts"`
	LastResults []*Result     `json:"last_results"`
	Error       error         `json:"error,omitempty"`
}

// Wait waits for all health checks to pass
func (w *Waiter) Wait(ctx context.Context) *WaitResult {
	startTime := time.Now()
	deadline := startTime.Add(w.config.Timeout)

	result := &WaitResult{
		Success:  false,
		Attempts: 0,
	}

	for {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(startTime)
			result.Error = ctx.Err()
			return result
		default:
		}

		if time.Now().After(deadline) {
			result.Duration = time.Since(startTime)
			result.Error = ErrTimeout
			return result
		}

		result.Attempts++

		// Perform health checks
		checkCtx, cancel := context.WithTimeout(ctx, w.checker.config.Timeout)
		results, err := w.checker.CheckAll(checkCtx)
		cancel()

		result.LastResults = results

		if err != nil && w.config.FailFast {
			result.Duration = time.Since(startTime)
			result.Error = err
			return result
		}

		// Report progress
		if w.config.OnProgress != nil && len(results) > 0 {
			for _, r := range results {
				w.config.OnProgress(result.Attempts, r)
			}
		}

		// Check if all healthy
		if w.checker.AllHealthy(results) {
			result.Success = true
			result.Duration = time.Since(startTime)
			return result
		}

		// Wait before next check
		select {
		case <-ctx.Done():
			result.Duration = time.Since(startTime)
			result.Error = ctx.Err()
			return result
		case <-time.After(w.config.CheckInterval):
			// Continue to next iteration
		}
	}
}

// WaitFor is a convenience function to wait for a single endpoint
func WaitFor(ctx context.Context, endpoint string, timeout time.Duration) error {
	config := DefaultConfig()
	checker := NewChecker(config)

	check := &Check{
		Name:     "endpoint",
		Endpoint: endpoint,
		Type:     CheckTypeHTTP,
		Method:   "GET",
	}

	if err := checker.AddCheck(check); err != nil {
		return err
	}

	waiterConfig := DefaultWaiterConfig()
	waiterConfig.Timeout = timeout
	waiter := NewWaiter(checker, waiterConfig)

	result := waiter.Wait(ctx)
	if !result.Success {
		if result.Error != nil {
			return result.Error
		}
		return ErrUnhealthy
	}
	return nil
}

// WaitForMultiple waits for multiple endpoints
func WaitForMultiple(ctx context.Context, endpoints []string, timeout time.Duration) error {
	config := DefaultConfig()
	checker := NewChecker(config)

	for i, ep := range endpoints {
		check := &Check{
			Name:     fmt.Sprintf("endpoint-%d", i+1),
			Endpoint: ep,
			Type:     CheckTypeHTTP,
			Method:   "GET",
		}
		if err := checker.AddCheck(check); err != nil {
			return err
		}
	}

	waiterConfig := DefaultWaiterConfig()
	waiterConfig.Timeout = timeout
	waiter := NewWaiter(checker, waiterConfig)

	result := waiter.Wait(ctx)
	if !result.Success {
		if result.Error != nil {
			return result.Error
		}
		return ErrAllUnhealthy
	}
	return nil
}

// Monitor continuously monitors health
type Monitor struct {
	checker  *Checker
	interval time.Duration
	onResult func([]*Result)
	stopCh   chan struct{}
	running  bool
	mu       sync.Mutex
}

// NewMonitor creates a new health monitor
func NewMonitor(checker *Checker, interval time.Duration) *Monitor {
	if interval == 0 {
		interval = httpclient.TimeoutProbing
	}
	return &Monitor{
		checker:  checker,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// SetCallback sets the result callback
func (m *Monitor) SetCallback(fn func([]*Result)) {
	m.onResult = fn
}

// Start starts the monitor
func (m *Monitor) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	go m.run(ctx)
}

// Stop stops the monitor
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		close(m.stopCh)
		m.running = false
	}
}

// IsRunning returns true if the monitor is running
func (m *Monitor) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *Monitor) run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			results, _ := m.checker.CheckAll(ctx)
			if m.onResult != nil {
				m.onResult(results)
			}
		}
	}
}

// Builder provides fluent API for building health checks
type Builder struct {
	checks []*Check
}

// NewBuilder creates a new health check builder
func NewBuilder() *Builder {
	return &Builder{
		checks: make([]*Check, 0),
	}
}

// AddHTTP adds an HTTP health check
func (b *Builder) AddHTTP(name, endpoint string) *Builder {
	b.checks = append(b.checks, &Check{
		Name:     name,
		Endpoint: endpoint,
		Type:     CheckTypeHTTP,
		Method:   "GET",
	})
	return b
}

// AddHTTPWithExpected adds an HTTP check with expected status
func (b *Builder) AddHTTPWithExpected(name, endpoint string, expectedStatus []int) *Builder {
	b.checks = append(b.checks, &Check{
		Name:           name,
		Endpoint:       endpoint,
		Type:           CheckTypeHTTP,
		Method:         "GET",
		ExpectedStatus: expectedStatus,
	})
	return b
}

// AddTCP adds a TCP health check
func (b *Builder) AddTCP(name, endpoint string) *Builder {
	b.checks = append(b.checks, &Check{
		Name:     name,
		Endpoint: endpoint,
		Type:     CheckTypeTCP,
	})
	return b
}

// Build returns the checks
func (b *Builder) Build() []*Check {
	return b.checks
}

// CreateChecker creates a checker from the built checks
func (b *Builder) CreateChecker() *Checker {
	config := DefaultConfig()
	config.Checks = b.checks
	return NewChecker(config)
}
