// Package runner provides concurrent execution for multi-target operations
package runner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/ratelimit"
	"github.com/waftester/waftester/pkg/regexcache"
)

// Result represents the result of processing a single target
type Result[T any] struct {
	Target   string
	Data     T
	Error    error
	Duration time.Duration
}

// Stats tracks execution statistics
type Stats struct {
	Total      int64
	Completed  int64
	Successful int64
	Failed     int64
	StartTime  time.Time
}

// RPS returns the current requests per second rate
func (s *Stats) RPS() float64 {
	elapsed := time.Since(s.StartTime).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&s.Completed)) / elapsed
}

// Progress returns completion percentage (0-100)
func (s *Stats) Progress() float64 {
	total := atomic.LoadInt64(&s.Total)
	if total == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&s.Completed)) / float64(total) * 100
}

// Runner executes tasks concurrently across multiple targets
type Runner[T any] struct {
	// Concurrency is the number of parallel workers (default 50)
	Concurrency int

	// RateLimit is max requests per second (0 = unlimited)
	RateLimit int

	// RateLimitPerHost enables per-host rate limiting
	// When true, RateLimit applies per host instead of globally
	RateLimitPerHost bool

	// Timeout per target
	Timeout time.Duration

	// Stats tracks execution statistics
	Stats Stats

	// OnProgress is called after each target completes
	OnProgress func(completed, total int64, result Result[T])

	// OnError is called when a target fails (optional)
	OnError func(target string, err error)

	// Internal rate limiter
	limiter *ratelimit.Limiter
}

// NewRunner creates a new runner with default settings
func NewRunner[T any]() *Runner[T] {
	return &Runner[T]{
		Concurrency: 50, // Default concurrency
		Timeout:     duration.HTTPFuzzing,
	}
}

// TaskFunc is the function type for processing a single target
type TaskFunc[T any] func(ctx context.Context, target string) (T, error)

// Run executes the task function for all targets concurrently
func (r *Runner[T]) Run(ctx context.Context, targets []string, task TaskFunc[T]) []Result[T] {
	if len(targets) == 0 {
		return nil
	}

	// Initialize stats
	r.Stats = Stats{
		Total:     int64(len(targets)),
		StartTime: time.Now(),
	}

	// Default concurrency
	concurrency := r.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	// Create semaphore for concurrency control
	sem := make(chan struct{}, concurrency)

	// Initialize rate limiter if needed
	if r.RateLimit > 0 && r.limiter == nil {
		r.limiter = ratelimit.New(&ratelimit.Config{
			RequestsPerSecond: r.RateLimit,
			PerHost:           r.RateLimitPerHost,
			Burst:             r.RateLimit / 5, // 20% burst capacity
		})
	}

	// Results channel
	resultsChan := make(chan Result[T], len(targets))

	// WaitGroup for all goroutines
	var wg sync.WaitGroup

	// Process each target
	for _, target := range targets {
		// Check context cancellation
		select {
		case <-ctx.Done():
			// Context cancelled, stop launching new goroutines
			goto cleanup
		default:
		}

		// Skip hosts that are known to be failing
		if hosterrors.Check(target) {
			atomic.AddInt64(&r.Stats.Completed, 1)
			atomic.AddInt64(&r.Stats.Failed, 1)
			resultsChan <- Result[T]{
				Target:   target,
				Error:    fmt.Errorf("host skipped: exceeded error threshold"),
				Duration: 0,
			}
			continue
		}

		// Rate limiting with per-host support
		if r.limiter != nil {
			host := extractHost(target)
			_ = r.limiter.WaitForHost(ctx, host)
		}

		// Acquire semaphore slot
		sem <- struct{}{}
		wg.Add(1)

		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			start := time.Now()

			// Create timeout context for this target
			taskCtx, cancel := context.WithTimeout(ctx, r.Timeout)
			defer cancel()

			// Execute the task
			data, err := task(taskCtx, t)
			duration := time.Since(start)

			result := Result[T]{
				Target:   t,
				Data:     data,
				Error:    err,
				Duration: duration,
			}

			// Update stats
			atomic.AddInt64(&r.Stats.Completed, 1)
			if err == nil {
				atomic.AddInt64(&r.Stats.Successful, 1)
			} else {
				atomic.AddInt64(&r.Stats.Failed, 1)
				// Track network errors for host skipping
				if hosterrors.IsNetworkError(err) {
					hosterrors.MarkError(t)
				}
				if r.OnError != nil {
					r.OnError(t, err)
				}
			}

			// Progress callback
			if r.OnProgress != nil {
				r.OnProgress(
					atomic.LoadInt64(&r.Stats.Completed),
					atomic.LoadInt64(&r.Stats.Total),
					result,
				)
			}

			resultsChan <- result
		}(target)
	}

cleanup:
	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	results := make([]Result[T], 0, len(targets))
	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// RunWithCallback executes tasks and calls callback for each result (streaming)
func (r *Runner[T]) RunWithCallback(ctx context.Context, targets []string, task TaskFunc[T], callback func(Result[T])) {
	if len(targets) == 0 {
		return
	}

	// Initialize stats
	r.Stats = Stats{
		Total:     int64(len(targets)),
		StartTime: time.Now(),
	}

	// Default concurrency
	concurrency := r.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	// Create semaphore for concurrency control
	sem := make(chan struct{}, concurrency)

	// Initialize rate limiter if needed
	if r.RateLimit > 0 && r.limiter == nil {
		r.limiter = ratelimit.New(&ratelimit.Config{
			RequestsPerSecond: r.RateLimit,
			PerHost:           r.RateLimitPerHost,
			Burst:             r.RateLimit / 5, // 20% burst capacity
		})
	}

	// WaitGroup for all goroutines
	var wg sync.WaitGroup

	// Process each target
	for _, target := range targets {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Skip hosts that are known to be failing
		if hosterrors.Check(target) {
			atomic.AddInt64(&r.Stats.Completed, 1)
			atomic.AddInt64(&r.Stats.Failed, 1)
			callback(Result[T]{
				Target:   target,
				Error:    fmt.Errorf("host skipped: exceeded error threshold"),
				Duration: 0,
			})
			continue
		}

		// Rate limiting with per-host support
		if r.limiter != nil {
			host := extractHost(target)
			_ = r.limiter.WaitForHost(ctx, host)
		}

		// Acquire semaphore slot
		sem <- struct{}{}
		wg.Add(1)

		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			start := time.Now()

			// Create timeout context for this target
			taskCtx, cancel := context.WithTimeout(ctx, r.Timeout)
			defer cancel()

			// Execute the task
			data, err := task(taskCtx, t)
			duration := time.Since(start)

			result := Result[T]{
				Target:   t,
				Data:     data,
				Error:    err,
				Duration: duration,
			}

			// Update stats
			atomic.AddInt64(&r.Stats.Completed, 1)
			if err == nil {
				atomic.AddInt64(&r.Stats.Successful, 1)
			} else {
				atomic.AddInt64(&r.Stats.Failed, 1)
				// Track network errors for host skipping
				if hosterrors.IsNetworkError(err) {
					hosterrors.MarkError(t)
				}
			}

			// Call the callback immediately (streaming output)
			callback(result)
		}(target)
	}

	// Wait for all goroutines to complete
	wg.Wait()
}

// extractHost extracts the hostname from a URL or target string
func extractHost(target string) string {
	// Try to parse as URL first
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host := u.Hostname()
		if host != "" {
			return host
		}
	}

	// Fallback: strip scheme and path
	host := strings.TrimPrefix(target, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]
	return host
}

// PerformanceMetrics holds performance statistics for the runner
type PerformanceMetrics struct {
	HostErrorsTracked int64   // Number of hosts tracked in error cache
	HostErrorsHits    int64   // Number of requests skipped due to host errors
	HostErrorsMisses  int64   // Number of requests not skipped
	HostErrorsHitRate float64 // Hit rate percentage
	RegexCacheSize    int     // Number of compiled regexes cached
}

// GetPerformanceMetrics returns current performance metrics
func GetPerformanceMetrics() PerformanceMetrics {
	hits, misses := hosterrors.Stats()
	hitRate := 0.0
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100.0
	}

	return PerformanceMetrics{
		HostErrorsTracked: int64(hosterrors.Size()),
		HostErrorsHits:    hits,
		HostErrorsMisses:  misses,
		HostErrorsHitRate: hitRate,
		RegexCacheSize:    regexcache.Size(),
	}
}
