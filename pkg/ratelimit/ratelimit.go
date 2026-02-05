// Package ratelimit provides rate limiting functionality for HTTP requests
// Modeled after katana, ffuf, httpx, and gospider rate limiting systems
package ratelimit

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/duration"
)

// Config holds rate limiting configuration
type Config struct {
	// RequestsPerSecond limits requests per second (0 = unlimited)
	RequestsPerSecond int

	// RequestsPerMinute limits requests per minute (0 = unlimited)
	RequestsPerMinute int

	// Delay is fixed delay between requests
	Delay time.Duration

	// DelayMin and DelayMax for random delay range (if both set)
	DelayMin time.Duration
	DelayMax time.Duration

	// RandomDelay adds extra random delay (gospider style)
	RandomDelay time.Duration

	// PerHost enables per-host rate limiting (ffuf style)
	PerHost bool

	// AdaptiveSlowdown reduces rate on errors
	AdaptiveSlowdown bool
	SlowdownFactor   float64 // Multiply delay by this on error (default 1.5)
	SlowdownMaxDelay time.Duration
	RecoveryRate     float64 // Reduce delay by this factor on success

	// Burst allows bursting up to N requests before rate limiting kicks in
	Burst int
}

// DefaultConfig returns sensible defaults (150 req/sec like katana)
func DefaultConfig() *Config {
	return &Config{
		RequestsPerSecond: 150,
		RequestsPerMinute: 0,
		Delay:             0,
		PerHost:           false,
		AdaptiveSlowdown:  false,
		SlowdownFactor:    1.5,
		SlowdownMaxDelay:  duration.VerySlowResponse,
		RecoveryRate:      0.9,
		Burst:             10,
	}
}

// Limiter provides rate limiting for HTTP requests
type Limiter struct {
	config *Config
	mu     sync.Mutex

	// Global rate limiting state - use atomic for lock-free access
	lastRequestNano int64 // Unix nano timestamp, atomic

	// Per-second rate limiting (token bucket)
	secondBucket *tokenBucket

	// Per-minute rate limiting
	minuteWindow *slidingWindow

	// Per-host limiters (when PerHost is enabled)
	hostLimiters   map[string]*Limiter
	hostLimitersMu sync.RWMutex

	// Adaptive state
	currentDelay time.Duration
}

// tokenBucket implements a simple token bucket algorithm
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per nanosecond
	lastRefill time.Time
}

func newTokenBucket(rps int, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: float64(rps) / float64(time.Second),
		lastRefill: time.Now(),
	}
}

func (tb *tokenBucket) take() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tb.lastRefill = now

	// Refill tokens
	tb.tokens += float64(elapsed) * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}

	// Try to take a token
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

func (tb *tokenBucket) waitTime() time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.tokens >= 1 {
		return 0
	}

	// Calculate wait time for 1 token
	needed := 1 - tb.tokens
	return time.Duration(needed / tb.refillRate)
}

// slidingWindow tracks requests in a time window
type slidingWindow struct {
	mu       sync.Mutex
	window   time.Duration
	maxCount int
	requests []time.Time
}

func newSlidingWindow(max int, window time.Duration) *slidingWindow {
	return &slidingWindow{
		window:   window,
		maxCount: max,
		requests: make([]time.Time, 0, max),
	}
}

func (sw *slidingWindow) canProceed() bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-sw.window)

	// Remove old requests
	newReqs := sw.requests[:0]
	for _, t := range sw.requests {
		if t.After(cutoff) {
			newReqs = append(newReqs, t)
		}
	}
	sw.requests = newReqs

	return len(sw.requests) < sw.maxCount
}

func (sw *slidingWindow) record() {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.requests = append(sw.requests, time.Now())
}

func (sw *slidingWindow) waitTime() time.Duration {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if len(sw.requests) < sw.maxCount {
		return 0
	}

	// Wait until oldest request falls out of window
	oldest := sw.requests[0]
	return time.Until(oldest.Add(sw.window))
}

// New creates a new rate limiter with the given configuration
func New(cfg *Config) *Limiter {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	l := &Limiter{
		config:          cfg,
		lastRequestNano: time.Now().UnixNano(),
		currentDelay:    cfg.Delay,
		hostLimiters:    make(map[string]*Limiter),
	}

	// Set up token bucket for per-second limiting
	if cfg.RequestsPerSecond > 0 {
		burst := cfg.Burst
		if burst <= 0 {
			burst = cfg.RequestsPerSecond / 10
			if burst < 1 {
				burst = 1
			}
		}
		l.secondBucket = newTokenBucket(cfg.RequestsPerSecond, burst)
	}

	// Set up sliding window for per-minute limiting
	if cfg.RequestsPerMinute > 0 {
		l.minuteWindow = newSlidingWindow(cfg.RequestsPerMinute, time.Minute)
	}

	return l
}

// Wait blocks until the rate limit allows another request
func (l *Limiter) Wait(ctx context.Context) error {
	return l.WaitForHost(ctx, "")
}

// WaitForHost blocks until the rate limit allows another request for the given host
func (l *Limiter) WaitForHost(ctx context.Context, host string) error {
	// If per-host limiting is enabled, delegate to host-specific limiter
	if l.config.PerHost && host != "" {
		hostLimiter := l.getOrCreateHostLimiter(host)
		return hostLimiter.waitInternal(ctx)
	}

	return l.waitInternal(ctx)
}

func (l *Limiter) getOrCreateHostLimiter(host string) *Limiter {
	l.hostLimitersMu.RLock()
	hl, ok := l.hostLimiters[host]
	l.hostLimitersMu.RUnlock()

	if ok {
		return hl
	}

	l.hostLimitersMu.Lock()
	defer l.hostLimitersMu.Unlock()

	// Double-check after acquiring write lock
	if hl, ok = l.hostLimiters[host]; ok {
		return hl
	}

	// Create new per-host limiter with same config (but no per-host recursion)
	hostConfig := *l.config
	hostConfig.PerHost = false
	hl = New(&hostConfig)
	l.hostLimiters[host] = hl

	return hl
}

func (l *Limiter) waitInternal(ctx context.Context) error {
	// Use a reusable timer to avoid allocations on each wait
	var timer *time.Timer

	// Helper to wait with reusable timer
	waitWithTimer := func(d time.Duration) error {
		if timer == nil {
			timer = time.NewTimer(d)
			defer timer.Stop()
		} else {
			timer.Reset(d)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}

	// Check per-second bucket
	if l.secondBucket != nil {
		for !l.secondBucket.take() {
			waitTime := l.secondBucket.waitTime()
			if waitTime > 0 {
				if err := waitWithTimer(waitTime); err != nil {
					return err
				}
			}
		}
	}

	// Check per-minute window
	if l.minuteWindow != nil {
		for !l.minuteWindow.canProceed() {
			waitTime := l.minuteWindow.waitTime()
			if waitTime > 0 {
				if err := waitWithTimer(waitTime); err != nil {
					return err
				}
			}
		}
		l.minuteWindow.record()
	}

	// Apply fixed/random delay
	delay := l.calculateDelay()
	if delay > 0 {
		if err := waitWithTimer(delay); err != nil {
			return err
		}
	}

	// Record last request time atomically (no lock needed)
	atomic.StoreInt64(&l.lastRequestNano, time.Now().UnixNano())

	return nil
}

func (l *Limiter) calculateDelay() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	var delay time.Duration

	// Use delay range if both set
	if l.config.DelayMin > 0 && l.config.DelayMax > 0 {
		diff := l.config.DelayMax - l.config.DelayMin
		delay = l.config.DelayMin + time.Duration(rand.Int63n(int64(diff)))
	} else if l.currentDelay > 0 {
		delay = l.currentDelay
	}

	// Add random delay if set (gospider style)
	if l.config.RandomDelay > 0 {
		delay += time.Duration(rand.Int63n(int64(l.config.RandomDelay)))
	}

	return delay
}

// OnError should be called when a request fails (for adaptive rate limiting)
func (l *Limiter) OnError() {
	if !l.config.AdaptiveSlowdown {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Increase delay
	if l.currentDelay == 0 {
		l.currentDelay = 100 * time.Millisecond
	} else {
		l.currentDelay = time.Duration(float64(l.currentDelay) * l.config.SlowdownFactor)
	}

	if l.currentDelay > l.config.SlowdownMaxDelay {
		l.currentDelay = l.config.SlowdownMaxDelay
	}
}

// OnSuccess should be called when a request succeeds (for adaptive rate limiting)
func (l *Limiter) OnSuccess() {
	if !l.config.AdaptiveSlowdown {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Gradually reduce delay
	if l.currentDelay > 0 {
		l.currentDelay = time.Duration(float64(l.currentDelay) * l.config.RecoveryRate)
		if l.currentDelay < l.config.Delay {
			l.currentDelay = l.config.Delay
		}
	}
}

// Stats returns current rate limiter statistics
type Stats struct {
	CurrentDelay     time.Duration
	HostLimiterCount int
	TokensAvailable  float64
	MinuteRequests   int
}

func (l *Limiter) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()

	stats := Stats{
		CurrentDelay: l.currentDelay,
	}

	l.hostLimitersMu.RLock()
	stats.HostLimiterCount = len(l.hostLimiters)
	l.hostLimitersMu.RUnlock()

	if l.secondBucket != nil {
		l.secondBucket.mu.Lock()
		stats.TokensAvailable = l.secondBucket.tokens
		l.secondBucket.mu.Unlock()
	}

	if l.minuteWindow != nil {
		l.minuteWindow.mu.Lock()
		stats.MinuteRequests = len(l.minuteWindow.requests)
		l.minuteWindow.mu.Unlock()
	}

	return stats
}

// ClearHost removes the per-host rate limiter for a specific host.
// This helps prevent unbounded memory growth during long-running scans.
func (l *Limiter) ClearHost(host string) {
	l.hostLimitersMu.Lock()
	defer l.hostLimitersMu.Unlock()
	delete(l.hostLimiters, host)
}

// ClearAllHosts removes all per-host rate limiters.
// Use this periodically during long-running scans to free memory.
func (l *Limiter) ClearAllHosts() {
	l.hostLimitersMu.Lock()
	defer l.hostLimitersMu.Unlock()
	l.hostLimiters = make(map[string]*Limiter)
}

// MultiLimiter combines multiple rate limiters (e.g., global + per-host)
type MultiLimiter struct {
	limiters []*Limiter
}

// NewMultiLimiter creates a limiter that applies multiple rate limits
func NewMultiLimiter(limiters ...*Limiter) *MultiLimiter {
	return &MultiLimiter{limiters: limiters}
}

// Wait blocks until all limiters allow a request
func (ml *MultiLimiter) Wait(ctx context.Context) error {
	for _, l := range ml.limiters {
		if err := l.Wait(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Simple convenience constructors

// NewPerSecond creates a limiter with N requests per second
func NewPerSecond(rps int) *Limiter {
	return New(&Config{RequestsPerSecond: rps, Burst: rps / 10})
}

// NewPerMinute creates a limiter with N requests per minute
func NewPerMinute(rpm int) *Limiter {
	return New(&Config{RequestsPerMinute: rpm})
}

// NewWithDelay creates a limiter with fixed delay between requests
func NewWithDelay(delay time.Duration) *Limiter {
	return New(&Config{Delay: delay})
}

// NewWithDelayRange creates a limiter with random delay between min and max
func NewWithDelayRange(min, max time.Duration) *Limiter {
	return New(&Config{DelayMin: min, DelayMax: max})
}

// NewPerHost creates a per-host rate limiter
func NewPerHost(rps int) *Limiter {
	return New(&Config{RequestsPerSecond: rps, PerHost: true, Burst: rps / 10})
}

// NewAdaptive creates an adaptive rate limiter that slows down on errors
func NewAdaptive(rps int, baseDelay time.Duration) *Limiter {
	return New(&Config{
		RequestsPerSecond: rps,
		Delay:             baseDelay,
		AdaptiveSlowdown:  true,
		SlowdownFactor:    1.5,
		SlowdownMaxDelay:  duration.VerySlowResponse,
		RecoveryRate:      0.9,
	})
}
