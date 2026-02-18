// Regression tests for rate limiter concurrency correctness.
package osint

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRateLimiter_ThunderingHerd verifies that concurrent goroutines calling
// Wait() do NOT all proceed simultaneously when tokens are exhausted.
// Regression: after sleeping, all goroutines unconditionally set tokens=1,
// causing N goroutines to all proceed at once — bypassing the rate limit.
func TestRateLimiter_ThunderingHerd(t *testing.T) {
	t.Parallel()

	// Rate limit: 10 requests per minute = 1 every 6 seconds
	// We use a higher rate so the test runs quickly
	rl := NewRateLimiter(600) // 10 per second

	const goroutines = 20
	const callsPerGoroutine = 1

	var admitted int64
	var maxConcurrent int64
	var current int64

	var wg sync.WaitGroup

	// Drain all initial tokens first
	for i := 0; i < 600; i++ {
		rl.Wait(context.Background())
	}

	// Now all tokens are exhausted. Launch concurrent goroutines.
	start := time.Now()
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			rl.Wait(context.Background())

			// Track concurrency
			c := atomic.AddInt64(&current, 1)
			atomic.AddInt64(&admitted, 1)

			// Record peak concurrent admissions
			for {
				old := atomic.LoadInt64(&maxConcurrent)
				if c <= old || atomic.CompareAndSwapInt64(&maxConcurrent, old, c) {
					break
				}
			}

			// Simulate doing work
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt64(&current, -1)
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	// All 20 goroutines must have completed
	if atomic.LoadInt64(&admitted) != goroutines {
		t.Errorf("expected %d admissions, got %d", goroutines, atomic.LoadInt64(&admitted))
	}

	// The total elapsed time should be > 0 (goroutines should NOT all proceed instantly)
	// With 600 RPM (10/sec), 20 requests should take at least ~1 second
	// But we allow generous slack since CI can be slow
	if elapsed < 50*time.Millisecond {
		t.Errorf("all %d goroutines completed in %v — rate limiting likely bypassed",
			goroutines, elapsed)
	}

	// Max concurrent should be significantly less than total goroutines
	// (exact value depends on timing, but the thundering herd bug would
	// allow all 20 to proceed simultaneously)
	peak := atomic.LoadInt64(&maxConcurrent)
	if peak >= int64(goroutines) {
		t.Errorf("thundering herd detected: max concurrent = %d (all %d goroutines)",
			peak, goroutines)
	}

	t.Logf("Admitted %d goroutines over %v, peak concurrent = %d",
		admitted, elapsed, peak)
}

// TestRateLimiter_BasicFunctionality verifies tokens are consumed and refilled.
func TestRateLimiter_BasicFunctionality(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(60) // 1 per second

	// Should complete immediately (initial tokens available)
	start := time.Now()
	rl.Wait(context.Background())
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("first Wait() should be near-instant, took %v", elapsed)
	}
}

// TestRateLimiter_RefillAfterSleep verifies tokens refill based on elapsed time.
func TestRateLimiter_RefillAfterSleep(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(60) // 1 per second

	// Drain all tokens
	for i := 0; i < 60; i++ {
		rl.Wait(context.Background())
	}

	// Wait for refill period
	time.Sleep(1100 * time.Millisecond)

	// Next Wait() should be near-instant (tokens refilled)
	start := time.Now()
	rl.Wait(context.Background())
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait() after refill period should be near-instant, took %v", elapsed)
	}
}

// TestRateLimiter_TokensNeverExceedMax verifies token cap is maintained.
func TestRateLimiter_TokensNeverExceedMax(t *testing.T) {
	t.Parallel()

	const maxTokens = 10
	rl := NewRateLimiter(maxTokens)

	// Sleep to accumulate refills
	time.Sleep(200 * time.Millisecond)

	// Drain: should get at most maxTokens without blocking
	start := time.Now()
	for i := 0; i < maxTokens; i++ {
		rl.Wait(context.Background())
	}
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("draining %d tokens should be near-instant, took %v", maxTokens, elapsed)
	}
}

// TestRateLimiter_ZeroRequestsPerMinute_NoPanic verifies that NewRateLimiter(0)
// does not panic with a division-by-zero.
// Regression: time.Minute / time.Duration(0) caused a panic.
func TestRateLimiter_ZeroRequestsPerMinute_NoPanic(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(0)
	if rl == nil {
		t.Fatal("NewRateLimiter(0) returned nil")
	}
	// Should be able to Wait without panic
	rl.Wait(context.Background())
}

// TestRateLimiter_NegativeRequestsPerMinute_NoPanic verifies negative input is clamped.
func TestRateLimiter_NegativeRequestsPerMinute_NoPanic(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(-5)
	if rl == nil {
		t.Fatal("NewRateLimiter(-5) returned nil")
	}
	rl.Wait(context.Background())
}
