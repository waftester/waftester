package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiter_PerSecond(t *testing.T) {
	// Create limiter with 100 requests per second, burst of 10
	l := New(&Config{RequestsPerSecond: 100, Burst: 10})

	ctx := context.Background()
	start := time.Now()

	// Make 5 requests (should be within burst)
	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}

	elapsed := time.Since(start)

	// Should complete quickly due to burst (within 200ms)
	if elapsed > 200*time.Millisecond {
		t.Errorf("5 requests with burst took too long: %v", elapsed)
	}
}

func TestLimiter_PerSecond_Throttle(t *testing.T) {
	// Create limiter with 5 requests per second, burst of 1
	l := New(&Config{RequestsPerSecond: 5, Burst: 1})

	ctx := context.Background()
	start := time.Now()

	// Make 3 requests - should take ~400ms (2 waits of 200ms each after first)
	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}

	elapsed := time.Since(start)

	// Should take at least 300ms for 3 requests at 5/sec with burst 1
	// (first instant, then 200ms, then 200ms)
	if elapsed < 300*time.Millisecond {
		t.Errorf("Expected throttling, but completed in %v", elapsed)
	}
}

func TestLimiter_Delay(t *testing.T) {
	l := NewWithDelay(50 * time.Millisecond)

	ctx := context.Background()
	start := time.Now()

	// Make 3 requests
	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}

	elapsed := time.Since(start)

	// Should take at least 150ms (3 * 50ms delay)
	if elapsed < 150*time.Millisecond {
		t.Errorf("Expected delay, but completed in %v", elapsed)
	}
}

func TestLimiter_DelayRange(t *testing.T) {
	l := NewWithDelayRange(10*time.Millisecond, 50*time.Millisecond)

	ctx := context.Background()
	start := time.Now()

	// Make 5 requests
	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}

	elapsed := time.Since(start)

	// Should take between 50ms and 250ms
	if elapsed < 50*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Errorf("Expected random delay range, got %v", elapsed)
	}
}

func TestLimiter_PerHost(t *testing.T) {
	l := NewPerHost(10)

	ctx := context.Background()

	// Requests to different hosts should have separate buckets
	hosts := []string{"host1.com", "host2.com", "host3.com"}

	var wg sync.WaitGroup
	var count int32

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				if err := l.WaitForHost(ctx, h); err != nil {
					t.Errorf("Wait failed for %s: %v", h, err)
					return
				}
				atomic.AddInt32(&count, 1)
			}
		}(host)
	}

	wg.Wait()

	if count != 15 {
		t.Errorf("Expected 15 requests, got %d", count)
	}

	// Check that we have 3 host limiters
	stats := l.Stats()
	if stats.HostLimiterCount != 3 {
		t.Errorf("Expected 3 host limiters, got %d", stats.HostLimiterCount)
	}
}

func TestLimiter_Adaptive(t *testing.T) {
	l := NewAdaptive(100, 10*time.Millisecond)

	// Initial delay should be the base delay
	if l.currentDelay != 10*time.Millisecond {
		t.Errorf("Expected initial delay of 10ms, got %v", l.currentDelay)
	}

	// Simulate errors to increase delay
	l.OnError()
	if l.currentDelay != 15*time.Millisecond { // 10ms * 1.5
		t.Errorf("Expected delay of 15ms after error, got %v", l.currentDelay)
	}

	l.OnError()
	expected := time.Duration(float64(15*time.Millisecond) * 1.5)
	if l.currentDelay != expected {
		t.Errorf("Expected delay of %v after 2nd error, got %v", expected, l.currentDelay)
	}

	// Simulate success to recover
	for i := 0; i < 10; i++ {
		l.OnSuccess()
	}

	// Delay should have decreased but not below base
	if l.currentDelay < 10*time.Millisecond {
		t.Errorf("Delay dropped below base: %v", l.currentDelay)
	}
}

func TestLimiter_ContextCancellation(t *testing.T) {
	l := NewWithDelay(500 * time.Millisecond)

	// First request should work with longer timeout
	ctx1, cancel1 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel1()

	if err := l.Wait(ctx1); err != nil {
		t.Fatalf("First wait failed: %v", err)
	}

	// Second request with short timeout should be cancelled
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()

	err := l.Wait(ctx2)
	if err == nil {
		t.Error("Expected context cancellation error")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("Expected DeadlineExceeded, got %v", err)
	}
}

func TestMultiLimiter(t *testing.T) {
	l1 := NewPerSecond(10)
	l2 := NewWithDelay(20 * time.Millisecond)

	ml := NewMultiLimiter(l1, l2)

	ctx := context.Background()
	start := time.Now()

	// Make 3 requests
	for i := 0; i < 3; i++ {
		if err := ml.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}

	elapsed := time.Since(start)

	// Should respect delay (slowest limiter)
	if elapsed < 60*time.Millisecond {
		t.Errorf("Expected at least 60ms delay, got %v", elapsed)
	}
}

func TestSlidingWindow(t *testing.T) {
	sw := newSlidingWindow(3, 100*time.Millisecond)

	// First 3 should succeed
	for i := 0; i < 3; i++ {
		if !sw.canProceed() {
			t.Errorf("Request %d should be allowed", i)
		}
		sw.record()
	}

	// 4th should fail
	if sw.canProceed() {
		t.Error("4th request should be blocked")
	}

	// Wait for window to expire
	time.Sleep(110 * time.Millisecond)

	// Should succeed again
	if !sw.canProceed() {
		t.Error("Request after window should succeed")
	}
}

func TestTokenBucket(t *testing.T) {
	tb := newTokenBucket(10, 5) // 10 per second, burst of 5

	// Take all burst tokens
	for i := 0; i < 5; i++ {
		if !tb.take() {
			t.Errorf("Take %d should succeed", i)
		}
	}

	// Next should fail
	if tb.take() {
		t.Error("Take after burst should fail")
	}

	// Wait time should be positive
	wt := tb.waitTime()
	if wt <= 0 {
		t.Error("Expected positive wait time")
	}

	// Wait for refill
	time.Sleep(110 * time.Millisecond) // Should refill ~1 token

	// Should succeed again
	if !tb.take() {
		t.Error("Take after refill should succeed")
	}
}

func BenchmarkLimiter_NoLimit(b *testing.B) {
	l := New(&Config{})
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.Wait(ctx)
	}
}

func BenchmarkLimiter_WithRateLimit(b *testing.B) {
	l := NewPerSecond(10000) // High limit to avoid actual waiting
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.Wait(ctx)
	}
}
