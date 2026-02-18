// Regression tests for runner semaphore context handling (from 85-fix adversarial review).
//
// Bug: sem <- struct{}{} blocked forever when context was cancelled and
//
//	the semaphore was full. The goroutine would never exit.
//
// Fix: select { case sem <- struct{}{}: case <-ctx.Done(): goto cleanup }
package runner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRun_CancelledContextDoesNotBlock verifies that a cancelled context
// does not cause Run() to block on semaphore acquisition.
// Regression: bare `sem <- struct{}{}` blocked forever when ctx was cancelled
// and all semaphore slots were occupied.
func TestRun_CancelledContextDoesNotBlock(t *testing.T) {
	t.Parallel()

	r := NewRunner[string]()
	r.Concurrency = 1

	// Create many targets so the semaphore would fill up
	targets := make([]string, 100)
	for i := range targets {
		targets[i] = "target"
	}

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Run(ctx, targets, func(ctx context.Context, target string) (string, error) {
			// Simulate slow work
			time.Sleep(1 * time.Second)
			return "ok", nil
		})
	}()

	select {
	case <-done:
		// Success — Run returned promptly despite cancelled context
	case <-time.After(5 * time.Second):
		t.Fatal("BLOCKED: Run() did not return within 5s after context cancellation")
	}
}

// TestRun_ContextCancelDuringExecution verifies that cancelling the context
// mid-execution causes Run to stop processing remaining targets promptly.
func TestRun_ContextCancelDuringExecution(t *testing.T) {
	t.Parallel()

	r := NewRunner[string]()
	r.Concurrency = 2

	targets := make([]string, 50)
	for i := range targets {
		targets[i] = "target"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_ = r.Run(ctx, targets, func(ctx context.Context, target string) (string, error) {
		time.Sleep(500 * time.Millisecond)
		return "ok", nil
	})
	elapsed := time.Since(start)

	// Should complete well before all 50 targets × 500ms
	assert.Less(t, elapsed, 3*time.Second,
		"Run must respect context cancellation, not process all targets")
}

// TestRunWithCallback_CancelledContextDoesNotBlock verifies the callback variant
// also respects context cancellation at the semaphore.
func TestRunWithCallback_CancelledContextDoesNotBlock(t *testing.T) {
	t.Parallel()

	r := NewRunner[string]()
	r.Concurrency = 1

	targets := make([]string, 100)
	for i := range targets {
		targets[i] = "target"
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunWithCallback(ctx, targets, func(ctx context.Context, target string) (string, error) {
			time.Sleep(1 * time.Second)
			return "ok", nil
		}, func(result Result[string]) {
			// callback
		})
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("BLOCKED: RunWithCallback() did not return within 5s after context cancellation")
	}
}

// TestRun_CancelDuringRateLimitWait_StopsLaunching ensures cancellation while
// blocked in WaitForHost does not execute additional tasks.
func TestRun_CancelDuringRateLimitWait_StopsLaunching(t *testing.T) {
	t.Parallel()

	r := NewRunner[string]()
	r.Concurrency = 1
	r.RateLimit = 1

	targets := []string{"https://example.com/a", "https://example.com/b", "https://example.com/c"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var executed int32
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_ = r.Run(ctx, targets, func(ctx context.Context, target string) (string, error) {
		atomic.AddInt32(&executed, 1)
		return "ok", nil
	})

	assert.LessOrEqual(t, atomic.LoadInt32(&executed), int32(1),
		"runner executed tasks after context cancellation during rate-limit wait")
}

// TestRunWithCallback_CancelDuringRateLimitWait_StopsLaunching ensures callback
// runner also stops launching tasks when cancellation happens during limiter wait.
func TestRunWithCallback_CancelDuringRateLimitWait_StopsLaunching(t *testing.T) {
	t.Parallel()

	r := NewRunner[string]()
	r.Concurrency = 1
	r.RateLimit = 1

	targets := []string{"https://example.com/a", "https://example.com/b", "https://example.com/c"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var executed int32
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	r.RunWithCallback(ctx, targets, func(ctx context.Context, target string) (string, error) {
		atomic.AddInt32(&executed, 1)
		return "ok", nil
	}, func(result Result[string]) {})

	assert.LessOrEqual(t, atomic.LoadInt32(&executed), int32(1),
		"runner callback variant executed tasks after context cancellation during rate-limit wait")
}
