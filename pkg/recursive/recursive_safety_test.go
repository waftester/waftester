package recursive

// Safety tests for recursive fuzzer — verifies context cancellation propagation,
// no goroutine leaks, and graceful error handling.
// Would have caught R4 (recursive fuzzer deadlock, context leak).

import (
	"context"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/testutil"
)

// TestFuzzer_Run_ContextCancel verifies Run returns promptly when context is cancelled.
func TestFuzzer_Run_ContextCancel(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.MaxDepth = 3
	cfg.MaxResults = 100

	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	testutil.AssertTimeout(t, "Run cancelled ctx", 5*time.Second, func() {
		_, err := f.Run(ctx, "https://example.com")
		if err != nil {
			t.Logf("Run error on cancelled ctx: %v (expected)", err)
		}
	})
}

// TestFuzzer_Run_Timeout verifies Run doesn't hang when target is unreachable.
func TestFuzzer_Run_Timeout(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.MaxDepth = 1
	cfg.MaxResults = 1

	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	testutil.AssertTimeout(t, "Run timeout", 10*time.Second, func() {
		_, _ = f.Run(ctx, "https://192.0.2.1") // non-routable address
	})
}

// TestFuzzer_Run_InvalidURL verifies Run handles invalid URL gracefully.
func TestFuzzer_Run_InvalidURL(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = f.Run(ctx, "://invalid")
	if err == nil {
		t.Log("Run accepted invalid URL — no explicit validation (acceptable)")
	}
}

// TestFuzzer_Run_EmptyURL verifies Run handles empty URL gracefully.
func TestFuzzer_Run_EmptyURL(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = f.Run(ctx, "")
	if err == nil {
		t.Log("Run accepted empty URL — no explicit validation (acceptable)")
	}
}

// TestFuzzer_GoroutineLeak verifies Run doesn't leak goroutines after completion.
func TestFuzzer_GoroutineLeak(t *testing.T) {
	t.Parallel()

	tracker := testutil.TrackGoroutines()

	cfg := DefaultConfig()
	cfg.MaxDepth = 1
	cfg.MaxResults = 1

	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, _ = f.Run(ctx, "https://192.0.2.1") // non-routable, will timeout

	// Wait for goroutines to wind down
	time.Sleep(100 * time.Millisecond)
	tracker.CheckLeaks(t, 3) // tolerance for runtime + http goroutines
}

// TestDefaultConfig_Valid verifies DefaultConfig returns usable values.
func TestDefaultConfig_Valid(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	if cfg.MaxDepth <= 0 {
		t.Errorf("MaxDepth=%d, want >0", cfg.MaxDepth)
	}
	if cfg.MaxResults <= 0 {
		t.Errorf("MaxResults=%d, want >0", cfg.MaxResults)
	}
}
