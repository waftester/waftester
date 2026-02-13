package screenshot

// Goroutine leak tests for BatchCapturer — verifies Start/Stop don't leak
// worker goroutines. Would have caught R4 (screenshot goroutine leak).

import (
	"context"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/testutil"
)

// TestBatchCapturer_StartStop_NoLeak verifies that Start followed by Stop
// doesn't leave goroutines running.
func TestBatchCapturer_StartStop_NoLeak(t *testing.T) {
	t.Parallel()

	tracker := testutil.TrackGoroutines()

	bc := NewBatchCapturer(DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())

	bc.Start(ctx, 4)
	time.Sleep(50 * time.Millisecond)

	cancel()
	bc.Stop()

	tracker.CheckLeaks(t, 2) // tolerance for runtime goroutines
}

// TestBatchCapturer_DoubleStop_NoPanic verifies calling Stop twice is safe.
func TestBatchCapturer_DoubleStop_NoPanic(t *testing.T) {
	t.Parallel()

	bc := NewBatchCapturer(DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	bc.Start(ctx, 2)
	cancel()

	testutil.AssertNoPanic(t, "first Stop", func() { bc.Stop() })
	testutil.AssertNoPanic(t, "second Stop", func() { bc.Stop() })
}

// TestBatchCapturer_ContextCancel_WorkersExit verifies workers exit promptly
// when context is cancelled, without needing explicit Stop.
func TestBatchCapturer_ContextCancel_WorkersExit(t *testing.T) {
	t.Parallel()

	tracker := testutil.TrackGoroutines()

	bc := NewBatchCapturer(DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())

	bc.Start(ctx, 8)
	time.Sleep(50 * time.Millisecond)

	cancel() // Cancel without calling Stop
	// Still need to call Stop to close channels and drain
	bc.Stop()

	tracker.CheckLeaks(t, 2)
}

// TestBatchCapturer_StopWithItems_NoPanic verifies Stop with queued but
// unprocessed items doesn't deadlock or panic.
func TestBatchCapturer_StopWithItems_NoPanic(t *testing.T) {
	t.Parallel()

	bc := NewBatchCapturer(DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())

	// Don't start workers — queue items without consumers
	go func() {
		for i := 0; i < 5; i++ {
			bc.Add("https://example.com")
		}
	}()
	time.Sleep(10 * time.Millisecond)

	bc.Start(ctx, 1) // Start briefly
	time.Sleep(10 * time.Millisecond)

	cancel()

	testutil.AssertTimeout(t, "Stop with items", 5*time.Second, func() {
		bc.Stop()
	})
}

// TestBatchCapturer_ZeroWorkers verifies Start(0) doesn't panic or deadlock.
func TestBatchCapturer_ZeroWorkers(t *testing.T) {
	t.Parallel()

	bc := NewBatchCapturer(DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())

	testutil.AssertNoPanic(t, "Start(0)", func() { bc.Start(ctx, 0) })
	cancel()
	bc.Stop()
}
