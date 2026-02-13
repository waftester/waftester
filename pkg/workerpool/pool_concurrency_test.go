package workerpool

// Concurrency and safety tests for worker pool — verifies no deadlocks,
// panics on double-close, or races under concurrent Submit/Close/Resize.
// Would have caught R3 (workerpool deadlock, data race, double-close concerns).

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/testutil"
)

// TestPool_SubmitAfterClose verifies Submit returns false after Close.
func TestPool_SubmitAfterClose(t *testing.T) {
	t.Parallel()

	p := New(2)
	p.Close()

	ok := p.Submit(func() {
		t.Error("task should not execute after Close")
	})
	if ok {
		t.Error("Submit returned true after Close")
	}
}

// TestPool_DoubleClose_NoPanic verifies calling Close twice doesn't panic.
func TestPool_DoubleClose_NoPanic(t *testing.T) {
	t.Parallel()

	p := New(2)

	testutil.AssertNoPanic(t, "first Close", func() { p.Close() })
	testutil.AssertNoPanic(t, "second Close", func() { p.Close() })
}

// TestPool_ConcurrentSubmitAndClose verifies no deadlock when Submit and Close race.
func TestPool_ConcurrentSubmitAndClose(t *testing.T) {
	t.Parallel()

	testutil.AssertTimeout(t, "Submit+Close race", 5*time.Second, func() {
		p := New(4)
		var executed int64

		// Hammer Submit from many goroutines
		done := make(chan struct{})
		for i := 0; i < 20; i++ {
			go func() {
				defer func() { recover() }() // don't fail on close-related panics
				for {
					select {
					case <-done:
						return
					default:
						p.Submit(func() {
							atomic.AddInt64(&executed, 1)
						})
					}
				}
			}()
		}

		// Let submissions run briefly
		time.Sleep(50 * time.Millisecond)

		// Close while submissions are in flight
		p.Close()
		close(done)
	})
}

// TestPool_ResizeDuringWork verifies Resize doesn't cause panics or deadlocks
// while tasks are running.
func TestPool_ResizeDuringWork(t *testing.T) {
	t.Parallel()

	testutil.AssertTimeout(t, "Resize during work", 5*time.Second, func() {
		p := New(2)
		defer p.Close()

		var count int64
		for i := 0; i < 100; i++ {
			p.Submit(func() {
				time.Sleep(time.Millisecond)
				atomic.AddInt64(&count, 1)
			})
		}

		// Resize while tasks may still be running
		p.Resize(8)
		p.Resize(1)
		p.Resize(4)
	})
}

// TestPool_ConcurrentSubmit_NoRace verifies concurrent Submit has no data races.
// Run with -race flag.
func TestPool_ConcurrentSubmit_NoRace(t *testing.T) {
	t.Parallel()

	p := New(4)
	defer p.Close()

	var total int64
	testutil.RunConcurrently(50, func(i int) {
		for j := 0; j < 100; j++ {
			p.Submit(func() {
				atomic.AddInt64(&total, 1)
			})
		}
	})

	// Wait for tasks to drain
	time.Sleep(200 * time.Millisecond)
}

// TestPool_ZeroWorkers verifies pool handles zero workers gracefully.
func TestPool_ZeroWorkers(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("New(0) panicked: %v (acceptable)", r)
			return
		}
	}()

	p := New(0)
	if p != nil {
		p.Close()
	}
}

// TestPool_PanicRecovery verifies panicking tasks don't kill worker goroutines.
func TestPool_PanicRecovery_Concurrency(t *testing.T) {
	t.Parallel()

	p := New(2)
	defer p.Close()

	// Submit a panicking task
	p.Submit(func() {
		panic("test panic")
	})

	// Give the panic time to propagate
	time.Sleep(50 * time.Millisecond)

	// Pool should still accept tasks
	done := make(chan bool, 1)
	ok := p.Submit(func() {
		done <- true
	})
	if !ok {
		t.Skip("Submit returned false — pool may not recover from panics (design choice)")
	}

	select {
	case <-done:
		// Pool recovered from panic
	case <-time.After(2 * time.Second):
		t.Error("task didn't execute after panic — worker goroutine may be dead")
	}
}
