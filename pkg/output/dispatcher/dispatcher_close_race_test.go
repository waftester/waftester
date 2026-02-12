// Regression tests for dispatcher Close() race condition (Bug #2).
//
// Before the fix, Close() called hookWg.Wait() without holding the write lock.
// A concurrent Dispatch() that already passed the closed.Load() checks could
// call hookWg.Add(1) during or after Wait(), causing a WaitGroup misuse panic.
// The fix acquires mu.Lock() before hookWg.Wait(), ensuring no Dispatch() is
// mid-execution when Wait() begins.
package dispatcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// TestCloseRace_ConcurrentDispatchAndClose hammers Dispatch() and Close()
// concurrently to trigger the WaitGroup race that existed before the fix.
//
// Regression: Close() did not hold write lock before hookWg.Wait(), allowing
// a Dispatch() goroutine running concurrently to call hookWg.Add(1) which
// panics if Wait() has already started.
func TestCloseRace_ConcurrentDispatchAndClose(t *testing.T) {
	t.Parallel()

	for i := 0; i < 50; i++ {
		d := New(Config{Async: true})

		h := newMockHook()
		h.shouldBlock = true
		h.blockTime = time.Millisecond
		d.RegisterHook(h)

		event := newMockEvent(events.EventTypeResult)
		ctx := context.Background()

		// Launch multiple dispatchers.
		var wg sync.WaitGroup
		const dispatchers = 20
		wg.Add(dispatchers)
		for j := 0; j < dispatchers; j++ {
			go func() {
				defer wg.Done()
				_ = d.Dispatch(ctx, event)
			}()
		}

		// Close concurrently while dispatches are in flight.
		go func() {
			time.Sleep(time.Microsecond * 50)
			_ = d.Close()
		}()

		wg.Wait()
		// If we reach here without panic, the race is fixed.
	}
}

// TestClose_HoldsLockBeforeWait verifies that Close() blocks new Dispatch()
// calls before waiting for outstanding hooks.
func TestClose_HoldsLockBeforeWait(t *testing.T) {
	t.Parallel()

	d := New(Config{Async: true})

	// Hook that takes 100ms to complete.
	h := newMockHook()
	h.shouldBlock = true
	h.blockTime = 100 * time.Millisecond
	d.RegisterHook(h)

	event := newMockEvent(events.EventTypeResult)
	ctx := context.Background()

	// Dispatch one event (starts async hook).
	if err := d.Dispatch(ctx, event); err != nil {
		t.Fatal(err)
	}

	// Close should wait for the hook and then release.
	start := time.Now()
	_ = d.Close()
	elapsed := time.Since(start)

	if elapsed < 50*time.Millisecond {
		t.Errorf("Close() returned in %v, expected >= 50ms (hook takes 100ms)", elapsed)
	}

	// After close, further dispatches are silently dropped (returns nil).
	// Verify the hook does NOT receive new events after Close().
	preCloseCount := h.getEventCount()
	_ = d.Dispatch(ctx, event)
	if h.getEventCount() != preCloseCount {
		t.Error("hook received event after Close() — dispatch should be dropped")
	}
}
