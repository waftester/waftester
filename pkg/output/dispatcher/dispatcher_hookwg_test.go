// Regression test for bug: Dispatcher.Close() did not wait for async hooks.
//
// Before the fix, async hooks were fire-and-forget goroutines. Close() would
// flush and close writers without waiting for hook goroutines to finish, causing
// data loss and race conditions when hooks were still running after Close()
// returned. The fix adds a sync.WaitGroup (hookWg) so Close() blocks until
// all async hooks complete.
package dispatcher

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// TestCloseWaitsForAsyncHooks verifies Close() blocks until all async hooks
// finish, rather than returning immediately.
func TestCloseWaitsForAsyncHooks(t *testing.T) {
	t.Parallel()

	d := New(Config{Async: true})

	h := newMockHook()
	h.shouldBlock = true
	h.blockTime = 200 * time.Millisecond
	d.RegisterHook(h)

	event := newMockEvent(events.EventTypeResult)

	// Dispatch fires the async hook goroutine.
	if err := d.Dispatch(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	// Close should block until the async hook finishes (~200ms).
	start := time.Now()
	_ = d.Close()
	elapsed := time.Since(start)

	// If Close returned without waiting, elapsed would be ~0ms.
	if elapsed < 100*time.Millisecond {
		t.Errorf("Close() returned in %v; expected it to wait for async hook (~200ms)", elapsed)
	}

	// Verify the hook actually processed the event.
	if h.getEventCount() != 1 {
		t.Errorf("hook received %d events after Close(); want 1", h.getEventCount())
	}
}

// TestCloseWaitsForMultipleAsyncHooks verifies Close() waits for ALL hooks,
// not just the first one.
func TestCloseWaitsForMultipleAsyncHooks(t *testing.T) {
	t.Parallel()

	d := New(Config{Async: true})

	const numHooks = 5
	hooks := make([]*mockHook, numHooks)
	for i := range hooks {
		hooks[i] = newMockHook()
		hooks[i].shouldBlock = true
		hooks[i].blockTime = 100 * time.Millisecond
		d.RegisterHook(hooks[i])
	}

	event := newMockEvent(events.EventTypeResult)
	if err := d.Dispatch(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	_ = d.Close()

	for i, h := range hooks {
		if h.getEventCount() != 1 {
			t.Errorf("hook[%d] received %d events; want 1", i, h.getEventCount())
		}
	}
}

// TestAsyncHookError_DoesNotPreventClose verifies that hook errors don't
// cause Close() to hang.
func TestAsyncHookError_DoesNotPreventClose(t *testing.T) {
	t.Parallel()

	d := New(Config{Async: true})

	h := newMockHook()
	h.shouldFail = true
	d.RegisterHook(h)

	event := newMockEvent(events.EventTypeResult)
	_ = d.Dispatch(context.Background(), event)

	// Close must complete promptly even though the hook returned an error.
	done := make(chan struct{})
	go func() {
		_ = d.Close()
		close(done)
	}()

	select {
	case <-done:
		// Good.
	case <-time.After(2 * time.Second):
		t.Fatal("Close() hung after async hook error")
	}
}

// TestDispatchAfterClose_NoHookPanic verifies that dispatching after Close
// does not panic when async hooks would normally increment hookWg on a zeroed
// WaitGroup state. (Defense in depth.)
func TestDispatchAfterClose_NoHookPanic(t *testing.T) {
	t.Parallel()

	d := New(Config{Async: true})

	var hookCalled int32
	h := &simpleHook{
		onEvent: func(_ context.Context, _ events.Event) error {
			atomic.AddInt32(&hookCalled, 1)
			return nil
		},
		eventTypes: nil, // all events
	}
	d.RegisterHook(h)

	_ = d.Close()

	// Dispatch after close — must not panic and must not process.
	_ = d.Dispatch(context.Background(), newMockEvent(events.EventTypeResult))

	// Give any spawned goroutine time to run.
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadInt32(&hookCalled) != 0 {
		t.Error("hook was called after Close() — closed flag not checked")
	}
}

// TestConcurrentDispatchAndClose verifies that calling Dispatch() concurrently
// with Close() does not panic (no WaitGroup Add-after-Wait race).
func TestConcurrentDispatchAndClose(t *testing.T) {
	t.Parallel()

	d := New(Config{Async: true})

	var eventCount int64
	h := &simpleHook{
		onEvent: func(_ context.Context, _ events.Event) error {
			atomic.AddInt64(&eventCount, 1)
			time.Sleep(time.Millisecond)
			return nil
		},
		eventTypes: nil,
	}
	d.RegisterHook(h)

	// Launch many concurrent dispatchers.
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = d.Dispatch(context.Background(), newMockEvent(events.EventTypeResult))
			}
		}()
	}

	// Let some dispatches occur, then close mid-flight.
	time.Sleep(5 * time.Millisecond)
	_ = d.Close()

	wg.Wait()

	// Verify: no panic occurred, and at least some events were processed.
	if atomic.LoadInt64(&eventCount) == 0 {
		t.Error("no events processed — expected at least some before close")
	}
}

// simpleHook is a minimal Hook implementation for focused tests.
type simpleHook struct {
	onEvent    func(context.Context, events.Event) error
	eventTypes []events.EventType
}

func (h *simpleHook) OnEvent(ctx context.Context, event events.Event) error {
	return h.onEvent(ctx, event)
}

func (h *simpleHook) EventTypes() []events.EventType {
	return h.eventTypes
}
