// Regression test for bug: worker pool running counter drift on panic recovery.
//
// Before the fix, when a worker panicked the replacement goroutine was spawned
// first (p.wg.Add(1); go p.worker()) and only then the current goroutine fell
// through to atomic.AddInt32(&p.running, -1). Because the replacement was
// NOT incrementing running before the current worker decremented it, a brief
// undercount occurred. Under high panic rates the counter could drift
// permanently, leading to incorrect Running() reports and premature capacity
// exhaustion. The fix increments running for the replacement BEFORE the
// deferred decrement for the dying worker executes.
package workerpool

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWorkerPanicRecovery_RunningCountStable verifies that after many panics
// the Running() count converges back to the pool size — no permanent drift.
func TestWorkerPanicRecovery_RunningCountStable(t *testing.T) {
	t.Parallel()

	const poolSize = 4
	p := New(poolSize)
	defer p.Close()

	// Let workers fully start.
	time.Sleep(20 * time.Millisecond)

	// Submit many panicking tasks. Each panic kills a worker and triggers
	// a respawn — the running counter must stay accurate through all of it.
	const panics = 50
	var done sync.WaitGroup
	done.Add(panics)

	for i := 0; i < panics; i++ {
		p.Submit(func() {
			defer done.Done()
			panic("intentional test panic")
		})
	}

	done.Wait()
	// Give workers time to respawn and stabilise.
	time.Sleep(50 * time.Millisecond)

	running := p.Running()
	if running != poolSize {
		t.Errorf("Running() = %d after %d panics; want %d (counter drifted)", running, panics, poolSize)
	}
}

// TestWorkerPanicRecovery_CounterNeverNegative checks that the running counter
// never becomes negative during a barrage of panics.
func TestWorkerPanicRecovery_CounterNeverNegative(t *testing.T) {
	t.Parallel()

	const poolSize = 4
	p := New(poolSize)
	defer p.Close()

	time.Sleep(20 * time.Millisecond)

	var wg sync.WaitGroup
	var sawNegative int32

	// Observer goroutine: polls Running() looking for negative values.
	ctx := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx:
				return
			default:
				if p.Running() < 0 {
					atomic.StoreInt32(&sawNegative, 1)
				}
				time.Sleep(time.Microsecond)
			}
		}
	}()

	// Fire panics concurrently.
	const panics = 100
	var taskWg sync.WaitGroup
	taskWg.Add(panics)
	for i := 0; i < panics; i++ {
		p.Submit(func() {
			defer taskWg.Done()
			panic("boom")
		})
	}
	taskWg.Wait()
	close(ctx)
	wg.Wait()

	if atomic.LoadInt32(&sawNegative) != 0 {
		t.Error("Running() went negative during panic storm — counter drift detected")
	}
}

// TestWorkerPanicRecovery_TasksStillProcess verifies that after panics the pool
// can still process normal tasks — workers were actually respawned.
func TestWorkerPanicRecovery_TasksStillProcess(t *testing.T) {
	t.Parallel()

	const poolSize = 4
	p := New(poolSize)
	defer p.Close()

	// Cause several panics.
	var panicWg sync.WaitGroup
	panicWg.Add(10)
	for i := 0; i < 10; i++ {
		p.Submit(func() {
			defer panicWg.Done()
			panic("intentional")
		})
	}
	panicWg.Wait()
	time.Sleep(20 * time.Millisecond)

	// Now submit normal tasks — they must all complete.
	const normalTasks = 50
	var counter int64
	var normalWg sync.WaitGroup
	normalWg.Add(normalTasks)
	for i := 0; i < normalTasks; i++ {
		ok := p.Submit(func() {
			defer normalWg.Done()
			atomic.AddInt64(&counter, 1)
		})
		if !ok {
			t.Fatal("Submit returned false on an open pool after panics")
		}
	}
	normalWg.Wait()

	if got := atomic.LoadInt64(&counter); got != normalTasks {
		t.Errorf("processed %d tasks after panics; want %d", got, normalTasks)
	}
}
