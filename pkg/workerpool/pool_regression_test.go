// Regression tests for concurrency bugs in the worker pool.
package workerpool

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Regression test for bug: Submit on closed pool could panic due to send on closed channel.
func TestSubmitOnClosedPool_NoPanic(t *testing.T) {
	t.Parallel()

	p := New(4)
	p.Close()

	var wg sync.WaitGroup
	wg.Add(100)

	for i := 0; i < 100; i++ {
		go func() {
			defer wg.Done()
			ok := p.Submit(func() {
				t.Error("task should not execute on closed pool")
			})
			if ok {
				t.Error("Submit should return false on closed pool")
			}
		}()
	}

	wg.Wait()
}

// Regression test for bug: ParallelFor on closed pool could panic or hang.
func TestParallelForWithClosedPool_NoPanic(t *testing.T) {
	t.Parallel()

	p := New(4)
	p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.ParallelFor(10, func(i int) {
			t.Errorf("ParallelFor callback should not execute on closed pool, got index %d", i)
		})
	}()

	select {
	case <-done:
		// Completed without hanging — success.
	case <-ctx.Done():
		t.Fatal("ParallelFor on closed pool hung past 2s deadline")
	}
}

// Regression test for bug: concurrent Submit calls could race on atomic CAS patterns.
func TestPoolSubmitConcurrent_NoRace(t *testing.T) {
	t.Parallel()

	p := New(4)

	var counter int64
	var wg sync.WaitGroup

	const goroutines = 10
	const tasksPerGoroutine = 100

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < tasksPerGoroutine; i++ {
				ok := p.Submit(func() {
					atomic.AddInt64(&counter, 1)
				})
				if !ok {
					t.Error("Submit returned false on open pool")
				}
			}
		}()
	}

	wg.Wait()
	p.Close()

	got := atomic.LoadInt64(&counter)
	const want = goroutines * tasksPerGoroutine
	if got != want {
		t.Errorf("expected %d tasks to run, got %d", want, got)
	}
}

// Regression test for bug: Map on closed pool could hang or panic.
func TestPool_MapWithClosedPool(t *testing.T) {
	t.Parallel()

	p := New(4)
	p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		items := []int{1, 2, 3, 4, 5}
		results := Map(p, items, func(v int) int {
			return v * 2
		})
		// Results slice must exist and have correct length,
		// though values may be zero since tasks don't run on a closed pool.
		if len(results) != len(items) {
			t.Errorf("expected results length %d, got %d", len(items), len(results))
		}
	}()

	select {
	case <-done:
		// Success.
	case <-ctx.Done():
		t.Fatal("Map on closed pool hung past 2s deadline")
	}
}

// Regression test for bug: Filter on closed pool could hang or panic.
func TestPool_FilterWithClosedPool(t *testing.T) {
	t.Parallel()

	p := New(4)
	p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		items := []int{1, 2, 3, 4, 5}
		results := Filter(p, items, func(v int) bool {
			return v%2 == 0
		})
		// Should return empty or partial results without hanging.
		_ = results
	}()

	select {
	case <-done:
		// Success.
	case <-ctx.Done():
		t.Fatal("Filter on closed pool hung past 2s deadline")
	}
}

// Regression test for bug: Submit() racing with Close() could cause panic
// from send-on-closed-channel. The defer/recover in Submit() must catch this.
// This is the most critical race: wg.Add(1) in Submit racing with wg.Wait()
// in Close after the channel is already closed.
func TestPool_SubmitAndCloseRace_NoPanic(t *testing.T) {
	t.Parallel()

	for trial := 0; trial < 20; trial++ {
		p := New(4)

		// Pre-fill the pool with some work so workers are active
		var counter atomic.Int64
		for i := 0; i < 20; i++ {
			p.Submit(func() {
				time.Sleep(time.Millisecond)
				counter.Add(1)
			})
		}

		// Now race Submit and Close from different goroutines
		var wg sync.WaitGroup
		wg.Add(2)

		// Submitter goroutine: keeps trying to submit
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				p.Submit(func() {
					counter.Add(1)
				})
			}
		}()

		// Closer goroutine: closes the pool while submitter is active
		go func() {
			defer wg.Done()
			// Small delay so submitter gets a head start
			time.Sleep(100 * time.Microsecond)
			p.Close()
		}()

		wg.Wait()

		// If we reach here without panic, the test passes.
		// Also verify the pool reports as closed.
		if !p.IsClosed() {
			t.Errorf("trial %d: pool should be closed after Close()", trial)
		}
	}
}

// Regression test: multiple concurrent Close() calls must not double-close the channel.
func TestPool_DoubleClosed_NoPanic(t *testing.T) {
	t.Parallel()

	p := New(4)

	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			p.Close()
		}()
	}
	wg.Wait()

	if !p.IsClosed() {
		t.Error("pool should be closed")
	}
}

// Regression test for A2: Submit holding RLock during blocking channel send
// could deadlock Close which needs exclusive Lock. The fix releases RLock
// before blockingSend and uses a done channel for cancellation.
func TestPool_BlockingSendCloseDeadlock(t *testing.T) {
	t.Parallel()

	// Small pool with tiny buffer to force the blocking-send path.
	const workers = 2
	p := &Pool{
		workers: workers,
		tasks:   make(chan func(), 1), // minimal buffer
		done:    make(chan struct{}),
	}

	// Fill the buffer and occupy all workers so Submit must block.
	blocker := make(chan struct{})
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		atomic.AddInt32(&p.running, 1)
		go p.worker()
	}
	// Occupy workers
	for i := 0; i < workers; i++ {
		p.tasks <- func() { <-blocker }
	}
	// Fill remaining buffer
	p.tasks <- func() { <-blocker }

	// Now Submit must take the blockingSend path because the buffer is full.
	submitDone := make(chan bool, 1)
	go func() {
		ok := p.Submit(func() {})
		submitDone <- ok
	}()

	// Give goroutine time to enter blockingSend.
	time.Sleep(20 * time.Millisecond)

	// Close must complete within a deadline — if it deadlocks, the test fails.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		p.Close()
	}()

	// Unblock workers so they drain and exit.
	close(blocker)

	select {
	case <-closeDone:
		// Close completed — no deadlock.
	case <-ctx.Done():
		t.Fatal("Close deadlocked: timed out after 3s (A2 regression)")
	}

	// Submit should have returned false (pool closed while blocked).
	select {
	case ok := <-submitDone:
		// ok may be true (task sent before close) or false (done signal).
		// Either is acceptable — the key property is no deadlock.
		_ = ok
	case <-time.After(time.Second):
		t.Fatal("Submit goroutine hung after Close completed")
	}
}
