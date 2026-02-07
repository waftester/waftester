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
