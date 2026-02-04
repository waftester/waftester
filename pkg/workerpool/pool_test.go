package workerpool

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPool_Submit(t *testing.T) {
	p := New(4)
	defer p.Close()

	var counter int64
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		p.Submit(func() {
			defer wg.Done()
			atomic.AddInt64(&counter, 1)
		})
	}

	wg.Wait()

	if counter != 100 {
		t.Errorf("Expected 100, got %d", counter)
	}
}

func TestPool_Running(t *testing.T) {
	p := New(4)
	defer p.Close()

	// Submit blocking tasks
	blocker := make(chan struct{})
	for i := 0; i < 4; i++ {
		p.Submit(func() {
			<-blocker
		})
	}

	// Wait for workers to start
	time.Sleep(10 * time.Millisecond)

	running := p.Running()
	if running != 4 {
		t.Errorf("Expected 4 running workers, got %d", running)
	}

	close(blocker)
}

func TestPool_Close(t *testing.T) {
	p := New(4)

	var counter int64
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		p.Submit(func() {
			defer wg.Done()
			atomic.AddInt64(&counter, 1)
		})
	}

	wg.Wait()
	p.Close()

	if !p.IsClosed() {
		t.Error("Pool should be closed")
	}

	// Submit after close should fail
	ok := p.Submit(func() {})
	if ok {
		t.Error("Submit should fail after close")
	}
}

func TestPool_ParallelFor(t *testing.T) {
	p := New(4)
	defer p.Close()

	results := make([]int, 10)
	p.ParallelFor(10, func(i int) {
		results[i] = i * 2
	})

	for i, v := range results {
		if v != i*2 {
			t.Errorf("results[%d] = %d, want %d", i, v, i*2)
		}
	}
}

func TestPool_Map(t *testing.T) {
	p := New(4)
	defer p.Close()

	items := []int{1, 2, 3, 4, 5}
	results := Map(p, items, func(x int) int {
		return x * x
	})

	expected := []int{1, 4, 9, 16, 25}
	for i, v := range results {
		if v != expected[i] {
			t.Errorf("results[%d] = %d, want %d", i, v, expected[i])
		}
	}
}

func TestPool_Filter(t *testing.T) {
	p := New(4)
	defer p.Close()

	items := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	evens := Filter(p, items, func(x int) bool {
		return x%2 == 0
	})

	if len(evens) != 5 {
		t.Errorf("Expected 5 evens, got %d", len(evens))
	}

	for _, v := range evens {
		if v%2 != 0 {
			t.Errorf("Expected even, got %d", v)
		}
	}
}

func TestPool_SubmitWait(t *testing.T) {
	p := New(4)
	defer p.Close()

	var result int
	p.SubmitWait(func() {
		result = 42
	})

	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}
}

func TestPool_Resize(t *testing.T) {
	p := New(4)
	defer p.Close()

	if p.Cap() != 4 {
		t.Errorf("Expected cap 4, got %d", p.Cap())
	}

	p.Resize(8)

	if p.Cap() != 8 {
		t.Errorf("Expected cap 8, got %d", p.Cap())
	}
}

func TestPool_Default(t *testing.T) {
	p := Default()

	var counter int64
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		p.Submit(func() {
			defer wg.Done()
			atomic.AddInt64(&counter, 1)
		})
	}

	wg.Wait()

	if counter != 100 {
		t.Errorf("Expected 100, got %d", counter)
	}
}

func TestPool_PanicRecovery(t *testing.T) {
	p := New(4)
	defer p.Close()

	var counter int64
	var wg sync.WaitGroup

	// Submit a panicking task
	wg.Add(1)
	p.Submit(func() {
		defer wg.Done()
		panic("test panic")
	})

	// Submit normal tasks
	for i := 0; i < 10; i++ {
		wg.Add(1)
		p.Submit(func() {
			defer wg.Done()
			atomic.AddInt64(&counter, 1)
		})
	}

	wg.Wait()

	// Pool should still work after panic
	if counter != 10 {
		t.Errorf("Expected 10, got %d", counter)
	}
}

func TestPool_Go(t *testing.T) {
	p := New(4)
	defer p.Close()

	var counter int64
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		// Go is an alias for Submit
		p.Go(func() {
			defer wg.Done()
			atomic.AddInt64(&counter, 1)
		})
	}

	wg.Wait()

	if counter != 10 {
		t.Errorf("Expected 10, got %d", counter)
	}
}

func TestPool_Waiting(t *testing.T) {
	p := New(1) // Single worker
	defer p.Close()

	blocker := make(chan struct{})
	var wg sync.WaitGroup

	// Block the single worker
	wg.Add(1)
	p.Submit(func() {
		defer wg.Done()
		<-blocker
	})

	// Give time for worker to start
	time.Sleep(10 * time.Millisecond)

	// Submit more tasks that will queue up
	for i := 0; i < 5; i++ {
		p.Submit(func() {})
	}

	// Check waiting count (should be ~5)
	waiting := p.Waiting()
	if waiting < 1 {
		t.Errorf("Expected at least 1 waiting, got %d", waiting)
	}

	// Unblock
	close(blocker)
	wg.Wait()
}

// Benchmarks

func BenchmarkPool_Submit(b *testing.B) {
	p := New(8)
	defer p.Close()

	var wg sync.WaitGroup
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		wg.Add(1)
		p.Submit(func() {
			wg.Done()
		})
	}
	wg.Wait()
}

func BenchmarkGoroutine_Direct(b *testing.B) {
	var wg sync.WaitGroup
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			wg.Done()
		}()
	}
	wg.Wait()
}

func BenchmarkPool_ParallelFor(b *testing.B) {
	p := New(8)
	defer p.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ParallelFor(100, func(idx int) {
			// Light work
			_ = idx * idx
		})
	}
}
