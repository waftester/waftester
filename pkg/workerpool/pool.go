// Package workerpool provides a bounded goroutine pool for controlling
// concurrency and reducing goroutine creation overhead. Based on patterns
// from cloudwego/netpoll gopool and panjf2000/ants.
package workerpool

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// Pool manages a fixed pool of worker goroutines.
// It prevents goroutine explosion and reduces stack allocation overhead
// by reusing workers for multiple tasks.
type Pool struct {
	// Number of workers
	workers int32

	// Task channel
	tasks chan func()

	// Running worker count
	running int32

	// Closed flag
	closed int32

	// WaitGroup for graceful shutdown
	wg sync.WaitGroup
}

// DefaultPool is a shared pool sized to GOMAXPROCS.
var (
	defaultPool *Pool
	defaultOnce sync.Once
)

// Default returns the shared worker pool.
// The pool size is based on GOMAXPROCS * 4 for I/O-bound work.
func Default() *Pool {
	defaultOnce.Do(func() {
		// I/O bound work benefits from more goroutines than CPU cores
		workers := runtime.GOMAXPROCS(0) * 4
		if workers < 16 {
			workers = 16
		}
		if workers > 256 {
			workers = 256
		}
		defaultPool = New(workers)
	})
	return defaultPool
}

// New creates a new worker pool with the specified number of workers.
// Workers are started lazily when tasks are submitted.
func New(workers int) *Pool {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}

	p := &Pool{
		workers: int32(workers),
		tasks:   make(chan func(), workers*16), // Buffered for burst handling
	}

	return p
}

// Submit adds a task to the pool.
// The task will be executed by an available worker.
// If all workers are busy, the task waits in the queue.
// Returns false if the pool is closed.
func (p *Pool) Submit(task func()) bool {
	if atomic.LoadInt32(&p.closed) == 1 {
		return false
	}

	// Try to spawn a new worker if below limit
	for {
		running := atomic.LoadInt32(&p.running)
		if running >= p.workers {
			break
		}
		if atomic.CompareAndSwapInt32(&p.running, running, running+1) {
			p.wg.Add(1)
			go p.worker()
			break
		}
	}

	// Send task to queue
	select {
	case p.tasks <- task:
		return true
	default:
		// Queue is full, try to spawn emergency worker using atomic CAS
		// to prevent spawning more than workers*2
		for {
			running := atomic.LoadInt32(&p.running)
			if running >= p.workers*2 {
				break // Already at max capacity
			}
			if atomic.CompareAndSwapInt32(&p.running, running, running+1) {
				p.wg.Add(1)
				go p.worker()
				break
			}
		}
		p.tasks <- task // Block until space available
		return true
	}
}

// Go is an alias for Submit that matches common pool APIs.
func (p *Pool) Go(task func()) bool {
	return p.Submit(task)
}

// worker is the goroutine that processes tasks.
func (p *Pool) worker() {
	defer func() {
		// Recover from panics in tasks
		if r := recover(); r != nil {
			// Respawn worker to maintain pool capacity
			if atomic.LoadInt32(&p.closed) == 0 {
				// Keep running count and wg.Add since we're replacing ourselves
				go p.worker()
				return // Don't decrement running since replacement is spawned
			}
		}
		atomic.AddInt32(&p.running, -1)
		p.wg.Done()
	}()

	for task := range p.tasks {
		if task != nil {
			task()
		}
	}
}

// Running returns the current number of running workers.
func (p *Pool) Running() int {
	return int(atomic.LoadInt32(&p.running))
}

// Cap returns the worker capacity.
func (p *Pool) Cap() int {
	return int(atomic.LoadInt32(&p.workers))
}

// Waiting returns the number of tasks waiting in the queue.
func (p *Pool) Waiting() int {
	return len(p.tasks)
}

// Close shuts down the pool gracefully.
// All pending tasks are completed before returning.
func (p *Pool) Close() {
	if !atomic.CompareAndSwapInt32(&p.closed, 0, 1) {
		return // Already closed
	}
	close(p.tasks)
	p.wg.Wait()
}

// IsClosed returns true if the pool is closed.
func (p *Pool) IsClosed() bool {
	return atomic.LoadInt32(&p.closed) == 1
}

// Resize changes the pool capacity.
// If shrinking, excess workers will exit after completing their current task.
func (p *Pool) Resize(workers int) {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	atomic.StoreInt32(&p.workers, int32(workers))
}

// SubmitWait submits a task and waits for it to complete.
// Useful for synchronous operations that need pool-based execution.
func (p *Pool) SubmitWait(task func()) bool {
	done := make(chan struct{})
	ok := p.Submit(func() {
		defer close(done)
		task()
	})
	if ok {
		<-done
	}
	return ok
}

// ParallelFor executes fn for each index from 0 to n-1 in parallel.
// Blocks until all iterations complete.
func (p *Pool) ParallelFor(n int, fn func(i int)) {
	if n <= 0 {
		return
	}

	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		idx := i
		p.Submit(func() {
			defer wg.Done()
			fn(idx)
		})
	}

	wg.Wait()
}

// Map applies fn to each item in parallel and returns results in order.
// Returns partial results if the pool is closed during execution.
func Map[T, R any](p *Pool, items []T, fn func(T) R) []R {
	results := make([]R, len(items))
	var wg sync.WaitGroup
	wg.Add(len(items))

	for i, item := range items {
		idx := i
		val := item
		if !p.Submit(func() {
			defer wg.Done()
			results[idx] = fn(val)
		}) {
			// Submit failed (pool closed), compensate for wg.Add
			wg.Done()
		}
	}

	wg.Wait()
	return results
}

// Filter applies fn to each item in parallel and returns items where fn returns true.
// Returns partial results if the pool is closed during execution.
func Filter[T any](p *Pool, items []T, fn func(T) bool) []T {
	keep := make([]bool, len(items))
	var wg sync.WaitGroup
	wg.Add(len(items))

	for i, item := range items {
		idx := i
		val := item
		if !p.Submit(func() {
			defer wg.Done()
			keep[idx] = fn(val)
		}) {
			// Submit failed (pool closed), compensate for wg.Add
			wg.Done()
		}
	}

	wg.Wait()

	// Collect results
	results := make([]T, 0, len(items)/2)
	for i, item := range items {
		if keep[i] {
			results = append(results, item)
		}
	}
	return results
}
