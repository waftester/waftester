// Regression tests for evasion matrix deadlock (from 85-fix adversarial review).
//
// Bug: TestsChan() held RLock during channel sends. If the receiver needed
// to acquire a write lock (e.g., to mutate the matrix), the goroutine would
// deadlock because the channel send blocked while holding the read lock.
// Fix: Copy the slice under RLock, release the lock, then send lock-free.
package evasionmatrix

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTestsChan_NoDeadlockWithConcurrentMutation verifies that receiving from
// TestsChan() while another goroutine calls a write-locked method doesn't deadlock.
// Regression: old code held RLock during ch<-test, so a concurrent Lock() blocked forever.
func TestTestsChan_NoDeadlockWithConcurrentMutation(t *testing.T) {
	t.Parallel()

	// Build a matrix with enough tests to make the channel send block
	m := New().Payloads("p1", "p2", "p3", "p4", "p5").
		Encoders("plain").
		Placeholders("url-param").
		Build()

	require.True(t, m.Count() > 0, "matrix must have tests")

	done := make(chan struct{})
	go func() {
		defer close(done)

		ch := m.TestsChan()

		// Read one test to create backpressure on the channel
		first := <-ch

		// While TestsChan goroutine may still be sending, force a write lock
		// This would deadlock if TestsChan held RLock during sends
		_ = m.Filter(func(t Test) bool { return t.ID != first.ID })

		// Drain remaining tests
		for range ch {
		}
	}()

	select {
	case <-done:
		// Success — no deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK: TestsChan + concurrent mutation blocked for 5s")
	}
}

// TestTestsChan_ConcurrentReadersNoDeadlock verifies multiple concurrent readers
// of TestsChan don't deadlock with each other or with write operations.
func TestTestsChan_ConcurrentReadersNoDeadlock(t *testing.T) {
	t.Parallel()

	m := New().Payloads("a", "b", "c").
		Encoders("plain").
		Placeholders("url-param").
		Build()

	const readers = 5
	var wg sync.WaitGroup
	wg.Add(readers + 1)

	// Spawn multiple readers
	for range readers {
		go func() {
			defer wg.Done()
			ch := m.TestsChan()
			for range ch {
			}
		}()
	}

	// Spawn one writer that calls Count() (takes RLock)
	go func() {
		defer wg.Done()
		for range 10 {
			_ = m.Count()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK: concurrent TestsChan readers blocked for 5s")
	}
}

// TestTestsChan_DeliversAllTests verifies the channel delivers every test exactly once.
func TestTestsChan_DeliversAllTests(t *testing.T) {
	t.Parallel()

	m := New().Payloads("x", "y", "z").
		Encoders("plain").
		Placeholders("url-param").
		Build()

	expected := m.Count()
	ch := m.TestsChan()

	received := 0
	for range ch {
		received++
	}
	assert.Equal(t, expected, received, "TestsChan must deliver all tests")
}
