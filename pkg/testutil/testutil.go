// Package testutil provides shared test helpers for WAFtester.
// Fault injection, goroutine leak detection, and panic assertion utilities.
package testutil

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// ErrFault is the sentinel error returned by fault injection helpers.
var ErrFault = errors.New("injected fault")

// FailingWriter is an io.Writer that fails after N bytes written.
// If Limit is 0, every Write call fails immediately.
type FailingWriter struct {
	written int
	Limit   int
}

func (w *FailingWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.Limit {
		remaining := w.Limit - w.written
		if remaining > 0 {
			w.written += remaining
			return remaining, ErrFault
		}
		return 0, ErrFault
	}
	w.written += len(p)
	return len(p), nil
}

// FailingWriteCloser is an io.WriteCloser that succeeds on Write but fails on Close.
// Simulates disk-full or gzip flush errors.
type FailingWriteCloser struct {
	buf      []byte
	CloseErr error
}

func NewFailingWriteCloser() *FailingWriteCloser {
	return &FailingWriteCloser{CloseErr: ErrFault}
}

func (w *FailingWriteCloser) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *FailingWriteCloser) Close() error {
	return w.CloseErr
}

func (w *FailingWriteCloser) Bytes() []byte {
	return w.buf
}

// GoroutineTracker captures goroutine count before/after a test to detect leaks.
type GoroutineTracker struct {
	before int
}

// TrackGoroutines snapshots the current goroutine count. Call CheckLeaks after.
func TrackGoroutines() *GoroutineTracker {
	// Allow any pending goroutines to settle
	runtime.Gosched()
	return &GoroutineTracker{before: runtime.NumGoroutine()}
}

// CheckLeaks waits briefly for goroutines to drain, then fails the test if
// more goroutines are running than when tracking started.
// tolerance allows N extra goroutines (for runtime jitter).
func (g *GoroutineTracker) CheckLeaks(t *testing.T, tolerance int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.Gosched()
		after := runtime.NumGoroutine()
		if after <= g.before+tolerance {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	if after > g.before+tolerance {
		t.Errorf("goroutine leak: before=%d after=%d tolerance=%d", g.before, after, tolerance)
	}
}

// AssertNoPanic calls fn and fails the test if it panics.
func AssertNoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: unexpected panic: %v", name, r)
		}
	}()
	fn()
}

// AssertTimeout runs fn and fails if it doesn't complete within d.
func AssertTimeout(t *testing.T, name string, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		// ok
	case <-time.After(d):
		t.Fatalf("%s: timed out after %v (possible deadlock)", name, d)
	}
}

// RunConcurrently runs fn count times across goroutines and waits for all to finish.
// Useful for race condition testing.
func RunConcurrently(count int, fn func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(count)
	for i := 0; i < count; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // synchronize start
			fn(idx)
		}(i)
	}
	close(start)
	wg.Wait()
}

// NullWriter is an io.Writer that discards everything (like io.Discard but typed for clarity).
type NullWriter struct{}

func (NullWriter) Write(p []byte) (int, error) { return len(p), nil }

// CountingWriter counts bytes written.
type CountingWriter struct {
	N int64
}

func (w *CountingWriter) Write(p []byte) (int, error) {
	w.N += int64(len(p))
	return len(p), nil
}

// MustComplete wraps a function call and panics if it returns a non-nil error.
// Only for test setup where failure should be fatal.
func MustComplete(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// PoisonSyncMap stores a non-standard type in a sync.Map to simulate corruption.
// This is useful for testing sync.Map type assertion safety.
func PoisonSyncMap(m *sync.Map, key interface{}) {
	m.Store(key, fmt.Sprintf("poison-value-%v", key))
}
