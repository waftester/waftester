// Regression tests for output writer bugs (from 85-fix adversarial review).
//
// Bug 1: TaggedWriter.Write() mutated the shared *TestResult pointer directly,
//         causing data races when multiple writers received the same result.
// Fix 1: Shallow-copy the TestResult before modifying ID.
//
// Bug 2: MultiWriter.Write() only kept the last error, silently swallowing
//         earlier failures.
// Fix 2: Collect all errors and return errors.Join(errs...).
//
// Bug 3: ECSVWriter.Close() didn't flush the csv.Writer or propagate file close errors.
// Fix 3: Named return (retErr error), flush + check writer.Error() + defer file.Close().
package output

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failWriter is a mock ResultWriter that always returns an error.
type failWriter struct {
	err    error
	closed bool
}

func (f *failWriter) Write(_ *TestResult) error { return f.err }
func (f *failWriter) Close() error              { f.closed = true; return f.err }

// recordWriter records the IDs it received (thread-safe).
type recordWriter struct {
	mu  sync.Mutex
	ids []string
}

func (r *recordWriter) Write(result *TestResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, result.ID)
	return nil
}
func (r *recordWriter) Close() error { return nil }

// TestTaggedWriter_NoSharedMutation verifies that TaggedWriter does NOT mutate
// the original *TestResult pointer. Before the fix, concurrent TaggedWriters
// receiving the same result would corrupt each other's ID field.
func TestTaggedWriter_NoSharedMutation(t *testing.T) {
	t.Parallel()

	inner := &recordWriter{}
	tagged := NewTaggedWriter(inner, "source-A")

	original := &TestResult{ID: "original-id", Category: "sqli"}

	err := tagged.Write(original)
	require.NoError(t, err)

	// The ORIGINAL result must NOT have been modified
	assert.Equal(t, "original-id", original.ID,
		"TaggedWriter must not mutate the shared *TestResult pointer")

	// The inner writer should have received the tagged version
	inner.mu.Lock()
	defer inner.mu.Unlock()
	require.Len(t, inner.ids, 1)
	assert.Contains(t, inner.ids[0], "[source-A]")
}

// TestTaggedWriter_ConcurrentWritesSameResult verifies no data race when
// multiple TaggedWriters receive the same *TestResult concurrently.
func TestTaggedWriter_ConcurrentWritesSameResult(t *testing.T) {
	t.Parallel()

	const numWriters = 10
	const numWrites = 100

	writers := make([]*recordWriter, numWriters)
	taggedWriters := make([]*TaggedWriter, numWriters)
	for i := range numWriters {
		writers[i] = &recordWriter{}
		taggedWriters[i] = NewTaggedWriter(writers[i], strings.Repeat("x", i+1))
	}

	// Shared result pointer — pre-fix this would be mutated by all writers
	shared := &TestResult{ID: "shared-id", Category: "xss"}

	var wg sync.WaitGroup
	wg.Add(numWriters)
	for i := range numWriters {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < numWrites; j++ {
				_ = taggedWriters[idx].Write(shared)
			}
		}(i)
	}
	wg.Wait()

	// Original must be unmodified
	assert.Equal(t, "shared-id", shared.ID,
		"shared result corrupted by concurrent TaggedWriters")

	// Each writer should have received exactly numWrites results
	for i, w := range writers {
		w.mu.Lock()
		assert.Len(t, w.ids, numWrites, "writer %d should have %d results", i, numWrites)
		w.mu.Unlock()
	}
}

// TestMultiWriter_AggregatesAllErrors verifies that errors from ALL inner
// writers are reported, not just the last one.
// Regression: only lastErr was returned, swallowing earlier failures.
func TestMultiWriter_AggregatesAllErrors(t *testing.T) {
	t.Parallel()

	err1 := errors.New("writer-1 failed")
	err2 := errors.New("writer-2 failed")
	err3 := errors.New("writer-3 failed")

	multi := NewMultiWriter(
		&failWriter{err: err1},
		&mockWriter{results: make([]*TestResult, 0)}, // succeeds
		&failWriter{err: err2},
		&failWriter{err: err3},
	)

	result := &TestResult{ID: "test", Category: "sqli"}
	writeErr := multi.Write(result)

	require.Error(t, writeErr)
	assert.ErrorIs(t, writeErr, err1, "must include error from writer-1")
	assert.ErrorIs(t, writeErr, err2, "must include error from writer-2")
	assert.ErrorIs(t, writeErr, err3, "must include error from writer-3")
}

// TestMultiWriter_CloseAggregatesErrors verifies Close also joins all errors.
func TestMultiWriter_CloseAggregatesErrors(t *testing.T) {
	t.Parallel()

	err1 := errors.New("close-1 failed")
	err2 := errors.New("close-2 failed")

	multi := NewMultiWriter(
		&failWriter{err: err1},
		&failWriter{err: err2},
	)

	closeErr := multi.Close()
	require.Error(t, closeErr)
	assert.ErrorIs(t, closeErr, err1)
	assert.ErrorIs(t, closeErr, err2)
}

// TestMultiWriter_NoErrorWhenAllSucceed verifies nil is returned when all succeed.
func TestMultiWriter_NoErrorWhenAllSucceed(t *testing.T) {
	t.Parallel()

	multi := NewMultiWriter(
		&mockWriter{results: make([]*TestResult, 0)},
		&mockWriter{results: make([]*TestResult, 0)},
	)

	result := &TestResult{ID: "ok"}
	assert.NoError(t, multi.Write(result))
	assert.NoError(t, multi.Close())
}

// TestECSVWriter_CloseFlushesAndReportsErrors verifies that Close flushes
// buffered data and propagates errors properly via named return.
func TestECSVWriter_CloseFlushesAndReportsErrors(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	w, err := NewECSVWriter(tmpDir + "/test.csv")
	require.NoError(t, err)

	// Write a row, then close — flush must happen
	result := &TestResult{
		ID:       "flush-test",
		Category: "xss",
		Outcome:  "Pass",
	}
	require.NoError(t, w.Write(result))
	require.NoError(t, w.Close(), "Close must propagate any flush/close errors")
}
