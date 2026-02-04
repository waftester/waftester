package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// =============================================================================
// Mock Event Implementation
// =============================================================================

// mockEvent is a test event implementation.
type mockEvent struct {
	eventType events.EventType
	timestamp time.Time
	scanID    string
}

func (e mockEvent) EventType() events.EventType { return e.eventType }
func (e mockEvent) Timestamp() time.Time        { return e.timestamp }
func (e mockEvent) ScanID() string              { return e.scanID }

func newMockEvent(eventType events.EventType) mockEvent {
	return mockEvent{
		eventType: eventType,
		timestamp: time.Now(),
		scanID:    "test-scan-123",
	}
}

// =============================================================================
// Mock Writer Implementation
// =============================================================================

// mockWriter is a thread-safe mock writer for testing.
type mockWriter struct {
	mu             sync.Mutex
	writeCount     atomic.Int32
	flushCount     atomic.Int32
	closeCount     atomic.Int32
	supportedTypes []events.EventType
	writtenEvents  []events.Event
	shouldFail     bool
	failError      error
}

func newMockWriter(supportedTypes ...events.EventType) *mockWriter {
	return &mockWriter{
		supportedTypes: supportedTypes,
		writtenEvents:  make([]events.Event, 0),
	}
}

func (w *mockWriter) Write(event events.Event) error {
	w.writeCount.Add(1)
	if w.shouldFail {
		if w.failError != nil {
			return w.failError
		}
		return errors.New("mock write error")
	}
	w.mu.Lock()
	w.writtenEvents = append(w.writtenEvents, event)
	w.mu.Unlock()
	return nil
}

func (w *mockWriter) Flush() error {
	w.flushCount.Add(1)
	return nil
}

func (w *mockWriter) Close() error {
	w.closeCount.Add(1)
	return nil
}

func (w *mockWriter) SupportsEvent(eventType events.EventType) bool {
	// If no types specified, support all
	if len(w.supportedTypes) == 0 {
		return true
	}
	for _, t := range w.supportedTypes {
		if t == eventType {
			return true
		}
	}
	return false
}

func (w *mockWriter) getWriteCount() int32 {
	return w.writeCount.Load()
}

func (w *mockWriter) getFlushCount() int32 {
	return w.flushCount.Load()
}

func (w *mockWriter) getCloseCount() int32 {
	return w.closeCount.Load()
}

func (w *mockWriter) getWrittenEvents() []events.Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]events.Event, len(w.writtenEvents))
	copy(result, w.writtenEvents)
	return result
}

// =============================================================================
// Mock Hook Implementation
// =============================================================================

// mockHook is a thread-safe mock hook for testing.
type mockHook struct {
	mu          sync.Mutex
	eventCount  atomic.Int32
	eventTypes  []events.EventType
	shouldBlock bool
	blockTime   time.Duration
	shouldFail  bool
	events      []events.Event
}

func newMockHook(eventTypes ...events.EventType) *mockHook {
	return &mockHook{
		eventTypes: eventTypes,
		events:     make([]events.Event, 0),
	}
}

func (h *mockHook) OnEvent(ctx context.Context, event events.Event) error {
	h.eventCount.Add(1)
	if h.shouldBlock && h.blockTime > 0 {
		time.Sleep(h.blockTime)
	}
	if h.shouldFail {
		return errors.New("mock hook error")
	}
	h.mu.Lock()
	h.events = append(h.events, event)
	h.mu.Unlock()
	return nil
}

func (h *mockHook) EventTypes() []events.EventType {
	return h.eventTypes
}

func (h *mockHook) getEventCount() int32 {
	return h.eventCount.Load()
}

func (h *mockHook) getEvents() []events.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]events.Event, len(h.events))
	copy(result, h.events)
	return result
}

// =============================================================================
// Tests for New()
// =============================================================================

func TestNew_DefaultBatchSize(t *testing.T) {
	d := New(Config{})

	if d.batchSize != 100 {
		t.Errorf("expected default batchSize 100, got %d", d.batchSize)
	}
	if d.async != false {
		t.Errorf("expected async to be false by default, got %v", d.async)
	}
	if len(d.writers) != 0 {
		t.Errorf("expected empty writers slice, got %d writers", len(d.writers))
	}
	if len(d.hooks) != 0 {
		t.Errorf("expected empty hooks slice, got %d hooks", len(d.hooks))
	}
}

func TestNew_CustomBatchSize(t *testing.T) {
	d := New(Config{BatchSize: 50})

	if d.batchSize != 50 {
		t.Errorf("expected batchSize 50, got %d", d.batchSize)
	}
}

func TestNew_ZeroBatchSize_UsesDefault(t *testing.T) {
	d := New(Config{BatchSize: 0})

	if d.batchSize != 100 {
		t.Errorf("expected default batchSize 100 for zero value, got %d", d.batchSize)
	}
}

func TestNew_NegativeBatchSize_UsesDefault(t *testing.T) {
	d := New(Config{BatchSize: -10})

	if d.batchSize != 100 {
		t.Errorf("expected default batchSize 100 for negative value, got %d", d.batchSize)
	}
}

func TestNew_AsyncEnabled(t *testing.T) {
	d := New(Config{Async: true})

	if d.async != true {
		t.Errorf("expected async to be true, got %v", d.async)
	}
}

// =============================================================================
// Tests for RegisterWriter
// =============================================================================

func TestRegisterWriter(t *testing.T) {
	d := New(Config{})
	w := newMockWriter()

	d.RegisterWriter(w)

	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.writers) != 1 {
		t.Errorf("expected 1 writer, got %d", len(d.writers))
	}
}

func TestRegisterWriter_Multiple(t *testing.T) {
	d := New(Config{})
	w1 := newMockWriter()
	w2 := newMockWriter()
	w3 := newMockWriter()

	d.RegisterWriter(w1)
	d.RegisterWriter(w2)
	d.RegisterWriter(w3)

	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.writers) != 3 {
		t.Errorf("expected 3 writers, got %d", len(d.writers))
	}
}

// =============================================================================
// Tests for RegisterHook
// =============================================================================

func TestRegisterHook(t *testing.T) {
	d := New(Config{})
	h := newMockHook()

	d.RegisterHook(h)

	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.hooks) != 1 {
		t.Errorf("expected 1 hook, got %d", len(d.hooks))
	}
}

func TestRegisterHook_Multiple(t *testing.T) {
	d := New(Config{})
	h1 := newMockHook()
	h2 := newMockHook()

	d.RegisterHook(h1)
	d.RegisterHook(h2)

	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.hooks) != 2 {
		t.Errorf("expected 2 hooks, got %d", len(d.hooks))
	}
}

// =============================================================================
// Tests for Dispatch
// =============================================================================

func TestDispatch_SendsToAllSupportingWriters(t *testing.T) {
	d := New(Config{})
	w1 := newMockWriter(events.EventTypeResult)
	w2 := newMockWriter(events.EventTypeResult, events.EventTypeBypass)
	w3 := newMockWriter(events.EventTypeBypass) // Does not support Result

	d.RegisterWriter(w1)
	d.RegisterWriter(w2)
	d.RegisterWriter(w3)

	event := newMockEvent(events.EventTypeResult)
	err := d.Dispatch(context.Background(), event)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if w1.getWriteCount() != 1 {
		t.Errorf("w1 expected 1 write, got %d", w1.getWriteCount())
	}
	if w2.getWriteCount() != 1 {
		t.Errorf("w2 expected 1 write, got %d", w2.getWriteCount())
	}
	if w3.getWriteCount() != 0 {
		t.Errorf("w3 expected 0 writes (unsupported event), got %d", w3.getWriteCount())
	}
}

func TestDispatch_SendsToAllSupportingHooks(t *testing.T) {
	d := New(Config{Async: false})
	h1 := newMockHook(events.EventTypeResult)
	h2 := newMockHook() // Empty = all events
	h3 := newMockHook(events.EventTypeBypass)

	d.RegisterHook(h1)
	d.RegisterHook(h2)
	d.RegisterHook(h3)

	event := newMockEvent(events.EventTypeResult)
	err := d.Dispatch(context.Background(), event)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if h1.getEventCount() != 1 {
		t.Errorf("h1 expected 1 event, got %d", h1.getEventCount())
	}
	if h2.getEventCount() != 1 {
		t.Errorf("h2 expected 1 event (receives all), got %d", h2.getEventCount())
	}
	if h3.getEventCount() != 0 {
		t.Errorf("h3 expected 0 events (unsupported type), got %d", h3.getEventCount())
	}
}

func TestDispatch_WriterSupportsAllEvents(t *testing.T) {
	d := New(Config{})
	w := newMockWriter() // No types = supports all

	d.RegisterWriter(w)

	eventTypes := []events.EventType{
		events.EventTypeStart,
		events.EventTypeResult,
		events.EventTypeBypass,
		events.EventTypeComplete,
	}

	for _, et := range eventTypes {
		event := newMockEvent(et)
		_ = d.Dispatch(context.Background(), event)
	}

	if w.getWriteCount() != 4 {
		t.Errorf("expected 4 writes (all events), got %d", w.getWriteCount())
	}
}

// =============================================================================
// Test for Dispatch_ConcurrentSafe
// =============================================================================

func TestDispatch_ConcurrentSafe(t *testing.T) {
	d := New(Config{})
	w := newMockWriter()
	d.RegisterWriter(w)

	const numGoroutines = 10
	const eventsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := newMockEvent(events.EventTypeResult)
				if err := d.Dispatch(context.Background(), event); err != nil {
					t.Errorf("goroutine %d: dispatch error: %v", goroutineID, err)
				}
			}
		}(i)
	}

	wg.Wait()

	expectedWrites := int32(numGoroutines * eventsPerGoroutine)
	if w.getWriteCount() != expectedWrites {
		t.Errorf("expected %d writes, got %d", expectedWrites, w.getWriteCount())
	}
}

// =============================================================================
// Test for WriterFailure_OthersStillReceive
// =============================================================================

func TestWriterFailure_OthersStillReceive(t *testing.T) {
	d := New(Config{})

	w1 := newMockWriter()
	w2 := newMockWriter()
	w2.shouldFail = true
	w2.failError = fmt.Errorf("simulated failure in writer 2")
	w3 := newMockWriter()

	d.RegisterWriter(w1)
	d.RegisterWriter(w2)
	d.RegisterWriter(w3)

	event := newMockEvent(events.EventTypeResult)
	err := d.Dispatch(context.Background(), event)

	// Dispatch should not return error even if one writer fails
	if err != nil {
		t.Errorf("expected no error from Dispatch, got %v", err)
	}

	// w1 and w3 should still receive the event
	if w1.getWriteCount() != 1 {
		t.Errorf("w1 expected 1 write, got %d", w1.getWriteCount())
	}
	if w2.getWriteCount() != 1 {
		t.Errorf("w2 expected 1 write attempt, got %d", w2.getWriteCount())
	}
	if w3.getWriteCount() != 1 {
		t.Errorf("w3 expected 1 write, got %d", w3.getWriteCount())
	}

	// Verify w1 and w3 stored the event, w2 did not (because it failed)
	if len(w1.getWrittenEvents()) != 1 {
		t.Errorf("w1 expected 1 stored event, got %d", len(w1.getWrittenEvents()))
	}
	if len(w2.getWrittenEvents()) != 0 {
		t.Errorf("w2 expected 0 stored events (failed), got %d", len(w2.getWrittenEvents()))
	}
	if len(w3.getWrittenEvents()) != 1 {
		t.Errorf("w3 expected 1 stored event, got %d", len(w3.getWrittenEvents()))
	}
}

// =============================================================================
// Test for Close_FlushesAllWriters
// =============================================================================

func TestClose_FlushesAllWriters(t *testing.T) {
	d := New(Config{})
	w1 := newMockWriter()
	w2 := newMockWriter()
	w3 := newMockWriter()

	d.RegisterWriter(w1)
	d.RegisterWriter(w2)
	d.RegisterWriter(w3)

	err := d.Close()

	if err != nil {
		t.Errorf("expected no error from Close, got %v", err)
	}

	// All writers should be flushed and closed
	if w1.getFlushCount() != 1 {
		t.Errorf("w1 expected 1 flush, got %d", w1.getFlushCount())
	}
	if w1.getCloseCount() != 1 {
		t.Errorf("w1 expected 1 close, got %d", w1.getCloseCount())
	}

	if w2.getFlushCount() != 1 {
		t.Errorf("w2 expected 1 flush, got %d", w2.getFlushCount())
	}
	if w2.getCloseCount() != 1 {
		t.Errorf("w2 expected 1 close, got %d", w2.getCloseCount())
	}

	if w3.getFlushCount() != 1 {
		t.Errorf("w3 expected 1 flush, got %d", w3.getFlushCount())
	}
	if w3.getCloseCount() != 1 {
		t.Errorf("w3 expected 1 close, got %d", w3.getCloseCount())
	}
}

func TestFlush_FlushesAllWriters(t *testing.T) {
	d := New(Config{})
	w1 := newMockWriter()
	w2 := newMockWriter()

	d.RegisterWriter(w1)
	d.RegisterWriter(w2)

	err := d.Flush()

	if err != nil {
		t.Errorf("expected no error from Flush, got %v", err)
	}

	if w1.getFlushCount() != 1 {
		t.Errorf("w1 expected 1 flush, got %d", w1.getFlushCount())
	}
	if w2.getFlushCount() != 1 {
		t.Errorf("w2 expected 1 flush, got %d", w2.getFlushCount())
	}

	// Writers should NOT be closed after Flush
	if w1.getCloseCount() != 0 {
		t.Errorf("w1 expected 0 close after Flush, got %d", w1.getCloseCount())
	}
}

// =============================================================================
// Test for RegisterDuringDispatch_Race
// =============================================================================

func TestRegisterDuringDispatch_Race(t *testing.T) {
	d := New(Config{})

	// Pre-register one writer
	preWriter := newMockWriter()
	d.RegisterWriter(preWriter)

	const numDispatchGoroutines = 5
	const numRegisterGoroutines = 5
	const eventsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numDispatchGoroutines + numRegisterGoroutines)

	// Concurrent dispatches
	for i := 0; i < numDispatchGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := newMockEvent(events.EventTypeResult)
				_ = d.Dispatch(context.Background(), event)
			}
		}()
	}

	// Concurrent writer registrations
	var registeredWriters []*mockWriter
	var regMu sync.Mutex
	for i := 0; i < numRegisterGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				w := newMockWriter()
				regMu.Lock()
				registeredWriters = append(registeredWriters, w)
				regMu.Unlock()
				d.RegisterWriter(w)
			}
		}()
	}

	wg.Wait()

	// The pre-registered writer should have received all events from dispatch goroutines
	expectedPreWriterEvents := int32(numDispatchGoroutines * eventsPerGoroutine)
	if preWriter.getWriteCount() != expectedPreWriterEvents {
		t.Errorf("preWriter expected %d writes, got %d", expectedPreWriterEvents, preWriter.getWriteCount())
	}

	// Check that registration completed without panics
	d.mu.RLock()
	expectedWriters := 1 + (numRegisterGoroutines * eventsPerGoroutine)
	actualWriters := len(d.writers)
	d.mu.RUnlock()

	if actualWriters != expectedWriters {
		t.Errorf("expected %d registered writers, got %d", expectedWriters, actualWriters)
	}
}

// =============================================================================
// Test for AsyncHooks_NonBlocking vs SyncHooks_Blocking
// =============================================================================

func TestAsyncHooks_NonBlocking(t *testing.T) {
	d := New(Config{Async: true})

	h := newMockHook()
	h.shouldBlock = true
	h.blockTime = 100 * time.Millisecond

	d.RegisterHook(h)

	event := newMockEvent(events.EventTypeResult)

	start := time.Now()
	err := d.Dispatch(context.Background(), event)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Dispatch should return quickly because hooks are async
	if elapsed >= 50*time.Millisecond {
		t.Errorf("async dispatch took too long (%v), expected < 50ms", elapsed)
	}

	// Wait for the async hook to complete
	time.Sleep(150 * time.Millisecond)

	if h.getEventCount() != 1 {
		t.Errorf("hook expected 1 event after async processing, got %d", h.getEventCount())
	}
}

func TestSyncHooks_Blocking(t *testing.T) {
	d := New(Config{Async: false})

	h := newMockHook()
	h.shouldBlock = true
	h.blockTime = 50 * time.Millisecond

	d.RegisterHook(h)

	event := newMockEvent(events.EventTypeResult)

	start := time.Now()
	err := d.Dispatch(context.Background(), event)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Dispatch should block for at least the hook's block time
	if elapsed < 50*time.Millisecond {
		t.Errorf("sync dispatch returned too quickly (%v), expected >= 50ms", elapsed)
	}

	if h.getEventCount() != 1 {
		t.Errorf("hook expected 1 event, got %d", h.getEventCount())
	}
}

func TestAsyncHooks_MultipleHooks(t *testing.T) {
	d := New(Config{Async: true})

	const numHooks = 3
	hooks := make([]*mockHook, numHooks)
	for i := 0; i < numHooks; i++ {
		hooks[i] = newMockHook()
		hooks[i].shouldBlock = true
		hooks[i].blockTime = 50 * time.Millisecond
		d.RegisterHook(hooks[i])
	}

	event := newMockEvent(events.EventTypeResult)

	start := time.Now()
	_ = d.Dispatch(context.Background(), event)
	elapsed := time.Since(start)

	// Even with 3 hooks each blocking 50ms, async dispatch should return fast
	if elapsed >= 30*time.Millisecond {
		t.Errorf("async dispatch with multiple hooks took too long (%v)", elapsed)
	}

	// Wait for all hooks to complete
	time.Sleep(100 * time.Millisecond)

	for i, h := range hooks {
		if h.getEventCount() != 1 {
			t.Errorf("hook[%d] expected 1 event, got %d", i, h.getEventCount())
		}
	}
}

// =============================================================================
// Test for hookSupportsEvent
// =============================================================================

func TestHookSupportsEvent_EmptySlice(t *testing.T) {
	d := New(Config{})
	h := newMockHook() // Empty = all events

	// Test that empty slice means all events are supported
	eventTypes := []events.EventType{
		events.EventTypeStart,
		events.EventTypeResult,
		events.EventTypeBypass,
		events.EventTypeProgress,
		events.EventTypeError,
		events.EventTypeSummary,
		events.EventTypeComplete,
	}

	for _, et := range eventTypes {
		if !d.hookSupportsEvent(h, et) {
			t.Errorf("hook with empty EventTypes should support %s", et)
		}
	}
}

func TestHookSupportsEvent_SpecificTypes(t *testing.T) {
	d := New(Config{})
	h := newMockHook(events.EventTypeResult, events.EventTypeBypass)

	if !d.hookSupportsEvent(h, events.EventTypeResult) {
		t.Error("hook should support EventTypeResult")
	}
	if !d.hookSupportsEvent(h, events.EventTypeBypass) {
		t.Error("hook should support EventTypeBypass")
	}
	if d.hookSupportsEvent(h, events.EventTypeStart) {
		t.Error("hook should not support EventTypeStart")
	}
	if d.hookSupportsEvent(h, events.EventTypeComplete) {
		t.Error("hook should not support EventTypeComplete")
	}
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

func TestDispatch_NoWritersOrHooks(t *testing.T) {
	d := New(Config{})
	event := newMockEvent(events.EventTypeResult)

	err := d.Dispatch(context.Background(), event)

	if err != nil {
		t.Errorf("expected no error when dispatching with no writers/hooks, got %v", err)
	}
}

func TestClose_NoWriters(t *testing.T) {
	d := New(Config{})

	err := d.Close()

	if err != nil {
		t.Errorf("expected no error when closing with no writers, got %v", err)
	}
}

func TestFlush_NoWriters(t *testing.T) {
	d := New(Config{})

	err := d.Flush()

	if err != nil {
		t.Errorf("expected no error when flushing with no writers, got %v", err)
	}
}

func TestHookFailure_OthersStillReceive(t *testing.T) {
	d := New(Config{Async: false})

	h1 := newMockHook()
	h2 := newMockHook()
	h2.shouldFail = true
	h3 := newMockHook()

	d.RegisterHook(h1)
	d.RegisterHook(h2)
	d.RegisterHook(h3)

	event := newMockEvent(events.EventTypeResult)
	err := d.Dispatch(context.Background(), event)

	// Dispatch should not return error even if one hook fails
	if err != nil {
		t.Errorf("expected no error from Dispatch, got %v", err)
	}

	// All hooks should have been called
	if h1.getEventCount() != 1 {
		t.Errorf("h1 expected 1 event, got %d", h1.getEventCount())
	}
	if h2.getEventCount() != 1 {
		t.Errorf("h2 expected 1 event attempt, got %d", h2.getEventCount())
	}
	if h3.getEventCount() != 1 {
		t.Errorf("h3 expected 1 event, got %d", h3.getEventCount())
	}
}
