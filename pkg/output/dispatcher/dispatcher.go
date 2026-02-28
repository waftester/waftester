// Package dispatcher provides the central event routing for output.
// It receives events from the scanner and routes them to registered writers
// and hooks. Writers handle file output (JSON, SARIF, etc.), while hooks
// handle real-time integrations (webhooks, Slack, GitHub, etc.).
//
// The dispatcher is the central hub that all scanner output flows through,
// decoupling event generation from event consumption.
package dispatcher

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/waftester/waftester/pkg/output/events"
)

// Writer is the canonical interface for all event-based output writers.
// Writers are responsible for persisting events to various output formats
// such as JSON, SARIF, CSV, or console output.
// For legacy TestResult-based writing, see output.ResultWriter.
type Writer interface {
	// Write writes an event to the output.
	Write(event events.Event) error

	// Flush ensures all buffered events are written.
	Flush() error

	// Close closes the writer and releases any resources.
	Close() error

	// SupportsEvent returns true if the writer handles this event type.
	SupportsEvent(eventType events.EventType) bool
}

// Hook is the interface for event hooks.
// Hooks are used for real-time integrations such as webhooks,
// Slack notifications, or GitHub status updates.
type Hook interface {
	// OnEvent is called for each matching event.
	OnEvent(ctx context.Context, event events.Event) error

	// EventTypes returns the event types this hook handles.
	// Return nil or empty slice to receive all events.
	EventTypes() []events.EventType
}

// Dispatcher routes events to writers and hooks.
// It is safe for concurrent use.
type Dispatcher struct {
	writers []Writer
	hooks   []Hook
	mu      sync.RWMutex
	hookWg  sync.WaitGroup
	closed  atomic.Bool

	// Options
	batchSize int
	async     bool
	buffer    []events.Event
	bufferMu  sync.Mutex
}

// Config configures the dispatcher behavior.
type Config struct {
	// BatchSize sets how many events to buffer before flushing.
	// A value of 0 or less defaults to 100.
	BatchSize int

	// Async enables asynchronous hook processing.
	// When true, hooks are called in goroutines.
	Async bool
}

// New creates a new event dispatcher with the given configuration.
func New(cfg Config) *Dispatcher {
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	return &Dispatcher{
		writers:   make([]Writer, 0),
		hooks:     make([]Hook, 0),
		batchSize: batchSize,
		async:     cfg.Async,
		buffer:    make([]events.Event, 0, batchSize),
	}
}

// RegisterWriter adds a writer to the dispatcher.
// Writers will receive events that match their SupportsEvent filter.
func (d *Dispatcher) RegisterWriter(w Writer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writers = append(d.writers, w)
}

// RegisterHook adds a hook to the dispatcher.
// Hooks will receive events that match their EventTypes filter.
func (d *Dispatcher) RegisterHook(h Hook) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hooks = append(d.hooks, h)
}

// Dispatch sends an event to all registered writers and hooks.
// It returns nil even if individual writers or hooks fail, to ensure
// all consumers have a chance to receive the event.
// After Close() has been called, Dispatch returns nil without processing.
func (d *Dispatcher) Dispatch(ctx context.Context, event events.Event) error {
	// Fast path: reject dispatches after Close() has started.
	if d.closed.Load() {
		return nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// Double-check after acquiring lock to avoid race with Close().
	if d.closed.Load() {
		return nil
	}

	// Send to all writers that support this event type
	for _, w := range d.writers {
		if w.SupportsEvent(event.EventType()) {
			if err := w.Write(event); err != nil {
				slog.Warn("writer failed", slog.String("event", string(event.EventType())), slog.String("error", err.Error()))
				continue
			}
		}
	}

	// Send to all hooks that handle this event type
	for _, h := range d.hooks {
		if d.hookSupportsEvent(h, event.EventType()) {
			if d.async {
				d.hookWg.Add(1)
				go func(hook Hook) {
					defer d.hookWg.Done()
					if err := hook.OnEvent(ctx, event); err != nil {
						slog.Warn("async hook failed", slog.String("event", string(event.EventType())), slog.String("error", err.Error()))
					}
				}(h)
			} else {
				if err := h.OnEvent(ctx, event); err != nil {
					slog.Warn("hook failed", slog.String("event", string(event.EventType())), slog.String("error", err.Error()))
					continue
				}
			}
		}
	}

	return nil
}

// hookSupportsEvent checks if a hook handles the given event type.
func (d *Dispatcher) hookSupportsEvent(h Hook, eventType events.EventType) bool {
	types := h.EventTypes()
	// Empty slice means hook receives all events
	if len(types) == 0 {
		return true
	}
	for _, et := range types {
		if et == eventType {
			return true
		}
	}
	return false
}

// Flush flushes all registered writers.
func (d *Dispatcher) Flush() error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, w := range d.writers {
		_ = w.Flush()
	}

	return nil
}

// Close flushes and closes all writers, and waits for async hooks to complete.
// After Close is called, the dispatcher should not be used.
func (d *Dispatcher) Close() error {
	// Signal no more dispatches should start before waiting for hooks.
	d.closed.Store(true)

	// Acquire the write lock BEFORE waiting for hooks. This ensures
	// no Dispatch() is mid-execution (holding RLock) when we call
	// hookWg.Wait(), preventing a WaitGroup misuse panic from a
	// concurrent hookWg.Add(1) during or after Wait().
	d.mu.Lock()
	d.hookWg.Wait()

	for _, w := range d.writers {
		_ = w.Flush()
		_ = w.Close()
	}

	// Close hooks that hold resources (e.g., OTel tracer, Prometheus HTTP server).
	for _, h := range d.hooks {
		if closer, ok := h.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	d.mu.Unlock()

	return nil
}
