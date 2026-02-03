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
	"sync"

	"github.com/waftester/waftester/pkg/output/events"
)

// Writer is the interface for all output writers.
// Writers are responsible for persisting events to various output formats
// such as JSON, SARIF, CSV, or console output.
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
func (d *Dispatcher) Dispatch(ctx context.Context, event events.Event) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Send to all writers that support this event type
	for _, w := range d.writers {
		if w.SupportsEvent(event.EventType()) {
			if err := w.Write(event); err != nil {
				// Log but don't fail - other writers should still receive
				continue
			}
		}
	}

	// Send to all hooks that handle this event type
	for _, h := range d.hooks {
		if d.hookSupportsEvent(h, event.EventType()) {
			if d.async {
				go func(hook Hook) {
					_ = hook.OnEvent(ctx, event)
				}(h)
			} else {
				if err := h.OnEvent(ctx, event); err != nil {
					// Log but don't fail
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

// Close flushes and closes all writers.
// After Close is called, the dispatcher should not be used.
func (d *Dispatcher) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, w := range d.writers {
		_ = w.Flush()
		_ = w.Close()
	}

	return nil
}
