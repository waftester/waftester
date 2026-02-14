package writers

import (
	"github.com/waftester/waftester/pkg/output/events"
)

// SpecWriter enriches spec scanning events with endpoint context and
// delegates to the underlying format writer. It acts as a decorator
// that adds spec-level metadata to events before they reach format-specific writers.
type SpecWriter struct {
	// Inner is the underlying format writer (JSON, SARIF, table, etc.).
	Inner Writer

	// SpecSource is the spec file or URL being scanned.
	SpecSource string

	// SpecFormat is the spec format (openapi3, swagger2, etc.).
	SpecFormat string
}

// Writer interface matches the dispatcher.Writer contract.
// Redeclared here to avoid import cycle with dispatcher package.
type Writer interface {
	Write(event events.Event) error
	Flush() error
	Close() error
	SupportsEvent(eventType events.EventType) bool
}

// NewSpecWriter wraps an existing writer with spec context enrichment.
func NewSpecWriter(inner Writer, specSource, specFormat string) *SpecWriter {
	return &SpecWriter{
		Inner:      inner,
		SpecSource: specSource,
		SpecFormat: specFormat,
	}
}

// Write delegates to the inner writer. Spec events are passed through directly
// since they already contain endpoint context.
func (w *SpecWriter) Write(event events.Event) error {
	return w.Inner.Write(event)
}

// Flush delegates to the inner writer.
func (w *SpecWriter) Flush() error {
	return w.Inner.Flush()
}

// Close delegates to the inner writer.
func (w *SpecWriter) Close() error {
	return w.Inner.Close()
}

// SupportsEvent returns true for all spec event types plus any event types
// the inner writer supports.
func (w *SpecWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeSpecScanStarted,
		events.EventTypeEndpointScanStarted,
		events.EventTypeEndpointFinding,
		events.EventTypeEndpointScanCompleted,
		events.EventTypeSpecScanCompleted:
		return true
	}
	return w.Inner.SupportsEvent(eventType)
}
