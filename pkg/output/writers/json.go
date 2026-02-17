// Package writers provides output writers for various formats.
package writers

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/jsonutil"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*JSONWriter)(nil)

// JSONWriter writes events as a JSON array.
// Unlike JSONLWriter which streams events one per line, this writer
// buffers all events in memory and writes them as a single JSON array
// when Close is called. This is suitable for batch/file output.
type JSONWriter struct {
	w      io.Writer
	mu     sync.Mutex
	opts   JSONOptions
	buffer []events.Event
}

// JSONOptions configures the JSON writer behavior.
type JSONOptions struct {
	// OmitRaw omits raw/verbose data from output to reduce size.
	OmitRaw bool

	// OmitEvidence omits all evidence fields from result events.
	OmitEvidence bool

	// Pretty enables indented JSON output.
	Pretty bool

	// IndentSize sets the number of spaces for indentation (default 2).
	IndentSize int
}

// NewJSONWriter creates a new JSON array writer that writes to w.
// The writer buffers all events and writes them as a JSON array on Close.
// The writer is safe for concurrent use.
func NewJSONWriter(w io.Writer, opts JSONOptions) *JSONWriter {
	if opts.IndentSize == 0 {
		opts.IndentSize = 2
	}
	return &JSONWriter{
		w:      w,
		opts:   opts,
		buffer: make([]events.Event, 0),
	}
}

// Write buffers an event for later JSON array output.
// The event is stored in memory until Close is called.
func (jw *JSONWriter) Write(event events.Event) error {
	jw.mu.Lock()
	defer jw.mu.Unlock()
	jw.buffer = append(jw.buffer, event)
	return nil
}

// Flush is a no-op for JSON writer.
// All events are written as a single array on Close.
func (jw *JSONWriter) Flush() error {
	return nil
}

// Close writes all buffered events as a JSON array and closes the writer.
// If the underlying writer implements io.Closer, it will be closed.
func (jw *JSONWriter) Close() error {
	jw.mu.Lock()
	defer jw.mu.Unlock()

	encoder := jsonutil.NewStreamEncoder(jw.w)
	if jw.opts.Pretty {
		indent := strings.Repeat(" ", jw.opts.IndentSize)
		encoder.SetIndent("", indent)
	}

	if err := encoder.Encode(jw.buffer); err != nil {
		return fmt.Errorf("json: encode: %w", err)
	}

	if closer, ok := jw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SupportsEvent returns true for result, bypass, and summary events.
// These are the primary event types for batch JSON output.
func (jw *JSONWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeBypass, events.EventTypeSummary:
		return true
	default:
		return false
	}
}
