// Package writers provides output writers for various formats.
//
// This package contains implementations of the dispatcher.Writer interface
// for different output formats including JSONL (newline-delimited JSON),
// SARIF, and other formats suitable for CI/CD integration.
package writers

import (
	"io"
	"sync"

	"github.com/waftester/waftester/pkg/jsonutil"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*JSONLWriter)(nil)

// JSONLWriter writes events as newline-delimited JSON (JSONL).
// Each event is serialized as a complete JSON object on a single line,
// making it ideal for streaming processing and CI/CD pipelines.
//
// JSONL format allows each line to be parsed independently, enabling
// tools like jq, grep, and streaming parsers to process events in real-time.
type JSONLWriter struct {
	w       io.Writer
	mu      sync.Mutex
	opts    JSONLOptions
	encoder *jsonutil.Encoder
}

// JSONLOptions configures the JSONL writer behavior.
type JSONLOptions struct {
	// OmitRaw omits raw/verbose data from output to reduce size.
	OmitRaw bool

	// OmitEvidence omits all evidence fields from result events.
	OmitEvidence bool

	// OnlyBypasses filters output to only include bypass events.
	// When true, only events with EventTypeBypass or ResultEvents
	// with OutcomeBypass are written.
	OnlyBypasses bool

	// Pretty enables indented JSON output.
	// Note: This is not JSONL compliant but useful for debugging.
	Pretty bool
}

// NewJSONLWriter creates a new JSONL writer that writes to w.
// The writer is safe for concurrent use.
func NewJSONLWriter(w io.Writer, opts JSONLOptions) *JSONLWriter {
	encoder := jsonutil.NewStreamEncoder(w)
	if opts.Pretty {
		encoder.SetIndent("", "  ")
	}
	return &JSONLWriter{
		w:       w,
		opts:    opts,
		encoder: encoder,
	}
}

// Write writes an event as a single JSON line.
// Returns nil if the event was filtered out by options.
func (jw *JSONLWriter) Write(event events.Event) error {
	jw.mu.Lock()
	defer jw.mu.Unlock()

	// Filter: only bypasses if requested
	if jw.opts.OnlyBypasses {
		if event.EventType() != events.EventTypeBypass {
			// Check if it's a result event with bypass outcome
			if re, ok := event.(*events.ResultEvent); ok {
				if re.Result.Outcome != events.OutcomeBypass {
					return nil // Skip non-bypass results
				}
			} else {
				return nil // Skip non-bypass/non-result events
			}
		}
	}

	// Handle evidence filtering
	if jw.opts.OmitEvidence {
		if re, ok := event.(*events.ResultEvent); ok {
			// Create a copy with evidence removed
			filtered := *re
			filtered.Evidence = nil
			return jw.encoder.Encode(&filtered)
		}
	}

	return jw.encoder.Encode(event)
}

// Flush flushes any buffered data.
// JSONL writes immediately, so this is a no-op.
func (jw *JSONLWriter) Flush() error {
	// JSONL writes immediately via encoder, no buffering
	return nil
}

// Close closes the writer and releases any resources.
// If the underlying writer implements io.Closer, it will be closed.
func (jw *JSONLWriter) Close() error {
	if closer, ok := jw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SupportsEvent returns true for all event types.
// JSONL can serialize any event type.
func (jw *JSONLWriter) SupportsEvent(_ events.EventType) bool {
	return true // JSONL supports all event types
}
