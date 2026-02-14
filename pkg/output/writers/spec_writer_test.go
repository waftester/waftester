package writers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/output/events"
)

// mockWriter captures calls to verify delegation.
type mockWriter struct {
	written    []events.Event
	flushed    bool
	closed     bool
	supported  map[events.EventType]bool
	writeErr   error
}

func newMockWriter() *mockWriter {
	return &mockWriter{
		supported: map[events.EventType]bool{
			"scan_started": true,
			"scan_result":  true,
		},
	}
}

func (m *mockWriter) Write(event events.Event) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.written = append(m.written, event)
	return nil
}

func (m *mockWriter) Flush() error {
	m.flushed = true
	return nil
}

func (m *mockWriter) Close() error {
	m.closed = true
	return nil
}

func (m *mockWriter) SupportsEvent(eventType events.EventType) bool {
	return m.supported[eventType]
}

func TestNewSpecWriter(t *testing.T) {
	t.Parallel()
	inner := newMockWriter()
	sw := NewSpecWriter(inner, "openapi.yaml", "openapi3")

	assert.Equal(t, "openapi.yaml", sw.SpecSource)
	assert.Equal(t, "openapi3", sw.SpecFormat)
	assert.Equal(t, inner, sw.Inner)
}

func TestSpecWriterSupportsSpecEvents(t *testing.T) {
	t.Parallel()
	inner := newMockWriter()
	sw := NewSpecWriter(inner, "spec.json", "openapi3")

	// Spec event types should be supported.
	assert.True(t, sw.SupportsEvent(events.EventTypeSpecScanStarted))
	assert.True(t, sw.SupportsEvent(events.EventTypeEndpointScanStarted))
	assert.True(t, sw.SupportsEvent(events.EventTypeEndpointFinding))
	assert.True(t, sw.SupportsEvent(events.EventTypeEndpointScanCompleted))
	assert.True(t, sw.SupportsEvent(events.EventTypeSpecScanCompleted))
}

func TestSpecWriterDelegatesInnerSupports(t *testing.T) {
	t.Parallel()
	inner := newMockWriter()
	sw := NewSpecWriter(inner, "spec.json", "openapi3")

	// Inner writer supports "scan_started" and "scan_result".
	assert.True(t, sw.SupportsEvent("scan_started"))
	assert.True(t, sw.SupportsEvent("scan_result"))

	// But not arbitrary types.
	assert.False(t, sw.SupportsEvent("unknown_type"))
}

func TestSpecWriterDelegatesWrite(t *testing.T) {
	t.Parallel()
	inner := newMockWriter()
	sw := NewSpecWriter(inner, "spec.json", "openapi3")

	event := events.NewSpecScanStartedEvent("scan-1", "spec.json", "openapi3", 5, 100, []string{"sqli"}, "standard")
	err := sw.Write(event)
	require.NoError(t, err)

	assert.Len(t, inner.written, 1)
}

func TestSpecWriterDelegatesFlush(t *testing.T) {
	t.Parallel()
	inner := newMockWriter()
	sw := NewSpecWriter(inner, "spec.json", "openapi3")

	err := sw.Flush()
	require.NoError(t, err)
	assert.True(t, inner.flushed)
}

func TestSpecWriterDelegatesClose(t *testing.T) {
	t.Parallel()
	inner := newMockWriter()
	sw := NewSpecWriter(inner, "spec.json", "openapi3")

	err := sw.Close()
	require.NoError(t, err)
	assert.True(t, inner.closed)
}

func TestSpecWriterWriteError(t *testing.T) {
	t.Parallel()
	inner := newMockWriter()
	inner.writeErr = assert.AnError
	sw := NewSpecWriter(inner, "spec.json", "openapi3")

	event := events.NewSpecScanStartedEvent("scan-1", "spec.json", "openapi3", 5, 100, []string{"sqli"}, "standard")
	err := sw.Write(event)
	assert.Error(t, err)
}
