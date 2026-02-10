package assessment

import (
	"io"
	"log/slog"
	"testing"
)

func TestWithLogger_SetsCustomLogger(t *testing.T) {
	custom := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := New(nil, WithLogger(custom))
	if a.logger != custom {
		t.Error("expected custom logger to be set via WithLogger option")
	}
}

func TestNew_DefaultLogger(t *testing.T) {
	a := New(nil)
	if a.logger == nil {
		t.Error("expected default logger to be non-nil")
	}
	// Should be slog.Default()
	if a.logger != slog.Default() {
		t.Error("expected default logger to be slog.Default()")
	}
}

func TestNew_WithNilLogger(t *testing.T) {
	// Passing WithLogger(nil) — should still work; constructor sets slog.Default()
	// first, then option overrides to nil. If nil is problematic,
	// the code should handle it. Currently it would set nil.
	// This test documents the behavior.
	a := New(nil, WithLogger(nil))
	if a.logger != nil {
		t.Error("expected WithLogger(nil) to set nil logger")
	}
}
