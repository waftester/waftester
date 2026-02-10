package core

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestWithLogger_SetsCustomLogger(t *testing.T) {
	custom := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := NewExecutor(ExecutorConfig{
		TargetURL:   "http://localhost",
		Concurrency: 1,
		RateLimit:   10,
		Timeout:     1 * time.Second,
	}, WithLogger(custom))
	if e.logger != custom {
		t.Error("expected custom logger to be set via WithLogger option")
	}
}

func TestNewExecutor_DefaultLogger(t *testing.T) {
	e := NewExecutor(ExecutorConfig{
		TargetURL:   "http://localhost",
		Concurrency: 1,
		RateLimit:   10,
		Timeout:     1 * time.Second,
	})
	if e.logger == nil {
		t.Error("expected default logger to be non-nil")
	}
	if e.logger != slog.Default() {
		t.Error("expected default logger to be slog.Default()")
	}
}
