package hooks

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// =============================================================================
// logRecorder — captures slog.Record entries for assertions
// =============================================================================

type logRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *logRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	return nil
}

func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *logRecorder) WithGroup(string) slog.Handler       { return r }

func (r *logRecorder) getRecords() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	dst := make([]slog.Record, len(r.records))
	copy(dst, r.records)
	return dst
}

// =============================================================================
// orDefault tests
// =============================================================================

func TestOrDefault_NilReturnsDefault(t *testing.T) {
	result := orDefault(nil)
	if result != slog.Default() {
		t.Error("expected slog.Default() for nil input")
	}
}

func TestOrDefault_NonNilReturnsInput(t *testing.T) {
	custom := slog.New(slog.NewTextHandler(io.Discard, nil))
	result := orDefault(custom)
	if result != custom {
		t.Error("expected custom logger to be returned")
	}
}

// =============================================================================
// Webhook structured logging tests
// =============================================================================

func TestWebhook_CustomLogger_LogsOnFailure(t *testing.T) {
	rec := &logRecorder{}
	logger := slog.New(rec)

	// Server that always returns 400 (client error — not retried).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	hook := NewWebhookHook(srv.URL, WebhookOptions{
		Logger:     logger,
		RetryCount: 1,
		Timeout:    2 * time.Second,
	})

	event := newTestResultEvent(events.SeverityHigh, events.OutcomeBypass)
	_ = hook.OnEvent(context.Background(), event)

	records := rec.getRecords()
	if len(records) == 0 {
		t.Fatal("expected log output, got none")
	}

	// Expect "failed to send event after retries" warning.
	found := false
	for _, r := range records {
		if strings.Contains(r.Message, "failed to send event") {
			if r.Level != slog.LevelWarn {
				t.Errorf("expected Warn level, got %v", r.Level)
			}
			// Verify structured "error" attribute exists.
			hasError := false
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == "error" {
					hasError = true
					return false
				}
				return true
			})
			if !hasError {
				t.Error("expected slog.String(\"error\", ...) attribute")
			}
			found = true
			break
		}
	}
	if !found {
		var msgs []string
		for _, r := range records {
			msgs = append(msgs, r.Message)
		}
		t.Errorf("expected 'failed to send event' log message, got: %v", msgs)
	}
}

func TestWebhook_NilLogger_NoPanic(t *testing.T) {
	// Server that always returns 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Create webhook with nil Logger — should default to slog.Default().
	hook := NewWebhookHook(srv.URL, WebhookOptions{
		Logger:  nil,
		Timeout: 2 * time.Second,
	})

	event := newTestResultEvent(events.SeverityHigh, events.OutcomeBypass)
	err := hook.OnEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No panic means nil logger was safely defaulted.
}

func TestWebhook_CustomLogger_MarshalError(t *testing.T) {
	rec := &logRecorder{}
	logger := slog.New(rec)

	// Endpoint doesn't matter — marshal fails before sending.
	hook := NewWebhookHook("http://localhost:1", WebhookOptions{
		Logger:  logger,
		Timeout: 1 * time.Second,
	})

	// Send an unmarshalable event (channel in struct causes json.Marshal failure).
	badEvent := &unmarshalableEvent{}
	_ = hook.OnEvent(context.Background(), badEvent)

	records := rec.getRecords()
	found := false
	for _, r := range records {
		if strings.Contains(r.Message, "failed to marshal") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'failed to marshal event' log message for bad event")
	}
}

// unmarshalableEvent is an event that causes json.Marshal to fail.
type unmarshalableEvent struct{}

func (u *unmarshalableEvent) EventType() events.EventType { return events.EventTypeResult }
func (u *unmarshalableEvent) Timestamp() time.Time        { return time.Now() }
func (u *unmarshalableEvent) ScanID() string              { return "test" }
func (u *unmarshalableEvent) MarshalJSON() ([]byte, error) {
	return nil, errors.New("intentional marshal failure")
}
