// Regression tests for API abuse division by zero (from 85-fix adversarial review).
//
// Bug: TestRateLimiting computed avgTime = totalTime / time.Duration(requests)
//      without checking requests > 0, causing a divide-by-zero panic.
// Fix: Guard with `if requests > 0` before division.
package apiabuse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTestRateLimiting_ZeroRequestsNoPanic verifies that calling
// TestRateLimiting with 0 requests does NOT panic.
// Regression: totalTime / time.Duration(0) caused divide-by-zero.
func TestTestRateLimiting_ZeroRequestsNoPanic(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewScanner(DefaultConfig())

	require.NotPanics(t, func() {
		result, err := s.TestRateLimiting(context.Background(), srv.URL, 0)
		assert.NoError(t, err)
		assert.Equal(t, time.Duration(0), result.ResponseTime,
			"zero requests should produce zero response time")
	}, "TestRateLimiting with 0 requests must not panic")
}

// TestTestRateLimiting_OneRequest verifies the edge case of a single request.
func TestTestRateLimiting_OneRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewScanner(DefaultConfig())

	result, err := s.TestRateLimiting(context.Background(), srv.URL, 1)
	require.NoError(t, err)
	assert.True(t, result.ResponseTime > 0, "single request should have positive response time")
}

// TestTestRateLimiting_CancelledContext verifies graceful handling of context cancellation.
func TestTestRateLimiting_CancelledContext(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewScanner(DefaultConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := s.TestRateLimiting(ctx, srv.URL, 100)
	assert.ErrorIs(t, err, context.Canceled,
		"cancelled context should return context.Canceled")
}
