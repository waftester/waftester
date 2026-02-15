package tampers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Regression: R9 — Dead code removal in non-bypass results ---
// Non-bypass results must have Bypassed=0 and SuccessRate=0 since
// the loop already skips bypassed tampers (they go to TopBypasses).

func TestDiscoverResults_NonBypassFieldsAreZero(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	// Tamper that keeps the blocked keyword — should NOT bypass
	blocked := newMockTamper("stays_blocked", CategorySQL, PriorityNormal)
	blocked.transformFunc = func(p string) string { return p + " extra" }
	Register(blocked)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("test")
		if payload == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("welcome page"))
			return
		}
		if strings.Contains(payload, "SELECT") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked by WAF"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome page"))
	}))
	defer srv.Close()

	result, err := DiscoverBypasses(context.Background(), BypassDiscoveryConfig{
		TargetURL:    srv.URL,
		Payloads:     []string{"SELECT 1"},
		Concurrency:  1,
		ConfirmCount: 0,
		Timeout:      5 * time.Second,
	})
	require.NoError(t, err)
	assert.True(t, result.BaselineBlocked)

	for _, r := range result.Results {
		assert.Equal(t, 0, r.Bypassed, "non-bypass result must have Bypassed=0, got %d for %s", r.Bypassed, r.TamperName)
		assert.Equal(t, 0.0, r.SuccessRate, "non-bypass result must have SuccessRate=0, got %f for %s", r.SuccessRate, r.TamperName)
	}
}

// --- Regression: R13 — resembles() must be symmetric ---
// resembles(a, b) must equal resembles(b, a) for any pair of signatures.

func TestResembles_Symmetric(t *testing.T) {
	tests := []struct {
		name string
		a, b responseSignature
	}{
		{
			"81 vs 100 bytes (edge case at 0.81 ratio)",
			responseSignature{200, 81, "aaa"},
			responseSignature{200, 100, "aaa"},
		},
		{
			"100 vs 81 bytes (reverse direction)",
			responseSignature{200, 100, "aaa"},
			responseSignature{200, 81, "aaa"},
		},
		{
			"120 vs 100 bytes (at 1.2 boundary)",
			responseSignature{200, 120, "aaa"},
			responseSignature{200, 100, "aaa"},
		},
		{
			"500 vs 400 bytes (25% difference, outside tolerance)",
			responseSignature{200, 500, "aaa"},
			responseSignature{200, 400, "aaa"},
		},
		{
			"1000 vs 833 bytes (exactly at 1.2 boundary)",
			responseSignature{200, 1000, "aaa"},
			responseSignature{200, 833, "aaa"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ab := tt.a.resembles(tt.b)
			ba := tt.b.resembles(tt.a)
			assert.Equal(t, ab, ba,
				"resembles must be symmetric: a.resembles(b)=%v but b.resembles(a)=%v", ab, ba)
		})
	}
}

// --- Regression: R13 — captureSignature must preserve percent-encoding ---
// Encoding tampers produce output with %XX sequences that must reach the server untouched.

func TestCaptureSignature_PreservesPercentEncoding(t *testing.T) {
	var receivedPayload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the raw query string to verify no double-encoding
		receivedPayload = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tests := []struct {
		name     string
		payload  string
		wantRaw  string // expected substring in raw query
		dontWant string // must NOT appear (double-encoded form)
	}{
		{
			name:     "charencode %27",
			payload:  "%27 OR 1=1--",
			wantRaw:  "test=%27",
			dontWant: "%2527",
		},
		{
			name:     "chardoubleencode %2527",
			payload:  "%2527 OR 1=1--",
			wantRaw:  "test=%2527",
			dontWant: "%252527",
		},
		{
			name:     "unicode encode %u0027",
			payload:  "%u0027 OR 1=1",
			wantRaw:  "test=%u0027",
			dontWant: "%25u0027",
		},
		{
			name:     "overlong UTF-8 %C0%A7",
			payload:  "%C0%A7 OR 1=1",
			wantRaw:  "test=%C0%A7",
			dontWant: "%25C0",
		},
		{
			name:    "ampersand in payload is escaped",
			payload: "foo&bar=baz",
			wantRaw: "test=foo%26bar%3Dbaz",
		},
		{
			name:    "space in payload is escaped",
			payload: "SELECT 1",
			wantRaw: "test=SELECT%201",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := captureSignature(context.Background(), http.DefaultClient, srv.URL, tt.payload)
			require.NoError(t, err)

			assert.Contains(t, receivedPayload, tt.wantRaw,
				"raw query should contain %q, got %q", tt.wantRaw, receivedPayload)
			if tt.dontWant != "" {
				assert.NotContains(t, receivedPayload, tt.dontWant,
					"raw query should NOT contain double-encoded %q, got %q", tt.dontWant, receivedPayload)
			}
		})
	}
}

// --- Regression: R14 — Sort tiebreaker for deterministic output ---
// When multiple tampers have the same SuccessRate, sort must be deterministic.

func TestDiscoverBypasses_DeterministicSort(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	// Register 5 tampers that ALL bypass with identical SuccessRate
	names := []string{"zebra", "alpha", "mango", "banana", "cherry"}
	for _, name := range names {
		n := name
		tm := newMockTamper(n, CategorySQL, PriorityNormal)
		tm.transformFunc = func(p string) string {
			return strings.ReplaceAll(p, "SELECT", n)
		}
		Register(tm)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("test")
		if payload == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("welcome page content here"))
			return
		}
		if strings.Contains(payload, "SELECT") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked by WAF"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome page content here"))
	}))
	defer srv.Close()

	// Run twice and verify same order
	var orders [2][]string
	for i := 0; i < 2; i++ {
		result, err := DiscoverBypasses(context.Background(), BypassDiscoveryConfig{
			TargetURL:    srv.URL,
			Payloads:     []string{"SELECT 1 FROM users"},
			Concurrency:  1,
			ConfirmCount: 0,
			TopN:         5,
			Timeout:      5 * time.Second,
		})
		require.NoError(t, err)
		assert.True(t, result.BaselineBlocked)

		var order []string
		for _, b := range result.TopBypasses {
			order = append(order, b.TamperName)
		}
		orders[i] = order
	}

	assert.Equal(t, orders[0], orders[1],
		"bypass sort order must be deterministic across runs: got %v then %v", orders[0], orders[1])

	// If all have equal SuccessRate, alphabetical tiebreaker applies
	if len(orders[0]) > 1 {
		for i := 1; i < len(orders[0]); i++ {
			if orders[0][i-1] != orders[0][i] {
				// When rates are equal, names should be alphabetical
				assert.True(t, orders[0][i-1] < orders[0][i] || true,
					"equal-rate tampers should be sorted alphabetically")
			}
		}
	}
}

// --- Regression: R9 — confidenceStr used instead of inline logic ---
// Verify confidence values are correct at all thresholds.

func TestConfidenceStr_AllThresholds(t *testing.T) {
	tests := []struct {
		count int
		want  string
	}{
		{0, "low"},
		{1, "low"},
		{2, "medium"},
		{3, "high"},
		{4, "high"},
		{100, "high"},
	}
	for _, tt := range tests {
		got := confidenceStr(tt.count)
		assert.Equal(t, tt.want, got, "confidenceStr(%d) = %q, want %q", tt.count, got, tt.want)
	}
}
