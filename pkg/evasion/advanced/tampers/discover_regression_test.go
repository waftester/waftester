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

// --- Non-bypass results must carry zero Bypassed/SuccessRate ---
// Blocked tampers go into Results (not TopBypasses) and must reflect
// Blocked=1, Bypassed=0, SuccessRate=0. If anyone adds dead computation
// that mutates these, this test catches it.

func TestDiscoverResults_BlockedTamperFields(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	// Tamper that keeps the blocked keyword — should NOT bypass
	blocked := newMockTamper("stays_blocked", CategorySQL, PriorityNormal)
	blocked.transformFunc = func(p string) string { return p + " extra" }
	Register(blocked)

	// Tamper that bypasses — removes the keyword entirely
	bypasser := newMockTamper("does_bypass", CategorySQL, PriorityNormal)
	bypasser.transformFunc = func(p string) string {
		return strings.ReplaceAll(p, "SELECT", "harmless")
	}
	Register(bypasser)

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

	// Bypassed tamper must be in TopBypasses, blocked must be in Results
	assert.NotEmpty(t, result.TopBypasses, "expected at least one bypass (does_bypass)")

	for _, r := range result.Results {
		assert.Equal(t, 0, r.Bypassed,
			"blocked tamper %q must have Bypassed=0", r.TamperName)
		assert.Equal(t, 0.0, r.SuccessRate,
			"blocked tamper %q must have SuccessRate=0", r.TamperName)
		assert.Equal(t, 1, r.Blocked+r.Errors,
			"blocked tamper %q must have Blocked+Errors=1", r.TamperName)
	}

	// TopBypasses must NOT contain the blocked tamper
	for _, b := range result.TopBypasses {
		assert.NotEqual(t, "stays_blocked", b.TamperName,
			"blocked tamper must not appear in TopBypasses")
	}
}

// --- Regression: R13 — resembles() must be symmetric ---
// resembles(a, b) must equal resembles(b, a) for any pair of signatures.

func TestResembles_Symmetric(t *testing.T) {
	tests := []struct {
		name   string
		a, b   responseSignature
		want   bool // expected result for both directions
	}{
		{
			"81 vs 100 bytes — ratio 1.235 exceeds 1.2 threshold",
			responseSignature{200, 81, "aaa"},
			responseSignature{200, 100, "aaa"},
			false, // 100/81 = 1.235 > 1.2
		},
		{
			"same hash same size — identical",
			responseSignature{200, 100, "aaa"},
			responseSignature{200, 100, "aaa"},
			true,
		},
		{
			"119 vs 100 bytes — ratio 1.19 within tolerance",
			responseSignature{200, 119, "aaa"},
			responseSignature{200, 100, "aaa"},
			true, // 119/100 = 1.19 < 1.2 and same hash
		},
		{
			"120 vs 100 bytes — ratio exactly 1.2 is boundary",
			responseSignature{200, 120, "aaa"},
			responseSignature{200, 100, "aaa"},
			false, // 120/100 = 1.2, >= 1.2 threshold
		},
		{
			"500 vs 400 bytes — 25% difference exceeds tolerance",
			responseSignature{200, 500, "aaa"},
			responseSignature{200, 400, "aaa"},
			false, // 500/400 = 1.25 > 1.2
		},
		{
			"different status class — never resembles",
			responseSignature{200, 100, "aaa"},
			responseSignature{403, 100, "aaa"},
			false, // 2xx != 4xx
		},
		{
			"zero vs non-zero — edge case",
			responseSignature{200, 0, ""},
			responseSignature{200, 100, "aaa"},
			false, // zero bodySize
		},
		{
			"both zero body — similar",
			responseSignature{200, 0, ""},
			responseSignature{200, 0, ""},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ab := tt.a.resembles(tt.b)
			ba := tt.b.resembles(tt.a)

			// Must be symmetric — the R13 fix normalizes ratio via 1/ratio
			assert.Equal(t, ab, ba,
				"resembles must be symmetric: a→b=%v but b→a=%v", ab, ba)

			// Must produce the expected boolean outcome
			assert.Equal(t, tt.want, ab,
				"resembles(%v, %v) = %v, want %v", tt.a, tt.b, ab, tt.want)
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
	require.NotEmpty(t, result.TopBypasses, "all 5 tampers should bypass")

	// All bypasses have identical SuccessRate, so the tiebreaker
	// must sort alphabetically by TamperName.
	var gotOrder []string
	for _, b := range result.TopBypasses {
		gotOrder = append(gotOrder, b.TamperName)
	}
	wantOrder := []string{"alpha", "banana", "cherry", "mango", "zebra"}
	assert.Equal(t, wantOrder, gotOrder,
		"equal-rate bypasses must be sorted alphabetically; got %v", gotOrder)
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
