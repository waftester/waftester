package tampers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverBypasses_BaselineBlocked(t *testing.T) {
	// Mock WAF: blocks raw payload (case-sensitive "SELECT"), passes case-swapped
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("test")
		if payload == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("welcome to the site"))
			return
		}
		// Block if contains uppercase "SELECT" or lowercase "select"
		if strings.Contains(payload, "SELECT") || strings.Contains(payload, "select") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked by WAF"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome to the site"))
	}))
	defer srv.Close()

	result, err := DiscoverBypasses(context.Background(), BypassDiscoveryConfig{
		TargetURL:    srv.URL,
		Payloads:     []string{"SELECT 1 FROM users", "SELECT password FROM accounts"},
		Concurrency:  2,
		ConfirmCount: 1,
		Timeout:      5 * time.Second,
	})
	require.NoError(t, err)
	assert.True(t, result.BaselineBlocked, "raw payload should be blocked")
	assert.Greater(t, result.TotalTampers, 0, "should test at least one tamper")
}

func TestDiscoverBypasses_NothingBlocked(t *testing.T) {
	// No WAF — everything passes, nothing to bypass
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	result, err := DiscoverBypasses(context.Background(), BypassDiscoveryConfig{
		TargetURL: srv.URL,
		Payloads:  []string{"SELECT 1 FROM users"},
		Timeout:   5 * time.Second,
	})
	require.NoError(t, err)
	assert.False(t, result.BaselineBlocked, "payload should not be blocked")
	assert.Len(t, result.Results, 0, "no tampers should be tested")
	assert.Len(t, result.TopBypasses, 0)
}

func TestDiscoverBypasses_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("test")
		if payload == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("welcome"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := DiscoverBypasses(ctx, BypassDiscoveryConfig{
		TargetURL: srv.URL,
		Payloads:  []string{"SELECT 1"},
		Timeout:   5 * time.Second,
	})
	// Should either return error or partial result, not panic
	if err != nil {
		assert.Contains(t, err.Error(), "context canceled")
	} else {
		assert.NotNil(t, result)
	}
}

func TestDiscoverBypasses_WithMockTampers(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Clear and register controlled tampers
	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	// Tamper that uppercases — will still be blocked by case-sensitive WAF
	blockedTamper := newMockTamper("upper_all", CategorySQL, PriorityNormal)
	blockedTamper.transformFunc = func(p string) string { return strings.ToUpper(p) }
	Register(blockedTamper)

	// Tamper that replaces SQL keywords with non-ASCII lookalikes — bypasses
	bypassTamper := newMockTamper("keyword_replace", CategorySQL, PriorityNormal)
	bypassTamper.transformFunc = func(p string) string {
		return strings.ReplaceAll(p, "SELECT", "S3L3CT")
	}
	Register(bypassTamper)

	// Tamper that doesn't change anything — should be skipped
	noopTamper := newMockTamper("noop", CategorySQL, PriorityNormal)
	noopTamper.transformFunc = func(p string) string { return p }
	Register(noopTamper)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("test")
		if payload == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("welcome page content"))
			return
		}
		if strings.Contains(payload, "SELECT") || strings.Contains(payload, "select") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked by WAF"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome page content"))
	}))
	defer srv.Close()

	result, err := DiscoverBypasses(context.Background(), BypassDiscoveryConfig{
		TargetURL:    srv.URL,
		Payloads:     []string{"SELECT 1 FROM users"},
		Concurrency:  1,
		ConfirmCount: 0,
		Timeout:      5 * time.Second,
	})
	require.NoError(t, err)
	assert.True(t, result.BaselineBlocked)

	// keyword_replace should bypass
	foundBypass := false
	for _, b := range result.TopBypasses {
		if b.TamperName == "keyword_replace" {
			foundBypass = true
			assert.Greater(t, b.SuccessRate, 0.0)
			assert.Equal(t, "S3L3CT 1 FROM users", b.SampleOutput)
			break
		}
	}
	assert.True(t, foundBypass, "keyword_replace tamper should bypass the WAF")

	// upper_all should NOT bypass (SELECT stays uppercase)
	for _, b := range result.TopBypasses {
		assert.NotEqual(t, "upper_all", b.TamperName, "upper_all should not bypass")
	}
}

func TestDiscoverBypasses_Combinations(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	// Two tampers that individually bypass the WAF
	tamperA := newMockTamper("tamper_a", CategorySQL, PriorityNormal)
	tamperA.transformFunc = func(p string) string {
		return strings.ReplaceAll(p, "SELECT", "S3LECT")
	}
	Register(tamperA)

	tamperB := newMockTamper("tamper_b", CategorySpace, PriorityNormal)
	tamperB.transformFunc = func(p string) string {
		return strings.ReplaceAll(p, " ", "/**/")
	}
	Register(tamperB)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("test")
		if payload == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("welcome home page"))
			return
		}
		if strings.Contains(strings.ToLower(payload), "select") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked by WAF"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome home page"))
	}))
	defer srv.Close()

	result, err := DiscoverBypasses(context.Background(), BypassDiscoveryConfig{
		TargetURL:    srv.URL,
		Payloads:     []string{"SELECT 1 FROM users", "SELECT id FROM products"},
		Concurrency:  1,
		ConfirmCount: 1,
		TopN:         5,
		Timeout:      5 * time.Second,
	})
	require.NoError(t, err)
	assert.True(t, result.BaselineBlocked)

	// tamper_a bypasses (S3LECT doesn't contain "select" case-insensitive... wait, S3LECT
	// does actually NOT contain "select" — so it bypasses)
	assert.Greater(t, len(result.TopBypasses), 0, "at least one tamper should bypass")

	// Combinations should include tamper_a + tamper_b
	if len(result.Combinations) > 0 {
		found := false
		for _, c := range result.Combinations {
			if len(c.TamperNames) == 2 {
				found = true
				break
			}
		}
		assert.True(t, found, "should have at least one combination result")
	}
}

func TestDiscoverBypasses_OnProgress(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	tamper := newMockTamper("progress_test", CategorySQL, PriorityNormal)
	tamper.transformFunc = func(p string) string { return "harmless" }
	Register(tamper)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("test")
		if payload == "" || payload == "harmless" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok response body"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked"))
	}))
	defer srv.Close()

	var progressCalls []string
	var progressMu sync.Mutex

	result, err := DiscoverBypasses(context.Background(), BypassDiscoveryConfig{
		TargetURL:    srv.URL,
		Payloads:     []string{"SELECT 1"},
		Concurrency:  1,
		ConfirmCount: 0,
		Timeout:      5 * time.Second,
		OnProgress: func(name, res string) {
			progressMu.Lock()
			progressCalls = append(progressCalls, name+":"+res)
			progressMu.Unlock()
		},
	})
	require.NoError(t, err)
	assert.True(t, result.BaselineBlocked)
	assert.Contains(t, progressCalls, "progress_test:bypassed")
}

func TestResponseSignature_Resembles(t *testing.T) {
	tests := []struct {
		name   string
		a, b   responseSignature
		expect bool
	}{
		{
			"same status same size",
			responseSignature{200, 1000, "abc"},
			responseSignature{200, 1000, "abc"},
			true,
		},
		{
			"same status within tolerance same hash",
			responseSignature{200, 1000, "abc"},
			responseSignature{200, 900, "abc"},
			true,
		},
		{
			"same status within tolerance different hash",
			responseSignature{200, 1000, "abc"},
			responseSignature{200, 900, "def"},
			false,
		},
		{
			"different status family",
			responseSignature{200, 1000, "abc"},
			responseSignature{403, 1000, "abc"},
			false,
		},
		{
			"same status outside tolerance",
			responseSignature{200, 1000, "abc"},
			responseSignature{200, 500, "def"},
			false,
		},
		{
			"both zero size",
			responseSignature{200, 0, ""},
			responseSignature{200, 0, ""},
			true,
		},
		{
			"one zero size",
			responseSignature{200, 100, "abc"},
			responseSignature{200, 0, ""},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, tt.a.resembles(tt.b))
		})
	}
}

func TestCaptureSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test body"))
	}))
	defer srv.Close()

	sig, err := captureSignature(context.Background(), http.DefaultClient, srv.URL, "")
	require.NoError(t, err)
	assert.Equal(t, 200, sig.statusCode)
	assert.Equal(t, 9, sig.bodySize) // len("test body")
	assert.NotEmpty(t, sig.bodyHash)

	// With payload
	sig2, err := captureSignature(context.Background(), http.DefaultClient, srv.URL, "payload")
	require.NoError(t, err)
	assert.Equal(t, 200, sig2.statusCode)
}

func TestConfidenceStr(t *testing.T) {
	assert.Equal(t, "low", confidenceStr(1))
	assert.Equal(t, "medium", confidenceStr(2))
	assert.Equal(t, "high", confidenceStr(3))
	assert.Equal(t, "high", confidenceStr(10))
}
