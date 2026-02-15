package params

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/attackconfig"
)

// --- Regression: R10 — Per-method baseline ---
// POST requests must be compared against a POST baseline, not GET.
// Without this fix, almost ALL parameters were false-positively "discovered"
// when POST returned a different response than GET (e.g., 405 Method Not Allowed).

func TestWordlistDiscovery_PerMethodBaseline(t *testing.T) {
	getBody := "get response body here with enough content to hash"
	postBody := "post response body here which is intentionally different"

	// Server returns different responses for GET vs POST
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(getBody))
		case "POST":
			// Different from GET — if baseline is GET-only, every POST looks like a "hit"
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(postBody))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	// Write a tiny wordlist to a temp file
	dir := t.TempDir()
	wlFile := filepath.Join(dir, "wordlist.txt")
	require.NoError(t, os.WriteFile(wlFile, []byte("param1\nparam2\nparam3\n"), 0o644))

	d := NewDiscoverer(&Config{
		Base: attackconfig.Base{
			Concurrency: 1,
			Timeout:     5 * time.Second,
		},
		ChunkSize:    10,
		Positions:    []string{"query", "body"},
		Methods:      []string{"GET", "POST"},
		WordlistFile: wlFile,
	})

	getBaseline, err := d.getBaseline(context.Background(), srv.URL, "GET")
	require.NoError(t, err)

	params := d.wordlistDiscovery(context.Background(), srv.URL, []string{"GET", "POST"}, getBaseline)

	// With per-method baselines, POST params should NOT all be false positives.
	// The fix ensures each method gets compared against its own baseline.
	postParams := 0
	for _, p := range params {
		for _, m := range p.Methods {
			if m == "POST" {
				postParams++
			}
		}
	}

	// Without the fix, postParams would be == len(wordlist) because every POST
	// response differs from the GET baseline. With the fix, should be 0.
	assert.Equal(t, 0, postParams,
		"POST params should be 0 when POST responses are stable (per-method baseline)")
}

// --- Regression: R6 — Recursion depth limit ---
// An adversarial server that returns different responses every time should not
// cause stack overflow in binary search.

func TestTestParamChunk_RecursionDepthLimit(t *testing.T) {
	callCount := 0

	// Adversarial server: returns a different body every time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		// Different response each time triggers infinite binary search without the depth guard
		body := strings.Repeat("x", callCount*10)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d := NewDiscoverer(&Config{
		Base: attackconfig.Base{
			Concurrency: 1,
			Timeout:     10 * time.Second,
		},
		ChunkSize: 256,
	})

	h := md5.Sum([]byte("stable content"))
	baseline := &baselineResponse{
		StatusCode:    200,
		ContentLength: 100,
		ContentHash:   fmt.Sprintf("%x", h),
	}

	// This should NOT stack overflow — maxParamRecursionDepth=20 limits it
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	params := d.testParamChunk(ctx, srv.URL, "GET", []string{"a", "b", "c", "d"}, baseline)

	// The function should terminate without panic. The exact number of results
	// depends on implementation, but it must not crash.
	_ = params
	assert.Less(t, callCount, 1000,
		"recursion depth guard should prevent excessive requests (got %d)", callCount)
}

// --- Regression: R6 — maxParamRecursionDepth constant exists ---

func TestMaxParamRecursionDepth_IsPositive(t *testing.T) {
	assert.Greater(t, maxParamRecursionDepth, 0,
		"maxParamRecursionDepth must be positive")
	assert.LessOrEqual(t, maxParamRecursionDepth, 50,
		"maxParamRecursionDepth should be reasonable (<=50)")
}
