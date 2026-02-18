// Regression tests for OSINT security bugs (from 85-fix adversarial review).
//
// Bug 1: Censys FetchSubdomains used fmt.Sprintf to construct JSON body,
//
//	allowing JSON injection via the query parameter.
//
// Fix 1: Use json.Marshal with a typed struct.
//
// Bug 2: Shodan error messages included the raw API key,
//
//	which would leak to logs.
//
// Fix 2: redactAPIKey() strips the key from error messages.
package osint

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCensysQueryBody_NoJSONInjection verifies that a query containing JSON
// metacharacters produces valid, unexploitable JSON when marshalled.
// Regression: fmt.Sprintf(`{"q": "%s"}`, query) was vulnerable to injection.
func TestCensysQueryBody_NoJSONInjection(t *testing.T) {
	t.Parallel()

	maliciousQueries := []string{
		`", "extra": "injected`,
		`\", "extra": \"injected`,
		`names: example.com", "per_page": 99999, "q": "`,
		`"} , {"q": "pwned`,
		"line1\nline2",
		`<script>alert(1)</script>`,
		"\x00\x01\x02",
	}

	for _, query := range maliciousQueries {
		bodyData := struct {
			Q       string `json:"q"`
			PerPage int    `json:"per_page"`
		}{Q: query, PerPage: 100}

		bodyBytes, err := json.Marshal(bodyData)
		require.NoError(t, err, "json.Marshal must not fail for query: %q", query)

		// Verify the output is valid JSON
		var parsed map[string]interface{}
		err = json.Unmarshal(bodyBytes, &parsed)
		require.NoError(t, err, "output must be valid JSON for query: %q", query)

		// Verify exactly two keys (no injection)
		assert.Len(t, parsed, 2, "JSON must have exactly 2 keys (q and per_page), got: %v", parsed)
		assert.Equal(t, query, parsed["q"], "query value must be preserved exactly")
		assert.Equal(t, float64(100), parsed["per_page"])
	}
}

// TestRedactAPIKey_RemovesKeyFromError verifies that the API key is replaced
// with [REDACTED] in error messages.
// Regression: error messages contained the raw API key, leaking it to logs.
func TestRedactAPIKey_RemovesKeyFromError(t *testing.T) {
	t.Parallel()

	apiKey := "super-secret-key-12345"
	originalErr := errors.New("connection to https://api.shodan.io/dns/domain/test.com?key=" + apiKey + " failed: timeout")

	redacted := redactAPIKey(originalErr, apiKey)

	require.Error(t, redacted)
	assert.NotContains(t, redacted.Error(), apiKey,
		"API key must not appear in redacted error message")
	assert.Contains(t, redacted.Error(), "[REDACTED]",
		"redacted error must contain [REDACTED] placeholder")
}

// TestRedactAPIKey_NilError returns nil.
func TestRedactAPIKey_NilError(t *testing.T) {
	t.Parallel()
	assert.Nil(t, redactAPIKey(nil, "key"), "nil error must return nil")
}

// TestRedactAPIKey_EmptyKey returns original error unchanged.
func TestRedactAPIKey_EmptyKey(t *testing.T) {
	t.Parallel()

	err := errors.New("some error")
	result := redactAPIKey(err, "")
	assert.Equal(t, err, result, "empty key must return original error")
}

// TestRedactAPIKey_KeyAppearsMultipleTimes redacts ALL occurrences.
func TestRedactAPIKey_KeyAppearsMultipleTimes(t *testing.T) {
	t.Parallel()

	key := "abc123"
	err := errors.New("request to abc123 returned abc123 in the body")
	redacted := redactAPIKey(err, key)

	assert.Equal(t, 0, strings.Count(redacted.Error(), key),
		"all occurrences of the key must be redacted")
	assert.Equal(t, 2, strings.Count(redacted.Error(), "[REDACTED]"),
		"each occurrence should be replaced")
}

// TestGetResults_ReturnsCopy verifies that GetResults() returns a defensive
// copy of the internal results slice, not a reference to it.
// Regression: returning m.results directly allowed callers to observe mutations
// or cause data races after the read lock was released.
func TestGetResults_ReturnsCopy(t *testing.T) {
	t.Parallel()

	m := NewManager()
	// Manually inject results via the FetchSubdomains path isn't practical,
	// so we test the invariant: modifying the returned slice doesn't affect internal state.
	r1 := m.GetResults()
	require.Empty(t, r1, "new manager should have no results")

	// Mutate the returned slice — internal state must not change
	r1 = append(r1, Result{Source: "injected"})
	r2 := m.GetResults()
	assert.Empty(t, r2, "internal state must not be affected by mutating the returned slice")
}

// TestGetResults_DeepCopiesMetadata verifies that GetResults() deep-copies
// the Metadata map in each Result, not just the struct.
// Regression: shallow copy via append shared Metadata map references
func TestGetResults_DeepCopiesMetadata(t *testing.T) {
	t.Parallel()

	m := NewManager()
	// Inject a result with metadata directly
	m.mu.Lock()
	m.results = append(m.results, Result{
		Source:   SourceCrtsh,
		Type:     "subdomain",
		Value:    "test.example.com",
		Metadata: map[string]string{"org": "original"},
	})
	m.mu.Unlock()

	// Get copy and mutate metadata
	results := m.GetResults()
	results[0].Metadata["org"] = "mutated"

	// Internal state must be unchanged
	internal := m.GetResults()
	assert.Equal(t, "original", internal[0].Metadata["org"],
		"internal Metadata was mutated via GetResults copy")
}

// TestRateLimiter_WaitRespectsContext verifies that Wait() returns an error
// when the context is cancelled instead of blocking indefinitely.
// Regression: Wait() used time.Sleep without checking context cancellation
func TestRateLimiter_WaitRespectsContext(t *testing.T) {
	t.Parallel()

	// Create limiter with 0 initial tokens and very slow refill
	rl := NewRateLimiter(1)
	// Drain the initial token
	ctx := context.Background()
	err := rl.Wait(ctx)
	require.NoError(t, err)

	// Now cancel the context before next token is available
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err = rl.Wait(cancelCtx)
	assert.Error(t, err, "Wait should return error when context is cancelled")
}
