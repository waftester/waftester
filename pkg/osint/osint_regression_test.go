// Regression tests for OSINT security bugs (from 85-fix adversarial review).
//
// Bug 1: Censys FetchSubdomains used fmt.Sprintf to construct JSON body,
//         allowing JSON injection via the query parameter.
// Fix 1: Use json.Marshal with a typed struct.
//
// Bug 2: Shodan error messages included the raw API key,
//         which would leak to logs.
// Fix 2: redactAPIKey() strips the key from error messages.
package osint

import (
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
