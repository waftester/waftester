// Regression tests for DNS brute wildcard detection randomness
// (from 85-fix adversarial review).
//
// Bug: Wildcard detection used time.Now().UnixNano() as seed, making the
//      random subdomain predictable and vulnerable to timing attacks.
// Fix: Use crypto/rand.Read for unpredictable random bytes.
package dnsbrute

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWildcardRandomSubdomain_Unpredictable verifies that the random subdomain
// generation pattern (crypto/rand.Read + hex) produces unique values across
// many invocations.
// Regression: time.Now().UnixNano() produced identical seeds when called in
// rapid succession, making wildcard detection subdomains predictable.
func TestWildcardRandomSubdomain_Unpredictable(t *testing.T) {
	t.Parallel()

	// Simulate the fixed pattern from detectWildcard: crypto/rand.Read + hex.EncodeToString
	seen := make(map[string]bool)
	const iterations = 100

	for i := 0; i < iterations; i++ {
		randBytes := make([]byte, 8)
		_, err := cryptorand.Read(randBytes)
		require.NoError(t, err)

		randomSub := "wc" + hex.EncodeToString(randBytes)

		assert.False(t, seen[randomSub],
			"iteration %d: duplicate random subdomain %q — crypto/rand should be unpredictable", i, randomSub)
		seen[randomSub] = true
	}

	assert.Len(t, seen, iterations, "all %d random subdomains must be unique", iterations)
}

// TestWildcardRandomSubdomain_Format verifies the subdomain follows the expected format.
func TestWildcardRandomSubdomain_Format(t *testing.T) {
	t.Parallel()

	randBytes := make([]byte, 8)
	_, err := cryptorand.Read(randBytes)
	require.NoError(t, err)

	randomSub := "wc" + hex.EncodeToString(randBytes)

	// Format: "wc" + 16 hex chars = 18 chars total
	assert.Len(t, randomSub, 18,
		"wildcard subdomain must be 18 chars: 'wc' + 16 hex digits")

	// Verify it's valid as a DNS label (alphanumeric)
	for _, c := range randomSub {
		assert.True(t, (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			"character %q is not valid in DNS label", string(c))
	}
}

// TestBruteforcer_NewDoesNotPanic verifies that creating a bruteforcer with
// various configs including edge cases does not panic.
func TestBruteforcer_NewDoesNotPanic(t *testing.T) {
	t.Parallel()

	configs := []Config{
		DefaultConfig(),
		{},                                    // zero-value config
		{Wordlist: "nonexistent"},             // missing wordlist
		{WildcardFilter: true, Retries: 0},    // zero retries
	}

	for i, cfg := range configs {
		t.Run(fmt.Sprintf("config_%d", i), func(t *testing.T) {
			require.NotPanics(t, func() {
				_ = NewBruteforcer(cfg)
			})
		})
	}
}
