// Regression tests for IDOR bugs (from 85-fix adversarial review).
//
// Bug 1: responseSimilar() always returned true for same-length responses,
//
//	regardless of actual content. This caused false positives.
//
// Fix 1: 80% byte-level similarity check in 256-byte prefix sample.
//
// Bug 2: extractIDs() used regexp.MustCompile on user-supplied patterns,
//
//	which panicked on invalid regex.
//
// Fix 2: Changed to regexp.Compile + continue on error.
package idor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResponseSimilar_DifferentContentSameLength verifies that two responses
// with identical length but different content are NOT considered similar.
// Regression: old code returned true unconditionally for same-length responses.
func TestResponseSimilar_DifferentContentSameLength(t *testing.T) {
	t.Parallel()

	a := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	b := []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	assert.False(t, responseSimilar(a, b),
		"completely different content with same length must return false")
}

// TestResponseSimilar_IdenticalContent returns true for exact matches.
func TestResponseSimilar_IdenticalContent(t *testing.T) {
	t.Parallel()

	data := []byte(`{"user_id": 42, "name": "Alice", "email": "alice@example.com"}`)
	assert.True(t, responseSimilar(data, data),
		"identical content must return true")
}

// TestResponseSimilar_HighSimilarity returns true when >80% bytes match.
func TestResponseSimilar_HighSimilarity(t *testing.T) {
	t.Parallel()

	a := []byte("AAAAAAAAAAAAAAAAAAAAB") // 20 chars, 19 A's + 1 B
	b := []byte("AAAAAAAAAAAAAAAAAAAAC") // 20 chars, 19 A's + 1 C
	// 19/20 = 95% similarity → should be true
	assert.True(t, responseSimilar(a, b),
		"95%% similar content should return true")
}

// TestResponseSimilar_LowSimilarity returns false for dissimilar content.
func TestResponseSimilar_LowSimilarity(t *testing.T) {
	t.Parallel()

	a := []byte("ABCDEFGHIJKLMNOPQRST") // 20 unique chars
	b := []byte("TSRQPONMLKJIHGFEDCBA") // reversed
	// Very few bytes match at same positions
	assert.False(t, responseSimilar(a, b),
		"reversed content must return false")
}

// TestResponseSimilar_EmptyResponses returns false for empty bodies.
func TestResponseSimilar_EmptyResponses(t *testing.T) {
	t.Parallel()

	assert.False(t, responseSimilar(nil, nil), "nil,nil must return false")
	assert.False(t, responseSimilar([]byte{}, []byte{1}), "empty+non-empty must return false")
	assert.False(t, responseSimilar([]byte{1}, nil), "non-empty+nil must return false")
}

// TestResponseSimilar_DifferentLengths returns false when lengths differ >20%.
func TestResponseSimilar_DifferentLengths(t *testing.T) {
	t.Parallel()

	a := make([]byte, 100)
	b := make([]byte, 130) // 30% larger
	// Fill both with same byte to maximize similarity
	for i := range a {
		a[i] = 'X'
	}
	for i := range b {
		b[i] = 'X'
	}
	assert.False(t, responseSimilar(a, b),
		">20%% length difference must return false regardless of content")
}

// TestExtractIDs_InvalidRegexDoesNotPanic verifies that user-supplied regex
// patterns that are invalid do NOT cause a panic.
// Regression: extractIDs used regexp.MustCompile which panicked on bad patterns.
func TestExtractIDs_InvalidRegexDoesNotPanic(t *testing.T) {
	t.Parallel()

	s := NewScanner(Config{
		IDPatterns: []string{
			`[invalid(`,        // unclosed bracket
			`(?P<broken`,       // unclosed group
			`/users/(\d+)`,     // valid pattern
			`***`,              // invalid quantifier
			`"id"\s*:\s*(\d+)`, // valid pattern
		},
	})

	require.NotPanics(t, func() {
		ids := s.extractIDs("https://example.com/users/42")
		// Should still find IDs from the valid patterns
		assert.Contains(t, ids, "42", "valid patterns must still work")
	}, "invalid regex patterns must not panic")
}

// TestExtractIDs_EmptyPatterns returns no panic and empty results.
func TestExtractIDs_EmptyPatterns(t *testing.T) {
	t.Parallel()

	s := NewScanner(Config{IDPatterns: []string{}})
	ids := s.extractIDs("https://example.com/no-ids")
	// No patterns → no regex matches, but numeric path segments may still be found
	assert.NotNil(t, ids) // should not panic
}
