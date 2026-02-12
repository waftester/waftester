// Regression tests for UTF-7 encoding bug (from 85-fix adversarial review).
//
// Bug: Double-quote (") was encoded as "+ACIi-" (incorrect; extra "i").
// Fix: Changed to "+ACI-" which is the correct UTF-7 modified base64.
package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUTF7_DoubleQuoteRoundtrip verifies that " encodes to +ACI- and
// decodes back to ".
// Regression: was encoded as +ACIi- (extra "i"), breaking round-trip.
func TestUTF7_DoubleQuoteRoundtrip(t *testing.T) {
	t.Parallel()

	enc := &UTF7Encoder{}

	encoded, err := enc.Encode(`"`)
	require.NoError(t, err)
	assert.Equal(t, "+ACI-", encoded,
		`double-quote must encode to +ACI- (not +ACIi-)`)

	decoded, err := enc.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, `"`, decoded,
		"decoded must be the original double-quote")
}

// TestUTF7_AllSpecialCharsRoundtrip verifies all encoded special characters
// survive a round-trip.
func TestUTF7_AllSpecialCharsRoundtrip(t *testing.T) {
	t.Parallel()

	enc := &UTF7Encoder{}

	tests := []struct {
		char    string
		encoded string
	}{
		{`<`, "+ADw-"},
		{`>`, "+AD4-"},
		{`"`, "+ACI-"},
		{`'`, "+ACc-"},
		{`&`, "+ACY-"},
		{`(`, "+ACg-"},
		{`)`, "+ACk-"},
	}

	for _, tt := range tests {
		t.Run("char_"+tt.char, func(t *testing.T) {
			encoded, err := enc.Encode(tt.char)
			require.NoError(t, err)
			assert.Equal(t, tt.encoded, encoded, "encoding mismatch for %q", tt.char)

			decoded, err := enc.Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, tt.char, decoded, "roundtrip failed for %q", tt.char)
		})
	}
}

// TestUTF7_XSSPayloadRoundtrip verifies a realistic XSS payload survives round-trip.
func TestUTF7_XSSPayloadRoundtrip(t *testing.T) {
	t.Parallel()

	enc := &UTF7Encoder{}

	payload := `<script>alert("xss")</script>`
	encoded, err := enc.Encode(payload)
	require.NoError(t, err)

	// Must not contain raw angle brackets or quotes
	assert.NotContains(t, encoded, "<")
	assert.NotContains(t, encoded, ">")
	assert.NotContains(t, encoded, `"`)

	decoded, err := enc.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, payload, decoded, "XSS payload must survive roundtrip")
}

// TestUTF7_PlainASCIIUnchanged verifies that plain ASCII text passes through unchanged.
func TestUTF7_PlainASCIIUnchanged(t *testing.T) {
	t.Parallel()

	enc := &UTF7Encoder{}

	input := "hello world 123"
	encoded, err := enc.Encode(input)
	require.NoError(t, err)
	assert.Equal(t, input, encoded, "plain ASCII must pass through unchanged")
}
