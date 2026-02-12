// Regression tests for rune-aware string truncation (from 85-fix adversarial review).
//
// Bug: Truncate() was byte-based, so it could split multi-byte UTF-8 runes,
//      producing invalid UTF-8 output.
// Fix: Use utf8.RuneCountInString and []rune conversion.
package strutil

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

// TestTruncate_MultiByteRunesNotSplit verifies that truncation at a rune
// boundary does NOT produce invalid UTF-8.
// Regression: byte-based slicing split multi-byte runes, producing garbage.
func TestTruncate_MultiByteRunesNotSplit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		maxLen int
	}{
		{"emoji", "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥", 5},
		{"CJK", "你好世界测试数据漏洞扫描", 6},
		{"mixed_ascii_emoji", "hello 🌍🌍🌍🌍", 8},
		{"cyrillic", "Привет мир тестирование", 10},
		{"arabic", "مرحبا بالعالم", 5},
		{"single_4byte_rune", "🏴", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Truncate(tt.input, tt.maxLen)

			assert.True(t, utf8.ValidString(result),
				"Truncate(%q, %d) produced invalid UTF-8: %q (bytes: %x)",
				tt.input, tt.maxLen, result, []byte(result))

			runeCount := utf8.RuneCountInString(result)
			assert.LessOrEqual(t, runeCount, tt.maxLen,
				"result has %d runes, exceeds maxLen %d", runeCount, tt.maxLen)
		})
	}
}

// TestTruncate_EllipsisCountedInMaxLen verifies the "..." suffix is included
// in the maxLen rune count.
func TestTruncate_EllipsisCountedInMaxLen(t *testing.T) {
	t.Parallel()

	// 10 emoji = 10 runes, truncate to 7 → 4 emoji + "..." = 7 runes
	input := "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥"
	result := Truncate(input, 7)

	runeCount := utf8.RuneCountInString(result)
	assert.Equal(t, 7, runeCount, "result must be exactly maxLen runes")
	assert.True(t, utf8.ValidString(result))
}

// TestTruncate_ByteLengthDiffersFromRuneLength verifies the function uses
// rune count, not byte count.
func TestTruncate_ByteLengthDiffersFromRuneLength(t *testing.T) {
	t.Parallel()

	// "🔥" is 4 bytes but 1 rune. A string of 5 fire emoji is 20 bytes, 5 runes.
	input := "🔥🔥🔥🔥🔥"
	assert.Equal(t, 20, len(input), "precondition: 20 bytes")
	assert.Equal(t, 5, utf8.RuneCountInString(input), "precondition: 5 runes")

	// maxLen=5 → no truncation needed (5 runes ≤ 5)
	result := Truncate(input, 5)
	assert.Equal(t, input, result, "no truncation needed when rune count == maxLen")

	// maxLen=4 → truncate to 1 emoji + "..." = 4 runes
	result = Truncate(input, 4)
	assert.Equal(t, "🔥...", result)
	assert.True(t, utf8.ValidString(result))
}
