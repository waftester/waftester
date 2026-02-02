package hexutil

import (
	"fmt"
	"strings"
	"testing"
)

// Test data for benchmarks
var testPayload = "SELECT * FROM users WHERE id='1' OR '1'='1'--"

func TestLookupTablesCorrectness(t *testing.T) {
	// Test URL encoding matches expected format
	for i := 0; i < 256; i++ {
		expected := fmt.Sprintf("%%%02X", i)
		if URLEncoded[i] != expected {
			t.Errorf("URLEncoded[%d] = %q, expected %q", i, URLEncoded[i], expected)
		}
	}

	// Test lowercase URL encoding
	for i := 0; i < 256; i++ {
		expected := fmt.Sprintf("%%%02x", i)
		if URLEncodedLower[i] != expected {
			t.Errorf("URLEncodedLower[%d] = %q, expected %q", i, URLEncodedLower[i], expected)
		}
	}

	// Test hex escape
	for i := 0; i < 256; i++ {
		expected := fmt.Sprintf("\\x%02x", i)
		if HexEscape[i] != expected {
			t.Errorf("HexEscape[%d] = %q, expected %q", i, HexEscape[i], expected)
		}
	}

	// Test octal escape
	for i := 0; i < 256; i++ {
		expected := fmt.Sprintf("\\%03o", i)
		if OctalEscape[i] != expected {
			t.Errorf("OctalEscape[%d] = %q, expected %q", i, OctalEscape[i], expected)
		}
	}

	// Test binary escape
	for i := 0; i < 256; i++ {
		expected := fmt.Sprintf("%08b", i)
		if BinaryEscape[i] != expected {
			t.Errorf("BinaryEscape[%d] = %q, expected %q", i, BinaryEscape[i], expected)
		}
	}
}

func TestDecEntityCorrectness(t *testing.T) {
	for i := 32; i < 128; i++ {
		expected := fmt.Sprintf("&#%d;", i)
		if DecEntity[i] != expected {
			t.Errorf("DecEntity[%d] = %q, expected %q", i, DecEntity[i], expected)
		}
	}
}

func TestHexEntityCorrectness(t *testing.T) {
	for i := 32; i < 128; i++ {
		expected := fmt.Sprintf("&#x%02x;", i)
		if HexEntity[i] != expected {
			t.Errorf("HexEntity[%d] = %q, expected %q", i, HexEntity[i], expected)
		}
	}
}

// Benchmark: Lookup table vs fmt.Sprintf for hex escape
func BenchmarkHexEscape_LookupTable(b *testing.B) {
	var sb strings.Builder
	payload := []byte(testPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		sb.Grow(len(payload) * 4)
		for _, c := range payload {
			WriteHexEscape(&sb, c)
		}
		_ = sb.String()
	}
}

func BenchmarkHexEscape_FmtSprintf(b *testing.B) {
	var sb strings.Builder
	payload := []byte(testPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		for _, c := range payload {
			sb.WriteString(fmt.Sprintf("\\x%02x", c))
		}
		_ = sb.String()
	}
}

// Benchmark: Lookup table vs fmt.Sprintf for URL encoding
func BenchmarkURLEncode_LookupTable(b *testing.B) {
	var sb strings.Builder
	payload := []byte(testPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		sb.Grow(len(payload) * 3)
		for _, c := range payload {
			WriteURLEncoded(&sb, c)
		}
		_ = sb.String()
	}
}

func BenchmarkURLEncode_FmtSprintf(b *testing.B) {
	var sb strings.Builder
	payload := []byte(testPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		for _, c := range payload {
			sb.WriteString(fmt.Sprintf("%%%02X", c))
		}
		_ = sb.String()
	}
}

// Benchmark: Lookup table vs fmt.Sprintf for binary encoding
func BenchmarkBinaryEncode_LookupTable(b *testing.B) {
	var sb strings.Builder
	payload := []byte(testPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		sb.Grow(len(payload) * 8)
		for _, c := range payload {
			WriteBinaryEscape(&sb, c)
		}
		_ = sb.String()
	}
}

func BenchmarkBinaryEncode_FmtSprintf(b *testing.B) {
	var sb strings.Builder
	payload := []byte(testPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		for _, c := range payload {
			sb.WriteString(fmt.Sprintf("%08b", c))
		}
		_ = sb.String()
	}
}

// Benchmark: Unicode escape
func BenchmarkUnicodeEscape_LookupTable(b *testing.B) {
	var sb strings.Builder
	payload := testPayload
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		sb.Grow(len(payload) * 6)
		for _, r := range payload {
			WriteUnicodeEscape(&sb, r)
		}
		_ = sb.String()
	}
}

func BenchmarkUnicodeEscape_FmtSprintf(b *testing.B) {
	var sb strings.Builder
	payload := testPayload
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		for _, r := range payload {
			sb.WriteString(fmt.Sprintf("\\u%04x", r))
		}
		_ = sb.String()
	}
}

// =============================================================================
// UNIT TESTS FOR HELPER FUNCTIONS
// =============================================================================

func TestWriteHexEscape(t *testing.T) {
	var sb strings.Builder
	WriteHexEscape(&sb, 'A')
	if sb.String() != "\\x41" {
		t.Errorf("WriteHexEscape('A') = %q, expected \\x41", sb.String())
	}

	sb.Reset()
	WriteHexEscape(&sb, 0xFF)
	if sb.String() != "\\xff" {
		t.Errorf("WriteHexEscape(0xFF) = %q, expected \\xff", sb.String())
	}
}

func TestWriteHexEscapeUpper(t *testing.T) {
	var sb strings.Builder
	WriteHexEscapeUpper(&sb, 'A')
	if sb.String() != "\\x41" {
		t.Errorf("WriteHexEscapeUpper('A') = %q, expected \\x41", sb.String())
	}

	sb.Reset()
	WriteHexEscapeUpper(&sb, 0xFF)
	if sb.String() != "\\xFF" {
		t.Errorf("WriteHexEscapeUpper(0xFF) = %q, expected \\xFF", sb.String())
	}
}

func TestWriteOctalEscape(t *testing.T) {
	var sb strings.Builder
	WriteOctalEscape(&sb, 'A') // 65 = 101 octal
	if sb.String() != "\\101" {
		t.Errorf("WriteOctalEscape('A') = %q, expected \\101", sb.String())
	}

	sb.Reset()
	WriteOctalEscape(&sb, 0) // 0 = 000 octal
	if sb.String() != "\\000" {
		t.Errorf("WriteOctalEscape(0) = %q, expected \\000", sb.String())
	}
}

func TestWriteBinaryEscape(t *testing.T) {
	var sb strings.Builder
	WriteBinaryEscape(&sb, 'A') // 65 = 01000001
	if sb.String() != "01000001" {
		t.Errorf("WriteBinaryEscape('A') = %q, expected 01000001", sb.String())
	}
}

func TestWriteURLEncoded(t *testing.T) {
	var sb strings.Builder
	WriteURLEncoded(&sb, '<')
	if sb.String() != "%3C" {
		t.Errorf("WriteURLEncoded('<') = %q, expected %%3C", sb.String())
	}
}

func TestWriteURLEncodedLower(t *testing.T) {
	var sb strings.Builder
	WriteURLEncodedLower(&sb, '<')
	if sb.String() != "%3c" {
		t.Errorf("WriteURLEncodedLower('<') = %q, expected %%3c", sb.String())
	}
}

func TestWriteDoubleURLEncoded(t *testing.T) {
	var sb strings.Builder
	WriteDoubleURLEncoded(&sb, 'A')
	if sb.String() != "%2541" {
		t.Errorf("WriteDoubleURLEncoded('A') = %q, expected %%2541", sb.String())
	}
}

func TestWriteDecEntity(t *testing.T) {
	var sb strings.Builder
	WriteDecEntity(&sb, 'A') // 65
	if sb.String() != "&#65;" {
		t.Errorf("WriteDecEntity('A') = %q, expected &#65;", sb.String())
	}

	sb.Reset()
	WriteDecEntity(&sb, 0)
	if sb.String() != "&#0;" {
		t.Errorf("WriteDecEntity(0) = %q, expected &#0;", sb.String())
	}

	// Test multi-digit
	sb.Reset()
	WriteDecEntity(&sb, 127)
	if sb.String() != "&#127;" {
		t.Errorf("WriteDecEntity(127) = %q, expected &#127;", sb.String())
	}
}

func TestWriteHexEntity(t *testing.T) {
	var sb strings.Builder
	WriteHexEntity(&sb, 'A')
	if sb.String() != "&#x41;" {
		t.Errorf("WriteHexEntity('A') = %q, expected &#x41;", sb.String())
	}

	// Multi-byte rune
	sb.Reset()
	WriteHexEntity(&sb, 0x1234)
	if sb.String() != "&#x1234;" {
		t.Errorf("WriteHexEntity(0x1234) = %q, expected &#x1234;", sb.String())
	}
}

func TestWriteUnicodeEscape(t *testing.T) {
	var sb strings.Builder
	WriteUnicodeEscape(&sb, 'A')
	if sb.String() != "\\u0041" {
		t.Errorf("WriteUnicodeEscape('A') = %q, expected \\u0041", sb.String())
	}

	// Multi-byte rune
	sb.Reset()
	WriteUnicodeEscape(&sb, 0x1234)
	if sb.String() != "\\u1234" {
		t.Errorf("WriteUnicodeEscape(0x1234) = %q, expected \\u1234", sb.String())
	}
}

func TestWriteUnicodeEscapeUpper(t *testing.T) {
	var sb strings.Builder
	WriteUnicodeEscapeUpper(&sb, 0xABCD)
	if sb.String() != "\\uABCD" {
		t.Errorf("WriteUnicodeEscapeUpper(0xABCD) = %q, expected \\uABCD", sb.String())
	}
}

func TestWriteOverlong2Byte(t *testing.T) {
	var sb strings.Builder
	WriteOverlong2Byte(&sb, 'A') // 0x41
	// 2-byte overlong: C1 81
	if sb.String() != "%C1%81" {
		t.Errorf("WriteOverlong2Byte('A') = %q, expected %%C1%%81", sb.String())
	}
}

func TestWriteOverlong3Byte(t *testing.T) {
	var sb strings.Builder
	WriteOverlong3Byte(&sb, 'A') // 0x41
	// 3-byte overlong: E0 81 81
	if sb.String() != "%E0%81%81" {
		t.Errorf("WriteOverlong3Byte('A') = %q, expected %%E0%%81%%81", sb.String())
	}
}
