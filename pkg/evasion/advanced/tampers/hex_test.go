package tampers

import (
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// MSSQL CHAR() LOOKUP TABLE TESTS
// =============================================================================

func TestMSSQLCharLookupCorrectness(t *testing.T) {
	// Verify all ASCII values match expected format
	for i := 0; i < 128; i++ {
		expected := fmt.Sprintf("CHAR(%d)", i)
		got := mssqlCharLookup[i]
		if got != expected {
			t.Errorf("mssqlCharLookup[%d] = %q, expected %q", i, got, expected)
		}
	}
}

func TestGetMSSQLChar_ASCII(t *testing.T) {
	tests := []struct {
		input    rune
		expected string
	}{
		{0, "CHAR(0)"},
		{'a', "CHAR(97)"},
		{'A', "CHAR(65)"},
		{' ', "CHAR(32)"},
		{'0', "CHAR(48)"},
		{'<', "CHAR(60)"},
		{'>', "CHAR(62)"},
		{'\'', "CHAR(39)"},
		{127, "CHAR(127)"},
	}
	for _, tt := range tests {
		got := GetMSSQLChar(tt.input)
		if got != tt.expected {
			t.Errorf("GetMSSQLChar(%d) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestGetMSSQLChar_Unicode(t *testing.T) {
	// Test unicode characters > 127 (uses itoaLarge fallback)
	tests := []struct {
		input    rune
		expected string
	}{
		{128, "CHAR(128)"},
		{255, "CHAR(255)"},
		{256, "CHAR(256)"},
		{1000, "CHAR(1000)"},
		{'é', "CHAR(233)"},    // Latin small letter e with acute
		{'中', "CHAR(20013)"},  // Chinese character
		{'🔥', "CHAR(128293)"}, // Fire emoji
	}
	for _, tt := range tests {
		got := GetMSSQLChar(tt.input)
		if got != tt.expected {
			t.Errorf("GetMSSQLChar(%d) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{99, "99"},
		{100, "100"},
		{127, "127"},
	}
	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.expected {
			t.Errorf("itoa(%d) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestItoaLarge(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{128, "128"},
		{1000, "1000"},
		{12345, "12345"},
		{128293, "128293"}, // Fire emoji codepoint
		{1000000, "1000000"},
	}
	for _, tt := range tests {
		got := itoaLarge(tt.input)
		if got != tt.expected {
			t.Errorf("itoaLarge(%d) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

// =============================================================================
// URL ENCODING LOOKUP TABLE TESTS
// =============================================================================

func TestURLEncodedBytesCorrectness(t *testing.T) {
	for i := 0; i < 256; i++ {
		expected := fmt.Sprintf("%%%02X", i)
		got := urlEncodedBytes[i]
		if got != expected {
			t.Errorf("urlEncodedBytes[%d] = %q, expected %q", i, got, expected)
		}
	}
}

func TestDoubleURLEncodedBytesCorrectness(t *testing.T) {
	for i := 0; i < 256; i++ {
		expected := fmt.Sprintf("%%25%02X", i)
		got := doubleUrlEncodedBytes[i]
		if got != expected {
			t.Errorf("doubleUrlEncodedBytes[%d] = %q, expected %q", i, got, expected)
		}
	}
}

func TestWriteURLEncodedByte(t *testing.T) {
	var sb strings.Builder
	writeURLEncodedByte(&sb, 'A')
	if sb.String() != "%41" {
		t.Errorf("writeURLEncodedByte('A') = %q, expected %%41", sb.String())
	}

	sb.Reset()
	writeURLEncodedByte(&sb, '<')
	if sb.String() != "%3C" {
		t.Errorf("writeURLEncodedByte('<') = %q, expected %%3C", sb.String())
	}
}

func TestWriteDoubleURLEncodedByte(t *testing.T) {
	var sb strings.Builder
	writeDoubleURLEncodedByte(&sb, 'A')
	if sb.String() != "%2541" {
		t.Errorf("writeDoubleURLEncodedByte('A') = %q, expected %%2541", sb.String())
	}
}

// =============================================================================
// UNICODE ESCAPE TESTS
// =============================================================================

func TestWriteUnicodeEscape_ASCII(t *testing.T) {
	var sb strings.Builder
	writeUnicodeEscape(&sb, 'A', true)
	if sb.String() != "\\u0041" {
		t.Errorf("writeUnicodeEscape('A', true) = %q, expected \\u0041", sb.String())
	}

	sb.Reset()
	writeUnicodeEscape(&sb, 'A', false)
	if sb.String() != "\\u0041" {
		t.Errorf("writeUnicodeEscape('A', false) = %q, expected \\u0041", sb.String())
	}
}

func TestWriteUnicodeEscape_NonASCII(t *testing.T) {
	var sb strings.Builder
	// Test a character > 0xFF to exercise the multi-byte path
	writeUnicodeEscape(&sb, 0x1234, true)
	if sb.String() != "\\u1234" {
		t.Errorf("writeUnicodeEscape(0x1234, true) = %q, expected \\u1234", sb.String())
	}

	sb.Reset()
	writeUnicodeEscape(&sb, 0xABCD, false)
	if sb.String() != "\\uabcd" {
		t.Errorf("writeUnicodeEscape(0xABCD, false) = %q, expected \\uabcd", sb.String())
	}
}

// =============================================================================
// HTML ENTITY TESTS
// =============================================================================

func TestWriteDecEntity(t *testing.T) {
	var sb strings.Builder
	writeDecEntity(&sb, 'A')
	if sb.String() != "&#65;" {
		t.Errorf("writeDecEntity('A') = %q, expected &#65;", sb.String())
	}

	sb.Reset()
	writeDecEntity(&sb, 0)
	if sb.String() != "&#0;" {
		t.Errorf("writeDecEntity(0) = %q, expected &#0;", sb.String())
	}

	// Test multi-digit values
	sb.Reset()
	writeDecEntity(&sb, 1000)
	if sb.String() != "&#1000;" {
		t.Errorf("writeDecEntity(1000) = %q, expected &#1000;", sb.String())
	}
}

func TestWriteHexEntity_ASCII(t *testing.T) {
	var sb strings.Builder
	writeHexEntity(&sb, 'A')
	if sb.String() != "&#x41;" {
		t.Errorf("writeHexEntity('A') = %q, expected &#x41;", sb.String())
	}
}

func TestWriteHexEntity_MultiByte(t *testing.T) {
	var sb strings.Builder
	// Test character > 0xFF to exercise multi-byte path
	writeHexEntity(&sb, 0x1234)
	if sb.String() != "&#x1234;" {
		t.Errorf("writeHexEntity(0x1234) = %q, expected &#x1234;", sb.String())
	}

	sb.Reset()
	writeHexEntity(&sb, 0xABCD)
	if sb.String() != "&#xABCD;" {
		t.Errorf("writeHexEntity(0xABCD) = %q, expected &#xABCD;", sb.String())
	}
}

// =============================================================================
// OVERLONG UTF-8 TESTS
// =============================================================================

func TestWriteOverlongUTF8_2byte(t *testing.T) {
	var sb strings.Builder
	// 'A' (0x41) should become %C1%81 in 2-byte overlong
	writeOverlongUTF8_2byte(&sb, 0x41)
	expected := "%C1%81"
	if sb.String() != expected {
		t.Errorf("writeOverlongUTF8_2byte(0x41) = %q, expected %q", sb.String(), expected)
	}
}

func TestWriteOverlongUTF8_3byte(t *testing.T) {
	var sb strings.Builder
	// 'A' (0x41) should become %E0%81%81 in 3-byte overlong
	writeOverlongUTF8_3byte(&sb, 0x41)
	expected := "%E0%81%81"
	if sb.String() != expected {
		t.Errorf("writeOverlongUTF8_3byte(0x41) = %q, expected %q", sb.String(), expected)
	}
}

// =============================================================================
// BENCHMARKS
// =============================================================================

func BenchmarkGetMSSQLChar_ASCII(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetMSSQLChar('a')
	}
}

func BenchmarkGetMSSQLChar_Unicode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetMSSQLChar('中')
	}
}

func BenchmarkGetMSSQLChar_FmtSprintf(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = fmt.Sprintf("CHAR(%d)", 'a')
	}
}

func BenchmarkURLEncode_LookupTable(b *testing.B) {
	var sb strings.Builder
	payload := []byte("SELECT * FROM users")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		sb.Grow(len(payload) * 3)
		for _, c := range payload {
			writeURLEncodedByte(&sb, c)
		}
		_ = sb.String()
	}
}

func BenchmarkURLEncode_FmtSprintf(b *testing.B) {
	var sb strings.Builder
	payload := []byte("SELECT * FROM users")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		for _, c := range payload {
			sb.WriteString(fmt.Sprintf("%%%02X", c))
		}
		_ = sb.String()
	}
}
