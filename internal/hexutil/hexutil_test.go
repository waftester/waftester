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
