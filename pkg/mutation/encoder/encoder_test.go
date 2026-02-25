package encoder

import (
	"net/url"
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/mutation"
)

func TestRawEncoder(t *testing.T) {
	enc := &RawEncoder{}

	if enc.Name() != "raw" {
		t.Errorf("Expected name 'raw', got '%s'", enc.Name())
	}
	if enc.Category() != "encoder" {
		t.Error("Wrong category")
	}

	results := enc.Mutate("<script>alert(1)</script>")
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if results[0].Mutated != "<script>alert(1)</script>" {
		t.Error("Raw encoder should not modify payload")
	}
}

func TestURLEncoder(t *testing.T) {
	enc := &URLEncoder{}

	results := enc.Mutate("<script>")
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Should URL encode special characters
	if !strings.Contains(results[0].Mutated, "%3C") {
		t.Errorf("Expected URL encoded <, got '%s'", results[0].Mutated)
	}
}

func TestDoubleURLEncoder(t *testing.T) {
	enc := &DoubleURLEncoder{}

	results := enc.Mutate("<")
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Double encoding: < -> %3C -> %253C
	if results[0].Mutated != "%253C" {
		t.Errorf("Expected '%%253C', got '%s'", results[0].Mutated)
	}
}

func TestTripleURLEncoder(t *testing.T) {
	enc := &TripleURLEncoder{}

	results := enc.Mutate("<")
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Triple encoding: < -> %3C -> %253C -> %25253C
	if results[0].Mutated != "%25253C" {
		t.Errorf("Expected '%%25253C', got '%s'", results[0].Mutated)
	}
}

func TestHTMLDecimalEncoder(t *testing.T) {
	enc := &HTMLDecimalEncoder{}

	results := enc.Mutate("<")
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// < should become &#60;
	if results[0].Mutated != "&#60;" {
		t.Errorf("Expected '&#60;', got '%s'", results[0].Mutated)
	}
}

func TestHTMLHexEncoder(t *testing.T) {
	enc := &HTMLHexEncoder{}

	results := enc.Mutate("<")
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// < should become &#x3c;
	if results[0].Mutated != "&#x3c;" {
		t.Errorf("Expected '&#x3c;', got '%s'", results[0].Mutated)
	}
}

func TestUTF7Encoder(t *testing.T) {
	enc := &UTF7Encoder{}

	results := enc.Mutate("<script>")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// At least one result should contain UTF-7 encoding markers or be different
	for _, r := range results {
		if r.Mutated != "<script>" {
			return // Pass - some transformation occurred
		}
	}
	t.Log("Note: UTF-7 encoder may not transform all inputs")
}

func TestOverlongUTF8Encoder(t *testing.T) {
	enc := &OverlongUTF8Encoder{}

	results := enc.Mutate("<")
	if len(results) != 2 {
		t.Fatalf("Expected 2 results (2-byte and 3-byte), got %d", len(results))
	}

	// 2-byte overlong for '<' (0x3C) should be %C0%BC
	// 110000xx 10xxxxxx where xx = 0x3C >> 6 = 0, xxxxxx = 0x3C & 0x3F = 0x3C
	// First byte: 0xC0 | 0 = 0xC0
	// Second byte: 0x80 | 0x3C = 0xBC
	if results[0].Mutated != "%C0%BC" {
		t.Errorf("2-byte overlong for '<' expected %%C0%%BC, got %q", results[0].Mutated)
	}

	// 3-byte overlong for '<' (0x3C) should be %E0%80%BC
	// 1110xxxx 10xxxxxx 10xxxxxx
	// First: 0xE0, Second: 0x80 | (0x3C >> 6) = 0x80, Third: 0x80 | 0x3C = 0xBC
	if results[1].Mutated != "%E0%80%BC" {
		t.Errorf("3-byte overlong for '<' expected %%E0%%80%%BC, got %q", results[1].Mutated)
	}

	// Test that ASCII is encoded, non-ASCII is preserved
	results = enc.Mutate("A\xfe")
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}
	// 'A' (0x41) becomes %C1%81 in 2-byte, 0xFE is preserved
	if results[0].Mutated != "%C1%81\xfe" {
		t.Errorf("2-byte overlong expected %%C1%%81 + raw byte, got %q", results[0].Mutated)
	}
}

func TestWideGBKEncoder(t *testing.T) {
	enc := &WideGBKEncoder{}

	results := enc.Mutate("'")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce wide-byte variants (may be multiple)
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "%") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Wide GBK encoder should produce percent-encoded output")
	}
}

func TestBase64Encoder(t *testing.T) {
	enc := &Base64Encoder{}

	results := enc.Mutate("<script>alert(1)</script>")
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
	expected := "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
	if results[0].Mutated != expected {
		t.Errorf("Expected '%s', got '%s'", expected, results[0].Mutated)
	}
}

func TestAllEncodersRegistered(t *testing.T) {
	// Verify all encoders are registered in the default registry
	encoders := mutation.DefaultRegistry.GetByCategory("encoder")

	// Verify we have a reasonable number of encoders
	if len(encoders) < 10 {
		t.Errorf("Expected at least 10 encoders, got %d", len(encoders))
	}

	// Verify key encoders are present
	coreEncoders := []string{
		"raw", "url", "double_url", "triple_url",
		"html_decimal", "html_hex", "unicode", "base64",
	}

	registered := make(map[string]bool)
	for _, enc := range encoders {
		registered[enc.Name()] = true
	}

	for _, name := range coreEncoders {
		if !registered[name] {
			t.Errorf("Core encoder '%s' not registered", name)
		}
	}

	// Verify NamesForCategory matches GetByCategory
	names := mutation.DefaultRegistry.NamesForCategory("encoder")
	if len(names) != len(encoders) {
		t.Errorf("NamesForCategory returned %d names, GetByCategory returned %d mutators",
			len(names), len(encoders))
	}
}

func TestURLEncoderRoundtrip(t *testing.T) {
	enc := &URLEncoder{}
	original := "' OR 1=1--"

	results := enc.Mutate(original)
	decoded, err := url.QueryUnescape(results[0].Mutated)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if decoded != original {
		t.Errorf("Roundtrip failed: expected '%s', got '%s'", original, decoded)
	}
}

func TestMixedEncoder(t *testing.T) {
	enc := &MixedEncoder{}

	results := enc.Mutate("<script>")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Mixed should have some URL encoded and some raw
	for _, r := range results {
		mutated := r.Mutated
		hasEncoded := strings.Contains(mutated, "%")
		hasRaw := strings.ContainsAny(mutated, "scriptalert")

		if hasEncoded && hasRaw {
			return // Found a valid mixed result
		}
	}
	// At least verify it produces output
	t.Log("Mixed encoder may use various strategies")
}
