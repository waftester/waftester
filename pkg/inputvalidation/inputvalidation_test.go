package inputvalidation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTypeJugglingPayloads(t *testing.T) {
	payloads := TypeJugglingPayloads()

	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 type juggling payloads, got %d", len(payloads))
	}

	// Check for key payloads
	hasZero := false
	hasNull := false
	hasArray := false

	for _, p := range payloads {
		if p.Value == "0" || p.Value == "0e123" {
			hasZero = true
		}
		if p.Value == "null" {
			hasNull = true
		}
		if p.Value == "[]" || p.Value == "[0]" {
			hasArray = true
		}
	}

	if !hasZero {
		t.Error("Expected zero-related payloads")
	}
	if !hasNull {
		t.Error("Expected null payload")
	}
	if !hasArray {
		t.Error("Expected array payloads")
	}
}

func TestIntegerOverflowPayloads(t *testing.T) {
	payloads := IntegerOverflowPayloads()

	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 integer overflow payloads, got %d", len(payloads))
	}

	// Check for max values
	hasMaxInt32 := false
	hasMaxInt64 := false
	hasNegative := false

	for _, p := range payloads {
		if p.Value == "2147483647" {
			hasMaxInt32 = true
		}
		if p.Value == "9223372036854775807" {
			hasMaxInt64 = true
		}
		if strings.HasPrefix(p.Value, "-") {
			hasNegative = true
		}
	}

	if !hasMaxInt32 {
		t.Error("Expected max int32 payload")
	}
	if !hasMaxInt64 {
		t.Error("Expected max int64 payload")
	}
	if !hasNegative {
		t.Error("Expected negative value payloads")
	}
}

func TestBufferOverflowPayloads(t *testing.T) {
	payloads := BufferOverflowPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 buffer sizes, got %d", len(payloads))
	}

	// Sizes should be increasing
	prevSize := 0
	for _, p := range payloads {
		if p.Size <= prevSize {
			t.Errorf("Buffer sizes should be increasing, got %d after %d", p.Size, prevSize)
		}
		prevSize = p.Size
	}
}

func TestFormatStringPayloads(t *testing.T) {
	payloads := FormatStringPayloads()

	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 format string payloads, got %d", len(payloads))
	}

	hasPercentS := false
	hasPercentN := false
	hasTemplates := false

	for _, p := range payloads {
		if strings.Contains(p, "%s") {
			hasPercentS = true
		}
		if strings.Contains(p, "%n") {
			hasPercentN = true
		}
		if strings.Contains(p, "{{") || strings.Contains(p, "${") {
			hasTemplates = true
		}
	}

	if !hasPercentS {
		t.Error("Expected percent-s format payload")
	}
	if !hasPercentN {
		t.Error("Expected percent-n format payload")
	}
	if !hasTemplates {
		t.Error("Expected template injection payloads")
	}
}

func TestUnicodeBypassPayloads(t *testing.T) {
	payloads := UnicodeBypassPayloads()

	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 unicode bypass payloads, got %d", len(payloads))
	}

	hasFullwidth := false
	hasCyrillic := false
	hasNullByte := false

	for _, p := range payloads {
		if strings.Contains(p.Description, "Fullwidth") {
			hasFullwidth = true
		}
		if strings.Contains(p.Description, "Cyrillic") {
			hasCyrillic = true
		}
		if strings.Contains(p.Description, "Null byte") {
			hasNullByte = true
		}
	}

	if !hasFullwidth {
		t.Error("Expected fullwidth unicode payloads")
	}
	if !hasCyrillic {
		t.Error("Expected Cyrillic lookalike payloads")
	}
	if !hasNullByte {
		t.Error("Expected null byte payloads")
	}
}

func TestNullBytePayloads(t *testing.T) {
	payloads := NullBytePayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 null byte payloads, got %d", len(payloads))
	}

	hasEncoded := false
	hasRaw := false

	for _, p := range payloads {
		if strings.Contains(p, "%00") {
			hasEncoded = true
		}
		if strings.Contains(p, "\x00") {
			hasRaw = true
		}
	}

	if !hasEncoded {
		t.Error("Expected URL-encoded null byte")
	}
	if !hasRaw {
		t.Error("Expected raw null byte")
	}
}

func TestArrayManipulationPayloads(t *testing.T) {
	payloads := ArrayManipulationPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 array manipulation payloads, got %d", len(payloads))
	}

	hasNegativeIndex := false
	hasProto := false

	for _, p := range payloads {
		if strings.Contains(p, "[-1]") {
			hasNegativeIndex = true
		}
		if strings.Contains(p, "__proto__") || strings.Contains(p, "prototype") {
			hasProto = true
		}
	}

	if !hasNegativeIndex {
		t.Error("Expected negative index payload")
	}
	if !hasProto {
		t.Error("Expected prototype pollution related payloads")
	}
}

func TestRegexDoSPayloads(t *testing.T) {
	payloads := RegexDoSPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 ReDoS payloads, got %d", len(payloads))
	}

	// Payloads should be designed to cause exponential backtracking
	hasRepeatedChars := false
	for _, p := range payloads {
		if len(p) > 20 {
			hasRepeatedChars = true
			break
		}
	}

	if !hasRepeatedChars {
		t.Error("Expected payloads with repeated characters for ReDoS")
	}
}

func TestEncodingBypassPayloads(t *testing.T) {
	payloads := EncodingBypassPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 encoding bypass payloads, got %d", len(payloads))
	}

	hasURLEncoded := false
	hasHTMLEntity := false
	hasBase64 := false

	for _, p := range payloads {
		if strings.Contains(p.Description, "URL encoded") {
			hasURLEncoded = true
		}
		if strings.Contains(p.Description, "HTML entity") {
			hasHTMLEntity = true
		}
		if strings.Contains(p.Description, "Base64") {
			hasBase64 = true
		}
	}

	if !hasURLEncoded {
		t.Error("Expected URL encoded payloads")
	}
	if !hasHTMLEntity {
		t.Error("Expected HTML entity payloads")
	}
	if !hasBase64 {
		t.Error("Expected Base64 payloads")
	}
}

func TestBoundaryPayloads(t *testing.T) {
	payloads := BoundaryPayloads()

	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 boundary payloads, got %d", len(payloads))
	}

	hasEmpty := false
	hasNaN := false
	hasSlash := false

	for _, p := range payloads {
		if p.Value == "" {
			hasEmpty = true
		}
		if p.Value == "NaN" {
			hasNaN = true
		}
		if p.Value == "/" || p.Value == "\\" {
			hasSlash = true
		}
	}

	if !hasEmpty {
		t.Error("Expected empty string payload")
	}
	if !hasNaN {
		t.Error("Expected NaN payload")
	}
	if !hasSlash {
		t.Error("Expected slash payloads")
	}
}

func TestGenerateBufferPayload(t *testing.T) {
	payload := GenerateBufferPayload(100, 'A')

	if len(payload) != 100 {
		t.Errorf("Expected payload length 100, got %d", len(payload))
	}

	for _, c := range payload {
		if c != 'A' {
			t.Errorf("Expected all 'A' characters, got %c", c)
		}
	}
}

func TestNewTester(t *testing.T) {
	tester := NewTester("http://example.com", 0)

	if tester.target != "http://example.com" {
		t.Errorf("Expected target http://example.com, got %s", tester.target)
	}
	if tester.client == nil {
		t.Error("Expected HTTP client to be initialized")
	}
}

func TestAllPayloadCategories(t *testing.T) {
	categories := AllPayloadCategories()

	if len(categories) < 8 {
		t.Errorf("Expected at least 8 categories, got %d", len(categories))
	}

	expected := []string{"type_juggling", "integer_overflow", "null_byte", "encoding_bypass"}
	for _, exp := range expected {
		found := false
		for _, cat := range categories {
			if cat == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected category %s in list", exp)
		}
	}
}

func TestTestTypeJuggling(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("id")
		// Vulnerable: loose comparison in PHP-style
		if val == "0" || val == "0e123" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "admin": true}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestTypeJuggling(context.Background(), "/api/auth", "id")

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected some test results")
	}
}

func TestTestIntegerOverflow(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("amount")
		// Simulate overflow error on large values
		if len(val) > 15 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("integer overflow error"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestIntegerOverflow(context.Background(), "/api/transfer", "amount")

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	// Should detect the vulnerability
	foundVuln := false
	for _, r := range results {
		if r.Vulnerable && strings.Contains(r.Description, "overflow") {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect integer overflow vulnerability")
	}
}

func TestTestFormatString(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// Vulnerable: interpreting format specifiers
		if strings.Contains(name, "%x") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello 0x41414141"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello " + name))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestFormatString(context.Background(), "/greet", "name")

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected test results")
	}

	// Check that vulnerable case was detected
	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect format string vulnerability")
	}
}

func TestTestNullByte(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		// Vulnerable: null byte allows reading passwd
		if strings.Contains(file, "passwd") && strings.Contains(file, "%00") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestNullByte(context.Background(), "/read", "file")

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect null byte vulnerability")
	}
}

func TestTestEncodingBypass(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		// Vulnerable: reflects decoded content
		w.WriteHeader(http.StatusOK)
		// Simulate decoding %3C to <
		if strings.Contains(input, "script") {
			w.Write([]byte("<script>alert(1)</script>"))
			return
		}
		w.Write([]byte(input))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestEncodingBypass(context.Background(), "/search", "q")

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect encoding bypass vulnerability")
	}
}

func TestMin(t *testing.T) {
	if min(5, 10) != 5 {
		t.Error("min(5, 10) should be 5")
	}
	if min(10, 5) != 5 {
		t.Error("min(10, 5) should be 5")
	}
	if min(5, 5) != 5 {
		t.Error("min(5, 5) should be 5")
	}
}
