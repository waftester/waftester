package tampers

import (
	"testing"
)

func TestBase64Encode(t *testing.T) {
	tamper := &Base64Encode{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"test", "dGVzdA=="},
		{"' OR 1=1--", "JyBPUiAxPTEtLQ=="},
		{"<script>alert(1)</script>", "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Base64Encode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCharEncode(t *testing.T) {
	tamper := &CharEncode{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"ABC", "%41%42%43"},
		{"'", "%27"},
		{" ", "%20"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("CharEncode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCharDoubleEncode(t *testing.T) {
	tamper := &CharDoubleEncode{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"A", "%2541"},
		{"'", "%2527"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("CharDoubleEncode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCharUnicodeEncode(t *testing.T) {
	tamper := &CharUnicodeEncode{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"A", "%u0041"},
		{"'", "%u0027"},
		{"test", "%u0074%u0065%u0073%u0074"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("CharUnicodeEncode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCharUnicodeEscape(t *testing.T) {
	tamper := &CharUnicodeEscape{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"A", "\\u0041"},
		{"test", "\\u0074\\u0065\\u0073\\u0074"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("CharUnicodeEscape(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestDecEntities(t *testing.T) {
	tamper := &DecEntities{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"A", "&#65;"},
		{"<", "&#60;"},
		{"test", "&#116;&#101;&#115;&#116;"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("DecEntities(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHexEntities(t *testing.T) {
	tamper := &HexEntities{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"A", "&#x41;"},
		{"<", "&#x3C;"},
		{"test", "&#x74;&#x65;&#x73;&#x74;"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("HexEntities(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHTMLEncode(t *testing.T) {
	tamper := &HTMLEncode{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"<script>", "&lt;script&gt;"},
		{"test & demo", "test &amp; demo"},
		{"\"quoted\"", "&quot;quoted&quot;"},
		{"'single'", "&#x27;single&#x27;"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("HTMLEncode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestOverlongUTF8(t *testing.T) {
	tamper := &OverlongUTF8{}
	// For 'A' (0x41): 0xC0 | (0x41 >> 6) = 0xC1, 0x80 | (0x41 & 0x3F) = 0x81
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"A", "%C1%81"},
		{"/", "%C0%AF"}, // Classic directory traversal bypass
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("OverlongUTF8(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestOverlongUTF8More(t *testing.T) {
	tamper := &OverlongUTF8More{}
	// For 'A' (0x41): 0xE0, 0x80 | (0x41 >> 6) = 0x81, 0x80 | (0x41 & 0x3F) = 0x81
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"A", "%E0%81%81"},
		{"/", "%E0%80%AF"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("OverlongUTF8More(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestPercentage(t *testing.T) {
	tamper := &Percentage{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT", "%S%E%L%E%C%T"},
		{"test", "%t%e%s%t"},
		{"% ", "% "},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Percentage(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestUnmagicQuotes(t *testing.T) {
	tamper := &UnmagicQuotes{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"test'value", "test%bf%27value"},
		{"' OR '1'='1", "%bf%27 OR %bf%271%bf%27=%bf%271"},
		{"%27", "%bf%27"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("UnmagicQuotes(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestEncodingTampersRegistered(t *testing.T) {
	encodingTampers := []string{
		"base64encode",
		"charencode",
		"chardoubleencode",
		"charunicodeencode",
		"charunicodeescape",
		"decentities",
		"hexentities",
		"htmlencode",
		"overlongutf8",
		"overlongutf8more",
		"percentage",
		"unmagicquotes",
	}

	for _, name := range encodingTampers {
		tamper := Get(name)
		if tamper == nil {
			t.Errorf("Encoding tamper %q not registered", name)
			continue
		}
		if tamper.Category() != CategoryEncoding {
			t.Errorf("Tamper %q category = %q, want %q", name, tamper.Category(), CategoryEncoding)
		}
	}
}

func TestEncodingCategory(t *testing.T) {
	tampers := ByCategory(CategoryEncoding)
	if len(tampers) < 12 {
		t.Errorf("Expected at least 12 encoding tampers, got %d", len(tampers))
	}
}
