package tampers

import (
	"strings"
	"testing"
)

func TestEscapeNQuotes(t *testing.T) {
	tamper := &EscapeNQuotes{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"'", "\\'"},
		{"\"", "\\\""},
		{"test'value", "test\\'value"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("EscapeNQuotes(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMisUnion(t *testing.T) {
	tamper := &MisUnion{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"UNION SELECT", "-.1UNION SELECT"},
		{"1 union all", "1 -.1UNION all"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("MisUnion(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestModsecurityversioned(t *testing.T) {
	tamper := &Modsecurityversioned{}
	result := tamper.Transform("SELECT 1")
	// Should wrap in versioned comment
	if !strings.HasPrefix(result, "/*!") || !strings.HasSuffix(result, "*/") {
		t.Errorf("Modsecurityversioned should wrap in versioned comment: %q", result)
	}
	if !strings.Contains(result, "SELECT 1") {
		t.Errorf("Payload should be preserved: %q", result)
	}
}

func TestModsecurityzeroversioned(t *testing.T) {
	tamper := &Modsecurityzeroversioned{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT 1", "/*!00000SELECT 1*/"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Modsecurityzeroversioned(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMultipleURLEncode(t *testing.T) {
	tamper := &MultipleURLEncode{}
	result := tamper.Transform("'")
	// Single quote is %27, then % becomes %25, so %2527
	if result != "%2527" {
		t.Errorf("MultipleURLEncode(\"'\") = %q, want %%2527", result)
	}
}

func TestReverseOrder(t *testing.T) {
	tamper := &ReverseOrder{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"abc", "cba"},
		{"hello", "olleh"},
		{"12345", "54321"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("ReverseOrder(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSpaceToMySQLComment(t *testing.T) {
	tamper := &SpaceToMySQLComment{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT 1", "SELECT 1--sp_password"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("SpaceToMySQLComment(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestVersionedKeywords(t *testing.T) {
	tamper := &VersionedKeywords{}
	result := tamper.Transform("SELECT * FROM users WHERE id=1")
	if !strings.Contains(result, "/*!SELECT*/") {
		t.Errorf("Expected versioned SELECT: %q", result)
	}
	if !strings.Contains(result, "/*!WHERE*/") {
		t.Errorf("Expected versioned WHERE: %q", result)
	}
}

func TestVersionedMoreKeywords(t *testing.T) {
	tamper := &VersionedMoreKeywords{}
	result := tamper.Transform("SELECT * FROM users WHERE id=1 AND name LIKE 'test'")
	if !strings.Contains(result, "/*!SELECT*/") {
		t.Errorf("Expected versioned SELECT: %q", result)
	}
	if !strings.Contains(result, "/*!AND*/") {
		t.Errorf("Expected versioned AND: %q", result)
	}
	if !strings.Contains(result, "/*!LIKE*/") {
		t.Errorf("Expected versioned LIKE: %q", result)
	}
}

func TestMySQLTampersRegistered(t *testing.T) {
	mysqlTampers := []string{
		"charlongescape",
		"escapequotes",
		"misunion",
		"modsecurityversioned",
		"modsecurityzeroversioned",
		"multipleurlencode",
		"reverseorder",
		"sp_password",
		"versionedkeywords",
		"versionedmorekeywords",
	}

	for _, name := range mysqlTampers {
		tamper := Get(name)
		if tamper == nil {
			t.Errorf("MySQL tamper %q not registered", name)
		}
	}
}

func TestMySQLCategory(t *testing.T) {
	tampers := ByCategory(CategoryMySQL)
	if len(tampers) < 10 {
		t.Errorf("Expected at least 10 MySQL tampers, got %d", len(tampers))
	}
}
