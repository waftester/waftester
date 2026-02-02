package tampers

import (
	"strings"
	"testing"
)

func TestCommentRandom(t *testing.T) {
	tamper := &CommentRandom{}
	// Run multiple times to ensure randomness works
	input := "SELECT * FROM users"
	result := tamper.Transform(input)
	// Should contain original characters
	cleaned := strings.ReplaceAll(result, "/**/", "")
	if cleaned != input {
		t.Errorf("CommentRandom should preserve content: %q -> %q", input, result)
	}
}

func TestRandomComments(t *testing.T) {
	tamper := &RandomComments{}
	result := tamper.Transform("SELECT * FROM users")
	// Should have comments around keywords
	if !strings.Contains(result, "/*") || !strings.Contains(result, "*/") {
		t.Errorf("Expected comments in result: %q", result)
	}
	// Should contain the keywords
	if !strings.Contains(strings.ToUpper(result), "SELECT") {
		t.Errorf("Should contain SELECT: %q", result)
	}
}

func TestSlashStar(t *testing.T) {
	tamper := &SlashStar{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"test", "/*test*/"},
		{"SELECT 1", "/*SELECT 1*/"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("SlashStar(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestConcat(t *testing.T) {
	tamper := &Concat{}
	// Test with quoted string
	result := tamper.Transform("'testvalue'")
	if !strings.Contains(result, "||") {
		t.Errorf("Expected || in concatenated result: %q", result)
	}
}

func TestNullByte(t *testing.T) {
	tamper := &NullByte{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"test", "%00test"},
		{"SELECT", "%00SELECT"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("NullByte(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSuffix(t *testing.T) {
	tamper := &Suffix{}
	input := "SELECT 1"
	result := tamper.Transform(input)
	// Should have one of the suffixes
	hasValidSuffix := false
	for _, suffix := range suffixVariants {
		if strings.HasSuffix(result, suffix) {
			hasValidSuffix = true
			break
		}
	}
	if !hasValidSuffix {
		t.Errorf("Suffix should add valid SQL suffix: %q", result)
	}
	// Should start with original
	if !strings.HasPrefix(result, input) {
		t.Errorf("Suffix should preserve original: %q", result)
	}
}

func TestObfuscationTampersRegistered(t *testing.T) {
	obfuscationTampers := []string{
		"commentrandom",
		"randomcomments",
		"slashstar",
		"concat",
		"nullbyte",
		"suffix",
	}

	for _, name := range obfuscationTampers {
		tamper := Get(name)
		if tamper == nil {
			t.Errorf("Obfuscation tamper %q not registered", name)
			continue
		}
		if tamper.Category() != CategoryObfuscation {
			t.Errorf("Tamper %q category = %q, want %q", name, tamper.Category(), CategoryObfuscation)
		}
	}
}

func TestObfuscationCategory(t *testing.T) {
	tampers := ByCategory(CategoryObfuscation)
	if len(tampers) < 6 {
		t.Errorf("Expected at least 6 obfuscation tampers, got %d", len(tampers))
	}
}
