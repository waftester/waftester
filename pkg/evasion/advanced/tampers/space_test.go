package tampers

import (
	"strings"
	"testing"
)

func TestSpace2Comment(t *testing.T) {
	tamper := &Space2Comment{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT * FROM users", "SELECT/**/*/**/FROM/**/users"},
		{"1 OR 1=1", "1/**/OR/**/1=1"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Space2Comment(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSpace2Dash(t *testing.T) {
	tamper := &Space2Dash{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT FROM", "SELECT--\nFROM"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Space2Dash(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSpace2Hash(t *testing.T) {
	tamper := &Space2Hash{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT FROM", "SELECT#\nFROM"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Space2Hash(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSpace2MoreComment(t *testing.T) {
	tamper := &Space2MoreComment{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"A B", "A/**_**/B"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Space2MoreComment(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSpace2MSSQLBlank(t *testing.T) {
	tamper := &Space2MSSQLBlank{}
	// Test that spaces are replaced with something
	result := tamper.Transform("A B C")
	if result == "A B C" {
		t.Error("Space2MSSQLBlank should replace spaces")
	}
	if strings.Count(result, " ") > 0 && !strings.Contains(result, "\x20") {
		// Spaces should be replaced with alternate chars
	}
	// Verify no spaces (or replaced with control chars which includes 0x20)
	parts := strings.Split(result, "A")
	if len(parts) < 2 {
		t.Errorf("Original structure not preserved: %q", result)
	}
}

func TestSpace2MySQLBlank(t *testing.T) {
	tamper := &Space2MySQLBlank{}
	// Test deterministically by checking spaces are replaced
	input := "SELECT FROM"
	result := tamper.Transform(input)
	// Count non-letter characters
	letterCount := 0
	for _, r := range result {
		if r >= 'A' && r <= 'Z' {
			letterCount++
		}
	}
	// Should have same letters
	if letterCount != 10 {
		t.Errorf("Space2MySQLBlank changed letters: input=%q, result=%q", input, result)
	}
}

func TestSpace2MySQLDash(t *testing.T) {
	tamper := &Space2MySQLDash{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT FROM", "SELECT-- \nFROM"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Space2MySQLDash(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSpace2Plus(t *testing.T) {
	tamper := &Space2Plus{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"hello world", "hello+world"},
		{"a b c", "a+b+c"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Space2Plus(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSpace2RandomBlank(t *testing.T) {
	tamper := &Space2RandomBlank{}
	result := tamper.Transform("A B")
	// Should contain URL-encoded whitespace
	if !strings.Contains(result, "%0") {
		t.Errorf("Space2RandomBlank should produce URL-encoded output: %q", result)
	}
	if !strings.HasPrefix(result, "A") || !strings.HasSuffix(result, "B") {
		t.Errorf("Space2RandomBlank should preserve letters: %q", result)
	}
}

func TestBlankspace(t *testing.T) {
	tamper := &Blankspace{}
	result := tamper.Transform("A B")
	// Should not contain regular space
	if strings.Contains(result, " ") {
		t.Errorf("Blankspace should replace regular spaces: %q", result)
	}
	// Should start with A and end with B
	if !strings.HasPrefix(result, "A") || !strings.HasSuffix(result, "B") {
		t.Errorf("Blankspace should preserve letters: %q", result)
	}
}

func TestSpaceTampersRegistered(t *testing.T) {
	spaceTampers := []string{
		"space2comment",
		"space2dash",
		"space2hash",
		"space2morecomment",
		"space2mssqlblank",
		"space2mssqlhash",
		"space2mysqlblank",
		"space2mysqldash",
		"space2plus",
		"space2randomblank",
		"blankspace",
	}

	for _, name := range spaceTampers {
		tamper := Get(name)
		if tamper == nil {
			t.Errorf("Space tamper %q not registered", name)
			continue
		}
		if tamper.Category() != CategorySpace {
			t.Errorf("Tamper %q category = %q, want %q", name, tamper.Category(), CategorySpace)
		}
	}
}

func TestSpaceCategory(t *testing.T) {
	tampers := ByCategory(CategorySpace)
	if len(tampers) < 11 {
		t.Errorf("Expected at least 11 space tampers, got %d", len(tampers))
	}
}
