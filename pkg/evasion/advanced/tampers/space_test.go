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

	// Empty input returns empty.
	if got := tamper.Transform(""); got != "" {
		t.Errorf("Transform empty: got %q", got)
	}

	// No spaces → unchanged.
	if got := tamper.Transform("ABC"); got != "ABC" {
		t.Errorf("Transform no-space: got %q, want ABC", got)
	}

	// Valid MSSQL whitespace set (0x01–0x20).
	validBlanks := make(map[byte]bool)
	for b := byte(0x01); b <= 0x20; b++ {
		validBlanks[b] = true
	}

	// Run multiple times — every byte at a space position must be a valid
	// MSSQL blank, and non-space characters must be preserved.
	for range 50 {
		result := tamper.Transform("A B C")
		bytes := []byte(result)
		if len(bytes) != 5 {
			t.Fatalf("length changed: got %d (%q)", len(bytes), result)
		}
		if bytes[0] != 'A' || bytes[2] != 'B' || bytes[4] != 'C' {
			t.Fatalf("non-space chars altered: %q", result)
		}
		if !validBlanks[bytes[1]] {
			t.Errorf("position 1: byte 0x%02X not a valid MSSQL blank", bytes[1])
		}
		if !validBlanks[bytes[3]] {
			t.Errorf("position 3: byte 0x%02X not a valid MSSQL blank", bytes[3])
		}
	}
}

func TestSpace2MySQLBlank(t *testing.T) {
	tamper := &Space2MySQLBlank{}

	// Empty input returns empty.
	if got := tamper.Transform(""); got != "" {
		t.Errorf("Transform empty: got %q", got)
	}

	// Valid MySQL whitespace set.
	validBlanks := map[byte]bool{
		0x09: true, 0x0A: true, 0x0B: true,
		0x0C: true, 0x0D: true, 0x20: true,
	}

	// Run multiple times — every byte at a space position must be a valid
	// MySQL blank, and letters must be preserved.
	for range 50 {
		result := tamper.Transform("SELECT FROM")
		bytes := []byte(result)
		if len(bytes) != 11 {
			t.Fatalf("length changed: got %d (%q)", len(bytes), result)
		}
		// Letters preserved.
		if string(bytes[:6]) != "SELECT" || string(bytes[7:]) != "FROM" {
			t.Fatalf("letters altered: %q", result)
		}
		if !validBlanks[bytes[6]] {
			t.Errorf("position 6: byte 0x%02X not a valid MySQL blank", bytes[6])
		}
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
