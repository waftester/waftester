package tampers

import (
	"strings"
	"testing"
)

func TestApostrophenullencode(t *testing.T) {
	tamper := &Apostrophenullencode{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"'", "%00%27"},
		{"' OR '1'='1", "%00%27 OR %00%271%00%27=%00%271"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Apostrophenullencode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestApostrophemask(t *testing.T) {
	tamper := &Apostrophemask{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"'", "\uFF07"},
		{"test'value", "test\uFF07value"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Apostrophemask(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestBetween(t *testing.T) {
	tamper := &Between{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"id>5", "id NOT BETWEEN 0 AND 5"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Between(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCommentbeforeparentheses(t *testing.T) {
	tamper := &Commentbeforeparentheses{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT()", "SELECT/**/()"},
		{"CONCAT(a,b)", "CONCAT/**/(a,b)"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Commentbeforeparentheses(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestConcat2Concatws(t *testing.T) {
	tamper := &Concat2Concatws{}
	result := tamper.Transform("CONCAT(a,b)")
	if !strings.Contains(result, "CONCAT_WS") {
		t.Errorf("Expected CONCAT_WS in result: %q", result)
	}
}

func TestEqualToLike(t *testing.T) {
	tamper := &EqualToLike{}
	tests := []struct {
		input    string
		contains string
	}{
		{"a=b", "LIKE"},
		{">=", ">="},  // Should preserve >=
		{"!=1", "NOT LIKE"}, // Should convert != to NOT LIKE
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("EqualToLike(%q) = %q, should contain %q", tt.input, result, tt.contains)
		}
	}
}

func TestLowercase(t *testing.T) {
	tamper := &Lowercase{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT", "select"},
		{"TeSt", "test"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Lowercase(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestUppercase(t *testing.T) {
	tamper := &Uppercase{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"select", "SELECT"},
		{"TeSt", "TEST"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Uppercase(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestRandomCase(t *testing.T) {
	tamper := &RandomCase{}
	input := "teststring"
	result := tamper.Transform(input)
	// Just verify length and that it's not identical (statistically)
	if len(result) != len(input) {
		t.Errorf("RandomCase changed length: %d -> %d", len(input), len(result))
	}
	// Check that lowercase version matches
	if strings.ToLower(result) != input {
		t.Errorf("RandomCase changed characters: %q", result)
	}
}

func TestSymbolsComment(t *testing.T) {
	tamper := &SymbolsComment{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"1 AND 2", "1 && 2"},
		{"1 OR 2", "1 || 2"},
		{"1 and 2 or 3", "1 && 2 || 3"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("SymbolsComment(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHalfVersionedMoreKeywords(t *testing.T) {
	tamper := &HalfVersionedMoreKeywords{}
	result := tamper.Transform("SELECT * FROM users WHERE id=1")
	// Check versioned comments were added
	if !strings.Contains(result, "/*!SELECT*/") {
		t.Errorf("Expected versioned SELECT: %q", result)
	}
	if !strings.Contains(result, "/*!FROM*/") {
		t.Errorf("Expected versioned FROM: %q", result)
	}
}

func TestIfNull2CaseWhenNull(t *testing.T) {
	tamper := &IfNull2CaseWhenNull{}
	result := tamper.Transform("IFNULL(a, b)")
	if !strings.Contains(result, "CASE WHEN") {
		t.Errorf("Expected CASE WHEN in result: %q", result)
	}
}

func TestIfNull2IfNullStr(t *testing.T) {
	tamper := &IfNull2IfNullStr{}
	result := tamper.Transform("IFNULL(a, b)")
	if !strings.Contains(result, "IF(ISNULL") {
		t.Errorf("Expected IF(ISNULL in result: %q", result)
	}
}

func TestSubstringExtreme(t *testing.T) {
	tamper := &SubstringExtreme{}
	result := tamper.Transform("SUBSTRING(str, 2, 3)")
	if !strings.Contains(result, "RIGHT") && !strings.Contains(result, "LEFT") {
		t.Errorf("Expected RIGHT/LEFT in result: %q", result)
	}
}

func TestSQLTampersRegistered(t *testing.T) {
	sqlTampers := []string{
		"apostrophenullencode",
		"apostrophemask",
		"between",
		"commentbeforeparentheses",
		"concat2concatws",
		"equaltolike",
		"greatest",
		"halfversionedmorekeywords",
		"ifnull2casewhennull",
		"ifnull2ifisnull",
		"least",
		"lowercase",
		"uppercase",
		"randomcase",
		"symboliclogical",
		"substring2leftright",
	}

	for _, name := range sqlTampers {
		tamper := Get(name)
		if tamper == nil {
			t.Errorf("SQL tamper %q not registered", name)
			continue
		}
		if tamper.Category() != CategorySQL {
			t.Errorf("Tamper %q category = %q, want %q", name, tamper.Category(), CategorySQL)
		}
	}
}

func TestSQLCategory(t *testing.T) {
	tampers := ByCategory(CategorySQL)
	if len(tampers) < 16 {
		t.Errorf("Expected at least 16 SQL tampers, got %d", len(tampers))
	}
}
