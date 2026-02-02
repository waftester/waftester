package tampers

import (
	"strings"
	"testing"
)

func TestMSSQLBlind(t *testing.T) {
	tamper := &MSSQLBlind{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT", "{SELECT}"},
		{"SELECT * FROM users", "{SELECT} * {FROM} users"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("MSSQLBlind(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestChardeclareAndexec(t *testing.T) {
	tamper := &ChardeclareAndexec{}
	result := tamper.Transform("abc")
	// Should contain DECLARE and EXEC
	if !strings.Contains(result, "DECLARE") {
		t.Errorf("Expected DECLARE in result: %q", result)
	}
	if !strings.Contains(result, "EXEC") {
		t.Errorf("Expected EXEC in result: %q", result)
	}
	// Should contain CHAR(97) for 'a'
	if !strings.Contains(result, "CHAR(97)") {
		t.Errorf("Expected CHAR(97) in result: %q", result)
	}
}

func TestTopClause(t *testing.T) {
	tamper := &TopClause{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT *", "SELECT TOP 1 *"},
		{"select id", "SELECT TOP 1 id"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("TopClause(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSPPassword(t *testing.T) {
	tamper := &SPPassword{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT 1", "SELECT 1 --sp_password"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("SPPassword(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestBracketComment(t *testing.T) {
	tamper := &BracketComment{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"SELECT", "[SELECT]"},
		{"SELECT FROM", "[SELECT] [FROM]"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("BracketComment(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCharToUnicode(t *testing.T) {
	tamper := &CharToUnicode{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"CHAR(65)", "NCHAR(65)"},
		{"char(65)", "NCHAR(65)"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("CharToUnicode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMSSQLTampersRegistered(t *testing.T) {
	mssqlTampers := []string{
		"mssqlblind",
		"chardeclareandexec",
		"topclause",
		"sppassword",
		"bracketcomment",
		"chartounicode",
	}

	for _, name := range mssqlTampers {
		tamper := Get(name)
		if tamper == nil {
			t.Errorf("MSSQL tamper %q not registered", name)
			continue
		}
		if tamper.Category() != CategoryMSSQL {
			t.Errorf("Tamper %q category = %q, want %q", name, tamper.Category(), CategoryMSSQL)
		}
	}
}

func TestMSSQLCategory(t *testing.T) {
	tampers := ByCategory(CategoryMSSQL)
	if len(tampers) < 6 {
		t.Errorf("Expected at least 6 MSSQL tampers, got %d", len(tampers))
	}
}
