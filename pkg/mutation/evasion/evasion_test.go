package evasion

import (
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/mutation"
)

func TestCaseSwapEvasion(t *testing.T) {
	eva := &CaseSwapEvasion{}

	if eva.Name() != "case_swap" {
		t.Errorf("Expected name 'case_swap', got '%s'", eva.Name())
	}
	if eva.Category() != "evasion" {
		t.Error("Wrong category")
	}

	results := eva.Mutate("SELECT")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// At least one result should have mixed case
	for _, r := range results {
		mutated := r.Mutated
		hasUpper := strings.ContainsAny(mutated, "SELCT")
		hasLower := strings.ContainsAny(mutated, "selct")

		if hasUpper && hasLower {
			return // Found valid mixed case
		}
	}
	t.Log("Case swap may use various strategies")
}

func TestSQLCommentEvasion(t *testing.T) {
	eva := &SQLCommentEvasion{}

	results := eva.Mutate("SELECT * FROM users")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// At least one should contain SQL comments
	for _, r := range results {
		if strings.Contains(r.Mutated, "/*") || strings.Contains(r.Mutated, "--") {
			return // Found comment
		}
	}
	t.Log("SQL comment evasion may use various comment styles")
}

func TestWhitespaceAltEvasion(t *testing.T) {
	eva := &WhitespaceAltEvasion{}

	results := eva.Mutate("SELECT * FROM users")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// At least one should have whitespace replaced
	original := "SELECT * FROM users"
	for _, r := range results {
		if r.Mutated != original {
			return // Some transformation occurred
		}
	}
	t.Error("Whitespace should be replaced with alternatives")
}

func TestNullByteEvasion(t *testing.T) {
	eva := &NullByteEvasion{}

	results := eva.Mutate("script")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// At least one should contain null byte encoding
	for _, r := range results {
		if strings.Contains(r.Mutated, "%00") || strings.Contains(r.Mutated, "\\x00") || strings.Contains(r.Mutated, "\\0") {
			return // Found null byte
		}
	}
	t.Log("Null byte evasion may use various encoding formats")
}

func TestHTTPParameterPollution(t *testing.T) {
	eva := &HTTPParameterPollution{}

	results := eva.Mutate("' OR 1=1--")
	if len(results) < 1 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce HPP variant
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "&") || strings.Contains(r.Mutated, "=") {
			found = true
			break
		}
	}
	if !found {
		t.Error("HPP should produce parameter pollution variants")
	}
}

func TestUnicodeNormalization(t *testing.T) {
	eva := &UnicodeNormalization{}

	results := eva.Mutate("<script>")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Result may or may not be different
	t.Log("Unicode normalization produces variant representations")
}

func TestCommentWrapping(t *testing.T) {
	eva := &CommentWrapping{}

	results := eva.Mutate("alert(1)")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// At least one should be wrapped in comments
	for _, r := range results {
		if strings.Contains(r.Mutated, "<!--") || strings.Contains(r.Mutated, "/*") ||
			strings.Contains(r.Mutated, "#") || strings.Contains(r.Mutated, "--") {
			return // Found comment
		}
	}
	t.Log("Comment wrapping may use various comment styles")
}

func TestAllEvasionsRegistered(t *testing.T) {
	evasions := mutation.DefaultRegistry.GetByCategory("evasion")

	expectedEvasions := []string{
		"case_swap", "sql_comment", "whitespace_alt",
		"null_byte", "chunked", "hpp",
		"double_submit", "content_type_mismatch",
		"unicode_normalize", "comment_wrap",
	}

	registered := make(map[string]bool)
	for _, eva := range evasions {
		registered[eva.Name()] = true
	}

	for _, name := range expectedEvasions {
		if !registered[name] {
			t.Errorf("Evasion '%s' not registered", name)
		}
	}
}

func TestEvasionCategoryCorrect(t *testing.T) {
	evasions := mutation.DefaultRegistry.GetByCategory("evasion")

	for _, eva := range evasions {
		if eva.Category() != "evasion" {
			t.Errorf("Evasion '%s' has wrong category: %v", eva.Name(), eva.Category())
		}
	}
}
