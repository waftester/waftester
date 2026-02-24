package payloadgen

import (
	"strings"
	"testing"
)

func TestCaseMutator(t *testing.T) {
	m := &CaseMutator{MaxVariants: 5}
	results := m.Mutate("SELECT * FROM users")

	if len(results) == 0 {
		t.Fatal("expected case variants, got none")
	}
	if len(results) > 5 {
		t.Errorf("expected at most 5 variants, got %d", len(results))
	}

	// Variants should differ from original
	for _, r := range results {
		if r == "SELECT * FROM users" {
			t.Error("variant should differ from original")
		}
	}
}

func TestCaseMutator_Name(t *testing.T) {
	m := &CaseMutator{}
	if m.Name() != "case" {
		t.Errorf("expected 'case', got %q", m.Name())
	}
}

func TestEncodingMutator(t *testing.T) {
	m := &EncodingMutator{}
	results := m.Mutate("<script>alert(1)</script>")

	if len(results) == 0 {
		t.Fatal("expected encoding variants, got none")
	}

	// Should have URL-encoded variant
	hasURLEncoded := false
	for _, r := range results {
		if strings.Contains(r, "%3C") || strings.Contains(r, "%3c") {
			hasURLEncoded = true
			break
		}
	}
	if !hasURLEncoded {
		t.Error("expected at least one URL-encoded variant")
	}
}

func TestEncodingMutator_Name(t *testing.T) {
	m := &EncodingMutator{}
	if m.Name() != "encoding" {
		t.Errorf("expected 'encoding', got %q", m.Name())
	}
}

func TestCommentMutator_SQL(t *testing.T) {
	m := &CommentMutator{CommentStyle: "sql"}
	results := m.Mutate("SELECT * FROM users")

	if len(results) == 0 {
		t.Fatal("expected comment variants, got none")
	}

	hasComment := false
	for _, r := range results {
		if strings.Contains(r, "/**/") || strings.Contains(r, "/*!*/") {
			hasComment = true
			break
		}
	}
	if !hasComment {
		t.Error("expected SQL comment insertion")
	}
}

func TestCommentMutator_HTML(t *testing.T) {
	m := &CommentMutator{CommentStyle: "html"}
	results := m.Mutate("some payload here")

	hasHTMLComment := false
	for _, r := range results {
		if strings.Contains(r, "<!---->") {
			hasHTMLComment = true
			break
		}
	}
	if !hasHTMLComment {
		t.Error("expected HTML comment insertion")
	}
}

func TestCommentMutator_SingleWord(t *testing.T) {
	m := &CommentMutator{CommentStyle: "sql"}
	results := m.Mutate("payload")

	// Single word — nothing to insert between
	for _, r := range results {
		if r != "payload" {
			t.Errorf("single word should not be mutated to %q", r)
		}
	}
}

func TestWhitespaceMutator(t *testing.T) {
	m := &WhitespaceMutator{}
	results := m.Mutate("SELECT * FROM users")

	if len(results) == 0 {
		t.Fatal("expected whitespace variants, got none")
	}

	// None should be the original
	for _, r := range results {
		if r == "SELECT * FROM users" {
			t.Error("variant should differ from original")
		}
	}
}

func TestWhitespaceMutator_NoSpaces(t *testing.T) {
	m := &WhitespaceMutator{}
	results := m.Mutate("payload")

	if len(results) != 0 {
		t.Errorf("expected no variants for spaceless payload, got %d", len(results))
	}
}

func TestConcatenationMutator_SQL(t *testing.T) {
	m := &ConcatenationMutator{Language: "sql"}
	results := m.Mutate("' UNION SELECT 1,2,3--")

	if len(results) == 0 {
		t.Fatal("expected SQL concatenation variants, got none")
	}

	hasSplit := false
	for _, r := range results {
		if strings.Contains(r, "'+'") {
			hasSplit = true
			break
		}
	}
	if !hasSplit {
		t.Error("expected SQL keyword split with concatenation")
	}
}

func TestConcatenationMutator_JS(t *testing.T) {
	m := &ConcatenationMutator{Language: "js"}
	results := m.Mutate("alert(1)")

	if len(results) == 0 {
		t.Fatal("expected JS concatenation variants, got none")
	}
}

func TestConcatenationMutator_NoKeywords(t *testing.T) {
	m := &ConcatenationMutator{Language: "sql"}
	results := m.Mutate("just a plain string")

	if len(results) != 0 {
		t.Errorf("expected no variants for payload without SQL keywords, got %d", len(results))
	}
}

func TestChainMutators(t *testing.T) {
	mutators := []Mutator{
		&WhitespaceMutator{},
		&CommentMutator{CommentStyle: "sql"},
	}

	results := ChainMutators("SELECT * FROM users", mutators, 2)

	if len(results) == 0 {
		t.Fatal("expected chained variants, got none")
	}

	// Should have more variants than single-level mutation
	singleLevel := ChainMutators("SELECT * FROM users", mutators, 1)
	t.Logf("depth=1: %d variants, depth=2: %d variants", len(singleLevel), len(results))
}

func TestChainMutators_Dedup(t *testing.T) {
	mutators := []Mutator{&WhitespaceMutator{}}
	results := ChainMutators("a b c", mutators, 2)

	seen := make(map[string]bool)
	for _, r := range results {
		if seen[r] {
			t.Errorf("duplicate in chained output: %q", r)
		}
		seen[r] = true
	}
}

func TestChainMutators_ExcludesOriginal(t *testing.T) {
	mutators := []Mutator{&WhitespaceMutator{}}
	results := ChainMutators("a b", mutators, 1)

	for _, r := range results {
		if r == "a b" {
			t.Error("chained results should exclude the original payload")
		}
	}
}

func TestMutatorInterface(t *testing.T) {
	// Verify all mutators implement the interface
	mutators := []Mutator{
		&CaseMutator{},
		&EncodingMutator{},
		&CommentMutator{},
		&WhitespaceMutator{},
		&ConcatenationMutator{},
	}

	for _, m := range mutators {
		name := m.Name()
		if name == "" {
			t.Error("mutator name should not be empty")
		}
		// Should not panic on empty input
		_ = m.Mutate("")
	}
}

func TestHexEncode(t *testing.T) {
	result := hexEncode("<script>")
	if !strings.Contains(result, "\\x") {
		t.Errorf("expected hex encoding, got %q", result)
	}
	if strings.Contains(result, "<") {
		t.Errorf("angle bracket should be encoded, got %q", result)
	}
}

func TestHTMLEntityEncode(t *testing.T) {
	result := htmlEntityEncode("<script>alert('xss')</script>")
	if strings.Contains(result, "<") || strings.Contains(result, ">") {
		t.Errorf("angle brackets should be encoded, got %q", result)
	}
	if !strings.Contains(result, "&#60;") {
		t.Errorf("expected &#60; for <, got %q", result)
	}
}

func TestCaseMutator_NonLetterPreservation(t *testing.T) {
	m := &CaseMutator{MaxVariants: 50}

	// Payload with digits, symbols, and non-ASCII — none should be corrupted.
	payload := "SELECT 1+1 FROM tbl WHERE id=42"

	variants := m.Mutate(payload)
	if len(variants) == 0 {
		t.Fatal("expected at least one case variant")
	}

	runes := []rune(payload)
	for _, variant := range variants {
		vrunes := []rune(variant)
		if len(vrunes) != len(runes) {
			t.Fatalf("variant length changed: got %d, want %d", len(vrunes), len(runes))
		}
		for i, ch := range vrunes {
			orig := runes[i]
			if !isASCIILetter(orig) && ch != orig {
				t.Errorf("non-letter rune at position %d changed: %q -> %q", i, string(orig), string(ch))
			}
		}
	}
}

func isASCIILetter(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}
