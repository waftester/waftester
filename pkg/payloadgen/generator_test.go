package payloadgen

import (
	"strings"
	"testing"
)

func TestNewGenerator_HasDefaults(t *testing.T) {
	g := NewGenerator()
	categories := []string{"sqli", "xss", "ssti", "lfi", "ssrf", "rce"}
	for _, cat := range categories {
		if len(g.Templates[cat]) == 0 {
			t.Errorf("expected default templates for %q, got none", cat)
		}
	}
}

func TestGenerate_SQLi(t *testing.T) {
	g := NewGenerator()
	results := g.Generate(GenerationContext{
		Category:    "sqli",
		MaxPayloads: 50,
	})

	if len(results) == 0 {
		t.Fatal("expected sqli payloads, got none")
	}
	if len(results) > 50 {
		t.Errorf("expected at most 50 payloads, got %d", len(results))
	}

	// Verify some payloads contain SQL keywords
	hasSQLKeyword := false
	for _, p := range results {
		upper := strings.ToUpper(p)
		if strings.Contains(upper, "UNION") || strings.Contains(upper, "SELECT") ||
			strings.Contains(upper, "OR") || strings.Contains(upper, "DROP") {
			hasSQLKeyword = true
			break
		}
	}
	if !hasSQLKeyword {
		t.Error("expected at least one payload with SQL keywords")
	}
}

func TestGenerate_XSS(t *testing.T) {
	g := NewGenerator()
	results := g.Generate(GenerationContext{
		Category:    "xss",
		MaxPayloads: 100,
	})

	if len(results) == 0 {
		t.Fatal("expected xss payloads, got none")
	}

	// Check for HTML tags
	hasHTMLTag := false
	for _, p := range results {
		if strings.Contains(p, "<") || strings.Contains(p, "script") ||
			strings.Contains(p, "javascript") {
			hasHTMLTag = true
			break
		}
	}
	if !hasHTMLTag {
		t.Error("expected at least one payload with HTML/JS content")
	}
}

func TestGenerate_AllCategories(t *testing.T) {
	g := NewGenerator()
	results := g.Generate(GenerationContext{})

	if len(results) == 0 {
		t.Fatal("expected payloads from all categories, got none")
	}
	t.Logf("generated %d payloads across all categories", len(results))
}

func TestGenerate_Deduplication(t *testing.T) {
	g := NewGenerator()
	results := g.Generate(GenerationContext{Category: "sqli"})

	seen := make(map[string]bool)
	for _, p := range results {
		if seen[p] {
			t.Errorf("duplicate payload: %q", p)
		}
		seen[p] = true
	}
}

func TestGenerate_BlockedPatterns(t *testing.T) {
	g := NewGenerator()
	results := g.Generate(GenerationContext{
		Category:        "sqli",
		BlockedPatterns: []string{"UNION"},
	})

	for _, p := range results {
		if strings.Contains(strings.ToUpper(p), "UNION") {
			t.Errorf("payload should not contain UNION: %q", p)
		}
	}
}

func TestGenerate_MaxPayloads(t *testing.T) {
	g := NewGenerator()
	results := g.Generate(GenerationContext{
		Category:    "sqli",
		MaxPayloads: 5,
	})

	if len(results) > 5 {
		t.Errorf("expected at most 5 payloads, got %d", len(results))
	}
}

func TestGenerate_WithMutators(t *testing.T) {
	g := NewGenerator()
	g.Mutators = []Mutator{&WhitespaceMutator{}}

	withoutMutators := NewGenerator()
	baseResults := withoutMutators.Generate(GenerationContext{Category: "sqli", MaxPayloads: 10})
	mutatedResults := g.Generate(GenerationContext{Category: "sqli", MaxPayloads: 100})

	// Mutators should produce more variants
	if len(mutatedResults) <= len(baseResults) {
		t.Errorf("expected more results with mutators: base=%d, mutated=%d",
			len(baseResults), len(mutatedResults))
	}
}

func TestAddTemplate(t *testing.T) {
	g := NewGenerator()
	g.AddTemplate("custom", PayloadTemplate{
		Pattern: "CUSTOM-{{val}}",
		Variables: map[string][]string{
			"val": {"a", "b", "c"},
		},
	})

	results := g.Generate(GenerationContext{Category: "custom"})
	if len(results) != 3 {
		t.Errorf("expected 3 custom payloads, got %d", len(results))
	}
	for _, r := range results {
		if !strings.HasPrefix(r, "CUSTOM-") {
			t.Errorf("expected CUSTOM- prefix, got %q", r)
		}
	}
}

func TestExpandTemplate_NoVariables(t *testing.T) {
	tmpl := PayloadTemplate{Pattern: "static-payload"}
	results := expandTemplate(tmpl)
	if len(results) != 1 || results[0] != "static-payload" {
		t.Errorf("expected single static payload, got %v", results)
	}
}

func TestExpandTemplate_Cartesian(t *testing.T) {
	tmpl := PayloadTemplate{
		Pattern: "{{a}}-{{b}}",
		Variables: map[string][]string{
			"a": {"1", "2"},
			"b": {"x", "y"},
		},
	}
	results := expandTemplate(tmpl)
	if len(results) != 4 {
		t.Errorf("expected 4 combinations, got %d: %v", len(results), results)
	}
}

func TestCartesian_Empty(t *testing.T) {
	result := cartesian(nil)
	if len(result) != 1 || len(result[0]) != 0 {
		t.Errorf("expected single empty combination, got %v", result)
	}
}

func TestBlocked(t *testing.T) {
	if !blocked("test UNION select", []string{"union"}) {
		t.Error("should detect blocked pattern 'union' case-insensitively")
	}
	if blocked("test query", []string{"union"}) {
		t.Error("should not block 'test query' against 'union'")
	}
	if blocked("anything", nil) {
		t.Error("nil patterns should not block anything")
	}
}
