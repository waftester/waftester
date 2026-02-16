package mcpserver

import (
	"testing"

	"github.com/waftester/waftester/pkg/templateresolver"
)

// TestTemplateDescriptions_CoverAllTemplates verifies that every embedded
// template has a matching entry in templateDescriptions. Catches drift when
// templates are added or renamed.
func TestTemplateDescriptions_CoverAllTemplates(t *testing.T) {
	categories := templateresolver.ListAllCategories()
	var missing []string

	for _, cat := range categories {
		infos, err := templateresolver.ListCategory(cat.Kind)
		if err != nil {
			t.Fatalf("ListCategory(%s): %v", cat.Kind, err)
		}
		for _, info := range infos {
			key := string(info.Kind) + "/" + info.Name
			if _, ok := templateDescriptions[key]; !ok {
				missing = append(missing, key)
			}
		}
	}

	if len(missing) > 0 {
		t.Errorf("templateDescriptions missing %d entries (add descriptions for new templates):\n", len(missing))
		for _, m := range missing {
			t.Errorf("  %q", m)
		}
	}
}

// TestTemplateDescriptions_NoStaleEntries verifies that templateDescriptions
// contains no entries for templates that no longer exist in the embedded FS.
func TestTemplateDescriptions_NoStaleEntries(t *testing.T) {
	// Build a set of all valid keys from the embedded FS.
	valid := make(map[string]bool)
	for _, cat := range templateresolver.ListAllCategories() {
		infos, err := templateresolver.ListCategory(cat.Kind)
		if err != nil {
			t.Fatalf("ListCategory(%s): %v", cat.Kind, err)
		}
		for _, info := range infos {
			valid[string(info.Kind)+"/"+info.Name] = true
		}
	}

	for key := range templateDescriptions {
		if !valid[key] {
			t.Errorf("templateDescriptions has stale entry %q — template no longer exists", key)
		}
	}
}

// TestValidKindStrings_MatchesResolver verifies that validKindStrings() returns
// exactly the set of kinds from ListAllCategories, catching any drift between
// the tool's enum schema and the resolver's actual categories.
func TestValidKindStrings_MatchesResolver(t *testing.T) {
	kinds := validKindStrings()
	categories := templateresolver.ListAllCategories()

	if len(kinds) != len(categories) {
		t.Fatalf("validKindStrings() returned %d kinds, resolver has %d categories",
			len(kinds), len(categories))
	}

	catSet := make(map[string]bool, len(categories))
	for _, cat := range categories {
		catSet[string(cat.Kind)] = true
	}

	for _, kind := range kinds {
		if !catSet[kind] {
			t.Errorf("validKindStrings() contains %q which is not a resolver category", kind)
		}
	}
}
