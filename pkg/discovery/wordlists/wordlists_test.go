package wordlists

import (
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	for _, fw := range Frameworks {
		routes, err := Load(fw)
		if err != nil {
			t.Fatalf("framework %s should load: %v", fw, err)
		}
		if len(routes) < 20 {
			t.Errorf("framework %s has only %d routes, expected >20", fw, len(routes))
		}
		for _, r := range routes {
			if r == "" {
				t.Errorf("framework %s: empty route found", fw)
			}
			if strings.HasPrefix(r, "#") {
				t.Errorf("framework %s: comment leaked through: %s", fw, r)
			}
		}
	}
}

func TestLoad_UnknownFramework(t *testing.T) {
	_, err := Load("nonexistent")
	if err == nil {
		t.Error("expected error for unknown framework")
	}
}

func TestLoadMultiple(t *testing.T) {
	routes, err := LoadMultiple([]string{"rails", "spring"})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) < 50 {
		t.Errorf("expected >50 combined routes, got %d", len(routes))
	}

	// Verify deduplication
	seen := make(map[string]bool)
	for _, r := range routes {
		if seen[r] {
			t.Errorf("duplicate route: %s", r)
		}
		seen[r] = true
	}
}

func TestLoadAll(t *testing.T) {
	all := LoadAll()
	if len(all) < 200 {
		t.Errorf("expected >200 total routes, got %d", len(all))
	}

	// Verify deduplication
	seen := make(map[string]bool)
	for _, r := range all {
		if seen[r] {
			t.Errorf("duplicate route: %s", r)
		}
		seen[r] = true
	}
}

func TestDetectFrameworks(t *testing.T) {
	tests := []struct {
		name     string
		techs    []string
		expected []string
	}{
		{
			name:     "Ruby on Rails",
			techs:    []string{"Ruby", "Rails 7"},
			expected: []string{"rails", "generic-api"},
		},
		{
			name:     "Spring Boot",
			techs:    []string{"Spring Boot", "Java"},
			expected: []string{"spring", "generic-api"},
		},
		{
			name:     "Express.js",
			techs:    []string{"Node.js", "Express"},
			expected: []string{"express", "generic-api"},
		},
		{
			name:     "unknown tech",
			techs:    []string{"unknown-framework"},
			expected: []string{"generic-api"},
		},
		{
			name:     "empty techs",
			techs:    nil,
			expected: []string{"generic-api"},
		},
		{
			name:     "WordPress",
			techs:    []string{"WordPress 6.4", "PHP"},
			expected: []string{"wordpress", "laravel", "generic-api"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectFrameworks(tt.techs)
			for _, exp := range tt.expected {
				found := false
				for _, r := range result {
					if r == exp {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected %q in result %v", exp, result)
				}
			}
		})
	}
}

func TestDetectFrameworks_AlwaysIncludesGenericAPI(t *testing.T) {
	result := DetectFrameworks([]string{"Rails"})

	found := false
	for _, r := range result {
		if r == "generic-api" {
			found = true
			break
		}
	}
	if !found {
		t.Error("generic-api should always be included")
	}
}
