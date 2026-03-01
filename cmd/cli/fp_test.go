package main

import (
	"testing"
)

func TestParseCorpusSources(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int // expected number of sources
	}{
		{"all expands", "all", 6}, // all expands to 6 sources
		{"single", "leipzig", 1},
		{"multiple", "leipzig,edge,forms", 3},
		{"with spaces", "leipzig, edge, forms", 3},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCorpusSources(tt.input)
			if len(result) != tt.expected {
				t.Errorf("parseCorpusSources(%q) returned %d items, expected %d", tt.input, len(result), tt.expected)
			}
		})
	}
}

func TestCorpusSourcesAllExpands(t *testing.T) {
	result := parseCorpusSources("all")
	expected := []string{"leipzig", "edge", "forms", "api", "tech", "intl"}
	if len(result) != len(expected) {
		t.Errorf("parseCorpusSources('all') should expand to %d sources, got %d", len(expected), len(result))
		return
	}
	for i, exp := range expected {
		if result[i] != exp {
			t.Errorf("Source %d: expected %q, got %q", i, exp, result[i])
		}
	}
}

func TestCorpusSourcesMultiple(t *testing.T) {
	result := parseCorpusSources("leipzig,edge,api,tech")
	if len(result) != 4 {
		t.Errorf("Expected 4 sources, got %d", len(result))
	}
	expected := []string{"leipzig", "edge", "api", "tech"}
	for i, exp := range expected {
		if result[i] != exp {
			t.Errorf("Source %d: expected %q, got %q", i, exp, result[i])
		}
	}
}

// Note: displayFPResults and runLocalFPTest use UI and external dependencies,
// so they are better tested via integration tests or by mocking.
// The helper functions above handle the pure logic that can be unit tested.
