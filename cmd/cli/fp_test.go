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

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{"simple", "a,b,c", ",", []string{"a", "b", "c"}},
		{"with spaces", "a, b, c", ",", []string{"a", "b", "c"}},
		{"single", "single", ",", []string{"single"}},
		{"empty returns nil", "", ",", []string{}}, // empty string returns empty slice
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input, tt.sep)
			if len(result) != len(tt.expected) {
				t.Errorf("splitAndTrim(%q, %q) returned %d items, expected %d", tt.input, tt.sep, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("splitAndTrim(%q, %q)[%d] = %q, expected %q", tt.input, tt.sep, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestSplitString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected int
	}{
		{"simple", "a,b,c", ",", 3},
		{"semicolon", "a;b;c", ";", 3},
		{"no sep", "abc", ",", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitString(tt.input, tt.sep)
			if len(result) != tt.expected {
				t.Errorf("splitString(%q, %q) returned %d items, expected %d", tt.input, tt.sep, len(result), tt.expected)
			}
		})
	}
}

func TestTrimString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  hello  ", "hello"},
		{"hello", "hello"},
		{"  ", ""},
		{"", ""},
		{"\t\thello\t\t", "hello"}, // tabs are trimmed
		{"\nhello\n", "\nhello\n"}, // newlines are NOT trimmed
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := trimString(tt.input)
			if result != tt.expected {
				t.Errorf("trimString(%q) = %q, expected %q", tt.input, result, tt.expected)
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
