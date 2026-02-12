package main

import (
	"testing"
)

// TestPrintUsage tests printUsage doesn't panic
func TestPrintUsage(t *testing.T) {
	// Just verify it doesn't panic
	printUsage()
}

// Note: Testing main() directly is challenging because it calls os.Exit().
// The main package is mostly CLI glue code that orchestrates the pkg/ packages.
// The actual functionality is tested in the respective pkg/ packages.
//
// For proper main testing, we would need to:
// 1. Extract command handlers into testable functions
// 2. Use subprocess testing with -test.run
// 3. Use interfaces for dependency injection
//
// Since coverage of pkg/ packages is our priority, this test file
// verifies the basic structure and that helper functions don't crash.

func TestParseIntList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{"empty string", "", nil},
		{"single value", "200", []int{200}},
		{"multiple values", "200,403,500", []int{200, 403, 500}},
		{"values with spaces", " 200 , 403 , 500 ", []int{200, 403, 500}},
		{"trailing comma", "200,403,", []int{200, 403}},
		{"invalid values skipped", "200,abc,500", []int{200, 500}},
		{"all invalid", "abc,def", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIntList(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("parseIntList(%q) = %v (len %d), want %v (len %d)",
					tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("parseIntList(%q)[%d] = %d, want %d", tt.input, i, v, tt.want[i])
				}
			}
		})
	}
}
