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
