package main

import (
	"fmt"
	"os"

	"github.com/waftester/waftester/pkg/ui"
)

// exitWithError prints a formatted error message and exits with code 1.
// Use this instead of ui.PrintError + os.Exit(1) for consistent CLI error handling.
func exitWithError(format string, args ...any) {
	ui.PrintError(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// exitWithUsage prints an error message followed by a usage hint, then exits.
func exitWithUsage(msg, usage string) {
	ui.PrintError(msg)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Usage:", usage)
	os.Exit(1)
}
