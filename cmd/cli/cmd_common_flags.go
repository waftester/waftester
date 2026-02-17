package main

import (
	"flag"

	"github.com/waftester/waftester/pkg/input"
)

// CommonFlags holds flags shared across multiple CLI commands (probe, scan, autoscan).
// Use Register to bind these flags to a flag.FlagSet with command-specific defaults.
type CommonFlags struct {
	Targets    input.StringSliceFlag
	ListFile   string
	StdinInput bool
	Timeout    int
	SkipVerify bool
	Verbose    bool
}

// Register binds common flags to the given FlagSet.
// timeoutDefault sets the per-command default for -timeout.
func (cf *CommonFlags) Register(fs *flag.FlagSet, timeoutDefault int) {
	fs.Var(&cf.Targets, "u", "Target URL(s) - comma-separated or repeated")
	fs.Var(&cf.Targets, "target", "Target URL(s)")
	fs.StringVar(&cf.ListFile, "l", "", "File containing target URLs")
	fs.BoolVar(&cf.StdinInput, "stdin", false, "Read targets from stdin")
	fs.IntVar(&cf.Timeout, "timeout", timeoutDefault, "Request timeout in seconds")
	fs.BoolVar(&cf.SkipVerify, "skip-verify", false, "Skip TLS certificate verification")
	fs.BoolVar(&cf.Verbose, "verbose", false, "Verbose output")
	fs.BoolVar(&cf.Verbose, "v", false, "Verbose output (alias)")
}

// TargetSource creates an input.TargetSource from the common flags.
func (cf *CommonFlags) TargetSource() *input.TargetSource {
	return &input.TargetSource{
		URLs:     cf.Targets,
		ListFile: cf.ListFile,
		Stdin:    cf.StdinInput,
	}
}
