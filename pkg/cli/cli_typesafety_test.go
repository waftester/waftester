package cli

// Type safety tests for Runner.Run — verifies wrong option types return errors
// instead of panicking. Would have caught A-01 (Round 4).

import (
	"bytes"
	"testing"
)

// TestRun_WrongOptionType_NoP panic verifies that passing the wrong option type
// to each command returns an error rather than panicking via bare type assertion.
func TestRun_WrongOptionType_NoPanic(t *testing.T) {
	t.Parallel()

	cfg := &Config{Timeout: 1}
	runner := NewRunner(cfg, &bytes.Buffer{})

	// Every command paired with a deliberately wrong option type.
	// The string "wrong" is never a valid *XOptions.
	cases := []struct {
		cmd  Command
		opts interface{}
	}{
		{CommandEncode, "wrong"},
		{CommandEvade, 42},
		{CommandBenchmark, struct{}{}},
		{CommandFP, true},
		{CommandHealth, []byte("wrong")},
		{CommandGRPC, nil},
		{CommandSOAP, (*EncodeOptions)(nil)},     // wrong pointer type
		{CommandFTW, &EvasionOptions{}},           // wrong *Options
		{CommandReport, &BenchmarkOptions{}},      // wrong *Options
		{CommandParanoia, &FPOptions{}},           // wrong *Options
		{CommandPlaceholder, &HealthOptions{}},    // wrong *Options
	}

	for _, tc := range cases {
		t.Run(string(tc.cmd), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on wrong type for %s: %v", tc.cmd, r)
				}
			}()
			err := runner.Run(tc.cmd, tc.opts)
			if err == nil {
				t.Errorf("expected error for %s with wrong option type, got nil", tc.cmd)
			}
		})
	}
}

// TestRun_NilOptions verifies nil opts returns error, not panic.
func TestRun_NilOptions(t *testing.T) {
	t.Parallel()

	cfg := &Config{Timeout: 1}
	runner := NewRunner(cfg, &bytes.Buffer{})

	commands := []Command{
		CommandEncode, CommandEvade, CommandBenchmark, CommandFP,
		CommandHealth, CommandGRPC, CommandSOAP, CommandFTW,
		CommandReport, CommandParanoia, CommandPlaceholder,
	}

	for _, cmd := range commands {
		t.Run(string(cmd), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on nil opts for %s: %v", cmd, r)
				}
			}()
			err := runner.Run(cmd, nil)
			if err == nil {
				t.Errorf("expected error for %s with nil opts, got nil", cmd)
			}
		})
	}
}
