package runner

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors_Wrapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrHostBlocked", ErrHostBlocked, "runner: host blocked"},
		{"ErrAllHostsFailed", ErrAllHostsFailed, "runner: all hosts failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatalf("%s must not be nil", tt.name)
			}
			if got := tt.err.Error(); got != tt.msg {
				t.Errorf("%s.Error() = %q, want %q", tt.name, got, tt.msg)
			}

			wrapped := fmt.Errorf("scan: %w", tt.err)
			if !errors.Is(wrapped, tt.err) {
				t.Errorf("errors.Is must work through wrapping for %s", tt.name)
			}
		})
	}
}

func TestSentinelErrors_Distinct(t *testing.T) {
	if errors.Is(ErrHostBlocked, ErrAllHostsFailed) {
		t.Error("ErrHostBlocked and ErrAllHostsFailed must be distinct")
	}
}
