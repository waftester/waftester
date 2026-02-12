package payloads

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
		{"ErrPayloadNotFound", ErrPayloadNotFound, "payloads: payload not found"},
		{"ErrInvalidPayload", ErrInvalidPayload, "payloads: invalid payload"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatalf("%s must not be nil", tt.name)
			}
			if got := tt.err.Error(); got != tt.msg {
				t.Errorf("%s.Error() = %q, want %q", tt.name, got, tt.msg)
			}

			wrapped := fmt.Errorf("load: %w", tt.err)
			if !errors.Is(wrapped, tt.err) {
				t.Errorf("errors.Is must work through wrapping for %s", tt.name)
			}
		})
	}
}

func TestSentinelErrors_Distinct(t *testing.T) {
	if errors.Is(ErrPayloadNotFound, ErrInvalidPayload) {
		t.Error("ErrPayloadNotFound and ErrInvalidPayload must be distinct")
	}
}
