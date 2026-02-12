package finding

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors_Wrapping(t *testing.T) {
	wrapped := fmt.Errorf("scanning: %w", ErrTimeout)
	if !errors.Is(wrapped, ErrTimeout) {
		t.Error("errors.Is must work through wrapping for ErrTimeout")
	}
	if errors.Is(wrapped, ErrNoPayloads) {
		t.Error("must not match different sentinel")
	}
}

func TestSentinelErrors_AllDefined(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrTimeout", ErrTimeout, "finding: timeout"},
		{"ErrTargetUnreachable", ErrTargetUnreachable, "finding: target unreachable"},
		{"ErrNoPayloads", ErrNoPayloads, "finding: no payloads available"},
		{"ErrRateLimited", ErrRateLimited, "finding: target rate limiting detected"},
	}

	for _, s := range sentinels {
		t.Run(s.name, func(t *testing.T) {
			if s.err == nil {
				t.Fatalf("%s must not be nil", s.name)
			}
			if got := s.err.Error(); got != s.msg {
				t.Errorf("%s.Error() = %q, want %q", s.name, got, s.msg)
			}
		})
	}
}

func TestSentinelErrors_Distinct(t *testing.T) {
	sentinels := []error{ErrTimeout, ErrTargetUnreachable, ErrNoPayloads, ErrRateLimited}
	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			if errors.Is(sentinels[i], sentinels[j]) {
				t.Errorf("sentinel %d and %d must be distinct", i, j)
			}
		}
	}
}

func TestSentinelErrors_DeepWrapping(t *testing.T) {
	// Three levels of wrapping
	inner := fmt.Errorf("inner: %w", ErrRateLimited)
	middle := fmt.Errorf("middle: %w", inner)
	outer := fmt.Errorf("outer: %w", middle)

	if !errors.Is(outer, ErrRateLimited) {
		t.Error("errors.Is must work through deep wrapping")
	}
}
