// Regression tests for retry backoff overflow (from 85-fix adversarial review).
//
// Bug: CalcDelay used raw integer multiplication for exponential backoff,
// which overflowed int64 at high attempt numbers, producing negative durations.
// Fix: Use float64 arithmetic with explicit overflow/infinity checks.
package retry

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCalcDelay_ExponentialOverflowRegression verifies that exponential backoff
// never produces a negative, zero, or >MaxDelay duration at extreme attempt counts.
// Regression: int64(initDelay * 2^attempt) overflowed for attempt >= 63.
func TestCalcDelay_ExponentialOverflowRegression(t *testing.T) {
	t.Parallel()

	cfg := Config{
		InitDelay: 1 * time.Second,
		MaxDelay:  30 * time.Second,
		Strategy:  Exponential,
		Jitter:    false,
	}

	// Test all powers of 2 that would overflow int64
	overflowAttempts := []int{62, 63, 64, 100, 255, 1000, math.MaxInt32}
	for _, attempt := range overflowAttempts {
		delay := CalcDelay(cfg, attempt)
		require.True(t, delay > 0, "attempt %d: delay must be positive, got %v", attempt, delay)
		require.True(t, delay <= cfg.MaxDelay, "attempt %d: delay %v exceeds MaxDelay %v", attempt, delay, cfg.MaxDelay)
	}
}

// TestCalcDelay_LinearNoNegative ensures linear backoff never produces negative delays.
func TestCalcDelay_LinearNoNegative(t *testing.T) {
	t.Parallel()

	cfg := Config{
		InitDelay: 1 * time.Second,
		MaxDelay:  30 * time.Second,
		Strategy:  Linear,
		Jitter:    false,
	}

	// At very high attempt counts, initDelay * (attempt+1) could overflow
	for _, attempt := range []int{0, 1, 100, math.MaxInt32} {
		delay := CalcDelay(cfg, attempt)
		assert.True(t, delay >= 0, "attempt %d: delay must be non-negative, got %v", attempt, delay)
		assert.True(t, delay <= cfg.MaxDelay, "attempt %d: delay %v exceeds MaxDelay %v", attempt, delay, cfg.MaxDelay)
	}
}

// TestCalcDelay_JitterNeverExceedsMax confirms jitter cannot push delay above MaxDelay.
// Regression: jitter was added after overflow cap but before re-cap.
func TestCalcDelay_JitterNeverExceedsMax(t *testing.T) {
	t.Parallel()

	cfg := Config{
		InitDelay: 25 * time.Second,
		MaxDelay:  30 * time.Second,
		Strategy:  Exponential,
		Jitter:    true,
	}

	// Run many iterations — jitter is random; some attempts land near MaxDelay
	for i := 0; i < 1000; i++ {
		delay := CalcDelay(cfg, 1) // 25s * 2^1 = 50s → capped to 30s, then jitter
		assert.True(t, delay <= cfg.MaxDelay,
			"iteration %d: jitter pushed delay %v above MaxDelay %v", i, delay, cfg.MaxDelay)
		assert.True(t, delay > 0, "iteration %d: delay must be positive", i)
	}
}

// TestCalcDelay_ZeroMaxDelayPanics verifies behavior with edge-case config.
func TestCalcDelay_ZeroInitDelay(t *testing.T) {
	t.Parallel()

	cfg := Config{
		InitDelay: 0,
		MaxDelay:  30 * time.Second,
		Strategy:  Exponential,
		Jitter:    false,
	}

	delay := CalcDelay(cfg, 5)
	assert.Equal(t, time.Duration(0), delay, "zero InitDelay should produce zero delay")
}
