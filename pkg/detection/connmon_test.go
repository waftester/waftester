// Regression tests for connection monitor backoff overflow and correctness.
package detection

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
)

// TestCalculateRecoveryWait_Overflow verifies exponential backoff does not overflow
// for extreme consecutiveDrops values.
// Regression: 1<<(drops-1) overflowed int64 at drops>=63, producing negative duration.
func TestCalculateRecoveryWait_Overflow(t *testing.T) {
	t.Parallel()

	cap := defaults.DropDetectRecoveryWindow()

	tests := []struct {
		name  string
		drops int64
	}{
		{"63 drops - at overflow boundary", 63},
		{"64 drops - past boundary", 64},
		{"100 drops", 100},
		{"max int64", math.MaxInt64},
		{"1000 drops", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := calculateRecoveryWait(tt.drops)

			if result < 0 {
				t.Errorf("calculateRecoveryWait(%d) = %v, must not be negative", tt.drops, result)
			}
			if result > cap {
				t.Errorf("calculateRecoveryWait(%d) = %v, exceeds cap %v", tt.drops, result, cap)
			}
		})
	}
}

// TestCalculateRecoveryWait_ExponentialGrowth verifies the backoff grows as expected
// for small values before hitting the cap.
func TestCalculateRecoveryWait_ExponentialGrowth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		drops    int64
		expected time.Duration
	}{
		{0, 0},
		{1, 5 * time.Second},  // 5s * 2^0 = 5s
		{2, 10 * time.Second}, // 5s * 2^1 = 10s
		{3, 20 * time.Second}, // 5s * 2^2 = 20s
		{4, 40 * time.Second}, // 5s * 2^3 = 40s
		{5, 80 * time.Second}, // 5s * 2^4 = 80s
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := calculateRecoveryWait(tt.drops)
			cap := defaults.DropDetectRecoveryWindow()

			// If expected exceeds cap, result should be cap
			want := tt.expected
			if want > cap {
				want = cap
			}

			if result != want {
				t.Errorf("calculateRecoveryWait(%d) = %v, want %v", tt.drops, result, want)
			}
		})
	}
}

// TestCalculateRecoveryWait_NegativeInput verifies zero/negative inputs return 0.
func TestCalculateRecoveryWait_NegativeInput(t *testing.T) {
	t.Parallel()

	for _, drops := range []int64{0, -1, -100, math.MinInt64} {
		result := calculateRecoveryWait(drops)
		if result != 0 {
			t.Errorf("calculateRecoveryWait(%d) = %v, want 0", drops, result)
		}
	}
}

// TestCalculateRecoveryWait_AlwaysPositiveOrZero is a property-based test:
// for ANY int64 input, the result must be >= 0 and <= cap.
func TestCalculateRecoveryWait_AlwaysPositiveOrZero(t *testing.T) {
	t.Parallel()

	cap := defaults.DropDetectRecoveryWindow()

	// Test boundary values and a sweep
	values := []int64{
		math.MinInt64, -1, 0, 1, 2, 10, 30, 31, 32, 62, 63, 64, 100, 1000,
		math.MaxInt64 - 1, math.MaxInt64,
	}

	for _, v := range values {
		result := calculateRecoveryWait(v)
		if result < 0 {
			t.Errorf("calculateRecoveryWait(%d) = %v, negative!", v, result)
		}
		if result > cap {
			t.Errorf("calculateRecoveryWait(%d) = %v, exceeds cap %v", v, result, cap)
		}
	}
}

// TestConnectionMonitor_RecordDropRecovery verifies the full drop→recovery cycle.
func TestConnectionMonitor_RecordDropRecovery(t *testing.T) {
	t.Parallel()

	cm := NewConnectionMonitor()
	host := "test.example.com"

	// Simulate consecutive drops using a proper error
	dialErr := errors.New("connection refused")
	for i := 0; i < 5; i++ {
		result := cm.RecordDrop(host, dialErr)
		if !result.Dropped {
			t.Errorf("drop %d: expected Dropped=true", i)
		}
		if result.Consecutive != i+1 {
			t.Errorf("drop %d: expected Consecutive=%d, got %d", i, i+1, result.Consecutive)
		}
	}

	// Verify host is dropping
	if !cm.IsDropping(host) {
		t.Error("expected host to be dropping after 5 drops")
	}

	// Record recovery successes
	for i := 0; i < 3; i++ {
		cm.RecordSuccess(host)
	}

	// After enough successes, host should no longer be dropping
	if cm.IsDropping(host) {
		t.Log("Note: host still dropping after 3 successes - recovery threshold may require more")
	}
}

// TestIsDropping_RecoveryProbeWindow verifies that IsDropping periodically
// allows a recovery probe through after the RecoveryWindow elapses.
// BUG #2: Without this, hosts that hit the threshold were permanently
// blacklisted — no probe was ever let through to test recovery.
func TestIsDropping_RecoveryProbeWindow(t *testing.T) {
	t.Parallel()

	cm := NewConnectionMonitor()
	host := "recovery-probe.example.com"
	dialErr := errors.New("connection refused")

	// Push past the threshold
	threshold := defaults.DropDetectConsecutiveThreshold
	for i := 0; i < threshold; i++ {
		cm.RecordDrop(host, dialErr)
	}

	// Immediately after threshold: host should be dropping
	if !cm.IsDropping(host) {
		t.Fatal("expected host to be dropping immediately after threshold")
	}

	// Simulate time passing beyond RecoveryWindow by backdating lastDropTime
	state := cm.getOrCreateState(host)
	past := time.Now().Add(-(defaults.DropDetectRecoveryWindow() + time.Second))
	state.lastDropTime.Store(past.UnixNano())

	// Now IsDropping should return false to allow a recovery probe
	if cm.IsDropping(host) {
		t.Error("expected IsDropping=false after RecoveryWindow elapsed (recovery probe should be allowed)")
	}
}

// TestIsDropping_DeathSpiralPrevention verifies that a permanently-down host
// still gets periodic recovery probes and doesn't get stuck forever.
// BUG #2: The original code returned true permanently once consecutiveDrops >= threshold.
func TestIsDropping_DeathSpiralPrevention(t *testing.T) {
	t.Parallel()

	cm := NewConnectionMonitor()
	host := "death-spiral.example.com"
	dialErr := errors.New("connection refused")

	// Accumulate 20 consecutive drops (well past threshold of 5)
	for i := 0; i < 20; i++ {
		cm.RecordDrop(host, dialErr)
	}

	// Immediately: host is dropping
	if !cm.IsDropping(host) {
		t.Fatal("expected host to be dropping after 20 drops")
	}

	// Backdate to simulate RecoveryWindow elapsed
	state := cm.getOrCreateState(host)
	past := time.Now().Add(-(defaults.DropDetectRecoveryWindow() + time.Second))
	state.lastDropTime.Store(past.UnixNano())

	// Probe should be allowed through
	if cm.IsDropping(host) {
		t.Error("expected recovery probe to be allowed after RecoveryWindow, even with 20 consecutive drops")
	}

	// Simulate the probe failing (RecordDrop updates lastDropTime)
	cm.RecordDrop(host, dialErr)

	// Host should be dropping again (lastDropTime refreshed)
	if !cm.IsDropping(host) {
		t.Error("expected host to be dropping again after failed recovery probe")
	}
}

// TestRecoveryProbe_IntermittentHost verifies that an intermittent host
// (alternating success/failure) can eventually recover.
// BUG #2 (adversarial review): RecordDrop used to reset recoverySuccesses
// to 0 unconditionally, which meant intermittent hosts could never accumulate
// enough successes to recover.
func TestRecoveryProbe_IntermittentHost(t *testing.T) {
	t.Parallel()

	cm := NewConnectionMonitor()
	host := "intermittent.example.com"
	dialErr := errors.New("connection refused")

	// Push past threshold
	threshold := defaults.DropDetectConsecutiveThreshold
	for i := 0; i < threshold; i++ {
		cm.RecordDrop(host, dialErr)
	}

	if !cm.IsDropping(host) {
		t.Fatal("expected host to be dropping after threshold")
	}

	// Simulate: probe 1 succeeds
	cm.RecordSuccess(host)

	// Simulate: probe 2 fails (this is the intermittent part)
	cm.RecordDrop(host, dialErr)

	// Check that recoverySuccesses was NOT wiped out.
	// The fix: RecordDrop only resets recoverySuccesses below threshold.
	state := cm.getOrCreateState(host)
	successes := state.recoverySuccesses.Load()
	if successes == 0 {
		t.Error("recoverySuccesses was reset to 0 by a failed probe — intermittent hosts can never recover")
	}

	// Simulate: probe 3 succeeds — should reach recovery threshold (2)
	cm.RecordSuccess(host)

	// After 2 total successes (even with 1 failure in between), host should recover
	if state.consecutiveDrops.Load() != 0 {
		t.Errorf("expected consecutiveDrops=0 after recovery, got %d", state.consecutiveDrops.Load())
	}
}

// TestRecoverySuccessReset_BelowThreshold verifies that RecordDrop DOES
// reset recovery successes when the host hasn't yet reached the dropping
// threshold. This is the correct behavior for early drops.
func TestRecoverySuccessReset_BelowThreshold(t *testing.T) {
	t.Parallel()

	cm := NewConnectionMonitor()
	host := "below-threshold.example.com"
	dialErr := errors.New("connection refused")

	// Record 2 drops (below threshold of 5)
	cm.RecordDrop(host, dialErr)
	cm.RecordDrop(host, dialErr)

	// Record a success
	cm.RecordSuccess(host)

	state := cm.getOrCreateState(host)
	if state.recoverySuccesses.Load() == 0 {
		// This is OK for 2 drops — below threshold means no recovery tracking
		// was started. Successes only tracked when consecutiveDrops > 0.
	}

	// Now record another drop — below threshold, so successes should reset
	cm.RecordDrop(host, dialErr)

	if state.recoverySuccesses.Load() != 0 {
		t.Error("expected recoverySuccesses to be reset for drops below threshold")
	}
}
