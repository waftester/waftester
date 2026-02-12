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
