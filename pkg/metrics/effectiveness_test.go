package metrics

import (
	"math"
	"testing"
)

func TestCalcEffectiveness(t *testing.T) {
	tests := []struct {
		name    string
		blocked int
		failed  int
		want    float64
	}{
		{"typical scan", 937, 350, 72.80},
		{"all blocked", 100, 0, 100.0},
		{"all failed", 0, 100, 0.0},
		{"no tests", 0, 0, 0.0},
		{"one blocked", 1, 0, 100.0},
		{"one failed", 0, 1, 0.0},
		{"equal split", 50, 50, 50.0},
		{"high effectiveness", 950, 50, 95.0},
		{"low effectiveness", 100, 900, 10.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalcEffectiveness(tt.blocked, tt.failed)
			// Allow 0.01% tolerance for floating point
			if math.Abs(got-tt.want) > 0.01 {
				t.Errorf("CalcEffectiveness(%d, %d) = %.4f, want %.4f", tt.blocked, tt.failed, got, tt.want)
			}
		})
	}
}

func TestCalcEffectiveness_ExcludesSkipped(t *testing.T) {
	// The key insight: skipped tests should NOT dilute effectiveness.
	// With 937 blocked, 350 failed: effectiveness = 72.8%
	// If we incorrectly included 3239 skipped: effectiveness = 937/4526 = 20.7%
	// The correct formula gives consistent results regardless of skipped count.
	blocked := 937
	failed := 350
	got := CalcEffectiveness(blocked, failed)

	want := float64(blocked) / float64(blocked+failed) * 100
	if math.Abs(got-want) > 0.001 {
		t.Errorf("CalcEffectiveness(%d, %d) = %.4f, want %.4f", blocked, failed, got, want)
	}
}

func TestRateEffectiveness(t *testing.T) {
	tests := []struct {
		pct  float64
		want string
	}{
		{100.0, "Excellent"},
		{99.5, "Excellent"},
		{99.0, "Excellent"},
		{98.9, "Good"},
		{95.0, "Good"},
		{94.9, "Fair"},
		{90.0, "Fair"},
		{89.9, "Poor"},
		{80.0, "Poor"},
		{79.9, "Critical"},
		{50.0, "Critical"},
		{0.0, "Critical"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := RateEffectiveness(tt.pct)
			if got != tt.want {
				t.Errorf("RateEffectiveness(%.1f) = %q, want %q", tt.pct, got, tt.want)
			}
		})
	}
}
