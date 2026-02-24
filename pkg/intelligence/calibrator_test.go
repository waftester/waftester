package intelligence

import (
	"sync"
	"testing"
	"time"
)

func TestCUSUM_DetectsIncreaseShift(t *testing.T) {
	// Buffered so the goroutine never blocks if the test has already moved on.
	fired := make(chan string, 1)

	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             5.0,
		DriftAllowance:        0.5,
		MinObservations:       10,
		RecalibrationCooldown: 0, // No cooldown for testing
	}, func(metric string, _ float64) {
		select {
		case fired <- metric:
		default:
		}
	})

	cpd.SetBaseline("block_rate", 0.3)

	// Feed 15 observations at baseline to satisfy MinObservations
	for i := 0; i < 15; i++ {
		cpd.Observe("block_rate", 0.3)
	}
	// No detection should have fired yet.
	select {
	case <-fired:
		t.Fatal("false alarm during baseline period")
	default:
	}

	// Shift up significantly (deviation=1.2, drift=0.5, net +0.7/obs → exceeds threshold=5.0 in ~8 obs)
	for i := 0; i < 20; i++ {
		cpd.Observe("block_rate", 1.5)
	}

	// Wait for the async callback goroutine to fire.
	select {
	case metric := <-fired:
		if metric != "block_rate" {
			t.Fatalf("wrong metric: got %q, want %q", metric, "block_rate")
		}
	case <-time.After(time.Second):
		t.Fatal("CUSUM failed to detect upward shift within 1s")
	}
}

func TestCUSUM_DetectsDecreaseShift(t *testing.T) {
	fired := make(chan struct{}, 1)

	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             5.0,
		DriftAllowance:        0.5,
		MinObservations:       10,
		RecalibrationCooldown: 0,
	}, func(_ string, _ float64) {
		select {
		case fired <- struct{}{}:
		default:
		}
	})

	cpd.SetBaseline("latency", 100.0)

	// Baseline observations
	for i := 0; i < 15; i++ {
		cpd.Observe("latency", 100.0)
	}

	// Shift down
	for i := 0; i < 50; i++ {
		cpd.Observe("latency", 20.0)
	}

	select {
	case <-fired:
		// detected — pass
	case <-time.After(time.Second):
		t.Fatal("CUSUM failed to detect downward shift within 1s")
	}
}

func TestCUSUM_IgnoresNoise(t *testing.T) {
	var detected bool

	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             5.0,
		DriftAllowance:        0.5,
		MinObservations:       10,
		RecalibrationCooldown: 0,
	}, func(_ string, _ float64) {
		detected = true
	})

	cpd.SetBaseline("block_rate", 0.5)

	// Feed 50 observations with small noise around baseline
	for i := 0; i < 50; i++ {
		// Oscillate slightly: 0.5 ± 0.1
		value := 0.5
		if i%2 == 0 {
			value = 0.55
		} else {
			value = 0.45
		}
		cpd.Observe("block_rate", value)
	}

	if detected {
		t.Fatal("CUSUM triggered on noise within drift allowance")
	}
}

func TestCUSUM_MinObservationsRespected(t *testing.T) {
	var detected bool

	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             1.0, // Very sensitive
		DriftAllowance:        0.1,
		MinObservations:       20,
		RecalibrationCooldown: 0,
	}, func(_ string, _ float64) {
		detected = true
	})

	cpd.SetBaseline("block_rate", 0.3)

	// Feed large deviations but fewer than MinObservations
	for i := 0; i < 19; i++ {
		cpd.Observe("block_rate", 0.95)
	}

	if detected {
		t.Fatal("detected change before min observations reached")
	}
}

func TestCUSUM_ResetClearsState(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd.SetBaseline("metric_a", 1.0)

	// Accumulate some CUSUM state (value 2.0 gives deviation=1.0, drift=0.5, net +0.5/obs)
	for i := 0; i < 30; i++ {
		cpd.Observe("metric_a", 2.0)
	}

	state, ok := cpd.GetMetricState("metric_a")
	if !ok {
		t.Fatal("metric_a not found")
	}
	if state.SumHigh == 0 && state.SumLow == 0 {
		t.Fatal("expected non-zero CUSUM sums before reset")
	}

	// Reset
	cpd.ResetMetric("metric_a", 2.0)

	state, _ = cpd.GetMetricState("metric_a")
	if state.SumHigh != 0 || state.SumLow != 0 {
		t.Fatalf("CUSUM sums not reset: high=%f, low=%f", state.SumHigh, state.SumLow)
	}
	if state.Baseline != 2.0 {
		t.Fatalf("baseline not updated: got %f, want 2.0", state.Baseline)
	}
}

func TestCUSUM_CooldownPreventsSpam(t *testing.T) {
	// Buffered channel: capacity > 1 to detect spurious extra callbacks.
	fired := make(chan struct{}, 10)

	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             2.0,
		DriftAllowance:        0.3,
		MinObservations:       5,
		RecalibrationCooldown: 1 * time.Hour, // Very long cooldown
	}, func(_ string, _ float64) {
		select {
		case fired <- struct{}{}:
		default:
		}
	})

	cpd.SetBaseline("block_rate", 0.3)

	// Warm up past MinObservations
	for i := 0; i < 10; i++ {
		cpd.Observe("block_rate", 0.3)
	}

	// Feed many extreme values — should only trigger once due to cooldown
	for i := 0; i < 100; i++ {
		cpd.Observe("block_rate", 0.95)
	}

	// Wait for the one expected callback goroutine.
	select {
	case <-fired:
		// first (and only expected) detection
	case <-time.After(time.Second):
		t.Fatal("expected 1 detection with cooldown, got 0")
	}

	// Brief pause to let any spurious goroutines drain before checking.
	time.Sleep(50 * time.Millisecond)
	if extra := len(fired); extra > 0 {
		t.Fatalf("expected 1 detection with cooldown, got %d", 1+extra)
	}
}

func TestCUSUM_AutoCreatesMetricOnFirstObservation(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)

	// Observe without SetBaseline — should auto-create
	cpd.Observe("new_metric", 42.0)

	if cpd.MetricCount() != 1 {
		t.Fatalf("expected 1 metric, got %d", cpd.MetricCount())
	}

	state, ok := cpd.GetMetricState("new_metric")
	if !ok {
		t.Fatal("auto-created metric not found")
	}
	if state.Baseline != 42.0 {
		t.Fatalf("baseline should be first observation: got %f, want 42.0", state.Baseline)
	}
}

func TestCUSUM_IsStableReturnsCorrectly(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)

	// Unknown metric = stable
	if !cpd.IsStable("unknown") {
		t.Fatal("unknown metric should be stable")
	}

	cpd.SetBaseline("metric", 1.0)
	if !cpd.IsStable("metric") {
		t.Fatal("fresh metric should be stable")
	}
}

func TestCUSUM_ExportImport(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd.SetBaseline("block_rate", 0.3)
	cpd.SetBaseline("latency", 50.0)

	for i := 0; i < 10; i++ {
		cpd.Observe("block_rate", 0.35)
		cpd.Observe("latency", 52.0)
	}

	exported := cpd.Export()

	// Import into fresh detector
	cpd2 := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd2.Import(exported)

	// Verify baselines restored
	state1, ok1 := cpd2.GetMetricState("block_rate")
	state2, ok2 := cpd2.GetMetricState("latency")
	if !ok1 || !ok2 {
		t.Fatal("metrics not restored after import")
	}
	if state1.Baseline != 0.3 {
		t.Fatalf("block_rate baseline: got %f, want 0.3", state1.Baseline)
	}
	if state2.Baseline != 50.0 {
		t.Fatalf("latency baseline: got %f, want 50.0", state2.Baseline)
	}

	// CUSUM sums should be reset on import
	if state1.SumHigh != 0 || state1.SumLow != 0 {
		t.Fatal("CUSUM sums should be zero after import")
	}
}

func TestCUSUM_ImportNilIsNoOp(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd.Import(nil) // Should not panic
	if cpd.MetricCount() != 0 {
		t.Fatal("import nil should not create metrics")
	}
}

func TestCUSUM_ConcurrentSafety(t *testing.T) {
	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             5.0,
		DriftAllowance:        0.5,
		MinObservations:       5,
		RecalibrationCooldown: 0,
	}, func(_ string, _ float64) {})

	cpd.SetBaseline("metric", 1.0)

	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				cpd.Observe("metric", float64(i)*0.01)
				cpd.IsStable("metric")
				cpd.GetMetricState("metric")
			}
		}()
	}
	wg.Wait()
}

// --- Edge cases ---

func TestCUSUM_ResetUnknownMetricIsNoOp(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd.ResetMetric("nonexistent", 1.0) // must not panic
	if cpd.MetricCount() != 0 {
		t.Fatal("reset on unknown metric should not create the metric")
	}
}

func TestCUSUM_IsStableReturnsFalseWhenAboveThreshold(t *testing.T) {
	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             3.0,
		DriftAllowance:        0.1,
		MinObservations:       5,
		RecalibrationCooldown: 0,
	}, nil) // nil callback — we only care about internal state

	cpd.SetBaseline("metric", 0.0)
	// Feed large values to push SumHigh past threshold without triggering callback
	for i := 0; i < 30; i++ {
		cpd.Observe("metric", 2.0) // deviation=2.0, drift=0.1 → net +1.9/obs
	}

	if cpd.IsStable("metric") {
		t.Fatal("IsStable should return false when CUSUM sums exceed threshold")
	}
}

func TestCUSUM_ObserveReturnsBoolCorrectly(t *testing.T) {
	cfg := &CalibratorConfig{
		Threshold:             3.0,
		DriftAllowance:        0.2,
		MinObservations:       5,
		RecalibrationCooldown: 0,
	}
	cpd := NewChangePointDetector(cfg, func(_ string, _ float64) {})
	cpd.SetBaseline("x", 0.0)

	// Below MinObservations — always false
	for i := 0; i < 4; i++ {
		if cpd.Observe("x", 1.0) {
			t.Fatalf("Observe returned true before MinObservations (i=%d)", i)
		}
	}

	// After enough observations with a large shift, return must become true
	var detected bool
	for i := 0; i < 20; i++ {
		if cpd.Observe("x", 1.0) {
			detected = true
			break
		}
	}
	if !detected {
		t.Fatal("Observe never returned true despite clear shift")
	}
}

func TestCUSUM_SetBaselineOverwritesAccumulatedState(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd.SetBaseline("metric", 1.0)

	// Accumulate CUSUM state and observations
	for i := 0; i < 30; i++ {
		cpd.Observe("metric", 3.0)
	}

	state, _ := cpd.GetMetricState("metric")
	if state.Count == 0 {
		t.Fatal("expected nonzero count before overwrite")
	}

	// Re-set baseline — should wipe accumulated state
	cpd.SetBaseline("metric", 2.0)

	state, _ = cpd.GetMetricState("metric")
	if state.Baseline != 2.0 {
		t.Fatalf("baseline not updated: got %f, want 2.0", state.Baseline)
	}
	if state.SumHigh != 0 || state.SumLow != 0 {
		t.Fatalf("CUSUM sums not cleared by SetBaseline: high=%f low=%f", state.SumHigh, state.SumLow)
	}
	if state.Count != 0 {
		t.Fatalf("count not cleared by SetBaseline: got %d", state.Count)
	}
}

func TestCUSUM_MultipleMetricsAreIndependent(t *testing.T) {
	stableFired := make(chan struct{}, 1)
	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             3.0,
		DriftAllowance:        0.2,
		MinObservations:       5,
		RecalibrationCooldown: 0,
	}, func(metric string, _ float64) {
		if metric == "stable" {
			select {
			case stableFired <- struct{}{}:
			default:
			}
		}
	})

	cpd.SetBaseline("shifting", 0.0)
	cpd.SetBaseline("stable", 0.5)

	// Warm up both
	for i := 0; i < 10; i++ {
		cpd.Observe("shifting", 0.0)
		cpd.Observe("stable", 0.5)
	}

	// Shift only "shifting"; keep "stable" on baseline
	for i := 0; i < 50; i++ {
		cpd.Observe("shifting", 2.0)
		cpd.Observe("stable", 0.5)
	}

	// "stable" must never have fired
	select {
	case <-stableFired:
		t.Fatal("stable metric incorrectly detected a change")
	case <-time.After(100 * time.Millisecond):
		// expected — no spurious detection
	}

	// Verify "stable" CUSUM sums are low
	if !cpd.IsStable("stable") {
		t.Fatal("stable metric should remain stable")
	}
}

func TestCUSUM_CooldownExpiryAllowsRedetection(t *testing.T) {
	fired := make(chan struct{}, 10)
	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             2.0,
		DriftAllowance:        0.2,
		MinObservations:       5,
		RecalibrationCooldown: 20 * time.Millisecond, // short cooldown
	}, func(_ string, _ float64) {
		select {
		case fired <- struct{}{}:
		default:
		}
	})

	cpd.SetBaseline("metric", 0.0)

	// Warm up
	for i := 0; i < 10; i++ {
		cpd.Observe("metric", 0.0)
	}

	// Trigger first detection
	for i := 0; i < 30; i++ {
		cpd.Observe("metric", 2.0)
	}
	select {
	case <-fired:
		// first detection — ok
	case <-time.After(time.Second):
		t.Fatal("first detection never fired")
	}

	// Reset sums and baseline to allow a second detection
	cpd.ResetMetric("metric", 0.0)

	// Wait for cooldown to expire
	time.Sleep(30 * time.Millisecond)

	// Trigger again
	for i := 0; i < 30; i++ {
		cpd.Observe("metric", 2.0)
	}
	select {
	case <-fired:
		// second detection after cooldown — expected
	case <-time.After(time.Second):
		t.Fatal("second detection did not fire after cooldown expired")
	}
}

func TestCUSUM_DetectsAtExactMinObservationsBoundary(t *testing.T) {
	const minObs = 10
	fired := make(chan struct{}, 1)
	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             2.0,
		DriftAllowance:        0.1,
		MinObservations:       minObs,
		RecalibrationCooldown: 0,
	}, func(_ string, _ float64) {
		select {
		case fired <- struct{}{}:
		default:
		}
	})

	cpd.SetBaseline("metric", 0.0)

	// Feed minObs-1 extreme observations — must NOT detect
	for i := 0; i < minObs-1; i++ {
		cpd.Observe("metric", 5.0)
	}
	select {
	case <-fired:
		t.Fatal("detected before MinObservations reached")
	default:
	}

	// The Nth observation (exactly at boundary) should be eligible to detect
	for i := 0; i < 5; i++ {
		cpd.Observe("metric", 5.0)
	}
	select {
	case <-fired:
		// detected at or just past boundary — expected
	case <-time.After(time.Second):
		t.Fatal("detection did not fire at MinObservations boundary")
	}
}

func TestCUSUM_NilConfigFallsBackToDefaults(t *testing.T) {
	// NewChangePointDetector(nil, ...) must not panic and must use sane defaults
	cpd := NewChangePointDetector(nil, nil)
	if cpd == nil {
		t.Fatal("NewChangePointDetector returned nil")
	}
	// Defaults should match DefaultCalibratorConfig
	def := DefaultCalibratorConfig()
	cpd.SetBaseline("x", 1.0)
	state, ok := cpd.GetMetricState("x")
	if !ok {
		t.Fatal("metric not created")
	}
	if state.Threshold != def.Threshold {
		t.Fatalf("threshold: got %f, want %f", state.Threshold, def.Threshold)
	}
	if state.Drift != def.DriftAllowance {
		t.Fatalf("drift: got %f, want %f", state.Drift, def.DriftAllowance)
	}
}

func TestCUSUM_MagnitudeInCallbackIsAboveThreshold(t *testing.T) {
	const threshold = 4.0
	magnitudes := make(chan float64, 1)
	cpd := NewChangePointDetector(&CalibratorConfig{
		Threshold:             threshold,
		DriftAllowance:        0.2,
		MinObservations:       5,
		RecalibrationCooldown: 0,
	}, func(_ string, magnitude float64) {
		select {
		case magnitudes <- magnitude:
		default:
		}
	})

	cpd.SetBaseline("metric", 0.0)
	for i := 0; i < 5; i++ {
		cpd.Observe("metric", 0.0)
	}
	for i := 0; i < 30; i++ {
		cpd.Observe("metric", 3.0)
	}

	select {
	case m := <-magnitudes:
		if m < threshold {
			t.Fatalf("magnitude %f should be >= threshold %f", m, threshold)
		}
	case <-time.After(time.Second):
		t.Fatal("callback never fired")
	}
}

func TestCUSUM_ExportPreservesCount(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd.SetBaseline("metric", 1.0)

	const n = 15
	for i := 0; i < n; i++ {
		cpd.Observe("metric", 1.0)
	}

	exported := cpd.Export()

	cpd2 := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd2.Import(exported)

	state, ok := cpd2.GetMetricState("metric")
	if !ok {
		t.Fatal("metric not found after import")
	}
	// Count from the original state was n+0 (SetBaseline zeroes it, Observe increments).
	// Export stores Count; Import restores it.
	if state.Count != n {
		t.Fatalf("count after import: got %d, want %d", state.Count, n)
	}
}

func TestCUSUM_ImportOverwritesExistingMetrics(t *testing.T) {
	src := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	src.SetBaseline("shared", 99.0)

	dst := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	dst.SetBaseline("shared", 1.0) // different baseline
	dst.SetBaseline("extra", 5.0)  // extra metric not in src

	dst.Import(src.Export())

	state, ok := dst.GetMetricState("shared")
	if !ok {
		t.Fatal("shared metric missing after import")
	}
	if state.Baseline != 99.0 {
		t.Fatalf("import should overwrite: got baseline %f, want 99.0", state.Baseline)
	}

	// "extra" should still exist — Import merges, not replaces
	_, ok = dst.GetMetricState("extra")
	if !ok {
		t.Fatal("extra metric should survive import (merge semantics)")
	}
}
