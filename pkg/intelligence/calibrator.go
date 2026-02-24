// Package intelligence provides advanced cognitive capabilities for WAFtester.
// This file implements CUSUM (Cumulative Sum) change-point detection for
// adaptive re-calibration when WAF behavior shifts mid-scan.
package intelligence

import (
	"math"
	"sync"
	"time"
)

// ChangePointDetector uses CUSUM to detect shifts in WAF behavior.
// Monitors: block rate, response latency, status code distribution changes.
type ChangePointDetector struct {
	mu sync.Mutex

	// CUSUM state per metric
	metrics map[string]*CUSUMState

	// Configuration
	config *CalibratorConfig

	// Callback when change detected
	onChangePoint func(metric string, magnitude float64)
}

// CUSUMState tracks the cumulative sum for one metric.
type CUSUMState struct {
	Baseline   float64   // Expected value (from calibration)
	SumHigh    float64   // Upper CUSUM: detects increases
	SumLow     float64   // Lower CUSUM: detects decreases
	Threshold  float64   // Alert threshold (h)
	Drift      float64   // Allowable drift (k)
	LastValue  float64   // Most recent observation
	LastChange time.Time // Time of last detected change
	Count      int       // Total observations since last reset
}

// CalibratorConfig configures the change-point detector.
type CalibratorConfig struct {
	Threshold             float64       // CUSUM h parameter (higher = fewer false alarms)
	DriftAllowance        float64       // CUSUM k parameter (typically 0.5 * expected shift)
	MinObservations       int           // Min observations before detection active
	RecalibrationCooldown time.Duration // Min time between re-calibrations
}

// DefaultCalibratorConfig returns sensible defaults.
func DefaultCalibratorConfig() *CalibratorConfig {
	return &CalibratorConfig{
		Threshold:             5.0,
		DriftAllowance:        0.5,
		MinObservations:       20,
		RecalibrationCooldown: 30 * time.Second,
	}
}

// NewChangePointDetector creates a new CUSUM-based change-point detector.
func NewChangePointDetector(config *CalibratorConfig, onChangePoint func(string, float64)) *ChangePointDetector {
	if config == nil {
		config = DefaultCalibratorConfig()
	}
	return &ChangePointDetector{
		metrics:       make(map[string]*CUSUMState),
		config:        config,
		onChangePoint: onChangePoint,
	}
}

// SetBaseline initializes the expected value for a metric.
func (cpd *ChangePointDetector) SetBaseline(metric string, baseline float64) {
	cpd.mu.Lock()
	defer cpd.mu.Unlock()

	cpd.metrics[metric] = &CUSUMState{
		Baseline:  baseline,
		Threshold: cpd.config.Threshold,
		Drift:     cpd.config.DriftAllowance,
	}
}

// Observe records a new observation for a metric by updating CUSUM sums.
// Returns true if a change point was detected.
//
// The onChangePoint callback is fired asynchronously in a new goroutine AFTER
// all internal locks are released. This prevents deadlocks when the callback
// re-enters the Engine (which holds its own lock while calling Observe).
func (cpd *ChangePointDetector) Observe(metric string, value float64) bool {
	cpd.mu.Lock()

	state, ok := cpd.metrics[metric]
	if !ok {
		// Auto-create with first observation as baseline
		cpd.metrics[metric] = &CUSUMState{
			Baseline:  value,
			Threshold: cpd.config.Threshold,
			Drift:     cpd.config.DriftAllowance,
			Count:     1,
			LastValue: value,
		}
		cpd.mu.Unlock()
		return false
	}

	state.Count++
	state.LastValue = value

	// Skip detection until enough observations
	if state.Count < cpd.config.MinObservations {
		cpd.mu.Unlock()
		return false
	}

	// CUSUM update
	deviation := value - state.Baseline
	state.SumHigh = math.Max(0, state.SumHigh+deviation-state.Drift)
	state.SumLow = math.Max(0, state.SumLow-deviation-state.Drift)

	// Check thresholds
	detected := false
	var magnitude float64

	if state.SumHigh >= state.Threshold {
		magnitude = state.SumHigh
		detected = true
	} else if state.SumLow >= state.Threshold {
		magnitude = state.SumLow
		detected = true
	}

	if !detected {
		cpd.mu.Unlock()
		return false
	}

	// Cooldown check
	now := time.Now()
	if !state.LastChange.IsZero() && now.Sub(state.LastChange) < cpd.config.RecalibrationCooldown {
		cpd.mu.Unlock()
		return false
	}
	state.LastChange = now

	// Capture callback reference, then release the lock before firing.
	// This prevents two classes of deadlock:
	//   1. cpd.mu: the callback calls GetMetricState/ResetMetric, which also
	//      acquire cpd.mu.
	//   2. Engine.mu: Observe may be called while the Engine holds its write
	//      lock; the callback calls Engine.recalibrate which tries to acquire
	//      the same lock. Firing in a goroutine lets the engine lock drain
	//      before the callback runs.
	cb := cpd.onChangePoint
	cpd.mu.Unlock()

	if cb != nil {
		go cb(metric, magnitude)
	}
	return true
}

// ResetMetric resets CUSUM sums and sets a new baseline after re-calibration.
func (cpd *ChangePointDetector) ResetMetric(metric string, newBaseline float64) {
	cpd.mu.Lock()
	defer cpd.mu.Unlock()

	if state, ok := cpd.metrics[metric]; ok {
		state.Baseline = newBaseline
		state.SumHigh = 0
		state.SumLow = 0
		state.Count = 0
	}
}

// IsStable returns true if the CUSUM sums for a metric are below threshold.
func (cpd *ChangePointDetector) IsStable(metric string) bool {
	cpd.mu.Lock()
	defer cpd.mu.Unlock()

	state, ok := cpd.metrics[metric]
	if !ok {
		return true // No data = stable
	}
	return state.SumHigh < state.Threshold && state.SumLow < state.Threshold
}

// GetMetricState returns the current CUSUM state for a metric (for debugging).
func (cpd *ChangePointDetector) GetMetricState(metric string) (CUSUMState, bool) {
	cpd.mu.Lock()
	defer cpd.mu.Unlock()
	state, ok := cpd.metrics[metric]
	if !ok {
		return CUSUMState{}, false
	}
	return *state, true
}

// Reset clears all metric state, returning the detector to its initial state.
func (cpd *ChangePointDetector) Reset() {
	cpd.mu.Lock()
	defer cpd.mu.Unlock()
	cpd.metrics = make(map[string]*CUSUMState)
}

// MetricCount returns the number of tracked metrics.
func (cpd *ChangePointDetector) MetricCount() int {
	cpd.mu.Lock()
	defer cpd.mu.Unlock()
	return len(cpd.metrics)
}

// Export serializes calibrator state for persistence.
// Only baselines are persisted; CUSUM sums are runtime-only.
func (cpd *ChangePointDetector) Export() *CalibratorState {
	cpd.mu.Lock()
	defer cpd.mu.Unlock()

	metrics := make(map[string]*CUSUMMetricState, len(cpd.metrics))
	for key, state := range cpd.metrics {
		metrics[key] = &CUSUMMetricState{
			Baseline: state.Baseline,
			Count:    state.Count,
		}
	}
	return &CalibratorState{Metrics: metrics}
}

// Import restores baselines from persistence. CUSUM sums start fresh.
func (cpd *ChangePointDetector) Import(state *CalibratorState) {
	if state == nil {
		return
	}
	cpd.mu.Lock()
	defer cpd.mu.Unlock()

	for key, ms := range state.Metrics {
		cpd.metrics[key] = &CUSUMState{
			Baseline:  ms.Baseline,
			Count:     ms.Count,
			Threshold: cpd.config.Threshold,
			Drift:     cpd.config.DriftAllowance,
		}
	}
}
