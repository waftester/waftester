// Package intelligence provides advanced cognitive capabilities for WAFtester
// This file implements Metrics and Observability hooks
package intelligence

import (
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// METRICS - Observability hooks for monitoring intelligence engine performance
// Enables integration with Prometheus, StatsD, or custom monitoring systems
// ══════════════════════════════════════════════════════════════════════════════

// Metrics tracks intelligence engine performance metrics
type Metrics struct {
	// Finding processing
	FindingsProcessed atomic.Int64
	FindingsBlocked   atomic.Int64
	FindingsBypassed  atomic.Int64

	// Prediction metrics
	PredictionsRequested atomic.Int64
	PredictionsAccurate  atomic.Int64 // Predictions that matched actual result

	// Mutation metrics
	MutationsSuggested  atomic.Int64
	MutationsSuccessful atomic.Int64

	// Anomaly detection
	AnomaliesDetected atomic.Int64

	// Attack path metrics
	NodesAdded      atomic.Int64
	EdgesAdded      atomic.Int64
	PathsCalculated atomic.Int64
	NodesPruned     atomic.Int64

	// Memory metrics
	FindingsEvicted atomic.Int64

	// Persistence metrics
	SaveOperations atomic.Int64
	LoadOperations atomic.Int64
	SaveErrors     atomic.Int64
	LoadErrors     atomic.Int64

	// Timing
	mu              sync.RWMutex
	lastProcessTime time.Duration
	avgProcessTime  time.Duration
	processCount    int64
}

// NewMetrics creates a new metrics tracker
func NewMetrics() *Metrics {
	return &Metrics{}
}

// RecordFinding records a processed finding
func (m *Metrics) RecordFinding(blocked bool) {
	m.FindingsProcessed.Add(1)
	if blocked {
		m.FindingsBlocked.Add(1)
	} else {
		m.FindingsBypassed.Add(1)
	}
}

// RecordPrediction records a prediction request
func (m *Metrics) RecordPrediction(accurate bool) {
	m.PredictionsRequested.Add(1)
	if accurate {
		m.PredictionsAccurate.Add(1)
	}
}

// RecordMutation records a mutation suggestion
func (m *Metrics) RecordMutation(successful bool) {
	m.MutationsSuggested.Add(1)
	if successful {
		m.MutationsSuccessful.Add(1)
	}
}

// RecordAnomaly records an anomaly detection
func (m *Metrics) RecordAnomaly() {
	m.AnomaliesDetected.Add(1)
}

// RecordPathOperation records attack path operations
func (m *Metrics) RecordPathOperation(nodes, edges, pruned int) {
	m.NodesAdded.Add(int64(nodes))
	m.EdgesAdded.Add(int64(edges))
	if pruned > 0 {
		m.NodesPruned.Add(int64(pruned))
	}
	m.PathsCalculated.Add(1)
}

// RecordEviction records memory evictions
func (m *Metrics) RecordEviction(count int) {
	m.FindingsEvicted.Add(int64(count))
}

// RecordSave records a save operation
func (m *Metrics) RecordSave(success bool) {
	m.SaveOperations.Add(1)
	if !success {
		m.SaveErrors.Add(1)
	}
}

// RecordLoad records a load operation
func (m *Metrics) RecordLoad(success bool) {
	m.LoadOperations.Add(1)
	if !success {
		m.LoadErrors.Add(1)
	}
}

// RecordProcessTime records processing time
func (m *Metrics) RecordProcessTime(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastProcessTime = d
	m.processCount++
	// Exponential moving average
	if m.avgProcessTime == 0 {
		m.avgProcessTime = d
	} else {
		m.avgProcessTime = time.Duration(float64(m.avgProcessTime)*0.9 + float64(d)*0.1)
	}
}

// GetProcessTime returns processing time statistics
func (m *Metrics) GetProcessTime() (last, avg time.Duration, count int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastProcessTime, m.avgProcessTime, m.processCount
}

// GetPredictionAccuracy returns the prediction accuracy rate
func (m *Metrics) GetPredictionAccuracy() float64 {
	requested := m.PredictionsRequested.Load()
	if requested == 0 {
		return 0
	}
	return float64(m.PredictionsAccurate.Load()) / float64(requested)
}

// GetMutationSuccessRate returns the mutation success rate
func (m *Metrics) GetMutationSuccessRate() float64 {
	suggested := m.MutationsSuggested.Load()
	if suggested == 0 {
		return 0
	}
	return float64(m.MutationsSuccessful.Load()) / float64(suggested)
}

// GetBypassRate returns the overall bypass rate
func (m *Metrics) GetBypassRate() float64 {
	processed := m.FindingsProcessed.Load()
	if processed == 0 {
		return 0
	}
	return float64(m.FindingsBypassed.Load()) / float64(processed)
}

// Snapshot returns a point-in-time snapshot of all metrics
func (m *Metrics) Snapshot() *MetricsSnapshot {
	last, avg, count := m.GetProcessTime()
	return &MetricsSnapshot{
		Timestamp:            time.Now(),
		FindingsProcessed:    m.FindingsProcessed.Load(),
		FindingsBlocked:      m.FindingsBlocked.Load(),
		FindingsBypassed:     m.FindingsBypassed.Load(),
		PredictionsRequested: m.PredictionsRequested.Load(),
		PredictionsAccurate:  m.PredictionsAccurate.Load(),
		PredictionAccuracy:   m.GetPredictionAccuracy(),
		MutationsSuggested:   m.MutationsSuggested.Load(),
		MutationsSuccessful:  m.MutationsSuccessful.Load(),
		MutationSuccessRate:  m.GetMutationSuccessRate(),
		AnomaliesDetected:    m.AnomaliesDetected.Load(),
		NodesAdded:           m.NodesAdded.Load(),
		EdgesAdded:           m.EdgesAdded.Load(),
		PathsCalculated:      m.PathsCalculated.Load(),
		NodesPruned:          m.NodesPruned.Load(),
		FindingsEvicted:      m.FindingsEvicted.Load(),
		SaveOperations:       m.SaveOperations.Load(),
		LoadOperations:       m.LoadOperations.Load(),
		SaveErrors:           m.SaveErrors.Load(),
		LoadErrors:           m.LoadErrors.Load(),
		LastProcessTime:      last,
		AvgProcessTime:       avg,
		ProcessCount:         count,
		BypassRate:           m.GetBypassRate(),
	}
}

// MetricsSnapshot is a point-in-time snapshot of all metrics
type MetricsSnapshot struct {
	Timestamp            time.Time     `json:"timestamp"`
	FindingsProcessed    int64         `json:"findings_processed"`
	FindingsBlocked      int64         `json:"findings_blocked"`
	FindingsBypassed     int64         `json:"findings_bypassed"`
	PredictionsRequested int64         `json:"predictions_requested"`
	PredictionsAccurate  int64         `json:"predictions_accurate"`
	PredictionAccuracy   float64       `json:"prediction_accuracy"`
	MutationsSuggested   int64         `json:"mutations_suggested"`
	MutationsSuccessful  int64         `json:"mutations_successful"`
	MutationSuccessRate  float64       `json:"mutation_success_rate"`
	AnomaliesDetected    int64         `json:"anomalies_detected"`
	NodesAdded           int64         `json:"nodes_added"`
	EdgesAdded           int64         `json:"edges_added"`
	PathsCalculated      int64         `json:"paths_calculated"`
	NodesPruned          int64         `json:"nodes_pruned"`
	FindingsEvicted      int64         `json:"findings_evicted"`
	SaveOperations       int64         `json:"save_operations"`
	LoadOperations       int64         `json:"load_operations"`
	SaveErrors           int64         `json:"save_errors"`
	LoadErrors           int64         `json:"load_errors"`
	LastProcessTime      time.Duration `json:"last_process_time"`
	AvgProcessTime       time.Duration `json:"avg_process_time"`
	ProcessCount         int64         `json:"process_count"`
	BypassRate           float64       `json:"bypass_rate"`
}

// Reset resets all metrics to zero
func (m *Metrics) Reset() {
	m.FindingsProcessed.Store(0)
	m.FindingsBlocked.Store(0)
	m.FindingsBypassed.Store(0)
	m.PredictionsRequested.Store(0)
	m.PredictionsAccurate.Store(0)
	m.MutationsSuggested.Store(0)
	m.MutationsSuccessful.Store(0)
	m.AnomaliesDetected.Store(0)
	m.NodesAdded.Store(0)
	m.EdgesAdded.Store(0)
	m.PathsCalculated.Store(0)
	m.NodesPruned.Store(0)
	m.FindingsEvicted.Store(0)
	m.SaveOperations.Store(0)
	m.LoadOperations.Store(0)
	m.SaveErrors.Store(0)
	m.LoadErrors.Store(0)

	m.mu.Lock()
	m.lastProcessTime = 0
	m.avgProcessTime = 0
	m.processCount = 0
	m.mu.Unlock()
}

// MetricsHook is a callback interface for external monitoring systems
type MetricsHook interface {
	OnFindingProcessed(blocked bool, category string, latency time.Duration)
	OnPrediction(category string, predicted, actual float64)
	OnMutation(category string, successful bool)
	OnAnomaly(anomalyType string, confidence float64)
	OnSave(success bool, duration time.Duration)
	OnLoad(success bool, duration time.Duration)
}

// MetricsWithHook wraps Metrics with external hook support
type MetricsWithHook struct {
	*Metrics
	hook MetricsHook
}

// NewMetricsWithHook creates a metrics tracker with an external hook
func NewMetricsWithHook(hook MetricsHook) *MetricsWithHook {
	return &MetricsWithHook{
		Metrics: NewMetrics(),
		hook:    hook,
	}
}

// RecordFindingWithDetails records a finding with full details for the hook
func (m *MetricsWithHook) RecordFindingWithDetails(blocked bool, category string, latency time.Duration) {
	m.RecordFinding(blocked)
	if m.hook != nil {
		m.hook.OnFindingProcessed(blocked, category, latency)
	}
}
