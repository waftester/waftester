package tampers

import (
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector tracks tamper usage and effectiveness in real-time
type MetricsCollector struct {
	metrics map[string]*TamperMetrics
	mu      sync.RWMutex
}

// TamperMetrics holds statistics for a single tamper
type TamperMetrics struct {
	TamperName      string    `json:"tamper_name"`
	TotalAttempts   int64     `json:"total_attempts"`
	SuccessCount    int64     `json:"success_count"`    // Bypassed WAF
	BlockedCount    int64     `json:"blocked_count"`    // WAF blocked
	ErrorCount      int64     `json:"error_count"`      // Network/timeout errors
	TransformCount  int64     `json:"transform_count"`  // Total transformations
	TotalLatencyNs  int64     `json:"total_latency_ns"` // For average calculation
	LastUsed        time.Time `json:"last_used"`
	LastSuccess     time.Time `json:"last_success"`
	CharactersAdded int64     `json:"characters_added"` // Payload size impact
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: make(map[string]*TamperMetrics),
	}
}

// getOrCreate returns metrics for a tamper, creating if needed
func (m *MetricsCollector) getOrCreate(name string) *TamperMetrics {
	m.mu.RLock()
	metrics, ok := m.metrics[name]
	m.mu.RUnlock()

	if ok {
		return metrics
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if metrics, ok = m.metrics[name]; ok {
		return metrics
	}

	metrics = &TamperMetrics{TamperName: name}
	m.metrics[name] = metrics
	return metrics
}

// RecordTransform records a payload transformation
func (m *MetricsCollector) RecordTransform(name, original, transformed string) {
	metrics := m.getOrCreate(name)
	atomic.AddInt64(&metrics.TransformCount, 1)
	atomic.AddInt64(&metrics.CharactersAdded, int64(len(transformed)-len(original)))

	m.mu.Lock()
	metrics.LastUsed = time.Now()
	m.mu.Unlock()
}

// RecordSuccess records a successful bypass
func (m *MetricsCollector) RecordSuccess(tamperNames []string) {
	now := time.Now()
	for _, name := range tamperNames {
		metrics := m.getOrCreate(name)
		atomic.AddInt64(&metrics.TotalAttempts, 1)
		atomic.AddInt64(&metrics.SuccessCount, 1)

		m.mu.Lock()
		metrics.LastUsed = now
		metrics.LastSuccess = now
		m.mu.Unlock()
	}
}

// RecordFailure records a blocked request
func (m *MetricsCollector) RecordFailure(tamperNames []string) {
	now := time.Now()
	for _, name := range tamperNames {
		metrics := m.getOrCreate(name)
		atomic.AddInt64(&metrics.TotalAttempts, 1)
		atomic.AddInt64(&metrics.BlockedCount, 1)

		m.mu.Lock()
		metrics.LastUsed = now
		m.mu.Unlock()
	}
}

// RecordError records a network/timeout error
func (m *MetricsCollector) RecordError(tamperNames []string) {
	now := time.Now()
	for _, name := range tamperNames {
		metrics := m.getOrCreate(name)
		atomic.AddInt64(&metrics.TotalAttempts, 1)
		atomic.AddInt64(&metrics.ErrorCount, 1)

		m.mu.Lock()
		metrics.LastUsed = now
		m.mu.Unlock()
	}
}

// RecordLatency records request latency for a tamper chain
func (m *MetricsCollector) RecordLatency(tamperNames []string, latency time.Duration) {
	if len(tamperNames) == 0 {
		return
	}
	latencyNs := int64(latency)
	perTamper := latencyNs / int64(len(tamperNames))

	for _, name := range tamperNames {
		metrics := m.getOrCreate(name)
		atomic.AddInt64(&metrics.TotalLatencyNs, perTamper)
	}
}

// GetMetrics returns a copy of metrics for a specific tamper
func (m *MetricsCollector) GetMetrics(name string) *TamperMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if metrics, ok := m.metrics[name]; ok {
		// Return a copy to avoid race conditions
		return &TamperMetrics{
			TamperName:      metrics.TamperName,
			TotalAttempts:   atomic.LoadInt64(&metrics.TotalAttempts),
			SuccessCount:    atomic.LoadInt64(&metrics.SuccessCount),
			BlockedCount:    atomic.LoadInt64(&metrics.BlockedCount),
			ErrorCount:      atomic.LoadInt64(&metrics.ErrorCount),
			TransformCount:  atomic.LoadInt64(&metrics.TransformCount),
			TotalLatencyNs:  atomic.LoadInt64(&metrics.TotalLatencyNs),
			CharactersAdded: atomic.LoadInt64(&metrics.CharactersAdded),
			LastUsed:        metrics.LastUsed,
			LastSuccess:     metrics.LastSuccess,
		}
	}
	return nil
}

// GetAllMetrics returns a copy of all metrics
func (m *MetricsCollector) GetAllMetrics() map[string]*TamperMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*TamperMetrics, len(m.metrics))
	for name, metrics := range m.metrics {
		result[name] = &TamperMetrics{
			TamperName:      metrics.TamperName,
			TotalAttempts:   atomic.LoadInt64(&metrics.TotalAttempts),
			SuccessCount:    atomic.LoadInt64(&metrics.SuccessCount),
			BlockedCount:    atomic.LoadInt64(&metrics.BlockedCount),
			ErrorCount:      atomic.LoadInt64(&metrics.ErrorCount),
			TransformCount:  atomic.LoadInt64(&metrics.TransformCount),
			TotalLatencyNs:  atomic.LoadInt64(&metrics.TotalLatencyNs),
			CharactersAdded: atomic.LoadInt64(&metrics.CharactersAdded),
			LastUsed:        metrics.LastUsed,
			LastSuccess:     metrics.LastSuccess,
		}
	}
	return result
}

// GetSuccessRate returns the success rate for a tamper (0.0-1.0)
func (m *MetricsCollector) GetSuccessRate(name string) float64 {
	metrics := m.GetMetrics(name)
	if metrics == nil || metrics.TotalAttempts == 0 {
		return 0.5 // Unknown, assume average
	}
	return float64(metrics.SuccessCount) / float64(metrics.TotalAttempts)
}

// GetAverageLatency returns average request latency for a tamper
func (m *MetricsCollector) GetAverageLatency(name string) time.Duration {
	metrics := m.GetMetrics(name)
	if metrics == nil || metrics.TotalAttempts == 0 {
		return 0
	}
	return time.Duration(metrics.TotalLatencyNs / metrics.TotalAttempts)
}

// GetTopPerformers returns tampers sorted by success rate
func (m *MetricsCollector) GetTopPerformers(n int) []TamperPerformance {
	m.mu.RLock()
	defer m.mu.RUnlock()

	perfs := make([]TamperPerformance, 0, len(m.metrics))
	for name, metrics := range m.metrics {
		attempts := atomic.LoadInt64(&metrics.TotalAttempts)
		if attempts == 0 {
			continue
		}

		success := atomic.LoadInt64(&metrics.SuccessCount)
		perfs = append(perfs, TamperPerformance{
			Name:        name,
			SuccessRate: float64(success) / float64(attempts),
			Attempts:    attempts,
		})
	}

	// Sort by success rate descending
	for i := 0; i < len(perfs)-1; i++ {
		for j := i + 1; j < len(perfs); j++ {
			if perfs[j].SuccessRate > perfs[i].SuccessRate {
				perfs[i], perfs[j] = perfs[j], perfs[i]
			}
		}
	}

	if n > len(perfs) {
		n = len(perfs)
	}
	return perfs[:n]
}

// TamperPerformance represents performance data for display
type TamperPerformance struct {
	Name        string  `json:"name"`
	SuccessRate float64 `json:"success_rate"`
	Attempts    int64   `json:"attempts"`
}

// Summary returns a summary of all metrics
type MetricsSummary struct {
	TotalTampers     int      `json:"total_tampers"`
	TotalAttempts    int64    `json:"total_attempts"`
	TotalSuccesses   int64    `json:"total_successes"`
	TotalBlocked     int64    `json:"total_blocked"`
	TotalErrors      int64    `json:"total_errors"`
	OverallSuccess   float64  `json:"overall_success_rate"`
	TopPerformers    []string `json:"top_performers"`
	MostUsed         []string `json:"most_used"`
	AvgPayloadGrowth float64  `json:"avg_payload_growth_chars"`
}

// GetSummary returns an aggregate summary of all metrics
func (m *MetricsCollector) GetSummary() *MetricsSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summary := &MetricsSummary{
		TotalTampers: len(m.metrics),
	}

	type usage struct {
		name    string
		count   int64
		success float64
	}
	usages := make([]usage, 0, len(m.metrics))

	var totalCharsAdded int64
	var totalTransforms int64

	for name, metrics := range m.metrics {
		attempts := atomic.LoadInt64(&metrics.TotalAttempts)
		success := atomic.LoadInt64(&metrics.SuccessCount)
		blocked := atomic.LoadInt64(&metrics.BlockedCount)
		errors := atomic.LoadInt64(&metrics.ErrorCount)
		transforms := atomic.LoadInt64(&metrics.TransformCount)
		charsAdded := atomic.LoadInt64(&metrics.CharactersAdded)

		summary.TotalAttempts += attempts
		summary.TotalSuccesses += success
		summary.TotalBlocked += blocked
		summary.TotalErrors += errors
		totalCharsAdded += charsAdded
		totalTransforms += transforms

		if attempts > 0 {
			usages = append(usages, usage{
				name:    name,
				count:   attempts,
				success: float64(success) / float64(attempts),
			})
		}
	}

	if summary.TotalAttempts > 0 {
		summary.OverallSuccess = float64(summary.TotalSuccesses) / float64(summary.TotalAttempts)
	}

	if totalTransforms > 0 {
		summary.AvgPayloadGrowth = float64(totalCharsAdded) / float64(totalTransforms)
	}

	// Sort by count for most used
	for i := 0; i < len(usages)-1; i++ {
		for j := i + 1; j < len(usages); j++ {
			if usages[j].count > usages[i].count {
				usages[i], usages[j] = usages[j], usages[i]
			}
		}
	}
	for i := 0; i < min(5, len(usages)); i++ {
		summary.MostUsed = append(summary.MostUsed, usages[i].name)
	}

	// Sort by success rate for top performers
	for i := 0; i < len(usages)-1; i++ {
		for j := i + 1; j < len(usages); j++ {
			if usages[j].success > usages[i].success {
				usages[i], usages[j] = usages[j], usages[i]
			}
		}
	}
	for i := 0; i < min(5, len(usages)); i++ {
		summary.TopPerformers = append(summary.TopPerformers, usages[i].name)
	}

	return summary
}

// Reset clears all metrics
func (m *MetricsCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = make(map[string]*TamperMetrics)
}
