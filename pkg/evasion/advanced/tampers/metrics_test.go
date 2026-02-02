package tampers

import (
	"testing"
	"time"
)

func TestMetricsCollector(t *testing.T) {
	m := NewMetricsCollector()
	if m == nil {
		t.Fatal("expected non-nil collector")
	}
}

func TestMetricsRecordTransform(t *testing.T) {
	m := NewMetricsCollector()

	m.RecordTransform("space2comment", "SELECT * FROM", "SELECT/**/*/**/FROM")
	m.RecordTransform("space2comment", "a b", "a/**/b")

	metrics := m.GetMetrics("space2comment")
	if metrics == nil {
		t.Fatal("expected metrics for space2comment")
	}

	if metrics.TransformCount != 2 {
		t.Errorf("expected 2 transforms, got %d", metrics.TransformCount)
	}
}

func TestMetricsRecordSuccess(t *testing.T) {
	m := NewMetricsCollector()

	m.RecordSuccess([]string{"space2comment", "randomcase"})
	m.RecordSuccess([]string{"space2comment"})

	metrics := m.GetMetrics("space2comment")
	if metrics == nil {
		t.Fatal("expected metrics for space2comment")
	}

	if metrics.SuccessCount != 2 {
		t.Errorf("expected 2 successes, got %d", metrics.SuccessCount)
	}
	if metrics.TotalAttempts != 2 {
		t.Errorf("expected 2 attempts, got %d", metrics.TotalAttempts)
	}

	metricsRC := m.GetMetrics("randomcase")
	if metricsRC.SuccessCount != 1 {
		t.Errorf("expected 1 success for randomcase, got %d", metricsRC.SuccessCount)
	}
}

func TestMetricsRecordFailure(t *testing.T) {
	m := NewMetricsCollector()

	m.RecordFailure([]string{"charencode"})
	m.RecordFailure([]string{"charencode"})
	m.RecordSuccess([]string{"charencode"})

	metrics := m.GetMetrics("charencode")
	if metrics.BlockedCount != 2 {
		t.Errorf("expected 2 blocked, got %d", metrics.BlockedCount)
	}
	if metrics.SuccessCount != 1 {
		t.Errorf("expected 1 success, got %d", metrics.SuccessCount)
	}
	if metrics.TotalAttempts != 3 {
		t.Errorf("expected 3 attempts, got %d", metrics.TotalAttempts)
	}
}

func TestMetricsGetSuccessRate(t *testing.T) {
	m := NewMetricsCollector()

	// No data yet
	rate := m.GetSuccessRate("unknown")
	if rate != 0.5 {
		t.Errorf("expected 0.5 for unknown, got %f", rate)
	}

	// 2 success, 1 failure = 66.67%
	m.RecordSuccess([]string{"test"})
	m.RecordSuccess([]string{"test"})
	m.RecordFailure([]string{"test"})

	rate = m.GetSuccessRate("test")
	if rate < 0.66 || rate > 0.67 {
		t.Errorf("expected ~0.67, got %f", rate)
	}
}

func TestMetricsGetAllMetrics(t *testing.T) {
	m := NewMetricsCollector()

	m.RecordSuccess([]string{"a", "b", "c"})
	m.RecordFailure([]string{"d"})

	all := m.GetAllMetrics()
	if len(all) != 4 {
		t.Errorf("expected 4 metrics, got %d", len(all))
	}
}

func TestMetricsGetTopPerformers(t *testing.T) {
	m := NewMetricsCollector()

	// Create different success rates
	for i := 0; i < 10; i++ {
		m.RecordSuccess([]string{"best"})
	}
	for i := 0; i < 5; i++ {
		m.RecordSuccess([]string{"good"})
		m.RecordFailure([]string{"good"})
	}
	for i := 0; i < 10; i++ {
		m.RecordFailure([]string{"worst"})
	}

	top := m.GetTopPerformers(3)
	if len(top) != 3 {
		t.Errorf("expected 3 performers, got %d", len(top))
	}

	if top[0].Name != "best" {
		t.Errorf("expected 'best' as top performer, got %s", top[0].Name)
	}
	if top[0].SuccessRate != 1.0 {
		t.Errorf("expected 100%% success rate, got %f", top[0].SuccessRate)
	}
}

func TestMetricsRecordLatency(t *testing.T) {
	m := NewMetricsCollector()

	// Record 2 successes (TotalAttempts = 2)
	m.RecordSuccess([]string{"test"})
	m.RecordSuccess([]string{"test"})

	// Record latencies: 100ms + 200ms = 300ms total
	m.RecordLatency([]string{"test"}, 100*time.Millisecond)
	m.RecordLatency([]string{"test"}, 200*time.Millisecond)

	// Average = 300ms / 2 attempts = 150ms
	avgLatency := m.GetAverageLatency("test")
	if avgLatency < 140*time.Millisecond || avgLatency > 160*time.Millisecond {
		t.Errorf("expected latency around 150ms, got %v", avgLatency)
	}
}

func TestMetricsSummary(t *testing.T) {
	m := NewMetricsCollector()

	m.RecordSuccess([]string{"a", "b"})
	m.RecordSuccess([]string{"a"})
	m.RecordFailure([]string{"c"})
	m.RecordError([]string{"d"})

	summary := m.GetSummary()
	if summary.TotalTampers != 4 {
		t.Errorf("expected 4 tampers, got %d", summary.TotalTampers)
	}
	if summary.TotalAttempts != 5 {
		t.Errorf("expected 5 attempts, got %d", summary.TotalAttempts)
	}
	if summary.TotalSuccesses != 3 {
		t.Errorf("expected 3 successes, got %d", summary.TotalSuccesses)
	}
	if summary.TotalBlocked != 1 {
		t.Errorf("expected 1 blocked, got %d", summary.TotalBlocked)
	}
	if summary.TotalErrors != 1 {
		t.Errorf("expected 1 error, got %d", summary.TotalErrors)
	}
}

func TestMetricsReset(t *testing.T) {
	m := NewMetricsCollector()

	m.RecordSuccess([]string{"test"})
	m.Reset()

	all := m.GetAllMetrics()
	if len(all) != 0 {
		t.Errorf("expected 0 metrics after reset, got %d", len(all))
	}
}

func TestMetricsConcurrency(t *testing.T) {
	m := NewMetricsCollector()

	// Concurrent writes
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			m.RecordSuccess([]string{"concurrent"})
			m.RecordFailure([]string{"concurrent"})
			m.RecordTransform("concurrent", "a", "b")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	metrics := m.GetMetrics("concurrent")
	if metrics.TotalAttempts != 200 {
		t.Errorf("expected 200 attempts, got %d", metrics.TotalAttempts)
	}
	if metrics.TransformCount != 100 {
		t.Errorf("expected 100 transforms, got %d", metrics.TransformCount)
	}
}
