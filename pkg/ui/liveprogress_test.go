package ui

import (
	"bytes"
	"testing"
	"time"
)

func TestNewLiveProgress(t *testing.T) {
	cfg := LiveProgressConfig{
		Total:    100,
		Title:    "Testing",
		Unit:     "items",
		Mode:     OutputModeSilent, // Silent for tests
		BarWidth: 30,
	}

	p := NewLiveProgress(cfg)
	if p == nil {
		t.Fatal("NewLiveProgress returned nil")
	}

	if p.config.Total != 100 {
		t.Errorf("Expected Total 100, got %d", p.config.Total)
	}

	if p.config.Title != "Testing" {
		t.Errorf("Expected Title 'Testing', got '%s'", p.config.Title)
	}
}

func TestLiveProgressMetrics(t *testing.T) {
	cfg := LiveProgressConfig{
		Total: 10,
		Mode:  OutputModeSilent,
		Metrics: []MetricConfig{
			{Name: "success", Icon: "✓"},
			{Name: "errors", Icon: "✗"},
		},
	}

	p := NewLiveProgress(cfg)

	// Add metrics using AddMetric (increments by 1)
	p.AddMetric("success")
	p.AddMetric("success")
	p.AddMetric("errors")

	successVal := p.GetMetric("success")
	if successVal != 2 {
		t.Errorf("Expected success=2, got %d", successVal)
	}

	errorsVal := p.GetMetric("errors")
	if errorsVal != 1 {
		t.Errorf("Expected errors=1, got %d", errorsVal)
	}
}

func TestLiveProgressIncrement(t *testing.T) {
	cfg := LiveProgressConfig{
		Total: 10,
		Mode:  OutputModeSilent,
	}

	p := NewLiveProgress(cfg)

	for i := 0; i < 5; i++ {
		p.Increment()
	}

	if p.GetCompleted() != 5 {
		t.Errorf("Expected completed=5, got %d", p.GetCompleted())
	}
}

func TestLiveProgressSetStatus(t *testing.T) {
	cfg := LiveProgressConfig{
		Mode: OutputModeSilent,
	}

	p := NewLiveProgress(cfg)
	p.SetStatus("Processing file.txt")

	// Status is stored in atomic.Value, we can verify via SetStatus not panicking
	// The actual value is internal, but we test the public API works
}

func TestOutputModeStreaming(t *testing.T) {
	var buf bytes.Buffer

	cfg := LiveProgressConfig{
		Total:          5,
		Title:          "Test",
		Mode:           OutputModeStreaming,
		Writer:         &buf,
		StreamInterval: 10 * time.Millisecond,
	}

	p := NewLiveProgress(cfg)
	p.Start()

	// Simulate some work
	for i := 0; i < 3; i++ {
		p.Increment()
		time.Sleep(15 * time.Millisecond)
	}

	p.Stop()

	// In streaming mode, output should not contain ANSI escape codes
	if bytes.Contains(buf.Bytes(), []byte("\033[")) {
		t.Error("Streaming mode should not contain ANSI escape codes")
	}
}

func TestOutputModeSilent(t *testing.T) {
	var buf bytes.Buffer

	cfg := LiveProgressConfig{
		Total:  10,
		Mode:   OutputModeSilent,
		Writer: &buf,
	}

	p := NewLiveProgress(cfg)
	p.Start()
	p.Increment()
	p.Increment()
	p.Stop()

	// Silent mode should produce no output
	if buf.Len() > 0 {
		t.Errorf("Silent mode should produce no output, got: %s", buf.String())
	}
}

func TestLiveProgressSetTotal(t *testing.T) {
	cfg := LiveProgressConfig{
		Mode: OutputModeSilent,
	}

	p := NewLiveProgress(cfg)
	p.SetTotal(100)

	if p.GetTotal() != 100 {
		t.Errorf("Expected total=100, got %d", p.GetTotal())
	}
}

func TestLiveProgressSetCompleted(t *testing.T) {
	cfg := LiveProgressConfig{
		Total: 100,
		Mode:  OutputModeSilent,
	}

	p := NewLiveProgress(cfg)
	p.SetCompleted(50)

	if p.GetCompleted() != 50 {
		t.Errorf("Expected completed=50, got %d", p.GetCompleted())
	}
}

func TestLiveProgressIncrementBy(t *testing.T) {
	cfg := LiveProgressConfig{
		Total: 100,
		Mode:  OutputModeSilent,
	}

	p := NewLiveProgress(cfg)
	p.IncrementBy(10)
	p.IncrementBy(5)

	if p.GetCompleted() != 15 {
		t.Errorf("Expected completed=15, got %d", p.GetCompleted())
	}
}

func TestLiveProgressAddMetricBy(t *testing.T) {
	cfg := LiveProgressConfig{
		Mode: OutputModeSilent,
		Metrics: []MetricConfig{
			{Name: "bypasses", Icon: "🎯"},
		},
	}

	p := NewLiveProgress(cfg)
	p.AddMetricBy("bypasses", 5)
	p.AddMetricBy("bypasses", 3)

	if p.GetMetric("bypasses") != 8 {
		t.Errorf("Expected bypasses=8, got %d", p.GetMetric("bypasses"))
	}
}

func TestLiveProgressGetElapsed(t *testing.T) {
	cfg := LiveProgressConfig{
		Mode: OutputModeSilent,
	}

	p := NewLiveProgress(cfg)
	p.Start()
	time.Sleep(50 * time.Millisecond)
	elapsed := p.GetElapsed()
	p.Stop()

	if elapsed < 50*time.Millisecond {
		t.Errorf("Expected elapsed >= 50ms, got %v", elapsed)
	}
}

func TestLiveProgressRateSource(t *testing.T) {
	var buf bytes.Buffer
	var reqCount int64

	cfg := LiveProgressConfig{
		Total:          1,
		Title:          "Test",
		Mode:           OutputModeInteractive,
		Writer:         &buf,
		RateSource:     &reqCount,
		DisplayLines:   2,
		Metrics: []MetricConfig{
			{Name: "vulns", Label: "Vulns", Icon: "!"},
		},
	}

	p := NewLiveProgress(cfg)
	p.Start()

	// Simulate HTTP requests via the external counter
	for i := 0; i < 20; i++ {
		reqCount++
	}
	// Let the render loop pick it up
	time.Sleep(200 * time.Millisecond)

	p.Stop()

	output := buf.String()
	// The rate display should show a non-zero value since reqCount > 0,
	// even though completed is still 0.
	if !bytes.Contains([]byte(output), []byte("/s")) {
		t.Error("Expected /s rate indicator in output")
	}
	// Completed is 0, but rate should NOT be 0.0 because RateSource has 20
	if bytes.Contains([]byte(output), []byte("0.0/s")) {
		t.Error("Rate should not be 0.0/s when RateSource has requests; got 0.0/s")
	}
}
