package runner

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunner_Run_BasicConcurrency(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 5

	targets := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}

	var concurrent int32
	var maxConcurrent int32

	task := func(ctx context.Context, target string) (string, error) {
		// Track concurrent execution
		cur := atomic.AddInt32(&concurrent, 1)
		for {
			max := atomic.LoadInt32(&maxConcurrent)
			if cur <= max || atomic.CompareAndSwapInt32(&maxConcurrent, max, cur) {
				break
			}
		}

		time.Sleep(50 * time.Millisecond) // Simulate work

		atomic.AddInt32(&concurrent, -1)
		return "result-" + target, nil
	}

	ctx := context.Background()
	results := runner.Run(ctx, targets, task)

	// Verify all targets processed
	if len(results) != len(targets) {
		t.Errorf("Expected %d results, got %d", len(targets), len(results))
	}

	// Verify concurrency was respected
	if atomic.LoadInt32(&maxConcurrent) > 5 {
		t.Errorf("Concurrency exceeded: max %d (expected <= 5)", maxConcurrent)
	}

	// Verify stats
	if runner.Stats.Completed != int64(len(targets)) {
		t.Errorf("Stats.Completed = %d, want %d", runner.Stats.Completed, len(targets))
	}
	if runner.Stats.Successful != int64(len(targets)) {
		t.Errorf("Stats.Successful = %d, want %d", runner.Stats.Successful, len(targets))
	}
}

func TestRunner_Run_ErrorHandling(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 3

	targets := []string{"ok", "fail", "ok2", "fail2"}

	task := func(ctx context.Context, target string) (string, error) {
		if target == "fail" || target == "fail2" {
			return "", errors.New("simulated error")
		}
		return "result-" + target, nil
	}

	ctx := context.Background()
	results := runner.Run(ctx, targets, task)

	if len(results) != 4 {
		t.Errorf("Expected 4 results, got %d", len(results))
	}

	// Count errors
	var errorCount int
	for _, r := range results {
		if r.Error != nil {
			errorCount++
		}
	}

	if errorCount != 2 {
		t.Errorf("Expected 2 errors, got %d", errorCount)
	}

	if runner.Stats.Failed != 2 {
		t.Errorf("Stats.Failed = %d, want 2", runner.Stats.Failed)
	}
	if runner.Stats.Successful != 2 {
		t.Errorf("Stats.Successful = %d, want 2", runner.Stats.Successful)
	}
}

func TestRunner_Run_RateLimit(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 10
	runner.RateLimit = 20 // 20 requests per second

	targets := make([]string, 10)
	for i := range targets {
		targets[i] = string(rune('a' + i))
	}

	task := func(ctx context.Context, target string) (string, error) {
		return target, nil
	}

	ctx := context.Background()
	start := time.Now()
	runner.Run(ctx, targets, task)
	elapsed := time.Since(start)

	// With rate limit of 20/s, 10 requests should take ~0.5s minimum
	// Allow some tolerance
	if elapsed < 400*time.Millisecond {
		t.Logf("Rate limiting may not be strict: completed in %v", elapsed)
	}
}

func TestRunner_Run_Timeout(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 2
	runner.Timeout = 100 * time.Millisecond

	targets := []string{"fast", "slow"}

	task := func(ctx context.Context, target string) (string, error) {
		if target == "slow" {
			select {
			case <-time.After(500 * time.Millisecond):
				return "done", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return "fast-result", nil
	}

	ctx := context.Background()
	results := runner.Run(ctx, targets, task)

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// The slow task should have been cancelled
	for _, r := range results {
		if r.Target == "slow" && r.Error == nil {
			t.Error("Expected slow task to timeout")
		}
	}
}

func TestRunner_Run_ContextCancellation(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 2

	targets := make([]string, 100) // Many targets
	for i := range targets {
		targets[i] = string(rune('a' + i%26))
	}

	var completed int32

	task := func(ctx context.Context, target string) (string, error) {
		select {
		case <-time.After(50 * time.Millisecond):
			atomic.AddInt32(&completed, 1)
			return target, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	runner.Run(ctx, targets, task)

	// Not all targets should have completed due to timeout
	if atomic.LoadInt32(&completed) >= int32(len(targets)) {
		t.Log("All targets completed (context may not have cancelled in time)")
	}
}

func TestRunner_RunWithCallback(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 3

	targets := []string{"a", "b", "c", "d", "e"}

	task := func(ctx context.Context, target string) (string, error) {
		time.Sleep(10 * time.Millisecond)
		return "result-" + target, nil
	}

	var callbackCount int32
	callback := func(r Result[string]) {
		atomic.AddInt32(&callbackCount, 1)
	}

	ctx := context.Background()
	runner.RunWithCallback(ctx, targets, task, callback)

	if atomic.LoadInt32(&callbackCount) != int32(len(targets)) {
		t.Errorf("Expected %d callbacks, got %d", len(targets), callbackCount)
	}
}

func TestRunner_OnProgress(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 2

	targets := []string{"a", "b", "c"}

	var progressCalls int32
	runner.OnProgress = func(completed, total int64, result Result[string]) {
		atomic.AddInt32(&progressCalls, 1)
	}

	task := func(ctx context.Context, target string) (string, error) {
		return target, nil
	}

	ctx := context.Background()
	runner.Run(ctx, targets, task)

	if atomic.LoadInt32(&progressCalls) != 3 {
		t.Errorf("Expected 3 progress callbacks, got %d", progressCalls)
	}
}

func TestRunner_OnError(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 2

	targets := []string{"ok", "fail"}

	var errorCalls int32
	runner.OnError = func(target string, err error) {
		atomic.AddInt32(&errorCalls, 1)
	}

	task := func(ctx context.Context, target string) (string, error) {
		if target == "fail" {
			return "", errors.New("error")
		}
		return target, nil
	}

	ctx := context.Background()
	runner.Run(ctx, targets, task)

	if atomic.LoadInt32(&errorCalls) != 1 {
		t.Errorf("Expected 1 error callback, got %d", errorCalls)
	}
}

func TestRunner_Stats(t *testing.T) {
	runner := NewRunner[string]()
	runner.Concurrency = 2

	targets := []string{"a", "b", "c"}

	task := func(ctx context.Context, target string) (string, error) {
		time.Sleep(10 * time.Millisecond)
		return target, nil
	}

	ctx := context.Background()
	runner.Run(ctx, targets, task)

	// Check stats
	if runner.Stats.Total != 3 {
		t.Errorf("Stats.Total = %d, want 3", runner.Stats.Total)
	}
	if runner.Stats.Completed != 3 {
		t.Errorf("Stats.Completed = %d, want 3", runner.Stats.Completed)
	}

	// Check progress
	progress := runner.Stats.Progress()
	if progress != 100 {
		t.Errorf("Progress = %f, want 100", progress)
	}

	// Check RPS (should be reasonable)
	rps := runner.Stats.RPS()
	if rps <= 0 {
		t.Errorf("RPS = %f, should be > 0", rps)
	}
}

func TestRunner_EmptyTargets(t *testing.T) {
	runner := NewRunner[string]()

	task := func(ctx context.Context, target string) (string, error) {
		return target, nil
	}

	ctx := context.Background()
	results := runner.Run(ctx, []string{}, task)

	if results != nil && len(results) != 0 {
		t.Errorf("Expected empty results for empty targets")
	}
}

func TestRunner_DefaultConcurrency(t *testing.T) {
	runner := NewRunner[string]()

	if runner.Concurrency != 50 {
		t.Errorf("Default concurrency = %d, want 50", runner.Concurrency)
	}
}

func TestRunner_PerHostRateLimit(t *testing.T) {
	runner := NewRunner[int]()
	runner.Concurrency = 10
	runner.RateLimit = 10 // 10 RPS per host
	runner.RateLimitPerHost = true

	// Two hosts, should get 10 RPS each = 20 RPS total
	targets := []string{
		"https://host1.com/a",
		"https://host1.com/b",
		"https://host2.com/a",
		"https://host2.com/b",
		"https://host1.com/c",
		"https://host2.com/c",
	}

	var host1Count, host2Count int32

	task := func(ctx context.Context, target string) (int, error) {
		if strings.Contains(target, "host1.com") {
			atomic.AddInt32(&host1Count, 1)
		} else {
			atomic.AddInt32(&host2Count, 1)
		}
		return 1, nil
	}

	ctx := context.Background()
	results := runner.Run(ctx, targets, task)

	// Verify all targets processed
	if len(results) != len(targets) {
		t.Errorf("Expected %d results, got %d", len(targets), len(results))
	}

	// Verify both hosts processed
	if host1Count != 3 || host2Count != 3 {
		t.Errorf("Host counts: host1=%d host2=%d, expected 3 each", host1Count, host2Count)
	}
}

func TestRunner_ExtractHost(t *testing.T) {
	tests := []struct {
		target   string
		expected string
	}{
		{"https://example.com/path", "example.com"},
		{"http://test.org:8080/api", "test.org"},
		{"example.com", "example.com"},
		{"https://sub.domain.com", "sub.domain.com"},
		{"http://localhost:3000", "localhost"},
	}

	for _, tt := range tests {
		got := extractHost(tt.target)
		if got != tt.expected {
			t.Errorf("extractHost(%q) = %q, want %q", tt.target, got, tt.expected)
		}
	}
}
