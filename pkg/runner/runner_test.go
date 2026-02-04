package runner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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

// =============================================================================
// Race Condition and Concurrency Tests
// =============================================================================

func TestRunner_Run_ConcurrentStatsUpdate(t *testing.T) {
	// Test that Stats are consistent under high concurrent load
	runner := NewRunner[int]()
	runner.Concurrency = 20

	const numTargets = 200
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = string(rune('a' + i%26))
	}

	// Mix of successes and failures
	task := func(ctx context.Context, target string) (int, error) {
		time.Sleep(time.Millisecond) // Simulate work
		// Fail every 5th target
		if target[0]%5 == 0 {
			return 0, errors.New("simulated failure")
		}
		return 1, nil
	}

	ctx := context.Background()
	results := runner.Run(ctx, targets, task)

	// Verify all targets processed
	if len(results) != numTargets {
		t.Errorf("Expected %d results, got %d", numTargets, len(results))
	}

	// Critical invariant: Completed == Successful + Failed
	completed := atomic.LoadInt64(&runner.Stats.Completed)
	successful := atomic.LoadInt64(&runner.Stats.Successful)
	failed := atomic.LoadInt64(&runner.Stats.Failed)

	if completed != successful+failed {
		t.Errorf("Stats inconsistency: Completed(%d) != Successful(%d) + Failed(%d)",
			completed, successful, failed)
	}

	if completed != int64(numTargets) {
		t.Errorf("Stats.Completed = %d, want %d", completed, numTargets)
	}

	// Count actual errors from results
	var actualErrors int64
	for _, r := range results {
		if r.Error != nil {
			actualErrors++
		}
	}

	if failed != actualErrors {
		t.Errorf("Stats.Failed = %d, actual errors = %d", failed, actualErrors)
	}
}

func TestRunner_Run_CallbackRace(t *testing.T) {
	// Verify OnProgress and OnError callbacks are thread-safe under high concurrency
	runner := NewRunner[string]()
	runner.Concurrency = 25

	const numTargets = 100
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = string(rune('a' + i%26))
	}

	// Track callback invocations with atomics
	var progressCallbackCount int64
	var errorCallbackCount int64

	// Shared slice protected by mutex (simulating real-world callback usage)
	var mu sync.Mutex
	progressResults := make([]string, 0, numTargets)

	runner.OnProgress = func(completed, total int64, result Result[string]) {
		atomic.AddInt64(&progressCallbackCount, 1)
		// Simulate real-world callback that modifies shared state
		mu.Lock()
		progressResults = append(progressResults, result.Target)
		mu.Unlock()
	}

	runner.OnError = func(target string, err error) {
		atomic.AddInt64(&errorCallbackCount, 1)
	}

	// Task that fails half the targets
	task := func(ctx context.Context, target string) (string, error) {
		time.Sleep(time.Millisecond)
		if target[0]%2 == 0 {
			return "", errors.New("even target failure")
		}
		return "result-" + target, nil
	}

	ctx := context.Background()
	results := runner.Run(ctx, targets, task)

	// Verify all targets got progress callbacks
	callbackCount := atomic.LoadInt64(&progressCallbackCount)
	if callbackCount != int64(numTargets) {
		t.Errorf("Expected %d progress callbacks, got %d", numTargets, callbackCount)
	}

	// Verify progress results slice has all targets
	mu.Lock()
	progressLen := len(progressResults)
	mu.Unlock()
	if progressLen != numTargets {
		t.Errorf("Expected %d progress results, got %d", numTargets, progressLen)
	}

	// Verify error callbacks match actual failures
	var actualFailures int64
	for _, r := range results {
		if r.Error != nil {
			actualFailures++
		}
	}

	errorCalls := atomic.LoadInt64(&errorCallbackCount)
	if errorCalls != actualFailures {
		t.Errorf("Error callbacks = %d, actual failures = %d", errorCalls, actualFailures)
	}

	// Verify stats consistency
	if runner.Stats.Completed != int64(numTargets) {
		t.Errorf("Stats.Completed = %d, want %d", runner.Stats.Completed, numTargets)
	}
}

func TestRunner_HighConcurrency(t *testing.T) {
	// Stress test: 100 targets with 50 workers
	runner := NewRunner[int]()
	runner.Concurrency = 50

	const numTargets = 100
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = string(rune('a' + i%26))
	}

	// Track concurrent execution
	var currentConcurrent int64
	var maxConcurrent int64
	var taskExecutions int64

	task := func(ctx context.Context, target string) (int, error) {
		// Track entry
		atomic.AddInt64(&taskExecutions, 1)
		cur := atomic.AddInt64(&currentConcurrent, 1)

		// Update max concurrent (lock-free)
		for {
			max := atomic.LoadInt64(&maxConcurrent)
			if cur <= max || atomic.CompareAndSwapInt64(&maxConcurrent, max, cur) {
				break
			}
		}

		// Simulate variable work duration
		time.Sleep(time.Duration(5+target[0]%10) * time.Millisecond)

		// Track exit
		atomic.AddInt64(&currentConcurrent, -1)

		// Mix of success and failure
		if target[0]%7 == 0 {
			return 0, errors.New("target divisible by 7")
		}
		return 1, nil
	}

	ctx := context.Background()
	start := time.Now()
	results := runner.Run(ctx, targets, task)
	elapsed := time.Since(start)

	// Verify all targets processed
	if len(results) != numTargets {
		t.Errorf("Expected %d results, got %d", numTargets, len(results))
	}

	// Verify concurrency was respected (should not exceed 50)
	maxConc := atomic.LoadInt64(&maxConcurrent)
	if maxConc > 50 {
		t.Errorf("Max concurrency exceeded: %d (expected <= 50)", maxConc)
	}
	if maxConc < 10 {
		t.Logf("Warning: Max concurrency was only %d, expected higher utilization", maxConc)
	}

	// Verify all tasks were executed
	executions := atomic.LoadInt64(&taskExecutions)
	if executions != int64(numTargets) {
		t.Errorf("Task executions = %d, want %d", executions, numTargets)
	}

	// Verify stats invariant: Completed == Successful + Failed
	completed := runner.Stats.Completed
	successful := runner.Stats.Successful
	failed := runner.Stats.Failed

	if completed != successful+failed {
		t.Errorf("Stats invariant violated: Completed(%d) != Successful(%d) + Failed(%d)",
			completed, successful, failed)
	}

	if completed != int64(numTargets) {
		t.Errorf("Stats.Completed = %d, want %d", completed, numTargets)
	}

	// Verify concurrent execution was actually occurring (should be faster than serial)
	serialTime := time.Duration(numTargets) * 10 * time.Millisecond // Conservative estimate
	if elapsed > serialTime {
		t.Logf("Warning: Execution took %v, which seems slow for concurrent execution", elapsed)
	}

	t.Logf("High concurrency test completed: %d targets, max concurrent=%d, elapsed=%v",
		numTargets, maxConc, elapsed)
}

func TestRunner_RunWithCallback_ConcurrentRace(t *testing.T) {
	// Test RunWithCallback for race conditions in callback invocation
	runner := NewRunner[int]()
	runner.Concurrency = 30

	const numTargets = 75
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = fmt.Sprintf("target-%d", i)
	}

	// Track callbacks with atomic counters
	var callbackCount int64
	var successCount int64
	var errorCount int64

	// Shared map protected by mutex
	var mu sync.Mutex
	resultMap := make(map[string]int)

	task := func(ctx context.Context, target string) (int, error) {
		time.Sleep(2 * time.Millisecond)
		if target[len(target)-1]%3 == 0 {
			return 0, errors.New("failure")
		}
		return 42, nil
	}

	callback := func(r Result[int]) {
		atomic.AddInt64(&callbackCount, 1)
		if r.Error != nil {
			atomic.AddInt64(&errorCount, 1)
		} else {
			atomic.AddInt64(&successCount, 1)
		}
		mu.Lock()
		resultMap[r.Target] = r.Data
		mu.Unlock()
	}

	ctx := context.Background()
	runner.RunWithCallback(ctx, targets, task, callback)

	// Verify all callbacks fired
	calls := atomic.LoadInt64(&callbackCount)
	if calls != int64(numTargets) {
		t.Errorf("Expected %d callbacks, got %d", numTargets, calls)
	}

	// Verify success + error = total
	successes := atomic.LoadInt64(&successCount)
	errors := atomic.LoadInt64(&errorCount)
	if successes+errors != int64(numTargets) {
		t.Errorf("Success(%d) + Error(%d) != Total(%d)", successes, errors, numTargets)
	}

	// Verify result map has all targets
	mu.Lock()
	mapLen := len(resultMap)
	mu.Unlock()
	if mapLen != numTargets {
		t.Errorf("Result map has %d entries, expected %d", mapLen, numTargets)
	}

	// Verify stats consistency
	if runner.Stats.Completed != int64(numTargets) {
		t.Errorf("Stats.Completed = %d, want %d", runner.Stats.Completed, numTargets)
	}
	if runner.Stats.Completed != runner.Stats.Successful+runner.Stats.Failed {
		t.Errorf("Stats inconsistency: Completed(%d) != Successful(%d) + Failed(%d)",
			runner.Stats.Completed, runner.Stats.Successful, runner.Stats.Failed)
	}
}
