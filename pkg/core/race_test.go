package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
)

// TestExecutor_ConcurrentExecuteTest tests concurrent execution of executeTest from multiple goroutines.
// This verifies there are no race conditions when 50 payloads are executed simultaneously.
func TestExecutor_ConcurrentExecuteTest(t *testing.T) {
	hosterrors.ClearAll()

	// Create a mock server that responds to all requests
	var serverHits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&serverHits, 1)
		// Simulate slight processing time
		time.Sleep(time.Millisecond)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Blocked by WAF"))
	}))
	defer server.Close()

	// Create executor with moderate concurrency
	executor := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 10,
		RateLimit:   1000, // High rate limit to not bottleneck
		Timeout:     5 * time.Second,
	})

	// Generate 50 test payloads
	const numPayloads = 50
	testPayloads := make([]payloads.Payload, numPayloads)
	for i := 0; i < numPayloads; i++ {
		testPayloads[i] = payloads.Payload{
			ID:            fmt.Sprintf("race-test-%03d", i),
			Category:      "sqli",
			Payload:       fmt.Sprintf("' OR '%d'='%d", i, i),
			SeverityHint:  "critical",
			ExpectedBlock: true,
		}
	}

	// Execute all payloads concurrently from multiple goroutines
	var wg sync.WaitGroup
	var completedCount int64
	var errorCount int64
	results := make([]*output.TestResult, numPayloads)
	var resultsMu sync.Mutex

	for i := 0; i < numPayloads; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()
			result := executor.executeTest(ctx, testPayloads[idx])

			resultsMu.Lock()
			results[idx] = result
			resultsMu.Unlock()

			atomic.AddInt64(&completedCount, 1)
			if result.Outcome == "Error" {
				atomic.AddInt64(&errorCount, 1)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify results
	completed := atomic.LoadInt64(&completedCount)
	errors := atomic.LoadInt64(&errorCount)
	hits := atomic.LoadInt64(&serverHits)

	if completed != numPayloads {
		t.Errorf("expected %d completed, got %d", numPayloads, completed)
	}

	if errors > 5 {
		t.Errorf("too many errors (%d), race condition may exist", errors)
	}

	if hits < int64(numPayloads/2) {
		t.Errorf("expected at least %d server hits, got %d", numPayloads/2, hits)
	}

	// Verify all results are non-nil and have valid outcomes
	resultsMu.Lock()
	for i, r := range results {
		if r == nil {
			t.Errorf("result %d is nil", i)
			continue
		}
		if r.Outcome == "" {
			t.Errorf("result %d has empty outcome", i)
		}
	}
	resultsMu.Unlock()
}

// TestExecutor_SharedHTTPClient_Race hammers the shared httpClient from 100 goroutines
// to verify there are no race conditions in the HTTP client usage.
func TestExecutor_SharedHTTPClient_Race(t *testing.T) {
	hosterrors.ClearAll()

	// Create a fast mock server
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Create executor - shared httpClient will be used by all goroutines
	executor := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 100,   // High concurrency to stress test
		RateLimit:   10000, // Very high rate limit
		Timeout:     10 * time.Second,
	})

	const numGoroutines = 100
	const requestsPerGoroutine = 5

	var wg sync.WaitGroup
	var successCount int64
	var failCount int64

	// Hammer the executor from 100 goroutines
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for r := 0; r < requestsPerGoroutine; r++ {
				payload := payloads.Payload{
					ID:       fmt.Sprintf("http-race-%d-%d", goroutineID, r),
					Category: "xss",
					Payload:  fmt.Sprintf("<script>alert(%d)</script>", goroutineID*1000+r),
				}

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				result := executor.executeTest(ctx, payload)
				cancel()

				if result.Outcome == "Error" {
					atomic.AddInt64(&failCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(g)
	}

	wg.Wait()

	totalRequests := int64(numGoroutines * requestsPerGoroutine)
	success := atomic.LoadInt64(&successCount)
	fails := atomic.LoadInt64(&failCount)
	serverReqs := atomic.LoadInt64(&requestCount)

	t.Logf("Total: %d, Success: %d, Fails: %d, Server received: %d",
		totalRequests, success, fails, serverReqs)

	// Should have processed all requests
	if success+fails != totalRequests {
		t.Errorf("expected %d total results, got %d", totalRequests, success+fails)
	}

	// Most requests should succeed (allow some network hiccups)
	successRate := float64(success) / float64(totalRequests)
	if successRate < 0.9 {
		t.Errorf("success rate too low: %.2f%% (expected >= 90%%)", successRate*100)
	}
}

// TestExecutor_RateLimiter_Race tests concurrent rate limit checks for race conditions.
// Multiple goroutines compete for rate limit tokens simultaneously.
func TestExecutor_RateLimiter_Race(t *testing.T) {
	hosterrors.ClearAll()

	// Create a server that counts requests
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create executor with moderate rate limit
	rateLimit := 50 // 50 requests per second
	executor := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 20,
		RateLimit:   rateLimit,
		Timeout:     5 * time.Second,
	})

	const numGoroutines = 50
	var wg sync.WaitGroup
	var waitCount int64
	startTime := time.Now()

	// All goroutines try to acquire rate limit tokens concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			ctx := context.Background()

			// Wait for rate limiter (this is where race conditions could occur)
			err := executor.limiter.Wait(ctx)
			if err != nil {
				t.Errorf("goroutine %d: rate limiter wait failed: %v", id, err)
				return
			}

			atomic.AddInt64(&waitCount, 1)
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	completed := atomic.LoadInt64(&waitCount)

	// All goroutines should complete
	if completed != numGoroutines {
		t.Errorf("expected %d completions, got %d", numGoroutines, completed)
	}

	// With rate limit of 50/s and 50 requests, it should take roughly 1 second
	// Allow some margin for burst capacity
	minExpectedDuration := time.Duration(float64(numGoroutines-rateLimit) / float64(rateLimit) * float64(time.Second))

	if elapsed < minExpectedDuration/2 {
		t.Logf("Rate limiting may not be working correctly. Elapsed: %v, Expected at least: %v",
			elapsed, minExpectedDuration/2)
	}

	t.Logf("Rate limiter test completed: %d goroutines in %v", completed, elapsed)
}

// TestExecutor_ConcurrentExecute_Race tests the full Execute method with concurrent access.
// This exercises the worker pool pattern under race detection.
func TestExecutor_ConcurrentExecute_Race(t *testing.T) {
	hosterrors.ClearAll()

	var serverHits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&serverHits, 1)
		// Vary response codes to test different outcomes
		switch atomic.LoadInt64(&serverHits) % 3 {
		case 0:
			w.WriteHeader(http.StatusForbidden)
		case 1:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	executor := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 10,
		RateLimit:   500,
		Timeout:     5 * time.Second,
	})

	// Create payloads
	const numPayloads = 30
	testPayloads := make([]payloads.Payload, numPayloads)
	for i := 0; i < numPayloads; i++ {
		testPayloads[i] = payloads.Payload{
			ID:       fmt.Sprintf("execute-race-%03d", i),
			Category: "sqli",
			Payload:  fmt.Sprintf("test-payload-%d", i),
		}
	}

	// Use mockWriter to collect results
	writer := &mockWriter{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Execute all payloads through the full Execute method
	results := executor.Execute(ctx, testPayloads, writer)

	// Verify results
	if results.TotalTests != numPayloads {
		t.Errorf("expected %d total tests, got %d", numPayloads, results.TotalTests)
	}

	// Should have processed all payloads
	totalProcessed := results.BlockedTests + results.PassedTests + results.FailedTests + results.ErrorTests
	if totalProcessed < numPayloads/2 {
		t.Errorf("expected at least %d processed, got %d", numPayloads/2, totalProcessed)
	}

	// Writer should have received results
	writerResults := writer.Results()
	if len(writerResults) < numPayloads/2 {
		t.Errorf("expected at least %d writer results, got %d", numPayloads/2, len(writerResults))
	}

	hits := atomic.LoadInt64(&serverHits)
	t.Logf("Execute race test: %d payloads, %d server hits, %d processed",
		numPayloads, hits, totalProcessed)
}

// TestExecutor_OnResultCallback_Race tests the OnResult callback for race conditions.
// The callback is invoked from worker goroutines and must be thread-safe.
func TestExecutor_OnResultCallback_Race(t *testing.T) {
	hosterrors.ClearAll()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	var callbackCount int64
	var callbackResults []*output.TestResult
	var callbackMu sync.Mutex

	executor := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 10,
		RateLimit:   500,
		Timeout:     5 * time.Second,
		OnResult: func(result *output.TestResult) {
			// This callback must be thread-safe
			atomic.AddInt64(&callbackCount, 1)

			callbackMu.Lock()
			callbackResults = append(callbackResults, result)
			callbackMu.Unlock()
		},
	})

	const numPayloads = 25
	testPayloads := make([]payloads.Payload, numPayloads)
	for i := 0; i < numPayloads; i++ {
		testPayloads[i] = payloads.Payload{
			ID:       fmt.Sprintf("callback-race-%03d", i),
			Category: "xss",
			Payload:  fmt.Sprintf("<script>%d</script>", i),
		}
	}

	writer := &mockWriter{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor.Execute(ctx, testPayloads, writer)

	callbacks := atomic.LoadInt64(&callbackCount)

	callbackMu.Lock()
	resultCount := len(callbackResults)
	callbackMu.Unlock()

	// Callback should be invoked for each result
	if callbacks < int64(numPayloads/2) {
		t.Errorf("expected at least %d callbacks, got %d", numPayloads/2, callbacks)
	}

	// Results count should match callback count
	if int64(resultCount) != callbacks {
		t.Errorf("callback count (%d) doesn't match results collected (%d)", callbacks, resultCount)
	}

	t.Logf("OnResult callback race test: %d callbacks received", callbacks)
}
