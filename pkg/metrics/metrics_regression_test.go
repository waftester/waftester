// Regression tests for concurrency bugs in the metrics Calculator.
package metrics

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Regression test for bug: concurrent AddAttackResult/AddBenignResult could race on internal slices.
func TestCalculator_ConcurrentAdd(t *testing.T) {
	t.Parallel()

	calc := NewCalculator()

	var wg sync.WaitGroup

	const goroutines = 10
	const perGoroutine = 100

	// 10 goroutines adding attack results
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				calc.AddAttackResult(AttackResult{
					ID:         fmt.Sprintf("attack-%d-%d", id, i),
					Category:   "xss",
					Blocked:    i%2 == 0,
					StatusCode: 200,
					Latency:    time.Duration(i) * time.Millisecond,
				})
			}
		}(g)
	}

	// 10 goroutines adding benign results
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				calc.AddBenignResult(BenignResult{
					ID:         fmt.Sprintf("benign-%d-%d", id, i),
					Corpus:     "common-words",
					Blocked:    false,
					StatusCode: 200,
					Latency:    time.Duration(i) * time.Millisecond,
					Location:   "query",
				})
			}
		}(g)
	}

	wg.Wait()

	m := calc.Calculate("https://test.example.com", "TestWAF", 10*time.Second)
	if m == nil {
		t.Fatal("Calculate returned nil")
	}

	wantTotal := int64(goroutines*perGoroutine) * 2 // attacks + benign
	if m.TotalRequests != wantTotal {
		t.Errorf("expected %d total requests, got %d", wantTotal, m.TotalRequests)
	}
}

// Regression test for bug: calling Calculate while AddAttackResult is running could race.
func TestCalculator_CalculateDuringAdd(t *testing.T) {
	t.Parallel()

	calc := NewCalculator()

	var wg sync.WaitGroup

	// Goroutine continuously adding results
	wg.Add(1)
	stop := make(chan struct{})
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				calc.AddAttackResult(AttackResult{
					ID:         fmt.Sprintf("attack-%d", i),
					Category:   "sqli",
					Blocked:    i%3 == 0,
					StatusCode: 200,
					Latency:    time.Duration(i%100) * time.Millisecond,
				})
				i++
			}
		}
	}()

	// Goroutine calling Calculate repeatedly
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			m := calc.Calculate("https://test.example.com", "TestWAF", time.Second)
			if m == nil {
				t.Error("Calculate returned nil during concurrent add")
			}
		}
		close(stop)
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("CalculateDuringAdd deadlocked (5s timeout)")
	}
}
