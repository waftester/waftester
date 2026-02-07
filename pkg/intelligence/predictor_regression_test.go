// Regression tests for concurrency bugs in the Predictor.
package intelligence

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Regression test for bug: PredictBatch internally called Predict which took RLock,
// causing re-entrant lock deadlock when PredictBatch already held RLock.
func TestPredictBatch_NoDeadlock(t *testing.T) {
	t.Parallel()

	p := NewPredictor()

	// Record some test data via Learn (the public API)
	p.Learn(&Finding{
		Category:   "xss",
		Payload:    "<script>alert(1)</script>",
		Path:       "/test",
		Blocked:    true,
		StatusCode: 403,
		Latency:    50 * time.Millisecond,
	})
	p.Learn(&Finding{
		Category:   "sqli",
		Payload:    "' OR 1=1--",
		Path:       "/admin",
		Blocked:    false,
		StatusCode: 200,
		Latency:    30 * time.Millisecond,
	})

	candidates := []PayloadCandidate{
		{Category: "xss", Payload: "<img onerror=alert(1)>", Path: "/test"},
		{Category: "sqli", Payload: "1 UNION SELECT", Path: "/admin"},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ranked := p.PredictBatch(candidates, nil)
		if len(ranked) != len(candidates) {
			t.Errorf("expected %d ranked results, got %d", len(candidates), len(ranked))
		}
	}()

	select {
	case <-done:
		// Completed without deadlock — success.
	case <-time.After(2 * time.Second):
		t.Fatal("PredictBatch deadlocked (2s timeout)")
	}
}

// Regression test for bug: concurrent RecordResult (Learn) and Predict could panic or deadlock.
func TestPredictor_ConcurrentRecordAndPredict(t *testing.T) {
	t.Parallel()

	p := NewPredictor()

	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(4) // 2 writers + 2 readers

	// 2 goroutines recording findings
	for g := 0; g < 2; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				p.Learn(&Finding{
					Category:   fmt.Sprintf("cat-%d", i%5),
					Payload:    fmt.Sprintf("payload-%d-%d", id, i),
					Path:       fmt.Sprintf("/path-%d", i%3),
					Blocked:    i%2 == 0,
					StatusCode: 200 + (i % 5),
					Latency:    time.Duration(i) * time.Millisecond,
				})
			}
		}(g)
	}

	// 2 goroutines predicting
	for g := 0; g < 2; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				pred := p.Predict(
					fmt.Sprintf("cat-%d", i%5),
					fmt.Sprintf("test-payload-%d-%d", id, i),
					fmt.Sprintf("/path-%d", i%3),
					nil,
				)
				if pred == nil {
					t.Error("Predict returned nil")
				}
			}
		}(g)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("ConcurrentRecordAndPredict deadlocked (5s timeout)")
	}
}
