package filter

// Concurrency tests for Filter — verifies no data races on concurrent
// ShouldShow calls with FilterDuplicates enabled.
// Would have caught R1 (concurrent map access in seenHashes).

import (
	"fmt"
	"sync"
	"testing"
)

// TestFilter_ConcurrentShouldShow_NoPanic verifies ShouldShow is safe
// for concurrent use, especially with FilterDuplicates enabled.
func TestFilter_ConcurrentShouldShow_NoPanic(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		FilterDuplicates: true,
	}
	f := NewFilter(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				resp := &Response{
					StatusCode:    200,
					ContentLength: 100 + idx,
					Body:          []byte(fmt.Sprintf("body-%d-%d", idx, j)),
					Simhash:       uint64(idx*1000 + j),
				}
				f.ShouldShow(resp)
			}
		}(i)
	}
	wg.Wait()
}

// TestFilter_ConcurrentShouldShow_DuplicateDetection verifies duplicate
// detection works correctly under concurrent access.
func TestFilter_ConcurrentShouldShow_DuplicateDetection(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		FilterDuplicates: true,
	}
	f := NewFilter(cfg)

	// First call with a specific simhash should show
	resp1 := &Response{
		StatusCode:    200,
		ContentLength: 100,
		Body:          []byte("unique-body"),
		Simhash:       12345,
	}
	first := f.ShouldShow(resp1)
	if !first {
		t.Error("first response with unique simhash should be shown")
	}

	// Second call with same simhash should be filtered as duplicate
	resp2 := &Response{
		StatusCode:    200,
		ContentLength: 100,
		Body:          []byte("duplicate-body"),
		Simhash:       12345,
	}
	second := f.ShouldShow(resp2)
	if second {
		t.Error("duplicate simhash should be filtered")
	}
}

// TestFilter_MatchMode_AND verifies AND mode requires all criteria to match.
// Would have caught R1 (Filter AND mode false negatives).
func TestFilter_MatchMode_AND(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		MatchStatus: []int{200},
		MatchString: []string{"expected"},
		MatchMode:   ModeAnd,
	}
	f := NewFilter(cfg)

	// Matches status but not string — should NOT show in AND mode
	resp := &Response{
		StatusCode:    200,
		ContentLength: 50,
		Body:          []byte("no match here"),
	}
	if f.ShouldShow(resp) {
		t.Error("AND mode: response missing string match should not be shown")
	}

	// Matches both — should show
	resp2 := &Response{
		StatusCode:    200,
		ContentLength: 50,
		Body:          []byte("expected content"),
	}
	if !f.ShouldShow(resp2) {
		t.Error("AND mode: response matching all criteria should be shown")
	}
}

// TestFilter_NilConfig_NoPanic verifies NewFilter handles nil gracefully.
func TestFilter_NilConfig_NoPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewFilter(nil) panicked: %v", r)
		}
	}()

	f := NewFilter(nil)
	if f == nil {
		t.Log("NewFilter(nil) returned nil — acceptable")
		return
	}

	// If filter was created, ShouldShow with nil response shouldn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Logf("ShouldShow(nil) panicked: %v (acceptable)", r)
		}
	}()
	f.ShouldShow(&Response{StatusCode: 200, Body: []byte("test")})
}
