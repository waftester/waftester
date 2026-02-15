package apispec

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSpecScanResultAddFinding(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}

	r.AddFinding(SpecFinding{
		Method:   "GET",
		Path:     "/users",
		Category: "sqli",
		Severity: "high",
		Title:    "SQL Injection",
	})
	r.AddFinding(SpecFinding{
		Method:   "POST",
		Path:     "/login",
		Category: "xss",
		Severity: "medium",
		Title:    "XSS",
	})

	assert.Equal(t, 2, r.TotalFindings())
}

func TestSpecScanResultConcurrency(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.AddFinding(SpecFinding{
				Method:   "GET",
				Path:     "/test",
				Category: "sqli",
				Severity: "high",
				Title:    "test",
			})
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 100, r.TotalFindings())
}

func TestSpecScanResultBySeverity(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}
	r.AddFinding(SpecFinding{Severity: "high"})
	r.AddFinding(SpecFinding{Severity: "high"})
	r.AddFinding(SpecFinding{Severity: "medium"})

	bySev := r.BySeverity()
	assert.Equal(t, 2, bySev["high"])
	assert.Equal(t, 1, bySev["medium"])
}

func TestSpecScanResultByCategory(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}
	r.AddFinding(SpecFinding{Category: "sqli"})
	r.AddFinding(SpecFinding{Category: "sqli"})
	r.AddFinding(SpecFinding{Category: "xss"})

	byCat := r.ByCategory()
	assert.Equal(t, 2, byCat["sqli"])
	assert.Equal(t, 1, byCat["xss"])
}

func TestSpecScanResultAddError(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}
	r.AddError("connection refused")
	r.AddError("timeout")
	assert.Len(t, r.Errors, 2)
}

func TestSpecScanResultFinalize(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}
	time.Sleep(10 * time.Millisecond)
	r.Finalize()
	assert.False(t, r.CompletedAt.IsZero())
	assert.Greater(t, r.Duration.Nanoseconds(), int64(0))
}

func TestSpecScanResultAddEndpointResult(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}
	r.AddEndpointResult(EndpointResult{
		Method: "GET",
		Path:   "/users",
	})
	assert.Len(t, r.EndpointResults, 1)
}

// ──────────────────────────────────────────────────────────────────────────────
// Negative / edge-case tests.
// ──────────────────────────────────────────────────────────────────────────────

func TestSpecScanResultEmpty(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}
	assert.Equal(t, 0, r.TotalFindings())
	assert.Empty(t, r.BySeverity())
	assert.Empty(t, r.ByCategory())
	assert.Empty(t, r.Errors)
	assert.Empty(t, r.EndpointResults)
}

func TestSpecScanResultConcurrentErrors(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.AddFinding(SpecFinding{Severity: "high"})
		}()
		go func() {
			defer wg.Done()
			r.AddError("concurrent error")
		}()
	}
	wg.Wait()

	assert.Equal(t, 50, r.TotalFindings())
	assert.Len(t, r.Errors, 50)
}

func TestSpecScanResultFinalizeIdempotent(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{StartedAt: time.Now()}
	time.Sleep(5 * time.Millisecond)
	r.Finalize()
	first := r.CompletedAt
	firstDur := r.Duration

	time.Sleep(5 * time.Millisecond)
	r.Finalize()
	second := r.CompletedAt
	secondDur := r.Duration

	// Second call must be a no-op: same CompletedAt and Duration.
	assert.False(t, first.IsZero())
	assert.Equal(t, first, second, "Finalize must be idempotent: CompletedAt changed on second call")
	assert.Equal(t, firstDur, secondDur, "Finalize must be idempotent: Duration changed on second call")
}

func TestSpecScanResultBySeverityEmpty(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{}
	m := r.BySeverity()
	assert.NotNil(t, m)
	assert.Empty(t, m)
}

func TestSpecScanResultByCategoryEmpty(t *testing.T) {
	t.Parallel()
	r := &SpecScanResult{}
	m := r.ByCategory()
	assert.NotNil(t, m)
	assert.Empty(t, m)
}
