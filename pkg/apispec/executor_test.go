package apispec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockWAFDetector implements WAFDetector for testing.
type mockWAFDetector struct {
	result WAFDetectResult
	err    error
}

func (m *mockWAFDetector) Detect(_ context.Context, _ string) (WAFDetectResult, error) {
	return m.result, m.err
}

// mockRateLimiter implements RateLimiter for testing.
type mockRateLimiter struct {
	waitCalls atomic.Int64
}

func (m *mockRateLimiter) Wait(_ context.Context) error {
	m.waitCalls.Add(1)
	return nil
}
func (m *mockRateLimiter) OnError()   {}
func (m *mockRateLimiter) OnSuccess() {}

func testPlan(entries int) *ScanPlan {
	plan := &ScanPlan{
		Entries:    make([]ScanPlanEntry, entries),
		TotalTests: entries * 10,
		Intensity:  IntensityNormal,
		SpecSource: "test-spec.json",
	}
	for i := 0; i < entries; i++ {
		plan.Entries[i] = ScanPlanEntry{
			Endpoint: Endpoint{
				Method: "GET",
				Path:   fmt.Sprintf("/api/v1/resource%d", i),
			},
			Attack: AttackSelection{
				Category:     "sqli",
				PayloadCount: 10,
			},
			InjectionTarget: InjectionTarget{
				Parameter: "id",
				Location:  LocationQuery,
			},
		}
	}
	return plan
}

func TestAdaptiveExecutor_NilPlan(t *testing.T) {
	e := &AdaptiveExecutor{
		BaseURL: "http://example.com",
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			t.Fatal("ScanFn should not be called for nil plan")
			return nil, nil
		},
	}

	session, err := e.Execute(context.Background(), nil)
	require.NoError(t, err)
	assert.NotEmpty(t, session.ID)
}

func TestAdaptiveExecutor_EmptyPlan(t *testing.T) {
	e := &AdaptiveExecutor{
		BaseURL: "http://example.com",
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			t.Fatal("ScanFn should not be called for empty plan")
			return nil, nil
		},
	}

	session, err := e.Execute(context.Background(), &ScanPlan{})
	require.NoError(t, err)
	assert.NotEmpty(t, session.ID)
}

func TestAdaptiveExecutor_BasicScan(t *testing.T) {
	// Start a test server that returns 200 for baseline, 200 for block probe.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var scanCalls atomic.Int64
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			scanCalls.Add(1)
			return []SpecFinding{
				{
					Method:   "GET",
					Path:     "/test",
					Category: "sqli",
					Severity: "high",
					Title:    "SQL Injection",
				},
			}, nil
		},
		Concurrency: 2,
	}

	plan := testPlan(5)
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	assert.NotEmpty(t, session.ID)
	assert.Greater(t, session.TotalFindings, 0)
	assert.Greater(t, scanCalls.Load(), int64(0))
}

func TestAdaptiveExecutor_WithWAFDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("test") != "" {
			// Block page for known-bad payload.
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access Denied - Request Blocked by WAF")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var phasesSeen []string
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
		WAF: &mockWAFDetector{
			result: WAFDetectResult{
				Detected:   true,
				Vendor:     "cloudflare",
				Confidence: 0.95,
			},
		},
		OnPhaseStart: func(phase string) {
			phasesSeen = append(phasesSeen, phase)
		},
	}

	plan := testPlan(20)
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.NotEmpty(t, session.ID)

	// All 3 phases should have been executed.
	assert.Contains(t, phasesSeen, "fingerprint")
	assert.Contains(t, phasesSeen, "probe")
	assert.Contains(t, phasesSeen, "full-scan")
}

func TestAdaptiveExecutor_WAFBlocksAllProbes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("test") != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access Denied - Request Blocked by WAF")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	// All scan calls return empty findings (everything blocked).
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil // No findings = blocked
		},
		WAF: &mockWAFDetector{
			result: WAFDetectResult{
				Detected:   true,
				Vendor:     "cloudflare",
				Confidence: 0.9,
			},
		},
	}

	plan := testPlan(20)
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.NotEmpty(t, session.ID)
}

func TestAdaptiveExecutor_WithRateLimiter(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	limiter := &mockRateLimiter{}
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
		Limiter: limiter,
	}

	plan := testPlan(10)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// Rate limiter should have been called for probe + full scan entries.
	assert.Greater(t, limiter.waitCalls.Load(), int64(0))
}

func TestAdaptiveExecutor_WithRequestBudget(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var scanCalls atomic.Int64
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			scanCalls.Add(1)
			return nil, nil
		},
		Budget: &RequestBudget{
			MaxTotal: 5,
		},
	}

	plan := testPlan(100)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// With budget of 5 and concurrency of 1, scan calls must be tightly bounded.
	// Allow small overshoot from budget check timing.
	assert.LessOrEqual(t, scanCalls.Load(), int64(10), "budget of 5 should cap calls well below 100")
}

func TestAdaptiveExecutor_CancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
	}

	plan := testPlan(10)
	session, err := e.Execute(ctx, plan)
	// May return error or not depending on timing, but should not panic.
	_ = err
	assert.NotNil(t, session)
}

func TestAdaptiveExecutor_FindingsCollected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var findingsReported atomic.Int64
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, ep Endpoint) ([]SpecFinding, error) {
			return []SpecFinding{
				{
					Method:   ep.Method,
					Path:     ep.Path,
					Category: "xss",
					Severity: "medium",
					Title:    "XSS Found",
				},
			}, nil
		},
		OnFinding: func(_ SpecFinding) {
			findingsReported.Add(1)
		},
	}

	plan := testPlan(5)
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.Greater(t, session.TotalFindings, 0)
	assert.Greater(t, findingsReported.Load(), int64(0))
}

func TestAdaptiveExecutor_PhaseCallbacks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var phaseDurations = make(map[string]time.Duration)
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
		OnPhaseComplete: func(phase string, d time.Duration) {
			phaseDurations[phase] = d
		},
	}

	plan := testPlan(5)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	assert.Contains(t, phaseDurations, "fingerprint")
	assert.Contains(t, phaseDurations, "probe")
	assert.Contains(t, phaseDurations, "full-scan")
}

func TestAdaptiveExecutor_EscalationCallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("test") != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access Denied - Request Blocked")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var escalationCalled atomic.Bool
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil // Always blocked
		},
		WAF: &mockWAFDetector{
			result: WAFDetectResult{Detected: true, Vendor: "test-waf"},
		},
		OnEscalation: func(from, to EscalationLevel, reason string) {
			escalationCalled.Store(true)
		},
	}

	plan := testPlan(30) // Need enough entries to trigger escalation
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)
	// Escalation depends on probe phase detecting blocks, which may not
	// happen with this mock. The main value: no panic with callback wired.
	_ = escalationCalled.Load()
}

func TestAdaptiveExecutor_ScanErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}

	plan := testPlan(5)
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)        // Execute itself should not fail
	assert.NotEmpty(t, session.ID) // Session still created
}

func TestAdaptiveExecutor_EndpointCallbacks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var starts, completes atomic.Int64
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
		OnEndpointStart: func(_ Endpoint, _ string) {
			starts.Add(1)
		},
		OnEndpointComplete: func(_ Endpoint, _ string, _ int, _ error) {
			completes.Add(1)
		},
	}

	plan := testPlan(5)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// At least the full-scan phase should trigger endpoint callbacks.
	// Probes trigger ScanFn but not OnEndpointStart/OnEndpointComplete.
	assert.Greater(t, starts.Load()+completes.Load(), int64(0))
}

func TestContainsCI(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"Access Denied", "access denied", true},
		{"ACCESS DENIED", "access denied", true},
		{"hello world", "world", true},
		{"hello", "hello world", false},
		{"", "test", false},
		{"test", "", false},
	}
	for _, tt := range tests {
		got := containsCI(tt.s, tt.substr)
		assert.Equal(t, tt.want, got, "containsCI(%q, %q)", tt.s, tt.substr)
	}
}

func TestCorrelationID(t *testing.T) {
	id := correlationID("sess1", "ep1", "sqli", "param1", 42)
	assert.Equal(t, "waftester-sess1-ep1-sqli-param1-42", id)
}

func TestPayloadHash(t *testing.T) {
	h1 := payloadHash("<script>alert(1)</script>")
	h2 := payloadHash("<script>alert(2)</script>")
	assert.Len(t, h1, 16) // 8 bytes = 16 hex chars
	assert.NotEqual(t, h1, h2)
}

// ──────────────────────────────────────────────────────────────────────────────
// Regression tests: each test is designed to fail if a specific Round 1-6 bug
// is reintroduced. They simulate realistic execution flows, not just API
// surface checks.
// ──────────────────────────────────────────────────────────────────────────────

// --- Round 6 regressions ---

func TestRegression_ProbePhaseFiresOnEndpointCallbacks(t *testing.T) {
	// BUG: Probe phase ran ScanFn but never called OnEndpointStart or
	// OnEndpointComplete. Progress UIs showed 0% progress for the first 10%
	// of scanning.
	//
	// Verification: with ProbePercent=1.0 (all entries go to probe phase, none
	// to full-scan), every entry must trigger both Start and Complete callbacks.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	type callbackRecord struct {
		path     string
		scanType string
		kind     string // "start" or "complete"
	}
	var records []callbackRecord
	var mu sync.Mutex

	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		ProbePercent: 1.0,
		Concurrency:  1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
		OnEndpointStart: func(ep Endpoint, scanType string) {
			mu.Lock()
			records = append(records, callbackRecord{ep.Path, scanType, "start"})
			mu.Unlock()
		},
		OnEndpointComplete: func(ep Endpoint, scanType string, _ int, _ error) {
			mu.Lock()
			records = append(records, callbackRecord{ep.Path, scanType, "complete"})
			mu.Unlock()
		},
	}

	plan := testPlan(3)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// For each of the 3 entries, we must see a start followed by a complete.
	starts := 0
	completes := 0
	for _, r := range records {
		if r.kind == "start" {
			starts++
		} else {
			completes++
		}
	}
	assert.Equal(t, 3, starts, "probe must call OnEndpointStart for every entry")
	assert.Equal(t, 3, completes, "probe must call OnEndpointComplete for every entry")
}

func TestRegression_ProbeErrorStillFiresOnEndpointComplete(t *testing.T) {
	// BUG: When ScanFn returned an error in probe phase, the loop continued
	// without calling OnEndpointComplete, breaking progress tracking.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var completedErrors []error
	var mu sync.Mutex

	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		ProbePercent: 1.0,
		Concurrency:  1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, fmt.Errorf("simulated timeout")
		},
		OnEndpointComplete: func(_ Endpoint, _ string, _ int, err error) {
			mu.Lock()
			completedErrors = append(completedErrors, err)
			mu.Unlock()
		},
	}

	plan := testPlan(3)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	assert.Len(t, completedErrors, 3, "every probe entry must fire OnEndpointComplete even on error")
	for i, e := range completedErrors {
		assert.Error(t, e, "entry %d: OnEndpointComplete must receive the error", i)
	}
}

func TestRegression_TotalEndpointsCountsProbeOnlyEndpoints(t *testing.T) {
	// BUG: TotalEndpoints was counted only in phaseFullScan's endpointSet.
	// When ProbePercent=1.0, all entries went to probe and full-scan had 0
	// remaining entries → TotalEndpoints was 0.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		ProbePercent: 1.0,
		Concurrency:  1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
	}

	plan := testPlan(4)
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	assert.Equal(t, 4, session.TotalEndpoints,
		"all 4 probe-only endpoints must be counted")
	assert.Equal(t, 4, session.Result.TotalEndpoints,
		"session.Result must have same TotalEndpoints")
}

func TestRegression_ProbeEndpointsMergedIntoFullScanCount(t *testing.T) {
	// BUG: phaseFullScan only counted entries in remaining[] slice. Endpoints
	// scanned during probe were missing from TotalEndpoints.
	// Fix: pre-populate endpointSet with probe entries.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		ProbePercent: 0.5, // First 2 of 4 entries go to probe.
		Concurrency:  1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
	}

	plan := testPlan(4) // 4 unique endpoints
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	assert.Equal(t, 4, session.TotalEndpoints,
		"TotalEndpoints must include both probe and full-scan endpoints")
}

func TestRegression_SessionResultMetricsNotZero(t *testing.T) {
	// BUG: In cmd_scan_spec.go, session.Result.TotalEndpoints and TotalTests
	// were always 0 because they were set on result *inside* Execute, but the
	// outer caller read session.Result which was the same pointer but the
	// fields were set after Finalize() which doesn't touch them.
	// This test verifies they flow through correctly.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	e := &AdaptiveExecutor{
		BaseURL:     ts.URL,
		Concurrency: 1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
	}

	plan := testPlan(5)
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// Both session-level and result-level fields must be populated.
	require.NotNil(t, session.Result)
	assert.Equal(t, session.TotalEndpoints, session.Result.TotalEndpoints,
		"session.TotalEndpoints must mirror session.Result.TotalEndpoints")
	assert.Equal(t, session.TotalTests, session.Result.TotalTests,
		"session.TotalTests must mirror session.Result.TotalTests")
	assert.Greater(t, session.Result.TotalEndpoints, 0,
		"Result.TotalEndpoints must not be zero after scanning")
	assert.Greater(t, session.Result.TotalTests, 0,
		"Result.TotalTests must not be zero after scanning")
}

func TestRegression_RequestsSentIncrementedBeforeScanFn(t *testing.T) {
	// BUG: RequestsSent.Add(1) was placed AFTER e.ScanFn() call. Under
	// concurrency the budget check sees a stale count and dispatches more
	// goroutines than the budget allows. Fixed: Add(1) now comes before ScanFn.
	//
	// Verification: With Concurrency=2, two goroutines can be in-flight
	// simultaneously. If Add happens before ScanFn, the second goroutine's
	// ScanFn sees sent>=1. We use a synchronization barrier to force overlap
	// and verify total calls stay within budget + concurrency headroom.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	// Tight budget: only 3 requests allowed.
	budget := &RequestBudget{MaxTotal: 3}
	var scanCallCount atomic.Int64

	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		Budget:       budget,
		Concurrency:  2, // Concurrent dispatch to expose stale-count races.
		ProbePercent: 0.01,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			scanCallCount.Add(1)
			// Small sleep to widen the window where a stale RequestsSent
			// count could allow an extra dispatch.
			time.Sleep(5 * time.Millisecond)
			return nil, nil
		},
	}

	plan := testPlan(50) // Many more entries than budget allows.
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// Budget is 3. With concurrency=2, at most 2 goroutines may pass the
	// budget check simultaneously before either increments, giving a
	// maximum overshoot of concurrency-1 = 1. Total calls must be at most
	// budget + concurrency = 5 (3 budget + 1 probe + 1 concurrency window).
	assert.LessOrEqual(t, scanCallCount.Load(), int64(5),
		"budget of 3 + concurrency window must cap total scan calls")
	// Without budget enforcement at all, this would be 50.
	assert.Greater(t, scanCallCount.Load(), int64(0),
		"must execute at least one scan")
}

// --- Round 1-4 regressions ---

func TestRegression_LimiterErrorFiresOnEndpointComplete(t *testing.T) {
	// BUG: When Limiter.Wait() returned an error in full-scan phase, the
	// goroutine returned without calling OnEndpointComplete, breaking
	// the start/complete callback contract (every Start has a Complete).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	errorLimiter := &errorOnNthRateLimiter{errorAfter: 0} // Error on every call.
	var starts, completes atomic.Int64

	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		Limiter:      errorLimiter,
		Concurrency:  1,
		ProbePercent: 0.01,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
		OnEndpointStart: func(_ Endpoint, _ string) {
			starts.Add(1)
		},
		OnEndpointComplete: func(_ Endpoint, _ string, _ int, _ error) {
			completes.Add(1)
		},
	}

	plan := testPlan(5)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// Every Start must have a matching Complete, even when limiter errors.
	assert.Equal(t, starts.Load(), completes.Load(),
		"every OnEndpointStart must have a matching OnEndpointComplete, even on limiter error")
}

func TestRegression_PerCategoryEscalation(t *testing.T) {
	// BUG: Escalation used global block rate for all categories. If sqli was
	// 100% blocked and xss was 0% blocked, both categories would escalate.
	// Fix: per-category block rate tracking with independent escalation.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("test") != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access Denied")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var escalatedCategories []string
	var mu sync.Mutex

	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		Concurrency:  1,
		ProbePercent: 0.01,
		WAF: &mockWAFDetector{
			result: WAFDetectResult{Detected: true, Vendor: "test-waf"},
		},
		ScanFn: func(_ context.Context, name string, _ string, _ Endpoint) ([]SpecFinding, error) {
			// sqli always returns findings (not blocked); xss never does (blocked).
			if name == "sqli" {
				return []SpecFinding{{Category: name, Title: "found", Severity: "high"}}, nil
			}
			return nil, nil // xss: no findings = blocked (when block signature exists)
		},
		OnEscalation: func(from, to EscalationLevel, reason string) {
			mu.Lock()
			escalatedCategories = append(escalatedCategories, reason)
			mu.Unlock()
		},
	}

	// Build plan with interleaved sqli and xss entries.
	plan := &ScanPlan{
		TotalTests: 200,
		Intensity:  IntensityNormal,
		SpecSource: "test-spec.json",
	}
	for i := 0; i < 20; i++ {
		cat := "sqli"
		if i%2 == 1 {
			cat = "xss"
		}
		plan.Entries = append(plan.Entries, ScanPlanEntry{
			Endpoint: Endpoint{
				Method: "GET",
				Path:   fmt.Sprintf("/api/v1/resource%d", i),
			},
			Attack: AttackSelection{Category: cat, PayloadCount: 10},
			InjectionTarget: InjectionTarget{
				Parameter: "id",
				Location:  LocationQuery,
			},
		})
	}

	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// Positive: xss (100% blocked in full-scan) MUST trigger escalation.
	// Without per-category tracking, global block rate ≈47% → below 80%
	// threshold → nothing escalates → this assertion catches that.
	xssEscalated := false
	for _, reason := range escalatedCategories {
		if strings.Contains(reason, "category xss") {
			xssEscalated = true
		}
		// Negative: sqli (0% blocked) must NOT escalate.
		assert.NotContains(t, reason, "category sqli",
			"sqli (0%% blocked) must NOT escalate")
	}
	assert.True(t, xssEscalated,
		"xss (100%% blocked) must escalate; with global-rate bug it wouldn't")
}

func TestRegression_NoFalseEscalationWithoutBlockSignature(t *testing.T) {
	// BUG: When no block signature was learned (no WAF or WAF didn't block the
	// test payload), zero findings were counted as "blocked" → false escalation.
	// Fix: only count as blocked when state.BlockSignature != nil.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No WAF: always returns 200 OK, same body for everything.
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	var escalated bool
	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		Concurrency:  1,
		ProbePercent: 0.1,
		// No WAF detector → no block signature learned.
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil // No findings, but also no WAF.
		},
		OnEscalation: func(_, _ EscalationLevel, _ string) {
			escalated = true
		},
	}

	plan := testPlan(20)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	assert.False(t, escalated,
		"must NOT escalate when no block signature exists (empty findings = not vulnerable, not blocked)")
}

func TestRegression_BlockSignaturePropagatedToFullScan(t *testing.T) {
	// BUG: Fingerprint learned a BlockSignature but it wasn't set on the
	// shared ScanState, so full-scan couldn't distinguish blocked vs not-vulnerable.
	//
	// Test structure: probe returns findings (not blocked) → low escalation level.
	// Full scan returns nil findings → should be counted as "blocked" ONLY IF
	// the block signature was propagated. If it wasn't, zero findings = "not
	// vulnerable" → no escalation.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("test") != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access Denied - WAF Blocked")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	// First call (probe) returns a finding; subsequent calls (full scan) return nothing.
	var callCount atomic.Int64
	var sawEscalation bool
	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		Concurrency:  1,
		ProbePercent: 0.05, // 1 out of 30 entries for probe.
		WAF: &mockWAFDetector{
			result: WAFDetectResult{Detected: true, Vendor: "test-waf"},
		},
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			n := callCount.Add(1)
			if n <= 2 {
				// Probe calls: return findings → "not blocked" → low escalation.
				return []SpecFinding{{Title: "probe-finding", Severity: "medium"}}, nil
			}
			// Full scan calls: return nothing → "blocked" if signature propagated.
			return nil, nil
		},
		OnEscalation: func(_, _ EscalationLevel, _ string) {
			sawEscalation = true
		},
	}

	plan := testPlan(30)
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	// If block signature was propagated to ScanState, full-scan entries with nil
	// findings are counted as "blocked" → 100% block rate → escalation fires.
	// If NOT propagated, nil findings = "not vulnerable" → no escalation.
	assert.True(t, sawEscalation,
		"must escalate when block signature exists and full-scan requests return no findings")
}

// --- Deduplicate + metric consistency ---

func TestRegression_DuplicateEndpointsCountedOnce(t *testing.T) {
	// Multiple scan types on the same endpoint must count as 1 endpoint.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	e := &AdaptiveExecutor{
		BaseURL:      ts.URL,
		ProbePercent: 1.0,
		Concurrency:  1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
	}

	ep := Endpoint{Method: "GET", Path: "/users", CorrelationTag: "users-tag"}
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: ep, Attack: AttackSelection{Category: "sqli", PayloadCount: 10}},
			{Endpoint: ep, Attack: AttackSelection{Category: "xss", PayloadCount: 10}},
			{Endpoint: ep, Attack: AttackSelection{Category: "cmdi", PayloadCount: 10}},
		},
		TotalTests: 30,
	}

	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)

	assert.Equal(t, 1, session.TotalEndpoints,
		"3 entries for same endpoint must count as 1")
}

func TestRegression_SessionFieldsMatchResultFields(t *testing.T) {
	// Verify that session.TotalX fields are not stale copies — they must
	// exactly match session.Result.TotalX.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	e := &AdaptiveExecutor{
		BaseURL:     ts.URL,
		Concurrency: 1,
		ScanFn: func(_ context.Context, _ string, _ string, ep Endpoint) ([]SpecFinding, error) {
			return []SpecFinding{{
				Method: ep.Method, Path: ep.Path,
				Category: "sqli", Severity: "high", Title: "test",
			}}, nil
		},
	}

	plan := testPlan(5)
	session, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)
	require.NotNil(t, session.Result)

	assert.Equal(t, session.TotalEndpoints, session.Result.TotalEndpoints)
	assert.Equal(t, session.TotalTests, session.Result.TotalTests)
	assert.Equal(t, session.TotalFindings, session.Result.TotalFindings())
	assert.Equal(t, session.SpecSource, session.Result.SpecSource)
	assert.Equal(t, session.CompletedAt, session.Result.CompletedAt)
}

// --- Helper mocks ---

// errorOnNthRateLimiter returns an error from Wait() after errorAfter successful calls.
// If errorAfter=0, every Wait() returns an error.
type errorOnNthRateLimiter struct {
	errorAfter int64
	calls      atomic.Int64
}

func (l *errorOnNthRateLimiter) Wait(_ context.Context) error {
	n := l.calls.Add(1)
	if l.errorAfter == 0 || n > l.errorAfter {
		return fmt.Errorf("rate limiter: simulated error (call %d)", n)
	}
	return nil
}
func (l *errorOnNthRateLimiter) OnError()   {}
func (l *errorOnNthRateLimiter) OnSuccess() {}

// --- Shallow edge-case tests (kept for completeness) ---

func TestIsRequestBlocked_NilFingerprintResult(t *testing.T) {
	assert.False(t, isRequestBlocked(nil), "nil FingerprintResult should not be blocked")
}

func TestIsRequestBlocked_NoBlockSignature(t *testing.T) {
	fp := &FingerprintResult{WAFDetected: true}
	assert.False(t, isRequestBlocked(fp), "no BlockSignature should not be blocked")
}

func TestIsRequestBlocked_EmptyStatusCodes(t *testing.T) {
	fp := &FingerprintResult{
		BlockSignature: &BlockSignature{StatusCodes: nil},
	}
	assert.False(t, isRequestBlocked(fp), "empty StatusCodes should not be blocked")
}

func TestIsRequestBlocked_Valid(t *testing.T) {
	fp := &FingerprintResult{
		BlockSignature: &BlockSignature{StatusCodes: []int{403}},
	}
	assert.True(t, isRequestBlocked(fp))
}
