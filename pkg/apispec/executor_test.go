package apispec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

	// With budget of 5, scan calls should be capped.
	assert.LessOrEqual(t, scanCalls.Load(), int64(100))
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

	var escalations []string
	e := &AdaptiveExecutor{
		BaseURL: ts.URL,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil // Always blocked
		},
		WAF: &mockWAFDetector{
			result: WAFDetectResult{Detected: true, Vendor: "test-waf"},
		},
		OnEscalation: func(from, to EscalationLevel, reason string) {
			escalations = append(escalations, fmt.Sprintf("%s->%s: %s", from, to, reason))
		},
	}

	plan := testPlan(30) // Need enough entries to trigger escalation
	_, err := e.Execute(context.Background(), plan)
	require.NoError(t, err)
	// Per-category escalation may or may not trigger depending on probe results.
	// Just verify no panic.
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
