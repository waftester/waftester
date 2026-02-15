package apispec

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimpleExecutorEmptyPlan(t *testing.T) {
	t.Parallel()
	exec := &SimpleExecutor{
		BaseURL: "https://api.example.com",
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}

	session, err := exec.Execute(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.NotEmpty(t, session.ID)
}

func TestSimpleExecutorBasicExecution(t *testing.T) {
	t.Parallel()

	callCount := 0
	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 1,
		ScanFn: func(_ context.Context, name string, targetURL string, ep Endpoint) ([]SpecFinding, error) {
			callCount++
			return []SpecFinding{
				{
					Method:   ep.Method,
					Path:     ep.Path,
					Category: name,
					Severity: "high",
					Title:    "test finding",
				},
			}, nil
		},
	}

	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{
				Endpoint: Endpoint{Method: "GET", Path: "/users", CorrelationTag: "tag1"},
				Attack:   AttackSelection{Category: "sqli"},
			},
			{
				Endpoint: Endpoint{Method: "POST", Path: "/users", CorrelationTag: "tag2"},
				Attack:   AttackSelection{Category: "xss"},
			},
		},
		TotalTests: 100,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
	assert.Equal(t, 100, session.TotalTests)
	assert.Equal(t, 2, session.TotalEndpoints)
	assert.Equal(t, 2, session.TotalFindings)
}

func TestSimpleExecutorCallbacks(t *testing.T) {
	t.Parallel()

	var startedEndpoints []string
	var completedEndpoints []string
	var foundFindings []SpecFinding

	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 1,
		ScanFn: func(_ context.Context, name string, _ string, ep Endpoint) ([]SpecFinding, error) {
			return []SpecFinding{{
				Method: ep.Method, Path: ep.Path, Category: name,
				Severity: "medium", Title: "found",
			}}, nil
		},
		OnEndpointStart: func(ep Endpoint, scanType string) {
			startedEndpoints = append(startedEndpoints, ep.Path+" "+scanType)
		},
		OnEndpointComplete: func(ep Endpoint, scanType string, count int, err error) {
			completedEndpoints = append(completedEndpoints, ep.Path+" "+scanType)
		},
		OnFinding: func(f SpecFinding) {
			foundFindings = append(foundFindings, f)
		},
	}

	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{
				Endpoint: Endpoint{Method: "GET", Path: "/test", CorrelationTag: "t1"},
				Attack:   AttackSelection{Category: "sqli"},
			},
		},
		TotalTests: 10,
	}

	_, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.Len(t, startedEndpoints, 1)
	assert.Len(t, completedEndpoints, 1)
	assert.Len(t, foundFindings, 1)
}

func TestSimpleExecutorContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			t.Fatal("should not be called after cancellation")
			return nil, nil
		},
	}

	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{
				Endpoint: Endpoint{Method: "GET", Path: "/test", CorrelationTag: "t1"},
				Attack:   AttackSelection{Category: "sqli"},
			},
		},
	}

	session, err := exec.Execute(ctx, plan)
	require.NoError(t, err)
	assert.NotNil(t, session)
}

func TestSimpleExecutorConcurrency(t *testing.T) {
	t.Parallel()

	// Track concurrent execution.
	maxConcurrent := 0
	current := 0
	var mu = make(chan struct{}, 1)

	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 3,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			mu <- struct{}{}
			current++
			if current > maxConcurrent {
				maxConcurrent = current
			}
			<-mu

			time.Sleep(10 * time.Millisecond)

			mu <- struct{}{}
			current--
			<-mu
			return nil, nil
		},
	}

	entries := make([]ScanPlanEntry, 10)
	for i := range entries {
		entries[i] = ScanPlanEntry{
			Endpoint: Endpoint{Method: "GET", Path: "/test", CorrelationTag: CorrelationTag("GET", "/test")},
			Attack:   AttackSelection{Category: "sqli"},
		}
	}

	plan := &ScanPlan{Entries: entries}
	_, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)

	// With concurrency=3, max concurrent should be <= 3.
	assert.LessOrEqual(t, maxConcurrent, 3)
}

func TestResolveEndpointURL(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/users/{id}",
		Parameters: []Parameter{
			{Name: "id", In: LocationPath, Example: 42},
		},
	}

	url, err := resolveEndpointURL("https://api.example.com", ep)
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/users/42", url)
}

// ──────────────────────────────────────────────────────────────────────────────
// Regression tests for SimpleExecutor — each catches a specific historical bug.
// ──────────────────────────────────────────────────────────────────────────────

func TestRegression_SimpleExec_ErrorPathCallsOnEndpointComplete(t *testing.T) {
	// BUG: ScanFn error must still fire OnEndpointComplete with the error.
	// If this callback is skipped, the CLI's progress bar hangs because it
	// waits for complete_count == start_count.
	t.Parallel()

	type completionRecord struct {
		path     string
		count    int
		hadError bool
	}
	var completions []completionRecord

	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, fmt.Errorf("connection refused")
		},
		OnEndpointStart: func(_ Endpoint, _ string) {},
		OnEndpointComplete: func(ep Endpoint, _ string, count int, err error) {
			completions = append(completions, completionRecord{
				path: ep.Path, count: count, hadError: err != nil,
			})
		},
	}

	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/a", CorrelationTag: "a"}, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: Endpoint{Method: "GET", Path: "/b", CorrelationTag: "b"}, Attack: AttackSelection{Category: "xss"}},
		},
		TotalTests: 20,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)

	assert.Len(t, completions, 2, "every entry must fire OnEndpointComplete even on error")
	for _, c := range completions {
		assert.True(t, c.hadError, "%s: OnEndpointComplete must receive the error", c.path)
		assert.Equal(t, 0, c.count, "%s: finding count must be 0 on error", c.path)
	}
	assert.Equal(t, 0, session.TotalFindings)
}

func TestRegression_SimpleExec_ResolveURLErrorCallsComplete(t *testing.T) {
	// BUG: Empty base URL causes resolveEndpointURL to fail. If OnEndpointComplete
	// isn't called on this path, the start/complete contract is broken.
	t.Parallel()

	var starts, completes int
	exec := &SimpleExecutor{
		BaseURL:     "", // Will fail resolve
		Concurrency: 1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			t.Fatal("ScanFn must not be called when URL resolve fails")
			return nil, nil
		},
		OnEndpointStart: func(_ Endpoint, _ string) { starts++ },
		OnEndpointComplete: func(_ Endpoint, _ string, _ int, err error) {
			assert.Error(t, err, "must receive resolve error")
			completes++
		},
	}

	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/test", CorrelationTag: "t1"}, Attack: AttackSelection{Category: "sqli"}},
		},
	}

	_, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.Equal(t, starts, completes,
		"every OnEndpointStart must have a matching OnEndpointComplete")
}

func TestRegression_SimpleExec_DuplicateEndpointCounting(t *testing.T) {
	// Same endpoint with 3 different attack types must count as 1 endpoint.
	// This is a deduplication test: endpointsSeen uses correlation tags.
	t.Parallel()

	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 1,
		ScanFn: func(_ context.Context, name string, _ string, ep Endpoint) ([]SpecFinding, error) {
			return []SpecFinding{{
				Method: ep.Method, Path: ep.Path, Category: name,
				Severity: "high", Title: "found",
			}}, nil
		},
	}

	ep := Endpoint{Method: "POST", Path: "/users", CorrelationTag: "users-post"}
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: ep, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: ep, Attack: AttackSelection{Category: "xss"}},
			{Endpoint: ep, Attack: AttackSelection{Category: "cmdi"}},
		},
		TotalTests: 30,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.Equal(t, 1, session.TotalEndpoints, "same endpoint with 3 scan types = 1 endpoint")
	assert.Equal(t, 3, session.TotalFindings, "3 scan types = 3 findings")
}

func TestRegression_SimpleExec_EmptyTagDeduplication(t *testing.T) {
	// When CorrelationTag is empty, the executor auto-generates from method+path.
	// Without auto-generation, all empty-tag entries collapse to key "" → 1
	// endpoint regardless of actual path. With auto-generation, DIFFERENT
	// method+path combos produce different keys → correct count.
	t.Parallel()

	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 1,
		ScanFn: func(_ context.Context, _ string, _ string, _ Endpoint) ([]SpecFinding, error) {
			return nil, nil
		},
	}

	// Different paths with empty tags — must count as SEPARATE endpoints.
	// Without auto-tag-generation, both map to key "" → 1 endpoint (BUG).
	// With auto-tag-generation, they get distinct hashes → 2 endpoints.
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/items"}, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: Endpoint{Method: "POST", Path: "/orders"}, Attack: AttackSelection{Category: "xss"}},
		},
		TotalTests: 20,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.Equal(t, 2, session.TotalEndpoints,
		"different paths with empty tags must count as separate endpoints")
}

func TestRegression_SimpleExec_SessionResultConsistency(t *testing.T) {
	// Verify session fields mirror Result fields exactly.
	// BUG: session.Result was set but its TotalEndpoints/TotalTests were populated
	// after Finalize — if the caller reads Result before those lines, they get 0.
	t.Parallel()

	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 1,
		ScanFn: func(_ context.Context, name string, _ string, ep Endpoint) ([]SpecFinding, error) {
			return []SpecFinding{{
				Method: ep.Method, Path: ep.Path, Category: name,
				Severity: "high", Title: "finding",
			}}, nil
		},
	}

	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/a", CorrelationTag: "a"}, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: Endpoint{Method: "POST", Path: "/b", CorrelationTag: "b"}, Attack: AttackSelection{Category: "xss"}},
		},
		TotalTests: 50,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	require.NotNil(t, session.Result)

	assert.Equal(t, session.TotalEndpoints, session.Result.TotalEndpoints,
		"session.TotalEndpoints must match Result.TotalEndpoints")
	assert.Equal(t, session.TotalTests, session.Result.TotalTests,
		"session.TotalTests must match Result.TotalTests")
	assert.Equal(t, session.TotalFindings, session.Result.TotalFindings(),
		"session.TotalFindings must match Result.TotalFindings()")

	assert.Equal(t, 2, session.TotalEndpoints)
	assert.Equal(t, 50, session.TotalTests)
	assert.Equal(t, 2, session.TotalFindings)
}

func TestRegression_SimpleExec_FindingsCollectedInResult(t *testing.T) {
	// Verify findings from ScanFn are stored in session.Result.Findings
	// (not just counted in session.TotalFindings).
	t.Parallel()

	exec := &SimpleExecutor{
		BaseURL:     "https://api.example.com",
		Concurrency: 1,
		ScanFn: func(_ context.Context, name string, _ string, ep Endpoint) ([]SpecFinding, error) {
			return []SpecFinding{{
				Method: ep.Method, Path: ep.Path, Category: name,
				Severity: "high", Title: "SQL injection in " + ep.Path,
			}}, nil
		},
		OnFinding: func(_ SpecFinding) {}, // non-nil to verify it doesn't consume findings
	}

	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/users", CorrelationTag: "u"}, Attack: AttackSelection{Category: "sqli"}},
		},
		TotalTests: 10,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	require.NotNil(t, session.Result)

	assert.Len(t, session.Result.Findings, 1, "finding must be stored in Result.Findings")
	assert.Equal(t, "SQL injection in /users", session.Result.Findings[0].Title)
}

func TestResolveEndpointURLEmptyBase(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/test"}
	_, err := resolveEndpointURL("", ep)
	assert.Error(t, err, "empty base URL must return error")
}

func TestResolveEndpointURLMultiplePathParams(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/users/{userId}/posts/{postId}",
		Parameters: []Parameter{
			{Name: "userId", In: LocationPath, Example: 42},
			{Name: "postId", In: LocationPath, Default: 7},
		},
	}

	url, err := resolveEndpointURL("https://api.example.com", ep)
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/users/42/posts/7", url)
}

func TestResolveEndpointURLNoPathParams(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/users",
		Parameters: []Parameter{
			{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}},
		},
	}

	url, err := resolveEndpointURL("https://api.example.com", ep)
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/users", url)
}
