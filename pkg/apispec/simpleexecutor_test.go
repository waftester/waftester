package apispec

import (
	"context"
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
