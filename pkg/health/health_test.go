package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusConstants(t *testing.T) {
	assert.Equal(t, Status("healthy"), StatusHealthy)
	assert.Equal(t, Status("unhealthy"), StatusUnhealthy)
}

func TestCheckTypeConstants(t *testing.T) {
	assert.Equal(t, CheckType("http"), CheckTypeHTTP)
	assert.Equal(t, CheckType("tcp"), CheckTypeTCP)
}

func TestErrors(t *testing.T) {
	assert.Error(t, ErrTimeout)
	assert.Error(t, ErrUnhealthy)
}

func TestResultIsHealthy(t *testing.T) {
	r1 := &Result{Status: StatusHealthy}
	assert.True(t, r1.IsHealthy())

	r2 := &Result{Status: StatusUnhealthy}
	assert.False(t, r2.IsHealthy())
}

func TestCheckValidate(t *testing.T) {
	check := &Check{}
	assert.Error(t, check.Validate())

	check2 := &Check{Endpoint: "http://localhost"}
	assert.NoError(t, check2.Validate())
}

func TestCheckValidateDefaults(t *testing.T) {
	check := &Check{Endpoint: "http://localhost"}
	require.NoError(t, check.Validate())
	assert.Equal(t, CheckTypeHTTP, check.Type)
	assert.Equal(t, "GET", check.Method)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.NotNil(t, config)
	assert.Equal(t, 30*time.Second, config.Timeout)
}

func TestNewChecker(t *testing.T) {
	checker := NewChecker(nil)
	assert.NotNil(t, checker)
}

func TestCheckerAddCheck(t *testing.T) {
	checker := NewChecker(nil)
	check := &Check{Name: "test", Endpoint: "http://localhost"}
	err := checker.AddCheck(check)
	require.NoError(t, err)
	assert.Len(t, checker.config.Checks, 1)
}

func TestCheckerCheckOneHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewChecker(nil)
	check := &Check{Name: "test", Endpoint: server.URL, Type: CheckTypeHTTP}

	result, err := checker.CheckOne(context.Background(), check)
	require.NoError(t, err)
	assert.Equal(t, StatusHealthy, result.Status)
}

func TestCheckerCheckOneHTTPUnhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	checker := NewChecker(nil)
	check := &Check{Name: "test", Endpoint: server.URL}

	result, err := checker.CheckOne(context.Background(), check)
	require.NoError(t, err)
	assert.Equal(t, StatusUnhealthy, result.Status)
}

func TestCheckerCheckOneHTTPBodyMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy"}`))
	}))
	defer server.Close()

	checker := NewChecker(nil)
	check := &Check{Name: "test", Endpoint: server.URL, ExpectedBody: "healthy"}

	result, err := checker.CheckOne(context.Background(), check)
	require.NoError(t, err)
	assert.Equal(t, StatusHealthy, result.Status)
}

func TestCheckerCheckOneTCP(t *testing.T) {
	checker := NewChecker(nil)
	check := &Check{Name: "test", Endpoint: "localhost:8080", Type: CheckTypeTCP}

	result, err := checker.CheckOne(context.Background(), check)
	require.NoError(t, err)
	assert.Equal(t, StatusHealthy, result.Status)
}

func TestCheckerCheckAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Checks = []*Check{{Name: "test1", Endpoint: server.URL}}
	checker := NewChecker(config)

	results, err := checker.CheckAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestCheckerCheckAllNoEndpoints(t *testing.T) {
	checker := NewChecker(nil)
	_, err := checker.CheckAll(context.Background())
	assert.Equal(t, ErrNoEndpoints, err)
}

func TestCheckerAllHealthy(t *testing.T) {
	checker := NewChecker(nil)
	results := []*Result{{Status: StatusHealthy}, {Status: StatusHealthy}}
	assert.True(t, checker.AllHealthy(results))

	results2 := []*Result{{Status: StatusHealthy}, {Status: StatusUnhealthy}}
	assert.False(t, checker.AllHealthy(results2))
}

func TestDefaultWaiterConfig(t *testing.T) {
	config := DefaultWaiterConfig()
	assert.Equal(t, 60*time.Second, config.Timeout)
}

func TestNewWaiter(t *testing.T) {
	checker := NewChecker(nil)
	waiter := NewWaiter(checker, nil)
	assert.NotNil(t, waiter)
}

func TestWaiterWaitSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Checks = []*Check{{Name: "test", Endpoint: server.URL}}
	checker := NewChecker(config)

	waiterConfig := DefaultWaiterConfig()
	waiterConfig.Timeout = 5 * time.Second
	waiter := NewWaiter(checker, waiterConfig)

	result := waiter.Wait(context.Background())
	assert.True(t, result.Success)
}

func TestWaiterWaitTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Checks = []*Check{{Name: "test", Endpoint: server.URL}}
	checker := NewChecker(config)

	waiterConfig := DefaultWaiterConfig()
	waiterConfig.Timeout = 300 * time.Millisecond
	waiterConfig.CheckInterval = 100 * time.Millisecond
	waiter := NewWaiter(checker, waiterConfig)

	result := waiter.Wait(context.Background())
	assert.False(t, result.Success)
	assert.Equal(t, ErrTimeout, result.Error)
}

func TestWaitFor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := WaitFor(context.Background(), server.URL, 5*time.Second)
	assert.NoError(t, err)
}

func TestWaitForMultiple(t *testing.T) {
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	err := WaitForMultiple(context.Background(), []string{s1.URL, s2.URL}, 5*time.Second)
	assert.NoError(t, err)
}

func TestNewMonitor(t *testing.T) {
	checker := NewChecker(nil)
	monitor := NewMonitor(checker, 0)
	assert.NotNil(t, monitor)
	assert.Equal(t, 10*time.Second, monitor.interval)
}

func TestMonitorSetCallback(t *testing.T) {
	checker := NewChecker(nil)
	monitor := NewMonitor(checker, time.Second)
	monitor.SetCallback(func(results []*Result) {})
	assert.NotNil(t, monitor.onResult)
}

func TestMonitorStartStop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Checks = []*Check{{Name: "test", Endpoint: server.URL}}
	checker := NewChecker(config)
	monitor := NewMonitor(checker, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor.Start(ctx)
	assert.True(t, monitor.IsRunning())

	time.Sleep(100 * time.Millisecond)
	monitor.Stop()
	assert.False(t, monitor.IsRunning())
}

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder()
	assert.NotNil(t, builder)
}

func TestBuilderAddHTTP(t *testing.T) {
	builder := NewBuilder()
	builder.AddHTTP("test", "http://localhost")
	checks := builder.Build()
	assert.Len(t, checks, 1)
}

func TestBuilderChaining(t *testing.T) {
	checks := NewBuilder().
		AddHTTP("h1", "http://localhost:8080").
		AddTCP("t1", "localhost:9090").
		Build()
	assert.Len(t, checks, 2)
}

func TestBuilderCreateChecker(t *testing.T) {
	checker := NewBuilder().AddHTTP("test", "http://localhost").CreateChecker()
	assert.NotNil(t, checker)
}
