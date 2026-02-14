package apispec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCrossEndpointTests_Nil(t *testing.T) {
	tests := GenerateCrossEndpointTests(nil)
	assert.Nil(t, tests)
}

func TestGenerateCrossEndpointTests_Empty(t *testing.T) {
	tests := GenerateCrossEndpointTests(&Spec{})
	assert.Nil(t, tests)
}

func TestGenerateCrossEndpointTests_IDOR(t *testing.T) {
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "POST", Path: "/users/{id}"},
			{Method: "GET", Path: "/users/{id}"},
		},
	}

	tests := GenerateCrossEndpointTests(spec)

	var idorTests []CrossEndpointTest
	for _, tt := range tests {
		if tt.Type == CrossEndpointIDOR {
			idorTests = append(idorTests, tt)
		}
	}

	require.NotEmpty(t, idorTests)
	assert.True(t, idorTests[0].RequiresDualAuth)
	assert.Len(t, idorTests[0].Endpoints, 2)
}

func TestGenerateCrossEndpointTests_Race(t *testing.T) {
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "POST", Path: "/api/checkout"},
			{Method: "POST", Path: "/api/payment"},
			{Method: "GET", Path: "/api/status"},
		},
	}

	tests := GenerateCrossEndpointTests(spec)

	var raceTests []CrossEndpointTest
	for _, tt := range tests {
		if tt.Type == CrossEndpointRace {
			raceTests = append(raceTests, tt)
		}
	}

	assert.Len(t, raceTests, 2)
	for _, tt := range raceTests {
		assert.False(t, tt.RequiresDualAuth)
	}
}

func TestGenerateCrossEndpointTests_Privesc(t *testing.T) {
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/admin/users"},
			{Method: "DELETE", Path: "/internal/cache"},
			{Method: "GET", Path: "/api/public"},
		},
	}

	tests := GenerateCrossEndpointTests(spec)

	var privescTests []CrossEndpointTest
	for _, tt := range tests {
		if tt.Type == CrossEndpointPrivesc {
			privescTests = append(privescTests, tt)
		}
	}

	assert.Len(t, privescTests, 2)
	for _, tt := range privescTests {
		assert.True(t, tt.RequiresDualAuth)
	}
}

func TestGenerateCrossEndpointTests_TagBasedPrivesc(t *testing.T) {
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/api/settings", Tags: []string{"admin"}},
		},
	}

	tests := GenerateCrossEndpointTests(spec)

	var privescTests []CrossEndpointTest
	for _, tt := range tests {
		if tt.Type == CrossEndpointPrivesc {
			privescTests = append(privescTests, tt)
		}
	}
	assert.Len(t, privescTests, 1)
}

func TestExecuteCrossEndpointTests_DryRun(t *testing.T) {
	tests := []CrossEndpointTest{
		{Type: CrossEndpointIDOR, RequiresDualAuth: true},
		{Type: CrossEndpointRace},
	}

	results := ExecuteCrossEndpointTests(context.Background(), tests, CrossEndpointConfig{
		DryRun:     true,
		AuthTokenA: "admin",
		AuthTokenB: "user",
	})

	assert.Len(t, results, 2)
	for _, r := range results {
		assert.Nil(t, r.Finding)
		assert.Empty(t, r.Error)
	}
}

func TestExecuteCrossEndpointTests_SkipNoDualAuth(t *testing.T) {
	tests := []CrossEndpointTest{
		{Type: CrossEndpointIDOR, RequiresDualAuth: true},
		{Type: CrossEndpointRace, RequiresDualAuth: false},
	}

	results := ExecuteCrossEndpointTests(context.Background(), tests, CrossEndpointConfig{
		DryRun:     true,
		AuthTokenA: "admin",
		// No AuthTokenB.
	})

	// IDOR skipped, Race runs.
	assert.Len(t, results, 2)
	assert.Contains(t, results[0].Error, "dual auth")
	assert.Empty(t, results[1].Error)
}

func TestExecuteIDORTest_Finding(t *testing.T) {
	// Server returns 200 — IDOR detected.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	test := CrossEndpointTest{
		Type: CrossEndpointIDOR,
		Endpoints: []Endpoint{
			{Method: "POST", Path: "/users/1"},
			{Method: "GET", Path: "/users/1"},
		},
	}

	result := executeIDORTest(context.Background(), test, CrossEndpointConfig{
		AuthTokenB: "user-token",
		HTTPClient: srv.Client(),
		BaseURL:    srv.URL,
		Timeout:    5 * time.Second,
	})

	require.NotNil(t, result.Finding)
	assert.Equal(t, "idor", result.Finding.Category)
	assert.Equal(t, "high", result.Finding.Severity)
}

func TestExecuteIDORTest_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	test := CrossEndpointTest{
		Type: CrossEndpointIDOR,
		Endpoints: []Endpoint{
			{Method: "POST", Path: "/users/1"},
			{Method: "GET", Path: "/users/1"},
		},
	}

	result := executeIDORTest(context.Background(), test, CrossEndpointConfig{
		AuthTokenB: "user-token",
		HTTPClient: srv.Client(),
		BaseURL:    srv.URL,
		Timeout:    5 * time.Second,
	})

	assert.True(t, result.Passed)
	assert.Nil(t, result.Finding)
}

func TestExecutePrivescTest_Finding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	test := CrossEndpointTest{
		Type:      CrossEndpointPrivesc,
		Endpoints: []Endpoint{{Method: "GET", Path: "/admin/users"}},
	}

	result := executePrivescTest(context.Background(), test, CrossEndpointConfig{
		AuthTokenB: "user-token",
		HTTPClient: srv.Client(),
		BaseURL:    srv.URL,
		Timeout:    5 * time.Second,
	})

	require.NotNil(t, result.Finding)
	assert.Equal(t, "accesscontrol", result.Finding.Category)
	assert.Equal(t, "critical", result.Finding.Severity)
}

func TestExecutePrivescTest_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	test := CrossEndpointTest{
		Type:      CrossEndpointPrivesc,
		Endpoints: []Endpoint{{Method: "GET", Path: "/admin/users"}},
	}

	result := executePrivescTest(context.Background(), test, CrossEndpointConfig{
		AuthTokenB: "user-token",
		HTTPClient: srv.Client(),
		BaseURL:    srv.URL,
		Timeout:    5 * time.Second,
	})

	assert.True(t, result.Passed)
	assert.Nil(t, result.Finding)
}

func TestExecuteRaceTest_MultipleSources(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	test := CrossEndpointTest{
		Type:      CrossEndpointRace,
		Endpoints: []Endpoint{{Method: "POST", Path: "/api/checkout"}},
	}

	result := executeRaceTest(context.Background(), test, CrossEndpointConfig{
		HTTPClient:      srv.Client(),
		BaseURL:         srv.URL,
		Timeout:         5 * time.Second,
		RaceConcurrency: 5,
	})

	// All 5 succeed, so should report a finding.
	require.NotNil(t, result.Finding)
	assert.Equal(t, "race", result.Finding.Category)
}

func TestIsPrivilegedEndpoint(t *testing.T) {
	tests := []struct {
		path     string
		tags     []string
		expected bool
	}{
		{"/admin/users", nil, true},
		{"/internal/cache", nil, true},
		{"/debug/pprof", nil, true},
		{"/manage/settings", nil, true},
		{"/config/app", nil, true},
		{"/api/users", nil, false},
		{"/api/settings", []string{"admin"}, true},
		{"/api/data", []string{"management"}, true},
		{"/api/data", []string{"public"}, false},
	}

	for _, tt := range tests {
		ep := Endpoint{Path: tt.path, Tags: tt.tags}
		result := isPrivilegedEndpoint(ep)
		assert.Equal(t, tt.expected, result, "path=%s tags=%v", tt.path, tt.tags)
	}
}

func TestGenerateCrossEndpointTests_NoIDParams(t *testing.T) {
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "POST", Path: "/users"},
			{Method: "GET", Path: "/users"},
		},
	}

	tests := GenerateCrossEndpointTests(spec)

	// No {id} parameter, so no IDOR tests.
	for _, tt := range tests {
		assert.NotEqual(t, CrossEndpointIDOR, tt.Type)
	}
}
