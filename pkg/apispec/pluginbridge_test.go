package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEndpointToTargetBasic(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method:      "GET",
		Path:        "/users",
		OperationID: "getUsers",
		CorrelationTag: "abc123",
		Group:       "users",
		Tags:        []string{"users", "v1"},
	}

	target, err := EndpointToTarget("https://api.example.com", ep)
	require.NoError(t, err)
	require.NotNil(t, target)

	assert.Equal(t, "https://api.example.com/users", target.URL)
	assert.Equal(t, "api.example.com", target.Host)
	assert.Equal(t, "https", target.Scheme)
	assert.Equal(t, "/users", target.Path)
	assert.Equal(t, "GET", target.Method)
	assert.Equal(t, "getUsers", target.Metadata["operation_id"])
	assert.Equal(t, "abc123", target.Metadata["correlation_tag"])
}

func TestEndpointToTargetPathParams(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/users/{id}/posts/{postId}",
		Parameters: []Parameter{
			{Name: "id", In: LocationPath, Example: 42},
			{Name: "postId", In: LocationPath, Schema: SchemaInfo{Type: "integer"}},
		},
	}

	target, err := EndpointToTarget("https://api.example.com", ep)
	require.NoError(t, err)
	assert.Contains(t, target.URL, "/42/")
	assert.Contains(t, target.URL, "/1")
}

func TestEndpointToTargetHeaders(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/api",
		Parameters: []Parameter{
			{Name: "X-Custom", In: LocationHeader, Example: "value1"},
			{Name: "session", In: LocationCookie, Example: "abc"},
		},
	}

	target, err := EndpointToTarget("https://api.example.com", ep)
	require.NoError(t, err)
	assert.Equal(t, "value1", target.Headers["X-Custom"])
	assert.Equal(t, "abc", target.Cookies["session"])
}

func TestEndpointToTargetNoBaseURL(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/test"}

	_, err := EndpointToTarget("", ep)
	assert.Error(t, err)
}

func TestEndpointToTargetPort(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/test"}

	target, err := EndpointToTarget("https://api.example.com:8443", ep)
	require.NoError(t, err)
	assert.Equal(t, 8443, target.Port)
}

func TestIsAbsoluteURL(t *testing.T) {
	t.Parallel()
	assert.True(t, isAbsoluteURL("http://example.com"))
	assert.True(t, isAbsoluteURL("https://example.com"))
	assert.False(t, isAbsoluteURL("/api/users"))
	assert.False(t, isAbsoluteURL("api/users"))
	assert.False(t, isAbsoluteURL(""))
}

func TestJoinURL(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "https://api.com/users", joinURL("https://api.com", "/users"))
	assert.Equal(t, "https://api.com/users", joinURL("https://api.com/", "/users"))
	assert.Equal(t, "https://api.com/users", joinURL("https://api.com", "users"))
}
