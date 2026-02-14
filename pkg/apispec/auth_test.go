package apispec

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveAuthCLIBearer(t *testing.T) {
	t.Parallel()
	authFn := ResolveAuth(nil, AuthConfig{BearerToken: "my-token"})

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	authFn(req)

	assert.Equal(t, "Bearer my-token", req.Header.Get("Authorization"))
}

func TestResolveAuthCLIAPIKey(t *testing.T) {
	t.Parallel()
	authFn := ResolveAuth(nil, AuthConfig{APIKey: "key123"})

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	authFn(req)

	assert.Equal(t, "key123", req.Header.Get("X-API-Key"))
}

func TestResolveAuthCLIAPIKeyCustomHeader(t *testing.T) {
	t.Parallel()
	authFn := ResolveAuth(nil, AuthConfig{APIKey: "key123", APIKeyHeader: "X-My-Key"})

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	authFn(req)

	assert.Equal(t, "key123", req.Header.Get("X-My-Key"))
}

func TestResolveAuthCLIBasic(t *testing.T) {
	t.Parallel()
	authFn := ResolveAuth(nil, AuthConfig{BasicUser: "admin", BasicPass: "secret"})

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	authFn(req)

	user, pass, ok := req.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "admin", user)
	assert.Equal(t, "secret", pass)
}

func TestResolveAuthCLICustomHeaders(t *testing.T) {
	t.Parallel()
	authFn := ResolveAuth(nil, AuthConfig{
		CustomHeaders: map[string]string{
			"X-Custom-Auth": "secret-value",
		},
	})

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	authFn(req)

	assert.Equal(t, "secret-value", req.Header.Get("X-Custom-Auth"))
}

func TestResolveAuthCLIAuthHeader(t *testing.T) {
	t.Parallel()
	authFn := ResolveAuth(nil, AuthConfig{AuthHeader: "Token xyz"})

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	authFn(req)

	assert.Equal(t, "Token xyz", req.Header.Get("Authorization"))
}

func TestResolveAuthNoAuth(t *testing.T) {
	t.Parallel()
	authFn := ResolveAuth(nil, AuthConfig{})

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	authFn(req)

	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestResolveAuthCLIOverridesSpec(t *testing.T) {
	t.Parallel()
	specSchemes := []AuthScheme{
		{Name: "bearerAuth", Type: AuthBearer},
	}
	// CLI credentials should be used even when spec declares auth.
	authFn := ResolveAuth(specSchemes, AuthConfig{BearerToken: "cli-token"})

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	authFn(req)

	assert.Equal(t, "Bearer cli-token", req.Header.Get("Authorization"))
}

func TestDescribeSpecAuth(t *testing.T) {
	t.Parallel()
	schemes := []AuthScheme{
		{Name: "bearerAuth", Type: AuthBearer, BearerFormat: "JWT"},
		{Name: "apiKey", Type: AuthAPIKey, In: LocationHeader, FieldName: "X-API-Key"},
		{Name: "basic", Type: AuthBasic},
		{Name: "oauth", Type: AuthOAuth2, Flows: []OAuthFlow{{Type: "authorizationCode"}}},
		{Name: "custom", Type: AuthCustom},
	}

	descs := DescribeSpecAuth(schemes)
	require.Len(t, descs, 5)
	assert.Contains(t, descs[0], "JWT")
	assert.Contains(t, descs[0], "--bearer")
	assert.Contains(t, descs[1], "X-API-Key")
	assert.Contains(t, descs[2], "Basic")
	assert.Contains(t, descs[3], "authorizationCode")
	assert.Contains(t, descs[4], "custom")
}

func TestBuildBasicAuthHeader(t *testing.T) {
	t.Parallel()
	header := BuildBasicAuthHeader("admin", "pass")
	assert.True(t, len(header) > 6)
	assert.Equal(t, "Basic ", header[:6])
}
