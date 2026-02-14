package apispec

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRequestBasicGET(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/users",
		Parameters: []Parameter{
			{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}},
		},
	}
	target := InjectionTarget{Parameter: "q", Location: LocationQuery}

	req, err := BuildRequest("https://api.example.com", ep, target, "' OR 1=1--")
	require.NoError(t, err)
	require.NotNil(t, req)

	assert.Equal(t, http.MethodGet, req.Method)
	assert.Contains(t, req.URL.String(), "q=")
	assert.Contains(t, req.URL.RawQuery, "OR+1%3D1--")
}

func TestBuildRequestPathParam(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/users/{id}",
		Parameters: []Parameter{
			{Name: "id", In: LocationPath, Schema: SchemaInfo{Type: "integer"}},
		},
	}
	target := InjectionTarget{Parameter: "id", Location: LocationPath}

	req, err := BuildRequest("https://api.example.com", ep, target, "1 OR 1=1")
	require.NoError(t, err)
	// url.Parse decodes percent-encoding into Path; the encoded form lives in
	// the full URL string or RawPath (when it differs from Path).
	reqURL := req.URL.String()
	// url.PathEscape encodes spaces but not = (valid in path segments).
	assert.Contains(t, reqURL, "1%20OR%201=1")
}

func TestBuildRequestPathParamDefault(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/users/{id}/posts/{postId}",
		Parameters: []Parameter{
			{Name: "id", In: LocationPath, Example: 42},
			{Name: "postId", In: LocationPath, Schema: SchemaInfo{Type: "integer"}},
		},
	}
	// Inject into postId, id should use its example value.
	target := InjectionTarget{Parameter: "postId", Location: LocationPath}

	req, err := BuildRequest("https://api.example.com", ep, target, "999")
	require.NoError(t, err)
	assert.Contains(t, req.URL.Path, "/42/")
	assert.Contains(t, req.URL.Path, "999")
}

func TestBuildRequestJSONBody(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "POST",
		Path:   "/users",
		RequestBodies: map[string]RequestBody{
			"application/json": {
				Schema: SchemaInfo{
					Properties: map[string]SchemaInfo{
						"name":  {Type: "string"},
						"age":   {Type: "integer"},
					},
				},
			},
		},
	}
	target := InjectionTarget{
		Parameter:   "body",
		Location:    LocationBody,
		ContentType: "application/json",
	}

	req, err := BuildRequest("https://api.example.com", ep, target, "'; DROP TABLE users;--")
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Greater(t, req.ContentLength, int64(0))
}

func TestBuildRequestFormBody(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "POST",
		Path:   "/login",
		RequestBodies: map[string]RequestBody{
			"application/x-www-form-urlencoded": {
				Schema: SchemaInfo{
					Properties: map[string]SchemaInfo{
						"username": {Type: "string"},
						"password": {Type: "string"},
					},
				},
			},
		},
	}
	target := InjectionTarget{
		Parameter:   "body",
		Location:    LocationBody,
		ContentType: "application/x-www-form-urlencoded",
	}

	req, err := BuildRequest("https://api.example.com", ep, target, "admin' OR 1=1--")
	require.NoError(t, err)
	assert.Contains(t, req.Header.Get("Content-Type"), "form")
}

func TestBuildRequestHeaderInjection(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/api",
		Parameters: []Parameter{
			{Name: "X-Custom", In: LocationHeader, Schema: SchemaInfo{Type: "string"}},
		},
	}
	target := InjectionTarget{Parameter: "X-Custom", Location: LocationHeader}

	req, err := BuildRequest("https://api.example.com", ep, target, "injected<script>")
	require.NoError(t, err)
	assert.Equal(t, "injected<script>", req.Header.Get("X-Custom"))
}

func TestBuildRequestCookieInjection(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/api",
		Parameters: []Parameter{
			{Name: "session", In: LocationCookie, Schema: SchemaInfo{Type: "string"}},
		},
	}
	target := InjectionTarget{Parameter: "session", Location: LocationCookie}

	req, err := BuildRequest("https://api.example.com", ep, target, "injected")
	require.NoError(t, err)
	cookies := req.Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "session", cookies[0].Name)
	assert.Equal(t, "injected", cookies[0].Value)
}

func TestBuildRequestNoBaseURL(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/test"}
	target := InjectionTarget{Parameter: "q", Location: LocationQuery}

	_, err := BuildRequest("", ep, target, "payload")
	assert.Error(t, err)
}

func TestBuildRequestQueryParamDefaults(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/search",
		Parameters: []Parameter{
			{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}},
			{Name: "limit", In: LocationQuery, Schema: SchemaInfo{Type: "integer"}, Required: true},
			{Name: "format", In: LocationQuery, Example: "json"},
		},
	}
	target := InjectionTarget{Parameter: "q", Location: LocationQuery}

	req, err := BuildRequest("https://api.example.com", ep, target, "payload")
	require.NoError(t, err)

	q := req.URL.Query()
	assert.Equal(t, "payload", q.Get("q"))
	assert.Equal(t, "1", q.Get("limit"))        // default for integer
	assert.Equal(t, "json", q.Get("format"))     // example value
}

func TestExpandPathParams(t *testing.T) {
	t.Parallel()
	params := []Parameter{
		{Name: "id", In: LocationPath, Example: 42},
	}
	target := InjectionTarget{Parameter: "other", Location: LocationQuery}

	result := expandPathParams("/users/{id}", params, "payload", target)
	assert.Equal(t, "/users/42", result)
}

func TestResolveURL(t *testing.T) {
	t.Parallel()
	url, err := resolveURL("https://api.example.com", "/users")
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/users", url)

	url, err = resolveURL("https://api.example.com/", "/users")
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/users", url)

	url, err = resolveURL("https://api.example.com", "users")
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/users", url)
}

func TestDefaultValue(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "1", defaultValue(SchemaInfo{Type: "integer"}))
	assert.Equal(t, "1", defaultValue(SchemaInfo{Type: "number"}))
	assert.Equal(t, "true", defaultValue(SchemaInfo{Type: "boolean"}))
	assert.Equal(t, "test", defaultValue(SchemaInfo{Type: "string"}))
	assert.Equal(t, "active", defaultValue(SchemaInfo{Enum: []string{"active", "inactive"}}))
}

func TestBuildJSONBody(t *testing.T) {
	t.Parallel()
	schema := SchemaInfo{
		Properties: map[string]SchemaInfo{
			"name": {Type: "string"},
			"age":  {Type: "integer"},
		},
	}
	body := buildJSONBody(schema, "injected")
	assert.True(t, strings.HasPrefix(body, "{"))
	assert.True(t, strings.HasSuffix(body, "}"))
	assert.Contains(t, body, "injected")
}

func TestBuildJSONBodyEmpty(t *testing.T) {
	t.Parallel()
	body := buildJSONBody(SchemaInfo{}, "payload")
	assert.Contains(t, body, "payload")
}

func TestBuildFormBody(t *testing.T) {
	t.Parallel()
	schema := SchemaInfo{
		Properties: map[string]SchemaInfo{
			"user": {Type: "string"},
			"pass": {Type: "string"},
		},
	}
	body := buildFormBody(schema, "injected")
	assert.Contains(t, body, "injected")
	assert.Contains(t, body, "=")
}
