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
						"name": {Type: "string"},
						"age":  {Type: "integer"},
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
	assert.Equal(t, "1", q.Get("limit"))     // default for integer
	assert.Equal(t, "json", q.Get("format")) // example value
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

// ──────────────────────────────────────────────────────────────────────────────
// Negative / edge-case tests.
// ──────────────────────────────────────────────────────────────────────────────

func TestBuildRequestEmptyBaseURL(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/test"}
	target := InjectionTarget{Location: LocationQuery, Parameter: "q"}
	_, err := BuildRequest("", ep, target, "payload")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no base URL")
}

func TestBuildRequestEmptyMethod(t *testing.T) {
	// Empty method defaults to GET.
	t.Parallel()
	ep := Endpoint{Path: "/test"}
	target := InjectionTarget{Location: LocationQuery, Parameter: "q"}
	req, err := BuildRequest("https://example.com", ep, target, "payload")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, req.Method)
}

func TestBuildRequestBodyOnGET(t *testing.T) {
	// Body target on GET: body should still be built.
	t.Parallel()
	ep := Endpoint{
		Method: "GET",
		Path:   "/test",
		RequestBodies: map[string]RequestBody{
			"application/json": {
				Schema: SchemaInfo{
					Properties: map[string]SchemaInfo{
						"name": {Type: "string"},
					},
				},
			},
		},
	}
	target := InjectionTarget{Location: LocationBody}
	req, err := BuildRequest("https://example.com", ep, target, "<script>")
	require.NoError(t, err)
	assert.NotNil(t, req.Body)
	assert.Contains(t, req.Header.Get("Content-Type"), "json")
}

func TestBuildRequestDefaultBodyOnPOST(t *testing.T) {
	// Non-body target on POST with request bodies → should populate default body.
	t.Parallel()
	ep := Endpoint{
		Method: "POST",
		Path:   "/users",
		RequestBodies: map[string]RequestBody{
			"application/json": {
				Schema: SchemaInfo{
					Properties: map[string]SchemaInfo{
						"name": {Type: "string"},
					},
				},
			},
		},
		Parameters: []Parameter{
			{Name: "q", In: LocationQuery},
		},
	}
	target := InjectionTarget{Location: LocationQuery, Parameter: "q"}
	req, err := BuildRequest("https://example.com", ep, target, "payload")
	require.NoError(t, err)
	assert.NotNil(t, req.Body, "POST should have default body even for query injection")
}

func TestBuildRequestMultipartBoundary(t *testing.T) {
	// Multipart body should include boundary in Content-Type.
	t.Parallel()
	ep := Endpoint{
		Method: "POST",
		Path:   "/upload",
		RequestBodies: map[string]RequestBody{
			"multipart/form-data": {
				Schema: SchemaInfo{
					Properties: map[string]SchemaInfo{
						"file": {Type: "file", Format: "binary"},
					},
				},
			},
		},
	}
	target := InjectionTarget{Location: LocationBody, ContentType: "multipart/form-data"}
	req, err := BuildRequest("https://example.com", ep, target, "payload")
	require.NoError(t, err)
	ct := req.Header.Get("Content-Type")
	assert.Contains(t, ct, "boundary=")
}

func TestBuildBodyUnknownContentType(t *testing.T) {
	// Unknown content type → raw payload fallback.
	t.Parallel()
	ep := Endpoint{
		RequestBodies: map[string]RequestBody{
			"text/plain": {Schema: SchemaInfo{}},
		},
	}
	target := InjectionTarget{Location: LocationBody, ContentType: "text/plain"}
	body := buildBody(ep, target, "raw-payload")
	assert.Equal(t, "raw-payload", body)
}

func TestBuildBodyFallbackToFirstContentType(t *testing.T) {
	// Target has content type not in request bodies → falls back to first sorted key.
	t.Parallel()
	ep := Endpoint{
		RequestBodies: map[string]RequestBody{
			"application/json": {
				Schema: SchemaInfo{
					Properties: map[string]SchemaInfo{
						"x": {Type: "string"},
					},
				},
			},
		},
	}
	target := InjectionTarget{Location: LocationBody, ContentType: "application/xml"}
	body := buildBody(ep, target, "injected")
	assert.Contains(t, body, "injected", "should fall back to JSON body")
}

func TestBuildMultipartBodyNoProperties(t *testing.T) {
	// No schema properties → injects payload in a default "payload" field.
	t.Parallel()
	body := buildMultipartBody(SchemaInfo{}, "injected")
	assert.Contains(t, body, "injected")
	assert.Contains(t, body, "payload")
}

func TestBuildMultipartBodyBinaryFile(t *testing.T) {
	t.Parallel()
	schema := SchemaInfo{
		Properties: map[string]SchemaInfo{
			"avatar": {Type: "file", Format: "binary"},
		},
	}
	body := buildMultipartBody(schema, "payload")
	assert.Contains(t, body, "filename=")
	assert.Contains(t, body, "payload")
}

func TestDefaultValueEnum(t *testing.T) {
	t.Parallel()
	schema := SchemaInfo{Enum: []string{"a", "b", "c"}}
	assert.Equal(t, "a", defaultValue(schema))
}

func TestDefaultJSONValueNested(t *testing.T) {
	t.Parallel()
	schema := SchemaInfo{
		Type: "object",
		Properties: map[string]SchemaInfo{
			"inner": {Type: "string"},
		},
	}
	val := defaultJSONValue(schema)
	assert.Contains(t, val, "inner")
}

func TestDefaultJSONArrayWithItems(t *testing.T) {
	t.Parallel()
	items := SchemaInfo{Type: "integer"}
	schema := SchemaInfo{Type: "array", Items: &items}
	val := defaultJSONArray(schema)
	assert.Equal(t, "[1]", val)
}

func TestDefaultJSONArrayNoItems(t *testing.T) {
	t.Parallel()
	schema := SchemaInfo{Type: "array"}
	val := defaultJSONArray(schema)
	assert.Equal(t, `["test"]`, val)
}

func TestNeedsBodyMethods(t *testing.T) {
	t.Parallel()
	assert.True(t, needsBody("POST"))
	assert.True(t, needsBody("PUT"))
	assert.True(t, needsBody("PATCH"))
	assert.True(t, needsBody("post")) // case-insensitive
	assert.False(t, needsBody("GET"))
	assert.False(t, needsBody("DELETE"))
	assert.False(t, needsBody("HEAD"))
	assert.False(t, needsBody(""))
}

func TestDefaultContentTypeEmpty(t *testing.T) {
	t.Parallel()
	ep := Endpoint{} // no request bodies
	ct := defaultContentType(ep)
	assert.Equal(t, "application/json", ct)
}

func TestResolveURLVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		base    string
		path    string
		want    string
		wantErr bool
	}{
		{"trailing slash on base", "https://api.com/", "/users", "https://api.com/users", false},
		{"no leading slash on path", "https://api.com", "users", "https://api.com/users", false},
		{"both slashes", "https://api.com/", "/users", "https://api.com/users", false},
		{"empty base", "", "/users", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveURL(tt.base, tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestRegression_BuildJSONObjectInjectionTracking verifies that payload
// injection through nested objects is tracked via return value, not
// string containment. Before the fix, strings.Contains was used to detect
// injection — matching false positives when short payloads appear in defaults.
func TestRegression_BuildJSONObjectInjectionTracking(t *testing.T) {
	t.Parallel()

	t.Run("tracks injection via return value", func(t *testing.T) {
		// Object with nested object containing only integers, then a string field.
		// The nested call injects via fallback, which is tracked by the return bool.
		schema := SchemaInfo{
			Properties: map[string]SchemaInfo{
				"data": {
					Type: "object",
					Properties: map[string]SchemaInfo{
						"count": {Type: "integer"},
					},
				},
				"name": {Type: "string"},
			},
		}
		result, injected := buildJSONObject(schema, "test-payload", true)
		assert.True(t, injected)
		assert.Contains(t, result, "test-payload")
	})

	t.Run("no injection when disabled", func(t *testing.T) {
		schema := SchemaInfo{
			Properties: map[string]SchemaInfo{
				"name": {Type: "string"},
			},
		}
		result, injected := buildJSONObject(schema, "payload", false)
		assert.False(t, injected)
		assert.NotContains(t, result, "payload")
	})

	t.Run("empty schema returns not injected", func(t *testing.T) {
		schema := SchemaInfo{}
		result, injected := buildJSONObject(schema, "payload", true)
		assert.False(t, injected)
		assert.Equal(t, "{}", result)
	})
}
