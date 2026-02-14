package apispec

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHARBasic(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	assert.Equal(t, FormatHAR, spec.Format)
	assert.Equal(t, "HAR Import", spec.Title)
	assert.Equal(t, "1.2", spec.SpecVersion)

	// Server extracted from first entry
	require.NotEmpty(t, spec.Servers)
	assert.Equal(t, "https://api.example.com", spec.Servers[0].URL)
}

func TestHARDeduplication(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	// Two GET /users entries should be deduplicated to one
	getUsers := 0
	for _, ep := range spec.Endpoints {
		if ep.Method == "GET" && ep.Path == "/users" {
			getUsers++
		}
	}
	assert.Equal(t, 1, getUsers, "duplicate GET /users should be deduplicated")

	// Total: GET /users, POST /users, GET /users/123, PUT /users/123, POST /upload
	assert.Len(t, spec.Endpoints, 5)
}

func TestHARQueryParams(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	var getUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "GET" && spec.Endpoints[i].Path == "/users" {
			getUsers = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, getUsers)

	// Should have query params extracted
	queryParams := make(map[string]bool)
	for _, p := range getUsers.Parameters {
		if p.In == LocationQuery {
			queryParams[p.Name] = true
		}
	}
	assert.True(t, queryParams["page"], "should extract 'page' query param")
	assert.True(t, queryParams["limit"], "should extract 'limit' query param")
}

func TestHARCustomHeaders(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	var getUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "GET" && spec.Endpoints[i].Path == "/users" {
			getUsers = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, getUsers)

	// Should include custom headers but skip standard ones
	headerNames := make(map[string]bool)
	for _, p := range getUsers.Parameters {
		if p.In == LocationHeader {
			headerNames[p.Name] = true
		}
	}
	assert.True(t, headerNames["Authorization"], "should include Authorization")
	assert.True(t, headerNames["X-Custom-Header"], "should include custom headers")
	assert.False(t, headerNames["User-Agent"], "should skip User-Agent")
	assert.False(t, headerNames["Accept"], "should skip Accept")
}

func TestHARPostBody(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	var postUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "POST" && spec.Endpoints[i].Path == "/users" {
			postUsers = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, postUsers)

	// Should have JSON body
	assert.Contains(t, postUsers.ContentTypes, "application/json")
	rb, ok := postUsers.RequestBodies["application/json"]
	assert.True(t, ok)
	assert.NotNil(t, rb.Example, "should capture body text as example")
}

func TestHARFormBody(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	var postUpload *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "POST" && spec.Endpoints[i].Path == "/upload" {
			postUpload = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, postUpload)

	// Should have form body with params
	assert.Contains(t, postUpload.ContentTypes, "application/x-www-form-urlencoded")
	rb, ok := postUpload.RequestBodies["application/x-www-form-urlencoded"]
	assert.True(t, ok)
	assert.NotEmpty(t, rb.Schema.Properties, "should have form field properties")
}

func TestHARCharsetStripping(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	// PUT /users/123 has mimeType "application/json; charset=utf-8"
	var putUser *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "PUT" && spec.Endpoints[i].Path == "/users/123" {
			putUser = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, putUser)

	// Content type key should be stripped of charset
	assert.Contains(t, putUser.ContentTypes, "application/json")
	_, ok := putUser.RequestBodies["application/json"]
	assert.True(t, ok, "should use base content type without charset")
}

func TestHAREmptyEntries(t *testing.T) {
	data := []byte(`{"log":{"version":"1.2","entries":[]}}`)
	spec, err := parseHAR(data, "empty.har")
	require.NoError(t, err)

	assert.Equal(t, FormatHAR, spec.Format)
	assert.Empty(t, spec.Endpoints)
	assert.Empty(t, spec.Servers)
}

func TestHARMissingFields(t *testing.T) {
	data := []byte(`{"log":{"version":"1.2","entries":[{"request":{"method":"","url":""}},{"request":{"method":"GET","url":"https://api.com/test"}}]}}`)
	spec, err := parseHAR(data, "partial.har")
	require.NoError(t, err)

	// Empty method/url entry should be skipped
	assert.Len(t, spec.Endpoints, 1)
	assert.Equal(t, "GET", spec.Endpoints[0].Method)
}

func TestHARMergeParams(t *testing.T) {
	// Two entries for the same endpoint with different query params
	data := []byte(`{"log":{"version":"1.2","entries":[
		{"request":{"method":"GET","url":"https://api.com/items","queryString":[{"name":"page","value":"1"}]}},
		{"request":{"method":"GET","url":"https://api.com/items","queryString":[{"name":"page","value":"2"},{"name":"sort","value":"name"}]}}
	]}}`)

	spec, err := parseHAR(data, "merge.har")
	require.NoError(t, err)

	// Should be one endpoint
	require.Len(t, spec.Endpoints, 1)

	// Should have both params (page from first, sort merged from second)
	paramNames := make(map[string]bool)
	for _, p := range spec.Endpoints[0].Parameters {
		paramNames[p.Name] = true
	}
	assert.True(t, paramNames["page"])
	assert.True(t, paramNames["sort"])
}

func TestIsStandardHeader(t *testing.T) {
	assert.True(t, isStandardHeader("User-Agent"))
	assert.True(t, isStandardHeader("user-agent"))
	assert.True(t, isStandardHeader("Content-Type"))
	assert.True(t, isStandardHeader("Accept"))
	assert.False(t, isStandardHeader("Authorization"))
	assert.False(t, isStandardHeader("X-Custom"))
	assert.False(t, isStandardHeader("X-API-Key"))
}

func TestExtractHARPath(t *testing.T) {
	tests := []struct {
		url  string
		path string
		host string
	}{
		{"https://api.com/users/123", "/users/123", "https://api.com"},
		{"https://api.com/", "/", "https://api.com"},
		{"https://api.com", "/", "https://api.com"},
		{"http://localhost:8080/api/v1", "/api/v1", "http://localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			path, host := extractHARPath(tt.url)
			assert.Equal(t, tt.path, path)
			assert.Equal(t, tt.host, host)
		})
	}
}

func TestHARCorrelationTags(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	for _, ep := range spec.Endpoints {
		assert.NotEmpty(t, ep.CorrelationTag, "every endpoint should have a correlation tag")
		assert.Len(t, ep.CorrelationTag, 12, "tag should be 12 hex chars")
	}
}

func TestHARInvalidJSON(t *testing.T) {
	_, err := parseHAR([]byte(`not json`), "bad.har")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "har parse")
}

func TestHARQueryParamsFromURL(t *testing.T) {
	// When QueryString array is empty, params should be extracted from URL
	data := []byte(`{"log":{"version":"1.2","entries":[
		{"request":{"method":"GET","url":"https://api.com/search?q=test&page=1","queryString":[]}}
	]}}`)

	spec, err := parseHAR(data, "url-query.har")
	require.NoError(t, err)

	require.Len(t, spec.Endpoints, 1)
	paramNames := make(map[string]bool)
	for _, p := range spec.Endpoints[0].Parameters {
		if p.In == LocationQuery {
			paramNames[p.Name] = true
		}
	}
	assert.True(t, paramNames["q"], "should extract 'q' from URL")
	assert.True(t, paramNames["page"], "should extract 'page' from URL")
}

func TestHARNoFileExtensionDetection(t *testing.T) {
	// HAR format should be detected by content, not just file extension
	data, err := os.ReadFile("testdata/traffic.har")
	require.NoError(t, err)

	format := detectFormat(data, "recording.json") // wrong extension
	assert.Equal(t, FormatHAR, format)
}

func TestHARResponseCapture(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	// First endpoint should have response metadata from the HAR
	var getUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "GET" && spec.Endpoints[i].Path == "/users" {
			getUsers = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, getUsers, "should find GET /users")
	require.Contains(t, getUsers.Responses, "200")
	assert.Equal(t, "OK", getUsers.Responses["200"].Description)
}
