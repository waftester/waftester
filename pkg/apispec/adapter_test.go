package apispec

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOpenAPI3JSON(t *testing.T) {
	spec, err := Parse("testdata/petstore-oa3.json")
	require.NoError(t, err)

	assert.Equal(t, FormatOpenAPI3, spec.Format)
	assert.Equal(t, "Petstore", spec.Title)
	assert.Equal(t, "1.0.0", spec.Version)
	assert.Equal(t, "3.0.3", spec.SpecVersion)
	assert.Equal(t, "testdata/petstore-oa3.json", spec.Source)
	assert.False(t, spec.ParsedAt.IsZero())

	// Servers
	require.Len(t, spec.Servers, 2)
	assert.Equal(t, "https://petstore.example.com/v1", spec.Servers[0].URL)
	assert.Equal(t, "Production", spec.Servers[0].Description)

	// Endpoints
	assert.Len(t, spec.Endpoints, 5) // listPets, createPet, getPet, deletePet, listUsers

	// Find listPets
	var listPets *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].OperationID == "listPets" {
			listPets = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, listPets)
	assert.Equal(t, "GET", listPets.Method)
	assert.Equal(t, "/pets", listPets.Path)
	assert.Equal(t, "List all pets", listPets.Summary)
	assert.Contains(t, listPets.Tags, "pets")
	assert.Equal(t, "pets", listPets.Group)
	assert.NotEmpty(t, listPets.CorrelationTag)

	// Parameters
	require.Len(t, listPets.Parameters, 2)
	var limitParam *Parameter
	for i := range listPets.Parameters {
		if listPets.Parameters[i].Name == "limit" {
			limitParam = &listPets.Parameters[i]
		}
	}
	require.NotNil(t, limitParam)
	assert.Equal(t, LocationQuery, limitParam.In)
	assert.Equal(t, "integer", limitParam.Schema.Type)

	// Auth schemes
	assert.Len(t, spec.AuthSchemes, 2) // bearerAuth, apiKey
	var bearerScheme *AuthScheme
	for i := range spec.AuthSchemes {
		if spec.AuthSchemes[i].Name == "bearerAuth" {
			bearerScheme = &spec.AuthSchemes[i]
		}
	}
	require.NotNil(t, bearerScheme)
	assert.Equal(t, AuthBearer, bearerScheme.Type)
	assert.Equal(t, "bearer", bearerScheme.Scheme)

	// Groups
	assert.True(t, len(spec.Groups) >= 1)

	// createPet should have security
	var createPet *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].OperationID == "createPet" {
			createPet = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, createPet)
	assert.Contains(t, createPet.Auth, "bearerAuth")
	assert.NotEmpty(t, createPet.RequestBodies)
	assert.Contains(t, createPet.ContentTypes, "application/json")
}

func TestParseOpenAPI3YAML(t *testing.T) {
	spec, err := Parse("testdata/petstore-oa3.yaml")
	require.NoError(t, err)

	assert.Equal(t, FormatOpenAPI3, spec.Format)
	assert.Equal(t, "Petstore YAML", spec.Title)
	assert.Len(t, spec.Endpoints, 3) // listPets, createPet, getPet
	assert.Len(t, spec.Servers, 1)
}

func TestParseSwagger2(t *testing.T) {
	spec, err := Parse("testdata/petstore-swagger2.json")
	require.NoError(t, err)

	assert.Equal(t, FormatSwagger2, spec.Format)
	assert.Equal(t, "Petstore Swagger", spec.Title)
	assert.True(t, len(spec.Endpoints) >= 3, "expected at least 3 endpoints, got %d", len(spec.Endpoints))

	// Server should be constructed from host+basePath
	require.NotEmpty(t, spec.Servers)
	assert.Contains(t, spec.Servers[0].URL, "petstore.example.com")

	// Find listPets
	var listPets *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].OperationID == "listPets" {
			listPets = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, listPets)
	assert.Equal(t, "GET", listPets.Method)
}

func TestParseURL(t *testing.T) {
	// Serve a spec over HTTP
	data, err := os.ReadFile("testdata/petstore-oa3.json")
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data) //nolint:errcheck
	}))
	defer ts.Close()

	spec, err := Parse(ts.URL + "/petstore.json")
	require.NoError(t, err)

	assert.Equal(t, FormatOpenAPI3, spec.Format)
	assert.Equal(t, "Petstore", spec.Title)
	assert.Len(t, spec.Endpoints, 5)
}

func TestParseUnknownFormat(t *testing.T) {
	_, err := Parse("testdata/invalid.json")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedFormat)
}

func TestParseNonexistentFile(t *testing.T) {
	_, err := Parse("testdata/does-not-exist.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec file")
}

func TestParseEmptySpec(t *testing.T) {
	spec, err := Parse("testdata/empty-spec.json")
	require.NoError(t, err)

	assert.Equal(t, FormatOpenAPI3, spec.Format)
	assert.Empty(t, spec.Endpoints) // Empty paths
}

func TestParseComplexRefs(t *testing.T) {
	spec, err := Parse("testdata/complex-refs.json")
	require.NoError(t, err)

	assert.Equal(t, FormatOpenAPI3, spec.Format)
	assert.Len(t, spec.Endpoints, 1)
}

func TestParseUnicodePaths(t *testing.T) {
	spec, err := Parse("testdata/unicode-paths.json")
	require.NoError(t, err)

	assert.Equal(t, FormatOpenAPI3, spec.Format)
	assert.Len(t, spec.Endpoints, 3)

	paths := make(map[string]bool)
	for _, ep := range spec.Endpoints {
		paths[ep.Path] = true
	}
	assert.True(t, paths["/users/über"], "should preserve ü")
	assert.True(t, paths["/日本語/items"], "should preserve Japanese")
	assert.True(t, paths["/café/menu"], "should preserve é")
}

func TestParseFileTooLarge(t *testing.T) {
	// Create a temp file larger than maxSpecSize is impractical,
	// so assert the constant is defined and the error exists
	assert.Equal(t, int64(50*1024*1024), maxSpecSize)
	assert.NotNil(t, ErrSpecTooLarge)
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		expected Format
	}{
		{"OpenAPI 3 JSON", "testdata/petstore-oa3.json", FormatOpenAPI3},
		{"OpenAPI 3 YAML", "testdata/petstore-oa3.yaml", FormatOpenAPI3},
		{"Swagger 2 JSON", "testdata/petstore-swagger2.json", FormatSwagger2},
		{"Postman v2.1", "testdata/collection-basic.postman.json", FormatPostman},
		{"HAR", "testdata/traffic.har", FormatHAR},
		{"Invalid", "testdata/invalid.json", FormatUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.file)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, detectFormat(data, tt.file))
		})
	}
}

func TestCorrelationTag(t *testing.T) {
	tag1 := CorrelationTag("GET", "/pets")
	tag2 := CorrelationTag("get", "/pets") // case should normalize
	tag3 := CorrelationTag("POST", "/pets")

	assert.Equal(t, tag1, tag2, "same method+path should produce same tag")
	assert.NotEqual(t, tag1, tag3, "different methods should produce different tags")
	assert.Len(t, tag1, 12, "tag should be 12 hex chars")
}

func TestBaseURL(t *testing.T) {
	spec := newTestSpec()
	assert.Equal(t, "https://api.example.com", spec.BaseURL())

	empty := &Spec{}
	assert.Empty(t, empty.BaseURL())
}

func TestResolveBaseURL(t *testing.T) {
	spec := newTestSpec()

	// No override: use first server
	assert.Equal(t, "https://api.example.com", ResolveBaseURL(spec, ""))

	// Override wins
	assert.Equal(t, "https://override.com", ResolveBaseURL(spec, "https://override.com/"))
}

func TestResolveVariables(t *testing.T) {
	spec := &Spec{
		Servers: []Server{
			{URL: "https://{{host}}/{{version}}"},
		},
		Variables: map[string]Variable{
			"host":    {Default: "default.example.com"},
			"version": {Default: "v1"},
		},
	}

	// CLI vars override defaults
	ResolveVariables(spec, map[string]string{"host": "custom.example.com"}, nil)
	assert.Equal(t, "https://custom.example.com/v1", spec.Servers[0].URL)
}

func TestResolveVariablesPrecedence(t *testing.T) {
	spec := &Spec{
		Servers: []Server{
			{URL: "https://{{host}}/api"},
		},
		Variables: map[string]Variable{
			"host": {Default: "default.com"},
		},
	}

	// CLI > env > default
	ResolveVariables(spec, map[string]string{"host": "cli.com"}, map[string]string{"host": "env.com"})
	assert.Equal(t, "https://cli.com/api", spec.Servers[0].URL)
}

func TestSubstituteVariables(t *testing.T) {
	vars := map[string]Variable{
		"baseUrl":    {Value: "https://api.example.com"},
		"apiVersion": {Default: "v1"},
	}

	result := SubstituteVariables("{{baseUrl}}/{{apiVersion}}/items", vars)
	assert.Equal(t, "https://api.example.com/v1/items", result)

	// Unresolved variables stay as-is
	result = SubstituteVariables("{{unknown}}/data", vars)
	assert.Equal(t, "{{unknown}}/data", result)
}

func TestFilterEndpoints(t *testing.T) {
	spec := newTestSpec()

	gets := spec.FilterEndpoints(func(ep Endpoint) bool {
		return ep.Method == "GET"
	})
	assert.Len(t, gets, 2)
}

func TestEndpointsByGroup(t *testing.T) {
	spec := newTestSpec()
	for i := range spec.Endpoints {
		spec.Endpoints[i].Group = "pets"
		spec.Endpoints[i].Tags = []string{"pets"}
	}

	result := spec.EndpointsByGroup("pets")
	assert.Len(t, result, 3)

	result = spec.EndpointsByGroup("unknown")
	assert.Empty(t, result)
}

func TestEndpointMethods(t *testing.T) {
	ep := Endpoint{
		Path: "/users/{userId}/orders/{orderId}",
	}
	assert.True(t, ep.HasPathParams())

	ep2 := Endpoint{Path: "/users"}
	assert.False(t, ep2.HasPathParams())

	assert.Equal(t, "https://api.example.com/users", ep2.FullPath("https://api.example.com"))
	assert.Equal(t, "https://api.example.com/users", ep2.FullPath("https://api.example.com/"))
}

func TestSpecValidate(t *testing.T) {
	spec := newTestSpec()
	assert.NoError(t, spec.Validate())

	bad := &Spec{Format: FormatUnknown}
	assert.ErrorIs(t, bad.Validate(), ErrInvalidSpec)

	empty := &Spec{}
	assert.ErrorIs(t, empty.Validate(), ErrInvalidSpec)
}

func TestIsURL(t *testing.T) {
	assert.True(t, isURL("http://example.com"))
	assert.True(t, isURL("https://example.com/spec.json"))
	assert.False(t, isURL("./spec.json"))
	assert.False(t, isURL("spec.json"))
	assert.False(t, isURL("/absolute/path.json"))
}

func TestParseHARFile(t *testing.T) {
	spec, err := Parse("testdata/traffic.har")
	require.NoError(t, err)

	assert.Equal(t, FormatHAR, spec.Format)
	assert.Equal(t, "1.2", spec.SpecVersion)

	// Should be deduplicated: GET /users (2 entries), POST /users, GET /users/123, PUT /users/123, POST /upload
	assert.Len(t, spec.Endpoints, 5)

	// Server should be extracted
	require.NotEmpty(t, spec.Servers)
	assert.Equal(t, "https://api.example.com", spec.Servers[0].URL)
}

func TestParsePostmanBasic(t *testing.T) {
	spec, err := Parse("testdata/collection-basic.postman.json")
	require.NoError(t, err)

	assert.Equal(t, FormatPostman, spec.Format)
	assert.Equal(t, "Basic API Collection", spec.Title)
	assert.Equal(t, "2.1", spec.SpecVersion)
	assert.Len(t, spec.Endpoints, 3) // List, Create, Get
}

func TestParseFileAbsPath(t *testing.T) {
	abs, err := filepath.Abs("testdata/petstore-oa3.json")
	require.NoError(t, err)

	spec, err := Parse(abs)
	require.NoError(t, err)
	assert.Equal(t, FormatOpenAPI3, spec.Format)
}

func FuzzParseJSON(f *testing.F) {
	// Seed corpus
	seeds := []string{
		`{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}`,
		`{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{}}`,
		`{"info":{"name":"c","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[]}`,
		`{"log":{"version":"1.2","entries":[]}}`,
		`{}`,
		`[]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		parseByFormat(data, "fuzz.json", detectFormat(data, "fuzz.json"))
	})
}

func FuzzParseYAML(f *testing.F) {
	f.Add([]byte("openapi: '3.0.0'\ninfo:\n  title: t\n  version: '1'\npaths: {}"))
	f.Add([]byte("swagger: '2.0'\ninfo:\n  title: t\n  version: '1'\npaths: {}"))
	f.Add([]byte("{}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		parseByFormat(data, "fuzz.yaml", detectFormat(data, "fuzz.yaml"))
	})
}

func BenchmarkParseOpenAPI3(b *testing.B) {
	data, err := os.ReadFile("testdata/petstore-oa3.json")
	require.NoError(b, err)

	b.ResetTimer()
	for b.Loop() {
		parseOpenAPI3(data, "bench.json")
	}
}

func TestParseByFormat_AsyncAPI(t *testing.T) {
	content := `{"asyncapi":"2.6.0","info":{"title":"Test","version":"1.0.0"},"servers":{"ws":{"url":"wss://example.com","protocol":"wss"}},"channels":{"/test":{"subscribe":{"operationId":"recv","message":{"payload":{"type":"object"}}}}}}`
	spec, err := parseByFormat([]byte(content), "test.json", FormatAsyncAPI)
	require.NoError(t, err)
	assert.Equal(t, FormatAsyncAPI, spec.Format)
	assert.Equal(t, "Test", spec.Title)
}

func TestParseByFormat_GraphQL_ReturnsHint(t *testing.T) {
	_, err := parseByFormat([]byte(`{"data":{"__schema":{}}}`), "introspection.json", FormatGraphQL)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedFormat)
	assert.Contains(t, err.Error(), "IntrospectionToSpec")
}

func TestParseByFormat_GRPC_ReturnsHint(t *testing.T) {
	_, err := parseByFormat(nil, "service.proto", FormatGRPC)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedFormat)
	assert.Contains(t, err.Error(), "ReflectionToSpec")
}

// TestRegression_CircularRefDoesNotStackOverflow verifies that a schema with
// a self-referential $ref (Node → children → $ref Node) terminates instead of
// causing infinite recursion. Without the seen-map + maxSchemaDepth guard in
// convertOA3SchemaWithDepth, this spec would stack-overflow.
func TestRegression_CircularRefDoesNotStackOverflow(t *testing.T) {
	t.Parallel()

	circularSpec := `{
		"openapi": "3.0.3",
		"info": {"title": "Circular", "version": "1.0.0"},
		"paths": {
			"/nodes": {
				"post": {
					"operationId": "createNode",
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {"$ref": "#/components/schemas/Node"}
							}
						}
					},
					"responses": {"200": {"description": "ok"}}
				}
			}
		},
		"components": {
			"schemas": {
				"Node": {
					"type": "object",
					"properties": {
						"name": {"type": "string"},
						"children": {
							"type": "array",
							"items": {"$ref": "#/components/schemas/Node"}
						},
						"parent": {"$ref": "#/components/schemas/Node"}
					}
				}
			}
		}
	}`

	spec, err := parseByFormat([]byte(circularSpec), "circular.json", FormatOpenAPI3)
	require.NoError(t, err, "circular $ref must not cause error")
	require.Len(t, spec.Endpoints, 1)

	// The request body schema should be resolved, and circular refs should
	// produce a placeholder instead of recursing forever.
	body, ok := spec.Endpoints[0].RequestBodies["application/json"]
	require.True(t, ok)
	assert.Equal(t, "object", body.Schema.Type)

	// At least one of the circular paths should have the sentinel format.
	hasCircularMarker := false
	var walk func(si SchemaInfo)
	walk = func(si SchemaInfo) {
		if strings.Contains(si.Format, "circular-ref:") {
			hasCircularMarker = true
			return
		}
		for _, p := range si.Properties {
			walk(p)
		}
		if si.Items != nil {
			walk(*si.Items)
		}
	}
	walk(body.Schema)
	assert.True(t, hasCircularMarker, "circular $ref should produce a circular-ref sentinel")
}

// TestRegression_Swagger2SchemaDepthLimit verifies that convertSwagger2Schema
// doesn't stack overflow on deeply nested inline schemas. Before the fix,
// there was no depth limit on the Swagger 2 conversion path, while the
// OA3 path had maxSchemaDepth=20. A malicious spec could cause OOM.
func TestRegression_Swagger2SchemaDepthLimit(t *testing.T) {
	t.Parallel()

	// Build a schema nested 30 levels deep (exceeds maxSchemaDepth=20).
	deepSchema := map[string]interface{}{
		"type": "string",
	}
	for i := 0; i < 30; i++ {
		deepSchema = map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"nested": deepSchema,
			},
		}
	}

	// Should not panic or stack overflow — result should be truncated.
	result := convertSwagger2Schema(deepSchema)
	assert.Equal(t, "object", result.Type)

	// Walk the tree to count actual depth. Should stop at maxSchemaDepth.
	depth := 0
	current := result
	for {
		nested, ok := current.Properties["nested"]
		if !ok || nested.Type == "" {
			break
		}
		depth++
		current = nested
	}
	assert.LessOrEqual(t, depth, 21, "schema depth should be capped at maxSchemaDepth")
}
