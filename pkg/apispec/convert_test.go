package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToDiscoveryResult_NilSpec(t *testing.T) {
	t.Parallel()
	result := ToDiscoveryResult(nil, "https://example.com")
	assert.Equal(t, "https://example.com", result.Target)
	assert.Empty(t, result.Endpoints)
}

func TestToDiscoveryResult_BasicConversion(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{
				Method:       "GET",
				Path:         "/users",
				Group:        "users",
				ContentTypes: []string{"application/json"},
				Parameters: []Parameter{
					{Name: "page", In: LocationQuery, Schema: SchemaInfo{Type: "integer"}, Required: true},
					{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}, Example: "test"},
				},
			},
			{Method: "POST", Path: "/users", Group: "users"},
		},
	}

	result := ToDiscoveryResult(spec, "https://api.example.com")
	assert.Equal(t, "https://api.example.com", result.Target)
	require.Len(t, result.Endpoints, 2)

	ep := result.Endpoints[0]
	assert.Equal(t, "GET", ep.Method)
	assert.Equal(t, "/users", ep.Path)
	assert.Equal(t, "users", ep.Category)
	assert.Equal(t, "application/json", ep.ContentType)
	require.Len(t, ep.Parameters, 2)
	assert.Equal(t, "page", ep.Parameters[0].Name)
	assert.Equal(t, "query", ep.Parameters[0].Location)
	assert.Equal(t, "integer", ep.Parameters[0].Type)
	assert.True(t, ep.Parameters[0].Required)
	assert.Equal(t, "test", ep.Parameters[1].Example)
}

func TestToDiscoveryResult_Statistics(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/a", Group: "api", Parameters: []Parameter{{Name: "x"}, {Name: "y"}}},
			{Method: "POST", Path: "/b", Group: "api"},
			{Method: "GET", Path: "/c", Group: "auth"},
		},
	}

	result := ToDiscoveryResult(spec, "https://example.com")
	assert.Equal(t, 3, result.Statistics.TotalEndpoints)
	assert.Equal(t, 2, result.Statistics.ByMethod["GET"])
	assert.Equal(t, 1, result.Statistics.ByMethod["POST"])
	assert.Equal(t, 2, result.Statistics.ByCategory["api"])
	assert.Equal(t, 1, result.Statistics.ByCategory["auth"])
	assert.Equal(t, 2, result.Statistics.TotalParameters)
}

func TestToDiscoveryResult_AttackSurface(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Format: FormatOpenAPI3,
		AuthSchemes: []AuthScheme{
			{Name: "oauth", Type: AuthOAuth2},
		},
		Endpoints: []Endpoint{
			{
				Method:       "POST",
				Path:         "/upload",
				Auth:         []string{"bearer"},
				ContentTypes: []string{"application/json", "application/xml", "multipart/form-data"},
				Parameters:   []Parameter{{Name: "file"}},
				RequestBodies: map[string]RequestBody{
					"multipart/form-data": {Schema: SchemaInfo{Format: "binary"}},
				},
			},
		},
	}

	result := ToDiscoveryResult(spec, "https://example.com")
	as := result.AttackSurface

	assert.True(t, as.HasAuthEndpoints)
	assert.True(t, as.HasAPIEndpoints)
	assert.True(t, as.AcceptsJSON)
	assert.True(t, as.AcceptsXML)
	assert.True(t, as.AcceptsFormData)
	assert.True(t, as.HasFileUpload)
	assert.True(t, as.HasOAuth)
	assert.Contains(t, as.RelevantCategories, "brokenauth")
	assert.Contains(t, as.RelevantCategories, "upload")
	assert.Contains(t, as.RelevantCategories, "oauth")
}

func TestToDiscoveryResult_GraphQL(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Format:    FormatGraphQL,
		Endpoints: []Endpoint{{Method: "POST", Path: "/graphql"}},
	}

	result := ToDiscoveryResult(spec, "http://example.com/graphql")
	assert.True(t, result.AttackSurface.HasGraphQL)
	assert.Contains(t, result.AttackSurface.RelevantCategories, "graphql")
}

func TestToDiscoveryResult_AsyncAPI(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Format:    FormatAsyncAPI,
		Endpoints: []Endpoint{{Method: "WS", Path: "/ws"}},
	}

	result := ToDiscoveryResult(spec, "ws://example.com")
	assert.True(t, result.AttackSurface.HasWebSockets)
}

func TestToDiscoveryResult_NoContentType(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/plain"},
		},
	}

	result := ToDiscoveryResult(spec, "https://example.com")
	require.Len(t, result.Endpoints, 1)
	assert.Empty(t, result.Endpoints[0].ContentType)
}

func TestExampleToString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", exampleToString(nil))
	assert.Equal(t, "hello", exampleToString("hello"))
	assert.Equal(t, "", exampleToString(42))
}
