package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateContentTypeMutations_NoBody(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/users"}
	mutations := GenerateContentTypeMutations(ep)
	assert.Nil(t, mutations)
}

func TestGenerateContentTypeMutations_JSON(t *testing.T) {
	ep := Endpoint{
		Method: "POST",
		Path:   "/users",
		RequestBodies: map[string]RequestBody{
			"application/json": {Schema: SchemaInfo{Type: "object"}},
		},
	}

	mutations := GenerateContentTypeMutations(ep)
	require.Len(t, mutations, 4)

	mutatedTypes := make(map[string]bool)
	for _, m := range mutations {
		mutatedTypes[m.MutatedContentType] = true
		assert.Equal(t, "application/json", m.OriginalContentType)
		assert.NotEmpty(t, m.Purpose)
		assert.NotEmpty(t, m.Category)
	}

	assert.True(t, mutatedTypes["application/xml"], "missing XML mutation")
	assert.True(t, mutatedTypes["application/x-www-form-urlencoded"], "missing form mutation")
	assert.True(t, mutatedTypes["text/plain"], "missing text/plain mutation")
	assert.True(t, mutatedTypes["application/json; charset=utf-7"], "missing charset mutation")
}

func TestGenerateContentTypeMutations_XML(t *testing.T) {
	ep := Endpoint{
		Method: "POST",
		Path:   "/data",
		RequestBodies: map[string]RequestBody{
			"application/xml": {Schema: SchemaInfo{Type: "object"}},
		},
	}

	mutations := GenerateContentTypeMutations(ep)
	require.Len(t, mutations, 1)
	assert.Equal(t, "application/json", mutations[0].MutatedContentType)
}

func TestGenerateContentTypeMutations_Form(t *testing.T) {
	ep := Endpoint{
		Method: "POST",
		Path:   "/login",
		RequestBodies: map[string]RequestBody{
			"application/x-www-form-urlencoded": {Schema: SchemaInfo{Type: "object"}},
		},
	}

	mutations := GenerateContentTypeMutations(ep)
	require.Len(t, mutations, 2)

	targets := make(map[string]bool)
	for _, m := range mutations {
		targets[m.MutatedContentType] = true
	}
	assert.True(t, targets["application/json"])
	assert.True(t, targets["application/xml"])
}

func TestGenerateContentTypeMutations_Multipart(t *testing.T) {
	ep := Endpoint{
		Method: "POST",
		Path:   "/upload",
		RequestBodies: map[string]RequestBody{
			"multipart/form-data": {Schema: SchemaInfo{Type: "object"}},
		},
	}

	mutations := GenerateContentTypeMutations(ep)
	require.Len(t, mutations, 1)
	assert.Equal(t, "application/json", mutations[0].MutatedContentType)
}

func TestGenerateContentTypeMutations_MultipleContentTypes(t *testing.T) {
	ep := Endpoint{
		Method: "POST",
		Path:   "/data",
		RequestBodies: map[string]RequestBody{
			"application/json": {Schema: SchemaInfo{Type: "object"}},
			"application/xml":  {Schema: SchemaInfo{Type: "object"}},
		},
	}

	mutations := GenerateContentTypeMutations(ep)
	assert.NotEmpty(t, mutations)

	// Should have mutations from both content types.
	var fromJSON, fromXML bool
	for _, m := range mutations {
		if m.OriginalContentType == "application/json" {
			fromJSON = true
		}
		if m.OriginalContentType == "application/xml" {
			fromXML = true
		}
	}
	assert.True(t, fromJSON)
	assert.True(t, fromXML)
}

func TestGenerateMethodConfusionTests_GET(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/users/{id}"}
	tests := GenerateMethodConfusionTests(ep, nil)

	require.NotEmpty(t, tests)

	// GET is documented, so we shouldn't test GET.
	for _, tt := range tests {
		if !tt.UseOverrideHeader {
			assert.NotEqual(t, "GET", tt.TestedMethod, "should not test documented method")
		}
	}

	// Should include POST, DELETE, PUT, PATCH, TRACE (no HEAD, OPTIONS).
	testedMethods := make(map[string]bool)
	for _, tt := range tests {
		if !tt.UseOverrideHeader {
			testedMethods[tt.TestedMethod] = true
		}
	}
	assert.True(t, testedMethods["POST"])
	assert.True(t, testedMethods["DELETE"])
	assert.True(t, testedMethods["PUT"])
	assert.True(t, testedMethods["PATCH"])
	assert.True(t, testedMethods["TRACE"])
	assert.False(t, testedMethods["HEAD"])
	assert.False(t, testedMethods["OPTIONS"])
}

func TestGenerateMethodConfusionTests_MultipleDocumented(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/users/{id}"}
	tests := GenerateMethodConfusionTests(ep, []string{"GET", "PUT", "DELETE"})

	// GET, PUT, DELETE are documented — should not be tested.
	for _, tt := range tests {
		if !tt.UseOverrideHeader {
			assert.NotEqual(t, "GET", tt.TestedMethod)
			assert.NotEqual(t, "PUT", tt.TestedMethod)
			assert.NotEqual(t, "DELETE", tt.TestedMethod)
		}
	}
}

func TestGenerateMethodConfusionTests_OverrideHeaders(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/users"}
	tests := GenerateMethodConfusionTests(ep, nil)

	var overrideTests []MethodConfusionTest
	for _, tt := range tests {
		if tt.UseOverrideHeader {
			overrideTests = append(overrideTests, tt)
		}
	}

	// 3 dangerous methods x 3 override headers = 9.
	assert.Len(t, overrideTests, 9)

	for _, tt := range overrideTests {
		assert.Equal(t, "POST", tt.TestedMethod, "override tests should use POST")
		assert.Len(t, tt.OverrideHeaders, 1)
	}
}

func TestGenerateMethodConfusionTests_AllDocumented(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/users"}
	tests := GenerateMethodConfusionTests(ep, allHTTPMethods)

	// All methods documented: no direct method tests (HEAD/OPTIONS already skipped).
	for _, tt := range tests {
		if !tt.UseOverrideHeader {
			t.Errorf("unexpected direct method test: %s", tt.TestedMethod)
		}
	}

	// Override headers should also be empty since all dangerous methods are documented.
	overrideCount := 0
	for _, tt := range tests {
		if tt.UseOverrideHeader {
			overrideCount++
		}
	}
	assert.Equal(t, 0, overrideCount, "no override tests when all methods documented")
}

func TestGenerateEndpointMethodConfusionTests(t *testing.T) {
	ep := Endpoint{Method: "POST", Path: "/api/data"}
	tests := GenerateEndpointMethodConfusionTests(ep)
	assert.NotEmpty(t, tests)

	// POST is documented, should not test POST directly.
	for _, tt := range tests {
		if !tt.UseOverrideHeader {
			assert.NotEqual(t, "POST", tt.TestedMethod)
		}
	}
}

func TestMethodConfusionTest_Fields(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/api/users"}
	tests := GenerateMethodConfusionTests(ep, nil)

	for _, tt := range tests {
		assert.NotEmpty(t, tt.Purpose)
		assert.NotEmpty(t, tt.Path)
		assert.NotEmpty(t, tt.DocumentedMethod)
		assert.NotEmpty(t, tt.TestedMethod)
	}
}

func TestContentTypeMutation_Categories(t *testing.T) {
	ep := Endpoint{
		Method: "POST",
		Path:   "/api",
		RequestBodies: map[string]RequestBody{
			"application/json": {},
		},
	}

	mutations := GenerateContentTypeMutations(ep)
	categories := make(map[string]bool)
	for _, m := range mutations {
		categories[m.Category] = true
	}

	assert.True(t, categories["xxe"], "JSON->XML should produce xxe category")
	assert.True(t, categories["hpp"], "JSON->form should produce hpp category")
}
