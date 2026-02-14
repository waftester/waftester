package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePostmanBasicCollection(t *testing.T) {
	spec, err := Parse("testdata/collection-basic.postman.json")
	require.NoError(t, err)

	assert.Equal(t, FormatPostman, spec.Format)
	assert.Equal(t, "Basic API Collection", spec.Title)
	assert.Equal(t, "2.1", spec.SpecVersion)
	assert.Len(t, spec.Endpoints, 3)

	// Collection variables
	assert.Contains(t, spec.Variables, "baseUrl")
	assert.Equal(t, "https://api.example.com", spec.Variables["baseUrl"].Value)
	assert.Contains(t, spec.Variables, "apiVersion")
	assert.Equal(t, "v1", spec.Variables["apiVersion"].Value)

	// Collection-level auth
	require.NotEmpty(t, spec.AuthSchemes)
	assert.Equal(t, AuthBearer, spec.AuthSchemes[0].Type)
}

func TestParsePostmanNestedFolders(t *testing.T) {
	spec, err := Parse("testdata/collection-nested.postman.json")
	require.NoError(t, err)

	assert.Equal(t, FormatPostman, spec.Format)
	assert.Equal(t, "Nested Folders Collection", spec.Title)

	// Should have groups: Users, Admin
	assert.True(t, len(spec.Groups) >= 2)
	groupNames := make(map[string]bool)
	for _, g := range spec.Groups {
		groupNames[g.Name] = true
	}
	assert.True(t, groupNames["Users"])
	assert.True(t, groupNames["Admin"])

	// Admin should have Users as parent
	for _, g := range spec.Groups {
		if g.Name == "Admin" {
			assert.Equal(t, "Users", g.ParentName)
		}
	}

	// Should have 4 endpoints: ListAllUsers, DeleteUser, GetProfile, HealthCheck
	assert.Len(t, spec.Endpoints, 4)

	// Auth inheritance: Admin endpoints should inherit apikey from Admin folder
	var listAllUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Summary == "List All Users" {
			listAllUsers = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, listAllUsers, "should find 'List All Users' endpoint")
	assert.Contains(t, listAllUsers.Auth, "apikey", "should inherit Admin folder auth")

	// GetProfile should inherit Users folder bearer auth
	var getProfile *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Summary == "Get Profile" {
			getProfile = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, getProfile)
	assert.Contains(t, getProfile.Auth, "bearer", "should inherit Users folder auth")

	// Health Check has no folder auth — no auth inherited
	var healthCheck *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Summary == "Health Check" {
			healthCheck = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, healthCheck)
	assert.Empty(t, healthCheck.Auth)
}

func TestParsePostmanVariableSubstitution(t *testing.T) {
	spec, err := Parse("testdata/collection-variables.postman.json")
	require.NoError(t, err)

	assert.Equal(t, "Variables Collection", spec.Title)

	// Variables should be populated
	assert.Contains(t, spec.Variables, "baseUrl")
	assert.Contains(t, spec.Variables, "apiVersion")
	assert.Contains(t, spec.Variables, "authToken")

	// Get Items endpoint should have resolved path
	require.Len(t, spec.Endpoints, 2)

	// Unresolved {{unknownVar}} should be preserved, not panic
	var unresolved *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Summary == "Unresolved Variable" {
			unresolved = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, unresolved)
	assert.Contains(t, unresolved.Path, "unknownVar", "unresolved vars should be preserved")
}

func TestParsePostmanV20(t *testing.T) {
	spec, err := Parse("testdata/collection-v2.0.postman.json")
	require.NoError(t, err)

	assert.Equal(t, FormatPostman, spec.Format)
	assert.Equal(t, "2.0", spec.SpecVersion)
	assert.Equal(t, "V2.0 Collection", spec.Title)
	assert.Len(t, spec.Endpoints, 1)
}

func TestPostmanDisabledParams(t *testing.T) {
	spec, err := Parse("testdata/collection-basic.postman.json")
	require.NoError(t, err)

	// "List Pets" has a disabled "status" query param
	var listPets *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Summary == "List Pets" {
			listPets = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, listPets)

	// Disabled param should not appear
	for _, p := range listPets.Parameters {
		if p.In == LocationQuery {
			assert.NotEqual(t, "status", p.Name, "disabled param should not be included")
		}
	}
}

func TestPostmanPathVariables(t *testing.T) {
	spec, err := Parse("testdata/collection-basic.postman.json")
	require.NoError(t, err)

	// "Get Pet" has a :petId path variable
	var getPet *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Summary == "Get Pet" {
			getPet = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, getPet)

	// Path should have :petId converted to {petId}
	assert.Contains(t, getPet.Path, "{petId}", "should convert :param to {param}")

	// Should have a path parameter
	var pathParam *Parameter
	for i := range getPet.Parameters {
		if getPet.Parameters[i].In == LocationPath {
			pathParam = &getPet.Parameters[i]
		}
	}
	require.NotNil(t, pathParam)
	assert.Equal(t, "petId", pathParam.Name)
	assert.True(t, pathParam.Required)
}

func TestPostmanRequestBody(t *testing.T) {
	spec, err := Parse("testdata/collection-basic.postman.json")
	require.NoError(t, err)

	var createPet *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Summary == "Create Pet" {
			createPet = &spec.Endpoints[i]
		}
	}
	require.NotNil(t, createPet)

	assert.Contains(t, createPet.ContentTypes, "application/json")
	assert.Contains(t, createPet.RequestBodies, "application/json")
}

func TestLoadPostmanEnvironment(t *testing.T) {
	env, err := LoadPostmanEnvironment("testdata/test.postman_environment.json")
	require.NoError(t, err)

	assert.Equal(t, "https://staging.example.com", env["baseUrl"])
	assert.Equal(t, "test-api-key-12345", env["apiKey"])
	assert.Equal(t, "test-bearer-token", env["bearerToken"])

	// Disabled var should not appear
	_, exists := env["disabledVar"]
	assert.False(t, exists, "disabled variables should be excluded")
}

func TestLoadPostmanEnvironmentNotFound(t *testing.T) {
	_, err := LoadPostmanEnvironment("testdata/nonexistent.json")
	require.Error(t, err)
}

func TestLoadPostmanEnvironmentMergePrecedence(t *testing.T) {
	// Simulate: env file < collection vars < --var CLI

	// Load env file
	envVars, err := LoadPostmanEnvironment("testdata/test.postman_environment.json")
	require.NoError(t, err)

	// Parse collection with variables
	spec, err := Parse("testdata/collection-variables.postman.json")
	require.NoError(t, err)

	// Convert env to the right format
	envMap := make(map[string]string)
	for k, v := range envVars {
		envMap[k] = v
	}

	// CLI overrides everything
	cliVars := map[string]string{"baseUrl": "https://cli-override.com"}

	ResolveVariables(spec, cliVars, envMap)

	// CLI should win
	assert.Equal(t, "https://cli-override.com", spec.Variables["baseUrl"].Value)
}

func TestNormalizePostmanPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/users/:userId", "/users/{userId}"},
		{"/users/:userId/orders/:orderId", "/users/{userId}/orders/{orderId}"},
		{"/users", "/users"},
		{"/:id", "/{id}"},
		{"/", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizePostmanPath(tt.input))
		})
	}
}

func TestConvertPostmanAuth(t *testing.T) {
	tests := []struct {
		authType string
		expected AuthType
	}{
		{"bearer", AuthBearer},
		{"basic", AuthBasic},
		{"apikey", AuthAPIKey},
		{"oauth2", AuthOAuth2},
		{"custom-type", AuthCustom},
	}

	for _, tt := range tests {
		t.Run(tt.authType, func(t *testing.T) {
			auth := &postmanAuth{Type: tt.authType}
			result := convertPostmanAuth("test", auth)
			assert.Equal(t, tt.expected, result.Type)
		})
	}
}
