package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/discovery"
)

func TestReconcile_NilSpec(t *testing.T) {
	t.Parallel()
	result := Reconcile(nil, &discovery.DiscoveryResult{}, true)
	assert.NotNil(t, result)
	assert.Empty(t, result.LiveEndpoints)
}

func TestReconcile_NilDiscovery(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users"},
		},
	}
	result := Reconcile(spec, nil, true)
	require.Len(t, result.LiveEndpoints, 1)
	assert.Equal(t, "/users", result.LiveEndpoints[0].Path)
	assert.Empty(t, result.DeadEndpoints)
}

func TestReconcile_LivenessCheck_EndpointFound(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users"},
			{Method: "POST", Path: "/users"},
		},
	}
	disc := &discovery.DiscoveryResult{
		Endpoints: []discovery.Endpoint{
			{Method: "GET", Path: "/users"},
			{Method: "POST", Path: "/users"},
		},
	}

	result := Reconcile(spec, disc, true)
	assert.Len(t, result.LiveEndpoints, 2)
	assert.Empty(t, result.DeadEndpoints)
	assert.Empty(t, result.UnlistedEndpoints)
}

func TestReconcile_LivenessCheck_DeadEndpoint(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users"},
			{Method: "DELETE", Path: "/admin/nuke"},
		},
	}
	disc := &discovery.DiscoveryResult{
		Endpoints: []discovery.Endpoint{
			{Method: "GET", Path: "/users"},
		},
	}

	result := Reconcile(spec, disc, true)
	assert.Len(t, result.LiveEndpoints, 1)
	require.Len(t, result.DeadEndpoints, 1)
	assert.Equal(t, "/admin/nuke", result.DeadEndpoints[0].Endpoint.Path)
	assert.Contains(t, result.DeadEndpoints[0].Reason, "not found")
}

func TestReconcile_NoLivenessCheck(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users"},
			{Method: "DELETE", Path: "/admin/nuke"},
		},
	}
	disc := &discovery.DiscoveryResult{
		Endpoints: []discovery.Endpoint{
			{Method: "GET", Path: "/users"},
		},
	}

	result := Reconcile(spec, disc, false)
	assert.Len(t, result.LiveEndpoints, 2)
	assert.Empty(t, result.DeadEndpoints)
}

func TestReconcile_UnlistedEndpoints(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users"},
		},
	}
	disc := &discovery.DiscoveryResult{
		Endpoints: []discovery.Endpoint{
			{Method: "GET", Path: "/users"},
			{Method: "GET", Path: "/debug/pprof"},
			{Method: "POST", Path: "/internal/metrics"},
		},
	}

	result := Reconcile(spec, disc, true)
	assert.Len(t, result.LiveEndpoints, 1)
	assert.Len(t, result.UnlistedEndpoints, 2)
}

func TestReconcile_PathTemplateMatching(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users/{userId}"},
		},
	}
	disc := &discovery.DiscoveryResult{
		Endpoints: []discovery.Endpoint{
			{Method: "GET", Path: "/users/{id}"},
		},
	}

	result := Reconcile(spec, disc, true)
	// Both normalize to /users/{_}, so they match.
	assert.Len(t, result.LiveEndpoints, 1)
	assert.Empty(t, result.DeadEndpoints)
}

func TestReconcile_AttachesTechnologies(t *testing.T) {
	t.Parallel()
	spec := &Spec{}
	disc := &discovery.DiscoveryResult{
		Technologies:   []string{"nginx", "PHP"},
		WAFDetected:    true,
		WAFFingerprint: "Cloudflare",
	}

	result := Reconcile(spec, disc, true)
	assert.Equal(t, []string{"nginx", "PHP"}, result.Technologies)
	assert.True(t, result.WAFDetected)
	assert.Equal(t, "Cloudflare", result.WAFFingerprint)
}

func TestReconcile_ConvertedEndpointHasCorrelationTag(t *testing.T) {
	t.Parallel()
	spec := &Spec{}
	disc := &discovery.DiscoveryResult{
		Endpoints: []discovery.Endpoint{
			{Method: "POST", Path: "/api/v1/submit"},
		},
	}

	result := Reconcile(spec, disc, true)
	require.Len(t, result.UnlistedEndpoints, 1)
	assert.NotEmpty(t, result.UnlistedEndpoints[0].CorrelationTag)
	assert.Equal(t, "POST", result.UnlistedEndpoints[0].Method)
}

func TestReconcile_ConvertedEndpointParameters(t *testing.T) {
	t.Parallel()
	spec := &Spec{}
	disc := &discovery.DiscoveryResult{
		Endpoints: []discovery.Endpoint{
			{
				Method: "GET",
				Path:   "/search",
				Parameters: []discovery.Parameter{
					{Name: "q", Location: "query", Type: "string", Required: true, Example: "test"},
					{Name: "page", Location: "query", Type: "number"},
				},
			},
		},
	}

	result := Reconcile(spec, disc, true)
	require.Len(t, result.UnlistedEndpoints, 1)
	ep := result.UnlistedEndpoints[0]
	require.Len(t, ep.Parameters, 2)
	assert.Equal(t, "q", ep.Parameters[0].Name)
	assert.Equal(t, LocationQuery, ep.Parameters[0].In)
	assert.True(t, ep.Parameters[0].Required)
	assert.Equal(t, "test", ep.Parameters[0].Example)
	assert.Equal(t, "string", ep.Parameters[0].Schema.Type)
}

func TestReconcile_ConvertedEndpointCategory(t *testing.T) {
	t.Parallel()
	spec := &Spec{}
	disc := &discovery.DiscoveryResult{
		Endpoints: []discovery.Endpoint{
			{Method: "POST", Path: "/auth/login", Category: "auth", ContentType: "application/json"},
		},
	}

	result := Reconcile(spec, disc, true)
	require.Len(t, result.UnlistedEndpoints, 1)
	ep := result.UnlistedEndpoints[0]
	assert.Equal(t, "auth", ep.Group)
	assert.Contains(t, ep.Tags, "auth")
	assert.Contains(t, ep.ContentTypes, "application/json")
}

func TestInjectTechnologies_NilPlan(t *testing.T) {
	t.Parallel()
	// Should not panic.
	InjectTechnologies(nil, []string{"nginx"})
}

func TestInjectTechnologies_EmptyTech(t *testing.T) {
	t.Parallel()
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Attack: AttackSelection{Category: "sqli", Reason: "param type"}},
		},
	}
	InjectTechnologies(plan, nil)
	assert.Equal(t, "param type", plan.Entries[0].Attack.Reason)
}

func TestInjectTechnologies_ServerDetected(t *testing.T) {
	t.Parallel()
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Attack: AttackSelection{Category: "smuggling", Reason: "method confusion"}},
			{Attack: AttackSelection{Category: "sqli", Reason: "param type"}},
		},
	}
	InjectTechnologies(plan, []string{"Nginx", "PHP"})
	assert.Contains(t, plan.Entries[0].Attack.Reason, "server technology detected")
	assert.NotContains(t, plan.Entries[1].Attack.Reason, "server technology")
}

func TestInjectTechnologies_GraphQLConfirmed(t *testing.T) {
	t.Parallel()
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Attack: AttackSelection{Category: "graphql", Reason: "path pattern"}},
		},
	}
	InjectTechnologies(plan, []string{"GraphQL"})
	assert.Contains(t, plan.Entries[0].Attack.Reason, "GraphQL confirmed")
}

func TestEndpointKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/users", "GET /users"},
		{"get", "/users", "GET /users"},
		{"", "/users", "GET /users"},
		{"POST", "/users/{id}", "POST /users/{_}"},
		{"DELETE", "/items/{itemId}/sub/{subId}", "DELETE /items/{_}/sub/{_}"},
	}
	for _, tt := range tests {
		got := endpointKey(tt.method, tt.path)
		assert.Equal(t, tt.want, got, "endpointKey(%q, %q)", tt.method, tt.path)
	}
}

func TestLocationFromString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  Location
	}{
		{"query", LocationQuery},
		{"QUERY", LocationQuery},
		{"path", LocationPath},
		{"header", LocationHeader},
		{"cookie", LocationCookie},
		{"body", LocationBody},
		{"unknown", LocationQuery},
		{"", LocationQuery},
	}
	for _, tt := range tests {
		got := locationFromString(tt.input)
		assert.Equal(t, tt.want, got, "locationFromString(%q)", tt.input)
	}
}

func TestContentTypesFromDiscovery(t *testing.T) {
	t.Parallel()
	assert.Nil(t, contentTypesFromDiscovery(""))
	assert.Equal(t, []string{"text/html"}, contentTypesFromDiscovery("text/html"))
}
