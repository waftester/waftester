package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildIntelligentPlanNilSpec(t *testing.T) {
	t.Parallel()
	plan := BuildIntelligentPlan(nil, IntelligenceOptions{})
	require.NotNil(t, plan)
	assert.Empty(t, plan.Entries)
}

func TestBuildIntelligentPlanEmptyEndpoints(t *testing.T) {
	t.Parallel()
	spec := &Spec{Endpoints: nil}
	plan := BuildIntelligentPlan(spec, IntelligenceOptions{})
	assert.Empty(t, plan.Entries)
}

func TestLayerParamType(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{
		Parameters: []Parameter{
			{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}},
		},
	}
	layerParamType(ep, sel)

	// String query param should suggest injection attacks.
	assert.Contains(t, sel, "sqli")
	assert.Contains(t, sel, "xss")
	assert.Contains(t, sel, "cmdi")
	assert.Contains(t, sel, "ssti")
}

func TestLayerParamTypeURI(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{
		Parameters: []Parameter{
			{Name: "callback", In: LocationQuery, Schema: SchemaInfo{Type: "string", Format: "uri"}},
		},
	}
	layerParamType(ep, sel)

	assert.Contains(t, sel, "ssrf")
	assert.Contains(t, sel, "redirect")
}

func TestLayerParamTypeBody(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{
		RequestBodies: map[string]RequestBody{
			"application/json": {
				Schema: SchemaInfo{
					Properties: map[string]SchemaInfo{
						"data": {Type: "object"},
					},
				},
			},
		},
	}
	layerParamType(ep, sel)

	assert.Contains(t, sel, "nosqli")
	assert.Contains(t, sel, "prototype")
	assert.Contains(t, sel, "massassignment")
}

func TestLayerParamName(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{
		Parameters: []Parameter{
			{Name: "redirect_url", In: LocationQuery},
		},
	}
	layerParamName(ep, sel)

	assert.Contains(t, sel, "ssrf")
	assert.Contains(t, sel, "redirect")
}

func TestLayerPathPatternLogin(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Path: "/login"}
	layerPathPattern(ep, sel)

	assert.Contains(t, sel, "brokenauth")
	assert.Contains(t, sel, "jwt")
	assert.Equal(t, PriorityHigh, ep.Priority)
}

func TestLayerPathPatternAdmin(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Path: "/admin/users"}
	layerPathPattern(ep, sel)

	assert.Contains(t, sel, "accesscontrol")
	assert.Equal(t, PriorityCritical, ep.Priority)
}

func TestLayerPathPatternHealth(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Path: "/health"}
	layerPathPattern(ep, sel)

	// Health endpoints have no attack categories.
	for _, s := range sel {
		assert.NotEmpty(t, s.Layers)
	}
	assert.Equal(t, PriorityLow, ep.Priority)
}

func TestLayerPathPatternVersionPrefix(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Path: "/v1/login"}
	layerPathPattern(ep, sel)

	assert.Contains(t, sel, "brokenauth")
}

func TestLayerAuthContextMissingAuth(t *testing.T) {
	t.Parallel()
	endpoints := []Endpoint{
		{Method: "GET", Path: "/users", Auth: []string{"bearerAuth"}},
		{Method: "POST", Path: "/users", Auth: []string{"bearerAuth"}},
		{Method: "GET", Path: "/users/public"}, // No auth.
	}
	authMap := buildAuthMap(endpoints)

	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Method: "GET", Path: "/users/public"}
	layerAuthContext(ep, authMap, sel)

	assert.Contains(t, sel, "accesscontrol")
	assert.Contains(t, sel, "brokenauth")
}

func TestLayerAuthContextAllHaveAuth(t *testing.T) {
	t.Parallel()
	endpoints := []Endpoint{
		{Method: "GET", Path: "/users", Auth: []string{"bearerAuth"}},
		{Method: "POST", Path: "/users", Auth: []string{"bearerAuth"}},
	}
	authMap := buildAuthMap(endpoints)

	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Method: "GET", Path: "/users", Auth: []string{"bearerAuth"}}
	layerAuthContext(ep, authMap, sel)

	// Should not flag when endpoint has auth.
	assert.NotContains(t, sel, "accesscontrol")
}

func TestLayerSchemaConstraintsMaxLength(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	maxLen := 100
	ep := &Endpoint{
		Parameters: []Parameter{
			{Name: "name", In: LocationQuery, Schema: SchemaInfo{Type: "string", MaxLength: &maxLen}},
		},
	}
	layerSchemaConstraints(ep, sel)

	assert.Contains(t, sel, "inputvalidation")
}

func TestLayerSchemaConstraintsEnum(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{
		Parameters: []Parameter{
			{Name: "status", In: LocationQuery, Schema: SchemaInfo{
				Type: "string",
				Enum: []string{"active", "inactive"},
			}},
		},
	}
	layerSchemaConstraints(ep, sel)

	assert.Contains(t, sel, "inputvalidation")
	assert.Contains(t, sel, "sqli")
}

func TestLayerSchemaConstraintsURIFormat(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{
		Parameters: []Parameter{
			{Name: "website", In: LocationQuery, Schema: SchemaInfo{Type: "string", Format: "uri"}},
		},
	}
	layerSchemaConstraints(ep, sel)

	assert.Contains(t, sel, "ssrf")
	assert.Contains(t, sel, "redirect")
}

func TestLayerContentTypeMutationJSONToXML(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{
		RequestBodies: map[string]RequestBody{
			"application/json": {},
		},
	}
	layerContentTypeMutation(ep, sel)

	assert.Contains(t, sel, "xxe")
}

func TestLayerContentTypeMutationNoBody(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{}
	layerContentTypeMutation(ep, sel)

	assert.Empty(t, sel)
}

func TestLayerMethodConfusion(t *testing.T) {
	t.Parallel()
	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Method: "GET", Path: "/users"}
	layerMethodConfusion(ep, sel)

	assert.Contains(t, sel, "httpprobe")
	s := sel["httpprobe"]
	assert.Contains(t, s.Reason, "DELETE")
}

func TestLayerCrossEndpointIDOR(t *testing.T) {
	t.Parallel()
	endpoints := []Endpoint{
		{Method: "GET", Path: "/users/{id}"},
		{Method: "PUT", Path: "/users/{id}"},
	}
	pathIndex := buildPathIndex(endpoints)

	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Method: "GET", Path: "/users/{id}"}
	layerCrossEndpoint(ep, pathIndex, sel)

	assert.Contains(t, sel, "idor")
	assert.Contains(t, sel, "accesscontrol")
}

func TestLayerCrossEndpointRace(t *testing.T) {
	t.Parallel()
	endpoints := []Endpoint{
		{Method: "POST", Path: "/orders"},
		{Method: "PUT", Path: "/orders"},
	}
	pathIndex := buildPathIndex(endpoints)

	sel := make(map[string]*AttackSelection)
	ep := &Endpoint{Method: "POST", Path: "/orders"}
	layerCrossEndpoint(ep, pathIndex, sel)

	assert.Contains(t, sel, "race")
}

func TestAssignPriorityDeprecated(t *testing.T) {
	t.Parallel()
	ep := &Endpoint{Deprecated: true, Path: "/old"}
	p := assignPriority(ep)
	assert.Equal(t, PriorityCritical, p)
}

func TestAssignPriorityAdmin(t *testing.T) {
	t.Parallel()
	ep := &Endpoint{Path: "/admin/dashboard"}
	p := assignPriority(ep)
	assert.Equal(t, PriorityCritical, p)
}

func TestAssignPriorityHealth(t *testing.T) {
	t.Parallel()
	ep := &Endpoint{Path: "/health"}
	p := assignPriority(ep)
	assert.Equal(t, PriorityLow, p)
}

func TestAssignPriorityDefault(t *testing.T) {
	t.Parallel()
	ep := &Endpoint{Path: "/users"}
	p := assignPriority(ep)
	assert.Equal(t, PriorityMedium, p)
}

func TestBuildIntelligentPlanSorted(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/health", CorrelationTag: "t1"}, // low
			{Method: "POST", Path: "/admin/users", CorrelationTag: "t2", // critical
				Parameters: []Parameter{{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}}}},
			{Method: "GET", Path: "/users", CorrelationTag: "t3", // medium
				Parameters: []Parameter{{Name: "id", In: LocationQuery, Schema: SchemaInfo{Type: "integer"}}}},
		},
	}
	plan := BuildIntelligentPlan(spec, IntelligenceOptions{Intensity: IntensityNormal})

	require.NotEmpty(t, plan.Entries)
	// Verify critical endpoints come first.
	if len(plan.Entries) >= 2 {
		assert.GreaterOrEqual(t, int(plan.Entries[0].Endpoint.Priority), int(plan.Entries[len(plan.Entries)-1].Endpoint.Priority))
	}
}

func TestBuildIntelligentPlanUserFilter(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users", CorrelationTag: "t1",
				Parameters: []Parameter{{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}}}},
		},
	}
	plan := BuildIntelligentPlan(spec, IntelligenceOptions{
		ScanTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	})

	// Only sqli entries should be in the plan.
	for _, entry := range plan.Entries {
		assert.Equal(t, "sqli", entry.Attack.Category)
	}
}

func TestBuildIntelligentPlanSkipTypes(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users", CorrelationTag: "t1",
				Parameters: []Parameter{{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}}}},
		},
	}
	plan := BuildIntelligentPlan(spec, IntelligenceOptions{
		SkipTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	})

	for _, entry := range plan.Entries {
		assert.NotEqual(t, "sqli", entry.Attack.Category)
	}
}

func TestBuildIntelligentPlanTotalTests(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users", CorrelationTag: "t1",
				Parameters: []Parameter{{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}}}},
		},
	}
	plan := BuildIntelligentPlan(spec, IntelligenceOptions{Intensity: IntensityNormal})

	// TotalTests should equal sum of PayloadCounts.
	total := 0
	for _, entry := range plan.Entries {
		total += entry.Attack.PayloadCount
	}
	assert.Equal(t, total, plan.TotalTests)
}

func TestBuildIntelligentPlanReasons(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "POST", Path: "/login", CorrelationTag: "t1",
				Parameters: []Parameter{{Name: "username", In: LocationBody, Schema: SchemaInfo{Type: "string"}}}},
		},
	}
	plan := BuildIntelligentPlan(spec, IntelligenceOptions{Intensity: IntensityNormal})

	for _, entry := range plan.Entries {
		assert.NotEmpty(t, entry.Attack.Reason, "category %s should have a reason", entry.Attack.Category)
		assert.NotEmpty(t, entry.Attack.Layers, "category %s should have layers", entry.Attack.Category)
	}
}

func TestBuildIntelligentPlanFileUploadEndpoint(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "POST", Path: "/upload", CorrelationTag: "t1",
				Parameters: []Parameter{{Name: "file", In: LocationBody, Schema: SchemaInfo{Type: "string", Format: "binary"}}}},
		},
	}
	plan := BuildIntelligentPlan(spec, IntelligenceOptions{Intensity: IntensityNormal})

	hasUpload := false
	for _, entry := range plan.Entries {
		if entry.Attack.Category == "upload" {
			hasUpload = true
		}
	}
	assert.True(t, hasUpload, "file upload endpoint should include 'upload' attack")
}

func TestBuildIntelligentPlanNoParamsOnlyMeta(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/status", CorrelationTag: "t1"},
		},
	}
	plan := BuildIntelligentPlan(spec, IntelligenceOptions{
		Intensity:        IntensityNormal,
		IncludeMetaScans: true,
	})

	// Should have meta scans even without parameters.
	require.NotEmpty(t, plan.Entries)
	for _, entry := range plan.Entries {
		// Should be meta-like scans.
		assert.NotEmpty(t, entry.Attack.Category)
	}
}

func TestNormalizePath(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/users/{_}", normalizePath("/users/{id}"))
	assert.Equal(t, "/users/{_}/posts/{_}", normalizePath("/users/{userId}/posts/{postId}"))
	assert.Equal(t, "/users", normalizePath("/users"))
}

func TestPathGroup(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/users", pathGroup("/users/123"))
	assert.Equal(t, "/", pathGroup("/"))
	assert.Equal(t, "/api", pathGroup("/api/v1/users"))
}

// TestRegression_FormatPercent verifies the formatPercent helper produces a
// percent suffix. The original bug returned bare integers without "%".
func TestRegression_FormatPercent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   float64
		want string
	}{
		{0.0, "0%"},
		{0.5, "50%"},
		{0.75, "75%"},
		{1.0, "100%"},
		{1.5, "100%"}, // clamped at 100%
		{0.999, "99%"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, formatPercent(tt.in), "formatPercent(%v)", tt.in)
	}
}
