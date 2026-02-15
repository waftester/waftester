package apispec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSimplePlanEmpty(t *testing.T) {
	t.Parallel()
	cfg := &SpecConfig{Intensity: IntensityNormal}

	// nil spec
	plan := BuildSimplePlan(nil, cfg)
	require.NotNil(t, plan)
	assert.Empty(t, plan.Entries)

	// spec with no endpoints
	plan = BuildSimplePlan(&Spec{}, cfg)
	require.NotNil(t, plan)
	assert.Empty(t, plan.Entries)
}

func TestBuildSimplePlanSingleEndpoint(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{
				Method: "GET",
				Path:   "/users",
				Parameters: []Parameter{
					{Name: "q", In: LocationQuery, Schema: SchemaInfo{Type: "string"}},
				},
			},
		},
	}

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli", "xss"},
		Intensity: IntensityNormal,
	}

	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)

	// sqli + xss are injection scans, so each gets an entry per parameter.
	// 1 endpoint × 1 param × 2 scan types = 2 entries.
	assert.Len(t, plan.Entries, 2)
	assert.Greater(t, plan.TotalTests, 0)
	assert.Greater(t, plan.EstimatedDuration.Milliseconds(), int64(0))
}

func TestBuildSimplePlanMetaScans(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/health"},
		},
	}

	cfg := &SpecConfig{
		ScanTypes: []string{"cors", "secheaders"},
		Intensity: IntensityNormal,
	}

	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)

	// Meta scans run once per endpoint, not per parameter.
	assert.Len(t, plan.Entries, 2)
}

func TestBuildSimplePlanRequestBody(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{
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
			},
		},
	}

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	}

	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)

	// 1 endpoint × 1 body target × 1 scan type = 1 entry.
	assert.Len(t, plan.Entries, 1)
	assert.Equal(t, LocationBody, plan.Entries[0].InjectionTarget.Location)
	assert.Equal(t, "application/json", plan.Entries[0].InjectionTarget.ContentType)
}

func TestBuildSimplePlanIntensity(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/test", Parameters: []Parameter{{Name: "q", In: LocationQuery}}},
		},
	}

	quick := BuildSimplePlan(spec, &SpecConfig{ScanTypes: []string{"sqli"}, Intensity: IntensityQuick})
	normal := BuildSimplePlan(spec, &SpecConfig{ScanTypes: []string{"sqli"}, Intensity: IntensityNormal})
	deep := BuildSimplePlan(spec, &SpecConfig{ScanTypes: []string{"sqli"}, Intensity: IntensityDeep})

	assert.Less(t, quick.TotalTests, normal.TotalTests)
	assert.Less(t, normal.TotalTests, deep.TotalTests)
}

func TestBuildSimplePlanFiltering(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/users", Group: "users"},
			{Method: "GET", Path: "/admin", Group: "admin"},
		},
	}

	cfg := &SpecConfig{
		Groups:    []string{"users"},
		ScanTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	}

	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)

	// Only the users endpoint should be in the plan.
	for _, entry := range plan.Entries {
		assert.Equal(t, "/users", entry.Endpoint.Path)
	}
}

func TestBuildSimplePlanSkipTypes(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/test", Parameters: []Parameter{{Name: "q", In: LocationQuery}}},
		},
	}

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli", "xss", "cors"},
		SkipTypes: []string{"cors"},
		Intensity: IntensityNormal,
	}

	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)

	for _, entry := range plan.Entries {
		assert.NotEqual(t, "cors", entry.Attack.Category)
	}
}

func TestIsMetaScan(t *testing.T) {
	t.Parallel()
	assert.True(t, isMetaScan("cors"))
	assert.True(t, isMetaScan("secheaders"))
	assert.True(t, isMetaScan("wafdetect"))
	assert.False(t, isMetaScan("sqli"))
	assert.False(t, isMetaScan("xss"))
}

func TestEstimatePayloads(t *testing.T) {
	t.Parallel()
	quick := estimatePayloads("sqli", IntensityQuick)
	normal := estimatePayloads("sqli", IntensityNormal)
	deep := estimatePayloads("sqli", IntensityDeep)
	paranoid := estimatePayloads("sqli", IntensityParanoid)

	assert.Less(t, quick, normal)
	assert.Less(t, normal, deep)
	assert.Less(t, deep, paranoid)
	assert.Greater(t, quick, 0)
}

func TestInjectableTargets(t *testing.T) {
	t.Parallel()
	ep := Endpoint{
		Parameters: []Parameter{
			{Name: "q", In: LocationQuery},
			{Name: "id", In: LocationPath},
			{Name: "X-Custom", In: LocationHeader},
		},
		RequestBodies: map[string]RequestBody{
			"application/json": {},
		},
	}

	targets := injectableTargets(ep)
	assert.Len(t, targets, 4) // 3 params + 1 body
}

// ──────────────────────────────────────────────────────────────────────────────
// Negative / edge-case tests.
// ──────────────────────────────────────────────────────────────────────────────

func TestInjectableTargetsEmpty(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/health"}
	targets := injectableTargets(ep)
	assert.Empty(t, targets)
}

func TestBuildSimplePlanNoParams(t *testing.T) {
	// Endpoints with no parameters should still get meta scans.
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/health"},
		},
	}

	cfg := &SpecConfig{
		ScanTypes: []string{"cors"},
		Intensity: IntensityNormal,
	}

	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)
	assert.Len(t, plan.Entries, 1, "meta scan should run even with no params")
	assert.Equal(t, "cors", plan.Entries[0].Attack.Category)
}

func TestBuildSimplePlanNoParamsInjectionScan(t *testing.T) {
	// Injection scan on endpoint with no params → should still generate
	// an entry with a default injection target.
	t.Parallel()
	spec := &Spec{
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/test"},
		},
	}

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	}

	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)
	assert.Greater(t, len(plan.Entries), 0,
		"injection scan should generate entry even with no params (uses default target)")
}

func TestEstimatePayloadsUnknownScanType(t *testing.T) {
	t.Parallel()
	count := estimatePayloads("unknown-type", IntensityNormal)
	assert.Greater(t, count, 0, "unknown scan type should return a default payload count")
}

func TestEstimateDurationZeroTests(t *testing.T) {
	t.Parallel()
	d := estimateDuration(0, IntensityNormal)
	assert.Equal(t, time.Duration(0), d)
}

func TestPayloadBaseCountKnown(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 50, payloadBaseCount("sqli"))
	assert.Equal(t, 40, payloadBaseCount("xss"))
}

func TestPayloadBaseCountUnknown(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 10, payloadBaseCount("nonexistent"))
}
