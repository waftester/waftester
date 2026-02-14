package apispec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderPreview_NilPlan(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	RenderPreview(&buf, nil, nil, DefaultPreviewConfig())
	assert.Contains(t, buf.String(), "No scan plan")
}

func TestRenderPreview_EmptyPlan(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	plan := &ScanPlan{Intensity: IntensityNormal}
	RenderPreview(&buf, plan, nil, DefaultPreviewConfig())
	assert.Contains(t, buf.String(), "Endpoints:   0")
	assert.Contains(t, buf.String(), "Total tests: 0")
}

func TestRenderPreview_Summary(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	plan := &ScanPlan{
		Intensity:  IntensityDeep,
		TotalTests: 42,
		Entries: []ScanPlanEntry{
			{
				Endpoint: Endpoint{Method: "GET", Path: "/users", Priority: PriorityHigh},
				Attack:   AttackSelection{Category: "sqli", PayloadCount: 20, Reason: "param type"},
			},
			{
				Endpoint: Endpoint{Method: "GET", Path: "/users", Priority: PriorityHigh},
				Attack:   AttackSelection{Category: "xss", PayloadCount: 22, Reason: "param type"},
			},
		},
	}
	spec := &Spec{Format: FormatOpenAPI3}
	RenderPreview(&buf, plan, spec, DefaultPreviewConfig())

	output := buf.String()
	assert.Contains(t, output, "Endpoints:   1")
	assert.Contains(t, output, "Attack types: 2")
	assert.Contains(t, output, "Total tests: 42")
	assert.Contains(t, output, "deep")
	assert.Contains(t, output, "openapi3")
}

func TestRenderPreview_PriorityBreakdown(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Priority: PriorityCritical}, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: Endpoint{Priority: PriorityCritical}, Attack: AttackSelection{Category: "xss"}},
			{Endpoint: Endpoint{Priority: PriorityLow}, Attack: AttackSelection{Category: "cors"}},
		},
	}
	RenderPreview(&buf, plan, nil, DefaultPreviewConfig())

	output := buf.String()
	assert.Contains(t, output, "CRITICAL")
	assert.Contains(t, output, "LOW")
}

func TestRenderPreview_CategoryBreakdown(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/a"}, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: Endpoint{Method: "GET", Path: "/b"}, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: Endpoint{Method: "GET", Path: "/c"}, Attack: AttackSelection{Category: "xss"}},
		},
	}
	RenderPreview(&buf, plan, nil, DefaultPreviewConfig())

	output := buf.String()
	assert.Contains(t, output, "sqli")
	assert.Contains(t, output, "2 targets")
	assert.Contains(t, output, "xss")
	assert.Contains(t, output, "1 targets")
}

func TestRenderPreview_EndpointTable(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{
				Endpoint: Endpoint{Method: "POST", Path: "/login", Priority: PriorityHigh},
				Attack:   AttackSelection{Category: "brokenauth", PayloadCount: 15, Reason: "path pattern"},
			},
		},
	}
	cfg := DefaultPreviewConfig()
	RenderPreview(&buf, plan, nil, cfg)

	output := buf.String()
	assert.Contains(t, output, "POST /login")
	assert.Contains(t, output, "brokenauth")
	assert.Contains(t, output, "Tests: 15")
}

func TestRenderPreview_Truncation(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	entries := make([]ScanPlanEntry, 0, 60)
	for i := 0; i < 60; i++ {
		entries = append(entries, ScanPlanEntry{
			Endpoint: Endpoint{Method: "GET", Path: "/ep" + string(rune('a'+i%26))},
			Attack:   AttackSelection{Category: "sqli"},
		})
	}
	plan := &ScanPlan{Entries: entries}
	cfg := PreviewConfig{MaxEndpoints: 5}
	RenderPreview(&buf, plan, nil, cfg)

	output := buf.String()
	assert.Contains(t, output, "more endpoints")
}

func TestRenderPreview_AuthWarning(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{
				Endpoint: Endpoint{Method: "GET", Path: "/admin", Auth: []string{"bearer"}},
				Attack:   AttackSelection{Category: "sqli"},
			},
		},
	}
	spec := &Spec{
		AuthSchemes: []AuthScheme{{Name: "bearer", Type: AuthBearer}},
	}
	RenderPreview(&buf, plan, spec, DefaultPreviewConfig())

	assert.Contains(t, buf.String(), "require auth")
}

func TestRenderPreview_LargePlanWarning(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	entries := make([]ScanPlanEntry, 1001)
	for i := range entries {
		entries[i] = ScanPlanEntry{
			Endpoint: Endpoint{Method: "GET", Path: "/x"},
			Attack:   AttackSelection{Category: "sqli"},
		}
	}
	plan := &ScanPlan{Entries: entries}
	cfg := PreviewConfig{MaxEndpoints: 0} // no truncation
	RenderPreview(&buf, plan, nil, cfg)

	assert.Contains(t, buf.String(), "Large plan")
}

func TestPriorityLabel(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "CRIT", priorityLabel(PriorityCritical))
	assert.Equal(t, "HIGH", priorityLabel(PriorityHigh))
	assert.Equal(t, " MED", priorityLabel(PriorityMedium))
	assert.Equal(t, " LOW", priorityLabel(PriorityLow))
	assert.Equal(t, " MED", priorityLabel(Priority(99)))
}

func TestCountUniqueEndpoints(t *testing.T) {
	t.Parallel()
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/a"}},
			{Endpoint: Endpoint{Method: "GET", Path: "/a"}},
			{Endpoint: Endpoint{Method: "POST", Path: "/a"}},
		},
	}
	assert.Equal(t, 2, countUniqueEndpoints(plan))
}

func TestDedupStrings(t *testing.T) {
	t.Parallel()
	result := dedupStrings([]string{"a", "b", "a", "c", "b"})
	assert.Equal(t, []string{"a", "b", "c"}, result)

	assert.Empty(t, dedupStrings(nil))
}

func TestRenderPreview_NoReasons(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{
				Endpoint: Endpoint{Method: "GET", Path: "/test"},
				Attack:   AttackSelection{Category: "sqli"},
			},
		},
	}
	cfg := PreviewConfig{ShowReasons: false, ShowPayloadCounts: false}
	RenderPreview(&buf, plan, nil, cfg)

	output := buf.String()
	assert.Contains(t, output, "GET /test")
	assert.NotContains(t, output, "Tests:")
}

func TestRenderPreview_DedupAttacksPerEndpoint(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	plan := &ScanPlan{
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/x"}, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: Endpoint{Method: "GET", Path: "/x"}, Attack: AttackSelection{Category: "sqli"}},
			{Endpoint: Endpoint{Method: "GET", Path: "/x"}, Attack: AttackSelection{Category: "xss"}},
		},
	}
	RenderPreview(&buf, plan, nil, DefaultPreviewConfig())

	output := buf.String()
	// Count occurrences of "sqli" in the Scans line — should appear once.
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Scans:") {
			assert.Equal(t, 1, strings.Count(line, "sqli"), "sqli should appear once in Scans line")
			break
		}
	}
}
