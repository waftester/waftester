package apispec

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareFindings_AllNew(t *testing.T) {
	current := []SpecFinding{
		{Method: "GET", Path: "/users", Category: "sqli", Parameter: "id"},
		{Method: "POST", Path: "/login", Category: "xss", Parameter: "email"},
	}

	result := CompareFindings(nil, current)

	assert.Equal(t, 0, result.BaselineCount)
	assert.Equal(t, 2, result.CurrentCount)
	assert.Len(t, result.New, 2)
	assert.Empty(t, result.Fixed)
	assert.Empty(t, result.Regressed)
	assert.Empty(t, result.Unchanged)
}

func TestCompareFindings_AllFixed(t *testing.T) {
	baseline := []SpecFinding{
		{Method: "GET", Path: "/users", Category: "sqli", Parameter: "id"},
		{Method: "POST", Path: "/login", Category: "xss", Parameter: "email"},
	}

	result := CompareFindings(baseline, nil)

	assert.Equal(t, 2, result.BaselineCount)
	assert.Equal(t, 0, result.CurrentCount)
	assert.Len(t, result.Fixed, 2)
	assert.Empty(t, result.New)
}

func TestCompareFindings_Mixed(t *testing.T) {
	baseline := []SpecFinding{
		{Method: "GET", Path: "/users", Category: "sqli", Parameter: "id", Severity: "high"},
		{Method: "POST", Path: "/login", Category: "xss", Parameter: "email", Severity: "medium"},
		{Method: "DELETE", Path: "/admin", Category: "accesscontrol", Parameter: "", Severity: "critical"},
	}

	current := []SpecFinding{
		{Method: "GET", Path: "/users", Category: "sqli", Parameter: "id", Severity: "high"},      // unchanged
		{Method: "POST", Path: "/login", Category: "xss", Parameter: "email", Severity: "high"},   // regressed (medium -> high)
		{Method: "PUT", Path: "/data", Category: "nosqli", Parameter: "body", Severity: "medium"}, // new
	}

	result := CompareFindings(baseline, current)

	assert.Len(t, result.Fixed, 1)     // DELETE /admin gone
	assert.Len(t, result.Regressed, 1) // POST /login worsened
	assert.Len(t, result.New, 1)       // PUT /data is new
	assert.Len(t, result.Unchanged, 1) // GET /users same

	assert.Equal(t, 3, result.BaselineCount)
	assert.Equal(t, 3, result.CurrentCount)
}

func TestCompareFindings_Empty(t *testing.T) {
	result := CompareFindings(nil, nil)

	assert.Empty(t, result.Fixed)
	assert.Empty(t, result.New)
	assert.Empty(t, result.Regressed)
	assert.Empty(t, result.Unchanged)
}

func TestSaveAndLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	findings := []SpecFinding{
		{Method: "GET", Path: "/api", Category: "sqli", Severity: "high"},
		{Method: "POST", Path: "/login", Category: "xss", Severity: "medium"},
	}

	err := SaveBaseline(path, findings, "petstore.yaml")
	require.NoError(t, err)

	bl, err := LoadBaseline(path)
	require.NoError(t, err)

	assert.Equal(t, "petstore.yaml", bl.SpecSource)
	assert.NotEmpty(t, bl.CreatedAt)
	assert.Len(t, bl.Findings, 2)
	assert.Equal(t, "sqli", bl.Findings[0].Category)
}

func TestLoadBaseline_NotFound(t *testing.T) {
	_, err := LoadBaseline("/nonexistent/baseline.json")
	assert.Error(t, err)
}

func TestLoadBaseline_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, writeTestFile(path, "not json"))

	_, err := LoadBaseline(path)
	assert.Error(t, err)
}

func TestFindingKey(t *testing.T) {
	f := SpecFinding{
		Method:    "GET",
		Path:      "/users",
		Category:  "sqli",
		Parameter: "id",
	}

	key := findingKey(f)
	assert.Equal(t, "GET|/users|sqli|id", key)
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity string
		rank     int
	}{
		{"info", 1},
		{"low", 2},
		{"medium", 3},
		{"high", 4},
		{"critical", 5},
		{"unknown", 0},
		{"", 0},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.rank, severityRank(tt.severity), "severity=%s", tt.severity)
	}
}

func TestCompareFindings_SameSeverityUnchanged(t *testing.T) {
	baseline := []SpecFinding{
		{Method: "GET", Path: "/api", Category: "sqli", Parameter: "q", Severity: "high"},
	}
	current := []SpecFinding{
		{Method: "GET", Path: "/api", Category: "sqli", Parameter: "q", Severity: "high"},
	}

	result := CompareFindings(baseline, current)
	assert.Len(t, result.Unchanged, 1)
	assert.Empty(t, result.Regressed)
}

func TestCompareFindings_ImprovedSeverityUnchanged(t *testing.T) {
	// Severity improved (high -> low) counts as unchanged, not regressed.
	baseline := []SpecFinding{
		{Method: "GET", Path: "/api", Category: "sqli", Parameter: "q", Severity: "high"},
	}
	current := []SpecFinding{
		{Method: "GET", Path: "/api", Category: "sqli", Parameter: "q", Severity: "low"},
	}

	result := CompareFindings(baseline, current)
	assert.Len(t, result.Unchanged, 1)
	assert.Empty(t, result.Regressed)
}
