package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpecConfigHasSpec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		cfg    SpecConfig
		expect bool
	}{
		{"empty", SpecConfig{}, false},
		{"path", SpecConfig{SpecPath: "api.yaml"}, true},
		{"url", SpecConfig{SpecURL: "https://example.com/spec"}, true},
		{"content", SpecConfig{SpecContent: `{"openapi":"3.0"}`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, tt.cfg.HasSpec())
		})
	}
}

func TestSpecConfigSource(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "api.yaml", (&SpecConfig{SpecPath: "api.yaml"}).Source())
	assert.Equal(t, "https://x.com/api", (&SpecConfig{SpecURL: "https://x.com/api"}).Source())
	assert.Equal(t, "inline", (&SpecConfig{SpecContent: "{}"}).Source())
	assert.Equal(t, "", (&SpecConfig{}).Source())
}

func TestSpecConfigMatchesPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		filter string
		path   string
		match  bool
	}{
		{"", "/anything", true},
		{"/users/*", "/users/123", true},
		{"/users/*", "/pets/123", false},
		{"/api/v1/*", "/api/v1/users", true},
		{"/api/v1/*", "/api/v2/users", false},
	}
	for _, tt := range tests {
		t.Run(tt.filter+"→"+tt.path, func(t *testing.T) {
			cfg := SpecConfig{PathFilter: tt.filter}
			assert.Equal(t, tt.match, cfg.MatchesPath(tt.path))
		})
	}
}

func TestSpecConfigMatchesGroup(t *testing.T) {
	t.Parallel()

	// No filter matches everything.
	cfg := SpecConfig{}
	assert.True(t, cfg.MatchesGroup("admin", nil))

	// Group filter.
	cfg = SpecConfig{Groups: []string{"admin"}}
	assert.True(t, cfg.MatchesGroup("admin", nil))
	assert.False(t, cfg.MatchesGroup("public", nil))

	// Group filter matches tags.
	assert.True(t, cfg.MatchesGroup("", []string{"admin", "v2"}))

	// Skip group.
	cfg = SpecConfig{SkipGroups: []string{"health"}}
	assert.True(t, cfg.MatchesGroup("admin", nil))
	assert.False(t, cfg.MatchesGroup("health", nil))
	assert.False(t, cfg.MatchesGroup("", []string{"health"}))

	// Case insensitive.
	cfg = SpecConfig{Groups: []string{"Admin"}}
	assert.True(t, cfg.MatchesGroup("admin", nil))
}

func TestSpecConfigFilterEndpoints(t *testing.T) {
	t.Parallel()
	eps := []Endpoint{
		{Method: "GET", Path: "/users/1", Group: "users", Tags: []string{"users"}},
		{Method: "POST", Path: "/users", Group: "users", Tags: []string{"users"}},
		{Method: "GET", Path: "/pets/1", Group: "pets", Tags: []string{"pets"}},
		{Method: "GET", Path: "/health", Group: "system", Tags: []string{"health"}},
	}

	// No filter returns all.
	cfg := SpecConfig{}
	assert.Len(t, cfg.FilterEndpoints(eps), 4)

	// Group filter.
	cfg = SpecConfig{Groups: []string{"users"}}
	filtered := cfg.FilterEndpoints(eps)
	assert.Len(t, filtered, 2)

	// Skip group.
	cfg = SpecConfig{SkipGroups: []string{"system"}}
	filtered = cfg.FilterEndpoints(eps)
	assert.Len(t, filtered, 3)

	// Path filter.
	cfg = SpecConfig{PathFilter: "/users/*"}
	filtered = cfg.FilterEndpoints(eps)
	assert.Len(t, filtered, 1) // only /users/1 matches
}

func TestSpecConfigShouldScan(t *testing.T) {
	t.Parallel()

	// No filter allows all.
	cfg := SpecConfig{}
	assert.True(t, cfg.ShouldScan("sqli"))

	// Explicit types.
	cfg = SpecConfig{ScanTypes: []string{"sqli", "xss"}}
	assert.True(t, cfg.ShouldScan("sqli"))
	assert.True(t, cfg.ShouldScan("XSS"))
	assert.False(t, cfg.ShouldScan("cors"))

	// Skip types.
	cfg = SpecConfig{SkipTypes: []string{"cors"}}
	assert.True(t, cfg.ShouldScan("sqli"))
	assert.False(t, cfg.ShouldScan("cors"))

	// Skip takes precedence.
	cfg = SpecConfig{ScanTypes: []string{"cors"}, SkipTypes: []string{"cors"}}
	assert.False(t, cfg.ShouldScan("cors"))
}

func TestAuthConfigHasAuth(t *testing.T) {
	t.Parallel()
	assert.False(t, (&AuthConfig{}).HasAuth())
	assert.True(t, (&AuthConfig{BearerToken: "tok"}).HasAuth())
	assert.True(t, (&AuthConfig{APIKey: "key"}).HasAuth())
	assert.True(t, (&AuthConfig{AuthHeader: "Basic abc"}).HasAuth())
	assert.True(t, (&AuthConfig{BasicUser: "user"}).HasAuth())
	assert.True(t, (&AuthConfig{CustomHeaders: map[string]string{"X-Custom": "val"}}).HasAuth())
}

func TestSpecFlagsToConfig(t *testing.T) {
	t.Parallel()

	// Simulate flag parsing.
	sf := SpecFlags{}
	path := "api.yaml"
	sf.SpecPath = &path
	specURL := ""
	sf.SpecURL = &specURL
	group := "admin,users"
	sf.Group = &group
	skipGroup := "health"
	sf.SkipGroup = &skipGroup
	pathFilter := "/api/*"
	sf.PathFilter = &pathFilter
	vs := varSlice{"key1=val1", "key2=val2"}
	sf.Var = &vs
	envFile := "env.json"
	sf.EnvFile = &envFile
	dryRun := true
	sf.DryRun = &dryRun
	confirm := false
	sf.Confirm = &confirm
	intensity := "deep"
	sf.Intensity = &intensity

	cfg := sf.ToConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, "api.yaml", cfg.SpecPath)
	assert.Equal(t, []string{"admin", "users"}, cfg.Groups)
	assert.Equal(t, []string{"health"}, cfg.SkipGroups)
	assert.Equal(t, "/api/*", cfg.PathFilter)
	assert.Equal(t, map[string]string{"key1": "val1", "key2": "val2"}, cfg.Variables)
	assert.Equal(t, "env.json", cfg.EnvFile)
	assert.True(t, cfg.DryRun)
	assert.False(t, cfg.Confirm)
	assert.Equal(t, IntensityDeep, cfg.Intensity)
}

func TestVarSlice(t *testing.T) {
	t.Parallel()
	var vs varSlice
	assert.NoError(t, vs.Set("key=value"))
	assert.NoError(t, vs.Set("host=example.com"))
	assert.Contains(t, vs.String(), "key=value")

	m := vs.ToMap()
	assert.Len(t, m, 2)
	assert.Equal(t, "value", m["key"])
	assert.Equal(t, "example.com", m["host"])
}

func TestSplitCSV(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a", "b", "c"}, splitCSV("a,b,c"))
	assert.Equal(t, []string{"a", "b"}, splitCSV(" a , b "))
	assert.Nil(t, splitCSV(""))
	assert.Equal(t, []string{"single"}, splitCSV("single"))
}
