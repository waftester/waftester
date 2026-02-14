package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/nuclei"
)

func TestSelectTemplates_EmptyTemplates(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/users"}
	attacks := []AttackSelection{{Category: "sqli"}}
	result := SelectTemplatesForEndpoint(ep, attacks, nil)
	assert.Empty(t, result)
}

func TestSelectTemplates_TagMatch(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/users"}
	attacks := []AttackSelection{{Category: "sqli"}, {Category: "xss"}}
	templates := []*nuclei.Template{
		{ID: "sqli-error", Info: nuclei.Info{Tags: "sqli,owasp"}},
		{ID: "cors-check", Info: nuclei.Info{Tags: "cors,misconfig"}},
	}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	require.Len(t, result, 1)
	assert.Equal(t, "sqli-error", result[0].Template.ID)
	assert.Contains(t, result[0].Reason, "tag match")
}

func TestSelectTemplates_PathMatch(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/admin/users"}
	attacks := []AttackSelection{{Category: "sqli"}}
	templates := []*nuclei.Template{
		{
			ID:   "admin-panel",
			Info: nuclei.Info{Tags: "admin"},
			HTTP: []nuclei.HTTPRequest{
				{Path: []string{"{{BaseURL}}/admin"}},
			},
		},
	}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	require.Len(t, result, 1)
	assert.Contains(t, result[0].Reason, "path match")
}

func TestSelectTemplates_MethodMatch(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "POST", Path: "/api/data"}
	attacks := []AttackSelection{{Category: "nosqli"}}
	templates := []*nuclei.Template{
		{
			ID:   "post-inject",
			Info: nuclei.Info{Tags: "nosqli"},
			HTTP: []nuclei.HTTPRequest{
				{Method: "POST"},
			},
		},
	}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	require.Len(t, result, 1)
	assert.Contains(t, result[0].Reason, "tag match")
	assert.Contains(t, result[0].Reason, "method match")
}

func TestSelectTemplates_MethodMatchFromRaw(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "PUT", Path: "/api/items"}
	attacks := []AttackSelection{{Category: "sqli"}}
	templates := []*nuclei.Template{
		{
			ID:   "raw-put",
			Info: nuclei.Info{Tags: "sqli"},
			HTTP: []nuclei.HTTPRequest{
				{Raw: []string{"PUT /api/items HTTP/1.1\nHost: {{Hostname}}"}},
			},
		},
	}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	require.Len(t, result, 1)
	assert.Contains(t, result[0].Reason, "method match")
}

func TestSelectTemplates_NoDuplicateIDs(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/admin"}
	attacks := []AttackSelection{{Category: "sqli"}}
	templates := []*nuclei.Template{
		{ID: "sqli-1", Info: nuclei.Info{Tags: "sqli"}},
		{ID: "sqli-1", Info: nuclei.Info{Tags: "sqli"}}, // duplicate
	}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	assert.Len(t, result, 1)
}

func TestSelectTemplates_NilTemplate(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/users"}
	attacks := []AttackSelection{{Category: "sqli"}}
	templates := []*nuclei.Template{nil, {ID: "sqli-1", Info: nuclei.Info{Tags: "sqli"}}}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	assert.Len(t, result, 1)
}

func TestSelectTemplates_NoMatch(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/users"}
	attacks := []AttackSelection{{Category: "sqli"}}
	templates := []*nuclei.Template{
		{ID: "cors-check", Info: nuclei.Info{Tags: "cors"}},
	}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	assert.Empty(t, result)
}

func TestSelectTemplates_CaseInsensitiveTags(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "GET", Path: "/api"}
	attacks := []AttackSelection{{Category: "SQLI"}}
	templates := []*nuclei.Template{
		{ID: "sqli-1", Info: nuclei.Info{Tags: "SQLi,OWASP"}},
	}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	assert.Len(t, result, 1)
}

func TestSelectTemplates_CombinedReasons(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Method: "POST", Path: "/admin/login"}
	attacks := []AttackSelection{{Category: "brokenauth"}}
	templates := []*nuclei.Template{
		{
			ID:   "auth-bypass",
			Info: nuclei.Info{Tags: "brokenauth"},
			HTTP: []nuclei.HTTPRequest{
				{Method: "POST", Path: []string{"{{BaseURL}}/admin/login"}},
			},
		},
	}

	result := SelectTemplatesForEndpoint(ep, attacks, templates)
	require.Len(t, result, 1)
	assert.Contains(t, result[0].Reason, "tag match")
	assert.Contains(t, result[0].Reason, "path match")
	assert.Contains(t, result[0].Reason, "method match")
}

func TestExtractTemplatePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"{{BaseURL}}/admin", "/admin"},
		{"{{BaseURL}}/api/v1/users?id=1", "/api/v1/users"},
		{"{{RootURL}}/login", "/login"},
		{"{{BaseURL}}", ""},
		{"{{BaseURL}}/", ""},
		{"/plain/path", "/plain/path"},
	}
	for _, tt := range tests {
		got := extractTemplatePath(tt.input)
		assert.Equal(t, tt.want, got, "extractTemplatePath(%q)", tt.input)
	}
}

func TestMatchTags(t *testing.T) {
	t.Parallel()
	tmpl := &nuclei.Template{Info: nuclei.Info{Tags: "sqli, xss, owasp"}}
	assert.True(t, matchTags(tmpl, map[string]bool{"sqli": true}))
	assert.True(t, matchTags(tmpl, map[string]bool{"xss": true}))
	assert.False(t, matchTags(tmpl, map[string]bool{"csrf": true}))
	assert.False(t, matchTags(tmpl, map[string]bool{}))
}

func TestMatchMethod_Empty(t *testing.T) {
	t.Parallel()
	tmpl := &nuclei.Template{}
	assert.False(t, matchMethod(tmpl, "GET"))
}
