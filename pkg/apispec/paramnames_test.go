package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchParamNameURL(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("redirect_url")
	assert.Contains(t, cats, "ssrf")
	assert.Contains(t, cats, "redirect")
	assert.Contains(t, cats, "requestforgery")
}

func TestMatchParamNameFile(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("filename")
	assert.Contains(t, cats, "traversal")
	assert.Contains(t, cats, "lfi")
}

func TestMatchParamNameQuery(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("search")
	assert.Contains(t, cats, "sqli")
	assert.Contains(t, cats, "xss")
}

func TestMatchParamNameID(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("user_id")
	assert.Contains(t, cats, "idor")
	assert.Contains(t, cats, "accesscontrol")
}

func TestMatchParamNameCamelCase(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("redirectUrl")
	assert.Contains(t, cats, "ssrf")
	assert.Contains(t, cats, "redirect")
}

func TestMatchParamNameKebabCase(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("redirect-url")
	assert.Contains(t, cats, "ssrf")
	assert.Contains(t, cats, "redirect")
}

func TestMatchParamNameNoMatch(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("foobar")
	assert.Empty(t, cats)
}

func TestMatchParamNameAuth(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("access_token")
	assert.Contains(t, cats, "brokenauth")
	assert.Contains(t, cats, "jwt")
}

func TestMatchParamNameXML(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("xml_data")
	assert.Contains(t, cats, "xxe")
	assert.Contains(t, cats, "xmlinjection")
}

func TestMatchParamNameTemplate(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("template")
	assert.Contains(t, cats, "ssti")
}

func TestMatchParamNameLDAP(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("base_dn")
	assert.Contains(t, cats, "ldap")
}

func TestMatchParamNameCallback(t *testing.T) {
	t.Parallel()
	cats := MatchParamName("webhook_url")
	assert.Contains(t, cats, "ssrf")
	assert.Contains(t, cats, "requestforgery")
}

func TestMatchParamNameNoDuplicates(t *testing.T) {
	t.Parallel()
	// "url" matches URL rule. Should not have duplicate categories.
	cats := MatchParamName("url")
	seen := make(map[string]bool)
	for _, c := range cats {
		assert.False(t, seen[c], "duplicate category: %s", c)
		seen[c] = true
	}
}

func TestNormalizeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input, want string
	}{
		{"redirectUrl", "redirect_url"},
		{"user-id", "user_id"},
		{"simple", "simple"},
		{"XMLData", "x_m_l_data"},
		{"userId", "user_id"},
		{"a", "a"},
		{"", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, normalizeName(tt.input), "input: %s", tt.input)
	}
}
