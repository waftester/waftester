package placeholders

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLParamPlaceholder(t *testing.T) {
	p := Get("url-param")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/path", "' OR 1=1--", nil)
	require.NoError(t, err)
	assert.Contains(t, req.URL.String(), "param=%27+OR+1%3D1--")
}

func TestURLParamWithCustomName(t *testing.T) {
	p := Get("url-param")
	require.NotNil(t, p)

	config := &PlaceholderConfig{ParamName: "id"}
	req, err := p.Apply(context.Background(), "https://example.com/", "test", config)
	require.NoError(t, err)
	assert.Contains(t, req.URL.String(), "id=test")
}

func TestURLPathPlaceholder(t *testing.T) {
	p := Get("url-path")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "<script>", nil)
	require.NoError(t, err)
	assert.Contains(t, req.URL.Path, "<script>")
}

func TestURLFragmentPlaceholder(t *testing.T) {
	p := Get("url-fragment")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "payload", nil)
	require.NoError(t, err)
	assert.Equal(t, "payload", req.URL.Fragment)
}

func TestHeaderPlaceholder(t *testing.T) {
	p := Get("header")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "payload", nil)
	require.NoError(t, err)
	assert.Equal(t, "payload", req.Header.Get("X-Test-Payload"))
}

func TestHeaderWithCustomName(t *testing.T) {
	p := Get("header")
	require.NotNil(t, p)

	config := &PlaceholderConfig{HeaderName: "X-Custom"}
	req, err := p.Apply(context.Background(), "https://example.com/", "payload", config)
	require.NoError(t, err)
	assert.Equal(t, "payload", req.Header.Get("X-Custom"))
}

func TestUserAgentPlaceholder(t *testing.T) {
	p := Get("user-agent")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "evil-agent", nil)
	require.NoError(t, err)
	assert.Equal(t, "evil-agent", req.Header.Get("User-Agent"))
}

func TestRefererPlaceholder(t *testing.T) {
	p := Get("referer")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "http://evil.com", nil)
	require.NoError(t, err)
	assert.Equal(t, "http://evil.com", req.Header.Get("Referer"))
}

func TestCookiePlaceholder(t *testing.T) {
	p := Get("cookie")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "payload", nil)
	require.NoError(t, err)
	assert.Contains(t, req.Header.Get("Cookie"), "test=payload")
}

func TestCookieWithCustomName(t *testing.T) {
	p := Get("cookie")
	require.NotNil(t, p)

	config := &PlaceholderConfig{CookieName: "session"}
	req, err := p.Apply(context.Background(), "https://example.com/", "payload", config)
	require.NoError(t, err)
	assert.Contains(t, req.Header.Get("Cookie"), "session=payload")
}

func TestBodyJSONPlaceholder(t *testing.T) {
	p := Get("body-json")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "' OR 1=1", nil)
	require.NoError(t, err)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))

	body, _ := io.ReadAll(req.Body)
	assert.Contains(t, string(body), "' OR 1=1")
}

func TestBodyFormPlaceholder(t *testing.T) {
	p := Get("body-form")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "payload", nil)
	require.NoError(t, err)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

	body, _ := io.ReadAll(req.Body)
	assert.Contains(t, string(body), "data=payload")
}

func TestBodyXMLPlaceholder(t *testing.T) {
	p := Get("body-xml")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "<script>alert(1)</script>", nil)
	require.NoError(t, err)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "application/xml", req.Header.Get("Content-Type"))

	body, _ := io.ReadAll(req.Body)
	assert.Contains(t, string(body), "<script>alert(1)</script>")
}

func TestBodyMultipartPlaceholder(t *testing.T) {
	p := Get("body-multipart")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "payload", nil)
	require.NoError(t, err)
	assert.Equal(t, "POST", req.Method)
	assert.Contains(t, req.Header.Get("Content-Type"), "multipart/form-data")

	body, _ := io.ReadAll(req.Body)
	assert.Contains(t, string(body), "payload")
}

func TestBodyRawPlaceholder(t *testing.T) {
	p := Get("body-raw")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "<script>", nil)
	require.NoError(t, err)
	assert.Equal(t, "POST", req.Method)

	body, _ := io.ReadAll(req.Body)
	assert.Equal(t, "<script>", string(body))
}

func TestBodyRawWithCustomContentType(t *testing.T) {
	p := Get("body-raw")
	require.NotNil(t, p)

	config := &PlaceholderConfig{ContentType: "application/javascript"}
	req, err := p.Apply(context.Background(), "https://example.com/", "payload", config)
	require.NoError(t, err)
	assert.Equal(t, "application/javascript", req.Header.Get("Content-Type"))
}

func TestHostHeaderPlaceholder(t *testing.T) {
	p := Get("host-header")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "evil.com", nil)
	require.NoError(t, err)
	assert.Equal(t, "evil.com", req.Host)
}

func TestXForwardedForPlaceholder(t *testing.T) {
	p := Get("x-forwarded-for")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "127.0.0.1, evil.com", nil)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1, evil.com", req.Header.Get("X-Forwarded-For"))
}

func TestContentTypePlaceholder(t *testing.T) {
	p := Get("content-type")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "text/html; charset=utf-7", nil)
	require.NoError(t, err)
	assert.Equal(t, "text/html; charset=utf-7", req.Header.Get("Content-Type"))
}

func TestAcceptPlaceholder(t *testing.T) {
	p := Get("accept")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "*/*; q=evil", nil)
	require.NoError(t, err)
	assert.Equal(t, "*/*; q=evil", req.Header.Get("Accept"))
}

func TestAuthorizationPlaceholder(t *testing.T) {
	p := Get("authorization")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/", "Bearer ' OR 1=1--", nil)
	require.NoError(t, err)
	assert.Equal(t, "Bearer ' OR 1=1--", req.Header.Get("Authorization"))
}

func TestListPlaceholders(t *testing.T) {
	list := List()
	assert.GreaterOrEqual(t, len(list), 15)
	assert.Contains(t, list, "url-param")
	assert.Contains(t, list, "header")
	assert.Contains(t, list, "body-json")
	assert.Contains(t, list, "cookie")
	assert.Contains(t, list, "user-agent")
}

func TestAllPlaceholders(t *testing.T) {
	all := All()
	assert.GreaterOrEqual(t, len(all), 15)
}

func TestApplyAll(t *testing.T) {
	requests, err := ApplyAll(context.Background(), "https://example.com/", "test", nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(requests), 15)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.Equal(t, "param", config.ParamName)
	assert.Equal(t, "X-Test-Payload", config.HeaderName)
	assert.Equal(t, "test", config.CookieName)
	assert.Equal(t, "data", config.FieldName)
}

func TestMergeConfig(t *testing.T) {
	custom := &PlaceholderConfig{ParamName: "custom"}
	merged := MergeConfig(custom)
	assert.Equal(t, "custom", merged.ParamName)
	assert.Equal(t, "X-Test-Payload", merged.HeaderName) // Default value preserved
}

func TestMergeConfigNil(t *testing.T) {
	merged := MergeConfig(nil)
	assert.Equal(t, "param", merged.ParamName)
}

func TestGetNonexistent(t *testing.T) {
	p := Get("nonexistent")
	assert.Nil(t, p)
}

func TestPlaceholderDescriptions(t *testing.T) {
	for _, p := range All() {
		assert.NotEmpty(t, p.Name())
		assert.NotEmpty(t, p.Description())
	}
}

func TestURLPathWithExistingPath(t *testing.T) {
	p := Get("url-path")
	require.NotNil(t, p)

	req, err := p.Apply(context.Background(), "https://example.com/api/v1", "payload", nil)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(req.URL.Path, "payload"))
}
