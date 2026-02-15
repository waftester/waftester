package headless

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClickablesJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    int
		wantErr bool
	}{
		{
			name: "multiple elements",
			json: `[
				{"selector":"#login","tag":"button","text":"Login","type":"button","href":"","onclick":""},
				{"selector":"a","tag":"a","text":"Home","type":"link","href":"/home","onclick":""},
				{"selector":"div.menu","tag":"div","text":"Menu","type":"cursor-pointer","href":"","onclick":""}
			]`,
			want: 3,
		},
		{
			name: "empty array",
			json: `[]`,
			want: 0,
		},
		{
			name: "single framework binding",
			json: `[{"selector":"[ng-click]","tag":"span","text":"Click me","type":"framework-binding","href":"","onclick":""}]`,
			want: 1,
		},
		{
			name:    "invalid JSON",
			json:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elements, err := ParseClickablesJSON(tt.json)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, elements, tt.want)
		})
	}
}

func TestParseClickablesJSON_Fields(t *testing.T) {
	json := `[{"selector":"#submit-btn","tag":"button","text":"Submit Form","type":"button","href":"","onclick":"submitForm()"}]`
	elements, err := ParseClickablesJSON(json)
	require.NoError(t, err)
	require.Len(t, elements, 1)

	el := elements[0]
	assert.Equal(t, "#submit-btn", el.Selector)
	assert.Equal(t, "button", el.Tag)
	assert.Equal(t, "Submit Form", el.Text)
	assert.Equal(t, "button", el.Type)
	assert.Equal(t, "submitForm()", el.OnClick)
}

func TestParseClickablesJSON_AllTypes(t *testing.T) {
	// Verify all 6 element types parse correctly
	json := `[
		{"selector":"a.nav","tag":"a","text":"Nav","type":"link","href":"/nav","onclick":""},
		{"selector":"#btn","tag":"button","text":"Go","type":"button","href":"","onclick":""},
		{"selector":"div.click","tag":"div","text":"Click","type":"onclick","href":"","onclick":"doStuff()"},
		{"selector":"span.role","tag":"span","text":"Tab","type":"role-button","href":"","onclick":""},
		{"selector":"[ng-click]","tag":"div","text":"Angular","type":"framework-binding","href":"","onclick":""},
		{"selector":"li.ptr","tag":"li","text":"Item","type":"cursor-pointer","href":"","onclick":""}
	]`

	elements, err := ParseClickablesJSON(json)
	require.NoError(t, err)
	require.Len(t, elements, 6)

	expectedTypes := []string{"link", "button", "onclick", "role-button", "framework-binding", "cursor-pointer"}
	for i, el := range elements {
		assert.Equal(t, expectedTypes[i], el.Type, "element %d type mismatch", i)
	}
}

func TestCollectDiscoveredURLs(t *testing.T) {
	results := []EventCrawlResult{
		{
			DiscoveredURLs: []string{
				"https://example.com/api/users",
				"https://example.com/page2",
			},
		},
		{
			DiscoveredURLs: []string{
				"https://example.com/api/users", // duplicate
				"https://other.com/external",
				"https://example.com/page3",
			},
		},
		{
			DiscoveredURLs: []string{
				"data:text/html,<h1>test</h1>",
				"blob:https://example.com/uuid",
			},
		},
	}

	t.Run("same origin", func(t *testing.T) {
		urls := CollectDiscoveredURLs(results, "https://example.com", true)
		assert.Len(t, urls, 3) // api/users, page2, page3 — deduplicated, no external/data/blob
		assert.Contains(t, urls, "https://example.com/api/users")
		assert.Contains(t, urls, "https://example.com/page2")
		assert.Contains(t, urls, "https://example.com/page3")
		assert.NotContains(t, urls, "https://other.com/external")
	})

	t.Run("all origins", func(t *testing.T) {
		urls := CollectDiscoveredURLs(results, "https://example.com", false)
		assert.Len(t, urls, 4) // includes external but not data:/blob:
		assert.Contains(t, urls, "https://other.com/external")
	})

	t.Run("empty results", func(t *testing.T) {
		urls := CollectDiscoveredURLs(nil, "https://example.com", true)
		assert.Empty(t, urls)
	})

	t.Run("invalid base URL", func(t *testing.T) {
		urls := CollectDiscoveredURLs(results, "://invalid", true)
		assert.Nil(t, urls)
	})
}

func TestCollectDiscoveredURLs_XHROnly(t *testing.T) {
	results := []EventCrawlResult{
		{
			XHRRequests: []string{
				"https://example.com/api/v1/data",
				"https://example.com/api/v1/config",
			},
			DiscoveredURLs: []string{
				"https://example.com/api/v1/data",
				"https://example.com/api/v1/config",
			},
		},
	}

	urls := CollectDiscoveredURLs(results, "https://example.com", true)
	assert.Len(t, urls, 2)
}

func TestDefaultEventCrawlConfig(t *testing.T) {
	cfg := DefaultEventCrawlConfig()
	assert.Equal(t, 50, cfg.MaxClicks)
	assert.True(t, cfg.SkipExternal)
	assert.Equal(t, 5*time.Second, cfg.ClickTimeout)
	assert.Equal(t, 2*time.Second, cfg.WaitAfterClick)
}

func TestClickableElement_JSON(t *testing.T) {
	el := ClickableElement{
		Selector: "#login",
		Tag:      "button",
		Text:     "Login",
		Type:     "button",
	}
	assert.Equal(t, "#login", el.Selector)
	assert.Equal(t, "button", el.Tag)
	assert.Equal(t, "Login", el.Text)
	assert.Equal(t, "button", el.Type)
	assert.Empty(t, el.Href)
	assert.Empty(t, el.OnClick)
}

func TestEventCrawlResult_Structure(t *testing.T) {
	result := EventCrawlResult{
		Element: ClickableElement{
			Selector: "a.nav",
			Tag:      "a",
			Text:     "Dashboard",
			Type:     "link",
			Href:     "/dashboard",
		},
		DiscoveredURLs: []string{"https://example.com/dashboard"},
		XHRRequests:    []string{"https://example.com/api/dashboard/stats"},
		NavigatedTo:    "https://example.com/dashboard",
		DOMChanged:     true,
	}

	assert.Equal(t, "a.nav", result.Element.Selector)
	assert.Len(t, result.DiscoveredURLs, 1)
	assert.Len(t, result.XHRRequests, 1)
	assert.True(t, result.DOMChanged)
	assert.Equal(t, "https://example.com/dashboard", result.NavigatedTo)
}

func TestDiscoverClickablesJS_Defined(t *testing.T) {
	// Verify the JS constant is non-empty and contains expected patterns
	assert.NotEmpty(t, discoverClickablesJS)
	assert.Contains(t, discoverClickablesJS, "querySelectorAll")
	assert.Contains(t, discoverClickablesJS, "cursor-pointer")
	assert.Contains(t, discoverClickablesJS, "framework-binding")
	assert.Contains(t, discoverClickablesJS, "role-button")
	assert.Contains(t, discoverClickablesJS, "ng-click")
	assert.Contains(t, discoverClickablesJS, "v-on")
	assert.Contains(t, discoverClickablesJS, "data-action")
	assert.Contains(t, discoverClickablesJS, "getBoundingClientRect")
}
