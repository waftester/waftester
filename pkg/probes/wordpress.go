package probes

import (
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

// WordPressResult holds WordPress detection results including discovered plugins and themes.
type WordPressResult struct {
	Detected bool     `json:"detected"`
	Plugins  []string `json:"plugins,omitempty"`
	Themes   []string `json:"themes,omitempty"`
}

// DetectWordPress checks an HTTP response body for WordPress indicators
// and extracts discovered plugins and themes via path patterns.
func DetectWordPress(body string) WordPressResult {
	wpIndicators := []string{
		"/wp-content/",
		"/wp-includes/",
		"/wp-admin/",
		"wp-json",
		"wordpress",
		`<meta name="generator" content="WordPress`,
	}
	bodyLower := strings.ToLower(body)
	detected := false
	for _, ind := range wpIndicators {
		if strings.Contains(bodyLower, strings.ToLower(ind)) {
			detected = true
			break
		}
	}
	if !detected {
		return WordPressResult{}
	}

	// Extract plugins
	pluginRe := regexcache.MustGet(`/wp-content/plugins/([^/'"]+)`)
	pluginMatches := pluginRe.FindAllStringSubmatch(body, 50)
	pluginSet := make(map[string]bool)
	for _, m := range pluginMatches {
		if len(m) > 1 {
			pluginSet[m[1]] = true
		}
	}
	plugins := make([]string, 0, len(pluginSet))
	for p := range pluginSet {
		plugins = append(plugins, p)
	}

	// Extract themes
	themeRe := regexcache.MustGet(`/wp-content/themes/([^/'"]+)`)
	themeMatches := themeRe.FindAllStringSubmatch(body, 50)
	themeSet := make(map[string]bool)
	for _, m := range themeMatches {
		if len(m) > 1 {
			themeSet[m[1]] = true
		}
	}
	themes := make([]string, 0, len(themeSet))
	for t := range themeSet {
		themes = append(themes, t)
	}

	return WordPressResult{
		Detected: detected,
		Plugins:  plugins,
		Themes:   themes,
	}
}
