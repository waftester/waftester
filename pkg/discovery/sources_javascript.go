// Package discovery - JavaScript URL extraction and analysis
package discovery

import (
	"crypto/md5"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/regexcache"
)

// This is the famous LinkFinder regex pattern
var LinkFinderRegex = regexcache.MustGet(`(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`)

// FindLinksInJS extracts URLs and paths from JavaScript content
func FindLinksInJS(content string) []string {
	// Decode URL-encoded and unicode-escaped content
	content = decodeJSContent(content)
	return findLinksInJSDecoded(content)
}

// findLinksInJSDecoded extracts URLs from already-decoded JavaScript content.
// Use this when the caller has already called decodeJSContent to avoid double-decoding.
func findLinksInJSDecoded(content string) []string {
	var links []string
	seen := make(map[string]bool)

	// Handle very large files by adding newlines
	if len(content) > 1000000 {
		content = strings.ReplaceAll(content, ";", ";\n")
		content = strings.ReplaceAll(content, ",", ",\n")
	}

	// Standard LinkFinder regex
	matches := LinkFinderRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			link := strings.TrimSpace(match[1])
			link = filterNewlines(link)
			if link != "" && !seen[link] {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	// Additional API route patterns for modern SPAs
	apiPatterns := []*regexp.Regexp{
		// fetch("/api/...") or fetch('/api/...')
		regexcache.MustGet(`fetch\s*\(\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// axios.get("/api/..."), axios.post(...), etc.
		regexcache.MustGet(`axios\.\w+\s*\(\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// $.ajax({ url: "/api/..." }) or $.get("/api/...")
		regexcache.MustGet(`\$\.(?:ajax|get|post)\s*\(\s*(?:\{[^}]*url\s*:\s*)?["'\x60](/[^"'\x60]+)["'\x60]`),
		// apiEndpoint: "/api/v1/users" or API_URL = "/api"
		regexcache.MustGet(`(?:api|API|endpoint|ENDPOINT|url|URL|path|PATH|route|ROUTE)\s*[=:]\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// path("/api/v1/users") in router definitions
		regexcache.MustGet(`path\s*\(\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// Route definitions: <Route path="/users" or route: "/users"
		regexcache.MustGet(`[Rr]oute[^=]*(?:path|to)\s*[=:]\s*["'\x60](/[^"'\x60]+)["'\x60]`),
		// createAsyncThunk or API functions: "/api/users"
		regexcache.MustGet(`(?:createAsyncThunk|useMutation|useQuery)\s*\([^,]+,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{?[^}]*["'\x60](/api[^"'\x60]+)["'\x60]`),
		// Template strings with API paths: `${baseUrl}/api/users`
		regexcache.MustGet(`\x60\$\{[^}]+\}(/api[^$\x60]+)\x60`),
		// /v1/, /v2/, /v3/ versioned APIs
		regexcache.MustGet(`["'\x60](/v[1-3]/[^"'\x60]+)["'\x60]`),
		// REST patterns: /users/:id, /posts/{id}
		regexcache.MustGet(`["'\x60](/(?:api/)?(?:users|posts|items|products|orders|auth|login|register|admin|settings|profile|upload|files|documents|media|search|reports|analytics|notifications|messages|comments|reviews|categories|tags)[^"'\x60]*)["'\x60]`),
	}

	for _, pattern := range apiPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				link := strings.TrimSpace(match[1])
				link = filterNewlines(link)
				// Clean up template string artifacts
				link = strings.ReplaceAll(link, "${", "")
				link = strings.ReplaceAll(link, "}", "")
				if link != "" && !seen[link] && strings.HasPrefix(link, "/") {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	return links
}

// Pre-compiled replacer and regex for decodeJSContent and filterNewlines
var (
	jsUnicodeReplacer = strings.NewReplacer(
		`\u002f`, "/",
		`\u002F`, "/",
		`\u0026`, "&",
		`\u003d`, "=",
		`\u003D`, "=",
		`\u003f`, "?",
		`\u003F`, "?",
	)
	filterNewlinesRegex = regexcache.MustGet(`[\t\r\n]+`)
)

// jsURLsCache caches expensive JS URL extraction results
var jsURLsCache sync.Map // map[string][]JSURLMatch (hash -> matches)

// contentHash generates a fast hash for cache keys
func contentHash(content string) string {
	h := md5.Sum([]byte(content))
	return hex.EncodeToString(h[:])
}

func decodeJSContent(s string) string {
	// URL decode
	if decoded, err := url.QueryUnescape(s); err == nil {
		s = decoded
	}

	// Unicode escape sequences (using pre-compiled replacer)
	return jsUnicodeReplacer.Replace(s)
}

func filterNewlines(s string) string {
	return filterNewlinesRegex.ReplaceAllString(strings.TrimSpace(s), " ")
}

// ==================== ENHANCED JAVASCRIPT PARSING ====================
// From jsluice - smarter extraction of URLs from JavaScript

// JSURLMatch represents a URL found in JavaScript with context
type JSURLMatch struct {
	URL         string            `json:"url"`
	Method      string            `json:"method,omitempty"`
	Type        string            `json:"type"` // fetch, xhr, jquery, location, etc.
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams []string          `json:"query_params,omitempty"`
	BodyParams  []string          `json:"body_params,omitempty"`
}

// Enhanced JavaScript URL extraction patterns
var (
	// fetch() calls - fetch('/api/users', { method: 'POST' })
	fetchPattern = regexcache.MustGet(`fetch\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*\{([^}]+)\})?`)

	// XMLHttpRequest.open() - xhr.open('POST', '/api/data')
	xhrOpenPattern = regexcache.MustGet(`\.open\s*\(\s*['"]([A-Z]+)['"]\s*,\s*['"]([^'"]+)['"]`)

	// jQuery AJAX - $.ajax({ url: '/api', method: 'POST' })
	jqueryAjaxPattern = regexcache.MustGet(`\$\.ajax\s*\(\s*\{([^}]+)\}`)

	// jQuery shortcuts - $.get('/api'), $.post('/api')
	jqueryGetPattern  = regexcache.MustGet(`\$\.get\s*\(\s*['"]([^'"]+)['"]`)
	jqueryPostPattern = regexcache.MustGet(`\$\.post\s*\(\s*['"]([^'"]+)['"]`)

	// Location assignments - location.href = '/path'
	locationPattern = regexcache.MustGet(`(?:location\.href|window\.location|document\.location)\s*=\s*['"]([^'"]+)['"]`)

	// location.replace() - location.replace('/path')
	locationReplacePattern = regexcache.MustGet(`location\.replace\s*\(\s*['"]([^'"]+)['"]`)

	// window.open() - window.open('/popup')
	windowOpenPattern = regexcache.MustGet(`window\.open\s*\(\s*['"]([^'"]+)['"]`)

	// src/href assignments - element.src = '/image.png'
	srcHrefPattern = regexcache.MustGet(`\.(src|href)\s*=\s*['"]([^'"]+)['"]`)

	// API endpoint patterns - const API_URL = '/api/v1'
	apiConstPattern = regexcache.MustGet(`(?:API_URL|API_ENDPOINT|BASE_URL|apiUrl|apiEndpoint|baseUrl)\s*[=:]\s*['"]([^'"]+)['"]`)

	// Route definitions - '/users/:id'
	routePattern = regexcache.MustGet(`['"](/[a-zA-Z0-9_/-]+/:[a-zA-Z0-9_]+(?:/[a-zA-Z0-9_/-]*)*)['"]`)

	// Helper patterns for extracting method/url from options
	methodExtractPattern = regexcache.MustGet(`(?i)(?:method|type)\s*:\s*['"]([A-Z]+)['"]`)
	urlExtractPattern    = regexcache.MustGet(`(?i)url\s*:\s*['"]([^'"]+)['"]`)
)

// ExtractJSURLsEnhanced performs smart JavaScript URL extraction
func ExtractJSURLsEnhanced(content string) []JSURLMatch {
	// Check cache first
	hash := contentHash(content)
	if cached, ok := jsURLsCache.Load(hash); ok {
		return cached.([]JSURLMatch)
	}

	// Pre-allocate with estimated capacity
	matches := make([]JSURLMatch, 0, 64)
	seen := make(map[string]bool, 64)

	// Decode escaped content first
	content = decodeJSContent(content)

	// fetch() calls
	for _, match := range fetchPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "fetch:" + url
			if !seen[key] {
				seen[key] = true
				m := JSURLMatch{URL: url, Type: "fetch", Method: "GET"}
				if len(match) > 2 && match[2] != "" {
					m.Method = extractMethodFromOptions(match[2])
				}
				matches = append(matches, m)
			}
		}
	}

	// XHR.open()
	for _, match := range xhrOpenPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 2 {
			method := strings.ToUpper(match[1])
			url := match[2]
			key := "xhr:" + method + ":" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: method, Type: "xhr"})
			}
		}
	}

	// jQuery AJAX
	for _, match := range jqueryAjaxPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			options := match[1]
			url := extractURLFromOptions(options)
			if url != "" {
				key := "jquery:" + url
				if !seen[key] {
					seen[key] = true
					method := extractMethodFromOptions(options)
					if method == "" {
						method = "GET"
					}
					matches = append(matches, JSURLMatch{URL: url, Method: method, Type: "jquery.ajax"})
				}
			}
		}
	}

	// jQuery $.get
	for _, match := range jqueryGetPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "jget:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: "jquery.get"})
			}
		}
	}

	// jQuery $.post
	for _, match := range jqueryPostPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "jpost:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "POST", Type: "jquery.post"})
			}
		}
	}

	// location assignments
	for _, match := range locationPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "location:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: "location"})
			}
		}
	}

	// location.replace()
	for _, match := range locationReplacePattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "replace:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: "location.replace"})
			}
		}
	}

	// window.open()
	for _, match := range windowOpenPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "open:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: "window.open"})
			}
		}
	}

	// src/href assignments
	for _, match := range srcHrefPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 2 {
			url := match[2]
			key := "src:" + url
			if !seen[key] && isValidURLPath(url) {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Method: "GET", Type: match[1] + "_assignment"})
			}
		}
	}

	// API constants
	for _, match := range apiConstPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "api:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Type: "api_constant"})
			}
		}
	}

	// Route definitions
	for _, match := range routePattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			url := match[1]
			key := "route:" + url
			if !seen[key] {
				seen[key] = true
				matches = append(matches, JSURLMatch{URL: url, Type: "route"})
			}
		}
	}

	// Also run the original LinkFinder regex (content already decoded, skip re-decode)
	basicLinks := findLinksInJSDecoded(content)
	for _, link := range basicLinks {
		key := "link:" + link
		if !seen[key] {
			seen[key] = true
			matches = append(matches, JSURLMatch{URL: link, Type: "linkfinder"})
		}
	}

	// Cache the result
	jsURLsCache.Store(hash, matches)
	return matches
}

func extractMethodFromOptions(options string) string {
	if match := methodExtractPattern.FindStringSubmatch(options); len(match) > 1 {
		return strings.ToUpper(match[1])
	}
	return "GET"
}

func extractURLFromOptions(options string) string {
	if match := urlExtractPattern.FindStringSubmatch(options); len(match) > 1 {
		return match[1]
	}
	return ""
}

func isValidURLPath(s string) bool {
	// Filter out data: URLs, javascript:, etc.
	if strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "javascript:") ||
		strings.HasPrefix(s, "mailto:") || strings.HasPrefix(s, "tel:") {
		return false
	}
	// Should start with /, //, http, or be a relative path
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "http") ||
		(len(s) > 1 && !strings.ContainsAny(s[:1], " (){}[]<>"))
}
