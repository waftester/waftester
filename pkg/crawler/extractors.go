package crawler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/waftester/waftester/pkg/js"
)

// APIEndpointInfo represents a discovered API endpoint with method and source.
type APIEndpointInfo struct {
	Path   string `json:"path"`
	Method string `json:"method,omitempty"`
	Source string `json:"source,omitempty"`
}

// SecretFinding represents a potential secret or token found during crawling.
type SecretFinding struct {
	Type    string `json:"type"`              // e.g. "aws_key", "github_token"
	Match   string `json:"match"`             // the matched string (redacted middle)
	Context string `json:"context,omitempty"` // surrounding text
	Source  string `json:"source,omitempty"`  // where it was found
}

// extractFromResponseHeaders extracts URLs from HTTP response headers.
// Mines Link, Content-Security-Policy, Location, Content-Location,
// Set-Cookie, and Refresh headers that reveal application structure.
func extractFromResponseHeaders(headers http.Header, base *url.URL) ([]string, []APIEndpointInfo) {
	var links []string
	var endpoints []APIEndpointInfo

	// Link header (RFC 8288): Link: </api/v2>; rel="next"
	for _, link := range headers.Values("Link") {
		for _, part := range strings.Split(link, ",") {
			part = strings.TrimSpace(part)
			if start := strings.Index(part, "<"); start >= 0 {
				if end := strings.Index(part[start:], ">"); end > 0 {
					u := part[start+1 : start+end]
					if resolved := resolveURL(u, base); resolved != "" {
						links = append(links, resolved)
						endpoints = append(endpoints, APIEndpointInfo{Path: u, Source: "link-header"})
					}
				}
			}
		}
	}

	// Location and Content-Location headers
	for _, hdr := range []string{"Location", "Content-Location"} {
		if v := headers.Get(hdr); v != "" {
			if resolved := resolveURL(v, base); resolved != "" {
				links = append(links, resolved)
			}
		}
	}

	// Refresh header: Refresh: 5; url=https://example.com
	if refresh := headers.Get("Refresh"); refresh != "" {
		if u := parseRefreshURL(refresh); u != "" {
			if resolved := resolveURL(u, base); resolved != "" {
				links = append(links, resolved)
			}
		}
	}

	// Content-Security-Policy: extract domain sources
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		links = append(links, extractURLsFromCSP(csp)...)
	}

	// Set-Cookie: extract domain and path attributes
	for _, cookie := range headers.Values("Set-Cookie") {
		for _, attr := range strings.Split(cookie, ";") {
			attr = strings.TrimSpace(attr)
			lower := strings.ToLower(attr)
			if strings.HasPrefix(lower, "path=") {
				p := strings.TrimPrefix(attr[5:], "")
				if p != "/" && p != "" {
					if resolved := resolveURL(p, base); resolved != "" {
						links = append(links, resolved)
					}
				}
			}
		}
	}

	return links, endpoints
}

// parseRefreshURL extracts the URL from a Refresh header value.
// Format: "5; url=https://example.com"
func parseRefreshURL(val string) string {
	lower := strings.ToLower(val)
	idx := strings.Index(lower, "url=")
	if idx < 0 {
		return ""
	}
	u := strings.TrimSpace(val[idx+4:])
	u = strings.Trim(u, "'\"")
	return u
}

// cspSourceRE matches http/https URLs in CSP directives.
var cspSourceRE = regexp.MustCompile(`https?://[^\s;,]+`)

// extractURLsFromCSP extracts URLs from a Content-Security-Policy header value.
func extractURLsFromCSP(csp string) []string {
	matches := cspSourceRE.FindAllString(csp, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	var result []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}
	return result
}

// extractFromJSONResponse extracts URLs and API paths from JSON response bodies.
func extractFromJSONResponse(body []byte, base *url.URL) ([]string, []APIEndpointInfo) {
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		// Try JSON array
		var arr []interface{}
		if err2 := json.Unmarshal(body, &arr); err2 != nil {
			return nil, nil
		}
		// Wrap array items
		obj = map[string]interface{}{"_items": arr}
	}

	seen := make(map[string]bool)
	var links []string
	var endpoints []APIEndpointInfo
	extractURLsFromJSON(obj, base, seen, &links, &endpoints, 0)
	return links, endpoints
}

// extractURLsFromJSON recursively walks JSON and extracts URLs and paths.
func extractURLsFromJSON(obj map[string]interface{}, base *url.URL, seen map[string]bool, links *[]string, endpoints *[]APIEndpointInfo, depth int) {
	if depth > 10 {
		return
	}
	for key, val := range obj {
		switch v := val.(type) {
		case string:
			if seen[v] {
				continue
			}
			if looksLikeURL(v) {
				seen[v] = true
				if resolved := resolveURL(v, base); resolved != "" {
					*links = append(*links, resolved)
				}
			} else if looksLikePath(v) {
				seen[v] = true
				if resolved := resolveURL(v, base); resolved != "" {
					*links = append(*links, resolved)
				}
				// Infer method from key name
				method := inferMethodFromKey(key)
				*endpoints = append(*endpoints, APIEndpointInfo{
					Path:   v,
					Method: method,
					Source: "json-response",
				})
			}
		case map[string]interface{}:
			extractURLsFromJSON(v, base, seen, links, endpoints, depth+1)
		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					extractURLsFromJSON(m, base, seen, links, endpoints, depth+1)
				} else if s, ok := item.(string); ok {
					if !seen[s] && (looksLikeURL(s) || looksLikePath(s)) {
						seen[s] = true
						if resolved := resolveURL(s, base); resolved != "" {
							*links = append(*links, resolved)
						}
					}
				}
			}
		}
	}
}

// looksLikeURL checks if a string looks like an absolute URL.
func looksLikeURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "//")
}

// looksLikeFilename returns true if s looks like a bare filename with a known extension
// (e.g., "config.json", "login.php"). Used to catch LinkFinder group-5 matches that
// are neither absolute URLs nor slash-prefixed paths.
func looksLikeFilename(s string) bool {
	dot := strings.LastIndexByte(s, '.')
	if dot < 1 || dot == len(s)-1 {
		return false
	}
	ext := strings.ToLower(s[dot+1:])
	switch ext {
	case "php", "asp", "aspx", "jsp", "json", "action", "html", "js", "txt", "xml",
		"css", "htm", "do", "cgi", "pl", "py", "rb", "cfm", "yaml", "yml", "toml",
		"config", "env", "ini", "conf", "properties", "sql", "graphql", "wsdl":
		return true
	}
	return false
}

// looksLikePath checks if a string looks like a URL path (e.g., /api/v1/users).
func looksLikePath(s string) bool {
	if len(s) < 2 || len(s) > 200 {
		return false
	}
	if s[0] != '/' {
		return false
	}
	// Must have at least one letter after the slash
	hasLetter := false
	for _, c := range s[1:] {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return false
	}
	// Reject binary/whitespace
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// inferMethodFromKey guesses HTTP method from a JSON key name.
func inferMethodFromKey(key string) string {
	lower := strings.ToLower(key)
	switch {
	case strings.Contains(lower, "delete"):
		return "DELETE"
	case strings.Contains(lower, "update") || strings.Contains(lower, "edit") || strings.Contains(lower, "put"):
		return "PUT"
	case strings.Contains(lower, "create") || strings.Contains(lower, "add") || strings.Contains(lower, "post"):
		return "POST"
	case strings.Contains(lower, "patch"):
		return "PATCH"
	default:
		return "GET"
	}
}

// extractFromJSFile analyzes a JavaScript file response for URLs and API endpoints.
func extractFromJSFile(body []byte, base *url.URL, analyzer *js.Analyzer) ([]string, []APIEndpointInfo) {
	if analyzer == nil || len(body) == 0 {
		return nil, nil
	}

	data := analyzer.Analyze(string(body))
	if data == nil {
		return nil, nil
	}

	var links []string
	var endpoints []APIEndpointInfo

	for _, u := range data.URLs {
		if resolved := resolveURL(u.URL, base); resolved != "" {
			links = append(links, resolved)
		}
	}

	for _, ep := range data.Endpoints {
		if resolved := resolveURL(ep.Path, base); resolved != "" {
			links = append(links, resolved)
		}
		endpoints = append(endpoints, APIEndpointInfo{
			Path:   ep.Path,
			Method: ep.Method,
			Source: "js-" + ep.Source,
		})
	}

	return links, endpoints
}

// extractInlineJSTokenizer parses HTML for inline <script> tags and analyzes
// their content for URLs and API endpoints.
func extractInlineJSTokenizer(htmlStr string, base *url.URL, analyzer *js.Analyzer) ([]string, []APIEndpointInfo) {
	if analyzer == nil {
		return nil, nil
	}

	var allLinks []string
	var allEndpoints []APIEndpointInfo

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	var inScript bool

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return allLinks, allEndpoints
		case html.StartTagToken:
			t := z.Token()
			if t.DataAtom.String() == "script" {
				// Skip external scripts (handled separately)
				hasSrc := false
				for _, a := range t.Attr {
					if a.Key == "src" && a.Val != "" {
						hasSrc = true
						break
					}
				}
				if !hasSrc {
					inScript = true
				}
			}
		case html.EndTagToken:
			t := z.Token()
			if t.DataAtom.String() == "script" {
				inScript = false
			}
		case html.TextToken:
			if inScript {
				text := z.Token().Data
				if len(strings.TrimSpace(text)) < 10 {
					continue
				}
				data := analyzer.Analyze(text)
				if data == nil {
					continue
				}
				for _, u := range data.URLs {
					if resolved := resolveURL(u.URL, base); resolved != "" {
						allLinks = append(allLinks, resolved)
					}
				}
				for _, ep := range data.Endpoints {
					if resolved := resolveURL(ep.Path, base); resolved != "" {
						allLinks = append(allLinks, resolved)
					}
					allEndpoints = append(allEndpoints, APIEndpointInfo{
						Path:   ep.Path,
						Method: ep.Method,
						Source: "inline-js-" + ep.Source,
					})
				}
			}
		}
	}
}

// mediaElements lists HTML elements whose src/data attributes should be extracted.
var mediaElements = map[string]string{
	"iframe": "src",
	"embed":  "src",
	"object": "data",
	"video":  "src",
	"audio":  "src",
	"source": "src",
}

// extractMediaElementsTokenizer extracts URLs from media/embed HTML elements.
func extractMediaElementsTokenizer(htmlStr string, base *url.URL) []string {
	var links []string
	z := html.NewTokenizer(strings.NewReader(htmlStr))

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return links
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		t := z.Token()
		attrName, ok := mediaElements[t.DataAtom.String()]
		if !ok {
			continue
		}
		val := getAttr(t, attrName)
		if val == "" {
			continue
		}
		if resolved := resolveURL(val, base); resolved != "" {
			links = append(links, resolved)
		}
	}
}

// cssURLRE matches url() references in inline CSS.
var cssURLRE = regexp.MustCompile(`url\s*\(\s*["']?([^"')]+)["']?\s*\)`)

// linkFinderRE is the famous LinkFinder regex from BurpSuite/Gospider.
// It catches URLs and paths embedded in JavaScript, JSON, minified code, and
// any other text content. This is the single highest-value URL extractor.
var linkFinderRE = regexp.MustCompile(`(?:"|')` +
	`(` +
	`(?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}` + // Full URLs
	`|` +
	`(?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,}` + // Relative paths
	`|` +
	`[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?|#][^"|']{0,}|)` + // File paths
	`|` +
	`[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[?|#][^"|']{0,}|)` + // Deep paths
	`|` +
	`[a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?|#][^"|']{0,}|)` + // Files with extensions
	`)` +
	`(?:"|')`)

// extractWithLinkFinder applies the LinkFinder regex to any text content,
// returning discovered URLs and paths. This catches things all HTML parsers miss,
// especially in minified JavaScript bundles.
func extractWithLinkFinder(content string, base *url.URL) ([]string, []APIEndpointInfo) {
	if len(content) == 0 {
		return nil, nil
	}

	// For very large files, break into lines to help the regex engine
	if len(content) > 1000000 {
		content = strings.ReplaceAll(content, ";", ";\n")
		content = strings.ReplaceAll(content, ",", ",\n")
	}

	matches := linkFinderRE.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool, len(matches))
	var links []string
	var endpoints []APIEndpointInfo

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		match := strings.TrimSpace(m[1])
		if match == "" || seen[match] {
			continue
		}
		seen[match] = true

		if looksLikeURL(match) {
			if resolved := resolveURL(match, base); resolved != "" {
				links = append(links, resolved)
			}
		} else if looksLikePath(match) || strings.HasPrefix(match, "./") || strings.HasPrefix(match, "../") || looksLikeFilename(match) {
			if resolved := resolveURL(match, base); resolved != "" {
				links = append(links, resolved)
			}
			endpoints = append(endpoints, APIEndpointInfo{
				Path:   match,
				Method: "GET",
				Source: "linkfinder",
			})
		}
	}

	return links, endpoints
}

// extractCSSURLsTokenizer extracts URLs from inline style attributes and
// <style> tag content in HTML.
func extractCSSURLsTokenizer(htmlStr string, base *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	z := html.NewTokenizer(strings.NewReader(htmlStr))
	var inStyle bool

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return links
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.DataAtom.String() == "style" {
				inStyle = true
			}
			// Check inline style attributes
			styleVal := getAttr(t, "style")
			if styleVal != "" {
				for _, m := range cssURLRE.FindAllStringSubmatch(styleVal, -1) {
					if resolved := resolveURL(m[1], base); resolved != "" && !seen[resolved] {
						seen[resolved] = true
						links = append(links, resolved)
					}
				}
			}
		case html.EndTagToken:
			t := z.Token()
			if t.DataAtom.String() == "style" {
				inStyle = false
			}
		case html.TextToken:
			if inStyle {
				text := z.Token().Data
				for _, m := range cssURLRE.FindAllStringSubmatch(text, -1) {
					if resolved := resolveURL(m[1], base); resolved != "" && !seen[resolved] {
						seen[resolved] = true
						links = append(links, resolved)
					}
				}
			}
		}
	}
}

// ---------- Email extraction ----------

var emailRE = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// extractEmails finds email addresses in text content.
func extractEmails(text string) []string {
	matches := emailRE.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	var result []string
	for _, m := range matches {
		lower := strings.ToLower(m)
		// Skip common false positives
		if strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") ||
			strings.HasSuffix(lower, ".gif") || strings.HasSuffix(lower, ".js") ||
			strings.HasSuffix(lower, ".css") {
			continue
		}
		if !seen[lower] {
			seen[lower] = true
			result = append(result, lower)
		}
	}
	return result
}

// ---------- Parameter extraction ----------

// extractParameters collects parameter names from URLs found in text.
func extractParameters(urls []string) []string {
	seen := make(map[string]bool)
	var params []string
	for _, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		for key := range parsed.Query() {
			if !seen[key] {
				seen[key] = true
				params = append(params, key)
			}
		}
	}
	return params
}

// ---------- Secret detection ----------

// secretPatterns maps secret type names to compiled regexes.
var secretPatterns = []struct {
	Name string
	RE   *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"aws_secret_key", regexp.MustCompile(`(?i)aws_?secret_?access_?key\s*[:=]\s*[A-Za-z0-9/+=]{40}`)},
	{"github_token", regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}`)},
	{"github_classic", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"slack_token", regexp.MustCompile(`xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`)},
	{"slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}`)},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"stripe_live", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"stripe_test", regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`)},
	{"heroku_api", regexp.MustCompile(`(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)},
	{"generic_api_key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api_secret|access_token)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?`)},
	{"generic_secret", regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]`)},
	{"mailgun_key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},
	{"twilio_sid", regexp.MustCompile(`AC[a-z0-9]{32}`)},
	{"sendgrid_key", regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`)},
}

// extractSecrets finds potential secrets/tokens in text content.
func extractSecrets(text, source string) []SecretFinding {
	var findings []SecretFinding
	seen := make(map[string]bool)
	for _, sp := range secretPatterns {
		for _, match := range sp.RE.FindAllString(text, 5) {
			if seen[match] {
				continue
			}
			seen[match] = true
			findings = append(findings, SecretFinding{
				Type:   sp.Name,
				Match:  redactMiddle(match),
				Source: source,
			})
		}
	}
	return findings
}

// redactMiddle keeps the first 4 and last 4 characters, replacing the middle with ***.
func redactMiddle(s string) string {
	if len(s) <= 12 {
		return s[:4] + "***"
	}
	return s[:4] + "***" + s[len(s)-4:]
}
