package headless

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/regexcache"
)

// XHRExtractor captures and analyzes XHR/fetch requests from page navigation
// Based on katana's XHR extraction capabilities
type XHRExtractor struct {
	capturedRequests []NetworkRequest
	capturedWSInfo   []WebSocketInfo
	mu               sync.RWMutex

	// Filtering options
	ignoreStatic   bool     // ignore requests for static assets
	ignoreExts     []string // file extensions to ignore
	captureHeaders bool     // capture request headers
	captureBody    bool     // capture request body
}

// XHRConfig configures XHR extraction behavior
type XHRConfig struct {
	IgnoreStatic   bool
	IgnoreExts     []string
	CaptureHeaders bool
	CaptureBody    bool
}

// DefaultXHRConfig returns default XHR extraction configuration
func DefaultXHRConfig() *XHRConfig {
	return &XHRConfig{
		IgnoreStatic: true,
		IgnoreExts: []string{
			".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
			".css", ".woff", ".woff2", ".ttf", ".eot",
			".mp3", ".mp4", ".webm", ".ogg",
		},
		CaptureHeaders: true,
		CaptureBody:    true,
	}
}

// NewXHRExtractor creates a new XHR extractor
func NewXHRExtractor(config *XHRConfig) *XHRExtractor {
	if config == nil {
		config = DefaultXHRConfig()
	}
	return &XHRExtractor{
		capturedRequests: make([]NetworkRequest, 0),
		capturedWSInfo:   make([]WebSocketInfo, 0),
		ignoreStatic:     config.IgnoreStatic,
		ignoreExts:       config.IgnoreExts,
		captureHeaders:   config.CaptureHeaders,
		captureBody:      config.CaptureBody,
	}
}

// AddRequest records a captured network request
func (x *XHRExtractor) AddRequest(req NetworkRequest) {
	if x.shouldIgnore(req.URL) {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.capturedRequests = append(x.capturedRequests, req)
}

// AddWebSocket records a captured WebSocket connection
func (x *XHRExtractor) AddWebSocket(ws WebSocketInfo) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.capturedWSInfo = append(x.capturedWSInfo, ws)
}

// GetRequests returns all captured requests
func (x *XHRExtractor) GetRequests() []NetworkRequest {
	x.mu.RLock()
	defer x.mu.RUnlock()
	result := make([]NetworkRequest, len(x.capturedRequests))
	copy(result, x.capturedRequests)
	return result
}

// GetWebSockets returns all captured WebSocket connections
func (x *XHRExtractor) GetWebSockets() []WebSocketInfo {
	x.mu.RLock()
	defer x.mu.RUnlock()
	result := make([]WebSocketInfo, len(x.capturedWSInfo))
	copy(result, x.capturedWSInfo)
	return result
}

// GetAPIEndpoints extracts potential API endpoints from captured requests
func (x *XHRExtractor) GetAPIEndpoints() []APIEndpoint {
	x.mu.RLock()
	defer x.mu.RUnlock()

	endpoints := make(map[string]APIEndpoint)

	for _, req := range x.capturedRequests {
		parsed, err := url.Parse(req.URL)
		if err != nil {
			continue
		}

		// Normalize path (remove query params for grouping)
		path := parsed.Path

		// Check if this looks like an API endpoint
		if !looksLikeAPI(path) {
			continue
		}

		key := req.Method + " " + path
		if existing, ok := endpoints[key]; ok {
			existing.SeenCount++
			endpoints[key] = existing
		} else {
			endpoints[key] = APIEndpoint{
				Path:        path,
				Method:      req.Method,
				ContentType: req.ContentType,
				HasBody:     req.PostData != "",
				SeenCount:   1,
			}
		}
	}

	// Sort keys for deterministic output order
	keys := make([]string, 0, len(endpoints))
	for k := range endpoints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := make([]APIEndpoint, 0, len(endpoints))
	for _, k := range keys {
		result = append(result, endpoints[k])
	}
	return result
}

// APIEndpoint represents a discovered API endpoint
type APIEndpoint struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	ContentType string            `json:"content_type,omitempty"`
	HasBody     bool              `json:"has_body"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	SeenCount   int               `json:"seen_count"`
}

// looksLikeAPI checks if a path looks like an API endpoint
func looksLikeAPI(path string) bool {
	lower := strings.ToLower(path)

	// Positive indicators
	apiPatterns := []string{
		"/api/", "/api.", "/v1/", "/v2/", "/v3/",
		"/rest/", "/graphql", "/gql",
		"/json", "/xml", "/data/",
		"/ajax/", "/async/", "/xhr/",
	}
	for _, pattern := range apiPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Content-based extension check (APIs don't usually have these)
	staticExts := []string{".html", ".htm", ".css", ".js", ".png", ".jpg", ".gif", ".svg"}
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}

	// Check for JSON-like paths
	if strings.HasSuffix(lower, ".json") {
		return true
	}

	return false
}

// shouldIgnore checks if a URL should be ignored
func (x *XHRExtractor) shouldIgnore(urlStr string) bool {
	if !x.ignoreStatic {
		return false
	}

	lower := strings.ToLower(urlStr)
	for _, ext := range x.ignoreExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// Reset clears all captured data
func (x *XHRExtractor) Reset() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.capturedRequests = make([]NetworkRequest, 0)
	x.capturedWSInfo = make([]WebSocketInfo, 0)
}

// ExtractURLsFromJS extracts URLs from JavaScript code
// This is a simplified version - for full extraction, use JSLuice-style parsing
func ExtractURLsFromJS(jsCode string, baseURL string) []string {
	var urls []string
	seen := make(map[string]bool)

	base, err := url.Parse(baseURL)
	if err != nil {
		return urls
	}

	// Pattern: fetch('url') or fetch("url")
	fetchPattern := regexcache.MustGet(`fetch\s*\(\s*['"]([^'"]+)['"]`)
	matches := fetchPattern.FindAllStringSubmatch(jsCode, -1)
	for _, m := range matches {
		if len(m) > 1 {
			if resolved := resolveURL(m[1], base); resolved != "" && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	// Pattern: XMLHttpRequest.open('method', 'url')
	xhrPattern := regexcache.MustGet(`\.open\s*\(\s*['"][^'"]+['"]\s*,\s*['"]([^'"]+)['"]`)
	matches = xhrPattern.FindAllStringSubmatch(jsCode, -1)
	for _, m := range matches {
		if len(m) > 1 {
			if resolved := resolveURL(m[1], base); resolved != "" && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	// Pattern: axios.get|post|put|delete('url')
	axiosPattern := regexcache.MustGet(`axios\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`)
	matches = axiosPattern.FindAllStringSubmatch(jsCode, -1)
	for _, m := range matches {
		if len(m) > 2 {
			if resolved := resolveURL(m[2], base); resolved != "" && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	// Pattern: $.ajax({ url: 'url' }) or $.get/post('url')
	jqueryPattern := regexcache.MustGet(`\$\.(ajax|get|post)\s*\(\s*(?:\{[^}]*url\s*:\s*)?['"]([^'"]+)['"]`)
	matches = jqueryPattern.FindAllStringSubmatch(jsCode, -1)
	for _, m := range matches {
		if len(m) > 2 {
			if resolved := resolveURL(m[2], base); resolved != "" && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	// Pattern: url: "..." or "url": "..."
	urlPropertyPattern := regexcache.MustGet(`["']?url["']?\s*[:=]\s*['"]([^'"]+)['"]`)
	matches = urlPropertyPattern.FindAllStringSubmatch(jsCode, -1)
	for _, m := range matches {
		if len(m) > 1 {
			if resolved := resolveURL(m[1], base); resolved != "" && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	// Pattern: /api/... paths
	apiPathPattern := regexcache.MustGet(`['"](/(?:api|v[0-9]+)/[^'"]+)['"]`)
	matches = apiPathPattern.FindAllStringSubmatch(jsCode, -1)
	for _, m := range matches {
		if len(m) > 1 {
			if resolved := resolveURL(m[1], base); resolved != "" && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	return urls
}

// SimulateXHRRequest creates a mock network request for testing
func SimulateXHRRequest(method, urlStr string, headers map[string]string, body string) NetworkRequest {
	return NetworkRequest{
		URL:       urlStr,
		Method:    method,
		Headers:   headers,
		PostData:  body,
		Timestamp: time.Now(),
	}
}

// ToJSON exports captured requests as JSON
func (x *XHRExtractor) ToJSON() (string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	data := struct {
		Requests   []NetworkRequest `json:"requests"`
		WebSockets []WebSocketInfo  `json:"websockets"`
	}{
		Requests:   x.capturedRequests,
		WebSockets: x.capturedWSInfo,
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	return string(bytes), err
}
