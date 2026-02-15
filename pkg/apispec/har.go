package apispec

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// HAR v1.2 internal types for JSON unmarshalling.
// These are not exported — Parse() converts them to unified Spec types.

type harFile struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Entries []harEntry `json:"entries"`
}

type harEntry struct {
	Request  harRequest  `json:"request"`
	Response harResponse `json:"response,omitempty"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	Headers     []harNameValue `json:"headers,omitempty"`
	QueryString []harNameValue `json:"queryString,omitempty"`
	Cookies     []harNameValue `json:"cookies,omitempty"`
	PostData    *harPostData   `json:"postData,omitempty"`
}

type harResponse struct {
	Status     int            `json:"status"`
	StatusText string         `json:"statusText"`
	Headers    []harNameValue `json:"headers,omitempty"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MimeType string         `json:"mimeType"`
	Text     string         `json:"text,omitempty"`
	Params   []harNameValue `json:"params,omitempty"`
}

// parseHAR parses a HAR v1.2 file into a unified Spec.
// Entries are deduplicated by method+path so repeated requests
// collapse into a single endpoint.
func parseHAR(data []byte, source string) (*Spec, error) {
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("har parse: %w", err)
	}

	spec := &Spec{
		Format:      FormatHAR,
		Title:       "HAR Import",
		SpecVersion: har.Log.Version,
		Source:      source,
		ParsedAt:    time.Now(),
		Variables:   make(map[string]Variable),
	}

	// Track seen endpoints for deduplication.
	// Key: "METHOD /path"
	seen := make(map[string]int) // key -> index in spec.Endpoints

	var baseHost string

	for _, entry := range har.Log.Entries {
		if entry.Request.Method == "" || entry.Request.URL == "" {
			continue
		}

		method := strings.ToUpper(entry.Request.Method)
		path, host := extractHARPath(entry.Request.URL)

		// Skip static assets — not useful for API security testing.
		if isStaticAsset(path) {
			continue
		}

		// Capture first host as base server
		if baseHost == "" && host != "" {
			baseHost = host
		}

		// Convert literal IDs in path to template parameters.
		tpath, pathParams := templatizeHARPath(path)

		key := method + " " + tpath
		if idx, exists := seen[key]; exists {
			// Merge new params into existing endpoint
			mergeHARParams(&spec.Endpoints[idx], entry)
			continue
		}

		ep := Endpoint{
			Method:         method,
			Path:           tpath,
			Summary:        method + " " + tpath,
			CorrelationTag: CorrelationTag(method, tpath),
			RequestBodies:  make(map[string]RequestBody),
			Responses:      make(map[string]Response),
			Parameters:     pathParams,
		}

		// Extract query parameters
		for _, q := range entry.Request.QueryString {
			ep.Parameters = append(ep.Parameters, Parameter{
				Name:    q.Name,
				In:      LocationQuery,
				Example: q.Value,
			})
		}

		// Also extract query params from URL in case QueryString is empty
		if len(entry.Request.QueryString) == 0 {
			if u, err := url.Parse(entry.Request.URL); err == nil {
				for k, vals := range u.Query() {
					ep.Parameters = append(ep.Parameters, Parameter{
						Name:    k,
						In:      LocationQuery,
						Example: vals[0],
					})
				}
			}
		}

		// Extract cookies as parameters
		for _, c := range entry.Request.Cookies {
			ep.Parameters = append(ep.Parameters, Parameter{
				Name:    c.Name,
				In:      LocationCookie,
				Example: c.Value,
			})
		}

		// Extract headers — skip standard ones that are noise.
		// Detect auth from captured headers.
		for _, h := range entry.Request.Headers {
			lname := strings.ToLower(h.Name)
			if isStandardHeader(h.Name) {
				continue
			}
			// Capture auth info from traffic
			if lname == "authorization" {
				addHARAuthScheme(spec, AuthScheme{
					Name:   "bearer",
					Type:   AuthBearer,
					Scheme: "bearer",
				})
			} else if lname == "x-api-key" {
				addHARAuthScheme(spec, AuthScheme{
					Name:      h.Name,
					Type:      AuthAPIKey,
					In:        LocationHeader,
					FieldName: h.Name,
				})
			}
			ep.Parameters = append(ep.Parameters, Parameter{
				Name:    h.Name,
				In:      LocationHeader,
				Example: h.Value,
			})
		}

		// Extract body
		if entry.Request.PostData != nil {
			convertHARPostData(entry.Request.PostData, &ep)
		}

		// Extract response metadata.
		if entry.Response.Status > 0 {
			code := fmt.Sprintf("%d", entry.Response.Status)
			resp := Response{
				Description: entry.Response.StatusText,
			}
			if len(entry.Response.Headers) > 0 {
				resp.Headers = make(map[string]Parameter)
				for _, h := range entry.Response.Headers {
					if isStandardHeader(h.Name) {
						continue
					}
					resp.Headers[h.Name] = Parameter{
						Name:    h.Name,
						In:      LocationHeader,
						Example: h.Value,
					}
				}
			}
			ep.Responses[code] = resp
		}

		seen[key] = len(spec.Endpoints)
		spec.Endpoints = append(spec.Endpoints, ep)
	}

	if baseHost != "" {
		spec.Servers = append(spec.Servers, Server{URL: baseHost})
	}

	return spec, nil
}

// extractHARPath extracts the path and host from a full URL.
// Returns path and scheme+host for server detection.
func extractHARPath(rawURL string) (string, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, ""
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	host := ""
	if u.Scheme != "" && u.Host != "" {
		host = u.Scheme + "://" + u.Host
	}

	return path, host
}

// harIDPatterns detects path segments that look like identifiers.
var harIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\d+$`), // numeric: 123
	regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`), // UUID
	regexp.MustCompile(`^[0-9a-fA-F]{24}$`), // MongoDB ObjectID
	regexp.MustCompile(`^[0-9a-fA-F]{32}$`), // 32-char hex
}

// templatizeHARPath replaces ID-like segments with {id} path parameters.
// Returns the templatized path and any detected path parameters.
func templatizeHARPath(path string) (string, []Parameter) {
	segments := strings.Split(path, "/")
	var params []Parameter
	paramIdx := 0

	for i, seg := range segments {
		if seg == "" {
			continue
		}
		for _, pat := range harIDPatterns {
			if pat.MatchString(seg) {
				paramName := fmt.Sprintf("id%d", paramIdx)
				if paramIdx == 0 {
					paramName = "id"
				}
				paramIdx++
				params = append(params, Parameter{
					Name:     paramName,
					In:       LocationPath,
					Required: true,
					Example:  seg,
					Schema:   SchemaInfo{Type: "string"},
				})
				segments[i] = "{" + paramName + "}"
				break
			}
		}
	}

	return strings.Join(segments, "/"), params
}

// mergeHARParams adds new parameters from an entry to an existing endpoint,
// skipping duplicates by name+location.
func mergeHARParams(ep *Endpoint, entry harEntry) {
	existingParams := make(map[string]bool)
	for _, p := range ep.Parameters {
		existingParams[string(p.In)+":"+p.Name] = true
	}

	for _, q := range entry.Request.QueryString {
		key := string(LocationQuery) + ":" + q.Name
		if !existingParams[key] {
			ep.Parameters = append(ep.Parameters, Parameter{
				Name:    q.Name,
				In:      LocationQuery,
				Example: q.Value,
			})
			existingParams[key] = true
		}
	}

	for _, h := range entry.Request.Headers {
		if isStandardHeader(h.Name) {
			continue
		}
		key := string(LocationHeader) + ":" + h.Name
		if !existingParams[key] {
			ep.Parameters = append(ep.Parameters, Parameter{
				Name:    h.Name,
				In:      LocationHeader,
				Example: h.Value,
			})
			existingParams[key] = true
		}
	}
}

// convertHARPostData converts HAR post data to request body entries.
func convertHARPostData(pd *harPostData, ep *Endpoint) {
	ct := pd.MimeType
	if ct == "" {
		ct = "application/octet-stream"
	}

	// Strip charset and boundary suffixes for the content type key
	baseType := ct
	if idx := strings.Index(ct, ";"); idx >= 0 {
		baseType = strings.TrimSpace(ct[:idx])
	}

	ep.ContentTypes = append(ep.ContentTypes, baseType)

	rb := RequestBody{}

	if len(pd.Params) > 0 {
		schema := SchemaInfo{
			Type:       "object",
			Properties: make(map[string]SchemaInfo),
		}
		for _, p := range pd.Params {
			schema.Properties[p.Name] = SchemaInfo{Type: "string"}
		}
		rb.Schema = schema
	} else if pd.Text != "" {
		rb.Example = pd.Text
	}

	ep.RequestBodies[baseType] = rb
}

// isStandardHeader returns true for common HTTP headers that are noise
// for security testing and should be skipped during HAR import.
var standardHeaders = map[string]bool{
	"accept":                    true,
	"accept-encoding":           true,
	"accept-language":           true,
	"cache-control":             true,
	"connection":                true,
	"content-length":            true,
	"content-type":              true,
	"host":                      true,
	"origin":                    true,
	"referer":                   true,
	"sec-ch-ua":                 true,
	"sec-ch-ua-mobile":          true,
	"sec-ch-ua-platform":        true,
	"sec-fetch-dest":            true,
	"sec-fetch-mode":            true,
	"sec-fetch-site":            true,
	"user-agent":                true,
	"upgrade-insecure-requests": true,
}

func isStandardHeader(name string) bool {
	return standardHeaders[strings.ToLower(name)]
}

// staticExtensions are file extensions to skip during HAR import.
// These are static assets, not API endpoints.
var staticExtensions = map[string]bool{
	".js": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".map": true, ".webp": true, ".avif": true,
}

// isStaticAsset returns true if the path looks like a static file request.
func isStaticAsset(path string) bool {
	// Find last dot in the last path segment
	lastSlash := strings.LastIndex(path, "/")
	segment := path
	if lastSlash >= 0 {
		segment = path[lastSlash:]
	}
	dotIdx := strings.LastIndex(segment, ".")
	if dotIdx < 0 {
		return false
	}
	return staticExtensions[strings.ToLower(segment[dotIdx:])]
}

// addHARAuthScheme adds a detected auth scheme to the spec, avoiding duplicates.
func addHARAuthScheme(spec *Spec, scheme AuthScheme) {
	for _, existing := range spec.AuthSchemes {
		if existing.Type == scheme.Type && existing.Name == scheme.Name {
			return
		}
	}
	spec.AuthSchemes = append(spec.AuthSchemes, scheme)
}
