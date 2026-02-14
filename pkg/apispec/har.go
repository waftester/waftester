package apispec

import (
	"encoding/json"
	"fmt"
	"net/url"
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

		// Capture first host as base server
		if baseHost == "" && host != "" {
			baseHost = host
		}

		key := method + " " + path
		if idx, exists := seen[key]; exists {
			// Merge new params into existing endpoint
			mergeHARParams(&spec.Endpoints[idx], entry)
			continue
		}

		ep := Endpoint{
			Method:         method,
			Path:           path,
			Summary:        method + " " + path,
			CorrelationTag: CorrelationTag(method, path),
			RequestBodies:  make(map[string]RequestBody),
			Responses:      make(map[string]Response),
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

		// Extract headers (skip standard ones that are noise)
		for _, h := range entry.Request.Headers {
			if isStandardHeader(h.Name) {
				continue
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
