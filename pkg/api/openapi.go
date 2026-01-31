// Package api provides API discovery and OpenAPI/Swagger parsing
// Based on kiterunner's API route generation capabilities
package api

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Route represents an API route discovered from OpenAPI specs
type Route struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	OperationID string            `json:"operation_id,omitempty"`
	Summary     string            `json:"summary,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Parameters  []Parameter       `json:"parameters,omitempty"`
	RequestBody *RequestBody      `json:"request_body,omitempty"`
	ContentType []string          `json:"content_types,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Security    []string          `json:"security,omitempty"`
	Deprecated  bool              `json:"deprecated,omitempty"`
}

// Parameter represents an API parameter
type Parameter struct {
	Name        string      `json:"name"`
	In          string      `json:"in"` // path, query, header, cookie
	Required    bool        `json:"required"`
	Type        string      `json:"type,omitempty"`
	Format      string      `json:"format,omitempty"`
	Description string      `json:"description,omitempty"`
	Example     interface{} `json:"example,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
}

// RequestBody represents a request body definition
type RequestBody struct {
	ContentType string                 `json:"content_type"`
	Required    bool                   `json:"required"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
	Example     interface{}            `json:"example,omitempty"`
}

// OpenAPISpec represents a parsed OpenAPI/Swagger specification
type OpenAPISpec struct {
	Version  string           `json:"version"` // "2.0" for Swagger, "3.0.x" for OpenAPI
	Title    string           `json:"title"`
	BasePath string           `json:"base_path"`
	Host     string           `json:"host,omitempty"`
	Routes   []Route          `json:"routes"`
	Servers  []string         `json:"servers,omitempty"`
	Security []SecurityScheme `json:"security,omitempty"`
}

// SecurityScheme represents an authentication/authorization scheme
type SecurityScheme struct {
	Name   string `json:"name"`
	Type   string `json:"type"`             // apiKey, http, oauth2, openIdConnect
	In     string `json:"in,omitempty"`     // header, query, cookie (for apiKey)
	Scheme string `json:"scheme,omitempty"` // basic, bearer (for http)
}

// Parser parses OpenAPI/Swagger specifications
type Parser struct {
	inferParameterTypes bool
	generateExamples    bool
}

// NewParser creates a new OpenAPI parser
func NewParser() *Parser {
	return &Parser{
		inferParameterTypes: true,
		generateExamples:    true,
	}
}

// ParseFile parses an OpenAPI/Swagger spec from a file
func (p *Parser) ParseFile(path string) (*OpenAPISpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return p.Parse(data)
}

// Parse parses OpenAPI/Swagger spec from JSON data
func (p *Parser) Parse(data []byte) (*OpenAPISpec, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Detect version
	if swagger, ok := raw["swagger"].(string); ok && swagger == "2.0" {
		return p.parseSwagger2(raw)
	}

	if openapi, ok := raw["openapi"].(string); ok && strings.HasPrefix(openapi, "3.") {
		return p.parseOpenAPI3(raw)
	}

	return nil, fmt.Errorf("unknown specification format")
}

// parseSwagger2 parses Swagger 2.0 format
func (p *Parser) parseSwagger2(raw map[string]interface{}) (*OpenAPISpec, error) {
	spec := &OpenAPISpec{
		Version: "2.0",
	}

	// Extract basic info
	if info, ok := raw["info"].(map[string]interface{}); ok {
		if title, ok := info["title"].(string); ok {
			spec.Title = title
		}
	}

	if basePath, ok := raw["basePath"].(string); ok {
		spec.BasePath = basePath
	}

	if host, ok := raw["host"].(string); ok {
		spec.Host = host
	}

	// Parse paths
	if paths, ok := raw["paths"].(map[string]interface{}); ok {
		spec.Routes = p.parseSwagger2Paths(paths)
	}

	// Parse security definitions
	if secDefs, ok := raw["securityDefinitions"].(map[string]interface{}); ok {
		spec.Security = p.parseSwagger2Security(secDefs)
	}

	return spec, nil
}

func (p *Parser) parseSwagger2Paths(paths map[string]interface{}) []Route {
	var routes []Route

	for path, methods := range paths {
		methodsMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		for method, operation := range methodsMap {
			// Skip non-HTTP methods (like "parameters")
			if !isHTTPMethod(method) {
				continue
			}

			route := Route{
				Path:   path,
				Method: strings.ToUpper(method),
			}

			if op, ok := operation.(map[string]interface{}); ok {
				if opID, ok := op["operationId"].(string); ok {
					route.OperationID = opID
				}
				if summary, ok := op["summary"].(string); ok {
					route.Summary = summary
				}
				if tags, ok := op["tags"].([]interface{}); ok {
					for _, t := range tags {
						if tag, ok := t.(string); ok {
							route.Tags = append(route.Tags, tag)
						}
					}
				}
				if deprecated, ok := op["deprecated"].(bool); ok {
					route.Deprecated = deprecated
				}
				if params, ok := op["parameters"].([]interface{}); ok {
					route.Parameters = p.parseParameters(params)
				}
				if consumes, ok := op["consumes"].([]interface{}); ok {
					for _, c := range consumes {
						if ct, ok := c.(string); ok {
							route.ContentType = append(route.ContentType, ct)
						}
					}
				}
			}

			routes = append(routes, route)
		}
	}

	return routes
}

// parseOpenAPI3 parses OpenAPI 3.0+ format
func (p *Parser) parseOpenAPI3(raw map[string]interface{}) (*OpenAPISpec, error) {
	spec := &OpenAPISpec{
		Version: raw["openapi"].(string),
	}

	// Extract basic info
	if info, ok := raw["info"].(map[string]interface{}); ok {
		if title, ok := info["title"].(string); ok {
			spec.Title = title
		}
	}

	// Parse servers
	if servers, ok := raw["servers"].([]interface{}); ok {
		for _, s := range servers {
			if server, ok := s.(map[string]interface{}); ok {
				if url, ok := server["url"].(string); ok {
					spec.Servers = append(spec.Servers, url)
				}
			}
		}
	}

	// Parse paths
	if paths, ok := raw["paths"].(map[string]interface{}); ok {
		spec.Routes = p.parseOpenAPI3Paths(paths)
	}

	// Parse security schemes
	if components, ok := raw["components"].(map[string]interface{}); ok {
		if secSchemes, ok := components["securitySchemes"].(map[string]interface{}); ok {
			spec.Security = p.parseOpenAPI3Security(secSchemes)
		}
	}

	return spec, nil
}

func (p *Parser) parseOpenAPI3Paths(paths map[string]interface{}) []Route {
	var routes []Route

	for path, methods := range paths {
		methodsMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		for method, operation := range methodsMap {
			if !isHTTPMethod(method) {
				continue
			}

			route := Route{
				Path:   path,
				Method: strings.ToUpper(method),
			}

			if op, ok := operation.(map[string]interface{}); ok {
				if opID, ok := op["operationId"].(string); ok {
					route.OperationID = opID
				}
				if summary, ok := op["summary"].(string); ok {
					route.Summary = summary
				}
				if tags, ok := op["tags"].([]interface{}); ok {
					for _, t := range tags {
						if tag, ok := t.(string); ok {
							route.Tags = append(route.Tags, tag)
						}
					}
				}
				if deprecated, ok := op["deprecated"].(bool); ok {
					route.Deprecated = deprecated
				}
				if params, ok := op["parameters"].([]interface{}); ok {
					route.Parameters = p.parseParameters(params)
				}

				// Parse request body (OpenAPI 3.0)
				if reqBody, ok := op["requestBody"].(map[string]interface{}); ok {
					route.RequestBody = p.parseRequestBody(reqBody)
					if route.RequestBody != nil {
						route.ContentType = []string{route.RequestBody.ContentType}
					}
				}
			}

			routes = append(routes, route)
		}
	}

	return routes
}

func (p *Parser) parseParameters(params []interface{}) []Parameter {
	var result []Parameter

	for _, param := range params {
		paramMap, ok := param.(map[string]interface{})
		if !ok {
			continue
		}

		par := Parameter{}

		if name, ok := paramMap["name"].(string); ok {
			par.Name = name
		}
		if in, ok := paramMap["in"].(string); ok {
			par.In = in
		}
		if required, ok := paramMap["required"].(bool); ok {
			par.Required = required
		}
		if desc, ok := paramMap["description"].(string); ok {
			par.Description = desc
		}

		// Extract type from schema or directly
		if schema, ok := paramMap["schema"].(map[string]interface{}); ok {
			if t, ok := schema["type"].(string); ok {
				par.Type = t
			}
			if f, ok := schema["format"].(string); ok {
				par.Format = f
			}
			if enum, ok := schema["enum"].([]interface{}); ok {
				for _, e := range enum {
					if v, ok := e.(string); ok {
						par.Enum = append(par.Enum, v)
					}
				}
			}
		} else if t, ok := paramMap["type"].(string); ok {
			par.Type = t
		}

		if ex, ok := paramMap["example"]; ok {
			par.Example = ex
		}
		if def, ok := paramMap["default"]; ok {
			par.Default = def
		}

		result = append(result, par)
	}

	return result
}

func (p *Parser) parseRequestBody(reqBody map[string]interface{}) *RequestBody {
	rb := &RequestBody{}

	if required, ok := reqBody["required"].(bool); ok {
		rb.Required = required
	}

	if content, ok := reqBody["content"].(map[string]interface{}); ok {
		// Get the first content type
		for ct, schema := range content {
			rb.ContentType = ct
			if schemaMap, ok := schema.(map[string]interface{}); ok {
				if s, ok := schemaMap["schema"].(map[string]interface{}); ok {
					rb.Schema = s
				}
				if ex, ok := schemaMap["example"]; ok {
					rb.Example = ex
				}
			}
			break // Just get the first content type
		}
	}

	return rb
}

func (p *Parser) parseSwagger2Security(secDefs map[string]interface{}) []SecurityScheme {
	var schemes []SecurityScheme

	for name, def := range secDefs {
		defMap, ok := def.(map[string]interface{})
		if !ok {
			continue
		}

		scheme := SecurityScheme{Name: name}

		if t, ok := defMap["type"].(string); ok {
			scheme.Type = t
		}
		if in, ok := defMap["in"].(string); ok {
			scheme.In = in
		}

		schemes = append(schemes, scheme)
	}

	return schemes
}

func (p *Parser) parseOpenAPI3Security(secSchemes map[string]interface{}) []SecurityScheme {
	var schemes []SecurityScheme

	for name, def := range secSchemes {
		defMap, ok := def.(map[string]interface{})
		if !ok {
			continue
		}

		scheme := SecurityScheme{Name: name}

		if t, ok := defMap["type"].(string); ok {
			scheme.Type = t
		}
		if in, ok := defMap["in"].(string); ok {
			scheme.In = in
		}
		if s, ok := defMap["scheme"].(string); ok {
			scheme.Scheme = s
		}

		schemes = append(schemes, scheme)
	}

	return schemes
}

func isHTTPMethod(method string) bool {
	methods := []string{"get", "post", "put", "patch", "delete", "options", "head", "trace"}
	lower := strings.ToLower(method)
	for _, m := range methods {
		if m == lower {
			return true
		}
	}
	return false
}

// GenerateTestCases generates test cases from routes
func (spec *OpenAPISpec) GenerateTestCases(baseURL string) []TestCase {
	var cases []TestCase

	for _, route := range spec.Routes {
		tc := TestCase{
			Name:        route.OperationID,
			Method:      route.Method,
			Path:        spec.BasePath + route.Path,
			ContentType: firstOrDefault(route.ContentType, "application/json"),
			Tags:        route.Tags,
		}

		if tc.Name == "" {
			tc.Name = route.Method + " " + route.Path
		}

		// Fill in path parameters with examples
		tc.Path = substitutePathParams(tc.Path, route.Parameters)

		// Build query parameters
		queryParams := extractQueryParams(route.Parameters)
		if len(queryParams) > 0 {
			tc.Path += "?" + buildQueryString(queryParams)
		}

		// Build headers
		tc.Headers = extractHeaders(route.Parameters)

		// Build request body
		if route.RequestBody != nil && route.RequestBody.Example != nil {
			if body, err := json.Marshal(route.RequestBody.Example); err == nil {
				tc.Body = string(body)
			}
		}

		cases = append(cases, tc)
	}

	return cases
}

// TestCase represents a generated API test case
type TestCase struct {
	Name        string            `json:"name"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type"`
	Tags        []string          `json:"tags,omitempty"`
}

func substitutePathParams(path string, params []Parameter) string {
	result := path
	for _, p := range params {
		if p.In != "path" {
			continue
		}
		placeholder := "{" + p.Name + "}"
		value := getExampleValue(p)
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

func extractQueryParams(params []Parameter) map[string]string {
	result := make(map[string]string)
	for _, p := range params {
		if p.In == "query" && (p.Required || p.Example != nil) {
			result[p.Name] = getExampleValue(p)
		}
	}
	return result
}

func extractHeaders(params []Parameter) map[string]string {
	result := make(map[string]string)
	for _, p := range params {
		if p.In == "header" {
			result[p.Name] = getExampleValue(p)
		}
	}
	return result
}

func getExampleValue(p Parameter) string {
	if p.Example != nil {
		return fmt.Sprintf("%v", p.Example)
	}
	if p.Default != nil {
		return fmt.Sprintf("%v", p.Default)
	}
	if len(p.Enum) > 0 {
		return p.Enum[0]
	}

	// Generate based on type
	switch p.Type {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "string":
		switch p.Format {
		case "email":
			return "test@example.com"
		case "uuid":
			return "00000000-0000-0000-0000-000000000000"
		case "date":
			return "2024-01-15"
		case "date-time":
			return "2024-01-15T10:00:00Z"
		default:
			return "test"
		}
	default:
		return "test"
	}
}

func buildQueryString(params map[string]string) string {
	var parts []string
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	return strings.Join(parts, "&")
}

func firstOrDefault(slice []string, def string) string {
	if len(slice) > 0 {
		return slice[0]
	}
	return def
}

// InferAPIRoutes attempts to infer API routes from HTML/JS responses
func InferAPIRoutes(content string) []Route {
	var routes []Route
	seen := make(map[string]bool)

	// Pattern: /api/v1/resource, /api/resource, /v1/resource
	apiPattern := regexp.MustCompile(`['"](/(?:api(?:/v\d+)?|v\d+)/[a-zA-Z0-9_/-]+)['"]`)
	matches := apiPattern.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		if len(m) > 1 {
			path := m[1]
			if !seen[path] {
				seen[path] = true
				routes = append(routes, Route{
					Path:   path,
					Method: "GET", // Default to GET
				})
			}
		}
	}

	return routes
}
