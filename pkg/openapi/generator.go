package openapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// TestCase represents a generated WAF test case
type TestCase struct {
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Endpoint       string            `json:"endpoint"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	QueryParams    map[string]string `json:"query_params,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	ContentType    string            `json:"content_type,omitempty"`
	ExpectedStatus int               `json:"expected_status,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Payload        string            `json:"payload,omitempty"`
	PayloadType    string            `json:"payload_type,omitempty"`
	InjectionPoint string            `json:"injection_point,omitempty"`
}

// Generator generates WAF test cases from OpenAPI specs
type Generator struct {
	parser   *Parser
	baseURL  string
	payloads map[string][]string
}

// GeneratorOption configures the generator
type GeneratorOption func(*Generator)

// WithBaseURL sets a custom base URL
func WithBaseURL(url string) GeneratorOption {
	return func(g *Generator) {
		g.baseURL = strings.TrimSuffix(url, "/")
	}
}

// WithPayloads sets custom payloads for each category
func WithPayloads(payloads map[string][]string) GeneratorOption {
	return func(g *Generator) {
		g.payloads = payloads
	}
}

// NewGenerator creates a new test generator
func NewGenerator(opts ...GeneratorOption) *Generator {
	g := &Generator{
		parser:   NewParser(),
		payloads: defaultPayloads(),
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// defaultPayloads returns default attack payloads
func defaultPayloads() map[string][]string {
	return map[string][]string{
		"sqli": {
			"' OR '1'='1",
			"1' OR '1'='1'--",
			"'; DROP TABLE users--",
			"1 UNION SELECT * FROM users",
		},
		"xss": {
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
			"<svg onload=alert(1)>",
		},
		"lfi": {
			"../../../etc/passwd",
			"....//....//....//etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"/etc/passwd%00",
		},
		"rce": {
			"; ls -la",
			"| cat /etc/passwd",
			"$(whoami)",
			"`id`",
		},
		"xxe": {
			`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>`,
		},
	}
}

// GenerateFromFile generates test cases from an OpenAPI spec file
func (g *Generator) GenerateFromFile(path string) ([]TestCase, error) {
	spec, err := g.parser.ParseFile(path)
	if err != nil {
		return nil, err
	}
	return g.Generate(spec)
}

// GenerateFromURL generates test cases from an OpenAPI spec URL
func (g *Generator) GenerateFromURL(specURL string) ([]TestCase, error) {
	spec, err := g.parser.ParseURL(specURL)
	if err != nil {
		return nil, err
	}
	return g.Generate(spec)
}

// Generate generates test cases from a parsed OpenAPI spec
func (g *Generator) Generate(spec *Spec) ([]TestCase, error) {
	var tests []TestCase

	// Determine base URL
	baseURL := g.baseURL
	if baseURL == "" {
		baseURL = g.parser.GetBaseURL(spec)
	}

	operations := g.parser.GetOperations(spec)

	for _, op := range operations {
		// Generate baseline test (no attack)
		baseline := g.generateBaseline(op, baseURL)
		tests = append(tests, baseline)

		// Generate parameter injection tests
		paramTests := g.generateParameterTests(op, baseURL)
		tests = append(tests, paramTests...)

		// Generate body injection tests
		if op.Operation.RequestBody != nil {
			bodyTests := g.generateBodyTests(op, baseURL, spec)
			tests = append(tests, bodyTests...)
		}

		// Generate header injection tests
		headerTests := g.generateHeaderTests(op, baseURL)
		tests = append(tests, headerTests...)
	}

	return tests, nil
}

// generateBaseline creates a baseline test without attacks
func (g *Generator) generateBaseline(op EndpointOperation, baseURL string) TestCase {
	path := g.expandPath(op.Path, op.Operation.Parameters)

	return TestCase{
		Name:           fmt.Sprintf("baseline_%s_%s", op.Method, sanitizeName(op.Path)),
		Description:    fmt.Sprintf("Baseline test for %s %s", op.Method, op.Path),
		Endpoint:       baseURL + path,
		Method:         op.Method,
		Path:           path,
		Tags:           append([]string{"baseline"}, op.Operation.Tags...),
		ExpectedStatus: 200,
	}
}

// generateParameterTests creates injection tests for all parameters
func (g *Generator) generateParameterTests(op EndpointOperation, baseURL string) []TestCase {
	var tests []TestCase

	for _, param := range op.Operation.Parameters {
		for category, payloads := range g.payloads {
			for i, payload := range payloads {
				test := g.createParameterTest(op, baseURL, param, category, payload, i)
				tests = append(tests, test)
			}
		}
	}

	return tests
}

// createParameterTest creates a single parameter injection test
func (g *Generator) createParameterTest(op EndpointOperation, baseURL string, param Parameter, category, payload string, idx int) TestCase {
	path := g.expandPath(op.Path, op.Operation.Parameters)

	test := TestCase{
		Name:           fmt.Sprintf("%s_%s_%s_%s_%d", category, op.Method, sanitizeName(op.Path), param.Name, idx),
		Description:    fmt.Sprintf("%s injection in %s parameter %s", strings.ToUpper(category), param.In, param.Name),
		Method:         op.Method,
		Path:           path,
		Tags:           []string{category, "injection", param.In},
		Payload:        payload,
		PayloadType:    category,
		InjectionPoint: fmt.Sprintf("%s:%s", param.In, param.Name),
		ExpectedStatus: 403, // WAF should block
	}

	switch param.In {
	case "query":
		test.QueryParams = map[string]string{param.Name: payload}
		u, err := url.Parse(baseURL + path)
		if err != nil {
			test.Endpoint = baseURL + path
		} else {
			q := u.Query()
			q.Set(param.Name, payload)
			u.RawQuery = q.Encode()
			test.Endpoint = u.String()
		}

	case "path":
		// Replace path parameter with payload
		injectedPath := strings.Replace(path, "{"+param.Name+"}", url.PathEscape(payload), 1)
		test.Path = injectedPath
		test.Endpoint = baseURL + injectedPath

	case "header":
		test.Headers = map[string]string{param.Name: payload}
		test.Endpoint = baseURL + path

	case "cookie":
		test.Headers = map[string]string{"Cookie": fmt.Sprintf("%s=%s", param.Name, payload)}
		test.Endpoint = baseURL + path
	}

	return test
}

// generateBodyTests creates injection tests for request bodies
func (g *Generator) generateBodyTests(op EndpointOperation, baseURL string, spec *Spec) []TestCase {
	var tests []TestCase

	if op.Operation.RequestBody == nil || op.Operation.RequestBody.Content == nil {
		return tests
	}

	path := g.expandPath(op.Path, op.Operation.Parameters)

	for contentType, mediaType := range op.Operation.RequestBody.Content {
		schema := mediaType.Schema
		if schema != nil && schema.Ref != "" {
			schema = g.parser.ResolveRef(spec, schema.Ref)
		}

		if schema == nil {
			continue
		}

		// Get all injectable fields
		fields := g.getSchemaFields(schema, spec, "")

		for _, field := range fields {
			for category, payloads := range g.payloads {
				for i, payload := range payloads {
					test := g.createBodyTest(op, baseURL, path, contentType, field, category, payload, i)
					tests = append(tests, test)
				}
			}
		}
	}

	return tests
}

// SchemaField represents a field in a schema
type SchemaField struct {
	Path   string // JSON path like "user.name"
	Type   string
	Schema *Schema
}

// getSchemaFields extracts all injectable fields from a schema
func (g *Generator) getSchemaFields(schema *Schema, spec *Spec, prefix string) []SchemaField {
	var fields []SchemaField

	if schema == nil {
		return fields
	}

	// Resolve ref if present
	if schema.Ref != "" {
		schema = g.parser.ResolveRef(spec, schema.Ref)
		if schema == nil {
			return fields
		}
	}

	switch schema.Type {
	case "object":
		for name, propSchema := range schema.Properties {
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}

			// Resolve nested refs
			if propSchema.Ref != "" {
				propSchema = g.parser.ResolveRef(spec, propSchema.Ref)
			}

			if propSchema == nil {
				continue
			}

			if propSchema.Type == "string" || propSchema.Type == "integer" || propSchema.Type == "number" {
				fields = append(fields, SchemaField{
					Path:   path,
					Type:   propSchema.Type,
					Schema: propSchema,
				})
			} else if propSchema.Type == "object" {
				nested := g.getSchemaFields(propSchema, spec, path)
				fields = append(fields, nested...)
			}
		}

	case "array":
		if schema.Items != nil {
			// Add array item fields with [0] notation
			itemFields := g.getSchemaFields(schema.Items, spec, prefix+"[0]")
			fields = append(fields, itemFields...)
		}

	case "string", "integer", "number":
		if prefix != "" {
			fields = append(fields, SchemaField{
				Path:   prefix,
				Type:   schema.Type,
				Schema: schema,
			})
		}
	}

	return fields
}

// createBodyTest creates a single body injection test
func (g *Generator) createBodyTest(op EndpointOperation, baseURL, path, contentType string, field SchemaField, category, payload string, idx int) TestCase {
	test := TestCase{
		Name:           fmt.Sprintf("%s_%s_%s_body_%s_%d", category, op.Method, sanitizeName(op.Path), sanitizeName(field.Path), idx),
		Description:    fmt.Sprintf("%s injection in request body field %s", strings.ToUpper(category), field.Path),
		Endpoint:       baseURL + path,
		Method:         op.Method,
		Path:           path,
		ContentType:    contentType,
		Tags:           []string{category, "injection", "body"},
		Payload:        payload,
		PayloadType:    category,
		InjectionPoint: fmt.Sprintf("body:%s", field.Path),
		ExpectedStatus: 403,
	}

	// Generate appropriate body
	test.Body = g.generateInjectedBody(contentType, field.Path, payload)

	return test
}

// generateInjectedBody creates a request body with the payload injected
func (g *Generator) generateInjectedBody(contentType, fieldPath, payload string) string {
	switch {
	case strings.Contains(contentType, "json"):
		return g.generateJSONBody(fieldPath, payload)
	case strings.Contains(contentType, "x-www-form-urlencoded"):
		return g.generateFormBody(fieldPath, payload)
	case strings.Contains(contentType, "xml"):
		return g.generateXMLBody(fieldPath, payload)
	default:
		return payload
	}
}

// generateJSONBody creates a JSON body with the payload
func (g *Generator) generateJSONBody(fieldPath, payload string) string {
	// Build nested JSON from field path
	parts := strings.Split(fieldPath, ".")

	var result any = payload

	// Build from innermost to outermost
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		// Handle array notation
		if strings.HasSuffix(part, "[0]") {
			part = strings.TrimSuffix(part, "[0]")
			result = map[string]any{part: []any{result}}
		} else {
			result = map[string]any{part: result}
		}
	}

	data, _ := json.Marshal(result)
	return string(data)
}

// generateFormBody creates a form-urlencoded body
func (g *Generator) generateFormBody(fieldPath, payload string) string {
	// Use the leaf field name
	parts := strings.Split(fieldPath, ".")
	name := parts[len(parts)-1]
	name = strings.TrimSuffix(name, "[0]")
	return fmt.Sprintf("%s=%s", url.QueryEscape(name), url.QueryEscape(payload))
}

// generateXMLBody creates an XML body
func (g *Generator) generateXMLBody(fieldPath, payload string) string {
	parts := strings.Split(fieldPath, ".")

	// Build XML from field path
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\"?>")

	for _, part := range parts {
		part = strings.TrimSuffix(part, "[0]")
		sb.WriteString("<" + part + ">")
	}

	sb.WriteString(payload)

	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSuffix(parts[i], "[0]")
		sb.WriteString("</" + part + ">")
	}

	return sb.String()
}

// generateHeaderTests creates tests for common header injection
func (g *Generator) generateHeaderTests(op EndpointOperation, baseURL string) []TestCase {
	var tests []TestCase

	path := g.expandPath(op.Path, op.Operation.Parameters)

	// Common injectable headers
	headers := []string{"X-Forwarded-For", "User-Agent", "Referer", "X-Custom-Header"}

	for _, header := range headers {
		for category, payloads := range g.payloads {
			for i, payload := range payloads {
				test := TestCase{
					Name:           fmt.Sprintf("%s_%s_%s_header_%s_%d", category, op.Method, sanitizeName(op.Path), sanitizeName(header), i),
					Description:    fmt.Sprintf("%s injection in %s header", strings.ToUpper(category), header),
					Endpoint:       baseURL + path,
					Method:         op.Method,
					Path:           path,
					Headers:        map[string]string{header: payload},
					Tags:           []string{category, "injection", "header"},
					Payload:        payload,
					PayloadType:    category,
					InjectionPoint: fmt.Sprintf("header:%s", header),
					ExpectedStatus: 403,
				}
				tests = append(tests, test)
			}
		}
	}

	return tests
}

// expandPath replaces path parameters with example values
func (g *Generator) expandPath(path string, params []Parameter) string {
	result := path

	for _, param := range params {
		if param.In == "path" {
			value := "1" // Default value
			if param.Example != nil {
				value = fmt.Sprintf("%v", param.Example)
			} else if param.Schema != nil && param.Schema.Example != nil {
				value = fmt.Sprintf("%v", param.Schema.Example)
			}
			result = strings.Replace(result, "{"+param.Name+"}", value, 1)
		}
	}

	return result
}

// sanitizeName converts a path or name to a valid test name
func sanitizeName(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "{", "")
	s = strings.ReplaceAll(s, "}", "")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.Trim(s, "_")
	return s
}

// ExportTests exports test cases to JSON
func ExportTests(tests []TestCase) ([]byte, error) {
	return json.MarshalIndent(tests, "", "  ")
}
