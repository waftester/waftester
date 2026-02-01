// Package openapi provides OpenAPI specification parsing and test generation
package openapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"gopkg.in/yaml.v3"
)

// Spec represents a parsed OpenAPI specification
type Spec struct {
	OpenAPI    string              `json:"openapi" yaml:"openapi"`
	Info       Info                `json:"info" yaml:"info"`
	Servers    []Server            `json:"servers,omitempty" yaml:"servers,omitempty"`
	Paths      map[string]PathItem `json:"paths" yaml:"paths"`
	Components *Components         `json:"components,omitempty" yaml:"components,omitempty"`
}

// Info contains API metadata
type Info struct {
	Title       string `json:"title" yaml:"title"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Version     string `json:"version" yaml:"version"`
}

// Server represents a server definition
type Server struct {
	URL         string `json:"url" yaml:"url"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// PathItem represents all operations for a path
type PathItem struct {
	Get     *Operation `json:"get,omitempty" yaml:"get,omitempty"`
	Post    *Operation `json:"post,omitempty" yaml:"post,omitempty"`
	Put     *Operation `json:"put,omitempty" yaml:"put,omitempty"`
	Delete  *Operation `json:"delete,omitempty" yaml:"delete,omitempty"`
	Patch   *Operation `json:"patch,omitempty" yaml:"patch,omitempty"`
	Options *Operation `json:"options,omitempty" yaml:"options,omitempty"`
	Head    *Operation `json:"head,omitempty" yaml:"head,omitempty"`
}

// Operation represents a single API operation
type Operation struct {
	OperationID string              `json:"operationId,omitempty" yaml:"operationId,omitempty"`
	Summary     string              `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string              `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string            `json:"tags,omitempty" yaml:"tags,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty" yaml:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses,omitempty" yaml:"responses,omitempty"`
	Security    []SecurityReq       `json:"security,omitempty" yaml:"security,omitempty"`
}

// Parameter represents an operation parameter
type Parameter struct {
	Name        string  `json:"name" yaml:"name"`
	In          string  `json:"in" yaml:"in"` // query, path, header, cookie
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool    `json:"required,omitempty" yaml:"required,omitempty"`
	Schema      *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example     any     `json:"example,omitempty" yaml:"example,omitempty"`
}

// RequestBody represents the request body
type RequestBody struct {
	Description string               `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool                 `json:"required,omitempty" yaml:"required,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty" yaml:"content,omitempty"`
}

// MediaType represents a media type definition
type MediaType struct {
	Schema  *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example any     `json:"example,omitempty" yaml:"example,omitempty"`
}

// Schema represents a JSON Schema definition
type Schema struct {
	Type       string             `json:"type,omitempty" yaml:"type,omitempty"`
	Format     string             `json:"format,omitempty" yaml:"format,omitempty"`
	Properties map[string]*Schema `json:"properties,omitempty" yaml:"properties,omitempty"`
	Items      *Schema            `json:"items,omitempty" yaml:"items,omitempty"`
	Required   []string           `json:"required,omitempty" yaml:"required,omitempty"`
	Enum       []any              `json:"enum,omitempty" yaml:"enum,omitempty"`
	Ref        string             `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Example    any                `json:"example,omitempty" yaml:"example,omitempty"`
	MinLength  *int               `json:"minLength,omitempty" yaml:"minLength,omitempty"`
	MaxLength  *int               `json:"maxLength,omitempty" yaml:"maxLength,omitempty"`
	Minimum    *float64           `json:"minimum,omitempty" yaml:"minimum,omitempty"`
	Maximum    *float64           `json:"maximum,omitempty" yaml:"maximum,omitempty"`
	Pattern    string             `json:"pattern,omitempty" yaml:"pattern,omitempty"`
}

// Response represents an API response
type Response struct {
	Description string               `json:"description,omitempty" yaml:"description,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty" yaml:"content,omitempty"`
	Headers     map[string]Parameter `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// SecurityReq represents a security requirement
type SecurityReq map[string][]string

// Components contains reusable schema components
type Components struct {
	Schemas         map[string]*Schema         `json:"schemas,omitempty" yaml:"schemas,omitempty"`
	SecuritySchemes map[string]*SecurityScheme `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
	Parameters      map[string]*Parameter      `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// SecurityScheme represents an authentication scheme
type SecurityScheme struct {
	Type         string `json:"type" yaml:"type"`
	Scheme       string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty" yaml:"bearerFormat,omitempty"`
	Name         string `json:"name,omitempty" yaml:"name,omitempty"`
	In           string `json:"in,omitempty" yaml:"in,omitempty"`
}

// Parser parses OpenAPI specifications
type Parser struct {
	// Resolved schemas cache
	resolvedSchemas map[string]*Schema
}

// NewParser creates a new OpenAPI parser
func NewParser() *Parser {
	return &Parser{
		resolvedSchemas: make(map[string]*Schema),
	}
}

// ParseFile parses an OpenAPI spec from a file
func (p *Parser) ParseFile(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return p.ParseJSON(data)
	case ".yaml", ".yml":
		return p.ParseYAML(data)
	default:
		// Try to detect format
		if json.Valid(data) {
			return p.ParseJSON(data)
		}
		return p.ParseYAML(data)
	}
}

// ParseURL fetches and parses an OpenAPI spec from a URL
func (p *Parser) ParseURL(url string) (*Spec, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	data, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "json") {
		return p.ParseJSON(data)
	}
	if strings.Contains(contentType, "yaml") || strings.Contains(contentType, "yml") {
		return p.ParseYAML(data)
	}

	// Auto-detect
	if json.Valid(data) {
		return p.ParseJSON(data)
	}
	return p.ParseYAML(data)
}

// ParseJSON parses an OpenAPI spec from JSON data
func (p *Parser) ParseJSON(data []byte) (*Spec, error) {
	var spec Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &spec, nil
}

// ParseYAML parses an OpenAPI spec from YAML data
func (p *Parser) ParseYAML(data []byte) (*Spec, error) {
	var spec Spec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	return &spec, nil
}

// ResolveRef resolves a $ref reference to its schema
func (p *Parser) ResolveRef(spec *Spec, ref string) *Schema {
	if ref == "" {
		return nil
	}

	// Check cache
	if schema, ok := p.resolvedSchemas[ref]; ok {
		return schema
	}

	// Parse reference path: #/components/schemas/User
	refPattern := regexcache.MustGet(`^#/components/schemas/(.+)$`)
	matches := refPattern.FindStringSubmatch(ref)
	if len(matches) != 2 {
		return nil
	}

	schemaName := matches[1]
	if spec.Components == nil || spec.Components.Schemas == nil {
		return nil
	}

	schema, ok := spec.Components.Schemas[schemaName]
	if !ok {
		return nil
	}

	// Recursively resolve if schema has a ref
	if schema.Ref != "" {
		schema = p.ResolveRef(spec, schema.Ref)
	}

	// Cache
	p.resolvedSchemas[ref] = schema
	return schema
}

// GetOperations extracts all operations from a spec
func (p *Parser) GetOperations(spec *Spec) []EndpointOperation {
	var ops []EndpointOperation

	for path, pathItem := range spec.Paths {
		if pathItem.Get != nil {
			ops = append(ops, EndpointOperation{
				Path:      path,
				Method:    "GET",
				Operation: pathItem.Get,
			})
		}
		if pathItem.Post != nil {
			ops = append(ops, EndpointOperation{
				Path:      path,
				Method:    "POST",
				Operation: pathItem.Post,
			})
		}
		if pathItem.Put != nil {
			ops = append(ops, EndpointOperation{
				Path:      path,
				Method:    "PUT",
				Operation: pathItem.Put,
			})
		}
		if pathItem.Delete != nil {
			ops = append(ops, EndpointOperation{
				Path:      path,
				Method:    "DELETE",
				Operation: pathItem.Delete,
			})
		}
		if pathItem.Patch != nil {
			ops = append(ops, EndpointOperation{
				Path:      path,
				Method:    "PATCH",
				Operation: pathItem.Patch,
			})
		}
		if pathItem.Options != nil {
			ops = append(ops, EndpointOperation{
				Path:      path,
				Method:    "OPTIONS",
				Operation: pathItem.Options,
			})
		}
		if pathItem.Head != nil {
			ops = append(ops, EndpointOperation{
				Path:      path,
				Method:    "HEAD",
				Operation: pathItem.Head,
			})
		}
	}

	return ops
}

// EndpointOperation represents a single endpoint operation
type EndpointOperation struct {
	Path      string
	Method    string
	Operation *Operation
}

// GetBaseURL returns the first server URL from the spec
func (p *Parser) GetBaseURL(spec *Spec) string {
	if len(spec.Servers) > 0 {
		return strings.TrimSuffix(spec.Servers[0].URL, "/")
	}
	return ""
}
