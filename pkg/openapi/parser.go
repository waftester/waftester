// Package openapi provides OpenAPI specification parsing and test generation
package openapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
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
	Security   []SecurityReq       `json:"security,omitempty" yaml:"security,omitempty"`
}

// Info contains API metadata
type Info struct {
	Title       string `json:"title" yaml:"title"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Version     string `json:"version" yaml:"version"`
}

// Server represents a server definition
type Server struct {
	URL         string                    `json:"url" yaml:"url"`
	Description string                    `json:"description,omitempty" yaml:"description,omitempty"`
	Variables   map[string]ServerVariable `json:"variables,omitempty" yaml:"variables,omitempty"`
}

// ServerVariable represents a server variable with default and enum values.
type ServerVariable struct {
	Default     string   `json:"default" yaml:"default"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Enum        []string `json:"enum,omitempty" yaml:"enum,omitempty"`
}

// PathItem represents all operations for a path
type PathItem struct {
	Get        *Operation  `json:"get,omitempty" yaml:"get,omitempty"`
	Post       *Operation  `json:"post,omitempty" yaml:"post,omitempty"`
	Put        *Operation  `json:"put,omitempty" yaml:"put,omitempty"`
	Delete     *Operation  `json:"delete,omitempty" yaml:"delete,omitempty"`
	Patch      *Operation  `json:"patch,omitempty" yaml:"patch,omitempty"`
	Options    *Operation  `json:"options,omitempty" yaml:"options,omitempty"`
	Head       *Operation  `json:"head,omitempty" yaml:"head,omitempty"`
	Parameters []Parameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
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
	Name          string  `json:"name" yaml:"name"`
	In            string  `json:"in" yaml:"in"` // query, path, header, cookie
	Description   string  `json:"description,omitempty" yaml:"description,omitempty"`
	Required      bool    `json:"required,omitempty" yaml:"required,omitempty"`
	Schema        *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example       any     `json:"example,omitempty" yaml:"example,omitempty"`
	Style         string  `json:"style,omitempty" yaml:"style,omitempty"`
	Explode       *bool   `json:"explode,omitempty" yaml:"explode,omitempty"`
	AllowReserved bool    `json:"allowReserved,omitempty" yaml:"allowReserved,omitempty"`
	Deprecated    bool    `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
	Ref           string  `json:"$ref,omitempty" yaml:"$ref,omitempty"`
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

	// Composition keywords.
	AllOf         []*Schema      `json:"allOf,omitempty" yaml:"allOf,omitempty"`
	OneOf         []*Schema      `json:"oneOf,omitempty" yaml:"oneOf,omitempty"`
	AnyOf         []*Schema      `json:"anyOf,omitempty" yaml:"anyOf,omitempty"`
	Discriminator *Discriminator `json:"discriminator,omitempty" yaml:"discriminator,omitempty"`

	// Read/write hints.
	Nullable  bool `json:"nullable,omitempty" yaml:"nullable,omitempty"`
	ReadOnly  bool `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
	WriteOnly bool `json:"writeOnly,omitempty" yaml:"writeOnly,omitempty"`

	// Default value.
	Default any `json:"default,omitempty" yaml:"default,omitempty"`

	// Additional properties for map-like objects.
	AdditionalProperties *Schema `json:"additionalProperties,omitempty" yaml:"additionalProperties,omitempty"`
}

// Discriminator supports polymorphism in OpenAPI 3.
type Discriminator struct {
	PropertyName string            `json:"propertyName" yaml:"propertyName"`
	Mapping      map[string]string `json:"mapping,omitempty" yaml:"mapping,omitempty"`
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
	Type             string      `json:"type" yaml:"type"`
	Scheme           string      `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	BearerFormat     string      `json:"bearerFormat,omitempty" yaml:"bearerFormat,omitempty"`
	Name             string      `json:"name,omitempty" yaml:"name,omitempty"`
	In               string      `json:"in,omitempty" yaml:"in,omitempty"`
	Flows            *OAuthFlows `json:"flows,omitempty" yaml:"flows,omitempty"`
	OpenIDConnectURL string      `json:"openIdConnectUrl,omitempty" yaml:"openIdConnectUrl,omitempty"`
}

// OAuthFlows contains all OAuth2 flow definitions.
type OAuthFlows struct {
	Implicit          *OAuthFlow `json:"implicit,omitempty" yaml:"implicit,omitempty"`
	Password          *OAuthFlow `json:"password,omitempty" yaml:"password,omitempty"`
	ClientCredentials *OAuthFlow `json:"clientCredentials,omitempty" yaml:"clientCredentials,omitempty"`
	AuthorizationCode *OAuthFlow `json:"authorizationCode,omitempty" yaml:"authorizationCode,omitempty"`
}

// OAuthFlow represents a single OAuth2 flow.
type OAuthFlow struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty" yaml:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty" yaml:"tokenUrl,omitempty"`
	RefreshURL       string            `json:"refreshUrl,omitempty" yaml:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
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
func (p *Parser) ParseURL(targetURL string) (*Spec, error) {
	// Use context with 30 second timeout to prevent hanging on slow servers
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := httpclient.Default().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

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

	// Check cache (also breaks circular refs since we cache nil as sentinel).
	if schema, ok := p.resolvedSchemas[ref]; ok {
		return schema
	}

	// Mark as in-progress before recursing to break circular $ref chains.
	p.resolvedSchemas[ref] = nil

	// Parse reference path: #/components/schemas/User
	schemaPattern := regexcache.MustGet(`^#/components/schemas/(.+)$`)
	matches := schemaPattern.FindStringSubmatch(ref)
	if len(matches) == 2 {
		schemaName := matches[1]
		if spec.Components != nil && spec.Components.Schemas != nil {
			schema, ok := spec.Components.Schemas[schemaName]
			if ok && schema != nil {
				// Recursively resolve if schema has a ref
				if schema.Ref != "" {
					schema = p.ResolveRef(spec, schema.Ref)
				}
				p.resolvedSchemas[ref] = schema
				return schema
			}
		}
	}

	return nil
}

// ResolveParamRef resolves a $ref reference to a Parameter.
func (p *Parser) ResolveParamRef(spec *Spec, ref string) *Parameter {
	return p.resolveParamRefSeen(spec, ref, make(map[string]bool))
}

func (p *Parser) resolveParamRefSeen(spec *Spec, ref string, seen map[string]bool) *Parameter {
	if ref == "" || spec.Components == nil || spec.Components.Parameters == nil {
		return nil
	}
	if seen[ref] {
		return nil // break circular $ref
	}
	seen[ref] = true

	paramPattern := regexcache.MustGet(`^#/components/parameters/(.+)$`)
	matches := paramPattern.FindStringSubmatch(ref)
	if len(matches) != 2 {
		return nil
	}

	param, ok := spec.Components.Parameters[matches[1]]
	if !ok || param == nil {
		return nil
	}

	// Recursively resolve if param has a ref
	if param.Ref != "" {
		return p.resolveParamRefSeen(spec, param.Ref, seen)
	}

	return param
}

// GetOperations extracts all operations from a spec
func (p *Parser) GetOperations(spec *Spec) []EndpointOperation {
	var ops []EndpointOperation

	for path, pathItem := range spec.Paths {
		addOp := func(method string, op *Operation) {
			if op == nil {
				return
			}
			// Merge path-level parameters into operation parameters.
			// Operation params override path params with the same name+in.
			op.Parameters = mergeOA3Parameters(pathItem.Parameters, op.Parameters)
			ops = append(ops, EndpointOperation{
				Path:      path,
				Method:    method,
				Operation: op,
			})
		}
		addOp("GET", pathItem.Get)
		addOp("POST", pathItem.Post)
		addOp("PUT", pathItem.Put)
		addOp("DELETE", pathItem.Delete)
		addOp("PATCH", pathItem.Patch)
		addOp("OPTIONS", pathItem.Options)
		addOp("HEAD", pathItem.Head)
	}

	return ops
}

// mergeOA3Parameters merges path-level and operation-level parameters.
// Operation params override path params with the same name+in.
func mergeOA3Parameters(pathParams, opParams []Parameter) []Parameter {
	if len(pathParams) == 0 {
		return opParams
	}

	// Index operation params by name+in.
	opSet := make(map[string]bool, len(opParams))
	for _, p := range opParams {
		opSet[p.In+":"+p.Name] = true
	}

	// Start with operation params, then add non-overridden path params.
	merged := make([]Parameter, len(opParams))
	copy(merged, opParams)
	for _, p := range pathParams {
		if !opSet[p.In+":"+p.Name] {
			merged = append(merged, p)
		}
	}
	return merged
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

// ParseFromFile is a convenience function to parse an OpenAPI spec from a file
func ParseFromFile(path string) (*Spec, error) {
	p := NewParser()
	return p.ParseFile(path)
}

// ParseFromURL is a convenience function to parse an OpenAPI spec from a URL
func ParseFromURL(url string) (*Spec, error) {
	p := NewParser()
	return p.ParseURL(url)
}
