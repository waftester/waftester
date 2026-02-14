package apispec

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// Format identifies the source format of a parsed spec.
type Format string

const (
	FormatOpenAPI3 Format = "openapi3"
	FormatSwagger2 Format = "swagger2"
	FormatPostman  Format = "postman"
	FormatHAR      Format = "har"
	FormatGraphQL  Format = "graphql"
	FormatGRPC     Format = "grpc"
	FormatAsyncAPI Format = "asyncapi"
	FormatUnknown  Format = "unknown"
)

// Location identifies where a parameter is sent in the HTTP request.
type Location string

const (
	LocationQuery  Location = "query"
	LocationPath   Location = "path"
	LocationHeader Location = "header"
	LocationCookie Location = "cookie"
	LocationBody   Location = "body"
)

// AuthType identifies the authentication mechanism.
type AuthType string

const (
	AuthBearer AuthType = "bearer"
	AuthAPIKey AuthType = "apikey"
	AuthBasic  AuthType = "basic"
	AuthOAuth2 AuthType = "oauth2"
	AuthCustom AuthType = "custom"
)

// Priority indicates an endpoint's security testing importance.
type Priority int

const (
	PriorityLow    Priority = 1
	PriorityMedium Priority = 5
	PriorityHigh   Priority = 8
	PriorityCritical Priority = 10
)

// Intensity controls how deep the scanning goes.
type Intensity string

const (
	IntensityQuick    Intensity = "quick"
	IntensityNormal   Intensity = "normal"
	IntensityDeep     Intensity = "deep"
	IntensityParanoid Intensity = "paranoid"
)

// Spec is the unified representation of any API specification.
// Regardless of input format (OpenAPI 3.x, Swagger 2.0, Postman,
// HAR, etc.), Parse() produces this single type.
type Spec struct {
	// Format identifies the original source format.
	Format Format `json:"format"`

	// Title is the API title from the spec metadata.
	Title string `json:"title,omitempty"`

	// Description is the API description from the spec metadata.
	Description string `json:"description,omitempty"`

	// Version is the API version from the spec metadata (not the spec format version).
	Version string `json:"version,omitempty"`

	// SpecVersion is the spec format version (e.g., "3.0.3" for OpenAPI).
	SpecVersion string `json:"spec_version,omitempty"`

	// Servers contains base URL information. First entry is the default.
	// Use --target CLI flag to override.
	Servers []Server `json:"servers,omitempty"`

	// Endpoints is the list of API endpoints extracted from the spec.
	Endpoints []Endpoint `json:"endpoints"`

	// AuthSchemes describes authentication mechanisms declared in the spec.
	AuthSchemes []AuthScheme `json:"auth_schemes,omitempty"`

	// Variables contains spec-level variables (Postman collection variables,
	// OpenAPI server variables, environment overrides).
	Variables map[string]Variable `json:"variables,omitempty"`

	// Groups organizes endpoints by tag (OpenAPI) or folder (Postman).
	Groups []Group `json:"groups,omitempty"`

	// Source is the original file path or URL the spec was loaded from.
	Source string `json:"source,omitempty"`

	// ParsedAt is when the spec was parsed.
	ParsedAt time.Time `json:"parsed_at"`
}

// Server represents a base URL for the API.
type Server struct {
	URL         string              `json:"url"`
	Description string              `json:"description,omitempty"`
	Variables   map[string]Variable `json:"variables,omitempty"`
}

// Variable holds a variable definition with default and possible values.
type Variable struct {
	Default     string   `json:"default"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Value       string   `json:"value,omitempty"` // resolved value (from --var or env)
}

// Group organizes endpoints by logical grouping (OpenAPI tag or Postman folder).
type Group struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ParentName  string `json:"parent_name,omitempty"` // for nested Postman folders
}

// Endpoint represents a single API operation.
type Endpoint struct {
	// Method is the HTTP method (GET, POST, PUT, DELETE, PATCH, etc.).
	Method string `json:"method"`

	// Path is the URL path template (e.g., "/users/{id}").
	Path string `json:"path"`

	// OperationID is the unique identifier from the spec (operationId in OpenAPI).
	OperationID string `json:"operation_id,omitempty"`

	// Summary is a short description of what this endpoint does.
	Summary string `json:"summary,omitempty"`

	// Description is a longer description.
	Description string `json:"description,omitempty"`

	// Parameters is the list of inputs this endpoint accepts.
	Parameters []Parameter `json:"parameters,omitempty"`

	// RequestBodies maps content types to their request body definitions.
	RequestBodies map[string]RequestBody `json:"request_bodies,omitempty"`

	// ContentTypes lists the content types this endpoint accepts.
	ContentTypes []string `json:"content_types,omitempty"`

	// Responses maps status codes to response definitions.
	Responses map[string]Response `json:"responses,omitempty"`

	// Auth lists the authentication scheme names required for this endpoint.
	Auth []string `json:"auth,omitempty"`

	// Tags from OpenAPI or folder names from Postman.
	Tags []string `json:"tags,omitempty"`

	// Group is the primary group this endpoint belongs to.
	Group string `json:"group,omitempty"`

	// Priority indicates security testing importance (set by intelligence engine).
	Priority Priority `json:"priority,omitempty"`

	// Deprecated indicates the endpoint is deprecated.
	Deprecated bool `json:"deprecated,omitempty"`

	// DependsOn lists other endpoints that must be called first
	// (e.g., create user before get user).
	DependsOn []Dependency `json:"depends_on,omitempty"`

	// Examples contains example requests for this endpoint.
	Examples []Example `json:"examples,omitempty"`

	// PreRequirements lists setup steps (from Postman pre-request scripts, etc.).
	PreRequirements []string `json:"pre_requirements,omitempty"`

	// CorrelationTag is a stable identifier for cross-referencing findings
	// with WAF logs. Format: sha256(method + path)[:12].
	CorrelationTag string `json:"correlation_tag"`
}

// Parameter represents an input parameter — query, path, header, cookie, or body field.
type Parameter struct {
	Name        string     `json:"name"`
	In          Location   `json:"in"`
	Description string     `json:"description,omitempty"`
	Required    bool       `json:"required,omitempty"`
	Schema      SchemaInfo `json:"schema,omitempty"`
	Example     any        `json:"example,omitempty"`
	Default     any        `json:"default,omitempty"`
	Enum        []string   `json:"enum,omitempty"`

	// OpenAPI 3.x serialization parameters (Gap 113).
	Style         string `json:"style,omitempty"`
	Explode       *bool  `json:"explode,omitempty"`
	AllowReserved bool   `json:"allow_reserved,omitempty"`

	// Deprecated indicates this parameter is deprecated (Gap 114).
	Deprecated bool `json:"deprecated,omitempty"`
}

// SchemaInfo captures type information for parameters and request bodies.
type SchemaInfo struct {
	Type       string       `json:"type,omitempty"`
	Format     string       `json:"format,omitempty"`
	Pattern    string       `json:"pattern,omitempty"`
	MinLength  *int         `json:"min_length,omitempty"`
	MaxLength  *int         `json:"max_length,omitempty"`
	Minimum    *float64     `json:"minimum,omitempty"`
	Maximum    *float64     `json:"maximum,omitempty"`
	Enum       []string     `json:"enum,omitempty"`
	Properties map[string]SchemaInfo `json:"properties,omitempty"`
	Items      *SchemaInfo  `json:"items,omitempty"`
	Required   []string     `json:"required,omitempty"`

	// Composition (Gap 119).
	AllOf         []SchemaInfo `json:"all_of,omitempty"`
	OneOf         []SchemaInfo `json:"one_of,omitempty"`
	AnyOf         []SchemaInfo `json:"any_of,omitempty"`
	Discriminator string       `json:"discriminator,omitempty"`

	// Read/write hints (Gap 118).
	Nullable  bool `json:"nullable,omitempty"`
	ReadOnly  bool `json:"read_only,omitempty"`
	WriteOnly bool `json:"write_only,omitempty"`
}

// RequestBody defines the body payload for a specific content type.
type RequestBody struct {
	Description string     `json:"description,omitempty"`
	Required    bool       `json:"required,omitempty"`
	Schema      SchemaInfo `json:"schema,omitempty"`
	Example     any        `json:"example,omitempty"`
}

// Response describes an API response for a specific status code.
type Response struct {
	Description string               `json:"description,omitempty"`
	Content     map[string]SchemaInfo `json:"content,omitempty"`
	Headers     map[string]Parameter `json:"headers,omitempty"`
	Links       map[string]Link      `json:"links,omitempty"`
}

// Link represents an OpenAPI 3.x link object.
type Link struct {
	OperationID string         `json:"operation_id,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Description string         `json:"description,omitempty"`
}

// AuthScheme describes an authentication mechanism declared in the spec.
type AuthScheme struct {
	Name         string      `json:"name"`
	Type         AuthType    `json:"type"`
	Scheme       string      `json:"scheme,omitempty"`       // "bearer", "basic", etc.
	BearerFormat string      `json:"bearer_format,omitempty"`
	In           Location    `json:"in,omitempty"`           // for apikey: query, header, cookie
	FieldName    string      `json:"field_name,omitempty"`   // for apikey: header/query param name
	Flows        []OAuthFlow `json:"flows,omitempty"`        // for oauth2
}

// OAuthFlow describes an OAuth 2.0 flow (Gap 115).
type OAuthFlow struct {
	Type       string            `json:"type"` // implicit, password, clientCredentials, authorizationCode
	AuthURL    string            `json:"auth_url,omitempty"`
	TokenURL   string            `json:"token_url,omitempty"`
	RefreshURL string            `json:"refresh_url,omitempty"`
	Scopes     map[string]string `json:"scopes,omitempty"`
}

// Dependency expresses an ordering requirement between endpoints.
type Dependency struct {
	OperationID string `json:"operation_id"`
	Description string `json:"description,omitempty"`
}

// Example contains a sample request for an endpoint.
type Example struct {
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Body        any               `json:"body,omitempty"`
}

// SpecExecutor is the interface for executing a scan plan against parsed
// endpoints. P1 implements SimpleExecutor; P4 replaces it with AdaptiveExecutor.
type SpecExecutor interface {
	Execute(ctx interface{}, plan *ScanPlan) (*ScanSession, error)
}

// ScanPlan holds the complete test plan generated from a spec.
type ScanPlan struct {
	// Entries is the ordered list of scan operations.
	Entries []ScanPlanEntry `json:"entries"`

	// TotalTests is the estimated total number of individual test payloads.
	TotalTests int `json:"total_tests"`

	// EstimatedDuration is the estimated wall-clock time.
	EstimatedDuration time.Duration `json:"estimated_duration"`

	// Intensity is the scanning depth.
	Intensity Intensity `json:"intensity"`

	// SpecSource identifies which spec this plan was generated from.
	SpecSource string `json:"spec_source"`
}

// ScanPlanEntry is a single item in the scan plan: one attack type
// against one endpoint at one injection target.
type ScanPlanEntry struct {
	Endpoint        Endpoint        `json:"endpoint"`
	Attack          AttackSelection `json:"attack"`
	InjectionTarget InjectionTarget `json:"injection_target"`
}

// AttackSelection describes which attack to run and with how many payloads.
type AttackSelection struct {
	Category     string   `json:"category"`      // e.g., "sqli", "xss", "ssrf"
	Reason       string   `json:"reason"`         // why selected (for preview)
	PayloadCount int      `json:"payload_count"`
	Layers       []string `json:"layers"`         // which intelligence layers selected this
}

// InjectionTarget identifies where to inject payloads.
type InjectionTarget struct {
	Parameter   string   `json:"parameter"`
	Location    Location `json:"location"`
	ContentType string   `json:"content_type,omitempty"`
}

// ScanSession holds the results of executing a scan plan.
type ScanSession struct {
	ID              string        `json:"id"`
	StartedAt       time.Time     `json:"started_at"`
	CompletedAt     time.Time     `json:"completed_at"`
	Duration        time.Duration `json:"duration"`
	TotalEndpoints  int           `json:"total_endpoints"`
	TotalTests      int           `json:"total_tests"`
	TotalFindings   int           `json:"total_findings"`
	SpecSource      string        `json:"spec_source"`
}

// CorrelationTag generates a stable, deterministic identifier for an endpoint.
// Format: first 12 hex chars of SHA-256(METHOD + " " + path).
func CorrelationTag(method, path string) string {
	h := sha256.Sum256([]byte(strings.ToUpper(method) + " " + path))
	return fmt.Sprintf("%x", h[:6])
}

// BaseURL returns the first server URL from the spec, or empty string.
func (s *Spec) BaseURL() string {
	if len(s.Servers) == 0 {
		return ""
	}
	return s.Servers[0].URL
}

// EndpointsByGroup returns endpoints filtered by group name.
func (s *Spec) EndpointsByGroup(group string) []Endpoint {
	var result []Endpoint
	for _, ep := range s.Endpoints {
		if ep.Group == group {
			result = append(result, ep)
		}
		for _, tag := range ep.Tags {
			if tag == group && ep.Group != group {
				result = append(result, ep)
				break
			}
		}
	}
	return result
}

// EndpointsByTag returns endpoints that have the given tag.
func (s *Spec) EndpointsByTag(tag string) []Endpoint {
	var result []Endpoint
	for _, ep := range s.Endpoints {
		for _, t := range ep.Tags {
			if t == tag {
				result = append(result, ep)
				break
			}
		}
	}
	return result
}
