package apispec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/api"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/openapi"
	"gopkg.in/yaml.v3"
)

const (
	// maxSpecSize is the maximum spec file size (50 MB).
	maxSpecSize int64 = 50 * 1024 * 1024

	// parseTimeout is the maximum time to parse a spec.
	parseTimeout = 30 * time.Second
)

// Parse loads and parses an API spec from a file path or URL.
// It detects the format automatically and returns a unified Spec.
func Parse(source string) (*Spec, error) {
	ctx, cancel := context.WithTimeout(context.Background(), parseTimeout)
	defer cancel()
	return ParseContext(ctx, source)
}

// ParseContent parses inline spec content (YAML or JSON string) without
// requiring a file on disk. The sourceName is used for error messages and
// format hints (e.g. "inline.yaml").
func ParseContent(content string) (*Spec, error) {
	ctx, cancel := context.WithTimeout(context.Background(), parseTimeout)
	defer cancel()
	return ParseContentContext(ctx, content)
}

// ParseContentContext parses inline spec content with a caller-provided context.
func ParseContentContext(ctx context.Context, content string) (*Spec, error) {
	data := []byte(content)
	format := detectFormat(data, "inline")

	type result struct {
		spec *Spec
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		s, e := parseByFormat(data, "inline", format)
		ch <- result{s, e}
	}()

	select {
	case <-ctx.Done():
		return nil, ErrParseTimeout
	case r := <-ch:
		return r.spec, r.err
	}
}

// ParseContext loads and parses with a caller-provided context.
func ParseContext(ctx context.Context, source string) (*Spec, error) {
	data, err := loadSource(ctx, source)
	if err != nil {
		return nil, err
	}

	format := detectFormat(data, source)

	type result struct {
		spec *Spec
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		s, e := parseByFormat(data, source, format)
		ch <- result{s, e}
	}()

	select {
	case <-ctx.Done():
		return nil, ErrParseTimeout
	case r := <-ch:
		return r.spec, r.err
	}
}

// loadSource reads spec data from a file path or URL.
func loadSource(ctx context.Context, source string) ([]byte, error) {
	if isURL(source) {
		return loadURL(ctx, source)
	}
	return loadFile(source)
}

// loadFile reads a spec from the local filesystem with size enforcement.
// Uses io.LimitReader to enforce the size limit during read, avoiding
// a TOCTOU gap between stat and read.
func loadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open spec file: %w", err)
	}
	defer f.Close()

	// Read up to maxSpecSize+1 so we can detect oversized files.
	data, err := io.ReadAll(io.LimitReader(f, maxSpecSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}
	if int64(len(data)) > maxSpecSize {
		return nil, ErrSpecTooLarge
	}
	return data, nil
}

// loadURL fetches a spec from a URL with size validation.
func loadURL(ctx context.Context, specURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for spec URL: %w", err)
	}

	resp, err := httpclient.Default().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch spec URL: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spec URL returned status %d", resp.StatusCode)
	}

	// Use a large body limit since specs can be big
	data, err := iohelper.ReadBody(resp.Body, maxSpecSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec response: %w", err)
	}
	return data, nil
}

// isURL returns true if source looks like a URL (has http/https scheme).
func isURL(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

// detectFormat examines the raw data and source path to determine
// the spec format. Does not validate — just identifies.
func detectFormat(data []byte, source string) Format {
	// Try JSON first (faster)
	if json.Valid(data) {
		return detectFormatJSON(data)
	}

	// Try YAML
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err == nil {
		return detectFormatMap(doc)
	}

	// Check file extension as fallback
	ext := strings.ToLower(filepath.Ext(source))
	switch ext {
	case ".har":
		return FormatHAR
	case ".proto":
		return FormatGRPC
	}

	return FormatUnknown
}

// detectFormatJSON unmarshals JSON and checks for format markers.
func detectFormatJSON(data []byte) Format {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return FormatUnknown
	}
	return detectFormatMap(doc)
}

// detectFormatMap inspects a parsed document for format-specific keys.
func detectFormatMap(doc map[string]any) Format {
	// OpenAPI 3.x
	if v, ok := doc["openapi"].(string); ok && strings.HasPrefix(v, "3.") {
		return FormatOpenAPI3
	}

	// Swagger 2.0
	if v, ok := doc["swagger"].(string); ok && v == "2.0" {
		return FormatSwagger2
	}

	// Postman Collection v2.x
	if info, ok := doc["info"].(map[string]any); ok {
		if schema, ok := info["schema"].(string); ok {
			if strings.Contains(schema, "postman") {
				return FormatPostman
			}
		}
		// _postman_id is another marker
		if _, ok := info["_postman_id"]; ok {
			return FormatPostman
		}
	}

	// HAR file
	if _, ok := doc["log"]; ok {
		// HAR files have a top-level "log" key with "entries"
		if log, ok := doc["log"].(map[string]any); ok {
			if _, ok := log["entries"]; ok {
				return FormatHAR
			}
		}
	}

	// AsyncAPI
	if v, ok := doc["asyncapi"].(string); ok && strings.HasPrefix(v, "2.") {
		return FormatAsyncAPI
	}

	// GraphQL introspection result
	if _, ok := doc["data"]; ok {
		if data, ok := doc["data"].(map[string]any); ok {
			if _, ok := data["__schema"]; ok {
				return FormatGraphQL
			}
		}
	}

	return FormatUnknown
}

// parseByFormat dispatches to the format-specific parser.
func parseByFormat(data []byte, source string, format Format) (*Spec, error) {
	switch format {
	case FormatOpenAPI3:
		return parseOpenAPI3(data, source)
	case FormatSwagger2:
		return parseSwagger2(data, source)
	case FormatPostman:
		return parsePostman(data, source)
	case FormatHAR:
		return parseHAR(data, source)
	case FormatAsyncAPI:
		return ParseAsyncAPI(string(data))
	case FormatGraphQL:
		return nil, fmt.Errorf("%w: GraphQL specs require introspection — use IntrospectionToSpec(ctx, endpoint) instead of Parse()", ErrUnsupportedFormat)
	case FormatGRPC:
		return nil, fmt.Errorf("%w: gRPC specs require reflection — use ReflectionToSpec(ctx, addr) instead of Parse()", ErrUnsupportedFormat)
	default:
		return nil, fmt.Errorf("%w: detected %q from %s", ErrUnsupportedFormat, format, source)
	}
}

// parseOpenAPI3 wraps pkg/openapi/ types into the unified Spec.
func parseOpenAPI3(data []byte, source string) (*Spec, error) {
	parser := openapi.NewParser()

	var oaSpec *openapi.Spec
	var err error

	if json.Valid(data) {
		oaSpec, err = parser.ParseJSON(data)
	} else {
		oaSpec, err = parser.ParseYAML(data)
	}
	if err != nil {
		return nil, fmt.Errorf("openapi3 parse: %w", err)
	}

	spec := &Spec{
		Format:      FormatOpenAPI3,
		Title:       oaSpec.Info.Title,
		Description: oaSpec.Info.Description,
		Version:     oaSpec.Info.Version,
		SpecVersion: oaSpec.OpenAPI,
		Source:      source,
		ParsedAt:    time.Now(),
		Variables:   make(map[string]Variable),
	}

	// Convert servers
	for _, s := range oaSpec.Servers {
		spec.Servers = append(spec.Servers, Server{
			URL:         s.URL,
			Description: s.Description,
		})
	}

	// Extract security schemes
	if oaSpec.Components != nil && oaSpec.Components.SecuritySchemes != nil {
		schemeNames := make([]string, 0, len(oaSpec.Components.SecuritySchemes))
		for name := range oaSpec.Components.SecuritySchemes {
			schemeNames = append(schemeNames, name)
		}
		sort.Strings(schemeNames)
		for _, name := range schemeNames {
			ss := oaSpec.Components.SecuritySchemes[name]
			spec.AuthSchemes = append(spec.AuthSchemes, convertOA3SecurityScheme(name, ss))
		}
	}

	// Convert operations to endpoints
	ops := parser.GetOperations(oaSpec)
	tagSet := make(map[string]bool)
	for _, op := range ops {
		ep := convertOA3Operation(op, parser, oaSpec)

		// Apply spec-level security as defaults for operations without their own.
		if len(ep.Auth) == 0 && len(oaSpec.Security) > 0 {
			for _, secReq := range oaSpec.Security {
				names := make([]string, 0, len(secReq))
				for schemeName := range secReq {
					names = append(names, schemeName)
				}
				sort.Strings(names)
				ep.Auth = append(ep.Auth, names...)
			}
		}

		spec.Endpoints = append(spec.Endpoints, ep)
		for _, tag := range op.Operation.Tags {
			tagSet[tag] = true
		}
	}

	// Copy server variables.
	for _, s := range oaSpec.Servers {
		for k, v := range s.Variables {
			spec.Variables[k] = Variable{
				Default:     v.Default,
				Description: v.Description,
				Enum:        v.Enum,
			}
		}
	}

	// Build groups from tags (sorted for deterministic output).
	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		spec.Groups = append(spec.Groups, Group{Name: tag})
	}

	return spec, nil
}

// convertOA3SecurityScheme converts an OpenAPI 3 security scheme.
func convertOA3SecurityScheme(name string, ss *openapi.SecurityScheme) AuthScheme {
	as := AuthScheme{
		Name:         name,
		Scheme:       ss.Scheme,
		BearerFormat: ss.BearerFormat,
	}

	switch ss.Type {
	case "http":
		if strings.EqualFold(ss.Scheme, "bearer") {
			as.Type = AuthBearer
		} else {
			as.Type = AuthBasic
		}
	case "apiKey":
		as.Type = AuthAPIKey
		as.FieldName = ss.Name
		as.In = Location(ss.In)
	case "oauth2":
		as.Type = AuthOAuth2
		if ss.Flows != nil {
			as.Flows = convertOA3OAuthFlows(ss.Flows)
		}
	case "openIdConnect":
		as.Type = AuthOAuth2 // Treat as OAuth2 variant.
	default:
		as.Type = AuthCustom
	}

	return as
}

// convertOA3OAuthFlows converts OpenAPI 3 OAuth2 flows to unified OAuthFlow.
func convertOA3OAuthFlows(flows *openapi.OAuthFlows) []OAuthFlow {
	var result []OAuthFlow
	addFlow := func(name string, f *openapi.OAuthFlow) {
		if f == nil {
			return
		}
		result = append(result, OAuthFlow{
			Type:       name,
			AuthURL:    f.AuthorizationURL,
			TokenURL:   f.TokenURL,
			RefreshURL: f.RefreshURL,
			Scopes:     f.Scopes,
		})
	}
	addFlow("implicit", flows.Implicit)
	addFlow("password", flows.Password)
	addFlow("clientCredentials", flows.ClientCredentials)
	addFlow("authorizationCode", flows.AuthorizationCode)
	return result
}

// convertOA3Operation converts an OpenAPI 3 operation to a unified Endpoint.
func convertOA3Operation(op openapi.EndpointOperation, parser *openapi.Parser, oaSpec *openapi.Spec) Endpoint {
	ep := Endpoint{
		Method:         strings.ToUpper(op.Method),
		Path:           op.Path,
		OperationID:    op.Operation.OperationID,
		Summary:        op.Operation.Summary,
		Description:    op.Operation.Description,
		Tags:           op.Operation.Tags,
		CorrelationTag: CorrelationTag(op.Method, op.Path),
		RequestBodies:  make(map[string]RequestBody),
		Responses:      make(map[string]Response),
	}

	if len(op.Operation.Tags) > 0 {
		ep.Group = op.Operation.Tags[0]
	}

	// Convert parameters
	for _, p := range op.Operation.Parameters {
		ep.Parameters = append(ep.Parameters, convertOA3Parameter(p, parser, oaSpec))
	}

	// Convert request body
	if rb := op.Operation.RequestBody; rb != nil {
		for contentType, mt := range rb.Content {
			ep.ContentTypes = append(ep.ContentTypes, contentType)
			body := RequestBody{
				Description: rb.Description,
				Required:    rb.Required,
				Example:     mt.Example,
			}
			if mt.Schema != nil {
				body.Schema = convertOA3Schema(mt.Schema, parser, oaSpec)
			}
			ep.RequestBodies[contentType] = body
		}
	}

	// Convert responses
	for code, resp := range op.Operation.Responses {
		r := Response{
			Description: resp.Description,
		}
		if len(resp.Content) > 0 {
			r.Content = make(map[string]SchemaInfo)
			for ct, mt := range resp.Content {
				if mt.Schema != nil {
					r.Content[ct] = convertOA3Schema(mt.Schema, parser, oaSpec)
				}
			}
		}
		if len(resp.Headers) > 0 {
			r.Headers = make(map[string]Parameter)
			for hname, hparam := range resp.Headers {
				r.Headers[hname] = convertOA3Parameter(hparam, parser, oaSpec)
			}
		}
		ep.Responses[code] = r
	}

	// Convert security requirements to auth references
	for _, secReq := range op.Operation.Security {
		for schemeName := range secReq {
			ep.Auth = append(ep.Auth, schemeName)
		}
	}

	return ep
}

// convertOA3Parameter converts an OpenAPI 3 parameter.
func convertOA3Parameter(p openapi.Parameter, parser *openapi.Parser, oaSpec *openapi.Spec) Parameter {
	// Resolve parameter $ref.
	resolved := p
	if p.Ref != "" {
		if r := parser.ResolveParamRef(oaSpec, p.Ref); r != nil {
			resolved = *r
		}
	}

	param := Parameter{
		Name:          resolved.Name,
		In:            Location(resolved.In),
		Description:   resolved.Description,
		Required:      resolved.Required,
		Example:       resolved.Example,
		Style:         resolved.Style,
		AllowReserved: resolved.AllowReserved,
		Deprecated:    resolved.Deprecated,
	}
	if resolved.Explode != nil {
		param.Explode = resolved.Explode
	}

	if resolved.Schema != nil {
		schema := resolved.Schema
		if schema.Ref != "" {
			if r := parser.ResolveRef(oaSpec, schema.Ref); r != nil {
				schema = r
			}
		}
		param.Schema = convertOA3Schema(schema, parser, oaSpec)
		if schema.Enum != nil {
			for _, e := range schema.Enum {
				param.Enum = append(param.Enum, fmt.Sprintf("%v", e))
			}
		}
	}

	return param
}

// convertOA3Schema converts an OpenAPI 3 Schema to SchemaInfo.
func convertOA3Schema(s *openapi.Schema, parser *openapi.Parser, oaSpec *openapi.Spec) SchemaInfo {
	return convertOA3SchemaWithDepth(s, parser, oaSpec, make(map[string]bool), 0)
}

// maxSchemaDepth prevents stack overflow on deeply nested or circular schemas.
const maxSchemaDepth = 20

// convertOA3SchemaWithDepth converts with circular reference protection.
func convertOA3SchemaWithDepth(s *openapi.Schema, parser *openapi.Parser, oaSpec *openapi.Spec, seen map[string]bool, depth int) SchemaInfo {
	if s == nil || depth > maxSchemaDepth {
		return SchemaInfo{}
	}

	// Resolve $ref with circular detection.
	resolved := s
	if s.Ref != "" {
		if seen[s.Ref] {
			// Circular reference — return a placeholder instead of recursing.
			return SchemaInfo{Type: "object", Format: "circular-ref:" + s.Ref}
		}
		seen[s.Ref] = true
		defer delete(seen, s.Ref)

		if r := parser.ResolveRef(oaSpec, s.Ref); r != nil {
			resolved = r
		}
	}

	si := SchemaInfo{
		Type:      resolved.Type,
		Format:    resolved.Format,
		Pattern:   resolved.Pattern,
		MinLength: resolved.MinLength,
		MaxLength: resolved.MaxLength,
		Minimum:   resolved.Minimum,
		Maximum:   resolved.Maximum,
		Required:  resolved.Required,
		Nullable:  resolved.Nullable,
		ReadOnly:  resolved.ReadOnly,
		WriteOnly: resolved.WriteOnly,
	}

	// Discriminator.
	if resolved.Discriminator != nil {
		si.Discriminator = resolved.Discriminator.PropertyName
	}

	if resolved.Enum != nil {
		for _, e := range resolved.Enum {
			si.Enum = append(si.Enum, fmt.Sprintf("%v", e))
		}
	}

	// Convert properties (recurse)
	if len(resolved.Properties) > 0 {
		si.Properties = make(map[string]SchemaInfo)
		for name, prop := range resolved.Properties {
			si.Properties[name] = convertOA3SchemaWithDepth(prop, parser, oaSpec, seen, depth+1)
		}
	}

	// Convert items (array schema)
	if resolved.Items != nil {
		items := convertOA3SchemaWithDepth(resolved.Items, parser, oaSpec, seen, depth+1)
		si.Items = &items
	}

	// Convert composition keywords.
	for _, sub := range resolved.AllOf {
		si.AllOf = append(si.AllOf, convertOA3SchemaWithDepth(sub, parser, oaSpec, seen, depth+1))
	}
	for _, sub := range resolved.OneOf {
		si.OneOf = append(si.OneOf, convertOA3SchemaWithDepth(sub, parser, oaSpec, seen, depth+1))
	}
	for _, sub := range resolved.AnyOf {
		si.AnyOf = append(si.AnyOf, convertOA3SchemaWithDepth(sub, parser, oaSpec, seen, depth+1))
	}

	return si
}

// parseSwagger2 wraps pkg/api/ types into the unified Spec.
func parseSwagger2(data []byte, source string) (*Spec, error) {
	parser := api.NewParser()
	apiSpec, err := parser.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("swagger2 parse: %w", err)
	}

	spec := &Spec{
		Format:      FormatSwagger2,
		Title:       apiSpec.Title,
		SpecVersion: apiSpec.Version,
		Source:      source,
		ParsedAt:    time.Now(),
		Variables:   make(map[string]Variable),
	}

	// Build base URL from host + basePath.
	// Prefer scheme-qualified servers from the parser when available.
	for _, s := range apiSpec.Servers {
		spec.Servers = append(spec.Servers, Server{URL: s})
	}
	if len(spec.Servers) == 0 && apiSpec.Host != "" {
		baseURL := "https://" + apiSpec.Host
		if apiSpec.BasePath != "" {
			baseURL += apiSpec.BasePath
		}
		spec.Servers = append(spec.Servers, Server{URL: baseURL})
	}

	// Convert security schemes
	for _, ss := range apiSpec.Security {
		spec.AuthSchemes = append(spec.AuthSchemes, convertSwagger2Security(ss))
	}

	// Convert routes to endpoints
	tagSet := make(map[string]bool)
	for _, route := range apiSpec.Routes {
		ep := convertSwagger2Route(route)
		spec.Endpoints = append(spec.Endpoints, ep)
		for _, tag := range route.Tags {
			tagSet[tag] = true
		}
	}

	// Build groups from tags
	for tag := range tagSet {
		spec.Groups = append(spec.Groups, Group{Name: tag})
	}

	return spec, nil
}

// convertSwagger2Security converts a Swagger 2.0 security scheme.
func convertSwagger2Security(ss api.SecurityScheme) AuthScheme {
	as := AuthScheme{
		Name:   ss.Name,
		Scheme: ss.Scheme,
	}
	switch ss.Type {
	case "http", "basic":
		as.Type = AuthBasic
	case "apiKey":
		as.Type = AuthAPIKey
		as.In = Location(ss.In)
		as.FieldName = ss.Name
	case "oauth2":
		as.Type = AuthOAuth2
	default:
		as.Type = AuthCustom
	}
	return as
}

// convertSwagger2Route converts a Swagger 2.0 route to a unified Endpoint.
func convertSwagger2Route(route api.Route) Endpoint {
	ep := Endpoint{
		Method:         strings.ToUpper(route.Method),
		Path:           route.Path,
		OperationID:    route.OperationID,
		Summary:        route.Summary,
		Tags:           route.Tags,
		Deprecated:     route.Deprecated,
		CorrelationTag: CorrelationTag(route.Method, route.Path),
		RequestBodies:  make(map[string]RequestBody),
		Responses:      make(map[string]Response),
	}

	if len(route.Tags) > 0 {
		ep.Group = route.Tags[0]
	}

	// Convert parameters
	for _, p := range route.Parameters {
		ep.Parameters = append(ep.Parameters, convertSwagger2Parameter(p))
	}

	// Convert request body (from Swagger 2 explicit RequestBody, which was
	// promoted from body parameters in parseSwagger2Paths).
	if rb := route.RequestBody; rb != nil {
		ct := rb.ContentType
		if ct == "" {
			ct = "application/json"
		}
		ep.ContentTypes = append(ep.ContentTypes, ct)
		body := RequestBody{
			Required: rb.Required,
			Example:  rb.Example,
		}
		// Extract schema from the Swagger 2 raw schema map.
		if rb.Schema != nil {
			body.Schema = convertSwagger2Schema(rb.Schema)
		}
		ep.RequestBodies[ct] = body
	}

	// Convert content types
	for _, ct := range route.ContentType {
		if ct != "" {
			found := false
			for _, existing := range ep.ContentTypes {
				if existing == ct {
					found = true
					break
				}
			}
			if !found {
				ep.ContentTypes = append(ep.ContentTypes, ct)
			}
		}
	}

	// Security
	ep.Auth = route.Security

	return ep
}

// convertSwagger2Parameter converts a Swagger 2.0 parameter.
func convertSwagger2Parameter(p api.Parameter) Parameter {
	param := Parameter{
		Name:        p.Name,
		In:          Location(p.In),
		Description: p.Description,
		Required:    p.Required,
		Example:     p.Example,
		Default:     p.Default,
		Enum:        p.Enum,
		Schema: SchemaInfo{
			Type:   p.Type,
			Format: p.Format,
		},
	}
	return param
}

// convertSwagger2Schema converts a raw Swagger 2 schema map to SchemaInfo.
func convertSwagger2Schema(raw map[string]interface{}) SchemaInfo {
	return convertSwagger2SchemaDepth(raw, 0)
}

// convertSwagger2SchemaDepth converts with depth protection against
// deeply nested or circular inline schemas in Swagger 2.0 specs.
func convertSwagger2SchemaDepth(raw map[string]interface{}, depth int) SchemaInfo {
	if depth > maxSchemaDepth {
		return SchemaInfo{}
	}
	si := SchemaInfo{}
	if t, ok := raw["type"].(string); ok {
		si.Type = t
	}
	if f, ok := raw["format"].(string); ok {
		si.Format = f
	}
	if p, ok := raw["pattern"].(string); ok {
		si.Pattern = p
	}
	if props, ok := raw["properties"].(map[string]interface{}); ok {
		si.Properties = make(map[string]SchemaInfo, len(props))
		for name, prop := range props {
			if propMap, ok := prop.(map[string]interface{}); ok {
				si.Properties[name] = convertSwagger2SchemaDepth(propMap, depth+1)
			}
		}
	}
	if items, ok := raw["items"].(map[string]interface{}); ok {
		itemSchema := convertSwagger2SchemaDepth(items, depth+1)
		si.Items = &itemSchema
	}
	if req, ok := raw["required"].([]interface{}); ok {
		for _, r := range req {
			if s, ok := r.(string); ok {
				si.Required = append(si.Required, s)
			}
		}
	}
	if enum, ok := raw["enum"].([]interface{}); ok {
		for _, e := range enum {
			si.Enum = append(si.Enum, fmt.Sprintf("%v", e))
		}
	}
	return si
}

// ResolveBaseURL determines the effective base URL considering
// server list and target override.
func ResolveBaseURL(spec *Spec, targetOverride string) string {
	if targetOverride != "" {
		return strings.TrimSuffix(targetOverride, "/")
	}
	if len(spec.Servers) > 0 {
		return strings.TrimSuffix(spec.Servers[0].URL, "/")
	}
	return ""
}

// ResolveVariables applies variable substitutions to the spec.
// Precedence: cliVars override envVars override spec defaults.
func ResolveVariables(spec *Spec, cliVars map[string]string, envVars map[string]string) {
	if spec.Variables == nil {
		spec.Variables = make(map[string]Variable)
	}

	// Apply env vars first (lower precedence)
	for k, v := range envVars {
		if existing, ok := spec.Variables[k]; ok {
			existing.Value = v
			spec.Variables[k] = existing
		} else {
			spec.Variables[k] = Variable{Value: v}
		}
	}

	// Apply CLI vars (highest precedence)
	for k, v := range cliVars {
		if existing, ok := spec.Variables[k]; ok {
			existing.Value = v
			spec.Variables[k] = existing
		} else {
			spec.Variables[k] = Variable{Value: v}
		}
	}

	// Apply resolved values to server URLs
	for i, server := range spec.Servers {
		resolved := server.URL
		for k, v := range spec.Variables {
			val := v.Value
			if val == "" {
				val = v.Default
			}
			if val != "" {
				resolved = strings.ReplaceAll(resolved, "{{"+k+"}}", val)
				resolved = strings.ReplaceAll(resolved, "{"+k+"}", val)
			}
		}
		spec.Servers[i].URL = resolved
	}
}

// SubstituteVariables replaces {{var}} patterns in a string using the spec's variables.
func SubstituteVariables(s string, vars map[string]Variable) string {
	for k, v := range vars {
		val := v.Value
		if val == "" {
			val = v.Default
		}
		if val != "" {
			s = strings.ReplaceAll(s, "{{"+k+"}}", val)
		}
	}
	return s
}

// Validate performs basic structural validation on a parsed Spec.
// For full security validation, use ValidateSpec().
func (s *Spec) Validate() error {
	if s.Format == FormatUnknown || s.Format == "" {
		return fmt.Errorf("%w: format not set", ErrInvalidSpec)
	}
	return nil
}

// FilterEndpoints returns endpoints matching the given predicate.
func (s *Spec) FilterEndpoints(fn func(Endpoint) bool) []Endpoint {
	var result []Endpoint
	for _, ep := range s.Endpoints {
		if fn(ep) {
			result = append(result, ep)
		}
	}
	return result
}

// HasPathParams returns true if the endpoint path contains template parameters.
func (e *Endpoint) HasPathParams() bool {
	return strings.Contains(e.Path, "{")
}

// FullPath returns the endpoint's full URL given a base URL.
func (e *Endpoint) FullPath(baseURL string) string {
	base := strings.TrimSuffix(baseURL, "/")
	path := e.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}
