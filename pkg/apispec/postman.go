package apispec

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Postman Collection v2.0/v2.1 internal types for JSON unmarshalling.
// These are not exported — Parse() converts them to unified Spec types.

type postmanCollection struct {
	Info  postmanInfo    `json:"info"`
	Item  []postmanItem  `json:"item"`
	Auth  *postmanAuth   `json:"auth,omitempty"`
	Event []postmanEvent `json:"event,omitempty"`

	// Collection-level variables.
	Variable []postmanVariable `json:"variable,omitempty"`
}

type postmanInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Schema      string `json:"schema"`
	PostmanID   string `json:"_postman_id,omitempty"`
	Version     string `json:"version,omitempty"`
}

// postmanItem represents either a folder (has Item) or a request (has Request).
type postmanItem struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Item        []postmanItem  `json:"item,omitempty"`
	Request     *postmanReq    `json:"request,omitempty"`
	Auth        *postmanAuth   `json:"auth,omitempty"`
	Event       []postmanEvent `json:"event,omitempty"`
}

type postmanReq struct {
	Method      string       `json:"method"`
	URL         postmanURL   `json:"url"`
	Header      []postmanKV  `json:"header,omitempty"`
	Body        *postmanBody `json:"body,omitempty"`
	Description string       `json:"description,omitempty"`
	Auth        *postmanAuth `json:"auth,omitempty"`
}

// postmanURL can be a string or an object with path, query, host, etc.
type postmanURL struct {
	Raw      string      `json:"raw,omitempty"`
	Protocol string      `json:"protocol,omitempty"`
	Host     []string    `json:"host,omitempty"`
	Path     []string    `json:"path,omitempty"`
	Query    []postmanKV `json:"query,omitempty"`
	Variable []postmanKV `json:"variable,omitempty"`
}

// UnmarshalJSON handles postmanURL being either a plain string or an object.
func (u *postmanURL) UnmarshalJSON(data []byte) error {
	// Try string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		u.Raw = s
		return nil
	}

	// Object form
	type alias postmanURL
	var obj alias
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("unmarshal postman URL: %w", err)
	}
	*u = postmanURL(obj)
	return nil
}

type postmanKV struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	Type        string `json:"type,omitempty"`
}

type postmanBody struct {
	Mode       string      `json:"mode"`
	Raw        string      `json:"raw,omitempty"`
	URLEncoded []postmanKV `json:"urlencoded,omitempty"`
	FormData   []postmanKV `json:"formdata,omitempty"`
	Options    *struct {
		Raw *struct {
			Language string `json:"language,omitempty"`
		} `json:"raw,omitempty"`
	} `json:"options,omitempty"`
}

type postmanAuth struct {
	Type   string      `json:"type"`
	Bearer []postmanKV `json:"bearer,omitempty"`
	Basic  []postmanKV `json:"basic,omitempty"`
	APIKey []postmanKV `json:"apikey,omitempty"`
	OAuth2 []postmanKV `json:"oauth2,omitempty"`
}

type postmanEvent struct {
	Listen string        `json:"listen"` // "prerequest" or "test"
	Script postmanScript `json:"script"`
}

type postmanScript struct {
	Type string   `json:"type,omitempty"`
	Exec []string `json:"exec,omitempty"`
}

type postmanVariable struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

// parsePostman parses a Postman Collection v2.0/v2.1 into a unified Spec.
func parsePostman(data []byte, source string) (*Spec, error) {
	var coll postmanCollection
	if err := json.Unmarshal(data, &coll); err != nil {
		return nil, fmt.Errorf("postman parse: %w", err)
	}

	spec := &Spec{
		Format:    FormatPostman,
		Title:     coll.Info.Name,
		Source:    source,
		ParsedAt:  time.Now(),
		Variables: make(map[string]Variable),
	}

	// Extract schema version
	if strings.Contains(coll.Info.Schema, "v2.1") {
		spec.SpecVersion = "2.1"
	} else if strings.Contains(coll.Info.Schema, "v2.0") {
		spec.SpecVersion = "2.0"
	}

	// Extract collection-level variables
	for _, v := range coll.Variable {
		spec.Variables[v.Key] = Variable{
			Default: v.Value,
			Value:   v.Value,
		}
	}

	// Extract collection-level auth
	var collectionAuth *postmanAuth
	if coll.Auth != nil {
		collectionAuth = coll.Auth
		spec.AuthSchemes = append(spec.AuthSchemes, convertPostmanAuth("collection", coll.Auth))
	}

	// Extract pre-request scripts at collection level
	var collectionPreReqs []string
	for _, event := range coll.Event {
		if event.Listen == "prerequest" && len(event.Script.Exec) > 0 {
			collectionPreReqs = append(collectionPreReqs, strings.Join(event.Script.Exec, "\n"))
		}
	}

	// Flatten nested items into endpoints
	flattenPostmanItems(spec, coll.Item, nil, collectionAuth, collectionPreReqs)

	return spec, nil
}

// flattenPostmanItems recursively walks Postman items, converting folders to
// groups and requests to endpoints. Auth inherits: collection -> folder -> request.
func flattenPostmanItems(
	spec *Spec,
	items []postmanItem,
	folderPath []string,
	inheritedAuth *postmanAuth,
	inheritedPreReqs []string,
) {
	for _, item := range items {
		if len(item.Item) > 0 {
			// Folder: recurse into children
			path := append(append([]string{}, folderPath...), item.Name)

			parentName := ""
			if len(folderPath) > 0 {
				parentName = folderPath[len(folderPath)-1]
			}

			spec.Groups = append(spec.Groups, Group{
				Name:        item.Name,
				Description: item.Description,
				ParentName:  parentName,
			})

			// Folder-level auth overrides inherited
			auth := inheritedAuth
			if item.Auth != nil {
				auth = item.Auth
			}

			// Folder-level pre-request scripts
			preReqs := inheritedPreReqs
			for _, event := range item.Event {
				if event.Listen == "prerequest" && len(event.Script.Exec) > 0 {
					preReqs = append(append([]string{}, preReqs...), strings.Join(event.Script.Exec, "\n"))
				}
			}

			flattenPostmanItems(spec, item.Item, path, auth, preReqs)
			continue
		}

		if item.Request == nil {
			continue
		}

		ep := convertPostmanRequest(item, spec.Variables, folderPath)

		// Auth inheritance: request > folder > collection
		effectiveAuth := inheritedAuth
		if item.Auth != nil {
			effectiveAuth = item.Auth
		}
		if item.Request.Auth != nil {
			effectiveAuth = item.Request.Auth
		}
		if effectiveAuth != nil {
			ep.Auth = []string{effectiveAuth.Type}
		}

		// Pre-request script inheritance
		ep.PreRequirements = append(ep.PreRequirements, inheritedPreReqs...)
		for _, event := range item.Event {
			if event.Listen == "prerequest" && len(event.Script.Exec) > 0 {
				ep.PreRequirements = append(ep.PreRequirements, strings.Join(event.Script.Exec, "\n"))
			}
		}

		spec.Endpoints = append(spec.Endpoints, ep)
	}
}

// convertPostmanRequest converts a Postman request item to a unified Endpoint.
func convertPostmanRequest(item postmanItem, vars map[string]Variable, folderPath []string) Endpoint {
	req := item.Request

	method := strings.ToUpper(req.Method)
	rawURL := resolvePostmanURL(req.URL, vars)
	path := extractPostmanPath(rawURL, vars)

	ep := Endpoint{
		Method:         method,
		Path:           path,
		Summary:        item.Name,
		Description:    req.Description,
		CorrelationTag: CorrelationTag(method, path),
		RequestBodies:  make(map[string]RequestBody),
		Responses:      make(map[string]Response),
	}

	if len(folderPath) > 0 {
		ep.Group = folderPath[len(folderPath)-1]
		ep.Tags = folderPath
	}

	// Query parameters (from URL object)
	for _, q := range req.URL.Query {
		if q.Disabled {
			continue
		}
		ep.Parameters = append(ep.Parameters, Parameter{
			Name:        q.Key,
			In:          LocationQuery,
			Description: q.Description,
			Example:     substituteVars(q.Value, vars),
		})
	}

	// Path variables (from URL object)
	for _, v := range req.URL.Variable {
		ep.Parameters = append(ep.Parameters, Parameter{
			Name:        v.Key,
			In:          LocationPath,
			Required:    true,
			Description: v.Description,
			Example:     substituteVars(v.Value, vars),
		})
	}

	// Headers
	for _, h := range req.Header {
		if h.Disabled {
			continue
		}
		ep.Parameters = append(ep.Parameters, Parameter{
			Name:        h.Key,
			In:          LocationHeader,
			Description: h.Description,
			Example:     substituteVars(h.Value, vars),
		})
	}

	// Request body
	if req.Body != nil {
		convertPostmanBody(req.Body, &ep, vars)
	}

	return ep
}

// convertPostmanBody converts a Postman body to request body entries.
func convertPostmanBody(body *postmanBody, ep *Endpoint, vars map[string]Variable) {
	switch body.Mode {
	case "raw":
		ct := "application/json"
		if body.Options != nil && body.Options.Raw != nil {
			switch body.Options.Raw.Language {
			case "xml":
				ct = "application/xml"
			case "text":
				ct = "text/plain"
			case "html":
				ct = "text/html"
			case "javascript":
				ct = "application/javascript"
			}
		}
		ep.ContentTypes = append(ep.ContentTypes, ct)
		ep.RequestBodies[ct] = RequestBody{
			Example: substituteVars(body.Raw, vars),
		}
	case "urlencoded":
		ct := "application/x-www-form-urlencoded"
		ep.ContentTypes = append(ep.ContentTypes, ct)
		schema := SchemaInfo{
			Type:       "object",
			Properties: make(map[string]SchemaInfo),
		}
		for _, kv := range body.URLEncoded {
			if kv.Disabled {
				continue
			}
			schema.Properties[kv.Key] = SchemaInfo{Type: "string"}
		}
		ep.RequestBodies[ct] = RequestBody{Schema: schema}
	case "formdata":
		ct := "multipart/form-data"
		ep.ContentTypes = append(ep.ContentTypes, ct)
		schema := SchemaInfo{
			Type:       "object",
			Properties: make(map[string]SchemaInfo),
		}
		for _, kv := range body.FormData {
			if kv.Disabled {
				continue
			}
			propType := "string"
			if kv.Type == "file" {
				propType = "file"
			}
			schema.Properties[kv.Key] = SchemaInfo{Type: propType}
		}
		ep.RequestBodies[ct] = RequestBody{Schema: schema}
	}
}

// resolvePostmanURL reconstructs the URL from a postmanURL object,
// applying variable substitution.
func resolvePostmanURL(u postmanURL, vars map[string]Variable) string {
	if u.Raw != "" {
		return substituteVars(u.Raw, vars)
	}

	var sb strings.Builder
	if u.Protocol != "" {
		sb.WriteString(u.Protocol)
		sb.WriteString("://")
	}
	if len(u.Host) > 0 {
		sb.WriteString(strings.Join(u.Host, "."))
	}
	if len(u.Path) > 0 {
		for _, p := range u.Path {
			sb.WriteByte('/')
			sb.WriteString(p)
		}
	}

	return substituteVars(sb.String(), vars)
}

// extractPostmanPath extracts the URL path from a raw Postman URL.
// Strips scheme, host, and port. Preserves path templates like :id as {id}.
func extractPostmanPath(rawURL string, vars map[string]Variable) string {
	// Apply variable substitution
	resolved := substituteVars(rawURL, vars)

	// Try to parse as URL
	u, err := url.Parse(resolved)
	if err != nil || u.Path == "" {
		// If URL parsing fails, try to extract path from the raw string
		// Remove protocol and host
		path := resolved
		if idx := strings.Index(path, "://"); idx >= 0 {
			path = path[idx+3:]
		}
		if idx := strings.Index(path, "/"); idx >= 0 {
			path = path[idx:]
		} else {
			path = "/"
		}
		return normalizePostmanPath(path)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	return normalizePostmanPath(path)
}

// normalizePostmanPath converts Postman-style :param to OpenAPI-style {param}.
func normalizePostmanPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, ":") {
			parts[i] = "{" + part[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}

// convertPostmanAuth converts a Postman auth block to a unified AuthScheme.
func convertPostmanAuth(name string, auth *postmanAuth) AuthScheme {
	as := AuthScheme{Name: name}
	switch auth.Type {
	case "bearer":
		as.Type = AuthBearer
	case "basic":
		as.Type = AuthBasic
	case "apikey":
		as.Type = AuthAPIKey
		for _, kv := range auth.APIKey {
			if kv.Key == "in" {
				as.In = Location(kv.Value)
			}
			if kv.Key == "key" {
				as.FieldName = kv.Value
			}
		}
	case "oauth2":
		as.Type = AuthOAuth2
	default:
		as.Type = AuthCustom
	}
	return as
}

// substituteVars replaces {{var}} patterns in a string using variables.
func substituteVars(s string, vars map[string]Variable) string {
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

// LoadPostmanEnvironment reads a Postman environment file and returns
// a map of variable name to value. Merge precedence when combined with
// collection variables: env file < collection vars < --var CLI.
func LoadPostmanEnvironment(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read postman environment: %w", err)
	}

	var env struct {
		Name   string `json:"name"`
		Values []struct {
			Key     string `json:"key"`
			Value   string `json:"value"`
			Enabled bool   `json:"enabled"`
		} `json:"values"`
	}

	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse postman environment: %w", err)
	}

	result := make(map[string]string, len(env.Values))
	for _, v := range env.Values {
		if v.Enabled {
			result[v.Key] = v.Value
		}
	}
	return result, nil
}
