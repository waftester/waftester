package apispec

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/waftester/waftester/pkg/requestpool"
)

// BuildRequest constructs an *http.Request for the given endpoint with a payload
// injected at the specified injection target. The caller must call
// requestpool.Put(req) when done.
//
// baseURL is the resolved target base URL (spec BaseURL or CLI override).
// payload is the attack string to inject.
func BuildRequest(baseURL string, ep Endpoint, target InjectionTarget, payload string) (*http.Request, error) {
	// Build the full URL path, expanding path parameters.
	path := expandPathParams(ep.Path, ep.Parameters, payload, target)

	fullURL, err := resolveURL(baseURL, path)
	if err != nil {
		return nil, fmt.Errorf("build request URL: %w", err)
	}

	method := strings.ToUpper(ep.Method)
	if method == "" {
		method = http.MethodGet
	}

	req := requestpool.GetWithMethod(method)

	// Build query parameters.
	q := url.Values{}
	for _, p := range ep.Parameters {
		if p.In != LocationQuery {
			continue
		}
		if target.Location == LocationQuery && target.Parameter == p.Name {
			q.Set(p.Name, payload)
		} else if p.Example != nil {
			q.Set(p.Name, fmt.Sprintf("%v", p.Example))
		} else if p.Default != nil {
			q.Set(p.Name, fmt.Sprintf("%v", p.Default))
		} else if p.Required {
			q.Set(p.Name, defaultValue(p.Schema))
		}
	}
	if len(q) > 0 {
		fullURL = fullURL + "?" + q.Encode()
	}

	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		requestpool.Put(req)
		return nil, fmt.Errorf("parse built URL: %w", err)
	}
	req.URL = parsedURL
	req.Host = parsedURL.Host

	// Build body for body-targeted injection.
	if target.Location == LocationBody {
		body := buildBody(ep, target, payload)
		if body != "" {
			req.Body = newStringBody(body)
			req.ContentLength = int64(len(body))
			ct := target.ContentType
			if ct == "" {
				ct = "application/json"
			}
			req.Header.Set("Content-Type", ct)
		}
	}

	// Inject into headers.
	for _, p := range ep.Parameters {
		if p.In != LocationHeader {
			continue
		}
		if target.Location == LocationHeader && target.Parameter == p.Name {
			req.Header.Set(p.Name, payload)
		} else if p.Example != nil {
			req.Header.Set(p.Name, fmt.Sprintf("%v", p.Example))
		} else if p.Required {
			req.Header.Set(p.Name, defaultValue(p.Schema))
		}
	}

	// Inject into cookies.
	for _, p := range ep.Parameters {
		if p.In != LocationCookie {
			continue
		}
		value := defaultValue(p.Schema)
		if p.Example != nil {
			value = fmt.Sprintf("%v", p.Example)
		}
		if target.Location == LocationCookie && target.Parameter == p.Name {
			value = payload
		}
		req.AddCookie(&http.Cookie{Name: p.Name, Value: value})
	}

	return req, nil
}

// expandPathParams replaces {param} placeholders in the path template.
// If the injection target is a path parameter, the payload is injected there.
func expandPathParams(pathTemplate string, params []Parameter, payload string, target InjectionTarget) string {
	result := pathTemplate
	for _, p := range params {
		if p.In != LocationPath {
			continue
		}
		placeholder := "{" + p.Name + "}"
		if !strings.Contains(result, placeholder) {
			continue
		}

		var value string
		if target.Location == LocationPath && target.Parameter == p.Name {
			value = payload
		} else if p.Example != nil {
			value = fmt.Sprintf("%v", p.Example)
		} else if p.Default != nil {
			value = fmt.Sprintf("%v", p.Default)
		} else {
			value = defaultValue(p.Schema)
		}
		result = strings.ReplaceAll(result, placeholder, url.PathEscape(value))
	}
	return result
}

// resolveURL joins the base URL with the endpoint path.
func resolveURL(baseURL, path string) (string, error) {
	if baseURL == "" {
		return "", fmt.Errorf("no base URL")
	}

	// Remove trailing slash from base, ensure leading slash on path.
	base := strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path, nil
}

// buildBody constructs a request body with the payload injected.
func buildBody(ep Endpoint, target InjectionTarget, payload string) string {
	ct := target.ContentType
	if ct == "" {
		ct = "application/json"
	}

	rb, ok := ep.RequestBodies[ct]
	if !ok {
		// Fall back to first available content type.
		for contentType, body := range ep.RequestBodies {
			rb = body
			ct = contentType
			break
		}
	}

	if strings.Contains(ct, "json") {
		return buildJSONBody(rb.Schema, payload)
	}
	if strings.Contains(ct, "form") {
		return buildFormBody(rb.Schema, payload)
	}

	// Raw body: just the payload.
	return payload
}

// buildJSONBody creates a JSON object with schema properties, injecting the payload
// into the first string property.
func buildJSONBody(schema SchemaInfo, payload string) string {
	if len(schema.Properties) == 0 {
		return fmt.Sprintf(`{"payload":%q}`, payload)
	}

	// Sort property names for deterministic output.
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	sort.Strings(names)

	var parts []string
	injected := false
	for _, name := range names {
		prop := schema.Properties[name]
		if !injected && (prop.Type == "string" || prop.Type == "") {
			parts = append(parts, fmt.Sprintf("%q:%q", name, payload))
			injected = true
		} else {
			parts = append(parts, fmt.Sprintf("%q:%s", name, defaultJSONValue(prop)))
		}
	}
	if !injected {
		parts = append(parts, fmt.Sprintf("%q:%q", "payload", payload))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// buildFormBody creates a URL-encoded form body.
func buildFormBody(schema SchemaInfo, payload string) string {
	values := url.Values{}
	injected := false

	// Sort property names for deterministic output.
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		prop := schema.Properties[name]
		if !injected && (prop.Type == "string" || prop.Type == "") {
			values.Set(name, payload)
			injected = true
		} else {
			values.Set(name, defaultFormValue(prop))
		}
	}
	if !injected {
		values.Set("payload", payload)
	}
	return values.Encode()
}

// defaultValue returns a reasonable default for a parameter based on its schema type.
func defaultValue(schema SchemaInfo) string {
	if len(schema.Enum) > 0 {
		return schema.Enum[0]
	}
	switch schema.Type {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "array":
		return "test"
	default:
		return "test"
	}
}

// defaultJSONValue returns a JSON-encoded default value for a schema property.
func defaultJSONValue(schema SchemaInfo) string {
	switch schema.Type {
	case "integer":
		return "1"
	case "number":
		return "1.0"
	case "boolean":
		return "true"
	case "array":
		return `["test"]`
	case "object":
		return "{}"
	default:
		return `"test"`
	}
}

// defaultFormValue returns a default string value for form encoding.
func defaultFormValue(schema SchemaInfo) string {
	switch schema.Type {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	default:
		return "test"
	}
}

// stringBody wraps a string as an io.ReadCloser for http.Request.Body.
type stringBody struct {
	*strings.Reader
}

func (stringBody) Close() error { return nil }

func newStringBody(s string) *stringBody {
	return &stringBody{Reader: strings.NewReader(s)}
}
