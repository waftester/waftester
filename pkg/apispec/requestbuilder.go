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
			// Multipart bodies require the boundary parameter in Content-Type.
			if strings.Contains(ct, "multipart") {
				ct += "; boundary=----WafTesterBoundary"
			}
			req.Header.Set("Content-Type", ct)
		}
	} else if len(ep.RequestBodies) > 0 && needsBody(ep.Method) {
		// Non-body injection target on a method that expects a body (POST/PUT/PATCH).
		// Populate a default body so the server doesn't reject with 400.
		body := buildDefaultBody(ep)
		if body != "" {
			req.Body = newStringBody(body)
			req.ContentLength = int64(len(body))
			// Pick content type from request body spec.
			ct := defaultContentType(ep)
			if strings.Contains(ct, "multipart") {
				ct += "; boundary=----WafTesterBoundary"
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
// If the injection target is a path parameter, the payload is injected raw
// (no URL-encoding) because security testing payloads must reach the server
// unmodified. Non-payload values are URL-encoded for correctness.
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
			// Inject payload raw — no encoding. This is intentional:
			// security payloads like ../../../etc/passwd or <script> must
			// not be escaped by the testing tool.
			value = payload
			result = strings.ReplaceAll(result, placeholder, value)
		} else {
			if p.Example != nil {
				value = fmt.Sprintf("%v", p.Example)
			} else if p.Default != nil {
				value = fmt.Sprintf("%v", p.Default)
			} else {
				value = defaultValue(p.Schema)
			}
			result = strings.ReplaceAll(result, placeholder, url.PathEscape(value))
		}
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
		// Deterministic fallback: sort content types alphabetically.
		keys := make([]string, 0, len(ep.RequestBodies))
		for k := range ep.RequestBodies {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			ct = keys[0]
			rb = ep.RequestBodies[ct]
		}
	}

	if strings.Contains(ct, "json") {
		return buildJSONBody(rb.Schema, payload)
	}
	if strings.Contains(ct, "multipart") {
		return buildMultipartBody(rb.Schema, payload)
	}
	if strings.Contains(ct, "form") {
		return buildFormBody(rb.Schema, payload)
	}

	// Raw body: just the payload.
	return payload
}

// buildJSONBody creates a JSON object with schema properties, injecting the payload
// into the first string property. Recurses into nested objects.
func buildJSONBody(schema SchemaInfo, payload string) string {
	if len(schema.Properties) == 0 {
		return fmt.Sprintf(`{"payload":%q}`, payload)
	}
	result, _ := buildJSONObject(schema, payload, true)
	return result
}

// buildJSONObject recursively builds a JSON object. If injectPayload is true,
// the payload is injected into the first string field encountered.
// Returns the JSON string and whether the payload was injected.
func buildJSONObject(schema SchemaInfo, payload string, injectPayload bool) (string, bool) {
	if len(schema.Properties) == 0 {
		return "{}", false
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
		switch {
		case !injected && injectPayload && (prop.Type == "string" || prop.Type == ""):
			parts = append(parts, fmt.Sprintf("%q:%q", name, payload))
			injected = true
		case prop.Type == "object" && len(prop.Properties) > 0:
			// Recurse into nested objects. Only inject payload into the first
			// nested object if we haven't injected yet.
			nested, nestedInjected := buildJSONObject(prop, payload, injectPayload && !injected)
			parts = append(parts, fmt.Sprintf("%q:%s", name, nested))
			if nestedInjected {
				injected = true
			}
		case prop.Type == "array":
			parts = append(parts, fmt.Sprintf("%q:%s", name, defaultJSONArray(prop)))
		default:
			parts = append(parts, fmt.Sprintf("%q:%s", name, defaultJSONValue(prop)))
		}
	}
	if !injected && injectPayload {
		parts = append(parts, fmt.Sprintf("%q:%q", "payload", payload))
		injected = true
	}
	return "{" + strings.Join(parts, ",") + "}", injected
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

// buildMultipartBody creates a simple multipart/form-data body.
// Uses a fixed boundary for deterministic output.
func buildMultipartBody(schema SchemaInfo, payload string) string {
	const boundary = "----WafTesterBoundary"
	var b strings.Builder

	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	sort.Strings(names)

	injected := false
	for _, name := range names {
		prop := schema.Properties[name]
		b.WriteString("--" + boundary + "\r\n")
		if prop.Format == "binary" || prop.Type == "file" {
			b.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=%q; filename=\"test.txt\"\r\n", name))
			b.WriteString("Content-Type: application/octet-stream\r\n\r\n")
			if !injected {
				b.WriteString(payload)
				injected = true
			} else {
				b.WriteString("test")
			}
		} else {
			b.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=%q\r\n\r\n", name))
			if !injected && (prop.Type == "string" || prop.Type == "") {
				b.WriteString(payload)
				injected = true
			} else {
				b.WriteString(defaultFormValue(prop))
			}
		}
		b.WriteString("\r\n")
	}
	if !injected {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Disposition: form-data; name=\"payload\"\r\n\r\n")
		b.WriteString(payload)
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
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
		return defaultJSONArray(schema)
	case "object":
		if len(schema.Properties) > 0 {
			result, _ := buildJSONObject(schema, "test", false)
			return result
		}
		return "{}"
	default:
		return `"test"`
	}
}

// defaultJSONArray returns a JSON array using the items schema if available.
func defaultJSONArray(schema SchemaInfo) string {
	if schema.Items != nil {
		item := defaultJSONValue(*schema.Items)
		return "[" + item + "]"
	}
	return `["test"]`
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

// needsBody returns true for HTTP methods that typically carry a request body.
func needsBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

// defaultContentType returns the first content type from the endpoint's request
// bodies, falling back to application/json.
func defaultContentType(ep Endpoint) string {
	keys := make([]string, 0, len(ep.RequestBodies))
	for k := range ep.RequestBodies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		return keys[0]
	}
	return "application/json"
}

// buildDefaultBody constructs a body using example/default values from the
// endpoint's request body schema — no payload injection.
func buildDefaultBody(ep Endpoint) string {
	ct := defaultContentType(ep)
	rb := ep.RequestBodies[ct]
	if strings.Contains(ct, "json") {
		result, _ := buildJSONObject(rb.Schema, "", false)
		return result
	}
	if strings.Contains(ct, "form") {
		return buildFormBody(rb.Schema, "")
	}
	return ""
}
