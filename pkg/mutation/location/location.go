// Package location provides injection location plugins for WAF testing.
// Tests payloads in different parts of HTTP requests.
package location

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/waftester/waftester/pkg/mutation"
)

func init() {
	// Register all location mutators
	locations := []mutation.Mutator{
		&QueryParamLocation{},
		&PostFormLocation{},
		&PostJSONLocation{},
		&PostXMLLocation{},
		&HeaderXForwardLocation{},
		&HeaderRefererLocation{},
		&HeaderUserAgentLocation{},
		&HeaderCustomLocation{},
		&CookieLocation{},
		&PathSegmentLocation{},
		&MultipartLocation{},
		&FragmentLocation{},
		&BasicAuthLocation{},
	}

	for _, l := range locations {
		mutation.Register(l)
	}
}

// LocationPayload includes HTTP request building instructions
type LocationPayload struct {
	mutation.MutatedPayload
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
}

// =============================================================================
// QUERY PARAMETER LOCATION
// =============================================================================

type QueryParamLocation struct{}

func (l *QueryParamLocation) Name() string        { return "query_param" }
func (l *QueryParamLocation) Category() string    { return "location" }
func (l *QueryParamLocation) Description() string { return "Inject payload in URL query parameter" }

func (l *QueryParamLocation) Mutate(payload string) []mutation.MutatedPayload {
	params := []string{"id", "q", "search", "query", "input", "data", "value", "name", "test"}
	results := make([]mutation.MutatedPayload, 0, len(params))

	for _, param := range params {
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     fmt.Sprintf("?%s=%s", param, url.QueryEscape(payload)),
			MutatorName: fmt.Sprintf("%s_%s", l.Name(), param),
			Category:    l.Category(),
		})
	}

	return results
}

// =============================================================================
// POST FORM LOCATION
// =============================================================================

type PostFormLocation struct{}

func (l *PostFormLocation) Name() string        { return "post_form" }
func (l *PostFormLocation) Category() string    { return "location" }
func (l *PostFormLocation) Description() string { return "Inject payload in POST form body" }

func (l *PostFormLocation) Mutate(payload string) []mutation.MutatedPayload {
	params := []string{"id", "username", "password", "email", "data", "input", "message", "comment"}
	results := make([]mutation.MutatedPayload, 0, len(params))

	for _, param := range params {
		body := fmt.Sprintf("%s=%s", param, url.QueryEscape(payload))
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     body,
			MutatorName: fmt.Sprintf("%s_%s", l.Name(), param),
			Category:    l.Category(),
		})
	}

	return results
}

// =============================================================================
// JSON BODY LOCATION
// =============================================================================

type PostJSONLocation struct{}

func (l *PostJSONLocation) Name() string        { return "post_json" }
func (l *PostJSONLocation) Category() string    { return "location" }
func (l *PostJSONLocation) Description() string { return "Inject payload in JSON body fields" }

func (l *PostJSONLocation) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 6)

	// Simple JSON objects with different field names
	fields := []string{"id", "name", "query", "data", "input", "message", "value", "search"}

	for _, field := range fields {
		jsonObj := map[string]interface{}{field: payload}
		jsonBytes, err := json.Marshal(jsonObj)
		if err != nil {
			continue
		}
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     string(jsonBytes),
			MutatorName: fmt.Sprintf("%s_%s", l.Name(), field),
			Category:    l.Category(),
		})
	}

	// Nested JSON
	nestedJSON := map[string]interface{}{
		"user": map[string]interface{}{
			"input": payload,
		},
	}
	nestedBytes, err := json.Marshal(nestedJSON)
	if err == nil {
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     string(nestedBytes),
		MutatorName: l.Name() + "_nested",
		Category:    l.Category(),
	})
	}

	// Array in JSON
	arrayJSON := map[string]interface{}{
		"items": []string{payload},
	}
	arrayBytes, err2 := json.Marshal(arrayJSON)
	if err2 == nil {
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     string(arrayBytes),
		MutatorName: l.Name() + "_array",
		Category:    l.Category(),
	})
	}

	return results
}

// =============================================================================
// XML BODY LOCATION
// =============================================================================

type PostXMLLocation struct{}

func (l *PostXMLLocation) Name() string        { return "post_xml" }
func (l *PostXMLLocation) Category() string    { return "location" }
func (l *PostXMLLocation) Description() string { return "Inject payload in XML body elements" }

func (l *PostXMLLocation) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 5)

	// Simple XML element
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("<?xml version=\"1.0\"?><root><data>%s</data></root>", payload),
		MutatorName: l.Name() + "_element",
		Category:    l.Category(),
	})

	// XML attribute
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("<?xml version=\"1.0\"?><root data=\"%s\"/>", payload),
		MutatorName: l.Name() + "_attribute",
		Category:    l.Category(),
	})

	// CDATA section
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("<?xml version=\"1.0\"?><root><![CDATA[%s]]></root>", payload),
		MutatorName: l.Name() + "_cdata",
		Category:    l.Category(),
	})

	// XXE attempt
	xxePayload := fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe "%s">]><root>&xxe;</root>`, payload)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     xxePayload,
		MutatorName: l.Name() + "_xxe",
		Category:    l.Category(),
	})

	return results
}

// =============================================================================
// HEADER INJECTION LOCATIONS
// =============================================================================

type HeaderXForwardLocation struct{}

func (l *HeaderXForwardLocation) Name() string     { return "header_xforward" }
func (l *HeaderXForwardLocation) Category() string { return "location" }
func (l *HeaderXForwardLocation) Description() string {
	return "Inject payload in X-Forwarded-* headers"
}

func (l *HeaderXForwardLocation) Mutate(payload string) []mutation.MutatedPayload {
	headers := []string{
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Real-IP",
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-Custom-IP-Authorization",
	}

	results := make([]mutation.MutatedPayload, 0, len(headers))
	for _, header := range headers {
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     fmt.Sprintf("%s: %s", header, payload),
			MutatorName: l.Name() + "_" + strings.ToLower(strings.ReplaceAll(header, "-", "_")),
			Category:    l.Category(),
		})
	}

	return results
}

type HeaderRefererLocation struct{}

func (l *HeaderRefererLocation) Name() string        { return "header_referer" }
func (l *HeaderRefererLocation) Category() string    { return "location" }
func (l *HeaderRefererLocation) Description() string { return "Inject payload in Referer header" }

func (l *HeaderRefererLocation) Mutate(payload string) []mutation.MutatedPayload {
	return []mutation.MutatedPayload{
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("Referer: %s", payload),
			MutatorName: l.Name(),
			Category:    l.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("Referer: https://evil.com/%s", url.PathEscape(payload)),
			MutatorName: l.Name() + "_path",
			Category:    l.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("Referer: https://evil.com/?q=%s", url.QueryEscape(payload)),
			MutatorName: l.Name() + "_query",
			Category:    l.Category(),
		},
	}
}

type HeaderUserAgentLocation struct{}

func (l *HeaderUserAgentLocation) Name() string        { return "header_useragent" }
func (l *HeaderUserAgentLocation) Category() string    { return "location" }
func (l *HeaderUserAgentLocation) Description() string { return "Inject payload in User-Agent header" }

func (l *HeaderUserAgentLocation) Mutate(payload string) []mutation.MutatedPayload {
	return []mutation.MutatedPayload{
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("User-Agent: %s", payload),
			MutatorName: l.Name(),
			Category:    l.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("User-Agent: Mozilla/5.0 (%s)", payload),
			MutatorName: l.Name() + "_embedded",
			Category:    l.Category(),
		},
	}
}

type HeaderCustomLocation struct{}

func (l *HeaderCustomLocation) Name() string        { return "header_custom" }
func (l *HeaderCustomLocation) Category() string    { return "location" }
func (l *HeaderCustomLocation) Description() string { return "Inject payload in custom/rare headers" }

func (l *HeaderCustomLocation) Mutate(payload string) []mutation.MutatedPayload {
	headers := []string{
		"X-Api-Key",
		"X-Auth-Token",
		"Authorization",
		"X-Debug",
		"X-Request-Id",
		"X-Correlation-Id",
		"True-Client-IP",
		"Client-IP",
		"CF-Connecting-IP",
		"Fastly-Client-IP",
		"X-Cluster-Client-IP",
		"X-Client-IP",
		"Forwarded",
		"Via",
		"X-Host",
		"X-HTTP-Method-Override",
	}

	results := make([]mutation.MutatedPayload, 0, len(headers))
	for _, header := range headers {
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     fmt.Sprintf("%s: %s", header, payload),
			MutatorName: l.Name() + "_" + strings.ToLower(strings.ReplaceAll(header, "-", "_")),
			Category:    l.Category(),
		})
	}

	return results
}

// =============================================================================
// COOKIE LOCATION
// =============================================================================

type CookieLocation struct{}

func (l *CookieLocation) Name() string        { return "cookie" }
func (l *CookieLocation) Category() string    { return "location" }
func (l *CookieLocation) Description() string { return "Inject payload in Cookie header values" }

func (l *CookieLocation) Mutate(payload string) []mutation.MutatedPayload {
	cookieNames := []string{"session", "auth", "token", "user", "id", "data", "prefs"}
	results := make([]mutation.MutatedPayload, 0, len(cookieNames))

	for _, name := range cookieNames {
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     fmt.Sprintf("Cookie: %s=%s", name, url.QueryEscape(payload)),
			MutatorName: l.Name() + "_" + name,
			Category:    l.Category(),
		})
	}

	// Multiple cookies
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("Cookie: session=abc; data=%s; user=test", url.QueryEscape(payload)),
		MutatorName: l.Name() + "_multiple",
		Category:    l.Category(),
	})

	return results
}

// =============================================================================
// PATH SEGMENT LOCATION
// =============================================================================

type PathSegmentLocation struct{}

func (l *PathSegmentLocation) Name() string        { return "path_segment" }
func (l *PathSegmentLocation) Category() string    { return "location" }
func (l *PathSegmentLocation) Description() string { return "Inject payload in URL path segments" }

func (l *PathSegmentLocation) Mutate(payload string) []mutation.MutatedPayload {
	escapedPayload := url.PathEscape(payload)

	return []mutation.MutatedPayload{
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("/api/%s", escapedPayload),
			MutatorName: l.Name() + "_api",
			Category:    l.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("/user/%s/profile", escapedPayload),
			MutatorName: l.Name() + "_middle",
			Category:    l.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("/%s", escapedPayload),
			MutatorName: l.Name() + "_root",
			Category:    l.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("/api/v1/items/%s", escapedPayload),
			MutatorName: l.Name() + "_resource_id",
			Category:    l.Category(),
		},
		// Path traversal style
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("/..%s", escapedPayload),
			MutatorName: l.Name() + "_traversal",
			Category:    l.Category(),
		},
	}
}

// =============================================================================
// MULTIPART FORM DATA LOCATION
// =============================================================================

type MultipartLocation struct{}

func (l *MultipartLocation) Name() string        { return "multipart" }
func (l *MultipartLocation) Category() string    { return "location" }
func (l *MultipartLocation) Description() string { return "Inject payload in multipart form data" }

const multipartBoundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

func (l *MultipartLocation) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 4)

	// Text field
	textBody := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n%s\r\n--%s--",
		multipartBoundary, payload, multipartBoundary)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     textBody,
		MutatorName: l.Name() + "_text",
		Category:    l.Category(),
	})

	// Filename injection
	fileBody := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\nfilecontent\r\n--%s--",
		multipartBoundary, payload, multipartBoundary)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fileBody,
		MutatorName: l.Name() + "_filename",
		Category:    l.Category(),
	})

	// Content-Type injection
	ctBody := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: %s\r\n\r\nfilecontent\r\n--%s--",
		multipartBoundary, payload, multipartBoundary)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     ctBody,
		MutatorName: l.Name() + "_content_type",
		Category:    l.Category(),
	})

	// Field name injection
	nameBody := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\nvalue\r\n--%s--",
		multipartBoundary, payload, multipartBoundary)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     nameBody,
		MutatorName: l.Name() + "_fieldname",
		Category:    l.Category(),
	})

	return results
}

// =============================================================================
// FRAGMENT LOCATION
// =============================================================================

type FragmentLocation struct{}

func (l *FragmentLocation) Name() string        { return "fragment" }
func (l *FragmentLocation) Category() string    { return "location" }
func (l *FragmentLocation) Description() string { return "Inject payload in URL fragment (after #)" }

func (l *FragmentLocation) Mutate(payload string) []mutation.MutatedPayload {
	return []mutation.MutatedPayload{
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("#%s", payload),
			MutatorName: l.Name(),
			Category:    l.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("#section/%s", url.PathEscape(payload)),
			MutatorName: l.Name() + "_path",
			Category:    l.Category(),
		},
	}
}

// =============================================================================
// BASIC AUTH LOCATION
// =============================================================================

type BasicAuthLocation struct{}

func (l *BasicAuthLocation) Name() string        { return "basic_auth" }
func (l *BasicAuthLocation) Category() string    { return "location" }
func (l *BasicAuthLocation) Description() string { return "Inject payload in Basic Auth credentials" }

func (l *BasicAuthLocation) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 3)

	// In username
	usernameAuth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:password", payload)))
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("Authorization: Basic %s", usernameAuth),
		MutatorName: l.Name() + "_username",
		Category:    l.Category(),
	})

	// In password
	passwordAuth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("user:%s", payload)))
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("Authorization: Basic %s", passwordAuth),
		MutatorName: l.Name() + "_password",
		Category:    l.Category(),
	})

	// In both
	bothAuth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", payload, payload)))
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("Authorization: Basic %s", bothAuth),
		MutatorName: l.Name() + "_both",
		Category:    l.Category(),
	})

	return results
}
