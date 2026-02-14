package apispec

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/waftester/waftester/pkg/plugin"
)

// EndpointToTarget converts an apispec.Endpoint to a plugin.Target suitable
// for running registered plugin scanners against spec-defined endpoints.
func EndpointToTarget(baseURL string, ep Endpoint) (*plugin.Target, error) {
	fullPath := ep.Path
	if !isAbsoluteURL(fullPath) {
		base := baseURL
		if base == "" {
			return nil, fmt.Errorf("no base URL for endpoint %s %s", ep.Method, ep.Path)
		}
		// Expand path params with example/default values for target URL.
		for _, p := range ep.Parameters {
			if p.In != LocationPath {
				continue
			}
			placeholder := "{" + p.Name + "}"
			var val string
			if p.Example != nil {
				val = fmt.Sprintf("%v", p.Example)
			} else if p.Default != nil {
				val = fmt.Sprintf("%v", p.Default)
			} else {
				val = defaultValue(p.Schema)
			}
			fullPath = replaceAll(fullPath, placeholder, val)
		}
		fullPath = joinURL(base, fullPath)
	}

	parsed, err := url.Parse(fullPath)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}

	port := 0
	if parsed.Port() != "" {
		port, _ = strconv.Atoi(parsed.Port())
	}

	headers := make(map[string]string)
	cookies := make(map[string]string)

	for _, p := range ep.Parameters {
		val := exampleOrDefault(p)
		switch p.In {
		case LocationHeader:
			headers[p.Name] = val
		case LocationCookie:
			cookies[p.Name] = val
		}
	}

	metadata := map[string]interface{}{
		"operation_id":    ep.OperationID,
		"correlation_tag": ep.CorrelationTag,
		"group":           ep.Group,
		"tags":            ep.Tags,
		"deprecated":      ep.Deprecated,
	}

	return &plugin.Target{
		URL:      fullPath,
		Host:     parsed.Hostname(),
		Port:     port,
		Scheme:   parsed.Scheme,
		Path:     parsed.Path,
		Method:   ep.Method,
		Headers:  headers,
		Cookies:  cookies,
		Metadata: metadata,
	}, nil
}

// exampleOrDefault returns a string value from Example, Default, or schema defaults.
func exampleOrDefault(p Parameter) string {
	if p.Example != nil {
		return fmt.Sprintf("%v", p.Example)
	}
	if p.Default != nil {
		return fmt.Sprintf("%v", p.Default)
	}
	return defaultValue(p.Schema)
}

// isAbsoluteURL checks if the string starts with http:// or https://.
func isAbsoluteURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// joinURL joins a base URL and path, handling slashes.
func joinURL(base, path string) string {
	if len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	if len(path) > 0 && path[0] != '/' {
		path = "/" + path
	}
	return base + path
}

// replaceAll replaces all occurrences of old with new in s.
func replaceAll(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}
