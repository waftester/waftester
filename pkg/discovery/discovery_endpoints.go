// Package discovery - Known endpoint lists and categorization helpers
package discovery

import (
	"encoding/json"
	"net/url"
	"strings"
)

func categorizeEndpoint(path, method string) string {
	lower := strings.ToLower(path)

	switch {
	case strings.Contains(lower, "health") || strings.Contains(lower, "ping") || strings.Contains(lower, "status") || strings.Contains(lower, "ready") || strings.Contains(lower, "alive"):
		return "health"
	case strings.Contains(lower, "login") || strings.Contains(lower, "signup") || strings.Contains(lower, "register") ||
		strings.Contains(lower, "auth") || strings.Contains(lower, "oauth") || strings.Contains(lower, "sso") ||
		strings.Contains(lower, "token") || strings.Contains(lower, "session") || strings.Contains(lower, "password"):
		return "auth"
	case strings.Contains(lower, "graphql"):
		return "graphql"
	case strings.Contains(lower, "webhook") || strings.Contains(lower, "callback") || strings.Contains(lower, "hook"):
		return "webhook"
	case strings.Contains(lower, "admin") || strings.Contains(lower, "manage") || strings.Contains(lower, "dashboard"):
		return "admin"
	case strings.Contains(lower, "upload") || strings.Contains(lower, "import") || strings.Contains(lower, "asset") || strings.Contains(lower, "media"):
		return "upload"
	case strings.Contains(lower, "/api/") || strings.HasPrefix(lower, "/v1/") || strings.HasPrefix(lower, "/v2/") || strings.HasPrefix(lower, "/v3/"):
		return "api"
	case strings.Contains(lower, "websocket") || strings.Contains(lower, "/ws") || strings.Contains(lower, "socket.io"):
		return "websocket"
	case strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".css") || strings.HasSuffix(lower, ".png") ||
		strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".svg") || strings.HasSuffix(lower, ".woff") ||
		strings.HasSuffix(lower, ".ico") || strings.HasSuffix(lower, ".map"):
		return "static"
	case method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE":
		return "api"
	default:
		return "general"
	}
}

func extractParameters(path, body, contentType string) []Parameter {
	params := make([]Parameter, 0)

	// Extract path parameters — numeric or UUID segments that look like IDs.
	// /api/v1/users/42/posts → id=42 in path segment "users"
	// /items/550e8400-e29b-41d4-a716-446655440000 → uuid in path
	cleanPath := path
	if idx := strings.Index(cleanPath, "?"); idx != -1 {
		cleanPath = cleanPath[:idx]
	}
	segments := strings.Split(strings.Trim(cleanPath, "/"), "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		paramType := classifyPathSegment(seg)
		if paramType != "" {
			name := "id"
			if i > 0 {
				// Use previous segment as parameter name hint: /users/42 → user_id
				prev := strings.TrimRight(segments[i-1], "s")
				name = prev + "_id"
			}
			params = append(params, Parameter{
				Name:     name,
				Location: "path",
				Type:     paramType,
				Example:  seg,
			})
		}
	}

	// Extract query parameters from path
	if idx := strings.Index(path, "?"); idx != -1 {
		query := path[idx+1:]
		for _, pair := range strings.Split(query, "&") {
			if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
				params = append(params, Parameter{
					Name:     kv[0],
					Location: "query",
					Type:     inferTypeFromValue(kv[1]),
					Example:  kv[1],
				})
			}
		}
	}

	// Extract JSON body parameters
	if strings.Contains(contentType, "json") && len(body) > 0 {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
			for key, val := range jsonData {
				params = append(params, Parameter{
					Name:     key,
					Location: "body",
					Type:     inferType(val),
				})
			}
		}
	}

	// Extract form body parameters
	if strings.Contains(contentType, "form-urlencoded") && len(body) > 0 {
		for _, pair := range strings.Split(body, "&") {
			if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
				params = append(params, Parameter{
					Name:     kv[0],
					Location: "body",
					Type:     inferTypeFromValue(kv[1]),
					Example:  kv[1],
				})
			}
		}
	}

	return params
}

// classifyPathSegment returns the type if a path segment looks like a parameter,
// or empty string if it's a static segment.
func classifyPathSegment(seg string) string {
	// UUID: 8-4-4-4-12 hex
	if len(seg) == 36 && seg[8] == '-' && seg[13] == '-' && seg[18] == '-' && seg[23] == '-' {
		return "uuid"
	}
	// Pure numeric
	if len(seg) > 0 && len(seg) <= 20 {
		allDigit := true
		for _, c := range seg {
			if c < '0' || c > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			return "integer"
		}
	}
	// Hex hash (e.g., commit SHAs, object IDs)
	if len(seg) >= 24 && len(seg) <= 64 {
		allHex := true
		for _, c := range seg {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
		}
		if allHex {
			return "hash"
		}
	}
	return ""
}

// inferTypeFromValue guesses a parameter type from its string value.
func inferTypeFromValue(val string) string {
	if val == "true" || val == "false" {
		return "boolean"
	}
	allDigit := true
	for _, c := range val {
		if c < '0' || c > '9' {
			allDigit = false
			break
		}
	}
	if allDigit && len(val) > 0 {
		return "integer"
	}
	return "string"
}

func identifyRiskFactors(path, method string, body string) []string {
	risks := make([]string, 0)
	lower := strings.ToLower(path)
	bodyLower := strings.ToLower(body)

	// Parameter injection
	if strings.Contains(lower, "?") || strings.Contains(lower, "id=") || strings.Contains(lower, "query=") {
		risks = append(risks, "parameter_injection")
	}

	// File access / path traversal
	if strings.Contains(lower, "file") || strings.Contains(lower, "path") || strings.Contains(lower, "download") ||
		strings.Contains(lower, "include") || strings.Contains(lower, "template") || strings.Contains(lower, "read") {
		risks = append(risks, "file_access")
	}

	// Command execution
	if strings.Contains(bodyLower, "exec") || strings.Contains(bodyLower, "command") || strings.Contains(bodyLower, "shell") ||
		strings.Contains(lower, "exec") || strings.Contains(lower, "run") || strings.Contains(lower, "eval") {
		risks = append(risks, "command_execution")
	}

	// Open redirect
	if strings.Contains(lower, "redirect") || strings.Contains(lower, "url=") || strings.Contains(lower, "next=") ||
		strings.Contains(lower, "return") || strings.Contains(lower, "goto") || strings.Contains(lower, "dest") {
		risks = append(risks, "redirect")
	}

	// SSRF
	if strings.Contains(lower, "url=") || strings.Contains(lower, "proxy") || strings.Contains(lower, "fetch") ||
		strings.Contains(lower, "request") || strings.Contains(lower, "load") {
		risks = append(risks, "ssrf")
	}

	// Auth-sensitive
	if strings.Contains(lower, "admin") || strings.Contains(lower, "user") || strings.Contains(lower, "role") ||
		strings.Contains(lower, "permission") || strings.Contains(lower, "privilege") {
		risks = append(risks, "access_control")
	}

	// Data exposure
	if (method == "GET" || method == "") && (strings.Contains(lower, "export") || strings.Contains(lower, "dump") ||
		strings.Contains(lower, "backup") || strings.Contains(lower, "log") || strings.Contains(lower, "debug")) {
		risks = append(risks, "data_exposure")
	}

	// Deserialization
	if strings.Contains(bodyLower, "class") || strings.Contains(bodyLower, "__type") ||
		strings.Contains(bodyLower, "java.") || strings.Contains(bodyLower, "rO0") {
		risks = append(risks, "deserialization")
	}

	return risks
}

func inferType(val interface{}) string {
	switch val.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

func isInternalLink(link, target string) bool {
	if strings.HasPrefix(link, "/") && !strings.HasPrefix(link, "//") {
		return true
	}
	targetURL, err := url.Parse(target)
	if err != nil || targetURL == nil {
		return false
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return false
	}
	return linkURL.Host == "" || linkURL.Host == targetURL.Host
}

func extractPath(link string) string {
	if strings.HasPrefix(link, "/") {
		// Remove query string and fragment
		if idx := strings.Index(link, "?"); idx != -1 {
			link = link[:idx]
		}
		if idx := strings.Index(link, "#"); idx != -1 {
			link = link[:idx]
		}
		return link
	}
	parsed, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return parsed.Path
}
