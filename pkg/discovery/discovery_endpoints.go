// Package discovery - Known endpoint lists and categorization helpers
package discovery

import (
	"encoding/json"
	"net/url"
	"strings"
)

func getAuthentikEndpoints() []string {
	return []string{
		"/-/health/ready/",
		"/-/health/live/",
		"/api/v3/core/applications/",
		"/api/v3/core/groups/",
		"/api/v3/core/users/",
		"/api/v3/core/tokens/",
		"/api/v3/flows/executor/",
		"/api/v3/policies/",
		"/application/o/authorize/",
		"/application/o/token/",
		"/application/o/userinfo/",
		"/source/saml/",
		"/source/oauth/",
		"/if/flow/default-authentication-flow/",
		"/if/admin/",
		"/if/user/",
		"/ws/",
	}
}

func getN8nEndpoints() []string {
	return []string{
		"/healthz",
		"/rest/workflows",
		"/rest/credentials",
		"/rest/executions",
		"/rest/settings",
		"/rest/users",
		"/rest/oauth2-credential/",
		"/webhook/",
		"/webhook-test/",
		"/api/v1/",
		"/push",
	}
}

func getImmichEndpoints() []string {
	return []string{
		"/api/server/ping",
		"/api/server-info/",
		"/api/auth/login",
		"/api/auth/signup",
		"/api/users/",
		"/api/albums/",
		"/api/assets/",
		"/api/assets/upload",
		"/api/search/",
		"/api/faces/",
		"/api/people/",
	}
}

func getGenericEndpoints() []string {
	return []string{
		"/api/",
		"/api/v1/",
		"/api/v2/",
		"/login",
		"/logout",
		"/register",
		"/signup",
		"/admin/",
		"/dashboard/",
		"/settings/",
		"/profile/",
		"/users/",
		"/search",
		"/upload",
		"/download",
		"/graphql",
		"/swagger.json",
		"/openapi.json",
		"/.env",
		"/config",
	}
}

func categorizeEndpoint(path, method string) string {
	path = strings.ToLower(path)

	if strings.Contains(path, "health") || strings.Contains(path, "ping") {
		return "health"
	}
	if strings.Contains(path, "login") || strings.Contains(path, "auth") || strings.Contains(path, "oauth") {
		return "auth"
	}
	if strings.Contains(path, "api") {
		return "api"
	}
	if strings.Contains(path, "admin") {
		return "admin"
	}
	if strings.Contains(path, "upload") || strings.Contains(path, "asset") {
		return "upload"
	}
	if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".png") {
		return "static"
	}
	if strings.Contains(path, "webhook") {
		return "webhook"
	}
	return "general"
}

func extractParameters(path, body, contentType string) []Parameter {
	params := make([]Parameter, 0)

	// Extract query parameters from path
	if idx := strings.Index(path, "?"); idx != -1 {
		query := path[idx+1:]
		for _, pair := range strings.Split(query, "&") {
			if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
				params = append(params, Parameter{
					Name:     kv[0],
					Location: "query",
					Type:     "string",
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

	return params
}

func identifyRiskFactors(path, method string, body string) []string {
	risks := make([]string, 0)
	path = strings.ToLower(path)
	body = strings.ToLower(body)

	// Check for injection points
	if strings.Contains(path, "?") || strings.Contains(path, "id=") || strings.Contains(path, "query=") {
		risks = append(risks, "parameter_injection")
	}

	// Check for file access
	if strings.Contains(path, "file") || strings.Contains(path, "path") || strings.Contains(path, "download") {
		risks = append(risks, "file_access")
	}

	// Check for command execution hints
	if strings.Contains(body, "exec") || strings.Contains(body, "command") || strings.Contains(body, "shell") {
		risks = append(risks, "command_execution")
	}

	// Check for redirect
	if strings.Contains(path, "redirect") || strings.Contains(path, "url=") || strings.Contains(path, "next=") {
		risks = append(risks, "redirect")
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
