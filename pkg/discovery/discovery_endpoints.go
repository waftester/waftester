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

func getAgreementPulseEndpoints() []string {
	return []string{
		"/api/health",
		"/api/auth/login",
		"/api/auth/register",
		"/api/agreements/",
		"/api/documents/",
		"/api/users/",
		"/api/notifications/",
	}
}

// getOnehubEndpoints returns known endpoints for ADNOC OneHub (.NET/Azure-based)
// Updated with deep JavaScript analysis findings from config.js, foundation.js, and remote entries
func getOnehubEndpoints() []string {
	baseAPI := "/vms/onehub/LiteAppApi.2.0/api"
	return []string{
		// === BASE LITEAPP API ===
		baseAPI,
		baseAPI + "/",
		baseAPI + "/values",
		baseAPI + "/users",
		baseAPI + "/user",
		baseAPI + "/account",
		baseAPI + "/auth",
		baseAPI + "/login",
		baseAPI + "/token",
		baseAPI + "/refresh",
		baseAPI + "/logout",
		baseAPI + "/profile",
		// Document management
		baseAPI + "/documents",
		baseAPI + "/document",
		baseAPI + "/files",
		baseAPI + "/file",
		baseAPI + "/upload",
		baseAPI + "/download",
		baseAPI + "/attachments",
		// Content management
		baseAPI + "/content",
		baseAPI + "/pages",
		baseAPI + "/posts",
		baseAPI + "/news",
		baseAPI + "/articles",
		baseAPI + "/announcements",
		// Enterprise features
		baseAPI + "/departments",
		baseAPI + "/organizations",
		baseAPI + "/groups",
		baseAPI + "/teams",
		baseAPI + "/roles",
		baseAPI + "/permissions",
		// Search & lookup
		baseAPI + "/search",
		baseAPI + "/lookup",
		baseAPI + "/autocomplete",
		baseAPI + "/suggest",
		// Workflow & tasks
		baseAPI + "/workflows",
		baseAPI + "/tasks",
		baseAPI + "/approvals",
		baseAPI + "/requests",
		// Notifications
		baseAPI + "/notifications",
		baseAPI + "/alerts",
		baseAPI + "/messages",
		// Admin & config
		baseAPI + "/admin",
		baseAPI + "/settings",
		baseAPI + "/config",
		baseAPI + "/configuration",
		// Analytics & reporting
		baseAPI + "/analytics",
		baseAPI + "/reports",
		baseAPI + "/dashboard",
		baseAPI + "/stats",
		// Health
		baseAPI + "/health",
		baseAPI + "/ping",
		baseAPI + "/status",
		// Swagger/OpenAPI
		"/vms/onehub/LiteAppApi.2.0/swagger",
		"/vms/onehub/LiteAppApi.2.0/swagger/v1/swagger.json",
		"/vms/onehub/api",
		"/vms/onehub/LiteAppApi/api",
		"/vms/onehub/LiteAppApi.1.0/api",

		// === SITECORE CMS APIs (from config.js) ===
		"/sitecore/onehub/api/events/UpcomingEventsWidget",
		"/sitecore/onehub/api/news/GetAllNewsByDate",
		"/sitecore/onehub/api/news/GetNewsWidgetData",
		"/sitecore/onehub/api/WhatsNew/GetWhatsNewWidgetData",
		"/sitecore/onehub/api",

		// === SERVICENOW INTEGRATION (from config.js) ===
		"/servicenow/onehub/integration",
		"/servicenow/onehub/integration/incidents",
		"/servicenow/onehub/integration/requests",
		"/servicenow/onehub/integration/tickets",

		// === CORPORATE BI / ENTERPRISE SEARCH (from config.js) ===
		"/corporatebi/onehub/multi-api/kpi-insights/enterprise-search",
		"/corporatebi/onehub/multi-api",
		"/corporatebi/onehub",

		// === ONETALENT HR SYSTEM (from config.js) ===
		"/onetalent/v1",
		"/onetalent/v1/employees",
		"/onetalent/v1/profile",
		"/onetalent/v1/leave",
		"/onetalent/v1/attendance",

		// === RECOGNITION SYSTEM (from config.js) ===
		"/recognition/v1",
		"/recognition/v1/badges",
		"/recognition/v1/awards",
		"/recognition/v1/nominations",

		// === YAMMER INTEGRATION (from config.js) ===
		"/yammer/v1",
		"/yammer/v1/messages",
		"/yammer/v1/groups",
		"/yammer/v1/users",

		// === DELEGATION OF AUTHORITY (from config.js) ===
		"/doa",
		"/doa/api",
		"/doa/delegations",
		"/doa/authorities",

		// === DOC360 / POLICY SEARCH (from config.js) ===
		"/doc360/onehub/onehub/policy/search",
		"/doc360/onehub/policies",
		"/doc360/onehub/documents",

		// === BMS - BUILDING MANAGEMENT (from config.js) ===
		"/tbms/onehub",
		"/tbms/onehub/facilities",
		"/tbms/onehub/bookings",

		// === ACTION HUB (from config.js) ===
		"/onehubmf/actionhub",
		"/onehubmf/actionhub/actions",
		"/onehubmf/actionhub/tracking",

		// === CTS - CORRESPONDENCE TRACKING (from config.js) ===
		"/cts/api",
		"/cts/api/correspondence",
		"/cts/api/signatures",
		"/cts/api/workflows",

		// === POWERBI INTEGRATION (from foundation.js) ===
		"/powerbi/api/App",
		"/powerbi/api/Capacity",
		"/powerbi/api/Dashboard",
		"/powerbi/api/Dataset",
		"/powerbi/api/Report",
		"/powerbi/api/Workspace",

		// === CONFIG APIs (from foundation.js) ===
		"/api/config/v0",
		"/api/config/v0/icons",
		"/e-service-item/employee-photo",

		// === VMS - VISITOR MANAGEMENT (from remote_vms.js) ===
		"/container/entry/visitor_management_system",
		"/vms/details",
		"/vms/service",
		"/vms/visitors",
		"/vms/visits",
		"/vms/badges",
		"/vms/checkpoints",

		// === STANDARD ENDPOINTS ===
		"/api",
		"/api/v1",
		"/api/v2",
		"/admin",
		"/admin/",
		"/admin/content",
		"/admin/config.js",
		"/config.js",
		"/administrator",

		// === AZURE AD / AUTH ===
		"/signin-oidc",
		"/signout-callback-oidc",
		"/.auth/login",
		"/.auth/logout",
		"/.auth/me",

		// === SHAREPOINT/GRAPH STYLE ===
		"/_api",
		"/_api/web",
		"/_api/lists",
		"/_layouts",
		"/_vti_bin",

		// === MICRO-FRONTEND REMOTE ENTRIES (from config.js) ===
		"/onehub/blob/static-onehub-prod/vms/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/service-now/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/profile/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/search/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/meera/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/insights/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/cts/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/bms/remoteEntry.js",
		"/onehub/blob/static-onehub-prod/shorts/remoteEntry.js",
		"/onehub/blob/static-ai-prd/ai-marketplace/remoteEntry.js",

		// === WALKME (from config.js) ===
		"/walkme/onehub/prdwalkme",

		// === STATIC ASSETS ===
		"/static/fonts/fonts.css",
		"/static/fonts/adnoc-sans-w-rg/adnoc-sans-w-rg.woff2",
		"/js/main-98bd4238fcc42dfb79df.js",
		"/js/foundation-98bd4238fcc42dfb79df.js",
		"/js/microsoft-98bd4238fcc42dfb79df.js",
		"/js/packages-98bd4238fcc42dfb79df.js",
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
