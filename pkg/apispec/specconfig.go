package apispec

import (
	"path/filepath"
	"strings"
)

// SpecConfig holds all spec-related options shared between CLI and MCP.
// It is the single source of truth for how a spec scan is configured.
type SpecConfig struct {
	// SpecPath is the local file path to the API spec.
	SpecPath string `json:"spec_path,omitempty"`

	// SpecURL is a remote URL to fetch the API spec from.
	SpecURL string `json:"spec_url,omitempty"`

	// SpecContent is inline spec content (used by MCP tools).
	SpecContent string `json:"spec_content,omitempty"`

	// TargetOverride overrides the base URL from the spec (-u flag).
	TargetOverride string `json:"target_override,omitempty"`

	// Groups filters endpoints to only those in the named groups.
	Groups []string `json:"groups,omitempty"`

	// SkipGroups excludes endpoints in the named groups.
	SkipGroups []string `json:"skip_groups,omitempty"`

	// PathFilter is a glob pattern to match endpoint paths.
	PathFilter string `json:"path_filter,omitempty"`

	// Variables are key=value overrides for spec variables.
	Variables map[string]string `json:"variables,omitempty"`

	// EnvFile is a Postman environment file path.
	EnvFile string `json:"env_file,omitempty"`

	// DryRun outputs the scan plan without executing.
	DryRun bool `json:"dry_run,omitempty"`

	// Confirm skips the interactive confirmation prompt.
	Confirm bool `json:"confirm,omitempty"`

	// Intensity controls scanning depth.
	Intensity Intensity `json:"intensity,omitempty"`

	// ScanTypes limits which attack types to run (empty = all requested).
	ScanTypes []string `json:"scan_types,omitempty"`

	// SkipTypes excludes specific attack types.
	SkipTypes []string `json:"skip_types,omitempty"`

	// AllowInternal permits scanning of internal/private IPs.
	AllowInternal bool `json:"allow_internal,omitempty"`

	// Auth holds CLI-provided credentials.
	Auth AuthConfig `json:"auth,omitempty"`
}

// AuthConfig holds CLI-provided authentication credentials.
type AuthConfig struct {
	// BearerToken is a Bearer token value.
	BearerToken string `json:"bearer_token,omitempty"`

	// APIKey is an API key value.
	APIKey string `json:"api_key,omitempty"`

	// APIKeyHeader is the header name for the API key (default: X-API-Key).
	APIKeyHeader string `json:"api_key_header,omitempty"`

	// AuthHeader is a raw Authorization header value.
	AuthHeader string `json:"auth_header,omitempty"`

	// BasicUser is the username for HTTP Basic auth.
	BasicUser string `json:"basic_user,omitempty"`

	// BasicPass is the password for HTTP Basic auth.
	BasicPass string `json:"basic_pass,omitempty"`

	// CustomHeaders are additional auth-related headers.
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
}

// HasSpec returns true if any spec source is configured.
func (c *SpecConfig) HasSpec() bool {
	return c.SpecPath != "" || c.SpecURL != "" || c.SpecContent != ""
}

// Source returns the spec source identifier (path, URL, or "inline").
func (c *SpecConfig) Source() string {
	if c.SpecPath != "" {
		return c.SpecPath
	}
	if c.SpecURL != "" {
		return c.SpecURL
	}
	if c.SpecContent != "" {
		return "inline"
	}
	return ""
}

// MatchesPath reports whether the given endpoint path matches the path filter.
// An empty filter matches everything. Supports glob patterns.
func (c *SpecConfig) MatchesPath(path string) bool {
	if c.PathFilter == "" {
		return true
	}
	matched, err := filepath.Match(c.PathFilter, path)
	if err != nil {
		// Invalid pattern: fall back to prefix match.
		return strings.HasPrefix(path, strings.TrimSuffix(c.PathFilter, "*"))
	}
	return matched
}

// MatchesGroup reports whether the endpoint group/tags match the group filters.
// Returns true if no group filters are configured.
func (c *SpecConfig) MatchesGroup(group string, tags []string) bool {
	// Check skip-groups first.
	for _, sg := range c.SkipGroups {
		if strings.EqualFold(sg, group) {
			return false
		}
		for _, tag := range tags {
			if strings.EqualFold(sg, tag) {
				return false
			}
		}
	}

	// If no group filter, everything passes.
	if len(c.Groups) == 0 {
		return true
	}

	// Check if any group filter matches.
	for _, g := range c.Groups {
		if strings.EqualFold(g, group) {
			return true
		}
		for _, tag := range tags {
			if strings.EqualFold(g, tag) {
				return true
			}
		}
	}
	return false
}

// FilterEndpoints filters a spec's endpoints based on path and group config.
func (c *SpecConfig) FilterEndpoints(endpoints []Endpoint) []Endpoint {
	if c.PathFilter == "" && len(c.Groups) == 0 && len(c.SkipGroups) == 0 {
		return endpoints
	}

	var filtered []Endpoint
	for _, ep := range endpoints {
		if !c.MatchesPath(ep.Path) {
			continue
		}
		if !c.MatchesGroup(ep.Group, ep.Tags) {
			continue
		}
		filtered = append(filtered, ep)
	}
	return filtered
}

// ShouldScan reports whether the given scan type should be executed.
func (c *SpecConfig) ShouldScan(scanType string) bool {
	scanType = strings.ToLower(scanType)

	// Check skip list first.
	for _, s := range c.SkipTypes {
		if strings.EqualFold(s, scanType) {
			return false
		}
	}

	// If no explicit types, allow all.
	if len(c.ScanTypes) == 0 {
		return true
	}

	for _, s := range c.ScanTypes {
		if strings.EqualFold(s, scanType) {
			return true
		}
	}
	return false
}

// HasAuth reports whether any CLI auth credentials are configured.
func (c *AuthConfig) HasAuth() bool {
	return c.BearerToken != "" || c.APIKey != "" || c.AuthHeader != "" ||
		c.BasicUser != "" || len(c.CustomHeaders) > 0
}
