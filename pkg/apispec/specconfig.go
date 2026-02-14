package apispec

import (
	"fmt"
	"os"
	pathpkg "path"
	"strings"

	"gopkg.in/yaml.v3"
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

	// OAuth2ClientID is the client ID for OAuth2 client_credentials flow.
	OAuth2ClientID string `json:"oauth2_client_id,omitempty"`

	// OAuth2ClientSecret is the client secret for OAuth2 client_credentials flow.
	OAuth2ClientSecret string `json:"oauth2_client_secret,omitempty"`

	// OAuth2TokenURL is the token endpoint for OAuth2 client_credentials flow.
	// If empty, the token URL is inferred from the spec's securitySchemes.
	OAuth2TokenURL string `json:"oauth2_token_url,omitempty"`

	// OAuth2Scopes is a comma-separated list of scopes to request.
	OAuth2Scopes string `json:"oauth2_scopes,omitempty"`
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
// Uses path.Match (not filepath.Match) because API paths always use forward slashes.
func (c *SpecConfig) MatchesPath(path string) bool {
	if c.PathFilter == "" {
		return true
	}
	matched, err := pathpkg.Match(c.PathFilter, path)
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
		c.BasicUser != "" || len(c.CustomHeaders) > 0 ||
		c.OAuth2ClientID != ""
}

// ScanConfigFile represents a .waftester-spec.yaml file with per-endpoint
// scan overrides. This allows users to customize scanning behavior for
// specific endpoint paths without modifying the API spec.
type ScanConfigFile struct {
	// Overrides is a list of per-endpoint override rules.
	Overrides []EndpointOverride `yaml:"overrides" json:"overrides"`
}

// EndpointOverride configures scan behavior for endpoints matching Pattern.
type EndpointOverride struct {
	// Pattern is a glob pattern matching endpoint paths (e.g., "/admin/*").
	Pattern string `yaml:"pattern" json:"pattern"`

	// Skip excludes matching endpoints entirely.
	Skip bool `yaml:"skip,omitempty" json:"skip,omitempty"`

	// Intensity overrides the global intensity for matching endpoints.
	Intensity Intensity `yaml:"intensity,omitempty" json:"intensity,omitempty"`

	// ScanTypes restricts attack categories on matching endpoints.
	ScanTypes []string `yaml:"scan_types,omitempty" json:"scan_types,omitempty"`

	// SkipTypes excludes specific attack categories on matching endpoints.
	SkipTypes []string `yaml:"skip_types,omitempty" json:"skip_types,omitempty"`

	// MaxPayloads caps the number of payloads per attack on matching endpoints.
	MaxPayloads int `yaml:"max_payloads,omitempty" json:"max_payloads,omitempty"`
}

// LoadScanConfigFile loads a .waftester-spec.yaml override file.
// Returns nil,nil if the file does not exist (auto-load from CWD).
// Returns an error only when the file exists but is malformed.
func LoadScanConfigFile(path string) (*ScanConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read scan config: %w", err)
	}

	var cfg ScanConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse scan config %s: %w", path, err)
	}
	return &cfg, nil
}

// AutoLoadScanConfig attempts to load .waftester-spec.yaml from CWD.
// Returns nil if the file doesn't exist.
func AutoLoadScanConfig() (*ScanConfigFile, error) {
	return LoadScanConfigFile(".waftester-spec.yaml")
}

// FindOverride returns the first override matching the given endpoint path,
// or nil if no override matches.
func (f *ScanConfigFile) FindOverride(path string) *EndpointOverride {
	if f == nil {
		return nil
	}
	for i := range f.Overrides {
		if matchPathGlob(f.Overrides[i].Pattern, path) {
			return &f.Overrides[i]
		}
	}
	return nil
}

// ApplyToPlan filters a scan plan by removing entries for skipped endpoints
// and restricting scan types per the override rules.
func (f *ScanConfigFile) ApplyToPlan(plan *ScanPlan) {
	if f == nil || plan == nil || len(f.Overrides) == 0 {
		return
	}

	var kept []ScanPlanEntry
	for _, entry := range plan.Entries {
		override := f.FindOverride(entry.Endpoint.Path)
		if override == nil {
			kept = append(kept, entry)
			continue
		}

		// Skip entire endpoint.
		if override.Skip {
			continue
		}

		// Filter by scan types.
		if len(override.ScanTypes) > 0 && !containsStringCI(override.ScanTypes, entry.Attack.Category) {
			continue
		}
		if len(override.SkipTypes) > 0 && containsStringCI(override.SkipTypes, entry.Attack.Category) {
			continue
		}

		kept = append(kept, entry)
	}
	plan.Entries = kept
}

// matchPathGlob matches an endpoint path against a glob pattern.
// Supports standard filepath.Match syntax plus ** for recursive matching.
func matchPathGlob(pattern, path string) bool {
	// Handle ** (match any number of path segments).
	if strings.Contains(pattern, "**") {
		// Split at ** and check prefix/suffix.
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := parts[1]
		if !strings.HasPrefix(path, prefix) {
			return false
		}
		if suffix == "" {
			return true
		}
		return strings.HasSuffix(path, suffix)
	}

	matched, err := pathpkg.Match(pattern, path)
	if err != nil {
		// Invalid pattern: try prefix match.
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return matched
}

// containsStringCI reports whether strs contains s (case-insensitive).
func containsStringCI(strs []string, s string) bool {
	for _, v := range strs {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
