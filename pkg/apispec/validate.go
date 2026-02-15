package apispec

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SpecValidationResult holds the output of ValidateSpec.
type SpecValidationResult struct {
	// Valid is true if no errors were found (warnings are OK).
	Valid bool `json:"valid"`

	// Errors are hard failures that block scanning.
	Errors []ValidationIssue `json:"errors,omitempty"`

	// Warnings are informational findings that don't block scanning.
	Warnings []ValidationIssue `json:"warnings,omitempty"`

	// Spec is the parsed spec if validation succeeded (nil on structural errors).
	Spec *Spec `json:"-"`
}

// ValidationIssue describes a single validation finding.
type ValidationIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"` // JSON path to the issue (e.g., "paths./users.get")
}

// ValidateSpec performs pre-scan validation on a spec file.
// It checks syntax, $ref resolution, SSRF blocklist, credential
// detection, and other security concerns. Pass allowInternal=true
// to skip the SSRF blocklist for internal/private server URLs.
func ValidateSpec(path string, allowInternal bool) (*SpecValidationResult, error) {
	result := &SpecValidationResult{Valid: true}

	data, err := loadFile(path)
	if err != nil {
		return nil, err
	}

	format := detectFormat(data, path)
	if format == FormatUnknown {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationIssue{
			Code:    "unsupported_format",
			Message: "Could not detect spec format. Supported: OpenAPI 3.x, Swagger 2.0, Postman v2.x, HAR v1.2.",
		})
		return result, nil
	}

	spec, err := parseByFormat(data, path, format)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationIssue{
			Code:    "parse_error",
			Message: fmt.Sprintf("Failed to parse spec: %v", err),
		})
		return result, nil
	}

	result.Spec = spec

	// Run validation checks
	validateServerURLs(spec, allowInternal, result)
	validateRefs(data, path, format, result)
	detectCredentials(data, result)
	detectPreRequestScripts(data, format, result)
	validateVariableURLs(spec, allowInternal, result)

	return result, nil
}

// CheckServerURLs validates that no server URL targets an internal/blocked address.
// Returns an error listing all blocked URLs, or nil if all are safe.
// This is the lightweight guard for scan entry points — it runs inline
// without the full ValidateSpec machinery (ref checks, credential detection).
func CheckServerURLs(spec *Spec) error {
	var blocked []string
	for _, server := range spec.Servers {
		if isBlockedURL(server.URL) {
			blocked = append(blocked, server.URL)
		}
	}
	if len(blocked) > 0 {
		return fmt.Errorf("server URLs blocked by SSRF policy (use --allow-internal to override): %s",
			strings.Join(blocked, ", "))
	}
	return nil
}

// validateServerURLs checks server URLs against the SSRF blocklist.
func validateServerURLs(spec *Spec, allowInternal bool, result *SpecValidationResult) {
	if allowInternal {
		return
	}

	for _, server := range spec.Servers {
		if isBlockedURL(server.URL) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationIssue{
				Code:    "ssrf_blocked",
				Message: fmt.Sprintf("Server URL %q is blocked by SSRF policy. Use --allow-internal to override.", server.URL),
				Path:    "servers",
			})
		}
	}
}

// validateRefs checks $ref references for circular chains and path traversal.
// Only applies to JSON/YAML-based specs (OpenAPI, Swagger).
func validateRefs(data []byte, specPath string, format Format, result *SpecValidationResult) {
	if format != FormatOpenAPI3 && format != FormatSwagger2 {
		return
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		// YAML spec — convert to JSON-compatible map via yaml.Unmarshal.
		var raw interface{}
		if yamlErr := yaml.Unmarshal(data, &raw); yamlErr != nil {
			return // Neither valid JSON nor YAML.
		}
		jsonData, jsonErr := json.Marshal(convertYAMLToJSON(raw))
		if jsonErr != nil {
			return
		}
		if err2 := json.Unmarshal(jsonData, &doc); err2 != nil {
			return
		}
	}

	specDir := filepath.Dir(specPath)
	// Track all unique $ref values instead of using a recursive visited set.
	// Circular refs would need chain tracking — this simple approach detects
	// only path traversal, external refs, and file:// refs.
	findRefs(doc, specDir, result, "")
}

// findRefs recursively walks a parsed JSON document looking for $ref keys.
func findRefs(node any, specDir string, result *SpecValidationResult, jsonPath string) {
	switch v := node.(type) {
	case map[string]any:
		if ref, ok := v["$ref"].(string); ok {
			checkRef(ref, specDir, result, jsonPath)
		}
		for key, val := range v {
			childPath := jsonPath + "." + key
			findRefs(val, specDir, result, childPath)
		}
	case []any:
		for i, val := range v {
			childPath := fmt.Sprintf("%s[%d]", jsonPath, i)
			findRefs(val, specDir, result, childPath)
		}
	}
}

// checkRef validates a single $ref value.
func checkRef(ref, specDir string, result *SpecValidationResult, jsonPath string) {
	// Check for external HTTP references
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationIssue{
			Code:    "external_ref",
			Message: fmt.Sprintf("External $ref not supported: %s", ref),
			Path:    jsonPath,
		})
		return
	}

	// Check for file:// protocol
	if strings.HasPrefix(ref, "file://") {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationIssue{
			Code:    "file_ref_blocked",
			Message: fmt.Sprintf("file:// $ref blocked: %s", ref),
			Path:    jsonPath,
		})
		return
	}

	// Check for path traversal in external file refs
	// External refs look like "./models/pet.yaml#/definitions/Pet"
	if strings.Contains(ref, "/") && !strings.HasPrefix(ref, "#") {
		filePart := ref
		if idx := strings.Index(ref, "#"); idx >= 0 {
			filePart = ref[:idx]
		}

		// Reject absolute paths
		if filepath.IsAbs(filePart) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationIssue{
				Code:    "path_traversal",
				Message: fmt.Sprintf("Absolute path in $ref blocked: %s", ref),
				Path:    jsonPath,
			})
			return
		}

		// Reject path traversal
		if strings.Contains(filePart, "..") {
			absSpecDir, absErr := filepath.Abs(specDir)
			resolved := filepath.Join(specDir, filePart)
			resolved = filepath.Clean(resolved)
			absResolved, resErr := filepath.Abs(resolved)
			// Use absolute paths with trailing separator to prevent sibling
			// directory prefix matches (e.g., /app/specs vs /app/specs-evil).
			if absErr != nil || resErr != nil ||
				!strings.HasPrefix(absResolved+string(filepath.Separator), absSpecDir+string(filepath.Separator)) {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationIssue{
					Code:    "path_traversal",
					Message: fmt.Sprintf("Path traversal in $ref blocked: %s", ref),
					Path:    jsonPath,
				})
				return
			}
		}

		// Check file exists (warn, don't block)
		filePart = filepath.Join(specDir, filePart)
		if _, err := os.Stat(filePart); err != nil {
			result.Warnings = append(result.Warnings, ValidationIssue{
				Code:    "unresolvable_ref",
				Message: fmt.Sprintf("External $ref file not found: %s", ref),
				Path:    jsonPath,
			})
		}
	}
}

// credentialPatterns matches common credential-like values in specs.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Bearer\s+ey[A-Za-z0-9_-]+`),                        // JWT token
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_-]{20,}`), // API key assignment
	regexp.MustCompile(`(?i)password\s*[:=]\s*[^\s"']{8,}`),                    // Password assignment
	regexp.MustCompile(`(?i)(secret|token)\s*[:=]\s*[A-Za-z0-9_-]{20,}`),       // Secret/token assignment
}

// detectCredentials scans raw spec data for credential-like patterns.
func detectCredentials(data []byte, result *SpecValidationResult) {
	text := string(data)
	for _, pattern := range credentialPatterns {
		if loc := pattern.FindStringIndex(text); loc != nil {
			// Don't include the actual credential in the warning
			result.Warnings = append(result.Warnings, ValidationIssue{
				Code:    "credential_detected",
				Message: "Spec contains what appears to be a credential or secret. Consider removing it before sharing.",
			})
			return // One warning is enough
		}
	}
}

// detectPreRequestScripts checks for Postman pre-request scripts.
func detectPreRequestScripts(data []byte, format Format, result *SpecValidationResult) {
	if format != FormatPostman {
		return
	}

	// Quick check for pre-request scripts
	if strings.Contains(string(data), `"prerequest"`) {
		result.Warnings = append(result.Warnings, ValidationIssue{
			Code:    "pre_request_script",
			Message: "Collection contains pre-request scripts. These may set variables or perform setup that WAFtester cannot replicate automatically.",
		})
	}
}

// validateVariableURLs checks that variable-substituted server URLs
// don't resolve to SSRF-blocked targets.
func validateVariableURLs(spec *Spec, allowInternal bool, result *SpecValidationResult) {
	if allowInternal {
		return
	}

	for _, server := range spec.Servers {
		resolved := SubstituteVariables(server.URL, spec.Variables)
		if resolved != server.URL && isBlockedURL(resolved) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationIssue{
				Code:    "ssrf_variable_url",
				Message: fmt.Sprintf("Server URL resolves to blocked address after variable substitution: %s -> %s", server.URL, resolved),
				Path:    "servers",
			})
		}
	}
}

// hasTemplateHost checks if the URL's hostname portion contains template
// variables ({{ ... }}). We extract the hostname manually because Go's
// url.Parse rejects {{ in hostnames.
func hasTemplateHost(rawURL string) bool {
	// Strip scheme (e.g., "https://")
	rest := rawURL
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	// Everything before the first / is the authority (host:port).
	if idx := strings.Index(rest, "/"); idx >= 0 {
		rest = rest[:idx]
	}
	return strings.Contains(rest, "{{")
}

// SSRF blocklist — blocks requests to internal networks, metadata endpoints,
// and non-HTTP schemes.
func isBlockedURL(rawURL string) bool {
	// Check for template variables in the authority (hostname) portion
	// before url.Parse, because Go's parser rejects {{ in hostnames.
	// Only skip when the hostname itself is templated — {{ in paths
	// must NOT bypass the check (e.g., http://169.254.169.254/{{x).
	if hasTemplateHost(rawURL) {
		return false
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return true // Unparseable URLs are blocked
	}

	// Block non-HTTP schemes
	scheme := strings.ToLower(u.Scheme)
	if scheme != "" && scheme != "http" && scheme != "https" {
		return true
	}

	host := u.Hostname()
	if host == "" {
		return false // Relative URLs are OK
	}

	// Block localhost variants
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "0.0.0.0" {
		return true
	}

	// Block metadata endpoints
	if lower == "169.254.169.254" || lower == "metadata.google.internal" {
		return true
	}

	// Block private IP ranges
	ip := net.ParseIP(host)
	if ip == nil {
		// Try numeric IP notations that net.ParseIP doesn't handle.
		// These are common SSRF bypass techniques.
		ip = parseNumericIP(host)
	}
	if ip == nil {
		return false // Non-IP hostnames pass
	}

	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// parseNumericIP handles IP notations that net.ParseIP rejects:
//   - Decimal: 2130706433 → 127.0.0.1
//   - Octal:   0177.0.0.01 → 127.0.0.1
//   - Short:   127.1 → 127.0.0.1
func parseNumericIP(host string) net.IP {
	// Hex notation: 0x7f000001 → 127.0.0.1
	if strings.HasPrefix(host, "0x") || strings.HasPrefix(host, "0X") {
		if n, err := strconv.ParseUint(host[2:], 16, 32); err == nil {
			return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		}
	}

	// Decimal notation: single integer representing the full 32-bit address.
	if n, err := strconv.ParseUint(host, 10, 32); err == nil {
		return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}

	// Octal notation: any dotted-quad component starting with '0' is octal.
	parts := strings.Split(host, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil
	}
	hasOctal := false
	hasHexOctet := false
	for _, p := range parts {
		if len(p) > 2 && (strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X")) {
			hasHexOctet = true
		} else if len(p) > 1 && p[0] == '0' {
			hasOctal = true
		}
	}
	// Short notation: 127.1 (2 parts) or 127.0.1 (3 parts).
	if !hasOctal && !hasHexOctet && len(parts) == 4 {
		return nil // Standard dotted-quad without octal; net.ParseIP already handles this.
	}

	// Parse each component, handling octal and hex prefixes.
	octets := make([]byte, 4)
	for i, p := range parts {
		base := 10
		cleanP := p
		if len(p) > 2 && (strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X")) {
			base = 16
			cleanP = p[2:]
		} else if len(p) > 1 && p[0] == '0' {
			base = 8
		}
		v, err := strconv.ParseUint(cleanP, base, 32)
		if err != nil {
			return nil
		}
		if i == len(parts)-1 {
			// Last part absorbs remaining octets (e.g., 127.1 → 127.0.0.1).
			remaining := 4 - i
			max := uint64(1) << (uint(remaining) * 8)
			if v >= max {
				return nil
			}
			for j := remaining - 1; j >= 0; j-- {
				octets[i+j] = byte(v & 0xFF)
				v >>= 8
			}
		} else {
			if v > 255 {
				return nil
			}
			octets[i] = byte(v)
		}
	}
	return net.IPv4(octets[0], octets[1], octets[2], octets[3])
}
