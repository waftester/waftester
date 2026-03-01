package probes

import (
	"net/http"
	"sort"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

// SecurityHeaders contains extracted security header information
type SecurityHeaders struct {
	// Common security headers
	ContentSecurityPolicy       string `json:"csp,omitempty"`
	ContentSecurityPolicyReport string `json:"csp_report,omitempty"`
	XFrameOptions               string `json:"x_frame_options,omitempty"`
	XContentTypeOptions         string `json:"x_content_type_options,omitempty"`
	XXSSProtection              string `json:"x_xss_protection,omitempty"`
	StrictTransportSecurity     string `json:"hsts,omitempty"`
	ReferrerPolicy              string `json:"referrer_policy,omitempty"`
	PermissionsPolicy           string `json:"permissions_policy,omitempty"`
	CrossOriginOpenerPolicy     string `json:"coop,omitempty"`
	CrossOriginEmbedderPolicy   string `json:"coep,omitempty"`
	CrossOriginResourcePolicy   string `json:"corp,omitempty"`

	// Server info headers
	Server            string `json:"server,omitempty"`
	XPoweredBy        string `json:"x_powered_by,omitempty"`
	XAspNetVersion    string `json:"x_aspnet_version,omitempty"`
	XAspNetMvcVersion string `json:"x_aspnetmvc_version,omitempty"`
	Via               string `json:"via,omitempty"`

	// Cookie security
	SetCookies []CookieInfo `json:"set_cookies,omitempty"`

	// Cache headers
	CacheControl string `json:"cache_control,omitempty"`
	Pragma       string `json:"pragma,omitempty"`
	Expires      string `json:"expires,omitempty"`

	// Custom/unusual headers
	Custom map[string]string `json:"custom,omitempty"`

	// Parsed CSP
	CSPDirectives map[string][]string `json:"csp_directives,omitempty"`

	// Parsed HSTS
	HSTSMaxAge            int  `json:"hsts_max_age,omitempty"`
	HSTSIncludeSubdomains bool `json:"hsts_include_subdomains,omitempty"`
	HSTSPreload           bool `json:"hsts_preload,omitempty"`

	// Analysis results
	MissingHeaders []string `json:"missing_headers,omitempty"`
	WeakHeaders    []string `json:"weak_headers,omitempty"`
	Grade          string   `json:"grade,omitempty"`
}

// CookieInfo contains cookie security information
type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	MaxAge   int    `json:"max_age,omitempty"`
}

// HeaderExtractor extracts and analyzes security headers
type HeaderExtractor struct {
	// Headers that indicate security posture
	SecurityHeaderNames []string
	// Headers that leak server info
	InfoLeakHeaders []string
}

// NewHeaderExtractor creates a new header extractor with defaults
func NewHeaderExtractor() *HeaderExtractor {
	return &HeaderExtractor{
		SecurityHeaderNames: []string{
			"Content-Security-Policy",
			"Content-Security-Policy-Report-Only",
			"X-Frame-Options",
			"X-Content-Type-Options",
			"X-XSS-Protection",
			"Strict-Transport-Security",
			"Referrer-Policy",
			"Permissions-Policy",
			"Feature-Policy",
			"Cross-Origin-Opener-Policy",
			"Cross-Origin-Embedder-Policy",
			"Cross-Origin-Resource-Policy",
		},
		InfoLeakHeaders: []string{
			"Server",
			"X-Powered-By",
			"X-AspNet-Version",
			"X-AspNetMvc-Version",
			"X-Runtime",
			"X-Version",
			"X-Generator",
		},
	}
}

// Extract extracts security headers from HTTP response
func (e *HeaderExtractor) Extract(resp *http.Response) *SecurityHeaders {
	if resp == nil {
		return &SecurityHeaders{}
	}

	headers := &SecurityHeaders{
		Custom:        make(map[string]string),
		CSPDirectives: make(map[string][]string),
	}

	h := resp.Header

	// Security headers
	headers.ContentSecurityPolicy = h.Get("Content-Security-Policy")
	headers.ContentSecurityPolicyReport = h.Get("Content-Security-Policy-Report-Only")
	headers.XFrameOptions = h.Get("X-Frame-Options")
	headers.XContentTypeOptions = h.Get("X-Content-Type-Options")
	headers.XXSSProtection = h.Get("X-XSS-Protection")
	headers.StrictTransportSecurity = h.Get("Strict-Transport-Security")
	headers.ReferrerPolicy = h.Get("Referrer-Policy")
	headers.PermissionsPolicy = h.Get("Permissions-Policy")
	if headers.PermissionsPolicy == "" {
		headers.PermissionsPolicy = h.Get("Feature-Policy")
	}
	headers.CrossOriginOpenerPolicy = h.Get("Cross-Origin-Opener-Policy")
	headers.CrossOriginEmbedderPolicy = h.Get("Cross-Origin-Embedder-Policy")
	headers.CrossOriginResourcePolicy = h.Get("Cross-Origin-Resource-Policy")

	// Server info headers
	headers.Server = h.Get("Server")
	headers.XPoweredBy = h.Get("X-Powered-By")
	headers.XAspNetVersion = h.Get("X-AspNet-Version")
	headers.XAspNetMvcVersion = h.Get("X-AspNetMvc-Version")
	headers.Via = h.Get("Via")

	// Cache headers
	headers.CacheControl = h.Get("Cache-Control")
	headers.Pragma = h.Get("Pragma")
	headers.Expires = h.Get("Expires")

	// Parse CSP if present
	if headers.ContentSecurityPolicy != "" {
		headers.CSPDirectives = parseCSP(headers.ContentSecurityPolicy)
	} else if headers.ContentSecurityPolicyReport != "" {
		headers.CSPDirectives = parseCSP(headers.ContentSecurityPolicyReport)
	}

	// Parse HSTS if present
	if headers.StrictTransportSecurity != "" {
		headers.HSTSMaxAge, headers.HSTSIncludeSubdomains, headers.HSTSPreload = parseHSTS(headers.StrictTransportSecurity)
	}

	// Extract cookies
	for _, c := range resp.Cookies() {
		cookie := CookieInfo{
			Name:     c.Name,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			Domain:   c.Domain,
			Path:     c.Path,
			MaxAge:   c.MaxAge,
		}
		switch c.SameSite {
		case http.SameSiteStrictMode:
			cookie.SameSite = "Strict"
		case http.SameSiteLaxMode:
			cookie.SameSite = "Lax"
		case http.SameSiteNoneMode:
			cookie.SameSite = "None"
		}
		headers.SetCookies = append(headers.SetCookies, cookie)
	}

	// Find custom/unusual headers
	standardHeaders := map[string]bool{
		"content-type": true, "content-length": true, "date": true,
		"connection": true, "keep-alive": true, "transfer-encoding": true,
		"content-encoding": true, "vary": true, "etag": true,
		"last-modified": true, "accept-ranges": true, "age": true,
	}

	// Sort header names for deterministic output
	headerNames := make([]string, 0, len(h))
	for name := range h {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	for _, name := range headerNames {
		lower := strings.ToLower(name)
		if !standardHeaders[lower] && !isKnownSecurityHeader(lower) {
			if strings.HasPrefix(lower, "x-") || strings.HasPrefix(lower, "cf-") {
				headers.Custom[name] = h.Get(name)
			}
		}
	}

	// Analyze missing headers
	headers.MissingHeaders = e.findMissingHeaders(headers)

	// Analyze weak headers
	headers.WeakHeaders = e.findWeakHeaders(headers)

	// Calculate grade
	headers.Grade = e.calculateGrade(headers)

	return headers
}

// parseCSP parses Content-Security-Policy into directives
func parseCSP(csp string) map[string][]string {
	directives := make(map[string][]string)

	// Split by semicolon
	parts := strings.Split(csp, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// First word is directive name, rest are values
		words := strings.Fields(part)
		if len(words) == 0 {
			continue
		}

		directive := strings.ToLower(words[0])
		values := words[1:]
		directives[directive] = values
	}

	return directives
}

// parseHSTS parses Strict-Transport-Security header
func parseHSTS(hsts string) (maxAge int, includeSubdomains, preload bool) {
	parts := strings.Split(strings.ToLower(hsts), ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.HasPrefix(part, "max-age=") {
			ageStr := strings.TrimPrefix(part, "max-age=")
			ageStr = strings.Trim(ageStr, "\"'")
			// Parse as int with overflow protection.
			// Cap at MaxInt32 since HSTS max-age is in seconds and
			// values above ~68 years are nonsensical.
			const maxHSTS = 1<<31 - 1
			for _, c := range ageStr {
				if c >= '0' && c <= '9' {
					next := maxAge*10 + int(c-'0')
					if next < maxAge || next > maxHSTS { // overflow or unreasonable
						maxAge = maxHSTS
						break
					}
					maxAge = next
				} else {
					break
				}
			}
		} else if part == "includesubdomains" {
			includeSubdomains = true
		} else if part == "preload" {
			preload = true
		}
	}

	return
}

// isKnownSecurityHeader checks if header is a known security header
func isKnownSecurityHeader(name string) bool {
	known := []string{
		"content-security-policy", "content-security-policy-report-only",
		"x-frame-options", "x-content-type-options", "x-xss-protection",
		"strict-transport-security", "referrer-policy", "permissions-policy",
		"feature-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy",
		"cross-origin-resource-policy", "server", "x-powered-by", "x-aspnet-version",
		"x-aspnetmvc-version", "via", "cache-control", "pragma", "expires",
		"set-cookie",
	}

	for _, k := range known {
		if name == k {
			return true
		}
	}
	return false
}

// findMissingHeaders identifies missing security headers
func (e *HeaderExtractor) findMissingHeaders(h *SecurityHeaders) []string {
	var missing []string

	if h.ContentSecurityPolicy == "" && h.ContentSecurityPolicyReport == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if h.XFrameOptions == "" {
		missing = append(missing, "X-Frame-Options")
	}
	if h.XContentTypeOptions == "" {
		missing = append(missing, "X-Content-Type-Options")
	}
	if h.StrictTransportSecurity == "" {
		missing = append(missing, "Strict-Transport-Security")
	}
	if h.ReferrerPolicy == "" {
		missing = append(missing, "Referrer-Policy")
	}

	return missing
}

// findWeakHeaders identifies weakly configured headers
func (e *HeaderExtractor) findWeakHeaders(h *SecurityHeaders) []string {
	var weak []string

	// Check CSP for unsafe directives (sorted for deterministic output)
	if csp := h.CSPDirectives; len(csp) > 0 {
		directives := make([]string, 0, len(csp))
		for d := range csp {
			directives = append(directives, d)
		}
		sort.Strings(directives)
		for _, directive := range directives {
			for _, v := range csp[directive] {
				if v == "'unsafe-inline'" || v == "'unsafe-eval'" {
					weak = append(weak, "CSP: "+directive+" uses "+v)
				}
				if v == "*" {
					weak = append(weak, "CSP: "+directive+" uses wildcard")
				}
			}
		}
	}

	// Check HSTS max-age
	if h.StrictTransportSecurity != "" && h.HSTSMaxAge < 31536000 { // Less than 1 year
		weak = append(weak, "HSTS: max-age is less than 1 year")
	}

	// Check X-Frame-Options
	if h.XFrameOptions != "" {
		upper := strings.ToUpper(h.XFrameOptions)
		if upper == "ALLOWALL" || strings.Contains(upper, "ALLOW-FROM") {
			weak = append(weak, "X-Frame-Options: weak value")
		}
	}

	// Check cookie security
	for _, c := range h.SetCookies {
		if !c.HttpOnly {
			weak = append(weak, "Cookie "+c.Name+": missing HttpOnly")
		}
		if !c.Secure {
			weak = append(weak, "Cookie "+c.Name+": missing Secure")
		}
		if c.SameSite == "" || c.SameSite == "None" {
			weak = append(weak, "Cookie "+c.Name+": weak SameSite")
		}
	}

	// Check for info leak headers
	if h.Server != "" && len(h.Server) > 20 {
		weak = append(weak, "Server header exposes version info")
	}
	if h.XPoweredBy != "" {
		weak = append(weak, "X-Powered-By header present")
	}
	if h.XAspNetVersion != "" {
		weak = append(weak, "X-AspNet-Version header present")
	}

	return weak
}

// calculateGrade calculates security header grade
func (e *HeaderExtractor) calculateGrade(h *SecurityHeaders) string {
	score := 100

	// Missing headers
	score -= len(h.MissingHeaders) * 15

	// Weak headers
	score -= len(h.WeakHeaders) * 5

	// Bonuses for good practices
	if h.HSTSPreload {
		score += 5
	}
	if h.HSTSIncludeSubdomains {
		score += 5
	}
	if len(h.CSPDirectives) > 5 {
		score += 10 // Comprehensive CSP
	}
	if h.CrossOriginOpenerPolicy != "" {
		score += 5
	}
	if h.CrossOriginEmbedderPolicy != "" {
		score += 5
	}

	// Calculate grade
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// CSPInfo provides structured CSP information
type CSPInfo struct {
	Raw        string              `json:"raw"`
	Directives map[string][]string `json:"directives"`
	ReportURI  string              `json:"report_uri,omitempty"`
	ReportTo   string              `json:"report_to,omitempty"`
	Issues     []string            `json:"issues,omitempty"`
}

// AnalyzeCSP performs deep analysis of CSP
func AnalyzeCSP(csp string) *CSPInfo {
	info := &CSPInfo{
		Raw:        csp,
		Directives: parseCSP(csp),
	}

	// Extract report endpoints
	if uris, ok := info.Directives["report-uri"]; ok && len(uris) > 0 {
		info.ReportURI = uris[0]
	}
	if to, ok := info.Directives["report-to"]; ok && len(to) > 0 {
		info.ReportTo = to[0]
	}

	// Analyze issues
	info.Issues = analyzeCSPIssues(info.Directives)

	return info
}

// analyzeCSPIssues finds security issues in CSP
func analyzeCSPIssues(directives map[string][]string) []string {
	var issues []string

	// Check for dangerous values
	dangerous := map[string][]string{
		"script-src": {"'unsafe-inline'", "'unsafe-eval'", "data:", "blob:"},
		"style-src":  {"'unsafe-inline'"},
		"object-src": {"*", "data:", "blob:"},
		"base-uri":   {"*", "data:"},
	}

	// Sort dangerous directive keys for deterministic output
	dangerousKeys := make([]string, 0, len(dangerous))
	for k := range dangerous {
		dangerousKeys = append(dangerousKeys, k)
	}
	sort.Strings(dangerousKeys)
	for _, directive := range dangerousKeys {
		dangerousVals := dangerous[directive]
		if vals, ok := directives[directive]; ok {
			for _, v := range vals {
				matched := false
				for _, d := range dangerousVals {
					if v == d {
						issues = append(issues, directive+" contains "+d)
						matched = true
						break
					}
				}
				// Check for wildcards (skip if already reported as dangerous value)
				if !matched && (v == "*" || strings.HasPrefix(v, "*.")) {
					issues = append(issues, directive+" contains wildcard "+v)
				}
			}
		}
	}

	// Check for missing important directives
	important := []string{"default-src", "script-src", "object-src", "base-uri"}
	for _, d := range important {
		if _, ok := directives[d]; !ok {
			// Check if covered by default-src
			if _, hasDefault := directives["default-src"]; !hasDefault {
				issues = append(issues, "Missing "+d+" directive")
			}
		}
	}

	// Check for JSONP/callback bypasses
	jsonpBypass := regexcache.MustGet(`(?i)(googleapis\.com|google\.com|facebook\.com|\.cloudflare\.com)`)
	for _, vals := range directives {
		for _, v := range vals {
			if jsonpBypass.MatchString(v) {
				issues = append(issues, "Potential JSONP bypass via "+v)
			}
		}
	}

	sort.Strings(issues)
	return issues
}

// ExtractDomainsFromCSP extracts all domains mentioned in CSP
func ExtractDomainsFromCSP(csp string) []string {
	domainRE := regexcache.MustGet(`(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}`)

	matches := domainRE.FindAllString(csp, -1)
	domains := make(map[string]bool)

	for _, m := range matches {
		// Clean up
		m = strings.TrimPrefix(m, "https://")
		m = strings.TrimPrefix(m, "http://")
		m = strings.TrimSuffix(m, "/")
		m = strings.ToLower(m)
		domains[m] = true
	}

	result := make([]string, 0, len(domains))
	for d := range domains {
		result = append(result, d)
	}

	sort.Strings(result)
	return result
}
