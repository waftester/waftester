package payloadprovider

import (
	"sort"
	"strings"

	"github.com/waftester/waftester/pkg/nuclei"
)

// CategoryMapper bidirectionally maps between JSON payload categories
// and Nuclei template tags. This allows queries like "sqli" to find
// payloads whether they live in "SQL-Injection" JSON files or in
// Nuclei templates tagged "sqli".
type CategoryMapper struct {
	// tagToCategory maps a Nuclei tag to its canonical JSON category.
	tagToCategory map[string]string

	// categoryToTags maps a JSON category (lowercase key) to matching Nuclei tags.
	categoryToTags map[string][]string

	// aliases maps alternative names to canonical category names.
	aliases map[string]string

	// canonicalNames maps lowercase category key to the proper-cased canonical name.
	canonicalNames map[string]string
}

// NewCategoryMapper returns a mapper pre-loaded with the standard
// WAFtester category↔tag relationships.
func NewCategoryMapper() *CategoryMapper {
	m := &CategoryMapper{
		tagToCategory:  make(map[string]string),
		categoryToTags: make(map[string][]string),
		aliases:        make(map[string]string),
		canonicalNames: make(map[string]string),
	}

	// ── SQL Injection ──────────────────────────────────────────────
	m.register("SQL-Injection", "sqli", "sql-injection", "sql", "sqli-bypass")
	m.alias("sqli", "SQL-Injection")
	m.alias("sql-injection", "SQL-Injection")
	m.alias("sql injection", "SQL-Injection")

	// ── XSS ────────────────────────────────────────────────────────
	m.register("XSS", "xss", "cross-site-scripting", "xss-bypass", "reflected-xss", "stored-xss", "dom-xss")
	m.alias("cross-site-scripting", "XSS")
	m.alias("cross site scripting", "XSS")

	// ── Command Injection ──────────────────────────────────────────
	m.register("Command-Injection", "rce", "command-injection", "os-command", "cmdi")
	m.alias("rce", "Command-Injection")
	m.alias("os-command-injection", "Command-Injection")
	m.alias("cmdi", "Command-Injection")

	// ── SSRF ───────────────────────────────────────────────────────
	m.register("SSRF", "ssrf", "server-side-request-forgery", "ssrf-bypass")
	m.alias("server-side-request-forgery", "SSRF")

	// ── SSTI ───────────────────────────────────────────────────────
	m.register("SSTI", "ssti", "server-side-template-injection", "ssti-bypass", "template-injection")
	m.alias("template-injection", "SSTI")
	m.alias("server-side-template-injection", "SSTI")

	// ── LFI / Path Traversal ───────────────────────────────────────
	m.register("Path-Traversal", "lfi", "path-traversal", "directory-traversal", "lfi-bypass", "file-inclusion", "traversal")
	m.alias("lfi", "Path-Traversal")
	m.alias("directory-traversal", "Path-Traversal")
	m.alias("file-inclusion", "Path-Traversal")
	m.alias("traversal", "Path-Traversal")

	// ── XXE ────────────────────────────────────────────────────────
	m.register("XXE", "xxe", "xml-external-entity", "xxe-bypass")
	m.alias("xml-external-entity", "XXE")

	// ── NoSQL Injection ────────────────────────────────────────────
	m.register("NoSQL-Injection", "nosqli", "nosql-injection", "nosqli-bypass", "mongodb-injection")
	m.alias("nosqli", "NoSQL-Injection")
	m.alias("nosql-injection", "NoSQL-Injection")
	m.alias("nosql", "NoSQL-Injection")

	// ── CRLF Injection ─────────────────────────────────────────────
	m.register("CRLF-Injection", "crlf", "crlf-injection", "crlf-bypass", "header-injection")
	m.alias("crlf", "CRLF-Injection")
	m.alias("header-injection", "CRLF-Injection")

	// ── CORS ───────────────────────────────────────────────────────
	m.register("CORS", "cors", "cross-origin", "cors-misconfiguration", "origin-reflection")
	m.alias("cors", "CORS")
	m.alias("cross-origin", "CORS")

	// ── CSRF ───────────────────────────────────────────────────────
	m.register("CSRF", "csrf", "cross-site-request-forgery", "token-bypass")
	m.alias("csrf", "CSRF")
	m.alias("cross-site-request-forgery", "CSRF")

	// ── LDAP Injection ─────────────────────────────────────────────
	m.register("LDAP-Injection", "ldap", "ldap-injection")
	m.alias("ldap", "LDAP-Injection")

	// ── XPath Injection ────────────────────────────────────────────
	m.register("XPath-Injection", "xpath", "xpath-injection")
	m.alias("xpath", "XPath-Injection")

	// ── XML Injection ──────────────────────────────────────────────
	m.register("XML-Injection", "xml-injection", "xml")
	m.alias("xml-injection", "XML-Injection")

	// ── Prototype Pollution ────────────────────────────────────────
	m.register("Prototype-Pollution", "prototype-pollution", "proto-pollution")
	m.alias("prototype-pollution", "Prototype-Pollution")
	m.alias("proto-pollution", "Prototype-Pollution")
	m.alias("prototype", "Prototype-Pollution")

	// ── Request Smuggling ──────────────────────────────────────────
	m.register("Request-Smuggling", "request-smuggling", "http-smuggling", "http-desync", "smuggling")
	m.alias("request-smuggling", "Request-Smuggling")
	m.alias("http-smuggling", "Request-Smuggling")
	m.alias("smuggling", "Request-Smuggling")

	// ── Response Splitting ─────────────────────────────────────────
	m.register("Response-Splitting", "response-splitting", "http-response-split")
	m.alias("response-splitting", "Response-Splitting")

	// ── WAF Bypass ─────────────────────────────────────────────────
	m.register("WAF-Bypass", "waf-bypass", "bypass", "evasion", "waf")
	m.alias("waf-bypass", "WAF-Bypass")
	m.alias("bypass", "WAF-Bypass")
	m.alias("evasion", "WAF-Bypass")

	// ── Authentication ─────────────────────────────────────────────
	m.register("Authentication", "auth", "jwt", "oauth", "session", "broken-auth")
	m.alias("jwt", "Authentication")
	m.alias("oauth", "Authentication")
	m.alias("broken-auth", "Authentication")
	m.alias("brokenauth", "Authentication")
	m.alias("broken-authentication", "Authentication")

	// ── GraphQL ────────────────────────────────────────────────────
	m.register("GraphQL", "graphql", "graphql-injection")
	m.alias("graphql", "GraphQL")

	// ── Deserialization ────────────────────────────────────────────
	m.register("Deserialization", "deserialization", "insecure-deserialization")
	m.alias("deserialization", "Deserialization")
	m.alias("insecure-deserialization", "Deserialization")
	m.alias("deserialize", "Deserialization")

	// ── Cache Poisoning ────────────────────────────────────────────
	m.register("Cache-Poisoning", "cache-poisoning", "web-cache", "cache")
	m.alias("cache-poisoning", "Cache-Poisoning")
	m.alias("cache", "Cache-Poisoning")

	// ── Upload ─────────────────────────────────────────────────────
	m.register("Upload", "upload", "file-upload", "upload-bypass")
	m.alias("file-upload", "Upload")
	m.alias("upload", "Upload")

	// ── Fuzz ───────────────────────────────────────────────────────
	m.register("Fuzz", "fuzz", "fuzzing")
	m.alias("fuzz", "Fuzz")
	m.alias("fuzzing", "Fuzz")

	// ── RFI ────────────────────────────────────────────────────────
	m.register("RFI", "rfi", "remote-file-inclusion")
	m.alias("rfi", "RFI")

	// ── Open Redirect ──────────────────────────────────────────────
	m.register("Open-Redirect", "open-redirect", "redirect", "url-redirect", "unvalidated-redirect")
	m.alias("open-redirect", "Open-Redirect")
	m.alias("redirect", "Open-Redirect")
	m.alias("url-redirect", "Open-Redirect")

	// ── Polyglot ───────────────────────────────────────────────────
	m.register("Polyglot", "polyglot", "multi-context", "multi-vector")
	m.alias("polyglot", "Polyglot")
	m.alias("multi-context", "Polyglot")

	// ── AI / Prompt Injection ──────────────────────────────────────
	m.register("AI", "ai", "prompt-injection", "ml-poisoning", "llm")
	m.alias("ai", "AI")
	m.alias("prompt-injection", "AI")

	// ── Injection (generic) ────────────────────────────────────────
	m.register("Injection", "injection", "generic-injection")
	m.alias("injection", "Injection")

	// ── Logic / Business Logic ─────────────────────────────────────
	m.register("Logic", "logic", "business-logic", "idor", "privilege-escalation", "forced-browsing")
	m.alias("logic", "Logic")
	m.alias("business-logic", "Logic")
	m.alias("idor", "Logic")
	m.alias("bizlogic", "Logic")

	// ── Media ──────────────────────────────────────────────────────
	m.register("Media", "media", "exif-injection", "metadata-poison")
	m.alias("media", "Media")

	// ── Obfuscation ────────────────────────────────────────────────
	m.register("Obfuscation", "obfuscation", "encoding-evasion")
	m.alias("obfuscation", "Obfuscation")

	// ── Protocol ───────────────────────────────────────────────────
	m.register("Protocol", "protocol", "http2", "grpc")
	m.alias("protocol", "Protocol")

	// ── WebSocket ──────────────────────────────────────────────────
	m.register("WebSocket", "websocket", "ws", "cross-site-websocket-hijacking")
	m.alias("websocket", "WebSocket")
	m.alias("ws", "WebSocket")

	// ── Rate Limiting ──────────────────────────────────────────────
	m.register("Rate-Limiting", "ratelimit", "rate-limit", "rate-limiting", "burst")
	m.alias("ratelimit", "Rate-Limiting")
	m.alias("rate-limit", "Rate-Limiting")

	// ── HPP ────────────────────────────────────────────────────────
	m.register("HTTP-Parameter-Pollution", "hpp", "parameter-pollution")
	m.alias("hpp", "HTTP-Parameter-Pollution")
	m.alias("parameter-pollution", "HTTP-Parameter-Pollution")

	// ── Host Header Injection ──────────────────────────────────────
	m.register("Host-Header-Injection", "host-header", "host-header-injection")
	m.alias("host-header", "Host-Header-Injection")
	m.alias("host-header-injection", "Host-Header-Injection")
	m.alias("hostheader", "Host-Header-Injection")

	// ── Clickjacking ───────────────────────────────────────────────
	m.register("Clickjacking", "clickjacking", "x-frame-options", "ui-redressing")
	m.alias("clickjacking", "Clickjacking")
	m.alias("clickjack", "Clickjacking")

	// ── Access Control ─────────────────────────────────────────────
	m.register("Access-Control", "access-control", "broken-access-control", "authorization-bypass")
	m.alias("access-control", "Access-Control")
	m.alias("broken-access-control", "Access-Control")
	m.alias("accesscontrol", "Access-Control")

	// ── Race Condition ─────────────────────────────────────────────
	m.register("Race-Condition", "race-condition", "race", "toctou", "concurrency")
	m.alias("race-condition", "Race-Condition")
	m.alias("race", "Race-Condition")

	// ── Subdomain Takeover ─────────────────────────────────────────
	m.register("Subdomain-Takeover", "subdomain-takeover", "dangling-cname", "dns-hijack")
	m.alias("subdomain-takeover", "Subdomain-Takeover")
	m.alias("subtakeover", "Subdomain-Takeover")

	// ── Session Fixation ───────────────────────────────────────────
	m.register("Session-Fixation", "session-fixation", "session-hijack")
	m.alias("session-fixation", "Session-Fixation")
	m.alias("sessionfixation", "Session-Fixation")

	// ── Mass Assignment ────────────────────────────────────────────
	m.register("Mass-Assignment", "mass-assignment", "parameter-binding", "object-injection")
	m.alias("mass-assignment", "Mass-Assignment")
	m.alias("massassignment", "Mass-Assignment")

	// ── SSI Injection ──────────────────────────────────────────────
	m.register("SSI-Injection", "ssi", "server-side-includes", "ssi-injection")
	m.alias("ssi", "SSI-Injection")
	m.alias("server-side-includes", "SSI-Injection")

	// ── Security Misconfiguration ──────────────────────────────────
	m.register("Security-Misconfiguration", "misconfiguration", "security-headers", "debug-endpoints")
	m.alias("misconfiguration", "Security-Misconfiguration")
	m.alias("security-misconfiguration", "Security-Misconfiguration")
	m.alias("securitymisconfig", "Security-Misconfiguration")

	// ── Sensitive Data Exposure ────────────────────────────────────
	m.register("Sensitive-Data-Exposure", "sensitive-data", "information-disclosure", "data-leakage")
	m.alias("sensitive-data", "Sensitive-Data-Exposure")
	m.alias("information-disclosure", "Sensitive-Data-Exposure")
	m.alias("sensitivedata", "Sensitive-Data-Exposure")

	// ── Cryptographic Failure ──────────────────────────────────────
	m.register("Cryptographic-Failure", "crypto-failure", "weak-tls", "weak-cipher")
	m.alias("crypto-failure", "Cryptographic-Failure")
	m.alias("cryptofailure", "Cryptographic-Failure")
	m.alias("weak-crypto", "Cryptographic-Failure")

	// ── API Abuse ──────────────────────────────────────────────────
	m.register("API-Abuse", "api-abuse", "api-security", "resource-exhaustion")
	m.alias("api-abuse", "API-Abuse")
	m.alias("apiabuse", "API-Abuse")

	// ── Service-Specific ───────────────────────────────────────────
	m.register("Service-Specific", "service-specific", "vendor-specific")
	m.alias("service-specific", "Service-Specific")

	// ── WAF Validation ─────────────────────────────────────────────
	m.register("WAF-Validation", "waf-validation", "waf-testing", "rule-validation")
	m.alias("waf-validation", "WAF-Validation")

	// ── OWASP Top 10 ───────────────────────────────────────────────
	m.register("OWASP-Top10", "owasp-top10", "owasp", "top10")
	m.alias("owasp-top10", "OWASP-Top10")
	m.alias("owasp", "OWASP-Top10")

	// ── Regression ─────────────────────────────────────────────────
	m.register("Regression", "regression", "regression-test")
	m.alias("regression", "Regression")

	return m
}

// register sets up a canonical category name with its associated Nuclei tags.
func (m *CategoryMapper) register(canonicalCategory string, tags ...string) {
	lower := strings.ToLower(canonicalCategory)
	m.categoryToTags[lower] = tags
	m.canonicalNames[lower] = canonicalCategory

	for _, tag := range tags {
		m.tagToCategory[strings.ToLower(tag)] = canonicalCategory
	}
}

// alias maps an alternative name to a canonical category.
func (m *CategoryMapper) alias(aliasName, canonicalCategory string) {
	m.aliases[strings.ToLower(aliasName)] = canonicalCategory
}

// Resolve returns all canonical category names that match the input.
// For "sqli" it returns ["SQL-Injection"].
// For an unknown category, it returns the input as-is.
func (m *CategoryMapper) Resolve(input string) []string {
	lower := strings.ToLower(input)

	// Direct alias?
	if canonical, ok := m.aliases[lower]; ok {
		return []string{canonical}
	}

	// Tag → category?
	if cat, ok := m.tagToCategory[lower]; ok {
		return []string{cat}
	}

	// Category → itself (use canonical name)?
	if name, ok := m.canonicalNames[lower]; ok {
		return []string{name}
	}

	// Unknown: return as-is
	return []string{input}
}

// TagsToCategories converts a list of Nuclei template tags into
// JSON-compatible category names.
func (m *CategoryMapper) TagsToCategories(tags []string) []string {
	seen := make(map[string]bool, len(tags))
	var cats []string

	for _, tag := range tags {
		lower := strings.ToLower(strings.TrimSpace(tag))
		if cat, ok := m.tagToCategory[lower]; ok {
			if !seen[cat] {
				seen[cat] = true
				cats = append(cats, cat)
			}
		}
	}

	return cats
}

// CategoriesToTags converts a JSON category name into matching Nuclei
// template tags for filtering.
// The returned slice is a copy; callers may freely modify it.
func (m *CategoryMapper) CategoriesToTags(category string) []string {
	lower := strings.ToLower(category)

	// Check aliases first
	if canonical, ok := m.aliases[lower]; ok {
		lower = strings.ToLower(canonical)
	}

	if tags, ok := m.categoryToTags[lower]; ok {
		out := make([]string, len(tags))
		copy(out, tags)
		return out
	}

	return nil
}

// TemplateToCategory infers a JSON-compatible category from a Nuclei template.
func (m *CategoryMapper) TemplateToCategory(tmpl *nuclei.Template) string {
	tags := parseCommaSeparated(tmpl.Info.Tags)

	// Priority: specific attack tags first, then generic ones
	for _, tag := range tags {
		lower := strings.ToLower(strings.TrimSpace(tag))
		if cat, ok := m.tagToCategory[lower]; ok {
			// Skip generic tags
			if cat != "WAF-Bypass" || len(tags) <= 2 {
				return cat
			}
		}
	}

	// Fallback: try the first non-generic tag
	for _, tag := range tags {
		lower := strings.ToLower(strings.TrimSpace(tag))
		if cat, ok := m.tagToCategory[lower]; ok {
			return cat
		}
	}

	// Last resort: infer from template ID
	id := strings.ToLower(tmpl.ID)
	for _, pair := range []struct{ keyword, cat string }{
		{"sqli", "SQL-Injection"},
		{"xss", "XSS"},
		{"rce", "Command-Injection"},
		{"ssrf", "SSRF"},
		{"ssti", "SSTI"},
		{"lfi", "Path-Traversal"},
		{"xxe", "XXE"},
		{"nosql", "NoSQL-Injection"},
		{"crlf", "CRLF-Injection"},
	} {
		if strings.Contains(id, pair.keyword) {
			return pair.cat
		}
	}

	return "Unknown"
}

// AllCategories returns all registered canonical category names.
func (m *CategoryMapper) AllCategories() []string {
	cats := make([]string, 0, len(m.canonicalNames))
	for _, name := range m.canonicalNames {
		cats = append(cats, name)
	}
	return cats
}

// ShortNames returns the primary short alias for each registered category.
// These are the first tag passed to register() — the most recognizable
// short name for each category (e.g. "sqli", "xss", "lfi").
// Sorted alphabetically for deterministic output.
func (m *CategoryMapper) ShortNames() []string {
	seen := make(map[string]bool, len(m.categoryToTags))
	names := make([]string, 0, len(m.categoryToTags))
	for _, tags := range m.categoryToTags {
		if len(tags) > 0 && !seen[tags[0]] {
			seen[tags[0]] = true
			names = append(names, tags[0])
		}
	}
	// Also include well-known aliases that users commonly type.
	// These all resolve through Resolve() to valid canonical names.
	wellKnown := []string{
		"traversal", "cmdi", "cors", "csrf", "jwt", "oauth",
		"redirect", "prototype", "deserialize", "hpp",
		"clickjacking", "race", "smuggling", "ssi",
	}
	for _, alias := range wellKnown {
		if !seen[alias] {
			seen[alias] = true
			names = append(names, alias)
		}
	}
	sort.Strings(names)
	return names
}

// ValidCategories returns a set of all category names and aliases that
// are accepted as valid input. Includes canonical names, short aliases,
// and registered tags — all lowercased.
func (m *CategoryMapper) ValidCategories() map[string]bool {
	valid := make(map[string]bool, len(m.canonicalNames)+len(m.aliases)+len(m.tagToCategory))
	for lower := range m.canonicalNames {
		valid[lower] = true
	}
	for alias := range m.aliases {
		valid[alias] = true
	}
	for tag := range m.tagToCategory {
		valid[tag] = true
	}
	return valid
}

// canonicalName returns the proper-cased canonical name for a lowercase
// category key, or "" if the category is not registered.
func (m *CategoryMapper) canonicalName(lower string) string {
	return m.canonicalNames[lower]
}
