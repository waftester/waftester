package payloadprovider

import (
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
	m.register("Path-Traversal", "lfi", "path-traversal", "directory-traversal", "lfi-bypass", "file-inclusion")
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

	// ── LDAP Injection ─────────────────────────────────────────────
	m.register("LDAP-Injection", "ldap", "ldap-injection")
	m.alias("ldap", "LDAP-Injection")

	// ── XPath Injection ────────────────────────────────────────────
	m.register("XPath-Injection", "xpath", "xpath-injection")
	m.alias("xpath", "XPath-Injection")

	// ── Prototype Pollution ────────────────────────────────────────
	m.register("Prototype-Pollution", "prototype-pollution", "proto-pollution")
	m.alias("prototype-pollution", "Prototype-Pollution")
	m.alias("proto-pollution", "Prototype-Pollution")

	// ── Request Smuggling ──────────────────────────────────────────
	m.register("Request-Smuggling", "request-smuggling", "http-smuggling", "http-desync")
	m.alias("request-smuggling", "Request-Smuggling")
	m.alias("http-smuggling", "Request-Smuggling")

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

	// ── GraphQL ────────────────────────────────────────────────────
	m.register("GraphQL", "graphql", "graphql-injection")
	m.alias("graphql", "GraphQL")

	// ── Deserialization ────────────────────────────────────────────
	m.register("Deserialization", "deserialization", "insecure-deserialization")
	m.alias("deserialization", "Deserialization")
	m.alias("insecure-deserialization", "Deserialization")

	// ── Cache Poisoning ────────────────────────────────────────────
	m.register("Cache-Poisoning", "cache-poisoning", "web-cache")
	m.alias("cache-poisoning", "Cache-Poisoning")

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

// canonicalName returns the proper-cased canonical name for a lowercase
// category key, or "" if the category is not registered.
func (m *CategoryMapper) canonicalName(lower string) string {
	return m.canonicalNames[lower]
}
