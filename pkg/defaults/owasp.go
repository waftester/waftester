// Package defaults provides canonical default values for the entire codebase.
// This file contains OWASP Top 10 2021 reference data - the SINGLE SOURCE OF TRUTH.
//
// Usage:
//
//	category := defaults.OWASPCategoryMapping["sqli"]  // "A03:2021"
//	name := defaults.OWASPTop10[category].Name         // "Injection"
//	url := defaults.OWASPTop10[category].URL           // "https://owasp.org/..."
package defaults

// OWASPCategory represents an OWASP Top 10 2021 category with all metadata.
type OWASPCategory struct {
	Code        string // e.g., "A01:2021"
	Name        string // e.g., "Broken Access Control"
	FullName    string // e.g., "A01:2021 - Broken Access Control"
	URL         string // Official OWASP URL
	Description string // Brief description
}

// OWASPTop10 contains all OWASP Top 10 2021 categories indexed by code.
// This is the SINGLE SOURCE OF TRUTH for OWASP data across all writers/reporters.
var OWASPTop10 = map[string]OWASPCategory{
	"A01:2021": {
		Code:        "A01:2021",
		Name:        "Broken Access Control",
		FullName:    "A01:2021 - Broken Access Control",
		URL:         "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		Description: "Access control enforces policy such that users cannot act outside of their intended permissions.",
	},
	"A02:2021": {
		Code:        "A02:2021",
		Name:        "Cryptographic Failures",
		FullName:    "A02:2021 - Cryptographic Failures",
		URL:         "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
		Description: "Failures related to cryptography which often lead to sensitive data exposure.",
	},
	"A03:2021": {
		Code:        "A03:2021",
		Name:        "Injection",
		FullName:    "A03:2021 - Injection",
		URL:         "https://owasp.org/Top10/A03_2021-Injection/",
		Description: "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter.",
	},
	"A04:2021": {
		Code:        "A04:2021",
		Name:        "Insecure Design",
		FullName:    "A04:2021 - Insecure Design",
		URL:         "https://owasp.org/Top10/A04_2021-Insecure_Design/",
		Description: "Missing or ineffective control design. Insecure design cannot be fixed by a perfect implementation.",
	},
	"A05:2021": {
		Code:        "A05:2021",
		Name:        "Security Misconfiguration",
		FullName:    "A05:2021 - Security Misconfiguration",
		URL:         "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		Description: "Security misconfiguration is the most commonly seen issue, often a result of insecure default configurations.",
	},
	"A06:2021": {
		Code:        "A06:2021",
		Name:        "Vulnerable and Outdated Components",
		FullName:    "A06:2021 - Vulnerable and Outdated Components",
		URL:         "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
		Description: "Components with known vulnerabilities such as libraries, frameworks, and other software modules.",
	},
	"A07:2021": {
		Code:        "A07:2021",
		Name:        "Identification and Authentication Failures",
		FullName:    "A07:2021 - Identification and Authentication Failures",
		URL:         "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
		Description: "Confirmation of the user's identity, authentication, and session management is critical.",
	},
	"A08:2021": {
		Code:        "A08:2021",
		Name:        "Software and Data Integrity Failures",
		FullName:    "A08:2021 - Software and Data Integrity Failures",
		URL:         "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
		Description: "Code and infrastructure that does not protect against integrity violations.",
	},
	"A09:2021": {
		Code:        "A09:2021",
		Name:        "Security Logging and Monitoring Failures",
		FullName:    "A09:2021 - Security Logging and Monitoring Failures",
		URL:         "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
		Description: "Without logging and monitoring, breaches cannot be detected.",
	},
	"A10:2021": {
		Code:        "A10:2021",
		Name:        "Server-Side Request Forgery",
		FullName:    "A10:2021 - Server-Side Request Forgery (SSRF)",
		URL:         "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
		Description: "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.",
	},
}

// OWASPTop10Ordered returns OWASP Top 10 categories in order (A01 through A10).
// Use this when you need to iterate in numerical order.
var OWASPTop10Ordered = []string{
	"A01:2021",
	"A02:2021",
	"A03:2021",
	"A04:2021",
	"A05:2021",
	"A06:2021",
	"A07:2021",
	"A08:2021",
	"A09:2021",
	"A10:2021",
}

// OWASPCategoryMapping maps attack categories to their OWASP Top 10 2021 codes.
// Use GetOWASPCategory() for category lookup with proper normalization.
var OWASPCategoryMapping = map[string]string{
	// A01:2021 - Broken Access Control
	"traversal":      "A01:2021",
	"path-traversal": "A01:2021",
	"lfi":            "A01:2021",
	"rfi":            "A01:2021",
	"idor":           "A01:2021",
	"cors":           "A01:2021",
	"csrf":           "A01:2021",
	"open_redirect":  "A01:2021",
	"redirect":       "A01:2021",
	"open-redirect":  "A01:2021",
	"access-control": "A01:2021",

	// A02:2021 - Cryptographic Failures
	"crypto":              "A02:2021",
	"cryptographic":       "A02:2021",
	"sensitive-data":      "A02:2021",
	"sensitive-exposure":  "A02:2021",
	"weak-crypto":         "A02:2021",
	"insecure-randomness": "A02:2021",

	// A03:2021 - Injection
	"sqli":           "A03:2021",
	"sql-injection":  "A03:2021",
	"xss":            "A03:2021",
	"cmdi":           "A03:2021",
	"command":        "A03:2021",
	"os-command":     "A03:2021",
	"ldap":           "A03:2021",
	"ldap-injection": "A03:2021",
	"nosqli":         "A03:2021",
	"nosql":          "A03:2021",
	"ssti":           "A03:2021",
	"template":       "A03:2021",
	"rce":            "A03:2021",
	"crlf":           "A03:2021",
	"header":         "A03:2021",
	"xpath":          "A03:2021",
	"expression":     "A03:2021",

	// A04:2021 - Insecure Design
	"upload":         "A04:2021",
	"file-upload":    "A04:2021",
	"clickjack":      "A04:2021",
	"clickjacking":   "A04:2021",
	"insecure":       "A04:2021",
	"business-logic": "A04:2021",
	"race":           "A04:2021",
	"race-condition": "A04:2021",

	// A05:2021 - Security Misconfiguration
	"xxe":              "A05:2021",
	"xml":              "A05:2021",
	"smuggling":        "A05:2021",
	"http-smuggling":   "A05:2021",
	"misconfig":        "A05:2021",
	"misconfiguration": "A05:2021",
	"security-headers": "A05:2021",

	// A06:2021 - Vulnerable and Outdated Components
	"component":  "A06:2021",
	"dependency": "A06:2021",
	"outdated":   "A06:2021",
	"vulnerable": "A06:2021",
	"library":    "A06:2021",

	// A07:2021 - Identification and Authentication Failures
	"jwt":              "A07:2021",
	"auth":             "A07:2021",
	"authentication":   "A07:2021",
	"session":          "A07:2021",
	"session-fixation": "A07:2021",
	"brute-force":      "A07:2021",
	"password":         "A07:2021",
	"oauth":            "A07:2021",

	// A08:2021 - Software and Data Integrity Failures
	"deserialize":          "A08:2021",
	"deserialization":      "A08:2021",
	"insecure-deserialize": "A08:2021",
	"prototype":            "A08:2021",
	"prototype-pollution":  "A08:2021",
	"integrity":            "A08:2021",

	// A09:2021 - Security Logging and Monitoring Failures
	"logging":    "A09:2021",
	"monitoring": "A09:2021",
	"log":        "A09:2021",

	// A10:2021 - Server-Side Request Forgery
	"ssrf":    "A10:2021",
	"forgery": "A10:2021",
}

// CategoryReadableNames maps attack categories to human-readable names.
var CategoryReadableNames = map[string]string{
	"sqli":                "SQL Injection",
	"sql-injection":       "SQL Injection",
	"xss":                 "Cross-Site Scripting",
	"cmdi":                "Command Injection",
	"command":             "Command Injection",
	"os-command":          "OS Command Injection",
	"ldap":                "LDAP Injection",
	"ldap-injection":      "LDAP Injection",
	"nosqli":              "NoSQL Injection",
	"nosql":               "NoSQL Injection",
	"ssti":                "Server-Side Template Injection",
	"template":            "Template Injection",
	"xxe":                 "XML External Entity",
	"xml":                 "XML Injection",
	"ssrf":                "Server-Side Request Forgery",
	"traversal":           "Path Traversal",
	"path-traversal":      "Path Traversal",
	"lfi":                 "Local File Inclusion",
	"rfi":                 "Remote File Inclusion",
	"idor":                "Insecure Direct Object Reference",
	"cors":                "CORS Misconfiguration",
	"csrf":                "Cross-Site Request Forgery",
	"open_redirect":       "Open Redirect",
	"open-redirect":       "Open Redirect",
	"redirect":            "Open Redirect",
	"jwt":                 "JWT Validation Bypass",
	"auth":                "Authentication Bypass",
	"deserialize":         "Insecure Deserialization",
	"deserialization":     "Insecure Deserialization",
	"rce":                 "Remote Code Execution",
	"upload":              "Unrestricted File Upload",
	"file-upload":         "Unrestricted File Upload",
	"clickjack":           "Clickjacking",
	"clickjacking":        "Clickjacking",
	"smuggling":           "HTTP Request Smuggling",
	"http-smuggling":      "HTTP Request Smuggling",
	"crlf":                "CRLF Injection",
	"header":              "HTTP Header Injection",
	"xpath":               "XPath Injection",
	"prototype":           "Prototype Pollution",
	"prototype-pollution": "Prototype Pollution",
	"race":                "Race Condition",
	"race-condition":      "Race Condition",
	"oauth":               "OAuth Misconfiguration",
	"session":             "Session Management",
	"session-fixation":    "Session Fixation",
}

// GetOWASPCategory returns the OWASP Top 10 code for an attack category.
// Returns "A00:2021" (Unknown) if category is not mapped.
func GetOWASPCategory(category string) string {
	// Normalize: lowercase and handle common variations
	normalized := normalizeCategory(category)
	if code, ok := OWASPCategoryMapping[normalized]; ok {
		return code
	}
	return "A00:2021" // Unknown
}

// GetOWASPFullName returns the full OWASP category name (e.g., "A03:2021 - Injection").
// Returns empty string if code is not found.
func GetOWASPFullName(code string) string {
	if cat, ok := OWASPTop10[code]; ok {
		return cat.FullName
	}
	return ""
}

// GetOWASPURL returns the official OWASP URL for a category code.
// Returns empty string if code is not found.
func GetOWASPURL(code string) string {
	if cat, ok := OWASPTop10[code]; ok {
		return cat.URL
	}
	return ""
}

// GetCategoryReadableName returns a human-readable name for an attack category.
// Falls back to title-casing the category if not found.
func GetCategoryReadableName(category string) string {
	normalized := normalizeCategory(category)
	if name, ok := CategoryReadableNames[normalized]; ok {
		return name
	}
	// Fallback: convert underscores/hyphens to spaces and title case
	return titleCase(category)
}

// GetOWASPForCategory returns full OWASP metadata for an attack category.
// Returns a zero-value OWASPCategory with Code "A00:2021" if not found.
func GetOWASPForCategory(category string) OWASPCategory {
	code := GetOWASPCategory(category)
	if cat, ok := OWASPTop10[code]; ok {
		return cat
	}
	return OWASPCategory{
		Code:     "A00:2021",
		Name:     "Unknown",
		FullName: "A00:2021 - Unknown",
		URL:      "https://owasp.org/Top10/",
	}
}

// normalizeCategory normalizes a category string for lookup.
func normalizeCategory(category string) string {
	// Lowercase
	s := category
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result = append(result, c+32) // to lowercase
		} else if c == '_' {
			result = append(result, '-') // normalize underscore to hyphen
		} else {
			result = append(result, c)
		}
	}
	return string(result)
}

// titleCase converts a string to title case, handling underscores and hyphens.
func titleCase(s string) string {
	// Replace underscores and hyphens with spaces, then title case
	words := make([]string, 0)
	current := make([]byte, 0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c == '-' || c == ' ' {
			if len(current) > 0 {
				words = append(words, titleWord(string(current)))
				current = current[:0]
			}
		} else {
			current = append(current, c)
		}
	}
	if len(current) > 0 {
		words = append(words, titleWord(string(current)))
	}

	result := ""
	for i, w := range words {
		if i > 0 {
			result += " "
		}
		result += w
	}
	return result
}

// titleWord capitalizes the first letter of a word.
func titleWord(word string) string {
	if len(word) == 0 {
		return word
	}
	first := word[0]
	if first >= 'a' && first <= 'z' {
		first -= 32 // to uppercase
	}
	if len(word) == 1 {
		return string(first)
	}
	return string(first) + word[1:]
}
