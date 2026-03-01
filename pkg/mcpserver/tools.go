package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/payloads"
)

// toolHandler is the function signature for MCP tool handlers.
type toolHandler = func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error)

// loggedTool wraps a tool handler with structured logging. Every tool
// invocation is logged on entry (with arguments) and on exit (with
// success/error status and duration). This is critical for diagnosing
// MCP client integration issues where requests silently vanish.
func loggedTool(name string, fn toolHandler) toolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Redact sensitive argument fields before logging to prevent key/token leakage
		argBytes := []byte(req.Params.Arguments)
		var rawArgs map[string]interface{}
		if json.Unmarshal(argBytes, &rawArgs) == nil {
			redactMap(rawArgs)
			if redacted, err := json.Marshal(rawArgs); err == nil {
				argBytes = redacted
			}
		}
		argStr := string(argBytes)
		const maxArgLog = 200
		if len([]rune(argStr)) > maxArgLog {
			// Truncate at rune boundary to avoid splitting multi-byte UTF-8
			argStr = truncateString(argStr, maxArgLog) + "..."
		}
		slog.Info("mcp: tool invoked", "tool", name, "args", argStr)

		start := time.Now()
		result, err := fn(ctx, req)
		elapsed := time.Since(start).Round(time.Millisecond)

		if err != nil {
			slog.Error("mcp: tool error", "tool", name, "duration", elapsed, "error", err)
		} else if result != nil && result.IsError {
			// Tool returned an error result (not a Go error).
			slog.Warn("mcp: tool returned error result", "tool", name, "duration", elapsed)
		} else {
			slog.Info("mcp: tool completed", "tool", name, "duration", elapsed)
		}
		return result, err
	}
}

// sensitiveSubstrings are substrings that, if found in a lowercased JSON key,
// trigger redaction. This is intentionally broad to catch variations like
// "x_api_key", "my_secret_token", "auth_header", etc.
var sensitiveSubstrings = []string{
	"secret", "password", "token", "credential", "license",
	"auth", "bearer", "jwt", "cookie", "session",
	"private", "signing", "encrypt",
	// Use specific patterns to avoid over-redacting benign fields
	// like "keyboard", "hotkey", "access_level", "accessibility".
	"api_key", "apikey", "api-key",
	"_key", "-key",
	"proxy_pass", "proxy_url", "proxy_auth",
	"access_token", "access_key", "access_secret",
}

// sensitiveExactKeys are field names that are sensitive only as exact matches.
// For example, "key" is a common name for API keys / secrets, but as a
// substring it would false-positive on "keyboard", "monkey", "hotkey", etc.
var sensitiveExactKeys = []string{
	"key",
}

// isSensitiveKey returns true if the lowercased key contains any sensitive
// substring, or matches an exact sensitive key name.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, exact := range sensitiveExactKeys {
		if lower == exact {
			return true
		}
	}
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// redactMap recursively redacts sensitive fields in a JSON-like map.
// It traverses nested maps and arrays so payloads like
// {"config":{"api_key":"..."}} and {"items":[{"token":"..."}]} are caught.
func redactMap(m map[string]interface{}) {
	for k, v := range m {
		if isSensitiveKey(k) {
			m[k] = "[REDACTED]"
			continue
		}
		// Recurse into nested objects
		switch val := v.(type) {
		case map[string]interface{}:
			redactMap(val)
		case []interface{}:
			for _, item := range val {
				if nested, ok := item.(map[string]interface{}); ok {
					redactMap(nested)
				}
			}
		}
	}
}

// truncateString truncates s to at most maxLen runes, avoiding mid-rune byte splits.
func truncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen])
}

// truncateBytes truncates s to at most maxBytes bytes, stepping back to the
// nearest valid UTF-8 rune boundary to avoid producing an invalid UTF-8 fragment.
func truncateBytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Step back from the byte limit until we land on a rune boundary.
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

// categoryMeta holds rich metadata for each attack category — used to enrich
// tool responses so AI agents understand the domain context.
type categoryMeta struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	OWASPCode   string `json:"owasp_code"`
	OWASPName   string `json:"owasp_name"`
	RiskLevel   string `json:"risk_level"`
	CommonUsage string `json:"common_usage"`
}

// categoryDescriptions provides domain-expert descriptions for every attack
// category the payload catalog supports.
var categoryDescriptions = map[string]categoryMeta{
	"sqli": {
		Name:        "SQL Injection",
		Description: "Payloads that inject SQL syntax into application queries to extract data, bypass authentication, or execute commands on the database server.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test login forms, search parameters, API query parameters, and any input that feeds into SQL queries.",
	},
	"xss": {
		Name:        "Cross-Site Scripting (XSS)",
		Description: "Payloads that inject JavaScript or HTML into web pages to steal cookies, redirect users, or execute actions on behalf of victims.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test search boxes, comment fields, URL parameters rendered in HTML, and any reflected/stored user input.",
	},
	"traversal": {
		Name:        "Path Traversal / LFI",
		Description: "Payloads that traverse directory structures (../../etc/passwd) to read sensitive files from the server filesystem.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "High",
		CommonUsage: "Test file download endpoints, include parameters, template paths, and any input used in filesystem operations.",
	},
	"auth": {
		Name:        "Authentication Bypass",
		Description: "Payloads targeting authentication mechanisms — default credentials, token manipulation, session fixation, and auth logic flaws.",
		OWASPCode:   "A07:2021",
		OWASPName:   "Identification and Authentication Failures",
		RiskLevel:   "Critical",
		CommonUsage: "Test login endpoints, password reset flows, MFA implementations, and session management.",
	},
	"ssrf": {
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "Payloads that trick the server into making requests to internal resources, cloud metadata endpoints, or other backend services.",
		OWASPCode:   "A10:2021",
		OWASPName:   "Server-Side Request Forgery",
		RiskLevel:   "Critical",
		CommonUsage: "Test URL input fields, webhook configurations, image/file fetch features, and any server-side URL processing.",
	},
	"ssti": {
		Name:        "Server-Side Template Injection (SSTI)",
		Description: "Payloads injecting template syntax ({{7*7}}, ${7*7}) into server-side template engines to achieve remote code execution.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test template rendering endpoints, email templates, PDF generators, and any user-controlled template content.",
	},
	"cmdi": {
		Name:        "OS Command Injection",
		Description: "Payloads that inject operating system commands (;whoami, |cat /etc/passwd) to execute arbitrary commands on the server.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test ping/traceroute tools, file processors, system administration interfaces, and any input passed to shell commands.",
	},
	"xxe": {
		Name:        "XML External Entity (XXE)",
		Description: "Payloads exploiting XML parsers to read local files, perform SSRF, or cause denial of service via entity expansion.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Test XML/SOAP endpoints, file upload (DOCX/SVG/XML), and any XML processing functionality.",
	},
	"nosqli": {
		Name:        "NoSQL Injection",
		Description: "Payloads targeting NoSQL databases (MongoDB, CouchDB) with operator injection ({$gt:''}, {$ne:null}) or JavaScript injection.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test MongoDB-backed APIs, JSON query parameters, and NoSQL database interfaces.",
	},
	"graphql": {
		Name:        "GraphQL Injection & Abuse",
		Description: "Payloads targeting GraphQL APIs — introspection queries, query depth attacks, batching abuse, and injection via variables.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "High",
		CommonUsage: "Test GraphQL endpoints for introspection leaks, authorization bypasses, and resource exhaustion.",
	},
	"cors": {
		Name:        "CORS Misconfiguration",
		Description: "Payloads testing Cross-Origin Resource Sharing misconfigurations that allow unauthorized cross-origin data access.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "Medium",
		CommonUsage: "Test API endpoints for overly permissive Access-Control-Allow-Origin headers and credential leakage.",
	},
	"crlf": {
		Name:        "CRLF Injection / HTTP Response Splitting",
		Description: "Payloads injecting carriage return/line feed characters to manipulate HTTP headers, set cookies, or redirect responses.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test URL parameters reflected in response headers, redirect endpoints, and cookie-setting flows.",
	},
	"redirect": {
		Name:        "Open Redirect",
		Description: "Payloads exploiting URL redirect functionality to send users to malicious external sites for phishing or credential theft.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "Medium",
		CommonUsage: "Test login redirect parameters, OAuth callback URLs, and any URL forwarding functionality.",
	},
	"upload": {
		Name:        "Malicious File Upload",
		Description: "Payloads testing file upload validation — double extensions, MIME type bypass, path traversal in filenames, and polyglot files.",
		OWASPCode:   "A04:2021",
		OWASPName:   "Insecure Design",
		RiskLevel:   "Critical",
		CommonUsage: "Test file upload endpoints for web shells, content type bypass, and filename-based attacks.",
	},
	"jwt": {
		Name:        "JWT Token Attacks",
		Description: "Payloads targeting JSON Web Token implementations — algorithm confusion (none/HS256→RS256), key brute-force, and claim manipulation.",
		OWASPCode:   "A02:2021",
		OWASPName:   "Cryptographic Failures",
		RiskLevel:   "Critical",
		CommonUsage: "Test JWT-authenticated APIs for algorithm confusion, weak secrets, and token manipulation vulnerabilities.",
	},
	"oauth": {
		Name:        "OAuth/OIDC Attacks",
		Description: "Payloads targeting OAuth 2.0 and OpenID Connect flows — redirect URI manipulation, CSRF, token leakage, and scope escalation.",
		OWASPCode:   "A07:2021",
		OWASPName:   "Identification and Authentication Failures",
		RiskLevel:   "High",
		CommonUsage: "Test OAuth authorization endpoints, redirect URI validation, and token exchange flows.",
	},
	"prototype": {
		Name:        "Prototype Pollution",
		Description: "Payloads injecting properties into JavaScript Object.prototype to modify application behavior, bypass security checks, or achieve RCE.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test JSON merge/deep-copy endpoints, configuration APIs, and any server-side JavaScript object manipulation.",
	},
	"prototype-pollution": {
		Name:        "Prototype Pollution",
		Description: "Payloads injecting properties into JavaScript Object.prototype to modify application behavior, bypass security checks, or achieve RCE.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test JSON merge/deep-copy endpoints, configuration APIs, and any server-side JavaScript object manipulation.",
	},
	"deserialize": {
		Name:        "Insecure Deserialization",
		Description: "Payloads exploiting unsafe deserialization in Java, PHP, Python, .NET, and Ruby to achieve remote code execution or privilege escalation.",
		OWASPCode:   "A08:2021",
		OWASPName:   "Software and Data Integrity Failures",
		RiskLevel:   "Critical",
		CommonUsage: "Test serialized data inputs (Java ObjectInputStream, PHP unserialize, Python pickle) and session/state storage.",
	},
	"deserialization": {
		Name:        "Insecure Deserialization",
		Description: "Payloads exploiting unsafe deserialization in Java, PHP, Python, .NET, and Ruby to achieve remote code execution or privilege escalation.",
		OWASPCode:   "A08:2021",
		OWASPName:   "Software and Data Integrity Failures",
		RiskLevel:   "Critical",
		CommonUsage: "Test serialized data inputs (Java ObjectInputStream, PHP unserialize, Python pickle) and session/state storage.",
	},
	// Broader category names from payload files
	"injection": {
		Name:        "Injection (General)",
		Description: "General injection payloads covering SQL, LDAP, XPath, and other injection vectors that manipulate backend queries or commands.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Broad injection testing across multiple backend technologies.",
	},
	"open-redirect": {
		Name:        "Open Redirect",
		Description: "Payloads exploiting URL redirect functionality to send users to malicious external sites for phishing or credential theft.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "Medium",
		CommonUsage: "Test login redirect parameters, OAuth callback URLs, and any URL forwarding functionality.",
	},
	"polyglot": {
		Name:        "Polyglot Payloads",
		Description: "Multi-context payloads that combine multiple attack vectors (XSS+SQLi+SSTI) in a single string — effective for broad WAF testing.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test WAF coverage gaps by sending payloads valid in multiple injection contexts simultaneously.",
	},
	"ai": {
		Name:        "AI / Prompt Injection",
		Description: "Payloads targeting AI/ML systems — prompt injection, model poisoning, jailbreak attempts, and workflow abuse vectors.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test LLM-powered features, chatbots, AI agents, and any AI-assisted input processing.",
	},
	"logic": {
		Name:        "Business Logic Attacks",
		Description: "Payloads targeting application logic flaws — IDOR, privilege escalation, forced browsing, and workflow bypass.",
		OWASPCode:   "A04:2021",
		OWASPName:   "Insecure Design",
		RiskLevel:   "High",
		CommonUsage: "Test authorization boundaries, role-based access, and multi-step workflow integrity.",
	},
	"media": {
		Name:        "Media / File Metadata",
		Description: "Payloads embedded in image EXIF data, document metadata, and media file headers to test upload processing pipelines.",
		OWASPCode:   "A04:2021",
		OWASPName:   "Insecure Design",
		RiskLevel:   "Medium",
		CommonUsage: "Test image upload processing, EXIF parsing, and media file handling for injection via metadata.",
	},
	"obfuscation": {
		Name:        "Obfuscation / Encoding",
		Description: "Payloads using encoding tricks, character substitution, and obfuscation to bypass WAF pattern matching rules.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Test WAF rule thoroughness by sending known-bad payloads through various encoding layers.",
	},
	"protocol": {
		Name:        "Protocol-Level Attacks",
		Description: "Payloads targeting HTTP/2, WebSocket, and protocol-level vulnerabilities including request smuggling and downgrade attacks.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Test HTTP/2 endpoints, WebSocket handlers, and protocol negotiation for smuggling and abuse.",
	},
	"ratelimit": {
		Name:        "Rate Limit Testing",
		Description: "Payloads for testing rate limiting effectiveness — burst simulation, zone bypass attempts, and distributed request patterns.",
		OWASPCode:   "A04:2021",
		OWASPName:   "Insecure Design",
		RiskLevel:   "Medium",
		CommonUsage: "Test API rate limiters, login attempt throttling, and DDoS protection thresholds.",
	},
	"service-specific": {
		Name:        "Service-Specific Attacks",
		Description: "Payloads targeting specific services and platforms — vendor-specific vulnerabilities, API abuse, and known CVE patterns.",
		OWASPCode:   "A06:2021",
		OWASPName:   "Vulnerable and Outdated Components",
		RiskLevel:   "High",
		CommonUsage: "Test specific third-party services, known platform vulnerabilities, and vendor-specific API abuse.",
	},
	"waf-validation": {
		Name:        "WAF Validation / Rule Testing",
		Description: "Payloads designed to validate WAF rule effectiveness — ModSecurity CRS tests, custom rule verification, and regression checks.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "Medium",
		CommonUsage: "Verify WAF rules block what they should, test custom rulesets, and validate after configuration changes.",
	},
	"owasp-top10": {
		Name:        "OWASP Top 10 Coverage",
		Description: "Payloads mapped to OWASP Top 10 categories for compliance-driven testing and coverage reporting.",
		OWASPCode:   "A00:2021",
		OWASPName:   "OWASP Top 10 (All Categories)",
		RiskLevel:   "Critical",
		CommonUsage: "Run compliance-focused scans covering all OWASP Top 10 risk categories.",
	},
	"regression": {
		Name:        "Regression Tests",
		Description: "Payloads from previously-discovered bypasses and fixed vulnerabilities — ensures WAF rules stay effective after updates.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Run after WAF rule updates, CRS upgrades, or configuration changes to catch regressions.",
	},
	"waf-bypass": {
		Name:        "WAF Bypass Techniques",
		Description: "Payloads specifically crafted to evade WAF detection using encoding tricks, protocol abuse, and rule gap exploitation.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "Critical",
		CommonUsage: "Test WAF resilience against evasion techniques — run after initial scan to find bypass paths.",
	},
	"rfi": {
		Name:        "Remote File Inclusion (RFI)",
		Description: "Payloads that include remote files from attacker-controlled servers to achieve code execution on the target.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test include/require parameters, template loading, and any remote resource fetching functionality.",
	},
	"ldap": {
		Name:        "LDAP Injection",
		Description: "Payloads manipulating LDAP queries to bypass authentication, enumerate directory entries, or extract sensitive data.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test LDAP-backed authentication, directory search interfaces, and any LDAP query construction.",
	},
	"xpath": {
		Name:        "XPath Injection",
		Description: "Payloads injecting XPath syntax into XML document queries to extract data or bypass access controls.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test XML-based search, SOAP services, and any application using XPath for data retrieval.",
	},
	"request-smuggling": {
		Name:        "HTTP Request Smuggling",
		Description: "Payloads exploiting discrepancies between front-end and back-end HTTP parsing to smuggle malicious requests.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "Critical",
		CommonUsage: "Test reverse proxy / CDN / WAF chains for CL.TE, TE.CL, and H2.CL desync vulnerabilities.",
	},
	"cache-poisoning": {
		Name:        "Cache Poisoning",
		Description: "Payloads that poison web caches to serve malicious content to other users — exploits cache key inconsistencies.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Test CDN/reverse proxy caching for key normalization issues, unkeyed header injection, and cache deception.",
	},
	"fuzz": {
		Name:        "Fuzzing Payloads",
		Description: "General-purpose fuzzing payloads — special characters, boundary values, encoding variations, and format strings.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Medium",
		CommonUsage: "Broad fuzzing of input fields to discover unexpected behavior, crashes, or security-relevant responses.",
	},
	"csrf": {
		Name:        "Cross-Site Request Forgery (CSRF)",
		Description: "Payloads testing CSRF protections — token absence, token bypass, SameSite cookie misconfiguration, and cross-origin state changes.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "High",
		CommonUsage: "Test state-changing endpoints for missing or weak CSRF tokens, SameSite cookie attributes, and origin validation.",
	},
	"xml-injection": {
		Name:        "XML Injection",
		Description: "Payloads injecting malicious XML content to manipulate document structure, bypass input validation, or trigger parser vulnerabilities.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test XML-based APIs, SOAP services, and any XML document processing for injection and parser abuse.",
	},
	"response-splitting": {
		Name:        "HTTP Response Splitting",
		Description: "Payloads injecting CRLF sequences into HTTP responses to add headers, set cookies, or split responses for cache poisoning.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test URL redirects, header reflection, and any input echoed in HTTP response headers.",
	},
	"websocket": {
		Name:        "WebSocket Security",
		Description: "Payloads targeting WebSocket connections — cross-site WebSocket hijacking, message injection, and authentication bypass.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "High",
		CommonUsage: "Test WebSocket endpoints for origin validation, authentication on upgrade, and message-level injection.",
	},
	"hpp": {
		Name:        "HTTP Parameter Pollution (HPP)",
		Description: "Payloads exploiting duplicate parameter handling differences between front-end and back-end to bypass WAF rules or alter logic.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Medium",
		CommonUsage: "Test parameter handling by sending duplicate query/body parameters to exploit parsing inconsistencies.",
	},
	"host-header": {
		Name:        "Host Header Injection",
		Description: "Payloads manipulating the HTTP Host header to poison password reset links, bypass virtual host routing, or enable cache poisoning.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Test password reset flows, virtual host routing, and any functionality that uses the Host header for URL generation.",
	},
	"clickjacking": {
		Name:        "Clickjacking / UI Redressing",
		Description: "Payloads testing frame-based UI attacks — missing X-Frame-Options, weak CSP frame-ancestors, and iframe embedding vulnerabilities.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "Medium",
		CommonUsage: "Test pages with state-changing actions for missing framing protections (X-Frame-Options, CSP frame-ancestors).",
	},
	"access-control": {
		Name:        "Broken Access Control",
		Description: "Payloads testing authorization boundaries — privilege escalation, horizontal/vertical access bypass, and missing function-level checks.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "Critical",
		CommonUsage: "Test admin endpoints with low-privilege tokens, IDOR via numeric IDs, and role-based access enforcement.",
	},
	"race-condition": {
		Name:        "Race Condition / TOCTOU",
		Description: "Payloads exploiting race conditions — time-of-check/time-of-use bugs, concurrent request abuse, and double-spend attacks.",
		OWASPCode:   "A04:2021",
		OWASPName:   "Insecure Design",
		RiskLevel:   "High",
		CommonUsage: "Test financial transactions, coupon redemption, and any endpoint where concurrent requests could cause inconsistent state.",
	},
	"subdomain-takeover": {
		Name:        "Subdomain Takeover",
		Description: "Payloads detecting dangling DNS records (CNAME, A) pointing to deprovisioned cloud resources that can be claimed by attackers.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Test DNS records for dangling CNAMEs to deprovisioned S3 buckets, Heroku apps, Azure, and other cloud services.",
	},
	"session-fixation": {
		Name:        "Session Fixation",
		Description: "Payloads testing session management — fixation attacks, session ID prediction, and failure to regenerate tokens after authentication.",
		OWASPCode:   "A07:2021",
		OWASPName:   "Identification and Authentication Failures",
		RiskLevel:   "High",
		CommonUsage: "Test login flows for session ID regeneration, cookie attributes (HttpOnly, Secure, SameSite), and fixation vectors.",
	},
	"mass-assignment": {
		Name:        "Mass Assignment",
		Description: "Payloads testing mass assignment / parameter binding — injecting admin=true, role=admin, or other privileged fields into update requests.",
		OWASPCode:   "A04:2021",
		OWASPName:   "Insecure Design",
		RiskLevel:   "High",
		CommonUsage: "Test user profile updates, registration endpoints, and any API accepting JSON/form bodies for unprotected field binding.",
	},
	"ssi": {
		Name:        "Server-Side Includes (SSI) Injection",
		Description: "Payloads injecting SSI directives (<!--#exec -->, <!--#include -->) to execute commands or include files on the server.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test web servers with SSI enabled (.shtml pages) for directive injection in user-controlled input.",
	},
	"misconfiguration": {
		Name:        "Security Misconfiguration",
		Description: "Payloads testing security misconfigurations — debug endpoints, default credentials, missing security headers, and verbose error pages.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Test for exposed admin panels, debug modes, stack traces in errors, and missing security headers.",
	},
	"sensitive-data": {
		Name:        "Sensitive Data Exposure",
		Description: "Payloads detecting exposed sensitive data — API keys in responses, PII leakage, directory listings, and information disclosure.",
		OWASPCode:   "A02:2021",
		OWASPName:   "Cryptographic Failures",
		RiskLevel:   "High",
		CommonUsage: "Test API responses for leaked credentials, error messages with stack traces, and unprotected sensitive endpoints.",
	},
	"crypto-failure": {
		Name:        "Cryptographic Failure",
		Description: "Payloads testing cryptographic weaknesses — weak TLS versions, insecure cipher suites, missing HSTS, and weak hashing algorithms.",
		OWASPCode:   "A02:2021",
		OWASPName:   "Cryptographic Failures",
		RiskLevel:   "High",
		CommonUsage: "Test TLS configuration, certificate validation, HSTS enforcement, and detection of weak cryptographic primitives.",
	},
	"api-abuse": {
		Name:        "API Abuse",
		Description: "Payloads targeting API-specific vulnerabilities — excessive data exposure, mass assignment, BOLA, resource exhaustion, and broken auth.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "High",
		CommonUsage: "Test REST/GraphQL APIs for OWASP API Top 10 issues including BOLA, broken auth, and excessive data exposure.",
	},
	"lfi": {
		Name:        "Path Traversal / LFI",
		Description: "Payloads that traverse directory structures (../../etc/passwd) to read sensitive files from the server filesystem.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "High",
		CommonUsage: "Test file download endpoints, include parameters, template paths, and any input used in filesystem operations.",
	},
	"rce": {
		Name:        "OS Command Injection",
		Description: "Payloads that inject operating system commands (;whoami, |cat /etc/passwd) to execute arbitrary commands on the server.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test ping/traceroute tools, file processors, system administration interfaces, and any input passed to shell commands.",
	},
}

// categoryMapper is a package-level mapper used by lookupCategoryMeta to
// resolve aliases without constructing a new mapper on every call.
var categoryMapper = payloadprovider.NewCategoryMapper()

// lookupCategoryMeta resolves a category name (which may be an alias like
// "lfi", "rce", "deserialization") to its metadata in categoryDescriptions.
// It first tries a direct map lookup, then resolves through the CategoryMapper
// to find the canonical category and checks all its tags against the map.
func lookupCategoryMeta(category string) (categoryMeta, bool) {
	lower := strings.ToLower(category)
	if meta, ok := categoryDescriptions[lower]; ok {
		return meta, true
	}
	// Resolve through mapper: "lfi" → "Path-Traversal", "rce" → "Command-Injection"
	resolved := categoryMapper.Resolve(lower)
	if len(resolved) > 0 {
		// Check all tags for the resolved canonical category
		tags := categoryMapper.CategoriesToTags(resolved[0])
		for _, tag := range tags {
			if meta, ok := categoryDescriptions[tag]; ok {
				return meta, true
			}
		}
	}
	return categoryMeta{}, false
}

// registerTools adds all WAF testing tools to the MCP server.
func (s *Server) registerTools() {
	s.addListPayloadsTool()
	s.addDetectWAFTool()
	s.addDiscoverTool()
	s.addLearnTool()
	s.addScanTool()
	s.addAssessTool()
	s.addMutateTool()
	s.addBypassTool()
	s.addProbeTool()
	s.addGenerateCICDTool()
	s.addListTampersTool()
	s.addDiscoverBypassesTool()
	s.addListTemplatesTool()
	s.addShowTemplateTool()
	if s.config.EventCrawlFn != nil {
		s.addEventCrawlTool()
	}
	s.registerAsyncTools() // get_task_status, cancel_task, list_tasks
}

// ═══════════════════════════════════════════════════════════════════════════
// list_payloads — Browse the attack payload catalog
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addListPayloadsTool() {
	categoryShortNames := payloadprovider.NewCategoryMapper().ShortNames()
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "list_payloads",
			Title: "List Attack Payloads",
			Description: `Inventory tool — browse the local attack payload catalog WITHOUT sending any traffic.

USE THIS TOOL WHEN:
• The user asks "what payloads/categories/attacks do you support?"
• You need to check how many payloads exist for a category before running 'scan'
• You want to show the user sample payloads for a specific attack type
• Planning which categories to include in a scan or assessment

DO NOT USE THIS TOOL WHEN:
• You want to actually TEST a target — use 'scan' instead
• You want WAF bypass testing — use 'bypass' instead
• You want to encode/mutate a specific payload — use 'mutate' instead

This is a READ-ONLY local operation. Zero network requests. Instant results.

EXAMPLE INPUTS:
• See everything: {} (no arguments)
• Browse SQL injection payloads: {"category": "sqli"}
• Only critical XSS payloads: {"category": "xss", "severity": "Critical"}
• High+ severity across all categories: {"severity": "High"}

CATEGORIES: ` + strings.Join(categoryShortNames, ", ") + `
SEVERITY (descending): Critical > High > Medium > Low

Returns: total count, per-category breakdown, severity distribution, 5 sample payloads.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"category": map[string]any{
						"type":        "string",
						"description": "Filter by specific attack category. Leave empty to see all categories.",
						"enum":        categoryShortNames,
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Filter by minimum severity level. Only payloads at this severity or higher are returned.",
						"enum":        finding.TitleCaseStrings(),
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(false),
				Title:          "List Attack Payloads",
			},
		},
		loggedTool("list_payloads", s.handleListPayloads),
	)
}

type listPayloadsArgs struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
}

type payloadSummary struct {
	Summary        string         `json:"summary"`
	TotalPayloads  int            `json:"total_payloads"`
	TotalAvailable int            `json:"total_available"`
	Categories     int            `json:"categories"`
	ByCategory     map[string]int `json:"by_category"`
	BySeverity     map[string]int `json:"by_severity"`
	FilterApplied  string         `json:"filter_applied,omitempty"`
	CategoryInfo   *categoryMeta  `json:"category_info,omitempty"`
	SamplePayloads []sampleEntry  `json:"sample_payloads,omitempty"`
	UnifiedTotal   int            `json:"unified_total,omitempty"`
	NucleiExtra    int            `json:"nuclei_extra,omitempty"`
	NextSteps      []string       `json:"next_steps"`
}

type sampleEntry struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Snippet  string   `json:"snippet"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

// enrichWithNuclei appends Nuclei-sourced unified payloads to a JSON payload slice.
func enrichWithNuclei(all []payloads.Payload, unified []payloadprovider.UnifiedPayload) []payloads.Payload {
	for _, up := range unified {
		if up.Source == payloadprovider.SourceNuclei {
			sev := up.Severity
			if sev == "" {
				sev = "Medium"
			}
			all = append(all, payloads.Payload{
				ID:            up.ID,
				Payload:       up.Payload,
				Category:      up.Category,
				Method:        up.Method,
				SeverityHint:  sev,
				ExpectedBlock: true,
				Tags:          up.Tags,
			})
		}
	}
	return all
}

func (s *Server) handleListPayloads(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args listPayloadsArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v. Expected optional 'category' (string) and 'severity' (string).", err)), nil
	}

	// Load from unified engine (JSON + Nuclei templates)
	provider := s.PayloadProvider()
	if err := provider.Load(); err != nil {
		return errorResult(fmt.Sprintf("failed to load payloads from %s: %v. Verify the payload directory exists and contains JSON files.", s.config.PayloadDir, err)), nil
	}

	all, err := provider.JSONPayloads()
	if err != nil {
		return errorResult(fmt.Sprintf("failed to extract payloads: %v", err)), nil
	}

	// Enrich with Nuclei template payloads
	unified, err := provider.GetAll()
	if err != nil {
		slog.Warn("mcp: failed to load unified payloads", "error", err)
	}
	all = enrichWithNuclei(all, unified)

	totalAvailable := len(all)

	filtered := payloads.Filter(all, args.Category, args.Severity)
	stats := payloads.GetStats(filtered)

	bySeverity := make(map[string]int)
	for _, p := range filtered {
		sev := strings.ToLower(p.SeverityHint)
		if sev == "" {
			sev = "unclassified"
		}
		bySeverity[sev]++
	}

	summary := payloadSummary{
		TotalPayloads:  stats.TotalPayloads,
		TotalAvailable: totalAvailable,
		Categories:     stats.CategoriesUsed,
		ByCategory:     stats.ByCategory,
		BySeverity:     bySeverity,
	}

	if args.Category != "" || args.Severity != "" {
		parts := make([]string, 0, 2)
		if args.Category != "" {
			parts = append(parts, "category="+args.Category)
		}
		if args.Severity != "" {
			parts = append(parts, "severity≥"+args.Severity)
		}
		summary.FilterApplied = strings.Join(parts, ", ")
	}

	// Add category metadata when filtering by category
	if args.Category != "" {
		if meta, ok := lookupCategoryMeta(args.Category); ok {
			summary.CategoryInfo = &meta
		}
	}

	// Include up to 10 sample payloads with rich details
	limit := 10
	if len(filtered) < limit {
		limit = len(filtered)
	}
	for _, p := range filtered[:limit] {
		snippet := p.Payload
		if len(snippet) > 120 {
			snippet = truncateBytes(snippet, 120) + "…"
		}
		sev := p.SeverityHint
		if sev == "" {
			sev = "Unclassified"
		}
		summary.SamplePayloads = append(summary.SamplePayloads, sampleEntry{
			ID:       p.ID,
			Category: p.Category,
			Severity: sev,
			Snippet:  snippet,
			Tags:     p.Tags,
			Notes:    p.Notes,
		})
	}

	// Build narrative summary
	summary.Summary = buildListPayloadsSummary(args, stats, totalAvailable, bySeverity)

	// Report unified stats (payloads already include Nuclei)
	if uStats, err := provider.GetStats(); err == nil && uStats.NucleiPayloads > 0 {
		summary.UnifiedTotal = uStats.TotalPayloads
		summary.NucleiExtra = uStats.NucleiPayloads
	}

	// Build actionable next steps
	summary.NextSteps = buildListPayloadsNextSteps(args, stats)

	return jsonResult(summary)
}

// buildListPayloadsSummary generates a human/AI-readable narrative of the payload listing.
func buildListPayloadsSummary(args listPayloadsArgs, stats payloads.LoadStats, totalAvailable int, bySeverity map[string]int) string {
	var sb strings.Builder

	if stats.TotalPayloads == 0 {
		if args.Category != "" {
			fmt.Fprintf(&sb, "No payloads found for category '%s'", args.Category)
			if args.Severity != "" {
				fmt.Fprintf(&sb, " at severity '%s' or higher", args.Severity)
			}
			sb.WriteString(". ")
			if meta, ok := lookupCategoryMeta(args.Category); ok {
				fmt.Fprintf(&sb, "The '%s' category (%s) exists but may not have payloads in the current payload directory. ", args.Category, meta.Name)
			}
			fmt.Fprintf(&sb, "Total payloads available across all categories: %d. Try removing filters or checking the payload directory.", totalAvailable)
		} else {
			sb.WriteString("No payloads found in the payload directory. Verify the payload directory path is correct and contains JSON payload files.")
		}
		return sb.String()
	}

	if args.Category != "" {
		if meta, ok := lookupCategoryMeta(args.Category); ok {
			fmt.Fprintf(&sb, "Found %d %s (%s) payloads", stats.TotalPayloads, meta.Name, strings.ToUpper(args.Category))
		} else {
			fmt.Fprintf(&sb, "Found %d '%s' payloads", stats.TotalPayloads, args.Category)
		}
	} else {
		fmt.Fprintf(&sb, "Found %d total payloads across %d categories", stats.TotalPayloads, stats.CategoriesUsed)
	}

	if args.Severity != "" {
		fmt.Fprintf(&sb, " at severity '%s' or higher", args.Severity)
	}
	sb.WriteString(". ")

	// Severity breakdown
	if crit, ok := bySeverity["critical"]; ok && crit > 0 {
		fmt.Fprintf(&sb, "%d Critical", crit)
		if high, ok := bySeverity["high"]; ok && high > 0 {
			fmt.Fprintf(&sb, ", %d High", high)
		}
		sb.WriteString(" severity. ")
	} else if high, ok := bySeverity["high"]; ok && high > 0 {
		fmt.Fprintf(&sb, "%d High severity. ", high)
	}

	fmt.Fprintf(&sb, "Showing %d samples out of %d total (%d available across all categories).",
		min(10, stats.TotalPayloads), stats.TotalPayloads, totalAvailable)

	return sb.String()
}

// buildListPayloadsNextSteps generates contextual next-step suggestions.
func buildListPayloadsNextSteps(args listPayloadsArgs, stats payloads.LoadStats) []string {
	steps := make([]string, 0, 4)

	if stats.TotalPayloads == 0 {
		steps = append(steps, "Try 'list_payloads' with no filters to see all available categories and payloads")
		allCats := payloadprovider.NewCategoryMapper().ShortNames()
		steps = append(steps, "Check available categories: "+strings.Join(allCats, ", "))
		return steps
	}

	if args.Category != "" {
		steps = append(steps,
			fmt.Sprintf("Use 'scan' with {\"target\": \"https://your-target.com\", \"categories\": [\"%s\"]} to test these %d payloads against a WAF", args.Category, stats.TotalPayloads))
		steps = append(steps,
			"Use 'mutate' to generate WAF-evasion variants of any payload above (e.g., URL encoding, Unicode, double-encoding)")
		if args.Severity == "" {
			steps = append(steps,
				fmt.Sprintf("Filter by severity: {\"category\": \"%s\", \"severity\": \"Critical\"} to focus on the most dangerous payloads", args.Category))
		}
	} else {
		steps = append(steps,
			"Use 'scan' with {\"target\": \"https://your-target.com\"} to test ALL payloads against a WAF")
		steps = append(steps,
			"Filter by category (e.g., {\"category\": \"sqli\"}) to explore a specific attack type")
		steps = append(steps,
			"Use 'detect_waf' first to identify the WAF vendor, then run targeted scans")
	}

	steps = append(steps, "Use 'assess' for a full enterprise assessment with F1 score, false positive rate, and letter grade (A+ through F)")
	steps = append(steps, "Read 'waftester://payloads/unified' to see combined stats from JSON + Nuclei template sources")
	steps = append(steps, "Use 'waf-tester template --enrich' to inject JSON payloads into Nuclei templates for maximum coverage")

	return steps
}
