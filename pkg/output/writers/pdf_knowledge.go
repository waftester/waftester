// Package writers provides output writers for various formats.
package writers

// cweNames maps CWE IDs to human-readable names for PDF report display.
// Covers CWEs commonly seen in WAF testing results.
var cweNames = map[int]string{
	20:   "Improper Input Validation",
	22:   "Path Traversal",
	77:   "Command Injection",
	78:   "OS Command Injection",
	79:   "Cross-site Scripting (XSS)",
	80:   "Basic XSS",
	89:   "SQL Injection",
	90:   "LDAP Injection",
	91:   "XML Injection",
	94:   "Code Injection",
	98:   "Improper Control of Filename for Include",
	113:  "Improper Neutralization of CRLF Sequences in HTTP Headers",
	116:  "Improper Encoding or Escaping of Output",
	134:  "Use of Externally-Controlled Format String",
	200:  "Exposure of Sensitive Information",
	209:  "Information Exposure Through an Error Message",
	284:  "Improper Access Control",
	285:  "Improper Authorization",
	287:  "Improper Authentication",
	294:  "Authentication Bypass by Capture-replay",
	311:  "Missing Encryption of Sensitive Data",
	312:  "Cleartext Storage of Sensitive Information",
	319:  "Cleartext Transmission of Sensitive Information",
	326:  "Inadequate Encryption Strength",
	327:  "Use of a Broken or Risky Cryptographic Algorithm",
	328:  "Use of Weak Hash",
	346:  "Origin Validation Error",
	352:  "Cross-Site Request Forgery (CSRF)",
	384:  "Session Fixation",
	400:  "Uncontrolled Resource Consumption",
	434:  "Unrestricted Upload of File with Dangerous Type",
	444:  "HTTP Request/Response Smuggling",
	451:  "User Interface (UI) Misrepresentation of Critical Information",
	502:  "Deserialization of Untrusted Data",
	521:  "Weak Password Requirements",
	522:  "Insufficiently Protected Credentials",
	525:  "Use of Web Browser Cache Containing Sensitive Information",
	532:  "Insertion of Sensitive Information into Log File",
	538:  "Insertion of Sensitive Information into Externally-Accessible File",
	564:  "SQL Injection: Hibernate",
	601:  "URL Redirection to Untrusted Site (Open Redirect)",
	611:  "Improper Restriction of XML External Entity Reference",
	613:  "Insufficient Session Expiration",
	614:  "Sensitive Cookie in HTTPS Session Without Secure Attribute",
	639:  "Authorization Bypass Through User-Controlled Key (IDOR)",
	643:  "Improper Neutralization of Data within XPath Expressions",
	693:  "Protection Mechanism Failure",
	776:  "Improper Restriction of Recursive Entity References in DTDs",
	829:  "Inclusion of Functionality from Untrusted Control Sphere",
	862:  "Missing Authorization",
	863:  "Incorrect Authorization",
	918:  "Server-Side Request Forgery (SSRF)",
	942:  "Permissive Regular Expression",
	943:  "Improper Neutralization of Special Elements in Data Query Logic",
	1021: "Improper Restriction of Rendered UI Layers (Clickjacking)",
	1236: "Improper Neutralization of Formula Elements in a CSV File",
}

// cweName returns the descriptive name for a CWE ID, or an empty string if unknown.
func cweName(id int) string {
	return cweNames[id]
}

// categoryRemediation provides per-category guidance for WAF bypass findings.
// Each entry contains a short description and a reference URL.
type categoryRemediationInfo struct {
	Title        string
	Guidance     string
	ReferenceURL string
}

// categoryRemediations maps attack categories to remediation advice.
var categoryRemediations = map[string]categoryRemediationInfo{
	"sqli": {
		Title:        "SQL Injection",
		Guidance:     "Enable parameterized queries and prepared statements. Verify WAF rules cover UNION, stacked queries, blind, and error-based SQLi variants. Ensure rules match case-insensitive patterns and common evasion encodings (URL, hex, Unicode).",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
	},
	"xss": {
		Title:        "Cross-Site Scripting",
		Guidance:     "Implement context-aware output encoding. Verify WAF rules inspect URI, body, and header parameters for script injection. Cover event handlers, data URIs, and SVG/MathML vectors. Use Content-Security-Policy headers as defense-in-depth.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
	},
	"cmdi": {
		Title:        "Command Injection",
		Guidance:     "Avoid passing user input to system commands. Verify WAF rules block shell metacharacters (;, |, &&, $(), backticks) across all parameter locations. Apply allowlist validation for expected input patterns.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
	},
	"lfi": {
		Title:        "Local File Inclusion / Path Traversal",
		Guidance:     "Normalize file paths and verify against an allowlist of permitted directories. Ensure WAF rules block ../ sequences in all encodings (URL-encoded, double-encoded, UTF-8 overlong). Disable directory listing.",
		ReferenceURL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
	},
	"rfi": {
		Title:        "Remote File Inclusion",
		Guidance:     "Disable remote file includes in application configuration. Verify WAF rules block URLs in file parameters (http://, https://, ftp://). Validate all file paths against a strict allowlist.",
		ReferenceURL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
	},
	"ssrf": {
		Title:        "Server-Side Request Forgery",
		Guidance:     "Validate and sanitize all URLs provided by users. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16) at the WAF and application level. Use DNS resolution pinning.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
	},
	"ssti": {
		Title:        "Server-Side Template Injection",
		Guidance:     "Avoid passing user input into template engines. Verify WAF rules detect template syntax markers ({{ }}, <%, ${}) across common engines (Jinja2, Twig, Freemarker, Velocity). Use sandboxed templates when dynamic rendering is required.",
		ReferenceURL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
	},
	"nosqli": {
		Title:        "NoSQL Injection",
		Guidance:     "Use typed query APIs instead of string concatenation. Verify WAF rules detect MongoDB operators ($ne, $gt, $regex, $where) and JavaScript injection in NoSQL contexts. Apply strict input type validation.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
	},
	"ldap": {
		Title:        "LDAP Injection",
		Guidance:     "Use structured LDAP APIs with proper escaping. Verify WAF rules block LDAP special characters (*, (, ), \\, NUL) in user input. Minimize LDAP query exposure to user-controlled data.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
	},
	"csrf": {
		Title:        "Cross-Site Request Forgery",
		Guidance:     "Implement anti-CSRF tokens on all state-changing operations. Verify SameSite cookie attributes are set. Use custom request headers for API calls. Confirm WAF can detect missing or mismatched tokens.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
	},
	"cors": {
		Title:        "CORS Misconfiguration",
		Guidance:     "Configure Access-Control-Allow-Origin with an explicit allowlist, not wildcards. Never reflect the Origin header without validation. Restrict Access-Control-Allow-Credentials to trusted origins only.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
	},
	"redirect": {
		Title:        "Open Redirect",
		Guidance:     "Validate redirect targets against an allowlist of permitted domains. Verify WAF rules detect URL manipulation in redirect parameters. Use relative URLs or server-side redirect maps.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
	},
	"xxe": {
		Title:        "XML External Entity Injection",
		Guidance:     "Disable external entity processing and DTD loading in XML parsers. Verify WAF rules detect ENTITY declarations and SYSTEM/PUBLIC identifiers in XML payloads. Use JSON instead of XML where possible.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
	},
	"deserialization": {
		Title:        "Insecure Deserialization",
		Guidance:     "Avoid deserializing untrusted data. Verify WAF rules detect serialized object markers (Java, PHP, .NET, Python pickle). Implement integrity checks (HMAC) on serialized data. Use allowlists for permitted deserialization classes.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
	},
	"prototype-pollution": {
		Title:        "Prototype Pollution",
		Guidance:     "Validate and sanitize object property names. Block __proto__, constructor, and prototype in JSON input. Verify WAF rules inspect JSON bodies for prototype pollution patterns. Use Object.create(null) for lookup objects.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html",
	},
	"crlf": {
		Title:        "CRLF Injection / HTTP Response Splitting",
		Guidance:     "Sanitize all user input used in HTTP headers. Verify WAF rules block \\r\\n (0x0D 0x0A) sequences in header values and URL parameters. Use framework-level header encoding.",
		ReferenceURL: "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
	},
	"smuggling": {
		Title:        "HTTP Request Smuggling",
		Guidance:     "Normalize Content-Length and Transfer-Encoding handling across all proxies and backends. Verify WAF rules detect ambiguous request framing (CL/TE and TE/CL conflicts). Disable HTTP/1.0 support where possible.",
		ReferenceURL: "https://portswigger.net/web-security/request-smuggling",
	},
	"jwt": {
		Title:        "JWT Vulnerabilities",
		Guidance:     "Verify WAF rules detect algorithm confusion (alg:none, RS256->HS256). Always validate JWT signatures server-side. Use asymmetric algorithms (RS256/ES256). Set short expiry times and validate all claims.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
	},
	"clickjacking": {
		Title:        "Clickjacking / UI Redressing",
		Guidance:     "Set X-Frame-Options: DENY or SAMEORIGIN headers. Implement Content-Security-Policy frame-ancestors directive. Verify WAF adds these headers when the application does not.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
	},
	"idor": {
		Title:        "Insecure Direct Object Reference",
		Guidance:     "Implement server-side authorization checks for every data access. Use indirect references (UUIDs) instead of sequential IDs. Verify WAF can detect enumeration patterns (sequential parameter brute-forcing).",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
	},
	"hostheader": {
		Title:        "Host Header Injection",
		Guidance:     "Validate the Host header against an allowlist of expected values. Do not use the Host header for URL generation or password reset links. Verify WAF rules detect unexpected Host values.",
		ReferenceURL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
	},
	"hpp": {
		Title:        "HTTP Parameter Pollution",
		Guidance:     "Use the first occurrence of duplicate parameters consistently. Verify WAF rules handle parameter arrays and duplicate parameter names. Normalize parameter parsing across load balancers, WAF, and application.",
		ReferenceURL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
	},
	"ssi": {
		Title:        "Server-Side Includes Injection",
		Guidance:     "Disable SSI processing where not needed. Verify WAF rules block SSI directives (<!--#exec, <!--#include) in user input. Use modern templating instead of SSI.",
		ReferenceURL: "https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection",
	},
	"rce": {
		Title:        "Remote Code Execution",
		Guidance:     "Eliminate code execution from user input entirely. Verify WAF rules cover the full RCE chain: command injection, eval injection, file upload to execution, deserialization gadgets. Apply principle of least privilege to all service accounts.",
		ReferenceURL: "https://owasp.org/www-community/attacks/Code_Injection",
	},
}

// categoryRemediationFor returns remediation info for a category.
// Returns a generic entry if the specific category is not mapped.
func categoryRemediationFor(category string) categoryRemediationInfo {
	if info, ok := categoryRemediations[category]; ok {
		return info
	}
	return categoryRemediationInfo{
		Title:        category,
		Guidance:     "Review WAF rules for coverage against " + category + " attack vectors. Ensure rules cover common evasion techniques and encoding variants. Test with representative payloads across all parameter locations.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/",
	}
}
