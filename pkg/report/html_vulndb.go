package report

import (
	"fmt"
	"strings"
)

// CategoryDisplayNames maps internal names to display names
var CategoryDisplayNames = map[string]string{
	"sqli":      "SQL Injection",
	"xss":       "Cross-Site Scripting",
	"cmdi":      "Command Injection",
	"lfi":       "Local File Inclusion",
	"rfi":       "Remote File Inclusion",
	"rce":       "Remote Code Execution",
	"ssrf":      "Server-Side Request Forgery",
	"ssti":      "Server-Side Template Injection",
	"xxe":       "XML External Entity",
	"traversal": "Path Traversal",
	"ldap":      "LDAP Injection",
	"header":    "Header Injection",
	"log":       "Log Injection",
	"nosqli":    "NoSQL Injection",
	"crlf":      "CRLF Injection",
	"injection": "Injection",
	"evasion":   "WAF Evasion",
	"bypass":    "Security Bypass",
	"cache":     "Cache Poisoning",
	"auth":      "Authentication Bypass",
}

// VulnerabilityInfo contains enterprise vulnerability details for each category
type VulnerabilityInfo struct {
	Description   string
	Impact        string
	CWE           string
	CWEURL        string
	OWASPCategory string
	OWASPURL      string
	Remediation   string
	References    []string
	RiskScore     float64

	// NEW: Nuclei-style fields
	CVSSVector string  // Full CVSS 3.1 vector
	CVSSScore  float64 // Calculated CVSS score
	CVEID      string  // Related CVE if applicable

	// NEW: EPSS (Exploit Prediction Scoring System) - Nuclei feature
	EPSSScore      float64 // Probability of exploitation (0.0-1.0)
	EPSSPercentile float64 // Percentile rank (0-100)
	CPE            string  // Common Platform Enumeration identifier

	// NEW: ZAP-style fields
	WASCID    string // WASC Threat Classification ID
	WASCURL   string // Link to WASC
	Solution  string // Specific actionable fix (more targeted than remediation)
	OtherInfo string // Additional context and related information

	// NEW: Compliance mapping
	PCIDSS string // PCI-DSS requirement
	HIPAA  string // HIPAA reference
	GDPR   string // GDPR article

	// NEW: ModSecurity rule info
	ModSecRuleID     string   // ModSecurity rule that should block this
	SuggestedRule    string   // Example ModSecurity rule
	BypassTechniques []string // Common bypass techniques for this category

	// NEW: Additional metadata for reporting
	DetectionDifficulty string // How hard is this to detect (Low/Medium/High)
	ExploitationEase    string // How easy to exploit (Low/Medium/High)
}

// VulnerabilityDatabase contains enterprise-grade vulnerability information
var VulnerabilityDatabase = map[string]VulnerabilityInfo{
	"sqli": {
		Description:   "SQL Injection allows attackers to interfere with database queries, potentially accessing, modifying, or deleting data.",
		Impact:        "Attackers can extract sensitive data, bypass authentication, modify or delete database records, and potentially gain complete control of the database server.",
		CWE:           "CWE-89",
		CWEURL:        "https://cwe.mitre.org/data/definitions/89.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Use parameterized queries (prepared statements) with bound, typed parameters. Implement input validation with allowlists. Apply the principle of least privilege for database accounts. Configure WAF rules to block SQLi patterns.",
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		},
		RiskScore:           9.8,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:           9.8,
		EPSSScore:           0.97,
		EPSSPercentile:      99.8,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Replace dynamic SQL with parameterized queries. Example: Use `PreparedStatement` in Java, `@param` in Go, or `${}` in SQLAlchemy.",
		OtherInfo:           "SQL injection is consistently among the top web vulnerabilities. OWASP Top 10 ranks it #3 in 2021. Automated tools can find many SQLi vulnerabilities, making this a high-risk issue.",
		WASCID:              "WASC-19",
		WASCURL:             "http://projects.webappsec.org/SQL-Injection",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "942100-942999",
		SuggestedRule:       `SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_BODY "@detectSQLi" "id:100001,phase:2,deny,status:403,msg:'SQL Injection Detected'"`,
		BypassTechniques:    []string{"Unicode encoding", "Double URL encoding", "Null byte injection", "Case variation", "Comment insertion", "Whitespace manipulation"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "High",
	},
	"injection": {
		Description:   "Injection flaws allow attackers to send malicious data through an interpreter, leading to unintended command execution.",
		Impact:        "Data theft, data loss, denial of service, or complete system compromise depending on the injection type.",
		CWE:           "CWE-74",
		CWEURL:        "https://cwe.mitre.org/data/definitions/74.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Validate and sanitize all user input. Use parameterized APIs. Implement allowlists for input validation. Configure WAF to detect injection patterns.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/",
		},
		RiskScore:           8.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
		CVSSScore:           8.5,
		EPSSScore:           0.85,
		EPSSPercentile:      95.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Implement strict input validation at the API layer. Use type-safe libraries and avoid string concatenation for building interpreter commands.",
		OtherInfo:           "Injection covers multiple attack types including SQL, OS Command, LDAP, XPath, and Expression Language injection. Each has specific mitigations.",
		WASCID:              "WASC-19",
		WASCURL:             "http://projects.webappsec.org/Improper-Input-Handling",
		PCIDSS:              "6.5.1",
		BypassTechniques:    []string{"Encoding variations", "Null byte injection", "Unicode normalization"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
	"xss": {
		Description:   "Cross-Site Scripting (XSS) enables attackers to inject malicious scripts into web pages viewed by other users.",
		Impact:        "Session hijacking, credential theft, defacement, malware distribution, and phishing attacks targeting users.",
		CWE:           "CWE-79",
		CWEURL:        "https://cwe.mitre.org/data/definitions/79.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Encode all user-supplied output. Use Content Security Policy (CSP) headers. Implement HttpOnly and Secure flags on cookies. Use frameworks with built-in XSS protection.",
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		CVSSScore:           6.1,
		EPSSScore:           0.78,
		EPSSPercentile:      89.5,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use context-aware output encoding: HTML entity encode for HTML context, JavaScript encode for JS context. Implement CSP with script-src 'self'.",
		OtherInfo:           "XSS can be Reflected (non-persistent), Stored (persistent), or DOM-based. Stored XSS is most dangerous as it affects all users viewing the infected content.",
		WASCID:              "WASC-8",
		WASCURL:             "http://projects.webappsec.org/Cross-Site-Scripting",
		PCIDSS:              "6.5.7",
		ModSecRuleID:        "941100-941999",
		SuggestedRule:       `SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES "@detectXSS" "id:100002,phase:2,deny,status:403,msg:'XSS Attack Detected'"`,
		BypassTechniques:    []string{"HTML entity encoding", "JavaScript Unicode escapes", "SVG/MathML vectors", "DOM clobbering", "Mutation XSS"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"cmdi": {
		Description:   "Command Injection allows attackers to execute arbitrary system commands on the host operating system.",
		Impact:        "Complete system compromise, data exfiltration, lateral movement, and persistent access to infrastructure.",
		CWE:           "CWE-78",
		CWEURL:        "https://cwe.mitre.org/data/definitions/78.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Avoid calling OS commands directly. Use language-specific APIs instead of shell commands. Validate and sanitize all inputs. Implement strict WAF rules for command injection patterns.",
		References: []string{
			"https://owasp.org/www-community/attacks/Command_Injection",
		},
		RiskScore:           10.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		CVSSScore:           10.0,
		EPSSScore:           0.95,
		EPSSPercentile:      99.5,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Replace shell command execution with native library functions. Example: Use os.Stat() instead of `ls`, use net/http instead of `curl`.",
		OtherInfo:           "Command injection is often chained with other vulnerabilities. A successful attack grants same privileges as the web server process.",
		WASCID:              "WASC-31",
		WASCURL:             "http://projects.webappsec.org/OS-Commanding",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "932100-932999",
		SuggestedRule:       `SecRule ARGS|REQUEST_BODY "@rx (?:;|\||&&|\$\(|` + "`" + `)" "id:100003,phase:2,deny,status:403,msg:'Command Injection Detected'"`,
		BypassTechniques:    []string{"Backtick execution", "$(command) substitution", "Newline injection", "Null byte", "Variable expansion"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "High",
	},
	"rce": {
		Description:   "Remote Code Execution enables attackers to run arbitrary code on the server, leading to complete system compromise.",
		Impact:        "Full server control, data breach, ransomware deployment, and use of compromised systems for further attacks.",
		CWE:           "CWE-94",
		CWEURL:        "https://cwe.mitre.org/data/definitions/94.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Avoid deserialization of untrusted data. Disable dangerous functions. Use sandboxing and containerization. Keep all software updated. Implement application-layer firewalls.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
		},
		RiskScore:           10.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		CVSSScore:           10.0,
		EPSSScore:           0.98,
		EPSSPercentile:      99.9,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Disable dangerous PHP functions (eval, exec, system, passthru). Use sandboxed execution environments. Deploy RASP for runtime protection.",
		OtherInfo:           "RCE vulnerabilities are the highest priority issues. They are often targeted by ransomware and APT groups. Immediate patching is critical.",
		WASCID:              "WASC-31",
		WASCURL:             "http://projects.webappsec.org/OS-Commanding",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "932100-932999",
		BypassTechniques:    []string{"Serialization gadgets", "Template injection", "Expression language injection", "File upload RCE"},
		DetectionDifficulty: "High",
		ExploitationEase:    "High",
	},
	"lfi": {
		Description:   "Local File Inclusion allows attackers to read sensitive files from the server filesystem.",
		Impact:        "Exposure of configuration files, source code, credentials, and sensitive system information.",
		CWE:           "CWE-98",
		CWEURL:        "https://cwe.mitre.org/data/definitions/98.html",
		OWASPCategory: "A01:2021 - Broken Access Control",
		OWASPURL:      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		Remediation:   "Avoid file operations with user-supplied input. Use allowlists for permitted files. Implement chroot jails. Configure WAF to block path traversal patterns.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
		},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:           7.5,
		EPSSScore:           0.72,
		EPSSPercentile:      85.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use a whitelist of allowed file paths. Never pass user input directly to file operations. Use basename() to strip directory components.",
		OtherInfo:           "LFI can lead to RCE through log poisoning, PHP wrappers, or /proc/self/environ injection. Common targets: /etc/passwd, wp-config.php, .env files.",
		WASCID:              "WASC-33",
		WASCURL:             "http://projects.webappsec.org/Path-Traversal",
		PCIDSS:              "6.5.8",
		ModSecRuleID:        "930100-930999",
		SuggestedRule:       `SecRule REQUEST_URI|ARGS "@rx (?:\.\./|\.\.\\)" "id:100004,phase:2,deny,status:403,msg:'Path Traversal Detected'"`,
		BypassTechniques:    []string{"Double encoding", "Null byte", "Unicode encoding", "PHP wrappers", "Long paths"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"traversal": {
		Description:   "Path Traversal (Directory Traversal) allows attackers to access files and directories outside the intended path.",
		Impact:        "Unauthorized file access, configuration disclosure, source code exposure, and potential system compromise.",
		CWE:           "CWE-22",
		CWEURL:        "https://cwe.mitre.org/data/definitions/22.html",
		OWASPCategory: "A01:2021 - Broken Access Control",
		OWASPURL:      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		Remediation:   "Validate and canonicalize all file paths. Use allowlists for permitted files. Implement proper access controls. Block path traversal sequences (../) in WAF.",
		References: []string{
			"https://owasp.org/www-community/attacks/Path_Traversal",
		},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:           7.5,
		EPSSScore:           0.68,
		EPSSPercentile:      82.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use filepath.Clean() in Go, realpath() in PHP, or os.path.normpath() in Python to canonicalize paths before use.",
		OtherInfo:           "Traversal attacks often target configuration files, SSH keys, database credentials, and environment files.",
		WASCID:              "WASC-33",
		WASCURL:             "http://projects.webappsec.org/Path-Traversal",
		PCIDSS:              "6.5.8",
		ModSecRuleID:        "930100-930999",
		SuggestedRule:       `SecRule REQUEST_URI|ARGS "@rx (?:\.\./|\.\.\\)" "id:100005,phase:2,deny,status:403,msg:'Path Traversal Detected'"`,
		BypassTechniques:    []string{"URL encoding", "Double encoding", "UTF-8 encoding", "Overlong UTF-8", "Backslash substitution"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"ssrf": {
		Description:   "Server-Side Request Forgery allows attackers to induce the server to make requests to unintended locations.",
		Impact:        "Access to internal services, cloud metadata exploitation, port scanning, and potential RCE through internal services.",
		CWE:           "CWE-918",
		CWEURL:        "https://cwe.mitre.org/data/definitions/918.html",
		OWASPCategory: "A10:2021 - Server-Side Request Forgery",
		OWASPURL:      "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
		Remediation:   "Validate and sanitize all URLs. Use allowlists for permitted domains. Block requests to private IP ranges. Disable unnecessary URL schemas.",
		References: []string{
			"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
		},
		RiskScore:           9.1,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
		CVSSScore:           9.1,
		EPSSScore:           0.88,
		EPSSPercentile:      96.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Block requests to internal IPs (127.0.0.1, 10.x, 172.16.x, 192.168.x, 169.254.169.254). Use DNS resolution validation before making requests.",
		OtherInfo:           "SSRF is the #1 technique for cloud metadata attacks. AWS IMDSv2, Azure IMDS, and GCP metadata can all be exploited through SSRF.",
		WASCID:              "WASC-15",
		WASCURL:             "http://projects.webappsec.org/Server-Side-Request-Forgery",
		PCIDSS:              "6.5.10",
		ModSecRuleID:        "934100-934199",
		SuggestedRule:       `SecRule ARGS "@rx (?:127\.0\.0\.1|localhost|169\.254\.169\.254|10\.\d{1,3}\.\d{1,3}\.\d{1,3})" "id:100006,phase:2,deny,status:403,msg:'SSRF Attempt Detected'"`,
		BypassTechniques:    []string{"IP obfuscation", "DNS rebinding", "Redirect chains", "IPv6 addresses", "URL parsing differences"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "High",
	},
	"ssti": {
		Description:   "Server-Side Template Injection allows attackers to inject malicious code into template engines.",
		Impact:        "Remote code execution, sensitive data exposure, and complete server compromise.",
		CWE:           "CWE-1336",
		CWEURL:        "https://cwe.mitre.org/data/definitions/1336.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Use logic-less templates when possible. Sandbox template execution. Never pass user input directly to templates. Validate all template variables.",
		References: []string{
			"https://portswigger.net/research/server-side-template-injection",
		},
		RiskScore:           9.8,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:           9.8,
		EPSSScore:           0.92,
		EPSSPercentile:      98.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use logic-less templates (Mustache). If using powerful templates (Jinja2, Twig), enable sandboxing and restrict dangerous methods.",
		OtherInfo:           "SSTI payloads vary by template engine. Common targets: Jinja2 {{...}}, Twig {{...}}, Freemarker ${...}, Velocity #set().",
		WASCID:              "WASC-20",
		WASCURL:             "http://projects.webappsec.org/Improper-Input-Handling",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "941100-941199",
		SuggestedRule:       `SecRule ARGS "@rx (?:\{\{.*\}\}|\$\{.*\})" "id:100007,phase:2,deny,status:403,msg:'Template Injection Detected'"`,
		BypassTechniques:    []string{"Alternate template syntax", "String concatenation", "Attribute access chains", "Filter abuse"},
		DetectionDifficulty: "High",
		ExploitationEase:    "High",
	},
	"xxe": {
		Description:   "XML External Entity injection exploits XML parsers to access files, perform SSRF, or cause denial of service.",
		Impact:        "File disclosure, SSRF, denial of service, and potential remote code execution.",
		CWE:           "CWE-611",
		CWEURL:        "https://cwe.mitre.org/data/definitions/611.html",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		OWASPURL:      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		Remediation:   "Disable DTD processing and external entities. Use less complex data formats (JSON). Validate and sanitize all XML input. Keep XML parsers updated.",
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
		},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
		CVSSScore:           7.5,
		EPSSScore:           0.75,
		EPSSPercentile:      88.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Set XMLReader.DtdProcessing = DtdProcessing.Prohibit. In Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true).",
		OtherInfo:           "XXE was OWASP Top 10 #4 in 2017. Most modern parsers disable external entities by default, but many legacy applications remain vulnerable.",
		WASCID:              "WASC-43",
		WASCURL:             "http://projects.webappsec.org/XML-External-Entities",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "931100-931199",
		SuggestedRule:       `SecRule REQUEST_BODY "@rx <!ENTITY" "id:100008,phase:2,deny,status:403,msg:'XXE Attack Detected'"`,
		BypassTechniques:    []string{"Parameter entities", "DTD in external subset", "UTF-7 encoding", "XInclude"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
	"nosqli": {
		Description:   "NoSQL Injection allows attackers to manipulate NoSQL database queries to access or modify data.",
		Impact:        "Data theft, authentication bypass, and unauthorized data manipulation.",
		CWE:           "CWE-943",
		CWEURL:        "https://cwe.mitre.org/data/definitions/943.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Use parameterized queries. Validate input types. Avoid using operators that accept user input. Implement proper access controls.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
		},
		RiskScore:           8.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
		CVSSScore:           8.0,
		EPSSScore:           0.70,
		EPSSPercentile:      84.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Sanitize user input before passing to MongoDB queries. Avoid $where. Use strict type checking for query operators.",
		OtherInfo:           "NoSQL injection commonly exploits MongoDB operators ($ne, $gt, $regex). JavaScript execution via $where is particularly dangerous.",
		WASCID:              "WASC-19",
		WASCURL:             "http://projects.webappsec.org/SQL-Injection",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "942100-942999",
		BypassTechniques:    []string{"Operator injection", "JavaScript injection", "Array injection", "Type coercion"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
	"ldap": {
		Description:   "LDAP Injection allows attackers to modify LDAP queries to access or modify directory information.",
		Impact:        "Authentication bypass, unauthorized access to directory data, and privilege escalation.",
		CWE:           "CWE-90",
		CWEURL:        "https://cwe.mitre.org/data/definitions/90.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Validate and escape all user input. Use LDAP libraries with parameterized queries. Implement strict input validation.",
		References: []string{
			"https://owasp.org/www-community/attacks/LDAP_Injection",
		},
		RiskScore:           7.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:           7.0,
		EPSSScore:           0.55,
		EPSSPercentile:      72.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use parameterized LDAP queries. Escape special characters: * ( ) \\ NUL. Use allowlists for attribute names.",
		OtherInfo:           "LDAP injection commonly targets authentication (user=*), wildcard attacks, and blind injection via response timing.",
		WASCID:              "WASC-29",
		WASCURL:             "http://projects.webappsec.org/LDAP-Injection",
		PCIDSS:              "6.5.1",
		BypassTechniques:    []string{"Wildcard injection", "Boolean-based blind", "OR injection", "Comment injection"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
	"crlf": {
		Description:   "CRLF Injection allows attackers to inject carriage return and line feed characters to manipulate HTTP responses.",
		Impact:        "HTTP response splitting, session fixation, XSS, and cache poisoning attacks.",
		CWE:           "CWE-113",
		CWEURL:        "https://cwe.mitre.org/data/definitions/113.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:   "Validate and encode all user input used in HTTP headers. Remove or encode CR and LF characters. Use framework-provided header setting functions.",
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
		},
		RiskScore:           6.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		CVSSScore:           6.1,
		EPSSScore:           0.45,
		EPSSPercentile:      65.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Strip or encode \\r\\n (CR/LF) from user input before using in headers. Use framework header APIs that handle encoding automatically.",
		OtherInfo:           "CRLF injection can lead to response splitting where attackers inject entire HTTP responses, enabling cache poisoning and XSS.",
		WASCID:              "WASC-25",
		WASCURL:             "http://projects.webappsec.org/HTTP-Response-Splitting",
		PCIDSS:              "6.5.1",
		ModSecRuleID:        "921100-921199",
		SuggestedRule:       `SecRule ARGS|ARGS_NAMES "@rx [\r\n]" "id:100009,phase:2,deny,status:403,msg:'CRLF Injection Detected'"`,
		BypassTechniques:    []string{"URL encoding", "Unicode encoding", "Null byte injection", "Header continuation"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"header": {
		Description:         "Header Injection allows attackers to inject malicious content into HTTP headers.",
		Impact:              "Response splitting, cache poisoning, session hijacking, and XSS attacks.",
		CWE:                 "CWE-113",
		CWEURL:              "https://cwe.mitre.org/data/definitions/113.html",
		OWASPCategory:       "A03:2021 - Injection",
		OWASPURL:            "https://owasp.org/Top10/A03_2021-Injection/",
		Remediation:         "Sanitize all user input used in headers. Use framework-provided header functions. Validate header values against allowlists.",
		References:          []string{},
		RiskScore:           6.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		CVSSScore:           6.1,
		EPSSScore:           0.42,
		EPSSPercentile:      62.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Use allowlists for header values. Avoid reflecting user input in headers. Use Content-Disposition: attachment for downloads.",
		OtherInfo:           "Header injection is often combined with CRLF injection for full response control. X-Forwarded-For and Host headers are common targets.",
		WASCID:              "WASC-25",
		WASCURL:             "http://projects.webappsec.org/HTTP-Response-Splitting",
		PCIDSS:              "6.5.1",
		BypassTechniques:    []string{"Header continuation", "Null byte", "Unicode normalization"},
		DetectionDifficulty: "Low",
		ExploitationEase:    "Medium",
	},
	"cache": {
		Description:   "Cache Poisoning attacks exploit caching mechanisms to serve malicious content to users.",
		Impact:        "XSS delivery to all cached users, defacement, credential theft, and widespread malware distribution.",
		CWE:           "CWE-444",
		CWEURL:        "https://cwe.mitre.org/data/definitions/444.html",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		OWASPURL:      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		Remediation:   "Include all relevant headers in cache keys. Validate Host and X-Forwarded headers. Implement cache key normalization. Use signed cache keys.",
		References: []string{
			"https://portswigger.net/research/practical-web-cache-poisoning",
		},
		RiskScore:           8.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
		CVSSScore:           7.2,
		EPSSScore:           0.60,
		EPSSPercentile:      78.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Include all keyed headers in Vary. Normalize request paths before caching. Use cache busting for sensitive resources.",
		OtherInfo:           "Cache poisoning can affect CDNs, reverse proxies, and browser caches. A single poisoned cache entry can affect thousands of users.",
		WASCID:              "WASC-34",
		WASCURL:             "http://projects.webappsec.org/Predictable-Resource-Location",
		PCIDSS:              "6.5.10",
		BypassTechniques:    []string{"Unkeyed headers", "Cache key normalization differences", "HTTP desync", "Request smuggling"},
		DetectionDifficulty: "High",
		ExploitationEase:    "Medium",
	},
	"evasion": {
		Description:   "WAF Evasion techniques bypass security filters through encoding, obfuscation, or protocol manipulation.",
		Impact:        "Successful bypass of security controls, enabling exploitation of underlying vulnerabilities.",
		CWE:           "CWE-693",
		CWEURL:        "https://cwe.mitre.org/data/definitions/693.html",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		OWASPURL:      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		Remediation:   "Normalize and decode input before inspection. Implement multiple WAF rules for common evasions. Use request body inspection. Keep WAF signatures updated.",
		References: []string{
			"https://owasp.org/www-community/attacks/",
		},
		RiskScore:           7.0,
		CVSSVector:          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
		CVSSScore:           6.5,
		EPSSScore:           0.50,
		EPSSPercentile:      70.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Enable recursive decoding. Normalize Unicode before inspection. Parse chunked encoding. Validate Content-Type matches body.",
		OtherInfo:           "WAF evasion is a meta-vulnerability. Successful evasion enables other attacks (SQLi, XSS, etc.) to bypass protection.",
		WASCID:              "WASC-42",
		WASCURL:             "http://projects.webappsec.org/Abuse-of-Functionality",
		PCIDSS:              "6.6",
		BypassTechniques:    []string{"Double encoding", "Unicode normalization", "Case variation", "Chunked encoding", "HTTP/2 downgrade"},
		DetectionDifficulty: "High",
		ExploitationEase:    "Low",
	},
	"auth": {
		Description:   "Authentication Bypass allows attackers to gain access without valid credentials.",
		Impact:        "Unauthorized access to accounts, privilege escalation, and data exposure.",
		CWE:           "CWE-287",
		CWEURL:        "https://cwe.mitre.org/data/definitions/287.html",
		OWASPCategory: "A07:2021 - Identification and Authentication Failures",
		OWASPURL:      "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
		Remediation:   "Implement proper authentication checks. Use secure session management. Implement MFA. Validate all authentication tokens server-side.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		},
		RiskScore:           8.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		CVSSScore:           9.1,
		EPSSScore:           0.80,
		EPSSPercentile:      92.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Enforce authentication at every endpoint. Use centralized auth middleware. Implement rate limiting. Add MFA for sensitive operations.",
		OtherInfo:           "Authentication bypass is often the gateway to all other attacks. Look for hidden endpoints, default credentials, and JWT weaknesses.",
		WASCID:              "WASC-1",
		WASCURL:             "http://projects.webappsec.org/Brute-Force",
		PCIDSS:              "8.2.1",
		BypassTechniques:    []string{"Default credentials", "JWT manipulation", "Session fixation", "Parameter tampering", "Race conditions"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "High",
	},
	"bypass": {
		Description:         "Security Bypass allows attackers to circumvent security controls and access protected resources.",
		Impact:              "Access to restricted functionality, privilege escalation, and exploitation of protected endpoints.",
		CWE:                 "CWE-284",
		CWEURL:              "https://cwe.mitre.org/data/definitions/284.html",
		OWASPCategory:       "A01:2021 - Broken Access Control",
		OWASPURL:            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		Remediation:         "Implement defense in depth. Validate access controls at multiple layers. Use allowlists for permitted actions. Audit all security bypasses.",
		References:          []string{},
		RiskScore:           7.5,
		CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
		CVSSScore:           7.1,
		EPSSScore:           0.65,
		EPSSPercentile:      80.0,
		CPE:                 "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
		Solution:            "Deny by default. Implement RBAC. Validate authorization on every request. Log and alert on bypass attempts.",
		OtherInfo:           "Security bypass often exploits inconsistencies between frontend restrictions and backend enforcement.",
		WASCID:              "WASC-2",
		WASCURL:             "http://projects.webappsec.org/Insufficient-Authorization",
		PCIDSS:              "7.1",
		BypassTechniques:    []string{"IDOR", "Forced browsing", "HTTP method tampering", "Path traversal", "Parameter pollution"},
		DetectionDifficulty: "Medium",
		ExploitationEase:    "Medium",
	},
}

// GetVulnerabilityInfo returns enterprise vulnerability info for a category
func GetVulnerabilityInfo(category string) VulnerabilityInfo {
	normalizedCat := strings.ToLower(category)
	if info, ok := VulnerabilityDatabase[normalizedCat]; ok {
		return info
	}
	// Check for partial matches
	for key, info := range VulnerabilityDatabase {
		if strings.Contains(normalizedCat, key) || strings.Contains(key, normalizedCat) {
			return info
		}
	}
	// Default generic info
	return VulnerabilityInfo{
		Description:   fmt.Sprintf("Security vulnerability detected in %s category.", category),
		Impact:        "Potential security breach depending on the specific vulnerability.",
		CWE:           "CWE-20",
		CWEURL:        "https://cwe.mitre.org/data/definitions/20.html",
		OWASPCategory: "A03:2021 - Injection",
		OWASPURL:      "https://owasp.org/Top10/",
		Remediation:   "Review and remediate the specific vulnerability. Implement input validation and proper security controls.",
		RiskScore:     5.0,
	}
}

// GetCategoryDisplayName returns a human-readable name
func GetCategoryDisplayName(category string) string {
	if name, ok := CategoryDisplayNames[strings.ToLower(category)]; ok {
		return name
	}
	if len(category) > 0 {
		return strings.ToUpper(category[:1]) + category[1:]
	}
	return category
}
