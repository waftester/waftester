// Package defaults provides canonical default values for the entire codebase.
// This file contains WASC Threat Classification reference data - the SINGLE SOURCE OF TRUTH.
//
// WASC (Web Application Security Consortium) Threat Classification v2.0
// provides a standardized vocabulary for describing web security vulnerabilities.
//
// Usage:
//
//	wasc := defaults.WASCMapping["sqli"]           // "WASC-19"
//	name := defaults.WASCThreatClass["WASC-19"].Name  // "SQL Injection"
//	url := defaults.WASCThreatClass["WASC-19"].URL    // "http://projects.webappsec.org/..."
package defaults

// WASCThreat represents a WASC Threat Classification entry with all metadata.
type WASCThreat struct {
	ID          string // e.g., "WASC-19"
	Name        string // e.g., "SQL Injection"
	Description string // Brief description
	URL         string // Official WASC project URL
}

// WASCThreatClass contains all WASC Threat Classification entries indexed by ID.
// This is the SINGLE SOURCE OF TRUTH for WASC data across all writers/reporters.
var WASCThreatClass = map[string]WASCThreat{
	"WASC-01": {
		ID:          "WASC-01",
		Name:        "Insufficient Authentication",
		Description: "Insufficient Authentication occurs when a web site permits an attacker to access sensitive content or functionality without having to properly authenticate.",
		URL:         "http://projects.webappsec.org/w/page/13246939/Insufficient%20Authentication",
	},
	"WASC-02": {
		ID:          "WASC-02",
		Name:        "Insufficient Authorization",
		Description: "Insufficient Authorization is when a web site permits access to sensitive content or functionality that should require increased access control restrictions.",
		URL:         "http://projects.webappsec.org/w/page/13246940/Insufficient%20Authorization",
	},
	"WASC-03": {
		ID:          "WASC-03",
		Name:        "Integer Overflows",
		Description: "An Integer Overflow is the condition that occurs when the result of an arithmetic operation exceeds the maximum size of the integer type used to store it.",
		URL:         "http://projects.webappsec.org/w/page/13246946/Integer%20Overflows",
	},
	"WASC-04": {
		ID:          "WASC-04",
		Name:        "Insufficient Transport Layer Protection",
		Description: "Insufficient Transport Layer Protection allows communication to be exposed to untrusted third parties, providing an attack vector to compromise the web application.",
		URL:         "http://projects.webappsec.org/w/page/13246945/Insufficient%20Transport%20Layer%20Protection",
	},
	"WASC-05": {
		ID:          "WASC-05",
		Name:        "Remote File Inclusion",
		Description: "Remote File Inclusion (RFI) is an attack technique used to exploit the dynamic file include mechanisms in web applications.",
		URL:         "http://projects.webappsec.org/w/page/13246955/Remote%20File%20Inclusion",
	},
	"WASC-06": {
		ID:          "WASC-06",
		Name:        "Format String",
		Description: "A Format String attack is a class of vulnerabilities discovered in 1999. The attack can be used to read or write memory.",
		URL:         "http://projects.webappsec.org/w/page/13246926/Format%20String",
	},
	"WASC-07": {
		ID:          "WASC-07",
		Name:        "Buffer Overflow",
		Description: "Buffer Overflow errors occur when we operate on buffers of char type and when the data being written exceeds its boundary.",
		URL:         "http://projects.webappsec.org/w/page/13246916/Buffer%20Overflow",
	},
	"WASC-08": {
		ID:          "WASC-08",
		Name:        "Cross-site Scripting",
		Description: "Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance.",
		URL:         "http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting",
	},
	"WASC-09": {
		ID:          "WASC-09",
		Name:        "Cross-site Request Forgery",
		Description: "Cross-site Request Forgery (CSRF) is an attack which forces an end user to execute unwanted actions on a web application.",
		URL:         "http://projects.webappsec.org/w/page/13246919/Cross%20Site%20Request%20Forgery",
	},
	"WASC-10": {
		ID:          "WASC-10",
		Name:        "Denial of Service",
		Description: "Denial of Service (DoS) is an attack technique with the intent of preventing a web site from serving normal user activity.",
		URL:         "http://projects.webappsec.org/w/page/13246921/Denial%20of%20Service",
	},
	"WASC-11": {
		ID:          "WASC-11",
		Name:        "Brute Force",
		Description: "A Brute Force attack is an automated process of trial and error used to guess a person's username, password, credit-card number or cryptographic key.",
		URL:         "http://projects.webappsec.org/w/page/13246915/Brute%20Force",
	},
	"WASC-12": {
		ID:          "WASC-12",
		Name:        "Content Spoofing",
		Description: "Content Spoofing is an attack technique used to trick a user into believing that certain content appearing on a web site is legitimate.",
		URL:         "http://projects.webappsec.org/w/page/13246917/Content%20Spoofing",
	},
	"WASC-13": {
		ID:          "WASC-13",
		Name:        "Information Leakage",
		Description: "Information Leakage is when a web site reveals sensitive data, such as developer comments or error messages, which may aid an attacker.",
		URL:         "http://projects.webappsec.org/w/page/13246936/Information%20Leakage",
	},
	"WASC-14": {
		ID:          "WASC-14",
		Name:        "Server Misconfiguration",
		Description: "Server Misconfiguration errors allow attackers to access restricted files or functionality.",
		URL:         "http://projects.webappsec.org/w/page/13246959/Server%20Misconfiguration",
	},
	"WASC-15": {
		ID:          "WASC-15",
		Name:        "Application Misconfiguration",
		Description: "Application Misconfiguration attacks exploit configuration weaknesses found in web applications.",
		URL:         "http://projects.webappsec.org/w/page/13246914/Application%20Misconfiguration",
	},
	"WASC-16": {
		ID:          "WASC-16",
		Name:        "Directory Indexing",
		Description: "Automatic directory listing/indexing is a web server function that lists all of the files within a requested directory.",
		URL:         "http://projects.webappsec.org/w/page/13246922/Directory%20Indexing",
	},
	"WASC-17": {
		ID:          "WASC-17",
		Name:        "Improper Filesystem Permissions",
		Description: "Improper File permissions occur when file/directory permissions are improperly configured on a web server.",
		URL:         "http://projects.webappsec.org/w/page/13246934/Improper%20Filesystem%20Permissions",
	},
	"WASC-18": {
		ID:          "WASC-18",
		Name:        "Credential/Session Prediction",
		Description: "Credential/Session Prediction is a method of hijacking or impersonating a web site user.",
		URL:         "http://projects.webappsec.org/w/page/13246918/Credential%20Session%20Prediction",
	},
	"WASC-19": {
		ID:          "WASC-19",
		Name:        "SQL Injection",
		Description: "SQL Injection is an attack technique used to exploit applications that construct SQL statements from user-supplied input.",
		URL:         "http://projects.webappsec.org/w/page/13246963/SQL%20Injection",
	},
	"WASC-20": {
		ID:          "WASC-20",
		Name:        "Improper Input Handling",
		Description: "Improper Input Handling is when input data is not properly validated, filtered, or sanitized.",
		URL:         "http://projects.webappsec.org/w/page/13246933/Improper%20Input%20Handling",
	},
	"WASC-21": {
		ID:          "WASC-21",
		Name:        "Insufficient Anti-automation",
		Description: "Insufficient Anti-automation is when a web site permits an attacker to automate a process that was originally designed to only be performed manually.",
		URL:         "http://projects.webappsec.org/w/page/13246938/Insufficient%20Anti-automation",
	},
	"WASC-22": {
		ID:          "WASC-22",
		Name:        "Improper Output Handling",
		Description: "Improper Output Handling is when output data is not properly encoded, escaped, or sanitized.",
		URL:         "http://projects.webappsec.org/w/page/13246935/Improper%20Output%20Handling",
	},
	"WASC-23": {
		ID:          "WASC-23",
		Name:        "XML Injection",
		Description: "XML Injection is an attack technique used to manipulate or compromise the logic of an XML application or document.",
		URL:         "http://projects.webappsec.org/w/page/13247004/XML%20Injection",
	},
	"WASC-24": {
		ID:          "WASC-24",
		Name:        "HTTP Request Splitting",
		Description: "HTTP Request Splitting is an attack where the attacker can manipulate requests to inject additional HTTP requests.",
		URL:         "http://projects.webappsec.org/w/page/13246929/HTTP%20Request%20Splitting",
	},
	"WASC-25": {
		ID:          "WASC-25",
		Name:        "HTTP Response Splitting",
		Description: "HTTP Response Splitting is an attack where the attacker can forge a completely controlled response sent from the target server.",
		URL:         "http://projects.webappsec.org/w/page/13246931/HTTP%20Response%20Splitting",
	},
	"WASC-26": {
		ID:          "WASC-26",
		Name:        "HTTP Request Smuggling",
		Description: "HTTP Request Smuggling is an attack technique that abuses the discrepancy in parsing of non RFC compliant HTTP requests.",
		URL:         "http://projects.webappsec.org/w/page/13246930/HTTP%20Request%20Smuggling",
	},
	"WASC-27": {
		ID:          "WASC-27",
		Name:        "HTTP Response Smuggling",
		Description: "HTTP Response Smuggling is an attack technique that abuses HTTP parsing discrepancies to smuggle responses.",
		URL:         "http://projects.webappsec.org/w/page/13246932/HTTP%20Response%20Smuggling",
	},
	"WASC-28": {
		ID:          "WASC-28",
		Name:        "Null Byte Injection",
		Description: "Null Byte Injection is an exploitation technique that uses null byte characters to bypass sanity checking filters.",
		URL:         "http://projects.webappsec.org/w/page/13246949/Null%20Byte%20Injection",
	},
	"WASC-29": {
		ID:          "WASC-29",
		Name:        "LDAP Injection",
		Description: "LDAP Injection is an attack technique used to exploit applications that construct LDAP statements from user-supplied input.",
		URL:         "http://projects.webappsec.org/w/page/13246947/LDAP%20Injection",
	},
	"WASC-30": {
		ID:          "WASC-30",
		Name:        "Mail Command Injection",
		Description: "Mail Command Injection is an attack technique used to exploit mail servers and webmail applications.",
		URL:         "http://projects.webappsec.org/w/page/13246948/Mail%20Command%20Injection",
	},
	"WASC-31": {
		ID:          "WASC-31",
		Name:        "OS Commanding",
		Description: "OS Commanding is an attack technique used to exploit applications that execute operating system commands.",
		URL:         "http://projects.webappsec.org/w/page/13246950/OS%20Commanding",
	},
	"WASC-32": {
		ID:          "WASC-32",
		Name:        "Routing Detour",
		Description: "Routing Detour attacks occur when an attacker can take control of an intermediary web service routing message.",
		URL:         "http://projects.webappsec.org/w/page/13246956/Routing%20Detour",
	},
	"WASC-33": {
		ID:          "WASC-33",
		Name:        "Path Traversal",
		Description: "Path Traversal is an attack technique that allows an attacker access to files, directories, and commands outside the document root.",
		URL:         "http://projects.webappsec.org/w/page/13246952/Path%20Traversal",
	},
	"WASC-34": {
		ID:          "WASC-34",
		Name:        "Predictable Resource Location",
		Description: "Predictable Resource Location is an attack technique used to uncover hidden web site content and functionality.",
		URL:         "http://projects.webappsec.org/w/page/13246953/Predictable%20Resource%20Location",
	},
	"WASC-35": {
		ID:          "WASC-35",
		Name:        "SOAP Array Abuse",
		Description: "SOAP Array Abuse is an attack that causes denial of service via massive array size declarations.",
		URL:         "http://projects.webappsec.org/w/page/13246962/SOAP%20Array%20Abuse",
	},
	"WASC-36": {
		ID:          "WASC-36",
		Name:        "SSI Injection",
		Description: "SSI Injection is a server-side exploit technique that allows an attacker to inject code into HTML pages.",
		URL:         "http://projects.webappsec.org/w/page/13246964/SSI%20Injection",
	},
	"WASC-37": {
		ID:          "WASC-37",
		Name:        "Session Fixation",
		Description: "Session Fixation is an attack technique that forces a user's session ID to an explicit value.",
		URL:         "http://projects.webappsec.org/w/page/13246960/Session%20Fixation",
	},
	"WASC-38": {
		ID:          "WASC-38",
		Name:        "URL Redirector Abuse",
		Description: "URL Redirector Abuse is a vulnerability used to send users to malicious sites without their knowledge.",
		URL:         "http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse",
	},
	"WASC-39": {
		ID:          "WASC-39",
		Name:        "XPath Injection",
		Description: "XPath Injection is an attack technique used to exploit applications that construct XPath queries from user-supplied input.",
		URL:         "http://projects.webappsec.org/w/page/13247005/XPath%20Injection",
	},
	"WASC-40": {
		ID:          "WASC-40",
		Name:        "Insufficient Process Validation",
		Description: "Insufficient Process Validation occurs when a web site permits an attacker to bypass the intended flow of an application.",
		URL:         "http://projects.webappsec.org/w/page/13246943/Insufficient%20Process%20Validation",
	},
	"WASC-41": {
		ID:          "WASC-41",
		Name:        "XML Attribute Blowup",
		Description: "XML Attribute Blowup is a denial of service attack that abuses XML attribute processing.",
		URL:         "http://projects.webappsec.org/w/page/13247002/XML%20Attribute%20Blowup",
	},
	"WASC-42": {
		ID:          "WASC-42",
		Name:        "Abuse of Functionality",
		Description: "Abuse of Functionality is an attack technique that uses a web site's own features and functionality to consume, defraud, or circumvent access control mechanisms.",
		URL:         "http://projects.webappsec.org/w/page/13246913/Abuse%20of%20Functionality",
	},
	"WASC-43": {
		ID:          "WASC-43",
		Name:        "XML External Entities",
		Description: "XML External Entities (XXE) is a vulnerability that allows an attacker to interfere with an application's processing of XML data.",
		URL:         "http://projects.webappsec.org/w/page/13247003/XML%20External%20Entities",
	},
	"WASC-44": {
		ID:          "WASC-44",
		Name:        "XML Entity Expansion",
		Description: "XML Entity Expansion is a denial of service attack targeting XML parsers via recursive entity definitions.",
		URL:         "http://projects.webappsec.org/w/page/13247001/XML%20Entity%20Expansion",
	},
	"WASC-45": {
		ID:          "WASC-45",
		Name:        "Fingerprinting",
		Description: "Fingerprinting is a technique used to determine the software version and type of a running web server or application.",
		URL:         "http://projects.webappsec.org/w/page/13246925/Fingerprinting",
	},
	"WASC-46": {
		ID:          "WASC-46",
		Name:        "XQuery Injection",
		Description: "XQuery Injection is an attack technique used to exploit applications that construct XQuery expressions from user-supplied input.",
		URL:         "http://projects.webappsec.org/w/page/13247006/XQuery%20Injection",
	},
	"WASC-47": {
		ID:          "WASC-47",
		Name:        "Insufficient Session Expiration",
		Description: "Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs.",
		URL:         "http://projects.webappsec.org/w/page/13246944/Insufficient%20Session%20Expiration",
	},
	"WASC-48": {
		ID:          "WASC-48",
		Name:        "Insecure Indexing",
		Description: "Insecure Indexing is when a web site's search indices contain sensitive information that should not be publicly available.",
		URL:         "http://projects.webappsec.org/w/page/13246937/Insecure%20Indexing",
	},
	"WASC-49": {
		ID:          "WASC-49",
		Name:        "Insufficient Password Recovery",
		Description: "Insufficient Password Recovery is when a web site permits an attacker to illegally obtain, change or recover another user's password.",
		URL:         "http://projects.webappsec.org/w/page/13246942/Insufficient%20Password%20Recovery",
	},
}

// wascOrdered contains WASC IDs in numerical order.
var wascOrdered = []string{
	"WASC-01", "WASC-02", "WASC-03", "WASC-04", "WASC-05",
	"WASC-06", "WASC-07", "WASC-08", "WASC-09", "WASC-10",
	"WASC-11", "WASC-12", "WASC-13", "WASC-14", "WASC-15",
	"WASC-16", "WASC-17", "WASC-18", "WASC-19", "WASC-20",
	"WASC-21", "WASC-22", "WASC-23", "WASC-24", "WASC-25",
	"WASC-26", "WASC-27", "WASC-28", "WASC-29", "WASC-30",
	"WASC-31", "WASC-32", "WASC-33", "WASC-34", "WASC-35",
	"WASC-36", "WASC-37", "WASC-38", "WASC-39", "WASC-40",
	"WASC-41", "WASC-42", "WASC-43", "WASC-44", "WASC-45",
	"WASC-46", "WASC-47", "WASC-48", "WASC-49",
}

// WASCOrdered returns WASC IDs in numerical order.
// Returns a copy to prevent callers from mutating the underlying slice.
func WASCOrdered() []string {
	result := make([]string, len(wascOrdered))
	copy(result, wascOrdered)
	return result
}

// WASCMapping maps attack categories to their WASC Threat Classification IDs.
// Use GetWASCID() for category lookup with proper normalization.
var WASCMapping = map[string]string{
	// Authentication/Authorization
	"auth":             "WASC-01",
	"authentication":   "WASC-01",
	"auth-bypass":      "WASC-01",
	"idor":             "WASC-02",
	"access-control":   "WASC-02",
	"broken-access":    "WASC-02",
	"brute-force":      "WASC-11",
	"brute_force":      "WASC-11",
	"password":         "WASC-11",
	"session":          "WASC-18",
	"session-fixation": "WASC-37",
	"session_fixation": "WASC-37",

	// Injection attacks
	"sqli":            "WASC-19",
	"sql-injection":   "WASC-19",
	"sql_injection":   "WASC-19",
	"xss":             "WASC-08",
	"cross-site":      "WASC-08",
	"cmdi":            "WASC-31",
	"command":         "WASC-31",
	"os-command":      "WASC-31",
	"os_command":      "WASC-31",
	"rce":             "WASC-31",
	"ldap":            "WASC-29",
	"ldap-injection":  "WASC-29",
	"xpath":           "WASC-39",
	"xpath-injection": "WASC-39",
	"xml":             "WASC-23",
	"xml-injection":   "WASC-23",
	"xxe":             "WASC-43",
	"ssi":             "WASC-36",
	"ssi-injection":   "WASC-36",

	// Path/File attacks
	"traversal":      "WASC-33",
	"path-traversal": "WASC-33",
	"lfi":            "WASC-33",
	"rfi":            "WASC-05",
	"upload":         "WASC-17",
	"file-upload":    "WASC-17",

	// CSRF/Clickjacking
	"csrf":         "WASC-09",
	"clickjack":    "WASC-42",
	"clickjacking": "WASC-42",

	// HTTP manipulation
	"smuggling":         "WASC-26",
	"http-smuggling":    "WASC-26",
	"request-smuggling": "WASC-26",
	"crlf":              "WASC-25",
	"header":            "WASC-25",
	"response-split":    "WASC-25",
	"null-byte":         "WASC-28",

	// Redirect/Spoofing
	"redirect":      "WASC-38",
	"open-redirect": "WASC-38",
	"open_redirect": "WASC-38",
	"content-spoof": "WASC-12",

	// Configuration/Info disclosure
	"misconfig":        "WASC-14",
	"misconfiguration": "WASC-14",
	"info-leak":        "WASC-13",
	"fingerprint":      "WASC-45",
	"directory":        "WASC-16",
	"dir-listing":      "WASC-16",

	// Template/Serialization
	"ssti":            "WASC-20",
	"template":        "WASC-20",
	"deserialize":     "WASC-20",
	"deserialization": "WASC-20",
	"prototype":       "WASC-20",

	// Denial of Service
	"dos":        "WASC-10",
	"ddos":       "WASC-10",
	"rate-limit": "WASC-10",

	// SSRF and Forgery
	"ssrf":    "WASC-42",
	"forgery": "WASC-42",

	// Crypto
	"crypto":      "WASC-04",
	"tls":         "WASC-04",
	"ssl":         "WASC-04",
	"weak-crypto": "WASC-04",

	// NoSQL (mapped to general injection)
	"nosqli": "WASC-20",
	"nosql":  "WASC-20",

	// JWT/OAuth
	"jwt":   "WASC-01",
	"oauth": "WASC-01",

	// Race conditions and logic flaws
	"race":           "WASC-40",
	"race-condition": "WASC-40",
	"business-logic": "WASC-40",

	// CORS (abuse of functionality)
	"cors": "WASC-42",
}

// GetWASCID returns the WASC ID for an attack category.
// Returns empty string if category is not mapped.
func GetWASCID(category string) string {
	normalized := normalizeCategory(category)
	if id, ok := WASCMapping[normalized]; ok {
		return id
	}
	return ""
}

// GetWASC returns the full WASC metadata for an attack category.
// Returns nil if category is not mapped.
func GetWASC(category string) *WASCThreat {
	id := GetWASCID(category)
	if id == "" {
		return nil
	}
	if wasc, ok := WASCThreatClass[id]; ok {
		return &wasc
	}
	return nil
}

// GetWASCURL returns the WASC project URL for a WASC ID.
// Returns empty string if ID is not found.
func GetWASCURL(wascID string) string {
	if wasc, ok := WASCThreatClass[wascID]; ok {
		return wasc.URL
	}
	return ""
}

// GetWASCName returns the WASC threat name for a WASC ID.
// Returns the ID itself if not found.
func GetWASCName(wascID string) string {
	if wasc, ok := WASCThreatClass[wascID]; ok {
		return wasc.Name
	}
	return wascID
}
