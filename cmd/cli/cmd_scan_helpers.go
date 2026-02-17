package main

import (
	"net"
	"net/http"
	"strings"
)

// detectTechStack identifies web technologies from HTTP response headers, cookies, and body content.
// Returns a deduplicated slice of technology names.
func detectTechStack(resp *http.Response, body []byte) []string {
	var techStack []string

	// Analyze headers
	server := strings.ToLower(resp.Header.Get("Server"))
	powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
	generator := strings.ToLower(resp.Header.Get("X-Generator"))

	if strings.Contains(server, "nginx") {
		techStack = append(techStack, "nginx")
	}
	if strings.Contains(server, "apache") {
		techStack = append(techStack, "apache")
	}
	if strings.Contains(server, "iis") {
		techStack = append(techStack, "iis")
	}
	if strings.Contains(powered, "php") {
		techStack = append(techStack, "php")
	}
	if strings.Contains(powered, "asp") || strings.Contains(powered, ".net") {
		techStack = append(techStack, "asp.net")
	}
	if strings.Contains(powered, "express") {
		techStack = append(techStack, "express")
	}
	if generator != "" {
		techStack = append(techStack, generator)
	}

	// Analyze cookies
	for _, cookie := range resp.Cookies() {
		name := strings.ToLower(cookie.Name)
		if strings.Contains(name, "phpsessid") {
			techStack = append(techStack, "php")
		}
		if strings.Contains(name, "jsessionid") {
			techStack = append(techStack, "java")
		}
		if strings.Contains(name, "asp.net") || strings.Contains(name, "aspxauth") {
			techStack = append(techStack, "asp.net")
		}
		if strings.Contains(name, "csrftoken") {
			techStack = append(techStack, "django")
		}
		if strings.Contains(name, "_rails") {
			techStack = append(techStack, "rails")
		}
	}

	// Analyze body
	bodyStr := strings.ToLower(string(body))
	if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wordpress") {
		techStack = append(techStack, "wordpress")
	}
	if strings.Contains(bodyStr, "__next") || strings.Contains(bodyStr, "next.js") {
		techStack = append(techStack, "next.js")
	}
	if strings.Contains(bodyStr, "react") && strings.Contains(bodyStr, "reactdom") {
		techStack = append(techStack, "react")
	}
	if strings.Contains(bodyStr, "angular") || strings.Contains(bodyStr, "ng-app") {
		techStack = append(techStack, "angular")
	}
	if strings.Contains(bodyStr, "vue.js") || strings.Contains(bodyStr, "v-bind") {
		techStack = append(techStack, "vue.js")
	}
	if strings.Contains(bodyStr, "laravel") {
		techStack = append(techStack, "laravel")
	}
	if strings.Contains(bodyStr, "drupal") {
		techStack = append(techStack, "drupal")
	}
	if strings.Contains(bodyStr, "joomla") {
		techStack = append(techStack, "joomla")
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, t := range techStack {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}

	return unique
}

// performDNSRecon performs DNS reconnaissance on a domain and returns findings.
func performDNSRecon(domain string) *DNSReconResult {
	result := &DNSReconResult{}

	// Resolve CNAME chain
	cnames, err := net.LookupCNAME(domain)
	if err == nil && cnames != "" && cnames != domain+"." {
		result.CNAMEs = []string{strings.TrimSuffix(cnames, ".")}
	}

	// MX Records
	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			result.MXRecords = append(result.MXRecords, mx.Host)
		}
	}

	// TXT Records
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		result.TXTRecords = txtRecords
	}

	// NS Records
	nsRecords, err := net.LookupNS(domain)
	if err == nil {
		for _, ns := range nsRecords {
			result.NSRecords = append(result.NSRecords, ns.Host)
		}
	}

	return result
}

// dnsReconTotalRecords returns the total number of DNS records found.
func dnsReconTotalRecords(r *DNSReconResult) int {
	if r == nil {
		return 0
	}
	return len(r.CNAMEs) + len(r.MXRecords) + len(r.TXTRecords) + len(r.NSRecords)
}

// scanTipsByType maps scan type names to user-facing tips shown
// in the progress display. Only tips for requested scan types are shown.
var scanTipsByType = map[string]string{
	"sqli":      "SQLi uses error-based, time-based, union, and boolean techniques",
	"xss":       "XSS tests reflected, stored, and DOM-based vectors",
	"ssrf":      "SSRF probes for internal network access and cloud metadata",
	"traversal": "Path traversal tests for file system access vulnerabilities",
	"cmdi":      "Command injection tests OS command execution vectors",
	"nosqli":    "NoSQLi tests MongoDB, CouchDB, and other NoSQL backends",
	"ssti":      "SSTI probes template engines for server-side code execution",
	"jwt":       "JWT tests for algorithm confusion, weak secrets, and claim tampering",
	"graphql":   "GraphQL tests introspection, batching, and injection vectors",
	"cors":      "CORS tests for overly permissive cross-origin policies",
	"csrf":      "CSRF tests for missing or weak anti-forgery tokens",
	"lfi":       "LFI tests for local file read via path manipulation",
	"rfi":       "RFI tests for remote file inclusion via URL injection",
	"rce":       "RCE tests for remote code execution via multiple vectors",
	"ldap":      "LDAP injection tests directory service query manipulation",
	"smuggling": "Request smuggling tests CL/TE and TE/CL desync vectors",
}

// buildScanTips returns tips relevant to the scan types being run.
// Falls back to a generic tip when no type-specific tips match.
func buildScanTips(shouldScan func(string) bool) []string {
	var tips []string
	for scanType, tip := range scanTipsByType {
		if shouldScan(scanType) {
			tips = append(tips, tip)
		}
	}
	// Always include a generic tip so the list is never empty
	tips = append(tips, "Each scan type uses context-aware payload selection")
	return tips
}
