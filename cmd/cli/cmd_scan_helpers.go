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
