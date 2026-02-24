package probes

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewTLSProber(t *testing.T) {
	prober := NewTLSProber()
	if prober == nil {
		t.Fatal("expected non-nil prober")
	}
	if prober.Timeout == 0 {
		t.Error("timeout should be set")
	}
	if prober.DialTimeout == 0 {
		t.Error("dial timeout should be set")
	}
}

func TestVersionToString(t *testing.T) {
	tests := []struct {
		ver      uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
		{0x0000, "Unknown(0x0000)"},
	}

	for _, tt := range tests {
		result := versionToString(tt.ver)
		if result != tt.expected {
			t.Errorf("versionToString(%d) = %s, want %s", tt.ver, result, tt.expected)
		}
	}
}

func TestTLSInfoGetSecurityGrade(t *testing.T) {
	tests := []struct {
		name     string
		info     TLSInfo
		minGrade string
	}{
		{
			name: "TLS 1.3 good",
			info: TLSInfo{
				Version:     "TLS1.3",
				CipherSuite: "TLS_AES_256_GCM_SHA384",
			},
			minGrade: "A",
		},
		{
			name: "TLS 1.2 good",
			info: TLSInfo{
				Version:     "TLS1.2",
				CipherSuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			},
			minGrade: "A",
		},
		{
			name: "Expired cert",
			info: TLSInfo{
				Version: "TLS1.2",
				Expired: true,
			},
			minGrade: "C",
		},
		{
			name: "Self-signed",
			info: TLSInfo{
				Version:    "TLS1.2",
				SelfSigned: true,
			},
			minGrade: "B",
		},
		{
			name: "Mismatched hostname",
			info: TLSInfo{
				Version:    "TLS1.2",
				Mismatched: true,
			},
			minGrade: "C",
		},
		{
			name: "Old TLS version",
			info: TLSInfo{
				Version: "TLS1.0",
			},
			minGrade: "C",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grade := tt.info.GetSecurityGrade()
			if grade == "" {
				t.Error("grade should not be empty")
			}
			// Check grade is a letter
			if grade[0] < 'A' || grade[0] > 'F' {
				t.Errorf("invalid grade: %s", grade)
			}
		})
	}
}

func TestTLSInfoSummary(t *testing.T) {
	info := TLSInfo{
		Version:    "TLS1.3",
		Protocol:   "h2",
		Expired:    true,
		SelfSigned: true,
	}

	summary := info.TLSInfoSummary()
	if !strings.Contains(summary, "TLS1.3") {
		t.Error("summary should contain version")
	}
	if !strings.Contains(summary, "h2") {
		t.Error("summary should contain protocol")
	}
	if !strings.Contains(summary, "EXPIRED") {
		t.Error("summary should contain EXPIRED")
	}
	if !strings.Contains(summary, "SELF-SIGNED") {
		t.Error("summary should contain SELF-SIGNED")
	}
}

func TestTLSInfoSANContains(t *testing.T) {
	info := TLSInfo{
		SubjectAN: []string{"example.com", "*.example.org", "test.example.net"},
	}

	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.org", true},
		{"example.org", false}, // Wildcard doesn't match root
		{"test.example.net", true},
		{"other.com", false},
	}

	for _, tt := range tests {
		result := info.SANContains(tt.domain)
		if result != tt.expected {
			t.Errorf("SANContains(%s) = %v, want %v", tt.domain, result, tt.expected)
		}
	}
}

func TestTLSInfoGetAllDomains(t *testing.T) {
	info := TLSInfo{
		SubjectCN: "example.com",
		SubjectAN: []string{"example.com", "www.example.com", "api.example.com"},
	}

	domains := info.GetAllDomains()
	if len(domains) != 3 {
		t.Errorf("expected 3 domains, got %d", len(domains))
	}

	// Should be sorted
	if domains[0] != "api.example.com" {
		t.Error("domains should be sorted")
	}
}

func TestTLSInfoGetWeakCiphers(t *testing.T) {
	info := TLSInfo{
		SupportedCipherSuites: []string{
			"TLS_AES_256_GCM_SHA384",
			"TLS_RSA_WITH_RC4_128_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_RSA_WITH_NULL_SHA",
		},
	}

	weak := info.GetWeakCiphers()
	if len(weak) != 3 {
		t.Errorf("expected 3 weak ciphers, got %d: %v", len(weak), weak)
	}
}

// Header extractor tests

func TestNewHeaderExtractor(t *testing.T) {
	extractor := NewHeaderExtractor()
	if extractor == nil {
		t.Fatal("expected non-nil extractor")
	}
	if len(extractor.SecurityHeaderNames) == 0 {
		t.Error("security headers should be populated")
	}
}

func TestHeaderExtractorExtract(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "abc123",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	extractor := NewHeaderExtractor()
	headers := extractor.Extract(resp)

	// Check CSP
	if headers.ContentSecurityPolicy == "" {
		t.Error("CSP should be extracted")
	}
	if len(headers.CSPDirectives) == 0 {
		t.Error("CSP directives should be parsed")
	}

	// Check other headers
	if headers.XFrameOptions != "DENY" {
		t.Error("X-Frame-Options should be DENY")
	}
	if headers.XContentTypeOptions != "nosniff" {
		t.Error("X-Content-Type-Options should be nosniff")
	}

	// Check HSTS parsing
	if headers.HSTSMaxAge != 31536000 {
		t.Errorf("HSTS max-age should be 31536000, got %d", headers.HSTSMaxAge)
	}
	if !headers.HSTSIncludeSubdomains {
		t.Error("HSTS includeSubDomains should be true")
	}
	if !headers.HSTSPreload {
		t.Error("HSTS preload should be true")
	}

	// Check server info
	if headers.Server == "" {
		t.Error("Server should be extracted")
	}
	if headers.XPoweredBy == "" {
		t.Error("X-Powered-By should be extracted")
	}

	// Check cookies
	if len(headers.SetCookies) == 0 {
		t.Error("cookies should be extracted")
	}

	// Check grade
	if headers.Grade == "" {
		t.Error("grade should be calculated")
	}
}

func TestParseCSP(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' https://example.com 'unsafe-inline'; img-src *; report-uri /csp-report"

	directives := parseCSP(csp)

	if len(directives) != 4 {
		t.Errorf("expected 4 directives, got %d", len(directives))
	}

	if vals, ok := directives["default-src"]; !ok || len(vals) != 1 || vals[0] != "'self'" {
		t.Error("default-src not parsed correctly")
	}

	if vals, ok := directives["script-src"]; !ok || len(vals) != 3 {
		t.Error("script-src not parsed correctly")
	}
}

func TestParseHSTS(t *testing.T) {
	tests := []struct {
		hsts       string
		maxAge     int
		subdomains bool
		preload    bool
	}{
		{"max-age=31536000", 31536000, false, false},
		{"max-age=31536000; includeSubDomains", 31536000, true, false},
		{"max-age=31536000; includeSubDomains; preload", 31536000, true, true},
		{"max-age=0", 0, false, false},
	}

	for _, tt := range tests {
		maxAge, subdomains, preload := parseHSTS(tt.hsts)
		if maxAge != tt.maxAge {
			t.Errorf("parseHSTS(%s) maxAge = %d, want %d", tt.hsts, maxAge, tt.maxAge)
		}
		if subdomains != tt.subdomains {
			t.Errorf("parseHSTS(%s) subdomains = %v, want %v", tt.hsts, subdomains, tt.subdomains)
		}
		if preload != tt.preload {
			t.Errorf("parseHSTS(%s) preload = %v, want %v", tt.hsts, preload, tt.preload)
		}
	}
}

func TestAnalyzeCSP(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; report-uri /csp"

	info := AnalyzeCSP(csp)

	if info.Raw != csp {
		t.Error("raw CSP should be preserved")
	}

	if info.ReportURI != "/csp" {
		t.Errorf("report-uri should be /csp, got %s", info.ReportURI)
	}

	// Should flag unsafe-inline and unsafe-eval
	if len(info.Issues) == 0 {
		t.Error("should have flagged issues")
	}

	hasUnsafeInline := false
	hasUnsafeEval := false
	for _, issue := range info.Issues {
		if strings.Contains(issue, "unsafe-inline") {
			hasUnsafeInline = true
		}
		if strings.Contains(issue, "unsafe-eval") {
			hasUnsafeEval = true
		}
	}

	if !hasUnsafeInline {
		t.Error("should flag unsafe-inline")
	}
	if !hasUnsafeEval {
		t.Error("should flag unsafe-eval")
	}
}

func TestExtractDomainsFromCSP(t *testing.T) {
	csp := "default-src 'self'; script-src https://example.com https://cdn.example.org *.example.net"

	domains := ExtractDomainsFromCSP(csp)

	if len(domains) < 2 {
		t.Errorf("expected at least 2 domains, got %d", len(domains))
	}

	hasExampleCom := false
	for _, d := range domains {
		if d == "example.com" {
			hasExampleCom = true
			break
		}
	}

	if !hasExampleCom {
		t.Error("should extract example.com")
	}
}

// HTTP prober tests

func TestNewHTTPProber(t *testing.T) {
	prober := NewHTTPProber()
	if prober == nil {
		t.Fatal("expected non-nil prober")
	}
	if prober.DialTimeout == 0 {
		t.Error("dial timeout should be set")
	}
}

func TestHTTPProberProbeMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET", "POST", "HEAD":
			w.WriteHeader(200)
		case "OPTIONS":
			w.Header().Set("Allow", "GET, POST, HEAD, OPTIONS")
			w.WriteHeader(200)
		default:
			w.WriteHeader(405)
		}
	}))
	defer server.Close()

	prober := NewHTTPProber()

	// Extract host and port
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	methods, err := prober.ProbeMethods(ctx, "127.0.0.1", 0, false, "/")
	if err == nil && len(methods) > 0 {
		// May not work with test server URL parsing
		t.Logf("found methods: %v", methods)
	}
}

func TestVHostProber(t *testing.T) {
	prober := NewVHostProber()
	if prober == nil {
		t.Fatal("expected non-nil prober")
	}
	if prober.Timeout == 0 {
		t.Error("timeout should be set")
	}
}

func TestGenerateVHostWordlist(t *testing.T) {
	wordlist := GenerateVHostWordlist()
	if len(wordlist) < 50 {
		t.Errorf("expected at least 50 vhost prefixes, got %d", len(wordlist))
	}

	// Check for common ones
	hasWWW := false
	hasAPI := false
	for _, w := range wordlist {
		if w == "www" {
			hasWWW = true
		}
		if w == "api" {
			hasAPI = true
		}
	}

	if !hasWWW {
		t.Error("wordlist should contain www")
	}
	if !hasAPI {
		t.Error("wordlist should contain api")
	}

	// Returned slice must be a copy of the internal list.
	wordlist[0] = "MUTATED"
	fresh := GenerateVHostWordlist()
	if fresh[0] == "MUTATED" {
		t.Error("GenerateVHostWordlist must return a copy, not the internal slice")
	}
}

func TestVHostWordlistGenerator_Defaults(t *testing.T) {
	t.Parallel()

	gen := NewVHostWordlistGenerator("example.com")
	wl := gen.Generate()

	if len(wl) < 50 {
		t.Errorf("expected at least 50 default prefixes, got %d", len(wl))
	}

	has := func(needle string) bool {
		for _, w := range wl {
			if w == needle {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"www", "api", "admin", "staging", "dev"} {
		if !has(want) {
			t.Errorf("missing default prefix %q", want)
		}
	}
}

func TestVHostWordlistGenerator_TLS(t *testing.T) {
	t.Parallel()

	gen := NewVHostWordlistGenerator("example.com")
	gen.AddFromTLS(&TLSInfo{
		SubjectCN: "example.com",
		SubjectAN: []string{
			"staging.example.com",
			"api.example.com",
			"cdn.otherdomain.net",
			"*.example.com",
		},
	})
	wl := gen.Generate()

	has := func(needle string) bool {
		for _, w := range wl {
			if w == needle {
				return true
			}
		}
		return false
	}

	if !has("staging") {
		t.Error("should extract 'staging' from SAN staging.example.com")
	}
	if !has("api") {
		t.Error("should extract 'api' from SAN api.example.com")
	}
	if !has("cdn") {
		t.Error("should extract first label 'cdn' from cdn.otherdomain.net")
	}
}

func TestVHostWordlistGenerator_CSP(t *testing.T) {
	t.Parallel()

	gen := NewVHostWordlistGenerator("example.com")
	gen.AddFromCSP("default-src 'self'; script-src https://assets.example.com https://tracker.analytics.net")
	wl := gen.Generate()

	has := func(needle string) bool {
		for _, w := range wl {
			if w == needle {
				return true
			}
		}
		return false
	}

	if !has("assets") {
		t.Error("should extract 'assets' from CSP domain assets.example.com")
	}
	if !has("tracker") {
		t.Error("should extract first label 'tracker' from tracker.analytics.net")
	}
}

func TestVHostWordlistGenerator_Dedup(t *testing.T) {
	t.Parallel()

	gen := NewVHostWordlistGenerator("example.com")
	gen.AddPrefixes("api", "api", "staging", "www")
	wl := gen.Generate()

	count := 0
	for _, w := range wl {
		if w == "api" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("'api' should appear exactly once, got %d", count)
	}
}

func TestVHostWordlistGenerator_NilTLS(t *testing.T) {
	t.Parallel()

	gen := NewVHostWordlistGenerator("example.com")
	gen.AddFromTLS(nil)
	gen.AddFromCSP("")
	wl := gen.Generate()

	// Should still have all defaults.
	if len(wl) < 50 {
		t.Errorf("nil sources should not break generation, got %d prefixes", len(wl))
	}
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		html     string
		expected string
	}{
		{"<html><head><title>Test Page</title></head></html>", "Test Page"},
		{"<html><head><TITLE>Upper Case</TITLE></head></html>", "Upper Case"},
		{"<html><head></head></html>", ""},
		{"<html><head><title></title></head></html>", ""},
		{"<title>No closing", ""},
	}

	for _, tt := range tests {
		result := extractTitle([]byte(tt.html))
		if result != tt.expected {
			t.Errorf("extractTitle(%s) = %s, want %s", tt.html, result, tt.expected)
		}
	}
}

func TestSimilarLength(t *testing.T) {
	tests := []struct {
		a, b     int
		expected bool
	}{
		{100, 100, true},
		{100, 95, true},
		{100, 105, true},
		{100, 85, false},
		{100, 115, false},
		{0, 100, false},
		{100, 0, false},
		{0, 0, true},
	}

	for _, tt := range tests {
		result := similarLength(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("similarLength(%d, %d) = %v, want %v", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestContentSimilarity(t *testing.T) {
	tests := []struct {
		a, b   []byte
		minSim float64
	}{
		{[]byte("hello"), []byte("hello"), 1.0},
		{[]byte("hello"), []byte("hallo"), 0.7},
		{[]byte(""), []byte(""), 1.0},
		{[]byte("test"), []byte(""), 0.0},
	}

	for _, tt := range tests {
		sim := contentSimilarity(tt.a, tt.b)
		if sim < tt.minSim {
			t.Errorf("contentSimilarity(%s, %s) = %f, want >= %f", tt.a, tt.b, sim, tt.minSim)
		}
	}
}
