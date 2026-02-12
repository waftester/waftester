package waf

import (
	"net/http"
	"regexp"
	"testing"
	"time"
)

// --- Sample data for WAF benchmarks ---

// sampleWAFHeaders returns realistic response headers from a Cloudflare-protected site.
func sampleWAFHeaders() http.Header {
	return http.Header{
		"Server":                    {"cloudflare"},
		"Cf-Ray":                    {"7f1234abcdef-IAD"},
		"Cf-Cache-Status":           {"DYNAMIC"},
		"Content-Type":              {"text/html; charset=utf-8"},
		"X-Content-Type-Options":    {"nosniff"},
		"X-Frame-Options":           {"DENY"},
		"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
		"Cache-Control":             {"no-cache, no-store, must-revalidate"},
		"X-Request-Id":              {"req-abcdef-123456"},
	}
}

// sampleModSecHeaders returns headers from a ModSecurity-protected site.
func sampleModSecHeaders() http.Header {
	return http.Header{
		"Server":       {"nginx/modsecurity"},
		"Content-Type": {"text/html"},
		"X-Powered-By": {"Express"},
	}
}

// sampleCleanHeaders returns headers with no WAF signatures at all.
func sampleCleanHeaders() http.Header {
	return http.Header{
		"Content-Type": {"text/html; charset=utf-8"},
		"Date":         {"Mon, 10 Feb 2026 12:00:00 GMT"},
		"Connection":   {"keep-alive"},
	}
}

// BenchmarkDetector_DetectHeaders benchmarks WAF detection from response headers.
// This is the hot path of signature matching against a set of headers.
func BenchmarkDetector_DetectHeaders(b *testing.B) {
	d := NewDetector(5 * time.Second)

	resp := &http.Response{
		StatusCode: 403,
		Header:     sampleWAFHeaders(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sig := range d.signatures {
			_ = d.checkWAFSignature(sig, resp, "")
		}
	}
}

// BenchmarkDetector_DetectHeaders_WithBody benchmarks WAF detection with both headers and body.
func BenchmarkDetector_DetectHeaders_WithBody(b *testing.B) {
	d := NewDetector(5 * time.Second)

	resp := &http.Response{
		StatusCode: 403,
		Header:     sampleWAFHeaders(),
	}
	body := "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head>" +
		"<body><div>Sorry, you have been blocked. Ray ID: 7f1234abcdef</div>" +
		"<p>This website is using a security service to protect itself.</p></body></html>"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sig := range d.signatures {
			_ = d.checkWAFSignature(sig, resp, body)
		}
	}
}

// BenchmarkWAFSignatureMatch benchmarks individual WAF signature matching against HTTP headers.
func BenchmarkWAFSignatureMatch(b *testing.B) {
	d := NewDetector(5 * time.Second)

	benchCases := []struct {
		name    string
		headers http.Header
		body    string
	}{
		{"cloudflare", sampleWAFHeaders(), ""},
		{"modsecurity", sampleModSecHeaders(), ""},
		{"clean_no_match", sampleCleanHeaders(), ""},
		{"cloudflare_with_body", sampleWAFHeaders(), "Attention Required! | Cloudflare. Ray ID: abc123."},
		{"modsec_with_body", sampleModSecHeaders(), "ModSecurity - Access Denied. Request rejected."},
	}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			resp := &http.Response{
				StatusCode: 403,
				Header:     bc.headers,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, sig := range d.signatures {
					_ = d.checkWAFSignature(sig, resp, bc.body)
				}
			}
		})
	}
}

// BenchmarkEvasionTechniques benchmarks evasion technique generation.
func BenchmarkEvasionTechniques(b *testing.B) {
	evasion := NewEvasion()

	payloads := []string{
		"' OR '1'='1'--",
		"<script>alert(1)</script>",
		"{{7*7}}",
		"../../../etc/passwd",
		"; cat /etc/passwd",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := payloads[i%len(payloads)]
		_ = evasion.Transform(p)
	}
}

// BenchmarkEvasionTransformByCategory benchmarks evasion with a specific category.
func BenchmarkEvasionTransformByCategory(b *testing.B) {
	evasion := NewEvasion()

	categories := []string{"encoding", "obfuscation", "case"}
	payload := "' OR '1'='1'--"

	for _, cat := range categories {
		b.Run(cat, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = evasion.TransformWithCategory(payload, cat)
			}
		})
	}
}

// BenchmarkFingerprint benchmarks the fingerprint matching logic.
func BenchmarkFingerprint(b *testing.B) {
	fp := &Fingerprint{
		Hash:          "abcdef1234567890",
		Components:    []string{"Content-Type,Date,Server,X-Powered-By", "a1b2c3d4", "e5f6a7b8", "403"},
		HeaderOrder:   "Content-Type,Date,Server,X-Powered-By",
		ErrorPageHash: "1234abcd5678efgh",
		BlockPageHash: "abcd1234efgh5678",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = MatchFingerprint(fp)
	}
}

// BenchmarkCalculateSimilarity benchmarks the hash similarity calculation.
func BenchmarkCalculateSimilarity(b *testing.B) {
	hash1 := "abcdef1234567890"
	hash2 := "abcdef1234567891"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculateSimilarity(hash1, hash2)
	}
}

// BenchmarkDetectorNew benchmarks creating a new Detector with all signatures initialized.
func BenchmarkDetectorNew(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewDetector(5 * time.Second)
	}
}

// BenchmarkCDNSignatureMatch benchmarks CDN signature matching.
func BenchmarkCDNSignatureMatch(b *testing.B) {
	d := NewDetector(5 * time.Second)

	resp := &http.Response{
		StatusCode: 200,
		Header:     sampleWAFHeaders(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sig := range d.cdnSigs {
			_ = d.checkCDNSignature(sig, resp)
		}
	}
}

// BenchmarkHeaderPatternRegex benchmarks the regex patterns used in WAF header matching.
func BenchmarkHeaderPatternRegex(b *testing.B) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile("(?i)mod_security|modsecurity|NYOB"),
		regexp.MustCompile("(?i)cloudflare"),
		regexp.MustCompile(".+"),
		regexp.MustCompile("(?i)imperva|incapsula"),
		regexp.MustCompile("(?i)akamai|ghost"),
	}

	headerValues := []string{
		"nginx/modsecurity",
		"cloudflare",
		"abc123def456-IAD",
		"Apache/2.4.51",
		"",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pat := patterns[i%len(patterns)]
		val := headerValues[i%len(headerValues)]
		if val != "" {
			_ = pat.MatchString(val)
		}
	}
}

// BenchmarkEvasionInit benchmarks the initialization of evasion techniques.
func BenchmarkEvasionInit(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewEvasion()
	}
}
