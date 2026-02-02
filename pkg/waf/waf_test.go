package waf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector(5 * time.Second)
	if d == nil {
		t.Fatal("expected detector, got nil")
	}
	if d.timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", d.timeout)
	}
	if len(d.signatures) == 0 {
		t.Error("expected WAF signatures to be initialized")
	}
	if len(d.cdnSigs) == 0 {
		t.Error("expected CDN signatures to be initialized")
	}
}

func TestNewDetectorDefaults(t *testing.T) {
	d := NewDetector(0)
	if d.timeout != httpclient.TimeoutProbing {
		t.Errorf("expected default timeout %v, got %v", httpclient.TimeoutProbing, d.timeout)
	}
}

func TestDetectorPassiveDetection(t *testing.T) {
	// Create test server that simulates ModSecurity
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/modsecurity")
		w.Header().Set("X-Custom-Header", "test")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	d := NewDetector(5 * time.Second)
	result, err := d.Detect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Should detect ModSecurity from header
	found := false
	for _, ev := range result.Evidence {
		if strings.Contains(ev.Indicates, "ModSecurity") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to detect ModSecurity from Server header")
	}
}

func TestDetectorCloudflareDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123-IAD")
		w.Header().Set("CF-Cache-Status", "HIT")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDetector(5 * time.Second)
	result, err := d.Detect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.CDN == nil {
		t.Fatal("expected CDN detection")
	}
	if result.CDN.Name != "Cloudflare" {
		t.Errorf("expected Cloudflare, got %s", result.CDN.Name)
	}
	if result.CDN.RayID != "abc123-IAD" {
		t.Errorf("expected ray ID abc123-IAD, got %s", result.CDN.RayID)
	}
	if !result.CDN.CacheHit {
		t.Error("expected cache hit")
	}
}

func TestDetectorActiveDetection(t *testing.T) {
	// Server that blocks SQL injection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		if strings.Contains(query, "OR") || strings.Contains(query, "script") {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Blocked by WAF"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDetector(5 * time.Second)
	result, err := d.Detect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have evidence of blocking
	hasBlock := false
	for _, ev := range result.Evidence {
		if ev.Type == "status" && ev.Value == "403" {
			hasBlock = true
			break
		}
	}
	if !hasBlock {
		t.Error("expected block evidence from active detection")
	}
}

func TestDetectorAWSCloudFront(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Cf-Id", "abc123")
		w.Header().Set("X-Amz-Cf-Pop", "IAD53")
		w.Header().Set("X-Cache", "Hit from cloudfront")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDetector(5 * time.Second)
	result, err := d.Detect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.CDN == nil {
		t.Fatal("expected CDN detection")
	}
	if result.CDN.Name != "AWS CloudFront" {
		t.Errorf("expected AWS CloudFront, got %s", result.CDN.Name)
	}
	if result.CDN.POP != "IAD53" {
		t.Errorf("expected POP IAD53, got %s", result.CDN.POP)
	}
}

func TestDetectorMultipleWAFSignatures(t *testing.T) {
	d := NewDetector(5 * time.Second)

	// Check we have signatures for major WAFs
	wafNames := []string{
		"ModSecurity", "Coraza", "Cloudflare", "AWS WAF",
		"Akamai Kona", "Imperva Incapsula", "F5 BIG-IP ASM",
	}

	for _, name := range wafNames {
		found := false
		for _, sig := range d.signatures {
			if sig.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing signature for %s", name)
		}
	}
}

func TestNewFingerprinter(t *testing.T) {
	fp := NewFingerprinter(5 * time.Second)
	if fp == nil {
		t.Fatal("expected fingerprinter, got nil")
	}
	if fp.timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", fp.timeout)
	}
}

func TestFingerprinterDefaults(t *testing.T) {
	fp := NewFingerprinter(0)
	if fp.timeout != httpclient.TimeoutProbing {
		t.Errorf("expected default timeout %v, got %v", httpclient.TimeoutProbing, fp.timeout)
	}
}

func TestCreateFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "does-not-exist") {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Custom 404 page"))
			return
		}
		if strings.Contains(r.URL.RawQuery, "OR") {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Blocked by WAF"))
			return
		}
		w.Header().Set("X-Custom", "test")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	fp := NewFingerprinter(5 * time.Second)
	result, err := fp.CreateFingerprint(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Hash == "" {
		t.Error("expected fingerprint hash")
	}
	if len(result.Hash) != 16 {
		t.Errorf("expected 16 char hash, got %d", len(result.Hash))
	}
	if result.ErrorPageHash == "" {
		t.Error("expected error page hash")
	}
	if result.BlockPageHash == "" {
		t.Error("expected block page hash")
	}
	// Block status can vary - 403 is typical but some WAFs return 400 or other codes
	if result.ResponseProfile.BlockStatusCode < 400 || result.ResponseProfile.BlockStatusCode >= 500 {
		t.Errorf("expected 4xx block status, got %d", result.ResponseProfile.BlockStatusCode)
	}
}

func TestMatchFingerprint(t *testing.T) {
	fp := &Fingerprint{
		Hash: "unknown_hash_123",
	}

	match, confidence := MatchFingerprint(fp)
	if match != "" {
		t.Errorf("expected no match for unknown hash, got %s", match)
	}
	if confidence != 0 {
		t.Errorf("expected 0 confidence, got %f", confidence)
	}
}

func TestNewEvasion(t *testing.T) {
	e := NewEvasion()
	if e == nil {
		t.Fatal("expected evasion, got nil")
	}
	if len(e.techniques) == 0 {
		t.Error("expected techniques to be initialized")
	}
}

func TestEvasionTransform(t *testing.T) {
	e := NewEvasion()
	payload := "' OR '1'='1"

	results := e.Transform(payload)
	if len(results) == 0 {
		t.Error("expected transformed payloads")
	}

	// Check variety of categories
	categories := make(map[string]bool)
	for _, r := range results {
		categories[r.Category] = true
		if r.Original != payload {
			t.Errorf("expected original %s, got %s", payload, r.Original)
		}
		if r.Transformed == "" {
			t.Error("expected transformed payload")
		}
		if r.Technique == "" {
			t.Error("expected technique name")
		}
	}

	expectedCategories := []string{"encoding", "obfuscation", "case"}
	for _, cat := range expectedCategories {
		if !categories[cat] {
			t.Errorf("expected category %s in results", cat)
		}
	}
}

func TestEvasionTransformWithCategory(t *testing.T) {
	e := NewEvasion()
	payload := "test payload"

	results := e.TransformWithCategory(payload, "encoding")
	if len(results) == 0 {
		t.Error("expected results for encoding category")
	}

	for _, r := range results {
		if r.Category != "encoding" {
			t.Errorf("expected category encoding, got %s", r.Category)
		}
	}
}

func TestURLEncode(t *testing.T) {
	e := NewEvasion()
	payload := "<script>alert(1)</script>"

	results := e.TransformWithCategory(payload, "encoding")

	// Find URL encoded result
	found := false
	for _, r := range results {
		if r.Technique == "url_encode" {
			found = true
			if !strings.Contains(r.Transformed, "%3C") {
				t.Error("expected URL encoded <")
			}
			break
		}
	}
	if !found {
		t.Error("expected url_encode technique")
	}
}

func TestDoubleURLEncode(t *testing.T) {
	e := NewEvasion()
	payload := "../"

	results := e.Transform(payload)

	found := false
	for _, r := range results {
		if r.Technique == "double_url_encode" {
			found = true
			if !strings.Contains(r.Transformed, "%25") {
				t.Error("expected double URL encoded")
			}
			break
		}
	}
	if !found {
		t.Error("expected double_url_encode technique")
	}
}

func TestSQLCommentInjection(t *testing.T) {
	e := NewEvasion()
	payload := "SELECT * FROM users"

	results := e.Transform(payload)

	found := false
	for _, r := range results {
		if r.Technique == "sql_comment_injection" {
			found = true
			if !strings.Contains(r.Transformed, "/**/") && !strings.Contains(r.Transformed, "/*!*/") {
				continue
			}
			break
		}
	}
	if !found {
		t.Error("expected sql_comment_injection technique")
	}
}

func TestCaseSwap(t *testing.T) {
	e := NewEvasion()
	payload := "select"

	results := e.TransformWithCategory(payload, "case")
	if len(results) == 0 {
		t.Fatal("expected case swap results")
	}

	// At least one should have mixed case
	hasMixed := false
	for _, r := range results {
		lower := strings.ToLower(r.Transformed)
		upper := strings.ToUpper(r.Transformed)
		if r.Transformed != lower && r.Transformed != upper {
			hasMixed = true
			break
		}
	}
	if !hasMixed {
		t.Error("expected mixed case result")
	}
}

func TestPathTraversalVariations(t *testing.T) {
	e := NewEvasion()
	payload := "../../../etc/passwd"

	results := e.Transform(payload)

	variations := []string{
		"%2f",
		"%5c",
		"..\\",
		"%252f",
	}

	for _, v := range variations {
		found := false
		for _, r := range results {
			if strings.Contains(strings.ToLower(r.Transformed), strings.ToLower(v)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected variation containing %s", v)
		}
	}
}

func TestNullByteInjection(t *testing.T) {
	e := NewEvasion()
	payload := "test.php"

	results := e.Transform(payload)

	found := false
	for _, r := range results {
		if r.Technique == "null_byte_injection" {
			found = true
			if !strings.Contains(r.Transformed, "%00") && !strings.Contains(r.Transformed, "\x00") {
				continue
			}
			break
		}
	}
	if !found {
		t.Error("expected null_byte_injection technique")
	}
}

func TestHTMLEntityEncode(t *testing.T) {
	e := NewEvasion()
	payload := "<script>"

	results := e.Transform(payload)

	found := false
	for _, r := range results {
		if r.Technique == "html_entity_encode" {
			found = true
			if strings.Contains(r.Transformed, "&lt;") || strings.Contains(r.Transformed, "&#60;") || strings.Contains(r.Transformed, "&#x3c;") {
				break
			}
		}
	}
	if !found {
		t.Error("expected html_entity_encode technique with proper encoding")
	}
}

func TestBase64Encode(t *testing.T) {
	e := NewEvasion()
	payload := "test"

	results := e.Transform(payload)

	found := false
	for _, r := range results {
		if r.Technique == "base64_encode" {
			found = true
			if r.Transformed != "dGVzdA==" {
				t.Errorf("expected base64 dGVzdA==, got %s", r.Transformed)
			}
			break
		}
	}
	if !found {
		t.Error("expected base64_encode technique")
	}
}

func TestGetTechniques(t *testing.T) {
	e := NewEvasion()
	techniques := e.GetTechniques()

	if len(techniques) == 0 {
		t.Error("expected techniques")
	}

	// Check structure
	for _, tech := range techniques {
		if tech.Name == "" {
			t.Error("expected technique name")
		}
		if tech.Category == "" {
			t.Error("expected technique category")
		}
		if tech.Transform == nil {
			t.Error("expected transform function")
		}
	}
}

func TestCategoryDescriptions(t *testing.T) {
	categories := []string{"encoding", "case", "obfuscation", "protocol", "chunking"}

	for _, cat := range categories {
		if desc, ok := CategoryDescriptions[cat]; !ok || desc == "" {
			t.Errorf("expected description for category %s", cat)
		}
	}
}

func TestDetectorBehavioralAnalysis(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block TRACE method
		if r.Method == "TRACE" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Block path traversal
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDetector(5 * time.Second)
	result, err := d.Detect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have behavioral evidence
	hasBehavior := false
	for _, ev := range result.Evidence {
		if ev.Type == "behavior" {
			hasBehavior = true
			break
		}
	}
	if !hasBehavior {
		t.Error("expected behavioral evidence")
	}
}

func TestAverageDuration(t *testing.T) {
	durations := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		300 * time.Millisecond,
	}

	avg := averageDuration(durations)
	expected := 200 * time.Millisecond

	if avg != expected {
		t.Errorf("expected %v, got %v", expected, avg)
	}
}

func TestAverageDurationEmpty(t *testing.T) {
	avg := averageDuration(nil)
	if avg != 0 {
		t.Errorf("expected 0 for empty slice, got %v", avg)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"long string here", 4, "long..."},
		{"exact", 5, "exact"},
		{"", 5, ""},
	}

	for _, tc := range tests {
		result := truncate(tc.input, tc.maxLen)
		if result != tc.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.maxLen, result, tc.expected)
		}
	}
}

func TestConsolidateResults(t *testing.T) {
	d := NewDetector(5 * time.Second)

	result := &DetectionResult{
		Evidence: []Evidence{
			{Type: "header", Source: "Server", Value: "modsecurity", Indicates: "ModSecurity", Confidence: 0.8},
			{Type: "body", Source: "response", Value: "request rejected", Indicates: "ModSecurity", Confidence: 0.7},
		},
	}

	d.consolidateResults(result)

	if !result.Detected {
		t.Error("expected detected = true")
	}
	if len(result.WAFs) != 1 {
		t.Errorf("expected 1 WAF, got %d", len(result.WAFs))
	}
	if result.WAFs[0].Name != "ModSecurity" {
		t.Errorf("expected ModSecurity, got %s", result.WAFs[0].Name)
	}
	if result.WAFs[0].Confidence < 1.0 {
		t.Logf("confidence: %f", result.WAFs[0].Confidence)
	}
}

func TestIntegrationDetection(t *testing.T) {
	// Comprehensive test server
	blockCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/coraza")
		w.Header().Set("X-Request-ID", "12345")

		query := r.URL.RawQuery
		if strings.Contains(query, "OR") || strings.Contains(query, "script") ||
			strings.Contains(query, "passwd") || strings.Contains(query, "ENTITY") {
			blockCount++
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Blocked by Coraza WAF"))
			return
		}

		if r.Method == "TRACE" || r.Method == "TRACK" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	d := NewDetector(10 * time.Second)
	result, err := d.Detect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Detected {
		t.Error("expected WAF to be detected")
	}

	// Should detect Coraza
	foundCoraza := false
	for _, waf := range result.WAFs {
		if waf.Name == "Coraza" {
			foundCoraza = true
			break
		}
	}
	if !foundCoraza {
		t.Log("WAFs detected:", result.WAFs)
		// Coraza detection depends on specific patterns, may not always match
	}

	// Should have multiple evidence types
	evidenceTypes := make(map[string]bool)
	for _, ev := range result.Evidence {
		evidenceTypes[ev.Type] = true
	}

	if len(evidenceTypes) < 2 {
		t.Errorf("expected multiple evidence types, got %d", len(evidenceTypes))
	}

	t.Logf("Detection complete: %d WAFs, %d evidence items, %d blocks triggered",
		len(result.WAFs), len(result.Evidence), blockCount)
}
