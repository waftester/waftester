// Tests for all crawler improvements:
// - HTML tokenizer extraction (links, forms, scripts, images, comments, meta)
// - Retry logic with exponential backoff
// - Redirect chain tracking
// - Content-hash dedup and soft-404 detection
// - <base> tag support
// - Queue drop tracking
// - Missing URL sources (data-*, srcset, meta refresh, form actions)
// - Robots.txt enforcement
// - Progress reporting
// - Cookie jar persistence
package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================
// 1. HTML Tokenizer Extraction Tests
// ============================================================

func TestExtractLinksTokenizer_StandardHrefs(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/path/")
	html := `<html><body>
		<a href="/about">About</a>
		<a href="page.html">Page</a>
		<a href="https://other.com/ext">External</a>
		<a href="../up">Up</a>
		<a href="#section">Anchor</a>
		<a href="javascript:void(0)">JS</a>
		<a href="mailto:test@example.com">Email</a>
	</body></html>`

	links := extractLinksTokenizer(html, base)

	expected := map[string]bool{
		"https://example.com/about":          true,
		"https://example.com/path/page.html": true,
		"https://other.com/ext":              true,
		"https://example.com/up":             true,
	}

	if len(links) != len(expected) {
		t.Errorf("expected %d links, got %d: %v", len(expected), len(links), links)
	}

	for _, link := range links {
		if !expected[link] {
			t.Errorf("unexpected link: %s", link)
		}
	}
}

func TestExtractLinksTokenizer_DataAttributes(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html><body>
		<div data-href="/lazy-page">Lazy</div>
		<span data-url="/api/data">API</span>
		<a href="/normal">Normal</a>
	</body></html>`

	links := extractLinksTokenizer(html, base)

	expected := map[string]bool{
		"https://example.com/lazy-page": true,
		"https://example.com/api/data":  true,
		"https://example.com/normal":    true,
	}

	if len(links) != len(expected) {
		t.Errorf("expected %d links, got %d: %v", len(expected), len(links), links)
	}
	for _, link := range links {
		if !expected[link] {
			t.Errorf("unexpected link: %s", link)
		}
	}
}

func TestExtractLinksTokenizer_MetaRefresh(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html><head>
		<meta http-equiv="refresh" content="5;url=https://example.com/new-page">
	</head></html>`

	links := extractLinksTokenizer(html, base)

	found := false
	for _, link := range links {
		if link == "https://example.com/new-page" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected meta refresh URL in links, got: %v", links)
	}
}

func TestExtractLinksTokenizer_MetaRefreshCaseInsensitive(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html><head>
		<meta http-equiv="Refresh" content="0; URL='/redirect-target'">
	</head></html>`

	links := extractLinksTokenizer(html, base)

	found := false
	for _, link := range links {
		if strings.Contains(link, "redirect-target") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected meta refresh URL (case insensitive), got: %v", links)
	}
}

func TestExtractLinksTokenizer_Srcset(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	// srcset URLs are extracted as links; img src is extracted by extractImagesTokenizer
	html := `<html><body>
		<img srcset="/img/small.jpg 480w, /img/large.jpg 800w" src="/img/default.jpg">
		<source srcset="/video/poster.webp 1x, /video/poster-2x.webp 2x">
	</body></html>`

	links := extractLinksTokenizer(html, base)

	// Should find the srcset URLs (not the src — that's for images)
	expectedPaths := []string{"/img/small.jpg", "/img/large.jpg", "/video/poster.webp", "/video/poster-2x.webp"}
	for _, path := range expectedPaths {
		found := false
		for _, link := range links {
			if strings.Contains(link, path) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected srcset URL containing %s in links, got: %v", path, links)
		}
	}
}

func TestExtractLinksTokenizer_DeduplicatesURLs(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html><body>
		<a href="/page">Link 1</a>
		<a href="/page">Link 2</a>
		<a href="/page">Link 3</a>
	</body></html>`

	links := extractLinksTokenizer(html, base)

	if len(links) != 1 {
		t.Errorf("expected 1 deduplicated link, got %d: %v", len(links), links)
	}
}

func TestExtractLinksTokenizer_EmptyHTML(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	links := extractLinksTokenizer("", base)

	if len(links) != 0 {
		t.Errorf("expected 0 links from empty HTML, got %d", len(links))
	}
}

func TestExtractLinksTokenizer_MalformedHTML(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	// Unclosed tags, mismatched quotes — tokenizer should handle gracefully
	html := `<html><body>
		<a href="/valid">Good
		<a href='/also-valid'>Also good
		<a href=unquoted>Unquoted
		<div><a href="/nested"
	</body>`

	links := extractLinksTokenizer(html, base)

	// Should find at least /valid and /also-valid
	foundValid := false
	foundAlsoValid := false
	for _, link := range links {
		if strings.Contains(link, "/valid") {
			foundValid = true
		}
		if strings.Contains(link, "/also-valid") {
			foundAlsoValid = true
		}
	}
	if !foundValid {
		t.Errorf("should extract /valid from malformed HTML, got: %v", links)
	}
	if !foundAlsoValid {
		t.Errorf("should extract /also-valid from malformed HTML, got: %v", links)
	}
}

// ============================================================
// 2. Form Extraction Tests (Tokenizer)
// ============================================================

func TestExtractFormsTokenizer_BasicForms(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html><body>
		<form action="/login" method="POST" id="loginForm" name="login" enctype="multipart/form-data">
			<input type="text" name="username" placeholder="User" required>
			<input type="password" name="password">
			<input type="hidden" name="csrf" value="tok123">
			<textarea name="notes">Default text</textarea>
			<select name="role">
				<option value="admin">Admin</option>
			</select>
			<input type="submit" value="Login">
		</form>
	</body></html>`

	forms := extractFormsTokenizer(html, base)

	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}

	f := forms[0]
	if f.Method != "POST" {
		t.Errorf("expected POST, got %s", f.Method)
	}
	if !strings.Contains(f.Action, "/login") {
		t.Errorf("expected action containing /login, got %s", f.Action)
	}
	if f.ID != "loginForm" {
		t.Errorf("expected id loginForm, got %s", f.ID)
	}
	if f.Name != "login" {
		t.Errorf("expected name login, got %s", f.Name)
	}
	if f.Enctype != "multipart/form-data" {
		t.Errorf("expected enctype multipart/form-data, got %s", f.Enctype)
	}

	// Check inputs (submit has no name so should be skipped)
	namedInputs := 0
	for _, inp := range f.Inputs {
		if inp.Name != "" {
			namedInputs++
		}
	}
	if namedInputs < 5 {
		t.Errorf("expected at least 5 named inputs, got %d: %+v", namedInputs, f.Inputs)
	}

	// Check username input specifically
	var username *InputInfo
	for i := range f.Inputs {
		if f.Inputs[i].Name == "username" {
			username = &f.Inputs[i]
			break
		}
	}
	if username == nil {
		t.Fatal("should find username input")
	}
	if !username.Required {
		t.Error("username should be required")
	}
	if username.Placeholder != "User" {
		t.Errorf("expected placeholder User, got %s", username.Placeholder)
	}
}

func TestExtractFormsTokenizer_DefaultMethod(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<form action="/search"><input name="q" type="text"></form>`

	forms := extractFormsTokenizer(html, base)

	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if forms[0].Method != "GET" {
		t.Errorf("default method should be GET, got %s", forms[0].Method)
	}
}

func TestExtractFormsTokenizer_MultipleForms(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `
		<form action="/a" method="POST"><input name="x"></form>
		<form action="/b" method="GET"><input name="y"></form>
		<form action="/c"><input name="z"></form>
	`

	forms := extractFormsTokenizer(html, base)

	if len(forms) != 3 {
		t.Errorf("expected 3 forms, got %d", len(forms))
	}
}

func TestExtractFormsTokenizer_UnclosedForm(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	// Unclosed form — tokenizer should still capture it
	html := `<form action="/unclosed" method="POST"><input name="field">`

	forms := extractFormsTokenizer(html, base)

	if len(forms) != 1 {
		t.Fatalf("expected 1 form from unclosed HTML, got %d", len(forms))
	}
	if forms[0].Method != "POST" {
		t.Errorf("expected POST, got %s", forms[0].Method)
	}
}

func TestExtractFormsTokenizer_NoForms(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html><body><p>No forms here</p></body></html>`

	forms := extractFormsTokenizer(html, base)

	if len(forms) != 0 {
		t.Errorf("expected 0 forms, got %d", len(forms))
	}
}

// ============================================================
// 3. Comments Extraction (Tokenizer)
// ============================================================

func TestExtractCommentsTokenizer_VariousComments(t *testing.T) {
	t.Parallel()

	html := `<html>
		<!-- Important comment about authentication -->
		<body>
			<!-- TODO: Fix this vulnerability -->
			<!-- AB -->
			<!-- Short -->
			<p>Content</p>
		</body>
		<!-- End of page, version 2.0 -->
	</html>`

	comments := extractCommentsTokenizer(html)

	// "AB" is 2 chars, below threshold. "Short" is 5 chars, above threshold.
	if len(comments) != 4 {
		t.Errorf("expected 4 comments (skipping 'AB'), got %d: %v", len(comments), comments)
	}
}

func TestExtractCommentsTokenizer_NoComments(t *testing.T) {
	t.Parallel()

	html := `<html><body><p>No comments</p></body></html>`

	comments := extractCommentsTokenizer(html)

	if len(comments) != 0 {
		t.Errorf("expected 0 comments, got %d", len(comments))
	}
}

// ============================================================
// 4. Meta Extraction (Tokenizer)
// ============================================================

func TestExtractMetaTokenizer_AllTypes(t *testing.T) {
	t.Parallel()

	html := `<html><head>
		<meta name="description" content="Test description">
		<meta name="keywords" content="test, keywords">
		<meta property="og:title" content="OG Title">
		<meta content="reversed value" name="author">
		<meta charset="utf-8">
	</head></html>`

	meta := extractMetaTokenizer(html)

	tests := map[string]string{
		"description": "Test description",
		"keywords":    "test, keywords",
		"og:title":    "OG Title",
		"author":      "reversed value",
	}

	for key, expected := range tests {
		if meta[key] != expected {
			t.Errorf("meta[%s] = %q, want %q", key, meta[key], expected)
		}
	}

	// charset meta should not appear (no name or property)
	if _, ok := meta["charset"]; ok {
		t.Error("charset should not be in meta map")
	}
}

func TestExtractMetaTokenizer_Empty(t *testing.T) {
	t.Parallel()

	meta := extractMetaTokenizer("<html><head></head></html>")
	if len(meta) != 0 {
		t.Errorf("expected empty meta, got %d entries", len(meta))
	}
}

// ============================================================
// 5. Stylesheets Extraction (Tokenizer)
// ============================================================

func TestExtractStylesheetsTokenizer(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html><head>
		<link rel="stylesheet" href="/css/style.css">
		<link rel="stylesheet" href="https://cdn.example.com/bootstrap.css">
		<link rel="icon" href="/favicon.ico">
		<link rel="preload" href="/font.woff2" as="font">
	</head></html>`

	stylesheets := extractStylesheetsTokenizer(html, base)

	if len(stylesheets) != 2 {
		t.Errorf("expected 2 stylesheets, got %d: %v", len(stylesheets), stylesheets)
	}

	for _, s := range stylesheets {
		if strings.Contains(s, "favicon") || strings.Contains(s, "font") {
			t.Errorf("should not include non-stylesheet link: %s", s)
		}
	}
}

// ============================================================
// 6. Images Extraction (Tokenizer)
// ============================================================

func TestExtractImagesTokenizer_SrcAndDataSrc(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html><body>
		<img src="/img/logo.png">
		<img data-src="/img/lazy.jpg">
		<img src="data:image/png;base64,abc">
	</body></html>`

	images := extractImagesTokenizer(html, base)

	// data: URLs should be filtered out by resolveURL
	if len(images) != 2 {
		t.Errorf("expected 2 images, got %d: %v", len(images), images)
	}

	foundLazy := false
	for _, img := range images {
		if strings.Contains(img, "lazy.jpg") {
			foundLazy = true
		}
	}
	if !foundLazy {
		t.Error("should extract data-src for lazy-loaded images")
	}
}

// ============================================================
// 7. <base> Tag Detection
// ============================================================

func TestDetectBaseTag_Present(t *testing.T) {
	t.Parallel()

	pageURL, _ := url.Parse("https://example.com/deep/path/page.html")

	html := `<html><head><base href="https://cdn.example.com/assets/"></head></html>`
	base := detectBaseTag(html, pageURL)

	if base.String() != "https://cdn.example.com/assets/" {
		t.Errorf("expected base from <base> tag, got %s", base.String())
	}
}

func TestDetectBaseTag_RelativeBase(t *testing.T) {
	t.Parallel()

	pageURL, _ := url.Parse("https://example.com/app/page.html")

	html := `<html><head><base href="/static/"></head></html>`
	base := detectBaseTag(html, pageURL)

	if base.String() != "https://example.com/static/" {
		t.Errorf("expected resolved relative base, got %s", base.String())
	}
}

func TestDetectBaseTag_Missing(t *testing.T) {
	t.Parallel()

	pageURL, _ := url.Parse("https://example.com/page.html")

	html := `<html><head><title>No base</title></head></html>`
	base := detectBaseTag(html, pageURL)

	if base.String() != pageURL.String() {
		t.Errorf("expected page URL as fallback, got %s", base.String())
	}
}

func TestDetectBaseTag_CaseInsensitive(t *testing.T) {
	t.Parallel()

	pageURL, _ := url.Parse("https://example.com/")

	html := `<html><head><BASE HREF="https://cdn.example.com/"></head></html>`
	base := detectBaseTag(html, pageURL)

	if base.String() != "https://cdn.example.com/" {
		t.Errorf("expected case-insensitive base detection, got %s", base.String())
	}
}

// ============================================================
// 8. Meta Refresh URL Parsing
// ============================================================

func TestParseMetaRefreshURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		content  string
		expected string
	}{
		{"5;url=https://example.com/new", "https://example.com/new"},
		{"0; URL=https://example.com/redirect", "https://example.com/redirect"},
		{"0;url='/quoted'", "/quoted"},
		{"10", ""},             // No URL
		{"", ""},               // Empty
		{"url=/path", "/path"}, // No delay
	}

	for _, tt := range tests {
		result := parseMetaRefreshURL(tt.content)
		if result != tt.expected {
			t.Errorf("parseMetaRefreshURL(%q) = %q, want %q", tt.content, result, tt.expected)
		}
	}
}

// ============================================================
// 9. Robots.txt Parsing and Enforcement
// ============================================================

func TestParseRobotsDisallowed(t *testing.T) {
	t.Parallel()

	body := `
User-agent: *
Disallow: /admin
Disallow: /private/
Disallow: /api/internal

User-agent: Googlebot
Disallow: /google-only

# Comment line
Allow: /public
Sitemap: https://example.com/sitemap.xml
`

	disallowed := parseRobotsDisallowed(body)

	expected := []string{"/admin", "/private/", "/api/internal"}
	if len(disallowed) != len(expected) {
		t.Fatalf("expected %d disallowed, got %d: %v", len(expected), len(disallowed), disallowed)
	}

	for i, path := range expected {
		if disallowed[i] != path {
			t.Errorf("disallowed[%d] = %q, want %q", i, disallowed[i], path)
		}
	}
}

func TestParseRobotsDisallowed_EmptyBody(t *testing.T) {
	t.Parallel()

	disallowed := parseRobotsDisallowed("")
	if len(disallowed) != 0 {
		t.Errorf("expected 0 disallowed from empty body, got %d", len(disallowed))
	}
}

func TestParseRobotsDisallowed_NoWildcard(t *testing.T) {
	t.Parallel()

	body := `
User-agent: Googlebot
Disallow: /google
`

	disallowed := parseRobotsDisallowed(body)
	if len(disallowed) != 0 {
		t.Errorf("expected 0 disallowed (no * agent), got %d", len(disallowed))
	}
}

func TestIsRobotsDisallowed(t *testing.T) {
	t.Parallel()

	c := NewCrawler(&Config{
		FollowRobots:     true,
		RobotsDisallowed: []string{"/admin", "/private/", "/api/internal"},
	})

	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/admin", true},
		{"https://example.com/admin/users", true},
		{"https://example.com/private/data", true},
		{"https://example.com/api/internal/secret", true},
		{"https://example.com/public", false},
		{"https://example.com/api/v1", false},
	}

	for _, tt := range tests {
		result := c.isRobotsDisallowed(tt.url)
		if result != tt.expected {
			t.Errorf("isRobotsDisallowed(%s) = %v, want %v", tt.url, result, tt.expected)
		}
	}
}

func TestRobotsTxtEnforcementDuringCrawl(t *testing.T) {
	t.Parallel()

	requestedPaths := make(map[string]bool)
	mux := http.NewServeMux()

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("User-agent: *\nDisallow: /secret\n"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestedPaths[r.URL.Path] = true
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<a href="/public">Public</a>
			<a href="/secret/data">Secret</a>
		</body></html>`))
	})

	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		requestedPaths[r.URL.Path] = true
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Public page</body></html>`))
	})

	mux.HandleFunc("/secret/data", func(w http.ResponseWriter, r *http.Request) {
		requestedPaths[r.URL.Path] = true
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Secret page</body></html>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	config := &Config{
		MaxDepth:       2,
		MaxPages:       10,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		FollowRobots:   true,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	for range results {
		// Drain
	}

	if requestedPaths["/secret/data"] {
		t.Error("crawler should NOT have requested /secret/data (robots.txt disallowed)")
	}
	if !requestedPaths["/public"] {
		t.Error("crawler should have requested /public")
	}
}

// ============================================================
// 10. Retry Logic
// ============================================================

func TestRetryOnTransientErrors(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Service Unavailable"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Success</title></head><body>OK</body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       1,
		MaxPages:       5,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		MaxRetries:     2,
		RetryDelay:     10 * time.Millisecond,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var found *CrawlResult
	for result := range results {
		if result.URL == server.URL+"/" {
			found = result
		}
	}

	if found == nil {
		t.Fatal("expected at least one result")
	}

	if found.Title != "Success" {
		t.Errorf("expected title 'Success' after retry, got %q", found.Title)
	}

	// Should have made 3 attempts total (2 retries + 1 success)
	totalAttempts := attempts.Load()
	if totalAttempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", totalAttempts)
	}
}

func TestRetryExhausted_ReturnsLastStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("Rate limited"))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       1,
		MaxPages:       5,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		MaxRetries:     1,
		RetryDelay:     10 * time.Millisecond,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var found *CrawlResult
	for result := range results {
		found = result
	}

	if found == nil {
		t.Fatal("expected a result even when retries exhausted")
	}
	if found.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", found.StatusCode)
	}
}

func TestIsRetryableStatus(t *testing.T) {
	t.Parallel()

	retryable := []int{429, 502, 503, 504}
	for _, code := range retryable {
		if !isRetryableStatus(code) {
			t.Errorf("expected %d to be retryable", code)
		}
	}

	nonRetryable := []int{200, 301, 400, 401, 403, 404, 500}
	for _, code := range nonRetryable {
		if isRetryableStatus(code) {
			t.Errorf("expected %d to NOT be retryable", code)
		}
	}
}

// ============================================================
// 11. Redirect Chain Tracking
// ============================================================

func TestRedirectChainTracking(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})

	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/middle", http.StatusFound)
	})

	mux.HandleFunc("/middle", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusMovedPermanently)
	})

	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Final</title></head><body>Done</body></html>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	config := &Config{
		MaxDepth:       1,
		MaxPages:       5,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/start")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var found *CrawlResult
	for result := range results {
		found = result
	}

	if found == nil {
		t.Fatal("expected a result")
	}

	if found.FinalURL == "" {
		t.Error("expected FinalURL to be set after redirect")
	}
	if !strings.HasSuffix(found.FinalURL, "/final") {
		t.Errorf("expected FinalURL to end with /final, got %s", found.FinalURL)
	}

	if found.Title != "Final" {
		t.Errorf("expected title 'Final', got %q", found.Title)
	}

	if len(found.RedirectChain) < 2 {
		t.Errorf("expected redirect chain with at least 2 entries, got %d: %v", len(found.RedirectChain), found.RedirectChain)
	}
}

func TestNoRedirect_NoChain(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Direct</body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       1,
		MaxPages:       5,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var found *CrawlResult
	for result := range results {
		found = result
	}

	if found == nil {
		t.Fatal("expected a result")
	}

	if found.FinalURL != "" {
		t.Errorf("expected empty FinalURL for direct response, got %s", found.FinalURL)
	}
	if len(found.RedirectChain) != 0 {
		t.Errorf("expected no redirect chain, got %v", found.RedirectChain)
	}
}

// ============================================================
// 12. Content-Hash Dedup and Soft-404 Detection
// ============================================================

func TestContentHashDedup(t *testing.T) {
	t.Parallel()

	c := NewCrawler(nil)

	// First hash should not be duplicate
	if c.isContentDuplicate("abc123") {
		t.Error("first occurrence should not be duplicate")
	}

	// Second same hash should be duplicate
	if !c.isContentDuplicate("abc123") {
		t.Error("second occurrence should be duplicate")
	}

	// Different hash should not be duplicate
	if c.isContentDuplicate("def456") {
		t.Error("different hash should not be duplicate")
	}
}

func TestHashBody(t *testing.T) {
	t.Parallel()

	h1 := hashBody([]byte("hello world"))
	h2 := hashBody([]byte("hello world"))
	h3 := hashBody([]byte("different content"))

	if h1 != h2 {
		t.Error("same content should produce same hash")
	}
	if h1 == h3 {
		t.Error("different content should produce different hash")
	}
	if len(h1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("expected 16 char hash, got %d: %s", len(h1), h1)
	}
}

func TestSoft404Detection(t *testing.T) {
	t.Parallel()

	soft404Body := `<html><body><h1>Page Not Found</h1><p>Sorry, this page does not exist.</p></body></html>`

	mux := http.NewServeMux()

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>Home</title></head><body>
				<a href="/real-page">Real</a>
				<a href="/fake-page">Fake</a>
			</body></html>`))
			return
		}
		if r.URL.Path == "/real-page" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>Real Page</title></head><body>Real content</body></html>`))
			return
		}
		// All other paths return the same soft-404 page
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(soft404Body))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	config := &Config{
		MaxDepth:       2,
		MaxPages:       10,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var allResults []*CrawlResult
	for result := range results {
		allResults = append(allResults, result)
	}

	// Should have home and real-page with extracted content
	var homeResult, realResult *CrawlResult
	for _, r := range allResults {
		if strings.HasSuffix(r.URL, "/") {
			homeResult = r
		}
		if strings.Contains(r.URL, "/real-page") {
			realResult = r
		}
	}

	if homeResult == nil {
		t.Fatal("should have crawled home page")
	}
	if homeResult.Title != "Home" {
		t.Errorf("expected home title 'Home', got %q", homeResult.Title)
	}

	if realResult == nil {
		t.Fatal("should have crawled real-page")
	}
	if realResult.Title != "Real Page" {
		t.Errorf("expected real page title, got %q", realResult.Title)
	}
}

func TestSoft404CatchAll_DoesNotBlock(t *testing.T) {
	t.Parallel()

	// Server that serves the same content for ALL paths (catch-all like Go ServeMux)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Catch All</title></head><body>
			<a href="/page1">Page 1</a>
		</body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       2,
		MaxPages:       10,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var homeResult *CrawlResult
	for result := range results {
		if strings.HasSuffix(result.URL, "/") {
			homeResult = result
		}
	}

	if homeResult == nil {
		t.Fatal("should have crawled home page")
	}

	// The catch-all check should prevent soft-404 from blocking the real root page
	if homeResult.Title != "Catch All" {
		t.Errorf("catch-all server root should still have title extracted, got %q", homeResult.Title)
	}
}

// ============================================================
// 13. Cookie Jar Persistence
// ============================================================

func TestCookieJarPersistence(t *testing.T) {
	t.Parallel()

	var secondRequestHadCookie atomic.Bool

	mux := http.NewServeMux()

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Set a session cookie on the first request
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
			Path:  "/",
		})
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/page2">Page 2</a></body></html>`))
	})

	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		// Check if the cookie was sent
		cookie, err := r.Cookie("session")
		if err == nil && cookie.Value == "abc123" {
			secondRequestHadCookie.Store(true)
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Page 2</body></html>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	config := &Config{
		MaxDepth:       2,
		MaxPages:       10,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	for range results {
		// Drain
	}

	if !secondRequestHadCookie.Load() {
		t.Error("cookie jar should persist cookies: second request should have session cookie")
	}
}

// ============================================================
// 14. Queue Drop Tracking
// ============================================================

func TestQueueDropTracking(t *testing.T) {
	t.Parallel()

	c := NewCrawler(&Config{
		MaxDepth:       1,
		MaxPages:       100,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		UserAgent:      "test-crawler",
	})
	c.baseDomain = "example.com"

	// Fill the queue
	for i := 0; i < 10001; i++ {
		c.visited[fmt.Sprintf("https://example.com/page%d", i)] = true
	}

	// Queue a bunch of unique URLs — queue capacity is ChannelLarge (10000)
	// Start ctx so queue operations work
	c.ctx, c.cancel = context.WithCancel(context.Background())
	defer c.cancel()

	for i := 10001; i < 20100; i++ {
		c.queueURL(fmt.Sprintf("https://example.com/new%d", i), 1)
	}

	dropped := c.GetDroppedCount()
	if dropped == 0 {
		t.Error("expected some dropped URLs when queue is full")
	}
}

// ============================================================
// 15. Progress Reporting
// ============================================================

func TestProgressReporting(t *testing.T) {
	t.Parallel()

	var progressCalled atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		// Slow response to ensure progress ticker fires
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>
		</body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       2,
		MaxPages:       10,
		MaxConcurrency: 2,
		Timeout:        5 * time.Second,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
		OnProgress: func(stats CrawlStats) {
			progressCalled.Add(1)
		},
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	for range results {
		// Drain
	}

	// Progress should have been called at least once (ticker fires every 2s + final)
	if progressCalled.Load() < 1 {
		t.Error("expected progress callback to be called at least once")
	}
}

func TestStats(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Page</body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       1,
		MaxPages:       5,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	for range results {
		// Drain
	}

	stats := crawler.Stats()
	if stats.PagesCrawled < 1 {
		t.Errorf("expected at least 1 page crawled, got %d", stats.PagesCrawled)
	}
}

// ============================================================
// 16. Form Actions Queued for Crawling
// ============================================================

func TestFormActionsQueuedForCrawling(t *testing.T) {
	t.Parallel()

	var submitRequested atomic.Bool

	mux := http.NewServeMux()

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<form action="/submit-form" method="POST">
				<input name="data" type="text">
			</form>
		</body></html>`))
	})

	mux.HandleFunc("/submit-form", func(w http.ResponseWriter, r *http.Request) {
		submitRequested.Store(true)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Form target</body></html>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	config := &Config{
		MaxDepth:       2,
		MaxPages:       10,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		ExtractForms:   true,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	for range results {
		// Drain
	}

	if !submitRequested.Load() {
		t.Error("form action URL /submit-form should have been queued and crawled")
	}
}

// ============================================================
// 17. Scripts Extraction (Tokenizer)
// ============================================================

func TestExtractScriptsTokenizer_ExternalAndInline(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `<html>
		<head>
			<script src="/js/jquery.js"></script>
			<script src="https://cdn.example.com/lib.js"></script>
		</head>
		<body>
			<script>console.log("inline, no src")</script>
			<script src="/js/app.js"></script>
		</body>
	</html>`

	scripts := extractScriptsTokenizer(html, base)

	if len(scripts) != 3 {
		t.Errorf("expected 3 external scripts, got %d: %v", len(scripts), scripts)
	}
}

func TestExtractScriptsTokenizer_Dedup(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.com/")
	html := `
		<script src="/js/app.js"></script>
		<script src="/js/app.js"></script>
		<script src="/js/app.js"></script>
	`

	scripts := extractScriptsTokenizer(html, base)

	if len(scripts) != 1 {
		t.Errorf("expected 1 deduplicated script, got %d", len(scripts))
	}
}

// ============================================================
// 18. JS Rendering Warning
// ============================================================

func TestJSRenderingWarning(t *testing.T) {
	t.Parallel()

	// Should not panic when JSRendering is enabled — just logs warning
	c := NewCrawler(&Config{
		JSRendering:    true,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		UserAgent:      "test",
	})

	if c == nil {
		t.Fatal("crawler should be created even with JSRendering enabled")
	}
}

// ============================================================
// 19. DefaultConfig Validation
// ============================================================

func TestDefaultConfigRetrySettings(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	if config.MaxRetries != 2 {
		t.Errorf("expected MaxRetries=2, got %d", config.MaxRetries)
	}
	if config.RetryDelay != 500*time.Millisecond {
		t.Errorf("expected RetryDelay=500ms, got %v", config.RetryDelay)
	}
}

// ============================================================
// 20. Edge Cases
// ============================================================

func TestCrawlEmptyHTML(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(""))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:        1,
		MaxPages:        5,
		MaxConcurrency:  1,
		Timeout:         5 * time.Second,
		ExtractLinks:    true,
		ExtractForms:    true,
		ExtractScripts:  true,
		ExtractComments: true,
		ExtractMeta:     true,
		UserAgent:       "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var found *CrawlResult
	for result := range results {
		found = result
	}

	if found == nil {
		t.Fatal("expected a result from empty HTML")
	}
	if len(found.Links) != 0 {
		t.Errorf("expected 0 links from empty HTML, got %d", len(found.Links))
	}
	if len(found.Forms) != 0 {
		t.Errorf("expected 0 forms from empty HTML, got %d", len(found.Forms))
	}
}

func TestCrawlNonHTMLContent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"key": "value"}`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       1,
		MaxPages:       5,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		ExtractLinks:   true,
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var found *CrawlResult
	for result := range results {
		found = result
	}

	if found == nil {
		t.Fatal("expected a result for non-HTML content")
	}
	if found.ContentType != "application/json" {
		t.Errorf("expected application/json, got %s", found.ContentType)
	}
	// No extraction should happen
	if len(found.Links) != 0 {
		t.Errorf("should not extract links from JSON, got %d", len(found.Links))
	}
	if found.Title != "" {
		t.Errorf("should not extract title from JSON, got %q", found.Title)
	}
}

func TestCrawlServerError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       1,
		MaxPages:       5,
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		MaxRetries:     0, // No retries
		UserAgent:      "test-crawler",
	}
	crawler := NewCrawler(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	var found *CrawlResult
	for result := range results {
		found = result
	}

	if found == nil {
		t.Fatal("expected a result even for server errors")
	}
	if found.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", found.StatusCode)
	}
}
