package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.MaxDepth == 0 {
		t.Error("MaxDepth should be set")
	}
	if config.MaxPages == 0 {
		t.Error("MaxPages should be set")
	}
	if config.MaxConcurrency == 0 {
		t.Error("MaxConcurrency should be set")
	}
	if config.UserAgent == "" {
		t.Error("UserAgent should be set")
	}
	if len(config.DisallowedExtensions) == 0 {
		t.Error("DisallowedExtensions should be set")
	}
}

func TestNewCrawler(t *testing.T) {
	// With nil config
	c := NewCrawler(nil)
	if c == nil {
		t.Fatal("expected non-nil crawler")
	}
	if c.config == nil {
		t.Error("config should be set to default")
	}

	// With custom config
	config := &Config{
		MaxDepth:     5,
		MaxPages:     50,
		IncludeScope: []string{`https?://example\.com`},
		ExcludeScope: []string{`/admin`},
	}
	c2 := NewCrawler(config)
	if c2.config.MaxDepth != 5 {
		t.Error("custom config should be used")
	}
	if len(c2.includeRE) != 1 {
		t.Error("include patterns should be compiled")
	}
	if len(c2.excludeRE) != 1 {
		t.Error("exclude patterns should be compiled")
	}
}

func TestCrawlerNormalizeURL(t *testing.T) {
	c := NewCrawler(nil)

	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"#", ""},
		{"javascript:void(0)", ""},
		{"mailto:test@example.com", ""},
		{"tel:+1234567890", ""},
		{"https://example.com/page", "https://example.com/page"},
		{"https://example.com/page#section", "https://example.com/page"},
		{"https://example.com", "https://example.com/"},
	}

	for _, tt := range tests {
		result := c.normalizeURL(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeURL(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestCrawlerInScope(t *testing.T) {
	config := &Config{
		IncludeSubdomains: true,
		ExcludeScope:      []string{`/admin`, `/private`},
	}
	c := NewCrawler(config)
	c.baseDomain = "example.com"

	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/page", true},
		{"https://api.example.com/v1", true},
		{"https://other.com/page", false},
		{"https://example.com/admin", false},
		{"https://example.com/private/data", false},
	}

	for _, tt := range tests {
		result := c.inScope(tt.url)
		if result != tt.expected {
			t.Errorf("inScope(%s) = %v, want %v", tt.url, result, tt.expected)
		}
	}
}

func TestCrawlerAllowedExtension(t *testing.T) {
	config := DefaultConfig()
	c := NewCrawler(config)

	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/page.html", true},
		{"https://example.com/api/users", true},
		{"https://example.com/image.jpg", false},
		{"https://example.com/document.pdf", false},
		{"https://example.com/font.woff2", false},
		{"https://example.com/page", true}, // No extension
	}

	for _, tt := range tests {
		result := c.allowedExtension(tt.url)
		if result != tt.expected {
			t.Errorf("allowedExtension(%s) = %v, want %v", tt.url, result, tt.expected)
		}
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
		{"<title>  Whitespace  </title>", "Whitespace"},
	}

	for _, tt := range tests {
		result := extractTitle(tt.html)
		if result != tt.expected {
			t.Errorf("extractTitle() = %s, want %s", result, tt.expected)
		}
	}
}

func TestExtractMeta(t *testing.T) {
	html := `
		<html>
		<head>
			<meta name="description" content="Test description">
			<meta name="keywords" content="test, keywords">
			<meta property="og:title" content="OG Title">
			<meta content="reversed" name="author">
		</head>
		</html>
	`

	meta := extractMeta(html)

	if meta["description"] != "Test description" {
		t.Error("should extract description")
	}
	if meta["keywords"] != "test, keywords" {
		t.Error("should extract keywords")
	}
	if meta["og:title"] != "OG Title" {
		t.Error("should extract og:title")
	}
	if meta["author"] != "reversed" {
		t.Error("should extract reversed order meta")
	}
}

func TestExtractComments(t *testing.T) {
	html := `
		<html>
		<!-- This is a comment -->
		<body>
			<!-- TODO: Fix this -->
			<!-- AB -->
			<div>Content</div>
		</body>
		</html>
	`

	comments := extractComments(html)

	if len(comments) != 2 {
		t.Errorf("expected 2 comments (skipping short ones), got %d", len(comments))
	}

	hasComment := false
	for _, c := range comments {
		if strings.Contains(c, "This is a comment") {
			hasComment = true
			break
		}
	}
	if !hasComment {
		t.Error("should extract full comment")
	}
}

func TestExtractInputs(t *testing.T) {
	formBody := `
		<input type="text" name="username" id="user" placeholder="Enter username" required>
		<input type="password" name="password">
		<input type="hidden" name="csrf" value="token123">
		<textarea name="message">Default text</textarea>
		<select name="country">
			<option value="us">USA</option>
		</select>
	`

	inputs := extractInputs(formBody)

	if len(inputs) != 5 {
		t.Errorf("expected 5 inputs, got %d", len(inputs))
	}

	// Check username input
	var usernameInput *InputInfo
	for i := range inputs {
		if inputs[i].Name == "username" {
			usernameInput = &inputs[i]
			break
		}
	}

	if usernameInput == nil {
		t.Fatal("should find username input")
	}
	if usernameInput.Type != "text" {
		t.Error("username type should be text")
	}
	if usernameInput.ID != "user" {
		t.Error("username ID should be 'user'")
	}
	if !usernameInput.Required {
		t.Error("username should be required")
	}
}

func TestCrawlerWithTestServer(t *testing.T) {
	// Create test server
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Home Page</title></head>
			<body>
				<a href="/page1">Page 1</a>
				<a href="/page2">Page 2</a>
			</body>
			</html>
		`))
	})

	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Page 1</title></head>
			<body>
				<a href="/">Home</a>
				<form action="/submit" method="POST">
					<input type="text" name="data">
					<input type="submit">
				</form>
			</body>
			</html>
		`))
	})

	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Page 2</title></head>
			<body>
				<script src="/js/app.js"></script>
				<img src="/images/logo.png">
			</body>
			</html>
		`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Create crawler
	config := &Config{
		MaxDepth:       2,
		MaxPages:       10,
		MaxConcurrency: 2,
		Timeout:        5 * time.Second,
		Delay:          0,
		ExtractForms:   true,
		ExtractScripts: true,
		ExtractLinks:   true,
	}
	crawler := NewCrawler(config)

	// Start crawl
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := crawler.Crawl(ctx, server.URL+"/")
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	// Collect results
	var crawlResults []*CrawlResult
	for result := range results {
		crawlResults = append(crawlResults, result)
	}

	// Check we got some results
	if len(crawlResults) < 2 {
		t.Errorf("expected at least 2 results, got %d", len(crawlResults))
	}

	// Check for home page
	var homePage *CrawlResult
	for _, r := range crawlResults {
		if strings.HasSuffix(r.URL, "/") {
			homePage = r
			break
		}
	}

	if homePage == nil {
		t.Fatal("should have crawled home page")
	}

	if homePage.Title != "Home Page" {
		t.Errorf("home page title = %s, want 'Home Page'", homePage.Title)
	}

	if len(homePage.Links) < 2 {
		t.Error("home page should have links")
	}

	// Check for page with form
	var page1 *CrawlResult
	for _, r := range crawlResults {
		if strings.Contains(r.URL, "page1") {
			page1 = r
			break
		}
	}

	if page1 != nil && len(page1.Forms) == 0 {
		t.Error("page1 should have a form")
	}
}

func TestResolveURL(t *testing.T) {
	base, _ := parseURL("https://example.com/path/page.html")

	tests := []struct {
		href     string
		expected string
	}{
		{"/absolute", "https://example.com/absolute"},
		{"relative.html", "https://example.com/path/relative.html"},
		{"../up.html", "https://example.com/up.html"},
		{"https://other.com/page", "https://other.com/page"},
		{"//cdn.example.com/lib.js", "https://cdn.example.com/lib.js"},
		{"javascript:void(0)", ""},
		{"mailto:test@example.com", ""},
		{"#section", ""},
	}

	for _, tt := range tests {
		result := resolveURL(tt.href, base)
		if result != tt.expected {
			t.Errorf("resolveURL(%s) = %s, want %s", tt.href, result, tt.expected)
		}
	}
}

func parseURL(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}

func TestExtractForms(t *testing.T) {
	html := `
		<html>
		<body>
			<form action="/login" method="POST" id="loginForm" name="login">
				<input type="text" name="username">
				<input type="password" name="password">
				<input type="submit" value="Login">
			</form>
			<form action="/search" method="GET">
				<input type="text" name="q">
			</form>
		</body>
		</html>
	`

	base, _ := parseURL("https://example.com/")
	forms := extractForms(html, base)

	if len(forms) != 2 {
		t.Errorf("expected 2 forms, got %d", len(forms))
	}

	// Check login form
	var loginForm *FormInfo
	for i := range forms {
		if forms[i].ID == "loginForm" {
			loginForm = &forms[i]
			break
		}
	}

	if loginForm == nil {
		t.Fatal("should find login form")
	}

	if loginForm.Method != "POST" {
		t.Error("login form method should be POST")
	}

	if !strings.Contains(loginForm.Action, "/login") {
		t.Error("login form action should contain /login")
	}

	if len(loginForm.Inputs) < 2 {
		t.Error("login form should have at least 2 inputs")
	}
}

func TestExtractScripts(t *testing.T) {
	html := `
		<html>
		<head>
			<script src="/js/jquery.js"></script>
			<script src="https://cdn.example.com/lib.js"></script>
		</head>
		<body>
			<script>
				// Inline script - should not be extracted
				console.log("hello");
			</script>
			<script src="/js/app.js"></script>
		</body>
		</html>
	`

	base, _ := parseURL("https://example.com/")
	scripts := extractScripts(html, base)

	if len(scripts) != 3 {
		t.Errorf("expected 3 scripts, got %d: %v", len(scripts), scripts)
	}
}

func TestExtractStylesheets(t *testing.T) {
	html := `
		<html>
		<head>
			<link rel="stylesheet" href="/css/style.css">
			<link rel="stylesheet" href="https://cdn.example.com/bootstrap.css">
			<link rel="icon" href="/favicon.ico">
		</head>
		</html>
	`

	base, _ := parseURL("https://example.com/")
	stylesheets := extractStylesheets(html, base)

	if len(stylesheets) != 2 {
		t.Errorf("expected 2 stylesheets, got %d: %v", len(stylesheets), stylesheets)
	}

	// Should not include favicon
	for _, s := range stylesheets {
		if strings.Contains(s, "favicon") {
			t.Error("should not include favicon as stylesheet")
		}
	}
}

func TestExtractImages(t *testing.T) {
	html := `
		<html>
		<body>
			<img src="/images/logo.png">
			<img src="https://cdn.example.com/banner.jpg" alt="Banner">
			<img src="data:image/png;base64,..." alt="Inline">
		</body>
		</html>
	`

	base, _ := parseURL("https://example.com/")
	images := extractImages(html, base)

	// data: URLs should be filtered by resolveURL
	if len(images) != 2 {
		t.Errorf("expected 2 images, got %d: %v", len(images), images)
	}
}

func TestCrawlerGetVisited(t *testing.T) {
	c := NewCrawler(nil)
	c.visited["https://example.com/"] = true
	c.visited["https://example.com/page1"] = true
	c.visited["https://example.com/page2"] = true

	visited := c.GetVisited()

	if len(visited) != 3 {
		t.Errorf("expected 3 visited URLs, got %d", len(visited))
	}

	// Should be sorted
	if visited[0] != "https://example.com/" {
		t.Error("visited URLs should be sorted")
	}
}
