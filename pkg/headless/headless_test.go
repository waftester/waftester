package headless

import (
	"net/url"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MaxBrowsers != 4 {
		t.Errorf("expected MaxBrowsers 4, got %d", config.MaxBrowsers)
	}

	if !config.CaptureXHR {
		t.Error("expected CaptureXHR to be true")
	}

	if !config.BlockImages {
		t.Error("expected BlockImages to be true for performance")
	}

	if len(config.CookieConsentWords) == 0 {
		t.Error("expected cookie consent words to be populated")
	}
}

func TestNewBrowser(t *testing.T) {
	browser, err := NewBrowser(nil)
	if err != nil {
		t.Fatalf("failed to create browser: %v", err)
	}
	defer browser.Close()

	if browser.config == nil {
		t.Error("expected default config to be set")
	}
}

func TestExtractURLsFromPage(t *testing.T) {
	html := `
	<html>
	<head>
		<link rel="stylesheet" href="/css/style.css">
	</head>
	<body>
		<a href="/about">About</a>
		<a href="https://example.com/external">External</a>
		<a href="/contact?ref=nav">Contact</a>
		<img src="/images/logo.png">
		<script src='/js/app.js'></script>
		<form action="/api/submit" method="POST">
			<input type="text" name="name">
		</form>
		<img data-src="/lazy/image.jpg">
	</body>
	</html>
	`

	urls, err := ExtractURLsFromPage(html, "https://test.com")
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	expectedURLs := []string{
		"https://test.com/css/style.css",
		"https://test.com/about",
		"https://example.com/external",
		"https://test.com/contact?ref=nav",
		"https://test.com/images/logo.png",
		"https://test.com/js/app.js",
		"https://test.com/api/submit",
		"https://test.com/lazy/image.jpg",
	}

	for _, expected := range expectedURLs {
		found := false
		for _, u := range urls {
			if u.URL == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected URL not found: %s", expected)
		}
	}
}

func TestExtractURLsFromPageSkipsJavaScript(t *testing.T) {
	html := `
	<a href="javascript:void(0)">Bad Link</a>
	<a href="#">Anchor</a>
	<a href="/valid">Valid</a>
	`

	urls, _ := ExtractURLsFromPage(html, "https://test.com")

	for _, u := range urls {
		if u.URL == "#" || u.URL == "" {
			t.Error("should not include empty or anchor-only URLs")
		}
		if u.URL == "javascript:void(0)" {
			t.Error("should not include javascript: URLs")
		}
	}

	// Valid URL should be present
	found := false
	for _, u := range urls {
		if u.URL == "https://test.com/valid" {
			found = true
			break
		}
	}
	if !found {
		t.Error("valid URL should be extracted")
	}
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		raw      string
		base     string
		expected string
	}{
		{"/about", "https://example.com", "https://example.com/about"},
		{"//cdn.example.com/js", "https://example.com", "https://cdn.example.com/js"},
		{"https://other.com/page", "https://example.com", "https://other.com/page"},
		{"relative/path", "https://example.com/dir/", "https://example.com/dir/relative/path"},
		{"../up", "https://example.com/a/b/", "https://example.com/a/up"},
		{"mailto:test@test.com", "https://example.com", ""}, // should skip mailto
		{"tel:123456", "https://example.com", ""},           // should skip tel
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			base, _ := parseURL(tt.base)
			result := resolveURL(tt.raw, base)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func parseURL(u string) (*url.URL, error) {
	return url.Parse(u)
}

func TestExtractPageInfo(t *testing.T) {
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Test Page Title</title>
		<meta name="description" content="This is a test description">
		<meta property="og:image" content="https://example.com/image.png">
		<link rel="canonical" href="https://example.com/canonical">
	</head>
	<body>Content</body>
	</html>
	`

	info := ExtractPageInfo(html)

	if info.Title != "Test Page Title" {
		t.Errorf("expected title 'Test Page Title', got '%s'", info.Title)
	}

	if info.Description != "This is a test description" {
		t.Errorf("expected description, got '%s'", info.Description)
	}

	if info.OGImage != "https://example.com/image.png" {
		t.Errorf("expected og:image, got '%s'", info.OGImage)
	}

	if info.Canonical != "https://example.com/canonical" {
		t.Errorf("expected canonical, got '%s'", info.Canonical)
	}
}

func TestScreenshotHash(t *testing.T) {
	data := []byte("test screenshot data")
	hash1 := ScreenshotHash(data)
	hash2 := ScreenshotHash(data)

	if hash1 != hash2 {
		t.Error("same data should produce same hash")
	}

	different := ScreenshotHash([]byte("different data"))
	if hash1 == different {
		t.Error("different data should produce different hash")
	}
}

func TestDeduplicateURLs(t *testing.T) {
	urls := []FoundURL{
		{URL: "https://example.com/a", Source: "href"},
		{URL: "https://example.com/b", Source: "href"},
		{URL: "https://example.com/a", Source: "src"}, // duplicate URL
		{URL: "https://example.com/c", Source: "href"},
		{URL: "https://example.com/b", Source: "action"}, // duplicate URL
	}

	deduped := deduplicateURLs(urls)

	if len(deduped) != 3 {
		t.Errorf("expected 3 unique URLs, got %d", len(deduped))
	}
}

func TestFormFiller(t *testing.T) {
	filler := NewFormFiller(nil)

	form := FormInfo{
		Action: "/submit",
		Method: "POST",
		Fields: []FormField{
			{Name: "email", Type: "email"},
			{Name: "password", Type: "password"},
			{Name: "username", Type: "text"},
			{Name: "age", Type: "number"},
		},
	}

	filled := filler.FillForm(form)

	if filled["email"] == "" {
		t.Error("email should be filled")
	}
	if filled["password"] == "" {
		t.Error("password should be filled")
	}
	if filled["username"] == "" {
		t.Error("username should be filled")
	}
}

func TestFormFillerCustomValues(t *testing.T) {
	custom := map[string]string{
		"email": "custom@test.com",
	}
	filler := NewFormFiller(custom)

	field := FormField{Name: "email", Type: "email"}
	value := filler.GetValueForField(field)

	if value != "custom@test.com" {
		t.Errorf("expected custom email, got '%s'", value)
	}
}

func TestDetectFormType(t *testing.T) {
	tests := []struct {
		name     string
		form     FormInfo
		expected string
	}{
		{
			name: "login form",
			form: FormInfo{
				Fields: []FormField{
					{Name: "username", Type: "text"},
					{Name: "password", Type: "password"},
				},
			},
			expected: "login",
		},
		{
			name: "registration form",
			form: FormInfo{
				Fields: []FormField{
					{Name: "email", Type: "email"},
					{Name: "password", Type: "password"},
					{Name: "confirm_password", Type: "password"},
				},
			},
			expected: "registration",
		},
		{
			name: "search form",
			form: FormInfo{
				Method: "GET",
				Fields: []FormField{
					{Name: "q", Type: "text"},
				},
			},
			expected: "search",
		},
		{
			name: "contact form",
			form: FormInfo{
				Fields: []FormField{
					{Name: "name", Type: "text"},
					{Name: "email", Type: "email"},
					{Name: "message", Type: "textarea"},
				},
			},
			expected: "contact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectFormType(tt.form)
			if result != tt.expected {
				t.Errorf("expected form type '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestXHRExtractor(t *testing.T) {
	extractor := NewXHRExtractor(nil)

	// Add some requests
	extractor.AddRequest(NetworkRequest{
		URL:    "https://api.example.com/v1/users",
		Method: "GET",
	})
	extractor.AddRequest(NetworkRequest{
		URL:    "https://api.example.com/v1/posts",
		Method: "POST",
	})
	// This should be ignored (static asset)
	extractor.AddRequest(NetworkRequest{
		URL:    "https://example.com/style.css",
		Method: "GET",
	})

	requests := extractor.GetRequests()

	if len(requests) != 2 {
		t.Errorf("expected 2 requests (CSS should be ignored), got %d", len(requests))
	}
}

func TestXHRExtractorAPIEndpoints(t *testing.T) {
	extractor := NewXHRExtractor(nil)

	extractor.AddRequest(NetworkRequest{
		URL:    "https://api.example.com/api/v1/users",
		Method: "GET",
	})
	extractor.AddRequest(NetworkRequest{
		URL:    "https://api.example.com/api/v1/users",
		Method: "POST",
	})
	extractor.AddRequest(NetworkRequest{
		URL:    "https://api.example.com/api/v1/posts",
		Method: "GET",
	})

	endpoints := extractor.GetAPIEndpoints()

	if len(endpoints) != 3 {
		t.Errorf("expected 3 unique endpoints, got %d", len(endpoints))
	}
}

func TestExtractURLsFromJS(t *testing.T) {
	js := `
	fetch('/api/users');
	fetch("/api/posts");
	axios.get('/api/comments');
	$.ajax({ url: '/api/data' });
	const endpoint = '/api/v1/resource';
	xhr.open('GET', '/api/items');
	`

	urls := ExtractURLsFromJS(js, "https://example.com")

	expectedPaths := []string{
		"/api/users",
		"/api/posts",
		"/api/comments",
		"/api/data",
		"/api/v1/resource",
		"/api/items",
	}

	for _, path := range expectedPaths {
		found := false
		for _, u := range urls {
			if u == "https://example.com"+path {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected path %s not extracted", path)
		}
	}
}

func TestFormToURLEncoded(t *testing.T) {
	data := map[string]string{
		"name":  "test",
		"value": "123",
	}

	encoded := FormToURLEncoded(data)

	if !containsAll(encoded, []string{"name=test", "value=123"}) {
		t.Errorf("unexpected encoding: %s", encoded)
	}
}

func TestFormToJSON(t *testing.T) {
	data := map[string]string{
		"name":  "test",
		"value": "123",
	}

	jsonStr, err := FormToJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if jsonStr == "" {
		t.Error("expected non-empty JSON")
	}
}

func containsAll(s string, substrs []string) bool {
	for _, sub := range substrs {
		found := false
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
