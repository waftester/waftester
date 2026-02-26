package crawler

import (
	"net/http"
	"net/url"
	"testing"
)

func TestExtractFromResponseHeaders(t *testing.T) {
	base, _ := url.Parse("https://example.com")

	t.Run("link header", func(t *testing.T) {
		h := make(http.Header)
		h.Set("Link", `</api/v2>; rel="next", </api/v1>; rel="prev"`)
		links, eps := extractFromResponseHeaders(h, base)
		if len(links) != 2 {
			t.Fatalf("want 2 links, got %d", len(links))
		}
		if len(eps) != 2 {
			t.Fatalf("want 2 endpoints, got %d", len(eps))
		}
		if eps[0].Source != "link-header" {
			t.Errorf("want source link-header, got %s", eps[0].Source)
		}
	})

	t.Run("location header", func(t *testing.T) {
		h := make(http.Header)
		h.Set("Location", "/dashboard")
		links, _ := extractFromResponseHeaders(h, base)
		if len(links) != 1 {
			t.Fatalf("want 1 link, got %d", len(links))
		}
		if links[0] != "https://example.com/dashboard" {
			t.Errorf("want https://example.com/dashboard, got %s", links[0])
		}
	})

	t.Run("csp header", func(t *testing.T) {
		h := make(http.Header)
		h.Set("Content-Security-Policy", "default-src https://cdn.example.com https://api.example.com")
		links, _ := extractFromResponseHeaders(h, base)
		if len(links) != 2 {
			t.Fatalf("want 2 links from CSP, got %d: %v", len(links), links)
		}
	})

	t.Run("empty headers", func(t *testing.T) {
		h := make(http.Header)
		links, eps := extractFromResponseHeaders(h, base)
		if len(links) != 0 || len(eps) != 0 {
			t.Errorf("want empty results for empty headers")
		}
	})
}

func TestExtractURLsFromCSP(t *testing.T) {
	tests := []struct {
		name string
		csp  string
		want int
	}{
		{"with URLs", "default-src https://cdn.ex.com; script-src https://js.ex.com", 2},
		{"no URLs", "default-src 'self'", 0},
		{"duplicates", "default-src https://cdn.ex.com https://cdn.ex.com", 1},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractURLsFromCSP(tt.csp)
			if len(got) != tt.want {
				t.Errorf("want %d URLs, got %d: %v", tt.want, len(got), got)
			}
		})
	}
}

func TestExtractFromJSONResponse(t *testing.T) {
	base, _ := url.Parse("https://api.example.com")

	t.Run("object with URLs", func(t *testing.T) {
		body := []byte(`{"next": "/api/v2/users", "icon": "https://cdn.example.com/img.png"}`)
		links, eps := extractFromJSONResponse(body, base)
		if len(links) < 2 {
			t.Fatalf("want >= 2 links, got %d: %v", len(links), links)
		}
		if len(eps) < 1 {
			t.Fatalf("want >= 1 endpoint, got %d", len(eps))
		}
	})

	t.Run("nested object", func(t *testing.T) {
		body := []byte(`{"data": {"links": {"self": "/api/v1/me"}}}`)
		links, eps := extractFromJSONResponse(body, base)
		if len(links) != 1 {
			t.Fatalf("want 1 link, got %d: %v", len(links), links)
		}
		if len(eps) != 1 {
			t.Fatalf("want 1 endpoint, got %d", len(eps))
		}
	})

	t.Run("array response", func(t *testing.T) {
		body := []byte(`[{"url": "/items/1"}, {"url": "/items/2"}]`)
		links, _ := extractFromJSONResponse(body, base)
		if len(links) != 2 {
			t.Fatalf("want 2 links, got %d: %v", len(links), links)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		links, eps := extractFromJSONResponse([]byte("not json"), base)
		if links != nil || eps != nil {
			t.Error("want nil for invalid JSON")
		}
	})
}

func TestLooksLikePath(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"/api/v1/users", true},
		{"/dashboard", true},
		{"/a", true},
		{"/", false},
		{"", false},
		{"api/v1", false},
		{"/123", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := looksLikePath(tt.input); got != tt.want {
				t.Errorf("looksLikePath(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLooksLikeURL(t *testing.T) {
	if !looksLikeURL("https://example.com") {
		t.Error("https should be URL")
	}
	if !looksLikeURL("http://example.com") {
		t.Error("http should be URL")
	}
	if !looksLikeURL("//cdn.example.com/js/app.js") {
		t.Error("protocol-relative should be URL")
	}
	if looksLikeURL("/api/v1") {
		t.Error("path should not be URL")
	}
}

func TestInferMethodFromKey(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"deleteUser", "DELETE"},
		{"updateProfile", "PUT"},
		{"createPost", "POST"},
		{"addComment", "POST"},
		{"patchSettings", "PATCH"},
		{"getUserList", "GET"},
		{"self", "GET"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := inferMethodFromKey(tt.key); got != tt.want {
				t.Errorf("inferMethodFromKey(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestExtractInlineJSTokenizer_NilAnalyzer(t *testing.T) {
	base, _ := url.Parse("https://example.com")
	links, eps := extractInlineJSTokenizer("<script>fetch('/api')</script>", base, nil)
	if links != nil || eps != nil {
		t.Error("nil analyzer should return nil")
	}
}

func TestExtractMediaElementsTokenizer(t *testing.T) {
	base, _ := url.Parse("https://example.com")

	t.Run("iframe", func(t *testing.T) {
		h := `<html><body><iframe src="/embed/video"></iframe></body></html>`
		links := extractMediaElementsTokenizer(h, base)
		if len(links) != 1 {
			t.Fatalf("want 1 link, got %d", len(links))
		}
		if links[0] != "https://example.com/embed/video" {
			t.Errorf("got %s", links[0])
		}
	})

	t.Run("video with source", func(t *testing.T) {
		h := `<video><source src="/media/clip.mp4"></video>`
		links := extractMediaElementsTokenizer(h, base)
		if len(links) != 1 {
			t.Fatalf("want 1 link, got %d: %v", len(links), links)
		}
	})

	t.Run("object with data", func(t *testing.T) {
		h := `<object data="/flash/game.swf"></object>`
		links := extractMediaElementsTokenizer(h, base)
		if len(links) != 1 {
			t.Fatalf("want 1 link, got %d", len(links))
		}
	})

	t.Run("no media elements", func(t *testing.T) {
		h := `<html><body><p>Hello</p></body></html>`
		links := extractMediaElementsTokenizer(h, base)
		if len(links) != 0 {
			t.Errorf("want 0 links, got %d", len(links))
		}
	})
}

func TestExtractCSSURLsTokenizer(t *testing.T) {
	base, _ := url.Parse("https://example.com")

	t.Run("inline style", func(t *testing.T) {
		h := `<div style="background: url(/img/bg.png)"></div>`
		links := extractCSSURLsTokenizer(h, base)
		if len(links) != 1 {
			t.Fatalf("want 1 link, got %d: %v", len(links), links)
		}
		if links[0] != "https://example.com/img/bg.png" {
			t.Errorf("got %s", links[0])
		}
	})

	t.Run("style tag", func(t *testing.T) {
		h := `<style>.hero { background: url(/img/hero.jpg); }</style>`
		links := extractCSSURLsTokenizer(h, base)
		if len(links) != 1 {
			t.Fatalf("want 1 link, got %d: %v", len(links), links)
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		h := `<style>a { background: url(/img/x.png); } b { background: url(/img/x.png); }</style>`
		links := extractCSSURLsTokenizer(h, base)
		if len(links) != 1 {
			t.Errorf("want 1 deduped link, got %d: %v", len(links), links)
		}
	})

	t.Run("no CSS URLs", func(t *testing.T) {
		h := `<div style="color: red"></div>`
		links := extractCSSURLsTokenizer(h, base)
		if len(links) != 0 {
			t.Errorf("want 0 links, got %d", len(links))
		}
	})
}

func TestExtractFromJSFile_NilAnalyzer(t *testing.T) {
	base, _ := url.Parse("https://example.com")
	links, eps := extractFromJSFile([]byte("var x=1"), base, nil)
	if links != nil || eps != nil {
		t.Error("nil analyzer should return nil")
	}
}

func TestExtractFromJSFile_EmptyBody(t *testing.T) {
	base, _ := url.Parse("https://example.com")
	links, eps := extractFromJSFile(nil, base, nil)
	if links != nil || eps != nil {
		t.Error("empty body should return nil")
	}
}

func TestParseRefreshURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"5; url=https://example.com/new", "https://example.com/new"},
		{"0;URL=/login", "/login"},
		{"no url here", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := parseRefreshURL(tt.input)
		if got != tt.want {
			t.Errorf("parseRefreshURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractFromResponseHeaders_Refresh(t *testing.T) {
	base, _ := url.Parse("https://example.com")
	h := make(http.Header)
	h.Set("Refresh", "5; url=/redirected")
	links, _ := extractFromResponseHeaders(h, base)
	found := false
	for _, l := range links {
		if l == "https://example.com/redirected" {
			found = true
		}
	}
	if !found {
		t.Errorf("Refresh header URL not extracted, got %v", links)
	}
}

func TestExtractWithLinkFinder(t *testing.T) {
	base, _ := url.Parse("https://example.com")

	t.Run("javascript string URLs", func(t *testing.T) {
		content := `var api = "/api/v1/users"; var other = '/api/v2/posts';`
		links, eps := extractWithLinkFinder(content, base)
		if len(links) < 2 {
			t.Errorf("want at least 2 links, got %d: %v", len(links), links)
		}
		if len(eps) < 2 {
			t.Errorf("want at least 2 endpoints, got %d", len(eps))
		}
	})

	t.Run("full URLs", func(t *testing.T) {
		content := `var url = "https://api.example.com/data";`
		links, _ := extractWithLinkFinder(content, base)
		if len(links) < 1 {
			t.Errorf("want at least 1 link, got %d", len(links))
		}
	})

	t.Run("file paths", func(t *testing.T) {
		content := `"config.json" "login.php" "data.xml"`
		links, _ := extractWithLinkFinder(content, base)
		if len(links) < 2 {
			t.Errorf("want at least 2 links, got %d: %v", len(links), links)
		}
	})

	t.Run("empty content", func(t *testing.T) {
		links, eps := extractWithLinkFinder("", base)
		if links != nil || eps != nil {
			t.Error("empty content should return nil")
		}
	})

	t.Run("relative paths", func(t *testing.T) {
		content := `"./assets/main.js" "../config/settings.json"`
		links, _ := extractWithLinkFinder(content, base)
		if len(links) < 2 {
			t.Errorf("want at least 2 links, got %d: %v", len(links), links)
		}
	})
}

func TestExtractLinksTokenizer_ComprehensiveTags(t *testing.T) {
	base, _ := url.Parse("https://example.com")

	t.Run("button formaction", func(t *testing.T) {
		html := `<button formaction="/submit">Go</button>`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/submit")
	})

	t.Run("blockquote cite", func(t *testing.T) {
		html := `<blockquote cite="/source">text</blockquote>`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/source")
	})

	t.Run("body background", func(t *testing.T) {
		html := `<body background="/bg.jpg"><p>content</p></body>`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/bg.jpg")
	})

	t.Run("video poster", func(t *testing.T) {
		html := `<video poster="/thumb.jpg" src="/vid.mp4"></video>`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/thumb.jpg")
		assertContains(t, links, "https://example.com/vid.mp4")
	})

	t.Run("object data", func(t *testing.T) {
		html := `<object data="/flash.swf" codebase="/code/"></object>`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/flash.swf")
		assertContains(t, links, "https://example.com/code/")
	})

	t.Run("htmx attributes", func(t *testing.T) {
		html := `<div hx-get="/api/data" hx-post="/api/submit" hx-delete="/api/remove"></div>`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/api/data")
		assertContains(t, links, "https://example.com/api/submit")
		assertContains(t, links, "https://example.com/api/remove")
	})

	t.Run("a ping", func(t *testing.T) {
		html := `<a href="/page" ping="/track">link</a>`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/track")
	})

	t.Run("html manifest", func(t *testing.T) {
		html := `<html manifest="/app.manifest"><body></body></html>`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/app.manifest")
	})

	t.Run("meta content URL", func(t *testing.T) {
		html := `<meta property="og:url" content="https://example.com/page">`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/page")
	})

	t.Run("input type image src", func(t *testing.T) {
		html := `<input type="image" src="/submit-btn.png">`
		links := extractLinksTokenizer(html, base)
		assertContains(t, links, "https://example.com/submit-btn.png")
	})
}

func TestParseRobotsAllowAndSitemaps(t *testing.T) {
	base, _ := url.Parse("https://example.com")

	body := `User-agent: *
Allow: /api/
Disallow: /admin/
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/news-sitemap.xml`

	urls := parseRobotsAllowAndSitemaps(body, base)
	if len(urls) < 3 {
		t.Fatalf("want at least 3 URLs (1 allow + 2 sitemaps), got %d: %v", len(urls), urls)
	}

	found := map[string]bool{}
	for _, u := range urls {
		found[u] = true
	}
	if !found["https://example.com/api/"] {
		t.Error("missing Allow path /api/")
	}
	if !found["https://example.com/sitemap.xml"] {
		t.Error("missing Sitemap URL")
	}
	if !found["https://example.com/news-sitemap.xml"] {
		t.Error("missing news-sitemap URL")
	}
}

func assertContains(t *testing.T, links []string, want string) {
	t.Helper()
	for _, l := range links {
		if l == want {
			return
		}
	}
	t.Errorf("links %v does not contain %q", links, want)
}
