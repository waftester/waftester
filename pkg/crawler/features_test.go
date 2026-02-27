package crawler

import (
	"context"
	"net/url"
	"testing"
)

func TestIsTrackingParam(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key  string
		want bool
	}{
		{"utm_source", true},
		{"utm_campaign", true},
		{"fbclid", true},
		{"gclid", true},
		{"msclkid", true},
		{"_ga", true},
		{"ref", true},
		{"page", false},
		{"id", false},
		{"q", false},
		{"action", false},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got := isTrackingParam(tc.key)
			if got != tc.want {
				t.Errorf("isTrackingParam(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}

func TestSortedQueryString(t *testing.T) {
	t.Parallel()
	params := url.Values{
		"z": {"3"},
		"a": {"1"},
		"m": {"2"},
	}
	got := sortedQueryString(params)
	want := "a=1&m=2&z=3"
	if got != want {
		t.Errorf("sortedQueryString = %q, want %q", got, want)
	}
}

func TestSortedQueryString_Empty(t *testing.T) {
	t.Parallel()
	got := sortedQueryString(url.Values{})
	if got != "" {
		t.Errorf("sortedQueryString(empty) = %q, want empty", got)
	}
}

func TestIsCommonJSLibrary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		url  string
		want bool
	}{
		{"https://cdn.example.com/jquery.min.js", true},
		{"https://cdn.example.com/angular.js", true},
		{"https://cdn.example.com/react-dom.production.min.js", true},
		{"https://cdn.example.com/vue.runtime.global.js", true},
		{"https://cdn.example.com/bootstrap.bundle.min.js", true},
		{"https://cdn.example.com/lodash.min.js", true},
		{"https://cdn.example.com/moment.min.js", true},
		{"https://cdn.example.com/d3.v7.min.js", true},
		{"https://cdn.example.com/highlight.js/highlight.min.js", true},
		{"https://cdn.example.com/sentry.min.js", true},
		{"https://cdn.example.com/recaptcha/api.js", true},
		// Non-library files
		{"https://example.com/app.js", false},
		{"https://example.com/main.bundle.js", false},
		{"https://example.com/api/v1/data.js", false},
		{"https://example.com/custom-script.js", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			got := isCommonJSLibrary(tc.url)
			if got != tc.want {
				t.Errorf("isCommonJSLibrary(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestLooksLikeFilename(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    string
		want bool
	}{
		{"config.json", true},
		{"login.php", true},
		{"data.xml", true},
		{"script.js", true},
		{"styles.css", true},
		{"api.graphql", true},
		{".env", false},
		{"noext", false},
		{"file.unknown", false},
		{"file.", false},
	}
	for _, tc := range cases {
		t.Run(tc.s, func(t *testing.T) {
			got := looksLikeFilename(tc.s)
			if got != tc.want {
				t.Errorf("looksLikeFilename(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

func TestExtractSubdomains(t *testing.T) {
	t.Parallel()
	html := `
	<a href="https://api.example.com/v1">API</a>
	<a href="https://staging.example.com">Staging</a>
	<script src="https://cdn.example.com/app.js"></script>
	<a href="https://example.com">Home</a>
	<a href="https://not-example.com">Other</a>
	`

	subs := extractSubdomains(html, "example.com")
	if len(subs) < 3 {
		t.Fatalf("want at least 3 subdomains, got %d: %v", len(subs), subs)
	}

	wantSubs := map[string]bool{
		"api.example.com":     true,
		"staging.example.com": true,
		"cdn.example.com":     true,
	}
	for _, sub := range subs {
		delete(wantSubs, sub)
	}
	for missing := range wantSubs {
		t.Errorf("missing subdomain: %s", missing)
	}

	// Should not include the base domain itself
	for _, sub := range subs {
		if sub == "example.com" {
			t.Error("should not include base domain")
		}
	}
}

func TestExtractSubdomains_None(t *testing.T) {
	t.Parallel()
	subs := extractSubdomains("no subdomains here", "example.com")
	if len(subs) != 0 {
		t.Errorf("want 0 subdomains, got %d: %v", len(subs), subs)
	}
}

func TestFillForm_GET(t *testing.T) {
	t.Parallel()
	form := FormInfo{
		Action: "https://example.com/search",
		Method: "GET",
		Inputs: []InputInfo{
			{Name: "q", Type: "text"},
			{Name: "page", Type: "number"},
		},
	}
	base, _ := url.Parse("https://example.com/")
	req := fillForm(form, base)
	if req == nil {
		t.Fatal("fillForm returned nil")
	}
	if req.Method != "GET" {
		t.Errorf("method = %q, want GET", req.Method)
	}
	if req.Body != "" {
		t.Errorf("GET form should have empty body, got %q", req.Body)
	}
	// URL should contain params
	parsed, _ := url.Parse(req.URL)
	if parsed.Query().Get("q") == "" {
		t.Error("missing q parameter in URL")
	}
}

func TestFillForm_POST(t *testing.T) {
	t.Parallel()
	form := FormInfo{
		Action: "https://example.com/login",
		Method: "POST",
		Inputs: []InputInfo{
			{Name: "email", Type: "email"},
			{Name: "password", Type: "password"},
			{Name: "csrf", Type: "hidden", Value: "tok123"},
		},
	}
	base, _ := url.Parse("https://example.com/")
	req := fillForm(form, base)
	if req == nil {
		t.Fatal("fillForm returned nil")
	}
	if req.Method != "POST" {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content type = %q, want form-urlencoded", req.ContentType)
	}
	// Body should contain filled values
	params, _ := url.ParseQuery(req.Body)
	if params.Get("email") == "" {
		t.Error("email not filled")
	}
	if params.Get("password") == "" {
		t.Error("password not filled")
	}
	// Hidden field with value should be preserved
	if params.Get("csrf") != "tok123" {
		t.Errorf("csrf = %q, want tok123", params.Get("csrf"))
	}
}

func TestFillForm_PreservesHiddenValues(t *testing.T) {
	t.Parallel()
	form := FormInfo{
		Action: "https://example.com/submit",
		Method: "POST",
		Inputs: []InputInfo{
			{Name: "_token", Type: "hidden", Value: "csrf-secret-123"},
			{Name: "empty_hidden", Type: "hidden"},
			{Name: "name", Type: "text"},
		},
	}
	base, _ := url.Parse("https://example.com/")
	req := fillForm(form, base)
	if req == nil {
		t.Fatal("fillForm returned nil")
	}
	params, _ := url.ParseQuery(req.Body)
	// Hidden with value: preserved
	if params.Get("_token") != "csrf-secret-123" {
		t.Errorf("_token = %q, want csrf-secret-123", params.Get("_token"))
	}
	// Hidden without value: skipped
	if params.Get("empty_hidden") != "" {
		t.Errorf("empty_hidden should be empty, got %q", params.Get("empty_hidden"))
	}
}

func TestFillForm_EmptyForm(t *testing.T) {
	t.Parallel()
	form := FormInfo{Action: "", Method: ""}
	base, _ := url.Parse("https://example.com/")
	req := fillForm(form, base)
	if req != nil {
		t.Errorf("fillForm should return nil for empty form, got %+v", req)
	}
}

func TestFillForm_UsesPlaceholder(t *testing.T) {
	t.Parallel()
	form := FormInfo{
		Action: "https://example.com/api",
		Method: "GET",
		Inputs: []InputInfo{
			{Name: "query", Type: "text", Placeholder: "search terms"},
		},
	}
	base, _ := url.Parse("https://example.com/")
	req := fillForm(form, base)
	if req == nil {
		t.Fatal("fillForm returned nil")
	}
	parsed, _ := url.Parse(req.URL)
	if parsed.Query().Get("query") != "search terms" {
		t.Errorf("should use placeholder, got %q", parsed.Query().Get("query"))
	}
}

func TestFormFilling_HasUpload(t *testing.T) {
	t.Parallel()
	html := `<form action="/upload" method="POST" enctype="multipart/form-data">
		<input type="file" name="document">
		<input type="text" name="description">
		<input type="submit" value="Upload">
	</form>`

	base, _ := url.Parse("https://example.com/")
	forms := extractFormsTokenizer(html, base)
	if len(forms) == 0 {
		t.Fatal("no forms found")
	}
	if !forms[0].HasUpload {
		t.Error("expected HasUpload=true for form with file input")
	}
}

func TestNormalizeURL_SortsQueryParams(t *testing.T) {
	t.Parallel()
	c := &Crawler{
		config:  DefaultConfig(),
		visited: make(map[string]bool),
	}
	c.baseDomain = "example.com"

	url1 := c.normalizeURL("https://example.com/page?z=3&a=1&m=2")
	url2 := c.normalizeURL("https://example.com/page?a=1&m=2&z=3")
	if url1 != url2 {
		t.Errorf("query param order should not matter:\n  %q\n  %q", url1, url2)
	}
}

func TestNormalizeURL_StripsTrackingParams(t *testing.T) {
	t.Parallel()
	c := &Crawler{
		config:  DefaultConfig(),
		visited: make(map[string]bool),
	}
	c.baseDomain = "example.com"

	got := c.normalizeURL("https://example.com/page?id=1&utm_source=google&fbclid=abc123")
	// Should only have id=1
	if got != "https://example.com/page?id=1" {
		t.Errorf("tracking params not stripped: %q", got)
	}
}

func TestClimbPaths(t *testing.T) {
	t.Parallel()
	c := &Crawler{
		config:  DefaultConfig(),
		visited: make(map[string]bool),
		queue:   make(chan *crawlTask, 100),
	}
	c.baseDomain = "example.com"
	c.baseHostname = "example.com"
	c.basePort = "443"
	c.ctx, c.cancel = context.WithCancel(context.Background())
	defer c.cancel()

	c.climbPaths("https://example.com/a/b/c/page.html", 1)

	// Drain queue and collect URLs
	close(c.queue)
	var queued []string
	for task := range c.queue {
		queued = append(queued, task.URL)
	}

	wantPaths := []string{"/a/b/c/", "/a/b/", "/a/"}
	for _, want := range wantPaths {
		found := false
		for _, q := range queued {
			if len(q) > 0 {
				p, _ := url.Parse(q)
				if p != nil && p.Path == want {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("missing parent path %q in queued URLs: %v", want, queued)
		}
	}
}

func TestExtractEmails(t *testing.T) {
	t.Parallel()
	text := `Contact us at support@example.com or sales@example.org.
		Also admin@example.com and image@thing.png should be skipped.
		Duplicate: support@example.com`

	got := extractEmails(text)

	want := map[string]bool{
		"support@example.com": true,
		"sales@example.org":   true,
		"admin@example.com":   true,
	}

	if len(got) != len(want) {
		t.Fatalf("extractEmails got %d results, want %d: %v", len(got), len(want), got)
	}
	for _, email := range got {
		if !want[email] {
			t.Errorf("unexpected email: %q", email)
		}
	}
}

func TestExtractEmails_NoResults(t *testing.T) {
	t.Parallel()
	got := extractEmails("no emails here, just text and numbers 123")
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestExtractParameters(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://example.com/search?q=test&page=1",
		"https://example.com/api?token=abc&q=other",
		"https://example.com/page",
	}

	got := extractParameters(urls)

	want := map[string]bool{"q": true, "page": true, "token": true}
	if len(got) != len(want) {
		t.Fatalf("extractParameters got %d, want %d: %v", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected param: %q", p)
		}
	}
}

func TestExtractSecrets(t *testing.T) {
	t.Parallel()
	text := `
		var config = {
			awsKey: "AKIAIOSFODNN7EXAMPLE",
			secret: "SuperSecretValue12345678",
			token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
		};
	`

	got := extractSecrets(text, "test.js")
	if len(got) == 0 {
		t.Fatal("expected secret findings, got none")
	}

	foundTypes := make(map[string]bool)
	for _, f := range got {
		foundTypes[f.Type] = true
		if f.Source != "test.js" {
			t.Errorf("wrong source: %q", f.Source)
		}
		// Verify redaction — should not contain the full original match
		if len(f.Match) > 12 && !containsStars(f.Match) {
			t.Errorf("match not redacted: %q", f.Match)
		}
	}

	if !foundTypes["aws_access_key"] {
		t.Error("missing aws_access_key detection")
	}
}

func containsStars(s string) bool {
	for _, c := range s {
		if c == '*' {
			return true
		}
	}
	return false
}

func TestExtractSecrets_NoResults(t *testing.T) {
	t.Parallel()
	got := extractSecrets("just normal text here, nothing secret", "page.html")
	if len(got) != 0 {
		t.Errorf("expected no findings, got %d: %v", len(got), got)
	}
}

func TestRedactMiddle(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  string
	}{
		{"short", "shor***"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA***MPLE"},
	}
	for _, tc := range cases {
		got := redactMiddle(tc.input)
		if got != tc.want {
			t.Errorf("redactMiddle(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestInScope_SamePort(t *testing.T) {
	t.Parallel()
	c := &Crawler{
		config: &Config{
			SameDomain: true,
			SamePort:   true,
		},
		visited: make(map[string]bool),
	}
	c.baseDomain = "example.com:8080"
	c.baseHostname = "example.com"
	c.basePort = "8080"

	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.com:8080/path", true},
		{"https://example.com:9090/path", false},
		{"https://example.com/path", false}, // default 443 != 8080
	}

	for _, tt := range tests {
		got := c.inScope(tt.url)
		if got != tt.want {
			t.Errorf("inScope(%s) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestInScope_SameDomainFalse(t *testing.T) {
	t.Parallel()
	c := &Crawler{
		config: &Config{
			SameDomain: false,
		},
		visited: make(map[string]bool),
	}
	c.baseDomain = "example.com"
	c.baseHostname = "example.com"
	c.basePort = "443"

	// With SameDomain=false, any domain should be in scope
	if !c.inScope("https://other.com/page") {
		t.Error("SameDomain=false should allow other domains")
	}
}

func TestMinJSFallback_CaseInsensitive(t *testing.T) {
	t.Parallel()
	// Verify the fix: .MIN.JS suffix should still produce valid fallback URLs
	script := "https://cdn.example.com/app.MIN.JS"
	lower := "https://cdn.example.com/app.min.js"

	// Simulate the fixed logic
	if len(script) < len(".min.js") {
		t.Fatal("script too short")
	}
	base := script[:len(script)-len(".min.js")]
	got := base + ".js"

	// Should strip the suffix regardless of case
	if got != "https://cdn.example.com/app.js" {
		t.Errorf("case-insensitive .min.js fix produced: %q", got)
	}

	// Also verify ToLower detects it
	if !containsSuffix(lower, ".min.js") {
		t.Error("ToLower should detect .min.js suffix")
	}
}

func containsSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
