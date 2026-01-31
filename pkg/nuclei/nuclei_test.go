package nuclei

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseTemplate_Basic(t *testing.T) {
	yaml := `
id: test-template
info:
  name: Test Template
  author: tester
  severity: low
  description: A test template
http:
  - method: GET
    path:
      - "/"
    matchers:
      - type: status
        status:
          - 200
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse template: %v", err)
	}

	if tmpl.ID != "test-template" {
		t.Errorf("expected id 'test-template', got %s", tmpl.ID)
	}
	if tmpl.Info.Name != "Test Template" {
		t.Errorf("expected name 'Test Template', got %s", tmpl.Info.Name)
	}
	if tmpl.Info.Severity != "low" {
		t.Errorf("expected severity 'low', got %s", tmpl.Info.Severity)
	}
	if len(tmpl.HTTP) != 1 {
		t.Errorf("expected 1 HTTP request, got %d", len(tmpl.HTTP))
	}
}

func TestParseTemplate_MissingID(t *testing.T) {
	yaml := `
info:
  name: Test
`
	_, err := ParseTemplate([]byte(yaml))
	if err == nil {
		t.Error("expected error for missing id")
	}
}

func TestParseTemplate_MissingName(t *testing.T) {
	yaml := `
id: test
info:
  severity: low
`
	_, err := ParseTemplate([]byte(yaml))
	if err == nil {
		t.Error("expected error for missing name")
	}
}

func TestParseTemplate_WithMatchers(t *testing.T) {
	yaml := `
id: matcher-test
info:
  name: Matcher Test
  severity: high
http:
  - method: GET
    path:
      - "/test"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "success"
          - "ok"
        condition: or
      - type: status
        status:
          - 200
          - 201
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if len(tmpl.HTTP[0].Matchers) != 2 {
		t.Errorf("expected 2 matchers, got %d", len(tmpl.HTTP[0].Matchers))
	}
	if tmpl.HTTP[0].MatchersCondition != "and" {
		t.Errorf("expected 'and' condition, got %s", tmpl.HTTP[0].MatchersCondition)
	}
}

func TestParseTemplate_WithExtractors(t *testing.T) {
	yaml := `
id: extractor-test
info:
  name: Extractor Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    extractors:
      - type: regex
        name: version
        regex:
          - "version[\\s:]+([0-9.]+)"
        group: 1
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if len(tmpl.HTTP[0].Extractors) != 1 {
		t.Errorf("expected 1 extractor, got %d", len(tmpl.HTTP[0].Extractors))
	}
	if tmpl.HTTP[0].Extractors[0].Name != "version" {
		t.Errorf("expected name 'version', got %s", tmpl.HTTP[0].Extractors[0].Name)
	}
}

func TestParseTemplate_WithClassification(t *testing.T) {
	yaml := `
id: cve-test
info:
  name: CVE Test
  severity: critical
  classification:
    cve-id: CVE-2021-44228
    cvss-score: 10.0
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    cwe-id:
      - CWE-917
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if tmpl.Info.Classification == nil {
		t.Fatal("expected classification")
	}
	if tmpl.Info.Classification.CVE != "CVE-2021-44228" {
		t.Errorf("expected CVE 'CVE-2021-44228', got %s", tmpl.Info.Classification.CVE)
	}
	if tmpl.Info.Classification.CVSSScore != 10.0 {
		t.Errorf("expected CVSS 10.0, got %f", tmpl.Info.Classification.CVSSScore)
	}
}

func TestEngine_Execute_StatusMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	yaml := `
id: status-test
info:
  name: Status Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    matchers:
      - type: status
        status:
          - 200
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Matched {
		t.Error("expected match")
	}
}

func TestEngine_Execute_WordMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Hello World! This is a test page."))
	}))
	defer server.Close()

	yaml := `
id: word-test
info:
  name: Word Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    matchers:
      - type: word
        words:
          - "Hello World"
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Matched {
		t.Error("expected match for 'Hello World'")
	}
}

func TestEngine_Execute_RegexMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Version: 1.2.3-beta"))
	}))
	defer server.Close()

	yaml := `
id: regex-test
info:
  name: Regex Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    matchers:
      - type: regex
        regex:
          - "[0-9]+\\.[0-9]+\\.[0-9]+"
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Matched {
		t.Error("expected regex match")
	}
}

func TestEngine_Execute_NegativeMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	yaml := `
id: negative-test
info:
  name: Negative Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    matchers:
      - type: word
        words:
          - "error"
        negative: true
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Matched {
		t.Error("expected match (negative, 'error' not found)")
	}
}

func TestEngine_Execute_Extractor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Application version: 2.5.1"))
	}))
	defer server.Close()

	yaml := `
id: extract-test
info:
  name: Extract Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    extractors:
      - type: regex
        name: version
        regex:
          - "version:\\s*([0-9.]+)"
        group: 1
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.ExtractedData["version"]) == 0 {
		t.Error("expected extracted version")
	} else if result.ExtractedData["version"][0] != "2.5.1" {
		t.Errorf("expected '2.5.1', got %s", result.ExtractedData["version"][0])
	}
}

func TestEngine_Execute_HeaderExtractor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "test-value")
		w.WriteHeader(200)
	}))
	defer server.Close()

	yaml := `
id: header-extract-test
info:
  name: Header Extract Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    extractors:
      - type: kval
        name: custom
        kval:
          - X-Custom
        part: header
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.ExtractedData["custom"]) == 0 {
		t.Error("expected extracted header value")
	} else if result.ExtractedData["custom"][0] != "test-value" {
		t.Errorf("expected 'test-value', got %s", result.ExtractedData["custom"][0])
	}
}

func TestEngine_Execute_MatchersAND(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	yaml := `
id: and-test
info:
  name: AND Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "success"
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Matched {
		t.Error("expected match with AND condition")
	}
}

func TestEngine_Execute_MatchersAND_Fail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("failure"))
	}))
	defer server.Close()

	yaml := `
id: and-fail-test
info:
  name: AND Fail Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "success"
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Matched {
		t.Error("expected no match with AND condition (word not found)")
	}
}

func TestEngine_Execute_MultiplePaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			w.Write([]byte("Admin Panel"))
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	yaml := `
id: multi-path-test
info:
  name: Multi Path Test
  severity: info
http:
  - method: GET
    path:
      - "/login"
      - "/admin"
      - "/dashboard"
    matchers:
      - type: word
        words:
          - "Admin Panel"
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Matched {
		t.Error("expected match on /admin path")
	}
}

func TestEngine_Execute_Variables(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/status" {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	yaml := `
id: var-test
info:
  name: Variable Test
  severity: info
variables:
  version: v2
http:
  - method: GET
    path:
      - "/api/{{.version}}/status"
    matchers:
      - type: status
        status:
          - 200
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Matched {
		t.Error("expected match with variable substitution")
	}
}

func TestEngine_Execute_CaseInsensitive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("HELLO WORLD"))
	}))
	defer server.Close()

	yaml := `
id: case-test
info:
  name: Case Insensitive Test
  severity: info
http:
  - method: GET
    path:
      - "/"
    matchers:
      - type: word
        words:
          - "hello world"
        case-insensitive: true
`
	tmpl, _ := ParseTemplate([]byte(yaml))
	engine := NewEngine()

	result, err := engine.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Matched {
		t.Error("expected case-insensitive match")
	}
}

func TestLoadTemplate_FromFile(t *testing.T) {
	// Create temp file
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	content := `
id: file-test
info:
  name: File Test
  severity: low
http:
  - method: GET
    path:
      - "/"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	tmpl, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("failed to load template: %v", err)
	}

	if tmpl.ID != "file-test" {
		t.Errorf("expected id 'file-test', got %s", tmpl.ID)
	}
}

func TestLoadTemplatesFromDir(t *testing.T) {
	dir := t.TempDir()

	// Create multiple templates
	templates := []string{
		`id: t1
info:
  name: Template 1
  severity: low`,
		`id: t2
info:
  name: Template 2
  severity: medium`,
	}

	for i, content := range templates {
		path := filepath.Join(dir, "template"+string(rune('0'+i))+".yaml")
		os.WriteFile(path, []byte(content), 0644)
	}

	loaded, err := LoadTemplatesFromDir(dir)
	if err != nil {
		t.Fatalf("failed to load templates: %v", err)
	}

	if len(loaded) != 2 {
		t.Errorf("expected 2 templates, got %d", len(loaded))
	}
}

func TestFilterTemplates_BySeverity(t *testing.T) {
	templates := []*Template{
		{ID: "t1", Info: Info{Name: "T1", Severity: "critical"}},
		{ID: "t2", Info: Info{Name: "T2", Severity: "high"}},
		{ID: "t3", Info: Info{Name: "T3", Severity: "low"}},
	}

	filtered := FilterTemplates(templates, nil, []string{"critical", "high"})

	if len(filtered) != 2 {
		t.Errorf("expected 2 templates, got %d", len(filtered))
	}
}

func TestFilterTemplates_ByTags(t *testing.T) {
	templates := []*Template{
		{ID: "t1", Info: Info{Name: "T1", Tags: "sqli,injection"}},
		{ID: "t2", Info: Info{Name: "T2", Tags: "xss,web"}},
		{ID: "t3", Info: Info{Name: "T3", Tags: "misc"}},
	}

	filtered := FilterTemplates(templates, []string{"sqli"}, nil)

	if len(filtered) != 1 {
		t.Errorf("expected 1 template, got %d", len(filtered))
	}
	if filtered[0].ID != "t1" {
		t.Errorf("expected t1, got %s", filtered[0].ID)
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"http://example.com", "example.com"},
		{"https://example.com/path", "example.com"},
		{"https://example.com:8080/path", "example.com"},
		{"example.com", "example.com"},
	}

	for _, tc := range tests {
		got := extractHostname(tc.url)
		if got != tc.expected {
			t.Errorf("extractHostname(%s) = %s, want %s", tc.url, got, tc.expected)
		}
	}
}

func TestMatchWords_And(t *testing.T) {
	content := "hello world foo bar"

	// AND - all must match
	if !matchWords([]string{"hello", "world"}, content, "and", false) {
		t.Error("expected AND match")
	}
	if matchWords([]string{"hello", "missing"}, content, "and", false) {
		t.Error("expected AND not to match")
	}
}

func TestMatchWords_Or(t *testing.T) {
	content := "hello world"

	// OR - any must match
	if !matchWords([]string{"hello", "missing"}, content, "or", false) {
		t.Error("expected OR match")
	}
	if matchWords([]string{"foo", "bar"}, content, "or", false) {
		t.Error("expected OR not to match")
	}
}

func TestMatchStatus(t *testing.T) {
	if !matchStatus([]int{200, 201, 204}, 200, "") {
		t.Error("expected status match")
	}
	if matchStatus([]int{200, 201}, 404, "") {
		t.Error("expected status not to match")
	}
}

func TestMatchRegex(t *testing.T) {
	content := "version 1.2.3"

	if !matchRegex([]string{`[0-9]+\.[0-9]+\.[0-9]+`}, content, "") {
		t.Error("expected regex match")
	}
	if matchRegex([]string{`[a-z]+:[0-9]+`}, content, "") {
		t.Error("expected regex not to match")
	}
}

func TestDSLStatusCode(t *testing.T) {
	tests := []struct {
		expr   string
		code   int
		expect bool
	}{
		{"status_code == 200", 200, true},
		{"status_code == 200", 404, false},
		{"status_code != 404", 200, true},
		{"status_code > 300", 404, true},
		{"status_code < 300", 200, true},
		{"status_code >= 200", 200, true},
		{"status_code <= 200", 200, true},
	}

	for _, tc := range tests {
		got := evaluateDSLStatusCode(tc.expr, tc.code)
		if got != tc.expect {
			t.Errorf("evaluateDSLStatusCode(%q, %d) = %v, want %v", tc.expr, tc.code, got, tc.expect)
		}
	}
}

func TestDSLContains(t *testing.T) {
	tests := []struct {
		expr    string
		content string
		expect  bool
	}{
		{`contains(body, "hello")`, "hello world", true},
		{`contains(body, "missing")`, "hello world", false},
	}

	for _, tc := range tests {
		got := evaluateDSLContains(tc.expr, tc.content)
		if got != tc.expect {
			t.Errorf("evaluateDSLContains(%q) = %v, want %v", tc.expr, got, tc.expect)
		}
	}
}
