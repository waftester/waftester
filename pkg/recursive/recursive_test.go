package recursive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MaxDepth != 3 {
		t.Errorf("expected MaxDepth 3, got %d", config.MaxDepth)
	}
	if config.Concurrency != 10 {
		t.Errorf("expected Concurrency 10, got %d", config.Concurrency)
	}
	if config.Timeout != httpclient.TimeoutProbing {
		t.Errorf("expected Timeout %v, got %v", httpclient.TimeoutProbing, config.Timeout)
	}
	if len(config.Extensions) == 0 {
		t.Error("expected extensions")
	}
	if !config.FollowLinks {
		t.Error("expected FollowLinks true")
	}
	if len(config.SuccessCodes) == 0 {
		t.Error("expected success codes")
	}
}

func TestNewFuzzer(t *testing.T) {
	config := DefaultConfig()
	config.Wordlist = []string{"admin", "api"}

	fuzzer, err := NewFuzzer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fuzzer == nil {
		t.Fatal("NewFuzzer returned nil")
	}
}

func TestNewFuzzer_Defaults(t *testing.T) {
	config := Config{}
	config.Wordlist = []string{"test"}

	fuzzer, err := NewFuzzer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fuzzer.config.MaxDepth != 3 {
		t.Error("should use default MaxDepth")
	}
	if fuzzer.config.Concurrency != 10 {
		t.Error("should use default Concurrency")
	}
}

func TestNewFuzzer_InvalidExcludeRegex(t *testing.T) {
	config := DefaultConfig()
	config.ExcludeRegex = "[invalid"

	_, err := NewFuzzer(config)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestNewFuzzer_InvalidIncludeRegex(t *testing.T) {
	config := DefaultConfig()
	config.IncludeRegex = "[invalid"

	_, err := NewFuzzer(config)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestNewFuzzer_ValidRegex(t *testing.T) {
	config := DefaultConfig()
	config.ExcludeRegex = `\.gif$`
	config.IncludeRegex = `^/api/`

	fuzzer, err := NewFuzzer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fuzzer.excludeRegex == nil {
		t.Error("excludeRegex should be set")
	}
	if fuzzer.includeRegex == nil {
		t.Error("includeRegex should be set")
	}
}

func TestFuzzer_isSuccess(t *testing.T) {
	config := DefaultConfig()
	fuzzer, _ := NewFuzzer(config)

	tests := []struct {
		code     int
		expected bool
	}{
		{200, true},
		{201, true},
		{204, true},
		{301, true},
		{302, true},
		{401, true},
		{403, true},
		{404, false},
		{500, false},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.code), func(t *testing.T) {
			if fuzzer.isSuccess(tt.code) != tt.expected {
				t.Errorf("isSuccess(%d) = %v, want %v", tt.code, !tt.expected, tt.expected)
			}
		})
	}
}

func TestFuzzer_isDirectory(t *testing.T) {
	config := DefaultConfig()
	fuzzer, _ := NewFuzzer(config)

	tests := []struct {
		name     string
		result   Result
		expected bool
	}{
		{
			"redirect to slash",
			Result{StatusCode: 301, Redirect: "/admin/"},
			true,
		},
		{
			"redirect without slash",
			Result{StatusCode: 301, Redirect: "/file.txt"},
			false,
		},
		{
			"html content",
			Result{StatusCode: 200, ContentType: "text/html"},
			true,
		},
		{
			"json content",
			Result{StatusCode: 200, ContentType: "application/json"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if fuzzer.isDirectory(tt.result) != tt.expected {
				t.Errorf("isDirectory() = %v, want %v", !tt.expected, tt.expected)
			}
		})
	}
}

func TestFuzzer_GetStats(t *testing.T) {
	config := DefaultConfig()
	fuzzer, _ := NewFuzzer(config)
	fuzzer.startTime = time.Now()

	stats := fuzzer.GetStats()
	if stats.TotalRequests != 0 {
		t.Error("expected 0 requests")
	}
}

func TestFuzzer_GetResults(t *testing.T) {
	config := DefaultConfig()
	fuzzer, _ := NewFuzzer(config)

	results := fuzzer.GetResults()
	if results == nil {
		t.Error("expected non-nil results")
	}
}

func TestFuzzer_Stop(t *testing.T) {
	config := DefaultConfig()
	fuzzer, _ := NewFuzzer(config)

	// Should not panic
	fuzzer.Stop()

	// Set up real context
	ctx, cancel := context.WithCancel(context.Background())
	fuzzer.cancel = cancel
	fuzzer.Stop()

	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("context should be cancelled")
	}
}

func TestFuzzer_Run(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Home"))
		case "/admin":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin"))
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Wordlist = []string{"admin", "api", "missing"}
	config.MaxDepth = 1
	config.Delay = 0

	fuzzer, err := NewFuzzer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := fuzzer.Run(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) < 2 {
		t.Errorf("expected at least 2 results, got %d", len(results))
	}

	stats := fuzzer.GetStats()
	if stats.Found == 0 {
		t.Error("expected some findings")
	}
}

func TestNewLinkExtractor(t *testing.T) {
	extractor, err := NewLinkExtractor("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if extractor == nil {
		t.Fatal("NewLinkExtractor returned nil")
	}
}

func TestNewLinkExtractor_InvalidURL(t *testing.T) {
	_, err := NewLinkExtractor("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestLinkExtractor_Extract(t *testing.T) {
	extractor, _ := NewLinkExtractor("https://example.com")

	html := `
		<a href="/page1">Page 1</a>
		<a href="/page2">Page 2</a>
		<img src="/img/logo.png">
		<form action="/submit">
		<a href="https://example.com/internal">Internal</a>
		<a href="https://other.com/external">External</a>
		<a href="javascript:void(0)">JS</a>
		<a href="mailto:test@example.com">Email</a>
		<a href="#anchor">Anchor</a>
	`

	links := extractor.Extract(html)

	if len(links) < 4 {
		t.Errorf("expected at least 4 links, got %d", len(links))
	}

	// Should not include external or special links
	for _, link := range links {
		if link == "https://other.com/external" {
			t.Error("should not include external links")
		}
		if link == "javascript:void(0)" {
			t.Error("should not include javascript links")
		}
	}
}

func TestLinkExtractor_normalizeLink(t *testing.T) {
	extractor, _ := NewLinkExtractor("https://example.com/path/")

	tests := []struct {
		input    string
		expected string
	}{
		{"/absolute", "https://example.com/absolute"},
		{"relative", "https://example.com/path/relative"},
		{"../parent", "https://example.com/parent"},
		{"https://example.com/full", "https://example.com/full"},
		{"https://other.com/external", ""}, // External
		{"javascript:void(0)", ""},
		{"mailto:test@test.com", ""},
		{"#anchor", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractor.normalizeLink(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeLink(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCommonWordlists(t *testing.T) {
	if len(CommonWordlists) == 0 {
		t.Error("expected wordlists")
	}

	for name, words := range CommonWordlists {
		if len(words) == 0 {
			t.Errorf("wordlist %s is empty", name)
		}
	}

	if _, ok := CommonWordlists["common"]; !ok {
		t.Error("expected 'common' wordlist")
	}
	if _, ok := CommonWordlists["api"]; !ok {
		t.Error("expected 'api' wordlist")
	}
}

func TestNewResultAnalyzer(t *testing.T) {
	results := []Result{{URL: "http://test.com"}}
	analyzer := NewResultAnalyzer(results)

	if analyzer == nil {
		t.Fatal("NewResultAnalyzer returned nil")
	}
	if len(analyzer.results) != 1 {
		t.Error("results not stored")
	}
}

func TestResultAnalyzer_GroupByStatusCode(t *testing.T) {
	results := []Result{
		{StatusCode: 200},
		{StatusCode: 200},
		{StatusCode: 404},
		{StatusCode: 301},
	}

	analyzer := NewResultAnalyzer(results)
	groups := analyzer.GroupByStatusCode()

	if len(groups[200]) != 2 {
		t.Errorf("expected 2 200s, got %d", len(groups[200]))
	}
	if len(groups[404]) != 1 {
		t.Errorf("expected 1 404, got %d", len(groups[404]))
	}
}

func TestResultAnalyzer_GroupByContentType(t *testing.T) {
	results := []Result{
		{ContentType: "text/html; charset=utf-8"},
		{ContentType: "text/html"},
		{ContentType: "application/json"},
	}

	analyzer := NewResultAnalyzer(results)
	groups := analyzer.GroupByContentType()

	if len(groups["text/html"]) != 2 {
		t.Errorf("expected 2 text/html, got %d", len(groups["text/html"]))
	}
}

func TestResultAnalyzer_FindInteresting(t *testing.T) {
	results := []Result{
		{Path: "/admin"},
		{Path: "/index.html"},
		{Path: "/.git/config"},
		{Path: "/api/v1/users"},
		{Path: "/style.css"},
	}

	analyzer := NewResultAnalyzer(results)
	interesting := analyzer.FindInteresting()

	if len(interesting) < 3 {
		t.Errorf("expected at least 3 interesting, got %d", len(interesting))
	}
}

func TestResultAnalyzer_Summary(t *testing.T) {
	results := []Result{
		{StatusCode: 200, ContentType: "text/html", Path: "/admin"},
		{StatusCode: 200, ContentType: "application/json"},
		{StatusCode: 404},
	}

	analyzer := NewResultAnalyzer(results)
	summary := analyzer.Summary()

	if summary["total"] != 3 {
		t.Errorf("expected total 3, got %v", summary["total"])
	}
	if summary["interesting"].(int) < 1 {
		t.Error("expected interesting findings")
	}
}

func TestResultAnalyzer_SortByLength(t *testing.T) {
	results := []Result{
		{Length: 100},
		{Length: 500},
		{Length: 200},
	}

	analyzer := NewResultAnalyzer(results)
	sorted := analyzer.SortByLength()

	if sorted[0].Length != 500 {
		t.Error("should be sorted by length descending")
	}
	if sorted[2].Length != 100 {
		t.Error("should be sorted by length descending")
	}
}

func TestResultAnalyzer_Filter(t *testing.T) {
	results := []Result{
		{StatusCode: 200},
		{StatusCode: 404},
		{StatusCode: 200},
	}

	analyzer := NewResultAnalyzer(results)
	filtered := analyzer.Filter(func(r Result) bool {
		return r.StatusCode == 200
	})

	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered results, got %d", len(filtered))
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "http://example.com/admin",
		Path:        "/admin",
		StatusCode:  200,
		ContentType: "text/html",
		Length:      1234,
		Depth:       2,
		FoundIn:     "http://example.com",
		Method:      "GET",
		Redirect:    "",
		Headers:     map[string]string{"Server": "nginx"},
		Timestamp:   time.Now(),
		Tags:        []string{"interesting"},
	}

	if result.URL != "http://example.com/admin" {
		t.Error("URL field incorrect")
	}
	if result.StatusCode != 200 {
		t.Error("StatusCode field incorrect")
	}
}

func TestStats_Fields(t *testing.T) {
	stats := Stats{
		TotalRequests: 100,
		Found:         10,
		Errors:        5,
		CurrentDepth:  2,
		Duration:      5 * time.Second,
		Rate:          20.0,
	}

	if stats.TotalRequests != 100 {
		t.Error("TotalRequests field incorrect")
	}
	if stats.Rate != 20.0 {
		t.Error("Rate field incorrect")
	}
}

func TestFuzzer_addTask(t *testing.T) {
	config := DefaultConfig()
	fuzzer, _ := NewFuzzer(config)

	// First add should succeed
	ok := fuzzer.addTask("http://example.com/", "admin", 0, "")
	if !ok {
		t.Error("first addTask should succeed")
	}

	// Duplicate should fail
	ok = fuzzer.addTask("http://example.com/", "admin", 0, "")
	if ok {
		t.Error("duplicate addTask should fail")
	}
}

func TestFuzzer_addTask_Filters(t *testing.T) {
	config := DefaultConfig()
	config.ExcludeRegex = `\.gif$`
	fuzzer, _ := NewFuzzer(config)

	// Should be excluded
	ok := fuzzer.addTask("http://example.com/", "image.gif", 0, "")
	if ok {
		t.Error("excluded URL should not be added")
	}
}
