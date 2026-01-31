package js

import (
	"strings"
	"testing"
)

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()
	if analyzer == nil {
		t.Fatal("expected non-nil analyzer")
	}
	if len(analyzer.URLPatterns) == 0 {
		t.Error("URL patterns should be initialized")
	}
	if len(analyzer.SecretPatterns) == 0 {
		t.Error("secret patterns should be initialized")
	}
	if len(analyzer.EndpointPatterns) == 0 {
		t.Error("endpoint patterns should be initialized")
	}
	if len(analyzer.DOMSinkPatterns) == 0 {
		t.Error("DOM sink patterns should be initialized")
	}
	if len(analyzer.CloudPatterns) == 0 {
		t.Error("cloud patterns should be initialized")
	}
}

func TestExtractURLs(t *testing.T) {
	code := `
		const apiUrl = "https://api.example.com/v1/users";
		fetch("/api/data");
		const path = '/users/123';
		const external = "//cdn.example.org/lib.js";
	`

	analyzer := NewAnalyzer()
	urls := analyzer.ExtractURLs(code)

	if len(urls) < 3 {
		t.Errorf("expected at least 3 URLs, got %d", len(urls))
	}

	// Check for absolute URL
	hasAbsolute := false
	for _, u := range urls {
		if u.Type == "absolute" && strings.Contains(u.URL, "api.example.com") {
			hasAbsolute = true
			break
		}
	}
	if !hasAbsolute {
		t.Error("should find absolute URL")
	}

	// Check for relative URL
	hasRelative := false
	for _, u := range urls {
		if u.Type == "relative" {
			hasRelative = true
			break
		}
	}
	if !hasRelative {
		t.Error("should find relative URL")
	}
}

func TestExtractEndpoints(t *testing.T) {
	code := `
		fetch("/api/users");
		axios.get("/api/products");
		axios.post("/api/orders", data);
		$.ajax("/legacy/endpoint");
		xhr.open("PUT", "/api/items/123");
	`

	analyzer := NewAnalyzer()
	endpoints := analyzer.ExtractEndpoints(code)

	if len(endpoints) < 3 {
		t.Errorf("expected at least 3 endpoints, got %d", len(endpoints))
	}

	// Check for fetch endpoint
	hasFetch := false
	for _, e := range endpoints {
		if e.Source == "fetch" && strings.Contains(e.Path, "users") {
			hasFetch = true
			break
		}
	}
	if !hasFetch {
		t.Error("should find fetch endpoint")
	}

	// Check for axios with method
	hasAxiosPost := false
	for _, e := range endpoints {
		if e.Source == "axios" && e.Method == "POST" {
			hasAxiosPost = true
			break
		}
	}
	if !hasAxiosPost {
		t.Error("should find axios POST endpoint")
	}
}

func TestExtractSecrets(t *testing.T) {
	code := `
		const awsKey = "AKIAIOSFODNN7EXAMPLE";
		const googleKey = "AIzaSyDfGhJkLmNoPqRsTuVwXyZ123456789";
		const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
		const stripe = "sk_test_FAKE123456789abcdef";
		const github = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
	`

	analyzer := NewAnalyzer()
	secrets := analyzer.ExtractSecrets(code)

	if len(secrets) < 3 {
		t.Errorf("expected at least 3 secrets, got %d", len(secrets))
		for _, s := range secrets {
			t.Logf("found: %s = %s", s.Type, s.Value[:min(len(s.Value), 20)])
		}
	}

	// Check for AWS key
	hasAWS := false
	for _, s := range secrets {
		if s.Type == "aws_access_key" {
			hasAWS = true
			break
		}
	}
	if !hasAWS {
		t.Error("should find AWS access key")
	}

	// Check for JWT
	hasJWT := false
	for _, s := range secrets {
		if s.Type == "jwt_token" {
			hasJWT = true
			break
		}
	}
	if !hasJWT {
		t.Error("should find JWT token")
	}
}

func TestExtractVariables(t *testing.T) {
	code := `
		const apiKey = "my-api-key-12345678";
		let authToken = "bearer-token-value";
		var baseUrl = "https://api.example.com";
		const config = { key: "value" };
	`

	analyzer := NewAnalyzer()
	variables := analyzer.ExtractVariables(code)

	// Should find some variables
	if len(variables) < 1 {
		t.Errorf("expected at least 1 variable, got %d", len(variables))
	}
}

func TestFindDOMSinks(t *testing.T) {
	code := `
		document.getElementById("output").innerHTML = userInput;
		eval(code);
		document.write("<script>" + data + "</script>");
		location.href = redirectUrl;
		setTimeout("alert(1)", 100);
		$(".container").html(response);
	`

	analyzer := NewAnalyzer()
	sinks := analyzer.FindDOMSinks(code)

	if len(sinks) < 4 {
		t.Errorf("expected at least 4 DOM sinks, got %d", len(sinks))
		for _, s := range sinks {
			t.Logf("found: %s (severity: %s)", s.Sink, s.Severity)
		}
	}

	// Check for innerHTML (high severity)
	hasInnerHTML := false
	for _, s := range sinks {
		if strings.Contains(s.Sink, "innerHTML") && s.Severity == "high" {
			hasInnerHTML = true
			break
		}
	}
	if !hasInnerHTML {
		t.Error("should find innerHTML as high severity sink")
	}

	// Check for eval (high severity)
	hasEval := false
	for _, s := range sinks {
		if strings.Contains(s.Sink, "eval") && s.Severity == "high" {
			hasEval = true
			break
		}
	}
	if !hasEval {
		t.Error("should find eval as high severity sink")
	}
}

func TestExtractCloudURLs(t *testing.T) {
	code := `
		const s3Bucket = "https://mybucket.s3.amazonaws.com/file.json";
		const gcsBucket = "https://storage.googleapis.com/mybucket/file.json";
		const azureBlob = "https://myaccount.blob.core.windows.net/container/file";
		const firebase = "https://myapp.firebaseio.com/data";
		const heroku = "https://myapp.herokuapp.com/api";
	`

	analyzer := NewAnalyzer()
	cloudURLs := analyzer.ExtractCloudURLs(code)

	if len(cloudURLs) < 4 {
		t.Errorf("expected at least 4 cloud URLs, got %d", len(cloudURLs))
		for _, c := range cloudURLs {
			t.Logf("found: %s (%s)", c.URL, c.Service)
		}
	}

	// Check for AWS
	hasAWS := false
	for _, c := range cloudURLs {
		if c.Service == "aws" {
			hasAWS = true
			break
		}
	}
	if !hasAWS {
		t.Error("should find AWS cloud URL")
	}

	// Check for GCP
	hasGCP := false
	for _, c := range cloudURLs {
		if c.Service == "gcp" {
			hasGCP = true
			break
		}
	}
	if !hasGCP {
		t.Error("should find GCP cloud URL")
	}
}

func TestExtractSubdomains(t *testing.T) {
	code := `
		const api = "https://api.example.com/v1";
		const cdn = "https://cdn.example.com/assets";
		const internal = "https://internal.example.com/admin";
		const google = "https://fonts.googleapis.com/css"; // Should be filtered as CDN
	`

	analyzer := NewAnalyzer()
	subdomains := analyzer.ExtractSubdomains(code)

	if len(subdomains) < 2 {
		t.Errorf("expected at least 2 subdomains, got %d", len(subdomains))
	}

	// Should filter out googleapis.com as CDN
	for _, s := range subdomains {
		if strings.Contains(s, "googleapis.com") {
			t.Error("should filter out googleapis.com as CDN")
		}
	}
}

func TestAnalyze(t *testing.T) {
	code := `
		// Full analysis test
		const apiKey = "AKIAIOSFODNN7EXAMPLE";
		fetch("https://api.example.com/users");
		document.getElementById("output").innerHTML = data;
		const bucket = "https://mybucket.s3.amazonaws.com/file.json";
	`

	analyzer := NewAnalyzer()
	data := analyzer.Analyze(code)

	if data == nil {
		t.Fatal("expected non-nil data")
	}

	// Should have findings in multiple categories
	if len(data.URLs) == 0 {
		t.Error("should find URLs")
	}
	if len(data.Secrets) == 0 {
		t.Error("should find secrets")
	}
	if len(data.DOMSinks) == 0 {
		t.Error("should find DOM sinks")
	}
	if len(data.CloudURLs) == 0 {
		t.Error("should find cloud URLs")
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		input  string
		minEnt float64
		maxEnt float64
	}{
		{"aaaa", 0, 1},       // Low entropy
		{"abcd", 1.5, 3},     // Medium entropy
		{"a1b2c3d4", 2.5, 4}, // Higher entropy
		{"", 0, 0},           // Empty
	}

	for _, tt := range tests {
		entropy := calculateEntropy(tt.input)
		if entropy < tt.minEnt || entropy > tt.maxEnt {
			t.Errorf("entropy(%s) = %f, want between %f and %f", tt.input, entropy, tt.minEnt, tt.maxEnt)
		}
	}
}

func TestExtractParams(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		url           string
		expectedCount int
	}{
		{"/api/users?page=1&limit=10", 2},
		{"/api/users/:id", 1},
		{"/api/users/{userId}/posts/{postId}", 2},
		{"/api/simple", 0},
	}

	for _, tt := range tests {
		params := analyzer.extractParams(tt.url)
		if len(params) != tt.expectedCount {
			t.Errorf("extractParams(%s) got %d params, want %d: %v", tt.url, len(params), tt.expectedCount, params)
		}
	}
}

func TestIsCommonCDN(t *testing.T) {
	cdns := []string{
		"fonts.googleapis.com",
		"ajax.googleapis.com",
		"cdn.jsdelivr.net",
		"cdnjs.cloudflare.com",
	}

	for _, cdn := range cdns {
		if !isCommonCDN(cdn) {
			t.Errorf("%s should be identified as CDN", cdn)
		}
	}

	nonCDNs := []string{
		"api.example.com",
		"internal.company.com",
	}

	for _, nonCDN := range nonCDNs {
		if isCommonCDN(nonCDN) {
			t.Errorf("%s should not be identified as CDN", nonCDN)
		}
	}
}

func TestServiceCategory(t *testing.T) {
	tests := []struct {
		service  string
		expected string
	}{
		{"s3", "aws"},
		{"cloudfront", "aws"},
		{"gcs", "gcp"},
		{"firebase", "gcp"},
		{"azure_blob", "azure"},
		{"heroku", "heroku"},
	}

	for _, tt := range tests {
		result := serviceCategory(tt.service)
		if result != tt.expected {
			t.Errorf("serviceCategory(%s) = %s, want %s", tt.service, result, tt.expected)
		}
	}
}

func TestExtractedDataToJSON(t *testing.T) {
	data := &ExtractedData{
		URLs: []URLInfo{
			{URL: "/api/test", Type: "relative"},
		},
		Secrets: []SecretInfo{
			{Type: "api_key", Value: "test123", Confidence: "low"},
		},
	}

	json, err := data.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	if len(json) == 0 {
		t.Error("JSON should not be empty")
	}

	if !strings.Contains(string(json), "api/test") {
		t.Error("JSON should contain URL")
	}
}

func TestExtractedDataSummary(t *testing.T) {
	data := &ExtractedData{
		URLs:       make([]URLInfo, 5),
		Endpoints:  make([]EndpointInfo, 3),
		Secrets:    make([]SecretInfo, 2),
		DOMSinks:   make([]DOMSinkInfo, 4),
		CloudURLs:  make([]CloudURL, 1),
		Subdomains: []string{"api.example.com", "cdn.example.com"},
	}

	summary := data.Summary()

	if !strings.Contains(summary, "URLs: 5") {
		t.Error("summary should contain URLs count")
	}
	if !strings.Contains(summary, "Endpoints: 3") {
		t.Error("summary should contain Endpoints count")
	}
	if !strings.Contains(summary, "Secrets: 2") {
		t.Error("summary should contain Secrets count")
	}
}

func TestIntToString(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{123, "123"},
		{-5, "-5"},
	}

	for _, tt := range tests {
		result := intToString(tt.input)
		if result != tt.expected {
			t.Errorf("intToString(%d) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
