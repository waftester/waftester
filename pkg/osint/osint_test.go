package osint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.clients == nil {
		t.Error("clients map not initialized")
	}
	if m.configs == nil {
		t.Error("configs map not initialized")
	}
	if m.results == nil {
		t.Error("results slice not initialized")
	}
	if m.rateLimit == nil {
		t.Error("rateLimit not initialized")
	}
}

func TestRegisterSource_CrtshNoKey(t *testing.T) {
	m := NewManager()
	config := SourceConfig{
		Source:  SourceCrtsh,
		Enabled: true,
	}
	err := m.RegisterSource(config)
	if err != nil {
		t.Fatalf("crt.sh should not require API key: %v", err)
	}
	sources := m.GetSources()
	if len(sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(sources))
	}
}

func TestRegisterSource_ShodanRequiresKey(t *testing.T) {
	m := NewManager()
	config := SourceConfig{
		Source:  SourceShodan,
		Enabled: true,
		APIKey:  "", // Missing key
	}
	err := m.RegisterSource(config)
	if err == nil {
		t.Error("expected error for missing Shodan API key")
	}
}

func TestRegisterSource_DisabledSource(t *testing.T) {
	m := NewManager()
	config := SourceConfig{
		Source:  SourceShodan,
		Enabled: false,
	}
	err := m.RegisterSource(config)
	if err != nil {
		t.Errorf("disabled source should not error: %v", err)
	}
	sources := m.GetSources()
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

func TestRegisterSource_UnknownSource(t *testing.T) {
	m := NewManager()
	config := SourceConfig{
		Source:  Source("unknown"),
		Enabled: true,
	}
	err := m.RegisterSource(config)
	if err == nil {
		t.Error("expected error for unknown source")
	}
}

func TestShodanClient_Validate(t *testing.T) {
	tests := []struct {
		name    string
		apiKey  string
		wantErr bool
	}{
		{"with key", "test-key", false},
		{"without key", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewShodanClient(tt.apiKey)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestShodanClient_Name(t *testing.T) {
	c := NewShodanClient("test-key")
	if c.Name() != SourceShodan {
		t.Errorf("expected %s, got %s", SourceShodan, c.Name())
	}
}

func TestCensysClient_Validate(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    string
		apiSecret string
		wantErr   bool
	}{
		{"both set", "key", "secret", false},
		{"missing key", "", "secret", true},
		{"missing secret", "key", "", true},
		{"both missing", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCensysClient(tt.apiKey, tt.apiSecret)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCrtshClient_Validate(t *testing.T) {
	c := NewCrtshClient()
	if err := c.Validate(); err != nil {
		t.Errorf("crt.sh should not require validation: %v", err)
	}
}

func TestCrtshClient_Name(t *testing.T) {
	c := NewCrtshClient()
	if c.Name() != SourceCrtsh {
		t.Errorf("expected %s, got %s", SourceCrtsh, c.Name())
	}
}

func TestSecurityTrailsClient_Validate(t *testing.T) {
	c := NewSecurityTrailsClient("")
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing key")
	}

	c = NewSecurityTrailsClient("test-key")
	if err := c.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDNSDumpsterClient_Validate(t *testing.T) {
	c := NewDNSDumpsterClient()
	if err := c.Validate(); err != nil {
		t.Errorf("DNSDumpster should not require validation: %v", err)
	}
}

func TestChaosClient_Validate(t *testing.T) {
	c := NewChaosClient("")
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing key")
	}
}

func TestBinaryEdgeClient_Validate(t *testing.T) {
	c := NewBinaryEdgeClient("")
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing key")
	}
}

func TestFullHuntClient_Validate(t *testing.T) {
	c := NewFullHuntClient("")
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing key")
	}
}

func TestCrtshClient_FetchSubdomains(t *testing.T) {
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"name_value": "api.example.com"},
			{"name_value": "*.example.com\nwww.example.com"},
			{"name_value": "mail.example.com"}
		]`))
	}))
	defer server.Close()

	c := &CrtshClient{
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) < 3 {
		t.Errorf("expected at least 3 results, got %d", len(results))
	}

	// Check all results are for correct domain
	for _, r := range results {
		if r.Source != SourceCrtsh {
			t.Errorf("wrong source: %s", r.Source)
		}
		if r.Type != "subdomain" {
			t.Errorf("wrong type: %s", r.Type)
		}
	}
}

func TestCrtshClient_FetchSubdomains_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	c := &CrtshClient{
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestShodanClient_FetchSubdomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns/domain/example.com" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"subdomains": ["api", "www", "mail"]}`))
	}))
	defer server.Close()

	c := &ShodanClient{
		apiKey:     "test-key",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	expected := []string{"api.example.com", "www.example.com", "mail.example.com"}
	for i, r := range results {
		if r.Value != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], r.Value)
		}
	}
}

func TestShodanClient_FetchIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"example.com": "93.184.216.34"}`))
	}))
	defer server.Close()

	c := &ShodanClient{
		apiKey:     "test-key",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchIPs(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if results[0].Value != "93.184.216.34" {
		t.Errorf("wrong IP: %s", results[0].Value)
	}
}

func TestShodanClient_FetchPorts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ports": [22, 80, 443]}`))
	}))
	defer server.Close()

	c := &ShodanClient{
		apiKey:     "test-key",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchPorts(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	expected := []string{"22", "80", "443"}
	for i, r := range results {
		if r.Value != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], r.Value)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(100)

	// Should be able to get tokens immediately
	start := time.Now()
	for i := 0; i < 10; i++ {
		limiter.Wait()
	}
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("first 10 tokens should be instant, took %v", elapsed)
	}
}

func TestDeduplicateResults(t *testing.T) {
	results := []Result{
		{Source: SourceCrtsh, Type: "subdomain", Value: "api.example.com"},
		{Source: SourceCrtsh, Type: "subdomain", Value: "api.example.com"},  // Duplicate
		{Source: SourceShodan, Type: "subdomain", Value: "api.example.com"}, // Different source
		{Source: SourceCrtsh, Type: "subdomain", Value: "www.example.com"},
	}

	unique := deduplicateResults(results)
	if len(unique) != 3 {
		t.Errorf("expected 3 unique results, got %d", len(unique))
	}
}

func TestExtractDomainFromURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"https://example.com", "example.com", false},
		{"http://api.example.com/path", "api.example.com", false},
		{"example.com", "example.com", false},
		{"www.example.com:8080", "www.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ExtractDomainFromURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a.b.c.example.com", true},
		{"example", false},
		{"-example.com", false},
		{"example-.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if IsValidDomain(tt.domain) != tt.valid {
				t.Errorf("IsValidDomain(%s) = %v, want %v", tt.domain, !tt.valid, tt.valid)
			}
		})
	}
}

func TestManager_GetResults(t *testing.T) {
	m := NewManager()

	// Initially empty
	results := m.GetResults()
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestManager_Clear(t *testing.T) {
	m := NewManager()
	m.results = []Result{{Value: "test"}}

	m.Clear()

	if len(m.results) != 0 {
		t.Errorf("expected 0 results after clear, got %d", len(m.results))
	}
}

func TestSecurityTrailsClient_FetchSubdomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") == "" {
			t.Error("missing APIKEY header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"subdomains": ["api", "www"]}`))
	}))
	defer server.Close()

	c := &SecurityTrailsClient{
		apiKey:     "test-key",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestBinaryEdgeClient_FetchSubdomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key") == "" {
			t.Error("missing X-Key header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"events": ["api.example.com", "www.example.com"]}`))
	}))
	defer server.Close()

	c := &BinaryEdgeClient{
		apiKey:     "test-key",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestFullHuntClient_FetchSubdomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") == "" {
			t.Error("missing X-API-KEY header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hosts": ["api.example.com", "www.example.com"]}`))
	}))
	defer server.Close()

	c := &FullHuntClient{
		apiKey:     "test-key",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestChaosClient_FetchSubdomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("missing Authorization header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"subdomains": ["api", "www"]}`))
	}))
	defer server.Close()

	c := &ChaosClient{
		apiKey:     "test-key",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestCensysClient_FetchSubdomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user == "" || pass == "" {
			t.Error("missing basic auth")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"hits": [{"name": "api.example.com"}, {"name": "www.example.com"}]}}`))
	}))
	defer server.Close()

	c := &CensysClient{
		apiKey:     "test-key",
		apiSecret:  "test-secret",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	results, err := c.FetchSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestShodanClient_FetchSubdomains_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := &ShodanClient{
		apiKey:     "invalid-key",
		httpClient: httpclient.Default(),
		baseURL:    server.URL,
	}

	_, err := c.FetchSubdomains(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error for HTTP 401")
	}
}

func TestSourceConstants(t *testing.T) {
	sources := []Source{
		SourceShodan,
		SourceCensys,
		SourceCrtsh,
		SourceSecurityTrails,
		SourceDNSDumpster,
		SourceChaos,
		SourceWayback,
		SourceCommonCrawl,
		SourceOTX,
		SourceVirusTotal,
		SourceBinaryEdge,
		SourceFullHunt,
		SourceHunterIO,
		SourceZoomEye,
		SourceFofa,
	}

	seen := make(map[Source]bool)
	for _, s := range sources {
		if seen[s] {
			t.Errorf("duplicate source constant: %s", s)
		}
		seen[s] = true
	}
}
