package browser

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestProfiles(t *testing.T) {
	profiles := AllProfiles()
	if len(profiles) == 0 {
		t.Error("AllProfiles should return profiles")
	}

	// Check each profile has required fields
	for _, p := range profiles {
		if p.Name == "" {
			t.Error("Profile should have a name")
		}
		if p.UserAgent == "" {
			t.Error("Profile should have a user agent")
		}
	}
}

func TestChromeProfile(t *testing.T) {
	if Chrome.Name != "Chrome" {
		t.Errorf("Chrome.Name = %s, want Chrome", Chrome.Name)
	}
	if Chrome.UserAgent == "" {
		t.Error("Chrome should have a user agent")
	}
	if len(Chrome.Headers) == 0 {
		t.Error("Chrome should have headers")
	}
	if _, ok := Chrome.Headers["Accept"]; !ok {
		t.Error("Chrome should have Accept header")
	}
}

func TestFirefoxProfile(t *testing.T) {
	if Firefox.Name != "Firefox" {
		t.Errorf("Firefox.Name = %s, want Firefox", Firefox.Name)
	}
	if Firefox.UserAgent == "" {
		t.Error("Firefox should have a user agent")
	}
}

func TestSafariProfile(t *testing.T) {
	if Safari.Name != "Safari" {
		t.Errorf("Safari.Name = %s, want Safari", Safari.Name)
	}
}

func TestEdgeProfile(t *testing.T) {
	if Edge.Name != "Edge" {
		t.Errorf("Edge.Name = %s, want Edge", Edge.Name)
	}
}

func TestMobileProfile(t *testing.T) {
	if Mobile.Name != "Mobile" {
		t.Errorf("Mobile.Name = %s, want Mobile", Mobile.Name)
	}
}

func TestBotProfile(t *testing.T) {
	if Bot.Name != "Googlebot" {
		t.Errorf("Bot.Name = %s, want Googlebot", Bot.Name)
	}
}

func TestNewClient(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	if client.profile != Chrome {
		t.Error("Default profile should be Chrome")
	}
	if client.timeout != 30*time.Second {
		t.Errorf("Default timeout = %v, want 30s", client.timeout)
	}
}

func TestClientOptions(t *testing.T) {
	client, err := NewClient(
		WithProfile(Firefox),
		WithTimeout(10*time.Second),
		WithRetries(3),
		WithRetryDelay(500*time.Millisecond),
		WithFollowRedirects(false),
		WithMaxRedirects(5),
		WithBaseURL("http://example.com"),
	)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	if client.profile != Firefox {
		t.Error("Profile should be Firefox")
	}
	if client.timeout != 10*time.Second {
		t.Error("Timeout should be 10s")
	}
	if client.retries != 3 {
		t.Error("Retries should be 3")
	}
	if client.retryDelay != 500*time.Millisecond {
		t.Error("RetryDelay should be 500ms")
	}
	if client.followRedir {
		t.Error("FollowRedirects should be false")
	}
	if client.maxRedirs != 5 {
		t.Error("MaxRedirects should be 5")
	}
	if client.baseURL != "http://example.com" {
		t.Error("BaseURL mismatch")
	}
}

func TestRequest(t *testing.T) {
	req := &Request{
		Method:      "POST",
		URL:         "/api/test",
		Headers:     map[string]string{"X-Custom": "value"},
		BodyString:  `{"test": true}`,
		ContentType: "application/json",
		Referer:     "http://example.com/page",
		Origin:      "http://example.com",
		XHR:         true,
	}

	if req.Method != "POST" {
		t.Error("Method mismatch")
	}
	if req.URL != "/api/test" {
		t.Error("URL mismatch")
	}
	if req.ContentType != "application/json" {
		t.Error("ContentType mismatch")
	}
	if !req.XHR {
		t.Error("XHR should be true")
	}
}

func TestResponse(t *testing.T) {
	resp := &Response{
		StatusCode:    200,
		Status:        "200 OK",
		Headers:       http.Header{"Content-Type": []string{"text/html"}},
		Body:          []byte("<html></html>"),
		ContentType:   "text/html",
		ContentLength: 13,
		Latency:       100 * time.Millisecond,
		RedirectCount: 0,
		FinalURL:      "http://example.com/",
		Blocked:       false,
	}

	if resp.StatusCode != 200 {
		t.Error("StatusCode mismatch")
	}
	if resp.Blocked {
		t.Error("Should not be blocked")
	}
	if resp.Latency != 100*time.Millisecond {
		t.Error("Latency mismatch")
	}
}

func TestClientGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify browser-like headers
		if r.Header.Get("User-Agent") == "" {
			t.Error("Request should have User-Agent")
		}
		if r.Method != "GET" {
			t.Errorf("Method = %s, want GET", r.Method)
		}
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "OK" {
		t.Errorf("Body = %s, want OK", resp.Body)
	}
}

func TestClientPost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("Content-Type should be form-urlencoded")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	data := url.Values{"username": []string{"admin"}, "password": []string{"secret"}}
	resp, err := client.Post(server.URL, data)
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestClientPostJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("Content-Type should be application/json")
		}
		if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
			t.Error("XHR header should be set")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	resp, err := client.PostJSON(server.URL, `{"test": true}`)
	if err != nil {
		t.Fatalf("PostJSON failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestClientBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("Blocked"))
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !resp.Blocked {
		t.Error("Response should be marked as blocked")
	}
}

func TestClientReferer(t *testing.T) {
	var capturedReferer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReferer = r.Header.Get("Referer")
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	// First request sets referer for next
	client.Get(server.URL + "/page1")
	client.Get(server.URL + "/page2")

	if capturedReferer == "" {
		t.Error("Second request should have referer")
	}
}

func TestClientHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	client.Get(server.URL + "/page1")
	client.Get(server.URL + "/page2")
	client.Get(server.URL + "/page3")

	history := client.History()
	if len(history) != 3 {
		t.Errorf("History should have 3 entries, got %d", len(history))
	}

	client.ClearHistory()
	if len(client.History()) != 0 {
		t.Error("History should be cleared")
	}
}

func TestClientCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	client.Get(server.URL)

	u, _ := url.Parse(server.URL)
	cookies := client.Cookies(u)
	if len(cookies) == 0 {
		t.Error("Should have cookies")
	}

	client.ClearCookies()
	cookies = client.Cookies(u)
	if len(cookies) != 0 {
		t.Error("Cookies should be cleared")
	}
}

func TestClientSetCookie(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	u, _ := url.Parse("http://example.com")
	client.SetCookie(u, &http.Cookie{Name: "test", Value: "value"})

	cookies := client.Cookies(u)
	if len(cookies) != 1 {
		t.Errorf("Expected 1 cookie, got %d", len(cookies))
	}
}

func TestClientProfile(t *testing.T) {
	client, err := NewClient(WithProfile(Firefox))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	if client.Profile() != Firefox {
		t.Error("Profile should be Firefox")
	}

	client.SetProfile(Safari)
	if client.Profile() != Safari {
		t.Error("Profile should be Safari after SetProfile")
	}
}

func TestClientBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/test" {
			t.Errorf("Path = %s, want /api/test", r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	resp, err := client.Get("/api/test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d", resp.StatusCode)
	}
}

func TestNewSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	session, err := NewSession(server.URL)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	if session.Client() == nil {
		t.Error("Session should have a client")
	}
}

func TestSessionLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "authenticated"})
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	session, err := NewSession(server.URL)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	resp, err := session.Login("/login", url.Values{"user": []string{"admin"}})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Login StatusCode = %d", resp.StatusCode)
	}
}

func TestSessionLogout(t *testing.T) {
	session, err := NewSession("http://example.com")
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	err = session.Logout()
	if err != nil {
		t.Errorf("Logout failed: %v", err)
	}
}

func TestTestCase(t *testing.T) {
	tc := &TestCase{
		ID:          "test-001",
		Description: "SQL Injection test",
		Profile:     Firefox,
		Request: &Request{
			Method: "GET",
			URL:    "/search?q=' OR 1=1--",
		},
		ExpectBlock: true,
		Timeout:     5 * time.Second,
	}

	if tc.ID != "test-001" {
		t.Error("ID mismatch")
	}
	if tc.Profile != Firefox {
		t.Error("Profile mismatch")
	}
	if !tc.ExpectBlock {
		t.Error("ExpectBlock should be true")
	}
}

func TestResult(t *testing.T) {
	result := &Result{
		TestCase: &TestCase{ID: "test-001"},
		Response: &Response{StatusCode: 403, Blocked: true},
		Passed:   true,
		Latency:  50 * time.Millisecond,
	}

	if result.TestCase.ID != "test-001" {
		t.Error("TestCase ID mismatch")
	}
	if !result.Passed {
		t.Error("Should be passed")
	}
	if result.Latency != 50*time.Millisecond {
		t.Error("Latency mismatch")
	}
}

func TestNewRunner(t *testing.T) {
	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer runner.Close()

	if runner.client == nil {
		t.Error("Runner should have a client")
	}
}

func TestRunnerRun(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer server.Close()

	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer runner.Close()

	tc := &TestCase{
		ID:          "test-001",
		Request:     &Request{Method: "GET", URL: server.URL},
		ExpectBlock: true,
	}

	result := runner.Run(tc)
	if !result.Passed {
		t.Error("Test should pass (expected block, got blocked)")
	}
}

func TestRunnerRunAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block" {
			w.WriteHeader(403)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer server.Close()

	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer runner.Close()

	testCases := []*TestCase{
		{ID: "test-1", Request: &Request{URL: server.URL + "/ok"}, ExpectBlock: false},
		{ID: "test-2", Request: &Request{URL: server.URL + "/block"}, ExpectBlock: true},
	}

	results := runner.RunAll(testCases)
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}

func TestRunnerSummary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block" {
			w.WriteHeader(403)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer server.Close()

	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer runner.Close()

	runner.Run(&TestCase{ID: "1", Request: &Request{URL: server.URL + "/ok"}, ExpectBlock: false})
	runner.Run(&TestCase{ID: "2", Request: &Request{URL: server.URL + "/block"}, ExpectBlock: true})
	runner.Run(&TestCase{ID: "3", Request: &Request{URL: server.URL + "/block"}, ExpectBlock: false}) // Fail

	summary := runner.Summary()
	if summary.TotalTests != 3 {
		t.Errorf("TotalTests = %d, want 3", summary.TotalTests)
	}
	if summary.Passed != 2 {
		t.Errorf("Passed = %d, want 2", summary.Passed)
	}
	if summary.Failed != 1 {
		t.Errorf("Failed = %d, want 1", summary.Failed)
	}
	if summary.Blocked != 2 {
		t.Errorf("Blocked = %d, want 2", summary.Blocked)
	}
}

func TestRunnerResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer runner.Close()

	runner.Run(&TestCase{ID: "1", Request: &Request{URL: server.URL}})
	runner.Run(&TestCase{ID: "2", Request: &Request{URL: server.URL}})

	results := runner.Results()
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}

func TestSummary(t *testing.T) {
	summary := &Summary{
		TotalTests:   10,
		Passed:       8,
		Failed:       1,
		Errors:       1,
		Blocked:      3,
		TotalLatency: time.Second,
		AvgLatency:   100 * time.Millisecond,
	}

	if summary.TotalTests != 10 {
		t.Error("TotalTests mismatch")
	}
	if summary.Passed != 8 {
		t.Error("Passed mismatch")
	}
	if summary.Failed != 1 {
		t.Error("Failed mismatch")
	}
	if summary.Errors != 1 {
		t.Error("Errors mismatch")
	}
}

func TestIsBlockedResponse(t *testing.T) {
	tests := []struct {
		statusCode int
		blocked    bool
	}{
		{200, false},
		{201, false},
		{301, false},
		{400, false},
		{403, true},
		{406, true},
		{418, true},
		{429, true},
		{500, true},
		{502, true},
		{503, true},
	}

	for _, tt := range tests {
		resp := &http.Response{StatusCode: tt.statusCode}
		if isBlockedResponse(resp) != tt.blocked {
			t.Errorf("isBlockedResponse(%d) = %v, want %v", tt.statusCode, !tt.blocked, tt.blocked)
		}
	}
}

func TestRunnerWithProfile(t *testing.T) {
	var capturedUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		w.WriteHeader(200)
	}))
	defer server.Close()

	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer runner.Close()

	tc := &TestCase{
		ID:      "test-1",
		Profile: Firefox,
		Request: &Request{URL: server.URL},
	}

	runner.Run(tc)

	if capturedUA != Firefox.UserAgent {
		t.Errorf("User-Agent should be Firefox's, got %s", capturedUA)
	}
}

func TestClientCustomHeaders(t *testing.T) {
	var capturedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Custom-Header")
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	client.Do(&Request{
		Method:  "GET",
		URL:     server.URL,
		Headers: map[string]string{"X-Custom-Header": "custom-value"},
	})

	if capturedHeader != "custom-value" {
		t.Errorf("Custom header = %s, want custom-value", capturedHeader)
	}
}
