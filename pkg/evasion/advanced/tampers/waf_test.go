package tampers

import (
	"net/http"
	"strings"
	"testing"
)

func TestInformationschemacomment(t *testing.T) {
	tamper := &Informationschemacomment{}
	result := tamper.Transform("INFORMATION_SCHEMA.tables")
	if !strings.Contains(result, "/**/") {
		t.Errorf("Expected comment in result: %q", result)
	}
}

func TestSchemasplit(t *testing.T) {
	tamper := &Schemasplit{}
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"information_schema", "information`/**/.`schema"},
		{"INFORMATION_SCHEMA", "INFORMATION`/**/.`SCHEMA"},
	}
	for _, tt := range tests {
		result := tamper.Transform(tt.input)
		if result != tt.expected {
			t.Errorf("Schemasplit(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestLuanginxWAF(t *testing.T) {
	tamper := &LuanginxWAF{}
	result := tamper.Transform("SELECT * FROM users")
	// Should contain null bytes
	if !strings.Contains(result, "%00") {
		t.Errorf("Expected null bytes in result: %q", result)
	}
	// Original content should be preserved (minus null bytes)
	cleaned := strings.ReplaceAll(result, "%00", "")
	if cleaned != "SELECT * FROM users" {
		t.Errorf("Original content not preserved: %q", cleaned)
	}
}

func TestXForwardedFor(t *testing.T) {
	tamper := &XForwardedFor{}
	
	// Payload should pass through unchanged
	result := tamper.Transform("test")
	if result != "test" {
		t.Errorf("XForwardedFor should not modify payload: %q", result)
	}
	
	// Request should have headers added
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req = tamper.TransformRequest(req)
	
	if req.Header.Get("X-Forwarded-For") == "" {
		t.Error("X-Forwarded-For header should be set")
	}
	if req.Header.Get("X-Real-IP") == "" {
		t.Error("X-Real-IP header should be set")
	}
}

func TestRandomUserAgent(t *testing.T) {
	tamper := &RandomUserAgent{}
	
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req = tamper.TransformRequest(req)
	
	ua := req.Header.Get("User-Agent")
	if ua == "" {
		t.Error("User-Agent header should be set")
	}
	// Should be one of our user agents
	found := false
	for _, expectedUA := range userAgents {
		if ua == expectedUA {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("User-Agent not in expected list: %q", ua)
	}
}

func TestJSONObfuscate(t *testing.T) {
	tamper := &JSONObfuscate{}
	result := tamper.Transform(`{"key":"value"}`)
	// Should have some modifications (whitespace, escapes)
	if result == `{"key":"value"}` {
		t.Error("JSONObfuscate should modify JSON")
	}
}

func TestWAFTampersRegistered(t *testing.T) {
	wafTampers := []string{
		"informationschemacomment",
		"schemasplit",
		"luanginxwaf",
		"jsonobfuscate",
	}

	for _, name := range wafTampers {
		tamper := Get(name)
		if tamper == nil {
			t.Errorf("WAF tamper %q not registered", name)
			continue
		}
		if tamper.Category() != CategoryWAF {
			t.Errorf("Tamper %q category = %q, want %q", name, tamper.Category(), CategoryWAF)
		}
	}
}

func TestHTTPTampersRegistered(t *testing.T) {
	httpTampers := []string{
		"xforwardedfor",
		"randomuseragent",
		"varnishbypass",
	}

	for _, name := range httpTampers {
		tamper := Get(name)
		if tamper == nil {
			t.Errorf("HTTP tamper %q not registered", name)
			continue
		}
		if tamper.Category() != CategoryHTTP {
			t.Errorf("Tamper %q category = %q, want %q", name, tamper.Category(), CategoryHTTP)
		}
	}
}

func TestWAFCategory(t *testing.T) {
	tampers := ByCategory(CategoryWAF)
	if len(tampers) < 4 {
		t.Errorf("Expected at least 4 WAF tampers, got %d", len(tampers))
	}
}

func TestHTTPCategory(t *testing.T) {
	tampers := ByCategory(CategoryHTTP)
	if len(tampers) < 3 {
		t.Errorf("Expected at least 3 HTTP tampers, got %d", len(tampers))
	}
}
