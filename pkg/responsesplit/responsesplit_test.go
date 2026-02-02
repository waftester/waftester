package responsesplit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 10 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 10", config.Concurrency)
	}
	if config.Timeout != httpclient.TimeoutProbing {
		t.Errorf("DefaultConfig().Timeout = %v, want %v", config.Timeout, httpclient.TimeoutProbing)
	}
}

func TestNewScanner(t *testing.T) {
	config := DefaultConfig()
	scanner := NewScanner(config)
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if scanner.client == nil {
		t.Error("Scanner client is nil")
	}
}

func TestScanner_Scan_Vulnerable(t *testing.T) {
	// Server that reflects parameter in header (vulnerable)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("redirect")
		// Dangerous: directly setting header from user input
		if strings.Contains(input, "INJECTED") {
			w.Header().Set("X-Injected", "INJECTED")
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL, map[string]string{
		"redirect": "test",
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			if r.Severity != "HIGH" {
				t.Errorf("Vulnerable result severity = %s, want HIGH", r.Severity)
			}
		}
	}

	if !foundVuln {
		t.Error("Expected to find response splitting vulnerability")
	}
}

func TestScanner_Scan_Safe(t *testing.T) {
	// Server that sanitizes input
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK - safe response"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL, map[string]string{
		"redirect": "test",
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, r := range results {
		if r.Vulnerable {
			t.Error("Expected no vulnerabilities in safe endpoint")
		}
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("GetResults returned nil")
	}
}

func TestPayloads(t *testing.T) {
	payloads := Payloads()
	if len(payloads) < 10 {
		t.Errorf("Payloads count = %d, want at least 10", len(payloads))
	}

	// Check for CRLF payloads
	foundCRLF := false
	for _, p := range payloads {
		if p.Type == "crlf" {
			foundCRLF = true
			break
		}
	}
	if !foundCRLF {
		t.Error("Expected CRLF payloads")
	}

	// Check for encoded payloads
	foundEncoded := false
	for _, p := range payloads {
		if p.Encoded {
			foundEncoded = true
			break
		}
	}
	if !foundEncoded {
		t.Error("Expected encoded payloads")
	}
}

func TestHeaderInjectionPayloads(t *testing.T) {
	payloads := HeaderInjectionPayloads()
	if len(payloads) < 1 {
		t.Errorf("HeaderInjectionPayloads count = %d, want at least 1", len(payloads))
	}

	// Check for redirect payload
	foundRedirect := false
	for _, p := range payloads {
		if p.Type == "redirect" {
			foundRedirect = true
			if !strings.Contains(p.Value, "Location") {
				t.Error("Redirect payload should contain Location header")
			}
		}
	}
	if !foundRedirect {
		t.Error("Expected redirect payload")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:        "http://example.com",
		Parameter:  "redirect",
		Payload:    "test\\r\\nX-Injected: value",
		Location:   "header",
		StatusCode: 200,
		Vulnerable: true,
		Evidence:   "Header injection detected",
		Severity:   "HIGH",
	}

	if result.URL != "http://example.com" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
	if result.Location != "header" {
		t.Error("Location not set correctly")
	}
}

func TestPayload_Types(t *testing.T) {
	payloads := Payloads()

	types := make(map[string]bool)
	for _, p := range payloads {
		types[p.Type] = true
	}

	expectedTypes := []string{"crlf", "crlf-encoded", "lf", "body-injection"}
	for _, typ := range expectedTypes {
		if !types[typ] {
			t.Errorf("Expected payload type: %s", typ)
		}
	}
}

func TestPayload_EncodedVariants(t *testing.T) {
	payloads := Payloads()

	encodedCount := 0
	rawCount := 0
	for _, p := range payloads {
		if p.Encoded {
			encodedCount++
		} else {
			rawCount++
		}
	}

	if encodedCount == 0 {
		t.Error("Expected some encoded payloads")
	}
	if rawCount == 0 {
		t.Error("Expected some raw payloads")
	}
}
