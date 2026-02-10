package nosqli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
)

func TestNewTester(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config.Concurrency != 5 {
			t.Errorf("expected default concurrency 5, got %d", tester.config.Concurrency)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TesterConfig{
			Base: attackconfig.Base{
				Timeout:     60 * time.Second,
				Concurrency: 10,
			},
			Database: DBMongoDB,
		}
		tester := NewTester(config)
		if tester.config.Concurrency != 10 {
			t.Errorf("expected concurrency 10, got %d", tester.config.Concurrency)
		}
		if tester.config.Database != DBMongoDB {
			t.Errorf("expected MongoDB database, got %s", tester.config.Database)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}

	if config.Concurrency != 5 {
		t.Errorf("expected concurrency 5, got %d", config.Concurrency)
	}

	if len(config.TestParams) == 0 {
		t.Error("expected default test params")
	}
}

func TestGetPayloads(t *testing.T) {
	tester := NewTester(nil)

	t.Run("MongoDB payloads", func(t *testing.T) {
		payloads := tester.GetPayloads(DBMongoDB)
		if len(payloads) == 0 {
			t.Fatal("expected MongoDB payloads")
		}

		// Check that at least some MongoDB-specific payloads exist
		foundOperator := false
		for _, p := range payloads {
			if strings.Contains(p.Value, "$gt") || strings.Contains(p.Value, "$ne") {
				foundOperator = true
				break
			}
		}
		if !foundOperator {
			t.Error("expected MongoDB operator payloads")
		}
	})

	t.Run("CouchDB payloads", func(t *testing.T) {
		payloads := tester.GetPayloads(DBCouchDB)
		if len(payloads) == 0 {
			t.Fatal("expected CouchDB payloads")
		}
	})

	t.Run("Redis payloads", func(t *testing.T) {
		payloads := tester.GetPayloads(DBRedis)
		if len(payloads) == 0 {
			t.Fatal("expected Redis payloads")
		}
	})

	t.Run("Unknown includes all", func(t *testing.T) {
		allPayloads := tester.GetPayloads(DBUnknown)
		mongoPayloads := tester.GetPayloads(DBMongoDB)

		if len(allPayloads) < len(mongoPayloads) {
			t.Error("unknown database should include all payloads")
		}
	})
}

func TestDetectEvidence(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		name       string
		body       string
		statusCode int
		db         Database
		expectHit  bool
	}{
		{
			name:       "MongoDB error in response",
			body:       `{"error": "MongoError: query failed"}`,
			statusCode: 500,
			db:         DBMongoDB,
			expectHit:  true,
		},
		{
			name:       "CouchDB pattern",
			body:       `{"error": "not_found", "reason": "missing"}`,
			statusCode: 404,
			db:         DBCouchDB,
			expectHit:  true,
		},
		{
			name:       "ObjectId leak",
			body:       `{"_id": ObjectId("507f1f77bcf86cd799439011")}`,
			statusCode: 200,
			db:         DBMongoDB,
			expectHit:  true,
		},
		{
			name:       "Auth bypass success indicators",
			body:       `<html>Welcome to your dashboard</html>`,
			statusCode: 200,
			db:         DBMongoDB,
			expectHit:  true,
		},
		{
			name:       "Normal response",
			body:       `{"status": "ok"}`,
			statusCode: 200,
			db:         DBMongoDB,
			expectHit:  false,
		},
		{
			name:       "Redis info",
			body:       `redis_version:6.2.0`,
			statusCode: 200,
			db:         DBRedis,
			expectHit:  true,
		},
		{
			name:       "BSON object hint",
			body:       `BSONObj size must be > 0`,
			statusCode: 500,
			db:         DBMongoDB,
			expectHit:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := tester.detectEvidence(tt.body, tt.statusCode, tt.db)
			if tt.expectHit && evidence == "" {
				t.Errorf("expected evidence but got none for body: %s", tt.body)
			}
			if !tt.expectHit && evidence != "" {
				t.Errorf("unexpected evidence: %s", evidence)
			}
		})
	}
}

func TestDetectDatabase(t *testing.T) {
	tests := []struct {
		name     string
		handler  http.HandlerFunc
		expected Database
	}{
		{
			name: "CouchDB server header",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "CouchDB/3.0.0")
				w.Write([]byte(`{}`))
			},
			expected: DBCouchDB,
		},
		{
			name: "Express/Node suggests MongoDB",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Powered-By", "Express")
				w.Write([]byte(`{}`))
			},
			expected: DBMongoDB,
		},
		{
			name: "Unknown database",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"status": "ok"}`))
			},
			expected: DBUnknown,
		},
		{
			name: "MongoDB hint in body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`Connected to MongoDB cluster`))
			},
			expected: DBMongoDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			tester := NewTester(nil)
			ctx := context.Background()

			db, err := tester.DetectDatabase(ctx, server.URL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if db != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, db)
			}
		})
	}
}

func TestTestQueryParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		// Simulate vulnerable response - check raw query for injection patterns
		if strings.Contains(query, "gt") || strings.Contains(query, "%24gt") {
			w.WriteHeader(500)
			w.Write([]byte(`MongoError: query selector is not valid`))
			return
		}
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	payloads := []Payload{
		{Value: "[$gt]=", Description: "Test $gt", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "query"},
	}

	vulns, err := tester.TestParameter(ctx, server.URL, "username", payloads)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected vulnerability to be detected")
	}
}

func TestTestJSONBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(400)
			return
		}

		// Check if injection payload present
		if val, ok := body["username"]; ok {
			if strings.Contains(string(val), "$gt") {
				w.WriteHeader(500)
				w.Write([]byte(`MongoError: operator injection detected`))
				return
			}
		}

		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	payloads := []Payload{
		{Value: `{"$gt": ""}`, Description: "Test $gt JSON", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
	}

	vulns, err := tester.TestParameter(ctx, server.URL, "username", payloads)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected vulnerability to be detected")
	}
}

func TestTestFormBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}

		username := r.FormValue("username")
		if strings.Contains(username, "$where") {
			w.WriteHeader(500)
			w.Write([]byte(`$where clause not allowed`))
			return
		}

		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	payloads := []Payload{
		{Value: `'; return true; var x='`, Description: "Test JS injection", Database: DBMongoDB, Type: VulnJSInjection, ContentType: "form"},
	}

	// This won't trigger the vulnerability since the payload doesn't contain $where
	vulns, err := tester.TestParameter(ctx, server.URL, "username", payloads)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No vulnerability expected for this specific test
	_ = vulns
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	config := &TesterConfig{
		Base: attackconfig.Base{
			Timeout:     5 * time.Second,
			Concurrency: 1,
		},
		TestParams: []string{"username"},
	}

	tester := NewTester(config)
	ctx := context.Background()

	result, err := tester.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != server.URL {
		t.Errorf("expected URL %s, got %s", server.URL, result.URL)
	}

	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}

	if result.TestedPayloads == 0 {
		t.Error("expected payloads to be tested")
	}
}

func TestIsNoSQLOperator(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{`{"$gt": ""}`, true},
		{`{"$ne": null}`, true},
		{`{"$regex": ".*"}`, true},
		{`{"$where": "1==1"}`, true},
		{`{"$exists": true}`, true},
		{`{"name": "test"}`, false},
		{`normal string`, false},
		{"", false},
		{`$gt`, true},
		{`some$gtthing`, true}, // embedded operator
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsNoSQLOperator(tt.input)
			if result != tt.expected {
				t.Errorf("IsNoSQLOperator(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeForMongoDB(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`{"$gt": ""}`, "gt: "},
		{`normal`, "normal"},
		{`test'injection`, "testinjection"},
		{`{"key": "value"}`, "key: value"},
		{`array[0]`, "array0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeForMongoDB(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeForMongoDB(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		expected finding.Severity
	}{
		{VulnAuthBypass, finding.Critical},
		{VulnDataExfiltration, finding.Critical},
		{VulnOperatorInjection, finding.High},
		{VulnJSInjection, finding.High},
		{VulnBlindInjection, finding.Medium},
		{VulnArrayInjection, finding.High},
	}

	for _, tt := range tests {
		t.Run(string(tt.vulnType), func(t *testing.T) {
			result := getSeverity(tt.vulnType)
			if result != tt.expected {
				t.Errorf("getSeverity(%s) = %s, want %s", tt.vulnType, result, tt.expected)
			}
		})
	}
}

func TestGetCVSS(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		expected float64
	}{
		{VulnAuthBypass, 9.8},
		{VulnDataExfiltration, 8.6},
		{VulnJSInjection, 8.1},
		{VulnOperatorInjection, 7.5},
		{VulnBlindInjection, 6.5},
	}

	for _, tt := range tests {
		t.Run(string(tt.vulnType), func(t *testing.T) {
			result := getCVSS(tt.vulnType)
			if result != tt.expected {
				t.Errorf("getCVSS(%s) = %f, want %f", tt.vulnType, result, tt.expected)
			}
		})
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	expected := 6 // operator, js, auth, data, blind, array
	if len(types) != expected {
		t.Errorf("expected %d vulnerability types, got %d", expected, len(types))
	}

	// Check that all expected types are present
	typeMap := make(map[VulnerabilityType]bool)
	for _, vt := range types {
		typeMap[vt] = true
	}

	if !typeMap[VulnOperatorInjection] {
		t.Error("missing VulnOperatorInjection")
	}
	if !typeMap[VulnAuthBypass] {
		t.Error("missing VulnAuthBypass")
	}
}

func TestAllDatabases(t *testing.T) {
	databases := AllDatabases()

	expected := 4 // mongo, couch, redis, firebase
	if len(databases) != expected {
		t.Errorf("expected %d databases, got %d", expected, len(databases))
	}
}

func TestGenerateAuthBypassPayloads(t *testing.T) {
	payloads := GenerateAuthBypassPayloads()

	if len(payloads) == 0 {
		t.Fatal("expected auth bypass payloads")
	}

	// All should be auth bypass type
	for _, p := range payloads {
		if p.Type != VulnAuthBypass {
			t.Errorf("expected VulnAuthBypass type, got %s", p.Type)
		}
	}
}

func TestGenerateOperatorPayloads(t *testing.T) {
	payloads := GenerateOperatorPayloads()

	if len(payloads) == 0 {
		t.Fatal("expected operator payloads")
	}

	// All should be operator injection type
	for _, p := range payloads {
		if p.Type != VulnOperatorInjection {
			t.Errorf("expected VulnOperatorInjection type, got %s", p.Type)
		}
	}
}

func TestGetNoSQLiRemediation(t *testing.T) {
	remediation := GetNoSQLiRemediation()

	if remediation == "" {
		t.Error("expected remediation text")
	}

	// Check for key recommendations
	if !strings.Contains(remediation, "sanitize") {
		t.Error("remediation should mention sanitization")
	}
	if !strings.Contains(remediation, "parameterized") {
		t.Error("remediation should mention parameterized queries")
	}
}

func TestGetMongoDBRemediation(t *testing.T) {
	remediation := GetMongoDBRemediation()

	if remediation == "" {
		t.Error("expected MongoDB remediation text")
	}

	if !strings.Contains(remediation, "$where") {
		t.Error("MongoDB remediation should mention $where")
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnOperatorInjection,
		Description: "Test vulnerability",
		Severity:    finding.High,
		URL:         "http://example.com",
		Parameter:   "username",
		Payload:     `{"$gt": ""}`,
		Evidence:    "MongoError",
		Database:    DBMongoDB,
		Remediation: "Fix it",
		CVSS:        7.5,
	}

	// Test JSON marshalling
	data, err := json.Marshal(vuln)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Vulnerability
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Type != vuln.Type {
		t.Errorf("type mismatch: expected %s, got %s", vuln.Type, decoded.Type)
	}
	if decoded.CVSS != vuln.CVSS {
		t.Errorf("CVSS mismatch: expected %f, got %f", vuln.CVSS, decoded.CVSS)
	}
}

func TestScanResult(t *testing.T) {
	result := ScanResult{
		URL:            "http://example.com",
		StartTime:      time.Now(),
		EndTime:        time.Now().Add(5 * time.Second),
		Duration:       5 * time.Second,
		DatabaseHint:   DBMongoDB,
		TestedPayloads: 50,
		Vulnerabilities: []Vulnerability{
			{Type: VulnOperatorInjection},
		},
	}

	// Test JSON marshalling
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.URL != result.URL {
		t.Errorf("URL mismatch")
	}
	if len(decoded.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(decoded.Vulnerabilities))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is to..."},
		{"", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := truncate(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestPayloadContentTypes(t *testing.T) {
	tester := NewTester(nil)
	payloads := tester.GetPayloads(DBMongoDB)

	hasJSON := false
	hasQuery := false
	hasForm := false

	for _, p := range payloads {
		switch p.ContentType {
		case "json":
			hasJSON = true
		case "query":
			hasQuery = true
		case "form":
			hasForm = true
		}
	}

	if !hasJSON {
		t.Error("expected JSON content type payloads")
	}
	if !hasQuery {
		t.Error("expected query content type payloads")
	}
	if !hasForm {
		t.Error("expected form content type payloads")
	}
}
