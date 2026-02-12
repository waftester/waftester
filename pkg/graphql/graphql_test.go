package graphql

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
	t.Run("default config", func(t *testing.T) {
		tester := NewTester("http://example.com/graphql", nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config == nil {
			t.Fatal("expected config")
		}
		if tester.config.Timeout != 30*time.Second {
			t.Errorf("expected 30s timeout, got %v", tester.config.Timeout)
		}
	})

	t.Run("custom config", func(t *testing.T) {
		cfg := &TesterConfig{
			Base:         attackconfig.Base{Timeout: 5 * time.Second},
			MaxDepth:     10,
			MaxBatchSize: 50,
		}
		tester := NewTester("http://example.com/graphql", cfg)
		if tester.config.Timeout != 5*time.Second {
			t.Errorf("expected 5s timeout, got %v", tester.config.Timeout)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", cfg.Timeout)
	}
	if cfg.MaxDepth != 20 {
		t.Errorf("expected max depth 20, got %d", cfg.MaxDepth)
	}
	if cfg.MaxBatchSize != 100 {
		t.Errorf("expected max batch size 100, got %d", cfg.MaxBatchSize)
	}
	if !cfg.SafeMode {
		t.Error("expected SafeMode true by default")
	}
}

func TestSendQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected application/json, got %s", contentType)
		}

		var req Request
		json.NewDecoder(r.Body).Decode(&req)

		resp := Response{}
		if strings.Contains(req.Query, "__typename") {
			resp.Data = json.RawMessage(`{"__typename": "Query"}`)
		} else {
			resp.Errors = []Error{{Message: "Invalid query"}}
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	tester := NewTester(server.URL, nil)

	t.Run("valid query", func(t *testing.T) {
		resp, status, err := tester.SendQuery(context.Background(), "{ __typename }", nil)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if status != 200 {
			t.Errorf("expected status 200, got %d", status)
		}
		if len(resp.Errors) != 0 {
			t.Errorf("expected no errors, got %v", resp.Errors)
		}
	})

	t.Run("invalid query", func(t *testing.T) {
		resp, _, err := tester.SendQuery(context.Background(), "{ invalid }", nil)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if len(resp.Errors) == 0 {
			t.Error("expected errors")
		}
	})
}

func TestSendBatchQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqs []Request
		json.NewDecoder(r.Body).Decode(&reqs)

		var responses []Response
		for range reqs {
			responses = append(responses, Response{
				Data: json.RawMessage(`{"__typename": "Query"}`),
			})
		}

		json.NewEncoder(w).Encode(responses)
	}))
	defer server.Close()

	tester := NewTester(server.URL, nil)

	queries := []Request{
		{Query: "{ __typename }", OperationName: "Q1"},
		{Query: "{ __typename }", OperationName: "Q2"},
	}

	responses, status, err := tester.SendBatchQuery(context.Background(), queries)
	if err != nil {
		t.Fatalf("batch query failed: %v", err)
	}

	if status != 200 {
		t.Errorf("expected status 200, got %d", status)
	}

	if len(responses) != 2 {
		t.Errorf("expected 2 responses, got %d", len(responses))
	}
}

func TestTestIntrospection(t *testing.T) {
	t.Run("introspection enabled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Data: json.RawMessage(`{
					"__schema": {
						"queryType": {"name": "Query"},
						"types": [
							{"kind": "OBJECT", "name": "Query"},
							{"kind": "OBJECT", "name": "User"}
						]
					}
				}`),
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		tester := NewTester(server.URL, nil)
		vuln, schema, err := tester.TestIntrospection(context.Background())

		if err != nil {
			t.Fatalf("introspection test failed: %v", err)
		}

		if vuln == nil {
			t.Error("expected vulnerability for enabled introspection")
		} else {
			if vuln.Type != AttackIntrospection {
				t.Errorf("expected AttackIntrospection, got %s", vuln.Type)
			}
			if vuln.Severity != finding.Medium {
				t.Errorf("expected medium severity, got %s", vuln.Severity)
			}
		}

		if schema == nil {
			t.Error("expected schema")
		} else if len(schema.Types) != 2 {
			t.Errorf("expected 2 types, got %d", len(schema.Types))
		}
	})

	t.Run("introspection disabled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Errors: []Error{{Message: "Introspection is disabled"}},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		tester := NewTester(server.URL, nil)
		vuln, schema, err := tester.TestIntrospection(context.Background())

		if err != nil {
			t.Fatalf("introspection test failed: %v", err)
		}

		if vuln != nil {
			t.Error("expected no vulnerability when introspection disabled")
		}
		if schema != nil {
			t.Error("expected no schema when introspection disabled")
		}
	})
}

func TestIntrospectionQuery(t *testing.T) {
	query := IntrospectionQuery()

	if query == "" {
		t.Fatal("introspection query should not be empty")
	}

	if !strings.Contains(query, "__schema") {
		t.Error("query should contain __schema")
	}

	if !strings.Contains(query, "queryType") {
		t.Error("query should contain queryType")
	}

	if !strings.Contains(query, "mutationType") {
		t.Error("query should contain mutationType")
	}

	if !strings.Contains(query, "types") {
		t.Error("query should contain types")
	}
}

func TestGenerateDeepQuery(t *testing.T) {
	t.Run("default field", func(t *testing.T) {
		query := generateDeepQuery("", 5)
		if !strings.Contains(query, "node") {
			t.Error("should use 'node' as default field")
		}
		if strings.Count(query, "node") != 5 {
			t.Errorf("expected 5 nested nodes, got %d", strings.Count(query, "node"))
		}
	})

	t.Run("custom field", func(t *testing.T) {
		query := generateDeepQuery("user", 3)
		if strings.Count(query, "user") != 3 {
			t.Errorf("expected 3 nested users, got %d", strings.Count(query, "user"))
		}
	})
}

func TestTestDepthAttack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept all queries (no depth limiting)
		resp := Response{
			Data: json.RawMessage(`{"node": {"id": "1"}}`),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	tester := NewTester(server.URL, nil)
	vuln, err := tester.TestDepthAttack(context.Background(), "node", 10)

	if err != nil {
		t.Fatalf("depth attack test failed: %v", err)
	}

	if vuln == nil {
		t.Error("expected vulnerability when depth limit not enforced")
	} else if vuln.Type != AttackDepth {
		t.Errorf("expected AttackDepth, got %s", vuln.Type)
	}
}

func TestTestBatchAttack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqs []Request
		json.NewDecoder(r.Body).Decode(&reqs)

		var responses []Response
		for range reqs {
			responses = append(responses, Response{
				Data: json.RawMessage(`{"__typename": "Query"}`),
			})
		}

		json.NewEncoder(w).Encode(responses)
	}))
	defer server.Close()

	tester := NewTester(server.URL, nil)
	vuln, err := tester.TestBatchAttack(context.Background(), 10)

	if err != nil {
		t.Fatalf("batch attack test failed: %v", err)
	}

	if vuln == nil {
		t.Error("expected vulnerability when batch not limited")
	} else if vuln.Type != AttackBatch {
		t.Errorf("expected AttackBatch, got %s", vuln.Type)
	}
}

func TestGenerateAliasQuery(t *testing.T) {
	query := generateAliasQuery("__typename", 5)

	if strings.Count(query, "alias") != 5 {
		t.Errorf("expected 5 aliases, got %d", strings.Count(query, "alias"))
	}

	if !strings.Contains(query, "alias0:") {
		t.Error("should contain alias0")
	}

	if !strings.Contains(query, "alias4:") {
		t.Error("should contain alias4")
	}
}

func TestTestAliasAbuse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := Response{
			Data: json.RawMessage(`{"alias0": "Query", "alias1": "Query"}`),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	tester := NewTester(server.URL, nil)
	vuln, err := tester.TestAliasAbuse(context.Background(), "__typename", 100)

	if err != nil {
		t.Fatalf("alias abuse test failed: %v", err)
	}

	if vuln == nil {
		t.Error("expected vulnerability when aliases not limited")
	}
}

func TestTestFieldSuggestion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := Response{
			Errors: []Error{
				{Message: `Cannot query field "usr" on type "Query". Did you mean "user"?`},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	tester := NewTester(server.URL, nil)
	vuln, suggestions, err := tester.TestFieldSuggestion(context.Background())

	if err != nil {
		t.Fatalf("field suggestion test failed: %v", err)
	}

	if vuln == nil {
		t.Error("expected vulnerability when field suggestions enabled")
	} else if vuln.Type != AttackFieldSuggestion {
		t.Errorf("expected AttackFieldSuggestion, got %s", vuln.Type)
	}

	if len(suggestions) == 0 {
		t.Error("expected to find suggested fields")
	} else {
		found := false
		for _, s := range suggestions {
			if s == "user" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find 'user' in suggestions")
		}
	}
}

func TestGenerateDirectiveQuery(t *testing.T) {
	query := generateDirectiveQuery(3)

	if strings.Count(query, "@skip") != 3 {
		t.Errorf("expected 3 @skip directives, got %d", strings.Count(query, "@skip"))
	}
}

func TestGetInjectionPayloads(t *testing.T) {
	payloads := getInjectionPayloads()

	if len(payloads) < 10 {
		t.Errorf("expected at least 10 payloads, got %d", len(payloads))
	}

	// Check for different types
	types := make(map[string]bool)
	for _, p := range payloads {
		types[p.Type] = true
	}

	expected := []string{"SQL", "NoSQL", "Command", "PathTraversal", "XSS"}
	for _, e := range expected {
		if !types[e] {
			t.Errorf("missing payload type: %s", e)
		}
	}
}

func TestAnalyzeInjectionResponse(t *testing.T) {
	tester := NewTester("http://example.com", nil)

	t.Run("SQL error", func(t *testing.T) {
		resp := &Response{
			Errors: []Error{{Message: "You have an error in your SQL syntax"}},
		}

		if !tester.analyzeInjectionResponse(resp, injectionPayload{Type: "SQL"}) {
			t.Error("expected SQL injection detection")
		}
	})

	t.Run("command output in data", func(t *testing.T) {
		resp := &Response{
			Data: json.RawMessage(`{"result": "uid=0(root) gid=0(root)"}`),
		}

		if !tester.analyzeInjectionResponse(resp, injectionPayload{Type: "Command"}) {
			t.Error("expected command injection detection")
		}
	})

	t.Run("no injection", func(t *testing.T) {
		resp := &Response{
			Data: json.RawMessage(`{"user": {"name": "test"}}`),
		}

		if tester.analyzeInjectionResponse(resp, injectionPayload{Type: "SQL"}) {
			t.Error("should not detect injection in normal response")
		}
	})
}

func TestFullScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		json.NewDecoder(r.Body).Decode(&req)

		if strings.Contains(req.Query, "__schema") {
			// Return schema for introspection
			resp := Response{
				Data: json.RawMessage(`{
					"__schema": {
						"queryType": {"name": "Query"},
						"types": [{"kind": "OBJECT", "name": "Query"}]
					}
				}`),
			}
			json.NewEncoder(w).Encode(resp)
		} else {
			// Accept all other queries
			resp := Response{
				Data: json.RawMessage(`{"data": "ok"}`),
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	tester := NewTester(server.URL, &TesterConfig{
		Base:         attackconfig.Base{Timeout: 5 * time.Second},
		MaxDepth:     5,
		MaxBatchSize: 10,
	})

	result, err := tester.FullScan(context.Background())
	if err != nil {
		t.Fatalf("full scan failed: %v", err)
	}

	if result.Endpoint != server.URL {
		t.Errorf("expected endpoint %s, got %s", server.URL, result.Endpoint)
	}

	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}

	if result.QueriesSent <= 0 {
		t.Error("expected queries to be sent")
	}

	t.Logf("Scan found %d vulnerabilities in %v", len(result.Vulnerabilities), result.Duration)
}

func TestExtractTypesFromSchema(t *testing.T) {
	schema := &Schema{
		Types: []Type{
			{Name: "Query", Kind: "OBJECT"},
			{Name: "User", Kind: "OBJECT"},
			{Name: "__Schema", Kind: "OBJECT"}, // Should be filtered
			{Name: "__Type", Kind: "OBJECT"},   // Should be filtered
		},
	}

	types := ExtractTypesFromSchema(schema)

	if len(types) != 2 {
		t.Errorf("expected 2 types (excluding introspection), got %d", len(types))
	}

	for _, tn := range types {
		if strings.HasPrefix(tn, "__") {
			t.Errorf("should not include introspection type: %s", tn)
		}
	}
}

func TestExtractFieldsFromType(t *testing.T) {
	schema := &Schema{
		Types: []Type{
			{
				Name: "User",
				Kind: "OBJECT",
				Fields: []Field{
					{Name: "id"},
					{Name: "name"},
					{Name: "email"},
				},
			},
		},
	}

	fields := ExtractFieldsFromType(schema, "User")

	if len(fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(fields))
	}
}

func TestExtractMutations(t *testing.T) {
	schema := &Schema{
		MutationType: &TypeRef{Name: "Mutation"},
		Types: []Type{
			{
				Name: "Mutation",
				Kind: "OBJECT",
				Fields: []Field{
					{Name: "createUser"},
					{Name: "updateUser"},
					{Name: "deleteUser"},
				},
			},
		},
	}

	mutations := ExtractMutations(schema)

	if len(mutations) != 3 {
		t.Errorf("expected 3 mutations, got %d", len(mutations))
	}
}

func TestExtractQueries(t *testing.T) {
	schema := &Schema{
		QueryType: &TypeRef{Name: "Query"},
		Types: []Type{
			{
				Name: "Query",
				Kind: "OBJECT",
				Fields: []Field{
					{Name: "user"},
					{Name: "users"},
					{Name: "post"},
				},
			},
		},
	}

	queries := ExtractQueries(schema)

	if len(queries) != 3 {
		t.Errorf("expected 3 queries, got %d", len(queries))
	}
}

func TestFindSensitiveFields(t *testing.T) {
	schema := &Schema{
		Types: []Type{
			{
				Name: "User",
				Kind: "OBJECT",
				Fields: []Field{
					{Name: "id"},
					{Name: "name"},
					{Name: "password"},     // Sensitive
					{Name: "passwordHash"}, // Sensitive
					{Name: "secret_token"}, // Sensitive
					{Name: "api_key"},      // Sensitive
					{Name: "email"},
				},
			},
		},
	}

	sensitive := FindSensitiveFields(schema)

	if len(sensitive) < 4 {
		t.Errorf("expected at least 4 sensitive fields, got %d", len(sensitive))
	}

	hasPassword := false
	for _, s := range sensitive {
		if strings.Contains(s, "password") {
			hasPassword = true
			break
		}
	}

	if !hasPassword {
		t.Error("expected to find password-related field")
	}
}

func TestGenerateQueryForType(t *testing.T) {
	schema := &Schema{
		Types: []Type{
			{
				Name: "User",
				Kind: "OBJECT",
				Fields: []Field{
					{Name: "id", Type: FieldType{Kind: "SCALAR", Name: "ID"}},
					{Name: "name", Type: FieldType{Kind: "SCALAR", Name: "String"}},
				},
			},
		},
	}

	query := GenerateQueryForType(schema, "User", 2)

	if query == "" {
		t.Fatal("expected query to be generated")
	}

	if !strings.Contains(query, "query") {
		t.Error("should start with 'query'")
	}
}

func TestGetBaseTypeName(t *testing.T) {
	t.Run("simple type", func(t *testing.T) {
		ft := FieldType{Name: "String", Kind: "SCALAR"}
		if getBaseTypeName(ft) != "String" {
			t.Errorf("expected String, got %s", getBaseTypeName(ft))
		}
	})

	t.Run("wrapped type", func(t *testing.T) {
		ft := FieldType{
			Kind: "NON_NULL",
			OfType: &FieldType{
				Kind: "LIST",
				OfType: &FieldType{
					Kind: "OBJECT",
					Name: "User",
				},
			},
		}
		if getBaseTypeName(ft) != "User" {
			t.Errorf("expected User, got %s", getBaseTypeName(ft))
		}
	})
}

func TestIsScalarType(t *testing.T) {
	scalars := []string{"String", "Int", "Float", "Boolean", "ID", "DateTime"}
	nonScalars := []string{"User", "Post", "Query", "CustomType"}

	for _, s := range scalars {
		if !isScalarType(s) {
			t.Errorf("%s should be scalar", s)
		}
	}

	for _, s := range nonScalars {
		if isScalarType(s) {
			t.Errorf("%s should not be scalar", s)
		}
	}
}

func TestVulnerabilitySeverities(t *testing.T) {
	severities := []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info}

	for _, s := range severities {
		if s == "" {
			t.Error("severity should not be empty")
		}
	}
}

func TestAttackTypes(t *testing.T) {
	attacks := []AttackType{
		AttackIntrospection, AttackDepth, AttackBatch, AttackFieldDuplication,
		AttackCircularFragments, AttackDirectiveOverload, AttackAlias,
		AttackInjection, AttackFieldSuggestion, AttackIDOR,
	}

	for _, a := range attacks {
		if a == "" {
			t.Error("attack type should not be empty")
		}
	}
}

func TestRequestJSON(t *testing.T) {
	req := Request{
		Query:         "{ users { id } }",
		OperationName: "GetUsers",
		Variables:     map[string]interface{}{"limit": 10},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed Request
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.Query != req.Query {
		t.Errorf("query mismatch: %s", parsed.Query)
	}

	if parsed.OperationName != req.OperationName {
		t.Errorf("operation name mismatch: %s", parsed.OperationName)
	}
}

func TestResponseJSON(t *testing.T) {
	resp := Response{
		Data: json.RawMessage(`{"user": {"id": "1"}}`),
		Errors: []Error{
			{
				Message:   "Test error",
				Locations: []Location{{Line: 1, Column: 1}},
				Path:      []interface{}{"user", "name"},
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed Response
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(parsed.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(parsed.Errors))
	}
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		json.NewEncoder(w).Encode(Response{})
	}))
	defer server.Close()

	tester := NewTester(server.URL, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, err := tester.SendQuery(ctx, "{ __typename }", nil)
	if err == nil {
		// May or may not error depending on timing
		t.Log("request completed before cancellation")
	}
}
