package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewParser(t *testing.T) {
	parser := NewParser()
	if parser == nil {
		t.Fatal("expected non-nil parser")
	}
}

func TestParseSwagger2(t *testing.T) {
	swagger2Spec := `{
		"swagger": "2.0",
		"info": {
			"title": "Test API",
			"version": "1.0.0"
		},
		"basePath": "/api/v1",
		"host": "example.com",
		"paths": {
			"/users": {
				"get": {
					"operationId": "getUsers",
					"summary": "Get all users",
					"tags": ["users"],
					"parameters": [
						{
							"name": "limit",
							"in": "query",
							"type": "integer"
						}
					]
				},
				"post": {
					"operationId": "createUser",
					"summary": "Create a user",
					"tags": ["users"],
					"consumes": ["application/json"]
				}
			},
			"/users/{id}": {
				"get": {
					"operationId": "getUser",
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"type": "string"
						}
					]
				}
			}
		}
	}`

	parser := NewParser()
	spec, err := parser.Parse([]byte(swagger2Spec))

	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if spec.Version != "2.0" {
		t.Errorf("expected version 2.0, got %s", spec.Version)
	}

	if spec.Title != "Test API" {
		t.Errorf("expected title 'Test API', got '%s'", spec.Title)
	}

	if spec.BasePath != "/api/v1" {
		t.Errorf("expected basePath '/api/v1', got '%s'", spec.BasePath)
	}

	if len(spec.Routes) != 3 {
		t.Errorf("expected 3 routes, got %d", len(spec.Routes))
	}

	// Verify specific route
	for _, route := range spec.Routes {
		if route.Path == "/users" && route.Method == "GET" {
			if route.OperationID != "getUsers" {
				t.Errorf("expected operationId 'getUsers', got '%s'", route.OperationID)
			}
			if len(route.Tags) != 1 || route.Tags[0] != "users" {
				t.Error("expected tag 'users'")
			}
		}
	}
}

func TestParseOpenAPI3(t *testing.T) {
	openapi3Spec := `{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API v3",
			"version": "1.0.0"
		},
		"servers": [
			{"url": "https://api.example.com/v1"},
			{"url": "https://staging-api.example.com/v1"}
		],
		"paths": {
			"/items": {
				"get": {
					"operationId": "listItems",
					"summary": "List items",
					"parameters": [
						{
							"name": "page",
							"in": "query",
							"schema": {"type": "integer"}
						}
					]
				},
				"post": {
					"operationId": "createItem",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {"type": "object"},
								"example": {"name": "test"}
							}
						}
					}
				}
			}
		},
		"components": {
			"securitySchemes": {
				"bearerAuth": {
					"type": "http",
					"scheme": "bearer"
				}
			}
		}
	}`

	parser := NewParser()
	spec, err := parser.Parse([]byte(openapi3Spec))

	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if spec.Version != "3.0.0" {
		t.Errorf("expected version 3.0.0, got %s", spec.Version)
	}

	if len(spec.Servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(spec.Servers))
	}

	if len(spec.Routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(spec.Routes))
	}

	// Check POST has request body
	for _, route := range spec.Routes {
		if route.Method == "POST" {
			if route.RequestBody == nil {
				t.Error("expected requestBody for POST")
			} else {
				if route.RequestBody.ContentType != "application/json" {
					t.Errorf("expected content type 'application/json', got '%s'", route.RequestBody.ContentType)
				}
			}
		}
	}

	// Check security scheme
	if len(spec.Security) != 1 {
		t.Errorf("expected 1 security scheme, got %d", len(spec.Security))
	} else {
		if spec.Security[0].Name != "bearerAuth" {
			t.Errorf("expected security scheme 'bearerAuth', got '%s'", spec.Security[0].Name)
		}
	}
}

func TestGenerateTestCases(t *testing.T) {
	spec := &OpenAPISpec{
		BasePath: "/api",
		Routes: []Route{
			{
				Path:        "/users/{id}",
				Method:      "GET",
				OperationID: "getUser",
				Parameters: []Parameter{
					{Name: "id", In: "path", Type: "string", Example: "123"},
				},
			},
			{
				Path:   "/search",
				Method: "GET",
				Parameters: []Parameter{
					{Name: "q", In: "query", Type: "string", Required: true},
					{Name: "limit", In: "query", Type: "integer", Default: 10},
				},
			},
		},
	}

	cases := spec.GenerateTestCases("https://api.example.com")

	if len(cases) != 2 {
		t.Errorf("expected 2 test cases, got %d", len(cases))
	}

	// Check path parameter substitution
	for _, tc := range cases {
		if tc.Name == "getUser" {
			if tc.Path != "/api/users/123" {
				t.Errorf("expected path '/api/users/123', got '%s'", tc.Path)
			}
		}
		if tc.Path == "/api/search" || tc.Method == "GET" {
			// Should have query params
			if !containsString(tc.Path, "q=") {
				t.Logf("path: %s", tc.Path)
			}
		}
	}
}

func TestParameterExampleValues(t *testing.T) {
	tests := []struct {
		param    Parameter
		expected string
	}{
		{Parameter{Type: "integer"}, "1"},
		{Parameter{Type: "boolean"}, "true"},
		{Parameter{Type: "string", Format: "email"}, "test@example.com"},
		{Parameter{Type: "string", Format: "uuid"}, "00000000-0000-0000-0000-000000000000"},
		{Parameter{Type: "string", Format: "date"}, "2024-01-15"},
		{Parameter{Type: "string", Enum: []string{"active", "inactive"}}, "active"},
		{Parameter{Example: "custom"}, "custom"},
		{Parameter{Default: "defaultValue"}, "defaultValue"},
	}

	for _, tt := range tests {
		result := getExampleValue(tt.param)
		if result != tt.expected {
			t.Errorf("expected '%s', got '%s' for param %+v", tt.expected, result, tt.param)
		}
	}
}

func TestInferAPIRoutes(t *testing.T) {
	content := `
		const userAPI = '/api/v1/users';
		fetch('/api/posts');
		axios.get("/v2/comments");
		$.ajax({ url: "/api/products/search" });
	`

	routes := InferAPIRoutes(content)

	if len(routes) < 3 {
		t.Errorf("expected at least 3 routes, got %d", len(routes))
	}

	foundPaths := make(map[string]bool)
	for _, r := range routes {
		foundPaths[r.Path] = true
	}

	expectedPaths := []string{"/api/v1/users", "/api/posts", "/v2/comments"}
	for _, p := range expectedPaths {
		if !foundPaths[p] {
			t.Errorf("expected path '%s' not found", p)
		}
	}
}

func TestDepthScanner(t *testing.T) {
	// Create mock server
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not found"))
	}))
	defer server.Close()

	scanner := NewDepthScanner(nil)

	ctx := context.Background()
	result, err := scanner.ScanPath(ctx, server.URL, "/test/path", "GET")

	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if result.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", result.StatusCode)
	}
}

func TestPreflightCheck(t *testing.T) {
	// Wildcard server - returns 200 for everything
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome!"))
	}))
	defer server.Close()

	scanner := NewDepthScanner(nil)

	ctx := context.Background()
	info, err := scanner.PreflightCheck(ctx, server.URL, 1)

	if err != nil {
		t.Fatalf("preflight error: %v", err)
	}

	if !info.IsWildcard {
		t.Error("expected wildcard detection")
	}
}

func TestContentLenIgnoreRange(t *testing.T) {
	config := &DepthScanConfig{
		ContentLenIgnore: []Range{
			{Min: 0, Max: 100},
			{Min: 500, Max: 600},
		},
	}

	scanner := NewDepthScanner(config)

	if !scanner.isInIgnoreRange(50) {
		t.Error("50 should be in ignore range 0-100")
	}

	if !scanner.isInIgnoreRange(550) {
		t.Error("550 should be in ignore range 500-600")
	}

	if scanner.isInIgnoreRange(200) {
		t.Error("200 should not be in any ignore range")
	}
}

func TestBuildDepthPrefix(t *testing.T) {
	tests := []struct {
		depth    int
		segments int
	}{
		{0, 0},
		{1, 1},
		{3, 3},
		{5, 5},
	}

	for _, tt := range tests {
		prefix := buildDepthPrefix(tt.depth)
		if tt.depth == 0 {
			if prefix != "" {
				t.Errorf("depth 0 should return empty string, got '%s'", prefix)
			}
		} else {
			segments := len(strings.Split(strings.Trim(prefix, "/"), "/"))
			if segments != tt.segments {
				t.Errorf("expected %d segments for depth %d, got %d", tt.segments, tt.depth, segments)
			}
		}
	}
}

func TestRouteToJSON(t *testing.T) {
	route := Route{
		Path:        "/api/users",
		Method:      "GET",
		OperationID: "getUsers",
		Tags:        []string{"users"},
	}

	data, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded Route
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Path != route.Path {
		t.Error("path mismatch")
	}
}

func TestIsHTTPMethod(t *testing.T) {
	validMethods := []string{"get", "GET", "post", "POST", "put", "delete", "patch", "options", "head"}
	for _, m := range validMethods {
		if !isHTTPMethod(m) {
			t.Errorf("%s should be valid HTTP method", m)
		}
	}

	invalidMethods := []string{"parameters", "servers", "components", "x-extension", ""}
	for _, m := range invalidMethods {
		if isHTTPMethod(m) {
			t.Errorf("%s should not be valid HTTP method", m)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}
