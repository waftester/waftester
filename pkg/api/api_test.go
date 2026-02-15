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
		if tc.Path == "/api/search" {
			// Search endpoint should have query params
			if !containsString(tc.Path, "q=") {
				t.Errorf("expected query param q= in path %q", tc.Path)
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

// ──────────────────────────────────────────────────────────────────────────────
// Regression tests: each catches a specific Round 5 parser bug.
// ──────────────────────────────────────────────────────────────────────────────

func TestRegression_OpenAPI3PathLevelParams(t *testing.T) {
	// BUG (Round 5): parseOpenAPI3Paths only read operation-level params,
	// silently dropping path-level params. A spec like GET /users/{userId}
	// with userId defined at path level would produce a route with 0 path
	// params → the scanner would send requests to /users/{userId} literally.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"paths": {
			"/users/{userId}": {
				"parameters": [
					{
						"name": "userId",
						"in": "path",
						"required": true,
						"schema": {"type": "integer"}
					}
				],
				"get": {
					"operationId": "getUser",
					"parameters": [
						{
							"name": "include",
							"in": "query",
							"schema": {"type": "string"}
						}
					]
				}
			}
		}
	}`

	parser := NewParser()
	result, err := parser.Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(result.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(result.Routes))
	}

	route := result.Routes[0]
	if len(route.Parameters) != 2 {
		t.Fatalf("expected 2 params (path-level userId + operation-level include), got %d: %v",
			len(route.Parameters), route.Parameters)
	}

	// Verify both params present and have correct locations.
	paramByName := make(map[string]Parameter)
	for _, p := range route.Parameters {
		paramByName[p.Name] = p
	}
	if _, ok := paramByName["userId"]; !ok {
		t.Fatal("missing path-level param 'userId'")
	}
	if paramByName["userId"].In != "path" {
		t.Errorf("userId.In = %q, want 'path'", paramByName["userId"].In)
	}
	if _, ok := paramByName["include"]; !ok {
		t.Fatal("missing operation-level param 'include'")
	}
}

func TestRegression_OpenAPI3PathParamsMergedAcrossOperations(t *testing.T) {
	// Path-level params must be available for EVERY operation under that path.
	// Previously, only the first operation received them.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"paths": {
			"/users/{userId}": {
				"parameters": [
					{
						"name": "userId",
						"in": "path",
						"required": true,
						"schema": {"type": "integer"}
					}
				],
				"get": {
					"operationId": "getUser"
				},
				"delete": {
					"operationId": "deleteUser",
					"parameters": [
						{
							"name": "force",
							"in": "query",
							"schema": {"type": "boolean"}
						}
					]
				}
			}
		}
	}`

	parser := NewParser()
	result, err := parser.Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(result.Routes) != 2 {
		t.Fatalf("expected 2 routes (GET + DELETE), got %d", len(result.Routes))
	}

	for _, route := range result.Routes {
		hasUserID := false
		for _, p := range route.Parameters {
			if p.Name == "userId" {
				hasUserID = true
			}
		}
		if !hasUserID {
			t.Errorf("%s %s: missing path-level param 'userId'", route.Method, route.Path)
		}
	}

	// DELETE should have userId + force = 2 params.
	for _, route := range result.Routes {
		if route.Method == "DELETE" && len(route.Parameters) != 2 {
			t.Errorf("DELETE expects 2 params (userId + force), got %d", len(route.Parameters))
		}
	}
}

func TestRegression_OpenAPI3OperationOverridesPathParam(t *testing.T) {
	// Per OpenAPI 3 spec: when same param name+in appears at both path and
	// operation level, operation-level takes precedence.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"paths": {
			"/items/{itemId}": {
				"parameters": [
					{
						"name": "itemId",
						"in": "path",
						"required": true,
						"schema": {"type": "string"},
						"description": "path-level"
					}
				],
				"get": {
					"parameters": [
						{
							"name": "itemId",
							"in": "path",
							"required": true,
							"schema": {"type": "integer"},
							"description": "operation-level"
						}
					]
				}
			}
		}
	}`

	parser := NewParser()
	result, err := parser.Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	route := result.Routes[0]
	if len(route.Parameters) != 1 {
		t.Fatalf("expected 1 param (operation overrides path), got %d", len(route.Parameters))
	}
	if route.Parameters[0].Type != "integer" {
		t.Errorf("expected operation-level type 'integer', got '%s'", route.Parameters[0].Type)
	}
}

func TestRegression_RealisticMultiEndpointSpec(t *testing.T) {
	// A realistic spec with multiple paths, shared path params, request bodies,
	// and mixed param locations. This is what a real scanner processes.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Users API", "version": "2.0.0"},
		"servers": [{"url": "https://api.example.com/v2"}],
		"paths": {
			"/users": {
				"get": {
					"parameters": [
						{"name": "page", "in": "query", "schema": {"type": "integer"}},
						{"name": "limit", "in": "query", "schema": {"type": "integer"}}
					]
				},
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"},
										"email": {"type": "string"}
									}
								}
							}
						}
					}
				}
			},
			"/users/{userId}": {
				"parameters": [
					{
						"name": "userId",
						"in": "path",
						"required": true,
						"schema": {"type": "integer"}
					}
				],
				"get": {
					"parameters": [
						{"name": "fields", "in": "query", "schema": {"type": "string"}}
					]
				},
				"put": {
					"parameters": [
						{"name": "X-Request-Id", "in": "header", "schema": {"type": "string"}}
					],
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"}
									}
								}
							}
						}
					}
				}
			},
			"/users/{userId}/posts/{postId}": {
				"parameters": [
					{"name": "userId", "in": "path", "required": true, "schema": {"type": "integer"}},
					{"name": "postId", "in": "path", "required": true, "schema": {"type": "integer"}}
				],
				"get": {
					"operationId": "getUserPost"
				}
			}
		}
	}`

	parser := NewParser()
	result, err := parser.Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// 5 operations: GET /users, POST /users, GET /users/{userId},
	// PUT /users/{userId}, GET /users/{userId}/posts/{postId}
	if len(result.Routes) != 5 {
		t.Fatalf("expected 5 routes, got %d", len(result.Routes))
	}

	// Build a lookup by method+path.
	type routeKey struct{ method, path string }
	routeMap := make(map[routeKey]Route)
	for _, r := range result.Routes {
		routeMap[routeKey{r.Method, r.Path}] = r
	}

	// GET /users: 2 query params, no path params.
	getUsers := routeMap[routeKey{"GET", "/users"}]
	if len(getUsers.Parameters) != 2 {
		t.Errorf("GET /users: want 2 params, got %d", len(getUsers.Parameters))
	}

	// GET /users/{userId}: path-level userId + operation-level fields = 2 params.
	getUser := routeMap[routeKey{"GET", "/users/{userId}"}]
	if len(getUser.Parameters) != 2 {
		t.Errorf("GET /users/{userId}: want 2 params (userId + fields), got %d: %+v",
			len(getUser.Parameters), getUser.Parameters)
	}

	// PUT /users/{userId}: path-level userId + header X-Request-Id = 2 params.
	putUser := routeMap[routeKey{"PUT", "/users/{userId}"}]
	if len(putUser.Parameters) != 2 {
		t.Errorf("PUT /users/{userId}: want 2 params (userId + X-Request-Id), got %d: %+v",
			len(putUser.Parameters), putUser.Parameters)
	}

	// GET /users/{userId}/posts/{postId}: 2 path-level params, no operation params.
	getPost := routeMap[routeKey{"GET", "/users/{userId}/posts/{postId}"}]
	if len(getPost.Parameters) != 2 {
		t.Errorf("GET /users/{userId}/posts/{postId}: want 2 params, got %d: %+v",
			len(getPost.Parameters), getPost.Parameters)
	}
	// Verify the params are actually path params.
	for _, p := range getPost.Parameters {
		if p.In != "path" {
			t.Errorf("expected path param, got %q for %q", p.In, p.Name)
		}
	}
}

func TestRegression_Swagger2PathLevelParams(t *testing.T) {
	// Swagger 2 already handled path-level params, but verify the merge logic
	// didn't break it.
	spec := `{
		"swagger": "2.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"basePath": "/api",
		"paths": {
			"/users/{userId}": {
				"parameters": [
					{
						"name": "userId",
						"in": "path",
						"required": true,
						"type": "string"
					}
				],
				"get": {
					"parameters": [
						{
							"name": "fields",
							"in": "query",
							"type": "string"
						}
					]
				}
			}
		}
	}`

	parser := NewParser()
	result, err := parser.Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(result.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(result.Routes))
	}

	route := result.Routes[0]
	if len(route.Parameters) != 2 {
		t.Fatalf("expected 2 params (path userId + query fields), got %d", len(route.Parameters))
	}

	paramByName := make(map[string]Parameter)
	for _, p := range route.Parameters {
		paramByName[p.Name] = p
	}
	if _, ok := paramByName["userId"]; !ok {
		t.Fatal("missing path-level param 'userId'")
	}
	if _, ok := paramByName["fields"]; !ok {
		t.Fatal("missing operation-level param 'fields'")
	}
}

func TestParseEmptySpec(t *testing.T) {
	parser := NewParser()
	_, err := parser.Parse([]byte("{}"))
	// Should not panic on empty spec.
	_ = err
}

func TestParseInvalidJSON(t *testing.T) {
	parser := NewParser()
	_, err := parser.Parse([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

// TestRegression_BuildQueryStringEncoding verifies that query string values
// are URL-encoded. Before the fix, values were concatenated raw, allowing
// parameter injection (e.g., "a&admin=true" would split into two params).
func TestRegression_BuildQueryStringEncoding(t *testing.T) {
	params := map[string]string{
		"search": "a&admin=true",
		"page":   "1",
	}
	qs := buildQueryString(params)

	// The "&" in the value must be encoded, not treated as a parameter separator.
	if strings.Count(qs, "&") != 1 {
		t.Errorf("expected exactly 1 literal '&' separator, got query string: %s", qs)
	}
	if strings.Contains(qs, "admin=true") {
		t.Errorf("parameter injection: 'admin=true' should be encoded, got: %s", qs)
	}
	if !strings.Contains(qs, "a%26admin%3Dtrue") {
		t.Errorf("expected URL-encoded value 'a%%26admin%%3Dtrue', got: %s", qs)
	}
}
