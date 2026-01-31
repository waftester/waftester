package openapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sample OpenAPI specs for testing
const sampleOpenAPIJSON = `{
  "openapi": "3.0.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "https://api.example.com/v1"
    }
  ],
  "paths": {
    "/users": {
      "get": {
        "operationId": "listUsers",
        "summary": "List all users",
        "parameters": [
          {
            "name": "search",
            "in": "query",
            "schema": {"type": "string"}
          }
        ],
        "responses": {
          "200": {"description": "Success"}
        }
      },
      "post": {
        "operationId": "createUser",
        "summary": "Create a user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/User"
              }
            }
          }
        },
        "responses": {
          "201": {"description": "Created"}
        }
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
            "schema": {"type": "integer"},
            "example": 123
          }
        ],
        "responses": {
          "200": {"description": "Success"}
        }
      }
    }
  },
  "components": {
    "schemas": {
      "User": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "email": {"type": "string"},
          "age": {"type": "integer"}
        }
      }
    }
  }
}`

const sampleOpenAPIYAML = `openapi: "3.0.0"
info:
  title: Test API YAML
  version: "1.0.0"
servers:
  - url: https://api.yaml.com
paths:
  /items:
    get:
      operationId: listItems
      parameters:
        - name: filter
          in: query
          schema:
            type: string
      responses:
        "200":
          description: Success
`

func TestParserParseJSON(t *testing.T) {
	parser := NewParser()
	spec, err := parser.ParseJSON([]byte(sampleOpenAPIJSON))

	require.NoError(t, err)
	assert.Equal(t, "3.0.0", spec.OpenAPI)
	assert.Equal(t, "Test API", spec.Info.Title)
	assert.Equal(t, "1.0.0", spec.Info.Version)
	assert.Len(t, spec.Servers, 1)
	assert.Equal(t, "https://api.example.com/v1", spec.Servers[0].URL)
	assert.Len(t, spec.Paths, 2)
}

func TestParserParseYAML(t *testing.T) {
	parser := NewParser()
	spec, err := parser.ParseYAML([]byte(sampleOpenAPIYAML))

	require.NoError(t, err)
	assert.Equal(t, "3.0.0", spec.OpenAPI)
	assert.Equal(t, "Test API YAML", spec.Info.Title)
	assert.Contains(t, spec.Paths, "/items")
}

func TestParserParseFile(t *testing.T) {
	// Create temp JSON file
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "spec.json")
	err := os.WriteFile(jsonPath, []byte(sampleOpenAPIJSON), 0644)
	require.NoError(t, err)

	parser := NewParser()
	spec, err := parser.ParseFile(jsonPath)

	require.NoError(t, err)
	assert.Equal(t, "Test API", spec.Info.Title)

	// Create temp YAML file
	yamlPath := filepath.Join(tmpDir, "spec.yaml")
	err = os.WriteFile(yamlPath, []byte(sampleOpenAPIYAML), 0644)
	require.NoError(t, err)

	spec2, err := parser.ParseFile(yamlPath)
	require.NoError(t, err)
	assert.Equal(t, "Test API YAML", spec2.Info.Title)
}

func TestParserGetOperations(t *testing.T) {
	parser := NewParser()
	spec, err := parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	ops := parser.GetOperations(spec)

	assert.Len(t, ops, 3) // GET /users, POST /users, GET /users/{id}

	methods := make(map[string]bool)
	paths := make(map[string]bool)
	for _, op := range ops {
		methods[op.Method] = true
		paths[op.Path] = true
	}

	assert.True(t, methods["GET"])
	assert.True(t, methods["POST"])
	assert.True(t, paths["/users"])
	assert.True(t, paths["/users/{id}"])
}

func TestParserResolveRef(t *testing.T) {
	parser := NewParser()
	spec, err := parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	schema := parser.ResolveRef(spec, "#/components/schemas/User")

	require.NotNil(t, schema)
	assert.Equal(t, "object", schema.Type)
	assert.Contains(t, schema.Properties, "name")
	assert.Contains(t, schema.Properties, "email")
	assert.Contains(t, schema.Properties, "age")
}

func TestParserGetBaseURL(t *testing.T) {
	parser := NewParser()
	spec, err := parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	baseURL := parser.GetBaseURL(spec)
	assert.Equal(t, "https://api.example.com/v1", baseURL)
}

func TestGeneratorGenerate(t *testing.T) {
	gen := NewGenerator()
	spec, err := gen.parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	tests, err := gen.Generate(spec)

	require.NoError(t, err)
	assert.NotEmpty(t, tests)

	// Should have baseline tests
	var baselineCount int
	for _, test := range tests {
		for _, tag := range test.Tags {
			if tag == "baseline" {
				baselineCount++
				break
			}
		}
	}
	assert.GreaterOrEqual(t, baselineCount, 1)
}

func TestGeneratorWithCustomBaseURL(t *testing.T) {
	gen := NewGenerator(WithBaseURL("https://custom.url.com/api"))
	spec, err := gen.parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	tests, err := gen.Generate(spec)
	require.NoError(t, err)

	// All endpoints should use custom base URL
	for _, test := range tests {
		assert.Contains(t, test.Endpoint, "https://custom.url.com/api")
	}
}

func TestGeneratorWithCustomPayloads(t *testing.T) {
	customPayloads := map[string][]string{
		"custom": {"CUSTOM_PAYLOAD_1", "CUSTOM_PAYLOAD_2"},
	}

	gen := NewGenerator(WithPayloads(customPayloads))
	spec, err := gen.parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	tests, err := gen.Generate(spec)
	require.NoError(t, err)

	// Find tests with custom payloads
	var customCount int
	for _, test := range tests {
		if test.Payload == "CUSTOM_PAYLOAD_1" || test.Payload == "CUSTOM_PAYLOAD_2" {
			customCount++
		}
	}
	assert.Greater(t, customCount, 0)
}

func TestGeneratorParameterInjection(t *testing.T) {
	gen := NewGenerator()
	spec, err := gen.parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	tests, err := gen.Generate(spec)
	require.NoError(t, err)

	// Find query parameter injection tests
	var queryTests []TestCase
	for _, test := range tests {
		if test.InjectionPoint == "query:search" {
			queryTests = append(queryTests, test)
		}
	}

	assert.NotEmpty(t, queryTests)
	// Should have tests for each payload category
	categories := make(map[string]bool)
	for _, test := range queryTests {
		categories[test.PayloadType] = true
	}
	assert.True(t, categories["sqli"])
	assert.True(t, categories["xss"])
}

func TestGeneratorPathParameterInjection(t *testing.T) {
	gen := NewGenerator()
	spec, err := gen.parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	tests, err := gen.Generate(spec)
	require.NoError(t, err)

	// Find path parameter injection tests
	var pathTests []TestCase
	for _, test := range tests {
		if test.InjectionPoint == "path:id" {
			pathTests = append(pathTests, test)
		}
	}

	assert.NotEmpty(t, pathTests)
	// Path should have payload injected
	for _, test := range pathTests {
		assert.NotContains(t, test.Path, "{id}")
	}
}

func TestGeneratorBodyInjection(t *testing.T) {
	gen := NewGenerator()
	spec, err := gen.parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	tests, err := gen.Generate(spec)
	require.NoError(t, err)

	// Find body injection tests
	var bodyTests []TestCase
	for _, test := range tests {
		for _, tag := range test.Tags {
			if tag == "body" {
				bodyTests = append(bodyTests, test)
				break
			}
		}
	}

	assert.NotEmpty(t, bodyTests)
	// Should have JSON body
	for _, test := range bodyTests {
		assert.NotEmpty(t, test.Body)
		assert.Equal(t, "application/json", test.ContentType)
	}
}

func TestGeneratorHeaderInjection(t *testing.T) {
	gen := NewGenerator()
	spec, err := gen.parser.ParseJSON([]byte(sampleOpenAPIJSON))
	require.NoError(t, err)

	tests, err := gen.Generate(spec)
	require.NoError(t, err)

	// Find header injection tests
	var headerTests []TestCase
	for _, test := range tests {
		for _, tag := range test.Tags {
			if tag == "header" {
				headerTests = append(headerTests, test)
				break
			}
		}
	}

	assert.NotEmpty(t, headerTests)
}

func TestGenerateJSONBody(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		fieldPath string
		payload   string
		expected  string
	}{
		{"name", "payload", `{"name":"payload"}`},
		{"user.name", "payload", `{"user":{"name":"payload"}}`},
		{"items[0]", "payload", `{"items":["payload"]}`},
	}

	for _, tt := range tests {
		t.Run(tt.fieldPath, func(t *testing.T) {
			result := gen.generateJSONBody(tt.fieldPath, tt.payload)
			assert.JSONEq(t, tt.expected, result)
		})
	}
}

func TestGenerateFormBody(t *testing.T) {
	gen := NewGenerator()

	result := gen.generateFormBody("user.email", "test@example.com")
	assert.Equal(t, "email=test%40example.com", result)
}

func TestGenerateXMLBody(t *testing.T) {
	gen := NewGenerator()

	result := gen.generateXMLBody("user.name", "payload")
	assert.Contains(t, result, "<user>")
	assert.Contains(t, result, "<name>")
	assert.Contains(t, result, "payload")
	assert.Contains(t, result, "</name>")
	assert.Contains(t, result, "</user>")
}

func TestExpandPath(t *testing.T) {
	gen := NewGenerator()

	params := []Parameter{
		{Name: "id", In: "path", Example: 123},
		{Name: "version", In: "path", Schema: &Schema{Example: "v2"}},
	}

	result := gen.expandPath("/users/{id}/docs/{version}", params)
	assert.Equal(t, "/users/123/docs/v2", result)
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/users/{id}", "users_id"},
		{"/api/v1/items", "api_v1_items"},
		{"field.name", "field_name"},
		{"some-path", "some_path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExportTests(t *testing.T) {
	tests := []TestCase{
		{
			Name:     "test1",
			Endpoint: "https://example.com/test",
			Method:   "GET",
		},
	}

	data, err := ExportTests(tests)
	require.NoError(t, err)
	assert.Contains(t, string(data), "test1")
	assert.Contains(t, string(data), "https://example.com/test")
}

func TestGenerateFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	specPath := filepath.Join(tmpDir, "api.json")
	err := os.WriteFile(specPath, []byte(sampleOpenAPIJSON), 0644)
	require.NoError(t, err)

	gen := NewGenerator()
	tests, err := gen.GenerateFromFile(specPath)

	require.NoError(t, err)
	assert.NotEmpty(t, tests)
}

func TestParserInvalidJSON(t *testing.T) {
	parser := NewParser()
	_, err := parser.ParseJSON([]byte("not valid json"))
	assert.Error(t, err)
}

func TestParserInvalidYAML(t *testing.T) {
	parser := NewParser()
	_, err := parser.ParseYAML([]byte("not: valid: yaml: ["))
	assert.Error(t, err)
}

func TestParserFileNotFound(t *testing.T) {
	parser := NewParser()
	_, err := parser.ParseFile("/nonexistent/file.json")
	assert.Error(t, err)
}

func TestGetSchemaFieldsNested(t *testing.T) {
	gen := NewGenerator()

	nestedSpec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0"},
		"paths": {},
		"components": {
			"schemas": {
				"Address": {
					"type": "object",
					"properties": {
						"street": {"type": "string"},
						"city": {"type": "string"}
					}
				},
				"User": {
					"type": "object",
					"properties": {
						"name": {"type": "string"},
						"address": {"$ref": "#/components/schemas/Address"}
					}
				}
			}
		}
	}`

	spec, err := gen.parser.ParseJSON([]byte(nestedSpec))
	require.NoError(t, err)

	userSchema := spec.Components.Schemas["User"]
	fields := gen.getSchemaFields(userSchema, spec, "")

	// Should have name, address.street, address.city
	paths := make(map[string]bool)
	for _, f := range fields {
		paths[f.Path] = true
	}

	assert.True(t, paths["name"])
	assert.True(t, paths["address.street"])
	assert.True(t, paths["address.city"])
}

func TestGetSchemaFieldsArray(t *testing.T) {
	gen := NewGenerator()

	arraySpec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0"},
		"paths": {},
		"components": {
			"schemas": {
				"Items": {
					"type": "array",
					"items": {
						"type": "object",
						"properties": {
							"id": {"type": "integer"},
							"name": {"type": "string"}
						}
					}
				}
			}
		}
	}`

	spec, err := gen.parser.ParseJSON([]byte(arraySpec))
	require.NoError(t, err)

	itemsSchema := spec.Components.Schemas["Items"]
	fields := gen.getSchemaFields(itemsSchema, spec, "")

	paths := make(map[string]bool)
	for _, f := range fields {
		paths[f.Path] = true
	}

	assert.True(t, paths["[0].id"])
	assert.True(t, paths["[0].name"])
}
