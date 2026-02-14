package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/graphql"
)

func testSchema() *graphql.Schema {
	return &graphql.Schema{
		QueryType:    &graphql.TypeRef{Name: "Query"},
		MutationType: &graphql.TypeRef{Name: "Mutation"},
		Types: []graphql.Type{
			{
				Kind: "OBJECT",
				Name: "Query",
				Fields: []graphql.Field{
					{
						Name:        "user",
						Description: "Get a user by ID",
						Args: []graphql.InputValue{
							{
								Name: "id",
								Type: graphql.FieldType{Kind: "NON_NULL", OfType: &graphql.FieldType{Kind: "SCALAR", Name: "ID"}},
							},
						},
						Type: graphql.FieldType{Kind: "OBJECT", Name: "User"},
					},
					{
						Name:              "legacySearch",
						Description:       "Old search endpoint",
						IsDeprecated:      true,
						DeprecationReason: "Use search instead",
						Args: []graphql.InputValue{
							{
								Name: "query",
								Type: graphql.FieldType{Kind: "SCALAR", Name: "String"},
							},
						},
						Type: graphql.FieldType{Kind: "LIST", OfType: &graphql.FieldType{Kind: "OBJECT", Name: "SearchResult"}},
					},
				},
			},
			{
				Kind: "OBJECT",
				Name: "Mutation",
				Fields: []graphql.Field{
					{
						Name: "createUser",
						Args: []graphql.InputValue{
							{
								Name: "input",
								Type: graphql.FieldType{Kind: "NON_NULL", OfType: &graphql.FieldType{Kind: "INPUT_OBJECT", Name: "CreateUserInput"}},
							},
						},
						Type: graphql.FieldType{Kind: "OBJECT", Name: "User"},
					},
				},
			},
			{
				Kind: "INPUT_OBJECT",
				Name: "CreateUserInput",
				InputFields: []graphql.InputValue{
					{
						Name: "name",
						Type: graphql.FieldType{Kind: "NON_NULL", OfType: &graphql.FieldType{Kind: "SCALAR", Name: "String"}},
					},
					{
						Name:         "email",
						Type:         graphql.FieldType{Kind: "SCALAR", Name: "String"},
						DefaultValue: "user@example.com",
					},
					{
						Name: "age",
						Type: graphql.FieldType{Kind: "SCALAR", Name: "Int"},
					},
				},
			},
			{
				Kind: "ENUM",
				Name: "Role",
				EnumValues: []graphql.EnumValue{
					{Name: "ADMIN"},
					{Name: "USER"},
					{Name: "MODERATOR"},
				},
			},
			{
				Kind: "OBJECT",
				Name: "User",
				Fields: []graphql.Field{
					{Name: "id", Type: graphql.FieldType{Kind: "SCALAR", Name: "ID"}},
					{Name: "name", Type: graphql.FieldType{Kind: "SCALAR", Name: "String"}},
				},
			},
			{
				Kind: "OBJECT",
				Name: "SearchResult",
			},
		},
	}
}

func TestSchemaToSpec_Format(t *testing.T) {
	t.Parallel()
	spec := SchemaToSpec(testSchema(), "http://api.example.com/graphql")
	assert.Equal(t, FormatGraphQL, spec.Format)
	assert.Equal(t, "http://api.example.com/graphql", spec.Source)
	assert.Len(t, spec.Servers, 1)
}

func TestSchemaToSpec_QueriesConvertedToEndpoints(t *testing.T) {
	t.Parallel()
	spec := SchemaToSpec(testSchema(), "http://api.example.com/graphql")

	var queryEps []Endpoint
	for _, ep := range spec.Endpoints {
		if ep.Group == "query" {
			queryEps = append(queryEps, ep)
		}
	}
	require.Len(t, queryEps, 2)

	userEp := queryEps[0]
	assert.Equal(t, "query_user", userEp.OperationID)
	assert.Equal(t, "POST", userEp.Method)
	assert.Equal(t, "/graphql", userEp.Path)
	assert.Contains(t, userEp.Tags, "graphql")
	assert.Contains(t, userEp.Tags, "query")
}

func TestSchemaToSpec_MutationsConvertedToEndpoints(t *testing.T) {
	t.Parallel()
	spec := SchemaToSpec(testSchema(), "http://api.example.com/graphql")

	var mutEps []Endpoint
	for _, ep := range spec.Endpoints {
		if ep.Group == "mutation" {
			mutEps = append(mutEps, ep)
		}
	}
	require.Len(t, mutEps, 1)
	assert.Equal(t, "mutation_createUser", mutEps[0].OperationID)
}

func TestSchemaToSpec_ArgumentsMappedToParameters(t *testing.T) {
	t.Parallel()
	spec := SchemaToSpec(testSchema(), "http://api.example.com/graphql")

	// Find the user query.
	var userEp Endpoint
	for _, ep := range spec.Endpoints {
		if ep.OperationID == "query_user" {
			userEp = ep
			break
		}
	}

	require.Len(t, userEp.Parameters, 1)
	param := userEp.Parameters[0]
	assert.Equal(t, "id", param.Name)
	assert.Equal(t, LocationBody, param.In)
	assert.True(t, param.Required) // NON_NULL wrapping
	assert.Equal(t, "string", param.Schema.Type)
	assert.Equal(t, "id", param.Schema.Format)
}

func TestSchemaToSpec_DeprecatedOperations(t *testing.T) {
	t.Parallel()
	spec := SchemaToSpec(testSchema(), "http://api.example.com/graphql")

	var deprecatedEp Endpoint
	for _, ep := range spec.Endpoints {
		if ep.OperationID == "query_legacySearch" {
			deprecatedEp = ep
			break
		}
	}

	assert.True(t, deprecatedEp.Deprecated)
	assert.Equal(t, PriorityCritical, deprecatedEp.Priority)
	assert.Contains(t, deprecatedEp.Description, "DEPRECATED")
	assert.Contains(t, deprecatedEp.Description, "Use search instead")
}

func TestSchemaToSpec_NestedInputTypes(t *testing.T) {
	t.Parallel()
	spec := SchemaToSpec(testSchema(), "http://api.example.com/graphql")

	var createUserEp Endpoint
	for _, ep := range spec.Endpoints {
		if ep.OperationID == "mutation_createUser" {
			createUserEp = ep
			break
		}
	}

	require.Len(t, createUserEp.Parameters, 1)
	inputParam := createUserEp.Parameters[0]
	assert.Equal(t, "input", inputParam.Name)
	assert.True(t, inputParam.Required)

	// The input type should be expanded.
	assert.Equal(t, "object", inputParam.Schema.Type)
	require.NotNil(t, inputParam.Schema.Properties)
	assert.Contains(t, inputParam.Schema.Properties, "name")
	assert.Contains(t, inputParam.Schema.Properties, "email")
	assert.Contains(t, inputParam.Schema.Properties, "age")
	assert.Equal(t, "string", inputParam.Schema.Properties["name"].Type)
	assert.Equal(t, "integer", inputParam.Schema.Properties["age"].Type)

	// Required fields from NON_NULL wrapper.
	assert.Contains(t, inputParam.Schema.Required, "name")
}

func TestSchemaToSpec_DefaultValues(t *testing.T) {
	t.Parallel()
	schema := &graphql.Schema{
		QueryType: &graphql.TypeRef{Name: "Query"},
		Types: []graphql.Type{
			{
				Kind: "OBJECT",
				Name: "Query",
				Fields: []graphql.Field{
					{
						Name: "search",
						Args: []graphql.InputValue{
							{
								Name:         "limit",
								Type:         graphql.FieldType{Kind: "SCALAR", Name: "Int"},
								DefaultValue: "10",
							},
						},
						Type: graphql.FieldType{Kind: "SCALAR", Name: "String"},
					},
				},
			},
		},
	}

	spec := SchemaToSpec(schema, "http://api.example.com/graphql")
	require.Len(t, spec.Endpoints, 1)
	require.Len(t, spec.Endpoints[0].Parameters, 1)
	assert.Equal(t, "10", spec.Endpoints[0].Parameters[0].Default)
}

func TestSchemaToSpec_EnumFields(t *testing.T) {
	t.Parallel()
	schema := &graphql.Schema{
		QueryType: &graphql.TypeRef{Name: "Query"},
		Types: []graphql.Type{
			{
				Kind: "OBJECT",
				Name: "Query",
				Fields: []graphql.Field{
					{
						Name: "usersByRole",
						Args: []graphql.InputValue{
							{
								Name: "role",
								Type: graphql.FieldType{Kind: "ENUM", Name: "Role"},
							},
						},
						Type: graphql.FieldType{Kind: "LIST", OfType: &graphql.FieldType{Kind: "OBJECT", Name: "User"}},
					},
				},
			},
			{
				Kind: "ENUM",
				Name: "Role",
				EnumValues: []graphql.EnumValue{
					{Name: "ADMIN"},
					{Name: "USER"},
					{Name: "MODERATOR"},
				},
			},
		},
	}

	spec := SchemaToSpec(schema, "http://api.example.com/graphql")
	require.Len(t, spec.Endpoints, 1)
	require.Len(t, spec.Endpoints[0].Parameters, 1)

	roleParam := spec.Endpoints[0].Parameters[0]
	assert.Equal(t, "string", roleParam.Schema.Type)
	assert.Equal(t, []string{"ADMIN", "USER", "MODERATOR"}, roleParam.Schema.Enum)
}

func TestSchemaToSpec_NoMutationType(t *testing.T) {
	t.Parallel()
	schema := &graphql.Schema{
		QueryType: &graphql.TypeRef{Name: "Query"},
		Types: []graphql.Type{
			{
				Kind: "OBJECT",
				Name: "Query",
				Fields: []graphql.Field{
					{Name: "health", Type: graphql.FieldType{Kind: "SCALAR", Name: "String"}},
				},
			},
		},
	}

	spec := SchemaToSpec(schema, "http://api.example.com/graphql")
	assert.Len(t, spec.Endpoints, 1)
	assert.Equal(t, "query_health", spec.Endpoints[0].OperationID)
}

func TestSchemaToSpec_CorrelationTags(t *testing.T) {
	t.Parallel()
	spec := SchemaToSpec(testSchema(), "http://api.example.com/graphql")
	for _, ep := range spec.Endpoints {
		assert.NotEmpty(t, ep.CorrelationTag, "endpoint %s should have correlation tag", ep.OperationID)
	}
}

func TestSchemaToSpec_ListArgType(t *testing.T) {
	t.Parallel()
	schema := &graphql.Schema{
		QueryType: &graphql.TypeRef{Name: "Query"},
		Types: []graphql.Type{
			{
				Kind: "OBJECT",
				Name: "Query",
				Fields: []graphql.Field{
					{
						Name: "usersByIds",
						Args: []graphql.InputValue{
							{
								Name: "ids",
								Type: graphql.FieldType{
									Kind:   "LIST",
									OfType: &graphql.FieldType{Kind: "SCALAR", Name: "ID"},
								},
							},
						},
						Type: graphql.FieldType{Kind: "LIST", OfType: &graphql.FieldType{Kind: "OBJECT", Name: "User"}},
					},
				},
			},
		},
	}

	spec := SchemaToSpec(schema, "http://api.example.com/graphql")
	require.Len(t, spec.Endpoints, 1)
	require.Len(t, spec.Endpoints[0].Parameters, 1)
	param := spec.Endpoints[0].Parameters[0]
	assert.Equal(t, "array", param.Schema.Type)
	require.NotNil(t, param.Schema.Items)
	assert.Equal(t, "string", param.Schema.Items.Type)
}

func TestExtractGraphQLOperations(t *testing.T) {
	t.Parallel()
	spec := SchemaToSpec(testSchema(), "http://api.example.com/graphql")
	queries, mutations := ExtractGraphQLOperations(spec)
	assert.Contains(t, queries, "user")
	assert.Contains(t, queries, "legacySearch")
	assert.Contains(t, mutations, "createUser")
}

func TestExtractGraphQLOperations_NonGraphQLSpec(t *testing.T) {
	t.Parallel()
	spec := &Spec{
		Format: FormatOpenAPI3,
		Endpoints: []Endpoint{
			{OperationID: "query_user"},
		},
	}
	queries, mutations := ExtractGraphQLOperations(spec)
	assert.Empty(t, queries)
	assert.Empty(t, mutations)
}

func TestGraphqlScalarToJSONType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		gqlType  string
		jsonType string
	}{
		{"Int", "integer"},
		{"Float", "number"},
		{"Boolean", "boolean"},
		{"String", "string"},
		{"ID", "string"},
		{"DateTime", "string"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.jsonType, graphqlScalarToJSONType(tt.gqlType), "for %s", tt.gqlType)
	}
}

func TestFieldTypeToSchema_MaxDepth(t *testing.T) {
	t.Parallel()
	// Deeply nested input type should hit max depth and return plain object.
	typeIndex := map[string]graphql.Type{
		"A": {Kind: "INPUT_OBJECT", Name: "A", InputFields: []graphql.InputValue{
			{Name: "b", Type: graphql.FieldType{Kind: "INPUT_OBJECT", Name: "A"}}, // self-referencing
		}},
	}
	schema := fieldTypeToSchema(graphql.FieldType{Kind: "INPUT_OBJECT", Name: "A"}, typeIndex, 0)
	assert.Equal(t, "object", schema.Type)
}

func TestIsNonNull(t *testing.T) {
	t.Parallel()
	assert.True(t, isNonNull(graphql.FieldType{Kind: "NON_NULL"}))
	assert.False(t, isNonNull(graphql.FieldType{Kind: "SCALAR"}))
}
