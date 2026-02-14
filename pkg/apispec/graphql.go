package apispec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/graphql"
)

// IntrospectionToSpec runs a GraphQL introspection query against the given
// endpoint and converts the schema into a Spec with FormatGraphQL.
//
// Each query and mutation becomes an Endpoint. Query arguments become
// Parameters with types mapped from GraphQL scalars to JSON schema types.
// Deprecated operations are marked on the Endpoint.
func IntrospectionToSpec(ctx context.Context, endpoint string) (*Spec, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("graphql endpoint is required")
	}

	cfg := graphql.DefaultConfig()
	tester := graphql.NewTester(endpoint, cfg)

	_, schema, err := tester.TestIntrospection(ctx)
	if err != nil {
		return nil, fmt.Errorf("introspection failed: %w", err)
	}
	if schema == nil {
		return nil, fmt.Errorf("introspection returned nil schema")
	}

	return SchemaToSpec(schema, endpoint), nil
}

// SchemaToSpec converts a parsed GraphQL schema into a Spec.
// This is separated from IntrospectionToSpec to allow testing
// without a live endpoint.
func SchemaToSpec(schema *graphql.Schema, endpoint string) *Spec {
	spec := &Spec{
		Format:      FormatGraphQL,
		Title:       "GraphQL API",
		Description: "Auto-discovered via introspection",
		Servers:     []Server{{URL: endpoint}},
		Source:      endpoint,
		ParsedAt:    time.Now(),
	}

	// Build type index for field lookups.
	typeIndex := buildTypeIndex(schema)

	// Convert queries.
	if schema.QueryType != nil {
		queryType := typeIndex[schema.QueryType.Name]
		for _, field := range queryType.Fields {
			ep := fieldToEndpoint(field, "query", endpoint, typeIndex)
			spec.Endpoints = append(spec.Endpoints, ep)
		}
	}

	// Convert mutations.
	if schema.MutationType != nil {
		mutationType := typeIndex[schema.MutationType.Name]
		for _, field := range mutationType.Fields {
			ep := fieldToEndpoint(field, "mutation", endpoint, typeIndex)
			spec.Endpoints = append(spec.Endpoints, ep)
		}
	}

	// Tag deprecated operations.
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Deprecated {
			spec.Endpoints[i].Priority = PriorityCritical
		}
	}

	return spec
}

// fieldToEndpoint converts a GraphQL field (query or mutation) into
// an apispec.Endpoint.
func fieldToEndpoint(field graphql.Field, opType string, endpoint string, typeIndex map[string]graphql.Type) Endpoint {
	method := "POST"
	// Path uses the GraphQL endpoint with the operation name.
	path := "/graphql"

	ep := Endpoint{
		Method:         method,
		Path:           path,
		OperationID:    fmt.Sprintf("%s_%s", opType, field.Name),
		Summary:        field.Description,
		Tags:           []string{"graphql", opType},
		Group:          opType,
		Deprecated:     field.IsDeprecated,
		CorrelationTag: CorrelationTag(method, fmt.Sprintf("/graphql/%s/%s", opType, field.Name)),
		ContentTypes:   []string{"application/json"},
		RequestBodies: map[string]RequestBody{
			"application/json": {
				Description: fmt.Sprintf("GraphQL %s: %s", opType, field.Name),
				Required:    true,
				Schema: SchemaInfo{
					Type: "object",
					Properties: map[string]SchemaInfo{
						"query": {Type: "string"},
						"variables": {
							Type:       "object",
							Properties: make(map[string]SchemaInfo),
						},
					},
				},
			},
		},
	}

	if field.IsDeprecated && field.DeprecationReason != "" {
		ep.Description = fmt.Sprintf("DEPRECATED: %s", field.DeprecationReason)
	}

	// Convert arguments to parameters.
	for _, arg := range field.Args {
		param := argToParameter(arg, typeIndex)
		ep.Parameters = append(ep.Parameters, param)
	}

	return ep
}

// argToParameter converts a GraphQL input value (argument) to an
// apispec.Parameter, expanding nested input types to flat parameters.
func argToParameter(arg graphql.InputValue, typeIndex map[string]graphql.Type) Parameter {
	schema := fieldTypeToSchema(arg.Type, typeIndex, 0)

	required := isNonNull(arg.Type)

	return Parameter{
		Name:        arg.Name,
		In:          LocationBody,
		Description: arg.Description,
		Required:    required,
		Schema:      schema,
		Default:     stringOrNil(arg.DefaultValue),
	}
}

// fieldTypeToSchema converts a GraphQL FieldType to a SchemaInfo,
// recursively expanding input object types up to maxDepth.
func fieldTypeToSchema(ft graphql.FieldType, typeIndex map[string]graphql.Type, depth int) SchemaInfo {
	const maxDepth = 5

	switch ft.Kind {
	case "NON_NULL":
		if ft.OfType != nil {
			return fieldTypeToSchema(*ft.OfType, typeIndex, depth)
		}
		return SchemaInfo{Type: "string"}

	case "LIST":
		var items SchemaInfo
		if ft.OfType != nil {
			items = fieldTypeToSchema(*ft.OfType, typeIndex, depth)
		}
		return SchemaInfo{Type: "array", Items: &items}

	case "SCALAR":
		return SchemaInfo{Type: graphqlScalarToJSONType(ft.Name), Format: graphqlScalarToFormat(ft.Name)}

	case "ENUM":
		enumType := typeIndex[ft.Name]
		var values []string
		for _, ev := range enumType.EnumValues {
			values = append(values, ev.Name)
		}
		return SchemaInfo{Type: "string", Enum: values}

	case "INPUT_OBJECT":
		if depth >= maxDepth {
			return SchemaInfo{Type: "object"}
		}
		inputType := typeIndex[ft.Name]
		props := make(map[string]SchemaInfo, len(inputType.InputFields))
		var required []string
		for _, f := range inputType.InputFields {
			props[f.Name] = fieldTypeToSchema(f.Type, typeIndex, depth+1)
			if isNonNull(f.Type) {
				required = append(required, f.Name)
			}
		}
		return SchemaInfo{
			Type:       "object",
			Properties: props,
			Required:   required,
		}

	case "OBJECT":
		// Output types are not expanded into parameters.
		return SchemaInfo{Type: "object"}

	default:
		return SchemaInfo{Type: "string"}
	}
}

// graphqlScalarToJSONType maps GraphQL scalar type names to JSON schema types.
func graphqlScalarToJSONType(name string) string {
	switch name {
	case "Int":
		return "integer"
	case "Float":
		return "number"
	case "Boolean":
		return "boolean"
	case "ID", "String":
		return "string"
	default:
		return "string"
	}
}

// graphqlScalarToFormat returns a JSON schema format hint for GraphQL scalars.
func graphqlScalarToFormat(name string) string {
	switch name {
	case "ID":
		return "id"
	case "Float":
		return "float"
	default:
		return ""
	}
}

// isNonNull checks whether a GraphQL type is wrapped in NON_NULL.
func isNonNull(ft graphql.FieldType) bool {
	return ft.Kind == "NON_NULL"
}

// buildTypeIndex creates a lookup map from type name to Type for
// efficient field resolution.
func buildTypeIndex(schema *graphql.Schema) map[string]graphql.Type {
	index := make(map[string]graphql.Type, len(schema.Types))
	for _, t := range schema.Types {
		index[t.Name] = t
	}
	return index
}

// stringOrNil returns the string as an any, or nil if empty.
func stringOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ExtractGraphQLOperations returns a summary of operations from a GraphQL spec.
// Useful for dry-run preview.
func ExtractGraphQLOperations(spec *Spec) (queries, mutations []string) {
	for _, ep := range spec.Endpoints {
		if spec.Format != FormatGraphQL {
			continue
		}
		parts := strings.SplitN(ep.OperationID, "_", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "query":
			queries = append(queries, parts[1])
		case "mutation":
			mutations = append(mutations, parts[1])
		}
	}
	return queries, mutations
}
