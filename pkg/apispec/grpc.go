package apispec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/grpc"
)

// ReflectionToSpec connects to a gRPC server, discovers services via
// reflection, and converts them into a unified Spec with FormatGRPC.
func ReflectionToSpec(ctx context.Context, addr string) (*Spec, error) {
	client, err := grpc.NewClient(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("grpc connect: %w", err)
	}
	defer client.Close()

	services, err := client.ListServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("grpc list services: %w", err)
	}

	spec := &Spec{
		Format:   FormatGRPC,
		Title:    "gRPC Services at " + addr,
		Servers:  []Server{{URL: addr}},
		ParsedAt: time.Now(),
		Source:   addr,
	}

	for _, svcName := range services {
		// Skip the reflection service itself.
		if strings.HasPrefix(svcName, "grpc.reflection.") {
			continue
		}

		desc, err := client.DescribeService(ctx, svcName)
		if err != nil {
			// Non-fatal: log and continue to next service.
			continue
		}

		group := Group{
			Name:        desc.Name,
			Description: "gRPC service " + svcName,
		}
		spec.Groups = append(spec.Groups, group)

		for _, method := range desc.Methods {
			ep := grpcMethodToEndpoint(svcName, desc.Name, method)
			ep.Group = desc.Name
			ep.Tags = []string{desc.Name}
			ep.CorrelationTag = CorrelationTag(ep.Method, ep.Path)
			spec.Endpoints = append(spec.Endpoints, ep)
		}
	}

	return spec, nil
}

// grpcMethodToEndpoint converts a gRPC method descriptor to an Endpoint.
func grpcMethodToEndpoint(serviceFQN, serviceName string, m grpc.MethodDescriptor) Endpoint {
	// gRPC path convention: /package.Service/Method
	path := m.FullName
	if path == "" {
		path = "/" + serviceFQN + "/" + m.Name
	}

	// Map gRPC to HTTP method: unary = POST, streaming = POST with note.
	httpMethod := "POST"

	ep := Endpoint{
		Method:      httpMethod,
		Path:        path,
		OperationID: serviceName + "_" + m.Name,
		Summary:     fmt.Sprintf("gRPC %s.%s", serviceName, m.Name),
		ContentTypes: []string{
			"application/grpc",
			"application/grpc+proto",
		},
		Parameters: grpcInputToParameters(m.InputType),
	}

	// Flag streaming methods. We store it in the Description since Endpoint
	// doesn't have a Streaming bool field.
	if m.ClientStreaming && m.ServerStreaming {
		ep.Description = "bidirectional streaming"
	} else if m.ClientStreaming {
		ep.Description = "client streaming"
	} else if m.ServerStreaming {
		ep.Description = "server streaming"
	} else {
		ep.Description = "unary"
	}

	return ep
}

// grpcInputToParameters creates a body parameter from the protobuf input type name.
func grpcInputToParameters(inputType string) []Parameter {
	// Strip leading dot from fully-qualified protobuf type.
	typeName := strings.TrimPrefix(inputType, ".")

	return []Parameter{
		{
			Name: "body",
			In:   LocationBody,
			Schema: SchemaInfo{
				Type:   "object",
				Format: "protobuf:" + typeName,
			},
			Required:    true,
			Description: "gRPC request message (" + typeName + ")",
		},
	}
}

// IsStreamingEndpoint checks if an endpoint represents a streaming gRPC method
// by inspecting the Description set during conversion.
func IsStreamingEndpoint(ep Endpoint) bool {
	switch ep.Description {
	case "client streaming", "server streaming", "bidirectional streaming":
		return true
	default:
		return false
	}
}
