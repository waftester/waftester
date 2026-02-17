// Package grpc provides gRPC testing capabilities for WAF assessment
package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Client is a gRPC client with reflection support
type Client struct {
	conn       *grpc.ClientConn
	target     string
	timeout    time.Duration
	reflClient grpc_reflection_v1alpha.ServerReflectionClient
	files      *protoregistry.Files
}

// ClientOption configures the client
type ClientOption func(*Client)

// WithTimeout sets the request timeout
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
	}
}

// NewClient creates a new gRPC client using the provided context for connection.
func NewClient(ctx context.Context, target string, opts ...ClientOption) (*Client, error) {
	c := &Client{
		target:  target,
		timeout: duration.HTTPFuzzing,
		files:   new(protoregistry.Files),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Connect to the gRPC server
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	c.conn = conn
	c.reflClient = grpc_reflection_v1alpha.NewServerReflectionClient(conn)

	return c, nil
}

// Close closes the connection
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ListServices returns all available services via reflection
func (c *Client) ListServices(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	stream, err := c.reflClient.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("reflection error: %w", err)
	}
	defer stream.CloseSend()

	// Request list of services
	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{
			ListServices: "",
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	listResp := resp.GetListServicesResponse()
	if listResp == nil {
		return nil, fmt.Errorf("invalid response type")
	}

	var services []string
	for _, svc := range listResp.Service {
		services = append(services, svc.Name)
	}

	return services, nil
}

// ServiceDescriptor contains service metadata
type ServiceDescriptor struct {
	Name    string
	Methods []MethodDescriptor
}

// MethodDescriptor contains method metadata
type MethodDescriptor struct {
	Name            string
	InputType       string
	OutputType      string
	ClientStreaming bool
	ServerStreaming bool
	FullName        string
}

// DescribeService returns metadata for a service
func (c *Client) DescribeService(ctx context.Context, serviceName string) (*ServiceDescriptor, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	stream, err := c.reflClient.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("reflection error: %w", err)
	}
	defer stream.CloseSend()

	// Request file containing the service
	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileContainingSymbol{
			FileContainingSymbol: serviceName,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	fdResp := resp.GetFileDescriptorResponse()
	if fdResp == nil {
		if errResp := resp.GetErrorResponse(); errResp != nil {
			return nil, fmt.Errorf("server error: %s", errResp.ErrorMessage)
		}
		return nil, fmt.Errorf("invalid response type")
	}

	// Parse file descriptors
	var fileDescProtos []*descriptorpb.FileDescriptorProto
	for _, fdBytes := range fdResp.FileDescriptorProto {
		fdProto := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(fdBytes, fdProto); err != nil {
			return nil, fmt.Errorf("failed to unmarshal file descriptor: %w", err)
		}
		fileDescProtos = append(fileDescProtos, fdProto)
	}

	// Find the service
	for _, fdProto := range fileDescProtos {
		for _, svc := range fdProto.Service {
			if svc.GetName() == serviceName || fdProto.GetPackage()+"."+svc.GetName() == serviceName {
				desc := &ServiceDescriptor{
					Name:    svc.GetName(),
					Methods: make([]MethodDescriptor, 0, len(svc.Method)),
				}

				for _, method := range svc.Method {
					desc.Methods = append(desc.Methods, MethodDescriptor{
						Name:            method.GetName(),
						InputType:       method.GetInputType(),
						OutputType:      method.GetOutputType(),
						ClientStreaming: method.GetClientStreaming(),
						ServerStreaming: method.GetServerStreaming(),
						FullName:        fmt.Sprintf("/%s.%s/%s", fdProto.GetPackage(), svc.GetName(), method.GetName()),
					})
				}

				return desc, nil
			}
		}
	}

	return nil, fmt.Errorf("service %s not found", serviceName)
}

// InvokeRequest represents a gRPC invocation request
type InvokeRequest struct {
	Service  string            // Service name
	Method   string            // Method name
	Data     map[string]any    // Request data (will be converted to protobuf)
	Metadata map[string]string // gRPC metadata (headers)
	Timeout  time.Duration     // Request timeout
}

// InvokeResponse contains the invocation result
type InvokeResponse struct {
	Data       map[string]any // Response data
	Response   []byte         // Raw response as bytes (for JSON serialization)
	Status     string         // gRPC status
	StatusCode int            // gRPC status code
	Metadata   map[string]string
	Latency    time.Duration
	Blocked    bool   // True if request was blocked (status code suggests WAF block)
	RawError   string // Raw error message if any
}

// Invoke calls a gRPC method dynamically
func (c *Client) Invoke(ctx context.Context, req *InvokeRequest) (*InvokeResponse, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = c.timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Add metadata if provided
	if len(req.Metadata) > 0 {
		md := metadata.New(req.Metadata)
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	start := time.Now()

	// Get method descriptor via reflection
	methodPath := fmt.Sprintf("/%s/%s", req.Service, req.Method)

	// Create dynamic message from input data
	inputMsg, err := c.createDynamicMessage(ctx, req.Service, req.Method, true, req.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to create input message: %w", err)
	}

	outputMsg, err := c.createDynamicMessage(ctx, req.Service, req.Method, false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create output message: %w", err)
	}

	// Invoke the method
	var respHeader, respTrailer metadata.MD
	err = c.conn.Invoke(ctx, methodPath, inputMsg, outputMsg,
		grpc.Header(&respHeader),
		grpc.Trailer(&respTrailer),
	)

	latency := time.Since(start)

	resp := &InvokeResponse{
		Latency:  latency,
		Metadata: make(map[string]string),
	}

	// Extract response metadata
	for k, v := range respHeader {
		if len(v) > 0 {
			resp.Metadata[k] = v[0]
		}
	}

	if err != nil {
		resp.RawError = err.Error()
		resp.Status = "ERROR"

		// Check if blocked (common WAF-related status codes)
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "permission denied") ||
			strings.Contains(errStr, "unauthenticated") ||
			strings.Contains(errStr, "resource exhausted") ||
			strings.Contains(errStr, "unavailable") {
			resp.Blocked = true
			resp.StatusCode = 7 // PERMISSION_DENIED equivalent
		}

		return resp, nil
	}

	resp.Status = "OK"
	resp.StatusCode = 0
	resp.Data = dynamicMessageToMap(outputMsg)

	// Serialize response to JSON for the Response field
	if respBytes, err := json.Marshal(resp.Data); err == nil {
		resp.Response = respBytes
	}

	return resp, nil
}

// createDynamicMessage creates a dynamic protobuf message for a method
func (c *Client) createDynamicMessage(ctx context.Context, service, method string, isInput bool, data map[string]any) (*dynamicpb.Message, error) {
	// Get service descriptor first
	svcDesc, err := c.DescribeService(ctx, service)
	if err != nil {
		return nil, err
	}

	// Find the method
	var methodDesc *MethodDescriptor
	for _, m := range svcDesc.Methods {
		if m.Name == method {
			methodDesc = &m
			break
		}
	}
	if methodDesc == nil {
		return nil, fmt.Errorf("method %s not found in service %s", method, service)
	}

	// Get the message type
	typeName := methodDesc.InputType
	if !isInput {
		typeName = methodDesc.OutputType
	}

	// Remove leading dot if present
	typeName = strings.TrimPrefix(typeName, ".")

	// Get message descriptor from registry
	msgDesc, err := c.getMessageDescriptor(ctx, typeName)
	if err != nil {
		return nil, err
	}

	// Create dynamic message
	msg := dynamicpb.NewMessage(msgDesc)

	// Set field values if data provided
	if data != nil {
		if err := setMessageFields(msg, data); err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// getMessageDescriptor retrieves a message descriptor via reflection
func (c *Client) getMessageDescriptor(ctx context.Context, typeName string) (protoreflect.MessageDescriptor, error) {
	stream, err := c.reflClient.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CloseSend()

	// Request file containing the type
	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileContainingSymbol{
			FileContainingSymbol: typeName,
		},
	}); err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	fdResp := resp.GetFileDescriptorResponse()
	if fdResp == nil {
		return nil, fmt.Errorf("invalid response for type %s", typeName)
	}

	// Parse and register file descriptors
	for _, fdBytes := range fdResp.FileDescriptorProto {
		fdProto := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(fdBytes, fdProto); err != nil {
			continue
		}

		fd, err := protodesc.NewFile(fdProto, c.files)
		if err != nil {
			// Already registered or incompatible — skip
			continue
		}

		if regErr := c.files.RegisterFile(fd); regErr != nil {
			continue // Already registered under this path
		}
	}

	// Find the message in registered files
	msgDesc, err := c.files.FindDescriptorByName(protoreflect.FullName(typeName))
	if err != nil {
		return nil, fmt.Errorf("message %s not found: %w", typeName, err)
	}

	md, ok := msgDesc.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is not a message type", typeName)
	}

	return md, nil
}

// setMessageFields sets fields on a dynamic message from a map
func setMessageFields(msg *dynamicpb.Message, data map[string]any) error {
	fields := msg.Descriptor().Fields()

	for key, value := range data {
		fd := fields.ByName(protoreflect.Name(key))
		if fd == nil {
			fd = fields.ByJSONName(key)
		}
		if fd == nil {
			continue // Skip unknown fields
		}

		pv, err := convertToProtoreflect(fd, value)
		if err != nil {
			return fmt.Errorf("field %s: %w", key, err)
		}

		msg.Set(fd, pv)
	}

	return nil
}

// convertToProtoreflect converts a Go value to protoreflect.Value
func convertToProtoreflect(fd protoreflect.FieldDescriptor, v any) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		s, ok := v.(string)
		if !ok {
			return protoreflect.Value{}, fmt.Errorf("expected string, got %T", v)
		}
		return protoreflect.ValueOfString(s), nil

	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		switch n := v.(type) {
		case int:
			return protoreflect.ValueOfInt32(int32(n)), nil
		case int32:
			return protoreflect.ValueOfInt32(n), nil
		case int64:
			return protoreflect.ValueOfInt32(int32(n)), nil
		case float64:
			return protoreflect.ValueOfInt32(int32(n)), nil
		default:
			return protoreflect.Value{}, fmt.Errorf("expected int, got %T", v)
		}

	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		switch n := v.(type) {
		case int:
			return protoreflect.ValueOfInt64(int64(n)), nil
		case int32:
			return protoreflect.ValueOfInt64(int64(n)), nil
		case int64:
			return protoreflect.ValueOfInt64(n), nil
		case float64:
			return protoreflect.ValueOfInt64(int64(n)), nil
		default:
			return protoreflect.Value{}, fmt.Errorf("expected int, got %T", v)
		}

	case protoreflect.BoolKind:
		b, ok := v.(bool)
		if !ok {
			return protoreflect.Value{}, fmt.Errorf("expected bool, got %T", v)
		}
		return protoreflect.ValueOfBool(b), nil

	case protoreflect.FloatKind:
		switch n := v.(type) {
		case float32:
			return protoreflect.ValueOfFloat32(n), nil
		case float64:
			return protoreflect.ValueOfFloat32(float32(n)), nil
		default:
			return protoreflect.Value{}, fmt.Errorf("expected float, got %T", v)
		}

	case protoreflect.DoubleKind:
		switch n := v.(type) {
		case float32:
			return protoreflect.ValueOfFloat64(float64(n)), nil
		case float64:
			return protoreflect.ValueOfFloat64(n), nil
		default:
			return protoreflect.Value{}, fmt.Errorf("expected float, got %T", v)
		}

	case protoreflect.BytesKind:
		switch b := v.(type) {
		case []byte:
			return protoreflect.ValueOfBytes(b), nil
		case string:
			return protoreflect.ValueOfBytes([]byte(b)), nil
		default:
			return protoreflect.Value{}, fmt.Errorf("expected bytes, got %T", v)
		}

	default:
		return protoreflect.Value{}, fmt.Errorf("unsupported field kind: %v", fd.Kind())
	}
}

// dynamicMessageToMap converts a dynamic message to a map
func dynamicMessageToMap(msg *dynamicpb.Message) map[string]any {
	result := make(map[string]any)

	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		result[string(fd.Name())] = protoreflectToGo(fd, v)
		return true
	})

	return result
}

// protoreflectToGo converts a protoreflect.Value to a Go value
func protoreflectToGo(fd protoreflect.FieldDescriptor, v protoreflect.Value) any {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return v.String()
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return int32(v.Int())
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return v.Int()
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return uint32(v.Uint())
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return v.Uint()
	case protoreflect.BoolKind:
		return v.Bool()
	case protoreflect.FloatKind:
		return float32(v.Float())
	case protoreflect.DoubleKind:
		return v.Float()
	case protoreflect.BytesKind:
		return v.Bytes()
	case protoreflect.MessageKind:
		if msg, ok := v.Message().Interface().(*dynamicpb.Message); ok {
			return dynamicMessageToMap(msg)
		}
		return nil
	default:
		return v.Interface()
	}
}

// TestCase represents a gRPC security test case
type TestCase struct {
	ID          string
	Service     string
	Method      string
	Description string
	Category    string
	Payload     map[string]any
	Metadata    map[string]string
	ExpectBlock bool
}

// Generator creates test cases for gRPC services
type Generator struct {
	client   *Client
	payloads []string
}

// NewGenerator creates a test case generator
func NewGenerator(client *Client, payloads []string) *Generator {
	return &Generator{
		client:   client,
		payloads: payloads,
	}
}

// Generate creates test cases for all services
func (g *Generator) Generate(ctx context.Context) ([]TestCase, error) {
	services, err := g.client.ListServices(ctx)
	if err != nil {
		return nil, err
	}

	var testCases []TestCase

	for _, svc := range services {
		// Skip reflection service
		if strings.Contains(svc, "reflection") || strings.Contains(svc, "grpc.health") {
			continue
		}

		svcDesc, err := g.client.DescribeService(ctx, svc)
		if err != nil {
			continue
		}

		for _, method := range svcDesc.Methods {
			cases := g.generateForMethod(svc, method)
			testCases = append(testCases, cases...)
		}
	}

	return testCases, nil
}

// generateForMethod creates test cases for a single method
func (g *Generator) generateForMethod(service string, method MethodDescriptor) []TestCase {
	var testCases []TestCase
	id := 1

	for _, payload := range g.payloads {
		// Test payload in first string field
		testCases = append(testCases, TestCase{
			ID:          fmt.Sprintf("grpc-%s-%s-%03d", service, method.Name, id),
			Service:     service,
			Method:      method.Name,
			Description: fmt.Sprintf("Inject payload in %s.%s", service, method.Name),
			Category:    "injection",
			Payload:     map[string]any{"data": payload, "input": payload},
			ExpectBlock: true,
		})
		id++

		// Test payload in metadata
		testCases = append(testCases, TestCase{
			ID:          fmt.Sprintf("grpc-%s-%s-%03d", service, method.Name, id),
			Service:     service,
			Method:      method.Name,
			Description: fmt.Sprintf("Inject payload in %s.%s metadata", service, method.Name),
			Category:    "injection",
			Payload:     map[string]any{},
			Metadata:    map[string]string{"x-custom-header": payload},
			ExpectBlock: true,
		})
		id++
	}

	return testCases
}

// InvokeMethod invokes a gRPC method with raw data
// callSpec format: "service/method" or "service.method"
func (c *Client) InvokeMethod(ctx context.Context, callSpec string, data []byte, metadata map[string]string) (*InvokeResponse, error) {
	// Parse the call spec
	var service, method string
	if strings.Contains(callSpec, "/") {
		parts := strings.SplitN(callSpec, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid call spec format: %s", callSpec)
		}
		service = parts[0]
		method = parts[1]
	} else if strings.Contains(callSpec, ".") {
		// Handle service.method format
		lastDot := strings.LastIndex(callSpec, ".")
		if lastDot == -1 || lastDot == len(callSpec)-1 {
			return nil, fmt.Errorf("invalid call spec format: %s", callSpec)
		}
		service = callSpec[:lastDot]
		method = callSpec[lastDot+1:]
	} else {
		return nil, fmt.Errorf("invalid call spec format, expected service/method or service.method: %s", callSpec)
	}

	// Parse JSON data into map
	var dataMap map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &dataMap); err != nil {
			// If not JSON, treat as raw value
			dataMap = map[string]any{"data": string(data)}
		}
	}

	return c.Invoke(ctx, &InvokeRequest{
		Service:  service,
		Method:   method,
		Data:     dataMap,
		Metadata: metadata,
	})
}
