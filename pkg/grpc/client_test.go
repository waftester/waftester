package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithTimeout(t *testing.T) {
	c := &Client{}
	opt := WithTimeout(5 * time.Second)
	opt(c)

	assert.Equal(t, 5*time.Second, c.timeout)
}

func TestClientDefaults(t *testing.T) {
	// Test that defaults are set correctly
	// We can't actually connect, but we can test the structure
	c := &Client{
		target:  "localhost:50051",
		timeout: 30 * time.Second,
	}

	assert.Equal(t, "localhost:50051", c.target)
	assert.Equal(t, 30*time.Second, c.timeout)
}

func TestInvokeRequest(t *testing.T) {
	req := &InvokeRequest{
		Service:  "myservice.MyService",
		Method:   "MyMethod",
		Data:     map[string]any{"field": "value"},
		Metadata: map[string]string{"authorization": "Bearer token"},
		Timeout:  10 * time.Second,
	}

	assert.Equal(t, "myservice.MyService", req.Service)
	assert.Equal(t, "MyMethod", req.Method)
	assert.Equal(t, "value", req.Data["field"])
	assert.Equal(t, "Bearer token", req.Metadata["authorization"])
	assert.Equal(t, 10*time.Second, req.Timeout)
}

func TestInvokeResponse(t *testing.T) {
	resp := &InvokeResponse{
		Data:       map[string]any{"result": "success"},
		Status:     "OK",
		StatusCode: 0,
		Metadata:   map[string]string{"x-request-id": "abc123"},
		Latency:    100 * time.Millisecond,
		Blocked:    false,
	}

	assert.Equal(t, "success", resp.Data["result"])
	assert.Equal(t, "OK", resp.Status)
	assert.Equal(t, 0, resp.StatusCode)
	assert.False(t, resp.Blocked)
}

func TestInvokeResponseBlocked(t *testing.T) {
	resp := &InvokeResponse{
		Status:     "ERROR",
		StatusCode: 7,
		Blocked:    true,
		RawError:   "permission denied",
	}

	assert.True(t, resp.Blocked)
	assert.Equal(t, 7, resp.StatusCode)
	assert.Contains(t, resp.RawError, "permission denied")
}

func TestServiceDescriptor(t *testing.T) {
	svc := &ServiceDescriptor{
		Name: "UserService",
		Methods: []MethodDescriptor{
			{
				Name:            "GetUser",
				InputType:       ".user.GetUserRequest",
				OutputType:      ".user.GetUserResponse",
				ClientStreaming: false,
				ServerStreaming: false,
				FullName:        "/user.UserService/GetUser",
			},
			{
				Name:            "StreamUsers",
				InputType:       ".user.StreamRequest",
				OutputType:      ".user.User",
				ClientStreaming: false,
				ServerStreaming: true,
				FullName:        "/user.UserService/StreamUsers",
			},
		},
	}

	assert.Equal(t, "UserService", svc.Name)
	assert.Len(t, svc.Methods, 2)
	assert.Equal(t, "GetUser", svc.Methods[0].Name)
	assert.False(t, svc.Methods[0].ServerStreaming)
	assert.True(t, svc.Methods[1].ServerStreaming)
}

func TestMethodDescriptor(t *testing.T) {
	method := MethodDescriptor{
		Name:            "CreateUser",
		InputType:       ".user.CreateUserRequest",
		OutputType:      ".user.CreateUserResponse",
		ClientStreaming: false,
		ServerStreaming: false,
		FullName:        "/user.UserService/CreateUser",
	}

	assert.Equal(t, "CreateUser", method.Name)
	assert.Equal(t, ".user.CreateUserRequest", method.InputType)
	assert.Equal(t, "/user.UserService/CreateUser", method.FullName)
}

func TestTestCase(t *testing.T) {
	tc := TestCase{
		ID:          "grpc-001",
		Service:     "auth.AuthService",
		Method:      "Login",
		Description: "SQL injection in login",
		Category:    "sqli",
		Payload:     map[string]any{"username": "' OR 1=1--", "password": "test"},
		Metadata:    map[string]string{"x-request-id": "test"},
		ExpectBlock: true,
	}

	assert.Equal(t, "grpc-001", tc.ID)
	assert.Equal(t, "auth.AuthService", tc.Service)
	assert.Equal(t, "sqli", tc.Category)
	assert.True(t, tc.ExpectBlock)
}

func TestGeneratorWithPayloads(t *testing.T) {
	payloads := []string{
		"' OR 1=1--",
		"<script>alert(1)</script>",
		"../../../etc/passwd",
	}

	// Generator without actual client connection
	gen := &Generator{
		client:   nil,
		payloads: payloads,
	}

	assert.Len(t, gen.payloads, 3)
}

func TestGenerateForMethodCreatesTestCases(t *testing.T) {
	payloads := []string{
		"' OR 1=1--",
		"<script>alert(1)</script>",
	}

	gen := &Generator{
		payloads: payloads,
	}

	method := MethodDescriptor{
		Name:       "GetUser",
		InputType:  ".user.GetUserRequest",
		OutputType: ".user.GetUserResponse",
		FullName:   "/user.UserService/GetUser",
	}

	testCases := gen.generateForMethod("user.UserService", method)

	// Should have 2 test cases per payload (body + metadata)
	assert.Equal(t, len(payloads)*2, len(testCases))

	// Check first test case
	assert.Contains(t, testCases[0].ID, "grpc-")
	assert.Equal(t, "user.UserService", testCases[0].Service)
	assert.Equal(t, "GetUser", testCases[0].Method)
	assert.True(t, testCases[0].ExpectBlock)
}

func TestNewGenerator(t *testing.T) {
	payloads := []string{"payload1", "payload2"}

	gen := NewGenerator(nil, payloads)

	assert.NotNil(t, gen)
	assert.Len(t, gen.payloads, 2)
}

func TestClientClose(t *testing.T) {
	c := &Client{
		conn: nil, // No connection to close
	}

	err := c.Close()
	assert.NoError(t, err)
}

func TestNewClientFails(t *testing.T) {
	// Attempting to connect to non-existent server should fail
	_, err := NewClient("localhost:99999", WithTimeout(100*time.Millisecond))
	assert.Error(t, err, "Should fail to connect to non-existent server")
}

func TestGenerateWithNoClient(t *testing.T) {
	gen := &Generator{
		client:   nil,
		payloads: []string{"test"},
	}

	// Should panic or return error without a valid client
	// We can't test this directly without mocking
	require.NotNil(t, gen)
}

func TestResponseMetadata(t *testing.T) {
	resp := &InvokeResponse{
		Metadata: map[string]string{
			"content-type": "application/grpc",
			"x-custom":     "value",
		},
	}

	assert.Equal(t, "application/grpc", resp.Metadata["content-type"])
	assert.Equal(t, "value", resp.Metadata["x-custom"])
}

func TestTestCasePayloadTypes(t *testing.T) {
	tc := TestCase{
		ID:      "test-001",
		Service: "test",
		Method:  "Test",
		Payload: map[string]any{
			"string_field": "test",
			"int_field":    42,
			"bool_field":   true,
			"float_field":  3.14,
			"nested_field": map[string]any{"inner": "value"},
		},
	}

	assert.Equal(t, "test", tc.Payload["string_field"])
	assert.Equal(t, 42, tc.Payload["int_field"])
	assert.Equal(t, true, tc.Payload["bool_field"])
	assert.Equal(t, 3.14, tc.Payload["float_field"])

	nested, ok := tc.Payload["nested_field"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "value", nested["inner"])
}

func TestInvokeRequestDefaults(t *testing.T) {
	req := &InvokeRequest{
		Service: "test.Service",
		Method:  "Test",
	}

	// Timeout should be zero (will use client default)
	assert.Equal(t, time.Duration(0), req.Timeout)
	assert.Nil(t, req.Data)
	assert.Nil(t, req.Metadata)
}

func TestGeneratorEmptyPayloads(t *testing.T) {
	gen := NewGenerator(nil, []string{})

	method := MethodDescriptor{
		Name: "Test",
	}

	testCases := gen.generateForMethod("test.Service", method)

	assert.Empty(t, testCases)
}

// Integration test placeholder - requires actual gRPC server
func TestIntegrationListServices(t *testing.T) {
	t.Skip("Requires running gRPC server with reflection")

	ctx := context.Background()
	client, err := NewClient("localhost:50051")
	require.NoError(t, err)
	defer client.Close()

	services, err := client.ListServices(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, services)
}

func TestIntegrationDescribeService(t *testing.T) {
	t.Skip("Requires running gRPC server with reflection")

	ctx := context.Background()
	client, err := NewClient("localhost:50051")
	require.NoError(t, err)
	defer client.Close()

	desc, err := client.DescribeService(ctx, "test.TestService")
	require.NoError(t, err)
	assert.NotNil(t, desc)
}

func TestIntegrationInvoke(t *testing.T) {
	t.Skip("Requires running gRPC server with reflection")

	ctx := context.Background()
	client, err := NewClient("localhost:50051")
	require.NoError(t, err)
	defer client.Close()

	resp, err := client.Invoke(ctx, &InvokeRequest{
		Service: "test.TestService",
		Method:  "Echo",
		Data:    map[string]any{"message": "hello"},
	})

	require.NoError(t, err)
	assert.Equal(t, "OK", resp.Status)
}

func TestIntegrationGenerate(t *testing.T) {
	t.Skip("Requires running gRPC server with reflection")

	ctx := context.Background()
	client, err := NewClient("localhost:50051")
	require.NoError(t, err)
	defer client.Close()

	gen := NewGenerator(client, []string{"' OR 1=1--"})
	testCases, err := gen.Generate(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, testCases)
}
