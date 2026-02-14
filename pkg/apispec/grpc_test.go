package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/grpc"
)

func TestGrpcMethodToEndpoint_Unary(t *testing.T) {
	m := grpc.MethodDescriptor{
		Name:            "GetUser",
		InputType:       ".users.GetUserRequest",
		OutputType:      ".users.GetUserResponse",
		ClientStreaming: false,
		ServerStreaming: false,
		FullName:        "/users.UserService/GetUser",
	}

	ep := grpcMethodToEndpoint("users.UserService", "UserService", m)

	assert.Equal(t, "POST", ep.Method)
	assert.Equal(t, "/users.UserService/GetUser", ep.Path)
	assert.Equal(t, "UserService_GetUser", ep.OperationID)
	assert.Equal(t, "unary", ep.Description)
	assert.Contains(t, ep.ContentTypes, "application/grpc")

	require.Len(t, ep.Parameters, 1)
	assert.Equal(t, "body", ep.Parameters[0].Name)
	assert.Equal(t, LocationBody, ep.Parameters[0].In)
	assert.True(t, ep.Parameters[0].Required)
	assert.Equal(t, "object", ep.Parameters[0].Schema.Type)
	assert.Equal(t, "protobuf:users.GetUserRequest", ep.Parameters[0].Schema.Format)
}

func TestGrpcMethodToEndpoint_ClientStreaming(t *testing.T) {
	m := grpc.MethodDescriptor{
		Name:            "Upload",
		InputType:       ".file.Chunk",
		ClientStreaming: true,
		ServerStreaming: false,
		FullName:        "/file.FileService/Upload",
	}

	ep := grpcMethodToEndpoint("file.FileService", "FileService", m)
	assert.Equal(t, "client streaming", ep.Description)
	assert.True(t, IsStreamingEndpoint(ep))
}

func TestGrpcMethodToEndpoint_ServerStreaming(t *testing.T) {
	m := grpc.MethodDescriptor{
		Name:            "Watch",
		InputType:       ".events.WatchRequest",
		ClientStreaming: false,
		ServerStreaming: true,
		FullName:        "/events.EventService/Watch",
	}

	ep := grpcMethodToEndpoint("events.EventService", "EventService", m)
	assert.Equal(t, "server streaming", ep.Description)
	assert.True(t, IsStreamingEndpoint(ep))
}

func TestGrpcMethodToEndpoint_BidirectionalStreaming(t *testing.T) {
	m := grpc.MethodDescriptor{
		Name:            "Chat",
		InputType:       ".chat.Message",
		ClientStreaming: true,
		ServerStreaming: true,
		FullName:        "/chat.ChatService/Chat",
	}

	ep := grpcMethodToEndpoint("chat.ChatService", "ChatService", m)
	assert.Equal(t, "bidirectional streaming", ep.Description)
	assert.True(t, IsStreamingEndpoint(ep))
}

func TestGrpcMethodToEndpoint_NoFullName(t *testing.T) {
	m := grpc.MethodDescriptor{
		Name:      "Create",
		InputType: ".api.CreateRequest",
	}

	ep := grpcMethodToEndpoint("api.Service", "Service", m)
	assert.Equal(t, "/api.Service/Create", ep.Path)
}

func TestIsStreamingEndpoint_Unary(t *testing.T) {
	ep := Endpoint{Description: "unary"}
	assert.False(t, IsStreamingEndpoint(ep))
}

func TestIsStreamingEndpoint_Regular(t *testing.T) {
	ep := Endpoint{Description: "some description"}
	assert.False(t, IsStreamingEndpoint(ep))
}

func TestGrpcInputToParameters(t *testing.T) {
	params := grpcInputToParameters(".pkg.MyMessage")

	require.Len(t, params, 1)
	p := params[0]
	assert.Equal(t, "body", p.Name)
	assert.Equal(t, LocationBody, p.In)
	assert.True(t, p.Required)
	assert.Equal(t, "object", p.Schema.Type)
	assert.Equal(t, "protobuf:pkg.MyMessage", p.Schema.Format)
	assert.Contains(t, p.Description, "pkg.MyMessage")
}

func TestGrpcMethodToEndpoint_Tags(t *testing.T) {
	// grpcMethodToEndpoint does not set Group/Tags — ReflectionToSpec does.
	m := grpc.MethodDescriptor{
		Name:     "List",
		FullName: "/svc.Svc/List",
	}

	ep := grpcMethodToEndpoint("svc.Svc", "Svc", m)
	assert.Equal(t, "", ep.Group)
	assert.Nil(t, ep.Tags)
	assert.Equal(t, "Svc_List", ep.OperationID)
}
