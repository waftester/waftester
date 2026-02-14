package apispec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAsyncAPI_Basic(t *testing.T) {
	content := `{
		"asyncapi": "2.6.0",
		"info": {
			"title": "Chat Service",
			"description": "Real-time chat",
			"version": "1.0.0"
		},
		"servers": {
			"production": {
				"url": "wss://chat.example.com",
				"protocol": "wss",
				"description": "Production WebSocket"
			}
		},
		"channels": {
			"/chat/messages": {
				"subscribe": {
					"operationId": "receiveMessage",
					"summary": "Receive chat messages",
					"message": {
						"contentType": "application/json",
						"payload": {
							"type": "object",
							"properties": {
								"text": {"type": "string", "maxLength": 500},
								"user": {"type": "string"}
							},
							"required": ["text"]
						}
					}
				},
				"publish": {
					"operationId": "sendMessage",
					"summary": "Send a chat message",
					"message": {
						"contentType": "application/json",
						"payload": {
							"type": "object",
							"properties": {
								"text": {"type": "string"},
								"channel": {"type": "string"}
							}
						}
					}
				}
			}
		}
	}`

	spec, err := ParseAsyncAPI(content)
	require.NoError(t, err)

	assert.Equal(t, FormatAsyncAPI, spec.Format)
	assert.Equal(t, "Chat Service", spec.Title)
	assert.Equal(t, "1.0.0", spec.Version)
	assert.Equal(t, "2.6.0", spec.SpecVersion)

	// One WebSocket server.
	require.Len(t, spec.Servers, 1)
	assert.Contains(t, spec.Servers[0].URL, "wss://")

	// Two endpoints: subscribe + publish.
	require.Len(t, spec.Endpoints, 2)

	var sub, pub Endpoint
	for _, ep := range spec.Endpoints {
		if ep.OperationID == "receiveMessage" {
			sub = ep
		}
		if ep.OperationID == "sendMessage" {
			pub = ep
		}
	}

	// Subscribe = GET (read).
	assert.Equal(t, "GET", sub.Method)
	assert.Equal(t, "/chat/messages", sub.Path)
	assert.NotEmpty(t, sub.Parameters)

	// Publish = POST (write).
	assert.Equal(t, "POST", pub.Method)
	assert.Equal(t, "/chat/messages", pub.Path)
}

func TestParseAsyncAPI_NonWebSocketSkipped(t *testing.T) {
	content := `{
		"asyncapi": "2.6.0",
		"info": {"title": "Events", "version": "1.0.0"},
		"servers": {
			"kafka": {
				"url": "kafka://broker:9092",
				"protocol": "kafka"
			}
		},
		"channels": {
			"user.created": {
				"subscribe": {
					"operationId": "onUserCreated",
					"message": {
						"payload": {"type": "object", "properties": {"id": {"type": "integer"}}}
					}
				}
			}
		}
	}`

	spec, err := ParseAsyncAPI(content)
	require.NoError(t, err)

	// No WebSocket servers.
	assert.Empty(t, spec.Servers)

	// Non-WebSocket channels skipped.
	assert.Empty(t, spec.Endpoints)
}

func TestParseAsyncAPI_MixedProtocols(t *testing.T) {
	content := `{
		"asyncapi": "2.6.0",
		"info": {"title": "Mixed", "version": "1.0.0"},
		"servers": {
			"ws": {"url": "ws://localhost:8080", "protocol": "ws"},
			"mqtt": {"url": "mqtt://broker:1883", "protocol": "mqtt"}
		},
		"channels": {
			"/notifications": {
				"subscribe": {
					"operationId": "getNotifs",
					"message": {"payload": {"type": "object", "properties": {"msg": {"type": "string"}}}}
				}
			}
		}
	}`

	spec, err := ParseAsyncAPI(content)
	require.NoError(t, err)

	// Only WebSocket server.
	require.Len(t, spec.Servers, 1)
	assert.Contains(t, spec.Servers[0].URL, "ws://")

	// Channel has WS server, so it should be included.
	assert.NotEmpty(t, spec.Endpoints)
}

func TestParseAsyncAPI_InvalidJSON(t *testing.T) {
	_, err := ParseAsyncAPI("not json")
	assert.Error(t, err)
}

func TestParseAsyncAPI_MissingVersion(t *testing.T) {
	_, err := ParseAsyncAPI(`{"info": {"title": "test"}}`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing asyncapi version")
}

func TestParseAsyncAPI_ParameterExtraction(t *testing.T) {
	content := `{
		"asyncapi": "2.6.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"servers": {"ws": {"url": "ws://localhost", "protocol": "ws"}},
		"channels": {
			"/events": {
				"publish": {
					"operationId": "sendEvent",
					"message": {
						"payload": {
							"type": "object",
							"properties": {
								"event_type": {"type": "string", "enum": ["click", "view"]},
								"timestamp": {"type": "string", "format": "date-time"},
								"value": {"type": "number", "minimum": 0, "maximum": 100}
							},
							"required": ["event_type"]
						}
					}
				}
			}
		}
	}`

	spec, err := ParseAsyncAPI(content)
	require.NoError(t, err)
	require.Len(t, spec.Endpoints, 1)

	ep := spec.Endpoints[0]
	require.Len(t, ep.Parameters, 3)

	paramMap := make(map[string]Parameter)
	for _, p := range ep.Parameters {
		paramMap[p.Name] = p
	}

	// event_type: string with enum, required.
	et := paramMap["event_type"]
	assert.Equal(t, "string", et.Schema.Type)
	assert.Equal(t, []string{"click", "view"}, et.Schema.Enum)
	assert.True(t, et.Required)

	// timestamp: date-time format.
	ts := paramMap["timestamp"]
	assert.Equal(t, "date-time", ts.Schema.Format)

	// value: number with bounds.
	val := paramMap["value"]
	assert.Equal(t, "number", val.Schema.Type)
	require.NotNil(t, val.Schema.Minimum)
	assert.Equal(t, float64(0), *val.Schema.Minimum)
}

func TestParseAsyncAPI_WSBinding(t *testing.T) {
	content := `{
		"asyncapi": "2.6.0",
		"info": {"title": "Binding Test", "version": "1.0.0"},
		"servers": {"main": {"url": "amqp://broker", "protocol": "amqp"}},
		"channels": {
			"/ws-channel": {
				"bindings": {
					"ws": {"method": "GET"}
				},
				"subscribe": {
					"operationId": "wsReceive",
					"message": {"payload": {"type": "object"}}
				}
			},
			"/amqp-channel": {
				"subscribe": {
					"operationId": "amqpReceive",
					"message": {"payload": {"type": "object"}}
				}
			}
		}
	}`

	spec, err := ParseAsyncAPI(content)
	require.NoError(t, err)

	// Only the WS-bound channel should be included.
	require.Len(t, spec.Endpoints, 1)
	assert.Equal(t, "/ws-channel", spec.Endpoints[0].Path)
}

func TestAsyncOpToEndpoint_Subscribe(t *testing.T) {
	op := &asyncOperation{
		OperationID: "receiveData",
		Summary:     "Receive data updates",
	}
	ch := asyncChannel{}

	ep := asyncOpToEndpoint("/data", "subscribe", op, ch)
	assert.Equal(t, "GET", ep.Method)
	assert.Equal(t, "/data", ep.Path)
	assert.Equal(t, "receiveData", ep.OperationID)
	assert.NotEmpty(t, ep.CorrelationTag)
}

func TestAsyncOpToEndpoint_Publish(t *testing.T) {
	op := &asyncOperation{
		OperationID: "sendData",
	}
	ch := asyncChannel{}

	ep := asyncOpToEndpoint("/data", "publish", op, ch)
	assert.Equal(t, "POST", ep.Method)
}

func TestAsyncSchemaToParams_Empty(t *testing.T) {
	params := asyncSchemaToParams(asyncSchemaObj{Type: "object"})
	assert.Nil(t, params)
}
