package apispec

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AsyncAPI parsing for WebSocket channels only.
// Ignores MQTT, AMQP, Kafka, and other non-WebSocket transports.

// asyncAPIDoc is the minimal structure needed to parse AsyncAPI specs.
type asyncAPIDoc struct {
	AsyncAPI string                   `json:"asyncapi"`
	Info     asyncAPIInfo             `json:"info"`
	Servers  map[string]asyncServer   `json:"servers"`
	Channels map[string]asyncChannel  `json:"channels"`
}

type asyncAPIInfo struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type asyncServer struct {
	URL         string            `json:"url"`
	Protocol    string            `json:"protocol"`
	Description string            `json:"description"`
	Variables   map[string]asyncVariable `json:"variables"`
}

type asyncVariable struct {
	Default     string   `json:"default"`
	Description string   `json:"description"`
	Enum        []string `json:"enum"`
}

type asyncChannel struct {
	Description string           `json:"description"`
	Subscribe   *asyncOperation  `json:"subscribe"`
	Publish     *asyncOperation  `json:"publish"`
	Bindings    *channelBindings `json:"bindings"`
}

type asyncOperation struct {
	OperationID string      `json:"operationId"`
	Summary     string      `json:"summary"`
	Description string      `json:"description"`
	Message     asyncMessage `json:"message"`
}

type asyncMessage struct {
	Name        string          `json:"name"`
	Title       string          `json:"title"`
	Summary     string          `json:"summary"`
	ContentType string          `json:"contentType"`
	Payload     json.RawMessage `json:"payload"`
}

type channelBindings struct {
	WS *wsBinding `json:"ws"`
}

type wsBinding struct {
	Method  string          `json:"method"`
	Query   json.RawMessage `json:"query"`
	Headers json.RawMessage `json:"headers"`
}

// asyncSchemaObj is a simplified JSON Schema for parameter extraction.
type asyncSchemaObj struct {
	Type       string                    `json:"type"`
	Format     string                    `json:"format"`
	Properties map[string]asyncSchemaObj `json:"properties"`
	Items      *asyncSchemaObj           `json:"items"`
	Required   []string                  `json:"required"`
	Enum       []string                  `json:"enum"`
	MaxLength  *int                      `json:"maxLength"`
	MinLength  *int                      `json:"minLength"`
	Pattern    string                    `json:"pattern"`
	Minimum    *float64                  `json:"minimum"`
	Maximum    *float64                  `json:"maximum"`
}

// ParseAsyncAPI parses an AsyncAPI specification from JSON content.
// Only WebSocket channels are extracted; other protocols are skipped.
func ParseAsyncAPI(content string) (*Spec, error) {
	var doc asyncAPIDoc
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("parse asyncapi: %w", err)
	}

	if doc.AsyncAPI == "" {
		return nil, fmt.Errorf("parse asyncapi: missing asyncapi version field")
	}

	spec := &Spec{
		Format:      FormatAsyncAPI,
		Title:       doc.Info.Title,
		Description: doc.Info.Description,
		Version:     doc.Info.Version,
		SpecVersion: doc.AsyncAPI,
		ParsedAt:    time.Now(),
	}

	// Extract WebSocket servers.
	for name, srv := range doc.Servers {
		protocol := strings.ToLower(srv.Protocol)
		if protocol != "ws" && protocol != "wss" {
			continue
		}

		url := srv.URL
		if protocol == "wss" && !strings.HasPrefix(url, "wss://") {
			url = "wss://" + url
		} else if protocol == "ws" && !strings.HasPrefix(url, "ws://") {
			url = "ws://" + url
		}

		spec.Servers = append(spec.Servers, Server{
			URL:         url,
			Description: srv.Description + " (" + name + ")",
		})
	}

	// Extract WebSocket channels as endpoints.
	for channelPath, ch := range doc.Channels {
		isWS := isWebSocketChannel(ch, doc.Servers)
		if !isWS {
			continue
		}

		if ch.Subscribe != nil {
			ep := asyncOpToEndpoint(channelPath, "subscribe", ch.Subscribe, ch)
			spec.Endpoints = append(spec.Endpoints, ep)
		}

		if ch.Publish != nil {
			ep := asyncOpToEndpoint(channelPath, "publish", ch.Publish, ch)
			spec.Endpoints = append(spec.Endpoints, ep)
		}
	}

	return spec, nil
}

// isWebSocketChannel determines if a channel uses WebSocket transport.
func isWebSocketChannel(ch asyncChannel, servers map[string]asyncServer) bool {
	// Check channel-level WebSocket binding.
	if ch.Bindings != nil && ch.Bindings.WS != nil {
		return true
	}

	// Check if any server uses WebSocket protocol.
	for _, srv := range servers {
		protocol := strings.ToLower(srv.Protocol)
		if protocol == "ws" || protocol == "wss" {
			return true
		}
	}

	return false
}

// asyncOpToEndpoint converts an AsyncAPI operation to an Endpoint.
func asyncOpToEndpoint(path, direction string, op *asyncOperation, ch asyncChannel) Endpoint {
	method := "POST"
	if direction == "subscribe" {
		method = "GET" // subscribe = receive = read
	}

	ep := Endpoint{
		Method:         method,
		Path:           path,
		OperationID:    op.OperationID,
		Summary:        op.Summary,
		Description:    op.Description,
		ContentTypes:   []string{"application/json"},
		CorrelationTag: CorrelationTag(method, path),
	}

	if ep.Summary == "" {
		ep.Summary = fmt.Sprintf("WebSocket %s on %s", direction, path)
	}

	// Extract parameters from message payload schema.
	if len(op.Message.Payload) > 0 {
		var schema asyncSchemaObj
		if err := json.Unmarshal(op.Message.Payload, &schema); err == nil {
			ep.Parameters = asyncSchemaToParams(schema)
		}
	}

	// Set content type from message if specified.
	if op.Message.ContentType != "" {
		ep.ContentTypes = []string{op.Message.ContentType}
	}

	return ep
}

// asyncSchemaToParams converts an AsyncAPI schema to Parameters.
func asyncSchemaToParams(schema asyncSchemaObj) []Parameter {
	if len(schema.Properties) == 0 {
		return nil
	}

	requiredSet := make(map[string]bool, len(schema.Required))
	for _, r := range schema.Required {
		requiredSet[r] = true
	}

	var params []Parameter
	for name, prop := range schema.Properties {
		p := Parameter{
			Name:     name,
			In:       LocationBody,
			Required: requiredSet[name],
			Schema: SchemaInfo{
				Type:      prop.Type,
				Format:    prop.Format,
				Enum:      prop.Enum,
				MaxLength: prop.MaxLength,
				MinLength: prop.MinLength,
				Pattern:   prop.Pattern,
				Minimum:   prop.Minimum,
				Maximum:   prop.Maximum,
			},
		}
		params = append(params, p)
	}

	return params
}
