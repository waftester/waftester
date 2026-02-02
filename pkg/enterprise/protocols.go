// Package enterprise provides gRPC, SOAP, and other enterprise protocol location support
// for WAF testing. Supports auto-detection and manual override of protocol types.
package enterprise

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/waftester/waftester/pkg/iohelper"
)

// ProtocolType represents an enterprise protocol type
type ProtocolType string

const (
	ProtocolHTTP     ProtocolType = "http"
	ProtocolGRPC     ProtocolType = "grpc"
	ProtocolGRPCWeb  ProtocolType = "grpc-web"
	ProtocolSOAP     ProtocolType = "soap"
	ProtocolXMLRPC   ProtocolType = "xml-rpc"
	ProtocolWCF      ProtocolType = "wcf"
	ProtocolGraphQL  ProtocolType = "graphql"
	ProtocolProtobuf ProtocolType = "protobuf"
)

// Location represents a protocol-specific injection location
type Location interface {
	// Name returns the location name
	Name() string
	// Protocol returns the protocol type
	Protocol() ProtocolType
	// BuildRequest builds an HTTP request with payload injected
	BuildRequest(ctx context.Context, baseURL, payload string) (*http.Request, error)
	// ContentType returns the content type for this location
	ContentType() string
	// Description returns a human-readable description
	Description() string
}

// ProtocolDetector detects protocols at a target URL
type ProtocolDetector struct {
	client *http.Client
}

// NewProtocolDetector creates a new protocol detector
func NewProtocolDetector(client *http.Client) *ProtocolDetector {
	return &ProtocolDetector{client: client}
}

// DetectedProtocol contains protocol detection results
type DetectedProtocol struct {
	Type       ProtocolType `json:"type"`
	Confidence float64      `json:"confidence"`
	Evidence   []string     `json:"evidence"`
	Endpoints  []string     `json:"endpoints,omitempty"`
}

// DetectProtocol auto-detects the protocol at a URL
func (d *ProtocolDetector) DetectProtocol(ctx context.Context, url string) (*DetectedProtocol, error) {
	// Try HEAD/GET first
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBody(resp.Body, iohelper.SmallMaxBodySize)
	bodyStr := string(body)

	// Check for gRPC-Web
	if resp.Header.Get("Content-Type") == "application/grpc-web" ||
		resp.Header.Get("Content-Type") == "application/grpc-web+proto" {
		return &DetectedProtocol{
			Type:       ProtocolGRPCWeb,
			Confidence: 0.9,
			Evidence:   []string{"Content-Type: application/grpc-web"},
		}, nil
	}

	// Check for gRPC
	if resp.Header.Get("Content-Type") == "application/grpc" {
		return &DetectedProtocol{
			Type:       ProtocolGRPC,
			Confidence: 0.9,
			Evidence:   []string{"Content-Type: application/grpc"},
		}, nil
	}

	// Check for SOAP
	if strings.Contains(bodyStr, "wsdl") || strings.Contains(bodyStr, "WSDL") ||
		strings.Contains(bodyStr, "soap:Envelope") || strings.Contains(bodyStr, "SOAP-ENV") {
		return &DetectedProtocol{
			Type:       ProtocolSOAP,
			Confidence: 0.8,
			Evidence:   []string{"SOAP/WSDL signatures in response"},
		}, nil
	}

	// Check for XML-RPC
	if strings.Contains(bodyStr, "<methodCall>") || strings.Contains(bodyStr, "<methodResponse>") {
		return &DetectedProtocol{
			Type:       ProtocolXMLRPC,
			Confidence: 0.8,
			Evidence:   []string{"XML-RPC signatures in response"},
		}, nil
	}

	// Check for WCF
	if strings.Contains(bodyStr, "svc") || strings.Contains(resp.Header.Get("Content-Type"), "application/soap+xml") {
		return &DetectedProtocol{
			Type:       ProtocolWCF,
			Confidence: 0.6,
			Evidence:   []string{"WCF service signatures"},
		}, nil
	}

	// Check for GraphQL
	if strings.Contains(url, "/graphql") || strings.Contains(url, "/gql") ||
		strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "GraphQL") {
		return &DetectedProtocol{
			Type:       ProtocolGraphQL,
			Confidence: 0.7,
			Evidence:   []string{"GraphQL endpoint pattern"},
		}, nil
	}

	// Default to HTTP
	return &DetectedProtocol{
		Type:       ProtocolHTTP,
		Confidence: 0.5,
		Evidence:   []string{"No specific protocol detected, defaulting to HTTP"},
	}, nil
}

// =====================================================================
// gRPC LOCATION
// =====================================================================

// GRPCLocation handles gRPC protocol injection
type GRPCLocation struct {
	ServiceName string
	MethodName  string
	FieldPath   string
}

func (l *GRPCLocation) Name() string {
	return fmt.Sprintf("grpc_%s_%s", l.ServiceName, l.MethodName)
}

func (l *GRPCLocation) Protocol() ProtocolType {
	return ProtocolGRPC
}

func (l *GRPCLocation) ContentType() string {
	return "application/grpc"
}

func (l *GRPCLocation) Description() string {
	return fmt.Sprintf("gRPC %s.%s field: %s", l.ServiceName, l.MethodName, l.FieldPath)
}

func (l *GRPCLocation) BuildRequest(ctx context.Context, baseURL, payload string) (*http.Request, error) {
	// gRPC uses HTTP/2 with binary protobuf
	// For WAF testing, we send the payload as if it were a protobuf string field
	// This is a simplified representation - real gRPC would need proper protobuf encoding

	// Wrap payload in a minimal protobuf-like structure
	// Field 1, wire type 2 (length-delimited) = tag 0x0a
	protoPayload := buildProtoString(1, payload)

	// gRPC frame: 1 byte flags + 4 bytes length + data
	grpcFrame := make([]byte, 5+len(protoPayload))
	grpcFrame[0] = 0 // no compression
	grpcFrame[1] = byte(len(protoPayload) >> 24)
	grpcFrame[2] = byte(len(protoPayload) >> 16)
	grpcFrame[3] = byte(len(protoPayload) >> 8)
	grpcFrame[4] = byte(len(protoPayload))
	copy(grpcFrame[5:], protoPayload)

	url := fmt.Sprintf("%s/%s/%s", strings.TrimSuffix(baseURL, "/"), l.ServiceName, l.MethodName)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(grpcFrame))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Grpc-Accept-Encoding", "identity")

	return req, nil
}

// buildProtoString creates a protobuf-encoded string field
func buildProtoString(fieldNum int, value string) []byte {
	// Tag = (field_number << 3) | wire_type
	// Wire type 2 = length-delimited (strings, bytes, embedded messages)
	tag := (fieldNum << 3) | 2

	// Varint encode the tag and length
	result := []byte{byte(tag)}

	// Add length as varint
	length := len(value)
	for length >= 0x80 {
		result = append(result, byte(length)|0x80)
		length >>= 7
	}
	result = append(result, byte(length))

	// Add the string value
	result = append(result, []byte(value)...)

	return result
}

// =====================================================================
// gRPC-Web LOCATION
// =====================================================================

// GRPCWebLocation handles gRPC-Web protocol injection
type GRPCWebLocation struct {
	ServiceName string
	MethodName  string
	FieldPath   string
}

func (l *GRPCWebLocation) Name() string {
	return fmt.Sprintf("grpc_web_%s_%s", l.ServiceName, l.MethodName)
}

func (l *GRPCWebLocation) Protocol() ProtocolType {
	return ProtocolGRPCWeb
}

func (l *GRPCWebLocation) ContentType() string {
	return "application/grpc-web+proto"
}

func (l *GRPCWebLocation) Description() string {
	return fmt.Sprintf("gRPC-Web %s.%s field: %s", l.ServiceName, l.MethodName, l.FieldPath)
}

func (l *GRPCWebLocation) BuildRequest(ctx context.Context, baseURL, payload string) (*http.Request, error) {
	// gRPC-Web is similar to gRPC but uses base64 encoding for binary data
	protoPayload := buildProtoString(1, payload)

	// gRPC-Web frame
	grpcFrame := make([]byte, 5+len(protoPayload))
	grpcFrame[0] = 0
	grpcFrame[1] = byte(len(protoPayload) >> 24)
	grpcFrame[2] = byte(len(protoPayload) >> 16)
	grpcFrame[3] = byte(len(protoPayload) >> 8)
	grpcFrame[4] = byte(len(protoPayload))
	copy(grpcFrame[5:], protoPayload)

	// Base64 encode for grpc-web-text
	encoded := base64.StdEncoding.EncodeToString(grpcFrame)

	url := fmt.Sprintf("%s/%s/%s", strings.TrimSuffix(baseURL, "/"), l.ServiceName, l.MethodName)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(encoded))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/grpc-web-text")
	req.Header.Set("Accept", "application/grpc-web-text")
	req.Header.Set("X-Grpc-Web", "1")

	return req, nil
}

// =====================================================================
// SOAP LOCATION
// =====================================================================

// SOAPLocation handles SOAP protocol injection
type SOAPLocation struct {
	Action      string
	Namespace   string
	ElementPath string
	SOAPVersion string // "1.1" or "1.2"
}

func (l *SOAPLocation) Name() string {
	return fmt.Sprintf("soap_%s", l.Action)
}

func (l *SOAPLocation) Protocol() ProtocolType {
	return ProtocolSOAP
}

func (l *SOAPLocation) ContentType() string {
	if l.SOAPVersion == "1.2" {
		return "application/soap+xml; charset=utf-8"
	}
	return "text/xml; charset=utf-8"
}

func (l *SOAPLocation) Description() string {
	return fmt.Sprintf("SOAP %s action, element: %s", l.Action, l.ElementPath)
}

func (l *SOAPLocation) BuildRequest(ctx context.Context, baseURL, payload string) (*http.Request, error) {
	var envelope string

	if l.SOAPVersion == "1.2" {
		envelope = l.buildSOAP12Envelope(payload)
	} else {
		envelope = l.buildSOAP11Envelope(payload)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, strings.NewReader(envelope))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", l.ContentType())
	if l.SOAPVersion != "1.2" {
		req.Header.Set("SOAPAction", l.Action)
	}

	return req, nil
}

func (l *SOAPLocation) buildSOAP11Envelope(payload string) string {
	// Escape XML special chars in payload
	escapedPayload := xmlEscape(payload)

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
               xmlns:ns="%s">
  <soap:Header/>
  <soap:Body>
    <ns:%s>
      <ns:input>%s</ns:input>
    </ns:%s>
  </soap:Body>
</soap:Envelope>`, l.Namespace, l.Action, escapedPayload, l.Action)
}

func (l *SOAPLocation) buildSOAP12Envelope(payload string) string {
	escapedPayload := xmlEscape(payload)

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:ns="%s">
  <soap:Header/>
  <soap:Body>
    <ns:%s>
      <ns:input>%s</ns:input>
    </ns:%s>
  </soap:Body>
</soap:Envelope>`, l.Namespace, l.Action, escapedPayload, l.Action)
}

// =====================================================================
// XML-RPC LOCATION
// =====================================================================

// XMLRPCLocation handles XML-RPC protocol injection
type XMLRPCLocation struct {
	MethodName string
	ParamIndex int
}

func (l *XMLRPCLocation) Name() string {
	return fmt.Sprintf("xmlrpc_%s_param%d", l.MethodName, l.ParamIndex)
}

func (l *XMLRPCLocation) Protocol() ProtocolType {
	return ProtocolXMLRPC
}

func (l *XMLRPCLocation) ContentType() string {
	return "text/xml"
}

func (l *XMLRPCLocation) Description() string {
	return fmt.Sprintf("XML-RPC %s method, param %d", l.MethodName, l.ParamIndex)
}

func (l *XMLRPCLocation) BuildRequest(ctx context.Context, baseURL, payload string) (*http.Request, error) {
	escapedPayload := xmlEscape(payload)

	body := fmt.Sprintf(`<?xml version="1.0"?>
<methodCall>
  <methodName>%s</methodName>
  <params>
    <param>
      <value><string>%s</string></value>
    </param>
  </params>
</methodCall>`, l.MethodName, escapedPayload)

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", l.ContentType())

	return req, nil
}

// =====================================================================
// WCF LOCATION
// =====================================================================

// WCFLocation handles WCF service injection
type WCFLocation struct {
	ServiceName string
	Operation   string
	Parameter   string
	Binding     string // basicHttpBinding, wsHttpBinding, netTcpBinding
}

func (l *WCFLocation) Name() string {
	return fmt.Sprintf("wcf_%s_%s", l.ServiceName, l.Operation)
}

func (l *WCFLocation) Protocol() ProtocolType {
	return ProtocolWCF
}

func (l *WCFLocation) ContentType() string {
	if l.Binding == "wsHttpBinding" {
		return "application/soap+xml; charset=utf-8"
	}
	return "text/xml; charset=utf-8"
}

func (l *WCFLocation) Description() string {
	return fmt.Sprintf("WCF %s.%s parameter: %s", l.ServiceName, l.Operation, l.Parameter)
}

func (l *WCFLocation) BuildRequest(ctx context.Context, baseURL, payload string) (*http.Request, error) {
	escapedPayload := xmlEscape(payload)

	// WCF uses SOAP with WS-Addressing
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://tempuri.org/I%s/%s</a:Action>
    <a:To s:mustUnderstand="1">%s</a:To>
  </s:Header>
  <s:Body>
    <%s xmlns="http://tempuri.org/">
      <%s>%s</%s>
    </%s>
  </s:Body>
</s:Envelope>`, l.ServiceName, l.Operation, baseURL, l.Operation, l.Parameter, escapedPayload, l.Parameter, l.Operation)

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", l.ContentType())
	req.Header.Set("SOAPAction", fmt.Sprintf("http://tempuri.org/I%s/%s", l.ServiceName, l.Operation))

	return req, nil
}

// =====================================================================
// GraphQL LOCATION
// =====================================================================

// GraphQLLocation handles GraphQL injection
type GraphQLLocation struct {
	OperationType string // "query" or "mutation"
	OperationName string
	VariableName  string
}

func (l *GraphQLLocation) Name() string {
	return fmt.Sprintf("graphql_%s_%s", l.OperationType, l.OperationName)
}

func (l *GraphQLLocation) Protocol() ProtocolType {
	return ProtocolGraphQL
}

func (l *GraphQLLocation) ContentType() string {
	return "application/json"
}

func (l *GraphQLLocation) Description() string {
	return fmt.Sprintf("GraphQL %s %s, variable: %s", l.OperationType, l.OperationName, l.VariableName)
}

func (l *GraphQLLocation) BuildRequest(ctx context.Context, baseURL, payload string) (*http.Request, error) {
	// Build GraphQL request with payload in variable
	gqlRequest := map[string]interface{}{
		"operationName": l.OperationName,
		"query": fmt.Sprintf(`%s %s($%s: String!) { %s(%s: $%s) }`,
			l.OperationType, l.OperationName, l.VariableName,
			l.OperationName, l.VariableName, l.VariableName),
		"variables": map[string]interface{}{
			l.VariableName: payload,
		},
	}

	body, err := json.Marshal(gqlRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", l.ContentType())
	req.Header.Set("Accept", "application/json")

	return req, nil
}

// =====================================================================
// Protobuf LOCATION (raw binary)
// =====================================================================

// ProtobufLocation handles raw protobuf injection
type ProtobufLocation struct {
	MessageType string
	FieldNumber int
}

func (l *ProtobufLocation) Name() string {
	return fmt.Sprintf("protobuf_%s_field%d", l.MessageType, l.FieldNumber)
}

func (l *ProtobufLocation) Protocol() ProtocolType {
	return ProtocolProtobuf
}

func (l *ProtobufLocation) ContentType() string {
	return "application/x-protobuf"
}

func (l *ProtobufLocation) Description() string {
	return fmt.Sprintf("Protobuf %s field %d", l.MessageType, l.FieldNumber)
}

func (l *ProtobufLocation) BuildRequest(ctx context.Context, baseURL, payload string) (*http.Request, error) {
	// Build minimal protobuf with payload as string field
	protoPayload := buildProtoString(l.FieldNumber, payload)

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, bytes.NewReader(protoPayload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", l.ContentType())

	return req, nil
}

// =====================================================================
// LOCATION FACTORY
// =====================================================================

// LocationFactory creates enterprise protocol locations
type LocationFactory struct{}

// NewLocationFactory creates a new location factory
func NewLocationFactory() *LocationFactory {
	return &LocationFactory{}
}

// CreateLocations returns all locations for a detected protocol
func (f *LocationFactory) CreateLocations(protocol ProtocolType) []Location {
	switch protocol {
	case ProtocolGRPC:
		return []Location{
			&GRPCLocation{ServiceName: "TestService", MethodName: "Process", FieldPath: "input"},
		}
	case ProtocolGRPCWeb:
		return []Location{
			&GRPCWebLocation{ServiceName: "TestService", MethodName: "Process", FieldPath: "input"},
		}
	case ProtocolSOAP:
		return []Location{
			&SOAPLocation{Action: "ProcessRequest", Namespace: "http://example.com/", ElementPath: "input", SOAPVersion: "1.1"},
			&SOAPLocation{Action: "ProcessRequest", Namespace: "http://example.com/", ElementPath: "input", SOAPVersion: "1.2"},
		}
	case ProtocolXMLRPC:
		return []Location{
			&XMLRPCLocation{MethodName: "processRequest", ParamIndex: 0},
		}
	case ProtocolWCF:
		return []Location{
			&WCFLocation{ServiceName: "TestService", Operation: "Process", Parameter: "input", Binding: "wsHttpBinding"},
		}
	case ProtocolGraphQL:
		return []Location{
			&GraphQLLocation{OperationType: "query", OperationName: "search", VariableName: "input"},
			&GraphQLLocation{OperationType: "mutation", OperationName: "update", VariableName: "data"},
		}
	case ProtocolProtobuf:
		return []Location{
			&ProtobufLocation{MessageType: "Request", FieldNumber: 1},
		}
	default:
		return nil
	}
}

// CreateCustomLocation creates a custom location based on protocol type and parameters
func (f *LocationFactory) CreateCustomLocation(protocol ProtocolType, params map[string]string) (Location, error) {
	switch protocol {
	case ProtocolGRPC:
		return &GRPCLocation{
			ServiceName: getOrDefault(params, "service", "Service"),
			MethodName:  getOrDefault(params, "method", "Method"),
			FieldPath:   getOrDefault(params, "field", "input"),
		}, nil
	case ProtocolGRPCWeb:
		return &GRPCWebLocation{
			ServiceName: getOrDefault(params, "service", "Service"),
			MethodName:  getOrDefault(params, "method", "Method"),
			FieldPath:   getOrDefault(params, "field", "input"),
		}, nil
	case ProtocolSOAP:
		return &SOAPLocation{
			Action:      getOrDefault(params, "action", "Request"),
			Namespace:   getOrDefault(params, "namespace", "http://example.com/"),
			ElementPath: getOrDefault(params, "element", "input"),
			SOAPVersion: getOrDefault(params, "version", "1.1"),
		}, nil
	case ProtocolXMLRPC:
		return &XMLRPCLocation{
			MethodName: getOrDefault(params, "method", "method"),
			ParamIndex: 0,
		}, nil
	case ProtocolWCF:
		return &WCFLocation{
			ServiceName: getOrDefault(params, "service", "Service"),
			Operation:   getOrDefault(params, "operation", "Process"),
			Parameter:   getOrDefault(params, "parameter", "input"),
			Binding:     getOrDefault(params, "binding", "wsHttpBinding"),
		}, nil
	case ProtocolGraphQL:
		return &GraphQLLocation{
			OperationType: getOrDefault(params, "type", "query"),
			OperationName: getOrDefault(params, "operation", "query"),
			VariableName:  getOrDefault(params, "variable", "input"),
		}, nil
	case ProtocolProtobuf:
		return &ProtobufLocation{
			MessageType: getOrDefault(params, "message", "Message"),
			FieldNumber: 1,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// =====================================================================
// UTILITY FUNCTIONS
// =====================================================================

func xmlEscape(s string) string {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return s
	}
	return buf.String()
}

func getOrDefault(m map[string]string, key, defaultVal string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return defaultVal
}

// GetAllProtocolTypes returns all supported protocol types
func GetAllProtocolTypes() []ProtocolType {
	return []ProtocolType{
		ProtocolHTTP,
		ProtocolGRPC,
		ProtocolGRPCWeb,
		ProtocolSOAP,
		ProtocolXMLRPC,
		ProtocolWCF,
		ProtocolGraphQL,
		ProtocolProtobuf,
	}
}

// FormatProtocolReport generates a report of detected protocols
func FormatProtocolReport(detected *DetectedProtocol, locations []Location) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║           ENTERPRISE PROTOCOL DETECTION                      ║\n")
	sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	sb.WriteString(fmt.Sprintf("║  Protocol:    %-46s ║\n", detected.Type))
	sb.WriteString(fmt.Sprintf("║  Confidence:  %.0f%%%-43s ║\n", detected.Confidence*100, ""))

	if len(detected.Evidence) > 0 {
		sb.WriteString("║  Evidence:                                                   ║\n")
		for _, e := range detected.Evidence {
			if len(e) > 56 {
				e = e[:53] + "..."
			}
			sb.WriteString(fmt.Sprintf("║    • %-56s ║\n", e))
		}
	}

	if len(locations) > 0 {
		sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
		sb.WriteString("║  INJECTION LOCATIONS                                         ║\n")
		sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
		for _, loc := range locations {
			desc := loc.Description()
			if len(desc) > 56 {
				desc = desc[:53] + "..."
			}
			sb.WriteString(fmt.Sprintf("║  → %-58s ║\n", desc))
		}
	}

	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}
