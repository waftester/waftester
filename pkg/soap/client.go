// Package soap provides SOAP/WSDL testing capabilities for WAF assessment
package soap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Client is a SOAP client
type Client struct {
	httpClient *http.Client
	endpoint   string
	timeout    time.Duration
	namespace  string
	soapAction string
}

// ClientOption configures the client
type ClientOption func(*Client)

// WithTimeout sets the request timeout
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
		// Do NOT mutate c.httpClient.Timeout — the client may be the shared
		// httpclient.Default() singleton and mutating it would change the
		// timeout for every other user of that client across the process.
	}
}

// WithSOAPAction sets the SOAPAction header
func WithSOAPAction(action string) ClientOption {
	return func(c *Client) {
		c.soapAction = action
	}
}

// WithNamespace sets the default namespace
func WithNamespace(ns string) ClientOption {
	return func(c *Client) {
		c.namespace = ns
	}
}

// NewClient creates a new SOAP client
func NewClient(endpoint string, opts ...ClientOption) *Client {
	c := &Client{
		endpoint:   endpoint,
		timeout:    duration.HTTPFuzzing,
		httpClient: httpclient.Default(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Envelope represents a SOAP envelope
type Envelope struct {
	XMLName xml.Name `xml:"soap:Envelope"`
	SoapNS  string   `xml:"xmlns:soap,attr"`
	XsiNS   string   `xml:"xmlns:xsi,attr,omitempty"`
	XsdNS   string   `xml:"xmlns:xsd,attr,omitempty"`
	Header  *Header  `xml:"soap:Header,omitempty"`
	Body    Body     `xml:"soap:Body"`
}

// Header represents a SOAP header
type Header struct {
	Content []byte `xml:",innerxml"`
}

// Body represents a SOAP body
type Body struct {
	Content []byte `xml:",innerxml"`
	Fault   *Fault `xml:"Fault,omitempty"`
}

// Fault represents a SOAP fault
type Fault struct {
	Code   string `xml:"faultcode"`
	String string `xml:"faultstring"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

// Request represents a SOAP request
type Request struct {
	Action     string            // SOAP action
	Operation  string            // Operation name
	Namespace  string            // Operation namespace
	Body       string            // Raw XML body content
	Headers    map[string]string // HTTP headers
	SOAPHeader string            // SOAP header content
}

// Response represents a SOAP response
type Response struct {
	StatusCode int
	Body       string
	Fault      *Fault
	RawXML     []byte
	Latency    time.Duration
	Headers    map[string]string
	Blocked    bool
}

// Call makes a SOAP call (convenience wrapper)
func (c *Client) Call(req *Request) (*Response, error) {
	return c.CallWithContext(context.Background(), req)
}

// CallWithContext makes a SOAP call with context for cancellation/timeout support
func (c *Client) CallWithContext(ctx context.Context, req *Request) (*Response, error) {
	// Apply timeout from client config if not already set in context
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Build SOAP envelope
	envelope := c.buildEnvelope(req)

	// Create HTTP request with context
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(envelope))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "text/xml; charset=utf-8")
	if req.Action != "" {
		httpReq.Header.Set("SOAPAction", req.Action)
	} else if c.soapAction != "" {
		httpReq.Header.Set("SOAPAction", c.soapAction)
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Make request
	start := time.Now()
	httpResp, err := c.httpClient.Do(httpReq)
	latency := time.Since(start)

	if err != nil {
		return &Response{
			Blocked: true,
			Latency: latency,
		}, fmt.Errorf("request failed: %w", err)
	}
	defer iohelper.DrainAndClose(httpResp.Body)

	// Read response
	body, err := iohelper.ReadBodyDefault(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	resp := &Response{
		StatusCode: httpResp.StatusCode,
		RawXML:     body,
		Latency:    latency,
		Headers:    make(map[string]string),
	}

	// Extract headers
	for k, v := range httpResp.Header {
		if len(v) > 0 {
			resp.Headers[k] = v[0]
		}
	}

	// Check if blocked
	if httpResp.StatusCode == 403 || httpResp.StatusCode == 406 ||
		httpResp.StatusCode == 418 || httpResp.StatusCode >= 500 {
		resp.Blocked = true
	}

	// Parse SOAP response
	var respEnvelope Envelope
	if err := xml.Unmarshal(body, &respEnvelope); err == nil {
		if respEnvelope.Body.Fault != nil {
			resp.Fault = respEnvelope.Body.Fault
		}
		resp.Body = string(respEnvelope.Body.Content)
	} else {
		resp.Body = string(body)
	}

	return resp, nil
}

// buildEnvelope creates a SOAP envelope
func (c *Client) buildEnvelope(req *Request) []byte {
	var sb strings.Builder

	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"`)
	sb.WriteString(` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
	sb.WriteString(` xmlns:xsd="http://www.w3.org/2001/XMLSchema"`)

	ns := req.Namespace
	if ns == "" {
		ns = c.namespace
	}
	if ns != "" {
		sb.WriteString(fmt.Sprintf(` xmlns:ns="%s"`, ns))
	}

	sb.WriteString(`>`)

	// Add header if present
	if req.SOAPHeader != "" {
		sb.WriteString(`<soap:Header>`)
		sb.WriteString(req.SOAPHeader)
		sb.WriteString(`</soap:Header>`)
	}

	sb.WriteString(`<soap:Body>`)

	if req.Operation != "" && req.Body == "" {
		if ns != "" {
			sb.WriteString(fmt.Sprintf(`<ns:%s/>`, req.Operation))
		} else {
			sb.WriteString(fmt.Sprintf(`<%s/>`, req.Operation))
		}
	} else {
		sb.WriteString(req.Body)
	}

	sb.WriteString(`</soap:Body>`)
	sb.WriteString(`</soap:Envelope>`)

	return []byte(sb.String())
}

// WSDLDefinition represents a parsed WSDL
type WSDLDefinition struct {
	TargetNamespace string
	Services        []ServiceInfo
	Operations      []OperationInfo
	Types           []TypeInfo
	Messages        []MessageInfo
}

// ServiceInfo describes a WSDL service
type ServiceInfo struct {
	Name     string
	Ports    []PortInfo
	Endpoint string
}

// PortInfo describes a WSDL port
type PortInfo struct {
	Name     string
	Binding  string
	Location string
}

// OperationInfo describes a WSDL operation
type OperationInfo struct {
	Name          string
	Input         string
	Output        string
	SOAPAction    string
	Documentation string
}

// TypeInfo describes a WSDL type
type TypeInfo struct {
	Name      string
	Elements  []ElementInfo
	Namespace string
	IsComplex bool
}

// ElementInfo describes a type element
type ElementInfo struct {
	Name      string
	Type      string
	MinOccurs int
	MaxOccurs string
	Nillable  bool
}

// MessageInfo describes a WSDL message
type MessageInfo struct {
	Name  string
	Parts []PartInfo
}

// PartInfo describes a message part
type PartInfo struct {
	Name    string
	Element string
	Type    string
}

// Pre-compiled regexes for WSDL parsing (avoid recompiling on every call).
var (
	wsdlNSRe      = regexp.MustCompile(`targetNamespace="([^"]+)"`)
	wsdlSvcRe     = regexp.MustCompile(`<(?:wsdl:)?service\s+name="([^"]+)"[^>]*>([\s\S]*?)</(?:wsdl:)?service>`)
	wsdlPortRe    = regexp.MustCompile(`<(?:wsdl:)?port\s+name="([^"]+)"[^>]*binding="([^"]+)"[^>]*>[\s\S]*?<(?:soap:)?address\s+location="([^"]+)"`)
	wsdlBindingRe = regexp.MustCompile(`<(?:wsdl:)?binding[^>]*>([\s\S]*?)</(?:wsdl:)?binding>`)
	wsdlBindOpRe  = regexp.MustCompile(`<(?:wsdl:)?operation\s+name="([^"]+)"[\s\S]*?<(?:soap:)?operation\s+soapAction="([^"]*)"`)
	wsdlMsgRe     = regexp.MustCompile(`<(?:wsdl:)?message\s+name="([^"]+)"[^>]*>([\s\S]*?)</(?:wsdl:)?message>`)
	wsdlPartRe    = regexp.MustCompile(`<(?:wsdl:)?part\s+name="([^"]+)"(?:\s+element="([^"]+)")?(?:\s+type="([^"]+)")?`)
	wsdlTypeRe    = regexp.MustCompile(`<(?:xs?|xsd):complexType\s+name="([^"]+)"[^>]*>([\s\S]*?)</(?:xs?|xsd):complexType>`)
	wsdlElemRe    = regexp.MustCompile(`<(?:xs?|xsd):element\s+name="([^"]+)"(?:\s+type="([^"]+)")?`)
)

// ParseWSDL parses a WSDL from URL or raw content
func ParseWSDL(content []byte) (*WSDLDefinition, error) {
	def := &WSDLDefinition{}

	// Extract target namespace
	nsMatch := wsdlNSRe.FindSubmatch(content)
	if len(nsMatch) > 1 {
		def.TargetNamespace = string(nsMatch[1])
	}

	// Extract services
	for _, match := range wsdlSvcRe.FindAllSubmatch(content, -1) {
		svc := ServiceInfo{Name: string(match[1])}

		// Extract ports
		for _, portMatch := range wsdlPortRe.FindAllSubmatch(match[2], -1) {
			svc.Ports = append(svc.Ports, PortInfo{
				Name:     string(portMatch[1]),
				Binding:  string(portMatch[2]),
				Location: string(portMatch[3]),
			})
			if svc.Endpoint == "" {
				svc.Endpoint = string(portMatch[3])
			}
		}

		def.Services = append(def.Services, svc)
	}

	// Extract operations from <binding> sections only.
	// Previous code matched <operation> globally, which captured both
	// <portType> and <binding> entries (2N matches for N operations),
	// then paired them positionally with <soap:operation> (N matches) —
	// causing wrong SOAPAction assignment.
	seen := make(map[string]bool)
	for _, bindMatch := range wsdlBindingRe.FindAllSubmatch(content, -1) {
		for _, opMatch := range wsdlBindOpRe.FindAllSubmatch(bindMatch[1], -1) {
			name := string(opMatch[1])
			if seen[name] {
				continue // deduplicate across multiple bindings
			}
			seen[name] = true
			def.Operations = append(def.Operations, OperationInfo{
				Name:       name,
				SOAPAction: string(opMatch[2]),
			})
		}
	}

	// Extract messages
	for _, match := range wsdlMsgRe.FindAllSubmatch(content, -1) {
		msg := MessageInfo{Name: string(match[1])}

		for _, partMatch := range wsdlPartRe.FindAllSubmatch(match[2], -1) {
			part := PartInfo{Name: string(partMatch[1])}
			if len(partMatch) > 2 {
				part.Element = string(partMatch[2])
			}
			if len(partMatch) > 3 {
				part.Type = string(partMatch[3])
			}
			msg.Parts = append(msg.Parts, part)
		}

		def.Messages = append(def.Messages, msg)
	}

	// Extract complex types
	for _, match := range wsdlTypeRe.FindAllSubmatch(content, -1) {
		typ := TypeInfo{
			Name:      string(match[1]),
			IsComplex: true,
		}

		for _, elemMatch := range wsdlElemRe.FindAllSubmatch(match[2], -1) {
			elem := ElementInfo{Name: string(elemMatch[1])}
			if len(elemMatch) > 2 {
				elem.Type = string(elemMatch[2])
			}
			typ.Elements = append(typ.Elements, elem)
		}

		def.Types = append(def.Types, typ)
	}

	return def, nil
}

// FetchWSDL fetches WSDL from a URL
func FetchWSDL(url string) (*WSDLDefinition, error) {
	client := httpclient.Default()
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch WSDL: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	content, err := iohelper.ReadBody(resp.Body, 5*1024*1024) // 5MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read WSDL: %w", err)
	}

	return ParseWSDL(content)
}

// TestCase represents a SOAP security test case
type TestCase struct {
	ID           string
	Operation    string
	Description  string
	Category     string
	Request      *Request
	ExpectBlock  bool
	PayloadField string
}

// Generator creates test cases for SOAP services
type Generator struct {
	wsdl     *WSDLDefinition
	endpoint string
	payloads []string
}

// NewGenerator creates a test case generator
func NewGenerator(wsdl *WSDLDefinition, endpoint string, payloads []string) *Generator {
	return &Generator{
		wsdl:     wsdl,
		endpoint: endpoint,
		payloads: payloads,
	}
}

// Generate creates test cases for all operations
func (g *Generator) Generate() []TestCase {
	var testCases []TestCase
	id := 1

	for _, op := range g.wsdl.Operations {
		for _, payload := range g.payloads {
			// Test payload in operation body
			tc := TestCase{
				ID:          fmt.Sprintf("soap-%s-%03d", op.Name, id),
				Operation:   op.Name,
				Description: fmt.Sprintf("Inject payload in %s operation", op.Name),
				Category:    "injection",
				Request: &Request{
					Action:    op.SOAPAction,
					Operation: op.Name,
					Namespace: g.wsdl.TargetNamespace,
					Body:      fmt.Sprintf(`<%s xmlns="%s"><input>%s</input></%s>`, op.Name, g.wsdl.TargetNamespace, payload, op.Name),
				},
				ExpectBlock: true,
			}
			testCases = append(testCases, tc)
			id++

			// Test payload in SOAP header
			tc = TestCase{
				ID:          fmt.Sprintf("soap-%s-%03d", op.Name, id),
				Operation:   op.Name,
				Description: fmt.Sprintf("Inject payload in %s SOAP header", op.Name),
				Category:    "injection",
				Request: &Request{
					Action:     op.SOAPAction,
					Operation:  op.Name,
					Namespace:  g.wsdl.TargetNamespace,
					SOAPHeader: fmt.Sprintf(`<CustomHeader>%s</CustomHeader>`, payload),
				},
				ExpectBlock: true,
			}
			testCases = append(testCases, tc)
			id++

			// Test XXE in body
			xxePayload := fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><%s xmlns="%s"><input>&xxe;</input></%s>`, op.Name, g.wsdl.TargetNamespace, op.Name)
			tc = TestCase{
				ID:          fmt.Sprintf("soap-%s-xxe-%03d", op.Name, id),
				Operation:   op.Name,
				Description: fmt.Sprintf("XXE attack in %s operation", op.Name),
				Category:    "xxe",
				Request: &Request{
					Action:    op.SOAPAction,
					Operation: op.Name,
					Namespace: g.wsdl.TargetNamespace,
					Body:      xxePayload,
				},
				ExpectBlock: true,
			}
			testCases = append(testCases, tc)
			id++
		}
	}

	return testCases
}

// GenerateForOperation creates test cases for a specific operation
func (g *Generator) GenerateForOperation(opName string) []TestCase {
	var testCases []TestCase
	id := 1

	var op *OperationInfo
	for _, o := range g.wsdl.Operations {
		if o.Name == opName {
			op = &o
			break
		}
	}

	if op == nil {
		return testCases
	}

	for _, payload := range g.payloads {
		tc := TestCase{
			ID:          fmt.Sprintf("soap-%s-%03d", op.Name, id),
			Operation:   op.Name,
			Description: fmt.Sprintf("Inject payload in %s operation", op.Name),
			Category:    "injection",
			Request: &Request{
				Action:    op.SOAPAction,
				Operation: op.Name,
				Namespace: g.wsdl.TargetNamespace,
				Body:      fmt.Sprintf(`<%s><data>%s</data></%s>`, op.Name, payload, op.Name),
			},
			ExpectBlock: true,
		}
		testCases = append(testCases, tc)
		id++
	}

	return testCases
}

// FetchAndParseWSDL fetches a WSDL from a URL and parses it
func FetchAndParseWSDL(ctx context.Context, url string) (*WSDLDefinition, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := httpclient.New(httpclient.Config{Timeout: duration.HTTPFuzzing})
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch WSDL: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Use bounded read to prevent memory exhaustion from malicious servers (5MB limit for WSDL)
	body, err := iohelper.ReadBody(resp.Body, 5*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("failed to read WSDL: %w", err)
	}

	return ParseWSDL(body)
}

// OperationsList is a convenience wrapper for operations
type OperationsList []OperationInfo

// GetOperations returns all operations from a WSDL
func (def *WSDLDefinition) GetOperations() OperationsList {
	return def.Operations
}
