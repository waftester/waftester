package soap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client := NewClient("http://example.com/soap")
	if client == nil {
		t.Fatal("Expected client to be created")
	}
	if client.endpoint != "http://example.com/soap" {
		t.Errorf("Expected endpoint 'http://example.com/soap', got '%s'", client.endpoint)
	}
	if client.timeout != 30*time.Second {
		t.Errorf("Expected default timeout of 30s, got %v", client.timeout)
	}
}

func TestClientOptions(t *testing.T) {
	client := NewClient("http://example.com/soap",
		WithTimeout(10*time.Second),
		WithSOAPAction("urn:myaction"),
		WithNamespace("http://example.com/ns"),
	)

	if client.timeout != 10*time.Second {
		t.Errorf("Expected timeout of 10s, got %v", client.timeout)
	}
	if client.soapAction != "urn:myaction" {
		t.Errorf("Expected soapAction 'urn:myaction', got '%s'", client.soapAction)
	}
	if client.namespace != "http://example.com/ns" {
		t.Errorf("Expected namespace 'http://example.com/ns', got '%s'", client.namespace)
	}
}

func TestRequestFields(t *testing.T) {
	req := &Request{
		Action:     "urn:test",
		Operation:  "GetData",
		Namespace:  "http://test.com",
		Body:       "<data>test</data>",
		SOAPHeader: "<auth>token</auth>",
		Headers: map[string]string{
			"X-Custom": "value",
		},
	}

	if req.Action != "urn:test" {
		t.Errorf("Expected action 'urn:test'")
	}
	if req.Operation != "GetData" {
		t.Errorf("Expected operation 'GetData'")
	}
	if req.Namespace != "http://test.com" {
		t.Errorf("Expected namespace 'http://test.com'")
	}
	if req.Body != "<data>test</data>" {
		t.Errorf("Expected body '<data>test</data>'")
	}
	if req.SOAPHeader != "<auth>token</auth>" {
		t.Errorf("Expected SOAPHeader '<auth>token</auth>'")
	}
	if req.Headers["X-Custom"] != "value" {
		t.Errorf("Expected custom header")
	}
}

func TestResponseFields(t *testing.T) {
	resp := &Response{
		StatusCode: 200,
		Body:       "<result>ok</result>",
		RawXML:     []byte("<envelope><result>ok</result></envelope>"),
		Latency:    100 * time.Millisecond,
		Headers:    map[string]string{"Content-Type": "text/xml"},
		Blocked:    false,
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200")
	}
	if resp.Body != "<result>ok</result>" {
		t.Errorf("Expected body")
	}
	if resp.Latency != 100*time.Millisecond {
		t.Errorf("Expected latency 100ms")
	}
	if resp.Blocked {
		t.Errorf("Expected not blocked")
	}
}

func TestResponseBlocked(t *testing.T) {
	tests := []struct {
		statusCode int
		blocked    bool
	}{
		{200, false},
		{403, true},
		{406, true},
		{418, true},
		{500, true},
		{502, true},
		{503, true},
	}

	for _, tt := range tests {
		resp := &Response{StatusCode: tt.statusCode, Blocked: tt.blocked}
		if resp.Blocked != tt.blocked {
			t.Errorf("Status %d: expected blocked=%v", tt.statusCode, tt.blocked)
		}
	}
}

func TestFault(t *testing.T) {
	fault := &Fault{
		Code:   "soap:Server",
		String: "Internal error",
		Actor:  "http://example.com/actor",
		Detail: "Stack trace here",
	}

	if fault.Code != "soap:Server" {
		t.Errorf("Expected fault code 'soap:Server'")
	}
	if fault.String != "Internal error" {
		t.Errorf("Expected fault string 'Internal error'")
	}
	if fault.Actor != "http://example.com/actor" {
		t.Errorf("Expected fault actor")
	}
	if fault.Detail != "Stack trace here" {
		t.Errorf("Expected fault detail")
	}
}

func TestBuildEnvelope(t *testing.T) {
	client := NewClient("http://example.com/soap", WithNamespace("http://test.com"))
	req := &Request{
		Operation:  "TestOp",
		Namespace:  "http://example.com/ns",
		SOAPHeader: "<auth>token</auth>",
	}

	envelope := client.buildEnvelope(req)
	xml := string(envelope)

	if !strings.Contains(xml, "soap:Envelope") {
		t.Error("Missing soap:Envelope")
	}
	if !strings.Contains(xml, "soap:Body") {
		t.Error("Missing soap:Body")
	}
	if !strings.Contains(xml, "soap:Header") {
		t.Error("Missing soap:Header")
	}
	if !strings.Contains(xml, "<auth>token</auth>") {
		t.Error("Missing SOAP header content")
	}
	if !strings.Contains(xml, "xmlns:ns=\"http://example.com/ns\"") {
		t.Error("Missing namespace declaration")
	}
}

func TestBuildEnvelopeWithBody(t *testing.T) {
	client := NewClient("http://example.com/soap")
	req := &Request{
		Body: "<MyOperation><param>value</param></MyOperation>",
	}

	envelope := client.buildEnvelope(req)
	xml := string(envelope)

	if !strings.Contains(xml, "<MyOperation><param>value</param></MyOperation>") {
		t.Error("Missing body content")
	}
}

func TestCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST method")
		}
		if !strings.Contains(r.Header.Get("Content-Type"), "text/xml") {
			t.Errorf("Expected text/xml content type")
		}
		if r.Header.Get("SOAPAction") != "urn:test" {
			t.Errorf("Expected SOAPAction header")
		}

		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><TestResponse>OK</TestResponse></soap:Body>
</soap:Envelope>`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	req := &Request{
		Action:    "urn:test",
		Operation: "Test",
		Body:      "<Test>data</Test>",
	}

	resp, err := client.Call(req)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if resp.Blocked {
		t.Error("Expected not blocked")
	}
	if resp.Latency == 0 {
		t.Error("Expected non-zero latency")
	}
}

func TestCallBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("Blocked by WAF"))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	req := &Request{
		Body: "<Attack>' OR 1=1--</Attack>",
	}

	resp, err := client.Call(req)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	if !resp.Blocked {
		t.Error("Expected request to be blocked")
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

func TestCallWithFault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(500)
		w.Write([]byte(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<soap:Fault>
<faultcode>soap:Server</faultcode>
<faultstring>Internal server error</faultstring>
</soap:Fault>
</soap:Body>
</soap:Envelope>`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	req := &Request{Operation: "Test"}

	resp, err := client.Call(req)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	if resp.StatusCode != 500 {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}
	// Response should be marked as blocked due to 500 status
	if !resp.Blocked {
		t.Error("Expected blocked for 500 status")
	}
}

func TestParseWSDL(t *testing.T) {
	wsdlContent := []byte(`<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
                  targetNamespace="http://example.com/service">
  <wsdl:message name="GetUserRequest">
    <wsdl:part name="userId" type="xsd:string"/>
  </wsdl:message>
  <wsdl:message name="GetUserResponse">
    <wsdl:part name="user" element="tns:User"/>
  </wsdl:message>
  <wsdl:portType name="UserService">
    <wsdl:operation name="GetUser">
      <wsdl:input message="tns:GetUserRequest"/>
      <wsdl:output message="tns:GetUserResponse"/>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="UserServiceBinding" type="tns:UserService">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="GetUser">
      <soap:operation soapAction="urn:GetUser"/>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="UserService">
    <wsdl:port name="UserServicePort" binding="tns:UserServiceBinding">
      <soap:address location="http://example.com/soap/UserService"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`)

	def, err := ParseWSDL(wsdlContent)
	if err != nil {
		t.Fatalf("ParseWSDL failed: %v", err)
	}

	if def.TargetNamespace != "http://example.com/service" {
		t.Errorf("Expected target namespace 'http://example.com/service', got '%s'", def.TargetNamespace)
	}

	if len(def.Services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(def.Services))
	} else {
		if def.Services[0].Name != "UserService" {
			t.Errorf("Expected service name 'UserService', got '%s'", def.Services[0].Name)
		}
		if len(def.Services[0].Ports) != 1 {
			t.Errorf("Expected 1 port, got %d", len(def.Services[0].Ports))
		} else {
			if def.Services[0].Ports[0].Location != "http://example.com/soap/UserService" {
				t.Errorf("Expected port location, got '%s'", def.Services[0].Ports[0].Location)
			}
		}
	}

	if len(def.Operations) != 2 { // One from portType, one from binding
		t.Logf("Found %d operations", len(def.Operations))
	}

	if len(def.Messages) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(def.Messages))
	}
}

func TestParseWSDLMessages(t *testing.T) {
	wsdlContent := []byte(`<?xml version="1.0"?>
<definitions targetNamespace="http://test.com">
  <message name="TestRequest">
    <part name="param1" type="xsd:string"/>
    <part name="param2" element="tns:Data"/>
  </message>
</definitions>`)

	def, err := ParseWSDL(wsdlContent)
	if err != nil {
		t.Fatalf("ParseWSDL failed: %v", err)
	}

	if len(def.Messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(def.Messages))
	}

	msg := def.Messages[0]
	if msg.Name != "TestRequest" {
		t.Errorf("Expected message name 'TestRequest', got '%s'", msg.Name)
	}
	if len(msg.Parts) != 2 {
		t.Errorf("Expected 2 parts, got %d", len(msg.Parts))
	}
}

func TestParseWSDLComplexTypes(t *testing.T) {
	wsdlContent := []byte(`<?xml version="1.0"?>
<definitions targetNamespace="http://test.com">
  <types>
    <xsd:schema>
      <xsd:complexType name="User">
        <xsd:sequence>
          <xsd:element name="id" type="xsd:int"/>
          <xsd:element name="name" type="xsd:string"/>
        </xsd:sequence>
      </xsd:complexType>
    </xsd:schema>
  </types>
</definitions>`)

	def, err := ParseWSDL(wsdlContent)
	if err != nil {
		t.Fatalf("ParseWSDL failed: %v", err)
	}

	if len(def.Types) != 1 {
		t.Fatalf("Expected 1 type, got %d", len(def.Types))
	}

	typ := def.Types[0]
	if typ.Name != "User" {
		t.Errorf("Expected type name 'User', got '%s'", typ.Name)
	}
	if !typ.IsComplex {
		t.Error("Expected IsComplex to be true")
	}
	if len(typ.Elements) != 2 {
		t.Errorf("Expected 2 elements, got %d", len(typ.Elements))
	}
}

func TestServiceInfo(t *testing.T) {
	svc := ServiceInfo{
		Name:     "TestService",
		Endpoint: "http://example.com/soap",
		Ports: []PortInfo{
			{Name: "TestPort", Binding: "TestBinding", Location: "http://example.com/soap"},
		},
	}

	if svc.Name != "TestService" {
		t.Error("Expected service name")
	}
	if svc.Endpoint != "http://example.com/soap" {
		t.Error("Expected endpoint")
	}
	if len(svc.Ports) != 1 {
		t.Error("Expected 1 port")
	}
}

func TestOperationInfo(t *testing.T) {
	op := OperationInfo{
		Name:          "GetUser",
		Input:         "GetUserRequest",
		Output:        "GetUserResponse",
		SOAPAction:    "urn:GetUser",
		Documentation: "Gets a user by ID",
	}

	if op.Name != "GetUser" {
		t.Error("Expected operation name")
	}
	if op.SOAPAction != "urn:GetUser" {
		t.Error("Expected SOAP action")
	}
}

func TestTypeInfo(t *testing.T) {
	typ := TypeInfo{
		Name:      "User",
		Namespace: "http://example.com/types",
		IsComplex: true,
		Elements: []ElementInfo{
			{Name: "id", Type: "xsd:int", MinOccurs: 1},
			{Name: "name", Type: "xsd:string", MinOccurs: 0, MaxOccurs: "1"},
		},
	}

	if typ.Name != "User" {
		t.Error("Expected type name")
	}
	if !typ.IsComplex {
		t.Error("Expected complex type")
	}
	if len(typ.Elements) != 2 {
		t.Error("Expected 2 elements")
	}
}

func TestNewGenerator(t *testing.T) {
	wsdl := &WSDLDefinition{
		TargetNamespace: "http://test.com",
		Operations: []OperationInfo{
			{Name: "Op1", SOAPAction: "urn:Op1"},
		},
	}

	payloads := []string{"' OR 1=1--", "<script>alert(1)</script>"}

	gen := NewGenerator(wsdl, "http://example.com/soap", payloads)
	if gen == nil {
		t.Fatal("Expected generator")
	}
	if gen.endpoint != "http://example.com/soap" {
		t.Error("Expected endpoint")
	}
	if len(gen.payloads) != 2 {
		t.Error("Expected 2 payloads")
	}
}

func TestGenerate(t *testing.T) {
	wsdl := &WSDLDefinition{
		TargetNamespace: "http://test.com",
		Operations: []OperationInfo{
			{Name: "GetUser", SOAPAction: "urn:GetUser"},
			{Name: "CreateUser", SOAPAction: "urn:CreateUser"},
		},
	}

	payloads := []string{"' OR 1=1--"}

	gen := NewGenerator(wsdl, "http://example.com/soap", payloads)
	testCases := gen.Generate()

	// 2 operations * 1 payload * 3 tests per payload (body, header, xxe) = 6
	if len(testCases) != 6 {
		t.Errorf("Expected 6 test cases, got %d", len(testCases))
	}

	// Check first test case
	if len(testCases) > 0 {
		tc := testCases[0]
		if tc.Operation != "GetUser" {
			t.Errorf("Expected operation 'GetUser', got '%s'", tc.Operation)
		}
		if tc.Request == nil {
			t.Error("Expected request")
		}
		if !tc.ExpectBlock {
			t.Error("Expected ExpectBlock to be true")
		}
	}
}

func TestGenerateForOperation(t *testing.T) {
	wsdl := &WSDLDefinition{
		TargetNamespace: "http://test.com",
		Operations: []OperationInfo{
			{Name: "GetUser", SOAPAction: "urn:GetUser"},
			{Name: "CreateUser", SOAPAction: "urn:CreateUser"},
		},
	}

	payloads := []string{"' OR 1=1--", "<script>"}

	gen := NewGenerator(wsdl, "http://example.com/soap", payloads)
	testCases := gen.GenerateForOperation("GetUser")

	// Only GetUser operation, 2 payloads
	if len(testCases) != 2 {
		t.Errorf("Expected 2 test cases, got %d", len(testCases))
	}

	for _, tc := range testCases {
		if tc.Operation != "GetUser" {
			t.Errorf("Expected operation 'GetUser', got '%s'", tc.Operation)
		}
	}
}

func TestGenerateForOperationNotFound(t *testing.T) {
	wsdl := &WSDLDefinition{
		TargetNamespace: "http://test.com",
		Operations: []OperationInfo{
			{Name: "GetUser", SOAPAction: "urn:GetUser"},
		},
	}

	gen := NewGenerator(wsdl, "http://example.com/soap", []string{"payload"})
	testCases := gen.GenerateForOperation("NonExistent")

	if len(testCases) != 0 {
		t.Errorf("Expected 0 test cases for non-existent operation")
	}
}

func TestTestCase(t *testing.T) {
	tc := TestCase{
		ID:          "soap-001",
		Operation:   "GetUser",
		Description: "SQL injection in GetUser",
		Category:    "sqli",
		Request: &Request{
			Action: "urn:GetUser",
			Body:   "<GetUser><id>' OR 1=1--</id></GetUser>",
		},
		ExpectBlock:  true,
		PayloadField: "id",
	}

	if tc.ID != "soap-001" {
		t.Error("Expected ID")
	}
	if tc.Operation != "GetUser" {
		t.Error("Expected operation")
	}
	if tc.Category != "sqli" {
		t.Error("Expected category")
	}
	if !tc.ExpectBlock {
		t.Error("Expected ExpectBlock")
	}
}

func TestEnvelope(t *testing.T) {
	env := Envelope{
		SoapNS: "http://schemas.xmlsoap.org/soap/envelope/",
		XsiNS:  "http://www.w3.org/2001/XMLSchema-instance",
		XsdNS:  "http://www.w3.org/2001/XMLSchema",
		Header: &Header{Content: []byte("<auth>token</auth>")},
		Body:   Body{Content: []byte("<Test>data</Test>")},
	}

	if env.SoapNS != "http://schemas.xmlsoap.org/soap/envelope/" {
		t.Error("Expected SOAP namespace")
	}
	if env.Header == nil {
		t.Error("Expected header")
	}
	if len(env.Body.Content) == 0 {
		t.Error("Expected body content")
	}
}

func TestFetchWSDLServer(t *testing.T) {
	wsdlContent := `<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
                  targetNamespace="http://test.com">
  <wsdl:service name="TestService">
    <wsdl:port name="TestPort" binding="tns:TestBinding">
      <soap:address location="http://test.com/soap"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(wsdlContent))
	}))
	defer server.Close()

	def, err := FetchWSDL(server.URL)
	if err != nil {
		t.Fatalf("FetchWSDL failed: %v", err)
	}

	if def.TargetNamespace != "http://test.com" {
		t.Error("Expected target namespace")
	}
	if len(def.Services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(def.Services))
	}
}

func TestFetchWSDLError(t *testing.T) {
	_, err := FetchWSDL("http://invalid-url-that-does-not-exist.test/wsdl")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestFetchWSDLBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	_, err := FetchWSDL(server.URL)
	if err == nil {
		t.Error("Expected error for 404 status")
	}
}

func TestGeneratorEmptyPayloads(t *testing.T) {
	wsdl := &WSDLDefinition{
		TargetNamespace: "http://test.com",
		Operations: []OperationInfo{
			{Name: "Op1"},
		},
	}

	gen := NewGenerator(wsdl, "http://example.com/soap", []string{})
	testCases := gen.Generate()

	if len(testCases) != 0 {
		t.Errorf("Expected 0 test cases with empty payloads, got %d", len(testCases))
	}
}

func TestGeneratorEmptyOperations(t *testing.T) {
	wsdl := &WSDLDefinition{
		TargetNamespace: "http://test.com",
		Operations:      []OperationInfo{},
	}

	gen := NewGenerator(wsdl, "http://example.com/soap", []string{"payload"})
	testCases := gen.Generate()

	if len(testCases) != 0 {
		t.Errorf("Expected 0 test cases with empty operations, got %d", len(testCases))
	}
}
