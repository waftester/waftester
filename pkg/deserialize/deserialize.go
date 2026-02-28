// Package deserialize provides insecure deserialization vulnerability testing.
// Tests for Java, PHP, Python, Ruby, and .NET deserialization attacks.
package deserialize

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/strutil"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of deserialization vulnerability.
type VulnerabilityType string

const (
	VulnJavaDeserial   VulnerabilityType = "java-deserialization"
	VulnPHPDeserial    VulnerabilityType = "php-deserialization"
	VulnPythonDeserial VulnerabilityType = "python-deserialization"
	VulnRubyDeserial   VulnerabilityType = "ruby-deserialization"
	VulnDotNetDeserial VulnerabilityType = "dotnet-deserialization"
	VulnNodeDeserial   VulnerabilityType = "node-deserialization"
	VulnYAMLDeserial   VulnerabilityType = "yaml-deserialization"
	VulnXMLDeserial    VulnerabilityType = "xml-deserialization"
	VulnJSONDeserial   VulnerabilityType = "json-deserialization"
)

// Vulnerability represents a detected deserialization vulnerability.
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    finding.Severity  `json:"severity"`
	URL         string            `json:"url"`
	Parameter   string            `json:"parameter,omitempty"`
	Payload     string            `json:"payload,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	GadgetChain string            `json:"gadget_chain,omitempty"`
	ConfirmedBy int               `json:"confirmed_by,omitempty"`
}

// Payload represents a deserialization test payload.
type Payload struct {
	Name        string            `json:"name"`
	Data        string            `json:"data"`
	Encoded     bool              `json:"encoded"`
	ContentType string            `json:"content_type"`
	VulnType    VulnerabilityType `json:"vuln_type"`
	Description string            `json:"description"`
	GadgetChain string            `json:"gadget_chain,omitempty"`
}

// TesterConfig holds configuration for deserialization testing.
type TesterConfig struct {
	attackconfig.Base
	Parameters     []string
	AuthHeader     string
	Cookies        map[string]string
	CallbackURL    string
	FollowRedirect bool
}

// Tester handles deserialization vulnerability testing.
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns default configuration.
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Base: attackconfig.Base{
			Timeout:     duration.HTTPFuzzing,
			UserAgent:   ui.UserAgentWithContext("Deserialize Tester"),
			Concurrency: defaults.ConcurrencyLow,
		},
		Parameters:     []string{"data", "object", "session", "token", "state", "viewstate"},
		Cookies:        make(map[string]string),
		FollowRedirect: false,
	}
}

// NewTester creates a new deserialization tester.
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	return &Tester{
		config: config,
		client: client,
	}
}

// TestPayload tests a single deserialization payload.
func (t *Tester) TestPayload(ctx context.Context, targetURL string, param string, payload Payload) (*Vulnerability, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	// Add payload to query parameter
	query := parsedURL.Query()
	payloadData := payload.Data
	if payload.Encoded {
		payloadData = base64.StdEncoding.EncodeToString([]byte(payload.Data))
	}
	query.Set(param, payloadData)
	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	bodyStr := string(body)

	// Check for deserialization indicators
	if t.isVulnerable(resp.StatusCode, bodyStr, payload.VulnType) {
		t.config.NotifyVulnerabilityFound()
		return &Vulnerability{
			Type:        payload.VulnType,
			Description: payload.Description,
			Severity:    finding.Critical,
			URL:         targetURL,
			Parameter:   param,
			Payload:     strutil.Truncate(payloadData, 200),
			Evidence:    fmt.Sprintf("Status: %d, Body contains deserialization indicators", resp.StatusCode),
			Remediation: getRemediation(payload.VulnType),
			CVSS:        9.8,
			GadgetChain: payload.GadgetChain,
		}, nil
	}

	return nil, nil
}

// TestPOST tests deserialization via POST body.
func (t *Tester) TestPOST(ctx context.Context, targetURL string, payload Payload) (*Vulnerability, error) {
	payloadData := payload.Data
	if payload.Encoded {
		payloadData = base64.StdEncoding.EncodeToString([]byte(payload.Data))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewBufferString(payloadData))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", payload.ContentType)
	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	bodyStr := string(body)

	if t.isVulnerable(resp.StatusCode, bodyStr, payload.VulnType) {
		t.config.NotifyVulnerabilityFound()
		return &Vulnerability{
			Type:        payload.VulnType,
			Description: payload.Description,
			Severity:    finding.Critical,
			URL:         targetURL,
			Payload:     strutil.Truncate(payloadData, 200),
			Evidence:    fmt.Sprintf("Status: %d, Response indicates deserialization", resp.StatusCode),
			Remediation: getRemediation(payload.VulnType),
			CVSS:        9.8,
			GadgetChain: payload.GadgetChain,
		}, nil
	}

	return nil, nil
}

// Scan performs comprehensive deserialization vulnerability scanning.
func (t *Tester) Scan(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error

	payloads := GetAllPayloads()
	sem := make(chan struct{}, t.config.Concurrency)

	for _, payload := range payloads {
		for _, param := range t.config.Parameters {
			wg.Add(1)
			go func(p Payload, par string) {
				defer wg.Done()

				// Check context before acquiring semaphore to avoid goroutine leak
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()

				vuln, err := t.TestPayload(ctx, targetURL, par, p)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}

				if vuln != nil {
					mu.Lock()
					vulns = append(vulns, *vuln)
					mu.Unlock()
				}
			}(payload, param)
		}
	}

	wg.Wait()
	return vulns, firstErr
}

// GetAllPayloads returns all deserialization test payloads.
func GetAllPayloads() []Payload {
	var payloads []Payload
	payloads = append(payloads, GetJavaPayloads()...)
	payloads = append(payloads, GetPHPPayloads()...)
	payloads = append(payloads, GetPythonPayloads()...)
	payloads = append(payloads, GetRubyPayloads()...)
	payloads = append(payloads, GetDotNetPayloads()...)
	payloads = append(payloads, GetNodePayloads()...)
	payloads = append(payloads, GetYAMLPayloads()...)
	return payloads
}

// GetJavaPayloads returns Java deserialization payloads.
// Uses markers instead of actual gadget chains for safety.
func GetJavaPayloads() []Payload {
	return []Payload{
		{
			Name:        "java-commons-collections",
			Data:        "JAVA_DESER_MARKER_CC",
			Encoded:     true,
			ContentType: "application/x-java-serialized-object",
			VulnType:    VulnJavaDeserial,
			Description: "Java Commons Collections gadget chain",
			GadgetChain: "CommonsCollections1",
		},
		{
			Name:        "java-spring",
			Data:        "JAVA_DESER_MARKER_SPRING",
			Encoded:     true,
			ContentType: "application/x-java-serialized-object",
			VulnType:    VulnJavaDeserial,
			Description: "Java Spring Framework gadget chain",
			GadgetChain: "Spring1",
		},
		{
			Name:        "java-hibernate",
			Data:        "JAVA_DESER_MARKER_HIBERNATE",
			Encoded:     true,
			ContentType: "application/x-java-serialized-object",
			VulnType:    VulnJavaDeserial,
			Description: "Java Hibernate gadget chain",
			GadgetChain: "Hibernate1",
		},
	}
}

// GetPHPPayloads returns PHP deserialization payloads.
func GetPHPPayloads() []Payload {
	return []Payload{
		{
			Name:        "php-object-injection",
			Data:        "PHP_DESER_MARKER_OBJ",
			Encoded:     true,
			ContentType: "application/x-php-serialized",
			VulnType:    VulnPHPDeserial,
			Description: "PHP object injection",
		},
		{
			Name:        "php-phar",
			Data:        "PHP_DESER_MARKER_PHAR",
			Encoded:     true,
			ContentType: "application/x-php-serialized",
			VulnType:    VulnPHPDeserial,
			Description: "PHP PHAR deserialization",
		},
	}
}

// GetPythonPayloads returns Python deserialization payloads.
func GetPythonPayloads() []Payload {
	return []Payload{
		{
			Name:        "python-pickle",
			Data:        "PYTHON_DESER_MARKER_PICKLE",
			Encoded:     true,
			ContentType: "application/python-pickle",
			VulnType:    VulnPythonDeserial,
			Description: "Python pickle deserialization",
		},
		{
			Name:        "python-yaml",
			Data:        "PYTHON_DESER_MARKER_YAML",
			Encoded:     true,
			ContentType: "text/yaml",
			VulnType:    VulnPythonDeserial,
			Description: "Python YAML unsafe load",
		},
	}
}

// GetRubyPayloads returns Ruby deserialization payloads.
func GetRubyPayloads() []Payload {
	return []Payload{
		{
			Name:        "ruby-marshal",
			Data:        "RUBY_DESER_MARKER_MARSHAL",
			Encoded:     true,
			ContentType: "application/x-ruby-marshal",
			VulnType:    VulnRubyDeserial,
			Description: "Ruby Marshal deserialization",
		},
		{
			Name:        "ruby-erb",
			Data:        "RUBY_DESER_MARKER_ERB",
			Encoded:     true,
			ContentType: "application/x-ruby-marshal",
			VulnType:    VulnRubyDeserial,
			Description: "Ruby ERB template injection via deserialization",
		},
	}
}

// GetDotNetPayloads returns .NET deserialization payloads.
func GetDotNetPayloads() []Payload {
	return []Payload{
		{
			Name:        "dotnet-viewstate",
			Data:        "DOTNET_DESER_MARKER_VIEWSTATE",
			Encoded:     true,
			ContentType: defaults.ContentTypeForm,
			VulnType:    VulnDotNetDeserial,
			Description: ".NET ViewState deserialization",
		},
		{
			Name:        "dotnet-binaryformatter",
			Data:        "DOTNET_DESER_MARKER_BINARY",
			Encoded:     true,
			ContentType: "application/octet-stream",
			VulnType:    VulnDotNetDeserial,
			Description: ".NET BinaryFormatter deserialization",
		},
		{
			Name:        "dotnet-json",
			Data:        "DOTNET_DESER_MARKER_JSON",
			Encoded:     true,
			ContentType: defaults.ContentTypeJSON,
			VulnType:    VulnDotNetDeserial,
			Description: ".NET JSON.NET TypeNameHandling",
		},
	}
}

// GetNodePayloads returns Node.js deserialization payloads.
func GetNodePayloads() []Payload {
	return []Payload{
		{
			Name:        "node-serialize",
			Data:        "NODE_DESER_MARKER_SERIALIZE",
			Encoded:     true,
			ContentType: defaults.ContentTypeJSON,
			VulnType:    VulnNodeDeserial,
			Description: "Node.js node-serialize IIFE",
		},
		{
			Name:        "node-funcster",
			Data:        "NODE_DESER_MARKER_FUNCSTER",
			Encoded:     true,
			ContentType: defaults.ContentTypeJSON,
			VulnType:    VulnNodeDeserial,
			Description: "Node.js funcster deserialization",
		},
	}
}

// GetYAMLPayloads returns YAML deserialization payloads.
func GetYAMLPayloads() []Payload {
	return []Payload{
		{
			Name:        "yaml-python-exec",
			Data:        "YAML_DESER_MARKER_PYTHON",
			Encoded:     false,
			ContentType: "text/yaml",
			VulnType:    VulnYAMLDeserial,
			Description: "YAML Python code execution",
		},
		{
			Name:        "yaml-ruby-exec",
			Data:        "YAML_DESER_MARKER_RUBY",
			Encoded:     false,
			ContentType: "text/yaml",
			VulnType:    VulnYAMLDeserial,
			Description: "YAML Ruby code execution",
		},
	}
}

func (t *Tester) applyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", t.config.UserAgent)
	if t.config.AuthHeader != "" {
		req.Header.Set("Authorization", t.config.AuthHeader)
	}
	cookieNames := make([]string, 0, len(t.config.Cookies))
	for name := range t.config.Cookies {
		cookieNames = append(cookieNames, name)
	}
	sort.Strings(cookieNames)
	for _, name := range cookieNames {
		req.AddCookie(&http.Cookie{Name: name, Value: t.config.Cookies[name]})
	}
}

func (t *Tester) isVulnerable(statusCode int, body string, vulnType VulnerabilityType) bool {
	// Check for error patterns indicating deserialization
	errorPatterns := []string{
		"serialization", "unserialize", "deserialize",
		"ClassNotFoundException", "InvalidClassException",
		"StreamCorruptedException", "ObjectInputStream",
		"__wakeup", "__destruct", "__toString",
		"pickle", "marshal", "yaml.load",
		"ViewState", "BinaryFormatter", "TypeNameHandling",
	}

	lowerBody := strings.ToLower(body)
	for _, pattern := range errorPatterns {
		if strings.Contains(lowerBody, strings.ToLower(pattern)) {
			return true
		}
	}

	// Server error with deserialization-specific stack trace indicators.
	// Generic "Exception"/"Error" alone is too broad — require at least one
	// deserialization-related class or keyword alongside the error.
	if statusCode >= 500 {
		deserialKeywords := []string{
			"ObjectInputStream", "BinaryFormatter", "unserialize",
			"pickle", "marshal", "yaml.load", "Deserialize",
			"SerializationException", "ClassNotFound", "InvalidClass",
			"StreamCorrupted", "TypeNameHandling", "JsonSerializationException",
		}
		for _, kw := range deserialKeywords {
			if strings.Contains(body, kw) {
				return true
			}
		}
	}

	return false
}

func getRemediation(vt VulnerabilityType) string {
	remediations := map[VulnerabilityType]string{
		VulnJavaDeserial:   "Use look-ahead deserialization, implement SerializationFilters",
		VulnPHPDeserial:    "Avoid unserialize() on untrusted data, use JSON instead",
		VulnPythonDeserial: "Use yaml.safe_load(), avoid pickle for untrusted data",
		VulnRubyDeserial:   "Use JSON.parse(), avoid Marshal.load on untrusted data",
		VulnDotNetDeserial: "Use TypeNameHandling.None, avoid BinaryFormatter",
		VulnNodeDeserial:   "Avoid node-serialize, use JSON.parse()",
		VulnYAMLDeserial:   "Use safe YAML loaders",
		VulnXMLDeserial:    "Disable external entity processing",
		VulnJSONDeserial:   "Validate JSON schema, avoid type handling",
	}
	if r, ok := remediations[vt]; ok {
		return r
	}
	return "Avoid deserializing untrusted data"
}

// AllVulnerabilityTypes returns all deserialization vulnerability types.
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnJavaDeserial, VulnPHPDeserial, VulnPythonDeserial,
		VulnRubyDeserial, VulnDotNetDeserial, VulnNodeDeserial,
		VulnYAMLDeserial, VulnXMLDeserial, VulnJSONDeserial,
	}
}

// VulnerabilityToJSON converts a vulnerability to JSON.
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GenerateReport generates a scan report.
func GenerateReport(vulns []Vulnerability) map[string]interface{} {
	byType := make(map[string]int)
	for _, v := range vulns {
		byType[string(v.Type)]++
	}
	return map[string]interface{}{
		"total_vulnerabilities": len(vulns),
		"by_type":               byType,
		"vulnerabilities":       vulns,
	}
}

// DetectSerializationFormat attempts to identify the serialization format.
func DetectSerializationFormat(data []byte) VulnerabilityType {
	// Check for Java serialization magic bytes
	if len(data) >= 2 && data[0] == 0xAC && data[1] == 0xED {
		return VulnJavaDeserial
	}

	// Check for PHP serialized object
	dataStr := string(data)
	phpPattern := regexcache.MustGet(`^[aOCNRsbidr]:\d+`)
	if phpPattern.MatchString(dataStr) {
		return VulnPHPDeserial
	}

	// Check for Python pickle
	if len(data) >= 2 && (data[0] == 0x80 || (data[0] == ']' && data[1] == 'q')) {
		return VulnPythonDeserial
	}

	// Check for Ruby Marshal
	if len(data) >= 2 && data[0] == 0x04 && data[1] == 0x08 {
		return VulnRubyDeserial
	}

	// Check for .NET BinaryFormatter
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x00 {
		return VulnDotNetDeserial
	}

	// Check for YAML indicators
	if strings.HasPrefix(dataStr, "---") || strings.Contains(dataStr, "!!python") || strings.Contains(dataStr, "!!ruby") {
		return VulnYAMLDeserial
	}

	return ""
}

// IsBase64Encoded checks if a string appears to be base64 encoded.
func IsBase64Encoded(s string) bool {
	if len(s) < 4 || len(s)%4 != 0 {
		return false
	}
	base64Pattern := regexcache.MustGet(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

// DecodeBase64 safely decodes base64 data.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeBase64 encodes data to base64.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// GetGadgetChains returns known gadget chains for a vulnerability type.
func GetGadgetChains(vt VulnerabilityType) []string {
	chains := map[VulnerabilityType][]string{
		VulnJavaDeserial: {
			"CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
			"CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
			"CommonsCollections7", "Spring1", "Spring2", "Hibernate1", "Hibernate2",
			"JRMPClient", "JRMPListener", "URLDNS", "Groovy1", "BeanShell1",
		},
		VulnDotNetDeserial: {
			"ObjectDataProvider", "TypeConfuseDelegate", "PSObject",
			"TextFormattingRunProperties", "WindowsIdentity", "ClaimsIdentity",
		},
		VulnPHPDeserial: {
			"Monolog/RCE1", "Monolog/RCE2", "Guzzle/FW1", "Guzzle/RCE1",
			"SwiftMailer/FW1", "Laravel/RCE1", "Laravel/RCE2",
		},
	}
	if c, ok := chains[vt]; ok {
		return c
	}
	return nil
}
