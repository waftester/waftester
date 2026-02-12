// Package upload provides file upload vulnerability testing.
// Tests for unrestricted file uploads, extension bypasses, content-type confusion,
// path traversal in filenames, polyglot files, and malicious content detection.
package upload

import (
	"context"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/bufpool"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/jsonutil"
	"github.com/waftester/waftester/pkg/strutil"
)

// VulnerabilityType represents the type of upload vulnerability.
type VulnerabilityType string

const (
	VulnUnrestrictedUpload VulnerabilityType = "unrestricted-upload"
	VulnExtensionBypass    VulnerabilityType = "extension-bypass"
	VulnContentTypeBypass  VulnerabilityType = "content-type-bypass"
	VulnPathTraversal      VulnerabilityType = "path-traversal"
	VulnPolyglot           VulnerabilityType = "polyglot"
	VulnWebShell           VulnerabilityType = "web-shell"
	VulnSizeBypass         VulnerabilityType = "size-bypass"
	VulnNullByte           VulnerabilityType = "null-byte"
	VulnDoubleExtension    VulnerabilityType = "double-extension"
	VulnMaliciousContent   VulnerabilityType = "malicious-content"
	VulnSVGXSS             VulnerabilityType = "svg-xss"
	VulnXMLXXE             VulnerabilityType = "xml-xxe"
)

// Vulnerability represents a detected upload vulnerability.
type Vulnerability struct {
	finding.Vulnerability
	Type        VulnerabilityType `json:"type"`
	Filename    string            `json:"filename"`
	ContentType string            `json:"content_type,omitempty"`
	FileSize    int               `json:"file_size,omitempty"`
}

// UploadPayload represents a file upload payload.
type UploadPayload struct {
	Filename    string            `json:"filename"`
	Content     []byte            `json:"content"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers,omitempty"`
	Description string            `json:"description"`
	VulnType    VulnerabilityType `json:"vuln_type"`
}

// TesterConfig holds configuration for upload testing.
type TesterConfig struct {
	attackconfig.Base
	FileField      string
	ExtraFields    map[string]string
	AuthHeader     string
	Cookies        map[string]string
	MaxFileSize    int64
	FollowRedirect bool
}

// Tester handles file upload vulnerability testing.
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns default configuration.
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Base: attackconfig.Base{
			Timeout:     duration.HTTPFuzzing,
			UserAgent:   "Upload-Tester/1.0",
			Concurrency: defaults.ConcurrencyLow,
		},
		FileField:      "file",
		ExtraFields:    make(map[string]string),
		Cookies:        make(map[string]string),
		MaxFileSize:    10 * 1024 * 1024,
		FollowRedirect: false,
	}
}

// NewTester creates a new upload tester.
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	return &Tester{
		config: config,
		client: httpclient.Default(),
	}
}

// TestUpload tests a single upload payload.
func (t *Tester) TestUpload(ctx context.Context, targetURL string, payload UploadPayload) (*Vulnerability, error) {
	// Enforce max file size to prevent OOM or excessive bandwidth
	if t.config.MaxFileSize > 0 && int64(len(payload.Content)) > t.config.MaxFileSize {
		return nil, fmt.Errorf("payload %q size %d exceeds max file size %d",
			payload.Filename, len(payload.Content), t.config.MaxFileSize)
	}

	body := bufpool.Get()
	defer bufpool.Put(body)
	writer := multipart.NewWriter(body)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, t.config.FileField, payload.Filename))
	h.Set("Content-Type", payload.ContentType)

	for k, v := range payload.Headers {
		h.Set(k, v)
	}

	part, err := writer.CreatePart(h)
	if err != nil {
		return nil, fmt.Errorf("creating form part: %w", err)
	}

	_, err = part.Write(payload.Content)
	if err != nil {
		return nil, fmt.Errorf("writing file content: %w", err)
	}

	for key, value := range t.config.ExtraFields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, fmt.Errorf("writing field %s: %w", key, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	respBody, _ := iohelper.ReadBodyDefault(resp.Body)

	if t.isUploadSuccessful(resp.StatusCode, string(respBody)) {
		return &Vulnerability{
			Vulnerability: finding.Vulnerability{
				Description: payload.Description,
				Severity:    getSeverity(payload.VulnType),
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Status: %d, Response: %s", resp.StatusCode, strutil.Truncate(string(respBody), 500)),
				Remediation: getRemediation(payload.VulnType),
				CVSS:        getCVSS(payload.VulnType),
			},
			Type:        payload.VulnType,
			Filename:    payload.Filename,
			ContentType: payload.ContentType,
			FileSize:    len(payload.Content),
		}, nil
	}

	return nil, nil
}

// Scan performs comprehensive upload vulnerability scanning.
func (t *Tester) Scan(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	// Quick pre-check: see if target accepts POST at all
	// This prevents wasting time on targets without upload functionality
	preCheckCtx, preCheckCancel := context.WithTimeout(ctx, duration.HTTPProbing)
	defer preCheckCancel()

	req, err := http.NewRequestWithContext(preCheckCtx, "OPTIONS", targetURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", t.config.UserAgent)
		resp, err := t.client.Do(req)
		if err != nil {
			// Target might be down or not responding - skip upload scan
			return nil, nil
		}
		iohelper.DrainAndClose(resp.Body)
		// If target explicitly rejects with 405 Method Not Allowed, skip
		if resp.StatusCode == 405 {
			return nil, nil
		}
	}

	var vulns []Vulnerability
	var mu sync.Mutex
	var wg sync.WaitGroup

	payloads := GetAllPayloads()
	sem := make(chan struct{}, t.config.Concurrency)

payloadLoop:
	for _, payload := range payloads {
		// Check context before spawning goroutine
		select {
		case <-ctx.Done():
			break payloadLoop
		default:
		}

		wg.Add(1)
		go func(p UploadPayload) {
			defer wg.Done()

			// Check context before acquiring semaphore with timeout
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			// Double-check context before making request
			select {
			case <-ctx.Done():
				return
			default:
			}

			vuln, err := t.TestUpload(ctx, targetURL, p)
			if err != nil {
				return
			}

			if vuln != nil {
				mu.Lock()
				vulns = append(vulns, *vuln)
				mu.Unlock()
			}
		}(payload)
	}

	wg.Wait()
	return vulns, nil
}

// GetAllPayloads returns all upload test payloads.
func GetAllPayloads() []UploadPayload {
	var payloads []UploadPayload
	payloads = append(payloads, GetExtensionBypassPayloads()...)
	payloads = append(payloads, GetContentTypeBypassPayloads()...)
	payloads = append(payloads, GetPathTraversalPayloads()...)
	payloads = append(payloads, GetPolyglotPayloads()...)
	payloads = append(payloads, GetWebShellPayloads()...)
	payloads = append(payloads, GetMaliciousContentPayloads()...)
	return payloads
}

// GetExtensionBypassPayloads returns extension bypass payloads.
// Note: Payloads use placeholder markers instead of real code to avoid AV detection.
func GetExtensionBypassPayloads() []UploadPayload {
	// Use base64 encoded placeholder to avoid AV detection
	phpPlaceholder := []byte("PLACEHOLDER_SCRIPT_TAG_MARKER")
	return []UploadPayload{
		{Filename: "test.php.jpg", Content: phpPlaceholder, ContentType: "image/jpeg", Description: "Double extension (.php.jpg)", VulnType: VulnDoubleExtension},
		{Filename: "test.jpg.php", Content: phpPlaceholder, ContentType: "application/octet-stream", Description: "Double extension (.jpg.php)", VulnType: VulnDoubleExtension},
		{Filename: "test.PHP", Content: phpPlaceholder, ContentType: "application/octet-stream", Description: "Case variation (.PHP)", VulnType: VulnExtensionBypass},
		{Filename: "test.phtml", Content: phpPlaceholder, ContentType: "application/octet-stream", Description: "Alternative extension (.phtml)", VulnType: VulnExtensionBypass},
		{Filename: "test.php%00.jpg", Content: phpPlaceholder, ContentType: "image/jpeg", Description: "Null byte injection", VulnType: VulnNullByte},
		{Filename: "test.php.", Content: phpPlaceholder, ContentType: "application/octet-stream", Description: "Trailing dot (.php.)", VulnType: VulnExtensionBypass},
		{Filename: "test.asp", Content: []byte("PLACEHOLDER_ASP_MARKER"), ContentType: "application/octet-stream", Description: "ASP upload", VulnType: VulnWebShell},
		{Filename: "test.jsp", Content: []byte("PLACEHOLDER_JSP_MARKER"), ContentType: "application/octet-stream", Description: "JSP upload", VulnType: VulnWebShell},
	}
}

// GetContentTypeBypassPayloads returns content-type bypass payloads.
func GetContentTypeBypassPayloads() []UploadPayload {
	phpPlaceholder := []byte("PLACEHOLDER_SCRIPT_CONTENT")
	return []UploadPayload{
		{Filename: "test.php", Content: phpPlaceholder, ContentType: "image/jpeg", Description: "Content-Type mismatch (image/jpeg)", VulnType: VulnContentTypeBypass},
		{Filename: "test.php", Content: phpPlaceholder, ContentType: "image/gif", Description: "Content-Type mismatch (image/gif)", VulnType: VulnContentTypeBypass},
		{Filename: "test.php", Content: phpPlaceholder, ContentType: "text/plain", Description: "Content-Type mismatch (text/plain)", VulnType: VulnContentTypeBypass},
		{Filename: "test.php", Content: phpPlaceholder, ContentType: "", Description: "Empty Content-Type", VulnType: VulnContentTypeBypass},
	}
}

// GetPathTraversalPayloads returns path traversal payloads.
func GetPathTraversalPayloads() []UploadPayload {
	content := []byte("traversal test content")
	return []UploadPayload{
		{Filename: "../../../test.txt", Content: content, ContentType: "text/plain", Description: "Path traversal (../)", VulnType: VulnPathTraversal},
		{Filename: "..\\..\\..\\test.txt", Content: content, ContentType: "text/plain", Description: "Path traversal (..\\)", VulnType: VulnPathTraversal},
		{Filename: "..%2F..%2F..%2Ftest.txt", Content: content, ContentType: "text/plain", Description: "Path traversal (URL encoded)", VulnType: VulnPathTraversal},
		{Filename: "/etc/cron.d/test", Content: content, ContentType: "text/plain", Description: "Absolute path", VulnType: VulnPathTraversal},
	}
}

// GetPolyglotPayloads returns polyglot file payloads.
func GetPolyglotPayloads() []UploadPayload {
	// GIF header with placeholder content
	gifPolyglot := append([]byte("GIF89a"), []byte("PLACEHOLDER_POLYGLOT_CONTENT")...)
	jpegPolyglot := createJPEGPolyglot()
	pngPolyglot := createPNGPolyglot()
	return []UploadPayload{
		{Filename: "polyglot.gif", Content: gifPolyglot, ContentType: "image/gif", Description: "GIF polyglot file", VulnType: VulnPolyglot},
		{Filename: "polyglot.jpg", Content: jpegPolyglot, ContentType: "image/jpeg", Description: "JPEG polyglot file", VulnType: VulnPolyglot},
		{Filename: "polyglot.png", Content: pngPolyglot, ContentType: "image/png", Description: "PNG polyglot file", VulnType: VulnPolyglot},
	}
}

// GetWebShellPayloads returns web shell detection payloads.
// Uses markers instead of actual code to avoid antivirus detection.
func GetWebShellPayloads() []UploadPayload {
	return []UploadPayload{
		{Filename: "test.php", Content: []byte("WEBSHELL_MARKER_COMMAND"), ContentType: "application/x-php", Description: "Command execution marker", VulnType: VulnWebShell},
		{Filename: "test.php", Content: []byte("WEBSHELL_MARKER_EVAL"), ContentType: "application/x-php", Description: "Code evaluation marker", VulnType: VulnWebShell},
		{Filename: "test.php", Content: []byte("WEBSHELL_MARKER_SHORT"), ContentType: "application/x-php", Description: "Short tag marker", VulnType: VulnWebShell},
		{Filename: "test.py", Content: []byte("PYTHON_MARKER"), ContentType: "text/x-python", Description: "Python marker", VulnType: VulnWebShell},
		{Filename: "test.js", Content: []byte("NODEJS_MARKER"), ContentType: "application/javascript", Description: "Node.js marker", VulnType: VulnWebShell},
	}
}

// GetMaliciousContentPayloads returns malicious content payloads.
func GetMaliciousContentPayloads() []UploadPayload {
	svgContent := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><text>test</text></svg>`)
	xmlContent := []byte(`<?xml version="1.0"?><root><data>test</data></root>`)
	return []UploadPayload{
		{Filename: "test.svg", Content: svgContent, ContentType: "image/svg+xml", Description: "SVG file upload", VulnType: VulnSVGXSS},
		{Filename: "test.xml", Content: xmlContent, ContentType: defaults.ContentTypeXML, Description: "XML file upload", VulnType: VulnXMLXXE},
		{Filename: ".htaccess", Content: []byte("# htaccess test"), ContentType: "text/plain", Description: ".htaccess upload", VulnType: VulnMaliciousContent},
	}
}

func (t *Tester) applyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", t.config.UserAgent)
	if t.config.AuthHeader != "" {
		req.Header.Set("Authorization", t.config.AuthHeader)
	}
	for name, value := range t.config.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
}

func (t *Tester) isUploadSuccessful(statusCode int, body string) bool {
	if statusCode >= 200 && statusCode < 300 {
		successIndicators := []string{"success", "uploaded", "complete", "file_url", "location", "path", "url"}
		lowerBody := strings.ToLower(body)
		for _, ind := range successIndicators {
			if strings.Contains(lowerBody, ind) {
				return true
			}
		}
		return true
	}
	if statusCode == 301 || statusCode == 302 || statusCode == 303 {
		return true
	}
	return false
}

func getSeverity(vt VulnerabilityType) finding.Severity {
	switch vt {
	case VulnWebShell, VulnUnrestrictedUpload:
		return finding.Critical
	case VulnPathTraversal, VulnPolyglot, VulnXMLXXE:
		return finding.High
	case VulnExtensionBypass, VulnContentTypeBypass, VulnDoubleExtension, VulnNullByte, VulnSVGXSS:
		return finding.High
	case VulnMaliciousContent, VulnSizeBypass:
		return finding.Medium
	default:
		return finding.Medium
	}
}

func getCVSS(vt VulnerabilityType) float64 {
	switch vt {
	case VulnWebShell, VulnUnrestrictedUpload:
		return 9.8
	case VulnPathTraversal:
		return 8.6
	case VulnPolyglot, VulnExtensionBypass, VulnContentTypeBypass:
		return 8.1
	case VulnXMLXXE:
		return 7.5
	case VulnSVGXSS, VulnMaliciousContent:
		return 6.1
	default:
		return 5.0
	}
}

func getRemediation(vt VulnerabilityType) string {
	remediations := map[VulnerabilityType]string{
		VulnUnrestrictedUpload: "Implement strict file type validation",
		VulnExtensionBypass:    "Validate file extensions server-side, use allowlists",
		VulnContentTypeBypass:  "Validate file content/magic bytes",
		VulnPathTraversal:      "Sanitize filenames, use random generated names",
		VulnPolyglot:           "Validate file content matches declared type",
		VulnWebShell:           "Block executable extensions, scan uploaded content",
		VulnNullByte:           "Strip null bytes from filenames",
		VulnDoubleExtension:    "Check all extensions in filename",
		VulnMaliciousContent:   "Sanitize uploaded content",
		VulnSVGXSS:             "Sanitize SVG files",
		VulnXMLXXE:             "Disable external entity processing",
		VulnSizeBypass:         "Implement server-side file size limits",
	}
	if r, ok := remediations[vt]; ok {
		return r
	}
	return "Implement comprehensive file upload validation"
}



func createJPEGPolyglot() []byte {
	// JPEG header bytes
	jpegHeader := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00}
	placeholder := []byte("POLYGLOT_CONTENT_MARKER")
	jpegFooter := []byte{0xFF, 0xD9}
	result := make([]byte, 0, len(jpegHeader)+len(placeholder)+len(jpegFooter))
	result = append(result, jpegHeader...)
	result = append(result, placeholder...)
	result = append(result, jpegFooter...)
	return result
}

func createPNGPolyglot() []byte {
	// PNG signature
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	placeholder := []byte("POLYGLOT_CONTENT_MARKER")
	result := make([]byte, 0, len(pngHeader)+len(placeholder))
	result = append(result, pngHeader...)
	result = append(result, placeholder...)
	return result
}

// AllVulnerabilityTypes returns all upload vulnerability types.
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnUnrestrictedUpload, VulnExtensionBypass, VulnContentTypeBypass,
		VulnPathTraversal, VulnPolyglot, VulnWebShell, VulnSizeBypass,
		VulnNullByte, VulnDoubleExtension, VulnMaliciousContent,
		VulnSVGXSS, VulnXMLXXE,
	}
}

// VulnerabilityToJSON converts a vulnerability to JSON.
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := jsonutil.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GenerateReport generates a scan report.
func GenerateReport(vulns []Vulnerability) map[string]interface{} {
	report := map[string]interface{}{
		"total_vulnerabilities": len(vulns),
		"by_severity":           make(map[string]int),
		"by_type":               make(map[string]int),
		"vulnerabilities":       vulns,
	}
	for _, v := range vulns {
		report["by_severity"].(map[string]int)[string(v.Severity)]++
		report["by_type"].(map[string]int)[string(v.Type)]++
	}
	return report
}

// GenerateTestFile generates a test file with specified extension.
func GenerateTestFile(extension string, malicious bool) UploadPayload {
	var content []byte
	var contentType string
	var vulnType VulnerabilityType

	switch extension {
	case "php":
		content = []byte("SCRIPT_PLACEHOLDER_MARKER")
		vulnType = VulnUnrestrictedUpload
		if malicious {
			vulnType = VulnWebShell
		}
		contentType = "application/x-php"
	case "jpg", "jpeg":
		content = []byte{0xFF, 0xD8, 0xFF, 0xE0}
		contentType = "image/jpeg"
		vulnType = VulnUnrestrictedUpload
	case "png":
		content = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
		contentType = "image/png"
		vulnType = VulnUnrestrictedUpload
	case "gif":
		content = []byte("GIF89a")
		contentType = "image/gif"
		vulnType = VulnUnrestrictedUpload
	default:
		content = []byte("test content data")
		contentType = "application/octet-stream"
		vulnType = VulnUnrestrictedUpload
	}

	return UploadPayload{
		Filename:    "test." + extension,
		Content:     content,
		ContentType: contentType,
		Description: fmt.Sprintf("Test %s file", extension),
		VulnType:    vulnType,
	}
}

// IsExecutableExtension checks if extension is executable.
func IsExecutableExtension(ext string) bool {
	executable := map[string]bool{
		"php": true, "php3": true, "php4": true, "php5": true, "phtml": true, "phar": true,
		"asp": true, "aspx": true, "ashx": true, "asmx": true,
		"jsp": true, "jspx": true, "cfm": true, "cfc": true,
		"pl": true, "cgi": true, "py": true, "rb": true,
		"sh": true, "bash": true, "exe": true, "dll": true, "bat": true, "cmd": true,
	}
	return executable[strings.ToLower(ext)]
}

// ExtractExtension extracts the file extension from a filename.
func ExtractExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

// Base64Encode encodes bytes to base64.
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// GetMIMEType returns the MIME type for a file extension.
func GetMIMEType(ext string) string {
	mimeTypes := map[string]string{
		"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
		"gif": "image/gif", "svg": "image/svg+xml", "pdf": "application/pdf",
		"txt": "text/plain", "html": "text/html", "xml": "application/xml",
		"json": "application/json", "php": "application/x-php", "js": "application/javascript",
	}
	if mime, ok := mimeTypes[strings.ToLower(ext)]; ok {
		return mime
	}
	return "application/octet-stream"
}

// IsMagicBytesValid checks if file content matches expected magic bytes.
func IsMagicBytesValid(content []byte, expectedType string) bool {
	if len(content) < 4 {
		return false
	}
	magicBytes := map[string][]byte{
		"jpeg": {0xFF, 0xD8, 0xFF}, "jpg": {0xFF, 0xD8, 0xFF},
		"png": {0x89, 0x50, 0x4E, 0x47}, "gif": {0x47, 0x49, 0x46, 0x38},
		"pdf": {0x25, 0x50, 0x44, 0x46}, "zip": {0x50, 0x4B, 0x03, 0x04},
	}
	expected, ok := magicBytes[strings.ToLower(expectedType)]
	if !ok {
		return false
	}
	if len(content) < len(expected) {
		return false
	}
	for i, b := range expected {
		if content[i] != b {
			return false
		}
	}
	return true
}

// Pre-compiled patterns for executable code detection (avoid per-call regexp.MustCompile).
var executableCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`<\?[a-z]`),            // Script tag pattern
	regexp.MustCompile(`<%[=\s]`),             // ASP tag pattern
	regexp.MustCompile(`function\s+\w+\s*\(`), // Function definition
	regexp.MustCompile(`\bimport\s+\w`),       // Import statement
	regexp.MustCompile(`require\s*\(`),        // Require call
	regexp.MustCompile(`WEBSHELL_MARKER`),     // Our test markers
	regexp.MustCompile(`PLACEHOLDER_SCRIPT`),  // Our test markers
}

// ContainsExecutableCode checks if content contains executable code patterns.
func ContainsExecutableCode(content []byte) bool {
	contentStr := string(content)
	for _, p := range executableCodePatterns {
		if p.MatchString(contentStr) {
			return true
		}
	}
	return false
}
