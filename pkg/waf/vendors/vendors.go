// Package vendors provides comprehensive WAF detection and bypass recommendations.
// Now supports 180+ WAF vendors ported from wafw00f with auto-tuning capabilities.
package vendors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// WAFVendor represents a detected WAF vendor
type WAFVendor string

const (
	VendorUnknown     WAFVendor = "unknown"
	VendorCloudflare  WAFVendor = "cloudflare"
	VendorAWSWAF      WAFVendor = "aws_waf"
	VendorAzureWAF    WAFVendor = "azure_waf"
	VendorAkamai      WAFVendor = "akamai"
	VendorModSecurity WAFVendor = "modsecurity"
	VendorImperva     WAFVendor = "imperva"
	VendorF5BigIP     WAFVendor = "f5_bigip"
	VendorFortinet    WAFVendor = "fortinet"
	VendorBarracuda   WAFVendor = "barracuda"
	VendorSucuri      WAFVendor = "sucuri"
	VendorWordfence   WAFVendor = "wordfence"
	VendorFastly      WAFVendor = "fastly"
	VendorCloudArmor  WAFVendor = "google_cloud_armor"
)

// DetectionResult contains WAF detection results with bypass hints
type DetectionResult struct {
	Detected            bool            `json:"detected"`
	Vendor              WAFVendor       `json:"vendor"`
	VendorName          string          `json:"vendor_name"`
	Confidence          float64         `json:"confidence"`
	Evidence            []string        `json:"evidence"`
	BypassHints         []string        `json:"bypass_hints"`
	RecommendedEncoders []string        `json:"recommended_encoders"`
	RecommendedEvasions []string        `json:"recommended_evasions"`
	RateLimits          *RateLimitInfo  `json:"rate_limits,omitempty"`
	BlockSignature      *BlockSignature `json:"block_signature,omitempty"`
}

// RateLimitInfo contains rate limiting information
type RateLimitInfo struct {
	Detected      bool   `json:"detected"`
	RequestsLimit int    `json:"requests_limit,omitempty"`
	WindowSeconds int    `json:"window_seconds,omitempty"`
	RetryAfter    int    `json:"retry_after,omitempty"`
	Description   string `json:"description,omitempty"`
}

// BlockSignature contains WAF block page characteristics
type BlockSignature struct {
	StatusCode      int      `json:"status_code"`
	ContentPatterns []string `json:"content_patterns"`
	Headers         []string `json:"headers"`
}

// VendorDetector detects specific WAF vendors
type VendorDetector struct {
	client  *http.Client
	timeout time.Duration
}

// NewVendorDetector creates a new vendor detector
func NewVendorDetector(timeout time.Duration) *VendorDetector {
	return NewVendorDetectorWithClient(timeout, nil)
}

// NewVendorDetectorWithClient creates a new vendor detector with optional custom HTTP client
func NewVendorDetectorWithClient(timeout time.Duration, httpClient *http.Client) *VendorDetector {
	if timeout == 0 {
		timeout = httpclient.TimeoutProbing
	}

	var client *http.Client
	if httpClient != nil {
		client = httpClient
	} else {
		// Use shared HTTP client pool for connection reuse and better performance
		client = httpclient.New(httpclient.Config{
			Timeout:            timeout,
			InsecureSkipVerify: true,
		})
	}

	return &VendorDetector{
		client:  client,
		timeout: timeout,
	}
}

// Detect performs comprehensive WAF vendor detection using 150+ signatures
func (d *VendorDetector) Detect(ctx context.Context, target string) (*DetectionResult, error) {
	result := &DetectionResult{
		Detected: false,
		Vendor:   VendorUnknown,
		Evidence: make([]string, 0),
	}

	// Phase 1: Passive detection from normal request
	resp, body, err := d.makeRequest(ctx, target, "GET", nil) //nolint:bodyclose // body is closed in makeRequest
	if err != nil {
		return nil, err
	}

	// Get all signatures sorted by priority
	signatures := GetAllSignatures()
	sort.Slice(signatures, func(i, j int) bool {
		return signatures[i].Priority > signatures[j].Priority
	})

	// Check each signature
	bestConfidence := 0.0
	var bestSignature *WAFSignature

	for i := range signatures {
		sig := &signatures[i]
		confidence, evidence := d.checkSignature(sig, resp, body, false)
		if confidence > bestConfidence {
			bestConfidence = confidence
			bestSignature = sig
			result.Evidence = evidence
		}
	}

	// Phase 2: Active detection with attack payload (triggers WAF blocks)
	attackResp, attackBody, err := d.makeAttackRequest(ctx, target) //nolint:bodyclose // body is closed in makeAttackRequest
	if err == nil && attackResp != nil {
		// Re-check signatures against attack response (higher confidence)
		for i := range signatures {
			sig := &signatures[i]
			confidence, evidence := d.checkSignature(sig, attackResp, attackBody, true)
			// Attack-triggered detection is more reliable
			confidence *= 1.3
			if confidence > bestConfidence {
				bestConfidence = confidence
				bestSignature = sig
				result.Evidence = evidence
			}
		}

		// Check block signature
		if attackResp.StatusCode == 403 || attackResp.StatusCode == 406 ||
			attackResp.StatusCode == 418 || attackResp.StatusCode == 429 || attackResp.StatusCode == 503 {
			result.BlockSignature = &BlockSignature{
				StatusCode:      attackResp.StatusCode,
				ContentPatterns: extractBlockPatterns(attackBody),
				Headers:         extractSignificantHeaders(attackResp),
			}
		}
	}

	if bestConfidence > 0.3 && bestSignature != nil {
		result.Detected = true
		result.Vendor = bestSignature.ID
		result.Confidence = minFloat(bestConfidence, 1.0)
		result.VendorName = bestSignature.Name

		// Add bypass hints and recommendations from signature
		result.BypassHints = bestSignature.BypassTips
		result.RecommendedEncoders = bestSignature.Encoders
		result.RecommendedEvasions = bestSignature.Evasions

		// Merge with dynamic hints from getBypassHints
		dynamicHints := getBypassHints(bestSignature.ID)
		if dynamicHints.RateLimits != nil {
			result.RateLimits = dynamicHints.RateLimits
		}
	}

	return result, nil
}

// checkSignature checks if a response matches a WAF signature
func (d *VendorDetector) checkSignature(sig *WAFSignature, resp *http.Response, body string, isAttack bool) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Check header patterns
	headers := sig.HeaderPatterns
	if isAttack && len(sig.AttackHeaders) > 0 {
		headers = sig.AttackHeaders
	}

	for headerName, pattern := range headers {
		value := resp.Header.Get(headerName)
		if value != "" && pattern.MatchString(value) {
			confidence += 0.3
			evidence = append(evidence, fmt.Sprintf("Header %s matches pattern", headerName))
		}
	}

	// Check cookie patterns
	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		for _, pattern := range sig.CookiePatterns {
			if pattern.MatchString(cookie) {
				confidence += 0.25
				evidence = append(evidence, "Cookie pattern matched")
				break
			}
		}
	}

	// Check body patterns (only for attack responses or if no attack headers)
	// Copy to a new slice to avoid corrupting the shared BodyPatterns backing array.
	patterns := sig.BodyPatterns
	if isAttack && len(sig.BlockPatterns) > 0 {
		combined := make([]*regexp.Regexp, 0, len(sig.BodyPatterns)+len(sig.BlockPatterns))
		combined = append(combined, sig.BodyPatterns...)
		combined = append(combined, sig.BlockPatterns...)
		patterns = combined
	}

	for _, pattern := range patterns {
		if pattern.MatchString(body) {
			confidence += 0.25
			evidence = append(evidence, fmt.Sprintf("Body matches: %s", pattern.String()[:min(30, len(pattern.String()))]))
		}
	}

	// Check status codes
	for _, code := range sig.StatusCodes {
		if resp.StatusCode == code {
			confidence += 0.2
			evidence = append(evidence, fmt.Sprintf("Status code %d matches", code))
		}
	}

	// Check reason phrases (if available in response)
	for _, phrase := range sig.ReasonPhrases {
		if strings.Contains(resp.Status, phrase) {
			confidence += 0.3
			evidence = append(evidence, fmt.Sprintf("Reason phrase: %s", phrase))
		}
	}

	// Reliable signatures get a boost
	if sig.Reliable && confidence > 0 {
		confidence *= 1.2
	}

	return minFloat(confidence, 1.0), evidence
}

// makeAttackRequest sends a combined attack payload to trigger WAF
func (d *VendorDetector) makeAttackRequest(ctx context.Context, target string) (*http.Response, string, error) {
	// Combined XSS + SQLi + LFI payload (wafw00f style)
	attackPayload := "?id=1'%20OR%20'1'%3D'1&test=<script>alert(1)</script>&file=../../../etc/passwd"
	return d.makeRequest(ctx, target+attackPayload, "GET", nil)
}

func (d *VendorDetector) makeRequest(ctx context.Context, url, method string, headers map[string]string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBody(resp.Body, 32768)
	return resp, string(body), nil
}

// =====================================================================
// VENDOR-SPECIFIC DETECTORS
// =====================================================================

func (d *VendorDetector) detectCloudflare(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Header detection
	if v := resp.Header.Get("CF-RAY"); v != "" {
		confidence += 0.4
		evidence = append(evidence, "CF-RAY header present")
	}
	if v := resp.Header.Get("CF-Cache-Status"); v != "" {
		confidence += 0.2
		evidence = append(evidence, "CF-Cache-Status header")
	}
	if strings.Contains(resp.Header.Get("Server"), "cloudflare") {
		confidence += 0.3
		evidence = append(evidence, "Server: cloudflare")
	}

	// Body detection
	if strings.Contains(body, "cloudflare") || strings.Contains(body, "cf-browser-verification") {
		confidence += 0.2
		evidence = append(evidence, "Cloudflare content in body")
	}

	// Error page detection
	if strings.Contains(body, "Attention Required! | Cloudflare") {
		confidence += 0.3
		evidence = append(evidence, "Cloudflare challenge page")
	}

	return minFloat(confidence, 1.0), evidence
}

// Pre-compiled regexps for hot-path detection functions.
// Avoids recompiling on every call to detect* methods.
var (
	awsWAFBodyRegex  = regexp.MustCompile(`(?i)aws\s*waf`)
	akamaiBodyRegex  = regexp.MustCompile(`(?i)akamai|ghost`)
	f5SupportIDRegex = regexp.MustCompile(`support ID: \d+`)
)

func (d *VendorDetector) detectAWSWAF(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// AWS WAF specific headers
	if v := resp.Header.Get("X-Amzn-RequestId"); v != "" {
		confidence += 0.2
		evidence = append(evidence, "X-Amzn-RequestId header")
	}
	if v := resp.Header.Get("X-Amz-Cf-Id"); v != "" {
		confidence += 0.2
		evidence = append(evidence, "X-Amz-Cf-Id header (CloudFront)")
	}

	// AWS WAF block patterns
	if strings.Contains(body, "Request blocked") && strings.Contains(body, "AWS") {
		confidence += 0.4
		evidence = append(evidence, "AWS WAF block page")
	}
	if awsWAFBodyRegex.MatchString(body) {
		confidence += 0.3
		evidence = append(evidence, "AWS WAF reference in body")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectAzureWAF(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Azure Front Door / Application Gateway headers
	if v := resp.Header.Get("X-Azure-Ref"); v != "" {
		confidence += 0.4
		evidence = append(evidence, "X-Azure-Ref header")
	}
	if v := resp.Header.Get("X-MS-Ref"); v != "" {
		confidence += 0.3
		evidence = append(evidence, "X-MS-Ref header")
	}

	// Azure WAF block patterns
	if strings.Contains(body, "Azure Web Application Firewall") {
		confidence += 0.4
		evidence = append(evidence, "Azure WAF block page")
	}
	if strings.Contains(body, "Front Door") && resp.StatusCode == 403 {
		confidence += 0.3
		evidence = append(evidence, "Azure Front Door block")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectAkamai(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Akamai headers
	if v := resp.Header.Get("X-Akamai-Transformed"); v != "" {
		confidence += 0.4
		evidence = append(evidence, "X-Akamai-Transformed header")
	}
	if strings.Contains(resp.Header.Get("Server"), "AkamaiGHost") {
		confidence += 0.4
		evidence = append(evidence, "Server: AkamaiGHost")
	}

	// Akamai Ghost reference
	if akamaiBodyRegex.MatchString(body) {
		confidence += 0.2
		evidence = append(evidence, "Akamai reference in body")
	}

	// Kona Site Defender
	if strings.Contains(body, "Access Denied") && strings.Contains(body, "Reference#") {
		confidence += 0.3
		evidence = append(evidence, "Kona Site Defender signature")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectModSecurity(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// ModSecurity signature
	if strings.Contains(resp.Header.Get("Server"), "ModSecurity") {
		confidence += 0.5
		evidence = append(evidence, "Server header contains ModSecurity")
	}

	// Common ModSecurity block patterns
	patterns := []string{
		"ModSecurity",
		"mod_security",
		"NAXSI",
		"Request forbidden by administrative rules",
		"Access denied with code 403",
	}
	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			confidence += 0.2
			evidence = append(evidence, fmt.Sprintf("Body contains: %s", pattern))
		}
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectImperva(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Imperva/Incapsula headers
	if v := resp.Header.Get("X-CDN"); strings.Contains(strings.ToLower(v), "incapsula") {
		confidence += 0.5
		evidence = append(evidence, "X-CDN: Incapsula")
	}
	if v := resp.Header.Get("X-Iinfo"); v != "" {
		confidence += 0.4
		evidence = append(evidence, "X-Iinfo header (Incapsula)")
	}

	// Incapsula patterns
	if strings.Contains(body, "Incapsula incident ID") || strings.Contains(body, "_Incapsula_Resource") {
		confidence += 0.4
		evidence = append(evidence, "Incapsula signature in body")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectF5BigIP(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// F5 BIG-IP ASM signatures
	if v := resp.Header.Get("X-WA-Info"); v != "" {
		confidence += 0.4
		evidence = append(evidence, "X-WA-Info header (F5)")
	}
	if strings.Contains(resp.Header.Get("Server"), "BigIP") {
		confidence += 0.5
		evidence = append(evidence, "Server: BigIP")
	}

	// ASM block patterns
	if strings.Contains(body, "The requested URL was rejected") {
		confidence += 0.3
		evidence = append(evidence, "F5 ASM block message")
	}
	if f5SupportIDRegex.MatchString(body) {
		confidence += 0.3
		evidence = append(evidence, "F5 support ID in response")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectFortinet(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// FortiWeb signatures
	if strings.Contains(resp.Header.Get("Server"), "FortiWeb") {
		confidence += 0.5
		evidence = append(evidence, "Server: FortiWeb")
	}

	// FortiGate/FortiWeb block patterns
	if strings.Contains(body, "FortiGate") || strings.Contains(body, "FortiWeb") {
		confidence += 0.4
		evidence = append(evidence, "Fortinet product reference")
	}
	if strings.Contains(body, "Web Page Blocked") && strings.Contains(body, "Fortinet") {
		confidence += 0.3
		evidence = append(evidence, "Fortinet block page")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectBarracuda(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Barracuda WAF signatures
	if strings.Contains(resp.Header.Get("Server"), "Barracuda") {
		confidence += 0.5
		evidence = append(evidence, "Server: Barracuda")
	}

	// Block patterns
	if strings.Contains(body, "Barracuda") && strings.Contains(body, "blocked") {
		confidence += 0.4
		evidence = append(evidence, "Barracuda block page")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectSucuri(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Sucuri signatures
	if v := resp.Header.Get("X-Sucuri-ID"); v != "" {
		confidence += 0.5
		evidence = append(evidence, "X-Sucuri-ID header")
	}
	if strings.Contains(resp.Header.Get("Server"), "Sucuri") {
		confidence += 0.4
		evidence = append(evidence, "Server: Sucuri")
	}

	// Sucuri block page
	if strings.Contains(body, "Sucuri WebSite Firewall") {
		confidence += 0.4
		evidence = append(evidence, "Sucuri block page")
	}
	if strings.Contains(body, "sucuri.net") {
		confidence += 0.2
		evidence = append(evidence, "Sucuri reference in body")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectWordfence(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Wordfence patterns (WordPress plugin)
	if strings.Contains(body, "Wordfence") {
		confidence += 0.5
		evidence = append(evidence, "Wordfence reference in body")
	}
	if strings.Contains(body, "wfBlock") {
		confidence += 0.3
		evidence = append(evidence, "Wordfence block function")
	}
	if strings.Contains(body, "Your access to this site has been limited") {
		confidence += 0.3
		evidence = append(evidence, "Wordfence block message")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectFastly(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Fastly headers
	if v := resp.Header.Get("X-Served-By"); strings.Contains(v, "cache-") {
		confidence += 0.3
		evidence = append(evidence, "Fastly cache header")
	}
	if v := resp.Header.Get("Fastly-Debug-Digest"); v != "" {
		confidence += 0.4
		evidence = append(evidence, "Fastly-Debug-Digest header")
	}
	if v := resp.Header.Get("X-Timer"); v != "" && strings.Contains(v, "VS0") {
		confidence += 0.2
		evidence = append(evidence, "Fastly X-Timer header")
	}

	return minFloat(confidence, 1.0), evidence
}

func (d *VendorDetector) detectCloudArmor(resp *http.Response, body string) (float64, []string) {
	var evidence []string
	confidence := 0.0

	// Google Cloud Armor / Google Front End
	if strings.Contains(resp.Header.Get("Server"), "Google Frontend") {
		confidence += 0.3
		evidence = append(evidence, "Server: Google Frontend")
	}
	if strings.Contains(resp.Header.Get("Via"), "google") {
		confidence += 0.2
		evidence = append(evidence, "Via: google")
	}

	// Cloud Armor block patterns
	if strings.Contains(body, "Google Cloud Armor") {
		confidence += 0.5
		evidence = append(evidence, "Cloud Armor reference")
	}

	return minFloat(confidence, 1.0), evidence
}

// =====================================================================
// BYPASS HINTS AND RECOMMENDATIONS
// =====================================================================

// BypassHints contains vendor-specific bypass recommendations
type BypassHints struct {
	Hints      []string
	Encoders   []string
	Evasions   []string
	RateLimits *RateLimitInfo
}

func getBypassHints(vendor WAFVendor) BypassHints {
	switch vendor {
	case VendorCloudflare:
		return BypassHints{
			Hints: []string{
				"Try Unicode normalization (NFKC/NFKD forms)",
				"Chunked transfer encoding may bypass",
				"Rate limiting typically starts at 1000 req/10s",
				"Use case variation in SQL keywords",
				"Try overlong UTF-8 encoding",
			},
			Encoders:   []string{"unicode", "overlong_utf8", "utf16le", "double_url"},
			Evasions:   []string{"case_swap", "chunked", "whitespace_alt"},
			RateLimits: &RateLimitInfo{Detected: true, RequestsLimit: 1000, WindowSeconds: 10},
		}

	case VendorAWSWAF:
		return BypassHints{
			Hints: []string{
				"AWS WAF uses regex matching - try regex DoS patterns",
				"Content-Type mismatch may bypass body inspection",
				"Try URL parameter pollution",
				"Nested encoding may evade detection",
			},
			Encoders:   []string{"double_url", "triple_url", "html_hex"},
			Evasions:   []string{"content_type_mismatch", "hpp", "sql_comment"},
			RateLimits: &RateLimitInfo{Detected: true, Description: "Configurable per rule"},
		}

	case VendorAzureWAF:
		return BypassHints{
			Hints: []string{
				"Azure WAF uses OWASP CRS - standard CRS bypasses apply",
				"Try XML content with CDATA sections",
				"Unicode encoding in JSON payloads",
				"WebSocket requests may bypass inspection",
			},
			Encoders:   []string{"unicode", "html_decimal", "base64"},
			Evasions:   []string{"sql_comment", "case_swap", "unicode_normalization"},
			RateLimits: nil,
		}

	case VendorAkamai:
		return BypassHints{
			Hints: []string{
				"Kona Site Defender has aggressive bot detection",
				"Use realistic browser headers and TLS fingerprint",
				"Try GBK/Shift-JIS wide byte encoding",
				"Request timing matters - avoid patterns",
			},
			Encoders:   []string{"wide_gbk", "wide_sjis", "overlong_utf8"},
			Evasions:   []string{"case_swap", "whitespace_alt", "null_byte"},
			RateLimits: &RateLimitInfo{Detected: true, Description: "Adaptive rate limiting"},
		}

	case VendorModSecurity:
		return BypassHints{
			Hints: []string{
				"Check paranoia level - higher PLs have more FPs",
				"SQL comments work well for SQLi bypass",
				"Try alternative whitespace characters",
				"Case manipulation for keyword detection",
				"Overlong UTF-8 often bypasses pattern matching",
			},
			Encoders:   []string{"overlong_utf8", "double_url", "html_decimal"},
			Evasions:   []string{"sql_comment", "whitespace_alt", "case_swap", "null_byte"},
			RateLimits: nil,
		}

	case VendorImperva:
		return BypassHints{
			Hints: []string{
				"Imperva uses machine learning - requires varied payloads",
				"Try HTTP parameter fragmentation",
				"Content-Type manipulation may help",
				"Time-based evasion with random delays",
			},
			Encoders:   []string{"unicode", "mixed", "utf16be"},
			Evasions:   []string{"chunked", "hpp", "content_type_mismatch"},
			RateLimits: &RateLimitInfo{Detected: true, Description: "ML-based rate limiting"},
		}

	case VendorF5BigIP:
		return BypassHints{
			Hints: []string{
				"F5 ASM uses signature-based detection",
				"Try payload obfuscation with comments",
				"URL encoding variants often bypass",
				"Check for parameter name whitelisting",
			},
			Encoders:   []string{"double_url", "html_hex", "octal"},
			Evasions:   []string{"sql_comment", "case_swap", "whitespace_alt"},
			RateLimits: nil,
		}

	default:
		return BypassHints{
			Hints: []string{
				"Generic WAF - try all encoding variants",
				"Test each mutation category separately",
				"Rate limit your requests to avoid IP blocking",
			},
			Encoders:   []string{"url", "double_url", "unicode", "overlong_utf8"},
			Evasions:   []string{"case_swap", "sql_comment", "whitespace_alt"},
			RateLimits: nil,
		}
	}
}

func getVendorDisplayName(vendor WAFVendor) string {
	names := map[WAFVendor]string{
		VendorCloudflare:  "Cloudflare",
		VendorAWSWAF:      "AWS WAF",
		VendorAzureWAF:    "Azure WAF (Front Door)",
		VendorAkamai:      "Akamai Kona Site Defender",
		VendorModSecurity: "ModSecurity / Coraza",
		VendorImperva:     "Imperva SecureSphere / Incapsula",
		VendorF5BigIP:     "F5 BIG-IP ASM",
		VendorFortinet:    "Fortinet FortiWeb",
		VendorBarracuda:   "Barracuda WAF",
		VendorSucuri:      "Sucuri WAF",
		VendorWordfence:   "Wordfence (WordPress)",
		VendorFastly:      "Fastly",
		VendorCloudArmor:  "Google Cloud Armor",
		VendorUnknown:     "Unknown WAF",
	}
	if name, ok := names[vendor]; ok {
		return name
	}
	return string(vendor)
}

func extractBlockPatterns(body string) []string {
	patterns := make([]string, 0)

	// Common block page indicators
	checks := []string{
		"Access Denied",
		"Request Blocked",
		"Forbidden",
		"blocked by",
		"security policy",
		"incident ID",
		"reference ID",
		"support ID",
	}

	for _, check := range checks {
		if strings.Contains(strings.ToLower(body), strings.ToLower(check)) {
			patterns = append(patterns, check)
		}
	}

	return patterns
}

func extractSignificantHeaders(resp *http.Response) []string {
	significant := make([]string, 0)

	interestingHeaders := []string{
		"Server", "X-Powered-By", "Via", "X-Cache",
		"X-CDN", "X-WAF", "X-Firewall", "X-Block",
	}

	for _, h := range interestingHeaders {
		if v := resp.Header.Get(h); v != "" {
			significant = append(significant, fmt.Sprintf("%s: %s", h, v))
		}
	}

	return significant
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// Ensure regexp is used (for pattern compilation in signatures)
var _ = regexp.MustCompile
