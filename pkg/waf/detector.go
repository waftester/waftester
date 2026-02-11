// Package waf provides advanced WAF and CDN detection capabilities
// Features from wafw00f, nuclei, httpx combined
package waf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/strutil"
)

// DetectionResult contains comprehensive WAF/CDN detection results
type DetectionResult struct {
	Detected       bool              `json:"detected"`
	WAFs           []WAFInfo         `json:"wafs,omitempty"`
	CDN            *CDNInfo          `json:"cdn,omitempty"`
	TLSFingerprint string            `json:"tls_fingerprint,omitempty"`
	JARMHash       string            `json:"jarm_hash,omitempty"`
	Confidence     float64           `json:"confidence"`
	Evidence       []Evidence        `json:"evidence"`
	RawHeaders     map[string]string `json:"raw_headers,omitempty"`
}

// WAFInfo contains information about a detected WAF
type WAFInfo struct {
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor"`
	Type        string   `json:"type"` // cloud, appliance, software, cdn-integrated
	Version     string   `json:"version,omitempty"`
	Confidence  float64  `json:"confidence"`
	Evidence    []string `json:"evidence"`
	BypassTips  []string `json:"bypass_tips,omitempty"`
	KnownRules  []string `json:"known_rules,omitempty"`
	RulesetInfo string   `json:"ruleset_info,omitempty"`
}

// CDNInfo contains information about a detected CDN
type CDNInfo struct {
	Name       string   `json:"name"`
	POP        string   `json:"pop,omitempty"` // Point of Presence
	CacheHit   bool     `json:"cache_hit"`
	RayID      string   `json:"ray_id,omitempty"` // Cloudflare
	RequestID  string   `json:"request_id,omitempty"`
	EdgeServer string   `json:"edge_server,omitempty"`
	Features   []string `json:"features,omitempty"`
}

// Evidence represents a single piece of detection evidence
type Evidence struct {
	Type        string  `json:"type"` // header, body, status, behavior, tls, timing
	Source      string  `json:"source"`
	Value       string  `json:"value"`
	Indicates   string  `json:"indicates"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description,omitempty"`
}

// Detector provides WAF and CDN detection
type Detector struct {
	client     *http.Client
	timeout    time.Duration
	userAgent  string
	signatures []WAFSignature
	cdnSigs    []CDNSignature
}

// WAFSignature defines a WAF detection pattern
type WAFSignature struct {
	Name            string
	Vendor          string
	Type            string
	HeaderPatterns  map[string]*regexp.Regexp
	BodyPatterns    []*regexp.Regexp
	StatusCodes     []int
	Behaviors       []BehaviorCheck
	JARMPrefixes    []string
	TLSFingerprints []string
	BypassTips      []string
	KnownRules      []string
}

// BehaviorCheck defines a behavioral test
type BehaviorCheck struct {
	Method      string
	Path        string
	Payload     string
	Headers     map[string]string
	ExpectBlock bool
}

// CDNSignature defines a CDN detection pattern
type CDNSignature struct {
	Name           string
	HeaderPatterns map[string]*regexp.Regexp
	CNAMEPatterns  []*regexp.Regexp
	IPRanges       []string
	Features       []string
}

// NewDetector creates a new WAF/CDN detector
func NewDetector(timeout time.Duration) *Detector {
	if timeout == 0 {
		timeout = httpclient.TimeoutProbing
	}

	// Use shared httpclient factory for connection pooling
	client := httpclient.New(httpclient.Config{
		Timeout:            timeout,
		InsecureSkipVerify: true,
		MaxIdleConns:       10,
		MaxConnsPerHost:    5,
		IdleConnTimeout:    duration.HTTPFuzzing,
	})

	d := &Detector{
		client:    client,
		timeout:   timeout,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}

	d.initSignatures()
	return d
}

// Detect performs comprehensive WAF and CDN detection
func (d *Detector) Detect(ctx context.Context, target string) (*DetectionResult, error) {
	result := &DetectionResult{
		Evidence:   make([]Evidence, 0),
		RawHeaders: make(map[string]string),
	}

	// Phase 1: Passive detection from normal request
	if err := d.passiveDetection(ctx, target, result); err != nil {
		return nil, fmt.Errorf("passive detection failed: %w", err)
	}

	// Phase 2: Active detection with attack payloads
	d.activeDetection(ctx, target, result)

	// Phase 3: Behavioral analysis
	d.behavioralAnalysis(ctx, target, result)

	// Phase 4: TLS fingerprinting
	d.tlsFingerprinting(ctx, target, result)

	// Phase 5: Timing analysis
	d.timingAnalysis(ctx, target, result)

	// Consolidate results
	d.consolidateResults(result)

	return result, nil
}

// passiveDetection analyzes headers and response from a clean request
func (d *Detector) passiveDetection(ctx context.Context, target string, result *DetectionResult) error {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Store raw headers
	for k, v := range resp.Header {
		result.RawHeaders[k] = strings.Join(v, ", ")
	}

	// Check each WAF signature
	for _, sig := range d.signatures {
		evidence := d.checkWAFSignature(sig, resp, "")
		if len(evidence) > 0 {
			result.Evidence = append(result.Evidence, evidence...)
		}
	}

	// Check CDN signatures
	for _, sig := range d.cdnSigs {
		if cdnInfo := d.checkCDNSignature(sig, resp); cdnInfo != nil {
			result.CDN = cdnInfo
		}
	}

	return nil
}

// activeDetection sends attack payloads to trigger WAF responses
func (d *Detector) activeDetection(ctx context.Context, target string, result *DetectionResult) {
	attackPayloads := []struct {
		name    string
		payload string
		method  string
	}{
		{"sqli", "?id=1' OR '1'='1'--", "GET"},
		{"xss", "?q=<script>alert(1)</script>", "GET"},
		{"lfi", "?file=../../../etc/passwd", "GET"},
		{"rce", "?cmd=;cat /etc/passwd", "GET"},
		{"xxe", "?xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", "GET"},
		{"ssti", "?name={{7*7}}", "GET"},
		{"cmdi", "?ip=127.0.0.1;id", "GET"},
		{"ssrf", "?url=http://169.254.169.254/latest/meta-data/", "GET"},
	}

	for _, attack := range attackPayloads {
		req, err := http.NewRequestWithContext(ctx, attack.method, target+attack.payload, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 8192)
		iohelper.DrainAndClose(resp.Body) // Drain remainder after ReadBody; defer not needed here — no early returns

		// Check for WAF block indicators
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 418 ||
			resp.StatusCode == 429 || resp.StatusCode == 503 {
			result.Evidence = append(result.Evidence, Evidence{
				Type:       "status",
				Source:     attack.name,
				Value:      fmt.Sprintf("%d", resp.StatusCode),
				Indicates:  "waf_block",
				Confidence: 0.8,
			})
		}

		// Check response body for block patterns
		bodyStr := string(body)
		for _, sig := range d.signatures {
			evidence := d.checkWAFSignature(sig, resp, bodyStr)
			if len(evidence) > 0 {
				for i := range evidence {
					evidence[i].Source = attack.name + "_attack"
					evidence[i].Confidence *= 1.2 // Higher confidence from attack trigger
					if evidence[i].Confidence > 1.0 {
						evidence[i].Confidence = 1.0
					}
				}
				result.Evidence = append(result.Evidence, evidence...)
			}
		}
	}
}

// behavioralAnalysis tests WAF behavior patterns
func (d *Detector) behavioralAnalysis(ctx context.Context, target string, result *DetectionResult) {
	tests := []struct {
		name        string
		method      string
		path        string
		headers     map[string]string
		expectBlock bool
	}{
		// Method-based detection
		{"trace_method", "TRACE", "", nil, true},
		{"track_method", "TRACK", "", nil, true},
		{"debug_method", "DEBUG", "", nil, true},

		// Header-based detection
		{"host_injection", "GET", "", map[string]string{"Host": "evil.com"}, true},
		{"xff_spoof", "GET", "", map[string]string{"X-Forwarded-For": "127.0.0.1"}, false},

		// Path-based detection
		{"dotdot_path", "GET", "/..%252f..%252f..%252fetc/passwd", nil, true},
		{"null_byte", "GET", "/test%00.php", nil, true},
	}

	normalReq, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	normalStatus := 0
	if err == nil {
		normalReq.Header.Set("User-Agent", d.userAgent)
		normalResp, err := d.client.Do(normalReq)
		if err == nil {
			normalStatus = normalResp.StatusCode
			iohelper.DrainAndClose(normalResp.Body)
		}
	}

	for _, test := range tests {
		testURL := target + test.path
		req, err := http.NewRequestWithContext(ctx, test.method, testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)
		for k, v := range test.headers {
			req.Header.Set(k, v)
		}

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		// Check if behavior matches expectation
		isBlocked := resp.StatusCode == 403 || resp.StatusCode == 406 ||
			resp.StatusCode == 418 || resp.StatusCode == 405

		if isBlocked && test.expectBlock {
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "behavior",
				Source:      test.name,
				Value:       fmt.Sprintf("%d (normal: %d)", resp.StatusCode, normalStatus),
				Indicates:   "waf_active",
				Confidence:  0.7,
				Description: "WAF blocks known attack pattern",
			})
		}
	}
}

// tlsFingerprinting captures TLS fingerprint
func (d *Detector) tlsFingerprinting(ctx context.Context, target string, result *DetectionResult) {
	// Parse target to get host
	if !strings.HasPrefix(target, "https://") {
		return // Only for HTTPS
	}

	host := strings.TrimPrefix(target, "https://")
	host = strings.Split(host, "/")[0]
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	dialer := &net.Dialer{Timeout: d.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Extract TLS version
	tlsVersion := ""
	switch state.Version {
	case tls.VersionTLS10:
		tlsVersion = "TLS 1.0"
	case tls.VersionTLS11:
		tlsVersion = "TLS 1.1"
	case tls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	case tls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	}

	// Extract cipher suite
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)

	// Create fingerprint
	result.TLSFingerprint = fmt.Sprintf("%s:%s", tlsVersion, cipherSuite)

	// Check for CDN-specific TLS patterns
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		issuer := cert.Issuer.CommonName

		cdnIndicators := map[string]string{
			"Cloudflare":            "Cloudflare",
			"Amazon":                "AWS CloudFront",
			"Fastly":                "Fastly",
			"Akamai":                "Akamai",
			"Google Trust Services": "Google Cloud CDN",
			"DigiCert":              "Various CDNs",
			"Let's Encrypt":         "Direct/Self-managed",
		}

		for pattern, cdn := range cdnIndicators {
			if strings.Contains(issuer, pattern) {
				result.Evidence = append(result.Evidence, Evidence{
					Type:       "tls",
					Source:     "certificate_issuer",
					Value:      issuer,
					Indicates:  cdn,
					Confidence: 0.5,
				})
			}
		}

		// Check SANs for CDN indicators
		for _, san := range cert.DNSNames {
			if strings.Contains(san, "cloudflare") ||
				strings.Contains(san, "cloudfront") ||
				strings.Contains(san, "fastly") ||
				strings.Contains(san, "akamai") {
				result.Evidence = append(result.Evidence, Evidence{
					Type:       "tls",
					Source:     "san",
					Value:      san,
					Indicates:  "cdn_certificate",
					Confidence: 0.9,
				})
			}
		}
	}
}

// timingAnalysis checks response timing patterns
func (d *Detector) timingAnalysis(ctx context.Context, target string, result *DetectionResult) {
	// Compare timing between normal and attack requests
	normalTimes := make([]time.Duration, 0, 3)
	attackTimes := make([]time.Duration, 0, 3)

	for i := 0; i < 3; i++ {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)
		resp, err := d.client.Do(req)
		if err == nil {
			iohelper.DrainAndClose(resp.Body)
			normalTimes = append(normalTimes, time.Since(start))
		}
	}

	// Attack request timing
	for i := 0; i < 3; i++ {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, "GET", target+"?id=1' OR '1'='1", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)
		resp, err := d.client.Do(req)
		if err == nil {
			iohelper.DrainAndClose(resp.Body)
			attackTimes = append(attackTimes, time.Since(start))
		}
	}

	if len(normalTimes) > 0 && len(attackTimes) > 0 {
		avgNormal := averageDuration(normalTimes)
		avgAttack := averageDuration(attackTimes)

		// Significant timing difference might indicate WAF processing
		if avgAttack > avgNormal*2 && avgAttack-avgNormal > 100*time.Millisecond {
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "timing",
				Source:      "response_latency",
				Value:       fmt.Sprintf("normal: %v, attack: %v", avgNormal, avgAttack),
				Indicates:   "waf_processing",
				Confidence:  0.4,
				Description: "Attack requests take significantly longer (WAF inspection)",
			})
		}
	}
}

// checkWAFSignature checks if a response matches a WAF signature
func (d *Detector) checkWAFSignature(sig WAFSignature, resp *http.Response, body string) []Evidence {
	evidence := make([]Evidence, 0)

	// Check header patterns
	for headerName, pattern := range sig.HeaderPatterns {
		headerValue := resp.Header.Get(headerName)
		if headerValue != "" && pattern.MatchString(headerValue) {
			evidence = append(evidence, Evidence{
				Type:       "header",
				Source:     headerName,
				Value:      headerValue,
				Indicates:  sig.Name,
				Confidence: 0.8,
			})
		}
	}

	// Check body patterns
	if body != "" {
		for _, pattern := range sig.BodyPatterns {
			if pattern.MatchString(body) {
				evidence = append(evidence, Evidence{
					Type:       "body",
					Source:     "response_body",
					Value:      strutil.Truncate(pattern.FindString(body), 100),
					Indicates:  sig.Name,
					Confidence: 0.7,
				})
			}
		}
	}

	return evidence
}

// checkCDNSignature checks if a response matches a CDN signature
func (d *Detector) checkCDNSignature(sig CDNSignature, resp *http.Response) *CDNInfo {
	for headerName, pattern := range sig.HeaderPatterns {
		headerValue := resp.Header.Get(headerName)
		if headerValue != "" && pattern.MatchString(headerValue) {
			info := &CDNInfo{
				Name:     sig.Name,
				Features: sig.Features,
			}

			// Extract specific info based on CDN
			switch sig.Name {
			case "Cloudflare":
				info.RayID = resp.Header.Get("CF-Ray")
				info.CacheHit = resp.Header.Get("CF-Cache-Status") == "HIT"
			case "AWS CloudFront":
				info.RequestID = resp.Header.Get("X-Amz-Cf-Id")
				info.POP = resp.Header.Get("X-Amz-Cf-Pop")
				info.CacheHit = strings.Contains(resp.Header.Get("X-Cache"), "Hit")
			case "Fastly":
				info.RequestID = resp.Header.Get("X-Served-By")
				info.CacheHit = resp.Header.Get("X-Cache") == "HIT"
			case "Akamai":
				info.EdgeServer = resp.Header.Get("X-Akamai-Transformed")
			}

			return info
		}
	}
	return nil
}

// consolidateResults aggregates evidence into WAF detections
func (d *Detector) consolidateResults(result *DetectionResult) {
	// Group evidence by WAF
	wafEvidence := make(map[string][]Evidence)
	for _, ev := range result.Evidence {
		if ev.Indicates != "" && ev.Indicates != "waf_block" && ev.Indicates != "waf_active" && ev.Indicates != "waf_processing" {
			wafEvidence[ev.Indicates] = append(wafEvidence[ev.Indicates], ev)
		}
	}

	// Create WAFInfo for each detected WAF
	for wafName, evidence := range wafEvidence {
		if len(evidence) == 0 {
			continue
		}

		// Calculate total confidence using simple sum-and-cap.
		// This is intentionally simpler than complementary probability
		// (1 - (1-c1)*(1-c2)*...) because detection evidence is not
		// statistically independent, and the cap provides a clear ceiling.
		totalConfidence := 0.0
		evidenceStrings := make([]string, 0)
		for _, ev := range evidence {
			totalConfidence += ev.Confidence
			evidenceStrings = append(evidenceStrings, fmt.Sprintf("%s: %s", ev.Source, ev.Value))
		}

		// Cap confidence at 1.0
		if totalConfidence > 1.0 {
			totalConfidence = 1.0
		}

		// Find signature for bypass tips
		var bypassTips, knownRules []string
		for _, sig := range d.signatures {
			if sig.Name == wafName {
				bypassTips = sig.BypassTips
				knownRules = sig.KnownRules
				break
			}
		}

		wafInfo := WAFInfo{
			Name:       wafName,
			Confidence: totalConfidence,
			Evidence:   evidenceStrings,
			BypassTips: bypassTips,
			KnownRules: knownRules,
		}

		// Set vendor and type from signature
		for _, sig := range d.signatures {
			if sig.Name == wafName {
				wafInfo.Vendor = sig.Vendor
				wafInfo.Type = sig.Type
				break
			}
		}

		result.WAFs = append(result.WAFs, wafInfo)
	}

	// Sort by confidence
	sort.Slice(result.WAFs, func(i, j int) bool {
		return result.WAFs[i].Confidence > result.WAFs[j].Confidence
	})

	// Set detected flag
	result.Detected = len(result.WAFs) > 0 || result.CDN != nil

	// Calculate overall confidence
	if len(result.WAFs) > 0 {
		result.Confidence = result.WAFs[0].Confidence
	}
}

// initSignatures initializes WAF and CDN detection signatures
func (d *Detector) initSignatures() {
	d.signatures = []WAFSignature{
		// ModSecurity
		{
			Name:   "ModSecurity",
			Vendor: "Trustwave/OWASP",
			Type:   "software",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)mod_security|modsecurity|NYOB`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)mod_security|modsecurity`),
				regexp.MustCompile(`(?i)not acceptable`),
				regexp.MustCompile(`(?i)request rejected`),
			},
			BypassTips: []string{
				"Try URL encoding variations",
				"Use case-swapping for keywords",
				"Try comment injection in SQL",
				"Use alternative encoding (hex, unicode)",
			},
			KnownRules: []string{"OWASP CRS", "Comodo", "Atomicorp"},
		},
		// Coraza
		{
			Name:   "Coraza",
			Vendor: "Coraza/OWASP",
			Type:   "software",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)coraza`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)coraza`),
			},
			BypassTips: []string{
				"Similar to ModSecurity bypasses",
				"Check for CRS version differences",
			},
			KnownRules: []string{"OWASP CRS"},
		},
		// Cloudflare
		{
			Name:   "Cloudflare",
			Vendor: "Cloudflare",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":          regexp.MustCompile(`(?i)cloudflare`),
				"CF-Ray":          regexp.MustCompile(`.+`),
				"CF-Cache-Status": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)cloudflare`),
				regexp.MustCompile(`(?i)attention required`),
				regexp.MustCompile(`(?i)ray ID`),
			},
			BypassTips: []string{
				"Find origin IP via historical DNS",
				"Check for exposed subdomains",
				"Use Cloudflare bypass techniques",
			},
		},
		// AWS WAF
		{
			Name:   "AWS WAF",
			Vendor: "Amazon",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-Amzn-Requestid": regexp.MustCompile(`.+`),
				"X-Amz-Cf-Id":      regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)aws|amazon`),
				regexp.MustCompile(`(?i)request blocked`),
			},
			BypassTips: []string{
				"Test for rule set gaps",
				"Try rate limit evasion",
			},
		},
		// Akamai
		{
			Name:   "Akamai Kona",
			Vendor: "Akamai",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":               regexp.MustCompile(`(?i)akamai|akamaiGhost`),
				"X-Akamai-Transformed": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)akamai`),
				regexp.MustCompile(`(?i)reference #`),
			},
			BypassTips: []string{
				"Check for misconfigured rules",
				"Test header manipulation",
			},
		},
		// Imperva/Incapsula
		{
			Name:   "Imperva Incapsula",
			Vendor: "Imperva",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-CDN": regexp.MustCompile(`(?i)incapsula|imperva`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)incapsula|imperva`),
				regexp.MustCompile(`(?i)incident`),
				regexp.MustCompile(`_Incapsula_Resource`),
			},
			BypassTips: []string{
				"Find origin via DNS history",
				"Test for whitelist IPs",
			},
		},
		// F5 BIG-IP ASM
		{
			Name:   "F5 BIG-IP ASM",
			Vendor: "F5",
			Type:   "appliance",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":     regexp.MustCompile(`(?i)BigIP|BIG-IP`),
				"X-WA-Info":  regexp.MustCompile(`.+`),
				"X-Cnection": regexp.MustCompile(`close`),
				"Set-Cookie": regexp.MustCompile(`(?i)TS[a-z0-9]{6,}=`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)request rejected`),
				regexp.MustCompile(`(?i)support ID`),
			},
			BypassTips: []string{
				"Test for attack signature gaps",
				"Try HTTP parameter pollution",
			},
		},
		// Fortinet FortiWeb
		{
			Name:   "FortiWeb",
			Vendor: "Fortinet",
			Type:   "appliance",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":     regexp.MustCompile(`(?i)fortiweb`),
				"Set-Cookie": regexp.MustCompile(`(?i)FORTIWAFSID`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)fortigate|fortinet|fortiweb`),
			},
		},
		// Barracuda
		{
			Name:   "Barracuda WAF",
			Vendor: "Barracuda",
			Type:   "appliance",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)barracuda`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)barracuda`),
			},
		},
		// Sucuri
		{
			Name:   "Sucuri",
			Vendor: "Sucuri",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":      regexp.MustCompile(`(?i)sucuri`),
				"X-Sucuri-ID": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)sucuri`),
				regexp.MustCompile(`(?i)cloudproxy`),
			},
		},
		// StackPath
		{
			Name:   "StackPath",
			Vendor: "StackPath",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-SP-":  regexp.MustCompile(`.+`),
				"Server": regexp.MustCompile(`(?i)stackpath`),
			},
		},
		// Wordfence
		{
			Name:   "Wordfence",
			Vendor: "Defiant",
			Type:   "software",
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)wordfence`),
				regexp.MustCompile(`(?i)generated by wordfence`),
			},
		},
		// NGINX+
		{
			Name:   "NGINX App Protect",
			Vendor: "F5/NGINX",
			Type:   "software",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)nginx`),
			},
			BypassTips: []string{
				"Test for signature gaps",
				"Check HTTP/2 handling",
			},
		},
		// Azure WAF
		{
			Name:   "Azure WAF",
			Vendor: "Microsoft",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-Azure-Ref": regexp.MustCompile(`.+`),
				"X-MS-Ref":    regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)azure|microsoft`),
			},
		},
		// Google Cloud Armor
		{
			Name:   "Google Cloud Armor",
			Vendor: "Google",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Via":    regexp.MustCompile(`(?i)google`),
				"Server": regexp.MustCompile(`(?i)gws|Google`),
			},
		},
		// DenyAll
		{
			Name:   "DenyAll",
			Vendor: "DenyAll",
			Type:   "appliance",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Set-Cookie": regexp.MustCompile(`(?i)sessioncookie=`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)conditionblocked`),
			},
		},
		// Citrix NetScaler AppFirewall
		{
			Name:   "Citrix NetScaler",
			Vendor: "Citrix",
			Type:   "appliance",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Via":        regexp.MustCompile(`(?i)NS-CACHE`),
				"Set-Cookie": regexp.MustCompile(`(?i)ns_af`),
				"Cneonction": regexp.MustCompile(`close`),
			},
		},
		// Radware AppWall
		{
			Name:   "Radware AppWall",
			Vendor: "Radware",
			Type:   "appliance",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-SL-CompState": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)unauthorized activity`),
			},
		},
		// SafeDog
		{
			Name:   "SafeDog",
			Vendor: "SafeDog",
			Type:   "software",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)safedog`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)safedog`),
			},
		},
		// 360 WAF
		{
			Name:   "360 WAF",
			Vendor: "360",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-Powered-By-360WZB": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)360wzb|360\.cn`),
			},
		},
		// Wallarm
		{
			Name:   "Wallarm",
			Vendor: "Wallarm",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)wallarm`),
			},
		},
		// Reblaze
		{
			Name:   "Reblaze",
			Vendor: "Reblaze",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)reblaze|rbzid`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)reblaze`),
			},
		},
		// Comodo WAF
		{
			Name:   "Comodo WAF",
			Vendor: "Comodo",
			Type:   "cloud",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)protected by COMODO`),
			},
		},
		// USP Secure Entry
		{
			Name:   "USP Secure Entry",
			Vendor: "United Security Providers",
			Type:   "appliance",
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)usp.+secure entry`),
			},
		},
		// TrafficShield
		{
			Name:   "TrafficShield",
			Vendor: "F5",
			Type:   "appliance",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)F5-TrafficShield`),
			},
		},
		// Varnish
		{
			Name:   "Varnish",
			Vendor: "Varnish Software",
			Type:   "software",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Via":       regexp.MustCompile(`(?i)varnish`),
				"X-Varnish": regexp.MustCompile(`.+`),
			},
		},
	}

	// CDN Signatures
	d.cdnSigs = []CDNSignature{
		{
			Name: "Cloudflare",
			HeaderPatterns: map[string]*regexp.Regexp{
				"CF-Ray": regexp.MustCompile(`.+`),
			},
			Features: []string{"DDoS protection", "WAF", "CDN", "Bot management"},
		},
		{
			Name: "AWS CloudFront",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-Amz-Cf-Id": regexp.MustCompile(`.+`),
			},
			Features: []string{"CDN", "Edge locations", "Lambda@Edge"},
		},
		{
			Name: "Fastly",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-Served-By": regexp.MustCompile(`(?i)cache-`),
			},
			Features: []string{"CDN", "Edge compute", "Image optimization"},
		},
		{
			Name: "Akamai",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-Akamai-Transformed": regexp.MustCompile(`.+`),
			},
			Features: []string{"CDN", "WAF", "DDoS protection", "Bot management"},
		},
		{
			Name: "KeyCDN",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)keycdn`),
			},
			Features: []string{"CDN", "Image optimization"},
		},
		{
			Name: "StackPath",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-SP-": regexp.MustCompile(`.+`),
			},
			Features: []string{"CDN", "WAF", "Edge compute"},
		},
		{
			Name: "Azure CDN",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-Azure-Ref": regexp.MustCompile(`.+`),
			},
			Features: []string{"CDN", "WAF integration"},
		},
		{
			Name: "Google Cloud CDN",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Via": regexp.MustCompile(`(?i)1\.1 google`),
			},
			Features: []string{"CDN", "Cloud Armor integration"},
		},
		{
			Name: "Bunny CDN",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":       regexp.MustCompile(`(?i)bunny`),
				"CDN-PullZone": regexp.MustCompile(`.+`),
			},
			Features: []string{"CDN", "Image optimization"},
		},
	}
}

// Helper functions
func averageDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}


