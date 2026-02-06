package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/payloads"
)

// registerResources adds all domain-knowledge resources to the MCP server.
func (s *Server) registerResources() {
	s.addVersionResource()
	s.addPayloadsResource()
	s.addPayloadsByCategoryResource()
	s.addGuideResource()
	s.addWAFSignaturesResource()
	s.addEvasionTechniquesResource()
	s.addOWASPMappingsResource()
	s.addConfigResource()
}

// ═══════════════════════════════════════════════════════════════════════════
// waftester://version — Server capabilities and version
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addVersionResource() {
	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "waftester://version",
			Name:        "WAF Tester Version",
			Description: "Server version, capabilities, and tool inventory.",
			MIMEType:    "application/json",
		},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			info := map[string]any{
				"name":    defaults.ToolNameDisplay,
				"version": defaults.Version,
				"capabilities": map[string]any{
					"tools":     10,
					"resources": 8,
					"prompts":   5,
				},
				"tools": []string{
					"list_payloads", "detect_waf", "discover", "learn", "scan",
					"assess", "mutate", "bypass", "probe", "generate_cicd",
				},
				"supported_waf_vendors": []string{
					"ModSecurity", "Coraza", "Cloudflare", "AWS WAF", "Azure WAF",
					"Akamai", "Imperva", "F5 BIG-IP", "Fortinet FortiWeb", "Barracuda",
					"Sucuri", "Google Cloud Armor", "Wallarm", "Signal Sciences",
					"Citrix ADC", "DenyAll", "SonicWall", "Radware AppWall",
					"AWS Shield", "Fastly", "StackPath", "Reblaze", "Edgecast",
					"KeyCDN", "Comodo WAF",
				},
				"attack_categories": []string{
					"sqli", "xss", "traversal", "auth", "ssrf", "ssti",
					"cmdi", "xxe", "nosqli", "graphql", "cors", "crlf",
					"redirect", "upload", "jwt", "oauth", "prototype", "deserialize",
				},
			}
			data, _ := json.MarshalIndent(info, "", "  ")
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: "waftester://version", MIMEType: "application/json", Text: string(data)},
				},
			}, nil
		},
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// waftester://payloads — Full payload catalog
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addPayloadsResource() {
	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "waftester://payloads",
			Name:        "Payload Catalog",
			Description: "Complete index of attack payload categories with counts, severities, and samples.",
			MIMEType:    "application/json",
		},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			loader := payloads.NewLoader(s.config.PayloadDir)
			all, err := loader.LoadAll()
			if err != nil {
				return nil, fmt.Errorf("loading payloads: %w", err)
			}

			stats := payloads.GetStats(all)

			bySeverity := make(map[string]int)
			for _, p := range all {
				if p.SeverityHint != "" {
					bySeverity[p.SeverityHint]++
				}
			}

			catalog := map[string]any{
				"total_payloads": stats.TotalPayloads,
				"categories":     stats.CategoriesUsed,
				"by_category":    stats.ByCategory,
				"by_severity":    bySeverity,
				"payload_dir":    s.config.PayloadDir,
			}
			data, _ := json.MarshalIndent(catalog, "", "  ")
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: "waftester://payloads", MIMEType: "application/json", Text: string(data)},
				},
			}, nil
		},
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// waftester://payloads/{category} — Per-category payloads
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addPayloadsByCategoryResource() {
	s.mcp.AddResourceTemplate(
		&mcp.ResourceTemplate{
			URITemplate: "waftester://payloads/{category}",
			Name:        "Payloads by Category",
			Description: "Attack payloads for a specific category (e.g. sqli, xss, traversal).",
			MIMEType:    "application/json",
		},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			// Extract category from URI: waftester://payloads/sqli → sqli
			uri := req.Params.URI
			category := ""
			if idx := strings.LastIndex(uri, "/"); idx >= 0 {
				category = uri[idx+1:]
			}
			if category == "" {
				return nil, fmt.Errorf("category is required in URI (e.g. waftester://payloads/sqli)")
			}

			loader := payloads.NewLoader(s.config.PayloadDir)
			all, err := loader.LoadAll()
			if err != nil {
				return nil, fmt.Errorf("loading payloads: %w", err)
			}

			filtered := payloads.Filter(all, category, "")
			if len(filtered) == 0 {
				return nil, fmt.Errorf("no payloads found for category %q", category)
			}

			type payloadEntry struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Payload  string `json:"payload"`
			}

			entries := make([]payloadEntry, 0, len(filtered))
			for _, p := range filtered {
				payload := p.Payload
				if len(payload) > 120 {
					payload = payload[:120] + "…"
				}
				entries = append(entries, payloadEntry{
					ID:       p.ID,
					Severity: p.SeverityHint,
					Payload:  payload,
				})
			}

			result := map[string]any{
				"category": category,
				"count":    len(filtered),
				"payloads": entries,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: uri, MIMEType: "application/json", Text: string(data)},
				},
			}, nil
		},
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// waftester://guide — Comprehensive WAF testing methodology guide
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addGuideResource() {
	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "waftester://guide",
			Name:        "WAF Testing Guide",
			Description: "Comprehensive guide to WAF security testing methodology, best practices, and interpretation.",
			MIMEType:    "text/markdown",
		},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: "waftester://guide", MIMEType: "text/markdown", Text: wafTestingGuide},
				},
			}, nil
		},
	)
}

const wafTestingGuide = `# WAF Security Testing Methodology Guide

## 1. Pre-Engagement

Before testing, ensure:
- Written authorization from the target owner
- Scope definition (which endpoints, which attacks)
- Rate limit agreement (requests per second)
- Notification plan (who to contact if issues arise)
- Rollback plan (what if something breaks)

## 2. Reconnaissance Phase

### 2.1 WAF Detection
Always start with WAF detection (detect_waf tool):
- Identifies the WAF vendor and version
- Reveals CDN/proxy layers
- Provides vendor-specific bypass tips
- Sets expectations for detection capabilities

### 2.2 Attack Surface Discovery
Use the discover tool to map:
- API endpoints and parameters
- Authentication endpoints
- File upload functionality
- Technology stack
- Hidden paths (robots.txt, sitemap, Wayback)
- JavaScript-exposed APIs and secrets

### 2.3 Test Plan Generation
Use the learn tool to create an intelligent test plan:
- Maps endpoints to relevant attack categories
- Prioritizes high-risk targets
- Identifies injection points
- Calculates optimal test configuration

## 3. Testing Phase

### 3.1 Baseline Scan
Start with a targeted scan:
- Use specific categories relevant to the application
- Start with low concurrency (5-10 workers)
- Monitor for rate limiting (429 responses)
- Review initial bypass findings

### 3.2 Enterprise Assessment
For formal evaluation, use the assess tool:
- Measures both true positive rate (attack detection) and false positive rate
- Calculates F1 score, precision, recall, MCC
- Assigns a grade (A+ through F)
- Provides actionable recommendations

### 3.3 Bypass Discovery
When initial scans find blocks:
1. Use mutate to generate encoded variants
2. Use bypass for systematic mutation matrix testing
3. Focus on the most impactful bypasses (critical/high severity)

## 4. Analysis & Interpretation

### Detection Rate
- 95%+ = Excellent WAF configuration
- 85-94% = Good, but review missed categories
- 70-84% = Significant gaps, needs rule tuning
- <70% = Major security risk

### False Positive Rate
- <1% = Excellent (enterprise ready)
- 1-5% = Good (may cause minor user impact)
- 5-10% = Needs tuning (users will be affected)
- >10% = Critical (will block legitimate traffic)

### F1 Score Interpretation
- 0.95+ = Enterprise-grade WAF
- 0.85-0.94 = Production quality
- 0.70-0.84 = Needs improvement
- <0.70 = Not suitable for production

## 5. Common Bypass Techniques

### Encoding-Based
- Double URL encoding: WAF decodes once, app decodes twice
- Unicode encoding: Bypasses ASCII-only rules
- HTML entities: Bypasses rules that don't normalize HTML
- Mixed case: Bypasses case-sensitive rules

### Protocol-Based
- HTTP/2 smuggling: Exploits H2-to-H1 translation
- Chunked encoding: Splits payload across chunks
- Content-Type confusion: JSON vs form vs multipart

### WAF-Specific
- ModSecurity: Rule ID gaps, PL1-4 paranoia level differences
- Cloudflare: Managed rules vs custom rules gaps
- AWS WAF: Rate-based vs rule-based bypass patterns

## 6. Reporting

A WAF test report should include:
1. Executive summary with grade and key findings
2. WAF vendor identification and configuration
3. Detection rate by attack category
4. False positive analysis
5. Critical bypasses with reproduction steps
6. Remediation recommendations
7. Comparison with industry benchmarks
`

// ═══════════════════════════════════════════════════════════════════════════
// waftester://waf-signatures — WAF vendor signatures and bypass tips
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addWAFSignaturesResource() {
	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "waftester://waf-signatures",
			Name:        "WAF Signatures",
			Description: "All supported WAF vendor signatures with detection methods, types, and bypass tips.",
			MIMEType:    "application/json",
		},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: "waftester://waf-signatures", MIMEType: "application/json", Text: wafSignaturesJSON},
				},
			}, nil
		},
	)
}

const wafSignaturesJSON = `{
  "total_signatures": 12,
  "signatures": [
    {
      "name": "ModSecurity",
      "vendor": "Trustwave / OWASP",
      "type": "software",
      "detection": ["Server header patterns", "Error page signatures", "ModSecurity action headers"],
      "bypass_tips": [
        "Check paranoia level (PL1 has many gaps)",
        "Try Unicode normalization bypasses",
        "Exploit rule ID gaps in CRS",
        "Double URL encoding often works at PL1-2"
      ]
    },
    {
      "name": "Coraza",
      "vendor": "Coraza (OWASP)",
      "type": "software",
      "detection": ["Similar to ModSecurity", "Go-specific error patterns"],
      "bypass_tips": [
        "Same CRS-based rules as ModSecurity",
        "Check for Go-specific parsing differences",
        "UTF-8 normalization gaps"
      ]
    },
    {
      "name": "Cloudflare",
      "vendor": "Cloudflare",
      "type": "cloud",
      "detection": ["CF-RAY header", "Server: cloudflare", "__cfduid cookie", "Error 1020 page"],
      "bypass_tips": [
        "Try managed rules vs custom rules separately",
        "IP reputation affects blocking threshold",
        "Some rules only block on 'High' sensitivity",
        "Test with different User-Agents"
      ]
    },
    {
      "name": "AWS WAF",
      "vendor": "Amazon",
      "type": "cloud",
      "detection": ["x-amzn headers", "403 responses with AWS branding", "AWS Shield indicators"],
      "bypass_tips": [
        "Test AWS managed rules vs custom rules",
        "Rate-based rules have 5-minute windows",
        "SQL injection rules may miss NoSQL payloads",
        "Try different regions for rule differences"
      ]
    },
    {
      "name": "Azure WAF",
      "vendor": "Microsoft",
      "type": "cloud",
      "detection": ["Azure Front Door headers", "Application Gateway signatures"],
      "bypass_tips": [
        "OWASP CRS 3.x rules have known gaps",
        "Custom rules may not cover all input types",
        "Bot protection rules can be fingerprinted",
        "Test both prevention and detection modes"
      ]
    },
    {
      "name": "Akamai",
      "vendor": "Akamai",
      "type": "cloud",
      "detection": ["Akamai-specific headers", "Reference ID in error pages", "Edge-Control headers"],
      "bypass_tips": [
        "Adaptive Security Engine has multiple sensitivity levels",
        "API Security rules differ from web rules",
        "Test both automated and custom rulesets",
        "Rate limiting is IP-based by default"
      ]
    },
    {
      "name": "Imperva",
      "vendor": "Imperva (Thales)",
      "type": "cloud",
      "detection": ["Incapsula cookies", "visid_incap header", "Error page branding"],
      "bypass_tips": [
        "SecureSphere vs CloudWAF have different rules",
        "Bot classification affects blocking",
        "JavaScript challenge can be automated",
        "Custom signatures may have regex gaps"
      ]
    },
    {
      "name": "F5 BIG-IP ASM",
      "vendor": "F5 Networks",
      "type": "appliance",
      "detection": ["BIGipServer cookie", "TS cookie prefix", "F5 branded error pages"],
      "bypass_tips": [
        "ASM learning mode creates rule gaps",
        "Parameter value length limits can be exploited",
        "File type policies may miss uncommon extensions",
        "XML parser differences create injection opportunities"
      ]
    },
    {
      "name": "Fortinet FortiWeb",
      "vendor": "Fortinet",
      "type": "appliance",
      "detection": ["FORTIWAFSID cookie", "Server: FortiWeb", "FortiWeb error pages"],
      "bypass_tips": [
        "Machine learning mode has false negative rates",
        "URL rewriting rules can be bypassed",
        "Known signature gaps for newer attack patterns"
      ]
    },
    {
      "name": "Barracuda",
      "vendor": "Barracuda Networks",
      "type": "appliance",
      "detection": ["barra_counter cookie", "Barracuda branded pages"],
      "bypass_tips": [
        "Signature-based detection has pattern gaps",
        "URL encoding tricks work on older firmware",
        "API endpoints may have different rule coverage"
      ]
    },
    {
      "name": "Sucuri",
      "vendor": "Sucuri (GoDaddy)",
      "type": "cloud",
      "detection": ["Sucuri-specific headers", "CloudProxy branding", "X-Sucuri-ID"],
      "bypass_tips": [
        "Firewall rules are frequently updated",
        "Try bypassing via direct-to-origin access",
        "Rate limiting thresholds are configurable"
      ]
    },
    {
      "name": "Google Cloud Armor",
      "vendor": "Google",
      "type": "cloud",
      "detection": ["Google Front End signatures", "GFE headers"],
      "bypass_tips": [
        "ModSecurity CRS preconfigured rules",
        "Custom rules use CEL expressions",
        "Rate limiting is global, not per-IP by default"
      ]
    }
  ]
}`

// ═══════════════════════════════════════════════════════════════════════════
// waftester://evasion-techniques — Evasion technique catalog
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addEvasionTechniquesResource() {
	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "waftester://evasion-techniques",
			Name:        "Evasion Techniques",
			Description: "Catalog of WAF evasion encodings and techniques with effectiveness ratings.",
			MIMEType:    "application/json",
		},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: "waftester://evasion-techniques", MIMEType: "application/json", Text: evasionTechniquesJSON},
				},
			}, nil
		},
	)
}

const evasionTechniquesJSON = `{
  "encoders": [
    {"name": "url", "description": "Standard URL encoding (%27, %3C, etc.)", "effectiveness": "medium", "best_against": ["basic signature WAFs", "ModSecurity PL1"]},
    {"name": "double_url", "description": "Double URL encoding (%2527, %253C)", "effectiveness": "high", "best_against": ["WAFs that decode once", "proxy-based WAFs"]},
    {"name": "unicode", "description": "Unicode escapes (\\u0027, \\u003C)", "effectiveness": "medium", "best_against": ["ASCII-only rule engines", "older WAFs"]},
    {"name": "html_hex", "description": "HTML hex entities (&#x27;, &#x3C;)", "effectiveness": "medium", "best_against": ["WAFs not normalizing HTML", "browser-rendered contexts"]},
    {"name": "html_dec", "description": "HTML decimal entities (&#39;, &#60;)", "effectiveness": "medium", "best_against": ["similar to html_hex"]},
    {"name": "base64", "description": "Base64 encoding of payload", "effectiveness": "low", "best_against": ["WAFs that don't decode base64", "custom app logic"]},
    {"name": "hex", "description": "Raw hex encoding (0x27, 0x3C)", "effectiveness": "medium", "best_against": ["SQL injection contexts", "binary protocols"]},
    {"name": "utf8_overlong", "description": "Overlong UTF-8 sequences", "effectiveness": "high", "best_against": ["WAFs with strict UTF-8 parsers"]}
  ],
  "evasion_techniques": [
    {"name": "case_swap", "description": "Mixed case (SeLeCt, ScRiPt)", "effectiveness": "medium", "target": "case-sensitive rules"},
    {"name": "sql_comment", "description": "SQL comment injection (SEL/**/ECT)", "effectiveness": "high", "target": "SQL injection rules"},
    {"name": "null_byte", "description": "Null byte insertion (%00)", "effectiveness": "high", "target": "C-based WAFs with string termination"},
    {"name": "whitespace", "description": "Alternative whitespace (tabs, newlines, /**/)", "effectiveness": "medium", "target": "space-dependent signatures"},
    {"name": "concat", "description": "String concatenation (CON+CAT, 'a'||'b')", "effectiveness": "medium", "target": "keyword-based signatures"}
  ],
  "injection_locations": [
    {"name": "query_param", "description": "URL query parameter (?q=PAYLOAD)", "risk": "high"},
    {"name": "post_form", "description": "POST form body (param=PAYLOAD)", "risk": "high"},
    {"name": "post_json", "description": "JSON body ({\"key\":\"PAYLOAD\"})", "risk": "high"},
    {"name": "header", "description": "HTTP header (X-Custom: PAYLOAD)", "risk": "medium"},
    {"name": "cookie", "description": "Cookie value (session=PAYLOAD)", "risk": "medium"},
    {"name": "path", "description": "URL path (/api/PAYLOAD/resource)", "risk": "medium"},
    {"name": "fragment", "description": "URL fragment (#PAYLOAD)", "risk": "low"}
  ],
  "usage_tips": [
    "Start with double_url encoding — it's the most commonly effective technique",
    "Combine case_swap with sql_comment for SQL injection bypasses",
    "Try multiple injection locations — WAFs often inspect query params but miss headers",
    "Use the 'bypass' tool to test all encoder x location x evasion combinations automatically",
    "null_byte is devastating against C-based WAF engines but rarely works against cloud WAFs"
  ]
}`

// ═══════════════════════════════════════════════════════════════════════════
// waftester://owasp-mappings — OWASP Top 10 2021 mappings
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addOWASPMappingsResource() {
	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "waftester://owasp-mappings",
			Name:        "OWASP Mappings",
			Description: "OWASP Top 10 2021 category mappings for all attack types, with CWE references.",
			MIMEType:    "application/json",
		},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			type owaspEntry struct {
				Code        string   `json:"code"`
				Name        string   `json:"name"`
				URL         string   `json:"url"`
				Description string   `json:"description"`
				Categories  []string `json:"mapped_attack_categories"`
			}

			// Build reverse mapping: OWASP code → attack categories
			reverseMap := make(map[string][]string)
			for category, code := range defaults.OWASPCategoryMapping {
				reverseMap[code] = append(reverseMap[code], category)
			}

			var entries []owaspEntry
			for _, code := range defaults.OWASPTop10Ordered {
				cat, ok := defaults.OWASPTop10[code]
				if !ok {
					continue
				}
				entries = append(entries, owaspEntry{
					Code:        cat.Code,
					Name:        cat.Name,
					URL:         cat.URL,
					Description: cat.Description,
					Categories:  reverseMap[code],
				})
			}

			result := map[string]any{
				"standard":          "OWASP Top 10 2021",
				"entries":           entries,
				"category_to_owasp": defaults.OWASPCategoryMapping,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: "waftester://owasp-mappings", MIMEType: "application/json", Text: string(data)},
				},
			}, nil
		},
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// waftester://config — Default configuration values and bounds
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addConfigResource() {
	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "waftester://config",
			Name:        "Configuration Defaults",
			Description: "Default configuration values, bounds, and recommendations for all tools.",
			MIMEType:    "application/json",
		},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			config := map[string]any{
				"scan": map[string]any{
					"concurrency":          map[string]any{"default": 10, "min": 1, "max": 100, "recommended": "5-10 for production, 20-30 for staging"},
					"rate_limit":           map[string]any{"default": 50, "min": 1, "max": 1000, "recommended": "10-20 for production, 50-100 for staging"},
					"timeout_seconds":      map[string]any{"default": 5, "min": 1, "max": 60},
					"blocked_status_codes": []int{403, 406, 429, 444, 503},
				},
				"assessment": map[string]any{
					"concurrency":     map[string]any{"default": 25, "min": 1, "max": 100},
					"rate_limit":      map[string]any{"default": 100, "min": 1, "max": 500},
					"timeout_seconds": map[string]any{"default": 10, "min": 1, "max": 60},
					"metrics":         []string{"detection_rate", "false_positive_rate", "precision", "f1_score", "f2_score", "mcc", "bypass_resistance", "block_consistency"},
					"grades":          []string{"A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D", "F"},
				},
				"bypass": map[string]any{
					"concurrency":     map[string]any{"default": 5, "min": 1, "max": 50, "recommended": "3-5 for stealth"},
					"rate_limit":      map[string]any{"default": 10, "min": 1, "max": 100, "recommended": "5-10 for stealth"},
					"timeout_seconds": map[string]any{"default": 10, "min": 1, "max": 60},
				},
				"discovery": map[string]any{
					"max_depth":       map[string]any{"default": 3, "min": 1, "max": 10},
					"concurrency":     map[string]any{"default": 10, "min": 1, "max": 50},
					"timeout_seconds": map[string]any{"default": 10, "min": 1, "max": 60},
					"service_presets": []string{"authentik", "n8n", "immich", "webapp", "intranet"},
				},
				"detect_waf": map[string]any{
					"timeout_seconds": map[string]any{"default": 10, "min": 1, "max": 60},
				},
				"payload_dir": s.config.PayloadDir,
			}
			data, _ := json.MarshalIndent(config, "", "  ")
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: "waftester://config", MIMEType: "application/json", Text: string(data)},
				},
			}, nil
		},
	)
}
