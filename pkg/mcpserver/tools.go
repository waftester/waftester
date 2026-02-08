package mcpserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/assessment"
	"github.com/waftester/waftester/pkg/core"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/learning"
	"github.com/waftester/waftester/pkg/metrics"
	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/waf"
)

// categoryMeta holds rich metadata for each attack category — used to enrich
// tool responses so AI agents understand the domain context.
type categoryMeta struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	OWASPCode   string `json:"owasp_code"`
	OWASPName   string `json:"owasp_name"`
	RiskLevel   string `json:"risk_level"`
	CommonUsage string `json:"common_usage"`
}

// categoryDescriptions provides domain-expert descriptions for every attack
// category the payload catalog supports.
var categoryDescriptions = map[string]categoryMeta{
	"sqli": {
		Name:        "SQL Injection",
		Description: "Payloads that inject SQL syntax into application queries to extract data, bypass authentication, or execute commands on the database server.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test login forms, search parameters, API query parameters, and any input that feeds into SQL queries.",
	},
	"xss": {
		Name:        "Cross-Site Scripting (XSS)",
		Description: "Payloads that inject JavaScript or HTML into web pages to steal cookies, redirect users, or execute actions on behalf of victims.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test search boxes, comment fields, URL parameters rendered in HTML, and any reflected/stored user input.",
	},
	"traversal": {
		Name:        "Path Traversal / LFI",
		Description: "Payloads that traverse directory structures (../../etc/passwd) to read sensitive files from the server filesystem.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "High",
		CommonUsage: "Test file download endpoints, include parameters, template paths, and any input used in filesystem operations.",
	},
	"auth": {
		Name:        "Authentication Bypass",
		Description: "Payloads targeting authentication mechanisms — default credentials, token manipulation, session fixation, and auth logic flaws.",
		OWASPCode:   "A07:2021",
		OWASPName:   "Identification and Authentication Failures",
		RiskLevel:   "Critical",
		CommonUsage: "Test login endpoints, password reset flows, MFA implementations, and session management.",
	},
	"ssrf": {
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "Payloads that trick the server into making requests to internal resources, cloud metadata endpoints, or other backend services.",
		OWASPCode:   "A10:2021",
		OWASPName:   "Server-Side Request Forgery",
		RiskLevel:   "Critical",
		CommonUsage: "Test URL input fields, webhook configurations, image/file fetch features, and any server-side URL processing.",
	},
	"ssti": {
		Name:        "Server-Side Template Injection (SSTI)",
		Description: "Payloads injecting template syntax ({{7*7}}, ${7*7}) into server-side template engines to achieve remote code execution.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test template rendering endpoints, email templates, PDF generators, and any user-controlled template content.",
	},
	"cmdi": {
		Name:        "OS Command Injection",
		Description: "Payloads that inject operating system commands (;whoami, |cat /etc/passwd) to execute arbitrary commands on the server.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Test ping/traceroute tools, file processors, system administration interfaces, and any input passed to shell commands.",
	},
	"xxe": {
		Name:        "XML External Entity (XXE)",
		Description: "Payloads exploiting XML parsers to read local files, perform SSRF, or cause denial of service via entity expansion.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "High",
		CommonUsage: "Test XML/SOAP endpoints, file upload (DOCX/SVG/XML), and any XML processing functionality.",
	},
	"nosqli": {
		Name:        "NoSQL Injection",
		Description: "Payloads targeting NoSQL databases (MongoDB, CouchDB) with operator injection ({$gt:''}, {$ne:null}) or JavaScript injection.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test MongoDB-backed APIs, JSON query parameters, and NoSQL database interfaces.",
	},
	"graphql": {
		Name:        "GraphQL Injection & Abuse",
		Description: "Payloads targeting GraphQL APIs — introspection queries, query depth attacks, batching abuse, and injection via variables.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "High",
		CommonUsage: "Test GraphQL endpoints for introspection leaks, authorization bypasses, and resource exhaustion.",
	},
	"cors": {
		Name:        "CORS Misconfiguration",
		Description: "Payloads testing Cross-Origin Resource Sharing misconfigurations that allow unauthorized cross-origin data access.",
		OWASPCode:   "A05:2021",
		OWASPName:   "Security Misconfiguration",
		RiskLevel:   "Medium",
		CommonUsage: "Test API endpoints for overly permissive Access-Control-Allow-Origin headers and credential leakage.",
	},
	"crlf": {
		Name:        "CRLF Injection / HTTP Response Splitting",
		Description: "Payloads injecting carriage return/line feed characters to manipulate HTTP headers, set cookies, or redirect responses.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test URL parameters reflected in response headers, redirect endpoints, and cookie-setting flows.",
	},
	"redirect": {
		Name:        "Open Redirect",
		Description: "Payloads exploiting URL redirect functionality to send users to malicious external sites for phishing or credential theft.",
		OWASPCode:   "A01:2021",
		OWASPName:   "Broken Access Control",
		RiskLevel:   "Medium",
		CommonUsage: "Test login redirect parameters, OAuth callback URLs, and any URL forwarding functionality.",
	},
	"upload": {
		Name:        "Malicious File Upload",
		Description: "Payloads testing file upload validation — double extensions, MIME type bypass, path traversal in filenames, and polyglot files.",
		OWASPCode:   "A04:2021",
		OWASPName:   "Insecure Design",
		RiskLevel:   "Critical",
		CommonUsage: "Test file upload endpoints for web shells, content type bypass, and filename-based attacks.",
	},
	"jwt": {
		Name:        "JWT Token Attacks",
		Description: "Payloads targeting JSON Web Token implementations — algorithm confusion (none/HS256→RS256), key brute-force, and claim manipulation.",
		OWASPCode:   "A02:2021",
		OWASPName:   "Cryptographic Failures",
		RiskLevel:   "Critical",
		CommonUsage: "Test JWT-authenticated APIs for algorithm confusion, weak secrets, and token manipulation vulnerabilities.",
	},
	"oauth": {
		Name:        "OAuth/OIDC Attacks",
		Description: "Payloads targeting OAuth 2.0 and OpenID Connect flows — redirect URI manipulation, CSRF, token leakage, and scope escalation.",
		OWASPCode:   "A07:2021",
		OWASPName:   "Identification and Authentication Failures",
		RiskLevel:   "High",
		CommonUsage: "Test OAuth authorization endpoints, redirect URI validation, and token exchange flows.",
	},
	"prototype": {
		Name:        "Prototype Pollution",
		Description: "Payloads injecting properties into JavaScript Object.prototype to modify application behavior, bypass security checks, or achieve RCE.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "High",
		CommonUsage: "Test JSON merge/deep-copy endpoints, configuration APIs, and any server-side JavaScript object manipulation.",
	},
	"deserialize": {
		Name:        "Insecure Deserialization",
		Description: "Payloads exploiting unsafe deserialization in Java, PHP, Python, .NET, and Ruby to achieve remote code execution or privilege escalation.",
		OWASPCode:   "A08:2021",
		OWASPName:   "Software and Data Integrity Failures",
		RiskLevel:   "Critical",
		CommonUsage: "Test serialized data inputs (Java ObjectInputStream, PHP unserialize, Python pickle) and session/state storage.",
	},
	// Broader category names from payload files
	"injection": {
		Name:        "Injection (General)",
		Description: "General injection payloads covering SQL, LDAP, XPath, and other injection vectors that manipulate backend queries or commands.",
		OWASPCode:   "A03:2021",
		OWASPName:   "Injection",
		RiskLevel:   "Critical",
		CommonUsage: "Broad injection testing across multiple backend technologies.",
	},
}

// registerTools adds all WAF testing tools to the MCP server.
func (s *Server) registerTools() {
	s.addListPayloadsTool()
	s.addDetectWAFTool()
	s.addDiscoverTool()
	s.addLearnTool()
	s.addScanTool()
	s.addAssessTool()
	s.addMutateTool()
	s.addBypassTool()
	s.addProbeTool()
	s.addGenerateCICDTool()
}

// ═══════════════════════════════════════════════════════════════════════════
// list_payloads — Browse the attack payload catalog
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addListPayloadsTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "list_payloads",
			Title: "List Attack Payloads",
			Description: `Inventory tool — browse the local attack payload catalog WITHOUT sending any traffic.

USE THIS TOOL WHEN:
• The user asks "what payloads/categories/attacks do you support?"
• You need to check how many payloads exist for a category before running 'scan'
• You want to show the user sample payloads for a specific attack type
• Planning which categories to include in a scan or assessment

DO NOT USE THIS TOOL WHEN:
• You want to actually TEST a target — use 'scan' instead
• You want WAF bypass testing — use 'bypass' instead
• You want to encode/mutate a specific payload — use 'mutate' instead

This is a READ-ONLY local operation. Zero network requests. Instant results.

EXAMPLE INPUTS:
• See everything: {} (no arguments)
• Browse SQL injection payloads: {"category": "sqli"}
• Only critical XSS payloads: {"category": "xss", "severity": "Critical"}
• High+ severity across all categories: {"severity": "High"}

CATEGORIES: sqli, xss, traversal, auth, ssrf, ssti, cmdi, xxe, nosqli, graphql, cors, crlf, redirect, upload, jwt, oauth, prototype, deserialize
SEVERITY (descending): Critical > High > Medium > Low

Returns: total count, per-category breakdown, severity distribution, 5 sample payloads.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"category": map[string]any{
						"type":        "string",
						"description": "Filter by specific attack category. Leave empty to see all categories.",
						"enum":        []string{"sqli", "xss", "traversal", "auth", "ssrf", "ssti", "cmdi", "xxe", "nosqli", "graphql", "cors", "crlf", "redirect", "upload", "jwt", "oauth", "prototype", "deserialize"},
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Filter by minimum severity level. Only payloads at this severity or higher are returned.",
						"enum":        []string{"Critical", "High", "Medium", "Low"},
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(false),
				Title:          "List Attack Payloads",
			},
		},
		s.handleListPayloads,
	)
}

type listPayloadsArgs struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
}

type payloadSummary struct {
	Summary        string         `json:"summary"`
	TotalPayloads  int            `json:"total_payloads"`
	TotalAvailable int            `json:"total_available"`
	Categories     int            `json:"categories"`
	ByCategory     map[string]int `json:"by_category"`
	BySeverity     map[string]int `json:"by_severity"`
	FilterApplied  string         `json:"filter_applied,omitempty"`
	CategoryInfo   *categoryMeta  `json:"category_info,omitempty"`
	SamplePayloads []sampleEntry  `json:"sample_payloads,omitempty"`
	UnifiedTotal   int            `json:"unified_total,omitempty"`
	NucleiExtra    int            `json:"nuclei_extra,omitempty"`
	NextSteps      []string       `json:"next_steps"`
}

type sampleEntry struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Snippet  string   `json:"snippet"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

func (s *Server) handleListPayloads(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args listPayloadsArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v. Expected optional 'category' (string) and 'severity' (string).", err)), nil
	}

	// Load from unified engine (JSON + Nuclei templates)
	provider := payloadprovider.NewProvider(s.config.PayloadDir, s.config.TemplateDir)
	if err := provider.Load(); err != nil {
		return errorResult(fmt.Sprintf("failed to load payloads from %s: %v. Verify the payload directory exists and contains JSON files.", s.config.PayloadDir, err)), nil
	}

	all, err := provider.JSONPayloads()
	if err != nil {
		return errorResult(fmt.Sprintf("failed to extract payloads: %v", err)), nil
	}

	// Enrich with Nuclei template payloads
	unified, _ := provider.GetAll()
	for _, up := range unified {
		if up.Source == payloadprovider.SourceNuclei {
			sev := up.Severity
			if sev == "" {
				sev = "Medium"
			}
			all = append(all, payloads.Payload{
				ID:            up.ID,
				Payload:       up.Payload,
				Category:      up.Category,
				Method:        up.Method,
				SeverityHint:  sev,
				ExpectedBlock: true,
				Tags:          up.Tags,
			})
		}
	}

	totalAvailable := len(all)

	filtered := payloads.Filter(all, args.Category, args.Severity)
	stats := payloads.GetStats(filtered)

	bySeverity := make(map[string]int)
	for _, p := range filtered {
		sev := p.SeverityHint
		if sev == "" {
			sev = "Unclassified"
		}
		bySeverity[sev]++
	}

	summary := payloadSummary{
		TotalPayloads:  stats.TotalPayloads,
		TotalAvailable: totalAvailable,
		Categories:     stats.CategoriesUsed,
		ByCategory:     stats.ByCategory,
		BySeverity:     bySeverity,
	}

	if args.Category != "" || args.Severity != "" {
		parts := make([]string, 0, 2)
		if args.Category != "" {
			parts = append(parts, "category="+args.Category)
		}
		if args.Severity != "" {
			parts = append(parts, "severity≥"+args.Severity)
		}
		summary.FilterApplied = strings.Join(parts, ", ")
	}

	// Add category metadata when filtering by category
	if args.Category != "" {
		if meta, ok := categoryDescriptions[strings.ToLower(args.Category)]; ok {
			summary.CategoryInfo = &meta
		}
	}

	// Include up to 10 sample payloads with rich details
	limit := 10
	if len(filtered) < limit {
		limit = len(filtered)
	}
	for _, p := range filtered[:limit] {
		snippet := p.Payload
		if len(snippet) > 120 {
			snippet = snippet[:120] + "…"
		}
		sev := p.SeverityHint
		if sev == "" {
			sev = "Unclassified"
		}
		summary.SamplePayloads = append(summary.SamplePayloads, sampleEntry{
			ID:       p.ID,
			Category: p.Category,
			Severity: sev,
			Snippet:  snippet,
			Tags:     p.Tags,
			Notes:    p.Notes,
		})
	}

	// Build narrative summary
	summary.Summary = buildListPayloadsSummary(args, stats, totalAvailable, bySeverity)

	// Report unified stats (payloads already include Nuclei)
	if uStats, err := provider.GetStats(); err == nil && uStats.NucleiPayloads > 0 {
		summary.UnifiedTotal = uStats.TotalPayloads
		summary.NucleiExtra = uStats.NucleiPayloads
	}

	// Build actionable next steps
	summary.NextSteps = buildListPayloadsNextSteps(args, stats)

	return jsonResult(summary)
}

// buildListPayloadsSummary generates a human/AI-readable narrative of the payload listing.
func buildListPayloadsSummary(args listPayloadsArgs, stats payloads.LoadStats, totalAvailable int, bySeverity map[string]int) string {
	var sb strings.Builder

	if stats.TotalPayloads == 0 {
		if args.Category != "" {
			fmt.Fprintf(&sb, "No payloads found for category '%s'", args.Category)
			if args.Severity != "" {
				fmt.Fprintf(&sb, " at severity '%s' or higher", args.Severity)
			}
			sb.WriteString(". ")
			if meta, ok := categoryDescriptions[strings.ToLower(args.Category)]; ok {
				fmt.Fprintf(&sb, "The '%s' category (%s) exists but may not have payloads in the current payload directory. ", args.Category, meta.Name)
			}
			fmt.Fprintf(&sb, "Total payloads available across all categories: %d. Try removing filters or checking the payload directory.", totalAvailable)
		} else {
			sb.WriteString("No payloads found in the payload directory. Verify the payload directory path is correct and contains JSON payload files.")
		}
		return sb.String()
	}

	if args.Category != "" {
		if meta, ok := categoryDescriptions[strings.ToLower(args.Category)]; ok {
			fmt.Fprintf(&sb, "Found %d %s (%s) payloads", stats.TotalPayloads, meta.Name, strings.ToUpper(args.Category))
		} else {
			fmt.Fprintf(&sb, "Found %d '%s' payloads", stats.TotalPayloads, args.Category)
		}
	} else {
		fmt.Fprintf(&sb, "Found %d total payloads across %d categories", stats.TotalPayloads, stats.CategoriesUsed)
	}

	if args.Severity != "" {
		fmt.Fprintf(&sb, " at severity '%s' or higher", args.Severity)
	}
	sb.WriteString(". ")

	// Severity breakdown
	if crit, ok := bySeverity["Critical"]; ok && crit > 0 {
		fmt.Fprintf(&sb, "%d Critical", crit)
		if high, ok := bySeverity["High"]; ok && high > 0 {
			fmt.Fprintf(&sb, ", %d High", high)
		}
		sb.WriteString(" severity. ")
	} else if high, ok := bySeverity["High"]; ok && high > 0 {
		fmt.Fprintf(&sb, "%d High severity. ", high)
	}

	fmt.Fprintf(&sb, "Showing %d samples out of %d total (%d available across all categories).",
		min(10, stats.TotalPayloads), stats.TotalPayloads, totalAvailable)

	return sb.String()
}

// buildListPayloadsNextSteps generates contextual next-step suggestions.
func buildListPayloadsNextSteps(args listPayloadsArgs, stats payloads.LoadStats) []string {
	steps := make([]string, 0, 4)

	if stats.TotalPayloads == 0 {
		steps = append(steps, "Try 'list_payloads' with no filters to see all available categories and payloads")
		steps = append(steps, "Check available categories: sqli, xss, traversal, auth, ssrf, ssti, cmdi, xxe, nosqli, graphql, cors, crlf, redirect, upload, jwt, oauth, prototype, deserialize")
		return steps
	}

	if args.Category != "" {
		steps = append(steps,
			fmt.Sprintf("Use 'scan' with {\"target\": \"https://your-target.com\", \"categories\": [\"%s\"]} to test these %d payloads against a WAF", args.Category, stats.TotalPayloads))
		steps = append(steps,
			fmt.Sprintf("Use 'mutate' to generate WAF-evasion variants of any payload above (e.g., URL encoding, Unicode, double-encoding)"))
		if args.Severity == "" {
			steps = append(steps,
				fmt.Sprintf("Filter by severity: {\"category\": \"%s\", \"severity\": \"Critical\"} to focus on the most dangerous payloads", args.Category))
		}
	} else {
		steps = append(steps,
			"Use 'scan' with {\"target\": \"https://your-target.com\"} to test ALL payloads against a WAF")
		steps = append(steps,
			"Filter by category (e.g., {\"category\": \"sqli\"}) to explore a specific attack type")
		steps = append(steps,
			"Use 'detect_waf' first to identify the WAF vendor, then run targeted scans")
	}

	steps = append(steps, "Use 'assess' for a full enterprise assessment with F1 score, false positive rate, and letter grade (A+ through F)")
	steps = append(steps, "Read 'waftester://payloads/unified' to see combined stats from JSON + Nuclei template sources")
	steps = append(steps, "Use 'waf-tester template --enrich' to inject JSON payloads into Nuclei templates for maximum coverage")

	return steps
}

// ═══════════════════════════════════════════════════════════════════════════
// detect_waf — WAF/CDN Detection & Fingerprinting
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addDetectWAFTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "detect_waf",
			Title: "Detect WAF/CDN",
			Description: `Fingerprint the WAF/CDN vendor protecting a target. This is step 1 of any engagement — run it FIRST.

USE THIS TOOL WHEN:
• Starting any new target — ALWAYS detect the WAF before scanning or bypassing
• The user asks "what WAF is protecting this site?"
• You need vendor-specific bypass hints before running 'bypass' or 'scan'
• Verifying whether a target even has a WAF in front of it

DO NOT USE THIS TOOL WHEN:
• The user already told you the WAF vendor (skip straight to 'scan' or 'bypass')
• You want full attack surface mapping — use 'discover' instead
• You want TLS/header/infra details without WAF focus — use 'probe' instead

Sends ~20 benign probes + ~5 trigger requests. Very low impact. Takes 10-30 seconds.
Covers 26+ WAF vendors with header analysis, behavioral probing, and TLS fingerprinting.

EXAMPLE INPUTS:
• Basic detection: {"target": "https://example.com"}
• With custom timeout: {"target": "https://slow-site.com", "timeout": 30}

Returns: vendor name, confidence %, detection method, CDN info, and bypass tips.
Known vendors: Cloudflare, AWS WAF, Azure WAF, Akamai, Imperva, ModSecurity, Coraza, F5 BIG-IP, Fortinet, Barracuda, Sucuri, Google Cloud Armor, Wallarm, and more.

TYPICAL WORKFLOW: detect_waf → discover → learn → scan → bypass`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to detect WAF on. Must include scheme (https://example.com).",
						"format":      "uri",
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Detection timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     60,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Detect WAF/CDN",
			},
		},
		s.handleDetectWAF,
	)
}

type detectWAFArgs struct {
	Target  string `json:"target"`
	Timeout int    `json:"timeout"`
}

func (s *Server) handleDetectWAF(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args detectWAFArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	notifyProgress(ctx, req, 0, 100, "Starting WAF detection on "+args.Target)
	logToSession(ctx, req, logInfo, "Initiating WAF/CDN detection for "+args.Target)

	detector := waf.NewDetector(timeout)

	notifyProgress(ctx, req, 15, 100, "Analyzing response headers…")
	notifyProgress(ctx, req, 30, 100, "Running behavioral probes…")

	result, err := detector.Detect(ctx, args.Target)
	if err != nil {
		return enrichedError(
			fmt.Sprintf("WAF detection failed: %v", err),
			[]string{
				"Verify the target URL is reachable and includes the scheme (https://).",
				"Try with skip_verify=true if the target uses a self-signed certificate.",
				"Check network connectivity and DNS resolution for the target host.",
				"Use 'probe' to test basic connectivity before retrying detection.",
			}), nil
	}

	notifyProgress(ctx, req, 100, 100, "Detection complete")
	logToSession(ctx, req, logInfo, fmt.Sprintf("WAF detection complete for %s", args.Target))

	// Wrap result with rich summary and next steps
	wrapped := buildDetectWAFResponse(result, args.Target)
	return jsonResult(wrapped)
}

// detectWAFResponse wraps DetectionResult with narrative context for AI agents.
type detectWAFResponse struct {
	Summary   string               `json:"summary"`
	Result    *waf.DetectionResult `json:"result"`
	NextSteps []string             `json:"next_steps"`
}

func buildDetectWAFResponse(result *waf.DetectionResult, target string) *detectWAFResponse {
	resp := &detectWAFResponse{Result: result}

	var sb strings.Builder
	if !result.Detected {
		fmt.Fprintf(&sb, "No WAF detected on %s (confidence: %.0f%%). ", target, result.Confidence*100)
		sb.WriteString("The target may be unprotected, or the WAF uses stealth mode (no identifiable signatures).")
		resp.NextSteps = []string{
			fmt.Sprintf("Use 'scan' on %s to test if attacks are blocked despite no WAF signature being found.", target),
			fmt.Sprintf("Use 'discover' to map the full attack surface of %s.", target),
			"Use 'probe' to check TLS configuration and security headers.",
		}
		resp.Summary = sb.String()
		return resp
	}

	if len(result.WAFs) > 0 {
		w := result.WAFs[0]
		fmt.Fprintf(&sb, "Detected %s WAF (%s) on %s at %.0f%% confidence. ", w.Name, w.Vendor, target, w.Confidence*100)
		if w.Type != "" {
			fmt.Fprintf(&sb, "Type: %s. ", w.Type)
		}
		if len(w.BypassTips) > 0 {
			fmt.Fprintf(&sb, "Known bypass approaches: %s. ", strings.Join(w.BypassTips, "; "))
		}
		if len(result.WAFs) > 1 {
			names := make([]string, len(result.WAFs)-1)
			for i, ww := range result.WAFs[1:] {
				names[i] = ww.Name
			}
			fmt.Fprintf(&sb, "Also detected: %s. ", strings.Join(names, ", "))
		}
	} else {
		fmt.Fprintf(&sb, "WAF detected on %s at %.0f%% confidence but specific vendor could not be identified. ", target, result.Confidence*100)
	}

	if result.CDN != nil {
		fmt.Fprintf(&sb, "CDN: %s. ", result.CDN.Name)
	}

	resp.Summary = sb.String()

	// Build next steps
	steps := make([]string, 0, 4)
	steps = append(steps,
		fmt.Sprintf("Use 'discover' to map the full attack surface of %s.", target))
	steps = append(steps,
		fmt.Sprintf("Use 'scan' with specific categories to test WAF blocking against %s.", target))
	if len(result.WAFs) > 0 && len(result.WAFs[0].BypassTips) > 0 {
		steps = append(steps,
			"Use 'bypass' with known-blocked payloads to test the WAF-specific bypass techniques listed above.")
	}
	steps = append(steps,
		fmt.Sprintf("Use 'assess' for a full enterprise WAF grade with F1 score and false positive measurement on %s.", target))
	resp.NextSteps = steps

	return resp
}

// ═══════════════════════════════════════════════════════════════════════════
// discover — Endpoint & Attack Surface Discovery
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addDiscoverTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "discover",
			Title: "Discover Attack Surface",
			Description: `Map the full attack surface of a target — endpoints, parameters, technologies, secrets. This is the deep recon tool.

USE THIS TOOL WHEN:
• Starting a comprehensive assessment — run after 'detect_waf', before 'learn'
• The user says "find all endpoints" or "map the attack surface" or "discover what's there"
• You need to feed endpoint data into 'learn' to generate a targeted test plan
• Testing a complex app with APIs, forms, JS files, and multiple paths

DO NOT USE THIS TOOL WHEN:
• The user already has a specific URL endpoint to test — use 'scan' directly
• You only need quick infra info (TLS, headers) — use 'probe' instead
• You only need to identify the WAF vendor — use 'detect_waf' instead

Crawls the target using 9 discovery sources: robots.txt, sitemap.xml, JavaScript analysis, Wayback Machine, HTML forms, active path brute-forcing, service presets, API spec parsing, and link following. Takes 1-5 minutes.

EXAMPLE INPUTS:
• Basic discovery: {"target": "https://app.example.com"}
• Known service: {"target": "https://auth.example.com", "service": "authentik"}
• Deep crawl: {"target": "https://big-app.com", "max_depth": 5, "concurrency": 20}
• Self-signed cert: {"target": "https://internal.local", "skip_verify": true}
• Passive only: {"target": "https://prod.com", "disable_active": true}

SERVICE PRESETS: authentik, n8n, immich, webapp, intranet — adds known endpoint patterns.

Returns: endpoint list with methods/params, technologies, secrets found, WAF status, attack surface analysis.

TYPICAL WORKFLOW: detect_waf → discover → learn → scan`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to discover (e.g. https://app.example.com).",
						"format":      "uri",
					},
					"max_depth": map[string]any{
						"type":        "integer",
						"description": "Maximum crawl depth for link following.",
						"default":     3,
						"minimum":     1,
						"maximum":     10,
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Number of parallel discovery workers.",
						"default":     10,
						"minimum":     1,
						"maximum":     50,
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "HTTP request timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     60,
					},
					"service": map[string]any{
						"type":        "string",
						"description": "Application preset — adds known endpoint patterns.",
						"enum":        []string{"authentik", "n8n", "immich", "webapp", "intranet"},
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification (for self-signed certs).",
						"default":     false,
					},
					"disable_active": map[string]any{
						"type":        "boolean",
						"description": "Skip active path brute-forcing (passive discovery only).",
						"default":     false,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Discover Attack Surface",
			},
		},
		s.handleDiscover,
	)
}

type discoverArgs struct {
	Target        string `json:"target"`
	MaxDepth      int    `json:"max_depth"`
	Concurrency   int    `json:"concurrency"`
	Timeout       int    `json:"timeout"`
	Service       string `json:"service"`
	SkipVerify    bool   `json:"skip_verify"`
	DisableActive bool   `json:"disable_active"`
}

func (s *Server) handleDiscover(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args discoverArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://app.example.com\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	if args.MaxDepth <= 0 {
		args.MaxDepth = defaults.DepthMedium
	}
	if args.Concurrency <= 0 {
		args.Concurrency = defaults.ConcurrencyMedium
	}

	cfg := discovery.DiscoveryConfig{
		Target:        args.Target,
		Timeout:       timeout,
		MaxDepth:      args.MaxDepth,
		Concurrency:   args.Concurrency,
		SkipVerify:    args.SkipVerify,
		Service:       args.Service,
		DisableActive: args.DisableActive,
	}

	notifyProgress(ctx, req, 0, 100, "Starting discovery on "+args.Target)
	logToSession(ctx, req, logInfo, "Initiating attack surface discovery for "+args.Target)

	discoverer := discovery.NewDiscoverer(cfg)

	notifyProgress(ctx, req, 10, 100, "Probing target and checking WAF…")

	result, err := discoverer.Discover(ctx)
	if err != nil {
		return enrichedError(
			fmt.Sprintf("discovery failed: %v", err),
			[]string{
				"Check that the target URL is reachable and returns a valid HTTP response.",
				"Try increasing the timeout parameter (e.g., timeout=30).",
				"If the target uses a self-signed cert, set skip_verify=true.",
				"Use 'detect_waf' first to verify basic connectivity to the target.",
			}), nil
	}

	notifyProgress(ctx, req, 100, 100, "Discovery complete")
	logToSession(ctx, req, logInfo, fmt.Sprintf("Discovered %d endpoints for %s", len(result.Endpoints), args.Target))

	summary := buildDiscoverySummary(result)
	return jsonResult(summary)
}

type discoverySummary struct {
	Summary        string                         `json:"summary"`
	Target         string                         `json:"target"`
	EndpointCount  int                            `json:"endpoint_count"`
	WAFDetected    bool                           `json:"waf_detected"`
	WAFFingerprint string                         `json:"waf_fingerprint,omitempty"`
	Technologies   []string                       `json:"technologies,omitempty"`
	AttackSurface  *discovery.AttackSurface       `json:"attack_surface,omitempty"`
	Statistics     *discovery.DiscoveryStatistics `json:"statistics,omitempty"`
	TopEndpoints   []endpointPreview              `json:"top_endpoints,omitempty"`
	SecretsFound   int                            `json:"secrets_found"`
	NextSteps      []string                       `json:"next_steps"`
}

type endpointPreview struct {
	Path       string `json:"path"`
	Method     string `json:"method"`
	Category   string `json:"category,omitempty"`
	Parameters int    `json:"parameters,omitempty"`
}

func buildDiscoverySummary(r *discovery.DiscoveryResult) *discoverySummary {
	s := &discoverySummary{
		Target:         r.Target,
		EndpointCount:  len(r.Endpoints),
		WAFDetected:    r.WAFDetected,
		WAFFingerprint: r.WAFFingerprint,
		Technologies:   r.Technologies,
		AttackSurface:  &r.AttackSurface,
		Statistics:     &r.Statistics,
	}

	// Count total secrets across all categories
	for _, secrets := range r.Secrets {
		s.SecretsFound += len(secrets)
	}

	limit := 20
	if len(r.Endpoints) < limit {
		limit = len(r.Endpoints)
	}
	for _, ep := range r.Endpoints[:limit] {
		s.TopEndpoints = append(s.TopEndpoints, endpointPreview{
			Path:       ep.Path,
			Method:     ep.Method,
			Category:   ep.Category,
			Parameters: len(ep.Parameters),
		})
	}

	// Build narrative summary
	var sb strings.Builder
	fmt.Fprintf(&sb, "Discovered %d endpoints on %s. ", len(r.Endpoints), r.Target)
	if r.WAFDetected {
		fmt.Fprintf(&sb, "WAF detected: %s. ", r.WAFFingerprint)
	} else {
		sb.WriteString("No WAF detected. ")
	}
	if len(r.Technologies) > 0 {
		fmt.Fprintf(&sb, "Technologies: %s. ", strings.Join(r.Technologies, ", "))
	}
	if s.SecretsFound > 0 {
		fmt.Fprintf(&sb, "WARNING: %d exposed secrets found! ", s.SecretsFound)
	}
	paramCount := 0
	for _, ep := range r.Endpoints {
		paramCount += len(ep.Parameters)
	}
	if paramCount > 0 {
		fmt.Fprintf(&sb, "Total injectable parameters: %d. ", paramCount)
	}
	fmt.Fprintf(&sb, "Showing top %d endpoints.", limit)
	s.Summary = sb.String()

	// Build next steps
	steps := make([]string, 0, 4)
	steps = append(steps,
		"Use 'learn' with this discovery output to generate a prioritized, endpoint-aware test plan.")
	steps = append(steps,
		fmt.Sprintf("Use 'scan' on %s with specific categories to test WAF blocking.", r.Target))
	if !r.WAFDetected {
		steps = append(steps,
			fmt.Sprintf("Use 'detect_waf' on %s for deeper WAF fingerprinting — discovery WAF check is basic.", r.Target))
	}
	if s.SecretsFound > 0 {
		steps = append(steps,
			fmt.Sprintf("URGENT: %d secrets exposed — investigate and rotate immediately.", s.SecretsFound))
	}
	steps = append(steps,
		"Use 'probe' for detailed TLS and security header analysis.")
	s.NextSteps = steps

	return s
}

// ═══════════════════════════════════════════════════════════════════════════
// learn — Intelligent Test Plan Generation
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addLearnTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "learn",
			Title: "Generate Test Plan",
			Description: `Turn discovery results into a prioritized test plan. This is the brain between 'discover' and 'scan'.

USE THIS TOOL WHEN:
• You just ran 'discover' and need to generate a smart test plan
• The user wants an intelligent, endpoint-aware scan (not just blind payload spraying)
• You want to prioritize which endpoints to test first based on risk

DO NOT USE THIS TOOL WHEN:
• You want to scan a single known URL — use 'scan' directly with a category
• You haven't run 'discover' yet — run that first to get the input JSON
• You want WAF metrics/grades — use 'assess' instead

Takes raw discovery JSON and produces: endpoint-to-attack mappings, priority rankings (P1 auth/injection through P5 fuzzing), injection point identification (query, body, headers, cookies), custom payload selection per endpoint, and optimal concurrency settings.

EXAMPLE INPUTS:
• From discovery output: {"discovery_json": "<paste raw JSON from discover tool>"}

The input MUST be the raw JSON string output from the 'discover' tool. Pass it as a string, not an object.

Returns: test groups, endpoint tests, priorities, category mappings, recommendations.

TYPICAL WORKFLOW: detect_waf → discover → learn → scan`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"discovery_json": map[string]any{
						"type":        "string",
						"description": "JSON string containing discovery results from the 'discover' tool. Pass the raw JSON output.",
					},
				},
				"required": []string{"discovery_json"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Generate Test Plan",
			},
		},
		s.handleLearn,
	)
}

type learnArgs struct {
	DiscoveryJSON string `json:"discovery_json"`
}

func (s *Server) handleLearn(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args learnArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.DiscoveryJSON == "" {
		return errorResult("discovery_json is required. Run the 'discover' tool first and pass its JSON output here."), nil
	}

	var disc discovery.DiscoveryResult
	if err := json.Unmarshal([]byte(args.DiscoveryJSON), &disc); err != nil {
		return errorResult(fmt.Sprintf("invalid discovery JSON: %v. Pass the raw JSON output from the 'discover' tool.", err)), nil
	}

	notifyProgress(ctx, req, 0, 100, "Analyzing discovery results…")
	logToSession(ctx, req, logInfo, fmt.Sprintf("Generating test plan for %s (%d endpoints)", disc.Target, len(disc.Endpoints)))

	learner := learning.NewLearner(&disc, s.config.PayloadDir)

	notifyProgress(ctx, req, 30, 100, "Mapping endpoints to attack categories…")

	plan := learner.GenerateTestPlan()

	notifyProgress(ctx, req, 100, 100, "Test plan generated")
	logToSession(ctx, req, logInfo, fmt.Sprintf("Test plan ready: %d groups, %d endpoint tests", len(plan.TestGroups), len(plan.EndpointTests)))

	wrapped := buildLearnResponse(plan)
	return jsonResult(wrapped)
}

// learnResponse wraps TestPlan with narrative context for AI agents.
type learnResponse struct {
	Summary   string             `json:"summary"`
	Plan      *learning.TestPlan `json:"plan"`
	NextSteps []string           `json:"next_steps"`
}

func buildLearnResponse(plan *learning.TestPlan) *learnResponse {
	resp := &learnResponse{Plan: plan}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Generated test plan for %s: %d test groups, %d endpoint-specific tests, ~%d total payloads. ",
		plan.Target, len(plan.TestGroups), len(plan.EndpointTests), plan.TotalTests)
	fmt.Fprintf(&sb, "Estimated time: %s. ", plan.EstimatedTime)

	// Highlight high-priority groups
	var p1Groups []string
	for _, g := range plan.TestGroups {
		if g.Priority <= 2 {
			p1Groups = append(p1Groups, g.Category)
		}
	}
	if len(p1Groups) > 0 {
		fmt.Fprintf(&sb, "High-priority categories: %s. ", strings.Join(p1Groups, ", "))
	}

	resp.Summary = sb.String()

	// Build next steps
	steps := make([]string, 0, 4)
	if len(plan.RecommendedFlags.Categories) > 0 {
		steps = append(steps,
			fmt.Sprintf("Use 'scan' with {\"target\": \"%s\", \"categories\": %v} to execute the test plan.",
				plan.Target, plan.RecommendedFlags.Categories))
	} else {
		steps = append(steps,
			fmt.Sprintf("Use 'scan' on %s to execute the test plan with all recommended categories.", plan.Target))
	}
	steps = append(steps,
		fmt.Sprintf("Set concurrency=%d, rate_limit=%d, timeout=%ds as recommended by the test plan.",
			plan.RecommendedFlags.Concurrency, plan.RecommendedFlags.RateLimit, plan.RecommendedFlags.Timeout))
	steps = append(steps,
		fmt.Sprintf("Use 'assess' on %s for a full enterprise assessment with formal grading after the scan.", plan.Target))
	if len(plan.RecommendedFlags.FocusAreas) > 0 {
		steps = append(steps,
			fmt.Sprintf("Focus areas identified: %s", strings.Join(plan.RecommendedFlags.FocusAreas, ", ")))
	}
	resp.NextSteps = steps

	return resp
}

// ═══════════════════════════════════════════════════════════════════════════
// scan — WAF Security Scan
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addScanTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "scan",
			Title: "WAF Security Scan",
			Description: `Fire attack payloads at a target and see what the WAF blocks vs. lets through. This is the core scanning tool.

Bundled templates are available in templates/policies/ and templates/overrides/. Read waftester://templates to see all options.

USE THIS TOOL WHEN:
• The user says "scan this", "test this URL", or "check if the WAF blocks SQLi"
• You want to test specific attack categories against a known URL
• You need a detection rate (% of attacks blocked) for a specific endpoint
• Running targeted tests after 'discover' + 'learn' identified interesting endpoints
• Quick validation: "does the WAF block XSS on /search?q=" — yes, use this

DO NOT USE THIS TOOL WHEN:
• You need formal WAF grades/metrics (F1, MCC, FPR) — use 'assess' instead
• You want to find bypass VARIANTS via encoding/mutation — use 'bypass' instead
• You want to just encode a payload without testing it — use 'mutate' instead
• You want to browse available payloads — use 'list_payloads' instead

'scan' vs 'assess': scan gives you a detection rate and bypass list. assess gives you enterprise metrics (F1 score, false positive rate, MCC, letter grade). Use scan for quick checks, assess for formal reports.
'scan' vs 'bypass': scan tests known payloads as-is. bypass applies the full mutation matrix (encoders x locations x evasions) to find WAF-evading variants.

EXAMPLE INPUTS:
• Quick SQLi scan: {"target": "https://example.com/search?q=test", "categories": ["sqli"]}
• SQLi + XSS: {"target": "https://app.example.com", "categories": ["sqli", "xss"]}
• All categories: {"target": "https://example.com"}
• Critical only: {"target": "https://prod.com", "severity": "Critical", "rate_limit": 20}
• Through Burp proxy: {"target": "https://example.com", "proxy": "http://127.0.0.1:8080"}
• Production-safe: {"target": "https://prod.com", "concurrency": 5, "rate_limit": 10}

RESULT MEANINGS:
• "Blocked" = WAF stopped the attack (good)
• "Fail" = attack reached the app (BAD — this is a bypass)
• "Error" = network issue (investigate connectivity)

Returns: detection rate, total/blocked/failed counts, bypass details with reproduction info, latency stats.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to scan (e.g. https://example.com/search?q=test).",
						"format":      "uri",
					},
					"categories": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Payload categories to test. Empty means all. Examples: [\"sqli\", \"xss\", \"traversal\"].",
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Minimum severity level to test.",
						"enum":        []string{"Critical", "High", "Medium", "Low"},
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Number of concurrent workers.",
						"default":     10,
						"minimum":     1,
						"maximum":     100,
					},
					"rate_limit": map[string]any{
						"type":        "integer",
						"description": "Maximum requests per second.",
						"default":     50,
						"minimum":     1,
						"maximum":     1000,
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "HTTP request timeout in seconds.",
						"default":     5,
						"minimum":     1,
						"maximum":     60,
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification.",
						"default":     false,
					},
					"proxy": map[string]any{
						"type":        "string",
						"description": "Proxy URL for requests (e.g. http://127.0.0.1:8080 for Burp Suite).",
						"format":      "uri",
					},
					"policy": map[string]any{
						"type":        "string",
						"description": "Path to a policy YAML file (e.g. templates/policies/standard.yaml). Controls exit code and grading threshold.",
					},
					"overrides": map[string]any{
						"type":        "string",
						"description": "Path to an overrides YAML file (e.g. templates/overrides/api-only.yaml). Customizes scan behavior for specific targets.",
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    false,
				IdempotentHint:  false,
				OpenWorldHint:   boolPtr(true),
				DestructiveHint: boolPtr(false),
				Title:           "WAF Security Scan",
			},
		},
		s.handleScan,
	)
}

type scanArgs struct {
	Target      string   `json:"target"`
	Categories  []string `json:"categories"`
	Severity    string   `json:"severity"`
	Concurrency int      `json:"concurrency"`
	RateLimit   int      `json:"rate_limit"`
	Timeout     int      `json:"timeout"`
	SkipVerify  bool     `json:"skip_verify"`
	Proxy       string   `json:"proxy"`
}

type scanResultSummary struct {
	Summary        string                   `json:"summary"`
	Target         string                   `json:"target"`
	DetectionRate  string                   `json:"detection_rate"`
	Interpretation string                   `json:"interpretation"`
	Results        *output.ExecutionResults `json:"results"`
	NextSteps      []string                 `json:"next_steps"`
}

func (s *Server) handleScan(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args scanArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	if args.Concurrency <= 0 {
		args.Concurrency = defaults.ConcurrencyMedium
	}
	if args.RateLimit <= 0 {
		args.RateLimit = 50
	}
	if args.Timeout <= 0 {
		args.Timeout = 5
	}

	notifyProgress(ctx, req, 0, 100, "Loading payloads…")
	logToSession(ctx, req, logInfo, fmt.Sprintf("Starting scan on %s (concurrency=%d, rate=%d/s)", args.Target, args.Concurrency, args.RateLimit))

	// Load from unified engine (JSON + Nuclei templates)
	provider := payloadprovider.NewProvider(s.config.PayloadDir, s.config.TemplateDir)
	if err := provider.Load(); err != nil {
		return enrichedError(
			fmt.Sprintf("failed to load payloads: %v", err),
			[]string{
				"Verify the payload directory exists and contains JSON payload files.",
				"Use 'list_payloads' to check available categories before scanning.",
				"Check file permissions on the payload directory.",
			}), nil
	}

	all, err := provider.JSONPayloads()
	if err != nil {
		return enrichedError(
			fmt.Sprintf("failed to extract payloads: %v", err),
			[]string{
				"Verify the payload directory contains valid JSON payload files.",
			}), nil
	}

	// Enrich with Nuclei template payloads converted to payloads.Payload format
	unified, _ := provider.GetAll()
	for _, up := range unified {
		if up.Source == payloadprovider.SourceNuclei {
			sev := up.Severity
			if sev == "" {
				sev = "Medium"
			}
			all = append(all, payloads.Payload{
				ID:            up.ID,
				Payload:       up.Payload,
				Category:      up.Category,
				Method:        up.Method,
				SeverityHint:  sev,
				ExpectedBlock: true,
				Tags:          up.Tags,
			})
		}
	}

	var filtered []payloads.Payload
	if len(args.Categories) > 0 {
		catSet := make(map[string]bool)
		for _, c := range args.Categories {
			catSet[strings.ToLower(c)] = true
		}
		for _, p := range all {
			if catSet[strings.ToLower(p.Category)] {
				filtered = append(filtered, p)
			}
		}
	} else {
		filtered = all
	}

	if args.Severity != "" {
		filtered = payloads.Filter(filtered, "", args.Severity)
	}

	if len(filtered) == 0 {
		return errorResult("no payloads match the specified filters. Try broadening the category or severity, or check that the payload directory contains files."), nil
	}

	notifyProgress(ctx, req, 10, 100, fmt.Sprintf("Loaded %d payloads, scanning…", len(filtered)))

	total := len(filtered)
	var received atomic.Int64
	var bypasses atomic.Int64

	executor := core.NewExecutor(core.ExecutorConfig{
		TargetURL:   args.Target,
		Concurrency: args.Concurrency,
		RateLimit:   args.RateLimit,
		Timeout:     time.Duration(args.Timeout) * time.Second,
		SkipVerify:  args.SkipVerify,
		Proxy:       args.Proxy,
		OnResult: func(r *output.TestResult) {
			n := received.Add(1)
			if r.Outcome == "Fail" {
				bypasses.Add(1)
				logToSession(ctx, req, logWarning,
					fmt.Sprintf("BYPASS: %s [%s] → %d", r.ID, r.Category, r.StatusCode))
			}
			if n%10 == 0 || n == int64(total) {
				pct := float64(n) / float64(total) * 80
				notifyProgress(ctx, req, 10+pct, 100,
					fmt.Sprintf("Tested %d/%d (bypasses: %d)…", n, total, bypasses.Load()))
			}
		},
	})

	execResults := executor.Execute(ctx, filtered, &discardWriter{})

	notifyProgress(ctx, req, 95, 100, "Generating summary…")

	// Calculate detection rate
	detectionRate := ""
	tested := execResults.BlockedTests + execResults.FailedTests
	if tested > 0 {
		rate := float64(execResults.BlockedTests) / float64(tested) * 100
		detectionRate = fmt.Sprintf("%.1f%%", rate)
	}

	summary := &scanResultSummary{
		Target:        args.Target,
		DetectionRate: detectionRate,
		Results:       &execResults,
	}

	// Build interpretation based on detection rate
	if tested > 0 {
		rate := float64(execResults.BlockedTests) / float64(tested) * 100
		switch {
		case rate >= 95:
			summary.Interpretation = fmt.Sprintf("Excellent WAF coverage (%.1f%%). The WAF blocked %d of %d attack payloads. Very few bypasses detected.", rate, execResults.BlockedTests, tested)
		case rate >= 85:
			summary.Interpretation = fmt.Sprintf("Good WAF coverage (%.1f%%), but %d payloads bypassed detection. Review the bypass details below and consider adding custom rules.", rate, execResults.FailedTests)
		case rate >= 70:
			summary.Interpretation = fmt.Sprintf("Moderate WAF coverage (%.1f%%). %d payloads bypassed the WAF — significant gaps exist that need rule tuning.", rate, execResults.FailedTests)
		case rate >= 50:
			summary.Interpretation = fmt.Sprintf("Weak WAF coverage (%.1f%%). %d of %d payloads bypassed detection. The WAF needs major rule updates or reconfiguration.", rate, execResults.FailedTests, tested)
		default:
			summary.Interpretation = fmt.Sprintf("Critical: WAF is largely ineffective (%.1f%% detection). %d of %d payloads bypassed. Consider the WAF misconfigured or disabled for this endpoint.", rate, execResults.FailedTests, tested)
		}
	}

	// Build contextual summary
	summary.Summary = fmt.Sprintf("Scanned %s with %d payloads. Detection rate: %s. Blocked: %d, Bypassed: %d, Errors: %d.",
		args.Target, execResults.TotalTests, detectionRate, execResults.BlockedTests, execResults.FailedTests, execResults.ErrorTests)

	// Build next steps based on results
	summary.NextSteps = buildScanNextSteps(execResults, args)

	notifyProgress(ctx, req, 100, 100, fmt.Sprintf("Scan complete — %d bypasses found", execResults.FailedTests))
	logToSession(ctx, req, logInfo, fmt.Sprintf("Scan finished: %d tested, %d blocked, %d bypassed, detection rate: %s",
		execResults.TotalTests, execResults.BlockedTests, execResults.FailedTests, detectionRate))

	return jsonResult(summary)
}

// discardWriter implements output.Writer and discards all results.
// Used when results are collected via the OnResult callback instead.
type discardWriter struct{}

func (w *discardWriter) Write(_ *output.TestResult) error { return nil }
func (w *discardWriter) Close() error                     { return nil }

// buildScanNextSteps generates contextual next steps based on scan results.
func buildScanNextSteps(results output.ExecutionResults, args scanArgs) []string {
	steps := make([]string, 0, 4)

	if results.FailedTests > 0 {
		steps = append(steps,
			fmt.Sprintf("CRITICAL: %d bypasses found. Use 'bypass' tool to test WAF-evasion mutations against %s and discover additional bypass variants.", results.FailedTests, args.Target))
		steps = append(steps,
			"Use 'mutate' with the bypassed payloads to generate encoded variants (URL, double-URL, Unicode, HTML hex) for deeper testing.")
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for a formal enterprise assessment with F1 score, false positive rate, MCC, and letter grade.", args.Target))
	} else if results.BlockedTests > 0 {
		steps = append(steps,
			fmt.Sprintf("All %d payloads were blocked — excellent WAF coverage for these categories.", results.BlockedTests))
		steps = append(steps,
			fmt.Sprintf("Use 'bypass' to test mutation-based evasions (encoding × location × technique) — WAF may miss encoded variants."))
		if len(args.Categories) > 0 {
			steps = append(steps,
				"Run 'scan' with additional categories to broaden coverage (try adding 'ssrf', 'ssti', 'cmdi', 'xxe').")
		}
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for enterprise metrics including false positive measurement.", args.Target))
	}

	if results.ErrorTests > 0 {
		steps = append(steps,
			fmt.Sprintf("%d errors occurred — check network connectivity, reduce rate_limit, or increase timeout.", results.ErrorTests))
	}

	return steps
}

// ═══════════════════════════════════════════════════════════════════════════
// assess — Enterprise WAF Assessment
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addAssessTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "assess",
			Title: "Enterprise WAF Assessment",
			Description: `Enterprise-grade WAF scoring with letter grades, F1/MCC metrics, and false positive measurement. The formal assessment tool.

USE THIS TOOL WHEN:
• The user asks for a "WAF assessment", "WAF grade", or "WAF score"
• You need quantitative metrics: F1 score, MCC, false positive rate, detection rate
• Producing a formal report or compliance artifact
• Comparing WAF vendors or configurations side-by-side
• The user wants a letter grade (A through F) for their WAF

DO NOT USE THIS TOOL WHEN:
• Quick check on a single category — use 'scan' instead (much faster)
• Looking for bypass variants via encoding — use 'bypass' instead
• Just need to identify the WAF vendor — use 'detect_waf' instead

'assess' vs 'scan': assess runs a full rubric across all categories, measures false positives using a benign corpus, computes F1/MCC/FPR, and assigns a letter grade. scan just fires payloads and reports pass/fail. Use assess for formal evaluations, scan for targeted checks.

EXAMPLE INPUTS:
• Standard assessment: {"target": "https://example.com"}
• Specific categories: {"target": "https://example.com", "categories": ["sqli", "xss", "cmdi"]}
• Skip false-positive testing (faster): {"target": "https://example.com", "enable_fp_testing": false}
• Conservative (production): {"target": "https://prod.com", "rate_limit": 10, "concurrency": 3}

GRADING RUBRIC: A+ (>97%) → A (>93%) → B (>85%) → C (>70%) → D (>50%) → F (<50%)
METRICS: Detection Rate, F1 Score (precision×recall balance), MCC (Matthews Correlation), FPR (false positive rate)

Returns: letter grade, category scores, F1/MCC/FPR metrics, bypass list, per-category breakdown, improvement recommendations.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to assess.",
						"format":      "uri",
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Concurrent workers.",
						"default":     25,
						"minimum":     1,
						"maximum":     100,
					},
					"rate_limit": map[string]any{
						"type":        "integer",
						"description": "Maximum requests per second.",
						"default":     100,
						"minimum":     1,
						"maximum":     500,
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Request timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     60,
					},
					"categories": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Attack categories to test. Empty means all.",
					},
					"enable_fp_testing": map[string]any{
						"type":        "boolean",
						"description": "Enable false positive testing with benign corpus.",
						"default":     true,
					},
					"detect_waf": map[string]any{
						"type":        "boolean",
						"description": "Auto-detect WAF vendor before testing.",
						"default":     true,
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification.",
						"default":     false,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				OpenWorldHint:   boolPtr(true),
				DestructiveHint: boolPtr(false),
				Title:           "Enterprise WAF Assessment",
			},
		},
		s.handleAssess,
	)
}

type assessArgs struct {
	Target          string   `json:"target"`
	Concurrency     int      `json:"concurrency"`
	RateLimit       int      `json:"rate_limit"`
	Timeout         int      `json:"timeout"`
	Categories      []string `json:"categories"`
	EnableFPTesting *bool    `json:"enable_fp_testing"`
	DetectWAF       *bool    `json:"detect_waf"`
	SkipVerify      bool     `json:"skip_verify"`
}

func (s *Server) handleAssess(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args assessArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	cfg := assessment.DefaultConfig()
	cfg.TargetURL = args.Target
	cfg.PayloadDir = s.config.PayloadDir
	cfg.SkipTLSVerify = args.SkipVerify
	cfg.OutputFormat = "json"

	if args.Concurrency > 0 {
		cfg.Concurrency = args.Concurrency
	}
	if args.RateLimit > 0 {
		cfg.RateLimit = float64(args.RateLimit)
	}
	if args.Timeout > 0 {
		cfg.Timeout = time.Duration(args.Timeout) * time.Second
	}
	if len(args.Categories) > 0 {
		cfg.Categories = args.Categories
	}
	if args.EnableFPTesting != nil {
		cfg.EnableFPTesting = *args.EnableFPTesting
	}
	if args.DetectWAF != nil {
		cfg.DetectWAF = *args.DetectWAF
	}

	notifyProgress(ctx, req, 0, 100, "Starting enterprise assessment on "+args.Target)
	logToSession(ctx, req, logInfo, "Enterprise WAF assessment initiated for "+args.Target)

	a := assessment.New(cfg)

	progressFn := func(completed, total int64, phase string) {
		if total > 0 {
			pct := float64(completed) / float64(total) * 90
			notifyProgress(ctx, req, pct, 100, fmt.Sprintf("[%s] %d/%d", phase, completed, total))
		}
	}

	metrics, err := a.Run(ctx, progressFn)
	if err != nil {
		return enrichedError(
			fmt.Sprintf("assessment failed: %v", err),
			[]string{
				"Verify the target is reachable and not aggressively rate-limiting.",
				"Try reducing concurrency and rate_limit for sensitive targets.",
				"Use 'scan' first for a lighter test, then 'assess' for full metrics.",
				"Check if the target requires authentication or specific headers.",
			}), nil
	}

	notifyProgress(ctx, req, 100, 100, fmt.Sprintf("Assessment complete — Grade: %s", metrics.Grade))
	logToSession(ctx, req, logInfo, fmt.Sprintf("Assessment complete: Grade=%s, F1=%.3f, FPR=%.3f",
		metrics.Grade, metrics.F1Score, metrics.FalsePositiveRate))

	wrapped := buildAssessResponse(metrics, args.Target)
	return jsonResult(wrapped)
}

// assessResponse wraps EnterpriseMetrics with narrative context for AI agents.
type assessResponse struct {
	Summary        string                     `json:"summary"`
	Interpretation string                     `json:"interpretation"`
	Metrics        *metrics.EnterpriseMetrics `json:"metrics"`
	NextSteps      []string                   `json:"next_steps"`
}

func buildAssessResponse(m *metrics.EnterpriseMetrics, target string) *assessResponse {
	resp := &assessResponse{Metrics: m}

	var sb strings.Builder
	fmt.Fprintf(&sb, "WAF Assessment for %s: Grade %s. ", target, m.Grade)
	fmt.Fprintf(&sb, "Detection Rate: %.1f%%, F1 Score: %.3f, MCC: %.3f, False Positive Rate: %.1f%%. ",
		m.DetectionRate*100, m.F1Score, m.MCC, m.FalsePositiveRate*100)
	if m.GradeReason != "" {
		sb.WriteString(m.GradeReason)
	}
	resp.Summary = sb.String()

	// Build interpretation based on grade — direct field access, no JSON round-trip.
	switch {
	case m.Grade == "A+" || m.Grade == "A":
		resp.Interpretation = fmt.Sprintf("Excellent WAF performance (Grade %s). The WAF demonstrates strong detection across tested categories with a well-balanced precision-recall tradeoff. F1=%.3f indicates minimal false negatives. FPR=%.1f%% means legitimate traffic is rarely blocked.",
			m.Grade, m.F1Score, m.FalsePositiveRate*100)
	case m.Grade == "B":
		resp.Interpretation = fmt.Sprintf("Good WAF performance (Grade %s) with room for improvement. Some attack categories may have gaps. Review per-category scores to identify weak areas. F1=%.3f, FPR=%.1f%%.",
			m.Grade, m.F1Score, m.FalsePositiveRate*100)
	case m.Grade == "C":
		resp.Interpretation = fmt.Sprintf("Moderate WAF performance (Grade %s). Significant gaps in detection exist. Review bypassed payloads and consider rule tuning or switching to a more comprehensive ruleset (e.g., CRS 4.x for ModSecurity/Coraza).", m.Grade)
	case m.Grade == "D" || m.Grade == "F":
		resp.Interpretation = fmt.Sprintf("Poor WAF performance (Grade %s). The WAF is failing to block a majority of attacks. This indicates misconfiguration, disabled rules, or an inadequate ruleset. Immediate action required.", m.Grade)
	default:
		resp.Interpretation = fmt.Sprintf("WAF Grade: %s. Review the per-category breakdown for detailed analysis.", m.Grade)
	}

	// Build next steps based on grade
	steps := make([]string, 0, 5)
	if m.Grade == "D" || m.Grade == "F" || m.Grade == "C" {
		steps = append(steps,
			"PRIORITY: Review bypassed payloads in the per-category breakdown and add custom WAF rules for each bypass pattern.")
		steps = append(steps,
			"Use 'bypass' with specific payloads that were blocked to test if encoding variants can still evade the WAF.")
	}
	if m.FalsePositiveRate > 0.05 {
		steps = append(steps,
			fmt.Sprintf("WARNING: False positive rate is %.1f%% (%.1f%% of legitimate requests blocked). Review and tune WAF rules to reduce false positives.",
				m.FalsePositiveRate*100, m.FalsePositiveRate*100))
	}
	steps = append(steps,
		fmt.Sprintf("Use 'scan' with specific categories (e.g., {\"target\": \"%s\", \"categories\": [\"sqli\"]}) to drill into weak areas.", target))
	steps = append(steps,
		"Use 'generate_cicd' to set up automated regression testing and track WAF grade over time.")
	steps = append(steps,
		"Re-run 'assess' after rule changes to measure improvement.")
	resp.NextSteps = steps

	return resp
}

// ═══════════════════════════════════════════════════════════════════════════
// mutate — Payload Mutation & Encoding
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addMutateTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "mutate",
			Title: "Mutate Payloads",
			Description: `Encode a payload string into WAF-evasion variants — URL, double-URL, Unicode, HTML hex. Offline encoding, no network traffic.

USE THIS TOOL WHEN:
• A payload was blocked and the user wants to see how it looks in different encodings
• The user says "encode this", "mutate this payload", or "show me evasion variants"
• Inspecting what the mutation matrix would produce before testing live with 'bypass'
• Preparing payloads for manual testing in Burp Suite or curl

DO NOT USE THIS TOOL WHEN:
• You want to also TEST the mutations against a WAF — use 'bypass' instead (it mutates AND tests)
• You want to scan a target — use 'scan' instead
• You want to browse the payload catalog — use 'list_payloads' instead

'mutate' vs 'bypass': mutate is offline — it shows you what the encodings look like. bypass is online — it encodes AND fires them at a target to find what passes. mutate = preview, bypass = execute.

EXAMPLE INPUTS:
• URL-encode a SQLi payload: {"payload": "' OR 1=1--", "encoders": ["url"]}
• Try multiple encodings: {"payload": "<script>alert(1)</script>", "encoders": ["url", "double_url", "unicode", "html_hex"]}
• All available encoders: {"payload": "{{7*7}}"}
• HTML hex encoding: {"payload": "<img src=x onerror=alert(1)>", "encoders": ["html_hex"]}

AVAILABLE ENCODERS: url, double_url, unicode, html_hex
If encoders is omitted, ALL are applied.

Returns: list of {encoder, encoded_payload} pairs ready for copy-paste testing.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"payload": map[string]any{
						"type":        "string",
						"description": "The attack payload string to mutate (e.g. \"' OR 1=1--\").",
					},
					"encoders": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "string",
							"enum": []string{"url", "double_url", "unicode", "html_hex"},
						},
						"description": "Encoders to apply. Default: all available encoders.",
					},
				},
				"required": []string{"payload"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Mutate Payloads",
			},
		},
		s.handleMutate,
	)
}

type mutateArgs struct {
	Payload  string   `json:"payload"`
	Encoders []string `json:"encoders"`
}

type mutateResult struct {
	Summary   string          `json:"summary"`
	Original  string          `json:"original"`
	Variants  []mutateVariant `json:"variants"`
	Count     int             `json:"count"`
	Tip       string          `json:"tip"`
	NextSteps []string        `json:"next_steps"`
}

type mutateVariant struct {
	Encoder string `json:"encoder"`
	Encoded string `json:"encoded"`
}

func (s *Server) handleMutate(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args mutateArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Payload == "" {
		return errorResult("payload is required. Example: {\"payload\": \"' OR 1=1--\"}"), nil
	}

	variants := applyBasicEncodings(args.Payload, args.Encoders)

	encoderList := make([]string, len(variants))
	for i, v := range variants {
		encoderList[i] = v.Encoder
	}

	result := mutateResult{
		Summary:  fmt.Sprintf("Generated %d encoded variants of the payload using: %s. Each variant applies a different encoding to bypass WAF pattern matching.", len(variants), strings.Join(encoderList, ", ")),
		Original: args.Payload,
		Variants: variants,
		Count:    len(variants),
		Tip:      "If double_url bypasses the WAF, it only decodes once. If unicode or html_hex bypasses, the WAF lacks multi-encoding support. Use the 'bypass' tool for automated testing of all mutations against a live target.",
		NextSteps: []string{
			fmt.Sprintf("Use 'bypass' with {\"target\": \"https://your-target.com\", \"payloads\": [\"%s\"]} to test all mutations against a live WAF.", args.Payload),
			"Copy individual variants above into Burp Suite Repeater or curl for manual verification.",
			"Try combining encodings: URL-encode a Unicode variant, or double-encode HTML hex — WAFs often fail on multi-layer encoding.",
			"Use 'list_payloads' to find more payloads in the same attack category for broader testing.",
		},
	}

	return jsonResult(result)
}

// applyBasicEncodings applies common encoding transformations to a payload.
func applyBasicEncodings(payload string, encoders []string) []mutateVariant {
	if len(encoders) == 0 {
		encoders = []string{"url", "double_url", "unicode", "html_hex"}
	}

	encSet := make(map[string]bool)
	for _, e := range encoders {
		encSet[strings.ToLower(e)] = true
	}

	var variants []mutateVariant

	if encSet["url"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "%%%02X", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "url", Encoded: sb.String()})
	}

	if encSet["double_url"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				hex := fmt.Sprintf("%%%02X", r)
				for _, c := range hex {
					if c == '%' {
						sb.WriteString("%25")
					} else {
						sb.WriteRune(c)
					}
				}
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "double_url", Encoded: sb.String()})
	}

	if encSet["unicode"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "\\u%04X", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "unicode", Encoded: sb.String()})
	}

	if encSet["html_hex"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "&#x%X;", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "html_hex", Encoded: sb.String()})
	}

	return variants
}

func shouldURLEncode(r rune) bool {
	switch r {
	case '<', '>', '\'', '"', '(', ')', '{', '}', '[', ']', ';', '|', '&', '=', ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// bypass — WAF Bypass Discovery
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addBypassTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "bypass",
			Title: "WAF Bypass Finder",
			Description: `Hunt for WAF bypasses by testing payload mutations against a live target. The mutation matrix engine.

USE THIS TOOL WHEN:
• A 'scan' found blocks and now you want encoding/mutation variants that evade the WAF
• The user says "find bypasses", "evade the WAF", or "can we get past the rules?"
• Red team engagement — you need to prove exploitability, not just detect coverage
• Testing a specific rule: "bypass the SQLi detection"

DO NOT USE THIS TOOL WHEN:
• You haven't scanned yet — use 'scan' first to establish a baseline
• You just want to SEE encoded variants without testing — use 'mutate' instead
• You want a WAF grade — use 'assess' instead

'bypass' vs 'scan': scan fires known payloads as-is. bypass takes payloads, generates mutations (encoder x location x evasion), and tests each one to find what the WAF misses. bypass is heavier, slower, and more thorough.
'bypass' vs 'mutate': mutate shows you the encodings offline. bypass encodes AND fires them at the target to find actual bypasses.

Mutation Matrix: For each payload, bypass tries multiple encoders (url, double_url, html_hex, unicode, hex) x injection locations (query_param, post_form, post_json, header, cookie, path) x evasion techniques (case_swap, sql_comment, null_byte, whitespace, concat). This exponential combination is what finds bypasses.

EXAMPLE INPUTS:
• Hunt SQLi bypasses: {"target": "https://example.com/search?q=test", "payloads": ["' OR 1=1--", "1 UNION SELECT null--"]}
• XSS bypass: {"target": "https://example.com", "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]}
• Stealth mode: {"target": "https://example.com", "payloads": ["' OR 1=1--"], "rate_limit": 5, "concurrency": 2}
• Self-signed cert: {"target": "https://internal.app", "payloads": ["{{7*7}}"], "skip_verify": true}

Returns: successful bypasses with exact payload + encoding + location, total mutations tested, bypass rate, reproduction details.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to test bypasses against.",
						"format":      "uri",
					},
					"payloads": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Attack payload strings to mutate and test. Example: [\"' OR 1=1--\", \"<script>alert(1)</script>\"].",
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Concurrent workers.",
						"default":     5,
						"minimum":     1,
						"maximum":     50,
					},
					"rate_limit": map[string]any{
						"type":        "integer",
						"description": "Maximum requests per second (keep low for stealth).",
						"default":     10,
						"minimum":     1,
						"maximum":     100,
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Request timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     60,
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification.",
						"default":     false,
					},
				},
				"required": []string{"target", "payloads"},
			},
			Annotations: &mcp.ToolAnnotations{
				OpenWorldHint:   boolPtr(true),
				DestructiveHint: boolPtr(false),
				Title:           "WAF Bypass Finder",
			},
		},
		s.handleBypass,
	)
}

type bypassArgs struct {
	Target      string   `json:"target"`
	Payloads    []string `json:"payloads"`
	Concurrency int      `json:"concurrency"`
	RateLimit   int      `json:"rate_limit"`
	Timeout     int      `json:"timeout"`
	SkipVerify  bool     `json:"skip_verify"`
}

func (s *Server) handleBypass(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bypassArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\", \"payloads\": [\"' OR 1=1--\"]}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}
	if len(args.Payloads) == 0 {
		return errorResult("at least one payload is required. Example: {\"payloads\": [\"' OR 1=1--\"]}"), nil
	}

	if args.Concurrency <= 0 {
		args.Concurrency = defaults.ConcurrencyLow
	}
	if args.RateLimit <= 0 {
		args.RateLimit = 10
	}
	if args.Timeout <= 0 {
		args.Timeout = 10
	}

	notifyProgress(ctx, req, 0, 100, fmt.Sprintf("Preparing bypass matrix for %d payloads…", len(args.Payloads)))
	logToSession(ctx, req, logInfo, fmt.Sprintf("Bypass testing %d payloads against %s", len(args.Payloads), args.Target))

	executor := mutation.NewExecutor(&mutation.ExecutorConfig{
		TargetURL:   args.Target,
		Concurrency: args.Concurrency,
		RateLimit:   float64(args.RateLimit),
		Timeout:     time.Duration(args.Timeout) * time.Second,
		SkipVerify:  args.SkipVerify,
	})

	notifyProgress(ctx, req, 10, 100, "Running mutation matrix…")

	result := executor.FindBypasses(ctx, args.Payloads)

	notifyProgress(ctx, req, 100, 100, fmt.Sprintf("Bypass testing complete — %d bypasses found", len(result.BypassPayloads)))
	logToSession(ctx, req, logInfo, fmt.Sprintf("Bypass results: %d/%d found bypasses", len(result.BypassPayloads), result.TotalTested))

	wrapped := buildBypassResponse(result, args)
	return jsonResult(wrapped)
}

// bypassResponse wraps WAFBypassResult with narrative context for AI agents.
type bypassResponse struct {
	Summary        string                    `json:"summary"`
	Interpretation string                    `json:"interpretation"`
	Result         *mutation.WAFBypassResult `json:"result"`
	NextSteps      []string                  `json:"next_steps"`
}

func buildBypassResponse(result *mutation.WAFBypassResult, args bypassArgs) *bypassResponse {
	resp := &bypassResponse{Result: result}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Tested %d mutation variants of %d payloads against %s. ", result.TotalTested, len(args.Payloads), args.Target)
	if result.Found {
		fmt.Fprintf(&sb, "FOUND %d bypasses (%.1f%% bypass rate). ", len(result.BypassPayloads), result.BypassRate)
		sb.WriteString("The WAF fails to detect mutated/encoded variants of the input payloads.")
	} else {
		sb.WriteString("No bypasses found — all mutation variants were blocked by the WAF.")
	}
	resp.Summary = sb.String()

	if result.Found {
		resp.Interpretation = fmt.Sprintf("The mutation matrix found %d WAF bypasses across %d total variants (%.1f%% bypass rate). Each bypass represents a specific encoder × injection location × evasion technique combination that the WAF fails to detect. These are actionable findings that indicate WAF rule gaps.",
			len(result.BypassPayloads), result.TotalTested, result.BypassRate)
	} else {
		resp.Interpretation = fmt.Sprintf("All %d mutation variants were blocked. The WAF has strong coverage against encoded/mutated variants of these payloads. Consider testing with different base payloads or categories.", result.TotalTested)
	}

	steps := make([]string, 0, 4)
	if result.Found {
		steps = append(steps,
			"CRITICAL: Report each bypass to the WAF administrator with the exact payload, encoding, and injection location.")
		steps = append(steps,
			"Use 'mutate' to inspect the successful bypass encodings in detail and understand why the WAF missed them.")
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for a comprehensive WAF grade that factors in these bypasses.", args.Target))
		steps = append(steps,
			"Use 'generate_cicd' to set up automated bypass regression testing so fixed rules don't regress.")
	} else {
		steps = append(steps,
			"Try different payload categories — the WAF may be weak against other attack types (e.g., 'ssti', 'ssrf', 'xxe').")
		steps = append(steps,
			"Use 'list_payloads' to browse the full catalog and select different attack vectors.")
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for an enterprise-grade WAF evaluation with formal metrics.", args.Target))
	}
	resp.NextSteps = steps

	return resp
}

// ═══════════════════════════════════════════════════════════════════════════
// probe — Infrastructure Probing
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addProbeTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "probe",
			Title: "Probe Infrastructure",
			Description: `Quick infra check — TLS config, security headers, server fingerprinting. No attack traffic. Read-only recon.

USE THIS TOOL WHEN:
• The user asks "is this site up?" or "what TLS version?" or "check security headers"
• You need to verify a target is reachable before scanning
• Fingerprinting the server (Apache, Nginx, IIS, etc.) or technology stack
• Checking HSTS, CSP, X-Frame-Options, or other security headers
• Quick tech recon without any invasive testing

DO NOT USE THIS TOOL WHEN:
• You need full attack surface mapping — use 'discover' instead (probe just reads headers)
• You need to identify the WAF vendor — use 'detect_waf' instead (probe doesn't do WAF fingerprinting)
• You want to test for vulnerabilities — use 'scan' or 'assess' instead

'probe' vs 'detect_waf': probe gives you TLS, headers, server info. detect_waf sends trigger requests to identify the WAF product. They are complementary but distinct.
'probe' vs 'discover': probe makes 1-2 requests and reads headers. discover crawls the entire site with 9 discovery sources. Scope difference: single page vs entire app.

EXAMPLE INPUTS:
• Basic probe: {"target": "https://example.com"}
• Self-signed cert: {"target": "https://internal.dev", "skip_verify": true}
• Slow target: {"target": "https://slow-site.com", "timeout": 30}

Returns: HTTP status, server header, TLS version + cipher suite, security headers (HSTS, CSP, etc.), response time, redirect chain, technology hints.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to probe (e.g. https://example.com).",
						"format":      "uri",
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Probe timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     30,
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification.",
						"default":     false,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Probe Infrastructure",
			},
		},
		s.handleProbe,
	)
}

type probeArgs struct {
	Target     string `json:"target"`
	Timeout    int    `json:"timeout"`
	SkipVerify bool   `json:"skip_verify"`
}

type probeReport struct {
	Target          string            `json:"target"`
	Reachable       bool              `json:"reachable"`
	StatusCode      int               `json:"status_code,omitempty"`
	Server          string            `json:"server,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	TLS             *probeTLSInfo     `json:"tls,omitempty"`
	SecurityHeaders []headerCheck     `json:"security_headers,omitempty"`
	RedirectChain   []string          `json:"redirect_chain,omitempty"`
	Error           string            `json:"error,omitempty"`
}

type probeTLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	Certificate string `json:"certificate,omitempty"`
	Expiry      string `json:"expiry,omitempty"`
}

type headerCheck struct {
	Header  string `json:"header"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Status  string `json:"status"` // "good" or "missing"
}

func (s *Server) handleProbe(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args probeArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	notifyProgress(ctx, req, 0, 100, "Probing "+args.Target+"…")
	report := probeTarget(ctx, args.Target, timeout, args.SkipVerify)
	notifyProgress(ctx, req, 100, 100, "Probe complete")

	wrapped := buildProbeResponse(report)
	return jsonResult(wrapped)
}

func probeTarget(ctx context.Context, target string, timeout time.Duration, skipVerify bool) *probeReport {
	report := &probeReport{
		Target:  target,
		Headers: make(map[string]string),
	}

	var redirectChain []string
	client := httpclient.New(httpclient.Config{
		Timeout:             timeout,
		InsecureSkipVerify:  skipVerify,
		TLSHandshakeTimeout: timeout,
	})
	client.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		redirectChain = append(redirectChain, r.URL.String())
		if len(redirectChain) > 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		report.Error = fmt.Sprintf("invalid URL: %v", err)
		return report
	}
	httpReq.Header.Set("User-Agent", defaults.UserAgent("probe"))

	resp, err := client.Do(httpReq)
	if err != nil {
		report.Error = fmt.Sprintf("request failed: %v", err)
		return report
	}
	defer func() {
		// Drain up to 4KB so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()

	report.Reachable = true
	report.StatusCode = resp.StatusCode
	report.Server = resp.Header.Get("Server")
	report.RedirectChain = redirectChain

	// Capture key fingerprinting headers
	for _, h := range []string{"Server", "X-Powered-By", "Via", "X-Cache", "CF-RAY", "X-Request-Id",
		"X-AspNet-Version", "X-Amzn-Trace-Id"} {
		if v := resp.Header.Get(h); v != "" {
			report.Headers[h] = v
		}
	}

	// TLS info
	if resp.TLS != nil {
		info := &probeTLSInfo{
			Version:     tlsVersionString(resp.TLS.Version),
			CipherSuite: tls.CipherSuiteName(resp.TLS.CipherSuite),
		}
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			info.Certificate = cert.Subject.CommonName
			info.Expiry = cert.NotAfter.Format(time.RFC3339)
		}
		report.TLS = info
	}

	// Security headers check
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for _, name := range securityHeaders {
		v := resp.Header.Get(name)
		check := headerCheck{
			Header:  name,
			Present: v != "",
			Value:   v,
			Status:  "missing",
		}
		if v != "" {
			check.Status = "good"
		}
		report.SecurityHeaders = append(report.SecurityHeaders, check)
	}

	return report
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// probeResponse wraps probeReport with narrative context for AI agents.
type probeResponse struct {
	Summary        string       `json:"summary"`
	Interpretation string       `json:"interpretation"`
	Report         *probeReport `json:"report"`
	NextSteps      []string     `json:"next_steps"`
}

func buildProbeResponse(report *probeReport) *probeResponse {
	resp := &probeResponse{Report: report}

	var sb strings.Builder
	if !report.Reachable {
		fmt.Fprintf(&sb, "Target %s is NOT reachable. Error: %s", report.Target, report.Error)
		resp.Summary = sb.String()
		resp.Interpretation = "The target is unreachable. This could indicate a network issue, DNS failure, firewall blocking, or the target is offline."
		resp.NextSteps = []string{
			"Verify the URL is correct and includes the scheme (https://).",
			"Check network connectivity and DNS resolution.",
			"If behind a VPN/firewall, ensure you have access.",
			"Try with skip_verify=true if the target uses a self-signed certificate.",
		}
		return resp
	}

	fmt.Fprintf(&sb, "Target %s is reachable (HTTP %d). ", report.Target, report.StatusCode)
	if report.Server != "" {
		fmt.Fprintf(&sb, "Server: %s. ", report.Server)
	}
	if report.TLS != nil {
		fmt.Fprintf(&sb, "TLS: %s (%s). ", report.TLS.Version, report.TLS.CipherSuite)
	}

	// Count security headers
	present := 0
	missing := 0
	for _, h := range report.SecurityHeaders {
		if h.Present {
			present++
		} else {
			missing++
		}
	}
	fmt.Fprintf(&sb, "Security headers: %d/%d present. ", present, present+missing)

	if len(report.RedirectChain) > 0 {
		fmt.Fprintf(&sb, "Redirects: %d hops. ", len(report.RedirectChain))
	}
	resp.Summary = sb.String()

	// Build interpretation
	var interp strings.Builder
	if report.TLS != nil {
		switch report.TLS.Version {
		case "TLS 1.3":
			interp.WriteString("TLS 1.3 — excellent, using the latest protocol. ")
		case "TLS 1.2":
			interp.WriteString("TLS 1.2 — acceptable, but TLS 1.3 is preferred for better security and performance. ")
		default:
			fmt.Fprintf(&interp, "%s — OUTDATED. Upgrade to TLS 1.2+ immediately. ", report.TLS.Version)
		}
	}

	if missing > 0 {
		missingNames := make([]string, 0, missing)
		for _, h := range report.SecurityHeaders {
			if !h.Present {
				missingNames = append(missingNames, h.Header)
			}
		}
		fmt.Fprintf(&interp, "Missing security headers (%d): %s. These should be added to harden the application. ", missing, strings.Join(missingNames, ", "))
	} else {
		interp.WriteString("All checked security headers are present — good security posture. ")
	}
	resp.Interpretation = interp.String()

	// Build next steps
	steps := make([]string, 0, 5)
	steps = append(steps,
		fmt.Sprintf("Use 'detect_waf' on %s to identify the WAF vendor and get bypass hints.", report.Target))
	steps = append(steps,
		fmt.Sprintf("Use 'discover' to map the full attack surface of %s.", report.Target))
	if missing > 0 {
		steps = append(steps,
			fmt.Sprintf("Add missing security headers (%d): configure HSTS, CSP, and X-Content-Type-Options at minimum.", missing))
	}
	if report.TLS != nil && report.TLS.Version != "TLS 1.3" && report.TLS.Version != "TLS 1.2" {
		steps = append(steps,
			"URGENT: Upgrade TLS to version 1.2 or 1.3. Older versions have known vulnerabilities.")
	}
	steps = append(steps,
		fmt.Sprintf("Use 'scan' on %s to test WAF blocking against attack payloads.", report.Target))
	resp.NextSteps = steps

	return resp
}

// ═══════════════════════════════════════════════════════════════════════════
// generate_cicd — CI/CD Pipeline Generation
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addGenerateCICDTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "generate_cicd",
			Title: "Generate CI/CD Pipeline",
			Description: `Generate a ready-to-use CI/CD pipeline config for automated WAF testing. Copy-paste output into your repo.

USE THIS TOOL WHEN:
• The user says "set up CI/CD for WAF testing" or "GitHub Actions for WAF" or "automate this"
• Creating recurring WAF regression tests that run on push/schedule
• Integrating WAF checks into an existing deployment pipeline

DO NOT USE THIS TOOL WHEN:
• You want to run a scan right now — use 'scan' or 'assess' instead
• You want to detect the WAF — use 'detect_waf' instead
• You need discovery or recon — use 'discover' instead

This is OFFLINE code generation. No network requests to any target. Produces a complete, ready-to-commit YAML/Groovy pipeline file for the chosen platform.

EXAMPLE INPUTS:
• GitHub Actions: {"platform": "github", "target": "https://staging.example.com", "scan_types": ["sqli", "xss"]}
• GitLab CI: {"platform": "gitlab", "target": "https://app.example.com"}
• Jenkins: {"platform": "jenkins", "target": "https://internal.app"}
• Azure DevOps: {"platform": "azure-devops", "target": "https://myapp.azurewebsites.net"}
• CircleCI: {"platform": "circleci", "target": "https://api.example.com", "scan_types": ["sqli"]}
• Bitbucket: {"platform": "bitbucket", "target": "https://example.com"}
• With schedule: {"platform": "github", "target": "https://example.com", "schedule": "0 2 * * 1"}

PLATFORMS: github, gitlab, jenkins, azure-devops, circleci, bitbucket

Returns: complete pipeline YAML/Groovy, ready to paste into your repo and commit.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"platform": map[string]any{
						"type":        "string",
						"description": "CI/CD platform to generate config for.",
						"enum":        []string{"github", "gitlab", "jenkins", "azure-devops", "circleci", "bitbucket"},
					},
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL for WAF testing (can use environment variable like $TARGET_URL).",
					},
					"scan_types": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Vulnerability scan types to include. Example: [\"sqli\", \"xss\"].",
					},
					"schedule": map[string]any{
						"type":        "string",
						"description": "Cron schedule for automated runs (e.g. '0 2 * * 1' for weekly Monday 2am).",
					},
				},
				"required": []string{"platform", "target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Generate CI/CD Pipeline",
			},
		},
		s.handleGenerateCICD,
	)
}

type cicdArgs struct {
	Platform  string   `json:"platform"`
	Target    string   `json:"target"`
	ScanTypes []string `json:"scan_types"`
	Schedule  string   `json:"schedule"`
}

func (s *Server) handleGenerateCICD(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args cicdArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Platform == "" {
		return errorResult("platform is required. Supported: github, gitlab, jenkins, azure-devops, circleci, bitbucket"), nil
	}
	if args.Target == "" {
		return errorResult("target URL is required."), nil
	}

	pipeline := generateCICDConfig(args)

	// Build structured response with the same envelope as all other tools.
	resp := buildCICDResponse(pipeline, args)
	return jsonResult(resp)
}

// cicdResponse wraps generated CI/CD pipeline config with structured metadata
// and actionable next steps for AI agent consumption.
type cicdResponse struct {
	Summary   string   `json:"summary"`
	Platform  string   `json:"platform"`
	FileName  string   `json:"file_name"`
	Pipeline  string   `json:"pipeline"`
	NextSteps []string `json:"next_steps"`
}

func buildCICDResponse(pipeline string, args cicdArgs) *cicdResponse {
	fileNames := map[string]string{
		"github":       ".github/workflows/waf-test.yml",
		"gitlab":       ".gitlab-ci.yml",
		"jenkins":      "Jenkinsfile",
		"azure-devops": "azure-pipelines.yml",
		"circleci":     ".circleci/config.yml",
		"bitbucket":    "bitbucket-pipelines.yml",
	}

	fileName := fileNames[args.Platform]
	if fileName == "" {
		fileName = "pipeline-config"
	}

	scanTypes := "sqli,xss"
	if len(args.ScanTypes) > 0 {
		scanTypes = strings.Join(args.ScanTypes, ",")
	}

	summary := fmt.Sprintf("Generated %s CI/CD pipeline targeting %s with scan types [%s]. Save as %s in your repository.",
		args.Platform, args.Target, scanTypes, fileName)

	nextSteps := []string{
		fmt.Sprintf("Save the 'pipeline' content as %s in your repository and commit.", fileName),
		"SECURITY: Replace the hardcoded target URL with a secret/environment variable before deploying to production.",
		"Adjust concurrency and rate_limit values for your target environment (conservative for production, aggressive for staging).",
		"Set up notifications (Slack, email, PagerDuty) for failed WAF tests so security regressions are caught immediately.",
		"Use 'assess' instead of 'scan' in the pipeline for formal enterprise grading with F1 score and letter grade.",
	}
	if args.Schedule != "" {
		nextSteps = append(nextSteps,
			fmt.Sprintf("Scheduled scans configured with cron '%s'. Verify the schedule matches your maintenance window.", args.Schedule))
	}

	return &cicdResponse{
		Summary:   summary,
		Platform:  args.Platform,
		FileName:  fileName,
		Pipeline:  pipeline,
		NextSteps: nextSteps,
	}
}

func generateCICDConfig(args cicdArgs) string {
	scanTypes := "sqli,xss"
	if len(args.ScanTypes) > 0 {
		scanTypes = strings.Join(args.ScanTypes, ",")
	}

	switch args.Platform {
	case "github":
		return generateGitHubActions(args.Target, scanTypes, args.Schedule)
	case "gitlab":
		return generateGitLabCI(args.Target, scanTypes, args.Schedule)
	case "jenkins":
		return generateJenkinsfile(args.Target, scanTypes)
	case "azure-devops":
		return generateAzureDevOps(args.Target, scanTypes)
	case "circleci":
		return generateCircleCI(args.Target, scanTypes)
	case "bitbucket":
		return generateBitbucket(args.Target, scanTypes)
	default:
		return fmt.Sprintf("# Unsupported platform: %s\n# Supported: github, gitlab, jenkins, azure-devops, circleci, bitbucket", args.Platform)
	}
}

func generateGitHubActions(target, scanTypes, schedule string) string {
	cron := ""
	if schedule != "" {
		cron = fmt.Sprintf("\n  schedule:\n    - cron: '%s'", schedule)
	}
	return fmt.Sprintf(`name: WAF Security Testing
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]%s

jobs:
  waf-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install waf-tester
        run: |
          curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
          chmod +x waf-tester

      - name: Run WAF Security Scan
        run: |
          ./waf-tester scan -u %s -types %s \
            -format sarif -o results.sarif \
            -c 10 -rl 50

      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
`, cron, target, scanTypes)
}

func generateGitLabCI(target, scanTypes, schedule string) string {
	scheduleNote := ""
	if schedule != "" {
		scheduleNote = fmt.Sprintf("\n# Schedule: %s (configure in GitLab CI/CD > Schedules)", schedule)
	}
	return fmt.Sprintf(`%s
waf-security-test:
  stage: test
  image: golang:1.24
  script:
    - curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
    - chmod +x waf-tester
    - ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
  artifacts:
    paths:
      - results.json
    expire_in: 30 days
`, scheduleNote, target, scanTypes)
}

func generateJenkinsfile(target, scanTypes string) string {
	return fmt.Sprintf(`pipeline {
    agent any
    stages {
        stage('WAF Security Test') {
            steps {
                sh '''
                    curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
                    chmod +x waf-tester
                    ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.json'
                }
            }
        }
    }
}
`, target, scanTypes)
}

func generateAzureDevOps(target, scanTypes string) string {
	return fmt.Sprintf(`trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
      chmod +x waf-tester
      ./waf-tester scan -u %s -types %s -format json -o $(Build.ArtifactStagingDirectory)/results.json -c 10 -rl 50
    displayName: 'Run WAF Security Scan'

  - publish: $(Build.ArtifactStagingDirectory)/results.json
    artifact: waf-test-results
`, target, scanTypes)
}

func generateCircleCI(target, scanTypes string) string {
	return fmt.Sprintf(`version: 2.1
jobs:
  waf-test:
    docker:
      - image: cimg/go:1.24
    steps:
      - checkout
      - run:
          name: Install waf-tester
          command: |
            curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
            chmod +x waf-tester
      - run:
          name: Run WAF Security Scan
          command: ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
      - store_artifacts:
          path: results.json

workflows:
  security:
    jobs:
      - waf-test
`, target, scanTypes)
}

func generateBitbucket(target, scanTypes string) string {
	return fmt.Sprintf(`pipelines:
  default:
    - step:
        name: WAF Security Test
        image: golang:1.24
        script:
          - curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
          - chmod +x waf-tester
          - ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
        artifacts:
          - results.json
`, target, scanTypes)
}
