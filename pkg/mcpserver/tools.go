package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/payloads"
)

// toolHandler is the function signature for MCP tool handlers.
type toolHandler = func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error)

// loggedTool wraps a tool handler with structured logging. Every tool
// invocation is logged on entry (with arguments) and on exit (with
// success/error status and duration). This is critical for diagnosing
// MCP client integration issues where requests silently vanish.
func loggedTool(name string, fn toolHandler) toolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Redact sensitive argument fields before logging to prevent key/token leakage
		argBytes := []byte(req.Params.Arguments)
		var rawArgs map[string]interface{}
		if json.Unmarshal(argBytes, &rawArgs) == nil {
			redactMap(rawArgs)
			if redacted, err := json.Marshal(rawArgs); err == nil {
				argBytes = redacted
			}
		}
		argStr := string(argBytes)
		const maxArgLog = 200
		if len([]rune(argStr)) > maxArgLog {
			// Truncate at rune boundary to avoid splitting multi-byte UTF-8
			argStr = truncateString(argStr, maxArgLog) + "..."
		}
		log.Printf("[mcp-tool] --> %s  args=%s", name, argStr)

		start := time.Now()
		result, err := fn(ctx, req)
		elapsed := time.Since(start).Round(time.Millisecond)

		if err != nil {
			log.Printf("[mcp-tool] <-- %s  ERROR  duration=%s  err=%v", name, elapsed, err)
		} else if result != nil && result.IsError {
			// Tool returned an error result (not a Go error).
			log.Printf("[mcp-tool] <-- %s  TOOL_ERROR  duration=%s", name, elapsed)
		} else {
			log.Printf("[mcp-tool] <-- %s  OK  duration=%s", name, elapsed)
		}
		return result, err
	}
}

// sensitiveSubstrings are substrings that, if found in a lowercased JSON key,
// trigger redaction. This is intentionally broad to catch variations like
// "x_api_key", "my_secret_token", "auth_header", etc.
var sensitiveSubstrings = []string{
	"secret", "password", "token", "credential", "key", "license",
	"auth", "bearer", "jwt", "cookie", "session", "proxy",
	"access", "private", "signing", "encrypt",
}

// isSensitiveKey returns true if the lowercased key contains any sensitive substring.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// redactMap recursively redacts sensitive fields in a JSON-like map.
// It traverses nested maps and arrays so payloads like
// {"config":{"api_key":"..."}} and {"items":[{"token":"..."}]} are caught.
func redactMap(m map[string]interface{}) {
	for k, v := range m {
		if isSensitiveKey(k) {
			m[k] = "[REDACTED]"
			continue
		}
		// Recurse into nested objects
		switch val := v.(type) {
		case map[string]interface{}:
			redactMap(val)
		case []interface{}:
			for _, item := range val {
				if nested, ok := item.(map[string]interface{}); ok {
					redactMap(nested)
				}
			}
		}
	}
}

// truncateString truncates s to at most maxLen runes, avoiding mid-rune byte splits.
func truncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen])
}

// truncateBytes truncates s to at most maxBytes bytes, stepping back to the
// nearest valid UTF-8 rune boundary to avoid producing an invalid UTF-8 fragment.
func truncateBytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Step back from the byte limit until we land on a rune boundary.
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

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
	s.addListTampersTool()
	s.addDiscoverBypassesTool()
	s.addListTemplatesTool()
	s.addShowTemplateTool()
	if s.config.EventCrawlFn != nil {
		s.addEventCrawlTool()
	}
	s.registerAsyncTools() // get_task_status, cancel_task, list_tasks
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
		loggedTool("list_payloads", s.handleListPayloads),
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
	provider := s.PayloadProvider()
	if err := provider.Load(); err != nil {
		return errorResult(fmt.Sprintf("failed to load payloads from %s: %v. Verify the payload directory exists and contains JSON files.", s.config.PayloadDir, err)), nil
	}

	all, err := provider.JSONPayloads()
	if err != nil {
		return errorResult(fmt.Sprintf("failed to extract payloads: %v", err)), nil
	}

	// Enrich with Nuclei template payloads
	unified, err := provider.GetAll()
	if err != nil {
		log.Printf("[mcp] failed to load unified payloads: %v", err)
	}
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
			snippet = truncateBytes(snippet, 120) + "…"
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
			"Use 'mutate' to generate WAF-evasion variants of any payload above (e.g., URL encoding, Unicode, double-encoding)")
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
