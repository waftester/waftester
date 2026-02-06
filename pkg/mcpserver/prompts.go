package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerPrompts adds all guided workflow prompts to the MCP server.
func (s *Server) registerPrompts() {
	s.addSecurityAuditPrompt()
	s.addWAFBypassPrompt()
	s.addFullAssessmentPrompt()
	s.addDiscoveryWorkflowPrompt()
	s.addEvasionResearchPrompt()
}

// ═══════════════════════════════════════════════════════════════════════════
// security_audit — 5-phase security audit workflow
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addSecurityAuditPrompt() {
	s.mcp.AddPrompt(
		&mcp.Prompt{
			Name:        "security_audit",
			Description: "Comprehensive 5-phase WAF security audit workflow. Guides through detection, discovery, scanning, assessment, and reporting.",
			Arguments: []*mcp.PromptArgument{
				{Name: "target", Description: "Target URL to audit (e.g. https://example.com)", Required: true},
				{Name: "scope", Description: "Scope: 'full' (all categories), 'api' (API-focused), or specific categories comma-separated (e.g. 'sqli,xss,ssrf')", Required: false},
				{Name: "environment", Description: "Target environment: 'production', 'staging', or 'development'", Required: false},
			},
		},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			target := req.Params.Arguments["target"]
			if target == "" {
				return nil, fmt.Errorf("'target' argument is required")
			}
			scope := req.Params.Arguments["scope"]
			if scope == "" {
				scope = "full"
			}
			env := req.Params.Arguments["environment"]
			if env == "" {
				env = "staging"
			}

			rateAdvice := "50 req/s"
			if env == "production" {
				rateAdvice = "10-20 req/s (production — be cautious)"
			} else if env == "development" {
				rateAdvice = "100 req/s (dev — full speed OK)"
			}

			return &mcp.GetPromptResult{
				Description: fmt.Sprintf("Security Audit: %s", target),
				Messages: []*mcp.PromptMessage{
					&mcp.PromptMessage{
						Role: "user",
						Content: &mcp.TextContent{
							Text: fmt.Sprintf(`Perform a comprehensive WAF security audit on %s.

## Phase 1: Reconnaissance
1. Run detect_waf on target %s to identify the WAF vendor
2. Read the waftester://waf-signatures resource to get vendor-specific bypass tips
3. Read the waftester://evasion-techniques resource to understand available encodings

## Phase 2: Attack Surface Discovery
4. Run discover on target %s with max_depth 3
5. Analyze the discovered endpoints, parameters, and risk factors
6. Summarize the attack surface: total endpoints, parameter injection points, tech stack

## Phase 3: Payload Scanning
Run scan on target with:
- Scope: %s
- Rate limit: %s
- Concurrency: 10
- Blocked status codes: [403, 406, 429, 503]

Report the detection rate and any bypass findings per category.

## Phase 4: Enterprise Assessment
Run assess on target to get formal metrics:
- Detection rate, false positive rate, F1 score, MCC
- Grade assignment (A+ through F)
- Category-level breakdown

## Phase 5: Report & Recommendations
Compile findings into a structured report:
1. Executive Summary (grade, detection rate, critical bypass count)
2. WAF Identification (vendor, version, deployment mode)
3. Attack Surface Summary (endpoints, parameters, risk areas)
4. Detection Analysis by OWASP Top 10 category
5. Critical Bypasses (with curl commands for reproduction)
6. Remediation Recommendations (prioritized)
7. Read waftester://owasp-mappings to map findings to compliance frameworks

Be thorough but respect the rate limit guidance for a %s environment.`,
								target, target, target, scope, rateAdvice, env),
						},
					},
				},
			}, nil
		},
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// waf_bypass — 6-step bypass discovery workflow
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addWAFBypassPrompt() {
	s.mcp.AddPrompt(
		&mcp.Prompt{
			Name:        "waf_bypass",
			Description: "Systematic 6-step WAF bypass discovery workflow. Identifies blocked payloads, applies evasion techniques, and finds working bypasses.",
			Arguments: []*mcp.PromptArgument{
				{Name: "target", Description: "Target URL protected by WAF", Required: true},
				{Name: "category", Description: "Attack category to focus on (e.g. 'sqli', 'xss')", Required: true},
				{Name: "stealth", Description: "Use stealth mode with low rate limits: 'true' or 'false'", Required: false},
			},
		},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			target := req.Params.Arguments["target"]
			category := req.Params.Arguments["category"]
			if target == "" || category == "" {
				return nil, fmt.Errorf("'target' and 'category' arguments are required")
			}
			stealth := req.Params.Arguments["stealth"]
			rateLimit := "10"
			concurrency := "5"
			if stealth == "true" {
				rateLimit = "3"
				concurrency = "2"
			}

			return &mcp.GetPromptResult{
				Description: fmt.Sprintf("WAF Bypass: %s on %s", category, target),
				Messages: []*mcp.PromptMessage{
					&mcp.PromptMessage{
						Role: "user",
						Content: &mcp.TextContent{
							Text: fmt.Sprintf(`Find WAF bypasses for %s attacks against %s.

## Step 1: Detect the WAF
Run detect_waf on %s to identify the vendor. This informs which evasion techniques will be most effective.

## Step 2: Baseline Scan
Run scan against %s with:
- categories: ["%s"]
- rate_limit: %s
- concurrency: %s
This establishes which payloads are blocked vs which already bypass.

## Step 3: Analyze Blocked Payloads
From the scan results, identify the payloads that were blocked.
Read waftester://evasion-techniques to understand available evasion methods.

## Step 4: Generate Mutations
Use mutate tool to create encoded variants of the blocked payloads:
- Try all encodings: url, double_url, unicode, html_hex
- Note which encodings are most effective for the WAF vendor found in Step 1

## Step 5: Automated Bypass Discovery
Run bypass against %s with:
- category: "%s"
- rate_limit: %s
- concurrency: %s
This systematically tests all mutation combinations.

## Step 6: Report
For each bypass found:
1. Original blocked payload
2. Successful evasion technique used
3. Encoding method
4. curl command for reproduction
5. Severity assessment
6. Remediation recommendation (specific WAF rule to add)

Focus on critical and high severity bypasses first.`,
								category, target, target, target, category, rateLimit, concurrency,
								target, category, rateLimit, concurrency),
						},
					},
				},
			}, nil
		},
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// full_assessment — Enterprise assessment with compliance mapping
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addFullAssessmentPrompt() {
	s.mcp.AddPrompt(
		&mcp.Prompt{
			Name:        "full_assessment",
			Description: "Enterprise-grade WAF assessment with metrics, grading, and OWASP compliance mapping.",
			Arguments: []*mcp.PromptArgument{
				{Name: "target", Description: "Target URL for assessment", Required: true},
				{Name: "compliance", Description: "Compliance framework: 'owasp', 'pci-dss', or 'both'", Required: false},
			},
		},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			target := req.Params.Arguments["target"]
			if target == "" {
				return nil, fmt.Errorf("'target' argument is required")
			}
			compliance := req.Params.Arguments["compliance"]
			if compliance == "" {
				compliance = "owasp"
			}

			return &mcp.GetPromptResult{
				Description: fmt.Sprintf("Enterprise Assessment: %s", target),
				Messages: []*mcp.PromptMessage{
					&mcp.PromptMessage{
						Role: "user",
						Content: &mcp.TextContent{
							Text: fmt.Sprintf(`Perform an enterprise WAF assessment on %s with %s compliance mapping.

## Pre-Assessment
1. Run detect_waf to identify the WAF and verify the target is protected
2. Run probe to analyze TLS configuration, security headers, and server fingerprint
3. Read waftester://config to understand recommended settings

## Assessment Execution
Run assess against %s with:
- concurrency: 25
- timeout: 10

## Compliance Mapping
Read waftester://owasp-mappings and map each finding to the relevant OWASP Top 10 2021 category.

## Results Analysis
Present results as:
1. **Executive Dashboard**
   - Overall Grade (A+ through F)
   - Detection Rate (percentage)
   - False Positive Rate (percentage)
   - F1 Score (0-1)
   - MCC (Matthews Correlation Coefficient)
   - Total tests / blocked / bypassed / errors

2. **Category Breakdown**
   - Per-category detection rates
   - Weakest categories identified
   - Strongest categories confirmed

3. **OWASP Compliance Matrix**
   - A01:2021 through A10:2021 coverage status
   - Which categories map to each OWASP item
   - Coverage gaps and recommendations

4. **Bypass Analysis**
   - Critical bypasses with reproduction steps
   - Severity distribution of bypasses
   - Vendor-specific bypass patterns

5. **Recommendations**
   - Priority 1: Critical gaps requiring immediate attention
   - Priority 2: Rule tuning recommendations  
   - Priority 3: Configuration improvements
   - Priority 4: Monitoring and alerting suggestions

Format the output suitable for executive and technical audiences.`,
								target, compliance, target),
						},
					},
				},
			}, nil
		},
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// discovery_workflow — Attack surface discovery and mapping
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addDiscoveryWorkflowPrompt() {
	s.mcp.AddPrompt(
		&mcp.Prompt{
			Name:        "discovery_workflow",
			Description: "Attack surface discovery and intelligent test plan generation workflow.",
			Arguments: []*mcp.PromptArgument{
				{Name: "target", Description: "Target URL to discover", Required: true},
				{Name: "depth", Description: "Discovery depth: 'shallow' (1), 'normal' (3), or 'deep' (5)", Required: false},
				{Name: "service", Description: "Known service type for optimized payloads (e.g. 'authentik', 'n8n', 'immich')", Required: false},
			},
		},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			target := req.Params.Arguments["target"]
			if target == "" {
				return nil, fmt.Errorf("'target' argument is required")
			}
			depth := "3"
			depthName := req.Params.Arguments["depth"]
			switch depthName {
			case "shallow":
				depth = "1"
			case "deep":
				depth = "5"
			case "normal", "":
				depth = "3"
			default:
				depth = depthName
			}
			service := req.Params.Arguments["service"]
			serviceClause := ""
			if service != "" {
				serviceClause = fmt.Sprintf("\n- service: \"%s\" (optimizes payload selection for this application)", service)
			}

			return &mcp.GetPromptResult{
				Description: fmt.Sprintf("Discovery: %s", target),
				Messages: []*mcp.PromptMessage{
					&mcp.PromptMessage{
						Role: "user",
						Content: &mcp.TextContent{
							Text: fmt.Sprintf(`Map the attack surface of %s and generate a smart test plan.

## Step 1: WAF Detection
Run detect_waf on %s first — we need to know if/what WAF protects this target.

## Step 2: Surface Discovery
Run discover against %s with:
- max_depth: %s%s

## Step 3: Analyze Discovery Results
From the discovery output, summarize:
1. **Endpoints**: Total count, top 10 highest-risk endpoints with their parameters
2. **Technologies**: Detected tech stack, frameworks, servers
3. **Secrets**: Any exposed API keys, tokens, or credentials found
4. **Risk Factors**: Categorize endpoints by risk level
5. **Attack Surface Map**: Which endpoints accept user input and where

## Step 4: Generate Test Plan
Use the learn tool with the discovery results to create an optimized test plan.
The test plan will map endpoints to relevant attack categories.

## Step 5: Recommendations
Based on the discovery:
1. Which endpoints should be tested first (highest risk)
2. Which attack categories are most relevant
3. Recommended scan configuration (concurrency, rate limit)
4. Any immediate security issues found during discovery (exposed secrets, missing headers)

Read waftester://payloads to understand available payload categories and counts.`,
								target, target, target, depth, serviceClause),
						},
					},
				},
			}, nil
		},
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// evasion_research — Systematic evasion technique research
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addEvasionResearchPrompt() {
	s.mcp.AddPrompt(
		&mcp.Prompt{
			Name:        "evasion_research",
			Description: "Systematic evasion technique research workflow. Tests encoding and mutation combinations against a specific WAF.",
			Arguments: []*mcp.PromptArgument{
				{Name: "target", Description: "Target URL protected by WAF", Required: true},
				{Name: "payload", Description: "Base payload to test evasion on (e.g. \"<script>alert(1)</script>\")", Required: true},
			},
		},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			target := req.Params.Arguments["target"]
			payload := req.Params.Arguments["payload"]
			if target == "" || payload == "" {
				return nil, fmt.Errorf("'target' and 'payload' arguments are required")
			}

			return &mcp.GetPromptResult{
				Description: fmt.Sprintf("Evasion Research: %s", target),
				Messages: []*mcp.PromptMessage{
					&mcp.PromptMessage{
						Role: "user",
						Content: &mcp.TextContent{
							Text: fmt.Sprintf(`Research evasion techniques against the WAF protecting %s.

Base payload for testing: %s

## Step 1: Identify the WAF
Run detect_waf on %s — the WAF vendor determines which evasion techniques have the highest chance of success.

## Step 2: Read Evasion Knowledge
Read these resources:
- waftester://evasion-techniques — catalog of all available encodings and their effectiveness
- waftester://waf-signatures — vendor-specific bypass tips

## Step 3: Generate Mutations
Use the mutate tool to create encoded variants of the base payload:
- Apply each encoding: url, double_url, unicode, html_hex
- The tool returns all variants with their encoding method

## Step 4: Test Infrastructure
Use probe on %s to understand:
- TLS configuration
- Security headers present
- Server technology
This helps predict which encoding methods are most likely to work.

## Step 5: Analysis Matrix
Create a matrix showing:
| Encoding | Variant | Expected Effectiveness | Rationale |
|----------|---------|----------------------|-----------|

For each variant, explain WHY it might bypass the specific WAF vendor:
- Does the WAF decode this encoding?
- Does the WAF normalize before matching?
- Are there known parser differentials?

## Step 6: Recommendations
1. Top 3 most promising evasion techniques for this WAF
2. Combination strategies (e.g., double_url + case_swap)
3. Alternative injection locations to try (headers, cookies, path)
4. Suggestions for chaining with the bypass tool for automated testing`,
								target, payload, target, target),
						},
					},
				},
			}, nil
		},
	)
}
