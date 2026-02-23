package mcpserver

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/templateresolver"
)

// templateDescriptions maps template keys ("<kind>/<name>") to human-written
// descriptions. Descriptions cannot be parsed from embedded files, so they
// live here as a static map guarded by invariant tests.
var templateDescriptions = map[string]string{
	// nuclei — bypass
	"nuclei/sqli-basic":    "SQL injection (UNION, error, blind, time-based)",
	"nuclei/sqli-evasion":  "SQLi WAF evasion (comments, encoding, HPP)",
	"nuclei/xss-basic":     "Cross-site scripting (script tags, events, SVG)",
	"nuclei/xss-evasion":   "XSS WAF evasion (entity encoding, bracket notation)",
	"nuclei/ssrf-bypass":   "SSRF cloud metadata and IP tricks",
	"nuclei/lfi-bypass":    "LFI with UTF-8, PHP wrappers, glob patterns",
	"nuclei/rce-bypass":    "RCE with IFS, wildcards, newline injection",
	"nuclei/ssti-bypass":   "SSTI multi-engine (Jinja2, Twig, ERB, Velocity)",
	"nuclei/xxe-bypass":    "XXE with OOB, XInclude, SVG injection",
	"nuclei/crlf-bypass":   "CRLF with Unicode, response splitting",
	"nuclei/nosqli-bypass": "NoSQL injection (MongoDB operators, $where)",

	// nuclei — detection
	"nuclei/cloudflare-detect":  "Cloudflare WAF (CF-Ray, headers, cookies)",
	"nuclei/aws-waf-detect":     "AWS WAF/CloudFront (x-amzn headers)",
	"nuclei/akamai-detect":      "Akamai Kona (GHost, Reference ID)",
	"nuclei/azure-waf-detect":   "Azure WAF/Application Gateway",
	"nuclei/modsecurity-detect": "ModSecurity/CRS (version + rule extractors)",

	// nuclei — assessment
	"nuclei/waf-assessment-workflow": "Coordinated WAF assessment workflow",

	// workflows
	"workflows/full-scan":     "Complete scan with fingerprinting, calibration, and triple report output.",
	"workflows/quick-probe":   "Fast probe for critical+high severity only.",
	"workflows/waf-detection": "WAF fingerprinting workflow.",
	"workflows/api-scan":      "API-focused scan with OpenAPI spec support.",
	"workflows/ci-gate":       "CI/CD gate with SARIF+JUnit output and policy enforcement.",

	// policies
	"policies/strict":      "Maximum security — blocks any bypass. 95% effectiveness floor.",
	"policies/standard":    "Balanced policy for production. 85% effectiveness.",
	"policies/permissive":  "Development-friendly, critical-only blocking.",
	"policies/owasp-top10": "Maps to OWASP Top 10 2021 categories.",
	"policies/pci-dss":     "PCI DSS v4.0 compliance requirements.",

	// overrides
	"overrides/api-only":                   "API-focused testing — JSON bodies, no browser attacks.",
	"overrides/crs-tuning":                 "ModSecurity CRS paranoia level tuning.",
	"overrides/false-positive-suppression": "Suppresses known false positives (static assets, healthchecks).",

	// output
	"output/markdown-report":    "Executive summary with severity distribution.",
	"output/text-summary":       "ASCII console-friendly report.",
	"output/slack-notification": "Slack Block Kit JSON notification.",
	"output/junit":              "JUnit XML for CI/CD integration.",
	"output/csv":                "CSV with 12 columns, OWASP/CWE links.",
	"output/asff":               "AWS Security Finding Format.",

	// report-configs
	"report-configs/minimal":    "Compact 6-section report.",
	"report-configs/enterprise": "11 sections with OWASP/PCI/NIST mapping.",
	"report-configs/compliance": "Regulatory attestation format.",
	"report-configs/dark":       "Modern dark theme, filterable results.",
	"report-configs/print":      "Print-optimized with grayscale charts.",
}

// buildTemplateEntries builds a sorted slice of templateEntry for a category.
// Shared between the list_templates tool and the waftester://templates resource.
func buildTemplateEntries(infos []templateresolver.TemplateInfo) []templateEntry {
	entries := make([]templateEntry, 0, len(infos))
	for _, info := range infos {
		key := string(info.Kind) + "/" + info.Name
		entries = append(entries, templateEntry{
			Name:        info.Name,
			Path:        info.Path,
			Description: templateDescriptions[key],
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries
}

// ═══════════════════════════════════════════════════════════════════════════
// list_templates — Browse the template library
// ═══════════════════════════════════════════════════════════════════════════

// validKindStrings returns the list of valid template kind strings derived
// from the resolver. Used by the list_templates tool schema and error messages
// to stay in sync with the actual template categories.
func validKindStrings() []string {
	categories := templateresolver.ListAllCategories()
	kinds := make([]string, len(categories))
	for i, cat := range categories {
		kinds[i] = string(cat.Kind)
	}
	return kinds
}

func (s *Server) addListTemplatesTool() {
	kindEnum := validKindStrings()
	kindsLine := strings.Join(kindEnum, ", ")

	s.addTool(
		&mcp.Tool{
			Name:  "list_templates",
			Title: "List Templates",
			Description: `Browse the bundled template library — policies, overrides, workflows, Nuclei bypass/detection templates, output formats, and report configs.

USE THIS TOOL WHEN:
• The user asks "what templates do you have?" or "show me available policies"
• You need to find the right template name before using it in a scan or workflow
• You want to explore a specific template category
• Planning which policy, override, or workflow to use

DO NOT USE THIS TOOL WHEN:
• You want to read the actual content of a template — use 'show_template' instead
• You want to run a scan — use 'scan' instead

This is a READ-ONLY local operation. Zero network requests. Instant results.

EXAMPLE INPUTS:
• See all categories: {}
• Browse policies: {"kind": "policies"}
• Browse Nuclei templates: {"kind": "nuclei"}
• Browse output formats: {"kind": "output"}

KINDS: ` + kindsLine,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"kind": map[string]any{
						"type":        "string",
						"description": "Filter by template category. Leave empty to see all categories with counts.",
						"enum":        kindEnum,
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    true,
				IdempotentHint:  true,
				OpenWorldHint:   boolPtr(false),
				DestructiveHint: boolPtr(false),
			},
		},
		loggedTool("list_templates", s.handleListTemplates),
	)
}

type listTemplatesArgs struct {
	Kind string `json:"kind"`
}

type templateEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
}

type listTemplatesResponse struct {
	Summary    string                        `json:"summary"`
	TotalCount int                           `json:"total_count"`
	Categories []listTemplatesCategoryDetail `json:"categories"`
	NextSteps  []string                      `json:"next_steps"`
}

type listTemplatesCategoryDetail struct {
	Kind      string          `json:"kind"`
	Count     int             `json:"count"`
	Templates []templateEntry `json:"templates,omitempty"`
}

func (s *Server) handleListTemplates(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args listTemplatesArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	// If a specific kind is requested, list its templates.
	if args.Kind != "" {
		kind := templateresolver.Kind(args.Kind)
		infos, err := templateresolver.ListCategory(kind)
		if err != nil {
			return errorResult(fmt.Sprintf("unknown kind %q — valid kinds: %s", args.Kind, strings.Join(validKindStrings(), ", "))), nil
		}

		entries := buildTemplateEntries(infos)

		nextSteps := []string{
			"Use 'show_template' with a template path to see its full content.",
		}
		if len(entries) > 0 {
			nextSteps = append(nextSteps, fmt.Sprintf("Example: {\"path\": \"%s\"}", entries[0].Path))
		}

		resp := &listTemplatesResponse{
			Summary:    fmt.Sprintf("%d templates in category %q.", len(entries), args.Kind),
			TotalCount: len(entries),
			Categories: []listTemplatesCategoryDetail{{
				Kind:      args.Kind,
				Count:     len(entries),
				Templates: entries,
			}},
			NextSteps: nextSteps,
		}
		return jsonResult(resp)
	}

	// No kind filter: show all categories with counts.
	categories := templateresolver.ListAllCategories()
	total := 0
	details := make([]listTemplatesCategoryDetail, 0, len(categories))
	for _, cat := range categories {
		total += cat.Count
		details = append(details, listTemplatesCategoryDetail{
			Kind:  string(cat.Kind),
			Count: cat.Count,
		})
	}

	resp := &listTemplatesResponse{
		Summary:    fmt.Sprintf("%d templates across %d categories.", total, len(categories)),
		TotalCount: total,
		Categories: details,
		NextSteps: []string{
			"Filter by category: {\"kind\": \"policies\"} or {\"kind\": \"nuclei\"}.",
			"Use 'show_template' to read a specific template's content.",
		},
	}
	return jsonResult(resp)
}

// ═══════════════════════════════════════════════════════════════════════════
// show_template — Read a template's content
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addShowTemplateTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "show_template",
			Title: "Show Template Content",
			Description: `Read the full content of a bundled template. Returns the raw YAML or Go template content.

USE THIS TOOL WHEN:
• The user asks "show me the strict policy" or "what's in the enterprise report config?"
• You need to inspect a template before using it
• You want to understand what a Nuclei template tests

DO NOT USE THIS TOOL WHEN:
• You want to browse available templates — use 'list_templates' first
• You want to run a template — use 'scan' with --policy or --overrides flags

EXAMPLE INPUTS:
• Policy: {"path": "policies/strict.yaml"}
• Nuclei template: {"path": "nuclei/http/waf-bypass/sqli-basic.yaml"}
• Output format: {"path": "output/csv.tmpl"}
• Short name (auto-resolved): {"path": "policies/strict"}

Returns the template content as text. Maximum 1MB.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Template path as returned by list_templates (e.g. 'policies/strict.yaml', 'nuclei/http/waf-bypass/sqli-basic.yaml'). Extension is optional.",
					},
				},
				"required": []string{"path"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    true,
				IdempotentHint:  true,
				OpenWorldHint:   boolPtr(false),
				DestructiveHint: boolPtr(false),
			},
		},
		loggedTool("show_template", s.handleShowTemplate),
	)
}

type showTemplateArgs struct {
	Path string `json:"path"`
}

func (s *Server) handleShowTemplate(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args showTemplateArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Path == "" {
		return errorResult("path is required — use list_templates to find template paths"), nil
	}

	// Normalize backslashes for Windows compatibility.
	path := strings.ReplaceAll(args.Path, "\\", "/")

	// Use ResolveEmbeddedPath which handles subdirectory paths (nuclei/**).
	result, err := templateresolver.ResolveEmbeddedPath(path)
	if err != nil {
		return errorResult(fmt.Sprintf("template not found: %s — use list_templates to see available templates", path)), nil
	}
	defer result.Content.Close()

	const maxSize = 1 << 20 // 1MB
	// Read one extra byte beyond maxSize to detect truncation.
	content, readErr := io.ReadAll(io.LimitReader(result.Content, maxSize+1))
	if readErr != nil {
		return errorResult(fmt.Sprintf("reading template: %v", readErr)), nil
	}

	if int64(len(content)) > maxSize {
		content = content[:maxSize]
		return textResult(string(content) + "\n\n[truncated — template exceeds 1MB limit]"), nil
	}

	return textResult(string(content)), nil
}
