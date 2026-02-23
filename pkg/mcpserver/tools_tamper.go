package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
)

// ═══════════════════════════════════════════════════════════════════════════
// discover_bypasses — Automated Tamper-Based Bypass Discovery
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addDiscoverBypassesTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "discover_bypasses",
			Title: "Discover WAF Bypass Tampers",
			Description: `Test every registered tamper technique against a live target to find WAF bypasses. This is the tamper-based bypass discovery engine.

Unlike 'bypass' (which uses encoding mutations like URL/Unicode/hex), this tool tests sqlmap-compatible tamper scripts — payload transformations such as space2comment, between2not, charencode, versionedkeywords, etc. Each tamper rewrites the attack payload using SQL, HTTP, or encoding tricks specific to WAF rule gaps.

USE THIS TOOL WHEN:
• You want to find which tamper techniques bypass a specific WAF
• The user says "discover tamper bypasses", "find WAF evasion techniques", or "what tampers work?"
• You know the WAF vendor and want vendor-specific bypass recommendations
• Red team engagement where you need to prove WAF rule gaps using transform-based evasions
• After a 'scan' found blocks — use this to find transforms that evade those rules

DO NOT USE THIS TOOL WHEN:
• You want encoding-based mutations (URL, Unicode, hex) — use 'bypass' instead
• You just want to scan with known payloads — use 'scan' instead
• You want to browse available tampers without testing — use 'list_tampers' instead

'discover_bypasses' vs 'bypass': 'bypass' tests encoding mutations (URL encode × location × evasion). 'discover_bypasses' tests tamper scripts (space2comment, charencode, between2not, etc.) — these are payload-level rewrites, not just encoding variants. They find different classes of bypasses.

EXAMPLE INPUTS:
• Basic discovery: {"target": "https://example.com/search?q=test"}
• Vendor-specific: {"target": "https://example.com", "waf_vendor": "cloudflare"}
• Quick scan: {"target": "https://example.com", "top_n": 3, "concurrency": 10}
• Thorough: {"target": "https://example.com", "confirm_count": 5, "top_n": 10}

ALGORITHM:
1. Sends raw payloads to establish a "blocked" baseline
2. Applies each registered tamper to the payload and re-sends
3. Compares response signatures to detect bypasses
4. Confirms bypasses with additional payloads
5. Tests pairwise combinations of top tampers
6. Returns ranked results with confidence scores

Returns: total tampers tested, bypass count, top bypass tampers with confidence and sample output, effective combinations, baseline status.

ASYNC TOOL: Returns a task_id immediately. Duration depends on tamper count and target speed (typically 30-120s). Poll with get_task_status.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to test tamper bypasses against. Must be a URL the WAF protects.",
						"format":      "uri",
					},
					"waf_vendor": map[string]any{
						"type":        "string",
						"description": "Detected WAF vendor name (e.g. 'cloudflare', 'modsecurity', 'aws'). Filters tampers to vendor-relevant techniques. Run 'detect_waf' first to get this.",
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Parallel tamper tests.",
						"default":     5,
						"minimum":     1,
						"maximum":     20,
					},
					"top_n": map[string]any{
						"type":        "integer",
						"description": "Number of top tampers to try in pairwise combinations.",
						"default":     5,
						"minimum":     1,
						"maximum":     20,
					},
					"confirm_count": map[string]any{
						"type":        "integer",
						"description": "Additional payloads to confirm each potential bypass. Higher = more confident results.",
						"default":     2,
						"minimum":     1,
						"maximum":     10,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    false,
				IdempotentHint:  false,
				OpenWorldHint:   boolPtr(true),
				DestructiveHint: boolPtr(false),
				Title:           "Discover WAF Bypass Tampers",
			},
		},
		loggedTool("discover_bypasses", s.handleDiscoverBypasses),
	)
}

type discoverBypassesArgs struct {
	Target       string `json:"target"`
	WAFVendor    string `json:"waf_vendor"`
	Concurrency  int    `json:"concurrency"`
	TopN         int    `json:"top_n"`
	ConfirmCount int    `json:"confirm_count"`
}

func (s *Server) handleDiscoverBypasses(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args discoverBypassesArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com/search?q=test\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	if args.Concurrency <= 0 {
		args.Concurrency = defaults.ConcurrencyLow
	}
	if args.Concurrency > defaults.ConcurrencyHigh {
		args.Concurrency = defaults.ConcurrencyHigh
	}
	if args.TopN <= 0 {
		args.TopN = 5
	}
	if args.TopN > 20 {
		args.TopN = 20
	}
	if args.ConfirmCount <= 0 {
		args.ConfirmCount = 2
	}
	if args.ConfirmCount > 10 {
		args.ConfirmCount = 10
	}

	tamperCount := tampers.Count()
	if tamperCount == 0 {
		return enrichedError(
			"no tamper techniques are registered",
			[]string{
				"The tamper registry is empty. This usually means tamper init() functions were not linked.",
				"Use 'list_tampers' to check available tampers.",
			}), nil
	}

	return s.launchAsync(ctx, "discover_bypasses", fmt.Sprintf("30-120s depending on %d tampers and target speed", tamperCount),
		func(taskCtx context.Context, task *Task) {
			task.SetProgress(0, 100, fmt.Sprintf("Preparing bypass discovery with %d tampers against %s", tamperCount, args.Target))

			cfg := tampers.BypassDiscoveryConfig{
				TargetURL:    args.Target,
				WAFVendor:    args.WAFVendor,
				Concurrency:  args.Concurrency,
				TopN:         args.TopN,
				ConfirmCount: args.ConfirmCount,
				Timeout:      duration.DialTimeout,
				OnProgress: func(tamperName, result string) {
					task.SetProgress(0, 100, fmt.Sprintf("Testing tamper %s: %s", tamperName, result))
				},
			}

			result, err := tampers.DiscoverBypasses(taskCtx, cfg)
			if err != nil {
				task.Fail(fmt.Sprintf("bypass discovery failed: %v", err))
				return
			}

			cancelled := taskCtx.Err() != nil

			wrapped := buildDiscoverBypassesResponse(result, args)
			if cancelled {
				wrapped.Summary = "PARTIAL RESULTS (discovery was cancelled): " + wrapped.Summary
			}

			data, err := json.Marshal(wrapped)
			if err != nil {
				task.Fail(fmt.Sprintf("marshaling result: %v", err))
				return
			}
			task.Complete(data)
		})
}

// discoverBypassesResponse wraps BypassDiscoveryResult with narrative context.
type discoverBypassesResponse struct {
	Summary        string                         `json:"summary"`
	Interpretation string                         `json:"interpretation"`
	Result         *tampers.BypassDiscoveryResult `json:"result"`
	NextSteps      []string                       `json:"next_steps"`
}

func buildDiscoverBypassesResponse(result *tampers.BypassDiscoveryResult, args discoverBypassesArgs) *discoverBypassesResponse {
	resp := &discoverBypassesResponse{Result: result}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Tested %d tamper techniques against %s. ", result.TotalTampers, args.Target)

	if !result.BaselineBlocked {
		sb.WriteString("WARNING: Raw payloads were NOT blocked by the WAF. The target may not have WAF protection, or the WAF is not blocking the test payloads. Cannot discover bypasses without a baseline block.")
		resp.Summary = sb.String()
		resp.Interpretation = "Bypass discovery requires the WAF to block raw (untampered) payloads. Since raw payloads got through, there is nothing to bypass. Either the target has no WAF, the WAF is in detection-only mode, or the test payloads are not in the WAF's ruleset."
		resp.NextSteps = []string{
			fmt.Sprintf("Use 'detect_waf' on %s to verify WAF presence.", args.Target),
			fmt.Sprintf("Use 'scan' on %s to test if any attack categories are blocked.", args.Target),
			"If the WAF is in detection-only mode, switch it to blocking mode before testing.",
		}
		return resp
	}

	if result.TotalBypasses > 0 {
		fmt.Fprintf(&sb, "FOUND %d bypass tampers. ", result.TotalBypasses)
		if len(result.TopBypasses) > 0 {
			names := make([]string, 0, len(result.TopBypasses))
			for _, b := range result.TopBypasses {
				names = append(names, b.TamperName)
			}
			fmt.Fprintf(&sb, "Top bypasses: %s. ", strings.Join(names, ", "))
		}
		if len(result.Combinations) > 0 {
			fmt.Fprintf(&sb, "%d effective tamper combinations found. ", len(result.Combinations))
		}
		fmt.Fprintf(&sb, "Duration: %s.", result.Duration.Round(time.Millisecond))
	} else {
		fmt.Fprintf(&sb, "No bypasses found — all tamper techniques were blocked. Duration: %s.", result.Duration.Round(time.Millisecond))
	}
	resp.Summary = sb.String()

	// Build interpretation
	if result.TotalBypasses > 0 {
		var interp strings.Builder
		fmt.Fprintf(&interp, "Found %d tamper techniques that bypass the WAF. ", result.TotalBypasses)
		for _, b := range result.TopBypasses {
			fmt.Fprintf(&interp, "%s (%s, %.0f%% success, confidence: %s). ",
				b.TamperName, b.Category, b.SuccessRate*100, b.Confidence)
		}
		if len(result.Combinations) > 0 {
			interp.WriteString("Pairwise combinations of top tampers were also tested and found additional bypass paths. ")
		}
		resp.Interpretation = interp.String()
	} else {
		resp.Interpretation = fmt.Sprintf("All %d tamper techniques were blocked by the WAF. The WAF has strong coverage against payload-level transformations. Consider testing with 'bypass' (encoding mutations) for a different evasion approach.", result.TotalTampers)
	}

	// Build next steps
	steps := make([]string, 0, 5)
	if result.TotalBypasses > 0 {
		steps = append(steps,
			"CRITICAL: Report bypass tampers to the WAF administrator. Each represents a rule gap that can be exploited.")
		if len(result.TopBypasses) > 0 {
			names := make([]string, 0, len(result.TopBypasses))
			for _, b := range result.TopBypasses {
				names = append(names, b.TamperName)
			}
			steps = append(steps,
				fmt.Sprintf("Use 'list_tampers' to learn more about the bypass techniques: %s", strings.Join(names, ", ")))
		}
		steps = append(steps,
			fmt.Sprintf("Use 'bypass' on %s to also test encoding-based mutations (URL, Unicode, hex) for additional bypass vectors.", args.Target))
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for a formal WAF grade that reflects these findings.", args.Target))
	} else {
		steps = append(steps,
			fmt.Sprintf("Use 'bypass' on %s to test encoding mutations — different evasion approach than tamper scripts.", args.Target))
		steps = append(steps,
			"Use 'list_tampers' to review available tamper techniques and their categories.")
		steps = append(steps,
			fmt.Sprintf("Use 'scan' with different categories to find attack surfaces the WAF might miss."))
	}
	resp.NextSteps = steps

	return resp
}

// ═══════════════════════════════════════════════════════════════════════════
// list_tampers — Browse Tamper Technique Catalog
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addListTampersTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "list_tampers",
			Title: "List Tamper Techniques",
			Description: `Browse the catalog of registered tamper techniques — sqlmap-compatible payload transformations for WAF bypass.

Each tamper rewrites attack payloads using SQL tricks, encoding transformations, whitespace substitutions, or WAF-specific bypasses. This tool lists them WITHOUT sending any network traffic.

USE THIS TOOL WHEN:
• The user asks "what tampers are available?", "list tamper techniques", or "show bypass methods"
• You need to understand what a specific tamper does before using it
• Planning which tamper to use with 'discover_bypasses' or in CLI --tamper flag
• You want to filter tampers by category (encoding, space, sql, waf, etc.) or WAF vendor tag

DO NOT USE THIS TOOL WHEN:
• You want to TEST tampers against a live target — use 'discover_bypasses' instead
• You want encoding-based mutations (URL, hex, Unicode) — use 'mutate' instead
• You want mutation-matrix bypass testing — use 'bypass' instead

CATEGORIES: encoding, space, sql, mysql, mssql, waf, http, obfuscation

EXAMPLE INPUTS:
• List all: {}
• SQL tampers only: {"category": "sql"}
• WAF-specific bypasses: {"category": "waf"}
• Tampers for Cloudflare: {"for_waf": "cloudflare"}
• MySQL-specific: {"category": "mysql"}

Returns: tamper count, per-category breakdown, tamper list with name/description/category/tags.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"category": map[string]any{
						"type":        "string",
						"description": "Filter by tamper category.",
						"enum":        []string{"encoding", "space", "sql", "mysql", "mssql", "waf", "http", "obfuscation"},
					},
					"for_waf": map[string]any{
						"type":        "string",
						"description": "Filter tampers tagged for a specific WAF vendor (e.g. 'cloudflare', 'modsecurity', 'aws').",
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    true,
				IdempotentHint:  true,
				DestructiveHint: boolPtr(false),
				Title:           "List Tamper Techniques",
			},
		},
		loggedTool("list_tampers", s.handleListTampers),
	)
}

type listTampersArgs struct {
	Category string `json:"category"`
	ForWAF   string `json:"for_waf"`
}

type tamperInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags,omitempty"`
}

type listTampersResponse struct {
	Summary           string         `json:"summary"`
	TotalCount        int            `json:"total_count"`
	FilteredCount     int            `json:"filtered_count"`
	CategoryBreakdown map[string]int `json:"category_breakdown"`
	Tampers           []tamperInfo   `json:"tampers"`
	NextSteps         []string       `json:"next_steps"`
}

func (s *Server) handleListTampers(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args listTampersArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	allTampers := tampers.All()
	totalCount := len(allTampers)

	// Build category breakdown
	catBreakdown := make(map[string]int)
	for _, t := range allTampers {
		catBreakdown[string(t.Category())]++
	}

	// Filter by category
	var filtered []tampers.Tamper
	if args.Category != "" {
		cat := tampers.Category(args.Category)
		filtered = tampers.ByCategory(cat)
	} else {
		filtered = allTampers
	}

	// Filter by WAF vendor tag
	if args.ForWAF != "" {
		vendor := strings.ToLower(args.ForWAF)
		var vendorFiltered []tampers.Tamper
		for _, t := range filtered {
			for _, tag := range t.Tags() {
				if strings.ToLower(tag) == vendor || strings.Contains(strings.ToLower(tag), vendor) {
					vendorFiltered = append(vendorFiltered, t)
					break
				}
			}
		}
		filtered = vendorFiltered
	}

	// Sort by name
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Name() < filtered[j].Name()
	})

	// Build response
	tamperList := make([]tamperInfo, 0, len(filtered))
	for _, t := range filtered {
		tamperList = append(tamperList, tamperInfo{
			Name:        t.Name(),
			Description: t.Description(),
			Category:    string(t.Category()),
			Tags:        t.Tags(),
		})
	}

	resp := &listTampersResponse{
		TotalCount:        totalCount,
		FilteredCount:     len(filtered),
		CategoryBreakdown: catBreakdown,
		Tampers:           tamperList,
	}

	// Build summary
	var sb strings.Builder
	if args.Category != "" || args.ForWAF != "" {
		fmt.Fprintf(&sb, "Showing %d of %d tamper techniques", len(filtered), totalCount)
		if args.Category != "" {
			fmt.Fprintf(&sb, " (category: %s)", args.Category)
		}
		if args.ForWAF != "" {
			fmt.Fprintf(&sb, " (WAF: %s)", args.ForWAF)
		}
		sb.WriteString(". ")
	} else {
		fmt.Fprintf(&sb, "%d tamper techniques available across %d categories. ", totalCount, len(catBreakdown))
	}

	// Show category breakdown
	cats := make([]string, 0, len(catBreakdown))
	for cat, count := range catBreakdown {
		cats = append(cats, fmt.Sprintf("%s: %d", cat, count))
	}
	sort.Strings(cats)
	fmt.Fprintf(&sb, "Categories: %s.", strings.Join(cats, ", "))
	resp.Summary = sb.String()

	// Build next steps
	steps := make([]string, 0, 4)
	if len(filtered) > 0 {
		steps = append(steps,
			"Use 'discover_bypasses' with a target URL to test which of these tampers actually bypass the WAF.")
	}
	if args.Category == "" {
		steps = append(steps,
			"Filter by category for focused browsing: {\"category\": \"sql\"} or {\"category\": \"waf\"}.")
	}
	steps = append(steps,
		"Use the tamper names with the CLI --tamper flag: waf-tester scan --tamper space2comment,charencode")
	steps = append(steps,
		"Use 'mutate' for encoding-based transformations (URL, Unicode, hex) — complementary to tamper scripts.")
	resp.NextSteps = steps

	return jsonResult(resp)
}
