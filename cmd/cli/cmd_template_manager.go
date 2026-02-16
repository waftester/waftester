package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/waftester/waftester/pkg/templateresolver"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// TEMPLATE MANAGER COMMAND — list/show bundled templates
// =============================================================================

// runTemplateManager handles "templates list" and "templates show" subcommands.
// Returns true if it handled the subcommand, false to fall through to runTemplate.
func runTemplateManager() bool {
	if len(os.Args) < 3 {
		return false
	}

	switch os.Args[2] {
	case "list":
		runTemplateList()
		return true
	case "show":
		runTemplateShow()
		return true
	default:
		return false
	}
}

// categoryDescriptions maps template kinds to human-readable descriptions.
var categoryDescriptions = map[templateresolver.Kind]string{
	templateresolver.KindNuclei:       "Nuclei-compatible WAF bypass and detection templates",
	templateresolver.KindWorkflow:     "Multi-step scan orchestration workflows",
	templateresolver.KindPolicy:       "CI/CD pass/fail gate policies",
	templateresolver.KindOverride:     "Test override configurations",
	templateresolver.KindOutputFormat: "Custom output format templates (Go text/template)",
	templateresolver.KindReportConfig: "HTML report theme and layout configs",
}

func runTemplateList() {
	ui.PrintCompactBanner()

	// Parse flags and positional args from os.Args[3:]
	jsonOutput := false
	var categoryArg string
	for _, arg := range os.Args[3:] {
		if arg == "--json" || arg == "-json" {
			jsonOutput = true
		} else if !strings.HasPrefix(arg, "-") && categoryArg == "" {
			categoryArg = arg
		}
	}

	// If a category was specified, list templates in that category
	if categoryArg != "" {
		kind, err := parseKind(categoryArg)
		if err != nil {
			ui.PrintError(err.Error())
			os.Exit(1)
		}
		listCategoryTemplates(kind, jsonOutput)
		return
	}

	// List all categories
	categories := templateresolver.ListAllCategories()

	if jsonOutput {
		type catJSON struct {
			Kind        string `json:"kind"`
			Count       int    `json:"count"`
			Description string `json:"description"`
		}
		out := make([]catJSON, 0, len(categories))
		for _, cat := range categories {
			out = append(out, catJSON{
				Kind:        string(cat.Kind),
				Count:       cat.Count,
				Description: categoryDescriptions[cat.Kind],
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			ui.PrintError(fmt.Sprintf("JSON encoding failed: %v", err))
			os.Exit(1)
		}
		return
	}

	ui.PrintSection("Template Library (Bundled)")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  CATEGORY\tCOUNT\tDESCRIPTION\n")
	fmt.Fprintf(w, "  ────────\t─────\t───────────\n")
	for _, cat := range categories {
		desc := categoryDescriptions[cat.Kind]
		fmt.Fprintf(w, "  %s\t%d\t%s\n", cat.Kind, cat.Count, desc)
	}
	w.Flush()

	fmt.Println()
	fmt.Println("  Use 'waf-tester templates list <category>' to see templates in a category.")
	fmt.Println("  Use 'waf-tester templates show <category>/<name>' to view a template.")
	fmt.Println()
	fmt.Println("  Short names work with flags:")
	fmt.Println("    --policy strict          (resolves to policies/strict.yaml)")
	fmt.Println("    --overrides api-only     (resolves to overrides/api-only.yaml)")
	fmt.Println("    --template-config dark   (resolves to report-configs/dark.yaml)")
	fmt.Println()
}

func listCategoryTemplates(kind templateresolver.Kind, jsonOutput bool) {
	infos, err := templateresolver.ListCategory(kind)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to list %s: %v", kind, err))
		os.Exit(1)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(infos); encErr != nil {
			ui.PrintError(fmt.Sprintf("JSON encoding error: %v", encErr))
			os.Exit(1)
		}
		return
	}

	ui.PrintSection(fmt.Sprintf("Templates: %s (%d)", kind, len(infos)))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  NAME\tPATH\n")
	fmt.Fprintf(w, "  ────\t────\n")
	for _, info := range infos {
		fmt.Fprintf(w, "  %s\t%s\n", info.Name, info.Path)
	}
	w.Flush()
	fmt.Println()
}

func runTemplateShow() {
	ui.PrintCompactBanner()

	if len(os.Args) < 4 {
		ui.PrintError("Template path required. Usage: waf-tester templates show <category>/<name>")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  waf-tester templates show policies/strict")
		fmt.Println("  waf-tester templates show workflows/full-scan")
		fmt.Println("  waf-tester templates show output/slack-notification")
		fmt.Println("  waf-tester templates show nuclei/http/waf-bypass/sqli-basic")
		os.Exit(1)
	}

	ref := os.Args[3]

	// Parse category/name from the reference.
	// Normalize backslashes so Windows users can type policies\strict.
	normalized := strings.ReplaceAll(ref, "\\", "/")
	parts := strings.SplitN(normalized, "/", 2)
	if len(parts) != 2 {
		ui.PrintError(fmt.Sprintf("Invalid template reference %q. Use <category>/<name> format.", ref))
		os.Exit(1)
	}

	kind, err := parseKind(parts[0])
	if err != nil {
		ui.PrintError(err.Error())
		os.Exit(1)
	}

	var result *templateresolver.Result
	if strings.Contains(parts[1], "/") {
		// Name has directory separators (e.g. nuclei subdirectories like
		// "http/waf-bypass/sqli-basic"). Use full embedded path directly.
		embeddedPath := string(kind) + "/" + parts[1]
		result, err = templateresolver.ResolveEmbeddedPath(embeddedPath)
	} else {
		result, err = templateresolver.Resolve(parts[1], kind)
	}
	if err != nil {
		ui.PrintError(fmt.Sprintf("Template not found: %v", err))
		os.Exit(1)
	}
	defer result.Content.Close()

	const maxSize = 1 << 20 // 1 MB
	data, err := io.ReadAll(io.LimitReader(result.Content, maxSize+1))
	if err != nil {
		ui.PrintError(fmt.Sprintf("Reading template: %v", err))
		os.Exit(1)
	}

	if len(data) > maxSize {
		data = data[:maxSize]
		// Trim any trailing partial UTF-8 sequence produced by byte-level truncation.
		for len(data) > 0 && !utf8.Valid(data) {
			data = data[:len(data)-1]
		}
		fmt.Fprintf(os.Stderr, "Warning: output truncated at %d bytes\n", maxSize)
	}

	if !utf8.Valid(data) {
		ui.PrintError(fmt.Sprintf("Template %q contains binary content and cannot be displayed", ref))
		os.Exit(1)
	}

	ui.PrintSection(fmt.Sprintf("Template: %s (source: %s)", ref, result.Source))
	fmt.Println()
	fmt.Println(string(data))
}

func parseKind(s string) (templateresolver.Kind, error) {
	// Accept both singular and plural, with and without hyphens
	switch strings.ToLower(s) {
	case "nuclei", "template", "templates":
		return templateresolver.KindNuclei, nil
	case "workflow", "workflows":
		return templateresolver.KindWorkflow, nil
	case "policy", "policies":
		return templateresolver.KindPolicy, nil
	case "override", "overrides":
		return templateresolver.KindOverride, nil
	case "output", "output-format", "output-formats":
		return templateresolver.KindOutputFormat, nil
	case "report-config", "report-configs", "report":
		return templateresolver.KindReportConfig, nil
	default:
		validKinds := "nuclei, template, templates, workflow, workflows, policy, policies, override, overrides, output, output-format, output-formats, report-config, report-configs, report"
		return "", fmt.Errorf("unknown template category %q. Valid categories: %s", s, validKinds)
	}
}
