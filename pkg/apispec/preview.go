package apispec

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// PreviewConfig controls preview rendering behavior.
type PreviewConfig struct {
	// MaxEndpoints limits the number of endpoints shown. 0 = no limit.
	MaxEndpoints int

	// ShowReasons includes the "why selected" column.
	ShowReasons bool

	// ShowPayloadCounts includes estimated payload counts.
	ShowPayloadCounts bool
}

// DefaultPreviewConfig returns sensible defaults for terminal display.
func DefaultPreviewConfig() PreviewConfig {
	return PreviewConfig{
		MaxEndpoints:      50,
		ShowReasons:       true,
		ShowPayloadCounts: true,
	}
}

// RenderPreview writes a human-readable plan summary to w.
// The output is designed for terminal display before scan execution.
func RenderPreview(w io.Writer, plan *ScanPlan, spec *Spec, cfg PreviewConfig) {
	if plan == nil {
		fmt.Fprintln(w, "  No scan plan generated.")
		return
	}

	// Header summary.
	renderSummary(w, plan, spec)

	// Priority breakdown.
	renderPriorityBreakdown(w, plan)

	// Attack category breakdown.
	renderCategoryBreakdown(w, plan)

	// Endpoint table.
	renderEndpointTable(w, plan, cfg)

	// Warnings.
	renderWarnings(w, plan, spec)

	// Duration estimate.
	if plan.EstimatedDuration > 0 {
		fmt.Fprintf(w, "\n  Estimated duration: %s\n", plan.EstimatedDuration.Round(time.Second))
	}
}

// renderSummary writes the top-level plan statistics.
func renderSummary(w io.Writer, plan *ScanPlan, spec *Spec) {
	fmt.Fprintln(w)

	endpointCount := countUniqueEndpoints(plan)
	categoryCount := countUniqueCategories(plan)

	fmt.Fprintf(w, "  Endpoints:   %d\n", endpointCount)
	fmt.Fprintf(w, "  Attack types: %d\n", categoryCount)
	fmt.Fprintf(w, "  Total tests: %d\n", plan.TotalTests)
	fmt.Fprintf(w, "  Intensity:   %s\n", plan.Intensity)

	if spec != nil && spec.Format != "" {
		fmt.Fprintf(w, "  Spec format: %s\n", spec.Format)
	}
}

// renderPriorityBreakdown shows how many entries are at each priority level.
func renderPriorityBreakdown(w io.Writer, plan *ScanPlan) {
	counts := map[Priority]int{}
	for _, e := range plan.Entries {
		counts[e.Endpoint.Priority]++
	}

	if len(counts) == 0 {
		return
	}

	fmt.Fprintf(w, "\n  Priority breakdown:\n")

	// Show in descending priority order.
	for _, p := range []struct {
		pri   Priority
		label string
	}{
		{PriorityCritical, "CRITICAL"},
		{PriorityHigh, "HIGH"},
		{PriorityMedium, "MEDIUM"},
		{PriorityLow, "LOW"},
	} {
		if c, ok := counts[p.pri]; ok {
			fmt.Fprintf(w, "    %-10s %d\n", p.label, c)
		}
	}
}

// renderCategoryBreakdown shows which attack categories are planned.
func renderCategoryBreakdown(w io.Writer, plan *ScanPlan) {
	categories := map[string]int{}
	for _, e := range plan.Entries {
		categories[e.Attack.Category]++
	}

	if len(categories) == 0 {
		return
	}

	// Sort alphabetically.
	names := make([]string, 0, len(categories))
	for name := range categories {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Fprintf(w, "\n  Attack categories:\n")
	for _, name := range names {
		fmt.Fprintf(w, "    %-20s %d targets\n", name, categories[name])
	}
}

// renderEndpointTable shows the per-endpoint plan details.
func renderEndpointTable(w io.Writer, plan *ScanPlan, cfg PreviewConfig) {
	if len(plan.Entries) == 0 {
		return
	}

	// Group entries by endpoint.
	type epKey struct {
		method string
		path   string
	}
	type epGroup struct {
		key        epKey
		priority   Priority
		attacks    []string
		reasons    []string
		totalTests int
	}

	groupOrder := make([]epKey, 0)
	groups := make(map[epKey]*epGroup)

	for _, e := range plan.Entries {
		key := epKey{e.Endpoint.Method, e.Endpoint.Path}
		g, exists := groups[key]
		if !exists {
			g = &epGroup{key: key, priority: e.Endpoint.Priority}
			groups[key] = g
			groupOrder = append(groupOrder, key)
		}
		g.attacks = append(g.attacks, e.Attack.Category)
		if cfg.ShowReasons && e.Attack.Reason != "" {
			g.reasons = append(g.reasons, e.Attack.Reason)
		}
		g.totalTests += e.Attack.PayloadCount
	}

	fmt.Fprintf(w, "\n  Endpoints:\n")

	limit := len(groupOrder)
	truncated := false
	if cfg.MaxEndpoints > 0 && limit > cfg.MaxEndpoints {
		limit = cfg.MaxEndpoints
		truncated = true
	}

	for i := 0; i < limit; i++ {
		key := groupOrder[i]
		g := groups[key]

		// Deduplicate attacks.
		uniqueAttacks := dedupStrings(g.attacks)

		priLabel := priorityLabel(g.priority)
		fmt.Fprintf(w, "    [%s] %s %s\n", priLabel, key.method, key.path)
		fmt.Fprintf(w, "      Scans: %s\n", strings.Join(uniqueAttacks, ", "))

		if cfg.ShowPayloadCounts && g.totalTests > 0 {
			fmt.Fprintf(w, "      Tests: %d\n", g.totalTests)
		}
	}

	if truncated {
		fmt.Fprintf(w, "\n    ... and %d more endpoints (use --dry-run for full plan)\n",
			len(groupOrder)-limit)
	}
}

// renderWarnings surfaces potential issues with the plan.
func renderWarnings(w io.Writer, plan *ScanPlan, spec *Spec) {
	var warnings []string

	if plan.TotalTests == 0 {
		warnings = append(warnings, "No test payloads estimated. The plan may be empty.")
	}

	if spec != nil && len(spec.AuthSchemes) > 0 {
		hasAuth := false
		for _, e := range plan.Entries {
			if len(e.Endpoint.Auth) > 0 {
				hasAuth = true
				break
			}
		}
		if hasAuth {
			warnings = append(warnings, "Some endpoints require auth. Use --bearer, --api-key, or --basic-user/--basic-pass.")
		}
	}

	if len(plan.Entries) > 1000 {
		warnings = append(warnings, fmt.Sprintf("Large plan (%d entries). Consider --intensity quick or --group to limit scope.", len(plan.Entries)))
	}

	if len(warnings) > 0 {
		fmt.Fprintf(w, "\n  Warnings:\n")
		for _, warn := range warnings {
			fmt.Fprintf(w, "    ! %s\n", warn)
		}
	}
}

// priorityLabel converts a Priority to a fixed-width display label.
func priorityLabel(p Priority) string {
	switch p {
	case PriorityCritical:
		return "CRIT"
	case PriorityHigh:
		return "HIGH"
	case PriorityMedium:
		return " MED"
	case PriorityLow:
		return " LOW"
	default:
		return " MED"
	}
}

// countUniqueEndpoints returns the number of distinct method+path pairs.
func countUniqueEndpoints(plan *ScanPlan) int {
	seen := make(map[string]bool)
	for _, e := range plan.Entries {
		seen[e.Endpoint.Method+" "+e.Endpoint.Path] = true
	}
	return len(seen)
}

// countUniqueCategories returns the number of distinct attack categories.
func countUniqueCategories(plan *ScanPlan) int {
	seen := make(map[string]bool)
	for _, e := range plan.Entries {
		seen[e.Attack.Category] = true
	}
	return len(seen)
}

// dedupStrings returns unique values preserving order.
func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
