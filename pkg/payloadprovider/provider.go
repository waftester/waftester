// Package payloadprovider bridges the JSON payload database and Nuclei template
// systems into a unified payload provider. It allows either system to leverage
// payloads from the other, eliminating the disconnect between the two engines.
//
// Architecture:
//
//	JSONSource  ─┐
//	              ├─► UnifiedProvider ─► consumers (CLI, MCP, smart mode)
//	NucleiSource ─┘
//
// Key capabilities:
//   - Unified payload access across both engines
//   - Category mapping between JSON categories and Nuclei template tags
//   - Template enrichment: inject JSON payloads into Nuclei templates
//   - Payload export: convert between formats
//   - Overlap estimation across sources
package payloadprovider

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/nuclei"
	"github.com/waftester/waftester/pkg/payloads"
)

// Source identifies where a payload originated.
type Source string

const (
	SourceJSON   Source = "json"
	SourceNuclei Source = "nuclei"
)

// UnifiedPayload is a normalised payload representation that works
// across both engines. It preserves origin for traceability.
type UnifiedPayload struct {
	ID       string   `json:"id"`
	Payload  string   `json:"payload"`
	Category string   `json:"category"`
	Method   string   `json:"method,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Source   Source   `json:"source"`

	// TemplateID is set when the payload came from a Nuclei template.
	TemplateID string `json:"template_id,omitempty"`

	// ExpectedBlock indicates whether a WAF SHOULD block this payload.
	ExpectedBlock bool `json:"expected_block,omitempty"`
}

// UnifiedStats aggregates statistics from both payload sources.
type UnifiedStats struct {
	TotalPayloads   int            `json:"total_payloads"`
	JSONPayloads    int            `json:"json_payloads"`
	NucleiPayloads  int            `json:"nuclei_payloads"`
	Categories      int            `json:"categories"`
	ByCategory      map[string]int `json:"by_category"`
	BySource        map[Source]int `json:"by_source"`
	OverlapEstimate int            `json:"overlap_estimate"` // approximate duplicate count
}

// CategoryInfo describes a unified category.
type CategoryInfo struct {
	Name           string `json:"name"`
	JSONCount      int    `json:"json_count"`
	NucleiCount    int    `json:"nuclei_count"`
	TotalCount     int    `json:"total_count"`
	HasJSONSource  bool   `json:"has_json_source"`
	HasNucleiTempl bool   `json:"has_nuclei_template"`
}

// Provider is the unified interface for accessing payloads.
type Provider struct {
	jsonLoader   *payloads.Loader
	nucleiDir    string
	payloadDir   string
	categoryMap  *CategoryMapper
	mu           sync.RWMutex
	jsonPayloads []payloads.Payload
	nucleiTempls []*nuclei.Template
	unified      []UnifiedPayload
	loaded       bool
}

// NewProvider creates a unified payload provider.
//
// payloadDir is the root of the JSON payload database (e.g. "payloads/").
// nucleiDir is the root of the Nuclei template directory (defaults.TemplateDir).
func NewProvider(payloadDir, nucleiDir string) *Provider {
	return &Provider{
		jsonLoader:  payloads.NewLoader(payloadDir),
		nucleiDir:   nucleiDir,
		payloadDir:  payloadDir,
		categoryMap: NewCategoryMapper(),
	}
}

// Load initialises both sources. It is safe to call multiple times;
// subsequent calls are no-ops unless Reset is called first.
func (p *Provider) Load() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.loaded {
		return nil
	}

	// Load JSON payloads
	jp, err := p.jsonLoader.LoadAll()
	if err != nil {
		return fmt.Errorf("loading JSON payloads: %w", err)
	}
	p.jsonPayloads = jp

	// Load Nuclei templates (best-effort — directory may not exist)
	if p.nucleiDir != "" {
		tmpls, err := nuclei.LoadDirectory(p.nucleiDir)
		if err == nil {
			p.nucleiTempls = tmpls
		}
		// silently skip if directory doesn't exist
	}

	p.unified = p.merge()
	p.loaded = true
	return nil
}

// Reset clears cached data so the next Load re-reads from disk.
func (p *Provider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jsonPayloads = nil
	p.nucleiTempls = nil
	p.unified = nil
	p.loaded = false
}

// GetAll returns every payload from both sources.
// The returned slice is a shallow copy; callers may freely append or reslice it.
func (p *Provider) GetAll() ([]UnifiedPayload, error) {
	if err := p.Load(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]UnifiedPayload, len(p.unified))
	copy(out, p.unified)
	return out, nil
}

// GetByCategory returns payloads matching the given category (case-insensitive).
// It respects the category mapping, so "sqli" also matches "SQL-Injection".
func (p *Provider) GetByCategory(category string) ([]UnifiedPayload, error) {
	all, err := p.GetAll()
	if err != nil {
		return nil, err
	}

	aliases := p.categoryMap.Resolve(category)
	aliasSet := make(map[string]bool, len(aliases))
	for _, a := range aliases {
		aliasSet[strings.ToLower(a)] = true
	}

	result := make([]UnifiedPayload, 0, 128)
	for _, up := range all {
		if aliasSet[strings.ToLower(up.Category)] {
			result = append(result, up)
		}
	}
	return result, nil
}

// GetByTags returns payloads that have ALL the specified tags.
func (p *Provider) GetByTags(tags []string) ([]UnifiedPayload, error) {
	all, err := p.GetAll()
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedPayload, 0, 128)
	for _, up := range all {
		if hasAllTags(up.Tags, tags) {
			result = append(result, up)
		}
	}
	return result, nil
}

// GetCategories returns information about all categories across both sources.
func (p *Provider) GetCategories() ([]CategoryInfo, error) {
	all, err := p.GetAll()
	if err != nil {
		return nil, err
	}

	catMap := make(map[string]*CategoryInfo)
	for _, up := range all {
		cat := strings.ToLower(up.Category)
		ci, ok := catMap[cat]
		if !ok {
			// Use canonical name from the mapper if available,
			// falling back to the raw category name.
			name := p.categoryMap.canonicalName(cat)
			if name == "" {
				name = up.Category
			}
			ci = &CategoryInfo{Name: name}
			catMap[cat] = ci
		}
		ci.TotalCount++
		switch up.Source {
		case SourceJSON:
			ci.JSONCount++
			ci.HasJSONSource = true
		case SourceNuclei:
			ci.NucleiCount++
			ci.HasNucleiTempl = true
		}
	}

	cats := make([]CategoryInfo, 0, len(catMap))
	for _, ci := range catMap {
		cats = append(cats, *ci)
	}
	return cats, nil
}

// GetStats returns combined statistics.
func (p *Provider) GetStats() (UnifiedStats, error) {
	all, err := p.GetAll()
	if err != nil {
		return UnifiedStats{}, err
	}

	stats := UnifiedStats{
		TotalPayloads: len(all),
		ByCategory:    make(map[string]int),
		BySource:      make(map[Source]int),
	}

	seen := make(map[string]Source) // payload text → first source
	for _, up := range all {
		stats.ByCategory[up.Category]++
		stats.BySource[up.Source]++

		if prev, ok := seen[up.Payload]; ok {
			if prev != up.Source {
				stats.OverlapEstimate++
			}
		} else {
			seen[up.Payload] = up.Source
		}
	}

	stats.JSONPayloads = stats.BySource[SourceJSON]
	stats.NucleiPayloads = stats.BySource[SourceNuclei]
	stats.Categories = len(stats.ByCategory)

	return stats, nil
}

// JSONPayloads returns the raw JSON payloads (for direct payload-engine use).
// The returned slice is a shallow copy.
func (p *Provider) JSONPayloads() ([]payloads.Payload, error) {
	if err := p.Load(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]payloads.Payload, len(p.jsonPayloads))
	copy(out, p.jsonPayloads)
	return out, nil
}

// NucleiTemplates returns the loaded Nuclei templates (for direct template-engine use).
// The returned slice is a shallow copy — the slice itself is independent, but
// elements are shared pointers. Callers that modify individual templates
// should deep-copy them first (e.g. via EnrichTemplate's documented mutation semantics).
func (p *Provider) NucleiTemplates() ([]*nuclei.Template, error) {
	if err := p.Load(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*nuclei.Template, len(p.nucleiTempls))
	copy(out, p.nucleiTempls)
	return out, nil
}

// ToNucleiPayloadMap converts unified payloads into a Nuclei-compatible
// payloads map suitable for injection into a template's HTTPRequest.Payloads field.
// The key is "payloads" and the value is a list of payload strings.
func ToNucleiPayloadMap(ups []UnifiedPayload) map[string]interface{} {
	strs := make([]interface{}, 0, len(ups))
	for _, up := range ups {
		strs = append(strs, up.Payload)
	}
	return map[string]interface{}{
		"payloads": strs,
	}
}

// EnrichTemplate injects JSON payloads matching the template's tags
// into the template's first HTTP request's Path list. This allows
// Nuclei templates to test against the full JSON payload database.
//
// NOTE: This method mutates tmpl in place. Callers that need to
// preserve the original template should pass a deep copy.
func (p *Provider) EnrichTemplate(tmpl *nuclei.Template) (*nuclei.Template, int, error) {
	if err := p.Load(); err != nil {
		return tmpl, 0, err
	}

	if len(tmpl.HTTP) == 0 {
		return tmpl, 0, nil
	}

	// Determine categories from template tags
	tags := parseCommaSeparated(tmpl.Info.Tags)
	categories := p.categoryMap.TagsToCategories(tags)

	if len(categories) == 0 {
		return tmpl, 0, nil
	}

	// Collect matching JSON payloads
	p.mu.RLock()
	matchingPayloads := make([]payloads.Payload, 0, 256)
	for _, jp := range p.jsonPayloads {
		for _, cat := range categories {
			if strings.EqualFold(jp.Category, cat) {
				matchingPayloads = append(matchingPayloads, jp)
				break
			}
		}
	}
	p.mu.RUnlock()

	if len(matchingPayloads) == 0 {
		return tmpl, 0, nil
	}

	// Build additional paths from JSON payloads
	existingPaths := make(map[string]bool, len(tmpl.HTTP[0].Path))
	for _, path := range tmpl.HTTP[0].Path {
		existingPaths[path] = true
	}

	added := 0
	for _, jp := range matchingPayloads {
		// Build a path from the JSON payload
		path := buildPathFromPayload(jp)
		if path != "" && !existingPaths[path] {
			tmpl.HTTP[0].Path = append(tmpl.HTTP[0].Path, path)
			existingPaths[path] = true
			added++
		}
	}

	return tmpl, added, nil
}

// merge combines JSON and Nuclei payloads into a single unified list.
func (p *Provider) merge() []UnifiedPayload {
	capacity := len(p.jsonPayloads)
	for _, t := range p.nucleiTempls {
		for _, h := range t.HTTP {
			capacity += len(h.Path)
		}
	}

	all := make([]UnifiedPayload, 0, capacity)

	// Add JSON payloads
	for _, jp := range p.jsonPayloads {
		all = append(all, UnifiedPayload{
			ID:            jp.ID,
			Payload:       jp.Payload,
			Category:      jp.Category,
			Method:        jp.Method,
			Severity:      jp.SeverityHint,
			Tags:          jp.Tags,
			Source:        SourceJSON,
			ExpectedBlock: jp.ExpectedBlock,
		})
	}

	// Extract payloads from Nuclei templates
	for _, tmpl := range p.nucleiTempls {
		category := p.categoryMap.TemplateToCategory(tmpl)
		for _, req := range tmpl.HTTP {
			for i, path := range req.Path {
				payload := extractPayloadFromPath(path)
				if payload == "" {
					continue
				}
				all = append(all, UnifiedPayload{
					ID:         fmt.Sprintf("%s-path-%d", tmpl.ID, i),
					Payload:    payload,
					Category:   category,
					Method:     req.Method,
					Severity:   tmpl.Info.Severity,
					Tags:       parseCommaSeparated(tmpl.Info.Tags),
					Source:     SourceNuclei,
					TemplateID: tmpl.ID,
				})
			}
		}
	}

	return all
}

// buildPathFromPayload converts a JSON Payload into a Nuclei-style path string.
// GET payloads are URL-encoded to prevent characters like & or = in the payload
// from breaking URL structure.
func buildPathFromPayload(jp payloads.Payload) string {
	target := jp.TargetPath
	if target == "" {
		target = "/"
	}

	// For GET payloads, inject as query parameter
	if strings.EqualFold(jp.Method, "GET") || jp.Method == "" {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		return "{{BaseURL}}" + target + sep + "input=" + url.QueryEscape(jp.Payload)
	}

	// For POST and other methods, just return the target path
	// (payload goes in the body, handled at execution time)
	return "{{BaseURL}}" + target
}

// extractPayloadFromPath extracts the attack payload from a Nuclei template path.
// e.g. "{{BaseURL}}/?id=1' UNION SELECT 1,2,3--" → "1' UNION SELECT 1,2,3--"
//
// This uses the first '=' sign as the delimiter, which works correctly for
// single-parameter URLs (the standard format in WAFtester templates). For
// multi-parameter URLs like "?a=1&b=PAYLOAD", it would return "1&b=PAYLOAD"
// — but this pattern does not occur in the current template corpus.
func extractPayloadFromPath(path string) string {
	// Remove BaseURL prefix
	path = strings.TrimPrefix(path, "{{BaseURL}}")

	// Find the parameter value (after = sign)
	if idx := strings.Index(path, "="); idx != -1 {
		return path[idx+1:]
	}

	// If path itself is the payload (e.g. /../../etc/passwd)
	if isPayloadPath(path) {
		return path
	}

	return ""
}

// isPayloadPath checks if a URL path itself is an attack vector.
func isPayloadPath(path string) bool {
	indicators := []string{
		"..", "etc/passwd", "win.ini", "<script", "${", "{{",
		"UNION", "SELECT", "env", "proc/self",
	}
	lower := strings.ToLower(path)
	for _, ind := range indicators {
		if strings.Contains(lower, strings.ToLower(ind)) {
			return true
		}
	}
	return false
}

// hasAllTags checks if haystack contains all needle tags (case-insensitive).
func hasAllTags(haystack, needles []string) bool {
	if len(needles) == 0 {
		return true
	}

	set := make(map[string]bool, len(haystack))
	for _, t := range haystack {
		set[strings.ToLower(strings.TrimSpace(t))] = true
	}

	for _, n := range needles {
		if !set[strings.ToLower(strings.TrimSpace(n))] {
			return false
		}
	}
	return true
}

// parseCommaSeparated splits a comma-separated string into trimmed values.
func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
