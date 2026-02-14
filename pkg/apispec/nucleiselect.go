package apispec

import (
	"path/filepath"
	"strings"

	"github.com/waftester/waftester/pkg/nuclei"
)

// TemplateMatch pairs a Nuclei template with the reason it was selected
// for a given endpoint.
type TemplateMatch struct {
	Template *nuclei.Template
	Reason   string
}

// SelectTemplatesForEndpoint returns Nuclei templates relevant to an endpoint
// by matching on three criteria:
//  1. Tag matching: template tags match attack categories from the plan entry.
//  2. Path matching: template HTTP paths overlap with the endpoint path.
//  3. Method matching: template uses the same HTTP method.
//
// Templates matching on multiple criteria are included once with a combined reason.
func SelectTemplatesForEndpoint(ep Endpoint, attacks []AttackSelection, templates []*nuclei.Template) []TemplateMatch {
	if len(templates) == 0 {
		return nil
	}

	// Build the set of attack categories for this endpoint.
	categorySet := make(map[string]bool, len(attacks))
	for _, a := range attacks {
		categorySet[strings.ToLower(a.Category)] = true
	}

	var matches []TemplateMatch
	seen := make(map[string]bool)

	for _, tmpl := range templates {
		if tmpl == nil {
			continue
		}

		var reasons []string

		// Criterion 1: tag matching.
		if matchTags(tmpl, categorySet) {
			reasons = append(reasons, "tag match")
		}

		// Criterion 2: path matching.
		if matchPath(tmpl, ep.Path) {
			reasons = append(reasons, "path match")
		}

		// Criterion 3: method matching.
		if matchMethod(tmpl, ep.Method) {
			reasons = append(reasons, "method match")
		}

		if len(reasons) > 0 && !seen[tmpl.ID] {
			seen[tmpl.ID] = true
			matches = append(matches, TemplateMatch{
				Template: tmpl,
				Reason:   strings.Join(reasons, ", "),
			})
		}
	}

	return matches
}

// matchTags checks whether any of the template's comma-separated tags
// appear in the attack category set.
func matchTags(tmpl *nuclei.Template, categories map[string]bool) bool {
	tags := strings.Split(tmpl.Info.Tags, ",")
	for _, tag := range tags {
		tag = strings.TrimSpace(strings.ToLower(tag))
		if tag != "" && categories[tag] {
			return true
		}
	}
	return false
}

// matchPath checks whether any of the template's HTTP request paths
// overlap with the endpoint path. Template paths use {{BaseURL}}
// prefix which is stripped before comparison.
func matchPath(tmpl *nuclei.Template, endpointPath string) bool {
	if len(tmpl.HTTP) == 0 {
		return false
	}

	// Normalize the endpoint path for comparison.
	epNorm := normalizePath(strings.ToLower(endpointPath))

	for _, req := range tmpl.HTTP {
		for _, p := range req.Path {
			templatePath := extractTemplatePath(p)
			if templatePath == "" {
				continue
			}
			tpNorm := strings.ToLower(templatePath)

			// Exact match or prefix match.
			if tpNorm == epNorm || strings.HasPrefix(epNorm, tpNorm) {
				return true
			}

			// Check if template targets a directory that contains
			// the endpoint (e.g., template "/admin" matches endpoint
			// "/admin/users").
			if strings.HasPrefix(epNorm, tpNorm+"/") {
				return true
			}
		}
	}
	return false
}

// matchMethod checks whether the template uses the same HTTP method
// as the endpoint.
func matchMethod(tmpl *nuclei.Template, method string) bool {
	if len(tmpl.HTTP) == 0 {
		return false
	}

	method = strings.ToUpper(method)
	for _, req := range tmpl.HTTP {
		if strings.EqualFold(req.Method, method) {
			return true
		}
		// Raw requests encode the method in the first line.
		for _, raw := range req.Raw {
			firstLine := strings.SplitN(raw, "\n", 2)[0]
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(firstLine)), method+" ") {
				return true
			}
		}
	}
	return false
}

// extractTemplatePath removes the {{BaseURL}} prefix and query string
// from a Nuclei template path, returning the clean path segment.
func extractTemplatePath(templatePath string) string {
	// Remove {{BaseURL}} or {{RootURL}} prefix.
	p := templatePath
	for _, prefix := range []string{"{{BaseURL}}", "{{RootURL}}", "{{baseURL}}", "{{rootURL}}"} {
		p = strings.TrimPrefix(p, prefix)
	}

	// Remove query string.
	if idx := strings.IndexByte(p, '?'); idx >= 0 {
		p = p[:idx]
	}

	// Clean up the path.
	p = filepath.ToSlash(p)
	if p == "" || p == "/" {
		return ""
	}

	return p
}
