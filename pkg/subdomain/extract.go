// Package subdomain extracts subdomains from text content.
// Used by the JS analyzer, discovery sources, and crawler.
package subdomain

import (
	"regexp"
	"sort"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/urlutil"
)

// domainPattern matches domain-like strings (with optional protocol prefix).
// Requires at least two labels (one dot) and a 2+ char TLD.
var domainPattern = regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}`)

// Extract finds subdomains in content and returns unique, sorted, lowercase
// results. When baseDomain is provided, an anchored regex is used for
// precision and the base domain itself is excluded from results. When
// baseDomain is empty, a loose regex finds all domain-like strings.
func Extract(content, baseDomain string) []string {
	if baseDomain != "" {
		return extractAnchored(content, baseDomain)
	}
	return extractLoose(content, "")
}

// extractAnchored uses a regex anchored on baseDomain for precise matching.
// Only returns strict subdomains (excludes baseDomain itself).
func extractAnchored(content, baseDomain string) []string {
	escaped := regexp.QuoteMeta(baseDomain)
	re := regexcache.MustGet(`(?i)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.` + escaped + `)`)

	matches := re.FindAllString(content, -1)
	if len(matches) == 0 {
		return nil
	}

	bd := strings.ToLower(baseDomain)
	seen := make(map[string]bool, len(matches))
	var result []string

	for _, m := range matches {
		lower := strings.ToLower(m)
		if lower == bd || seen[lower] {
			continue
		}
		seen[lower] = true
		result = append(result, lower)
	}

	sort.Strings(result)
	return result
}

// extractLoose uses a broad regex to find all domain-like strings.
// If baseDomain is set, results are filtered to subdomains of that domain
// (the base domain itself is excluded).
func extractLoose(content, baseDomain string) []string {
	matches := domainPattern.FindAllString(content, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(matches))
	var result []string

	bd := strings.ToLower(baseDomain)

	for _, m := range matches {
		clean := urlutil.StripScheme(m)
		clean = strings.ToLower(clean)

		if len(clean) < 5 {
			continue
		}

		if seen[clean] {
			continue
		}
		seen[clean] = true

		// Scope filter
		if bd != "" {
			if clean == bd || !strings.HasSuffix(clean, "."+bd) {
				continue
			}
		}

		result = append(result, clean)
	}

	sort.Strings(result)
	return result
}

// ExtractAll finds all domain-like strings in content without scope filtering.
// Use this when you need to see every domain mentioned (e.g., JS analysis
// where you want to filter CDNs yourself). The base domain itself is included.
func ExtractAll(content string) []string {
	return extractLoose(content, "")
}
