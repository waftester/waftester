// Package subdomain extracts subdomains from text content.
// Used by the JS analyzer, discovery sources, and crawler.
package subdomain

import (
	"regexp"
	"sort"
	"strings"
)

// domainPattern matches domain-like strings (with optional protocol prefix).
// Requires at least two labels (one dot) and a 2+ char TLD.
var domainPattern = regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}`)

// Extract finds all domain-like strings in content and returns unique,
// sorted, lowercase results. If baseDomain is non-empty, results are
// filtered to subdomains of that domain (or the domain itself).
func Extract(content, baseDomain string) []string {
	matches := domainPattern.FindAllString(content, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(matches))
	var result []string

	bd := strings.ToLower(baseDomain)

	for _, m := range matches {
		clean := strings.TrimPrefix(m, "https://")
		clean = strings.TrimPrefix(clean, "http://")
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
			if clean != bd && !strings.HasSuffix(clean, "."+bd) {
				continue
			}
		}

		result = append(result, clean)
	}

	sort.Strings(result)
	return result
}

// ExtractStrict finds subdomains using an anchored regex on baseDomain.
// Only returns results that are strict subdomains (excludes baseDomain
// itself). This is the behavior used by discovery and crawler callers
// that always have a known target domain.
func ExtractStrict(content, baseDomain string) []string {
	if baseDomain == "" {
		return nil
	}

	escaped := regexp.QuoteMeta(baseDomain)
	re, err := regexp.Compile(`(?i)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.` + escaped + `)`)
	if err != nil {
		return nil
	}

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
	return result
}
