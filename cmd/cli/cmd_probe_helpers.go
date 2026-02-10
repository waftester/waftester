// cmd_probe_helpers.go - Helper functions for probe command
package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/probes"
	"github.com/waftester/waftester/pkg/regexcache"
)

// generateCPE generates CPE 2.3 identifiers from technology detection results.
func generateCPE(tech *probes.TechResult) []string {
	if tech == nil {
		return nil
	}
	cpes := []string{}
	for _, t := range tech.Technologies {
		// CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
		vendor := strings.ToLower(strings.ReplaceAll(t.Name, " ", "_"))
		product := vendor
		version := t.Version
		if version == "" {
			version = "*"
		}
		cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
		cpes = append(cpes, cpe)
	}
	// Add server CPE if present
	if tech.Generator != "" {
		parts := strings.Fields(tech.Generator)
		if len(parts) > 0 {
			product := strings.ToLower(strings.ReplaceAll(parts[0], "/", "_"))
			version := "*"
			if len(parts) > 1 {
				version = parts[len(parts)-1]
			}
			cpe := fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", product, version)
			cpes = append(cpes, cpe)
		}
	}
	return cpes
}

// stripHTMLTags removes HTML/XML tags and collapses whitespace from content.
func stripHTMLTags(content string) string {
	// Remove script and style elements entirely
	scriptRe := regexcache.MustGet(`(?is)<script[^>]*>.*?</script>`)
	content = scriptRe.ReplaceAllString(content, "")
	styleRe := regexcache.MustGet(`(?is)<style[^>]*>.*?</style>`)
	content = styleRe.ReplaceAllString(content, "")
	// Remove all HTML tags
	tagRe := regexcache.MustGet(`<[^>]+>`)
	content = tagRe.ReplaceAllString(content, " ")
	// Collapse multiple whitespace
	spaceRe := regexcache.MustGet(`\s+`)
	content = spaceRe.ReplaceAllString(content, " ")
	return strings.TrimSpace(content)
}

// matchRange checks if value matches a range specification like "100,200-500".
func matchRange(value int, rangeSpec string) bool {
	if rangeSpec == "" {
		return true
	}
	parts := strings.Split(rangeSpec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) == 2 {
				low, _ := strconv.Atoi(strings.TrimSpace(bounds[0]))
				high, _ := strconv.Atoi(strings.TrimSpace(bounds[1]))
				if value >= low && value <= high {
					return true
				}
			}
		} else {
			match, _ := strconv.Atoi(part)
			if value == match {
				return true
			}
		}
	}
	return false
}

// matchTimeCondition checks if responseTime satisfies a condition like "<1s" or ">500ms".
func matchTimeCondition(responseTime time.Duration, condition string) bool {
	if condition == "" {
		return true
	}
	condition = strings.TrimSpace(condition)
	var op string
	var threshold string
	if strings.HasPrefix(condition, "<=") {
		op = "<="
		threshold = condition[2:]
	} else if strings.HasPrefix(condition, ">=") {
		op = ">="
		threshold = condition[2:]
	} else if strings.HasPrefix(condition, "<") {
		op = "<"
		threshold = condition[1:]
	} else if strings.HasPrefix(condition, ">") {
		op = ">"
		threshold = condition[1:]
	} else {
		return true // no operator, ignore
	}
	dur, err := time.ParseDuration(threshold)
	if err != nil {
		return true
	}
	switch op {
	case "<":
		return responseTime < dur
	case "<=":
		return responseTime <= dur
	case ">":
		return responseTime > dur
	case ">=":
		return responseTime >= dur
	}
	return true
}

// portSpec holds a parsed port specification with optional scheme.
type portSpec struct {
	scheme string
	port   int
}

// parseProbePorts parses NMAP-style port specifications like "http:80,https:443,8080-8090".
func parseProbePorts(spec string) []portSpec {
	var result []portSpec
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		scheme := "" // empty means use original URL scheme
		portPart := part

		// Check for scheme prefix (http:80 or https:443)
		if strings.Contains(part, ":") {
			colonIdx := strings.Index(part, ":")
			possibleScheme := strings.ToLower(part[:colonIdx])
			if possibleScheme == "http" || possibleScheme == "https" {
				scheme = possibleScheme
				portPart = part[colonIdx+1:]
			}
		}

		// Check for port range (8080-8090)
		if strings.Contains(portPart, "-") && !strings.HasPrefix(portPart, "-") {
			rangeParts := strings.Split(portPart, "-")
			if len(rangeParts) == 2 {
				startPort, err1 := strconv.Atoi(rangeParts[0])
				endPort, err2 := strconv.Atoi(rangeParts[1])
				if err1 == nil && err2 == nil && startPort <= endPort {
					for p := startPort; p <= endPort; p++ {
						result = append(result, portSpec{scheme, p})
					}
				}
			}
		} else {
			// Single port
			p, err := strconv.Atoi(portPart)
			if err == nil {
				result = append(result, portSpec{scheme, p})
			}
		}
	}
	return result
}

// expandProbeTargetPorts expands targets with the given port specifications.
func expandProbeTargetPorts(targets []string, portSpecs []portSpec) []string {
	var expanded []string
	for _, t := range targets {
		parsedURL, err := url.Parse(t)
		if err != nil {
			expanded = append(expanded, t)
			continue
		}
		baseHost := parsedURL.Hostname()
		for _, ps := range portSpecs {
			scheme := parsedURL.Scheme
			if ps.scheme != "" {
				scheme = ps.scheme
			}
			newURL := fmt.Sprintf("%s://%s:%d%s", scheme, baseHost, ps.port, parsedURL.Path)
			expanded = append(expanded, newURL)
		}
	}
	return expanded
}
