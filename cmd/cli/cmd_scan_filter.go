package main

import (
	"strings"

	"github.com/waftester/waftester/pkg/finding"
)

// scanFilterConfig holds the parsed filter/match criteria from CLI flags.
type scanFilterConfig struct {
	matchSeverities  map[finding.Severity]bool
	filterSeverities map[finding.Severity]bool
	matchCategories  map[string]bool
	filterCategories map[string]bool
	stripEvidence    bool
	stripRemediation bool
}

// parseScanFilters builds a scanFilterConfig from CLI flag values.
func parseScanFilters(matchSev, filterSev, matchCat, filterCat string, inclEvidence, inclRemediation bool) *scanFilterConfig {
	cfg := &scanFilterConfig{
		matchSeverities:  make(map[finding.Severity]bool),
		filterSeverities: make(map[finding.Severity]bool),
		matchCategories:  make(map[string]bool),
		filterCategories: make(map[string]bool),
		stripEvidence:    !inclEvidence,
		stripRemediation: !inclRemediation,
	}
	for _, s := range splitCSV(matchSev) {
		sev := finding.Severity(s)
		if sev.IsValid() {
			cfg.matchSeverities[sev] = true
		}
	}
	for _, s := range splitCSV(filterSev) {
		sev := finding.Severity(s)
		if sev.IsValid() {
			cfg.filterSeverities[sev] = true
		}
	}
	for _, c := range splitCSV(matchCat) {
		cfg.matchCategories[c] = true
	}
	for _, c := range splitCSV(filterCat) {
		cfg.filterCategories[c] = true
	}
	return cfg
}

func (f *scanFilterConfig) hasFilters() bool {
	return len(f.matchSeverities) > 0 || len(f.filterSeverities) > 0 ||
		len(f.matchCategories) > 0 || len(f.filterCategories) > 0 ||
		f.stripEvidence || f.stripRemediation
}

func (f *scanFilterConfig) includeCategory(cat string) bool {
	if len(f.matchCategories) > 0 && !f.matchCategories[cat] {
		return false
	}
	return !f.filterCategories[cat]
}

func (f *scanFilterConfig) includeSeverity(sev finding.Severity) bool {
	if len(f.matchSeverities) > 0 && !f.matchSeverities[sev] {
		return false
	}
	return !f.filterSeverities[sev]
}

// applyFilters removes findings that don't match the filter criteria, strips
// evidence/remediation fields, and recalculates TotalVulns/BySeverity/ByCategory.
func applyFilters(result *ScanResult, f *scanFilterConfig) {
	if !f.hasFilters() {
		return
	}

	result.TotalVulns = 0
	result.BySeverity = make(map[string]int)
	result.ByCategory = make(map[string]int)

	// stripBase clears evidence/remediation on an embedded finding.Vulnerability.
	stripBase := func(v *finding.Vulnerability) {
		if f.stripEvidence {
			v.Evidence = ""
		}
		if f.stripRemediation {
			v.Remediation = ""
		}
	}

	// tally updates the result counters.
	tally := func(cat string, sev finding.Severity) {
		result.TotalVulns++
		result.ByCategory[cat]++
		result.BySeverity[string(sev)]++
	}

	// ── Value-slice scanners ([]Vulnerability, embeds finding.Vulnerability) ──

	// SQLi
	if result.SQLi != nil {
		if !f.includeCategory("sqli") {
			result.SQLi = nil
		} else {
			filtered := result.SQLi.Vulnerabilities[:0]
			for i := range result.SQLi.Vulnerabilities {
				v := &result.SQLi.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, *v)
				}
			}
			result.SQLi.Vulnerabilities = filtered
			for i := range filtered {
				tally("sqli", filtered[i].Severity)
			}
		}
	}

	// XSS
	if result.XSS != nil {
		if !f.includeCategory("xss") {
			result.XSS = nil
		} else {
			filtered := result.XSS.Vulnerabilities[:0]
			for i := range result.XSS.Vulnerabilities {
				v := &result.XSS.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, *v)
				}
			}
			result.XSS.Vulnerabilities = filtered
			for i := range filtered {
				tally("xss", filtered[i].Severity)
			}
		}
	}

	// Traversal
	if result.Traversal != nil {
		if !f.includeCategory("traversal") {
			result.Traversal = nil
		} else {
			filtered := result.Traversal.Vulnerabilities[:0]
			for i := range result.Traversal.Vulnerabilities {
				v := &result.Traversal.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, *v)
				}
			}
			result.Traversal.Vulnerabilities = filtered
			for i := range filtered {
				tally("traversal", filtered[i].Severity)
			}
		}
	}

	// CRLF (own fields, not embedded)
	if result.CRLF != nil {
		if !f.includeCategory("crlf") {
			result.CRLF = nil
		} else {
			filtered := result.CRLF.Vulnerabilities[:0]
			for i := range result.CRLF.Vulnerabilities {
				v := &result.CRLF.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.CRLF.Vulnerabilities = filtered
			for i := range filtered {
				tally("crlf", filtered[i].Severity)
			}
		}
	}

	// Prototype
	if result.Prototype != nil {
		if !f.includeCategory("prototype") {
			result.Prototype = nil
		} else {
			filtered := result.Prototype.Vulnerabilities[:0]
			for i := range result.Prototype.Vulnerabilities {
				v := &result.Prototype.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, *v)
				}
			}
			result.Prototype.Vulnerabilities = filtered
			for i := range filtered {
				tally("prototype", filtered[i].Severity)
			}
		}
	}

	// WebSocket ([]Vulnerability, embeds finding.Vulnerability)
	if result.WebSocket != nil {
		if !f.includeCategory("websocket") {
			result.WebSocket = nil
		} else {
			filtered := result.WebSocket.Vulnerabilities[:0]
			for i := range result.WebSocket.Vulnerabilities {
				v := &result.WebSocket.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, *v)
				}
			}
			result.WebSocket.Vulnerabilities = filtered
			for i := range filtered {
				tally("websocket", filtered[i].Severity)
			}
		}
	}

	// ── Value-slice scanners ([]Vulnerability, own Severity/Evidence/Remediation) ──

	// HPP
	if result.HPP != nil {
		if !f.includeCategory("hpp") {
			result.HPP = nil
		} else {
			filtered := result.HPP.Vulnerabilities[:0]
			for i := range result.HPP.Vulnerabilities {
				v := &result.HPP.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.HPP.Vulnerabilities = filtered
			for i := range filtered {
				tally("hpp", filtered[i].Severity)
			}
		}
	}

	// NoSQLi
	if result.NoSQLi != nil {
		if !f.includeCategory("nosqli") {
			result.NoSQLi = nil
		} else {
			filtered := result.NoSQLi.Vulnerabilities[:0]
			for i := range result.NoSQLi.Vulnerabilities {
				v := &result.NoSQLi.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.NoSQLi.Vulnerabilities = filtered
			for i := range filtered {
				tally("nosqli", filtered[i].Severity)
			}
		}
	}

	// HostHeader
	if result.HostHeader != nil {
		if !f.includeCategory("hostheader") {
			result.HostHeader = nil
		} else {
			filtered := result.HostHeader.Vulnerabilities[:0]
			for i := range result.HostHeader.Vulnerabilities {
				v := &result.HostHeader.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.HostHeader.Vulnerabilities = filtered
			for i := range filtered {
				tally("hostheader", filtered[i].Severity)
			}
		}
	}

	// Cache
	if result.Cache != nil {
		if !f.includeCategory("cache") {
			result.Cache = nil
		} else {
			filtered := result.Cache.Vulnerabilities[:0]
			for i := range result.Cache.Vulnerabilities {
				v := &result.Cache.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.Cache.Vulnerabilities = filtered
			for i := range filtered {
				tally("cache", filtered[i].Severity)
			}
		}
	}

	// SSRF ([]Vulnerability, own fields)
	if result.SSRF != nil {
		if !f.includeCategory("ssrf") {
			result.SSRF = nil
		} else {
			filtered := result.SSRF.Vulnerabilities[:0]
			for i := range result.SSRF.Vulnerabilities {
				v := &result.SSRF.Vulnerabilities[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.SSRF.Vulnerabilities = filtered
			for i := range filtered {
				tally("ssrf", filtered[i].Severity)
			}
		}
	}

	// ── Pointer-slice scanners ([]*Vulnerability, embeds finding.Vulnerability) ──

	// CMDI
	if result.CMDI != nil {
		if !f.includeCategory("cmdi") {
			result.CMDI = nil
		} else {
			filtered := result.CMDI.Vulnerabilities[:0]
			for _, v := range result.CMDI.Vulnerabilities {
				if v != nil && f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, v)
				}
			}
			result.CMDI.Vulnerabilities = filtered
			for _, v := range filtered {
				tally("cmdi", v.Severity)
			}
		}
	}

	// Race
	if result.Race != nil {
		if !f.includeCategory("race") {
			result.Race = nil
		} else {
			filtered := result.Race.Vulnerabilities[:0]
			for _, v := range result.Race.Vulnerabilities {
				if v != nil && f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, v)
				}
			}
			result.Race.Vulnerabilities = filtered
			for _, v := range filtered {
				tally("race", v.Severity)
			}
		}
	}

	// ── Pointer-slice scanners ([]*Vulnerability, own fields) ──

	// CORS
	if result.CORS != nil {
		if !f.includeCategory("cors") {
			result.CORS = nil
		} else {
			filtered := result.CORS.Vulnerabilities[:0]
			for _, v := range result.CORS.Vulnerabilities {
				if v != nil && f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, v)
				}
			}
			result.CORS.Vulnerabilities = filtered
			for _, v := range filtered {
				tally("cors", v.Severity)
			}
		}
	}

	// Redirect
	if result.Redirect != nil {
		if !f.includeCategory("redirect") {
			result.Redirect = nil
		} else {
			filtered := result.Redirect.Vulnerabilities[:0]
			for _, v := range result.Redirect.Vulnerabilities {
				if v != nil && f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, v)
				}
			}
			result.Redirect.Vulnerabilities = filtered
			for _, v := range filtered {
				tally("redirect", v.Severity)
			}
		}
	}

	// GraphQL
	if result.GraphQL != nil {
		if !f.includeCategory("graphql") {
			result.GraphQL = nil
		} else {
			filtered := result.GraphQL.Vulnerabilities[:0]
			for _, v := range result.GraphQL.Vulnerabilities {
				if v != nil && f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, v)
				}
			}
			result.GraphQL.Vulnerabilities = filtered
			for _, v := range filtered {
				tally("graphql", v.Severity)
			}
		}
	}

	// ── Pointer slices ([]*Vulnerability, embeds finding.Vulnerability) ──

	// SSTI
	if len(result.SSTI) > 0 {
		if !f.includeCategory("ssti") {
			result.SSTI = nil
		} else {
			filtered := result.SSTI[:0]
			for _, v := range result.SSTI {
				if v != nil && f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, v)
				}
			}
			result.SSTI = filtered
			for _, v := range filtered {
				tally("ssti", v.Severity)
			}
		}
	}

	// XXE
	if len(result.XXE) > 0 {
		if !f.includeCategory("xxe") {
			result.XXE = nil
		} else {
			filtered := result.XXE[:0]
			for _, v := range result.XXE {
				if v != nil && f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, v)
				}
			}
			result.XXE = filtered
			for _, v := range filtered {
				tally("xxe", v.Severity)
			}
		}
	}

	// ── Top-level slices (own fields) ──

	// Upload (embeds finding.Vulnerability)
	if len(result.Upload) > 0 {
		if !f.includeCategory("upload") {
			result.Upload = nil
		} else {
			filtered := result.Upload[:0]
			for i := range result.Upload {
				v := &result.Upload[i]
				if f.includeSeverity(v.Severity) {
					stripBase(&v.Vulnerability)
					filtered = append(filtered, *v)
				}
			}
			result.Upload = filtered
			for i := range filtered {
				tally("upload", filtered[i].Severity)
			}
		}
	}

	// Deserialize (own Severity/Evidence/Remediation fields)
	if len(result.Deserialize) > 0 {
		if !f.includeCategory("deserialize") {
			result.Deserialize = nil
		} else {
			filtered := result.Deserialize[:0]
			for i := range result.Deserialize {
				v := &result.Deserialize[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.Deserialize = filtered
			for i := range filtered {
				tally("deserialize", filtered[i].Severity)
			}
		}
	}

	// OAuth (own fields)
	if len(result.OAuth) > 0 {
		if !f.includeCategory("oauth") {
			result.OAuth = nil
		} else {
			filtered := result.OAuth[:0]
			for i := range result.OAuth {
				v := &result.OAuth[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.OAuth = filtered
			for i := range filtered {
				tally("oauth", filtered[i].Severity)
			}
		}
	}

	// BizLogic (own fields)
	if len(result.BizLogic) > 0 {
		if !f.includeCategory("bizlogic") {
			result.BizLogic = nil
		} else {
			filtered := result.BizLogic[:0]
			for i := range result.BizLogic {
				v := &result.BizLogic[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.BizLogic = filtered
			for i := range filtered {
				tally("bizlogic", filtered[i].Severity)
			}
		}
	}

	// APIFuzz (own fields, no Remediation field)
	if len(result.APIFuzz) > 0 {
		if !f.includeCategory("apifuzz") {
			result.APIFuzz = nil
		} else {
			filtered := result.APIFuzz[:0]
			for i := range result.APIFuzz {
				v := &result.APIFuzz[i]
				if f.includeSeverity(v.Severity) {
					if f.stripEvidence {
						v.Evidence = ""
					}
					filtered = append(filtered, *v)
				}
			}
			result.APIFuzz = filtered
			for i := range filtered {
				tally("apifuzz", filtered[i].Severity)
			}
		}
	}

	// ── Special types ──

	// Smuggling: Severity is string, Evidence is []Evidence (not string)
	if result.Smuggling != nil {
		if !f.includeCategory("smuggling") {
			result.Smuggling = nil
		} else {
			filtered := result.Smuggling.Vulnerabilities[:0]
			for i := range result.Smuggling.Vulnerabilities {
				v := &result.Smuggling.Vulnerabilities[i]
				sev := finding.Severity(v.Severity)
				if f.includeSeverity(sev) {
					filtered = append(filtered, *v)
				}
			}
			result.Smuggling.Vulnerabilities = filtered
			for i := range filtered {
				tally("smuggling", finding.Severity(filtered[i].Severity))
			}
		}
	}

	// JWT: Severity is string, has Remediation (string) but no Evidence
	if len(result.JWT) > 0 {
		if !f.includeCategory("jwt") {
			result.JWT = nil
		} else {
			filtered := result.JWT[:0]
			for _, v := range result.JWT {
				if v == nil {
					continue
				}
				sev := finding.Severity(v.Severity)
				if f.includeSeverity(sev) {
					if f.stripRemediation {
						v.Remediation = ""
					}
					filtered = append(filtered, v)
				}
			}
			result.JWT = filtered
			for _, v := range filtered {
				tally("jwt", finding.Severity(v.Severity))
			}
		}
	}

	// ── Non-vulnerability scanners (category-only filtering) ──
	if !f.includeCategory("wafdetect") {
		result.WAFDetect = nil
	}
	if !f.includeCategory("waffprint") {
		result.WAFFprint = nil
	}
	if !f.includeCategory("wafevasion") {
		result.WAFEvasion = nil
	}
	if !f.includeCategory("tlsprobe") {
		result.TLSInfo = nil
	}
	if !f.includeCategory("httpprobe") {
		result.HTTPInfo = nil
	}
	if !f.includeCategory("secheaders") {
		result.SecHeaders = nil
	}
	if !f.includeCategory("jsanalyze") {
		result.JSAnalysis = nil
	}
	if !f.includeCategory("apidepth") {
		result.APIRoutes = nil
	}
	if !f.includeCategory("osint") {
		result.OSINT = nil
	}
	if !f.includeCategory("vhost") {
		result.VHosts = nil
	}
	if !f.includeCategory("techdetect") {
		result.TechStack = nil
	}
	if !f.includeCategory("dnsrecon") {
		result.DNSInfo = nil
	}

	// Subtakeover: []subtakeover.ScanResult — category-only, no per-vuln severity
	if !f.includeCategory("subtakeover") {
		result.Subtakeover = nil
	}
}

// splitCSV splits a comma-separated string into trimmed, lowercased, non-empty parts.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
