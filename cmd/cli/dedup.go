package main

import (
	"fmt"

	"github.com/waftester/waftester/pkg/apifuzz"
	"github.com/waftester/waftester/pkg/bizlogic"
	"github.com/waftester/waftester/pkg/cache"
	"github.com/waftester/waftester/pkg/cmdi"
	"github.com/waftester/waftester/pkg/cors"
	"github.com/waftester/waftester/pkg/crlf"
	"github.com/waftester/waftester/pkg/deserialize"
	"github.com/waftester/waftester/pkg/graphql"
	"github.com/waftester/waftester/pkg/hostheader"
	"github.com/waftester/waftester/pkg/hpp"
	"github.com/waftester/waftester/pkg/jwt"
	"github.com/waftester/waftester/pkg/nosqli"
	"github.com/waftester/waftester/pkg/oauth"
	"github.com/waftester/waftester/pkg/prototype"
	"github.com/waftester/waftester/pkg/race"
	"github.com/waftester/waftester/pkg/redirect"
	"github.com/waftester/waftester/pkg/smuggling"
	"github.com/waftester/waftester/pkg/sqli"
	"github.com/waftester/waftester/pkg/ssrf"
	"github.com/waftester/waftester/pkg/ssti"
	"github.com/waftester/waftester/pkg/subtakeover"
	"github.com/waftester/waftester/pkg/traversal"
	"github.com/waftester/waftester/pkg/upload"
	"github.com/waftester/waftester/pkg/websocket"
	"github.com/waftester/waftester/pkg/xss"
	"github.com/waftester/waftester/pkg/xxe"
)

// DeduplicateFindings groups findings by key, keeps the first occurrence,
// and calls setConfirmed with the count of findings sharing the same key.
func DeduplicateFindings[T any](findings []T, keyFn func(T) string, setConfirmed func(*T, int)) []T {
	if len(findings) <= 1 {
		if len(findings) == 1 {
			setConfirmed(&findings[0], 1)
		}
		return findings
	}

	type group struct {
		index int
		count int
	}
	groups := make(map[string]*group, len(findings))
	order := make([]string, 0, len(findings))

	for i, f := range findings {
		key := keyFn(f)
		if g, ok := groups[key]; ok {
			g.count++
		} else {
			groups[key] = &group{index: i, count: 1}
			order = append(order, key)
		}
	}

	// No duplicates found
	if len(order) == len(findings) {
		for i := range findings {
			setConfirmed(&findings[i], 1)
		}
		return findings
	}

	result := make([]T, 0, len(order))
	for _, key := range order {
		g := groups[key]
		f := findings[g.index]
		setConfirmed(&f, g.count)
		result = append(result, f)
	}
	return result
}

// deduplicateAllFindings deduplicates vulnerability findings across all
// scanners and recalculates aggregate counts from scratch.
func deduplicateAllFindings(r *ScanResult) {
	r.TotalVulns = 0
	r.BySeverity = make(map[string]int)
	r.ByCategory = make(map[string]int)

	// --- Scanners with *ScanResult wrappers ([]Vulnerability) ---

	if r.SQLi != nil && len(r.SQLi.Vulnerabilities) > 0 {
		r.SQLi.Vulnerabilities = DeduplicateFindings(r.SQLi.Vulnerabilities,
			func(v sqli.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Parameter, v.Type, v.DBMS)
			},
			func(v *sqli.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "sqli", len(r.SQLi.Vulnerabilities))
		for _, v := range r.SQLi.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.XSS != nil && len(r.XSS.Vulnerabilities) > 0 {
		r.XSS.Vulnerabilities = DeduplicateFindings(r.XSS.Vulnerabilities,
			func(v xss.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Parameter, v.Type, v.Context)
			},
			func(v *xss.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "xss", len(r.XSS.Vulnerabilities))
		for _, v := range r.XSS.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.Traversal != nil && len(r.Traversal.Vulnerabilities) > 0 {
		r.Traversal.Vulnerabilities = DeduplicateFindings(r.Traversal.Vulnerabilities,
			func(v traversal.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Parameter, v.Type, v.FileFound)
			},
			func(v *traversal.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "traversal", len(r.Traversal.Vulnerabilities))
		for _, v := range r.Traversal.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.NoSQLi != nil && len(r.NoSQLi.Vulnerabilities) > 0 {
		r.NoSQLi.Vulnerabilities = DeduplicateFindings(r.NoSQLi.Vulnerabilities,
			func(v nosqli.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Parameter, v.Type, v.Database)
			},
			func(v *nosqli.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "nosqli", len(r.NoSQLi.Vulnerabilities))
		for _, v := range r.NoSQLi.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.HPP != nil && len(r.HPP.Vulnerabilities) > 0 {
		r.HPP.Vulnerabilities = DeduplicateFindings(r.HPP.Vulnerabilities,
			func(v hpp.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Parameter, v.Type, v.Technology)
			},
			func(v *hpp.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "hpp", len(r.HPP.Vulnerabilities))
		for _, v := range r.HPP.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.CRLF != nil && len(r.CRLF.Vulnerabilities) > 0 {
		r.CRLF.Vulnerabilities = DeduplicateFindings(r.CRLF.Vulnerabilities,
			func(v crlf.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s", v.URL, v.Parameter, v.Type)
			},
			func(v *crlf.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "crlf", len(r.CRLF.Vulnerabilities))
		for _, v := range r.CRLF.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.Prototype != nil && len(r.Prototype.Vulnerabilities) > 0 {
		r.Prototype.Vulnerabilities = DeduplicateFindings(r.Prototype.Vulnerabilities,
			func(v prototype.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Parameter, v.Type, v.Gadget)
			},
			func(v *prototype.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "prototype", len(r.Prototype.Vulnerabilities))
		for _, v := range r.Prototype.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.HostHeader != nil && len(r.HostHeader.Vulnerabilities) > 0 {
		r.HostHeader.Vulnerabilities = DeduplicateFindings(r.HostHeader.Vulnerabilities,
			func(v hostheader.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s", v.URL, v.Header, v.Type)
			},
			func(v *hostheader.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "hostheader", len(r.HostHeader.Vulnerabilities))
		for _, v := range r.HostHeader.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.WebSocket != nil && len(r.WebSocket.Vulnerabilities) > 0 {
		r.WebSocket.Vulnerabilities = DeduplicateFindings(r.WebSocket.Vulnerabilities,
			func(v websocket.Vulnerability) string {
				return fmt.Sprintf("%s|%s", v.URL, v.Type)
			},
			func(v *websocket.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "websocket", len(r.WebSocket.Vulnerabilities))
		for _, v := range r.WebSocket.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.Cache != nil && len(r.Cache.Vulnerabilities) > 0 {
		r.Cache.Vulnerabilities = DeduplicateFindings(r.Cache.Vulnerabilities,
			func(v cache.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s", v.URL, v.Header, v.Type)
			},
			func(v *cache.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "cache", len(r.Cache.Vulnerabilities))
		for _, v := range r.Cache.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.GraphQL != nil && len(r.GraphQL.Vulnerabilities) > 0 {
		r.GraphQL.Vulnerabilities = DeduplicateFindings(r.GraphQL.Vulnerabilities,
			func(v *graphql.Vulnerability) string {
				return string(v.Type)
			},
			func(v **graphql.Vulnerability, n int) { (*v).ConfirmedBy = n },
		)
		addCounts(r, "graphql", len(r.GraphQL.Vulnerabilities))
		for _, v := range r.GraphQL.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	// --- Scanners with *Result wrappers ([]Vulnerability) ---

	if r.SSRF != nil && len(r.SSRF.Vulnerabilities) > 0 {
		r.SSRF.Vulnerabilities = DeduplicateFindings(r.SSRF.Vulnerabilities,
			func(v ssrf.Vulnerability) string {
				return fmt.Sprintf("%s|%s", v.Parameter, v.Type)
			},
			func(v *ssrf.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "ssrf", len(r.SSRF.Vulnerabilities))
		for _, v := range r.SSRF.Vulnerabilities {
			r.BySeverity[v.Severity]++ // Severity is string, not typed
		}
	}

	if r.Smuggling != nil && len(r.Smuggling.Vulnerabilities) > 0 {
		r.Smuggling.Vulnerabilities = DeduplicateFindings(r.Smuggling.Vulnerabilities,
			func(v smuggling.Vulnerability) string {
				return fmt.Sprintf("%s|%s", v.Type, v.Technique)
			},
			func(v *smuggling.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "smuggling", len(r.Smuggling.Vulnerabilities))
		for _, v := range r.Smuggling.Vulnerabilities {
			r.BySeverity[v.Severity]++ // Severity is string
		}
	}

	if r.Race != nil && len(r.Race.Vulnerabilities) > 0 {
		r.Race.Vulnerabilities = DeduplicateFindings(r.Race.Vulnerabilities,
			func(v *race.Vulnerability) string {
				return fmt.Sprintf("%s|%s", v.URL, v.Type)
			},
			func(v **race.Vulnerability, n int) { (*v).ConfirmedBy = n },
		)
		addCounts(r, "race", len(r.Race.Vulnerabilities))
		for _, v := range r.Race.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	// --- Scanners with *Result wrappers ([]*Vulnerability pointers) ---

	if r.CMDI != nil && len(r.CMDI.Vulnerabilities) > 0 {
		r.CMDI.Vulnerabilities = DeduplicateFindings(r.CMDI.Vulnerabilities,
			func(v *cmdi.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Parameter, v.Type, v.Platform)
			},
			func(v **cmdi.Vulnerability, n int) { (*v).ConfirmedBy = n },
		)
		addCounts(r, "cmdi", len(r.CMDI.Vulnerabilities))
		for _, v := range r.CMDI.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.CORS != nil && len(r.CORS.Vulnerabilities) > 0 {
		r.CORS.Vulnerabilities = DeduplicateFindings(r.CORS.Vulnerabilities,
			func(v *cors.Vulnerability) string {
				return fmt.Sprintf("%s|%s", v.URL, v.Type)
			},
			func(v **cors.Vulnerability, n int) { (*v).ConfirmedBy = n },
		)
		addCounts(r, "cors", len(r.CORS.Vulnerabilities))
		for _, v := range r.CORS.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if r.Redirect != nil && len(r.Redirect.Vulnerabilities) > 0 {
		r.Redirect.Vulnerabilities = DeduplicateFindings(r.Redirect.Vulnerabilities,
			func(v *redirect.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s", v.URL, v.Parameter, v.Type)
			},
			func(v **redirect.Vulnerability, n int) { (*v).ConfirmedBy = n },
		)
		addCounts(r, "redirect", len(r.Redirect.Vulnerabilities))
		for _, v := range r.Redirect.Vulnerabilities {
			r.BySeverity[string(v.Severity)]++
		}
	}

	// --- Flat slices on ScanResult ([]Vulnerability) ---

	if len(r.Upload) > 0 {
		r.Upload = DeduplicateFindings(r.Upload,
			func(v upload.Vulnerability) string {
				return fmt.Sprintf("%s|%s", v.URL, v.Type)
			},
			func(v *upload.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "upload", len(r.Upload))
		for _, v := range r.Upload {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if len(r.Deserialize) > 0 {
		r.Deserialize = DeduplicateFindings(r.Deserialize,
			func(v deserialize.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Parameter, v.Type, v.GadgetChain)
			},
			func(v *deserialize.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "deserialize", len(r.Deserialize))
		for _, v := range r.Deserialize {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if len(r.OAuth) > 0 {
		r.OAuth = DeduplicateFindings(r.OAuth,
			func(v oauth.Vulnerability) string {
				return fmt.Sprintf("%s|%s", v.URL, v.Type)
			},
			func(v *oauth.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "oauth", len(r.OAuth))
		for _, v := range r.OAuth {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if len(r.BizLogic) > 0 {
		r.BizLogic = DeduplicateFindings(r.BizLogic,
			func(v bizlogic.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.URL, v.Method, v.Parameter, v.Type)
			},
			func(v *bizlogic.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "bizlogic", len(r.BizLogic))
		for _, v := range r.BizLogic {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if len(r.APIFuzz) > 0 {
		r.APIFuzz = DeduplicateFindings(r.APIFuzz,
			func(v apifuzz.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s|%s", v.Endpoint, v.Method, v.Parameter, v.Type)
			},
			func(v *apifuzz.Vulnerability, n int) { v.ConfirmedBy = n },
		)
		addCounts(r, "apifuzz", len(r.APIFuzz))
		for _, v := range r.APIFuzz {
			r.BySeverity[string(v.Severity)]++
		}
	}

	// --- Pointer slices ([]*Vulnerability) ---

	if len(r.SSTI) > 0 {
		r.SSTI = DeduplicateFindings(r.SSTI,
			func(v *ssti.Vulnerability) string {
				return fmt.Sprintf("%s|%s|%s", v.URL, v.Parameter, v.Engine)
			},
			func(v **ssti.Vulnerability, n int) { (*v).ConfirmedBy = n },
		)
		addCounts(r, "ssti", len(r.SSTI))
		for _, v := range r.SSTI {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if len(r.XXE) > 0 {
		r.XXE = DeduplicateFindings(r.XXE,
			func(v *xxe.Vulnerability) string {
				return fmt.Sprintf("%s|%s", v.URL, v.Type)
			},
			func(v **xxe.Vulnerability, n int) { (*v).ConfirmedBy = n },
		)
		addCounts(r, "xxe", len(r.XXE))
		for _, v := range r.XXE {
			r.BySeverity[string(v.Severity)]++
		}
	}

	if len(r.JWT) > 0 {
		r.JWT = DeduplicateFindings(r.JWT,
			func(v *jwt.Vulnerability) string {
				return string(v.Type)
			},
			func(v **jwt.Vulnerability, n int) { (*v).ConfirmedBy = n },
		)
		addCounts(r, "jwt", len(r.JWT))
		for _, v := range r.JWT {
			r.BySeverity[v.Severity]++ // Severity is string
		}
	}

	// --- Subtakeover ([]ScanResult with embedded []Vulnerability) ---

	if len(r.Subtakeover) > 0 {
		totalSubVulns := 0
		for i := range r.Subtakeover {
			sr := &r.Subtakeover[i]
			if len(sr.Vulnerabilities) > 0 {
				sr.Vulnerabilities = DeduplicateFindings(sr.Vulnerabilities,
					func(v subtakeover.Vulnerability) string {
						return fmt.Sprintf("%s|%s|%s", v.Subdomain, v.Provider, v.Type)
					},
					func(v *subtakeover.Vulnerability, n int) { v.ConfirmedBy = n },
				)
				totalSubVulns += len(sr.Vulnerabilities)
				for _, v := range sr.Vulnerabilities {
					r.BySeverity[string(v.Severity)]++
				}
			}
		}
		if totalSubVulns > 0 {
			addCounts(r, "subtakeover", totalSubVulns)
		}
	}

	// --- Non-standard sources (no Vulnerability struct, just counts) ---

	if r.JSAnalysis != nil {
		if n := len(r.JSAnalysis.Secrets); n > 0 {
			r.TotalVulns += n
			r.BySeverity["Critical"] += n
			r.ByCategory["jsanalyze"] = n
		}
		if n := len(r.JSAnalysis.DOMSinks); n > 0 {
			r.TotalVulns += n
			for _, sink := range r.JSAnalysis.DOMSinks {
				r.BySeverity[sink.Severity]++
			}
		}
	}

	if r.OSINT != nil {
		if r.OSINT.TotalUnique > 0 {
			r.ByCategory["osint"] = r.OSINT.TotalUnique
		}
		if n := len(r.OSINT.Secrets); n > 0 {
			r.TotalVulns += n
			r.BySeverity["Critical"] += n
		}
	}

	if len(r.VHosts) > 0 {
		n := len(r.VHosts)
		r.ByCategory["vhost"] = n
		r.TotalVulns += n
		r.BySeverity["Low"] += n
	}

	// Informational categories (no TotalVulns contribution)
	if len(r.TechStack) > 0 {
		r.ByCategory["techdetect"] = len(r.TechStack)
	}
	if len(r.APIRoutes) > 0 {
		r.ByCategory["apidepth"] = len(r.APIRoutes)
	}
}

// addCounts increments TotalVulns and sets the category count.
func addCounts(r *ScanResult, category string, count int) {
	r.TotalVulns += count
	r.ByCategory[category] = count
}
