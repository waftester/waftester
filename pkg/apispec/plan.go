package apispec

import (
	"strings"
	"time"
)

// BuildSimplePlan creates a scan plan from user-selected scan types.
// Each endpoint gets one ScanPlanEntry per matching scan type per injectable parameter.
// This is the non-adaptive baseline; P2 replaces with BuildIntelligentPlan.
func BuildSimplePlan(spec *Spec, cfg *SpecConfig) *ScanPlan {
	if spec == nil || len(spec.Endpoints) == 0 {
		return &ScanPlan{
			SpecSource: cfg.Source(),
			Intensity:  cfg.Intensity,
		}
	}

	intensity := cfg.Intensity
	if intensity == "" {
		intensity = IntensityNormal
	}

	endpoints := cfg.FilterEndpoints(spec.Endpoints)

	var entries []ScanPlanEntry
	totalTests := 0

	for _, ep := range endpoints {
		targets := injectableTargets(ep)

		// If no injectable targets, still run meta scans against the endpoint itself.
		if len(targets) == 0 {
			targets = []InjectionTarget{{
				Parameter: "",
				Location:  LocationQuery,
			}}
		}

		for _, scanType := range allScanCategories {
			if !cfg.ShouldScan(scanType) {
				continue
			}

			// Meta scans (cors, secheaders, etc.) run once per endpoint, not per parameter.
			if isMetaScan(scanType) {
				payloads := estimatePayloads(scanType, intensity)
				entries = append(entries, ScanPlanEntry{
					Endpoint: ep,
					Attack: AttackSelection{
						Category:     scanType,
						Reason:       "user-selected",
						PayloadCount: payloads,
						Layers:       []string{"manual"},
					},
					InjectionTarget: InjectionTarget{
						Parameter: "",
						Location:  LocationQuery,
					},
				})
				totalTests += payloads
				continue
			}

			// Per-parameter scans: one entry per injectable target.
			for _, tgt := range targets {
				payloads := estimatePayloads(scanType, intensity)
				entries = append(entries, ScanPlanEntry{
					Endpoint: ep,
					Attack: AttackSelection{
						Category:     scanType,
						Reason:       "user-selected",
						PayloadCount: payloads,
						Layers:       []string{"manual"},
					},
					InjectionTarget: tgt,
				})
				totalTests += payloads
			}
		}
	}

	return &ScanPlan{
		Entries:           entries,
		TotalTests:        totalTests,
		EstimatedDuration: estimateDuration(totalTests, intensity),
		Intensity:         intensity,
		SpecSource:        cfg.Source(),
	}
}

// injectableTargets extracts all parameter locations that accept injection payloads.
func injectableTargets(ep Endpoint) []InjectionTarget {
	var targets []InjectionTarget

	for _, p := range ep.Parameters {
		targets = append(targets, InjectionTarget{
			Parameter: p.Name,
			Location:  p.In,
		})
	}

	for ct := range ep.RequestBodies {
		targets = append(targets, InjectionTarget{
			Parameter:   "body",
			Location:    LocationBody,
			ContentType: ct,
		})
	}

	return targets
}

// isMetaScan returns true for scan types that examine endpoint-level properties
// rather than injecting payloads into individual parameters.
func isMetaScan(scanType string) bool {
	switch scanType {
	case "cors", "secheaders", "tlsprobe", "httpprobe", "wafdetect",
		"waffprint", "wafevasion", "hostheader", "techdetect",
		"jsanalyze", "osint", "vhost", "dnsrecon",
		"csrf", "clickjack", "xmlinjection":
		return true
	}
	return false
}

// estimatePayloads returns a rough payload count for the given scan type and intensity.
func estimatePayloads(scanType string, intensity Intensity) int {
	base := payloadBaseCount(scanType)

	switch intensity {
	case IntensityQuick:
		return max(1, base/4)
	case IntensityNormal:
		return base
	case IntensityDeep:
		return base * 2
	case IntensityParanoid:
		return base * 4
	default:
		return base
	}
}

// payloadBaseCount returns the approximate number of payloads for a scan type at normal intensity.
func payloadBaseCount(scanType string) int {
	counts := map[string]int{
		"sqli":        50,
		"xss":         40,
		"traversal":   30,
		"cmdi":        25,
		"nosqli":      20,
		"hpp":         10,
		"crlf":        15,
		"prototype":   10,
		"cors":        5,
		"redirect":    15,
		"hostheader":  10,
		"websocket":   8,
		"cache":       12,
		"upload":      15,
		"deserialize": 10,
		"oauth":       8,
		"ssrf":        25,
		"ssti":        20,
		"xxe":         15,
		"smuggling":   10,
		"graphql":     15,
		"jwt":         12,
		"subtakeover": 5,
		"bizlogic":    8,
		"race":        5,
		"apifuzz":     30,
		"wafdetect":   3,
		"waffprint":   5,
		"wafevasion":  20,
		"tlsprobe":    3,
		"httpprobe":   5,
		"secheaders":  3,
		"jsanalyze":   5,
		"apidepth":    10,
		"osint":       5,
		"vhost":       8,
		"techdetect":  3,
		"dnsrecon":    5,
		"ldap":        20,
		"ssi":         15,
		"xpath":       20,
		"xmlinjection": 15,
		"rfi":         20,
		"lfi":         25,
		"rce":         20,
		"csrf":        5,
		"clickjack":   3,
		"idor":        15,
		"massassignment": 10,
	}
	if n, ok := counts[strings.ToLower(scanType)]; ok {
		return n
	}
	return 10
}

// estimateDuration provides a rough wall-clock estimate based on total tests and intensity.
func estimateDuration(totalTests int, intensity Intensity) time.Duration {
	// Average time per test in milliseconds, adjusted by intensity.
	msPerTest := 200
	switch intensity {
	case IntensityQuick:
		msPerTest = 100
	case IntensityDeep:
		msPerTest = 300
	case IntensityParanoid:
		msPerTest = 500
	}

	return time.Duration(totalTests*msPerTest) * time.Millisecond
}

// allScanCategories is the list of all scan types matching cmd_scan.go's allScanTypes.
var allScanCategories = []string{
	"sqli", "xss", "traversal", "cmdi", "nosqli", "hpp", "crlf",
	"prototype", "cors", "redirect", "hostheader", "websocket",
	"cache", "upload", "deserialize", "oauth", "ssrf", "ssti",
	"xxe", "smuggling", "graphql", "jwt", "subtakeover", "bizlogic",
	"race", "apifuzz", "ldap", "ssi", "xpath", "xmlinjection",
	"rfi", "lfi", "rce", "csrf", "clickjack", "idor", "massassignment",
	"wafdetect", "waffprint", "wafevasion",
	"tlsprobe", "httpprobe", "secheaders", "jsanalyze", "apidepth",
	"osint", "vhost", "techdetect", "dnsrecon",
}
