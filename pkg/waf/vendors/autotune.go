// Package vendors provides auto-tuning recommendations based on detected WAF vendor.
package vendors

import (
	"fmt"
	"strings"

	"github.com/waftester/waftester/pkg/strutil"
	"github.com/waftester/waftester/pkg/ui"
)

// AutoTuneConfig represents auto-tuning configuration for a specific vendor
type AutoTuneConfig struct {
	Vendor              WAFVendor `json:"vendor"`
	MutationStrategy    string    `json:"mutation_strategy"`
	EnabledMutations    []string  `json:"enabled_mutations"`
	DisabledMutations   []string  `json:"disabled_mutations"`
	PreferredEncodings  []string  `json:"preferred_encodings"`
	ConcurrencyLimit    int       `json:"concurrency_limit"`
	RateLimitRPS        float64   `json:"rate_limit_rps"`
	RequestDelayMs      int       `json:"request_delay_ms"`
	RetryOnBlock        bool      `json:"retry_on_block"`
	BypassMode          bool      `json:"bypass_mode"`
	RecommendedPayloads []string  `json:"recommended_payloads"`
	Notes               []string  `json:"notes"`
}

// GetAutoTuneConfig returns vendor-specific auto-tuning configuration
func GetAutoTuneConfig(result *DetectionResult) *AutoTuneConfig {
	if result == nil || !result.Detected {
		return getDefaultConfig()
	}

	switch result.Vendor {
	case VendorCloudflare:
		return getCloudflareConfig()
	case VendorAWSWAF:
		return getAWSWAFConfig()
	case VendorAzureWAF:
		return getAzureWAFConfig()
	case VendorAkamai:
		return getAkamaiConfig()
	case VendorModSecurity:
		return getModSecurityConfig()
	case VendorImperva:
		return getImpervaConfig()
	case VendorF5BigIP:
		return getF5Config()
	case VendorFortinet:
		return getFortinetConfig()
	case VendorBarracuda:
		return getBarracudaConfig()
	case VendorSucuri:
		return getSucuriConfig()
	case VendorWordfence:
		return getWordfenceConfig()
	case VendorFastly:
		return getFastlyConfig()
	case VendorCloudArmor:
		return getCloudArmorConfig()
	default:
		return getDefaultConfig()
	}
}

func getDefaultConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorUnknown,
		MutationStrategy: "balanced",
		EnabledMutations: []string{
			"url_encode", "double_url_encode", "unicode_encode",
			"case_swap", "sql_comment", "whitespace_alt",
		},
		ConcurrencyLimit: 5,
		RateLimitRPS:     10.0,
		RequestDelayMs:   100,
		RetryOnBlock:     true,
		BypassMode:       false,
		Notes: []string{
			"Unknown WAF - using balanced defaults",
			"Consider manual detection if auto-detect fails",
		},
	}
}

func getCloudflareConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorCloudflare,
		MutationStrategy: "unicode_focused",
		EnabledMutations: []string{
			"unicode_encode", "overlong_utf8", "utf16le",
			"case_swap", "chunked_encoding", "double_url_encode",
		},
		DisabledMutations: []string{
			"null_byte", // Cloudflare blocks null bytes aggressively
		},
		PreferredEncodings: []string{"unicode", "overlong_utf8", "utf16le"},
		ConcurrencyLimit:   3,
		RateLimitRPS:       5.0,
		RequestDelayMs:     200,
		RetryOnBlock:       true,
		BypassMode:         true,
		RecommendedPayloads: []string{
			"sql_injection", "xss_script", "lfi_traversal",
		},
		Notes: []string{
			"Cloudflare has aggressive bot detection",
			"Use realistic User-Agent and headers",
			"Unicode normalization can bypass many patterns",
			"Rate limiting at ~1000 req/10s",
		},
	}
}

func getAWSWAFConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorAWSWAF,
		MutationStrategy: "encoding_chain",
		EnabledMutations: []string{
			"double_url_encode", "triple_url_encode",
			"html_hex_encode", "param_pollution",
			"content_type_mismatch",
		},
		PreferredEncodings: []string{"double_url", "triple_url", "html_hex"},
		ConcurrencyLimit:   10,
		RateLimitRPS:       50.0,
		RequestDelayMs:     50,
		RetryOnBlock:       true,
		BypassMode:         true,
		RecommendedPayloads: []string{
			"sql_injection", "xss_event", "path_traversal",
		},
		Notes: []string{
			"AWS WAF uses regex-based rules",
			"Nested encoding often bypasses",
			"HTTP Parameter Pollution effective",
			"Rate limits are configurable per-rule",
		},
	}
}

func getAzureWAFConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorAzureWAF,
		MutationStrategy: "crs_bypass",
		EnabledMutations: []string{
			"unicode_encode", "sql_comment", "case_swap",
			"html_decimal_encode", "base64_encode",
		},
		PreferredEncodings: []string{"unicode", "html_decimal", "base64"},
		ConcurrencyLimit:   5,
		RateLimitRPS:       20.0,
		RequestDelayMs:     100,
		RetryOnBlock:       true,
		BypassMode:         true,
		RecommendedPayloads: []string{
			"sql_injection", "xss_script", "xml_external",
		},
		Notes: []string{
			"Azure WAF uses OWASP CRS",
			"Standard CRS bypass techniques apply",
			"CDATA sections in XML can bypass",
			"WebSocket requests may bypass inspection",
		},
	}
}

func getAkamaiConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorAkamai,
		MutationStrategy: "wide_byte",
		EnabledMutations: []string{
			"wide_gbk", "wide_sjis", "overlong_utf8",
			"case_swap", "whitespace_alt",
		},
		PreferredEncodings: []string{"wide_gbk", "wide_sjis", "overlong_utf8"},
		ConcurrencyLimit:   2,
		RateLimitRPS:       3.0,
		RequestDelayMs:     500,
		RetryOnBlock:       false, // Akamai has aggressive IP banning
		BypassMode:         true,
		RecommendedPayloads: []string{
			"sql_injection", "xss_script",
		},
		Notes: []string{
			"Kona Site Defender has aggressive bot detection",
			"Use realistic browser fingerprinting",
			"Wide byte encodings (GBK/Shift-JIS) often bypass",
			"Avoid pattern-like request timing",
			"IP banning is aggressive - be careful",
		},
	}
}

func getModSecurityConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorModSecurity,
		MutationStrategy: "crs_comprehensive",
		EnabledMutations: []string{
			"overlong_utf8", "double_url_encode", "sql_comment",
			"whitespace_alt", "case_swap", "null_byte",
			"html_decimal_encode",
		},
		PreferredEncodings: []string{"overlong_utf8", "double_url", "html_decimal"},
		ConcurrencyLimit:   10,
		RateLimitRPS:       50.0,
		RequestDelayMs:     20,
		RetryOnBlock:       true,
		BypassMode:         true,
		RecommendedPayloads: []string{
			"sql_injection", "xss_script", "xss_event",
			"lfi_traversal", "rce_command", "php_injection",
		},
		Notes: []string{
			"Check paranoia level (1-4) - affects rules",
			"SQL comments work well for SQLi bypass",
			"Alternative whitespace chars bypass pattern matching",
			"Case manipulation for keyword detection",
			"Overlong UTF-8 often bypasses pattern matching",
			"No inherent rate limiting - depends on config",
		},
	}
}

func getImpervaConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorImperva,
		MutationStrategy: "ml_evasion",
		EnabledMutations: []string{
			"unicode_encode", "mixed_encode", "utf16be",
			"chunked_encoding", "param_pollution",
		},
		PreferredEncodings: []string{"unicode", "mixed", "utf16be"},
		ConcurrencyLimit:   3,
		RateLimitRPS:       5.0,
		RequestDelayMs:     300,
		RetryOnBlock:       false, // ML-based detection adapts
		BypassMode:         true,
		RecommendedPayloads: []string{
			"sql_injection", "xss_script",
		},
		Notes: []string{
			"Imperva uses ML-based detection",
			"Requires varied payloads to evade learning",
			"HTTP parameter fragmentation can help",
			"Content-Type manipulation may bypass body inspection",
			"Random delays help evade timing analysis",
		},
	}
}

func getF5Config() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorF5BigIP,
		MutationStrategy: "signature_evasion",
		EnabledMutations: []string{
			"double_url_encode", "html_hex_encode", "octal_encode",
			"sql_comment", "case_swap", "whitespace_alt",
		},
		PreferredEncodings: []string{"double_url", "html_hex", "octal"},
		ConcurrencyLimit:   5,
		RateLimitRPS:       20.0,
		RequestDelayMs:     100,
		RetryOnBlock:       true,
		BypassMode:         true,
		RecommendedPayloads: []string{
			"sql_injection", "xss_script", "path_traversal",
		},
		Notes: []string{
			"F5 ASM uses signature-based detection",
			"Payload obfuscation with comments effective",
			"URL encoding variants often bypass",
			"Check for parameter name whitelisting",
		},
	}
}

func getFortinetConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorFortinet,
		MutationStrategy: "balanced",
		EnabledMutations: []string{
			"url_encode", "double_url_encode",
			"case_swap", "sql_comment",
		},
		PreferredEncodings: []string{"url", "double_url"},
		ConcurrencyLimit:   5,
		RateLimitRPS:       20.0,
		RequestDelayMs:     100,
		RetryOnBlock:       true,
		BypassMode:         true,
		Notes: []string{
			"FortiWeb has multiple detection modes",
			"Signature + anomaly detection hybrid",
			"Standard encoding bypasses often work",
		},
	}
}

func getBarracudaConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorBarracuda,
		MutationStrategy: "balanced",
		EnabledMutations: []string{
			"url_encode", "double_url_encode",
			"unicode_encode", "case_swap",
		},
		PreferredEncodings: []string{"url", "double_url", "unicode"},
		ConcurrencyLimit:   5,
		RateLimitRPS:       20.0,
		RequestDelayMs:     100,
		RetryOnBlock:       true,
		BypassMode:         true,
		Notes: []string{
			"Barracuda WAF uses signature-based detection",
			"Standard bypass techniques usually work",
		},
	}
}

func getSucuriConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorSucuri,
		MutationStrategy: "balanced",
		EnabledMutations: []string{
			"url_encode", "double_url_encode",
			"unicode_encode", "case_swap",
		},
		PreferredEncodings: []string{"url", "double_url", "unicode"},
		ConcurrencyLimit:   5,
		RateLimitRPS:       10.0,
		RequestDelayMs:     150,
		RetryOnBlock:       true,
		BypassMode:         true,
		Notes: []string{
			"Sucuri is a cloud-based WAF",
			"Has bot detection capabilities",
			"Standard bypass techniques work",
		},
	}
}

func getWordfenceConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorWordfence,
		MutationStrategy: "wordpress_focused",
		EnabledMutations: []string{
			"url_encode", "double_url_encode",
			"case_swap", "php_wrapper",
		},
		PreferredEncodings: []string{"url", "double_url"},
		ConcurrencyLimit:   5,
		RateLimitRPS:       10.0,
		RequestDelayMs:     200,
		RetryOnBlock:       true,
		BypassMode:         true,
		RecommendedPayloads: []string{
			"sql_injection", "php_injection", "lfi_traversal",
		},
		Notes: []string{
			"Wordfence is WordPress-specific",
			"PHP injection techniques are relevant",
			"May have IP-based rate limiting",
		},
	}
}

func getFastlyConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorFastly,
		MutationStrategy: "balanced",
		EnabledMutations: []string{
			"url_encode", "unicode_encode",
			"case_swap", "sql_comment",
		},
		PreferredEncodings: []string{"url", "unicode"},
		ConcurrencyLimit:   5,
		RateLimitRPS:       20.0,
		RequestDelayMs:     100,
		RetryOnBlock:       true,
		BypassMode:         true,
		Notes: []string{
			"Fastly uses VCL-based WAF rules",
			"Rules are highly customizable",
			"Detection depends on customer configuration",
		},
	}
}

func getCloudArmorConfig() *AutoTuneConfig {
	return &AutoTuneConfig{
		Vendor:           VendorCloudArmor,
		MutationStrategy: "crs_bypass",
		EnabledMutations: []string{
			"unicode_encode", "sql_comment", "case_swap",
			"double_url_encode",
		},
		PreferredEncodings: []string{"unicode", "double_url"},
		ConcurrencyLimit:   5,
		RateLimitRPS:       20.0,
		RequestDelayMs:     100,
		RetryOnBlock:       true,
		BypassMode:         true,
		Notes: []string{
			"Cloud Armor uses preconfigured rules",
			"OWASP CRS-based rules available",
			"ML-based adaptive protection available",
		},
	}
}

// ApplyAutoTune applies auto-tune configuration and returns CLI flags
func ApplyAutoTune(config *AutoTuneConfig) []string {
	flags := make([]string, 0)

	// Rate limiting
	if config.RateLimitRPS > 0 {
		flags = append(flags, fmt.Sprintf("--rate-limit=%.1f", config.RateLimitRPS))
	}

	// Concurrency
	if config.ConcurrencyLimit > 0 {
		flags = append(flags, fmt.Sprintf("--concurrency=%d", config.ConcurrencyLimit))
	}

	// Request delay
	if config.RequestDelayMs > 0 {
		flags = append(flags, fmt.Sprintf("--delay=%dms", config.RequestDelayMs))
	}

	// Bypass mode
	if config.BypassMode {
		flags = append(flags, "--mutation-level=aggressive")
	}

	// Preferred encodings
	if len(config.PreferredEncodings) > 0 {
		flags = append(flags, fmt.Sprintf("--encoders=%s", strings.Join(config.PreferredEncodings, ",")))
	}

	// Enabled mutations
	if len(config.EnabledMutations) > 0 {
		flags = append(flags, fmt.Sprintf("--mutations=%s", strings.Join(config.EnabledMutations, ",")))
	}

	return flags
}

// FormatAutoTuneReport generates a human-readable report
func FormatAutoTuneReport(detection *DetectionResult, config *AutoTuneConfig) string {
	var sb strings.Builder

	// Pick box-drawing character set based on terminal capability
	tl, tr, bl, br, hz, vt, lj, rj, bullet, arrow := "╔", "╗", "╚", "╝", "═", "║", "╠", "╣", "•", "→"
	if !ui.UnicodeTerminal() {
		tl, tr, bl, br, hz, vt, lj, rj, bullet, arrow = "+", "+", "+", "+", "=", "|", "+", "+", "-", "->"
	}
	hline := strings.Repeat(hz, 62)

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s%s%s\n", tl, hline, tr))
	sb.WriteString(fmt.Sprintf("%s              WAF AUTO-TUNE CONFIGURATION                     %s\n", vt, vt))
	sb.WriteString(fmt.Sprintf("%s%s%s\n", lj, hline, rj))

	if detection != nil && detection.Detected {
		sb.WriteString(fmt.Sprintf("%s  Detected WAF: %-45s %s\n", vt, detection.VendorName, vt))
		sb.WriteString(fmt.Sprintf("%s  Confidence:   %.0f%%%-42s %s\n", vt, detection.Confidence*100, "", vt))

		if len(detection.Evidence) > 0 {
			sb.WriteString(fmt.Sprintf("%s  Evidence:                                                   %s\n", vt, vt))
			for _, e := range detection.Evidence[:minInt(len(detection.Evidence), 3)] {
				sb.WriteString(fmt.Sprintf("%s    %s %-56s %s\n", vt, bullet, strutil.Truncate(e, 56), vt))
			}
		}
	} else {
		sb.WriteString(fmt.Sprintf("%s  Detected WAF: None (using defaults)                         %s\n", vt, vt))
	}

	sb.WriteString(fmt.Sprintf("%s%s%s\n", lj, hline, rj))
	sb.WriteString(fmt.Sprintf("%s  TUNING PARAMETERS                                           %s\n", vt, vt))
	sb.WriteString(fmt.Sprintf("%s%s%s\n", lj, hline, rj))
	sb.WriteString(fmt.Sprintf("%s  Strategy:      %-44s %s\n", vt, config.MutationStrategy, vt))
	sb.WriteString(fmt.Sprintf("%s  Concurrency:   %-44d %s\n", vt, config.ConcurrencyLimit, vt))
	sb.WriteString(fmt.Sprintf("%s  Rate Limit:    %.1f req/s%-35s %s\n", vt, config.RateLimitRPS, "", vt))
	sb.WriteString(fmt.Sprintf("%s  Request Delay: %dms%-40s %s\n", vt, config.RequestDelayMs, "", vt))
	sb.WriteString(fmt.Sprintf("%s  Bypass Mode:   %-44v %s\n", vt, config.BypassMode, vt))

	if len(config.PreferredEncodings) > 0 {
		sb.WriteString(fmt.Sprintf("%s  Encodings:     %-44s %s\n", vt,
			strutil.Truncate(strings.Join(config.PreferredEncodings, ", "), 44), vt))
	}

	if len(config.EnabledMutations) > 0 {
		sb.WriteString(fmt.Sprintf("%s  Mutations:                                                  %s\n", vt, vt))
		// Show first 4 mutations
		for i, m := range config.EnabledMutations {
			if i >= 4 {
				remaining := len(config.EnabledMutations) - 4
				sb.WriteString(fmt.Sprintf("%s    ... and %d more%-40s %s\n", vt, remaining, "", vt))
				break
			}
			sb.WriteString(fmt.Sprintf("%s    %s %-56s %s\n", vt, bullet, m, vt))
		}
	}

	if len(config.Notes) > 0 {
		sb.WriteString(fmt.Sprintf("%s%s%s\n", lj, hline, rj))
		sb.WriteString(fmt.Sprintf("%s  RECOMMENDATIONS                                             %s\n", vt, vt))
		sb.WriteString(fmt.Sprintf("%s%s%s\n", lj, hline, rj))
		for _, note := range config.Notes {
			wrapped := wrapText(note, 56)
			for _, line := range wrapped {
				sb.WriteString(fmt.Sprintf("%s  %s %-58s %s\n", vt, bullet, line, vt))
			}
		}
	}

	if detection != nil && len(detection.BypassHints) > 0 {
		sb.WriteString(fmt.Sprintf("%s%s%s\n", lj, hline, rj))
		sb.WriteString(fmt.Sprintf("%s  BYPASS HINTS                                                %s\n", vt, vt))
		sb.WriteString(fmt.Sprintf("%s%s%s\n", lj, hline, rj))
		for _, hint := range detection.BypassHints[:minInt(len(detection.BypassHints), 5)] {
			wrapped := wrapText(hint, 56)
			for _, line := range wrapped {
				sb.WriteString(fmt.Sprintf("%s  %s %-58s %s\n", vt, arrow, line, vt))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("%s%s%s\n", bl, hline, br))

	return sb.String()
}



func wrapText(s string, max int) []string {
	if len(s) <= max {
		return []string{s}
	}

	var lines []string
	words := strings.Fields(s)
	current := ""

	for _, word := range words {
		if current == "" {
			current = word
		} else if len(current)+1+len(word) <= max {
			current += " " + word
		} else {
			lines = append(lines, current)
			current = word
		}
	}

	if current != "" {
		lines = append(lines, current)
	}

	return lines
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
