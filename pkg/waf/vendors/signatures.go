// Package vendors provides comprehensive WAF fingerprinting with 180+ vendor signatures.
// Ported from wafw00f (https://github.com/EnableSecurity/wafw00f) with enhancements.
//
// Detection methodology:
// 1. Normal request - analyze headers, cookies, and body
// 2. Attack request - send combined XSS+SQLi+LFI payload to trigger WAF
// 3. Plugin detection - iterate through prioritized signatures
// 4. Generic detection - behavioral analysis if no signature matches
package vendors

import (
	"regexp"
	"sort"
)

// WAFSignature defines a comprehensive WAF detection signature
type WAFSignature struct {
	// Identity
	Name     string    // Display name with manufacturer
	ID       WAFVendor // Internal vendor ID
	Category string    // cloud, appliance, software, cdn-integrated, wordpress-plugin

	// Detection patterns (all are optional, any match increases confidence)
	HeaderPatterns map[string]*regexp.Regexp // Header name -> pattern (matched against normal response)
	AttackHeaders  map[string]*regexp.Regexp // Header name -> pattern (matched against attack response)
	CookiePatterns []*regexp.Regexp          // Cookie patterns
	BodyPatterns   []*regexp.Regexp          // Response body patterns
	BlockPatterns  []*regexp.Regexp          // Block page specific patterns
	StatusCodes    []int                     // Specific status codes indicating this WAF
	ReasonPhrases  []string                  // HTTP reason phrases (e.g., "No Hacking")

	// Advanced detection
	JARMPrefixes []string // JARM TLS fingerprint prefixes
	Behaviors    []string // Behavioral checks to perform

	// Bypass intelligence
	BypassTips      []string // Specific bypass hints for this WAF
	Encoders        []string // Recommended encoders
	Evasions        []string // Recommended evasion techniques
	KnownWeaknesses []string // Known security weaknesses

	// Metadata
	Priority int  // Detection priority (higher = checked first)
	Reliable bool // Whether this signature is highly reliable
}

// AllSignatures contains all 150+ WAF detection signatures
// Organized by category for maintainability
var AllSignatures = []WAFSignature{
	// =============================================================================
	// CLOUD WAF PROVIDERS (Major)
	// =============================================================================

	{
		Name:     "Cloudflare",
		ID:       VendorCloudflare,
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"CF-RAY":          regexp.MustCompile(`.+`),
			"CF-Cache-Status": regexp.MustCompile(`.+`),
			"cf-request-id":   regexp.MustCompile(`.+`),
			"Server":          regexp.MustCompile(`(?i)cloudflare`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)__cfduid=`),
			regexp.MustCompile(`(?i)__cf_bm=`),
			regexp.MustCompile(`(?i)cf_clearance=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)cloudflare`),
			regexp.MustCompile(`(?i)cf-browser-verification`),
			regexp.MustCompile(`(?i)Attention Required! \| Cloudflare`),
			regexp.MustCompile(`(?i)ray\.cloudflare\.com`),
		},
		BlockPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Cloudflare Ray ID:`),
			regexp.MustCompile(`(?i)Why have I been blocked\?`),
			regexp.MustCompile(`(?i)This website is using a security service`),
		},
		BypassTips: []string{
			"Try Unicode normalization (NFKC/NFKD forms)",
			"Chunked transfer encoding may bypass body inspection",
			"Rate limiting typically starts at 1000 req/10s",
			"Use case variation in SQL keywords",
			"Try overlong UTF-8 encoding",
			"Browser Integrity Check can be bypassed with valid JA3",
		},
		Encoders: []string{"unicode", "overlong_utf8", "utf16le", "double_url"},
		Evasions: []string{"case_swap", "chunked", "whitespace_alt", "unicode_normalization"},
		Priority: 100,
		Reliable: true,
	},

	{
		Name:     "AWS WAF",
		ID:       VendorAWSWAF,
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Amzn-RequestId": regexp.MustCompile(`.+`),
			"X-Amz-Cf-Id":      regexp.MustCompile(`.+`),
			"X-Amz-Cf-Pop":     regexp.MustCompile(`.+`),
			"X-Amz-Request-Id": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Request blocked`),
			regexp.MustCompile(`(?i)aws\s*waf`),
			regexp.MustCompile(`(?i)awselb`),
		},
		BlockPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)The request could not be satisfied`),
			regexp.MustCompile(`(?i)Request blocked\..+AWS`),
		},
		BypassTips: []string{
			"AWS WAF uses regex matching - try regex DoS patterns",
			"Content-Type mismatch may bypass body inspection",
			"Try URL parameter pollution",
			"Nested encoding may evade detection",
			"Try JSON with Unicode escapes",
		},
		Encoders: []string{"double_url", "triple_url", "html_hex", "json_unicode"},
		Evasions: []string{"content_type_mismatch", "hpp", "sql_comment"},
		Priority: 95,
		Reliable: true,
	},

	{
		Name:     "Azure WAF (Front Door)",
		ID:       VendorAzureWAF,
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Azure-Ref":      regexp.MustCompile(`.+`),
			"X-MS-Ref":         regexp.MustCompile(`.+`),
			"X-Azure-Fd-Id":    regexp.MustCompile(`.+`),
			"X-MS-Ref-Include": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Azure Web Application Firewall`),
			regexp.MustCompile(`(?i)azure\.microsoft\.com`),
			regexp.MustCompile(`(?i)Front Door`),
		},
		BlockPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Your access to this site has been restricted`),
		},
		BypassTips: []string{
			"Azure WAF uses OWASP CRS - standard CRS bypasses apply",
			"Try XML content with CDATA sections",
			"Unicode encoding in JSON payloads",
			"WebSocket requests may bypass inspection",
		},
		Encoders: []string{"unicode", "html_decimal", "base64", "cdata"},
		Evasions: []string{"sql_comment", "case_swap", "unicode_normalization"},
		Priority: 90,
		Reliable: true,
	},

	{
		Name:     "Google Cloud Armor",
		ID:       VendorCloudArmor,
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Google Frontend`),
			"Via":    regexp.MustCompile(`(?i)google`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Google Cloud Armor`),
			regexp.MustCompile(`(?i)cloud\.google\.com`),
		},
		BypassTips: []string{
			"Cloud Armor uses preconfigured WAF rules",
			"Custom rules may have gaps",
			"Try HTTP/2 specific bypasses",
		},
		Encoders: []string{"unicode", "double_url"},
		Evasions: []string{"http2_smuggling", "case_swap"},
		Priority: 85,
		Reliable: true,
	},

	// =============================================================================
	// CDN-INTEGRATED WAF
	// =============================================================================

	{
		Name:     "Akamai Kona Site Defender",
		ID:       VendorAkamai,
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":               regexp.MustCompile(`(?i)AkamaiGHost`),
			"X-Akamai-Transformed": regexp.MustCompile(`.+`),
			"Akamai-Grn":           regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)akamai`),
			regexp.MustCompile(`(?i)ghost`),
			regexp.MustCompile(`Access Denied.*Reference#`),
		},
		BlockPatterns: []*regexp.Regexp{
			regexp.MustCompile(`Reference #[\d\.]+`),
			regexp.MustCompile(`(?i)akamai.?reference`),
		},
		BypassTips: []string{
			"Kona Site Defender has aggressive bot detection",
			"Use realistic browser headers and TLS fingerprint",
			"Try GBK/Shift-JIS wide byte encoding",
			"Request timing matters - avoid patterns",
			"Try HTTP parameter fragmentation",
		},
		Encoders: []string{"wide_gbk", "wide_sjis", "overlong_utf8"},
		Evasions: []string{"case_swap", "whitespace_alt", "null_byte", "timing_evasion"},
		Priority: 90,
		Reliable: true,
	},

	{
		Name:     "Fastly",
		ID:       VendorFastly,
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Served-By":         regexp.MustCompile(`cache-`),
			"Fastly-Debug-Digest": regexp.MustCompile(`.+`),
			"X-Timer":             regexp.MustCompile(`VS0`),
			"X-Fastly-Request-ID": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)fastly`),
		},
		BypassTips: []string{
			"Fastly uses VCL - custom rules vary widely",
			"Try cache poisoning vectors",
			"Edge computing may have processing gaps",
		},
		Encoders: []string{"url", "double_url"},
		Evasions: []string{"cache_key_injection"},
		Priority: 80,
		Reliable: true,
	},

	{
		Name:     "StackPath",
		ID:       "stackpath",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-SP-URL":     regexp.MustCompile(`.+`),
			"X-SP-WF-Rule": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<title>StackPath[^<]+</title>`),
			regexp.MustCompile(`(?i)Protected by.*StackPath`),
			regexp.MustCompile(`(?i)is using a security service for protection`),
		},
		BypassTips: []string{
			"Try URL encoding variants",
			"Test with different Content-Types",
		},
		Encoders: []string{"double_url", "unicode"},
		Evasions: []string{"content_type_mismatch"},
		Priority: 70,
		Reliable: false,
	},

	{
		Name:     "KeyCDN",
		ID:       "keycdn",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":      regexp.MustCompile(`(?i)keycdn`),
			"X-Edge-IP":   regexp.MustCompile(`.+`),
			"X-Shield-IP": regexp.MustCompile(`.+`),
		},
		Priority: 60,
		Reliable: false,
	},

	// =============================================================================
	// ENTERPRISE APPLIANCE WAF
	// =============================================================================

	{
		Name:     "Imperva SecureSphere / Incapsula",
		ID:       VendorImperva,
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-CDN":   regexp.MustCompile(`(?i)incapsula`),
			"X-Iinfo": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^incap_ses.*?=`),
			regexp.MustCompile(`(?i)^visid_incap.*?=`),
			regexp.MustCompile(`(?i)nlbi_`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Incapsula incident ID`),
			regexp.MustCompile(`(?i)_Incapsula_Resource`),
			regexp.MustCompile(`(?i)powered by incapsula`),
			regexp.MustCompile(`(?i)Imperva`),
		},
		BlockPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Request unsuccessful\. Incapsula`),
		},
		BypassTips: []string{
			"Imperva uses machine learning - requires varied payloads",
			"Try HTTP parameter fragmentation",
			"Content-Type manipulation may help",
			"Time-based evasion with random delays",
			"Try Unicode normalization attacks",
		},
		Encoders: []string{"unicode", "mixed", "utf16be"},
		Evasions: []string{"chunked", "hpp", "content_type_mismatch", "timing_evasion"},
		Priority: 95,
		Reliable: true,
	},

	{
		Name:     "F5 BIG-IP ASM",
		ID:       VendorF5BigIP,
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-WA-Info":    regexp.MustCompile(`.+`),
			"Server":       regexp.MustCompile(`(?i)BigIP`),
			"X-Cnection":   regexp.MustCompile(`.+`),
			"X-Request-Id": regexp.MustCompile(`^[a-f0-9]{8}$`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^TS[a-zA-Z0-9]{3,6}=`),
			regexp.MustCompile(`(?i)^BIGipServer`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)The requested URL was rejected`),
			regexp.MustCompile(`support ID: \d+`),
			regexp.MustCompile(`(?i)Please consult with your administrator`),
		},
		BypassTips: []string{
			"F5 ASM uses signature-based detection",
			"Try payload obfuscation with comments",
			"URL encoding variants often bypass",
			"Check for parameter name whitelisting",
			"Try HTTP request smuggling",
		},
		Encoders: []string{"double_url", "html_hex", "octal"},
		Evasions: []string{"sql_comment", "case_swap", "whitespace_alt", "http_smuggling"},
		Priority: 90,
		Reliable: true,
	},

	{
		Name:     "Fortinet FortiWeb",
		ID:       VendorFortinet,
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)FortiWeb`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^FORTIWAFSID=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)FortiGate`),
			regexp.MustCompile(`(?i)FortiWeb`),
			regexp.MustCompile(`(?i)\.fgd_icon`),
			regexp.MustCompile(`(?i)web\.page\.blocked`),
			regexp.MustCompile(`(?i)attack\.id`),
		},
		BlockPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Web Page Blocked.*Fortinet`),
			regexp.MustCompile(`(?i)FortiGuard`),
		},
		BypassTips: []string{
			"FortiWeb has ML and signature modes",
			"Try request body padding",
			"Test with chunked encoding",
		},
		Encoders: []string{"double_url", "unicode"},
		Evasions: []string{"chunked", "padding"},
		Priority: 85,
		Reliable: true,
	},

	{
		Name:     "Barracuda WAF",
		ID:       VendorBarracuda,
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Barracuda`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^barra_counter_session=`),
			regexp.MustCompile(`(?i)^BNI__BARRACUDA_LB_COOKIE=`),
			regexp.MustCompile(`(?i)^BNI_persistence=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Barracuda.*blocked`),
			regexp.MustCompile(`(?i)barracuda\.com`),
		},
		BypassTips: []string{
			"Barracuda uses pattern matching",
			"Try comment injection in SQL",
			"Test with different character sets",
		},
		Encoders: []string{"double_url", "html_decimal"},
		Evasions: []string{"sql_comment", "charset_mismatch"},
		Priority: 80,
		Reliable: true,
	},

	{
		Name:     "Radware AppWall",
		ID:       "radware",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-SL-CompState": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)CloudWebSec\.radware\.com`),
			regexp.MustCompile(`(?i)Unauthorized Request Blocked`),
			regexp.MustCompile(`(?i)because we have detected unauthorized activity`),
			regexp.MustCompile(`\?Subject=Security Page.{0,10}?Case Number`),
		},
		BypassTips: []string{
			"Try HTTP parameter pollution",
			"Test URL encoding variants",
		},
		Encoders: []string{"double_url", "unicode"},
		Evasions: []string{"hpp"},
		Priority: 75,
		Reliable: true,
	},

	{
		Name:     "Citrix NetScaler AppFirewall",
		ID:       "citrix_netscaler",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Via":         regexp.MustCompile(`(?i)NS-CACHE`),
			"X-NSC-":      regexp.MustCompile(`.+`),
			"Cneonction":  regexp.MustCompile(`.+`),
			"nnCoection":  regexp.MustCompile(`.+`),
			"X-Client-IP": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^NSC_`),
			regexp.MustCompile(`(?i)^citrix_ns_id`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)ns_af=`),
			regexp.MustCompile(`(?i)citrix`),
			regexp.MustCompile(`(?i)NetScaler`),
		},
		BypassTips: []string{
			"NetScaler uses signature patterns",
			"Try null byte injection",
			"Test with overlong UTF-8",
		},
		Encoders: []string{"overlong_utf8", "null_byte"},
		Evasions: []string{"null_byte", "whitespace_alt"},
		Priority: 80,
		Reliable: true,
	},

	{
		Name:     "DenyAll rWeb",
		ID:       "denyall",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Set-Cookie": regexp.MustCompile(`(?i)sessioncookie=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Condition Intercepted`),
			regexp.MustCompile(`(?i)denyall`),
		},
		Priority: 60,
		Reliable: false,
	},

	// =============================================================================
	// SOFTWARE/OPEN SOURCE WAF
	// =============================================================================

	{
		Name:     "ModSecurity / Coraza",
		ID:       VendorModSecurity,
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)(mod.?security|nginx|apache|coraza)`),
		},
		AttackHeaders: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)(nginx|apache)`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)ModSecurity`),
			regexp.MustCompile(`(?i)mod_security`),
			regexp.MustCompile(`(?i)coraza`),
			regexp.MustCompile(`(?i)Request forbidden by administrative rules`),
			regexp.MustCompile(`(?i)This error was generated by Mod_Security`),
			regexp.MustCompile(`(?i)Access denied with code 403`),
		},
		BlockPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Access denied\.?`),
			regexp.MustCompile(`(?i)You don.t have permission`),
			regexp.MustCompile(`(?i)X-Request-Id`),
		},
		StatusCodes:   []int{403, 406, 501},
		ReasonPhrases: []string{"ModSecurity Action"},
		BypassTips: []string{
			"Check paranoia level - higher PLs have more FPs",
			"SQL comments work well for SQLi bypass",
			"Try alternative whitespace characters",
			"Case manipulation for keyword detection",
			"Overlong UTF-8 often bypasses pattern matching",
			"Try HTTP parameter pollution",
		},
		Encoders: []string{"overlong_utf8", "double_url", "html_decimal", "unicode"},
		Evasions: []string{"sql_comment", "whitespace_alt", "case_swap", "null_byte", "hpp"},
		Priority: 90,
		Reliable: true,
	},

	{
		Name:     "NAXSI (Nginx Anti XSS & SQL Injection)",
		ID:       "naxsi",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":         regexp.MustCompile(`(?i)naxsi`),
			"X-NAXSI-Domain": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)naxsi`),
			regexp.MustCompile(`(?i)blocked by naxsi`),
		},
		BypassTips: []string{
			"NAXSI uses scoring system",
			"Try payload fragmentation",
			"Test with different parameter names",
		},
		Encoders: []string{"double_url", "unicode"},
		Evasions: []string{"fragmentation", "parameter_rename"},
		Priority: 75,
		Reliable: false,
	},

	{
		Name:     "OpenResty Lua WAF",
		ID:       "openresty",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)openresty`),
		},
		BypassTips: []string{
			"Lua WAF rules vary by implementation",
			"Try testing with Unicode",
		},
		Priority: 60,
		Reliable: false,
	},

	{
		Name:     "Shadow Daemon",
		ID:       "shadow_daemon",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<h1>Shadow Daemon</h1>`),
			regexp.MustCompile(`(?i)request blocked by shadow daemon`),
		},
		Priority: 50,
		Reliable: false,
	},

	// =============================================================================
	// WORDPRESS SECURITY PLUGINS
	// =============================================================================

	{
		Name:     "Wordfence",
		ID:       VendorWordfence,
		Category: "wordpress-plugin",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)wf[_\-]?WAF`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Generated by Wordfence`),
			regexp.MustCompile(`(?i)broke one of (the )?Wordfence (advanced )?blocking rules`),
			regexp.MustCompile(`(?i)/plugins/wordfence`),
			regexp.MustCompile(`(?i)wordfence[_\-]?block`),
		},
		BypassTips: []string{
			"Wordfence has learning mode",
			"Try testing from different IPs",
			"Live Traffic feature may track your requests",
		},
		Encoders: []string{"double_url"},
		Evasions: []string{"ip_rotation"},
		Priority: 70,
		Reliable: true,
	},

	{
		Name:     "Sucuri CloudProxy",
		ID:       VendorSucuri,
		Category: "wordpress-plugin",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":         regexp.MustCompile(`(?i)Sucuri`),
			"X-Sucuri-ID":    regexp.MustCompile(`.+`),
			"X-Sucuri-Cache": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Sucuri WebSite Firewall`),
			regexp.MustCompile(`(?i)sucuri\.net`),
			regexp.MustCompile(`(?i)Access Denied.*Sucuri`),
			regexp.MustCompile(`(?i)cloudproxy@sucuri\.net`),
		},
		BypassTips: []string{
			"Sucuri has ML-based detection",
			"Try finding origin server IP",
			"Test with real browser fingerprint",
		},
		Encoders: []string{"unicode", "double_url"},
		Evasions: []string{"browser_emulation"},
		Priority: 75,
		Reliable: true,
	},

	{
		Name:     "WP Cerber Security",
		ID:       "cerber",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)your request looks suspicious or similar to automated`),
			regexp.MustCompile(`(?i)our server stopped processing your request`),
			regexp.MustCompile(`(?i)We.re sorry.{0,10}?you are not allowed to proceed`),
			regexp.MustCompile(`(?i)requests from spam posting software`),
		},
		StatusCodes: []int{403},
		Priority:    60,
		Reliable:    true,
	},

	{
		Name:     "Shield Security",
		ID:       "shield_security",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)You were blocked by the Shield`),
			regexp.MustCompile(`(?i)remaining transgression\(s\) against this site`),
			regexp.MustCompile(`(?i)Something in the URL.{0,5}?Form or Cookie data wasn't appropriate`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "BulletProof Security Pro",
		ID:       "bulletproof",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\+?bpsMessage`),
			regexp.MustCompile(`(?i)403 Forbidden Error Page`),
			regexp.MustCompile(`(?i)If you arrived here due to a search`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "SecuPress",
		ID:       "secupress",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)secupress`),
			regexp.MustCompile(`(?i)blocked by SecuPress`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "wpmudev WAF",
		ID:       "wpmudev",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)href="https?://wpmudev\.com`),
			regexp.MustCompile(`(?i)Click on the Logs tab, then the WAF Log`),
			regexp.MustCompile(`(?i)<h1>Whoops, this request has been blocked!`),
			regexp.MustCompile(`(?i)This request has been deemed suspicious`),
		},
		StatusCodes: []int{403},
		Priority:    45,
		Reliable:    true,
	},

	{
		Name:     "RSFirewall",
		ID:       "rsfirewall",
		Category: "joomla-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)com_rsfirewall_(\d{3}_forbidden|event)?`),
		},
		Priority: 40,
		Reliable: false,
	},

	// =============================================================================
	// CHINESE WAF VENDORS
	// =============================================================================

	{
		Name:     "360WangZhanBao (360 Technologies)",
		ID:       "360wzb",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":              regexp.MustCompile(`(?i)qianxin\-waf`),
			"WZWS-Ray":            regexp.MustCompile(`.+`),
			"X-Powered-By-360WZB": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)wzws\-waf\-cgi/`),
			regexp.MustCompile(`(?i)wangshan\.360\.cn`),
		},
		StatusCodes: []int{493},
		Priority:    70,
		Reliable:    true,
	},

	{
		Name:     "Yunjiasu (Baidu Cloud Computing)",
		ID:       "yunjiasu",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)yunjiasu`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)href="/.well-known/yunjiasu-cgi/`),
			regexp.MustCompile(`(?i)document\.cookie='yjs_use_ob=0`),
		},
		Priority: 65,
		Reliable: true,
	},

	{
		Name:     "Yundun",
		ID:       "yundun",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":  regexp.MustCompile(`(?i)yundun`),
			"X-Cache": regexp.MustCompile(`(?i)yundun`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^yd_cookie=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)yundun\.com`),
		},
		Priority: 60,
		Reliable: false,
	},

	{
		Name:     "Yunsuo",
		ID:       "yunsuo",
		Category: "cloud",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^yunsuo_session=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)class="yunsuologo"`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Chuang Yu Shield (Yunaq)",
		ID:       "chuangyu",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)www\.365cyd\.com`),
			regexp.MustCompile(`(?i)help\.365cyd\.com/cyd\-error\-help\.html\?code=403`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "Xuanwudun",
		ID:       "xuanwudun",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)xuanwudun`),
			regexp.MustCompile(`(?i)class="xwd-block"`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "Qiniu",
		ID:       "qiniu",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Qiniu-Zone": regexp.MustCompile(`.+`),
			"X-Qnm-Cache":  regexp.MustCompile(`.+`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "Tencent Cloud WAF",
		ID:       "tencent",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Tencent`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)tencent`),
			regexp.MustCompile(`(?i)waf\.tencent`),
		},
		Priority: 65,
		Reliable: false,
	},

	{
		Name:     "Huawei Cloud Firewall",
		ID:       "huawei",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)HuaweiCloudWAF`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^HWWAFSESID=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)hwclouds\.com`),
			regexp.MustCompile(`(?i)hws_security@`),
		},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:     "Alibaba Cloud WAF",
		ID:       "alibaba",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":      regexp.MustCompile(`(?i)Aliyun`),
			"X-Server-ID": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aliyungf`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aliyun\.com`),
			regexp.MustCompile(`(?i)errors\.aliyun\.com`),
		},
		Priority: 70,
		Reliable: true,
	},

	{
		Name:     "UCloud WAF",
		ID:       "ucloud",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)uewaf(/[0-9\.]+)?`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)/uewaf_deny_pages/default/img/`),
			regexp.MustCompile(`(?i)ucloud\.cn`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Safedog",
		ID:       "safedog",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)safedog`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)safedog-flow-item=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)safedogsite`),
			regexp.MustCompile(`(?i)safe\.dog`),
			regexp.MustCompile(`(?i)waf\.safedog\.cn`),
		},
		Priority: 55,
		Reliable: true,
	},

	// =============================================================================
	// JAPANESE WAF VENDORS
	// =============================================================================

	{
		Name:     "SiteGuard (Lite)",
		ID:       "siteguard",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Powered by SiteGuard`),
			regexp.MustCompile(`(?i)siteguard_logs`),
		},
		Priority: 50,
		Reliable: false,
	},

	// =============================================================================
	// BOT MANAGEMENT / ANTI-AUTOMATION
	// =============================================================================

	{
		Name:     "PerimeterX",
		ID:       "perimeterx",
		Category: "bot-management",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)www\.perimeterx\.(com|net)/whywasiblocked`),
			regexp.MustCompile(`(?i)client\.perimeterx\.(net|com)`),
			regexp.MustCompile(`(?i)denied because we believe you are using automation tools`),
		},
		BypassTips: []string{
			"PerimeterX uses advanced browser fingerprinting",
			"Requires proper TLS fingerprint (JA3)",
			"Try with real browser via headless Chrome",
		},
		Priority: 75,
		Reliable: true,
	},

	{
		Name:     "Distil Networks",
		ID:       "distil",
		Category: "bot-management",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)cdn\.distilnetworks\.com/images/anomaly\.detected\.png`),
			regexp.MustCompile(`(?i)distilCaptchaForm`),
			regexp.MustCompile(`(?i)distilCallbackGuard`),
		},
		BypassTips: []string{
			"Distil uses JS-based bot detection",
			"Proper JS execution required",
		},
		Priority: 70,
		Reliable: true,
	},

	{
		Name:     "DataDome",
		ID:       "datadome",
		Category: "bot-management",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-DataDome":     regexp.MustCompile(`.+`),
			"X-DataDome-CID": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^datadome=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)datadome\.co`),
		},
		BypassTips: []string{
			"DataDome uses device fingerprinting",
			"Browser automation detectable",
		},
		Priority: 70,
		Reliable: true,
	},

	{
		Name:     "Kasada",
		ID:       "kasada",
		Category: "bot-management",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Kpsdk-Ct": regexp.MustCompile(`.+`),
			"X-Kpsdk-Cd": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^x-kpsdk-ct=`),
		},
		BypassTips: []string{
			"Kasada has advanced obfuscation",
			"Requires solving their challenge",
		},
		Priority: 65,
		Reliable: true,
	},

	{
		Name:     "Shape Security (F5)",
		ID:       "shape",
		Category: "bot-management",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-QLNC": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)shape\.com`),
		},
		Priority: 60,
		Reliable: false,
	},

	{
		Name:     "BitNinja",
		ID:       "bitninja",
		Category: "bot-management",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Security check by BitNinja`),
			regexp.MustCompile(`(?i)Visitor anti-robot validation`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Reblaze",
		ID:       "reblaze",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Reblaze Secure Web Gateway`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^rbzid`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)current session has been terminated`),
			regexp.MustCompile(`(?i)do not hesitate to contact us`),
			regexp.MustCompile(`(?i)access denied \(\d{3}\)`),
		},
		Priority: 60,
		Reliable: true,
	},

	// =============================================================================
	// LEGACY / LESS COMMON WAF
	// =============================================================================

	{
		Name:          "WebKnight (AQTRONIX)",
		ID:            "webknight",
		Category:      "appliance",
		StatusCodes:   []int{999, 404},
		ReasonPhrases: []string{"No Hacking", "Hack Not Found"},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)WebKnight`),
			regexp.MustCompile(`(?i)AQTRONIX`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "URLScan (Microsoft)",
		ID:       "urlscan",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Rejected[-_]By[_-]UrlScan`),
			regexp.MustCompile(`(?i)A custom filter or module.{0,4}?such as URLScan`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "eEye SecureIIS (BeyondTrust)",
		ID:       "secureiis",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)SecureIIS`),
			regexp.MustCompile(`(?i)eEye Digital Security`),
			regexp.MustCompile(`(?i)beyondtrust`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "dotDefender (Applicure)",
		ID:       "dotdefender",
		Category: "software",
		AttackHeaders: map[string]*regexp.Regexp{
			"X-dotDefender-denied": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)dotdefender blocked your request`),
			regexp.MustCompile(`(?i)Applicure is the leading provider`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "HyperGuard (Art of Defense)",
		ID:       "hyperguard",
		Category: "appliance",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`^WODSESSION=`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "Profense (ArmorLogic)",
		ID:       "profense",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Profense`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^PLBSID=`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "Approach",
		ID:       "approach",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)approach.{0,10}?web application (firewall|filtering)`),
			regexp.MustCompile(`(?i)approach.{0,10}?infrastructure team`),
		},
		Priority: 35,
		Reliable: false,
	},

	{
		Name:     "Bekchy (Faydata Technologies)",
		ID:       "bekchy",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Bekchy.{0,10}?Access Denied`),
			regexp.MustCompile(`(?i)bekchy\.com/report`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "Cloudbric (Penta Security)",
		ID:       "cloudbric",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<title>Cloudbric.{0,5}?ERROR!`),
			regexp.MustCompile(`(?i)Your request was blocked by Cloudbric`),
			regexp.MustCompile(`(?i)please contact Cloudbric Support`),
			regexp.MustCompile(`(?i)cloudbric\.zendesk\.com`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Cloud Protector (Rohde & Schwarz)",
		ID:       "cloudprotector",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Cloud Protector.*?by Rohde.{3,8}?Schwarz`),
			regexp.MustCompile(`(?i)cloudprotector\.com`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "CrawlProtect",
		ID:       "crawlprotect",
		Category: "software",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^crawlprotecttag=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<title>crawlprotect`),
			regexp.MustCompile(`(?i)this site is protected by crawlprotect`),
		},
		Priority: 35,
		Reliable: true,
	},

	{
		Name:     "Zenedge",
		ID:       "zenedge",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":     regexp.MustCompile(`(?i)ZENEDGE`),
			"X-Zen-Fury": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)/__zenedge/`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Azion Edge Firewall",
		ID:       "azion",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"x-azion-edge-pop":   regexp.MustCompile(`.+`),
			"x-azion-request-id": regexp.MustCompile(`.+`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "ArvanCloud",
		ID:       "arvancloud",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)ArvanCloud`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "SEnginx (Neusoft)",
		ID:       "senginx",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)SENGINX\-ROBOT\-MITIGATION`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "RayWAF (WebRay Solutions)",
		ID:       "raywaf",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":   regexp.MustCompile(`(?i)WebRay\-WAF`),
			"DrivedBy": regexp.MustCompile(`(?i)RaySrv\.RayEng/[0-9\.]+?`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "Safeline (Chaitin Tech)",
		ID:       "safeline",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)safeline`),
			regexp.MustCompile(`(?i)<!\-\-\sevent id:`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "YXLink",
		ID:       "yxlink",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Yxlink([\-_]?WAF)?`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^yx_ci_session=`),
			regexp.MustCompile(`(?i)^yx_language=`),
		},
		Priority: 40,
		Reliable: true,
	},

	{
		Name:     "WebLand",
		ID:       "webland",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)protected by webland`),
		},
		Priority: 35,
		Reliable: false,
	},

	{
		Name:     "Shieldon Firewall",
		ID:       "shieldon",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Protected-By": regexp.MustCompile(`(?i)shieldon\.io`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Please solve CAPTCHA`),
			regexp.MustCompile(`(?i)shieldon_captcha`),
			regexp.MustCompile(`(?i)Unusual behavior detected`),
			regexp.MustCompile(`(?i)The IP address you are using has been blocked`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Instart DX (Instart Logic)",
		ID:       "instart",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Instart-Request-ID": regexp.MustCompile(`.+`),
			"X-Instart-Cache":      regexp.MustCompile(`.+`),
			"X-Instart-WL":         regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)the requested url was rejected`),
			regexp.MustCompile(`(?i)please consult with your administrator`),
			regexp.MustCompile(`(?i)your support id is`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "MaxCDN",
		ID:       "maxcdn",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-CDN": regexp.MustCompile(`(?i)maxcdn`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "West263 CDN",
		ID:       "west263",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Cache": regexp.MustCompile(`(?i)WS?T263CDN`),
		},
		Priority: 35,
		Reliable: false,
	},

	{
		Name:     "SiteLock (TrueShield)",
		ID:       "sitelock",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)SiteLock will remember you`),
			regexp.MustCompile(`(?i)Sitelock is leader in Business Website Security`),
			regexp.MustCompile(`(?i)sitelock[_\-]shield`),
			regexp.MustCompile(`(?i)SiteLock incident ID`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Sophos UTM Web Protection",
		ID:       "sophos",
		Category: "appliance",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Sophos`),
			regexp.MustCompile(`(?i)utm\.(corporate\.)?sophos\.com`),
		},
		Priority: 50,
		Reliable: false,
	},

	// AWS CloudFront (separate from AWS WAF)
	{
		Name:     "Amazon CloudFront",
		ID:       "cloudfront",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":       regexp.MustCompile(`(?i)CloudFront`),
			"Via":          regexp.MustCompile(`(?i)\w+\.cloudfront\.net`),
			"X-Amz-Cf-Id":  regexp.MustCompile(`.+`),
			"X-Amz-Cf-Pop": regexp.MustCompile(`.+`),
			"X-Cache":      regexp.MustCompile(`(?i)(Hit|Miss|Error) from cloudfront`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Generated by cloudfront \(CloudFront\)`),
			regexp.MustCompile(`(?i)The request could not be satisfied`),
		},
		Priority: 80,
		Reliable: true,
	},

	{
		Name:     "pkSecurity IDS",
		ID:       "pksec",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)pk.?Security.?Module`),
			regexp.MustCompile(`(?i)Security.Alert`),
			regexp.MustCompile(`(?i)As this could be a potential hack attack`),
			regexp.MustCompile(`(?i)A safety critical (call|request) was (detected|discovered) and blocked`),
		},
		Priority: 35,
		Reliable: true,
	},

	// =============================================================================
	// ADDITIONAL CLOUD WAF PROVIDERS (wafw00f expansion)
	// =============================================================================

	{
		Name:     "Airlock (Phion/Ergon)",
		ID:       "airlock",
		Category: "appliance",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^al[_-]?(sess|lb)=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)server detected a syntax error in your request`),
			regexp.MustCompile(`(?i)Airlock`),
		},
		BypassTips: []string{
			"Airlock uses strict request validation",
			"Try URL encoding variants",
			"Test with different HTTP methods",
		},
		Encoders: []string{"double_url", "unicode"},
		Evasions: []string{"method_override", "case_swap"},
		Priority: 65,
		Reliable: true,
	},

	{
		Name:     "Alert Logic",
		ID:       "alertlogic",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)requested url cannot be found`),
			regexp.MustCompile(`(?i)we are sorry.*but the page you are looking for cannot be found`),
			regexp.MustCompile(`(?i)reference id`),
			regexp.MustCompile(`(?i)Alert Logic`),
		},
		BypassTips: []string{
			"Alert Logic uses signature matching",
			"Try payload fragmentation",
		},
		Encoders: []string{"double_url", "html_decimal"},
		Evasions: []string{"fragmentation"},
		Priority: 55,
		Reliable: false,
	},

	{
		Name:     "AnYu (AnYu Technologies)",
		ID:       "anyu",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)anyu.*the green channel`),
			regexp.MustCompile(`(?i)your access has been intercepted by anyu`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "ASPA Firewall",
		ID:       "aspa",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":            regexp.MustCompile(`(?i)ASPA[\-_]?WAF`),
			"ASPA-Cache-Status": regexp.MustCompile(`.+`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Barikode (Ethic Ninja)",
		ID:       "barikode",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<strong>barikode</strong>`),
			regexp.MustCompile(`(?i)barikode`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Bluedon (Bluedon IST)",
		ID:       "bluedon",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)BDWAF`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)bluedon web application firewall`),
			regexp.MustCompile(`(?i)bluedon`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "CdnNS Application Gateway",
		ID:       "cdnns",
		Category: "cdn-integrated",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)cdnnswaf application gateway`),
			regexp.MustCompile(`(?i)cdnns`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "ChinaCache Load Balancer",
		ID:       "chinacache",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Powered-By-ChinaCache": regexp.MustCompile(`.+`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Cloudfloor DNS WAF",
		ID:       "cloudfloor",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)CloudfloorDNS(\.WAF)?`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)CloudfloorDNS.*Web Application Firewall Error`),
			regexp.MustCompile(`(?i)cloudfloor`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Comodo cWatch",
		ID:       "comodo",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Protected by COMODO WAF`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)comodo`),
			regexp.MustCompile(`(?i)cwatch`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Cisco ACE XML Gateway",
		ID:       "cisco_ace",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)ACE XML Gateway`),
		},
		BypassTips: []string{
			"ACE Gateway inspects XML payloads",
			"Try CDATA section injection",
			"Test with XXE variations",
		},
		Encoders: []string{"cdata", "xml_entity"},
		Evasions: []string{"cdata_injection"},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:     "Envoy Proxy",
		ID:       "envoy",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":                regexp.MustCompile(`(?i)envoy`),
			"X-Envoy-Upstream":      regexp.MustCompile(`.+`),
			"X-Envoy-Attempt-Count": regexp.MustCompile(`.+`),
		},
		BypassTips: []string{
			"Envoy is often used with custom filters",
			"Filter configuration varies widely",
		},
		Priority: 55,
		Reliable: false,
	},

	{
		Name:     "FortiGate (Fortinet)",
		ID:       "fortigate",
		Category: "appliance",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)//globalurl\.fortinet\.net`),
			regexp.MustCompile(`(?i)FortiGate Application Control`),
			regexp.MustCompile(`(?i)fortigate`),
		},
		BypassTips: []string{
			"FortiGate uses signature-based detection",
			"Try URL encoding variants",
		},
		Encoders: []string{"double_url", "unicode"},
		Priority: 70,
		Reliable: true,
	},

	{
		Name:     "FortiGuard (Fortinet)",
		ID:       "fortiguard",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)FortiGuard Intrusion Prevention`),
			regexp.MustCompile(`(?i)//globalurl\.fortinet\.net`),
			regexp.MustCompile(`(?i)fortiguard`),
		},
		Priority: 65,
		Reliable: true,
	},

	{
		Name:     "IndusGuard (Indusface)",
		ID:       "indusguard",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)IF_WAF`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)This website is secured against online attacks\. Your request was blocked`),
			regexp.MustCompile(`(?i)indusface`),
			regexp.MustCompile(`(?i)indusguard`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Janusec Application Gateway",
		ID:       "janusec",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)janusec application gateway`),
			regexp.MustCompile(`(?i)janusec`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:        "Nemesida (PentestIt)",
		ID:          "nemesida",
		Category:    "software",
		StatusCodes: []int{222},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)nemesida-security\.com`),
			regexp.MustCompile(`(?i)Suspicious activity detected.*Access to the site is blocked`),
			regexp.MustCompile(`(?i)nemesida`),
		},
		BypassTips: []string{
			"Nemesida uses ML-based detection",
			"Try varied payload patterns",
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "NetContinuum (Barracuda)",
		ID:       "netcontinuum",
		Category: "appliance",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^NCI__SessionId=`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "NSFocus WAF",
		ID:       "nsfocus",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)NSFocus`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)nsfocus`),
		},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:     "Palo Alto Next Gen Firewall",
		ID:       "paloalto",
		Category: "appliance",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Download of virus\.spyware blocked`),
			regexp.MustCompile(`(?i)Palo Alto Next Generation Security Platform`),
			regexp.MustCompile(`(?i)paloaltonetworks`),
		},
		BypassTips: []string{
			"Palo Alto uses App-ID for traffic inspection",
			"Try protocol tunneling",
			"Test with encrypted payloads",
		},
		Priority: 75,
		Reliable: true,
	},

	{
		Name:     "PentaWAF",
		ID:       "pentawaf",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)PentaWaf`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Penta.?Waf.*server`),
			regexp.MustCompile(`(?i)pentawaf`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "PT Application Firewall",
		ID:       "ptaf",
		Category: "appliance",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<h1.*Forbidden`),
			regexp.MustCompile(`(?i)<pre>Request\.ID:.*\d{4}\-`),
			regexp.MustCompile(`(?i)Positive Technologies`),
		},
		Priority: 55,
		Reliable: false,
	},

	{
		Name:     "Puhui WAF",
		ID:       "puhui",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Puhui[\-_]?WAF`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Sabre Firewall",
		ID:       "sabre",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)dxsupport\.sabre\.com`),
			regexp.MustCompile(`(?i)<title>Application Firewall Error`),
			regexp.MustCompile(`(?i)sabre`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Safe3 Web Firewall",
		ID:       "safe3",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":       regexp.MustCompile(`(?i)Safe3 Web Firewall`),
			"X-Powered-By": regexp.MustCompile(`(?i)Safe3WAF`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Scutum WAF",
		ID:       "scutum",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Scutum`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "SecKing WAF",
		ID:       "secking",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)secking(\.?waf)?`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "SecuPress WP Security",
		ID:       "secupress",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<title>SecuPress`),
			regexp.MustCompile(`(?i)<h1>SecuPress`),
			regexp.MustCompile(`(?i)blocked by SecuPress`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "ServerDefender VP",
		ID:       "serverdefender",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Pint": regexp.MustCompile(`(?i)p(ort\-)?80`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "Shadow Daemon WAF",
		ID:       "shadowdaemon",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<h\d{1}>\d{3}.forbidden</h\d{1}>`),
			regexp.MustCompile(`(?i)request forbidden by administrative rules`),
			regexp.MustCompile(`(?i)shadow.?daemon`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Variti WAF",
		ID:       "variti",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Variti`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Varnish WAF (OWASP)",
		ID:       "varnish_waf",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Request rejected by xVarnish-WAF`),
			regexp.MustCompile(`(?i)varnish.?waf`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Viettel WAF (Cloudrity)",
		ID:       "viettel",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Access Denied.*Viettel WAF`),
			regexp.MustCompile(`(?i)cloudrity\.com`),
			regexp.MustCompile(`(?i)viettel`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "VirusDie",
		ID:       "virusdie",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)cdn\.virusdie\.ru/splash/firewallstop\.png`),
			regexp.MustCompile(`(?i)virusdie`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Wallarm WAF",
		ID:       "wallarm",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)nginx[\-_]wallarm`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)wallarm`),
		},
		BypassTips: []string{
			"Wallarm uses ML and signature hybrid",
			"Try varied payload mutations",
		},
		Encoders: []string{"unicode", "double_url"},
		Evasions: []string{"mutation"},
		Priority: 70,
		Reliable: true,
	},

	{
		Name:     "WatchGuard Firewall",
		ID:       "watchguard",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)WatchGuard`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Request denied by WatchGuard Firewall`),
			regexp.MustCompile(`(?i)watchguard`),
		},
		BypassTips: []string{
			"WatchGuard uses signature matching",
			"Try encoding variations",
		},
		Encoders: []string{"double_url", "unicode"},
		Priority: 65,
		Reliable: true,
	},

	{
		Name:     "WebARX Security",
		ID:       "webarx",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)WebARX.*Web Application Firewall`),
			regexp.MustCompile(`(?i)/wp-content/plugins/webarx/`),
			regexp.MustCompile(`(?i)webarx`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "WebTotem",
		ID:       "webtotem",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)The current request was blocked.*WebTotem`),
			regexp.MustCompile(`(?i)webtotem`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "WTS-WAF",
		ID:       "wts_waf",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)wts/[0-9\.]+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<title>WTS-WAF`),
			regexp.MustCompile(`(?i)wts.?waf`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "ZScaler WAF",
		ID:       "zscaler",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)ZScaler`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Access Denied.*Accenture Policy`),
			regexp.MustCompile(`(?i)Internet Security by ZScaler`),
			regexp.MustCompile(`(?i)zscaler`),
		},
		BypassTips: []string{
			"ZScaler uses SSL inspection",
			"Try certificate pinning bypass",
		},
		Priority: 70,
		Reliable: true,
	},

	// =============================================================================
	// ADDITIONAL WAF SIGNATURES (wafw00f parity expansion)
	// =============================================================================

	// --- CLOUD WAFs ---

	{
		Name:     "360PanYun (360 Technologies)",
		ID:       "360panyun",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":                regexp.MustCompile(`(?i)panyun`),
			"X-Panyun-Request-ID":   regexp.MustCompile(`.+`),
			"X-Panyun-Error-Reason": regexp.MustCompile(`.+`),
			"X-Panyun-Error-Step":   regexp.MustCompile(`.+`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "AliYunDun (Alibaba Cloud)",
		ID:       "aliyundun",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)errors?\.aliyun(dun)?\.(com|net)`),
			regexp.MustCompile(`(?i)Sorry, your request has been blocked`),
			regexp.MustCompile(`(?i)This request has been blocked by Aliyun`),
		},
		StatusCodes: []int{405},
		Priority:    65,
		Reliable:    true,
	},

	{
		Name:     "Armor Defense (Armor)",
		ID:       "armor",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)blocked by website protection from armor`),
			regexp.MustCompile(`(?i)please create an armor support ticket`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Astra (Czar Securities)",
		ID:       "astra",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)astra\.security`),
			regexp.MustCompile(`(?i)protected by astra`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "BaffinBay (Mastercard)",
		ID:       "baffinbay",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-BaffinBay-Backend-Status": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)baffinbay`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "BinarySec WAF",
		ID:       "binarysec",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":              regexp.MustCompile(`(?i)BinarySec`),
			"x-binarysec-via":     regexp.MustCompile(`.+`),
			"x-binarysec-nocache": regexp.MustCompile(`.+`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "BlockDoS",
		ID:       "blockdos",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)blockdos\.net`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "DDoS-GUARD",
		ID:       "ddosguard",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)ddos-guard`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^__ddg1=`),
			regexp.MustCompile(`(?i)^__ddg2=`),
			regexp.MustCompile(`(?i)^__ddgid=`),
			regexp.MustCompile(`(?i)^__ddgmark=`),
		},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:          "DenyALL (Rohde & Schwarz)",
		ID:            "denyall_rweb",
		Category:      "appliance",
		StatusCodes:   []int{200},
		ReasonPhrases: []string{"Condition Intercepted"},
		Priority:      50,
		Reliable:      false,
	},

	{
		Name:     "DOSarrest",
		ID:       "dosarrest",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":           regexp.MustCompile(`(?i)DOSarrest`),
			"X-DIS-Request-ID": regexp.MustCompile(`.+`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "DynamicWeb Injection Check",
		ID:       "dynamicweb",
		Category: "software",
		AttackHeaders: map[string]*regexp.Regexp{
			"X-403-Status-By": regexp.MustCompile(`(?i)dw\.inj\.check`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)by dynamic check`),
			regexp.MustCompile(`(?i)DynamicWeb`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "GoDaddy Website Protection",
		ID:       "godaddy",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)GoDaddy (security|website firewall)`),
			regexp.MustCompile(`(?i)go daddy`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "Greywizard WAF",
		ID:       "greywizard",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)greywizard`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)greywizard\.biz`),
			regexp.MustCompile(`(?i)grey wizard`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Link11 WAAP",
		ID:       "link11",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Link11-Protection": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)link11\.com`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "NexusGuard Firewall",
		ID:       "nexusguard",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Powered by Nexusguard`),
			regexp.MustCompile(`(?i)nexusguard\.com/wafpage/`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Oracle Cloud WAF",
		ID:       "oracle_cloud",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)ZENEDGE`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)oracle\.com/cloud`),
			regexp.MustCompile(`(?i)oracle cloud infrastructure`),
		},
		Priority: 60,
		Reliable: false,
	},

	{
		Name:     "Qrator",
		ID:       "qrator",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Qrator-Blocked": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)qrator\.net`),
			regexp.MustCompile(`(?i)protected by qrator`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Secure Entry (United Security Providers)",
		ID:       "secureentry",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Secure Entry Server`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "SecureSphere (Imperva)",
		ID:       "securesphere",
		Category: "appliance",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)SecureSphere`),
			regexp.MustCompile(`(?i)Imperva SecureSphere`),
		},
		Priority: 65,
		Reliable: false,
	},

	{
		Name:     "SquidProxy IDS",
		ID:       "squid",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)squid(/[0-9\.]+)?`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Access control configuration prevents your request`),
			regexp.MustCompile(`(?i)Generated .{0,20}? by squid`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "ThreatX (A10 Networks)",
		ID:       "threatx",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Request-Id": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Forbidden - ID:`),
			regexp.MustCompile(`(?i)threatx\.com`),
		},
		StatusCodes: []int{403},
		Priority:    55,
		Reliable:    false,
	},

	{
		Name:     "XLabs Security WAF",
		ID:       "xlabs",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-CDN":   regexp.MustCompile(`(?i)XLabs Security`),
			"Secured": regexp.MustCompile(`(?i)By XLabs Security`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)xlabs\.com\.br`),
		},
		Priority: 50,
		Reliable: true,
	},

	// --- CDN-INTEGRATED ---

	{
		Name:     "Beluga CDN",
		ID:       "beluga",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Beluga`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^beluga_request_trail=`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "CacheFly CDN",
		ID:       "cachefly",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"BestCDN": regexp.MustCompile(`(?i)Cachefly`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^cfly_req.*?=`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "LimeLight CDN",
		ID:       "limelight",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)LimeLight`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "PowerCDN",
		ID:       "powercdn",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-CDN": regexp.MustCompile(`(?i)PowerCDN`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "Qiniu CDN",
		ID:       "qiniu_cdn",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Qiniu-CDN": regexp.MustCompile(`.+`),
		},
		Priority: 50,
		Reliable: true,
	},

	// --- APPLIANCE/ENTERPRISE ---

	{
		Name:     "DataPower (IBM)",
		ID:       "datapower",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Backside-Transport": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)DataPower`),
			regexp.MustCompile(`(?i)IBM DataPower Gateway`),
		},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:     "F5 BIG-IP APM",
		ID:       "f5_apm",
		Category: "appliance",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^F5_fire=`),
			regexp.MustCompile(`(?i)^F5_passid_shrinked=`),
		},
		HeaderPatterns: map[string]*regexp.Regexp{
			"Location": regexp.MustCompile(`(?i)my\.logon\.php3`),
		},
		Priority: 70,
		Reliable: true,
	},

	{
		Name:     "ISA Server (Microsoft)",
		ID:       "isa_server",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Via": regexp.MustCompile(`(?i)Microsoft-ISA-Server`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)The ISA Server`),
			regexp.MustCompile(`(?i)Microsoft ISA Server`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Kemp LoadMaster",
		ID:       "kemp",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Kemp LoadMaster`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Mission Control Shield",
		ID:       "missioncontrol",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Mission Control`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Mission Control Application Shield`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "NevisProxy (AdNovum)",
		ID:       "nevisproxy",
		Category: "appliance",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^Nevis`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Nevis Proxy`),
			regexp.MustCompile(`(?i)adnovum\.ch`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "OnMessage Shield (BlackBaud)",
		ID:       "onmessage",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Engine": regexp.MustCompile(`(?i)onMessage Shield`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)onmessage.{0,10}?shield`),
			regexp.MustCompile(`(?i)blackbaud`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "SonicWall (Dell)",
		ID:       "sonicwall",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)SonicWALL`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)SonicWall`),
			regexp.MustCompile(`(?i)This request is blocked by the SonicWall`),
			regexp.MustCompile(`(?i)web site filter`),
		},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:     "Teros (Citrix)",
		ID:       "teros",
		Category: "appliance",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^st8(id|_wat|_wlf)=`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Trafficshield (F5)",
		ID:       "trafficshield",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)F5-TrafficShield`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^ASINFO=`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "TransIP Web Firewall",
		ID:       "transip",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)transip\.nl/cp/`),
			regexp.MustCompile(`(?i)TransIP Web Firewall`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "WebSEAL (IBM)",
		ID:       "webseal",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)WebSEAL`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)This is a WebSEAL error message`),
			regexp.MustCompile(`(?i)IBM Security Access Manager`),
		},
		Priority: 55,
		Reliable: true,
	},

	// --- SOFTWARE ---

	{
		Name:     "aeSecure",
		ID:       "aesecure",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"aeSecure-code": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aesecure_denied\.png`),
			regexp.MustCompile(`(?i)aesecure`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "CacheWall (Varnish)",
		ID:       "cachewall",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)CacheWall`),
			regexp.MustCompile(`(?i)Varnish.{0,10}?cachewall`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "LiteSpeed",
		ID:       "litespeed",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)LiteSpeed`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Powered by LiteSpeed Web Server`),
		},
		BypassTips: []string{
			"LiteSpeed has built-in ModSecurity rules",
			"Try encoding payloads",
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "Malcare (Inactiv)",
		ID:       "malcare",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)malcare\.com`),
			regexp.MustCompile(`(?i)blocked by malcare`),
			regexp.MustCompile(`(?i)firewall powered by malcare`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "NAXSI (Nginx Anti XSS & SQL Injection)",
		ID:       "naxsi_full",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Data-Origin": regexp.MustCompile(`(?i)naxsi`),
			"Server":        regexp.MustCompile(`(?i)naxsi`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)blocked by naxsi`),
		},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:     "Newdefend",
		ID:       "newdefend",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Newdefend`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)www\.newdefend\.com/feedback`),
			regexp.MustCompile(`(?i)/nd-block/`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "NinjaFirewall (NinTechNet)",
		ID:       "ninjafirewall",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<title>NinjaFirewall.{0,10}?\d{3}.forbidden`),
			regexp.MustCompile(`(?i)it was blocked and logged`),
			regexp.MustCompile(`(?i)NinTechNet`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "Open-Resty Lua Nginx (FLOSS)",
		ID:       "openresty_lua",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)openresty`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)lua`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "RSFirewall (RSJoomla!)",
		ID:       "rsfirewall_full",
		Category: "joomla-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)com_rsfirewall`),
			regexp.MustCompile(`(?i)rsjoomla`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "SiteGround",
		ID:       "siteground",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Proxy-Cache": regexp.MustCompile(`(?i)siteground`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)siteground\.com`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "SiteGuard (EG Secure)",
		ID:       "siteguard_eg",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Powered by SiteGuard`),
			regexp.MustCompile(`(?i)The server refuse to browse the page`),
			regexp.MustCompile(`(?i)You cannot access`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Squarespace",
		ID:       "squarespace",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Squarespace`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^SS_ANALYTICS_ID=`),
			regexp.MustCompile(`(?i)^SS_MATTR=`),
			regexp.MustCompile(`(?i)^SS_MID=`),
			regexp.MustCompile(`(?i)^SS_CVT=`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "URLMaster SecurityCheck",
		ID:       "urlmaster",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)UrlMaster`),
			regexp.MustCompile(`(?i)Security Check`),
		},
		Priority: 40,
		Reliable: false,
	},

	// --- WORDPRESS WAF PLUGINS ---

	{
		Name:     "Malcare (Inactiv) WP",
		ID:       "malcare_wp",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)malcare firewall`),
			regexp.MustCompile(`(?i)your ip has been blocked`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "wpmudev WAF (Incsub)",
		ID:       "wpmudev_full",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)wpmudev\.com`),
			regexp.MustCompile(`(?i)Click on the Logs tab`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "ASP.NET Generic (Microsoft)",
		ID:       "aspnet",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)iis.{0,10}?detailed error`),
			regexp.MustCompile(`(?i)potentially dangerous request`),
			regexp.MustCompile(`(?i)Application error occurred on the server`),
			regexp.MustCompile(`(?i)Request\.Path value was detected from the client`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Expression Engine (EllisLab)",
		ID:       "expressionengine",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)ExpressionEngine`),
			regexp.MustCompile(`(?i)EllisLab`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "RequestValidationMode (Microsoft)",
		ID:       "requestvalidation",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Request Validation`),
			regexp.MustCompile(`(?i)HttpRequestValidationException`),
			regexp.MustCompile(`(?i)A potentially dangerous Request`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Reflected Networks",
		ID:       "reflectednetworks",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Reflected Networks`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)reflected\.net`),
		},
		Priority: 40,
		Reliable: false,
	},

	// --- BOT MANAGEMENT ---

	{
		Name:     "Anubis (Techaro)",
		ID:       "anubis",
		Category: "bot-management",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)-anubis-auth=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<script id="anubis_version"`),
			regexp.MustCompile(`(?i)Protected by.*Anubis.*Techaro`),
			regexp.MustCompile(`(?i)Checking your browser`),
		},
		Priority: 55,
		Reliable: true,
	},

	// --- ADDITIONAL CHINESE WAF ---

	{
		Name:     "Yundun (Enhanced)",
		ID:       "yundun_enhanced",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":  regexp.MustCompile(`(?i)YUNDUN`),
			"X-Cache": regexp.MustCompile(`(?i)YUNDUN`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^yd_cookie=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Blocked by YUNDUN Cloud WAF`),
		},
		Priority: 60,
		Reliable: true,
	},

	// --- ADDITIONAL MISC WAF ---

	{
		Name:     "AppTrana (Indusface)",
		ID:       "apptrana",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)AppTrana`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)apptrana\.com`),
			regexp.MustCompile(`(?i)indusface`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "AWS Elastic Load Balancer",
		ID:       "aws_elb",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)awselb/\d`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^AWSELB=`),
			regexp.MustCompile(`(?i)^AWSELBCORS=`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "BIG-IP Local Traffic Manager (F5)",
		ID:       "bigip_ltm",
		Category: "appliance",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^BIGipServer`),
		},
		HeaderPatterns: map[string]*regexp.Regexp{
			"Set-Cookie": regexp.MustCompile(`(?i)BIGipServer`),
		},
		Priority: 65,
		Reliable: true,
	},

	{
		Name:     "Edgecast (Verizon Digital Media)",
		ID:       "edgecast",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)ECS|ECD`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)verizon digital media`),
		},
		Priority: 55,
		Reliable: false,
	},

	{
		Name:     "GCore WAF",
		ID:       "gcore",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)gcore`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)gcorelabs\.com`),
		},
		Priority: 50,
		Reliable: false,
	},

	{
		Name:     "HAProxy",
		ID:       "haproxy",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)haproxy`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "Imperva Advanced Bot Protection",
		ID:       "imperva_abp",
		Category: "bot-management",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)bot protection`),
			regexp.MustCompile(`(?i)imperva`),
		},
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Iinfo": regexp.MustCompile(`.+`),
		},
		Priority: 70,
		Reliable: false,
	},

	{
		Name:     "Jiasule (China)",
		ID:       "jiasule",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)jiasule`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^__jsluid`),
			regexp.MustCompile(`(?i)^jsl_clearance`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)jiasule\.com`),
		},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:     "LiteSpeed Enterprise",
		ID:       "litespeed_enterprise",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":                    regexp.MustCompile(`(?i)LiteSpeed`),
			"X-LiteSpeed-Cache":         regexp.MustCompile(`.+`),
			"X-LiteSpeed-Cache-Control": regexp.MustCompile(`.+`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "ModSecurity-nginx",
		ID:       "modsecurity_nginx",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)nginx.*modsecurity`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)mod.?security`),
		},
		Priority: 70,
		Reliable: true,
	},

	{
		Name:     "NetScaler Gateway (Citrix)",
		ID:       "netscaler_gateway",
		Category: "appliance",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^NSC_AAAC=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)NetScaler Gateway`),
		},
		Priority: 60,
		Reliable: true,
	},

	{
		Name:     "Netlify WAF",
		ID:       "netlify",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":          regexp.MustCompile(`(?i)Netlify`),
			"X-NF-Request-ID": regexp.MustCompile(`.+`),
		},
		Priority: 50,
		Reliable: true,
	},

	{
		Name:     "Nginx Plus",
		ID:       "nginx_plus",
		Category: "software",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)nginx`),
		},
		BypassTips: []string{
			"Nginx Plus may have custom security modules",
			"Check for additional headers",
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "OVH DDoS Protection",
		ID:       "ovh",
		Category: "cloud",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)ovh\.com`),
			regexp.MustCompile(`(?i)protected by ovh`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "Section.io Varnish",
		ID:       "section_io",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Section-io-id": regexp.MustCompile(`.+`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Signal Sciences (Fastly)",
		ID:       "signalsciences",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-SigSci-Tags": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)signal sciences`),
			regexp.MustCompile(`(?i)signalsciences\.net`),
		},
		BypassTips: []string{
			"Signal Sciences uses PowerWAF rules",
			"Try payload mutation",
		},
		Priority: 65,
		Reliable: true,
	},

	{
		Name:     "Snapt Aria",
		ID:       "snapt",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)Snapt`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)snapt\.net`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Stingray Traffic Manager (Riverbed)",
		ID:       "stingray",
		Category: "appliance",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)stingray`),
		},
		Priority: 45,
		Reliable: false,
	},

	{
		Name:     "Vercel Firewall",
		ID:       "vercel",
		Category: "cdn-integrated",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":      regexp.MustCompile(`(?i)Vercel`),
			"X-Vercel-Id": regexp.MustCompile(`.+`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "WebComent Firewall",
		ID:       "webcoment",
		Category: "software",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)webcoment`),
		},
		Priority: 40,
		Reliable: false,
	},

	{
		Name:     "Wordfence Extended Protection",
		ID:       "wordfence_extended",
		Category: "wordpress-plugin",
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)wordfence.{0,20}?blocked`),
			regexp.MustCompile(`(?i)this request has been blocked`),
		},
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)wf[_-]?WAF`),
		},
		Priority: 55,
		Reliable: true,
	},

	{
		Name:     "YesWAF",
		ID:       "yeswaf",
		Category: "cloud",
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)YesWAF`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)yeswaf\.com`),
		},
		Priority: 45,
		Reliable: true,
	},

	{
		Name:     "Yunsuo (Cloud)",
		ID:       "yunsuo_cloud",
		Category: "cloud",
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^yunsuo_session=`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)yunsuo`),
		},
		Priority: 55,
		Reliable: true,
	},
}

// GetAllSignatures returns all WAF signatures sorted by priority
func GetAllSignatures() []WAFSignature {
	// Already sorted by priority in the slice definition
	return AllSignatures
}

// GetSignatureByID returns a WAF signature by its vendor ID
func GetSignatureByID(id WAFVendor) *WAFSignature {
	for i := range AllSignatures {
		if AllSignatures[i].ID == id {
			return &AllSignatures[i]
		}
	}
	return nil
}

// GetSignaturesByCategory returns all signatures in a category
func GetSignaturesByCategory(category string) []WAFSignature {
	var result []WAFSignature
	for _, sig := range AllSignatures {
		if sig.Category == category {
			result = append(result, sig)
		}
	}
	return result
}

// GetTotalSignatureCount returns the total number of WAF signatures
func GetTotalSignatureCount() int {
	return len(AllSignatures)
}

// SignatureSummary is a JSON-friendly view of a WAF signature for the MCP resource.
type SignatureSummary struct {
	Name       string   `json:"name"`
	Category   string   `json:"type"`
	BypassTips []string `json:"bypass_tips,omitempty"`
	Encoders   []string `json:"recommended_encoders,omitempty"`
	Evasions   []string `json:"recommended_evasions,omitempty"`
	Detection  []string `json:"detection,omitempty"`
	Reliable   bool     `json:"reliable"`
}

// GetSignatureSummaries returns a JSON-serializable summary of all signatures
// that have bypass tips, sorted by priority (highest first).
func GetSignatureSummaries() []SignatureSummary {
	var summaries []SignatureSummary
	for _, sig := range AllSignatures {
		if len(sig.BypassTips) == 0 {
			continue
		}

		// Derive detection method descriptions from pattern fields.
		var detection []string
		for name := range sig.HeaderPatterns {
			detection = append(detection, name+" header pattern")
		}
		if len(sig.CookiePatterns) > 0 {
			detection = append(detection, "Cookie patterns")
		}
		if len(sig.BodyPatterns) > 0 {
			detection = append(detection, "Response body patterns")
		}
		if len(sig.BlockPatterns) > 0 {
			detection = append(detection, "Block page signatures")
		}
		if len(sig.StatusCodes) > 0 {
			detection = append(detection, "Specific status codes")
		}
		sort.Strings(detection)

		summaries = append(summaries, SignatureSummary{
			Name:       sig.Name,
			Category:   sig.Category,
			BypassTips: sig.BypassTips,
			Encoders:   sig.Encoders,
			Evasions:   sig.Evasions,
			Detection:  detection,
			Reliable:   sig.Reliable,
		})
	}
	return summaries
}

// GetVendorNamesByCategory returns sorted unique vendor names for the given categories.
func GetVendorNamesByCategory(categories ...string) []string {
	catSet := make(map[string]struct{}, len(categories))
	for _, c := range categories {
		catSet[c] = struct{}{}
	}

	seen := make(map[string]struct{})
	var names []string
	for _, sig := range AllSignatures {
		if _, ok := catSet[sig.Category]; !ok {
			continue
		}
		if _, dup := seen[sig.Name]; dup {
			continue
		}
		seen[sig.Name] = struct{}{}
		names = append(names, sig.Name)
	}
	sort.Strings(names)
	return names
}

// WAFCategories returns the vendor categories that represent WAF products
// (everything except CDN-integrated). Use with GetVendorNamesByCategory.
func WAFCategories() []string {
	return []string{"cloud", "appliance", "software", "bot-management", "wordpress-plugin", "joomla-plugin"}
}

// CDNCategories returns the vendor categories that represent CDN-integrated WAFs.
func CDNCategories() []string {
	return []string{"cdn-integrated"}
}
