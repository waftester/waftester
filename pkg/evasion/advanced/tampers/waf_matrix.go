package tampers

// WAF Intelligence Matrix
// Maps WAF vendors to optimal tamper configurations based on research and testing.
// Each vendor has tamper recommendations ordered by effectiveness.

// TamperRecommendation represents a tamper's effectiveness for a specific WAF
type TamperRecommendation struct {
	Name          string  // Tamper name (must match registry)
	Effectiveness float64 // 0.0-1.0 effectiveness score
	Order         int     // Execution order in chain (lower = first)
	RequiresHTTP  bool    // Requires HTTP-level transformation
	Notes         string  // Additional context
}

// wafMatrix holds vendor-specific tamper recommendations
// Key: lowercase WAF vendor identifier
// Value: ordered slice of tamper recommendations
var wafMatrix = map[string][]TamperRecommendation{
	// === CLOUDFLARE ===
	"cloudflare": {
		{Name: "charunicodeencode", Effectiveness: 0.85, Order: 1, Notes: "CF struggles with unicode encoding"},
		{Name: "space2morecomment", Effectiveness: 0.82, Order: 2, Notes: "Multi-comment spacing bypasses pattern matching"},
		{Name: "randomcase", Effectiveness: 0.78, Order: 3, Notes: "Case randomization effective for SQL"},
		{Name: "modsecurityversioned", Effectiveness: 0.75, Order: 4, Notes: "Version comments often ignored"},
		{Name: "between", Effectiveness: 0.72, Order: 5, Notes: "BETWEEN bypass for comparison operators"},
		{Name: "space2comment", Effectiveness: 0.70, Order: 6},
		{Name: "percentage", Effectiveness: 0.68, Order: 7, Notes: "ASP/IIS specific"},
		{Name: "charencode", Effectiveness: 0.65, Order: 8},
		{Name: "unionalltounion", Effectiveness: 0.60, Order: 9},
		{Name: "equaltolike", Effectiveness: 0.55, Order: 10},
	},

	// === AWS WAF ===
	"aws_waf": {
		{Name: "chardoubleencode", Effectiveness: 0.90, Order: 1, Notes: "Double URL encoding very effective"},
		{Name: "space2hash", Effectiveness: 0.85, Order: 2, Notes: "MySQL hash comments"},
		{Name: "randomcase", Effectiveness: 0.80, Order: 3},
		{Name: "charunicodeencode", Effectiveness: 0.78, Order: 4},
		{Name: "between", Effectiveness: 0.75, Order: 5},
		{Name: "greatest", Effectiveness: 0.72, Order: 6, Notes: "GREATEST() function bypass"},
		{Name: "least", Effectiveness: 0.70, Order: 7, Notes: "LEAST() function bypass"},
		{Name: "space2morecomment", Effectiveness: 0.68, Order: 8},
		{Name: "modsecurityzeroversioned", Effectiveness: 0.65, Order: 9},
		{Name: "charencode", Effectiveness: 0.60, Order: 10},
	},

	// === AZURE WAF (Front Door / Application Gateway) ===
	"azure_waf": {
		{Name: "charunicodeencode", Effectiveness: 0.88, Order: 1, Notes: "Unicode encoding effective"},
		{Name: "space2morecomment", Effectiveness: 0.82, Order: 2},
		{Name: "between", Effectiveness: 0.78, Order: 3},
		{Name: "randomcase", Effectiveness: 0.75, Order: 4},
		{Name: "modsecurityversioned", Effectiveness: 0.72, Order: 5},
		{Name: "equaltolike", Effectiveness: 0.70, Order: 6},
		{Name: "greatest", Effectiveness: 0.68, Order: 7},
		{Name: "percentage", Effectiveness: 0.65, Order: 8},
		{Name: "space2comment", Effectiveness: 0.62, Order: 9},
		{Name: "charencode", Effectiveness: 0.58, Order: 10},
	},

	// === MODSECURITY (CRS) ===
	"modsecurity": {
		{Name: "modsecurityversioned", Effectiveness: 0.95, Order: 1, Notes: "Designed specifically for ModSecurity"},
		{Name: "modsecurityzeroversioned", Effectiveness: 0.92, Order: 2, Notes: "Zero-version variant"},
		{Name: "space2comment", Effectiveness: 0.88, Order: 3, Notes: "Classic CRS bypass"},
		{Name: "space2morecomment", Effectiveness: 0.85, Order: 4},
		{Name: "between", Effectiveness: 0.82, Order: 5},
		{Name: "equaltolike", Effectiveness: 0.80, Order: 6},
		{Name: "randomcase", Effectiveness: 0.75, Order: 7},
		{Name: "greatest", Effectiveness: 0.72, Order: 8},
		{Name: "least", Effectiveness: 0.70, Order: 9},
		{Name: "charencode", Effectiveness: 0.65, Order: 10},
		{Name: "unionalltounion", Effectiveness: 0.60, Order: 11},
		{Name: "percentage", Effectiveness: 0.55, Order: 12},
	},

	// === AKAMAI ===
	"akamai": {
		{Name: "chardoubleencode", Effectiveness: 0.85, Order: 1, Notes: "Double encoding bypasses normalization"},
		{Name: "space2morecomment", Effectiveness: 0.82, Order: 2},
		{Name: "charunicodeencode", Effectiveness: 0.80, Order: 3},
		{Name: "randomcase", Effectiveness: 0.75, Order: 4},
		{Name: "between", Effectiveness: 0.72, Order: 5},
		{Name: "modsecurityversioned", Effectiveness: 0.70, Order: 6},
		{Name: "greatest", Effectiveness: 0.68, Order: 7},
		{Name: "space2comment", Effectiveness: 0.65, Order: 8},
		{Name: "equaltolike", Effectiveness: 0.62, Order: 9},
		{Name: "percentage", Effectiveness: 0.58, Order: 10},
	},

	// === IMPERVA (Incapsula) ===
	"imperva": {
		{Name: "charunicodeencode", Effectiveness: 0.88, Order: 1, Notes: "Unicode escapes detection"},
		{Name: "space2morecomment", Effectiveness: 0.85, Order: 2},
		{Name: "modsecurityversioned", Effectiveness: 0.82, Order: 3},
		{Name: "randomcase", Effectiveness: 0.78, Order: 4},
		{Name: "between", Effectiveness: 0.75, Order: 5},
		{Name: "chardoubleencode", Effectiveness: 0.72, Order: 6},
		{Name: "greatest", Effectiveness: 0.70, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.68, Order: 8},
		{Name: "space2comment", Effectiveness: 0.65, Order: 9},
		{Name: "least", Effectiveness: 0.60, Order: 10},
	},

	// === F5 BIG-IP ASM ===
	"f5_bigip": {
		{Name: "space2comment", Effectiveness: 0.85, Order: 1, Notes: "Inline comments effective"},
		{Name: "chardoubleencode", Effectiveness: 0.82, Order: 2},
		{Name: "randomcase", Effectiveness: 0.78, Order: 3},
		{Name: "between", Effectiveness: 0.75, Order: 4},
		{Name: "modsecurityversioned", Effectiveness: 0.72, Order: 5},
		{Name: "charunicodeencode", Effectiveness: 0.70, Order: 6},
		{Name: "greatest", Effectiveness: 0.68, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.65, Order: 8},
		{Name: "space2morecomment", Effectiveness: 0.62, Order: 9},
		{Name: "unionalltounion", Effectiveness: 0.58, Order: 10},
	},

	// === FASTLY ===
	"fastly": {
		{Name: "charunicodeencode", Effectiveness: 0.82, Order: 1},
		{Name: "space2morecomment", Effectiveness: 0.80, Order: 2},
		{Name: "randomcase", Effectiveness: 0.78, Order: 3},
		{Name: "chardoubleencode", Effectiveness: 0.75, Order: 4},
		{Name: "between", Effectiveness: 0.72, Order: 5},
		{Name: "modsecurityversioned", Effectiveness: 0.70, Order: 6},
		{Name: "space2comment", Effectiveness: 0.68, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.65, Order: 8},
		{Name: "greatest", Effectiveness: 0.60, Order: 9},
	},

	// === GOOGLE CLOUD ARMOR ===
	"google_cloud_armor": {
		{Name: "charunicodeencode", Effectiveness: 0.85, Order: 1},
		{Name: "space2morecomment", Effectiveness: 0.82, Order: 2},
		{Name: "chardoubleencode", Effectiveness: 0.80, Order: 3},
		{Name: "randomcase", Effectiveness: 0.75, Order: 4},
		{Name: "between", Effectiveness: 0.72, Order: 5},
		{Name: "modsecurityversioned", Effectiveness: 0.70, Order: 6},
		{Name: "greatest", Effectiveness: 0.68, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.65, Order: 8},
		{Name: "space2comment", Effectiveness: 0.62, Order: 9},
		{Name: "least", Effectiveness: 0.58, Order: 10},
	},

	// === SUCURI ===
	"sucuri": {
		{Name: "space2comment", Effectiveness: 0.88, Order: 1, Notes: "Comment injection very effective"},
		{Name: "space2morecomment", Effectiveness: 0.85, Order: 2},
		{Name: "randomcase", Effectiveness: 0.82, Order: 3},
		{Name: "charunicodeencode", Effectiveness: 0.78, Order: 4},
		{Name: "between", Effectiveness: 0.75, Order: 5},
		{Name: "modsecurityversioned", Effectiveness: 0.72, Order: 6},
		{Name: "equaltolike", Effectiveness: 0.70, Order: 7},
		{Name: "chardoubleencode", Effectiveness: 0.68, Order: 8},
		{Name: "greatest", Effectiveness: 0.65, Order: 9},
	},

	// === WORDFENCE ===
	"wordfence": {
		{Name: "charunicodeencode", Effectiveness: 0.90, Order: 1, Notes: "Unicode encoding bypasses most rules"},
		{Name: "space2morecomment", Effectiveness: 0.85, Order: 2},
		{Name: "randomcase", Effectiveness: 0.82, Order: 3},
		{Name: "chardoubleencode", Effectiveness: 0.78, Order: 4},
		{Name: "between", Effectiveness: 0.75, Order: 5},
		{Name: "space2comment", Effectiveness: 0.72, Order: 6},
		{Name: "modsecurityversioned", Effectiveness: 0.70, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.68, Order: 8},
		{Name: "greatest", Effectiveness: 0.65, Order: 9},
	},

	// === FORTINET (FortiWeb) ===
	"fortinet": {
		{Name: "chardoubleencode", Effectiveness: 0.85, Order: 1},
		{Name: "space2morecomment", Effectiveness: 0.82, Order: 2},
		{Name: "charunicodeencode", Effectiveness: 0.80, Order: 3},
		{Name: "randomcase", Effectiveness: 0.75, Order: 4},
		{Name: "modsecurityversioned", Effectiveness: 0.72, Order: 5},
		{Name: "between", Effectiveness: 0.70, Order: 6},
		{Name: "space2comment", Effectiveness: 0.68, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.65, Order: 8},
		{Name: "greatest", Effectiveness: 0.60, Order: 9},
	},

	// === BARRACUDA ===
	"barracuda": {
		{Name: "space2comment", Effectiveness: 0.88, Order: 1},
		{Name: "charunicodeencode", Effectiveness: 0.85, Order: 2},
		{Name: "space2morecomment", Effectiveness: 0.82, Order: 3},
		{Name: "randomcase", Effectiveness: 0.78, Order: 4},
		{Name: "chardoubleencode", Effectiveness: 0.75, Order: 5},
		{Name: "between", Effectiveness: 0.72, Order: 6},
		{Name: "modsecurityversioned", Effectiveness: 0.70, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.68, Order: 8},
		{Name: "greatest", Effectiveness: 0.65, Order: 9},
	},

	// === CITRIX (NetScaler) ===
	"citrix": {
		{Name: "charunicodeencode", Effectiveness: 0.85, Order: 1},
		{Name: "space2morecomment", Effectiveness: 0.82, Order: 2},
		{Name: "chardoubleencode", Effectiveness: 0.80, Order: 3},
		{Name: "randomcase", Effectiveness: 0.75, Order: 4},
		{Name: "between", Effectiveness: 0.72, Order: 5},
		{Name: "space2comment", Effectiveness: 0.70, Order: 6},
		{Name: "modsecurityversioned", Effectiveness: 0.68, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.65, Order: 8},
	},

	// === RADWARE (AppWall) ===
	"radware": {
		{Name: "chardoubleencode", Effectiveness: 0.88, Order: 1},
		{Name: "space2morecomment", Effectiveness: 0.85, Order: 2},
		{Name: "charunicodeencode", Effectiveness: 0.82, Order: 3},
		{Name: "randomcase", Effectiveness: 0.78, Order: 4},
		{Name: "between", Effectiveness: 0.75, Order: 5},
		{Name: "modsecurityversioned", Effectiveness: 0.72, Order: 6},
		{Name: "space2comment", Effectiveness: 0.70, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.68, Order: 8},
	},

	// === WALLARM ===
	"wallarm": {
		{Name: "charunicodeencode", Effectiveness: 0.82, Order: 1},
		{Name: "space2morecomment", Effectiveness: 0.80, Order: 2},
		{Name: "chardoubleencode", Effectiveness: 0.78, Order: 3},
		{Name: "randomcase", Effectiveness: 0.75, Order: 4},
		{Name: "between", Effectiveness: 0.72, Order: 5},
		{Name: "modsecurityversioned", Effectiveness: 0.70, Order: 6},
		{Name: "space2comment", Effectiveness: 0.68, Order: 7},
		{Name: "equaltolike", Effectiveness: 0.65, Order: 8},
	},

	// === REBLAZE ===
	"reblaze": {
		{Name: "space2morecomment", Effectiveness: 0.85, Order: 1},
		{Name: "charunicodeencode", Effectiveness: 0.82, Order: 2},
		{Name: "chardoubleencode", Effectiveness: 0.80, Order: 3},
		{Name: "randomcase", Effectiveness: 0.75, Order: 4},
		{Name: "between", Effectiveness: 0.72, Order: 5},
		{Name: "space2comment", Effectiveness: 0.70, Order: 6},
		{Name: "modsecurityversioned", Effectiveness: 0.68, Order: 7},
	},

	// === SQREEN (Now Datadog) ===
	"sqreen": {
		{Name: "charunicodeencode", Effectiveness: 0.85, Order: 1},
		{Name: "space2morecomment", Effectiveness: 0.82, Order: 2},
		{Name: "randomcase", Effectiveness: 0.78, Order: 3},
		{Name: "chardoubleencode", Effectiveness: 0.75, Order: 4},
		{Name: "between", Effectiveness: 0.72, Order: 5},
		{Name: "modsecurityversioned", Effectiveness: 0.70, Order: 6},
	},

	// === SIGNAL SCIENCES (Now Fastly) ===
	"signal_sciences": {
		{Name: "charunicodeencode", Effectiveness: 0.82, Order: 1},
		{Name: "chardoubleencode", Effectiveness: 0.80, Order: 2},
		{Name: "space2morecomment", Effectiveness: 0.78, Order: 3},
		{Name: "randomcase", Effectiveness: 0.75, Order: 4},
		{Name: "between", Effectiveness: 0.72, Order: 5},
		{Name: "space2comment", Effectiveness: 0.70, Order: 6},
	},
}

// defaultRecommendations is used when WAF vendor is unknown
var defaultRecommendations = []TamperRecommendation{
	{Name: "space2comment", Effectiveness: 0.75, Order: 1, Notes: "Universal SQL comment injection"},
	{Name: "randomcase", Effectiveness: 0.72, Order: 2, Notes: "Case randomization widely effective"},
	{Name: "charencode", Effectiveness: 0.70, Order: 3, Notes: "URL encoding basics"},
	{Name: "between", Effectiveness: 0.68, Order: 4},
	{Name: "equaltolike", Effectiveness: 0.65, Order: 5},
	{Name: "modsecurityversioned", Effectiveness: 0.62, Order: 6},
	{Name: "space2morecomment", Effectiveness: 0.60, Order: 7},
	{Name: "chardoubleencode", Effectiveness: 0.58, Order: 8},
	{Name: "greatest", Effectiveness: 0.55, Order: 9},
	{Name: "charunicodeencode", Effectiveness: 0.52, Order: 10},
}

// GetRecommendations returns tamper recommendations for a WAF vendor
func GetRecommendations(vendor string) []TamperRecommendation {
	if recs, ok := wafMatrix[vendor]; ok {
		return recs
	}
	return defaultRecommendations
}

// GetAllVendors returns all WAF vendors in the matrix
func GetAllVendors() []string {
	vendors := make([]string, 0, len(wafMatrix))
	for v := range wafMatrix {
		vendors = append(vendors, v)
	}
	return vendors
}

// GetTampersForVendor returns just the tamper names for a vendor
func GetTampersForVendor(vendor string) []string {
	recs := GetRecommendations(vendor)
	names := make([]string, len(recs))
	for i, rec := range recs {
		names[i] = rec.Name
	}
	return names
}

// GetTopTampersForVendor returns the top N most effective tampers for a vendor
func GetTopTampersForVendor(vendor string, n int) []string {
	recs := GetRecommendations(vendor)
	if n > len(recs) {
		n = len(recs)
	}

	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i] = recs[i].Name
	}
	return names
}

// HasVendor checks if a vendor exists in the matrix
func HasVendor(vendor string) bool {
	_, ok := wafMatrix[vendor]
	return ok
}

// GetEffectiveness returns the effectiveness score for a tamper against a WAF
func GetEffectiveness(vendor, tamperName string) float64 {
	recs := GetRecommendations(vendor)
	for _, rec := range recs {
		if rec.Name == tamperName {
			return rec.Effectiveness
		}
	}
	return 0.5 // Default mid-effectiveness for unknown combinations
}
