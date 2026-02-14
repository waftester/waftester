package apispec

import (
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

// paramNameRule maps a regex pattern over parameter names to suggested
// attack categories. Patterns are matched case-insensitively.
type paramNameRule struct {
	Pattern    string   // regex matched against lowercase param name
	Categories []string // attack categories to suggest
}

// paramNameRules is the registry of parameter name patterns → attack categories.
// Order does not matter; all matching rules contribute (union).
var paramNameRules = []paramNameRule{
	// URL / redirect parameters
	{`(^|_)(url|uri|link|href|redirect|return|next|continue|goto|dest|destination|callback|forward|redir|return_to|target|ref)(_|$|url)`, []string{"ssrf", "redirect", "requestforgery"}},

	// File / path parameters
	{`(^|_)(file|filename|filepath|path|dir|directory|folder|doc|document|template|include|page|src|source|attachment|download)(_|$)`, []string{"traversal", "lfi", "rfi", "upload", "ssi"}},

	// Command / exec parameters
	{`(^|_)(cmd|command|exec|execute|run|shell|process|program|script|bin|binary|daemon|worker)(_|$)`, []string{"cmdi", "rce", "deserialize"}},

	// Query / search / filter parameters (likely reflected or used in DB queries)
	{`(^|_)(q|query|search|filter|find|keyword|term|s|text|lookup|where|sort|order|group_by|having|limit|offset|select|column|field|criteria)(_|$)`, []string{"sqli", "xss", "nosqli"}},

	// ID parameters (IDOR candidates)
	{`(^|_)(id|user_id|uid|account_id|profile_id|org_id|team_id|project_id|item_id|order_id|invoice_id|record_id|entity_id|object_id|resource_id)(_|$)`, []string{"idor", "accesscontrol", "sqli"}},

	// Authentication / session parameters
	{`(^|_)(token|auth|session|api_key|apikey|access_token|refresh_token|jwt|bearer|credential|password|passwd|pass|secret|pin|otp|mfa|totp)(_|$)`, []string{"brokenauth", "jwt", "sessionfixation"}},

	// Email parameters
	{`(^|_)(email|mail|e_mail|to|from|cc|bcc|recipient|sender|reply_to)(_|$)`, []string{"xss", "ssti", "cmdi"}},

	// XML / data format parameters
	{`(^|_)(xml|soap|wsdl|xsl|xslt|xpath|dtd|schema|data|payload|content|body|message|request|input)(_|$)`, []string{"xxe", "xmlinjection", "xpath", "deserialize"}},

	// Template / rendering parameters
	{`(^|_)(template|tpl|view|render|layout|format|lang|locale|theme|style|css)(_|$)`, []string{"ssti", "xss", "lfi"}},

	// Header / host parameters
	{`(^|_)(host|hostname|origin|referer|referrer|x_forwarded|forwarded|via|user_agent|ua)(_|$)`, []string{"hostheader", "ssrf", "hpp"}},

	// Numeric parameters that may overflow
	{`(^|_)(count|amount|quantity|size|length|width|height|price|cost|total|balance|age|year|month|day|page|num|number|index|position|rank)(_|$)`, []string{"sqli", "inputvalidation"}},

	// JSON / object parameters
	{`(^|_)(json|object|config|settings|options|preferences|metadata|attrs|attributes|properties|params|args|arguments)(_|$)`, []string{"prototype", "massassignment", "nosqli"}},

	// LDAP parameters
	{`(^|_)(dn|cn|ou|dc|ldap|base_dn|bind_dn|filter|scope)(_|$)`, []string{"ldap"}},

	// Regex / pattern parameters
	{`(^|_)(regex|regexp|pattern|match|expression|rule)(_|$)`, []string{"cmdi", "rce"}},

	// Callback / webhook parameters
	{`(^|_)(callback|webhook|hook|notify|notification|endpoint|ping|postback)(_|$)`, []string{"ssrf", "requestforgery"}},

	// Domain / IP parameters
	{`(^|_)(domain|ip|address|addr|server|proxy|upstream)(_|$)`, []string{"ssrf", "hostheader"}},
}

// MatchParamName returns the attack categories suggested by the parameter
// name. Returns nil if no rules match.
func MatchParamName(paramName string) []string {
	lower := strings.ToLower(paramName)
	// Normalize camelCase and kebab-case to underscore-separated.
	lower = normalizeName(lower)

	seen := make(map[string]bool)
	var categories []string

	for _, rule := range paramNameRules {
		re, err := regexcache.Get(rule.Pattern)
		if err != nil {
			continue
		}
		if re.MatchString(lower) {
			for _, cat := range rule.Categories {
				if !seen[cat] {
					seen[cat] = true
					categories = append(categories, cat)
				}
			}
		}
	}
	return categories
}

// normalizeName converts camelCase and kebab-case to underscore_separated
// for consistent matching.
func normalizeName(name string) string {
	var b strings.Builder
	b.Grow(len(name) + 4)
	for i, r := range name {
		if r == '-' {
			b.WriteByte('_')
			continue
		}
		// Insert underscore before uppercase letters (camelCase split).
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32) // toLower
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
