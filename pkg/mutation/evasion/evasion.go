// Package evasion provides WAF bypass evasion plugins.
// Integrates with the existing waf/evasion.go and adds additional techniques.
package evasion

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/waftester/waftester/pkg/mutation"
)

func init() {
	// Register all evasion mutators
	evasions := []mutation.Mutator{
		&CaseSwapEvasion{},
		&SQLCommentEvasion{},
		&WhitespaceAltEvasion{},
		&NullByteEvasion{},
		&ChunkedEvasion{},
		&HTTPParameterPollution{},
		&DoubleSubmitEvasion{},
		&ContentTypeMismatch{},
		&UnicodeNormalization{},
		&CommentWrapping{},
	}

	for _, e := range evasions {
		mutation.Register(e)
	}
}

// =============================================================================
// CASE MANIPULATION
// =============================================================================

type CaseSwapEvasion struct{}

func (e *CaseSwapEvasion) Name() string     { return "case_swap" }
func (e *CaseSwapEvasion) Category() string { return "evasion" }
func (e *CaseSwapEvasion) Description() string {
	return "Case manipulation to bypass case-sensitive WAF rules"
}

func (e *CaseSwapEvasion) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 4)

	// Alternating case: SeLeCt
	var alt strings.Builder
	for i, r := range payload {
		if i%2 == 0 {
			alt.WriteRune(unicode.ToUpper(r))
		} else {
			alt.WriteRune(unicode.ToLower(r))
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     alt.String(),
		MutatorName: e.Name() + "_alternate",
		Category:    e.Category(),
	})

	// Random-like pattern (every 3rd)
	var random strings.Builder
	for i, r := range payload {
		if (i+1)%3 == 0 {
			random.WriteString(strings.ToUpper(string(r)))
		} else {
			random.WriteString(strings.ToLower(string(r)))
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     random.String(),
		MutatorName: e.Name() + "_random",
		Category:    e.Category(),
	})

	// First letter upper
	words := strings.Fields(payload)
	var title strings.Builder
	for i, word := range words {
		if i > 0 {
			title.WriteString(" ")
		}
		if len(word) > 0 {
			title.WriteString(strings.ToUpper(string(word[0])))
			title.WriteString(strings.ToLower(word[1:]))
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     title.String(),
		MutatorName: e.Name() + "_title",
		Category:    e.Category(),
	})

	// Inverse
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ToUpper(payload),
		MutatorName: e.Name() + "_upper",
		Category:    e.Category(),
	})

	return results
}

// =============================================================================
// SQL COMMENT INJECTION
// =============================================================================

type SQLCommentEvasion struct{}

func (e *SQLCommentEvasion) Name() string     { return "sql_comment" }
func (e *SQLCommentEvasion) Category() string { return "evasion" }
func (e *SQLCommentEvasion) Description() string {
	return "SQL comment injection for keyword obfuscation"
}

func (e *SQLCommentEvasion) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 6)

	// Inline comments between every space: SELECT/**/FROM
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "/**/"),
		MutatorName: e.Name() + "_inline",
		Category:    e.Category(),
	})

	// MySQL version comments: /*!50000 SELECT */
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     "/*!50000 " + payload + " */",
		MutatorName: e.Name() + "_mysql_version",
		Category:    e.Category(),
	})

	// Nested style
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "/**_**/"),
		MutatorName: e.Name() + "_nested",
		Category:    e.Category(),
	})

	// Replace -- with #
	if strings.Contains(payload, "--") {
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     strings.ReplaceAll(payload, "--", "#"),
			MutatorName: e.Name() + "_hash",
			Category:    e.Category(),
		})
	}

	// Add comment at end
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     payload + " -- -",
		MutatorName: e.Name() + "_trailing",
		Category:    e.Category(),
	})

	// Multiline comment bypass
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "/*\n*/"),
		MutatorName: e.Name() + "_multiline",
		Category:    e.Category(),
	})

	return results
}

// =============================================================================
// WHITESPACE ALTERNATIVES
// =============================================================================

type WhitespaceAltEvasion struct{}

func (e *WhitespaceAltEvasion) Name() string        { return "whitespace_alt" }
func (e *WhitespaceAltEvasion) Category() string    { return "evasion" }
func (e *WhitespaceAltEvasion) Description() string { return "Alternative whitespace characters" }

func (e *WhitespaceAltEvasion) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 8)

	// Tab
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "\t"),
		MutatorName: e.Name() + "_tab",
		Category:    e.Category(),
	})

	// Newline
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "\n"),
		MutatorName: e.Name() + "_newline",
		Category:    e.Category(),
	})

	// Carriage return + newline
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "\r\n"),
		MutatorName: e.Name() + "_crlf",
		Category:    e.Category(),
	})

	// Vertical tab
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "\v"),
		MutatorName: e.Name() + "_vtab",
		Category:    e.Category(),
	})

	// Form feed
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "\f"),
		MutatorName: e.Name() + "_formfeed",
		Category:    e.Category(),
	})

	// Multiple spaces
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "  "),
		MutatorName: e.Name() + "_double",
		Category:    e.Category(),
	})

	// URL encoded space variations
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "%20"),
		MutatorName: e.Name() + "_percent20",
		Category:    e.Category(),
	})

	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "+"),
		MutatorName: e.Name() + "_plus",
		Category:    e.Category(),
	})

	return results
}

// =============================================================================
// NULL BYTE INJECTION
// =============================================================================

type NullByteEvasion struct{}

func (e *NullByteEvasion) Name() string     { return "null_byte" }
func (e *NullByteEvasion) Category() string { return "evasion" }
func (e *NullByteEvasion) Description() string {
	return "Null byte injection for string termination bypass"
}

func (e *NullByteEvasion) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 5)

	// Prepend null
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     "%00" + payload,
		MutatorName: e.Name() + "_prepend",
		Category:    e.Category(),
	})

	// Append null
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     payload + "%00",
		MutatorName: e.Name() + "_append",
		Category:    e.Category(),
	})

	// Insert in middle
	mid := len(payload) / 2
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     payload[:mid] + "%00" + payload[mid:],
		MutatorName: e.Name() + "_middle",
		Category:    e.Category(),
	})

	// Unicode null
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     payload + "\u0000",
		MutatorName: e.Name() + "_unicode",
		Category:    e.Category(),
	})

	// Between every word
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     strings.ReplaceAll(payload, " ", "%00 "),
		MutatorName: e.Name() + "_spaces",
		Category:    e.Category(),
	})

	return results
}

// =============================================================================
// CHUNKED TRANSFER ENCODING
// =============================================================================

type ChunkedEvasion struct{}

func (e *ChunkedEvasion) Name() string        { return "chunked" }
func (e *ChunkedEvasion) Category() string    { return "evasion" }
func (e *ChunkedEvasion) Description() string { return "Chunked transfer encoding variations" }

func (e *ChunkedEvasion) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 3)

	// Single character chunks
	var singleChunk strings.Builder
	for _, r := range payload {
		char := string(r)
		singleChunk.WriteString(fmt.Sprintf("1\r\n%s\r\n", char))
	}
	singleChunk.WriteString("0\r\n\r\n")
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     singleChunk.String(),
		MutatorName: e.Name() + "_single_char",
		Category:    e.Category(),
	})

	// Two-char chunks
	var twoChunk strings.Builder
	for i := 0; i < len(payload); i += 2 {
		end := i + 2
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[i:end]
		twoChunk.WriteString(fmt.Sprintf("%x\r\n%s\r\n", len(chunk), chunk))
	}
	twoChunk.WriteString("0\r\n\r\n")
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     twoChunk.String(),
		MutatorName: e.Name() + "_two_char",
		Category:    e.Category(),
	})

	// With chunk extensions
	var extChunk strings.Builder
	extChunk.WriteString(fmt.Sprintf("%x;ext=value\r\n%s\r\n0\r\n\r\n", len(payload), payload))
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     extChunk.String(),
		MutatorName: e.Name() + "_extension",
		Category:    e.Category(),
	})

	return results
}

// =============================================================================
// HTTP PARAMETER POLLUTION
// =============================================================================

type HTTPParameterPollution struct{}

func (e *HTTPParameterPollution) Name() string     { return "hpp" }
func (e *HTTPParameterPollution) Category() string { return "evasion" }
func (e *HTTPParameterPollution) Description() string {
	return "HTTP Parameter Pollution for WAF bypass"
}

func (e *HTTPParameterPollution) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 6)

	escaped := url.QueryEscape(payload)

	// Duplicate parameter - first value
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("id=%s&id=safe", escaped),
		MutatorName: e.Name() + "_first",
		Category:    e.Category(),
	})

	// Duplicate parameter - second value
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("id=safe&id=%s", escaped),
		MutatorName: e.Name() + "_second",
		Category:    e.Category(),
	})

	// Triple parameter
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("id=safe&id=%s&id=safe2", escaped),
		MutatorName: e.Name() + "_triple",
		Category:    e.Category(),
	})

	// PHP array notation
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("id[]=safe&id[]=%s", escaped),
		MutatorName: e.Name() + "_array",
		Category:    e.Category(),
	})

	// Semicolon separator (some servers)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("id=safe;id=%s", escaped),
		MutatorName: e.Name() + "_semicolon",
		Category:    e.Category(),
	})

	// Split payload across parameters
	if len(payload) > 2 {
		mid := len(payload) / 2
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     fmt.Sprintf("id=%s&id=%s", url.QueryEscape(payload[:mid]), url.QueryEscape(payload[mid:])),
			MutatorName: e.Name() + "_split",
			Category:    e.Category(),
		})
	}

	return results
}

// =============================================================================
// DOUBLE SUBMIT
// =============================================================================

type DoubleSubmitEvasion struct{}

func (e *DoubleSubmitEvasion) Name() string        { return "double_submit" }
func (e *DoubleSubmitEvasion) Category() string    { return "evasion" }
func (e *DoubleSubmitEvasion) Description() string { return "Submit payload in multiple locations" }

func (e *DoubleSubmitEvasion) Mutate(payload string) []mutation.MutatedPayload {
	escaped := url.QueryEscape(payload)

	return []mutation.MutatedPayload{
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("GET_id=%s|POST_id=%s", escaped, escaped),
			MutatorName: e.Name() + "_get_post",
			Category:    e.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("QUERY_id=%s|COOKIE_id=%s", escaped, escaped),
			MutatorName: e.Name() + "_query_cookie",
			Category:    e.Category(),
		},
	}
}

// =============================================================================
// CONTENT TYPE MISMATCH
// =============================================================================

type ContentTypeMismatch struct{}

func (e *ContentTypeMismatch) Name() string     { return "content_type_mismatch" }
func (e *ContentTypeMismatch) Category() string { return "evasion" }
func (e *ContentTypeMismatch) Description() string {
	return "Send body with mismatched Content-Type header"
}

func (e *ContentTypeMismatch) Mutate(payload string) []mutation.MutatedPayload {
	return []mutation.MutatedPayload{
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("Content-Type: text/plain|Body: %s", payload),
			MutatorName: e.Name() + "_text_plain",
			Category:    e.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("Content-Type: application/octet-stream|Body: %s", payload),
			MutatorName: e.Name() + "_octet",
			Category:    e.Category(),
		},
		{
			Original:    payload,
			Mutated:     fmt.Sprintf("Content-Type: image/gif|Body: %s", payload),
			MutatorName: e.Name() + "_image",
			Category:    e.Category(),
		},
	}
}

// =============================================================================
// UNICODE NORMALIZATION
// =============================================================================

type UnicodeNormalization struct{}

func (e *UnicodeNormalization) Name() string     { return "unicode_normalize" }
func (e *UnicodeNormalization) Category() string { return "evasion" }
func (e *UnicodeNormalization) Description() string {
	return "Unicode normalization bypass using lookalike chars"
}

// Character substitutions for Unicode normalization attacks
var unicodeSubstitutions = map[rune][]string{
	'<':  {"\uFF1C", "\u003C", "\u2039", "\u276E"}, // Fullwidth, less-than, single guillemet, heavy left-pointing angle
	'>':  {"\uFF1E", "\u003E", "\u203A", "\u276F"}, // Fullwidth, greater-than, single guillemet, heavy right-pointing angle
	'"':  {"\uFF02", "\u201C", "\u201D", "\u2033"}, // Fullwidth, smart quotes, double prime
	'\'': {"\uFF07", "\u2018", "\u2019", "\u02BC"}, // Fullwidth, smart quotes, modifier apostrophe
	'/':  {"\uFF0F", "\u2215", "\u2044"},           // Fullwidth, division slash, fraction slash
	'\\': {"\uFF3C", "\u2216"},                     // Fullwidth, set minus
	'=':  {"\uFF1D", "\u2261", "\u2A75"},           // Fullwidth, identical to, two consecutive equals
	';':  {"\uFF1B", "\u037E"},                     // Fullwidth, Greek question mark (looks like ;)
	'(':  {"\uFF08", "\u207D", "\u208D"},           // Fullwidth, superscript, subscript
	')':  {"\uFF09", "\u207E", "\u208E"},           // Fullwidth, superscript, subscript
	'a':  {"а", "\u0430"},                          // Cyrillic а
	'e':  {"е", "\u0435"},                          // Cyrillic е
	'o':  {"о", "\u043E"},                          // Cyrillic о
	'c':  {"с", "\u0441"},                          // Cyrillic с
}

func (e *UnicodeNormalization) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 3)

	// Fullwidth variant
	var fullwidth strings.Builder
	for _, r := range payload {
		if subs, ok := unicodeSubstitutions[r]; ok && len(subs) > 0 {
			fullwidth.WriteString(subs[0])
		} else if r >= '!' && r <= '~' {
			// Convert ASCII to fullwidth
			fullwidth.WriteRune(r - '!' + '\uFF01')
		} else {
			fullwidth.WriteRune(r)
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fullwidth.String(),
		MutatorName: e.Name() + "_fullwidth",
		Category:    e.Category(),
	})

	// Mixed substitution
	var mixed strings.Builder
	subIndex := 0
	for _, r := range payload {
		if subs, ok := unicodeSubstitutions[r]; ok && len(subs) > 0 {
			mixed.WriteString(subs[subIndex%len(subs)])
			subIndex++
		} else {
			mixed.WriteRune(r)
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     mixed.String(),
		MutatorName: e.Name() + "_mixed",
		Category:    e.Category(),
	})

	return results
}

// =============================================================================
// COMMENT WRAPPING (XSS/HTML specific)
// =============================================================================

type CommentWrapping struct{}

func (e *CommentWrapping) Name() string        { return "comment_wrap" }
func (e *CommentWrapping) Category() string    { return "evasion" }
func (e *CommentWrapping) Description() string { return "Wrap payload in HTML/JS comments" }

func (e *CommentWrapping) Mutate(payload string) []mutation.MutatedPayload {
	return []mutation.MutatedPayload{
		{
			Original:    payload,
			Mutated:     "<!--" + payload + "-->",
			MutatorName: e.Name() + "_html",
			Category:    e.Category(),
		},
		{
			Original:    payload,
			Mutated:     "/*" + payload + "*/",
			MutatorName: e.Name() + "_js",
			Category:    e.Category(),
		},
		{
			Original:    payload,
			Mutated:     "//" + payload + "\n",
			MutatorName: e.Name() + "_js_line",
			Category:    e.Category(),
		},
		{
			Original:    payload,
			Mutated:     "<!--//-->" + payload,
			MutatorName: e.Name() + "_html_js",
			Category:    e.Category(),
		},
	}
}
