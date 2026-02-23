package payloadgen

import (
	"math/rand"
	"net/url"
	"strings"
)

// Mutator transforms a payload into one or more variants.
type Mutator interface {
	// Mutate returns zero or more mutated variants of the input payload.
	Mutate(payload string) []string

	// Name returns a short identifier for the mutator.
	Name() string
}

// CaseMutator produces random-case variants of SQL/HTML keywords.
type CaseMutator struct {
	// MaxVariants limits the number of case variants produced per payload.
	MaxVariants int
}

func (m *CaseMutator) Name() string { return "case" }

func (m *CaseMutator) Mutate(payload string) []string {
	max := m.MaxVariants
	if max <= 0 {
		max = 3
	}
	results := make([]string, 0, max)
	for i := 0; i < max; i++ {
		var b strings.Builder
		b.Grow(len(payload))
		for _, ch := range payload {
			if rand.Intn(2) == 0 { //nolint:gosec // non-crypto randomness is fine for case mutation
				b.WriteRune(ch ^ 0x20) // toggle ASCII case
			} else {
				b.WriteRune(ch)
			}
		}
		variant := b.String()
		if variant != payload {
			results = append(results, variant)
		}
	}
	return results
}

// EncodingMutator applies various encoding schemes to bypass WAF pattern matching.
type EncodingMutator struct{}

func (m *EncodingMutator) Name() string { return "encoding" }

func (m *EncodingMutator) Mutate(payload string) []string {
	results := make([]string, 0, 5)

	// URL encoding
	urlEncoded := url.QueryEscape(payload)
	if urlEncoded != payload {
		results = append(results, urlEncoded)
	}

	// Double URL encoding
	doubleEncoded := url.QueryEscape(urlEncoded)
	if doubleEncoded != urlEncoded {
		results = append(results, doubleEncoded)
	}

	// Unicode encoding (replace ASCII with fullwidth equivalents)
	var unicodeBuf strings.Builder
	unicodeBuf.Grow(len(payload) * 3)
	for _, ch := range payload {
		if ch >= '!' && ch <= '~' {
			// Map ASCII printable to fullwidth Unicode (U+FF01..U+FF5E)
			unicodeBuf.WriteRune(ch - '!' + 0xFF01)
		} else {
			unicodeBuf.WriteRune(ch)
		}
	}
	unicodeVariant := unicodeBuf.String()
	if unicodeVariant != payload {
		results = append(results, unicodeVariant)
	}

	// HTML entity encoding for key characters
	htmlEncoded := htmlEntityEncode(payload)
	if htmlEncoded != payload {
		results = append(results, htmlEncoded)
	}

	// Hex encoding of key characters
	hexEncoded := hexEncode(payload)
	if hexEncoded != payload {
		results = append(results, hexEncoded)
	}

	return results
}

// CommentMutator inserts comments into payloads to break pattern matching.
type CommentMutator struct {
	// CommentStyle determines which comment syntax to use.
	// Supported: "sql" (default), "html", "both".
	CommentStyle string
}

func (m *CommentMutator) Name() string { return "comment" }

func (m *CommentMutator) Mutate(payload string) []string {
	style := m.CommentStyle
	if style == "" {
		style = "sql"
	}

	results := make([]string, 0, 3)

	if style == "sql" || style == "both" {
		// Insert SQL inline comments between keywords
		results = append(results, insertBetweenWords(payload, "/**/"))
		results = append(results, insertBetweenWords(payload, "/*!*/"))
	}

	if style == "html" || style == "both" {
		// Insert HTML comments
		results = append(results, insertBetweenWords(payload, "<!---->"))
	}

	return results
}

// WhitespaceMutator replaces spaces with alternative whitespace characters.
type WhitespaceMutator struct{}

func (m *WhitespaceMutator) Name() string { return "whitespace" }

func (m *WhitespaceMutator) Mutate(payload string) []string {
	alternatives := []string{
		"\t",     // tab
		"\n",     // newline
		"\r\n",   // CRLF
		"\u00a0", // non-breaking space
		"\u200b", // zero-width space
		"+",      // URL-encoded space
		"%09",    // URL tab
		"%0a",    // URL newline
	}

	results := make([]string, 0, len(alternatives))
	for _, alt := range alternatives {
		variant := strings.ReplaceAll(payload, " ", alt)
		if variant != payload {
			results = append(results, variant)
		}
	}
	return results
}

// ConcatenationMutator splits string literals using language-specific
// concatenation operators to evade pattern matching.
type ConcatenationMutator struct {
	// Language determines concatenation syntax: "sql" (default), "js", "php".
	Language string
}

func (m *ConcatenationMutator) Name() string { return "concatenation" }

func (m *ConcatenationMutator) Mutate(payload string) []string {
	lang := m.Language
	if lang == "" {
		lang = "sql"
	}

	results := make([]string, 0, 2)

	switch lang {
	case "sql":
		// Split SQL keywords with concatenation: UNION -> UN'+'ION
		for _, kw := range []string{"UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"} {
			if idx := strings.Index(strings.ToUpper(payload), kw); idx >= 0 {
				mid := len(kw) / 2
				concat := payload[:idx] + kw[:mid] + "'+'" + kw[mid:] + payload[idx+len(kw):]
				results = append(results, concat)
			}
		}
	case "js":
		// Split JavaScript strings: alert -> al"+"ert
		for _, fn := range []string{"alert", "confirm", "prompt", "eval", "fetch"} {
			if idx := strings.Index(payload, fn); idx >= 0 {
				mid := len(fn) / 2
				concat := payload[:idx] + fn[:mid] + "\"+\"" + fn[mid:] + payload[idx+len(fn):]
				results = append(results, concat)
			}
		}
	case "php":
		// PHP string concatenation with dots
		for _, fn := range []string{"system", "exec", "passthru", "shell_exec"} {
			if idx := strings.Index(payload, fn); idx >= 0 {
				mid := len(fn) / 2
				concat := payload[:idx] + "'" + fn[:mid] + "'.'" + fn[mid:] + "'" + payload[idx+len(fn):]
				results = append(results, concat)
			}
		}
	}

	return results
}

// ChainMutators applies mutators sequentially, up to maxDepth levels deep.
// Each level takes the output of the previous level as input.
// Deduplicates at each level to prevent exponential growth.
func ChainMutators(payload string, mutators []Mutator, maxDepth int) []string {
	if maxDepth <= 0 {
		maxDepth = 2
	}

	seen := map[string]bool{payload: true}
	current := []string{payload}

	for depth := 0; depth < maxDepth; depth++ {
		var next []string
		for _, p := range current {
			for _, m := range mutators {
				for _, variant := range m.Mutate(p) {
					if !seen[variant] {
						seen[variant] = true
						next = append(next, variant)
					}
				}
			}
		}
		if len(next) == 0 {
			break
		}
		current = next
	}

	// Return all unique variants (including originals from intermediate levels).
	result := make([]string, 0, len(seen))
	for s := range seen {
		if s != payload { // exclude the original
			result = append(result, s)
		}
	}
	return result
}

// insertBetweenWords inserts the separator between words in the payload.
func insertBetweenWords(payload, sep string) string {
	words := strings.Fields(payload)
	if len(words) <= 1 {
		return payload
	}
	return strings.Join(words, sep)
}

// htmlEntityEncode encodes angle brackets, quotes, and ampersands.
func htmlEntityEncode(s string) string {
	replacer := strings.NewReplacer(
		"<", "&#60;",
		">", "&#62;",
		"\"", "&#34;",
		"'", "&#39;",
		"&", "&#38;",
	)
	return replacer.Replace(s)
}

// hexEncode converts special characters to \xHH hex escapes.
func hexEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for _, ch := range s {
		switch {
		case ch == '<' || ch == '>' || ch == '\'' || ch == '"' || ch == '/' || ch == '\\':
			b.WriteString("\\x")
			b.WriteByte("0123456789abcdef"[byte(ch)>>4])
			b.WriteByte("0123456789abcdef"[byte(ch)&0x0f])
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}
