// Package encoder provides encoding mutation plugins for WAF bypass testing.
// Covers all encoding techniques from PayloadsAllTheThings, SecLists, and nuclei.
package encoder

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"unicode/utf16"

	"github.com/waftester/waftester/internal/hexutil"
	"github.com/waftester/waftester/pkg/mutation"
)

func init() {
	// Register all encoders with the default registry
	encoders := []mutation.Mutator{
		&RawEncoder{},
		&URLEncoder{},
		&DoubleURLEncoder{},
		&TripleURLEncoder{},
		&HTMLDecimalEncoder{},
		&HTMLHexEncoder{},
		&HTMLNamedEncoder{},
		&UnicodeEncoder{},
		&UTF7Encoder{},
		&UTF16LEEncoder{},
		&UTF16BEEncoder{},
		&OverlongUTF8Encoder{},
		&WideGBKEncoder{},
		&WideSJISEncoder{},
		&Base64Encoder{},
		&HexEncoder{},
		&OctalEncoder{},
		&MixedEncoder{},
	}

	for _, e := range encoders {
		mutation.Register(e)
	}
}

// =============================================================================
// RAW ENCODER (no transformation)
// =============================================================================

type RawEncoder struct{}

func (e *RawEncoder) Name() string        { return "raw" }
func (e *RawEncoder) Category() string    { return "encoder" }
func (e *RawEncoder) Description() string { return "No encoding - original payload" }

func (e *RawEncoder) Mutate(payload string) []mutation.MutatedPayload {
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     payload,
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

// =============================================================================
// URL ENCODING FAMILY
// =============================================================================

type URLEncoder struct{}

func (e *URLEncoder) Name() string        { return "url" }
func (e *URLEncoder) Category() string    { return "encoder" }
func (e *URLEncoder) Description() string { return "Standard URL percent-encoding" }

func (e *URLEncoder) Mutate(payload string) []mutation.MutatedPayload {
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     url.QueryEscape(payload),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type DoubleURLEncoder struct{}

func (e *DoubleURLEncoder) Name() string     { return "double_url" }
func (e *DoubleURLEncoder) Category() string { return "encoder" }
func (e *DoubleURLEncoder) Description() string {
	return "Double URL encoding - encodes the percent signs"
}

func (e *DoubleURLEncoder) Mutate(payload string) []mutation.MutatedPayload {
	first := url.QueryEscape(payload)
	second := url.QueryEscape(first)
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     second,
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type TripleURLEncoder struct{}

func (e *TripleURLEncoder) Name() string        { return "triple_url" }
func (e *TripleURLEncoder) Category() string    { return "encoder" }
func (e *TripleURLEncoder) Description() string { return "Triple URL encoding for deep bypass" }

func (e *TripleURLEncoder) Mutate(payload string) []mutation.MutatedPayload {
	first := url.QueryEscape(payload)
	second := url.QueryEscape(first)
	third := url.QueryEscape(second)
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     third,
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

// =============================================================================
// HTML ENTITY ENCODING
// =============================================================================

type HTMLDecimalEncoder struct{}

func (e *HTMLDecimalEncoder) Name() string        { return "html_decimal" }
func (e *HTMLDecimalEncoder) Category() string    { return "encoder" }
func (e *HTMLDecimalEncoder) Description() string { return "HTML decimal entities &#60; for <" }

func (e *HTMLDecimalEncoder) Mutate(payload string) []mutation.MutatedPayload {
	var result strings.Builder
	result.Grow(len(payload) * 6) // &#NN; = ~6 chars per rune
	for _, r := range payload {
		// Encode all printable ASCII as decimal entities
		if r >= 32 && r < 127 {
			hexutil.WriteDecEntity(&result, r)
		} else {
			result.WriteRune(r)
		}
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     result.String(),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type HTMLHexEncoder struct{}

func (e *HTMLHexEncoder) Name() string        { return "html_hex" }
func (e *HTMLHexEncoder) Category() string    { return "encoder" }
func (e *HTMLHexEncoder) Description() string { return "HTML hex entities &#x3c; for <" }

func (e *HTMLHexEncoder) Mutate(payload string) []mutation.MutatedPayload {
	var result strings.Builder
	result.Grow(len(payload) * 7) // &#xXX; = 7 chars per rune
	for _, r := range payload {
		if r >= 32 && r < 127 {
			hexutil.WriteHexEntity(&result, r)
		} else {
			result.WriteRune(r)
		}
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     result.String(),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type HTMLNamedEncoder struct{}

func (e *HTMLNamedEncoder) Name() string        { return "html_named" }
func (e *HTMLNamedEncoder) Category() string    { return "encoder" }
func (e *HTMLNamedEncoder) Description() string { return "HTML named entities &lt; for <" }

var htmlNamedEntities = map[rune]string{
	'<':  "&lt;",
	'>':  "&gt;",
	'"':  "&quot;",
	'\'': "&#39;",
	'&':  "&amp;",
	' ':  "&nbsp;",
}

func (e *HTMLNamedEncoder) Mutate(payload string) []mutation.MutatedPayload {
	var result strings.Builder
	for _, r := range payload {
		if entity, ok := htmlNamedEntities[r]; ok {
			result.WriteString(entity)
		} else {
			result.WriteRune(r)
		}
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     result.String(),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

// =============================================================================
// UNICODE ENCODING
// =============================================================================

type UnicodeEncoder struct{}

func (e *UnicodeEncoder) Name() string        { return "unicode" }
func (e *UnicodeEncoder) Category() string    { return "encoder" }
func (e *UnicodeEncoder) Description() string { return "Unicode escape sequences \\u003c for <" }

func (e *UnicodeEncoder) Mutate(payload string) []mutation.MutatedPayload {
	var result strings.Builder
	result.Grow(len(payload) * 6) // \uXXXX = 6 chars per rune
	for _, r := range payload {
		hexutil.WriteUnicodeEscape(&result, r)
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     result.String(),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type UTF7Encoder struct{}

func (e *UTF7Encoder) Name() string        { return "utf7" }
func (e *UTF7Encoder) Category() string    { return "encoder" }
func (e *UTF7Encoder) Description() string { return "UTF-7 encoding +ADw- for <" }

func (e *UTF7Encoder) Mutate(payload string) []mutation.MutatedPayload {
	var result strings.Builder
	for _, r := range payload {
		if r >= 32 && r < 127 && r != '+' && r != '-' {
			// Direct characters (simplified)
			result.WriteRune(r)
		} else {
			// Encode as UTF-7 modified base64
			encoded := base64.StdEncoding.EncodeToString([]byte(string(r)))
			// Trim padding
			encoded = strings.TrimRight(encoded, "=")
			result.WriteString("+" + encoded + "-")
		}
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     result.String(),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type UTF16LEEncoder struct{}

func (e *UTF16LEEncoder) Name() string        { return "utf16le" }
func (e *UTF16LEEncoder) Category() string    { return "encoder" }
func (e *UTF16LEEncoder) Description() string { return "UTF-16 Little Endian encoding" }

func (e *UTF16LEEncoder) Mutate(payload string) []mutation.MutatedPayload {
	encoded := utf16.Encode([]rune(payload))
	bytes := make([]byte, len(encoded)*2)
	for i, c := range encoded {
		bytes[i*2] = byte(c)
		bytes[i*2+1] = byte(c >> 8)
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     hex.EncodeToString(bytes),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type UTF16BEEncoder struct{}

func (e *UTF16BEEncoder) Name() string        { return "utf16be" }
func (e *UTF16BEEncoder) Category() string    { return "encoder" }
func (e *UTF16BEEncoder) Description() string { return "UTF-16 Big Endian encoding" }

func (e *UTF16BEEncoder) Mutate(payload string) []mutation.MutatedPayload {
	encoded := utf16.Encode([]rune(payload))
	bytes := make([]byte, len(encoded)*2)
	for i, c := range encoded {
		bytes[i*2] = byte(c >> 8)
		bytes[i*2+1] = byte(c)
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     hex.EncodeToString(bytes),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

// =============================================================================
// OVERLONG UTF-8 ENCODING (Critical WAF bypass!)
// =============================================================================

type OverlongUTF8Encoder struct{}

func (e *OverlongUTF8Encoder) Name() string     { return "overlong_utf8" }
func (e *OverlongUTF8Encoder) Category() string { return "encoder" }
func (e *OverlongUTF8Encoder) Description() string {
	return "Overlong UTF-8 encoding - uses more bytes than necessary (e.g., %c0%bc for <)"
}

func (e *OverlongUTF8Encoder) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 2)

	// 2-byte overlong variant
	var result2 strings.Builder
	result2.Grow(len(payload) * 6) // %XX%XX = 6 chars per byte
	for _, b := range []byte(payload) {
		if b < 128 {
			hexutil.WriteOverlong2Byte(&result2, b)
		} else {
			result2.WriteByte(b)
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     result2.String(),
		MutatorName: e.Name() + "_2byte",
		Category:    e.Category(),
	})

	// 3-byte overlong variant
	var result3 strings.Builder
	result3.Grow(len(payload) * 9) // %XX%XX%XX = 9 chars per byte
	for _, b := range []byte(payload) {
		if b < 128 {
			hexutil.WriteOverlong3Byte(&result3, b)
		} else {
			result3.WriteByte(b)
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     result3.String(),
		MutatorName: e.Name() + "_3byte",
		Category:    e.Category(),
	})

	return results
}

// =============================================================================
// WIDE BYTE ENCODING (GBK/Shift-JIS for SQL injection bypass)
// =============================================================================

type WideGBKEncoder struct{}

func (e *WideGBKEncoder) Name() string     { return "wide_gbk" }
func (e *WideGBKEncoder) Category() string { return "encoder" }
func (e *WideGBKEncoder) Description() string {
	return "GBK wide-byte injection (%bf%27 = valid GBK + quote)"
}

func (e *WideGBKEncoder) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 3)

	// Classic %bf%27 - the %bf byte combined with the backslash (0x5c) used to
	// escape quotes forms a valid GBK character, leaving the quote unescaped
	gbkPayload := strings.ReplaceAll(payload, "'", "%bf%27")
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     gbkPayload,
		MutatorName: e.Name() + "_bf27",
		Category:    e.Category(),
	})

	// %bf%5c variant (wide byte + backslash)
	gbkPayload2 := strings.ReplaceAll(payload, "'", "%bf%5c%27")
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     gbkPayload2,
		MutatorName: e.Name() + "_bf5c",
		Category:    e.Category(),
	})

	// %e5%5c variant (another valid GBK lead byte)
	gbkPayload3 := strings.ReplaceAll(payload, "'", "%e5%5c%27")
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     gbkPayload3,
		MutatorName: e.Name() + "_e55c",
		Category:    e.Category(),
	})

	return results
}

type WideSJISEncoder struct{}

func (e *WideSJISEncoder) Name() string     { return "wide_sjis" }
func (e *WideSJISEncoder) Category() string { return "encoder" }
func (e *WideSJISEncoder) Description() string {
	return "Shift-JIS wide-byte injection for Japanese systems"
}

func (e *WideSJISEncoder) Mutate(payload string) []mutation.MutatedPayload {
	// Shift-JIS uses 0x81-0x9F and 0xE0-0xFC as lead bytes
	sjisPayload := strings.ReplaceAll(payload, "'", "%81%27")
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     sjisPayload,
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

// =============================================================================
// OTHER ENCODINGS
// =============================================================================

type Base64Encoder struct{}

func (e *Base64Encoder) Name() string        { return "base64" }
func (e *Base64Encoder) Category() string    { return "encoder" }
func (e *Base64Encoder) Description() string { return "Standard Base64 encoding" }

func (e *Base64Encoder) Mutate(payload string) []mutation.MutatedPayload {
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     base64.StdEncoding.EncodeToString([]byte(payload)),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type HexEncoder struct{}

func (e *HexEncoder) Name() string        { return "hex" }
func (e *HexEncoder) Category() string    { return "encoder" }
func (e *HexEncoder) Description() string { return "Hex encoding with \\x prefix" }

func (e *HexEncoder) Mutate(payload string) []mutation.MutatedPayload {
	var result strings.Builder
	result.Grow(len(payload) * 4) // \xXX = 4 chars per byte
	for _, b := range []byte(payload) {
		hexutil.WriteHexEscape(&result, b)
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     result.String(),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

type OctalEncoder struct{}

func (e *OctalEncoder) Name() string        { return "octal" }
func (e *OctalEncoder) Category() string    { return "encoder" }
func (e *OctalEncoder) Description() string { return "Octal encoding \\074 for <" }

func (e *OctalEncoder) Mutate(payload string) []mutation.MutatedPayload {
	var result strings.Builder
	result.Grow(len(payload) * 4) // \\OOO = 4 chars per byte
	for _, b := range []byte(payload) {
		hexutil.WriteOctalEscape(&result, b)
	}
	return []mutation.MutatedPayload{{
		Original:    payload,
		Mutated:     result.String(),
		MutatorName: e.Name(),
		Category:    e.Category(),
	}}
}

// =============================================================================
// MIXED/CHAINED ENCODING
// =============================================================================

type MixedEncoder struct{}

func (e *MixedEncoder) Name() string     { return "mixed" }
func (e *MixedEncoder) Category() string { return "encoder" }
func (e *MixedEncoder) Description() string {
	return "Mixed encoding - different chars use different encodings"
}

func (e *MixedEncoder) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 3)

	// Variant 1: Alternate between URL and raw
	var mixed1 strings.Builder
	for i, r := range payload {
		if i%2 == 0 {
			mixed1.WriteString(url.QueryEscape(string(r)))
		} else {
			mixed1.WriteRune(r)
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     mixed1.String(),
		MutatorName: e.Name() + "_alternate",
		Category:    e.Category(),
	})

	// Variant 2: URL encode only special chars
	var mixed2 strings.Builder
	specialChars := "<>\"'&;|`$(){}[]\\!@#%^*=+"
	for _, r := range payload {
		if strings.ContainsRune(specialChars, r) {
			mixed2.WriteString(url.QueryEscape(string(r)))
		} else {
			mixed2.WriteRune(r)
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     mixed2.String(),
		MutatorName: e.Name() + "_special_only",
		Category:    e.Category(),
	})

	// Variant 3: HTML entity for < > and URL for rest
	var mixed3 strings.Builder
	for _, r := range payload {
		switch r {
		case '<':
			mixed3.WriteString("&lt;")
		case '>':
			mixed3.WriteString("&gt;")
		case '"':
			mixed3.WriteString(url.QueryEscape(string(r)))
		case '\'':
			mixed3.WriteString(url.QueryEscape(string(r)))
		default:
			mixed3.WriteRune(r)
		}
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     mixed3.String(),
		MutatorName: e.Name() + "_html_url",
		Category:    e.Category(),
	})

	return results
}
