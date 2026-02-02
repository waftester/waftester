package tampers

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func init() {
	// Register all encoding tampers
	Register(&Base64Encode{BaseTamper: NewBaseTamper(
		"base64encode",
		"Base64 encodes the entire payload",
		CategoryEncoding, PriorityLowest,
	)})

	Register(&CharEncode{BaseTamper: NewBaseTamper(
		"charencode",
		"URL-encodes all characters in the payload",
		CategoryEncoding, PriorityLowest,
	)})

	Register(&CharDoubleEncode{BaseTamper: NewBaseTamper(
		"chardoubleencode",
		"Double URL-encodes all characters",
		CategoryEncoding, PriorityLow,
	)})

	Register(&CharUnicodeEncode{BaseTamper: NewBaseTamper(
		"charunicodeencode",
		"Unicode URL-encodes characters (%uXXXX) for ASP/ASP.NET",
		CategoryEncoding, PriorityNormal,
		"asp", "aspnet",
	)})

	Register(&CharUnicodeEscape{BaseTamper: NewBaseTamper(
		"charunicodeescape",
		"Unicode-escapes characters (\\uXXXX format)",
		CategoryEncoding, PriorityNormal,
	)})

	Register(&DecEntities{BaseTamper: NewBaseTamper(
		"decentities",
		"HTML decimal entity encodes all characters (&#NNN;)",
		CategoryEncoding, PriorityNormal,
	)})

	Register(&HexEntities{BaseTamper: NewBaseTamper(
		"hexentities",
		"HTML hex entity encodes all characters (&#xNN;)",
		CategoryEncoding, PriorityNormal,
	)})

	Register(&HTMLEncode{BaseTamper: NewBaseTamper(
		"htmlencode",
		"HTML encodes special characters",
		CategoryEncoding, PriorityLowest,
	)})

	Register(&OverlongUTF8{BaseTamper: NewBaseTamper(
		"overlongutf8",
		"Converts ASCII to 2-byte overlong UTF-8 encoding",
		CategoryEncoding, PriorityNormal,
	)})

	Register(&OverlongUTF8More{BaseTamper: NewBaseTamper(
		"overlongutf8more",
		"Converts ASCII to 3-byte overlong UTF-8 encoding",
		CategoryEncoding, PriorityNormal,
	)})

	Register(&Percentage{BaseTamper: NewBaseTamper(
		"percentage",
		"Adds percent sign before each character (ASP-specific)",
		CategoryEncoding, PriorityNormal,
		"asp",
	)})

	Register(&UnmagicQuotes{BaseTamper: NewBaseTamper(
		"unmagicquotes",
		"Replaces quotes with multibyte combo (%bf%27) to bypass magic_quotes",
		CategoryEncoding, PriorityHighest,
		"php", "mysql",
	)})
}

// Base64Encode base64 encodes the entire payload
type Base64Encode struct {
	BaseTamper
}

func (t *Base64Encode) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// CharEncode URL-encodes all characters
type CharEncode struct {
	BaseTamper
}

func (t *CharEncode) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, b := range []byte(payload) {
		result.WriteString(fmt.Sprintf("%%%02X", b))
	}
	return result.String()
}

// CharDoubleEncode double URL-encodes all characters
type CharDoubleEncode struct {
	BaseTamper
}

func (t *CharDoubleEncode) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, b := range []byte(payload) {
		// First encode: %XX, then encode the %: %25XX
		result.WriteString(fmt.Sprintf("%%25%02X", b))
	}
	return result.String()
}

// CharUnicodeEncode converts to Unicode URL encoding (%uXXXX) for ASP/ASP.NET
type CharUnicodeEncode struct {
	BaseTamper
}

func (t *CharUnicodeEncode) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		if r > 127 {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("%%u00%02X", r))
		}
	}
	return result.String()
}

// CharUnicodeEscape converts to Unicode escape format (\uXXXX)
type CharUnicodeEscape struct {
	BaseTamper
}

func (t *CharUnicodeEscape) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		if r > 127 {
			result.WriteString(fmt.Sprintf("\\u%04X", r))
		} else {
			result.WriteString(fmt.Sprintf("\\u00%02X", r))
		}
	}
	return result.String()
}

// DecEntities converts to HTML decimal entities (&#NNN;)
type DecEntities struct {
	BaseTamper
}

func (t *DecEntities) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		result.WriteString(fmt.Sprintf("&#%d;", r))
	}
	return result.String()
}

// HexEntities converts to HTML hex entities (&#xNN;)
type HexEntities struct {
	BaseTamper
}

func (t *HexEntities) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		result.WriteString(fmt.Sprintf("&#x%X;", r))
	}
	return result.String()
}

// HTMLEncode HTML encodes special characters
type HTMLEncode struct {
	BaseTamper
}

func (t *HTMLEncode) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#x27;",
	)
	return replacer.Replace(payload)
}

// OverlongUTF8 converts ASCII to 2-byte overlong UTF-8 encoding
// This exploits how some systems decode UTF-8 improperly
type OverlongUTF8 struct {
	BaseTamper
}

func (t *OverlongUTF8) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, b := range []byte(payload) {
		if b < 128 {
			// Convert ASCII to 2-byte overlong: 110000xx 10xxxxxx
			// For byte b: first byte = 0xC0 | (b >> 6), second = 0x80 | (b & 0x3F)
			result.WriteString(fmt.Sprintf("%%%02X%%%02X", 0xC0|(b>>6), 0x80|(b&0x3F)))
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// OverlongUTF8More converts ASCII to 3-byte overlong UTF-8 encoding
type OverlongUTF8More struct {
	BaseTamper
}

func (t *OverlongUTF8More) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, b := range []byte(payload) {
		if b < 128 {
			// Convert ASCII to 3-byte overlong: 1110xxxx 10xxxxxx 10xxxxxx
			result.WriteString(fmt.Sprintf("%%%02X%%%02X%%%02X", 0xE0, 0x80|(b>>6), 0x80|(b&0x3F)))
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// Percentage adds percent sign before each character (ASP-specific bypass)
type Percentage struct {
	BaseTamper
}

func (t *Percentage) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		if r == '%' || r == ' ' {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("%%%c", r))
		}
	}
	return result.String()
}

// UnmagicQuotes replaces quotes with multibyte combo to bypass magic_quotes_gpc
// Uses %bf%27 which becomes 뿧 in GBK encoding, bypassing addslashes()
type UnmagicQuotes struct {
	BaseTamper
}

func (t *UnmagicQuotes) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// First handle already URL-encoded quotes
	result := strings.ReplaceAll(payload, "%27", "%bf%27")
	// Then replace literal single quotes
	result = strings.ReplaceAll(result, "'", "%bf%27")
	return result
}
