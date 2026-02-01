package encoding

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strings"

	"github.com/waftester/waftester/pkg/bufpool"
)

func init() {
	// Register all encoders
	Register(&PlainEncoder{})
	Register(&URLEncoder{})
	Register(&DoubleURLEncoder{})
	Register(&TripleURLEncoder{})
	Register(&Base64Encoder{})
	Register(&Base64FlatEncoder{})
	Register(&Base64URLEncoder{})
	Register(&UnicodeEncoder{})
	Register(&HTMLEntityEncoder{})
	Register(&HTMLNumericEncoder{})
	Register(&HTMLHexEncoder{})
	Register(&JSUnicodeEncoder{})
	Register(&JSHexEncoder{})
	Register(&UTF7Encoder{})
	Register(&XMLEntityEncoder{})
	Register(&HexEncoder{})
	Register(&OctalEncoder{})
	Register(&BinaryEncoder{})
}

// PlainEncoder returns payload unchanged
type PlainEncoder struct{}

func (e *PlainEncoder) Name() string                    { return "plain" }
func (e *PlainEncoder) Encode(p string) (string, error) { return p, nil }
func (e *PlainEncoder) Decode(p string) (string, error) { return p, nil }

// URLEncoder applies percent-encoding
type URLEncoder struct{}

func (e *URLEncoder) Name() string { return "url" }
func (e *URLEncoder) Encode(payload string) (string, error) {
	return url.QueryEscape(payload), nil
}
func (e *URLEncoder) Decode(encoded string) (string, error) {
	return url.QueryUnescape(encoded)
}

// DoubleURLEncoder applies URL encoding twice
type DoubleURLEncoder struct{}

func (e *DoubleURLEncoder) Name() string { return "double-url" }
func (e *DoubleURLEncoder) Encode(payload string) (string, error) {
	first := url.QueryEscape(payload)
	return url.QueryEscape(first), nil
}
func (e *DoubleURLEncoder) Decode(encoded string) (string, error) {
	first, err := url.QueryUnescape(encoded)
	if err != nil {
		return "", err
	}
	return url.QueryUnescape(first)
}

// TripleURLEncoder applies URL encoding three times
type TripleURLEncoder struct{}

func (e *TripleURLEncoder) Name() string { return "triple-url" }
func (e *TripleURLEncoder) Encode(payload string) (string, error) {
	first := url.QueryEscape(payload)
	second := url.QueryEscape(first)
	return url.QueryEscape(second), nil
}
func (e *TripleURLEncoder) Decode(encoded string) (string, error) {
	first, err := url.QueryUnescape(encoded)
	if err != nil {
		return "", err
	}
	second, err := url.QueryUnescape(first)
	if err != nil {
		return "", err
	}
	return url.QueryUnescape(second)
}

// Base64Encoder applies standard base64 encoding
type Base64Encoder struct{}

func (e *Base64Encoder) Name() string { return "base64" }
func (e *Base64Encoder) Encode(payload string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(payload)), nil
}
func (e *Base64Encoder) Decode(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	return string(decoded), err
}

// Base64FlatEncoder applies base64 without padding
type Base64FlatEncoder struct{}

func (e *Base64FlatEncoder) Name() string { return "base64flat" }
func (e *Base64FlatEncoder) Encode(payload string) (string, error) {
	return base64.RawStdEncoding.EncodeToString([]byte(payload)), nil
}
func (e *Base64FlatEncoder) Decode(encoded string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	return string(decoded), err
}

// Base64URLEncoder applies URL-safe base64 encoding
type Base64URLEncoder struct{}

func (e *Base64URLEncoder) Name() string { return "base64url" }
func (e *Base64URLEncoder) Encode(payload string) (string, error) {
	return base64.URLEncoding.EncodeToString([]byte(payload)), nil
}
func (e *Base64URLEncoder) Decode(encoded string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	return string(decoded), err
}

// UnicodeEncoder applies \uXXXX encoding
type UnicodeEncoder struct{}

func (e *UnicodeEncoder) Name() string { return "unicode" }
func (e *UnicodeEncoder) Encode(payload string) (string, error) {
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for _, r := range payload {
		if r < 128 && r > 31 && r != '<' && r != '>' && r != '"' && r != '\'' && r != '&' {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		}
	}
	return result.String(), nil
}
func (e *UnicodeEncoder) Decode(encoded string) (string, error) {
	result := encoded
	for i := 0; i < len(result)-5; i++ {
		if result[i] == '\\' && result[i+1] == 'u' {
			var r rune
			fmt.Sscanf(result[i+2:i+6], "%04x", &r)
			result = result[:i] + string(r) + result[i+6:]
		}
	}
	return result, nil
}

// HTMLEntityEncoder uses named HTML entities
type HTMLEntityEncoder struct{}

func (e *HTMLEntityEncoder) Name() string { return "html-entity" }
func (e *HTMLEntityEncoder) Encode(payload string) (string, error) {
	return html.EscapeString(payload), nil
}
func (e *HTMLEntityEncoder) Decode(encoded string) (string, error) {
	return html.UnescapeString(encoded), nil
}

// HTMLNumericEncoder uses &#XX; numeric entities
type HTMLNumericEncoder struct{}

func (e *HTMLNumericEncoder) Name() string { return "html-numeric" }
func (e *HTMLNumericEncoder) Encode(payload string) (string, error) {
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for _, r := range payload {
		if r == '<' || r == '>' || r == '"' || r == '\'' || r == '&' {
			result.WriteString(fmt.Sprintf("&#%d;", r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}
func (e *HTMLNumericEncoder) Decode(encoded string) (string, error) {
	return html.UnescapeString(encoded), nil
}

// HTMLHexEncoder uses &#xXX; hex entities
type HTMLHexEncoder struct{}

func (e *HTMLHexEncoder) Name() string { return "html-hex" }
func (e *HTMLHexEncoder) Encode(payload string) (string, error) {
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for _, r := range payload {
		if r == '<' || r == '>' || r == '"' || r == '\'' || r == '&' {
			result.WriteString(fmt.Sprintf("&#x%x;", r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}
func (e *HTMLHexEncoder) Decode(encoded string) (string, error) {
	return html.UnescapeString(encoded), nil
}

// JSUnicodeEncoder uses \xXX JavaScript encoding
type JSUnicodeEncoder struct{}

func (e *JSUnicodeEncoder) Name() string { return "js-unicode" }
func (e *JSUnicodeEncoder) Encode(payload string) (string, error) {
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for _, r := range payload {
		if r < 128 && r > 31 && r != '<' && r != '>' && r != '"' && r != '\'' {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}
	return result.String(), nil
}
func (e *JSUnicodeEncoder) Decode(encoded string) (string, error) {
	result := encoded
	for i := 0; i < len(result)-3; i++ {
		if result[i] == '\\' && result[i+1] == 'x' {
			var b byte
			fmt.Sscanf(result[i+2:i+4], "%02x", &b)
			result = result[:i] + string(b) + result[i+4:]
		}
	}
	return result, nil
}

// JSHexEncoder uses \xXX for all characters
type JSHexEncoder struct{}

func (e *JSHexEncoder) Name() string { return "js-hex" }
func (e *JSHexEncoder) Encode(payload string) (string, error) {
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for _, b := range []byte(payload) {
		result.WriteString(fmt.Sprintf("\\x%02x", b))
	}
	return result.String(), nil
}
func (e *JSHexEncoder) Decode(encoded string) (string, error) {
	result := encoded
	for i := 0; i < len(result)-3; i++ {
		if result[i] == '\\' && result[i+1] == 'x' {
			var b byte
			fmt.Sscanf(result[i+2:i+4], "%02x", &b)
			result = result[:i] + string(b) + result[i+4:]
		}
	}
	return result, nil
}

// UTF7Encoder applies UTF-7 encoding for bypasses
type UTF7Encoder struct{}

func (e *UTF7Encoder) Name() string { return "utf7" }
func (e *UTF7Encoder) Encode(payload string) (string, error) {
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for _, r := range payload {
		switch r {
		case '<':
			result.WriteString("+ADw-")
		case '>':
			result.WriteString("+AD4-")
		case '"':
			result.WriteString("+ACIi-")
		case '\'':
			result.WriteString("+ACc-")
		case '&':
			result.WriteString("+ACY-")
		case '(':
			result.WriteString("+ACg-")
		case ')':
			result.WriteString("+ACk-")
		default:
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}
func (e *UTF7Encoder) Decode(encoded string) (string, error) {
	result := strings.ReplaceAll(encoded, "+ADw-", "<")
	result = strings.ReplaceAll(result, "+AD4-", ">")
	result = strings.ReplaceAll(result, "+ACIi-", "\"")
	result = strings.ReplaceAll(result, "+ACc-", "'")
	result = strings.ReplaceAll(result, "+ACY-", "&")
	result = strings.ReplaceAll(result, "+ACg-", "(")
	result = strings.ReplaceAll(result, "+ACk-", ")")
	return result, nil
}

// XMLEntityEncoder wraps in CDATA or uses XML entities
type XMLEntityEncoder struct{}

func (e *XMLEntityEncoder) Name() string { return "xml-entity" }
func (e *XMLEntityEncoder) Encode(payload string) (string, error) {
	return "<![CDATA[" + payload + "]]>", nil
}
func (e *XMLEntityEncoder) Decode(encoded string) (string, error) {
	result := strings.TrimPrefix(encoded, "<![CDATA[")
	result = strings.TrimSuffix(result, "]]>")
	return result, nil
}

// HexEncoder applies hex encoding
type HexEncoder struct{}

func (e *HexEncoder) Name() string { return "hex" }
func (e *HexEncoder) Encode(payload string) (string, error) {
	return hex.EncodeToString([]byte(payload)), nil
}
func (e *HexEncoder) Decode(encoded string) (string, error) {
	decoded, err := hex.DecodeString(encoded)
	return string(decoded), err
}

// OctalEncoder applies octal encoding
type OctalEncoder struct{}

func (e *OctalEncoder) Name() string { return "octal" }
func (e *OctalEncoder) Encode(payload string) (string, error) {
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for _, b := range []byte(payload) {
		result.WriteString(fmt.Sprintf("\\%03o", b))
	}
	return result.String(), nil
}
func (e *OctalEncoder) Decode(encoded string) (string, error) {
	var result []byte
	for i := 0; i < len(encoded); {
		if encoded[i] == '\\' && i+3 < len(encoded) {
			var b byte
			fmt.Sscanf(encoded[i+1:i+4], "%03o", &b)
			result = append(result, b)
			i += 4
		} else {
			result = append(result, encoded[i])
			i++
		}
	}
	return string(result), nil
}

// BinaryEncoder applies binary encoding
type BinaryEncoder struct{}

func (e *BinaryEncoder) Name() string { return "binary" }
func (e *BinaryEncoder) Encode(payload string) (string, error) {
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for _, b := range []byte(payload) {
		result.WriteString(fmt.Sprintf("%08b", b))
	}
	return result.String(), nil
}
func (e *BinaryEncoder) Decode(encoded string) (string, error) {
	var result []byte
	for i := 0; i+8 <= len(encoded); i += 8 {
		var b byte
		fmt.Sscanf(encoded[i:i+8], "%08b", &b)
		result = append(result, b)
	}
	return string(result), nil
}
