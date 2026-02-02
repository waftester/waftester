// Package hexutil provides optimized hex encoding utilities for hot paths.
// Uses lookup tables instead of fmt.Sprintf for 10x performance improvement.
package hexutil

import "strings"

// Hex character tables
const (
	HexUpper = "0123456789ABCDEF"
	HexLower = "0123456789abcdef"
)

// Pre-computed lookup tables for common encoding patterns
var (
	// URLEncoded contains "%XX" for each byte value (0-255) - uppercase
	URLEncoded [256]string

	// URLEncodedLower contains "%xx" for each byte value (0-255) - lowercase
	URLEncodedLower [256]string

	// DoubleURLEncoded contains "%25XX" for each byte value
	DoubleURLEncoded [256]string

	// HexEscape contains "\xXX" for each byte value (lowercase)
	HexEscape [256]string

	// HexEscapeUpper contains "\xXX" for each byte value (uppercase)
	HexEscapeUpper [256]string

	// OctalEscape contains "\OOO" for each byte value
	OctalEscape [256]string

	// BinaryEscape contains "XXXXXXXX" (8 binary digits) for each byte value
	BinaryEscape [256]string

	// DecEntity contains "&#N;" for ASCII printable range (32-127)
	DecEntity [128]string

	// HexEntity contains "&#xXX;" for ASCII printable range (lowercase)
	HexEntity [128]string
)

func init() {
	for i := 0; i < 256; i++ {
		hi := HexUpper[i>>4]
		lo := HexUpper[i&0x0F]
		hiL := HexLower[i>>4]
		loL := HexLower[i&0x0F]

		URLEncoded[i] = "%" + string(hi) + string(lo)
		URLEncodedLower[i] = "%" + string(hiL) + string(loL)
		DoubleURLEncoded[i] = "%25" + string(hi) + string(lo)
		HexEscape[i] = "\\x" + string(hiL) + string(loL)
		HexEscapeUpper[i] = "\\x" + string(hi) + string(lo)

		// Pre-compute octal escape: \OOO (3 octal digits)
		OctalEscape[i] = "\\" + string('0'+byte(i/64)) + string('0'+byte((i/8)%8)) + string('0'+byte(i%8))

		// Pre-compute binary: 8 binary digits
		BinaryEscape[i] = string([]byte{
			'0' + byte((i>>7)&1),
			'0' + byte((i>>6)&1),
			'0' + byte((i>>5)&1),
			'0' + byte((i>>4)&1),
			'0' + byte((i>>3)&1),
			'0' + byte((i>>2)&1),
			'0' + byte((i>>1)&1),
			'0' + byte(i&1),
		})

		// Pre-compute decimal and hex entities for ASCII printable range
		if i >= 32 && i < 128 {
			DecEntity[i] = "&#" + itoa(i) + ";"
			HexEntity[i] = "&#x" + string(hiL) + string(loL) + ";"
		}
	}
}

// itoa is a simple int-to-string for small positive integers (avoids strconv import)
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte // max 3 digits for 0-127
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// WriteHexEscape writes a byte as \xXX (lowercase) to the builder
func WriteHexEscape(sb *strings.Builder, b byte) {
	sb.WriteString(HexEscape[b])
}

// WriteHexEscapeUpper writes a byte as \xXX (uppercase) to the builder
func WriteHexEscapeUpper(sb *strings.Builder, b byte) {
	sb.WriteString(HexEscapeUpper[b])
}

// WriteOctalEscape writes a byte as \OOO (3 octal digits) to the builder
func WriteOctalEscape(sb *strings.Builder, b byte) {
	sb.WriteString(OctalEscape[b])
}

// WriteBinaryEscape writes a byte as 8 binary digits to the builder
func WriteBinaryEscape(sb *strings.Builder, b byte) {
	sb.WriteString(BinaryEscape[b])
}

// WriteURLEncoded writes a byte as %XX (uppercase) to the builder
func WriteURLEncoded(sb *strings.Builder, b byte) {
	sb.WriteString(URLEncoded[b])
}

// WriteURLEncodedLower writes a byte as %xx (lowercase) to the builder
func WriteURLEncodedLower(sb *strings.Builder, b byte) {
	sb.WriteString(URLEncodedLower[b])
}

// WriteDoubleURLEncoded writes a byte as %25XX to the builder
func WriteDoubleURLEncoded(sb *strings.Builder, b byte) {
	sb.WriteString(DoubleURLEncoded[b])
}

// WriteDecEntity writes a rune as &#N; to the builder
func WriteDecEntity(sb *strings.Builder, r rune) {
	if r >= 32 && r < 128 {
		sb.WriteString(DecEntity[r])
	} else {
		// Fallback for extended characters
		sb.WriteString("&#")
		writeInt(sb, int(r))
		sb.WriteByte(';')
	}
}

// WriteHexEntity writes a rune as &#xXX; (lowercase) to the builder
func WriteHexEntity(sb *strings.Builder, r rune) {
	if r >= 32 && r < 128 {
		sb.WriteString(HexEntity[r])
	} else {
		// Fallback for extended characters - write as &#xXXXX;
		sb.WriteString("&#x")
		writeHexRune(sb, r)
		sb.WriteByte(';')
	}
}

// WriteUnicodeEscape writes a rune as \uXXXX to the builder
func WriteUnicodeEscape(sb *strings.Builder, r rune) {
	sb.WriteString("\\u")
	writeHex4(sb, uint16(r))
}

// WriteUnicodeEscapeUpper writes a rune as \uXXXX (uppercase) to the builder
func WriteUnicodeEscapeUpper(sb *strings.Builder, r rune) {
	sb.WriteString("\\u")
	writeHex4Upper(sb, uint16(r))
}

// writeInt writes an integer to the builder without allocations
func writeInt(sb *strings.Builder, n int) {
	if n == 0 {
		sb.WriteByte('0')
		return
	}
	var buf [10]byte // enough for 32-bit int
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	sb.Write(buf[i:])
}

// writeHex4 writes a 16-bit value as 4 lowercase hex digits
func writeHex4(sb *strings.Builder, v uint16) {
	sb.WriteByte(HexLower[v>>12&0xF])
	sb.WriteByte(HexLower[v>>8&0xF])
	sb.WriteByte(HexLower[v>>4&0xF])
	sb.WriteByte(HexLower[v&0xF])
}

// writeHex4Upper writes a 16-bit value as 4 uppercase hex digits
func writeHex4Upper(sb *strings.Builder, v uint16) {
	sb.WriteByte(HexUpper[v>>12&0xF])
	sb.WriteByte(HexUpper[v>>8&0xF])
	sb.WriteByte(HexUpper[v>>4&0xF])
	sb.WriteByte(HexUpper[v&0xF])
}

// writeHexRune writes a rune as hex digits (variable length)
func writeHexRune(sb *strings.Builder, r rune) {
	if r < 0x10 {
		sb.WriteByte(HexLower[r])
	} else if r < 0x100 {
		sb.WriteByte(HexLower[r>>4])
		sb.WriteByte(HexLower[r&0xF])
	} else if r < 0x1000 {
		sb.WriteByte(HexLower[r>>8])
		sb.WriteByte(HexLower[r>>4&0xF])
		sb.WriteByte(HexLower[r&0xF])
	} else {
		sb.WriteByte(HexLower[r>>12&0xF])
		sb.WriteByte(HexLower[r>>8&0xF])
		sb.WriteByte(HexLower[r>>4&0xF])
		sb.WriteByte(HexLower[r&0xF])
	}
}

// WriteOverlong2Byte writes a byte as 2-byte overlong UTF-8: %cXX%cXX
// Used for WAF bypass testing - encodes b as overlong 2-byte UTF-8
func WriteOverlong2Byte(sb *strings.Builder, b byte) {
	// 2-byte overlong: 110xxxxx 10xxxxxx
	first := 0xC0 | (b >> 6)
	second := 0x80 | (b & 0x3F)
	sb.WriteString("%c")
	sb.WriteByte(HexLower[first>>4])
	sb.WriteByte(HexLower[first&0xF])
	sb.WriteString("%c")
	sb.WriteByte(HexLower[second>>4])
	sb.WriteByte(HexLower[second&0xF])
}

// WriteOverlong3Byte writes a byte as 3-byte overlong UTF-8: %eXX%cXX%cXX
// Used for WAF bypass testing - encodes b as overlong 3-byte UTF-8
func WriteOverlong3Byte(sb *strings.Builder, b byte) {
	// 3-byte: 1110xxxx 10xxxxxx 10xxxxxx
	first := byte(0xE0)
	second := 0x80 | ((b >> 6) & 0x3F)
	third := 0x80 | (b & 0x3F)
	sb.WriteString("%e")
	sb.WriteByte(HexLower[first>>4])
	sb.WriteByte(HexLower[first&0xF])
	sb.WriteString("%c")
	sb.WriteByte(HexLower[second>>4])
	sb.WriteByte(HexLower[second&0xF])
	sb.WriteString("%c")
	sb.WriteByte(HexLower[third>>4])
	sb.WriteByte(HexLower[third&0xF])
}
