package tampers

import (
	"strings"
)

// Optimized hex encoding utilities.
// Avoids fmt.Sprintf overhead (10x faster) by using lookup tables.

// hexUpperTable is the uppercase hex character table
const hexUpperTable = "0123456789ABCDEF"

// hexLowerTable is the lowercase hex character table
const hexLowerTable = "0123456789abcdef"

// Pre-computed URL-encoded byte lookup table ("%XX" format)
// 256 entries, each is 3 bytes: '%' + 2 hex chars
var urlEncodedBytes [256]string

// Pre-computed double URL-encoded byte lookup table ("%25XX" format)
// Used for double-encoding bypass
var doubleUrlEncodedBytes [256]string

func init() {
	for i := 0; i < 256; i++ {
		urlEncodedBytes[i] = "%" + string(hexUpperTable[i>>4]) + string(hexUpperTable[i&0x0F])
		doubleUrlEncodedBytes[i] = "%25" + string(hexUpperTable[i>>4]) + string(hexUpperTable[i&0x0F])
	}
}

// writeURLEncodedByte writes a single byte as %XX to the builder
// This is 10x faster than fmt.Sprintf("%%%02X", b)
func writeURLEncodedByte(sb *strings.Builder, b byte) {
	sb.WriteString(urlEncodedBytes[b])
}

// writeDoubleURLEncodedByte writes a single byte as %25XX to the builder
func writeDoubleURLEncodedByte(sb *strings.Builder, b byte) {
	sb.WriteString(doubleUrlEncodedBytes[b])
}

// writeUnicodeEscape writes a rune as \uXXXX format (or \uXXXXXX for runes > 0xFFFF)
func writeUnicodeEscape(sb *strings.Builder, r rune, upper bool) {
	table := hexLowerTable
	if upper {
		table = hexUpperTable
	}
	sb.WriteString("\\u")
	if r <= 0xFF {
		sb.WriteByte('0')
		sb.WriteByte('0')
		sb.WriteByte(table[byte(r)>>4])
		sb.WriteByte(table[byte(r)&0x0F])
	} else if r <= 0xFFFF {
		sb.WriteByte(table[(r>>12)&0x0F])
		sb.WriteByte(table[(r>>8)&0x0F])
		sb.WriteByte(table[(r>>4)&0x0F])
		sb.WriteByte(table[r&0x0F])
	} else {
		// Runes > 0xFFFF need 6 hex digits (up to 0x10FFFF)
		sb.WriteByte(table[(r>>20)&0x0F])
		sb.WriteByte(table[(r>>16)&0x0F])
		sb.WriteByte(table[(r>>12)&0x0F])
		sb.WriteByte(table[(r>>8)&0x0F])
		sb.WriteByte(table[(r>>4)&0x0F])
		sb.WriteByte(table[r&0x0F])
	}
}

// writeASPUnicodeEncode writes a rune as %uXXXX format (ASP/IIS style)
func writeASPUnicodeEncode(sb *strings.Builder, r rune) {
	sb.WriteString("%u00")
	sb.WriteByte(hexUpperTable[byte(r)>>4])
	sb.WriteByte(hexUpperTable[byte(r)&0x0F])
}

// writeDecEntity writes a rune as &#NNN; HTML decimal entity
func writeDecEntity(sb *strings.Builder, r rune) {
	sb.WriteString("&#")
	// Fast int-to-string without fmt
	if r == 0 {
		sb.WriteByte('0')
	} else {
		// Buffer for max int32 digits
		var buf [10]byte
		i := len(buf)
		for r > 0 {
			i--
			buf[i] = byte(r%10) + '0'
			r /= 10
		}
		sb.Write(buf[i:])
	}
	sb.WriteByte(';')
}

// writeHexEntity writes a rune as &#xNN; HTML hex entity
func writeHexEntity(sb *strings.Builder, r rune) {
	sb.WriteString("&#x")
	if r <= 0xFF {
		sb.WriteByte(hexUpperTable[byte(r)>>4])
		sb.WriteByte(hexUpperTable[byte(r)&0x0F])
	} else {
		// For multi-byte, write all significant nibbles
		started := false
		for shift := 28; shift >= 0; shift -= 4 {
			nibble := (r >> shift) & 0x0F
			if nibble != 0 || started || shift == 0 {
				sb.WriteByte(hexUpperTable[nibble])
				started = true
			}
		}
	}
	sb.WriteByte(';')
}

// writeOverlongUTF8_2byte writes ASCII as 2-byte overlong UTF-8 (%XX%XX)
func writeOverlongUTF8_2byte(sb *strings.Builder, b byte) {
	// 2-byte overlong: 110000xx 10xxxxxx
	sb.WriteByte('%')
	first := 0xC0 | (b >> 6)
	sb.WriteByte(hexUpperTable[first>>4])
	sb.WriteByte(hexUpperTable[first&0x0F])
	sb.WriteByte('%')
	second := 0x80 | (b & 0x3F)
	sb.WriteByte(hexUpperTable[second>>4])
	sb.WriteByte(hexUpperTable[second&0x0F])
}

// writeOverlongUTF8_3byte writes ASCII as 3-byte overlong UTF-8 (%XX%XX%XX)
func writeOverlongUTF8_3byte(sb *strings.Builder, b byte) {
	// 3-byte overlong: 1110xxxx 10xxxxxx 10xxxxxx (for ASCII: E0 80|xx 80|xx)
	sb.WriteString("%E0%")
	second := 0x80 | (b >> 6)
	sb.WriteByte(hexUpperTable[second>>4])
	sb.WriteByte(hexUpperTable[second&0x0F])
	sb.WriteByte('%')
	third := 0x80 | (b & 0x3F)
	sb.WriteByte(hexUpperTable[third>>4])
	sb.WriteByte(hexUpperTable[third&0x0F])
}

// MSSQL CHAR() lookup table for ASCII values 0-127
// Pre-computed "CHAR(N)" strings to avoid fmt.Sprintf in hot loops
var mssqlCharLookup [128]string

func init() {
	for i := 0; i < 128; i++ {
		mssqlCharLookup[i] = "CHAR(" + itoa(i) + ")"
	}
}

// itoa converts small positive int to string without fmt
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

// GetMSSQLChar returns the MSSQL CHAR(N) string for a rune.
// Uses lookup table for ASCII (0-127), falls back to fmt.Sprintf for unicode.
func GetMSSQLChar(r rune) string {
	if r >= 0 && r < 128 {
		return mssqlCharLookup[r]
	}
	// Fallback for non-ASCII runes (rare in SQL injection payloads)
	return "CHAR(" + itoaLarge(int(r)) + ")"
}

// itoaLarge handles integers larger than 127
func itoaLarge(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte // max 10 digits for int32
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
