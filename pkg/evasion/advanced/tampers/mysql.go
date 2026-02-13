package tampers

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

func init() {
	// Register all MySQL-specific tampers
	Register(&CharlongEscape{BaseTamper: NewBaseTamper(
		"charlongescape",
		"Replaces CHAR(N) with long unicode escape format",
		CategoryMySQL, PriorityNormal,
		"mysql",
	)})

	Register(&EscapeNQuotes{BaseTamper: NewBaseTamper(
		"escapequotes",
		"Escapes quotes with backslash",
		CategoryMySQL, PriorityLow,
		"mysql",
	)})

	Register(&MisUnion{BaseTamper: NewBaseTamper(
		"misunion",
		"Replaces UNION with -.1UNION",
		CategoryMySQL, PriorityNormal,
		"mysql",
	)})

	Register(&Modsecurityversioned{BaseTamper: NewBaseTamper(
		"modsecurityversioned",
		"Wraps payload with MySQL versioned comment to bypass ModSecurity",
		CategoryMySQL, PriorityHighest,
		"mysql", "modsecurity",
	)})

	Register(&Modsecurityzeroversioned{BaseTamper: NewBaseTamper(
		"modsecurityzeroversioned",
		"Wraps payload with /*!00000 */ comment",
		CategoryMySQL, PriorityHighest,
		"mysql", "modsecurity",
	)})

	Register(&MultipleURLEncode{BaseTamper: NewBaseTamper(
		"multipleurlencode",
		"URL encodes payload multiple times",
		CategoryMySQL, PriorityNormal,
	)})

	Register(&ReverseOrder{BaseTamper: NewBaseTamper(
		"reverseorder",
		"Reverses payload character order",
		CategoryMySQL, PriorityLow,
	)})

	Register(&SpaceToMySQLComment{BaseTamper: NewBaseTamper(
		"sp_password",
		"Appends sp_password to payload for log evasion",
		CategoryMySQL, PriorityLowest,
		"mssql",
	)})

	Register(&VersionedKeywords{BaseTamper: NewBaseTamper(
		"versionedkeywords",
		"Encloses keywords with versioned MySQL comment",
		CategoryMySQL, PriorityNormal,
		"mysql",
	)})

	Register(&VersionedMoreKeywords{BaseTamper: NewBaseTamper(
		"versionedmorekeywords",
		"Encloses more keywords with versioned MySQL comment",
		CategoryMySQL, PriorityNormal,
		"mysql",
	)})
}

// CharlongEscape replaces CHAR(N) with Unicode escape
type CharlongEscape struct {
	BaseTamper
}

var charPattern = regexcache.MustGet(`(?i)CHAR\s*\(\s*(\d+)\s*\)`)

func (t *CharlongEscape) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return charPattern.ReplaceAllStringFunc(payload, func(match string) string {
		submatch := charPattern.FindStringSubmatch(match)
		if len(submatch) == 2 {
			// submatch[1] is decimal (e.g., "65"), convert to hex (e.g., "0x41")
			n, err := strconv.Atoi(submatch[1])
			if err != nil {
				return match
			}
			return fmt.Sprintf("0x%x", n)
		}
		return match
	})
}

// EscapeNQuotes escapes quotes with backslash
type EscapeNQuotes struct {
	BaseTamper
}

func (t *EscapeNQuotes) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	result := strings.ReplaceAll(payload, "'", "\\'")
	result = strings.ReplaceAll(result, "\"", "\\\"")
	return result
}

// MisUnion replaces UNION with -.1UNION to bypass filters
type MisUnion struct {
	BaseTamper
}

var unionPattern = regexcache.MustGet(`(?i)\bUNION\b`)

func (t *MisUnion) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return unionPattern.ReplaceAllString(payload, "-.1UNION")
}

// Modsecurityversioned wraps with MySQL version comment to bypass ModSecurity
type Modsecurityversioned struct {
	BaseTamper
}

func (t *Modsecurityversioned) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Random version number between 30000 and 99999
	version := 30000 + rand.Intn(69999)
	return "/*!" + strconv.Itoa(version) + payload + "*/"
}

// Modsecurityzeroversioned wraps with /*!00000 comment
type Modsecurityzeroversioned struct {
	BaseTamper
}

func (t *Modsecurityzeroversioned) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return "/*!00000" + payload + "*/"
}

// MultipleURLEncode encodes payload multiple times
type MultipleURLEncode struct {
	BaseTamper
}

func (t *MultipleURLEncode) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// First pass encoding
	var result strings.Builder
	result.Grow(len(payload) * 3)
	for _, b := range []byte(payload) {
		writeURLEncodedByte(&result, b)
	}
	// Second pass encoding (encode the %)
	encoded := result.String()
	var result2 strings.Builder
	result2.Grow(len(encoded) + len(encoded)/3) // ~33% expansion for %->%25
	for _, b := range []byte(encoded) {
		if b == '%' {
			result2.WriteString("%25")
		} else {
			result2.WriteByte(b)
		}
	}
	return result2.String()
}

// ReverseOrder reverses the payload
type ReverseOrder struct {
	BaseTamper
}

func (t *ReverseOrder) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	runes := []rune(payload)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// SpaceToMySQLComment appends sp_password for MSSQL log evasion
type SpaceToMySQLComment struct {
	BaseTamper
}

func (t *SpaceToMySQLComment) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return payload + "--sp_password"
}

// VersionedKeywords wraps SQL keywords with MySQL versioned comments
type VersionedKeywords struct {
	BaseTamper
}

var keywordsPattern = regexcache.MustGet(`(?i)\b(UNION|SELECT|INSERT|UPDATE|DELETE|WHERE)\b`)

func (t *VersionedKeywords) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return keywordsPattern.ReplaceAllStringFunc(payload, wrapVersionedKeyword)
}

// wrapVersionedKeyword wraps a keyword - avoids closure and fmt.Sprintf allocation
func wrapVersionedKeyword(match string) string {
	return "/*!" + strings.ToUpper(match) + "*/"
}

// VersionedMoreKeywords wraps more SQL keywords with versioned comments
type VersionedMoreKeywords struct {
	BaseTamper
}

var moreKeywordsPattern = regexcache.MustGet(`(?i)\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|FROM|WHERE|AND|OR|NOT|NULL|ORDER|GROUP|HAVING|LIMIT|OFFSET|JOIN|LIKE|IN|BETWEEN)\b`)

func (t *VersionedMoreKeywords) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return moreKeywordsPattern.ReplaceAllStringFunc(payload, wrapVersionedKeyword)
}
