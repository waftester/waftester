package tampers

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"unicode"
)

func init() {
	// Register all SQL generic tampers
	Register(&Apostrophenullencode{BaseTamper: NewBaseTamper(
		"apostrophenullencode",
		"Replaces apostrophe with illegal double unicode (%00%27)",
		CategorySQL, PriorityNormal,
	)})

	Register(&Apostrophemask{BaseTamper: NewBaseTamper(
		"apostrophemask",
		"Replaces apostrophe with UTF-8 full width equivalent (U+FF07)",
		CategorySQL, PriorityNormal,
	)})

	Register(&Between{BaseTamper: NewBaseTamper(
		"between",
		"Replaces > with NOT BETWEEN 0 AND, = with BETWEEN X AND X",
		CategorySQL, PriorityNormal,
	)})

	Register(&Commentbeforeparentheses{BaseTamper: NewBaseTamper(
		"commentbeforeparentheses",
		"Adds inline comment /**/ before parentheses",
		CategorySQL, PriorityNormal,
	)})

	Register(&Concat2Concatws{BaseTamper: NewBaseTamper(
		"concat2concatws",
		"Replaces CONCAT with CONCAT_WS",
		CategorySQL, PriorityNormal,
		"mysql", "postgres",
	)})

	Register(&EqualToLike{BaseTamper: NewBaseTamper(
		"equaltolike",
		"Replaces = with LIKE operator",
		CategorySQL, PriorityNormal,
	)})

	Register(&GreatestLeast{BaseTamper: NewBaseTamper(
		"greatest",
		"Replaces > with GREATEST counterpart",
		CategorySQL, PriorityNormal,
		"mysql", "postgres", "oracle",
	)})

	Register(&HalfVersionedMoreKeywords{BaseTamper: NewBaseTamper(
		"halfversionedmorekeywords",
		"Adds versioned MySQL comment before SQL keywords",
		CategorySQL, PriorityNormal,
		"mysql",
	)})

	Register(&IfNull2CaseWhenNull{BaseTamper: NewBaseTamper(
		"ifnull2casewhennull",
		"Replaces IFNULL(A,B) with CASE WHEN A IS NULL THEN B ELSE A END",
		CategorySQL, PriorityLow,
		"mysql",
	)})

	Register(&IfNull2IfNullStr{BaseTamper: NewBaseTamper(
		"ifnull2ifisnull",
		"Replaces IFNULL(A,B) with IF(ISNULL(A),B,A)",
		CategorySQL, PriorityLow,
		"mysql",
	)})

	Register(&Least{BaseTamper: NewBaseTamper(
		"least",
		"Replaces > with LEAST counterpart",
		CategorySQL, PriorityNormal,
		"mysql", "postgres", "oracle",
	)})

	Register(&Lowercase{BaseTamper: NewBaseTamper(
		"lowercase",
		"Converts payload to lowercase",
		CategorySQL, PriorityLowest,
	)})

	Register(&Uppercase{BaseTamper: NewBaseTamper(
		"uppercase",
		"Converts payload to uppercase",
		CategorySQL, PriorityLowest,
	)})

	Register(&RandomCase{BaseTamper: NewBaseTamper(
		"randomcase",
		"Randomly changes case of characters",
		CategorySQL, PriorityLowest,
	)})

	Register(&SymbolsComment{BaseTamper: NewBaseTamper(
		"symboliclogical",
		"Replaces AND/OR with symbolic equivalents (&&, ||)",
		CategorySQL, PriorityNormal,
	)})

	Register(&SubstringExtreme{BaseTamper: NewBaseTamper(
		"substring2leftright",
		"Replaces SUBSTRING with LEFT+RIGHT combo",
		CategorySQL, PriorityNormal,
		"mysql", "mssql",
	)})
}

// Apostrophenullencode replaces ' with %00%27
type Apostrophenullencode struct {
	BaseTamper
}

func (t *Apostrophenullencode) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, "'", "%00%27")
}

// Apostrophemask replaces ' with UTF-8 full width character (U+FF07)
type Apostrophemask struct {
	BaseTamper
}

func (t *Apostrophemask) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, "'", "\uFF07")
}

// Between replaces > with NOT BETWEEN 0 AND
type Between struct {
	BaseTamper
}

func (t *Between) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Replace > with NOT BETWEEN 0 AND
	result := strings.ReplaceAll(payload, ">", " NOT BETWEEN 0 AND ")
	return result
}

// Commentbeforeparentheses adds /**/ before (
type Commentbeforeparentheses struct {
	BaseTamper
}

var funcPattern = regexp.MustCompile(`(\w+)\(`)

func (t *Commentbeforeparentheses) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return funcPattern.ReplaceAllString(payload, "$1/**/(")
}

// Concat2Concatws replaces CONCAT with CONCAT_WS
type Concat2Concatws struct {
	BaseTamper
}

var concatPattern = regexp.MustCompile(`(?i)CONCAT\s*\(`)

func (t *Concat2Concatws) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return concatPattern.ReplaceAllString(payload, "CONCAT_WS(MID(CHAR(0),0,0),")
}

// EqualToLike replaces = with LIKE
type EqualToLike struct {
	BaseTamper
}

func (t *EqualToLike) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Only replace = when it's a comparison (not in >=, <=, !=, <>)
	result := strings.ReplaceAll(payload, "!=", "NOT LIKE")
	result = strings.ReplaceAll(result, "<>", "NOT LIKE")
	// Simple = replacement, avoiding >= and <=
	var sb strings.Builder
	runes := []rune(result)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '=' {
			if i > 0 && (runes[i-1] == '>' || runes[i-1] == '<' || runes[i-1] == '!') {
				sb.WriteRune(runes[i])
				continue
			}
			sb.WriteString(" LIKE ")
		} else {
			sb.WriteRune(runes[i])
		}
	}
	return sb.String()
}

// GreatestLeast replaces > with GREATEST counterpart
type GreatestLeast struct {
	BaseTamper
}

func (t *GreatestLeast) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Replace A > B with GREATEST(A,B)=A
	// This is a simplified version
	return strings.ReplaceAll(payload, ">", " IS NOT NULL AND GREATEST")
}

// HalfVersionedMoreKeywords adds versioned comment before keywords
type HalfVersionedMoreKeywords struct {
	BaseTamper
}

var sqlKeywords = []string{
	"UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
	"ALTER", "TRUNCATE", "FROM", "WHERE", "AND", "OR", "NOT", "NULL",
	"ORDER", "GROUP", "HAVING", "LIMIT", "OFFSET", "JOIN", "INNER",
	"OUTER", "LEFT", "RIGHT", "LIKE", "IN", "BETWEEN", "EXISTS",
}

func (t *HalfVersionedMoreKeywords) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	result := payload
	for _, kw := range sqlKeywords {
		// Case insensitive replacement with versioned comment
		pattern := regexp.MustCompile(`(?i)\b` + kw + `\b`)
		result = pattern.ReplaceAllString(result, "/*!"+kw+"*/")
	}
	return result
}

// IfNull2CaseWhenNull replaces IFNULL with CASE WHEN
type IfNull2CaseWhenNull struct {
	BaseTamper
}

var ifnullPattern = regexp.MustCompile(`(?i)IFNULL\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)`)

func (t *IfNull2CaseWhenNull) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return ifnullPattern.ReplaceAllString(payload, "CASE WHEN $1 IS NULL THEN $2 ELSE $1 END")
}

// IfNull2IfNullStr replaces IFNULL with IF(ISNULL...)
type IfNull2IfNullStr struct {
	BaseTamper
}

func (t *IfNull2IfNullStr) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return ifnullPattern.ReplaceAllString(payload, "IF(ISNULL($1),$2,$1)")
}

// Least replaces < with LEAST counterpart
type Least struct {
	BaseTamper
}

func (t *Least) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Replace A < B logic
	return strings.ReplaceAll(payload, "<", " IS NOT NULL AND LEAST")
}

// Lowercase converts to lowercase
type Lowercase struct {
	BaseTamper
}

func (t *Lowercase) Transform(payload string) string {
	return strings.ToLower(payload)
}

// Uppercase converts to uppercase
type Uppercase struct {
	BaseTamper
}

func (t *Uppercase) Transform(payload string) string {
	return strings.ToUpper(payload)
}

// RandomCase randomly changes case
type RandomCase struct {
	BaseTamper
}

func (t *RandomCase) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		if rand.Intn(2) == 0 {
			result.WriteRune(unicode.ToUpper(r))
		} else {
			result.WriteRune(unicode.ToLower(r))
		}
	}
	return result.String()
}

// SymbolsComment replaces AND/OR with symbolic equivalents
type SymbolsComment struct {
	BaseTamper
}

var andPattern = regexp.MustCompile(`(?i)\bAND\b`)
var orPattern = regexp.MustCompile(`(?i)\bOR\b`)

func (t *SymbolsComment) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	result := andPattern.ReplaceAllString(payload, "&&")
	result = orPattern.ReplaceAllString(result, "||")
	return result
}

// SubstringExtreme replaces SUBSTRING with LEFT/RIGHT combo
type SubstringExtreme struct {
	BaseTamper
}

var substringPattern = regexp.MustCompile(`(?i)SUBSTRING\s*\(\s*([^,]+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)`)

func (t *SubstringExtreme) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return substringPattern.ReplaceAllStringFunc(payload, func(match string) string {
		submatch := substringPattern.FindStringSubmatch(match)
		if len(submatch) == 4 {
			str := submatch[1]
			start := submatch[2]
			length := submatch[3]
			return fmt.Sprintf("RIGHT(LEFT(%s,%s+%s-1),%s)", str, start, length, length)
		}
		return match
	})
}
