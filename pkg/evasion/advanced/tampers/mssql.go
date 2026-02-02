package tampers

import (
	"fmt"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

func init() {
	// Register all MSSQL-specific tampers
	Register(&MSSQLBlind{BaseTamper: NewBaseTamper(
		"mssqlblind",
		"Adds braces and CHAR functions for MSSQL blind injection",
		CategoryMSSQL, PriorityNormal,
		"mssql",
	)})

	Register(&ChardeclareAndexec{BaseTamper: NewBaseTamper(
		"chardeclareandexec",
		"Declares variables and uses EXEC to run payload",
		CategoryMSSQL, PriorityNormal,
		"mssql",
	)})

	Register(&TopClause{BaseTamper: NewBaseTamper(
		"topclause",
		"Adds TOP clause to SELECT statements",
		CategoryMSSQL, PriorityLowest,
		"mssql",
	)})

	Register(&SPPassword{BaseTamper: NewBaseTamper(
		"sppassword",
		"Appends sp_password comment for MSSQL log evasion",
		CategoryMSSQL, PriorityLowest,
		"mssql",
	)})

	Register(&BracketComment{BaseTamper: NewBaseTamper(
		"bracketcomment",
		"Uses [comment] syntax for MSSQL identifiers",
		CategoryMSSQL, PriorityNormal,
		"mssql",
	)})

	Register(&CharToUnicode{BaseTamper: NewBaseTamper(
		"chartounicode",
		"Converts CHAR(N) to NCHAR(N) for Unicode bypass",
		CategoryMSSQL, PriorityNormal,
		"mssql",
	)})
}

// MSSQLBlind adds braces around keywords for blind injection
type MSSQLBlind struct {
	BaseTamper
}

// Pre-compiled pattern for all MSSQL keywords (single pass, no loop compilation)
var mssqlKeywordsPattern = regexcache.MustGet(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|AND|OR)\b`)

func (t *MSSQLBlind) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return mssqlKeywordsPattern.ReplaceAllStringFunc(payload, func(match string) string {
		return "{" + strings.ToUpper(match) + "}"
	})
}

// ChardeclareAndexec wraps payload in DECLARE/EXEC pattern
type ChardeclareAndexec struct {
	BaseTamper
}

func (t *ChardeclareAndexec) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Convert payload to CHAR representation
	var chars []string
	for _, r := range payload {
		chars = append(chars, fmt.Sprintf("CHAR(%d)", r))
	}
	charStr := strings.Join(chars, "+")
	return fmt.Sprintf("DECLARE @x VARCHAR(MAX)=(%s);EXEC(@x)", charStr)
}

// TopClause adds TOP 1 to SELECT statements
type TopClause struct {
	BaseTamper
}

var selectPattern = regexcache.MustGet(`(?i)\bSELECT\b`)

func (t *TopClause) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return selectPattern.ReplaceAllString(payload, "SELECT TOP 1")
}

// SPPassword appends sp_password comment for log evasion
type SPPassword struct {
	BaseTamper
}

func (t *SPPassword) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return payload + " --sp_password"
}

// BracketComment uses bracket syntax for identifiers
type BracketComment struct {
	BaseTamper
}

func (t *BracketComment) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Use same pre-compiled pattern as MSSQLBlind
	return mssqlKeywordsPattern.ReplaceAllStringFunc(payload, func(match string) string {
		return "[" + strings.ToUpper(match) + "]"
	})
}

// CharToUnicode converts CHAR(N) to NCHAR(N)
type CharToUnicode struct {
	BaseTamper
}

var charFuncPattern = regexcache.MustGet(`(?i)\bCHAR\s*\(`)

func (t *CharToUnicode) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return charFuncPattern.ReplaceAllString(payload, "NCHAR(")
}
