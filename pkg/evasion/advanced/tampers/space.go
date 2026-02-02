package tampers

import (
	"math/rand"
	"net/http"
	"strings"
)

func init() {
	// Register all space manipulation tampers
	Register(&Space2Comment{BaseTamper: NewBaseTamper(
		"space2comment",
		"Replaces space with inline comment /**/",
		CategorySpace, PriorityNormal,
	)})

	Register(&Space2Dash{BaseTamper: NewBaseTamper(
		"space2dash",
		"Replaces space with dash comment followed by newline (-- \\n)",
		CategorySpace, PriorityNormal,
		"mysql", "postgres",
	)})

	Register(&Space2Hash{BaseTamper: NewBaseTamper(
		"space2hash",
		"Replaces space with pound comment and newline (# \\n)",
		CategorySpace, PriorityNormal,
		"mysql",
	)})

	Register(&Space2MoreComment{BaseTamper: NewBaseTamper(
		"space2morecomment",
		"Replaces space with extended inline comment /**_**/",
		CategorySpace, PriorityNormal,
	)})

	Register(&Space2MSSQLBlank{BaseTamper: NewBaseTamper(
		"space2mssqlblank",
		"Replaces space with random MSSQL whitespace character",
		CategorySpace, PriorityNormal,
		"mssql",
	)})

	Register(&Space2MSSQLHash{BaseTamper: NewBaseTamper(
		"space2mssqlhash",
		"Replaces space with pound and newline (#\\n) for MSSQL",
		CategorySpace, PriorityNormal,
		"mssql",
	)})

	Register(&Space2MySQLBlank{BaseTamper: NewBaseTamper(
		"space2mysqlblank",
		"Replaces space with random MySQL whitespace character",
		CategorySpace, PriorityNormal,
		"mysql",
	)})

	Register(&Space2MySQLDash{BaseTamper: NewBaseTamper(
		"space2mysqldash",
		"Replaces space with dash comment (-- \\n) for MySQL",
		CategorySpace, PriorityNormal,
		"mysql",
	)})

	Register(&Space2Plus{BaseTamper: NewBaseTamper(
		"space2plus",
		"Replaces space with plus sign (+)",
		CategorySpace, PriorityLowest,
	)})

	Register(&Space2RandomBlank{BaseTamper: NewBaseTamper(
		"space2randomblank",
		"Replaces space with random blank character from valid set",
		CategorySpace, PriorityNormal,
	)})

	Register(&Blankspace{BaseTamper: NewBaseTamper(
		"blankspace",
		"Replaces space with random alternative whitespace",
		CategorySpace, PriorityNormal,
	)})

	Register(&VarnishBypass{BaseTamper: NewBaseTamper(
		"varnishbypass",
		"Appends HTTP header for Varnish cache bypass",
		CategoryHTTP, PriorityLowest,
		"varnish", "cache",
	)})
}

// Space2Comment replaces space with inline comment /**/
type Space2Comment struct {
	BaseTamper
}

func (t *Space2Comment) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, " ", "/**/")
}

// Space2Dash replaces space with dash comment and newline
type Space2Dash struct {
	BaseTamper
}

func (t *Space2Dash) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, " ", "--\n")
}

// Space2Hash replaces space with pound comment and newline
type Space2Hash struct {
	BaseTamper
}

func (t *Space2Hash) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, " ", "#\n")
}

// Space2MoreComment replaces space with extended inline comment
type Space2MoreComment struct {
	BaseTamper
}

func (t *Space2MoreComment) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, " ", "/**_**/")
}

// Space2MSSQLBlank replaces space with random MSSQL blank character
type Space2MSSQLBlank struct {
	BaseTamper
}

// MSSQL valid whitespace characters
var mssqlBlanks = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
}

func (t *Space2MSSQLBlank) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		if r == ' ' {
			result.WriteByte(mssqlBlanks[rand.Intn(len(mssqlBlanks))])
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// Space2MSSQLHash replaces space with # and newline for MSSQL
type Space2MSSQLHash struct {
	BaseTamper
}

func (t *Space2MSSQLHash) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, " ", "#\n")
}

// Space2MySQLBlank replaces space with random MySQL blank character
type Space2MySQLBlank struct {
	BaseTamper
}

// MySQL valid whitespace characters: 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20
var mysqlBlanks = []byte{0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20}

func (t *Space2MySQLBlank) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		if r == ' ' {
			result.WriteByte(mysqlBlanks[rand.Intn(len(mysqlBlanks))])
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// Space2MySQLDash replaces space with dash comment for MySQL
type Space2MySQLDash struct {
	BaseTamper
}

func (t *Space2MySQLDash) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, " ", "-- \n")
}

// Space2Plus replaces space with plus sign
type Space2Plus struct {
	BaseTamper
}

func (t *Space2Plus) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return strings.ReplaceAll(payload, " ", "+")
}

// Space2RandomBlank replaces space with random valid blank character
type Space2RandomBlank struct {
	BaseTamper
}

// Standard SQL whitespace alternatives
var randomBlanks = []string{"%09", "%0A", "%0C", "%0D"}

func (t *Space2RandomBlank) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		if r == ' ' {
			result.WriteString(randomBlanks[rand.Intn(len(randomBlanks))])
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// Blankspace replaces space with random alternative whitespace character
type Blankspace struct {
	BaseTamper
}

// Alternative whitespace characters (Unicode spaces)
var blankspaceChars = []rune{
	'\u00A0', // Non-breaking space
	'\u1680', // Ogham space mark
	'\u2000', // En quad
	'\u2001', // Em quad
	'\u2002', // En space
	'\u2003', // Em space
	'\u2004', // Three-per-em space
	'\u2005', // Four-per-em space
	'\u2006', // Six-per-em space
	'\u2007', // Figure space
	'\u2008', // Punctuation space
	'\u2009', // Thin space
	'\u200A', // Hair space
	'\u202F', // Narrow no-break space
	'\u205F', // Medium mathematical space
	'\u3000', // Ideographic space
}

func (t *Blankspace) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	for _, r := range payload {
		if r == ' ' {
			result.WriteRune(blankspaceChars[rand.Intn(len(blankspaceChars))])
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// VarnishBypass appends header to bypass Varnish cache
type VarnishBypass struct {
	BaseTamper
}

func (t *VarnishBypass) Transform(payload string) string {
	// Payload-level transform just returns as-is
	// Real work is done in TransformRequest
	return payload
}

// TransformRequest adds X-originating-IP header for Varnish bypass
func (t *VarnishBypass) TransformRequest(req *http.Request) *http.Request {
	if req == nil {
		return req
	}
	// Add header to bypass Varnish cache
	req.Header.Set("X-originating-IP", "127.0.0.1")
	return req
}
