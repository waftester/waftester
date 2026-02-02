package tampers

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

func init() {
	// Register all obfuscation tampers
	Register(&CommentRandom{BaseTamper: NewBaseTamper(
		"commentrandom",
		"Inserts random inline comments between characters",
		CategoryObfuscation, PriorityLow,
	)})

	Register(&RandomComments{BaseTamper: NewBaseTamper(
		"randomcomments",
		"Adds random comments around SQL keywords",
		CategoryObfuscation, PriorityNormal,
	)})

	Register(&SlashStar{BaseTamper: NewBaseTamper(
		"slashstar",
		"Wraps payload sections with /* comment */",
		CategoryObfuscation, PriorityNormal,
	)})

	Register(&Concat{BaseTamper: NewBaseTamper(
		"concat",
		"Concatenates strings using || or + operators",
		CategoryObfuscation, PriorityNormal,
	)})

	Register(&NullByte{BaseTamper: NewBaseTamper(
		"nullbyte",
		"Inserts null byte (%00) before payload",
		CategoryObfuscation, PriorityNormal,
	)})

	Register(&Suffix{BaseTamper: NewBaseTamper(
		"suffix",
		"Adds SQL comment suffix to payload",
		CategoryObfuscation, PriorityLowest,
	)})
}

// CommentRandom inserts random comments between characters
type CommentRandom struct {
	BaseTamper
}

func (t *CommentRandom) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	var result strings.Builder
	runes := []rune(payload)
	for i, r := range runes {
		result.WriteRune(r)
		// Randomly insert comment (about 30% chance)
		if i < len(runes)-1 && rand.Intn(10) < 3 {
			result.WriteString("/**/")
		}
	}
	return result.String()
}

// RandomComments adds comments around keywords
type RandomComments struct {
	BaseTamper
}

// Pre-compiled pattern for SQL keywords (single pass, no loop compilation)
var randomCommentKeywordsPattern = regexcache.MustGet(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|FROM|WHERE|AND|OR|UNION)\b`)

// Comment variants for random selection
var commentVariants = []string{"/**/", "/* */", "/**_**/", "/*-*/"}

func (t *RandomComments) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return randomCommentKeywordsPattern.ReplaceAllStringFunc(payload, func(match string) string {
		comment := commentVariants[rand.Intn(len(commentVariants))]
		return comment + match + comment
	})
}

// SlashStar wraps with comments
type SlashStar struct {
	BaseTamper
}

func (t *SlashStar) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Wrap entire payload
	return fmt.Sprintf("/*%s*/", payload)
}

// Concat splits strings and concatenates them
type Concat struct {
	BaseTamper
}

func (t *Concat) Transform(payload string) string {
	if payload == "" || len(payload) < 3 {
		return payload
	}
	
	// Find quoted strings and split them
	var result strings.Builder
	inString := false
	var currentQuote rune
	var stringContent strings.Builder
	
	for _, r := range payload {
		if !inString && (r == '\'' || r == '"') {
			inString = true
			currentQuote = r
			result.WriteRune(r)
		} else if inString && r == currentQuote {
			// Split the string content
			content := stringContent.String()
			if len(content) > 2 {
				mid := len(content) / 2
				result.WriteString(content[:mid])
				result.WriteRune(currentQuote)
				result.WriteString("||")
				result.WriteRune(currentQuote)
				result.WriteString(content[mid:])
			} else {
				result.WriteString(content)
			}
			result.WriteRune(r)
			inString = false
			stringContent.Reset()
		} else if inString {
			stringContent.WriteRune(r)
		} else {
			result.WriteRune(r)
		}
	}
	
	return result.String()
}

// NullByte inserts null byte before payload
type NullByte struct {
	BaseTamper
}

func (t *NullByte) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return "%00" + payload
}

// Suffix adds SQL comment suffix
type Suffix struct {
	BaseTamper
}

var suffixVariants = []string{
	"--",
	"-- -",
	"#",
	"/*",
	";--",
	";#",
}

func (t *Suffix) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	suffix := suffixVariants[rand.Intn(len(suffixVariants))]
	return payload + suffix
}
