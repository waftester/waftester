package tampers

import (
	"math/rand"
	"net/http"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

func init() {
	// Register all WAF bypass tampers
	Register(&Informationschemacomment{BaseTamper: NewBaseTamper(
		"informationschemacomment",
		"Adds comment to information_schema identifier",
		CategoryWAF, PriorityNormal,
		"mysql",
	)})

	Register(&Schemasplit{BaseTamper: NewBaseTamper(
		"schemasplit",
		"Splits schema names using backtick comment",
		CategoryWAF, PriorityNormal,
		"mysql",
	)})

	Register(&LuanginxWAF{BaseTamper: NewBaseTamper(
		"luanginxwaf",
		"Bypasses Lua-nginx-module WAF by adding null bytes",
		CategoryWAF, PriorityNormal,
		"nginx", "lua",
	)})

	Register(&XForwardedFor{BaseTamper: NewBaseTamper(
		"xforwardedfor",
		"Adds X-Forwarded-For header for WAF bypass",
		CategoryHTTP, PriorityLowest,
	)})

	Register(&RandomUserAgent{BaseTamper: NewBaseTamper(
		"randomuseragent",
		"Sets random User-Agent header",
		CategoryHTTP, PriorityLowest,
	)})

	Register(&JSONObfuscate{BaseTamper: NewBaseTamper(
		"jsonobfuscate",
		"Obfuscates JSON syntax to bypass WAF",
		CategoryWAF, PriorityNormal,
		"json", "api",
	)})
}

// Informationschemacomment adds comment after information_schema
type Informationschemacomment struct {
	BaseTamper
}

var infoSchemaPattern = regexcache.MustGet(`(?i)(INFORMATION_SCHEMA)\.`)

func (t *Informationschemacomment) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	return infoSchemaPattern.ReplaceAllString(payload, "$1/**/.`")
}

// Schemasplit splits schema with backtick comment
type Schemasplit struct {
	BaseTamper
}

func (t *Schemasplit) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Split common schema references
	result := strings.ReplaceAll(payload, "information_schema", "information`/**/.`schema")
	result = strings.ReplaceAll(result, "INFORMATION_SCHEMA", "INFORMATION`/**/.`SCHEMA")
	return result
}

// LuanginxWAF adds null bytes to bypass Lua-nginx WAF
type LuanginxWAF struct {
	BaseTamper
}

func (t *LuanginxWAF) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Pre-allocate: payload plus null bytes (~33% overhead)
	var result strings.Builder
	result.Grow(len(payload) + len(payload)/2)
	for i, r := range payload {
		result.WriteRune(r)
		// Add null byte every few characters
		if i > 0 && i%3 == 0 && i < len(payload)-1 {
			result.WriteString("%00")
		}
	}
	return result.String()
}

// XForwardedFor adds X-Forwarded-For header
type XForwardedFor struct {
	BaseTamper
}

func (t *XForwardedFor) Transform(payload string) string {
	return payload
}

func (t *XForwardedFor) TransformRequest(req *http.Request) *http.Request {
	if req == nil {
		return req
	}
	// Add randomized internal IP
	ips := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "localhost"}
	req.Header.Set("X-Forwarded-For", ips[rand.Intn(len(ips))])
	req.Header.Set("X-Real-IP", ips[rand.Intn(len(ips))])
	req.Header.Set("X-Originating-IP", ips[rand.Intn(len(ips))])
	return req
}

// RandomUserAgent sets random User-Agent
type RandomUserAgent struct {
	BaseTamper
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/92.0.4515.107 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
	"Googlebot/2.1 (+http://www.google.com/bot.html)",
	"Bingbot/2.0; +http://www.bing.com/bingbot.htm",
}

func (t *RandomUserAgent) Transform(payload string) string {
	return payload
}

func (t *RandomUserAgent) TransformRequest(req *http.Request) *http.Request {
	if req == nil {
		return req
	}
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	return req
}

// JSONObfuscate obfuscates JSON for WAF bypass
type JSONObfuscate struct {
	BaseTamper
}

func (t *JSONObfuscate) Transform(payload string) string {
	if payload == "" {
		return payload
	}
	// Pre-allocate with generous expansion for whitespace/escapes
	var result strings.Builder
	result.Grow(len(payload) * 2)
	for _, r := range payload {
		switch r {
		case '{':
			result.WriteString("{\r\n")
		case '}':
			result.WriteString("\r\n}")
		case ':':
			result.WriteString(" : ")
		case ',':
			result.WriteString(",\r\n")
		case '"':
			// Sometimes escape as Unicode
			if rand.Intn(2) == 0 {
				result.WriteString("\\u0022")
			} else {
				result.WriteRune(r)
			}
		default:
			// Randomly Unicode-escape some characters
			if r >= 'a' && r <= 'z' && rand.Intn(10) < 3 {
				writeUnicodeEscape(&result, r, false)
			} else {
				result.WriteRune(r)
			}
		}
	}
	return result.String()
}
