package dsl

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/waftester/waftester/pkg/regexcache"
)

// ResponseData holds the HTTP response fields available for DSL expression evaluation.
// These correspond to the variables accessible in -mdc and -fdc filter expressions.
type ResponseData struct {
	StatusCode    int
	ContentLength int64
	Body          string
	ContentType   string
	Title         string
	Host          string
	Server        string
	Location      string
}

// Evaluate evaluates a DSL expression against HTTP response data.
// It supports httpx-compatible filter expressions used in -mdc and -fdc flags.
//
// Supported variables: status_code, content_length, content_type, body, title, host, server, location
// Supported operators: ==, !=, <, >, <=, >=, &&, ||
// Supported functions: contains(var, "str"), matches(var, "regex"), hasPrefix(var, "str"),
//
//	hasSuffix(var, "str"), len(var)
//
// An empty expression returns true (match-all).
// A nil ResponseData returns false (no response = no match).
func Evaluate(expr string, data *ResponseData) bool {
	if expr == "" {
		return true
	}
	if data == nil {
		return false
	}

	variables := map[string]interface{}{
		"status_code":    data.StatusCode,
		"content_length": data.ContentLength,
		"content_type":   data.ContentType,
		"body":           data.Body,
		"title":          data.Title,
		"host":           data.Host,
		"server":         data.Server,
		"location":       data.Location,
	}

	// Handle !contains(body, "string") — must come before contains to avoid partial match
	notContainsRe := regexcache.MustGet(`!\s*contains\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
	expr = notContainsRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := notContainsRe.FindStringSubmatch(match)
		if len(parts) == 3 {
			if val, ok := variables[parts[1]]; ok {
				if strVal, ok := val.(string); ok {
					if !strings.Contains(strVal, parts[2]) {
						return "true"
					}
					return "false"
				}
			}
		}
		return "true"
	})

	// Handle contains(body, "string")
	containsRe := regexcache.MustGet(`contains\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
	expr = containsRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := containsRe.FindStringSubmatch(match)
		if len(parts) == 3 {
			if val, ok := variables[parts[1]]; ok {
				if strVal, ok := val.(string); ok {
					if strings.Contains(strVal, parts[2]) {
						return "true"
					}
					return "false"
				}
			}
		}
		return "false"
	})

	// Handle matches(body, "regex")
	matchesRe := regexcache.MustGet(`matches\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
	expr = matchesRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := matchesRe.FindStringSubmatch(match)
		if len(parts) == 3 {
			if val, ok := variables[parts[1]]; ok {
				if strVal, ok := val.(string); ok {
					re, err := regexcache.Get(parts[2])
					if err == nil && re.MatchString(strVal) {
						return "true"
					}
					return "false"
				}
			}
		}
		return "false"
	})

	// Handle hasPrefix(str, "prefix")
	hasPrefixRe := regexcache.MustGet(`hasPrefix\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
	expr = hasPrefixRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := hasPrefixRe.FindStringSubmatch(match)
		if len(parts) == 3 {
			if val, ok := variables[parts[1]]; ok {
				if strVal, ok := val.(string); ok {
					if strings.HasPrefix(strVal, parts[2]) {
						return "true"
					}
					return "false"
				}
			}
		}
		return "false"
	})

	// Handle hasSuffix(str, "suffix")
	hasSuffixRe := regexcache.MustGet(`hasSuffix\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
	expr = hasSuffixRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := hasSuffixRe.FindStringSubmatch(match)
		if len(parts) == 3 {
			if val, ok := variables[parts[1]]; ok {
				if strVal, ok := val.(string); ok {
					if strings.HasSuffix(strVal, parts[2]) {
						return "true"
					}
					return "false"
				}
			}
		}
		return "false"
	})

	// Handle len(var) — replace with actual character count (not byte count)
	lenRe := regexcache.MustGet(`len\s*\(\s*(\w+)\s*\)`)
	expr = lenRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := lenRe.FindStringSubmatch(match)
		if len(parts) == 2 {
			if val, ok := variables[parts[1]]; ok {
				if strVal, ok := val.(string); ok {
					return strconv.Itoa(utf8.RuneCountInString(strVal))
				}
			}
		}
		return "0"
	})

	// Handle numeric literal comparisons: 22 > 3 (produced by len() expansion)
	numLitRe := regexcache.MustGet(`(\d+)\s*(==|!=|<=|>=|<|>)\s*(\d+)`)
	expr = numLitRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := numLitRe.FindStringSubmatch(match)
		if len(parts) == 4 {
			left, _ := strconv.Atoi(parts[1])
			op := parts[2]
			right, _ := strconv.Atoi(parts[3])
			var result bool
			switch op {
			case "==":
				result = left == right
			case "!=":
				result = left != right
			case "<":
				result = left < right
			case ">":
				result = left > right
			case "<=":
				result = left <= right
			case ">=":
				result = left >= right
			}
			if result {
				return "true"
			}
			return "false"
		}
		return "false"
	})

	// Replace numeric variable comparisons: status_code == 200
	numericRe := regexcache.MustGet(`(status_code|content_length)\s*(==|!=|<=|>=|<|>)\s*(\d+)`)
	expr = numericRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := numericRe.FindStringSubmatch(match)
		if len(parts) == 4 {
			varName := parts[1]
			op := parts[2]
			expected, _ := strconv.Atoi(parts[3])
			var actual int
			if varName == "status_code" {
				actual = data.StatusCode
			} else if varName == "content_length" {
				actual = int(data.ContentLength)
			}
			var result bool
			switch op {
			case "==":
				result = actual == expected
			case "!=":
				result = actual != expected
			case "<":
				result = actual < expected
			case ">":
				result = actual > expected
			case "<=":
				result = actual <= expected
			case ">=":
				result = actual >= expected
			}
			if result {
				return "true"
			}
			return "false"
		}
		return "false"
	})

	// Replace string variable comparisons: content_type == "text/html"
	stringRe := regexcache.MustGet(`(content_type|title|host|path|method|scheme|server|location)\s*(==|!=)\s*"([^"]+)"`)
	expr = stringRe.ReplaceAllStringFunc(expr, func(match string) string {
		parts := stringRe.FindStringSubmatch(match)
		if len(parts) == 4 {
			varName := parts[1]
			op := parts[2]
			expected := parts[3]
			actual := ""
			if val, ok := variables[varName]; ok {
				if strVal, ok := val.(string); ok {
					actual = strVal
				}
			}
			var result bool
			switch op {
			case "==":
				result = actual == expected
			case "!=":
				result = actual != expected
			}
			if result {
				return "true"
			}
			return "false"
		}
		return "false"
	})

	// Evaluate the boolean expression (true, false, &&, ||)
	expr = strings.ReplaceAll(expr, "&&", "&")
	expr = strings.ReplaceAll(expr, "||", "|")

	// Split by | (OR) first, then by & (AND)
	orParts := strings.Split(expr, "|")
	for _, orPart := range orParts {
		orPart = strings.TrimSpace(orPart)
		andParts := strings.Split(orPart, "&")
		allTrue := true
		for _, andPart := range andParts {
			andPart = strings.TrimSpace(andPart)
			if andPart == "false" || andPart == "" {
				allTrue = false
				break
			}
			if andPart != "true" {
				// Unrecognized expression, treat as false
				allTrue = false
				break
			}
		}
		if allTrue {
			return true
		}
	}
	return false
}
