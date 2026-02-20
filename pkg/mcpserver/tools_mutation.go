package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ═══════════════════════════════════════════════════════════════════════════
// mutate — Payload Mutation & Encoding
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addMutateTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "mutate",
			Title: "Mutate Payloads",
			Description: `Encode a payload string into WAF-evasion variants — URL, double-URL, Unicode, HTML hex. Offline encoding, no network traffic.

USE THIS TOOL WHEN:
• A payload was blocked and the user wants to see how it looks in different encodings
• The user says "encode this", "mutate this payload", or "show me evasion variants"
• Inspecting what the mutation matrix would produce before testing live with 'bypass'
• Preparing payloads for manual testing in Burp Suite or curl

DO NOT USE THIS TOOL WHEN:
• You want to also TEST the mutations against a WAF — use 'bypass' instead (it mutates AND tests)
• You want to scan a target — use 'scan' instead
• You want to browse the payload catalog — use 'list_payloads' instead

'mutate' vs 'bypass': mutate is offline — it shows you what the encodings look like. bypass is online — it encodes AND fires them at a target to find what passes. mutate = preview, bypass = execute.

EXAMPLE INPUTS:
• URL-encode a SQLi payload: {"payload": "' OR 1=1--", "encoders": ["url"]}
• Try multiple encodings: {"payload": "<script>alert(1)</script>", "encoders": ["url", "double_url", "unicode", "html_hex"]}
• All available encoders: {"payload": "{{7*7}}"}
• HTML hex encoding: {"payload": "<img src=x onerror=alert(1)>", "encoders": ["html_hex"]}

AVAILABLE ENCODERS: url, double_url, unicode, html_hex
If encoders is omitted, ALL are applied.

Returns: list of {encoder, encoded_payload} pairs ready for copy-paste testing.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"payload": map[string]any{
						"type":        "string",
						"description": "The attack payload string to mutate (e.g. \"' OR 1=1--\").",
					},
					"encoders": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "string",
							"enum": []string{"url", "double_url", "unicode", "html_hex"},
						},
						"description": "Encoders to apply. Default: all available encoders.",
					},
				},
				"required": []string{"payload"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Mutate Payloads",
			},
		},
		loggedTool("mutate", s.handleMutate),
	)
}

type mutateArgs struct {
	Payload  string   `json:"payload"`
	Encoders []string `json:"encoders"`
}

type mutateResult struct {
	Summary   string          `json:"summary"`
	Original  string          `json:"original"`
	Variants  []mutateVariant `json:"variants"`
	Count     int             `json:"count"`
	Tip       string          `json:"tip"`
	NextSteps []string        `json:"next_steps"`
}

type mutateVariant struct {
	Encoder string `json:"encoder"`
	Encoded string `json:"encoded"`
}

func (s *Server) handleMutate(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args mutateArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Payload == "" {
		return errorResult("payload is required. Example: {\"payload\": \"' OR 1=1--\"}"), nil
	}

	variants := applyBasicEncodings(args.Payload, args.Encoders)

	encoderList := make([]string, len(variants))
	for i, v := range variants {
		encoderList[i] = v.Encoder
	}

	result := mutateResult{
		Summary:  fmt.Sprintf("Generated %d encoded variants of the payload using: %s. Each variant applies a different encoding to bypass WAF pattern matching.", len(variants), strings.Join(encoderList, ", ")),
		Original: args.Payload,
		Variants: variants,
		Count:    len(variants),
		Tip:      "If double_url bypasses the WAF, it only decodes once. If unicode or html_hex bypasses, the WAF lacks multi-encoding support. Use the 'bypass' tool for automated testing of all mutations against a live target.",
		NextSteps: []string{
			fmt.Sprintf("Use 'bypass' with {\"target\": \"https://your-target.com\", \"payloads\": [\"%s\"]} to test all mutations against a live WAF.", args.Payload),
			"Copy individual variants above into Burp Suite Repeater or curl for manual verification.",
			"Try combining encodings: URL-encode a Unicode variant, or double-encode HTML hex — WAFs often fail on multi-layer encoding.",
			"Use 'list_payloads' to find more payloads in the same attack category for broader testing.",
		},
	}

	return jsonResult(result)
}

// applyBasicEncodings applies common encoding transformations to a payload.
func applyBasicEncodings(payload string, encoders []string) []mutateVariant {
	if len(encoders) == 0 {
		encoders = []string{"url", "double_url", "unicode", "html_hex"}
	}

	encSet := make(map[string]bool)
	for _, e := range encoders {
		encSet[strings.ToLower(e)] = true
	}

	var variants []mutateVariant

	if encSet["url"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "%%%02X", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "url", Encoded: sb.String()})
	}

	if encSet["double_url"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				hex := fmt.Sprintf("%%%02X", r)
				for _, c := range hex {
					if c == '%' {
						sb.WriteString("%25")
					} else {
						sb.WriteRune(c)
					}
				}
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "double_url", Encoded: sb.String()})
	}

	if encSet["unicode"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "\\u%04X", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "unicode", Encoded: sb.String()})
	}

	if encSet["html_hex"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "&#x%X;", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "html_hex", Encoded: sb.String()})
	}

	return variants
}

func shouldURLEncode(r rune) bool {
	switch r {
	case '<', '>', '\'', '"', '(', ')', '{', '}', '[', ']', ';', '|', '&', '=', ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}
