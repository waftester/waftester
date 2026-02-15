package nuclei

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

// Flow is a parsed sequence of execution steps.
type Flow struct {
	Steps []FlowStep
}

// FlowStep is one step in the execution flow.
type FlowStep struct {
	BlockID   string     // Block to execute
	Condition *Condition // If set, execute only when condition is true
	ElseBlock string     // If condition is false, execute this block instead
}

// Condition controls whether a step executes.
type Condition struct {
	// Variable comparison: $varname op "value"
	Variable string // variable name (without $)
	Operator string // ==, !=, contains, matches
	Value    string // comparison value

	// Matcher reference: blockid.matched
	MatcherRef string // block ID to check .Matched on
}

// ParseFlow parses a flow DSL string into a Flow.
//
// Grammar:
//
//	flow       = step ("→" step)*
//	step       = block_ref | conditional
//	conditional = "if" "(" expr ")" block_ref ("else" block_ref)?
//	block_ref  = identifier
//	expr       = var_check | matcher_check
//	var_check  = "$" identifier op value
//	matcher_check = identifier ".matched"
//	op         = "==" | "!=" | "contains" | "matches"
func ParseFlow(input string) (*Flow, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return &Flow{}, nil
	}

	// Normalize arrow separators
	input = strings.ReplaceAll(input, "→", "->")
	parts := strings.Split(input, "->")

	flow := &Flow{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		step, err := parseStep(part)
		if err != nil {
			return nil, err
		}
		flow.Steps = append(flow.Steps, step)
	}
	return flow, nil
}

func parseStep(s string) (FlowStep, error) {
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "if") && len(s) > 2 && !isIdentChar(rune(s[2])) {
		return parseConditional(s)
	}

	if !isIdentifier(s) {
		return FlowStep{}, fmt.Errorf("invalid block reference: %q", s)
	}
	return FlowStep{BlockID: s}, nil
}

// parseConditional parses: if ($var op "val") block (else block)?
// or: if (block.matched) block (else block)?
func parseConditional(s string) (FlowStep, error) {
	openParen := strings.Index(s, "(")
	closeParen := strings.LastIndex(s, ")")
	if openParen == -1 || closeParen == -1 || closeParen <= openParen {
		return FlowStep{}, fmt.Errorf("malformed conditional: %q", s)
	}

	condStr := strings.TrimSpace(s[openParen+1 : closeParen])
	rest := strings.TrimSpace(s[closeParen+1:])

	restParts := strings.Fields(rest)
	if len(restParts) == 0 {
		return FlowStep{}, fmt.Errorf("conditional missing block reference: %q", s)
	}

	step := FlowStep{BlockID: restParts[0]}

	if len(restParts) >= 3 && restParts[1] == "else" {
		step.ElseBlock = restParts[2]
	}

	cond, err := parseCondition(condStr)
	if err != nil {
		return FlowStep{}, err
	}
	step.Condition = cond

	return step, nil
}

var matcherRefRe = regexp.MustCompile(`^(\w+)\.matched$`)
var varCheckRe = regexp.MustCompile(`^\$(\w+)\s*(==|!=|contains|matches)\s*"([^"]*)"$`)

func parseCondition(s string) (*Condition, error) {
	s = strings.TrimSpace(s)

	if m := matcherRefRe.FindStringSubmatch(s); m != nil {
		return &Condition{MatcherRef: m[1]}, nil
	}

	if m := varCheckRe.FindStringSubmatch(s); m != nil {
		return &Condition{
			Variable: m[1],
			Operator: m[2],
			Value:    m[3],
		}, nil
	}

	return nil, fmt.Errorf("unparseable condition: %q", s)
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if i == 0 && !isLetter(c) && c != '_' {
			return false
		}
		if !isIdentChar(c) {
			return false
		}
	}
	return true
}

func isIdentChar(c rune) bool {
	return isLetter(c) || isDigit(c) || c == '_' || c == '-'
}

func isLetter(c rune) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c rune) bool  { return c >= '0' && c <= '9' }

// EvaluateCondition checks if a condition is met given current variables and block results.
func EvaluateCondition(cond *Condition, vars map[string]string, blockResults map[string]*BlockResult) bool {
	if cond.MatcherRef != "" {
		br, ok := blockResults[cond.MatcherRef]
		return ok && br.Matched
	}

	val, exists := vars[cond.Variable]
	switch cond.Operator {
	case "==":
		return exists && val == cond.Value
	case "!=":
		return !exists || val != cond.Value
	case "contains":
		return exists && strings.Contains(val, cond.Value)
	case "matches":
		if !exists {
			return false
		}
		re, err := regexcache.Get(cond.Value)
		if err != nil {
			return false
		}
		return re.MatchString(val)
	}
	return false
}
