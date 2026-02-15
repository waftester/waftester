package nuclei

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFlow(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		steps   int
		wantErr bool
	}{
		{"simple arrow", "login → dashboard → logout", 3, false},
		{"ascii arrow", "login -> dashboard", 2, false},
		{"single block", "probe", 1, false},
		{"conditional var", `login → if ($token != "") dashboard`, 2, false},
		{"conditional matcher", `probe → if (probe.matched) exploit`, 2, false},
		{"conditional else", `login → if ($role == "admin") admin_panel else user_panel`, 2, false},
		{"empty", "", 0, false},
		{"with hyphens", "get-token -> use-token", 2, false},
		{"bad condition", `if ($x != "y" foo`, 0, true},
		{"bad block", `123invalid`, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow, err := ParseFlow(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, flow.Steps, tt.steps)
		})
	}
}

func TestParseFlow_StepDetails(t *testing.T) {
	flow, err := ParseFlow(`login → if ($role == "admin") admin else user`)
	require.NoError(t, err)
	require.Len(t, flow.Steps, 2)

	// First step: simple block
	assert.Equal(t, "login", flow.Steps[0].BlockID)
	assert.Nil(t, flow.Steps[0].Condition)

	// Second step: conditional with else
	step := flow.Steps[1]
	assert.Equal(t, "admin", step.BlockID)
	assert.Equal(t, "user", step.ElseBlock)
	require.NotNil(t, step.Condition)
	assert.Equal(t, "role", step.Condition.Variable)
	assert.Equal(t, "==", step.Condition.Operator)
	assert.Equal(t, "admin", step.Condition.Value)
}

func TestParseFlow_MatcherCondition(t *testing.T) {
	flow, err := ParseFlow(`probe → if (probe.matched) exploit`)
	require.NoError(t, err)
	require.Len(t, flow.Steps, 2)

	step := flow.Steps[1]
	assert.Equal(t, "exploit", step.BlockID)
	require.NotNil(t, step.Condition)
	assert.Equal(t, "probe", step.Condition.MatcherRef)
}

func TestEvaluateCondition(t *testing.T) {
	vars := map[string]string{"token": "abc123", "role": "admin"}
	blocks := map[string]*BlockResult{
		"login": {Matched: true},
		"probe": {Matched: false},
	}

	tests := []struct {
		name   string
		cond   Condition
		expect bool
	}{
		{"var equals true", Condition{Variable: "role", Operator: "==", Value: "admin"}, true},
		{"var equals false", Condition{Variable: "role", Operator: "==", Value: "user"}, false},
		{"var not empty", Condition{Variable: "token", Operator: "!=", Value: ""}, true},
		{"var is empty", Condition{Variable: "token", Operator: "!=", Value: "abc123"}, false},
		{"var contains", Condition{Variable: "token", Operator: "contains", Value: "abc"}, true},
		{"var contains miss", Condition{Variable: "token", Operator: "contains", Value: "xyz"}, false},
		{"var matches", Condition{Variable: "token", Operator: "matches", Value: `^abc\d+$`}, true},
		{"var matches miss", Condition{Variable: "token", Operator: "matches", Value: `^xyz`}, false},
		{"matcher true", Condition{MatcherRef: "login"}, true},
		{"matcher false", Condition{MatcherRef: "probe"}, false},
		{"matcher missing", Condition{MatcherRef: "nonexistent"}, false},
		{"missing var equals", Condition{Variable: "missing", Operator: "==", Value: "x"}, false},
		{"missing var not equals", Condition{Variable: "missing", Operator: "!=", Value: "x"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, EvaluateCondition(&tt.cond, vars, blocks))
		})
	}
}

func TestParseCondition_Invalid(t *testing.T) {
	_, err := parseCondition("not a valid condition")
	assert.Error(t, err)
}

func TestIsIdentifier(t *testing.T) {
	assert.True(t, isIdentifier("login"))
	assert.True(t, isIdentifier("get_token"))
	assert.True(t, isIdentifier("step-1"))
	assert.True(t, isIdentifier("_private"))
	assert.False(t, isIdentifier(""))
	assert.False(t, isIdentifier("123"))
	assert.False(t, isIdentifier("has space"))
}
