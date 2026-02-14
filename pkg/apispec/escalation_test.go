package apispec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEscalationLevel_String(t *testing.T) {
	tests := []struct {
		level EscalationLevel
		want  string
	}{
		{EscalationStandard, "standard"},
		{EscalationEncoded, "encoded"},
		{EscalationWAFSpecific, "waf-specific"},
		{EscalationMultiVector, "multi-vector"},
		{EscalationLevel(99), "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.level.String())
	}
}

func TestEscalationLevel_Encoders(t *testing.T) {
	tests := []struct {
		level    EscalationLevel
		minCount int
	}{
		{EscalationStandard, 1},
		{EscalationEncoded, 4},
		{EscalationWAFSpecific, 6},
		{EscalationMultiVector, 8},
	}
	for _, tt := range tests {
		encoders := tt.level.Encoders()
		assert.GreaterOrEqual(t, len(encoders), tt.minCount,
			"level %s should have at least %d encoders", tt.level, tt.minCount)
		// Every level includes plain.
		assert.Contains(t, encoders, "plain")
	}
}

func TestSelectEscalationLevel(t *testing.T) {
	tests := []struct {
		name        string
		blockRate   float64
		wafDetected bool
		want        EscalationLevel
	}{
		{"nothing blocked, no waf", 0.0, false, EscalationStandard},
		{"nothing blocked, waf detected", 0.0, true, EscalationStandard},
		{"low block rate", 0.3, false, EscalationEncoded},
		{"medium block rate, no waf", 0.7, false, EscalationEncoded},
		{"medium block rate, waf", 0.7, true, EscalationWAFSpecific},
		{"high block rate, no waf", 0.95, false, EscalationWAFSpecific},
		{"high block rate, waf", 0.95, true, EscalationMultiVector},
		{"all blocked, waf", 1.0, true, EscalationMultiVector},
		{"all blocked, no waf", 1.0, false, EscalationWAFSpecific},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SelectEscalationLevel(tt.blockRate, tt.wafDetected)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestShouldEscalate(t *testing.T) {
	tests := []struct {
		name      string
		level     EscalationLevel
		blockRate float64
		want      bool
	}{
		{"standard, low rate", EscalationStandard, 0.5, false},
		{"standard, high rate", EscalationStandard, 0.85, true},
		{"encoded, high rate", EscalationEncoded, 0.9, true},
		{"multi-vector, high rate", EscalationMultiVector, 1.0, false}, // max
		{"standard, exactly 0.8", EscalationStandard, 0.8, true},
		{"standard, below 0.8", EscalationStandard, 0.79, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldEscalate(tt.level, tt.blockRate)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRequestBudget_Allows(t *testing.T) {
	t.Run("nil budget allows everything", func(t *testing.T) {
		var b *RequestBudget
		assert.True(t, b.Allows(99999, time.Hour))
	})

	t.Run("max total exceeded", func(t *testing.T) {
		b := &RequestBudget{MaxTotal: 100}
		assert.True(t, b.Allows(99, 0))
		assert.False(t, b.Allows(100, 0))
	})

	t.Run("time limit exceeded", func(t *testing.T) {
		b := &RequestBudget{TimeLimit: 5 * time.Second}
		assert.True(t, b.Allows(0, 4*time.Second))
		assert.False(t, b.Allows(0, 6*time.Second))
	})

	t.Run("no limits", func(t *testing.T) {
		b := &RequestBudget{}
		assert.True(t, b.Allows(99999, time.Hour))
	})
}

func TestRequestBudget_AllowsForEndpoint(t *testing.T) {
	t.Run("nil budget allows", func(t *testing.T) {
		var b *RequestBudget
		assert.True(t, b.AllowsForEndpoint(99999))
	})

	t.Run("per endpoint exceeded", func(t *testing.T) {
		b := &RequestBudget{MaxPerEndpoint: 50}
		assert.True(t, b.AllowsForEndpoint(49))
		assert.False(t, b.AllowsForEndpoint(50))
	})
}

func TestNewScanState(t *testing.T) {
	s := NewScanState()
	assert.NotNil(t, s)
	assert.NotNil(t, s.CSRFTokens)
	assert.NotNil(t, s.AuthTokens)
	assert.NotNil(t, s.ExtractedVars)
	assert.Nil(t, s.BlockSignature)
}

func TestBlockSignature(t *testing.T) {
	bs := &BlockSignature{
		StatusCodes:  []int{403, 406},
		BodyPatterns: []string{"access denied", "request blocked"},
	}
	assert.Equal(t, 2, len(bs.StatusCodes))
	assert.Equal(t, 2, len(bs.BodyPatterns))
}

func TestFingerprintResult(t *testing.T) {
	fp := &FingerprintResult{
		WAFDetected:    true,
		WAFVendor:      "cloudflare",
		WAFConfidence:  0.95,
		BaselineStatus: 200,
		BaselineSize:   4096,
		HTTP2Supported: true,
	}
	assert.True(t, fp.WAFDetected)
	assert.Equal(t, "cloudflare", fp.WAFVendor)
	assert.Equal(t, 200, fp.BaselineStatus)
}

func TestProbeResult(t *testing.T) {
	pr := &ProbeResult{
		BlockRate:       0.6,
		TotalProbes:     10,
		BlockedProbes:   6,
		EscalationLevel: EscalationEncoded,
		PerCategoryBlockRate: map[string]float64{
			"sqli": 0.8,
			"xss":  0.4,
		},
	}
	assert.Equal(t, 0.6, pr.BlockRate)
	assert.Equal(t, EscalationEncoded, pr.EscalationLevel)
	assert.Equal(t, 0.8, pr.PerCategoryBlockRate["sqli"])
}
