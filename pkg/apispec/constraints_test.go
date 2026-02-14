package apispec

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateConstraintAttacks_NoConstraints(t *testing.T) {
	attacks := GenerateConstraintAttacks("name", SchemaInfo{Type: "string"})
	assert.Empty(t, attacks)
}

func TestGenerateConstraintAttacks_MaxLength(t *testing.T) {
	max := 50
	attacks := GenerateConstraintAttacks("username", SchemaInfo{
		Type:      "string",
		MaxLength: &max,
	})

	require.Len(t, attacks, 4)

	// Verify overflow by 1.
	assert.Equal(t, "maxLength", attacks[0].ConstraintType)
	assert.Len(t, attacks[0].Payload, 51)
	assert.Equal(t, "inputvalidation", attacks[0].Category)

	// Verify overflow by 10x.
	assert.Len(t, attacks[1].Payload, 500)

	// SQLi padded.
	assert.Equal(t, "sqli", attacks[2].Category)
	assert.True(t, strings.HasSuffix(attacks[2].Payload, "' OR 1=1--"))
	assert.Len(t, attacks[2].Payload, 51)

	// XSS padded.
	assert.Equal(t, "xss", attacks[3].Category)
	assert.Contains(t, attacks[3].Payload, "<script>")
}

func TestGenerateConstraintAttacks_Enum(t *testing.T) {
	attacks := GenerateConstraintAttacks("status", SchemaInfo{
		Enum: []string{"active", "inactive", "pending"},
	})

	require.Len(t, attacks, 3)

	assert.Equal(t, "inputvalidation", attacks[0].Category)
	assert.Equal(t, "__INVALID_ENUM_VALUE__", attacks[0].Payload)

	assert.Equal(t, "", attacks[1].Payload) // empty string

	assert.Equal(t, "sqli", attacks[2].Category)
	assert.True(t, strings.HasPrefix(attacks[2].Payload, "active"))
}

func TestGenerateConstraintAttacks_Pattern(t *testing.T) {
	attacks := GenerateConstraintAttacks("code", SchemaInfo{
		Pattern: "^[A-Z]{3}$",
	})

	require.Len(t, attacks, 3)

	for _, a := range attacks {
		assert.Equal(t, "pattern", a.ConstraintType)
		assert.Contains(t, a.Purpose, "pattern")
	}

	assert.Equal(t, "sqli", attacks[2].Category)
}

func TestGenerateConstraintAttacks_NumericBoundary(t *testing.T) {
	min := float64(0)
	max := float64(100)
	attacks := GenerateConstraintAttacks("age", SchemaInfo{
		Type:    "integer",
		Minimum: &min,
		Maximum: &max,
	})

	// 4 universal + 2 bound-specific + 1 SQLi = 7
	require.Len(t, attacks, 7)

	// Check MAX_INT.
	var foundMaxInt bool
	for _, a := range attacks {
		if strings.Contains(a.Payload, "9223372036854775807") {
			foundMaxInt = true
			assert.Equal(t, "inputvalidation", a.Category)
		}
	}
	assert.True(t, foundMaxInt, "expected MAX_INT attack")

	// Check below minimum.
	var foundBelowMin bool
	for _, a := range attacks {
		if a.Payload == "-1" && a.Purpose == "below minimum=0" {
			foundBelowMin = true
		}
	}
	assert.True(t, foundBelowMin, "expected below-minimum attack")

	// Check above maximum.
	var foundAboveMax bool
	for _, a := range attacks {
		if a.Payload == "101" && strings.Contains(a.Purpose, "above maximum") {
			foundAboveMax = true
		}
	}
	assert.True(t, foundAboveMax, "expected above-maximum attack")

	// SQLi.
	assert.Equal(t, "sqli", attacks[len(attacks)-1].Category)
}

func TestGenerateConstraintAttacks_NumericNoBounds(t *testing.T) {
	attacks := GenerateConstraintAttacks("count", SchemaInfo{Type: "integer"})

	// 4 universal + 1 SQLi = 5
	require.Len(t, attacks, 5)
}

func TestGenerateConstraintAttacks_FormatEmail(t *testing.T) {
	attacks := GenerateConstraintAttacks("email", SchemaInfo{
		Type:   "string",
		Format: "email",
	})

	require.Len(t, attacks, 4)

	categories := make(map[string]bool)
	for _, a := range attacks {
		categories[a.Category] = true
		assert.Contains(t, a.Payload, "@")
	}

	assert.True(t, categories["xss"])
	assert.True(t, categories["sqli"])
	assert.True(t, categories["ssti"])
	assert.True(t, categories["crlf"])
}

func TestGenerateConstraintAttacks_FormatURI(t *testing.T) {
	attacks := GenerateConstraintAttacks("callback", SchemaInfo{
		Type:   "string",
		Format: "uri",
	})

	require.Len(t, attacks, 4)

	var hasMetadata, hasFile bool
	for _, a := range attacks {
		if strings.Contains(a.Payload, "169.254.169.254") {
			hasMetadata = true
		}
		if strings.Contains(a.Payload, "file://") {
			hasFile = true
		}
	}
	assert.True(t, hasMetadata)
	assert.True(t, hasFile)
}

func TestGenerateConstraintAttacks_FormatDate(t *testing.T) {
	attacks := GenerateConstraintAttacks("created_at", SchemaInfo{
		Type:   "string",
		Format: "date-time",
	})
	require.Len(t, attacks, 3)
	assert.Equal(t, "sqli", attacks[0].Category)
}

func TestGenerateConstraintAttacks_FormatUUID(t *testing.T) {
	attacks := GenerateConstraintAttacks("id", SchemaInfo{
		Type:   "string",
		Format: "uuid",
	})
	require.Len(t, attacks, 2)
	assert.Equal(t, "sqli", attacks[0].Category)
}

func TestGenerateConstraintAttacks_FormatIPv4(t *testing.T) {
	attacks := GenerateConstraintAttacks("ip", SchemaInfo{
		Type:   "string",
		Format: "ipv4",
	})
	require.Len(t, attacks, 3)

	categories := make(map[string]bool)
	for _, a := range attacks {
		categories[a.Category] = true
	}
	assert.True(t, categories["ssrf"])
	assert.True(t, categories["cmdi"])
}

func TestGenerateConstraintAttacks_TypeConfusionBoolean(t *testing.T) {
	attacks := GenerateConstraintAttacks("is_admin", SchemaInfo{Type: "boolean"})
	require.Len(t, attacks, 2)
	assert.Equal(t, "yes", attacks[0].Payload)
	assert.Equal(t, "2", attacks[1].Payload)
}

func TestGenerateConstraintAttacks_TypeConfusionArray(t *testing.T) {
	attacks := GenerateConstraintAttacks("tags", SchemaInfo{Type: "array"})
	require.Len(t, attacks, 2)
	assert.Equal(t, "nosqli", attacks[1].Category)
}

func TestGenerateConstraintAttacks_TypeConfusionObject(t *testing.T) {
	attacks := GenerateConstraintAttacks("data", SchemaInfo{Type: "object"})
	require.Len(t, attacks, 2)
	assert.Equal(t, "prototype", attacks[0].Category)
}

func TestGenerateEndpointConstraintAttacks(t *testing.T) {
	max := 10
	ep := Endpoint{
		Parameters: []Parameter{
			{Name: "q", Schema: SchemaInfo{Type: "string", MaxLength: &max}},
		},
		RequestBodies: map[string]RequestBody{
			"application/json": {
				Schema: SchemaInfo{
					Properties: map[string]SchemaInfo{
						"email": {Type: "string", Format: "email"},
					},
				},
			},
		},
	}

	attacks := GenerateEndpointConstraintAttacks(ep)
	assert.NotEmpty(t, attacks)

	// Should have attacks from both parameter and body field.
	var fromQ, fromEmail bool
	for _, a := range attacks {
		if a.ParamName == "q" {
			fromQ = true
		}
		if a.ParamName == "email" {
			fromEmail = true
		}
	}
	assert.True(t, fromQ, "expected attacks from parameter 'q'")
	assert.True(t, fromEmail, "expected attacks from body field 'email'")
}

func TestGenerateConstraintAttacks_AllFieldsSet(t *testing.T) {
	// Every generated attack must have all required fields populated.
	max := 20
	schemas := []SchemaInfo{
		{Type: "string", MaxLength: &max},
		{Enum: []string{"a", "b"}},
		{Pattern: "^[0-9]+$"},
		{Type: "integer"},
		{Type: "string", Format: "email"},
		{Type: "string", Format: "uri"},
		{Type: "boolean"},
		{Type: "array"},
		{Type: "object"},
	}

	for _, s := range schemas {
		attacks := GenerateConstraintAttacks("test", s)
		for i, a := range attacks {
			assert.NotEmpty(t, a.ParamName, "attack %d missing ParamName", i)
			assert.NotEmpty(t, a.ConstraintType, "attack %d missing ConstraintType", i)
			assert.NotEmpty(t, a.Purpose, "attack %d missing Purpose", i)
			assert.NotEmpty(t, a.Category, "attack %d missing Category", i)
			// Payload can be empty (enum empty string test).
		}
	}
}

func TestPadPayload(t *testing.T) {
	result := padPayload("test", 10)
	assert.Len(t, result, 10)
	assert.True(t, strings.HasSuffix(result, "test"))

	// Payload already longer than target.
	result = padPayload("long payload here", 5)
	assert.Equal(t, "long payload here", result)
}

func TestGenerateConstraintAttacks_MaxLengthZero(t *testing.T) {
	zero := 0
	attacks := GenerateConstraintAttacks("f", SchemaInfo{MaxLength: &zero})
	assert.Empty(t, attacks, "maxLength=0 should generate no attacks")
}

func TestNumericBoundaryAttacks_NumberType(t *testing.T) {
	attacks := GenerateConstraintAttacks("price", SchemaInfo{Type: "number"})
	require.NotEmpty(t, attacks)
	assert.Contains(t, attacks[0].Payload, "-1")
}

func TestNumericBoundaryAttacks_MaxIntValue(t *testing.T) {
	attacks := GenerateConstraintAttacks("id", SchemaInfo{Type: "integer"})
	var found bool
	for _, a := range attacks {
		if a.Payload == "9223372036854775807" {
			found = true
			assert.Equal(t, int64(math.MaxInt64), int64(9223372036854775807))
		}
	}
	assert.True(t, found)
}
