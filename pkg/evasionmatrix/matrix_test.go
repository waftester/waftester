package evasionmatrix

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatrixGeneration(t *testing.T) {
	matrix := New().
		Payloads("' OR 1=1--", "<script>alert(1)</script>").
		Encoders("plain", "url", "base64").
		Placeholders("url-param", "header").
		Build()

	// 2 payloads × 3 encoders × 2 placeholders = 12 tests
	assert.Equal(t, 12, matrix.Count())
}

func TestMatrixIteration(t *testing.T) {
	matrix := New().
		Payloads("test").
		Encoders("plain").
		Placeholders("url-param").
		Build()

	tests := matrix.Tests()
	require.Len(t, tests, 1)
	assert.Equal(t, "test", tests[0].Payload)
	assert.Equal(t, "plain", tests[0].EncoderName)
	assert.Equal(t, "url-param", tests[0].PlaceholderName)
}

func TestMatrixEncodedPayload(t *testing.T) {
	matrix := New().
		Payloads("<script>").
		Encoders("url").
		Placeholders("url-param").
		Build()

	tests := matrix.Tests()
	require.Len(t, tests, 1)
	assert.Equal(t, "%3Cscript%3E", tests[0].EncodedPayload)
}

func TestMatrixTestID(t *testing.T) {
	matrix := New().
		Payloads("test1", "test2").
		Encoders("plain", "url").
		Placeholders("header").
		Build()

	tests := matrix.Tests()
	// Each test should have unique ID
	ids := make(map[string]bool)
	for _, test := range tests {
		assert.NotEmpty(t, test.ID)
		assert.False(t, ids[test.ID], "Duplicate ID: %s", test.ID)
		ids[test.ID] = true
	}
}

func TestMatrixFromCategories(t *testing.T) {
	matrix := NewFromCategories([]string{"sqli", "xss"})
	assert.Greater(t, matrix.Count(), 0)
}

func TestMatrixConcurrentSafe(t *testing.T) {
	matrix := New().
		Payloads("a", "b", "c").
		Encoders("plain", "url").
		Placeholders("url-param", "header", "cookie").
		Build()

	// Should be safe to iterate concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for _, test := range matrix.Tests() {
				_ = test.ID
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMatrixTestsChan(t *testing.T) {
	matrix := New().
		Payloads("a", "b").
		Encoders("plain").
		Placeholders("url-param").
		Build()

	count := 0
	for range matrix.TestsChan() {
		count++
	}
	assert.Equal(t, 2, count)
}

func TestDefaultMatrix(t *testing.T) {
	matrix := DefaultMatrix()
	// 4 payloads × 5 encoders × 5 placeholders = 100 tests
	assert.Equal(t, 100, matrix.Count())
}

func TestFullMatrix(t *testing.T) {
	matrix := FullMatrix()
	// Should have many tests (50 payloads × 18 encoders × 17 placeholders)
	assert.Greater(t, matrix.Count(), 1000)
}

func TestMatrixFilter(t *testing.T) {
	matrix := New().
		Payloads("sqli1", "xss1").
		Encoders("plain", "url").
		Placeholders("url-param").
		Categories("sqli").
		Build()

	filtered := matrix.Filter(func(test Test) bool {
		return test.EncoderName == "url"
	})

	assert.Equal(t, 2, filtered.Count())
	for _, test := range filtered.Tests() {
		assert.Equal(t, "url", test.EncoderName)
	}
}

func TestMatrixStats(t *testing.T) {
	matrix := New().
		Payloads("a", "b", "c").
		Encoders("plain", "url").
		Placeholders("url-param", "header").
		Categories("test").
		Build()

	stats := matrix.Stats()
	assert.Equal(t, 12, stats.TotalTests)
	assert.Equal(t, 3, stats.Payloads)
	assert.Equal(t, 2, stats.Encoders)
	assert.Equal(t, 2, stats.Placeholders)
	assert.Equal(t, 1, stats.Categories)
}

func TestExecutableTests(t *testing.T) {
	matrix := New().
		Payloads("<script>").
		Encoders("url").
		Placeholders("url-param").
		Build()

	execs := matrix.ExecutableTests("https://example.com/", nil)
	require.Len(t, execs, 1)
	assert.Equal(t, "https://example.com/", execs[0].TargetURL)

	req, err := execs[0].ToRequest(context.Background())
	require.NoError(t, err)
	// The encoded payload is URL-encoded, and the placeholder may URL-encode again
	assert.Contains(t, req.URL.String(), "script")
}

func TestExecutableTestInvalidPlaceholder(t *testing.T) {
	exec := ExecutableTest{
		Test: Test{
			PlaceholderName: "nonexistent",
			EncodedPayload:  "test",
		},
		TargetURL: "https://example.com/",
	}

	_, err := exec.ToRequest(context.Background())
	assert.Error(t, err)
}

func TestAllEncodersBuilder(t *testing.T) {
	matrix := New().
		Payloads("test").
		AllEncoders().
		Placeholders("url-param").
		Build()

	// Should have at least 15 encoders
	assert.GreaterOrEqual(t, matrix.Count(), 15)
}

func TestAllPlaceholdersBuilder(t *testing.T) {
	matrix := New().
		Payloads("test").
		Encoders("plain").
		AllPlaceholders().
		Build()

	// Should have at least 15 placeholders
	assert.GreaterOrEqual(t, matrix.Count(), 15)
}

func TestGetCategoryPayloads(t *testing.T) {
	sqli := GetCategoryPayloads("sqli")
	assert.GreaterOrEqual(t, len(sqli), 5)

	xss := GetCategoryPayloads("xss")
	assert.GreaterOrEqual(t, len(xss), 5)

	lfi := GetCategoryPayloads("lfi")
	assert.GreaterOrEqual(t, len(lfi), 5)

	rce := GetCategoryPayloads("rce")
	assert.GreaterOrEqual(t, len(rce), 5)

	ssrf := GetCategoryPayloads("ssrf")
	assert.GreaterOrEqual(t, len(ssrf), 5)

	// Unknown category should return empty
	unknown := GetCategoryPayloads("unknown")
	assert.Empty(t, unknown)
}

func TestMatrixDefaultEncoders(t *testing.T) {
	matrix := New().
		Payloads("test").
		Placeholders("url-param").
		Build()

	tests := matrix.Tests()
	require.Len(t, tests, 1)
	assert.Equal(t, "plain", tests[0].EncoderName)
}

func TestMatrixDefaultPlaceholders(t *testing.T) {
	matrix := New().
		Payloads("test").
		Encoders("plain").
		Build()

	tests := matrix.Tests()
	require.Len(t, tests, 1)
	assert.Equal(t, "url-param", tests[0].PlaceholderName)
}

func TestMatrixCategory(t *testing.T) {
	matrix := New().
		Payloads("test").
		Encoders("plain").
		Placeholders("url-param").
		Categories("sqli").
		Build()

	tests := matrix.Tests()
	require.Len(t, tests, 1)
	assert.Equal(t, "sqli", tests[0].Category)
}

func TestGenerateTestID(t *testing.T) {
	id1 := generateTestID("payload1", "enc1", "ph1")
	id2 := generateTestID("payload1", "enc1", "ph1")
	id3 := generateTestID("payload2", "enc1", "ph1")

	// Same inputs should produce same ID
	assert.Equal(t, id1, id2)
	// Different inputs should produce different ID
	assert.NotEqual(t, id1, id3)
	// ID should be 16 characters
	assert.Len(t, id1, 16)
}
