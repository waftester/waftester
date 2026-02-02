package advanced

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCategoryConstants(t *testing.T) {
	assert.Equal(t, Category("encoding"), CategoryEncoding)
	assert.Equal(t, Category("protocol"), CategoryProtocol)
	assert.Equal(t, Category("timing"), CategoryTiming)
	assert.Equal(t, Category("chunked"), CategoryChunked)
	assert.Equal(t, Category("multipart"), CategoryMultipart)
	assert.Equal(t, Category("http_method"), CategoryHTTPMethod)
	assert.Equal(t, Category("header"), CategoryHeader)
	assert.Equal(t, Category("path"), CategoryPath)
	assert.Equal(t, Category("unicode"), CategoryUnicode)
}

func TestTechniqueString(t *testing.T) {
	tech := &Technique{ID: "test-technique"}
	assert.Equal(t, "test-technique", tech.String())
}

func TestTechniqueApply(t *testing.T) {
	tech := &Technique{
		ID:        "upper",
		Transform: strings.ToUpper,
	}

	result := tech.Apply("hello")
	assert.Equal(t, "HELLO", result)
}

func TestTechniqueApplyNilTransform(t *testing.T) {
	tech := &Technique{ID: "noop"}
	result := tech.Apply("hello")
	assert.Equal(t, "hello", result)
}

func TestTechniqueApplyHTTP(t *testing.T) {
	tech := &Technique{
		ID: "add-header",
		HTTPMod: func(req *http.Request) *http.Request {
			req.Header.Set("X-Test", "value")
			return req
		},
	}

	req, _ := http.NewRequest("GET", "/", nil)
	modified := tech.ApplyHTTP(req)
	assert.Equal(t, "value", modified.Header.Get("X-Test"))
}

func TestTechniqueApplyHTTPNil(t *testing.T) {
	tech := &Technique{ID: "noop"}
	req, _ := http.NewRequest("GET", "/", nil)
	result := tech.ApplyHTTP(req)
	assert.Equal(t, req, result)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.Equal(t, 4, config.MaxChainDepth)
	assert.Equal(t, 100, config.MaxVariants)
	assert.Equal(t, 50*time.Millisecond, config.TimingDelay)
	assert.True(t, config.EnableUnicode)
	assert.False(t, config.EnableHTTPSmug)
}

func TestNewEngine(t *testing.T) {
	engine := NewEngine(nil)
	assert.NotNil(t, engine)
	assert.NotEmpty(t, engine.techniques)
}

func TestEngineRegister(t *testing.T) {
	engine := NewEngine(nil)
	initialCount := len(engine.techniques)

	tech := &Technique{ID: "custom-technique", Enabled: true}
	engine.Register(tech)

	assert.Equal(t, initialCount+1, len(engine.techniques))
}

func TestEngineGet(t *testing.T) {
	engine := NewEngine(nil)

	tech, ok := engine.Get("double-url")
	assert.True(t, ok)
	assert.Equal(t, "double-url", tech.ID)

	_, ok = engine.Get("nonexistent")
	assert.False(t, ok)
}

func TestEngineList(t *testing.T) {
	engine := NewEngine(nil)
	techniques := engine.List()
	assert.NotEmpty(t, techniques)
}

func TestEngineListByCategory(t *testing.T) {
	engine := NewEngine(nil)

	encoding := engine.ListByCategory(CategoryEncoding)
	assert.NotEmpty(t, encoding)

	for _, tech := range encoding {
		assert.Equal(t, CategoryEncoding, tech.Category)
	}
}

func TestEngineApply(t *testing.T) {
	engine := NewEngine(nil)

	result, err := engine.Apply("double-url", "<script>")
	require.NoError(t, err)
	assert.NotEqual(t, "<script>", result)
}

func TestEngineApplyNotFound(t *testing.T) {
	engine := NewEngine(nil)

	_, err := engine.Apply("nonexistent", "test")
	assert.Error(t, err)
}

func TestEngineChain(t *testing.T) {
	engine := NewEngine(nil)

	result, err := engine.Chain("test", "double-url", "base64-wrap")
	require.NoError(t, err)
	assert.NotEqual(t, "test", result)
}

func TestEngineChainError(t *testing.T) {
	engine := NewEngine(nil)

	_, err := engine.Chain("test", "double-url", "nonexistent")
	assert.Error(t, err)
}

func TestGenerateVariants(t *testing.T) {
	engine := NewEngine(nil)

	variants := engine.GenerateVariants("<script>alert(1)</script>", 10)
	require.NotEmpty(t, variants)
	assert.LessOrEqual(t, len(variants), 10)

	// First should be original
	assert.Contains(t, variants[0].Techniques, "original")
}

func TestGenerateVariantsDefault(t *testing.T) {
	engine := NewEngine(&Config{
		MaxChainDepth: 2,
		MaxVariants:   5,
		ChunkSizes:    []int{2},
		EnableUnicode: true,
		RandomSeed:    42,
	})

	variants := engine.GenerateVariants("test", 0) // Use default
	assert.NotEmpty(t, variants)
}

func TestDoubleURLEncode(t *testing.T) {
	result := DoubleURLEncode("'")
	assert.Equal(t, "%2527", result)
}

func TestTripleURLEncode(t *testing.T) {
	result := TripleURLEncode("'")
	assert.Contains(t, result, "%25")
}

func TestMixedCaseURLEncode(t *testing.T) {
	// Test that encoding produces valid hex patterns
	result := MixedCaseURLEncode("<>")
	assert.Contains(t, strings.ToUpper(result), "%3C")
	assert.Contains(t, strings.ToUpper(result), "%3E")

	// Test that the output length is correct (each char becomes %XX = 3 chars)
	result = MixedCaseURLEncode("<")
	assert.Len(t, result, 3)
	assert.Equal(t, '%', rune(result[0]))

	// Test that over many iterations, we get both cases (testing randomness)
	// This is statistical - with 100 iterations, probability of all same case is 2^-100
	upperCount := 0
	lowerCount := 0
	for i := 0; i < 100; i++ {
		r := MixedCaseURLEncode("<")
		if r == "%3C" {
			upperCount++
		} else if r == "%3c" {
			lowerCount++
		} else {
			t.Fatalf("unexpected encoding: %q", r)
		}
	}
	// Both should have at least some occurrences (with very high probability)
	assert.Greater(t, upperCount, 0, "expected some uppercase encodings")
	assert.Greater(t, lowerCount, 0, "expected some lowercase encodings")

	// Test alphanumeric chars are not encoded
	result = MixedCaseURLEncode("abc123")
	assert.Equal(t, "abc123", result)

	// Test empty string
	result = MixedCaseURLEncode("")
	assert.Equal(t, "", result)
}

func TestOverlongUTF8(t *testing.T) {
	result := OverlongUTF8("A")
	assert.NotEqual(t, "A", result)
	assert.Len(t, result, 2) // Overlong encoding of ASCII
}

func TestUnicodeNormalizationBypass(t *testing.T) {
	result := UnicodeNormalizationBypass("<script>")
	assert.NotEqual(t, "<script>", result)
	assert.NotContains(t, result, "<")
}

func TestNullByteInject(t *testing.T) {
	result := NullByteInject("test")
	assert.Contains(t, result, "\x00")
}

func TestNullByteInjectShort(t *testing.T) {
	result := NullByteInject("a")
	assert.Contains(t, result, "\x00")
}

func TestBase64Wrap(t *testing.T) {
	result := Base64Wrap("test")
	assert.Equal(t, "dGVzdA==", result)
}

func TestPathTraversalDots(t *testing.T) {
	result := PathTraversalDots("../../etc/passwd")
	assert.Contains(t, result, "%2e%2e")
}

func TestPathNormalization(t *testing.T) {
	result := PathNormalization("/etc/passwd")
	assert.Contains(t, result, "//./")
}

func TestHeaderSplitting(t *testing.T) {
	result := HeaderSplitting("test")
	assert.Contains(t, result, "\r\n")
}

func TestHeaderFolding(t *testing.T) {
	result := HeaderFolding("This is a test header value")
	assert.Contains(t, result, "\r\n ")
}

func TestHeaderFoldingShort(t *testing.T) {
	result := HeaderFolding("short")
	assert.Equal(t, "short", result)
}

func TestChunkPayload(t *testing.T) {
	result := ChunkPayload("test", 2)
	assert.Contains(t, result, "2\r\n")
	assert.Contains(t, result, "0\r\n\r\n")
}

func TestChunkPayloadZeroSize(t *testing.T) {
	result := ChunkPayload("test", 0)
	assert.Contains(t, result, "1\r\n") // Falls back to size 1
}

func TestMethodOverride(t *testing.T) {
	req, _ := http.NewRequest("DELETE", "/", nil)
	modified := MethodOverride(req)

	assert.Equal(t, "POST", modified.Method)
	assert.Equal(t, "DELETE", modified.Header.Get("X-HTTP-Method-Override"))
}

func TestHTTPVersionMod(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	modified := HTTPVersionMod(req)

	assert.Equal(t, "HTTP/1.0", modified.Proto)
	assert.Equal(t, 1, modified.ProtoMajor)
	assert.Equal(t, 0, modified.ProtoMinor)
}

func TestNewChunkedEncoder(t *testing.T) {
	encoder := NewChunkedEncoder(4)
	assert.Equal(t, 4, encoder.ChunkSize)
}

func TestChunkedEncoderEncode(t *testing.T) {
	encoder := NewChunkedEncoder(4)
	data := []byte("testdata")

	result := encoder.Encode(data)
	assert.Contains(t, string(result), "4\r\n")
	assert.Contains(t, string(result), "0\r\n")
}

func TestChunkedEncoderWithExtensions(t *testing.T) {
	encoder := NewChunkedEncoder(4)
	encoder.Extensions["name"] = "value"

	result := encoder.Encode([]byte("test"))
	assert.Contains(t, string(result), ";name=value")
}

func TestChunkedEncoderWithTrailer(t *testing.T) {
	encoder := NewChunkedEncoder(4)
	encoder.Trailer = http.Header{"X-Checksum": []string{"abc123"}}

	result := encoder.Encode([]byte("test"))
	assert.Contains(t, string(result), "X-Checksum: abc123")
}

func TestChunkedEncoderReader(t *testing.T) {
	encoder := NewChunkedEncoder(4)
	reader := encoder.EncodeReader([]byte("test"))

	var buf bytes.Buffer
	buf.ReadFrom(reader)
	assert.NotEmpty(t, buf.Bytes())
}

func TestNewTimingAttack(t *testing.T) {
	ta := NewTimingAttack()
	assert.Equal(t, 50*time.Millisecond, ta.BetweenDelay)
}

func TestTimingAttackExecute(t *testing.T) {
	ta := NewTimingAttack()
	ta.BetweenDelay = 1 * time.Millisecond
	ta.RandomJitter = 0

	var sent []string
	err := ta.Execute([]string{"a", "b", "c"}, func(s string) error {
		sent = append(sent, s)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, sent)
}

func TestTimingAttackWithDelays(t *testing.T) {
	ta := NewTimingAttack()
	ta.InitialDelay = 1 * time.Millisecond
	ta.BetweenDelay = 1 * time.Millisecond
	ta.FinalDelay = 1 * time.Millisecond
	ta.RandomJitter = 0

	start := time.Now()
	err := ta.Execute([]string{"a", "b"}, func(s string) error {
		return nil
	})

	require.NoError(t, err)
	assert.GreaterOrEqual(t, time.Since(start), 3*time.Millisecond)
}

func TestNewHTTPSmuggling(t *testing.T) {
	sm := NewHTTPSmuggling("cl-te")
	assert.Equal(t, "cl-te", sm.Technique)
}

func TestHTTPSmugglingPrepareRequestCLTE(t *testing.T) {
	sm := NewHTTPSmuggling("cl-te")
	req, err := sm.PrepareRequest("payload")

	require.NoError(t, err)
	assert.Equal(t, "7", req.Header.Get("Content-Length"))
	assert.Equal(t, "chunked", req.Header.Get("Transfer-Encoding"))
}

func TestHTTPSmugglingPrepareRequestTECL(t *testing.T) {
	sm := NewHTTPSmuggling("te-cl")
	req, err := sm.PrepareRequest("payload")

	require.NoError(t, err)
	assert.Equal(t, "chunked", req.Header.Get("Transfer-Encoding"))
	assert.Equal(t, "0", req.Header.Get("Content-Length"))
}

func TestHTTPSmugglingPrepareRequestTETE(t *testing.T) {
	sm := NewHTTPSmuggling("te-te")
	req, err := sm.PrepareRequest("payload")

	require.NoError(t, err)
	assert.Len(t, req.Header["Transfer-Encoding"], 2)
}

func TestNewMultipartEvasion(t *testing.T) {
	mp := NewMultipartEvasion()
	assert.NotEmpty(t, mp.Boundary)
}

func TestMultipartEvasionBuildPart(t *testing.T) {
	mp := NewMultipartEvasion()
	part := mp.BuildPart("file", "test.txt", "content")

	assert.Contains(t, string(part), "name=\"file\"")
	assert.Contains(t, string(part), "filename=\"test.txt\"")
	assert.Contains(t, string(part), "content")
}

func TestMultipartEvasionWithOptions(t *testing.T) {
	mp := NewMultipartEvasion()
	mp.DoubleQuotes = true
	mp.ExtraHeaders = true

	part := mp.BuildPart("file", "test.txt", "content")
	assert.Contains(t, string(part), "Content-Type: application/octet-stream")
}

func TestMultipartEvasionNullInFilename(t *testing.T) {
	mp := NewMultipartEvasion()
	mp.NullInFilename = true

	part := mp.BuildPart("file", "test.txt", "content")
	assert.Contains(t, string(part), "\x00")
}

func TestMultipartEvasionLongFilename(t *testing.T) {
	mp := NewMultipartEvasion()
	mp.LongFilename = true

	part := mp.BuildPart("file", "test.txt", "content")
	assert.True(t, len(part) > 250)
}

func TestMultipartEvasionFinalize(t *testing.T) {
	mp := NewMultipartEvasion()
	part := mp.BuildPart("field", "", "value")
	body := mp.Finalize([][]byte{part})

	assert.Contains(t, string(body), "--"+mp.Boundary+"--")
}

func TestMultipartEvasionContentType(t *testing.T) {
	mp := NewMultipartEvasion()
	ct := mp.ContentType()

	assert.Contains(t, ct, "multipart/form-data")
	assert.Contains(t, ct, "boundary=")
}

func TestShouldEncode(t *testing.T) {
	assert.False(t, shouldEncode('A'))
	assert.False(t, shouldEncode('z'))
	assert.False(t, shouldEncode('0'))
	assert.False(t, shouldEncode('-'))
	assert.True(t, shouldEncode('<'))
	assert.True(t, shouldEncode(' '))
}

func TestRandomString(t *testing.T) {
	s1 := randomString(10)
	s2 := randomString(10)

	assert.Len(t, s1, 10)
	assert.Len(t, s2, 10)
	// Random strings should be different (very high probability)
}

func TestGenerateChains(t *testing.T) {
	engine := NewEngine(&Config{
		MaxChainDepth: 3,
		RandomSeed:    42,
	})

	chains := engine.generateChains(2)
	assert.NotEmpty(t, chains)

	for _, chain := range chains {
		assert.Len(t, chain, 2)
	}
}
