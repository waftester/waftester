package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLEncoder(t *testing.T) {
	enc := Get("url")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>alert(1)</script>")
	require.NoError(t, err)
	assert.Equal(t, "%3Cscript%3Ealert%281%29%3C%2Fscript%3E", result)

	// Test decode
	decoded, err := enc.Decode(result)
	require.NoError(t, err)
	assert.Equal(t, "<script>alert(1)</script>", decoded)
}

func TestBase64Encoder(t *testing.T) {
	enc := Get("base64")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "PHNjcmlwdD4=", result)

	// Test decode
	decoded, err := enc.Decode(result)
	require.NoError(t, err)
	assert.Equal(t, "<script>", decoded)
}

func TestBase64FlatEncoder(t *testing.T) {
	enc := Get("base64flat")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "PHNjcmlwdD4", result) // No padding
}

func TestDoubleURLEncoder(t *testing.T) {
	enc := Get("double-url")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "%253Cscript%253E", result)

	// Test decode
	decoded, err := enc.Decode(result)
	require.NoError(t, err)
	assert.Equal(t, "<script>", decoded)
}

func TestTripleURLEncoder(t *testing.T) {
	enc := Get("triple-url")
	require.NotNil(t, enc)

	result, err := enc.Encode("<")
	require.NoError(t, err)
	assert.Equal(t, "%25253C", result)
}

func TestUnicodeEncoder(t *testing.T) {
	enc := Get("unicode")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "\\u003cscript\\u003e", result)
}

func TestHTMLEntityEncoder(t *testing.T) {
	enc := Get("html-entity")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "&lt;script&gt;", result)

	// Test decode
	decoded, err := enc.Decode(result)
	require.NoError(t, err)
	assert.Equal(t, "<script>", decoded)
}

func TestHTMLNumericEncoder(t *testing.T) {
	enc := Get("html-numeric")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "&#60;script&#62;", result)
}

func TestHTMLHexEncoder(t *testing.T) {
	enc := Get("html-hex")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "&#x3c;script&#x3e;", result)
}

func TestJSUnicodeEncoder(t *testing.T) {
	enc := Get("js-unicode")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "\\x3cscript\\x3e", result)
}

func TestJSHexEncoder(t *testing.T) {
	enc := Get("js-hex")
	require.NotNil(t, enc)

	result, err := enc.Encode("abc")
	require.NoError(t, err)
	assert.Equal(t, "\\x61\\x62\\x63", result)
}

func TestUTF7Encoder(t *testing.T) {
	enc := Get("utf7")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>")
	require.NoError(t, err)
	assert.Equal(t, "+ADw-script+AD4-", result)

	// Test decode
	decoded, err := enc.Decode(result)
	require.NoError(t, err)
	assert.Equal(t, "<script>", decoded)
}

func TestHexEncoder(t *testing.T) {
	enc := Get("hex")
	require.NotNil(t, enc)

	result, err := enc.Encode("abc")
	require.NoError(t, err)
	assert.Equal(t, "616263", result)

	// Test decode
	decoded, err := enc.Decode(result)
	require.NoError(t, err)
	assert.Equal(t, "abc", decoded)
}

func TestOctalEncoder(t *testing.T) {
	enc := Get("octal")
	require.NotNil(t, enc)

	result, err := enc.Encode("A")
	require.NoError(t, err)
	assert.Equal(t, "\\101", result)
}

func TestBinaryEncoder(t *testing.T) {
	enc := Get("binary")
	require.NotNil(t, enc)

	result, err := enc.Encode("A")
	require.NoError(t, err)
	assert.Equal(t, "01000001", result)
}

func TestChainedEncoding(t *testing.T) {
	chain := Chain("url", "base64")
	require.NotNil(t, chain)

	result, err := chain.Encode("<script>")
	require.NoError(t, err)
	// First URL encode, then Base64
	assert.NotEmpty(t, result)

	// Verify the chain name
	assert.Equal(t, "url+base64", chain.Name())
}

func TestListEncoders(t *testing.T) {
	list := List()
	assert.GreaterOrEqual(t, len(list), 15) // We have 18 encoders
	assert.Contains(t, list, "url")
	assert.Contains(t, list, "base64")
	assert.Contains(t, list, "unicode")
	assert.Contains(t, list, "hex")
	assert.Contains(t, list, "utf7")
}

func TestEncodeAll(t *testing.T) {
	payloads := []string{"<script>", "<img>", "<svg>"}
	results, err := EncodeAll("url", payloads)
	require.NoError(t, err)
	assert.Len(t, results, 3)
	assert.Equal(t, "%3Cscript%3E", results[0])
}

func TestEncodeAllInvalidEncoder(t *testing.T) {
	_, err := EncodeAll("nonexistent", []string{"test"})
	assert.Error(t, err)
}

func TestEncodeWithAll(t *testing.T) {
	results := EncodeWithAll("<script>")
	assert.GreaterOrEqual(t, len(results), 15)
	assert.Equal(t, "<script>", results["plain"])
	assert.Equal(t, "%3Cscript%3E", results["url"])
}

func TestPlainEncoder(t *testing.T) {
	enc := Get("plain")
	require.NotNil(t, enc)

	result, err := enc.Encode("test")
	require.NoError(t, err)
	assert.Equal(t, "test", result)
}

func TestBase64URLEncoder(t *testing.T) {
	enc := Get("base64url")
	require.NotNil(t, enc)

	// Test with characters that differ between standard and URL-safe base64
	result, err := enc.Encode("test?test")
	require.NoError(t, err)
	assert.NotContains(t, result, "+")
	assert.NotContains(t, result, "/")
}

func TestXMLEntityEncoder(t *testing.T) {
	enc := Get("xml-entity")
	require.NotNil(t, enc)

	result, err := enc.Encode("<script>alert(1)</script>")
	require.NoError(t, err)
	assert.Equal(t, "<![CDATA[<script>alert(1)</script>]]>", result)

	// Test decode
	decoded, err := enc.Decode(result)
	require.NoError(t, err)
	assert.Equal(t, "<script>alert(1)</script>", decoded)
}

func TestChainEncoderDecode(t *testing.T) {
	chain := Chain("url", "base64")
	require.NotNil(t, chain)

	original := "<script>"
	encoded, err := chain.Encode(original)
	require.NoError(t, err)

	decoded, err := chain.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestGetNonexistentEncoder(t *testing.T) {
	enc := Get("nonexistent")
	assert.Nil(t, enc)
}

func TestChainWithInvalidEncoder(t *testing.T) {
	chain := Chain("nonexistent1", "nonexistent2")
	assert.Nil(t, chain)
}

func TestChainWithPartiallyValidEncoders(t *testing.T) {
	chain := Chain("url", "nonexistent", "base64")
	require.NotNil(t, chain)
	// Should only include valid encoders
	result, err := chain.Encode("test")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}
