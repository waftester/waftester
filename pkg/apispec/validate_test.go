package apispec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSpecValid(t *testing.T) {
	result, err := ValidateSpec("testdata/petstore-oa3.json", false)
	require.NoError(t, err)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Errors)
	assert.NotNil(t, result.Spec)
}

func TestValidateSpecUnknownFormat(t *testing.T) {
	result, err := ValidateSpec("testdata/invalid.json", false)
	require.NoError(t, err)

	assert.False(t, result.Valid)
	require.NotEmpty(t, result.Errors)
	assert.Equal(t, "unsupported_format", result.Errors[0].Code)
}

func TestValidateSpecSSRFBlocked(t *testing.T) {
	// Create a temp spec with a blocked server URL
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"servers": [{"url": "http://169.254.169.254/api"}],
		"paths": {}
	}`
	tmpFile := filepath.Join(t.TempDir(), "ssrf-spec.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)

	assert.False(t, result.Valid)
	var found bool
	for _, e := range result.Errors {
		if e.Code == "ssrf_blocked" {
			found = true
		}
	}
	assert.True(t, found, "should block metadata endpoint")
}

func TestValidateSpecSSRFLocalhostBlocked(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"servers": [{"url": "http://localhost:8080/api"}],
		"paths": {}
	}`
	tmpFile := filepath.Join(t.TempDir(), "ssrf-localhost.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)

	assert.False(t, result.Valid)
}

func TestValidateSpecSSRFPrivateIP(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"servers": [{"url": "http://10.0.0.1/api"}],
		"paths": {}
	}`
	tmpFile := filepath.Join(t.TempDir(), "ssrf-private.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)
	assert.False(t, result.Valid)
}

func TestValidateSpecSSRFAllowInternal(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"servers": [{"url": "http://localhost:8080/api"}],
		"paths": {}
	}`
	tmpFile := filepath.Join(t.TempDir(), "ssrf-allow.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, true)
	require.NoError(t, err)

	// With allowInternal=true, should pass
	assert.True(t, result.Valid)
}

func TestValidateSpecCredentialDetection(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/test": {
				"get": {
					"parameters": [{
						"name": "auth",
						"in": "header",
						"example": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
					}],
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`
	tmpFile := filepath.Join(t.TempDir(), "cred-spec.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)

	// Should still be valid but with a warning
	assert.True(t, result.Valid)
	var found bool
	for _, w := range result.Warnings {
		if w.Code == "credential_detected" {
			found = true
		}
	}
	assert.True(t, found, "should warn about credential-like values")
}

func TestValidateSpecPreRequestScript(t *testing.T) {
	spec := `{
		"info": {
			"name": "test",
			"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
		},
		"event": [
			{
				"listen": "prerequest",
				"script": {
					"exec": ["pm.environment.set('token', 'value')"]
				}
			}
		],
		"item": []
	}`
	tmpFile := filepath.Join(t.TempDir(), "prereq-spec.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)

	var found bool
	for _, w := range result.Warnings {
		if w.Code == "pre_request_script" {
			found = true
		}
	}
	assert.True(t, found, "should warn about pre-request scripts")
}

func TestValidateSpecPathTraversal(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"paths": {
			"/test": {
				"get": {
					"responses": {
						"200": {
							"content": {
								"application/json": {
									"schema": {"$ref": "../../etc/passwd"}
								}
							}
						}
					}
				}
			}
		}
	}`
	tmpFile := filepath.Join(t.TempDir(), "traversal-spec.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)

	var found bool
	for _, e := range result.Errors {
		if e.Code == "path_traversal" {
			found = true
		}
	}
	assert.True(t, found, "should block path traversal in $ref")
}

func TestValidateSpecExternalHTTPRef(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"paths": {
			"/test": {
				"get": {
					"responses": {
						"200": {
							"content": {
								"application/json": {
									"schema": {"$ref": "http://evil.com/schema.json"}
								}
							}
						}
					}
				}
			}
		}
	}`
	tmpFile := filepath.Join(t.TempDir(), "external-ref-spec.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)

	var found bool
	for _, e := range result.Errors {
		if e.Code == "external_ref" {
			found = true
		}
	}
	assert.True(t, found, "should block external HTTP $ref")
}

func TestValidateSpecFileRef(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"paths": {
			"/test": {
				"get": {
					"responses": {
						"200": {
							"content": {
								"application/json": {
									"schema": {"$ref": "file:///etc/passwd"}
								}
							}
						}
					}
				}
			}
		}
	}`
	tmpFile := filepath.Join(t.TempDir(), "file-ref-spec.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)

	var found bool
	for _, e := range result.Errors {
		if e.Code == "file_ref_blocked" {
			found = true
		}
	}
	assert.True(t, found, "should block file:// $ref")
}

func TestIsBlockedURL(t *testing.T) {
	tests := []struct {
		url     string
		blocked bool
	}{
		{"https://api.example.com", false},
		{"http://localhost:8080", true},
		{"http://127.0.0.1", true},
		{"http://0.0.0.0", true},
		{"http://169.254.169.254", true},
		{"http://10.0.0.1", true},
		{"http://192.168.1.1", true},
		{"http://172.16.0.1", true},
		{"ftp://files.example.com", true},
		{"file:///etc/passwd", true},
		{"http://[::1]", true},
		{"http://metadata.google.internal", true},
		{"https://external.example.com/api", false},
		// SSRF bypass vectors.
		{"http://2130706433", true},         // Decimal IP for 127.0.0.1
		{"http://0177.0.0.1", true},         // Octal IP for 127.0.0.1
		{"http://0177.0.0.01", true},        // Mixed octal for 127.0.0.1
		{"http://2852039166", true},         // Decimal IP for 169.254.169.254
		{"http://[::ffff:127.0.0.1]", true}, // IPv6-mapped IPv4 loopback
		{"http://[::ffff:10.0.0.1]", true},  // IPv6-mapped IPv4 private
		{"http://127.1", true},              // Short notation for 127.0.0.1
		// Hex IP bypass vectors.
		{"http://0x7f000001", true}, // Hex IP for 127.0.0.1
		{"http://0X7F000001", true}, // Hex IP uppercase for 127.0.0.1
		{"http://0xA9FEA9FE", true}, // Hex IP for 169.254.169.254
		{"http://0x7f.0.0.1", true}, // Per-octet hex for 127.0.0.1
		{"http://0x0a.0.0.1", true}, // Per-octet hex for 10.0.0.1
		// {{ bypass: must check only hostname, not full URL.
		{"http://169.254.169.254/{{x", true}, // {{ in path must not bypass SSRF check
		{"http://127.0.0.1/path/{{", true},   // {{ in path must not bypass SSRF check
		{"https://{{host}}/api", false},      // {{ in hostname is OK (template URL)
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.blocked, isBlockedURL(tt.url))
		})
	}
}

func TestValidateSpecNonexistentFile(t *testing.T) {
	_, err := ValidateSpec("testdata/nonexistent.json", false)
	require.Error(t, err)
}

func TestValidateSpecVariableURLSSRF(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"servers": [{"url": "https://{{host}}/api"}],
		"paths": {}
	}`
	tmpFile := filepath.Join(t.TempDir(), "var-ssrf.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(spec), 0644))

	// The template URL itself isn't blocked (contains {{host}})
	// This tests that the basic validation passes
	result, err := ValidateSpec(tmpFile, false)
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

// TestRegression_PathTraversalSiblingDir verifies that a $ref like
// "../specs-evil/payload.yaml" is blocked even when the spec directory
// name is a prefix of the sibling (e.g., /app/specs vs /app/specs-evil).
// Before the fix, strings.HasPrefix matched the sibling as a subdirectory.
func TestRegression_PathTraversalSiblingDir(t *testing.T) {
	// Create a temp directory structure: base/specs/spec.json
	// The $ref "../specs-evil/payload.yaml" should be blocked — it escapes specs/.
	baseDir := t.TempDir()
	specDir := filepath.Join(baseDir, "specs")
	require.NoError(t, os.MkdirAll(specDir, 0755))

	spec := `{
		"openapi": "3.0.3",
		"info": {"title": "test", "version": "1"},
		"paths": {
			"/test": {
				"get": {
					"responses": {
						"200": {
							"content": {
								"application/json": {
									"schema": {"$ref": "../specs-evil/payload.yaml#/Payload"}
								}
							}
						}
					}
				}
			}
		}
	}`
	specFile := filepath.Join(specDir, "spec.json")
	require.NoError(t, os.WriteFile(specFile, []byte(spec), 0644))

	result, err := ValidateSpec(specFile, false)
	require.NoError(t, err)

	var found bool
	for _, e := range result.Errors {
		if e.Code == "path_traversal" {
			found = true
		}
	}
	assert.True(t, found, "should block sibling directory traversal in $ref")
}

// TestRegression_CheckServerURLs verifies that CheckServerURLs rejects
// specs with internal server URLs. Before the fix, neither runSpecScan
// nor runSpecPipeline called any SSRF validation — specs targeting
// 169.254.169.254 were scanned directly.
func TestRegression_CheckServerURLs(t *testing.T) {
	t.Parallel()

	t.Run("blocks internal URL", func(t *testing.T) {
		spec := &Spec{
			Servers: []Server{{URL: "http://169.254.169.254/latest/meta-data"}},
		}
		err := CheckServerURLs(spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SSRF policy")
	})

	t.Run("allows external URL", func(t *testing.T) {
		spec := &Spec{
			Servers: []Server{{URL: "https://api.example.com"}},
		}
		err := CheckServerURLs(spec)
		assert.NoError(t, err)
	})

	t.Run("blocks mixed internal and external", func(t *testing.T) {
		spec := &Spec{
			Servers: []Server{
				{URL: "https://api.example.com"},
				{URL: "http://10.0.0.1:8080/api"},
			},
		}
		err := CheckServerURLs(spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "10.0.0.1")
	})

	t.Run("empty servers OK", func(t *testing.T) {
		spec := &Spec{}
		err := CheckServerURLs(spec)
		assert.NoError(t, err)
	})
}
