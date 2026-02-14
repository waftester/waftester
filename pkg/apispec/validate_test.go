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
