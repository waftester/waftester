// Package apispec provides a unified API specification parser supporting
// OpenAPI 3.x, Swagger 2.0, Postman v2.x, HAR v1.2, and other formats.
// It produces a single Spec type regardless of input format.
package apispec

import "errors"

// Sentinel errors for spec parsing and validation.
var (
	// ErrUnsupportedFormat indicates the spec format could not be detected
	// or is not supported (not OpenAPI, Swagger, Postman, or HAR).
	ErrUnsupportedFormat = errors.New("apispec: unsupported or unrecognized spec format")

	// ErrInvalidSpec indicates the spec is structurally invalid (malformed
	// JSON/YAML, missing required fields, schema violations).
	ErrInvalidSpec = errors.New("apispec: invalid spec")

	// ErrCircularRef indicates a circular $ref chain was detected
	// (e.g., A references B which references A).
	ErrCircularRef = errors.New("apispec: circular $ref detected")

	// ErrUnresolvableRef indicates a $ref target could not be resolved.
	// This includes external HTTP references and blocked paths.
	ErrUnresolvableRef = errors.New("apispec: unresolvable $ref")

	// ErrSpecTooLarge indicates the spec file exceeds the size limit.
	ErrSpecTooLarge = errors.New("apispec: spec exceeds maximum size (50 MB)")

	// ErrNoEndpoints indicates parsing succeeded but no endpoints were found.
	// This is not fatal — the caller decides how to handle it.
	ErrNoEndpoints = errors.New("apispec: no endpoints found in spec")

	// ErrParseTimeout indicates spec parsing exceeded the time limit.
	ErrParseTimeout = errors.New("apispec: parsing timed out")

	// ErrPathTraversal indicates a $ref or file path attempted directory
	// traversal outside the spec's directory (e.g., ../../etc/passwd).
	ErrPathTraversal = errors.New("apispec: path traversal blocked")

	// ErrSSRFBlocked indicates a server URL matched the SSRF blocklist
	// (localhost, link-local, private ranges, file://, ftp://).
	ErrSSRFBlocked = errors.New("apispec: server URL blocked by SSRF policy")
)
