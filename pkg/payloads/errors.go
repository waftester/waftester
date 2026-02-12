package payloads

import "errors"

// Sentinel errors for payload management failure modes.
// Callers should use errors.Is() to check for these.
var (
	// ErrPayloadNotFound indicates the requested payload ID or
	// category does not exist.
	ErrPayloadNotFound = errors.New("payloads: payload not found")

	// ErrInvalidPayload indicates a payload failed validation
	// (malformed, empty, or missing required fields).
	ErrInvalidPayload = errors.New("payloads: invalid payload")
)
