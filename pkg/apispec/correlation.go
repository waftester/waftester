package apispec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// CorrelationTracker accumulates correlation records during a scan session.
// Safe for concurrent use.
type CorrelationTracker struct {
	mu        sync.Mutex
	sessionID string
	records   []CorrelationRecord
	seq       int
}

// NewCorrelationTracker creates a tracker for the given session.
// The session ID should be deterministic (derived from spec content and scan plan)
// so the same spec + same plan produces the same correlation IDs.
func NewCorrelationTracker(sessionID string) *CorrelationTracker {
	return &CorrelationTracker{
		sessionID: sessionID,
		records:   make([]CorrelationRecord, 0, 256),
	}
}

// GenerateSessionID derives a deterministic session ID from spec content and scan config.
// The first 8 hex characters of SHA-256(specSource + "|" + planHash) are used.
func GenerateSessionID(specSource, planHash string) string {
	h := sha256.Sum256([]byte(specSource + "|" + planHash))
	return hex.EncodeToString(h[:4])
}

// GenerateCorrelationID builds a correlation header value.
// Format: waftester-{session}-{endpoint-tag}-{attack}-{param}-{seq}
// Example: waftester-a3f8c21e-POST-users-sqli-body.email-0042
func GenerateCorrelationID(sessionID, endpointTag, attackCategory, injectionPoint string, seq int) string {
	return fmt.Sprintf("waftester-%s-%s-%s-%s-%04d",
		sessionID,
		sanitizeTag(endpointTag),
		sanitizeTag(attackCategory),
		sanitizeTag(injectionPoint),
		seq,
	)
}

// EndpointTag builds a tag from an HTTP method and path.
// Example: "POST", "/api/users" → "POST-api-users"
func EndpointTag(method, path string) string {
	tag := method + "-" + strings.TrimPrefix(path, "/")
	return sanitizeTag(tag)
}

// HashPayload returns a hex-encoded SHA-256 hash of the payload.
// Payloads are never stored in plaintext in correlation records.
func HashPayload(payload string) string {
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

// Record adds a correlation record to the tracker and returns the generated correlation ID.
func (ct *CorrelationTracker) Record(endpointTag, attackCategory, injectionPoint, payload string, blocked bool, wafResponse string) string {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.seq++
	corrID := GenerateCorrelationID(ct.sessionID, endpointTag, attackCategory, injectionPoint, ct.seq)

	ct.records = append(ct.records, CorrelationRecord{
		SessionID:      ct.sessionID,
		CorrelationID:  corrID,
		EndpointTag:    endpointTag,
		AttackCategory: attackCategory,
		InjectionPoint: injectionPoint,
		PayloadHash:    HashPayload(payload),
		Timestamp:      time.Now(),
		Blocked:        blocked,
		WAFResponse:    wafResponse,
	})

	return corrID
}

// Records returns a copy of all correlation records.
func (ct *CorrelationTracker) Records() []CorrelationRecord {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	out := make([]CorrelationRecord, len(ct.records))
	copy(out, ct.records)
	return out
}

// Count returns the number of recorded correlations.
func (ct *CorrelationTracker) Count() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return len(ct.records)
}

// ExportJSON writes all records to the given file path as formatted JSON.
func (ct *CorrelationTracker) ExportJSON(path string) error {
	ct.mu.Lock()
	records := make([]CorrelationRecord, len(ct.records))
	copy(records, ct.records)
	ct.mu.Unlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal correlations: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write correlations: %w", err)
	}
	return nil
}

// LoadCorrelationRecords reads correlation records from a JSON file.
func LoadCorrelationRecords(path string) ([]CorrelationRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read correlations: %w", err)
	}

	var records []CorrelationRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse correlations: %w", err)
	}
	return records, nil
}

// sanitizeTag replaces slashes and spaces with dashes and lowercases the result.
func sanitizeTag(s string) string {
	r := strings.NewReplacer("/", "-", " ", "-", "{", "", "}", "")
	return strings.ToLower(r.Replace(s))
}
