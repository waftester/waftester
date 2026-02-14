package apispec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSessionID_Deterministic(t *testing.T) {
	id1 := GenerateSessionID("openapi.yaml", "planhash123")
	id2 := GenerateSessionID("openapi.yaml", "planhash123")
	assert.Equal(t, id1, id2, "same inputs must produce same session ID")
	assert.Len(t, id1, 8, "session ID is 8 hex chars (4 bytes)")
}

func TestGenerateSessionID_DifferentInputs(t *testing.T) {
	id1 := GenerateSessionID("spec-a.yaml", "hash1")
	id2 := GenerateSessionID("spec-b.yaml", "hash1")
	id3 := GenerateSessionID("spec-a.yaml", "hash2")
	assert.NotEqual(t, id1, id2)
	assert.NotEqual(t, id1, id3)
}

func TestGenerateCorrelationID_Format(t *testing.T) {
	id := GenerateCorrelationID("a3f8c21e", "POST-users", "sqli", "body.email", 42)
	assert.Equal(t, "waftester-a3f8c21e-post-users-sqli-body.email-0042", id)
}

func TestGenerateCorrelationID_SanitizesSlashes(t *testing.T) {
	id := GenerateCorrelationID("abc", "GET-/api/users/{id}", "xss", "query.q", 1)
	assert.NotContains(t, id, "/")
	assert.NotContains(t, id, "{")
	assert.NotContains(t, id, "}")
	assert.Contains(t, id, "waftester-abc-")
}

func TestEndpointTag(t *testing.T) {
	tests := []struct {
		method, path, want string
	}{
		{"POST", "/api/users", "post-api-users"},
		{"GET", "/health", "get-health"},
		{"DELETE", "/api/users/{id}", "delete-api-users-id"},
	}
	for _, tt := range tests {
		got := EndpointTag(tt.method, tt.path)
		assert.Equal(t, tt.want, got, "EndpointTag(%s, %s)", tt.method, tt.path)
	}
}

func TestHashPayload(t *testing.T) {
	h1 := HashPayload("' OR 1=1 --")
	h2 := HashPayload("' OR 1=1 --")
	h3 := HashPayload("<script>alert(1)</script>")

	assert.Equal(t, h1, h2, "same payload = same hash")
	assert.NotEqual(t, h1, h3, "different payload = different hash")
	assert.Len(t, h1, 64, "SHA-256 hex is 64 chars")
	// Must not contain the original payload.
	assert.NotContains(t, h1, "OR")
}

func TestCorrelationTracker_Record(t *testing.T) {
	ct := NewCorrelationTracker("deadbeef")
	id1 := ct.Record("post-users", "sqli", "body.email", "' OR 1=1", true, "403 Forbidden")
	id2 := ct.Record("get-users", "xss", "query.q", "<script>", false, "")

	assert.NotEqual(t, id1, id2)
	assert.Equal(t, 2, ct.Count())

	records := ct.Records()
	assert.Len(t, records, 2)
	assert.Equal(t, "deadbeef", records[0].SessionID)
	assert.Equal(t, "sqli", records[0].AttackCategory)
	assert.True(t, records[0].Blocked)
	assert.False(t, records[1].Blocked)
	// Payload must be hashed, not plaintext.
	assert.NotContains(t, records[0].PayloadHash, "OR")
}

func TestCorrelationTracker_SequenceIncrementing(t *testing.T) {
	ct := NewCorrelationTracker("abcd1234")
	id1 := ct.Record("get-a", "sqli", "q", "p1", false, "")
	id2 := ct.Record("get-a", "sqli", "q", "p2", false, "")
	id3 := ct.Record("get-a", "sqli", "q", "p3", false, "")

	assert.True(t, strings.HasSuffix(id1, "-0001"))
	assert.True(t, strings.HasSuffix(id2, "-0002"))
	assert.True(t, strings.HasSuffix(id3, "-0003"))
}

func TestCorrelationTracker_Uniqueness(t *testing.T) {
	ct := NewCorrelationTracker("unique01")
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := ct.Record("ep", "cat", "pt", "payload", false, "")
		assert.False(t, seen[id], "duplicate correlation ID: %s", id)
		seen[id] = true
	}
}

func TestCorrelationTracker_ConcurrentSafety(t *testing.T) {
	ct := NewCorrelationTracker("conc0001")
	var wg sync.WaitGroup

	ids := make([]string, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ids[idx] = ct.Record("ep", "cat", "pt", "payload", false, "")
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 100, ct.Count())
	seen := make(map[string]bool)
	for _, id := range ids {
		assert.False(t, seen[id], "duplicate under concurrency: %s", id)
		seen[id] = true
	}
}

func TestCorrelationTracker_ExportAndLoad(t *testing.T) {
	ct := NewCorrelationTracker("export01")
	ct.Record("post-users", "sqli", "body.name", "' OR 1=1", true, "403")
	ct.Record("get-search", "xss", "query.q", "<img onerror=1>", false, "200")

	dir := t.TempDir()
	path := filepath.Join(dir, "correlations.json")

	require.NoError(t, ct.ExportJSON(path))

	loaded, err := LoadCorrelationRecords(path)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
	assert.Equal(t, "export01", loaded[0].SessionID)
	assert.Equal(t, "sqli", loaded[0].AttackCategory)
	assert.True(t, loaded[0].Blocked)
}

func TestCorrelationTracker_ExportJSON_ValidJSON(t *testing.T) {
	ct := NewCorrelationTracker("json0001")
	ct.Record("ep", "cat", "pt", "payload", false, "")

	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	require.NoError(t, ct.ExportJSON(path))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, json.Valid(data), "exported JSON must be valid")
}

func TestCorrelationTracker_RecordsCopy(t *testing.T) {
	ct := NewCorrelationTracker("copy0001")
	ct.Record("ep", "cat", "pt", "p", false, "")

	records := ct.Records()
	records[0].SessionID = "tampered"

	original := ct.Records()
	assert.Equal(t, "copy0001", original[0].SessionID, "Records must return a copy")
}

func TestLoadCorrelationRecords_BadPath(t *testing.T) {
	_, err := LoadCorrelationRecords("/nonexistent/path.json")
	assert.Error(t, err)
}

func TestLoadCorrelationRecords_BadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o644))

	_, err := LoadCorrelationRecords(path)
	assert.Error(t, err)
}

func TestSanitizeTag(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"/api/users/{id}", "-api-users-id"},
		{"POST /login", "post--login"},
		{"simple", "simple"},
		{"UPPER", "upper"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, sanitizeTag(tt.input), "sanitizeTag(%q)", tt.input)
	}
}
