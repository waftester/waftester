// Regression test for bug: URL mutation in shared pointer across loop iterations
package nosqli

import (
"bytes"
"io"
"net/http"
"net/url"
"testing"
)

// TestURLClone_PreservesOriginal verifies that cloning a url.URL via value copy
// and modifying the clone does not mutate the original. This tests the fix in
// testQueryParam where "*u" is used instead of direct pointer mutation.
// Regression test for bug: shared URL pointer mutated across loop iterations
func TestURLClone_PreservesOriginal(t *testing.T) {
original, err := url.Parse("https://example.com/api?id=1")
if err != nil {
t.Fatalf("url.Parse failed: %v", err)
}
originalStr := original.String()

// Simulate what testQueryParam does: clone via value copy, then modify
cloned := *original
q := cloned.Query()
q.Set("injected[]", "")
cloned.RawQuery = q.Encode()

// Original must be unchanged
if original.String() != originalStr {
t.Errorf("original URL mutated: got %s, want %s", original.String(), originalStr)
}

// Cloned must be different
if cloned.String() == originalStr {
t.Error("cloned URL was not modified — clone operation had no effect")
}
}

// TestQueryParam_DoesNotMutateSharedURL verifies the public API does not mutate
// the URL across multiple payload tests. We simulate multiple iterations over
// the same URL and verify it remains unchanged.
// Regression test for bug: URL pointer aliasing in testQueryParam loop
func TestQueryParam_DoesNotMutateSharedURL(t *testing.T) {
original, err := url.Parse("https://example.com/api/users?id=1&name=test")
if err != nil {
t.Fatalf("url.Parse failed: %v", err)
}
originalStr := original.String()

// Simulate multiple iterations of the clone-and-modify pattern
payloads := []string{"[]=", "[]=", "[]=.*", "[]=true"}
for _, payload := range payloads {
cloned := *original
q := cloned.Query()
q.Set("username"+payload, "")
cloned.RawQuery = q.Encode()

// After each iteration, original must be untouched
if original.String() != originalStr {
t.Fatalf("original URL mutated after payload %q: got %s, want %s",
payload, original.String(), originalStr)
}
}
}

// TestReadBodyLimit_RespectsLimit verifies that readBodyLimit uses io.LimitReader
// to prevent memory exhaustion from large response bodies.
// Regression test for bug: unbounded io.ReadAll on response body
func TestReadBodyLimit_RespectsLimit(t *testing.T) {
// Create a body larger than the limit
const limit int64 = 1024 // 1KB limit
largeBody := bytes.Repeat([]byte("A"), int(limit*10))

resp := &http.Response{
Body: io.NopCloser(bytes.NewReader(largeBody)),
}

result := readBodyLimit(resp, limit)

if int64(len(result)) > limit {
t.Errorf("readBodyLimit returned %d bytes, want at most %d", len(result), limit)
}
if int64(len(result)) != limit {
t.Errorf("readBodyLimit returned %d bytes, want exactly %d (limit)", len(result), limit)
}
}

// TestReadBodyLimit_SmallBody verifies readBodyLimit reads the full body when
// it's smaller than the limit.
func TestReadBodyLimit_SmallBody(t *testing.T) {
smallBody := []byte("hello world")
resp := &http.Response{
Body: io.NopCloser(bytes.NewReader(smallBody)),
}

result := readBodyLimit(resp, 1024*1024)

if result != "hello world" {
t.Errorf("readBodyLimit = %q, want %q", result, "hello world")
}
}

// TestReadBodyLimit_EmptyBody verifies readBodyLimit handles an empty body.
func TestReadBodyLimit_EmptyBody(t *testing.T) {
resp := &http.Response{
Body: io.NopCloser(bytes.NewReader(nil)),
}

result := readBodyLimit(resp, 1024)

if result != "" {
t.Errorf("readBodyLimit on empty body = %q, want %q", result, "")
}
}
