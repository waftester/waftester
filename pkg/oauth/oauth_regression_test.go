// Regression test for bug: crypto/rand failure must not fall back to time-based seeds
package oauth

import (
"testing"
)

// TestGenerateState_ReturnsError verifies GenerateState returns (string, error)
// and produces a non-empty string with nil error under normal conditions.
// Regression test for bug: crypto fallback to time-based seed
func TestGenerateState_ReturnsError(t *testing.T) {
state, err := GenerateState()
if err != nil {
t.Fatalf("GenerateState() returned unexpected error: %v", err)
}
if state == "" {
t.Fatal("GenerateState() returned empty string")
}

// Call twice — results must differ (proves randomness, not deterministic)
state2, err := GenerateState()
if err != nil {
t.Fatalf("GenerateState() second call returned error: %v", err)
}
if state == state2 {
t.Errorf("GenerateState() returned identical values: %q", state)
}
}

// TestGenerateNonce_ReturnsError verifies GenerateNonce returns (string, error)
// and produces a non-empty string with nil error under normal conditions.
// Regression test for bug: crypto fallback to time-based seed
func TestGenerateNonce_ReturnsError(t *testing.T) {
nonce, err := GenerateNonce()
if err != nil {
t.Fatalf("GenerateNonce() returned unexpected error: %v", err)
}
if nonce == "" {
t.Fatal("GenerateNonce() returned empty string")
}

nonce2, err := GenerateNonce()
if err != nil {
t.Fatalf("GenerateNonce() second call returned error: %v", err)
}
if nonce == nonce2 {
t.Errorf("GenerateNonce() returned identical values: %q", nonce)
}
}

// TestGeneratePKCE_ReturnsError verifies GeneratePKCEPair returns verifier, challenge, error
// and produces non-empty values with nil error under normal conditions.
// Regression test for bug: crypto fallback to time-based seed
func TestGeneratePKCE_ReturnsError(t *testing.T) {
verifier, challenge, err := GeneratePKCEPair()
if err != nil {
t.Fatalf("GeneratePKCEPair() returned unexpected error: %v", err)
}
if verifier == "" {
t.Fatal("GeneratePKCEPair() returned empty verifier")
}
if challenge == "" {
t.Fatal("GeneratePKCEPair() returned empty challenge")
}

// Verifier and challenge must be different (challenge = SHA256 of verifier)
if verifier == challenge {
t.Error("GeneratePKCEPair() verifier and challenge should differ")
}

// Call again — verifiers must differ
verifier2, _, err := GeneratePKCEPair()
if err != nil {
t.Fatalf("GeneratePKCEPair() second call returned error: %v", err)
}
if verifier == verifier2 {
t.Errorf("GeneratePKCEPair() returned identical verifiers: %q", verifier)
}
}

// TestGeneratedValues_AreRandom calls each generator 100 times and verifies
// all values are unique (no collisions from time-based seeds).
// Regression test for bug: time-based seed causing duplicate values
func TestGeneratedValues_AreRandom(t *testing.T) {
t.Run("GenerateState", func(t *testing.T) {
seen := make(map[string]struct{}, 100)
for i := 0; i < 100; i++ {
val, err := GenerateState()
if err != nil {
t.Fatalf("iteration %d: %v", i, err)
}
if _, exists := seen[val]; exists {
t.Fatalf("collision at iteration %d: %q already seen", i, val)
}
seen[val] = struct{}{}
}
})

t.Run("GenerateNonce", func(t *testing.T) {
seen := make(map[string]struct{}, 100)
for i := 0; i < 100; i++ {
val, err := GenerateNonce()
if err != nil {
t.Fatalf("iteration %d: %v", i, err)
}
if _, exists := seen[val]; exists {
t.Fatalf("collision at iteration %d: %q already seen", i, val)
}
seen[val] = struct{}{}
}
})

t.Run("GeneratePKCEPair", func(t *testing.T) {
seen := make(map[string]struct{}, 100)
for i := 0; i < 100; i++ {
verifier, _, err := GeneratePKCEPair()
if err != nil {
t.Fatalf("iteration %d: %v", i, err)
}
if _, exists := seen[verifier]; exists {
t.Fatalf("collision at iteration %d: %q already seen", i, verifier)
}
seen[verifier] = struct{}{}
}
})
}

// TestGeneratedValues_NotTimeBased generates two values in rapid succession
// (within the same millisecond). They MUST differ — proving they use crypto/rand.
// Regression test for bug: values derived from time.Now().UnixNano()
func TestGeneratedValues_NotTimeBased(t *testing.T) {
t.Run("State", func(t *testing.T) {
a, _ := GenerateState()
b, _ := GenerateState()
if a == b {
t.Error("two rapid GenerateState() calls returned identical values — likely time-based")
}
})

t.Run("Nonce", func(t *testing.T) {
a, _ := GenerateNonce()
b, _ := GenerateNonce()
if a == b {
t.Error("two rapid GenerateNonce() calls returned identical values — likely time-based")
}
})

t.Run("PKCE", func(t *testing.T) {
a, _, _ := GeneratePKCEPair()
b, _, _ := GeneratePKCEPair()
if a == b {
t.Error("two rapid GeneratePKCEPair() calls returned identical verifiers — likely time-based")
}
})
}
