package strategy

import (
	"testing"
)

// =============================================================================
// ShouldSkipPayload Tests
// =============================================================================

func TestShouldSkipPayload_MatchesSkipList(t *testing.T) {
	s := &Strategy{
		SkipIneffectiveMutators: []string{"base64_simple", "hex_space"},
	}
	if !s.ShouldSkipPayload("base64_simple") {
		t.Error("expected base64_simple to be skipped")
	}
	if !s.ShouldSkipPayload("hex_space") {
		t.Error("expected hex_space to be skipped")
	}
}

func TestShouldSkipPayload_CaseInsensitive(t *testing.T) {
	s := &Strategy{
		SkipIneffectiveMutators: []string{"base64_simple"},
	}
	if !s.ShouldSkipPayload("BASE64_SIMPLE") {
		t.Error("expected case-insensitive match to skip")
	}
	if !s.ShouldSkipPayload("Base64_Simple") {
		t.Error("expected mixed-case match to skip")
	}
}

func TestShouldSkipPayload_NoMatch(t *testing.T) {
	s := &Strategy{
		SkipIneffectiveMutators: []string{"base64_simple"},
	}
	if s.ShouldSkipPayload("unicode") {
		t.Error("unicode should not be skipped")
	}
	if s.ShouldSkipPayload("double_url") {
		t.Error("double_url should not be skipped")
	}
}

func TestShouldSkipPayload_EmptyEncoding(t *testing.T) {
	s := &Strategy{
		SkipIneffectiveMutators: []string{"base64_simple"},
	}
	if s.ShouldSkipPayload("") {
		t.Error("empty encoding should never be skipped")
	}
}

func TestShouldSkipPayload_NilStrategy(t *testing.T) {
	var s *Strategy
	if s.ShouldSkipPayload("base64_simple") {
		t.Error("nil strategy should never skip")
	}
}

func TestShouldSkipPayload_EmptySkipList(t *testing.T) {
	s := &Strategy{
		SkipIneffectiveMutators: []string{},
	}
	if s.ShouldSkipPayload("base64_simple") {
		t.Error("empty skip list should never skip")
	}
}

func TestShouldSkipPayload_NilSkipList(t *testing.T) {
	s := &Strategy{}
	if s.ShouldSkipPayload("base64_simple") {
		t.Error("nil skip list should never skip")
	}
}

// =============================================================================
// PrioritizePayloads Tests
// =============================================================================

func TestPrioritizePayloads_WithWAFMutators(t *testing.T) {
	s := &Strategy{
		PrioritizeMutators: []string{"xss", "rce"},
	}
	input := []string{"sqli", "rce", "xss", "traversal"}
	result := s.PrioritizePayloads(input)

	if len(result) != 4 {
		t.Fatalf("expected 4 results, got %d", len(result))
	}
	// xss should be first (priority 1), rce second (priority 2)
	if result[0] != "xss" {
		t.Errorf("expected xss first, got %s", result[0])
	}
	if result[1] != "rce" {
		t.Errorf("expected rce second, got %s", result[1])
	}
}

func TestPrioritizePayloads_NilStrategy(t *testing.T) {
	var s *Strategy
	input := []string{"sqli", "xss", "rce"}
	result := s.PrioritizePayloads(input)

	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}
	// Should use generic ordering: sqli(10) < xss(30) < rce(90)
	if result[0] != "sqli" {
		t.Errorf("expected sqli first in generic ordering, got %s", result[0])
	}
}

func TestPrioritizePayloads_EmptyPrioritize(t *testing.T) {
	s := &Strategy{
		PrioritizeMutators: []string{},
	}
	input := []string{"rce", "sqli", "xss"}
	result := s.PrioritizePayloads(input)

	// Generic ordering: sqli(10) < xss(30) < rce(90)
	if result[0] != "sqli" {
		t.Errorf("expected sqli first, got %s", result[0])
	}
	if result[1] != "xss" {
		t.Errorf("expected xss second, got %s", result[1])
	}
	if result[2] != "rce" {
		t.Errorf("expected rce third, got %s", result[2])
	}
}

func TestPrioritizePayloads_UnknownCategories(t *testing.T) {
	s := &Strategy{}
	input := []string{"unknown_cat", "sqli", "another_unknown"}
	result := s.PrioritizePayloads(input)

	// sqli has priority 10, unknowns get 100, so sqli first
	if result[0] != "sqli" {
		t.Errorf("expected sqli first, got %s", result[0])
	}
}

func TestPrioritizePayloads_EmptyInput(t *testing.T) {
	s := &Strategy{
		PrioritizeMutators: []string{"xss"},
	}
	result := s.PrioritizePayloads([]string{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d items", len(result))
	}
}

func TestPrioritizePayloads_NilInput(t *testing.T) {
	s := &Strategy{}
	result := s.PrioritizePayloads(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

func TestPrioritizePayloads_DoesNotMutateInput(t *testing.T) {
	s := &Strategy{
		PrioritizeMutators: []string{"rce"},
	}
	input := []string{"rce", "sqli", "xss"}
	original := make([]string, len(input))
	copy(original, input)

	_ = s.PrioritizePayloads(input)

	for i, v := range input {
		if v != original[i] {
			t.Errorf("input was mutated at index %d: expected %s, got %s", i, original[i], v)
		}
	}
}

func TestPrioritizePayloads_CaseInsensitiveBoost(t *testing.T) {
	s := &Strategy{
		PrioritizeMutators: []string{"XSS", "RCE"},
	}
	input := []string{"sqli", "rce", "xss"}
	result := s.PrioritizePayloads(input)

	if result[0] != "xss" {
		t.Errorf("expected xss first (case-insensitive boost), got %s", result[0])
	}
	if result[1] != "rce" {
		t.Errorf("expected rce second (case-insensitive boost), got %s", result[1])
	}
}
