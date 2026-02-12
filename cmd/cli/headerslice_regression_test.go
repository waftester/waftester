// Regression test for bug: -H / --header flag only accepted a single value.
//
// Before the fix, headers was a *string (flag.StringVar), so only the last
// -H value was kept. The fix uses a headerSlice type implementing flag.Value
// that appends each occurrence, supporting multiple -H flags.
package main

import "testing"

func TestHeaderSlice_MultipleValues(t *testing.T) {
	t.Parallel()

	var hs headerSlice

	// Simulate multiple -H flag calls.
	if err := hs.Set("Authorization: Bearer token123"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if err := hs.Set("X-Custom: value"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if err := hs.Set("Accept: application/json"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if len(hs) != 3 {
		t.Fatalf("got %d headers; want 3", len(hs))
	}

	want := []string{
		"Authorization: Bearer token123",
		"X-Custom: value",
		"Accept: application/json",
	}
	for i, w := range want {
		if hs[i] != w {
			t.Errorf("header[%d] = %q; want %q", i, hs[i], w)
		}
	}
}

func TestHeaderSlice_String(t *testing.T) {
	t.Parallel()

	var hs headerSlice
	_ = hs.Set("A: 1")
	_ = hs.Set("B: 2")

	got := hs.String()
	if got != "A: 1; B: 2" {
		t.Errorf("String() = %q; want %q", got, "A: 1; B: 2")
	}
}

func TestHeaderSlice_Empty(t *testing.T) {
	t.Parallel()

	var hs headerSlice
	if hs.String() != "" {
		t.Errorf("empty headerSlice.String() = %q; want empty", hs.String())
	}
	if len(hs) != 0 {
		t.Errorf("empty headerSlice has len %d; want 0", len(hs))
	}
}

func TestHeaderSlice_CommaInValue(t *testing.T) {
	t.Parallel()

	var hs headerSlice
	// Header values can contain commas — the headerSlice must NOT split on commas.
	_ = hs.Set("Accept: text/html, application/json")

	if len(hs) != 1 {
		t.Fatalf("got %d headers; want 1 (comma was incorrectly split)", len(hs))
	}
	if hs[0] != "Accept: text/html, application/json" {
		t.Errorf("header = %q; want %q", hs[0], "Accept: text/html, application/json")
	}
}
