package ui

import (
	"testing"
)

func TestDefaultSpinner(t *testing.T) {
	s := DefaultSpinner()
	if len(s.Frames) == 0 {
		t.Fatal("DefaultSpinner returned empty frames")
	}
	if s.Interval <= 0 {
		t.Fatal("DefaultSpinner returned non-positive interval")
	}

	// In test environments, stderr is typically a pipe (not a terminal),
	// so UnicodeTerminal() returns false and we get the ASCII spinner.
	if !UnicodeTerminal() {
		line := Spinners[SpinnerLine]
		if len(s.Frames) != len(line.Frames) {
			t.Errorf("expected ASCII spinner (%d frames), got %d frames", len(line.Frames), len(s.Frames))
		}
		for i, f := range s.Frames {
			if f != line.Frames[i] {
				t.Errorf("frame[%d] = %q, want %q", i, f, line.Frames[i])
			}
		}
	}
}

func TestIcon(t *testing.T) {
	tests := []struct {
		name    string
		unicode string
		ascii   string
	}{
		{"check", "✅", "+"},
		{"cross", "❌", "x"},
		{"warning", "⚠️", "!"},
		{"empty_ascii", "📊", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Icon(tt.unicode, tt.ascii)

			// In test environment stderr is piped, so we expect ASCII.
			if !UnicodeTerminal() {
				if result != tt.ascii {
					t.Errorf("Icon(%q, %q) = %q; want ASCII %q (non-terminal env)",
						tt.unicode, tt.ascii, result, tt.ascii)
				}
			} else {
				if result != tt.unicode {
					t.Errorf("Icon(%q, %q) = %q; want Unicode %q (terminal env)",
						tt.unicode, tt.ascii, result, tt.unicode)
				}
			}
		})
	}
}

func TestUnicodeTerminal(t *testing.T) {
	// In a test runner, stderr is piped — UnicodeTerminal() should return false.
	// This is a stable invariant for CI and local test runs.
	if UnicodeTerminal() {
		t.Log("UnicodeTerminal() returned true — running in a real terminal")
	} else {
		t.Log("UnicodeTerminal() returned false — piped/redirected (expected in tests)")
	}
}
