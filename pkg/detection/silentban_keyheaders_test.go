// Regression test for bug: keyHeaders included per-request variable headers
// (CF-Ray, X-Request-ID, Set-Cookie) that change on every request, causing
// false positive silent ban detection.
//
// The fix removes these variable headers from the tracked set.
package detection

import "testing"

func TestKeyHeaders_NoVariableHeaders(t *testing.T) {
	t.Parallel()

	// These headers change on every request and must NOT be in keyHeaders.
	excluded := []string{
		"CF-Ray",
		"X-Request-ID",
		"Set-Cookie",
	}

	for _, bad := range excluded {
		for _, h := range keyHeaders {
			if h == bad {
				t.Errorf("keyHeaders contains variable header %q which causes false positive ban detection", bad)
			}
		}
	}
}

func TestKeyHeaders_ContainsStableHeaders(t *testing.T) {
	t.Parallel()

	// These stable headers must be present for reliable baseline comparison.
	required := []string{
		"Server",
		"Content-Type",
	}

	for _, want := range required {
		found := false
		for _, h := range keyHeaders {
			if h == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("keyHeaders missing stable header %q", want)
		}
	}
}
