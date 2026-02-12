// Regression test for bug: containsPort returned true for bare IPv6 addresses.
//
// Before the fix, containsPort("::1") returned true because the address contains
// a colon. IPv6 bracket notation ("[::1]:53") must be handled specially: the port
// indicator is "]:", not just ":". The fix checks for bracket notation first.
package httpclient

import "testing"

func TestContainsPort_IPv6(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want bool
	}{
		// IPv6 with port.
		{"ipv6_bracket_with_port", "[::1]:8080", true},
		{"ipv6_full_with_port", "[2001:db8::1]:443", true},
		{"ipv6_loopback_with_port", "[::1]:53", true},

		// IPv6 without port — must be false.
		{"ipv6_bracket_no_port", "[::1]", false},
		{"ipv6_full_no_port", "[2001:db8::1]", false},

		// Bare IPv6 without brackets — must be false (no port).
		{"bare_ipv6_loopback", "::1", false},
		{"bare_ipv6_full", "2001:db8::1", false},
		{"bare_ipv6_link_local", "fe80::1", false},

		// IPv4 — unchanged behavior.
		{"ipv4_with_port", "1.2.3.4:53", true},
		{"ipv4_no_port", "1.2.3.4", false},
		{"hostname_with_port", "example.com:443", true},
		{"hostname_no_port", "example.com", false},

		// Edge cases.
		{"empty_string", "", false},
		{"just_brackets", "[]", false},
		{"bracket_colon_no_port", "[:]", false}, // malformed, but "]:" present
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := containsPort(tt.addr)
			if got != tt.want {
				t.Errorf("containsPort(%q) = %v; want %v", tt.addr, got, tt.want)
			}
		})
	}
}
