package strutil

import (
	"reflect"
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "long URL truncated",
			input:  "https://example.com/" + strings.Repeat("a", 480),
			maxLen: 80,
			want:   "https://example.com/" + strings.Repeat("a", 57) + "...",
		},
		{
			name:   "short payload unchanged",
			input:  "<script>",
			maxLen: 80,
			want:   "<script>",
		},
		{
			name:   "exact boundary unchanged",
			input:  "exactly10!",
			maxLen: 10,
			want:   "exactly10!",
		},
		{
			name:   "one over boundary",
			input:  "exactly11!x",
			maxLen: 10,
			want:   "exactly...",
		},
		{
			name:   "unicode preserved when short",
			input:  "attack🔥",
			maxLen: 80,
			want:   "attack🔥",
		},
		{
			name:   "zero maxLen returns empty",
			input:  "anything",
			maxLen: 0,
			want:   "",
		},
		{
			name:   "negative maxLen returns empty",
			input:  "anything",
			maxLen: -1,
			want:   "",
		},
		{
			name:   "empty string returns empty",
			input:  "",
			maxLen: 10,
			want:   "",
		},
		{
			name:   "maxLen 1 no ellipsis",
			input:  "hello",
			maxLen: 1,
			want:   "h",
		},
		{
			name:   "maxLen 3 no ellipsis",
			input:  "hello",
			maxLen: 3,
			want:   "hel",
		},
		{
			name:   "maxLen 4 with ellipsis",
			input:  "hello",
			maxLen: 4,
			want:   "h...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
			if tt.maxLen > 0 && len(got) > tt.maxLen {
				t.Errorf("Truncate result length %d exceeds maxLen %d", len(got), tt.maxLen)
			}
		})
	}
}

func TestSplitTrimmed(t *testing.T) {
	tests := []struct {
		name string
		s    string
		sep  string
		want []string
	}{
		{
			name: "comma separated with spaces",
			s:    " foo , bar , baz ",
			sep:  ",",
			want: []string{"foo", "bar", "baz"},
		},
		{
			name: "no spaces",
			s:    "foo,bar,baz",
			sep:  ",",
			want: []string{"foo", "bar", "baz"},
		},
		{
			name: "empty string returns nil",
			s:    "",
			sep:  ",",
			want: nil,
		},
		{
			name: "only whitespace elements",
			s:    " , , ",
			sep:  ",",
			want: nil,
		},
		{
			name: "single element",
			s:    "  hello  ",
			sep:  ",",
			want: []string{"hello"},
		},
		{
			name: "pipe separator",
			s:    "a | b | c",
			sep:  "|",
			want: []string{"a", "b", "c"},
		},
		{
			name: "trailing separator",
			s:    "foo,bar,",
			sep:  ",",
			want: []string{"foo", "bar"},
		},
		{
			name: "leading separator",
			s:    ",foo,bar",
			sep:  ",",
			want: []string{"foo", "bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitTrimmed(tt.s, tt.sep)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitTrimmed(%q, %q) = %v, want %v", tt.s, tt.sep, got, tt.want)
			}
		})
	}
}
