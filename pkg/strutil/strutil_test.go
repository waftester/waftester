package strutil

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
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
			if tt.maxLen > 0 && utf8.RuneCountInString(got) > tt.maxLen {
				t.Errorf("Truncate result length %d runes exceeds maxLen %d", utf8.RuneCountInString(got), tt.maxLen)
			}
		})
	}
}

func TestUnique(t *testing.T) {
	t.Run("strings", func(t *testing.T) {
		got := Unique([]string{"a", "b", "a", "c", "b"})
		want := []string{"a", "b", "c"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("ints", func(t *testing.T) {
		got := Unique([]int{1, 2, 3, 2, 1})
		want := []int{1, 2, 3}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("nil input", func(t *testing.T) {
		got := Unique[string](nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		got := Unique([]string{})
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("no duplicates", func(t *testing.T) {
		got := Unique([]string{"x", "y", "z"})
		want := []string{"x", "y", "z"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("all duplicates", func(t *testing.T) {
		got := Unique([]string{"a", "a", "a"})
		want := []string{"a"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
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

func TestAtoi(t *testing.T) {
	if got := Atoi("42"); got != 42 {
		t.Errorf("Atoi(\"42\") = %d, want 42", got)
	}
	if got := Atoi("invalid"); got != 0 {
		t.Errorf("Atoi(\"invalid\") = %d, want 0", got)
	}
	if got := Atoi(""); got != 0 {
		t.Errorf("Atoi(\"\") = %d, want 0", got)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "URL with slashes and colons",
			input:  "example.com:8080/path/to/page",
			maxLen: 0,
			want:   "example.com_8080_path_to_page",
		},
		{
			name:   "query string chars",
			input:  "example.com/search?q=test&page=1#top",
			maxLen: 0,
			want:   "example.com_search_q_test_page_1_top",
		},
		{
			name:   "backslash and special chars",
			input:  `C:\Users\file<name>|"star*"`,
			maxLen: 0,
			want:   "C__Users_file_name___star__",
		},
		{
			name:   "spaces replaced",
			input:  "hello world test",
			maxLen: 0,
			want:   "hello_world_test",
		},
		{
			name:   "truncated to maxLen runes",
			input:  strings.Repeat("a", 200),
			maxLen: 50,
			want:   strings.Repeat("a", 50),
		},
		{
			name:   "default maxLen is 100",
			input:  strings.Repeat("b", 150),
			maxLen: 0,
			want:   strings.Repeat("b", 100),
		},
		{
			name:   "negative maxLen uses default 100",
			input:  strings.Repeat("c", 150),
			maxLen: -1,
			want:   strings.Repeat("c", 100),
		},
		{
			name:   "control chars replaced",
			input:  "file\x00name\nnew\rline\ttab",
			maxLen: 0,
			want:   "file_name_new_line_tab",
		},
		{
			name:   "safe string unchanged",
			input:  "safe-filename.txt",
			maxLen: 0,
			want:   "safe-filename.txt",
		},
		{
			name:   "empty string",
			input:  "",
			maxLen: 0,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeFilename(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("SanitizeFilename(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestSortedMapKeys(t *testing.T) {
	t.Run("string values", func(t *testing.T) {
		m := map[string]string{"banana": "b", "apple": "a", "cherry": "c"}
		got := SortedMapKeys(m)
		want := []string{"apple", "banana", "cherry"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("int values", func(t *testing.T) {
		m := map[string]int{"z": 1, "a": 2, "m": 3}
		got := SortedMapKeys(m)
		want := []string{"a", "m", "z"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("interface values", func(t *testing.T) {
		m := map[string]interface{}{"beta": 1, "alpha": "x"}
		got := SortedMapKeys(m)
		want := []string{"alpha", "beta"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("nil map", func(t *testing.T) {
		got := SortedMapKeys[map[string]string](nil)
		if got == nil {
			t.Errorf("expected empty non-nil slice, got nil")
		}
		if len(got) != 0 {
			t.Errorf("expected empty slice, got %v", got)
		}
	})

	t.Run("empty map", func(t *testing.T) {
		got := SortedMapKeys(map[string]int{})
		if got == nil {
			t.Errorf("expected empty non-nil slice, got nil")
		}
		if len(got) != 0 {
			t.Errorf("expected empty slice, got %v", got)
		}
	})

	t.Run("single element", func(t *testing.T) {
		m := map[string]bool{"only": true}
		got := SortedMapKeys(m)
		want := []string{"only"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("http.Header named type", func(t *testing.T) {
		h := http.Header{
			"Content-Type":  []string{"text/plain"},
			"Authorization": []string{"Bearer tok"},
		}
		got := SortedMapKeys(h)
		want := []string{"Authorization", "Content-Type"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("url.Values named type", func(t *testing.T) {
		v := url.Values{
			"z_param": []string{"1"},
			"a_param": []string{"2"},
		}
		got := SortedMapKeys(v)
		want := []string{"a_param", "z_param"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}
