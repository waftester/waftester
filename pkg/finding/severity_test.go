package finding

import (
	"encoding/json"
	"sort"
	"testing"
)

func TestSeverityIsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		s    Severity
		want bool
	}{
		{Critical, true},
		{High, true},
		{Medium, true},
		{Low, true},
		{Info, true},
		{"Unknown", false},
		{"", false},
		{"CRITICAL", false}, // case-sensitive
		{"Critical", false}, // must be lowercase
	}
	for _, tt := range tests {
		t.Run(string(tt.s), func(t *testing.T) {
			t.Parallel()
			if got := tt.s.IsValid(); got != tt.want {
				t.Errorf("Severity(%q).IsValid() = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestSeverityScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		s    Severity
		want int
	}{
		{Critical, 5},
		{High, 4},
		{Medium, 3},
		{Low, 2},
		{Info, 1},
		{"Unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.s), func(t *testing.T) {
			t.Parallel()
			if got := tt.s.Score(); got != tt.want {
				t.Errorf("Severity(%q).Score() = %d, want %d", tt.s, got, tt.want)
			}
		})
	}
}

func TestSeveritySortOrder(t *testing.T) {
	t.Parallel()

	input := []Severity{Low, Critical, Medium, Info, High}
	sort.Slice(input, func(i, j int) bool {
		return input[i].Score() > input[j].Score()
	})
	expected := []Severity{Critical, High, Medium, Low, Info}
	for i, s := range input {
		if s != expected[i] {
			t.Errorf("pos %d: got %s, want %s", i, s, expected[i])
		}
	}
}

func TestSeverityJSON(t *testing.T) {
	t.Parallel()

	original := Critical
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) != `"critical"` {
		t.Errorf("got %s, want %q", data, "critical")
	}

	var decoded Severity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded != original {
		t.Errorf("roundtrip: got %s, want %s", decoded, original)
	}
}

func TestSeverityString(t *testing.T) {
	t.Parallel()

	if s := Critical.String(); s != "critical" {
		t.Errorf("got %q, want %q", s, "critical")
	}
	if s := Info.String(); s != "info" {
		t.Errorf("got %q, want %q", s, "info")
	}
}
