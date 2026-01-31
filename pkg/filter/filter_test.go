package filter

import (
	"regexp"
	"testing"
	"time"
)

func TestFilter_ShouldShow(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		resp   *Response
		want   bool
	}{
		{
			name:   "no criteria shows all",
			config: &Config{},
			resp:   &Response{StatusCode: 200, ContentLength: 100},
			want:   true,
		},
		{
			name:   "match status 200",
			config: &Config{MatchStatus: []int{200}},
			resp:   &Response{StatusCode: 200},
			want:   true,
		},
		{
			name:   "match status miss",
			config: &Config{MatchStatus: []int{200}},
			resp:   &Response{StatusCode: 404},
			want:   false,
		},
		{
			name:   "filter status 404",
			config: &Config{FilterStatus: []int{404}},
			resp:   &Response{StatusCode: 404},
			want:   false,
		},
		{
			name:   "filter status pass",
			config: &Config{FilterStatus: []int{404}},
			resp:   &Response{StatusCode: 200},
			want:   true,
		},
		{
			name:   "match size range",
			config: &Config{MatchSize: []Range{{Min: 100, Max: 200}}},
			resp:   &Response{StatusCode: 200, ContentLength: 150},
			want:   true,
		},
		{
			name:   "match size range miss",
			config: &Config{MatchSize: []Range{{Min: 100, Max: 200}}},
			resp:   &Response{StatusCode: 200, ContentLength: 50},
			want:   false,
		},
		{
			name:   "filter size",
			config: &Config{FilterSize: []Range{{Min: 0, Max: 0}}},
			resp:   &Response{StatusCode: 200, ContentLength: 0},
			want:   false,
		},
		{
			name:   "match word count",
			config: &Config{MatchWords: []Range{{Min: 5, Max: 10}}},
			resp:   &Response{Body: []byte("one two three four five six seven")},
			want:   true,
		},
		{
			name:   "match line count",
			config: &Config{MatchLines: []Range{{Min: 2, Max: 5}}},
			resp:   &Response{Body: []byte("line1\nline2\nline3")},
			want:   true,
		},
		{
			name:   "match regex",
			config: &Config{MatchRegex: []*regexp.Regexp{regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)}},
			resp:   &Response{Body: []byte("Date: 2024-01-15")},
			want:   true,
		},
		{
			name:   "match string",
			config: &Config{MatchString: []string{"success"}},
			resp:   &Response{Body: []byte(`{"status": "success"}`)},
			want:   true,
		},
		{
			name:   "filter string",
			config: &Config{FilterString: []string{"error"}},
			resp:   &Response{Body: []byte(`{"status": "error"}`)},
			want:   false,
		},
		{
			name:   "match response time",
			config: &Config{MatchTime: 100 * time.Millisecond},
			resp:   &Response{ResponseTime: 150 * time.Millisecond},
			want:   true,
		},
		{
			name:   "match CDN",
			config: &Config{MatchCDN: []string{"cloudflare"}},
			resp:   &Response{CDNProvider: "Cloudflare"},
			want:   true,
		},
		{
			name:   "filter error page",
			config: &Config{FilterErrorPage: true},
			resp:   &Response{StatusCode: 404, Body: []byte("Page not found")},
			want:   false,
		},
		{
			name: "combined match AND mode - all match",
			config: &Config{
				MatchStatus: []int{200},
				MatchSize:   []Range{{Min: 100, Max: 200}},
				MatchMode:   ModeAnd,
			},
			resp: &Response{StatusCode: 200, ContentLength: 150},
			want: true,
		},
		{
			name: "combined match AND mode - one miss",
			config: &Config{
				MatchStatus: []int{200},
				MatchSize:   []Range{{Min: 100, Max: 200}},
				MatchMode:   ModeAnd,
			},
			resp: &Response{StatusCode: 200, ContentLength: 50},
			want: false,
		},
		{
			name: "combined match OR mode - one match",
			config: &Config{
				MatchStatus: []int{200},
				MatchSize:   []Range{{Min: 100, Max: 200}},
				MatchMode:   ModeOr,
			},
			resp: &Response{StatusCode: 200, ContentLength: 50},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFilter(tt.config)
			got := f.ShouldShow(tt.resp)
			if got != tt.want {
				t.Errorf("ShouldShow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter_DuplicateDetection(t *testing.T) {
	f := NewFilter(&Config{FilterDuplicates: true})

	resp1 := &Response{Simhash: 12345}
	resp2 := &Response{Simhash: 12345}
	resp3 := &Response{Simhash: 67890}

	// First occurrence should show
	if !f.ShouldShow(resp1) {
		t.Error("First occurrence should show")
	}

	// Duplicate should be filtered
	if f.ShouldShow(resp2) {
		t.Error("Duplicate should be filtered")
	}

	// Different hash should show
	if !f.ShouldShow(resp3) {
		t.Error("Different hash should show")
	}
}

func TestParseRange(t *testing.T) {
	tests := []struct {
		input   string
		want    Range
		wantErr bool
	}{
		{"100", Range{Min: 100, Max: 100}, false},
		{"100-200", Range{Min: 100, Max: 200}, false},
		{"0-0", Range{Min: 0, Max: 0}, false},
		{"invalid", Range{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseRange(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseRange() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRanges(t *testing.T) {
	tests := []struct {
		input   string
		want    []Range
		wantErr bool
	}{
		{"100,200", []Range{{100, 100}, {200, 200}}, false},
		{"100-200,300-400", []Range{{100, 200}, {300, 400}}, false},
		{"100,200-300,400", []Range{{100, 100}, {200, 300}, {400, 400}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseRanges(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("ParseRanges() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseRanges()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseStatusCodes(t *testing.T) {
	tests := []struct {
		input   string
		wantLen int
		wantErr bool
	}{
		{"200", 1, false},
		{"200,301,302", 3, false},
		{"200-204", 5, false},
		{"2xx", 100, false}, // All 200-299
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseStatusCodes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseStatusCodes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("ParseStatusCodes() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestMatchHeaders(t *testing.T) {
	tests := []struct {
		name string
		want map[string]string
		have map[string][]string
		exp  bool
	}{
		{
			name: "exact match",
			want: map[string]string{"Content-Type": "application/json"},
			have: map[string][]string{"Content-Type": {"application/json"}},
			exp:  true,
		},
		{
			name: "partial match",
			want: map[string]string{"Content-Type": "json"},
			have: map[string][]string{"Content-Type": {"application/json"}},
			exp:  true,
		},
		{
			name: "missing header",
			want: map[string]string{"X-Custom": "value"},
			have: map[string][]string{"Content-Type": {"text/html"}},
			exp:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesHeaders(tt.want, tt.have)
			if got != tt.exp {
				t.Errorf("matchesHeaders() = %v, want %v", got, tt.exp)
			}
		})
	}
}
