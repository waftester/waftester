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

func TestIsErrorPage_PreservesWAFSignals(t *testing.T) {
	// WAF-relevant status codes must NOT be classified as error pages.
	// These are the primary signals the tool uses to detect WAF blocks.
	// Filtering them would hide the tool's most important output.
	wafCodes := []int{403, 406, 418, 429, 503}
	for _, code := range wafCodes {
		resp := &Response{StatusCode: code, Body: []byte("Request blocked")}
		if isErrorPage(resp) {
			t.Errorf("isErrorPage() returned true for WAF-signal status %d; these must pass through", code)
		}
	}
}

func TestIsErrorPage_FiltersGenericErrors(t *testing.T) {
	tests := []struct {
		name string
		resp *Response
		want bool
	}{
		{
			name: "404 with error body",
			resp: &Response{StatusCode: 404, Body: []byte("Page not found")},
			want: true,
		},
		{
			name: "500 generic error",
			resp: &Response{StatusCode: 500, Body: []byte("Internal Server Error")},
			want: true,
		},
		{
			name: "502 bad gateway",
			resp: &Response{StatusCode: 502, Body: []byte("Bad Gateway")},
			want: true,
		},
		{
			name: "200 is not error page",
			resp: &Response{StatusCode: 200, Body: []byte("OK")},
			want: false,
		},
		{
			name: "301 is not error page",
			resp: &Response{StatusCode: 301, Body: []byte("Moved")},
			want: false,
		},
		{
			name: "200 with error body pattern",
			resp: &Response{StatusCode: 200, Body: []byte("Page not found - custom 200 page")},
			want: true,
		},
		{
			name: "200 with internal server error body",
			resp: &Response{StatusCode: 200, Body: []byte("internal server error occurred")},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isErrorPage(tt.resp); got != tt.want {
				t.Errorf("isErrorPage(status=%d) = %v, want %v", tt.resp.StatusCode, got, tt.want)
			}
		})
	}
}

// --- Negative / edge-case tests ---

func TestNewFilter_NilConfig(t *testing.T) {
	t.Parallel()
	f := NewFilter(nil)
	if f == nil {
		t.Fatal("NewFilter(nil) returned nil")
	}
	// Default modes should be set
	if f.config.MatchMode != ModeOr {
		t.Errorf("default MatchMode = %q, want %q", f.config.MatchMode, ModeOr)
	}
	if f.config.FilterMode != ModeOr {
		t.Errorf("default FilterMode = %q, want %q", f.config.FilterMode, ModeOr)
	}
	// Should show any response with no criteria
	resp := &Response{StatusCode: 200}
	if !f.ShouldShow(resp) {
		t.Error("nil-config filter should show all responses")
	}
}

func TestShouldShow_NilBody(t *testing.T) {
	t.Parallel()
	f := NewFilter(&Config{MatchString: []string{"needle"}})
	resp := &Response{StatusCode: 200, Body: nil}
	// nil body cannot contain "needle" → should not match → not shown
	if f.ShouldShow(resp) {
		t.Error("MatchString with nil body should not show")
	}
}

func TestShouldShow_EmptyBody_MatchRegex(t *testing.T) {
	t.Parallel()
	f := NewFilter(&Config{MatchRegex: []*regexp.Regexp{regexp.MustCompile(`\d+`)}})
	resp := &Response{StatusCode: 200, Body: []byte{}}
	if f.ShouldShow(resp) {
		t.Error("regex requiring digits should not match empty body")
	}
}

func TestShouldShow_FilterRegexNilBody(t *testing.T) {
	t.Parallel()
	// FilterRegex on nil body should not panic
	f := NewFilter(&Config{FilterRegex: []*regexp.Regexp{regexp.MustCompile(`error`)}})
	resp := &Response{StatusCode: 200, Body: nil}
	if !f.ShouldShow(resp) {
		t.Error("FilterRegex should not match nil body")
	}
}

func TestShouldShow_DuplicateZeroSimhash(t *testing.T) {
	t.Parallel()
	f := NewFilter(&Config{FilterDuplicates: true})
	resp1 := &Response{StatusCode: 200, Simhash: 0}
	resp2 := &Response{StatusCode: 200, Simhash: 0}
	// Simhash 0 should bypass duplicate detection (code checks Simhash > 0)
	if !f.ShouldShow(resp1) {
		t.Error("first zero-simhash response should show")
	}
	if !f.ShouldShow(resp2) {
		t.Error("second zero-simhash response should also show (0 bypasses dedup)")
	}
}

func TestShouldShow_MatchMode_AND_NoCriteria(t *testing.T) {
	t.Parallel()
	f := NewFilter(&Config{MatchMode: ModeAnd})
	resp := &Response{StatusCode: 200}
	// No match criteria → hasMatchCriteria() is false → shows by default
	if !f.ShouldShow(resp) {
		t.Error("AND mode with no criteria should show all")
	}
}

func TestParseRange_EmptyString(t *testing.T) {
	t.Parallel()
	_, err := ParseRange("")
	if err == nil {
		t.Error("ParseRange(\"\") should return error")
	}
}

func TestParseRange_TrailingDash(t *testing.T) {
	t.Parallel()
	_, err := ParseRange("100-")
	if err == nil {
		t.Error("ParseRange(\"100-\") should return error")
	}
}

func TestParseRange_LeadingDash(t *testing.T) {
	t.Parallel()
	// "-5" splits to ["", "5"], Atoi("") fails
	_, err := ParseRange("-5")
	if err == nil {
		t.Error("ParseRange(\"-5\") should return error")
	}
}

func TestParseRange_ReversedRange(t *testing.T) {
	t.Parallel()
	// "200-100" is syntactically valid but creates a range where Min > Max
	r, err := ParseRange("200-100")
	if err != nil {
		t.Fatalf("ParseRange(\"200-100\") unexpected error: %v", err)
	}
	// The range is accepted but will never match anything via matchesAnyRange
	if r.Min != 200 || r.Max != 100 {
		t.Errorf("expected Range{200,100}, got %+v", r)
	}
	// Confirm it never matches
	if matchesAnyRange([]Range{r}, 150) {
		t.Error("reversed range should not match value between Min and Max")
	}
}

func TestParseRanges_EmptyString(t *testing.T) {
	t.Parallel()
	_, err := ParseRanges("")
	if err == nil {
		t.Error("ParseRanges(\"\") should return error")
	}
}

func TestParseRanges_OnlyCommas(t *testing.T) {
	t.Parallel()
	_, err := ParseRanges(",,")
	if err == nil {
		t.Error("ParseRanges(\",,\") should return error")
	}
}

func TestParseStatusCodes_EmptyString(t *testing.T) {
	t.Parallel()
	_, err := ParseStatusCodes("")
	if err == nil {
		t.Error("ParseStatusCodes(\"\") should return error")
	}
}

func TestParseStatusCodes_ReversedRange(t *testing.T) {
	t.Parallel()
	// "300-200" → loop from 300 to 200 never executes
	codes, err := ParseStatusCodes("300-200")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(codes) != 0 {
		t.Errorf("reversed range should produce 0 codes, got %d", len(codes))
	}
}

func TestParseStatusCodes_ZeroPrefix(t *testing.T) {
	t.Parallel()
	codes, err := ParseStatusCodes("0xx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(codes) != 100 {
		t.Errorf("0xx should produce 100 codes (0-99), got %d", len(codes))
	}
}

func TestMatchesHeaders_EmptyWant(t *testing.T) {
	t.Parallel()
	// Empty want map → vacuously true
	got := matchesHeaders(map[string]string{}, map[string][]string{"X-Foo": {"bar"}})
	if !got {
		t.Error("empty want should match anything")
	}
}

func TestMatchesHeaders_NilHave(t *testing.T) {
	t.Parallel()
	got := matchesHeaders(map[string]string{"X-Foo": "bar"}, nil)
	if got {
		t.Error("nil have should not match")
	}
}

func TestMatchesHeaders_EmptyHeaderValues(t *testing.T) {
	t.Parallel()
	// Key exists but values slice is empty
	got := matchesHeaders(
		map[string]string{"X-Foo": "bar"},
		map[string][]string{"X-Foo": {}},
	)
	if got {
		t.Error("empty header values should not match")
	}
}

func TestCombineResults_Empty(t *testing.T) {
	t.Parallel()
	if combineResults(nil, ModeOr) {
		t.Error("empty results with OR should return false")
	}
	if combineResults(nil, ModeAnd) {
		t.Error("empty results with AND should return false")
	}
}

func TestCombineResults_AllFalse_AND(t *testing.T) {
	t.Parallel()
	if combineResults([]bool{false, false, false}, ModeAnd) {
		t.Error("all-false AND should return false")
	}
}

func TestCombineResults_AllFalse_OR(t *testing.T) {
	t.Parallel()
	if combineResults([]bool{false, false, false}, ModeOr) {
		t.Error("all-false OR should return false")
	}
}

func TestIsErrorPage_NilBody(t *testing.T) {
	t.Parallel()
	// 404 with nil body — status alone triggers error page
	if !isErrorPage(&Response{StatusCode: 404, Body: nil}) {
		t.Error("404 with nil body should be error page")
	}
	// 200 with nil body — should not be error page
	if isErrorPage(&Response{StatusCode: 200, Body: nil}) {
		t.Error("200 with nil body should not be error page")
	}
}

func TestMatchesAnyRange_EmptyRanges(t *testing.T) {
	t.Parallel()
	if matchesAnyRange(nil, 100) {
		t.Error("nil ranges should not match")
	}
	if matchesAnyRange([]Range{}, 100) {
		t.Error("empty ranges should not match")
	}
}

func TestMatchesAnyRange_BoundaryValues(t *testing.T) {
	t.Parallel()
	r := []Range{{Min: 100, Max: 200}}
	if !matchesAnyRange(r, 100) {
		t.Error("Min boundary should match")
	}
	if !matchesAnyRange(r, 200) {
		t.Error("Max boundary should match")
	}
	if matchesAnyRange(r, 99) {
		t.Error("below Min should not match")
	}
	if matchesAnyRange(r, 201) {
		t.Error("above Max should not match")
	}
}
