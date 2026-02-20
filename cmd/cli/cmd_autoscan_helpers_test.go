package main

import (
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/ratelimit"
)

func TestInferHTTPMethod(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		source   string
		expected string
	}{
		// POST indicators from path
		{"create endpoint", "/api/create-user", "", "POST"},
		{"add endpoint", "/api/add-item", "", "POST"},
		{"upload endpoint", "/api/upload", "", "POST"},
		{"login endpoint", "/auth/login", "", "POST"},
		{"register endpoint", "/auth/register", "", "POST"},
		{"signup endpoint", "/auth/signup", "", "POST"},
		{"submit endpoint", "/form/submit", "", "POST"},
		{"new endpoint", "/api/new-order", "", "POST"},

		// PUT/PATCH indicators from path
		{"update endpoint", "/api/update-profile", "", "PUT"},
		{"edit endpoint", "/api/edit-item", "", "PUT"},
		{"modify endpoint", "/api/modify-record", "", "PUT"},
		{"save endpoint", "/api/save-settings", "", "PUT"},

		// DELETE indicators from path
		{"delete endpoint", "/api/delete-user", "", "DELETE"},
		{"remove endpoint", "/api/remove-item", "", "DELETE"},
		{"destroy endpoint", "/api/destroy-session", "", "DELETE"},

		// Source-based hints (word-boundary matching)
		{"source POST", "/api/data", "fetch POST", "POST"},
		{"source PUT", "/api/data", "method: put", "PUT"},
		{"source DELETE", "/api/data", "action: delete", "DELETE"},
		{"source PATCH", "/api/data", "method PATCH", "PATCH"},

		// Source false-positive prevention — substrings in larger words
		{"signpost not POST", "/api/data", "signpost handler", "GET"},
		{"output not PUT", "/api/data", "output stream", "GET"},
		{"dispatch not PATCH", "/api/data", "dispatch queue", "GET"},
		{"undeleted not DELETE", "/api/data", "undeleted records", "GET"},

		// Source word boundary — method at start/end of string
		{"POST at start", "/api/data", "POST /endpoint", "POST"},
		{"DELETE at end", "/api/data", "method=DELETE", "DELETE"},

		// Default to GET
		{"plain path", "/api/users", "", "GET"},
		{"static resource", "/images/logo.png", "", "GET"},
		{"root path", "/", "", "GET"},
		{"empty path", "", "", "GET"},

		// Case insensitivity
		{"uppercase CREATE", "/API/CREATE", "", "POST"},
		{"mixed case Update", "/Api/Update", "", "PUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferHTTPMethod(tt.path, tt.source)
			if result != tt.expected {
				t.Errorf("inferHTTPMethod(%q, %q) = %q, want %q", tt.path, tt.source, result, tt.expected)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncated with ellipsis", "hello world", 5, "he..."},
		{"empty string", "", 5, ""},
		{"single char truncate", "abcdef", 1, "a"},
		{"zero max", "hello", 0, ""},
		{"long URL truncated", "https://example.com/very/long/path/to/resource?param=value", 30, "https://example.com/very/lo..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.max)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.max, result, tt.expected)
			}
		})
	}
}

func TestSeverityToScore(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "9.5"},
		{"Critical", "9.5"},
		{"CRITICAL", "9.5"},
		{"high", "8.0"},
		{"High", "8.0"},
		{"medium", "5.5"},
		{"Medium", "5.5"},
		{"low", "3.0"},
		{"Low", "3.0"},
		{"info", "1.0"},
		{"unknown", "1.0"},
		{"", "1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := severityToScore(tt.severity)
			if result != tt.expected {
				t.Errorf("severityToScore(%q) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestHandleAdaptiveRate(t *testing.T) {
	t.Run("nil limiter does nothing", func(t *testing.T) {
		// Should not panic
		handleAdaptiveRate(429, "Blocked", nil, func(msg string) {
			t.Error("escalate should not be called with nil limiter")
		})
	})

	newTestLimiter := func() *ratelimit.Limiter {
		return ratelimit.New(&ratelimit.Config{
			AdaptiveSlowdown: true,
			SlowdownFactor:   2.0,
			SlowdownMaxDelay: 5 * time.Second,
			RecoveryRate:     0.5,
		})
	}

	t.Run("429 calls OnError and escalates", func(t *testing.T) {
		limiter := newTestLimiter()
		escalated := false
		handleAdaptiveRate(429, "Blocked", limiter, func(msg string) {
			escalated = true
			if msg != "HTTP 429 Too Many Requests" {
				t.Errorf("unexpected escalation message: %s", msg)
			}
		})
		if !escalated {
			t.Error("expected escalation on 429")
		}
		// Verify limiter delay increased (OnError was called)
		stats := limiter.Stats()
		if stats.CurrentDelay == 0 {
			t.Error("expected limiter delay to increase after OnError")
		}
	})

	t.Run("200 success calls OnSuccess no escalation", func(t *testing.T) {
		limiter := newTestLimiter()
		handleAdaptiveRate(200, "Bypassed", limiter, func(msg string) {
			t.Errorf("unexpected escalation on 200: %s", msg)
		})
	})

	t.Run("403 blocked calls OnSuccess no escalation", func(t *testing.T) {
		limiter := newTestLimiter()
		handleAdaptiveRate(403, "Blocked", limiter, func(msg string) {
			t.Errorf("unexpected escalation on 403 Blocked: %s", msg)
		})
	})

	t.Run("error outcome skips OnSuccess", func(t *testing.T) {
		limiter := newTestLimiter()
		handleAdaptiveRate(0, "Error", limiter, func(msg string) {
			t.Errorf("unexpected escalation on Error outcome: %s", msg)
		})
		// Neither OnError nor OnSuccess called — delay should be zero
		stats := limiter.Stats()
		if stats.CurrentDelay != 0 {
			t.Errorf("expected zero delay on Error outcome, got %v", stats.CurrentDelay)
		}
	})

	t.Run("skipped outcome does not call OnSuccess", func(t *testing.T) {
		limiter := newTestLimiter()
		// Prime with an error to set a non-zero delay
		handleAdaptiveRate(429, "Blocked", limiter, func(string) {})
		delayAfterError := limiter.Stats().CurrentDelay

		// Skipped should NOT trigger recovery
		handleAdaptiveRate(0, "Skipped", limiter, func(msg string) {
			t.Errorf("unexpected escalation on Skipped: %s", msg)
		})
		if limiter.Stats().CurrentDelay < delayAfterError {
			t.Error("Skipped outcome should not trigger recovery")
		}
	})
}

func TestMergeExecutionResults(t *testing.T) {
	t.Run("merge into empty dst", func(t *testing.T) {
		dst := output.ExecutionResults{}
		src := output.ExecutionResults{
			TotalTests:    10,
			PassedTests:   3,
			FailedTests:   2,
			BlockedTests:  4,
			ErrorTests:    1,
			DropsDetected: 1,
			BansDetected:  2,
			HostsSkipped:  1,
			FilteredTests: 3,
			StatusCodes:   map[int]int{200: 3, 403: 4},
			CategoryBreakdown: map[string]int{
				"sqli": 5,
				"xss":  5,
			},
			SeverityBreakdown: map[string]int{"high": 3, "critical": 2},
			OWASPBreakdown:    map[string]int{"A03:2021": 5},
			EndpointStats:     map[string]int{"/api": 3},
			MethodStats:       map[string]int{"POST": 4},
			DetectionStats:    map[string]int{"waf-block": 4},
			BypassPayloads:    []string{"payload1", "payload2"},
			BypassDetails: []output.BypassDetail{
				{Payload: "p1", Category: "sqli", StatusCode: 200},
			},
			TopErrors: []string{"timeout", "connection refused"},
			Latencies: []int64{100, 200, 300},
		}

		mergeExecutionResults(&dst, src)

		if dst.TotalTests != 10 {
			t.Errorf("TotalTests = %d, want 10", dst.TotalTests)
		}
		if dst.PassedTests != 3 {
			t.Errorf("PassedTests = %d, want 3", dst.PassedTests)
		}
		if dst.FailedTests != 2 {
			t.Errorf("FailedTests = %d, want 2", dst.FailedTests)
		}
		if dst.DropsDetected != 1 {
			t.Errorf("DropsDetected = %d, want 1", dst.DropsDetected)
		}
		if dst.BansDetected != 2 {
			t.Errorf("BansDetected = %d, want 2", dst.BansDetected)
		}
		if dst.HostsSkipped != 1 {
			t.Errorf("HostsSkipped = %d, want 1", dst.HostsSkipped)
		}
		if dst.FilteredTests != 3 {
			t.Errorf("FilteredTests = %d, want 3", dst.FilteredTests)
		}
		if dst.StatusCodes[200] != 3 {
			t.Errorf("StatusCodes[200] = %d, want 3", dst.StatusCodes[200])
		}
		if len(dst.BypassPayloads) != 2 {
			t.Errorf("BypassPayloads len = %d, want 2", len(dst.BypassPayloads))
		}
		if len(dst.BypassDetails) != 1 {
			t.Errorf("BypassDetails len = %d, want 1", len(dst.BypassDetails))
		}
		if len(dst.TopErrors) != 2 {
			t.Errorf("TopErrors len = %d, want 2", len(dst.TopErrors))
		}
		if len(dst.Latencies) != 3 {
			t.Errorf("Latencies len = %d, want 3", len(dst.Latencies))
		}
		if dst.SeverityBreakdown["high"] != 3 {
			t.Errorf("SeverityBreakdown[high] = %d, want 3", dst.SeverityBreakdown["high"])
		}
		if dst.OWASPBreakdown["A03:2021"] != 5 {
			t.Errorf("OWASPBreakdown[A03:2021] = %d, want 5", dst.OWASPBreakdown["A03:2021"])
		}
		if dst.EndpointStats["/api"] != 3 {
			t.Errorf("EndpointStats[/api] = %d, want 3", dst.EndpointStats["/api"])
		}
		if dst.MethodStats["POST"] != 4 {
			t.Errorf("MethodStats[POST] = %d, want 4", dst.MethodStats["POST"])
		}
		if dst.DetectionStats["waf-block"] != 4 {
			t.Errorf("DetectionStats[waf-block] = %d, want 4", dst.DetectionStats["waf-block"])
		}
	})

	t.Run("merge into existing dst accumulates", func(t *testing.T) {
		dst := output.ExecutionResults{
			TotalTests:    5,
			FailedTests:   1,
			BlockedTests:  3,
			HostsSkipped:  1,
			FilteredTests: 2,
			StatusCodes:   map[int]int{200: 2, 403: 3},
			CategoryBreakdown: map[string]int{
				"sqli": 3,
			},
			BypassPayloads: []string{"existing"},
			TopErrors:      []string{"err1"},
			Latencies:      []int64{50, 100},
		}
		src := output.ExecutionResults{
			TotalTests:    10,
			FailedTests:   2,
			BlockedTests:  6,
			HostsSkipped:  2,
			FilteredTests: 1,
			StatusCodes:   map[int]int{200: 1, 403: 4, 500: 2},
			CategoryBreakdown: map[string]int{
				"sqli": 2,
				"xss":  5,
			},
			BypassPayloads: []string{"new1", "new2"},
			TopErrors:      []string{"err2"},
			Latencies:      []int64{150},
		}

		mergeExecutionResults(&dst, src)

		if dst.TotalTests != 15 {
			t.Errorf("TotalTests = %d, want 15", dst.TotalTests)
		}
		if dst.FailedTests != 3 {
			t.Errorf("FailedTests = %d, want 3", dst.FailedTests)
		}
		if dst.HostsSkipped != 3 {
			t.Errorf("HostsSkipped = %d, want 3", dst.HostsSkipped)
		}
		if dst.FilteredTests != 3 {
			t.Errorf("FilteredTests = %d, want 3", dst.FilteredTests)
		}
		if dst.StatusCodes[200] != 3 {
			t.Errorf("StatusCodes[200] = %d, want 3", dst.StatusCodes[200])
		}
		if dst.StatusCodes[403] != 7 {
			t.Errorf("StatusCodes[403] = %d, want 7", dst.StatusCodes[403])
		}
		if dst.StatusCodes[500] != 2 {
			t.Errorf("StatusCodes[500] = %d, want 2", dst.StatusCodes[500])
		}
		if dst.CategoryBreakdown["sqli"] != 5 {
			t.Errorf("CategoryBreakdown[sqli] = %d, want 5", dst.CategoryBreakdown["sqli"])
		}
		if dst.CategoryBreakdown["xss"] != 5 {
			t.Errorf("CategoryBreakdown[xss] = %d, want 5", dst.CategoryBreakdown["xss"])
		}
		if len(dst.BypassPayloads) != 3 {
			t.Errorf("BypassPayloads len = %d, want 3", len(dst.BypassPayloads))
		}
		if len(dst.TopErrors) != 2 {
			t.Errorf("TopErrors len = %d, want 2", len(dst.TopErrors))
		}
		if len(dst.Latencies) != 3 {
			t.Errorf("Latencies len = %d, want 3", len(dst.Latencies))
		}
	})

	t.Run("merge with nil encoding stats", func(t *testing.T) {
		dst := output.ExecutionResults{}
		src := output.ExecutionResults{
			EncodingStats: map[string]*output.EncodingEffectiveness{
				"url": {TotalTests: 10, Bypasses: 3, BlockedTests: 7},
			},
		}

		mergeExecutionResults(&dst, src)

		if dst.EncodingStats["url"] == nil {
			t.Fatal("EncodingStats[url] should not be nil")
		}
		if dst.EncodingStats["url"].Bypasses != 3 {
			t.Errorf("EncodingStats[url].Bypasses = %d, want 3", dst.EncodingStats["url"].Bypasses)
		}
	})

	t.Run("merge encoding stats accumulates", func(t *testing.T) {
		dst := output.ExecutionResults{
			EncodingStats: map[string]*output.EncodingEffectiveness{
				"url": {TotalTests: 5, Bypasses: 1, BlockedTests: 4},
			},
		}
		src := output.ExecutionResults{
			EncodingStats: map[string]*output.EncodingEffectiveness{
				"url": {TotalTests: 10, Bypasses: 3, BlockedTests: 7},
			},
		}

		mergeExecutionResults(&dst, src)

		if dst.EncodingStats["url"].TotalTests != 15 {
			t.Errorf("TotalTests = %d, want 15", dst.EncodingStats["url"].TotalTests)
		}
		if dst.EncodingStats["url"].Bypasses != 4 {
			t.Errorf("Bypasses = %d, want 4", dst.EncodingStats["url"].Bypasses)
		}
	})

	t.Run("encoding stats cloned not aliased", func(t *testing.T) {
		src := output.ExecutionResults{
			EncodingStats: map[string]*output.EncodingEffectiveness{
				"base64": {TotalTests: 10, Bypasses: 5, BlockedTests: 5},
			},
		}
		dst := output.ExecutionResults{}

		mergeExecutionResults(&dst, src)

		// Mutating src after merge must not affect dst
		src.EncodingStats["base64"].TotalTests = 999

		if dst.EncodingStats["base64"].TotalTests != 10 {
			t.Errorf("dst was aliased to src: TotalTests = %d, want 10", dst.EncodingStats["base64"].TotalTests)
		}
	})

	t.Run("encoding stats bypass rate recalculated", func(t *testing.T) {
		dst := output.ExecutionResults{
			EncodingStats: map[string]*output.EncodingEffectiveness{
				"url": {TotalTests: 10, Bypasses: 2, BlockedTests: 8, BypassRate: 20.0},
			},
		}
		src := output.ExecutionResults{
			EncodingStats: map[string]*output.EncodingEffectiveness{
				"url": {TotalTests: 10, Bypasses: 8, BlockedTests: 2, BypassRate: 80.0},
			},
		}

		mergeExecutionResults(&dst, src)

		// After merge: 20 total, 10 bypasses → 50%
		wantRate := 50.0
		if dst.EncodingStats["url"].BypassRate != wantRate {
			t.Errorf("BypassRate = %f, want %f", dst.EncodingStats["url"].BypassRate, wantRate)
		}
	})

	t.Run("nil encoding stats value skipped", func(t *testing.T) {
		dst := output.ExecutionResults{}
		src := output.ExecutionResults{
			EncodingStats: map[string]*output.EncodingEffectiveness{
				"url":    {TotalTests: 5, Bypasses: 2, BlockedTests: 3},
				"broken": nil, // nil pointer value — must not panic
			},
		}

		mergeExecutionResults(&dst, src)

		if dst.EncodingStats["url"] == nil || dst.EncodingStats["url"].TotalTests != 5 {
			t.Error("valid encoding stat not merged correctly")
		}
		if dst.EncodingStats["broken"] != nil {
			t.Error("nil encoding stat should have been skipped")
		}
	})
}

func TestMergeExecutionResults_ThenRecalculate(t *testing.T) {
	t.Run("combined latencies produce correct stats", func(t *testing.T) {
		dst := output.ExecutionResults{Latencies: []int64{10, 20, 30}}
		src := output.ExecutionResults{Latencies: []int64{40, 50}}
		mergeExecutionResults(&dst, src)
		recalculateLatencyStats(&dst)

		if len(dst.Latencies) != 5 {
			t.Fatalf("Latencies len = %d, want 5", len(dst.Latencies))
		}
		if dst.LatencyStats.Min != 10 {
			t.Errorf("Min = %d, want 10", dst.LatencyStats.Min)
		}
		if dst.LatencyStats.Max != 50 {
			t.Errorf("Max = %d, want 50", dst.LatencyStats.Max)
		}
		if dst.LatencyStats.Avg != 30 {
			t.Errorf("Avg = %d, want 30", dst.LatencyStats.Avg)
		}
	})

	t.Run("resume with empty latencies preserves stats", func(t *testing.T) {
		// Simulates resume: LatencyStats loaded from JSON, Latencies empty (json:"-")
		dst := output.ExecutionResults{
			LatencyStats: output.LatencyStats{Min: 5, Max: 500, Avg: 100, P50: 80, P95: 400, P99: 480},
		}
		// No sub-passes ran, so no merge happened — Latencies stays empty
		if len(dst.Latencies) > 0 {
			recalculateLatencyStats(&dst)
		}
		// Stats should be preserved
		if dst.LatencyStats.Min != 5 || dst.LatencyStats.Max != 500 || dst.LatencyStats.Avg != 100 {
			t.Errorf("stats corrupted: min=%d max=%d avg=%d", dst.LatencyStats.Min, dst.LatencyStats.Max, dst.LatencyStats.Avg)
		}
	})

	t.Run("resume with sub-pass latencies recalculates", func(t *testing.T) {
		// Simulates resume: loaded from JSON (Latencies empty), then feedback pass merges
		dst := output.ExecutionResults{
			LatencyStats: output.LatencyStats{Min: 5, Max: 500, Avg: 100},
		}
		src := output.ExecutionResults{Latencies: []int64{60, 70, 80}}
		mergeExecutionResults(&dst, src)

		// Should recalculate from the available sub-pass latencies
		if len(dst.Latencies) > 0 {
			recalculateLatencyStats(&dst)
		}
		if dst.LatencyStats.Min != 60 || dst.LatencyStats.Max != 80 {
			t.Errorf("min=%d max=%d, want 60/80", dst.LatencyStats.Min, dst.LatencyStats.Max)
		}
	})
}

func TestPayloadsToCandidates(t *testing.T) {
	pp := []payloads.Payload{
		{Category: "sqli", Payload: "' OR 1=1", TargetPath: "/login", EncodingUsed: "url"},
		{Category: "xss", Payload: "<script>", TargetPath: "/search", EncodingUsed: ""},
	}
	candidates := payloadsToCandidates(pp)

	if len(candidates) != 2 {
		t.Fatalf("len = %d, want 2", len(candidates))
	}
	if candidates[0].Category != "sqli" {
		t.Errorf("candidates[0].Category = %q, want sqli", candidates[0].Category)
	}
	if candidates[0].Path != "/login" {
		t.Errorf("candidates[0].Path = %q, want /login", candidates[0].Path)
	}
	if candidates[0].Encoding != "url" {
		t.Errorf("candidates[0].Encoding = %q, want url", candidates[0].Encoding)
	}
	if candidates[1].Payload != "<script>" {
		t.Errorf("candidates[1].Payload = %q, want <script>", candidates[1].Payload)
	}

	// Empty input
	empty := payloadsToCandidates(nil)
	if len(empty) != 0 {
		t.Errorf("nil input: len = %d, want 0", len(empty))
	}
}

func TestRecalculateLatencyStats(t *testing.T) {
	t.Run("empty latencies zeroes stats", func(t *testing.T) {
		r := &output.ExecutionResults{
			LatencyStats: output.LatencyStats{Min: 100, Max: 500, Avg: 200},
		}
		recalculateLatencyStats(r)
		if r.LatencyStats.Min != 0 || r.LatencyStats.Max != 0 {
			t.Errorf("expected zeroed stats, got min=%d max=%d", r.LatencyStats.Min, r.LatencyStats.Max)
		}
	})

	t.Run("single latency", func(t *testing.T) {
		r := &output.ExecutionResults{Latencies: []int64{42}}
		recalculateLatencyStats(r)
		if r.LatencyStats.Min != 42 || r.LatencyStats.Max != 42 || r.LatencyStats.Avg != 42 {
			t.Errorf("single value: min=%d max=%d avg=%d", r.LatencyStats.Min, r.LatencyStats.Max, r.LatencyStats.Avg)
		}
	})

	t.Run("multiple latencies compute percentiles", func(t *testing.T) {
		// 100 values: 1, 2, 3, ... 100
		latencies := make([]int64, 100)
		for i := range latencies {
			latencies[i] = int64(i + 1)
		}
		r := &output.ExecutionResults{Latencies: latencies}
		recalculateLatencyStats(r)

		if r.LatencyStats.Min != 1 {
			t.Errorf("Min = %d, want 1", r.LatencyStats.Min)
		}
		if r.LatencyStats.Max != 100 {
			t.Errorf("Max = %d, want 100", r.LatencyStats.Max)
		}
		if r.LatencyStats.Avg != 50 {
			t.Errorf("Avg = %d, want 50", r.LatencyStats.Avg)
		}
		if r.LatencyStats.P50 != 51 {
			t.Errorf("P50 = %d, want 51", r.LatencyStats.P50)
		}
		if r.LatencyStats.P95 != 96 {
			t.Errorf("P95 = %d, want 96", r.LatencyStats.P95)
		}
		if r.LatencyStats.P99 != 100 {
			t.Errorf("P99 = %d, want 100", r.LatencyStats.P99)
		}
	})

	t.Run("two elements", func(t *testing.T) {
		r := &output.ExecutionResults{Latencies: []int64{10, 90}}
		recalculateLatencyStats(r)
		if r.LatencyStats.Min != 10 || r.LatencyStats.Max != 90 {
			t.Errorf("min=%d max=%d, want 10/90", r.LatencyStats.Min, r.LatencyStats.Max)
		}
		if r.LatencyStats.Avg != 50 {
			t.Errorf("Avg = %d, want 50", r.LatencyStats.Avg)
		}
		// With floor-based indexing: sorted[2*p/100] for all high percentiles → sorted[1] = 90
		if r.LatencyStats.P50 != 90 {
			t.Errorf("P50 = %d, want 90", r.LatencyStats.P50)
		}
		if r.LatencyStats.P95 != 90 {
			t.Errorf("P95 = %d, want 90", r.LatencyStats.P95)
		}
		if r.LatencyStats.P99 != 90 {
			t.Errorf("P99 = %d, want 90", r.LatencyStats.P99)
		}
	})

	t.Run("unsorted input sorted correctly", func(t *testing.T) {
		r := &output.ExecutionResults{Latencies: []int64{500, 100, 300, 200, 400}}
		recalculateLatencyStats(r)
		if r.LatencyStats.Min != 100 || r.LatencyStats.Max != 500 {
			t.Errorf("unsorted: min=%d max=%d", r.LatencyStats.Min, r.LatencyStats.Max)
		}
	})
}
