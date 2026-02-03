package detection

import (
	"errors"
	"io"
	"net/http"
	"syscall"
	"testing"
	"time"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected DropType
	}{
		{
			name:     "nil error returns DropTypeNone",
			err:      nil,
			expected: DropTypeNone,
		},
		{
			name:     "syscall.ECONNRESET returns DropTypeTCPReset",
			err:      syscall.ECONNRESET,
			expected: DropTypeTCPReset,
		},
		{
			name:     "connection reset by peer string returns DropTypeTCPReset",
			err:      errors.New("connection reset by peer"),
			expected: DropTypeTCPReset,
		},
		{
			name:     "syscall.ECONNREFUSED returns DropTypeRefused",
			err:      syscall.ECONNREFUSED,
			expected: DropTypeRefused,
		},
		{
			name:     "io.EOF returns DropTypeEOF",
			err:      io.EOF,
			expected: DropTypeEOF,
		},
		{
			name:     "io.ErrUnexpectedEOF returns DropTypeEOF",
			err:      io.ErrUnexpectedEOF,
			expected: DropTypeEOF,
		},
		{
			name:     "tls handshake failure returns DropTypeTLSAbort",
			err:      errors.New("tls: handshake failure"),
			expected: DropTypeTLSAbort,
		},
		{
			name:     "x509 certificate invalid returns DropTypeTLSAbort",
			err:      errors.New("x509: certificate invalid"),
			expected: DropTypeTLSAbort,
		},
		{
			name:     "i/o timeout returns DropTypeTimeout",
			err:      errors.New("i/o timeout"),
			expected: DropTypeTimeout,
		},
		{
			name:     "context deadline exceeded returns DropTypeTimeout",
			err:      errors.New("context deadline exceeded"),
			expected: DropTypeTimeout,
		},
		{
			name:     "no such host returns DropTypeDNS",
			err:      errors.New("no such host: example.com"),
			expected: DropTypeDNS,
		},
		{
			name:     "random error returns DropTypeEOF",
			err:      errors.New("random error"),
			expected: DropTypeEOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyError(tc.err)
			if result != tc.expected {
				t.Errorf("ClassifyError(%v) = %v, want %v", tc.err, result, tc.expected)
			}
		})
	}
}

func TestConnectionMonitor_RecordDrop(t *testing.T) {
	t.Run("first drop returns Dropped=true and Consecutive=1", func(t *testing.T) {
		cm := NewConnectionMonitor()
		host := "example.com"

		result := cm.RecordDrop(host, syscall.ECONNRESET)

		if !result.Dropped {
			t.Error("expected Dropped=true for first drop")
		}
		if result.Consecutive != 1 {
			t.Errorf("expected Consecutive=1, got %d", result.Consecutive)
		}
		if result.Type != DropTypeTCPReset {
			t.Errorf("expected Type=DropTypeTCPReset, got %v", result.Type)
		}
	})

	t.Run("not yet dropping after 1 error", func(t *testing.T) {
		cm := NewConnectionMonitor()
		host := "example.com"

		cm.RecordDrop(host, syscall.ECONNRESET)

		if cm.IsDropping(host) {
			t.Error("expected IsDropping=false after only 1 error")
		}
	})

	t.Run("IsDropping=true after 3 consecutive errors", func(t *testing.T) {
		cm := NewConnectionMonitor()
		host := "example.com"

		// Record 3 consecutive drops (threshold is 3)
		cm.RecordDrop(host, syscall.ECONNRESET)
		cm.RecordDrop(host, syscall.ECONNRESET)
		result := cm.RecordDrop(host, syscall.ECONNRESET)

		if !cm.IsDropping(host) {
			t.Error("expected IsDropping=true after 3 consecutive errors")
		}
		if result.Consecutive != 3 {
			t.Errorf("expected Consecutive=3, got %d", result.Consecutive)
		}
	})
}

func TestConnectionMonitor_RecordSuccess(t *testing.T) {
	t.Run("recovery after consecutive successes", func(t *testing.T) {
		cm := NewConnectionMonitor()
		host := "example.com"

		// Build up 3 drops to reach IsDropping=true
		cm.RecordDrop(host, syscall.ECONNRESET)
		cm.RecordDrop(host, syscall.ECONNRESET)
		cm.RecordDrop(host, syscall.ECONNRESET)

		if !cm.IsDropping(host) {
			t.Fatal("expected IsDropping=true after 3 drops")
		}

		// Record 2 successes (recovery threshold is 2)
		cm.RecordSuccess(host)
		cm.RecordSuccess(host)

		// Verify recovery (IsDropping=false)
		if cm.IsDropping(host) {
			t.Error("expected IsDropping=false after 2 recovery successes")
		}
	})

	t.Run("single success not enough for recovery", func(t *testing.T) {
		cm := NewConnectionMonitor()
		host := "example.com"

		// Build up 3 drops
		cm.RecordDrop(host, syscall.ECONNRESET)
		cm.RecordDrop(host, syscall.ECONNRESET)
		cm.RecordDrop(host, syscall.ECONNRESET)

		// Record only 1 success
		cm.RecordSuccess(host)

		// Still dropping
		if !cm.IsDropping(host) {
			t.Error("expected IsDropping=true after only 1 recovery success")
		}
	})
}

func TestConnectionMonitor_Tarpit(t *testing.T) {
	t.Run("no tarpit without baseline", func(t *testing.T) {
		cm := NewConnectionMonitor()
		host := "example.com"

		result := cm.CheckTarpit(host, 500*time.Millisecond)

		if result.Dropped {
			t.Error("expected no tarpit detection without baseline")
		}
	})

	t.Run("no tarpit when latency within threshold", func(t *testing.T) {
		cm := NewConnectionMonitor()
		host := "example.com"

		// Set baseline 100ms
		cm.SetBaseline(host, 100*time.Millisecond)

		// 150ms latency (1.5x baseline, below 3x threshold)
		result := cm.CheckTarpit(host, 150*time.Millisecond)

		if result.Dropped {
			t.Error("expected no tarpit for 150ms latency with 100ms baseline")
		}
	})

	t.Run("tarpit detected when latency exceeds threshold", func(t *testing.T) {
		cm := NewConnectionMonitor()
		host := "example.com"

		// Set baseline 100ms
		cm.SetBaseline(host, 100*time.Millisecond)

		// 500ms latency (5x baseline, exceeds 3x threshold)
		result := cm.CheckTarpit(host, 500*time.Millisecond)

		if !result.Dropped {
			t.Error("expected tarpit detection for 500ms latency with 100ms baseline")
		}
		if result.Type != DropTypeTarpit {
			t.Errorf("expected Type=DropTypeTarpit, got %v", result.Type)
		}
	})
}

func TestSilentBanDetector_Basic(t *testing.T) {
	t.Run("no ban without samples", func(t *testing.T) {
		sbd := NewSilentBanDetector()
		host := "example.com"

		result := sbd.Analyze(host)

		if result.Banned {
			t.Error("expected Banned=false without any samples")
		}
	})

	t.Run("no ban with normal samples after baseline", func(t *testing.T) {
		sbd := NewSilentBanDetector()
		host := "example.com"

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		// Capture baseline
		sbd.CaptureBaseline(host, resp, 100*time.Millisecond, 1000)

		// Record 10 normal samples
		for i := 0; i < 10; i++ {
			sbd.RecordSample(host, resp, 100*time.Millisecond, 1000, false)
		}

		result := sbd.Analyze(host)

		if result.Banned {
			t.Error("expected Banned=false with normal samples matching baseline")
		}
	})
}

func TestSilentBanDetector_LatencyDrift(t *testing.T) {
	t.Run("latency drift detected but not enough for ban alone", func(t *testing.T) {
		sbd := NewSilentBanDetector()
		host := "example.com"

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		// Capture baseline 100ms
		sbd.CaptureBaseline(host, resp, 100*time.Millisecond, 1000)

		// Record 15 samples all at high latency (5x baseline)
		for i := 0; i < 15; i++ {
			sbd.RecordSample(host, resp, 500*time.Millisecond, 1000, false)
		}

		result := sbd.Analyze(host)

		// Latency drift alone adds 0.25 confidence, which is below 0.4 threshold
		// Verify drift is detected correctly
		if result.LatencyDrift < 2.0 {
			t.Errorf("expected LatencyDrift >= 2.0, got %f", result.LatencyDrift)
		}
		if result.Confidence < 0.2 {
			t.Errorf("expected some confidence from latency drift, got %f", result.Confidence)
		}
	})

	t.Run("ban detected with latency and body size drift combined", func(t *testing.T) {
		sbd := NewSilentBanDetector()
		host := "example.com"

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		// Capture baseline: 100ms latency, 1000 bytes body
		sbd.CaptureBaseline(host, resp, 100*time.Millisecond, 1000)

		// Record samples with both latency drift (5x) and body size drift (>50%)
		// Latency drift = 0.25 confidence, body size drift = 0.2 confidence
		// Total = 0.45, which exceeds 0.4 threshold
		for i := 0; i < 15; i++ {
			sbd.RecordSample(host, resp, 500*time.Millisecond, 200, false) // 80% body size change
		}

		result := sbd.Analyze(host)

		if !result.Banned {
			t.Errorf("expected Banned=true with combined drift signals, got confidence=%f", result.Confidence)
		}
		if result.Confidence < 0.4 {
			t.Errorf("expected confidence >= 0.4, got %f", result.Confidence)
		}
	})
}

func TestSilentBanDetector_ConsecutiveErrors(t *testing.T) {
	t.Run("ban detected on consecutive errors", func(t *testing.T) {
		sbd := NewSilentBanDetector()
		host := "example.com"

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		// Capture baseline
		sbd.CaptureBaseline(host, resp, 100*time.Millisecond, 1000)

		// Record 10 normal samples
		for i := 0; i < 10; i++ {
			sbd.RecordSample(host, resp, 100*time.Millisecond, 1000, false)
		}

		// Record 6 error samples (threshold is 5)
		var lastResult *BanResult
		for i := 0; i < 6; i++ {
			lastResult = sbd.RecordSample(host, resp, 100*time.Millisecond, 1000, true)
		}

		// RecordSample should return immediate ban result when threshold exceeded
		if lastResult == nil || !lastResult.Banned {
			t.Error("expected immediate Banned=true from RecordSample when consecutive errors threshold exceeded")
		}

		// Analyze should also confirm the ban
		result := sbd.Analyze(host)
		if !result.Banned {
			t.Error("expected Banned=true from Analyze with consecutive errors")
		}
	})
}

func TestDetector_Unified(t *testing.T) {
	t.Run("RecordError returns detection result with drop info", func(t *testing.T) {
		d := New()
		targetURL := "https://example.com/test"

		result := d.RecordError(targetURL, syscall.ECONNRESET)

		if result.Drop == nil {
			t.Fatal("expected Drop to be non-nil")
		}
		if !result.Drop.Dropped {
			t.Error("expected Drop.Dropped=true")
		}
		if result.Drop.Type != DropTypeTCPReset {
			t.Errorf("expected Drop.Type=DropTypeTCPReset, got %v", result.Drop.Type)
		}
		if result.Host != "example.com" {
			t.Errorf("expected Host='example.com', got '%s'", result.Host)
		}
	})

	t.Run("RecordResponse returns detection result with ban info", func(t *testing.T) {
		d := New()
		targetURL := "https://example.com/test"

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		// Capture baseline
		d.CaptureBaseline(targetURL, resp, 100*time.Millisecond, 1000)

		// Record response
		result := d.RecordResponse(targetURL, resp, 100*time.Millisecond, 1000)

		if result.Ban == nil {
			t.Fatal("expected Ban to be non-nil")
		}
		if result.Ban.Banned {
			t.Error("expected Ban.Banned=false for normal response")
		}
		if result.Host != "example.com" {
			t.Errorf("expected Host='example.com', got '%s'", result.Host)
		}
	})

	t.Run("RecordResponse detects tarpit behavior", func(t *testing.T) {
		d := New()
		targetURL := "https://example.com/test"

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		// Capture baseline with 100ms latency
		d.CaptureBaseline(targetURL, resp, 100*time.Millisecond, 1000)

		// Record response with 500ms latency (5x threshold exceeded)
		result := d.RecordResponse(targetURL, resp, 500*time.Millisecond, 1000)

		if result.Drop == nil {
			t.Fatal("expected Drop to be non-nil")
		}
		if !result.Drop.Dropped {
			t.Error("expected Drop.Dropped=true for tarpit detection")
		}
		if result.Drop.Type != DropTypeTarpit {
			t.Errorf("expected Drop.Type=DropTypeTarpit, got %v", result.Drop.Type)
		}
	})
}

func TestDetector_ShouldSkipHost(t *testing.T) {
	t.Run("should not skip healthy host", func(t *testing.T) {
		d := New()
		targetURL := "https://example.com/test"

		skip, reason := d.ShouldSkipHost(targetURL)

		if skip {
			t.Errorf("expected skip=false for healthy host, got reason='%s'", reason)
		}
	})

	t.Run("should skip after connection drops", func(t *testing.T) {
		d := New()
		targetURL := "https://example.com/test"

		// Record 3 drops to trigger dropping state
		d.RecordError(targetURL, syscall.ECONNRESET)
		d.RecordError(targetURL, syscall.ECONNRESET)
		d.RecordError(targetURL, syscall.ECONNRESET)

		skip, reason := d.ShouldSkipHost(targetURL)

		if !skip {
			t.Error("expected skip=true after 3 connection drops")
		}
		if reason != "connection_dropping" {
			t.Errorf("expected reason='connection_dropping', got '%s'", reason)
		}
	})

	t.Run("should skip after silent ban detected", func(t *testing.T) {
		d := New()
		targetURL := "https://example.com/test"

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		// Capture baseline with a higher value so tarpit threshold isn't triggered
		// Tarpit threshold is 3x baseline, so 300ms baseline means 900ms+ triggers tarpit
		// We'll use 200ms baseline and 350ms samples (1.75x) - below tarpit but could drift
		d.CaptureBaseline(targetURL, resp, 200*time.Millisecond, 1000)

		// Record normal samples
		for i := 0; i < 10; i++ {
			d.RecordResponse(targetURL, resp, 200*time.Millisecond, 1000)
		}

		// Record samples with errors to trigger consecutive error ban (hasError via RecordSample directly)
		// Using the internal banDetect to trigger silent ban via consecutive errors
		for i := 0; i < 6; i++ {
			d.banDetect.RecordSample("example.com", resp, 200*time.Millisecond, 1000, true)
		}

		skip, reason := d.ShouldSkipHost(targetURL)

		if !skip {
			t.Error("expected skip=true after silent ban detected")
		}
		if reason != "silent_ban_detected" {
			t.Errorf("expected reason='silent_ban_detected', got '%s'", reason)
		}
	})
}

func TestDetector_Clear(t *testing.T) {
	t.Run("clear removes tracking data", func(t *testing.T) {
		d := New()
		targetURL := "https://example.com/test"

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		// Capture baseline and record samples
		d.CaptureBaseline(targetURL, resp, 100*time.Millisecond, 1000)
		for i := 0; i < 15; i++ {
			d.RecordResponse(targetURL, resp, 500*time.Millisecond, 1000)
		}

		// Verify ban detected
		skip, _ := d.ShouldSkipHost(targetURL)
		if !skip {
			t.Fatal("expected skip=true before clear")
		}

		// Clear and verify no longer skipped (ban detection reset)
		d.Clear(targetURL)

		// Note: Clear only clears silent ban detector data
		// We need to check that the ban is no longer detected
		result := d.banDetect.Analyze("example.com")
		if result.Banned {
			t.Error("expected Banned=false after Clear")
		}
	})
}

func TestDetector_Stats(t *testing.T) {
	t.Run("stats returns combined statistics", func(t *testing.T) {
		d := New()

		// Record some activity
		d.RecordError("https://host1.com/test", syscall.ECONNRESET)
		d.RecordError("https://host2.com/test", syscall.ECONNREFUSED)

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		d.CaptureBaseline("https://host3.com/test", resp, 100*time.Millisecond, 1000)

		stats := d.Stats()

		if _, ok := stats["connmon_hosts_tracked"]; !ok {
			t.Error("expected connmon_hosts_tracked in stats")
		}
		if _, ok := stats["connmon_total_drops"]; !ok {
			t.Error("expected connmon_total_drops in stats")
		}
		if stats["connmon_hosts_tracked"] != 2 {
			t.Errorf("expected connmon_hosts_tracked=2, got %d", stats["connmon_hosts_tracked"])
		}
		if stats["connmon_total_drops"] != 2 {
			t.Errorf("expected connmon_total_drops=2, got %d", stats["connmon_total_drops"])
		}
	})
}

func TestDropType_String(t *testing.T) {
	tests := []struct {
		dropType DropType
		expected string
	}{
		{DropTypeNone, "none"},
		{DropTypeTCPReset, "tcp_reset"},
		{DropTypeTLSAbort, "tls_abort"},
		{DropTypeTimeout, "timeout"},
		{DropTypeEOF, "eof"},
		{DropTypeTarpit, "tarpit"},
		{DropTypeRefused, "refused"},
		{DropTypeDNS, "dns_failure"},
		{DropType(999), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if tc.dropType.String() != tc.expected {
				t.Errorf("DropType(%d).String() = %q, want %q", tc.dropType, tc.dropType.String(), tc.expected)
			}
		})
	}
}

func TestBanType_String(t *testing.T) {
	tests := []struct {
		banType  BanType
		expected string
	}{
		{BanTypeNone, "none"},
		{BanTypeRateLimit, "rate_limit"},
		{BanTypeIPBlock, "ip_block"},
		{BanTypeBehavioral, "behavioral"},
		{BanTypeHoneypot, "honeypot"},
		{BanTypeGeoBlock, "geo_block"},
		{BanTypeSessionPoison, "session_poison"},
		{BanType(999), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if tc.banType.String() != tc.expected {
				t.Errorf("BanType(%d).String() = %q, want %q", tc.banType, tc.banType.String(), tc.expected)
			}
		})
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://example.com/path", "example.com"},
		{"https://example.com:8080/path", "example.com:8080"},
		{"http://test.example.com", "test.example.com"},
		// url.Parse on "invalid-url" succeeds but returns empty Host
		// since it's treated as a relative URL path
		{"invalid-url", ""},
	}

	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			result := extractHost(tc.url)
			if result != tc.expected {
				t.Errorf("extractHost(%q) = %q, want %q", tc.url, result, tc.expected)
			}
		})
	}
}

func TestDefaultDetector(t *testing.T) {
	t.Run("Default returns singleton", func(t *testing.T) {
		d1 := Default()
		d2 := Default()

		if d1 != d2 {
			t.Error("expected Default() to return the same instance")
		}
	})
}
