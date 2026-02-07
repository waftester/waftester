// Regression tests for concurrency bugs in the SilentBanDetector.
package detection

import (
	"net/http"
	"testing"
	"time"
)

// Regression test for bug: headerChanges grew monotonically without resetting on success,
// causing false positive ban detections after enough successful requests with header diffs.
func TestHeaderChanges_ResetOnSuccess(t *testing.T) {
	t.Parallel()

	d := NewSilentBanDetector()
	host := "test.example.com"

	// Capture a baseline with known headers.
	baseResp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}
	baseResp.Header.Set("Server", "nginx")
	baseResp.Header.Set("Content-Type", "text/html")
	d.CaptureBaseline(host, baseResp, 50*time.Millisecond, 1024)

	// Record error samples to build up consecutiveErrs and headerChanges.
	for i := 0; i < 3; i++ {
		d.RecordSample(host, nil, 100*time.Millisecond, 0, true)
	}

	// Record a successful response — this should reset consecutiveErrs and headerChanges.
	successResp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}
	successResp.Header.Set("Server", "nginx")
	successResp.Header.Set("Content-Type", "text/html")
	d.RecordSample(host, successResp, 50*time.Millisecond, 1024, false)

	// Record one more error — headerChanges should be low (just from this error, not accumulated).
	d.RecordSample(host, nil, 100*time.Millisecond, 0, true)

	// Analyze: should NOT detect a ban because headerChanges was reset by the success.
	result := d.Analyze(host)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}

	// With only 5 samples (3 errors + 1 success + 1 error), consecutive errors = 1,
	// which is below the threshold. No ban should be detected.
	if result.Banned && result.Type == BanTypeBehavioral {
		// If banned due to header changes, the reset didn't work
		for _, ev := range result.Evidence {
			if ev == "significant header changes detected" {
				t.Error("headerChanges was not reset on successful response — monotonic accumulation bug present")
			}
		}
	}
}

// Regression test for bug: ensure RecordSample does not panic when
// resp is nil (error case) and then non-nil (success case) in sequence.
func TestSilentBanDetector_NilRespSequence(t *testing.T) {
	t.Parallel()

	d := NewSilentBanDetector()
	host := "nil-resp.example.com"

	// Capture baseline.
	baseResp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}
	baseResp.Header.Set("Server", "apache")
	d.CaptureBaseline(host, baseResp, 40*time.Millisecond, 512)

	// Mix of nil and non-nil responses should not panic.
	for i := 0; i < 20; i++ {
		if i%3 == 0 {
			// Error sample with nil response.
			d.RecordSample(host, nil, 0, 0, true)
		} else {
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{},
			}
			resp.Header.Set("Server", "apache")
			d.RecordSample(host, resp, 40*time.Millisecond, 512, false)
		}
	}

	// Should complete without panic; verify Analyze works.
	result := d.Analyze(host)
	if result == nil {
		t.Fatal("Analyze returned nil after mixed nil/non-nil responses")
	}
}
