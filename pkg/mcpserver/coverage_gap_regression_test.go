package mcpserver

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
)

func TestBuildDiscoverBypassesResponse_BaselineNotBlocked(t *testing.T) {
	args := discoverBypassesArgs{Target: "https://example.com"}
	result := &tampers.BypassDiscoveryResult{
		TargetURL:       args.Target,
		TotalTampers:    12,
		BaselineBlocked: false,
	}

	resp := buildDiscoverBypassesResponse(result, args)
	if !strings.Contains(resp.Summary, "WARNING: Raw payloads were NOT blocked") {
		t.Fatalf("expected baseline warning in summary, got: %q", resp.Summary)
	}
	if !strings.Contains(resp.Interpretation, "requires the WAF to block raw") {
		t.Fatalf("expected baseline interpretation, got: %q", resp.Interpretation)
	}
	if len(resp.NextSteps) != 3 {
		t.Fatalf("expected 3 baseline next steps, got %d", len(resp.NextSteps))
	}
}

func TestBuildDiscoverBypassesResponse_WithBypassesAndCombinations(t *testing.T) {
	args := discoverBypassesArgs{Target: "https://example.com/search?q=test"}
	result := &tampers.BypassDiscoveryResult{
		TargetURL:       args.Target,
		TotalTampers:    20,
		TotalBypasses:   2,
		Duration:        3500 * time.Millisecond,
		BaselineBlocked: true,
		TopBypasses: []tampers.BypassResult{
			{TamperName: "space2comment", Category: "sql", SuccessRate: 0.9, Confidence: "high"},
			{TamperName: "randomcase", Category: "obfuscation", SuccessRate: 0.75, Confidence: "medium"},
		},
		Combinations: []tampers.BypassResult{{TamperName: "space2comment+randomcase"}},
	}

	resp := buildDiscoverBypassesResponse(result, args)
	if !strings.Contains(resp.Summary, "FOUND 2 bypass tampers") {
		t.Fatalf("expected bypass summary, got: %q", resp.Summary)
	}
	if !strings.Contains(resp.Summary, "1 effective tamper combinations found") {
		t.Fatalf("expected combinations summary, got: %q", resp.Summary)
	}
	if !strings.Contains(resp.Interpretation, "space2comment (sql, 90% success, confidence: high)") {
		t.Fatalf("expected detailed interpretation, got: %q", resp.Interpretation)
	}
	if len(resp.NextSteps) < 4 || !strings.Contains(resp.NextSteps[0], "CRITICAL") {
		t.Fatalf("expected critical remediation next steps, got: %#v", resp.NextSteps)
	}
}

func TestBuildDiscoverBypassesResponse_NoBypasses(t *testing.T) {
	args := discoverBypassesArgs{Target: "https://example.com"}
	result := &tampers.BypassDiscoveryResult{
		TargetURL:       args.Target,
		TotalTampers:    9,
		TotalBypasses:   0,
		Duration:        2 * time.Second,
		BaselineBlocked: true,
	}

	resp := buildDiscoverBypassesResponse(result, args)
	if !strings.Contains(resp.Summary, "No bypasses found") {
		t.Fatalf("expected no-bypass summary, got: %q", resp.Summary)
	}
	if !strings.Contains(resp.Interpretation, "All 9 tamper techniques were blocked") {
		t.Fatalf("expected no-bypass interpretation, got: %q", resp.Interpretation)
	}
	if len(resp.NextSteps) != 3 {
		t.Fatalf("expected 3 no-bypass next steps, got %d", len(resp.NextSteps))
	}
}

func TestTLSVersionString_AllBranches(t *testing.T) {
	tests := []struct {
		name string
		in   uint16
		want string
	}{
		{name: "tls10", in: tls.VersionTLS10, want: "TLS 1.0"},
		{name: "tls11", in: tls.VersionTLS11, want: "TLS 1.1"},
		{name: "tls12", in: tls.VersionTLS12, want: "TLS 1.2"},
		{name: "tls13", in: tls.VersionTLS13, want: "TLS 1.3"},
		{name: "unknown", in: 0x9999, want: "unknown (0x9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tlsVersionString(tt.in); got != tt.want {
				t.Fatalf("tlsVersionString(%#x) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildProbeResponse_Unreachable(t *testing.T) {
	report := &probeReport{
		Target:    "https://example.com",
		Reachable: false,
		Error:     "dial tcp timeout",
	}

	resp := buildProbeResponse(report)
	if !strings.Contains(resp.Summary, "NOT reachable") {
		t.Fatalf("expected unreachable summary, got: %q", resp.Summary)
	}
	if !strings.Contains(resp.Interpretation, "unreachable") {
		t.Fatalf("expected unreachable interpretation, got: %q", resp.Interpretation)
	}
	if len(resp.NextSteps) != 4 {
		t.Fatalf("expected 4 recovery steps, got %d", len(resp.NextSteps))
	}
}

func TestBuildProbeResponse_ReachableWithMissingHeadersAndOldTLS(t *testing.T) {
	report := &probeReport{
		Target:     "https://example.com",
		Reachable:  true,
		StatusCode: 200,
		Server:     "nginx",
		TLS: &probeTLSInfo{
			Version:     "TLS 1.1",
			CipherSuite: "TLS_RSA_WITH_AES_128_CBC_SHA",
		},
		SecurityHeaders: []headerCheck{
			{Header: "Strict-Transport-Security", Present: true, Status: "good"},
			{Header: "Content-Security-Policy", Present: false, Status: "missing"},
		},
		RedirectChain: []string{"https://example.com/login", "https://example.com/app"},
	}

	resp := buildProbeResponse(report)
	if !strings.Contains(resp.Summary, "Security headers: 1/2 present") {
		t.Fatalf("expected security header count in summary, got: %q", resp.Summary)
	}
	if !strings.Contains(resp.Interpretation, "OUTDATED") {
		t.Fatalf("expected outdated TLS warning, got: %q", resp.Interpretation)
	}
	if !strings.Contains(resp.Interpretation, "Missing security headers") {
		t.Fatalf("expected missing header warning, got: %q", resp.Interpretation)
	}

	joined := strings.Join(resp.NextSteps, " | ")
	if !strings.Contains(joined, "URGENT: Upgrade TLS") {
		t.Fatalf("expected urgent TLS next step, got: %#v", resp.NextSteps)
	}
	if !strings.Contains(joined, "Add missing security headers") {
		t.Fatalf("expected missing headers next step, got: %#v", resp.NextSteps)
	}
}

func TestEstimateScanDuration_Ranges(t *testing.T) {
	tests := []struct {
		name        string
		payloads    int
		concurrency int
		rateLimit   int
		wantExact   string
		wantContain string
	}{
		{name: "small defaults", payloads: 0, concurrency: 0, rateLimit: 0, wantExact: "5-15s"},
		{name: "under30", payloads: 100, concurrency: 5, rateLimit: 100, wantExact: "10-30s"},
		{name: "under120", payloads: 600, concurrency: 10, rateLimit: 100, wantExact: "30-120s"},
		{name: "over120", payloads: 5000, concurrency: 10, rateLimit: 100, wantContain: "consider narrowing categories for faster results"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateScanDuration(tt.payloads, tt.concurrency, tt.rateLimit)
			if tt.wantExact != "" && got != tt.wantExact {
				t.Fatalf("estimateScanDuration(...) = %q, want %q", got, tt.wantExact)
			}
			if tt.wantContain != "" && !strings.Contains(got, tt.wantContain) {
				t.Fatalf("estimateScanDuration(...) = %q, expected to contain %q", got, tt.wantContain)
			}
		})
	}
}

func TestResponseWriterWrappers_UnwrapAndClosePaths(t *testing.T) {
	rr := httptest.NewRecorder()

	lw := &loggingResponseWriter{ResponseWriter: rr, statusCode: http.StatusOK}
	if lw.Unwrap() != rr {
		t.Fatal("loggingResponseWriter.Unwrap did not return underlying writer")
	}

	kw := &keepAliveWriter{
		ResponseWriter: rr,
		flusher:        rr,
		done:           make(chan struct{}),
		stopped:        make(chan struct{}),
	}
	kw.WriteHeader(http.StatusAccepted)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("keepAliveWriter.WriteHeader code = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if kw.Unwrap() != rr {
		t.Fatal("keepAliveWriter.Unwrap did not return underlying writer")
	}

	var dw discardWriter
	if err := dw.Close(); err != nil {
		t.Fatalf("discardWriter.Close returned error: %v", err)
	}
}
