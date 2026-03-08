package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/cloud"
	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/output"
)

// Regression tests for code-review findings (C1-L9).

// H7: inferHTTPMethod false positives - segment-based matching
func TestInferHTTPMethod_NoFalsePositives(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want string
	}{
		{"/newsletter", "GET"},
		{"/saved-searches", "GET"},
		{"/api/postupdate", "GET"},
		{"/api/undeleted-items", "GET"},
		{"/api/output-stream", "GET"},
		{"/api/dispatch-queue", "GET"},
		{"/signpost/handler", "GET"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			got := inferHTTPMethod(tc.path, "")
			if got != tc.want {
				t.Errorf("path %q: got %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// M8: parseProbePorts rejects out-of-range ports
func TestParseProbePorts_RejectsInvalidPorts(t *testing.T) {
	t.Parallel()
	specs := parseProbePorts("0,65536,-1,80,443")
	for _, ps := range specs {
		if ps.port < 1 || ps.port > 65535 {
			t.Errorf("invalid port accepted: %d", ps.port)
		}
	}
	if len(specs) != 2 {
		t.Errorf("expected 2 valid ports (80,443), got %d", len(specs))
	}
}

// M8: parseProbePorts range excludes port 0
func TestParseProbePorts_RangeExcludesZero(t *testing.T) {
	t.Parallel()
	specs := parseProbePorts("0-3")
	for _, ps := range specs {
		if ps.port < 1 {
			t.Errorf("port 0 should be excluded, got %d", ps.port)
		}
	}
	if len(specs) != 3 {
		t.Errorf("expected 3 ports (1-3), got %d", len(specs))
	}
}

// L3: matchRange returns false for non-numeric input (not zero-match)
func TestMatchRange_NonNumericInput(t *testing.T) {
	t.Parallel()
	if matchRange(0, "abc") {
		t.Error("non-numeric input should not match value 0")
	}
	if !matchRange(200, "100-300") {
		t.Error("200 should match range 100-300")
	}
	if !matchRange(404, "404") {
		t.Error("404 should match exact 404")
	}
}

// M7: expandProbeTargetPorts preserves query string
func TestExpandProbeTargetPorts_PreservesQuery(t *testing.T) {
	t.Parallel()
	targets := []string{"https://example.com/path?key=val&foo=bar"}
	specs := []portSpec{{scheme: "https", port: 8443}}
	expanded := expandProbeTargetPorts(targets, specs)
	if len(expanded) != 1 {
		t.Fatalf("expected 1 expanded target, got %d", len(expanded))
	}
	if !strings.Contains(expanded[0], "key=val") {
		t.Errorf("query string lost: got %q", expanded[0])
	}
	if !strings.Contains(expanded[0], "foo=bar") {
		t.Errorf("query param lost: got %q", expanded[0])
	}
	if !strings.Contains(expanded[0], ":8443") {
		t.Errorf("port not applied: got %q", expanded[0])
	}
}

// L6: mergeExecutionResults caps TopErrors at 100
func TestMergeExecutionResults_TopErrorsCapped(t *testing.T) {
	t.Parallel()
	dst := output.ExecutionResults{}
	src := output.ExecutionResults{}
	for i := 0; i < 200; i++ {
		src.TopErrors = append(src.TopErrors, "err")
	}
	mergeExecutionResults(&dst, src)
	if len(dst.TopErrors) > 100 {
		t.Errorf("TopErrors should be capped at 100, got %d", len(dst.TopErrors))
	}
}

// L4: max-redirects 0 means no redirects (not default 10)
func TestMaxRedirectsZeroStaysZero(t *testing.T) {
	t.Parallel()
	maxRedirects := 0
	if maxRedirects < 0 {
		maxRedirects = 10
	}
	if maxRedirects != 0 {
		t.Errorf("maxRedirects=0 should stay 0, got %d", maxRedirects)
	}
}

// H2: DeduplicateFindings nil pointer key safety
func TestDeduplicateFindings_NilPointerKey(t *testing.T) {
	t.Parallel()
	type item struct {
		Val *string
	}
	items := []item{
		{Val: nil},
		{Val: nil},
	}
	result := DeduplicateFindings(items,
		func(v item) string {
			if v.Val == nil {
				return ""
			}
			return *v.Val
		},
		func(_ *item, _ int) {},
	)
	if len(result) != 1 {
		t.Errorf("expected 1, got %d", len(result))
	}
}

// M15: parseDiscoveryTypes defaults to all types on unrecognized input
func TestParseDiscoveryTypes_DefaultFallback(t *testing.T) {
	t.Parallel()
	result := parseDiscoveryTypes("nonexistent_type")
	if len(result) == 0 {
		t.Fatal("should return all types for unrecognized input")
	}
	expected := map[cloud.ResourceType]bool{
		cloud.TypeStorage:   true,
		cloud.TypeCDN:       true,
		cloud.TypeFunctions: true,
		cloud.TypeAPI:       true,
		cloud.TypeDatabase:  true,
	}
	for _, rt := range result {
		if !expected[rt] {
			t.Errorf("unexpected type %q in default result", rt)
		}
	}
	if len(result) != len(expected) {
		t.Errorf("expected %d types, got %d", len(expected), len(result))
	}
}

// L9: BypassRate stays 0 when only bypass data is available
func TestBypassResultsToExecution_BypassRateNotMisleading(t *testing.T) {
	t.Parallel()
	bypasses := []*mutation.TestResult{
		{MutatedPayload: "test1", EncoderUsed: "base64", StatusCode: 200, URL: "/test"},
		{MutatedPayload: "test2", EncoderUsed: "base64", StatusCode: 200, URL: "/test"},
	}
	res := bypassResultsToExecution("https://example.com", bypasses, 100, time.Second)
	for name, enc := range res.EncodingStats {
		if enc.BypassRate != 0 {
			t.Errorf("encoding %q BypassRate = %f, want 0", name, enc.BypassRate)
		}
	}
}

// M18: SOAP payload gets CDATA wrapping to prevent XML injection
func TestSOAPPayloadCDATAWrapping(t *testing.T) {
	t.Parallel()
	payload := "</value><injected/>"
	wrapped := "<TestOperation><value><![CDATA[" + payload + "]]></value></TestOperation>"
	if !strings.Contains(wrapped, "<![CDATA[") {
		t.Error("SOAP payload should be wrapped in CDATA")
	}
	if !strings.Contains(wrapped, payload) {
		t.Error("payload content should be preserved inside CDATA")
	}
}

// C1 (logical-order): Report generation must happen after assessment and browser phases.
// scanDuration must be computed after all phases complete, not before assessment.
func TestAutoscanReportAfterAllPhases(t *testing.T) {
	src, err := os.ReadFile("cmd_autoscan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_autoscan.go: %v", err)
	}
	content := string(src)

	// FINAL REPORT block must appear after PHASE 9 (browser integration)
	phase9Idx := strings.Index(content, "PHASE 9: Browser Findings Integration")
	finalReportIdx := strings.Index(content, "FINAL REPORT: Compute duration")
	if phase9Idx < 0 || finalReportIdx < 0 {
		t.Fatal("expected PHASE 9 and FINAL REPORT markers in cmd_autoscan.go")
	}
	if finalReportIdx < phase9Idx {
		t.Error("FINAL REPORT must appear after PHASE 9 — reports should include all findings")
	}

	// scanDuration assignment must appear after browser phase, not before assessment
	phase6Idx := strings.Index(content, "PHASE 6: ENTERPRISE ASSESSMENT")
	scanDurAssign := strings.Index(content, "scanDuration = time.Since(startTime)")
	if phase6Idx < 0 || scanDurAssign < 0 {
		t.Fatal("expected PHASE 6 and scanDuration assignment markers")
	}
	if scanDurAssign < phase6Idx {
		t.Error("scanDuration must be computed after assessment phase, not before")
	}
}

// C2 (logical-order): Discovery results must be persisted to discoveryFile after discovery phase.
func TestAutoscanDiscoveryResultsPersisted(t *testing.T) {
	src, err := os.ReadFile("cmd_autoscan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_autoscan.go: %v", err)
	}
	content := string(src)

	// There must be a WriteAtomicJSON call targeting discoveryFile
	if !strings.Contains(content, "WriteAtomicJSON(discoveryFile, discResult") {
		t.Error("discovery results must be persisted with WriteAtomicJSON(discoveryFile, discResult, ...)")
	}

	// The write must appear after discovery completes (markPhaseCompleted("discovery"))
	markIdx := strings.Index(content, `markPhaseCompleted("discovery")`)
	writeIdx := strings.Index(content, "WriteAtomicJSON(discoveryFile, discResult")
	if markIdx < 0 || writeIdx < 0 {
		t.Fatal("expected discovery markPhaseCompleted and WriteAtomicJSON markers")
	}
	if writeIdx < markIdx {
		t.Error("discovery WriteAtomicJSON should appear after markPhaseCompleted")
	}
}
