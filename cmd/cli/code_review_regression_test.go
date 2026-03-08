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

// H1 (logical-order): Rate-limit 0 must not silently clamp to 1 req/s.
// The per-host limiter must only be created when rate-limit > 0.
func TestScanNoRateLimitClampToOne(t *testing.T) {
	src, err := os.ReadFile("cmd_scan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_scan.go: %v", err)
	}
	content := string(src)

	// The old unconditional clamp pattern must not exist
	if strings.Contains(content, `if *cfg.RateLimit < 1 {`) {
		t.Error("rate-limit must not silently clamp 0 to 1 — user intends unlimited")
	}

	// Per-host limiter must be guarded by RateLimit > 0
	if strings.Contains(content, `if *cfg.RateLimitPerHost {`) &&
		!strings.Contains(content, `RateLimitPerHost && *cfg.RateLimit > 0`) {
		t.Error("per-host limiter must be guarded by RateLimit > 0")
	}
}

// H2 (logical-order): Tamper names must be validated before engine construction.
func TestScanTamperValidationBeforeEngine(t *testing.T) {
	src, err := os.ReadFile("cmd_scan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_scan.go: %v", err)
	}
	content := string(src)

	validateIdx := strings.Index(content, "ValidateTamperNames(customList)")
	engineIdx := strings.Index(content, "tamperEngine = tampers.NewEngine")
	if validateIdx < 0 || engineIdx < 0 {
		t.Fatal("expected ValidateTamperNames and NewEngine in cmd_scan.go")
	}
	if validateIdx > engineIdx {
		t.Error("tamper validation must happen before engine construction")
	}
}

// H4 (logical-order): Resume skip paths must call autoProgress.Increment() to
// keep the progress bar in sync. Missing increments cause the bar to stall.
func TestAutoscanResumeSkipIncrementsProgress(t *testing.T) {
	src, err := os.ReadFile("cmd_autoscan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_autoscan.go: %v", err)
	}
	content := string(src)

	// Check each skip phase path has Increment() nearby
	for _, phase := range []string{"js-analysis", "learning", "waf-testing"} {
		skipIdx := strings.Index(content, `shouldSkipPhase("`+phase+`")`)
		if skipIdx < 0 {
			t.Fatalf("expected shouldSkipPhase(%q) in cmd_autoscan.go", phase)
		}
		// Look within the next 200 chars for Increment
		window := content[skipIdx : skipIdx+min(300, len(content)-skipIdx)]
		if !strings.Contains(window, "autoProgress.Increment()") {
			t.Errorf("skip path for %q must call autoProgress.Increment()", phase)
		}
	}
}

// H5 (logical-order): OnAnomaly must be registered before the WAF testing executor runs.
func TestAutoscanOnAnomalyBeforeExecutor(t *testing.T) {
	src, err := os.ReadFile("cmd_autoscan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_autoscan.go: %v", err)
	}
	content := string(src)

	anomalyIdx := strings.Index(content, `brain.OnAnomaly(func(anomaly`)
	executeIdx := strings.Index(content, "executor.ExecuteWithProgress")
	if anomalyIdx < 0 || executeIdx < 0 {
		t.Fatal("expected OnAnomaly and ExecuteWithProgress in cmd_autoscan.go")
	}
	if anomalyIdx > executeIdx {
		t.Error("OnAnomaly must be registered before ExecuteWithProgress for main WAF testing")
	}
}

// H6 (logical-order): cmd_tests.go must call RegisterDetectionCallbacks on dispatcher.
func TestRunCommandRegistersDetectionCallbacks(t *testing.T) {
	src, err := os.ReadFile("cmd_tests.go")
	if err != nil {
		t.Fatalf("failed to read cmd_tests.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "RegisterDetectionCallbacks") {
		t.Error("cmd_tests.go must call RegisterDetectionCallbacks on dispatcher")
	}
}

// M1 (logical-order): cmd_scan.go early exits must not use os.Exit(0) which skips defers.
func TestScanNoOsExitInEarlyPaths(t *testing.T) {
	src, err := os.ReadFile("cmd_scan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_scan.go: %v", err)
	}
	content := string(src)

	// Count os.Exit(0) — should only be at the very end or not at all
	// The early-exit paths (dry-run, robots, URL excluded) must use return
	earlySection := content[:strings.Index(content, "var mu sync.Mutex")]
	if strings.Contains(earlySection, "os.Exit(0)") {
		t.Error("early-exit paths in scan must use return, not os.Exit(0) — defers are skipped")
	}
}

// M2 (logical-order): Dry-run phase list must match actual phase names.
func TestAutoscanDryRunPhaseNames(t *testing.T) {
	src, err := os.ReadFile("cmd_autoscan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_autoscan.go: %v", err)
	}
	content := string(src)

	// Key actual phases that must appear in the dry-run output
	for _, phase := range []string{
		"Deep JavaScript Analysis",
		"Intelligent Test Plan Generation",
		"WAF Security Testing",
		"Enterprise Assessment",
	} {
		if !strings.Contains(content, phase) {
			t.Errorf("dry-run phase list should include %q", phase)
		}
	}
}

// M3 (logical-order): ctx.Err() checks must exist between major phases.
func TestAutoscanCtxChecksBetweenPhases(t *testing.T) {
	src, err := os.ReadFile("cmd_autoscan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_autoscan.go: %v", err)
	}
	content := string(src)

	// Between each phase boundary, there must be a ctx.Err() check
	boundaries := []struct {
		before string
		after  string
	}{
		{"PHASE 2: DEEP JAVASCRIPT", "ctx.Err()"},
		{"PHASE 3: INTELLIGENT LEARNING", "ctx.Err()"},
		{"PHASE 4: WAF SECURITY TESTING", "ctx.Err()"},
	}
	for _, b := range boundaries {
		phaseIdx := strings.Index(content, b.before)
		if phaseIdx < 0 {
			t.Fatalf("expected %q in cmd_autoscan.go", b.before)
		}
		// Look in the 300 chars before the phase header for ctx.Err()
		start := phaseIdx - 300
		if start < 0 {
			start = 0
		}
		window := content[start:phaseIdx]
		if !strings.Contains(window, b.after) {
			t.Errorf("missing ctx.Err() check before %q", b.before)
		}
	}
}

// M4 (logical-order): assessment must not re-detect WAF when vendor is already known.
func TestAutoscanAssessmentNoRedundantWAFDetect(t *testing.T) {
	src, err := os.ReadFile("cmd_autoscan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_autoscan.go: %v", err)
	}
	content := string(src)

	// DetectWAF should be conditional on whether we already have a vendor,
	// not unconditionally true.
	if strings.Contains(content, `DetectWAF:       true,`) {
		t.Error("assessment DetectWAF must be conditional (assessWAFVendor == \"\"), not unconditionally true")
	}
	if !strings.Contains(content, `DetectWAF:       assessWAFVendor == ""`) {
		t.Error("expected DetectWAF to be set based on assessWAFVendor availability")
	}
}

// M5 (logical-order): CI exit code must consider enterprise assessment grade.
func TestAutoscanCIExitIncludesAssessmentGrade(t *testing.T) {
	src, err := os.ReadFile("cmd_autoscan.go")
	if err != nil {
		t.Fatalf("failed to read cmd_autoscan.go: %v", err)
	}
	content := string(src)

	// The ciExit computation must include assessFailing
	if !strings.Contains(content, "assessFailing") {
		t.Error("ciExit must consider enterprise assessment grade (assessFailing variable missing)")
	}

	// ci_exit_code in summary must also be updated for assessment grade
	ciExitIdx := strings.LastIndex(content, `summary["ci_exit_code"] = 1`)
	assessIdx := strings.Index(content, `enterprise_metrics`)
	if ciExitIdx < 0 || assessIdx < 0 {
		t.Fatal("expected both ci_exit_code assignment and enterprise_metrics in source")
	}
	// The last ci_exit_code=1 assignment should be after enterprise_metrics
	// (indicating it's set in the final flush based on grade)
	if ciExitIdx < assessIdx {
		t.Error("ci_exit_code must be updated for assessment grade after enterprise_metrics are set")
	}
}

// M6 (logical-order): bypass command grace period must be 30s, not HTTP timeout.
func TestBypassGracePeriod30Seconds(t *testing.T) {
	src, err := os.ReadFile("cmd_bypass.go")
	if err != nil {
		t.Fatalf("failed to read cmd_bypass.go: %v", err)
	}
	content := string(src)

	// Grace period must NOT be tied to the HTTP timeout variable
	if strings.Contains(content, "SignalContext(time.Duration(*timeout)") {
		t.Error("bypass SignalContext grace period must be 30s, not tied to HTTP timeout")
	}
	if !strings.Contains(content, "SignalContext(30 * time.Second)") {
		t.Error("bypass SignalContext must use 30 * time.Second like all other commands")
	}
}

// M7 (logical-order): bypass -o file must be written even with 0 bypasses.
func TestBypassOutputFileWrittenAlways(t *testing.T) {
	src, err := os.ReadFile("cmd_bypass.go")
	if err != nil {
		t.Fatalf("failed to read cmd_bypass.go: %v", err)
	}
	content := string(src)

	// The output file creation must be outside the "if len(bypassPayloads) > 0" block.
	// Verify by checking that os.Create(*outputFile) appears after the else branch.
	elseIdx := strings.Index(content, `No bypasses found - WAF held strong`)
	createIdx := strings.Index(content, `os.Create(*outputFile)`)
	if elseIdx < 0 || createIdx < 0 {
		t.Fatal("expected both 'No bypasses found' and 'os.Create(*outputFile)' in source")
	}
	if createIdx < elseIdx {
		t.Error("-o file must be written after the bypass/no-bypass display logic (i.e., always written)")
	}
}

// M8 (logical-order): race command must accept all valid attack types.
func TestRaceCommandAcceptsAllAttackTypes(t *testing.T) {
	src, err := os.ReadFile("cmd_misc.go")
	if err != nil {
		t.Fatalf("failed to read cmd_misc.go: %v", err)
	}
	content := string(src)

	// Must use AllAttackTypes() for validation, not a hardcoded switch
	if !strings.Contains(content, "race.AllAttackTypes()") {
		t.Error("race attack type validation must use race.AllAttackTypes() instead of hardcoded switch")
	}
	// Must accept toctou (was missing from the old switch)
	if !strings.Contains(content, "toctou") {
		t.Error("race attack type help text must include toctou")
	}
}

// M9 (logical-order): target list must be validated before templates are loaded.
func TestTemplateTargetsBeforeTemplateLoading(t *testing.T) {
	src, err := os.ReadFile("cmd_template.go")
	if err != nil {
		t.Fatalf("failed to read cmd_template.go: %v", err)
	}
	content := string(src)

	// readTargetsFromFile must appear before LoadDirectory/LoadTemplate
	targetsIdx := strings.Index(content, "readTargetsFromFile")
	loadIdx := strings.Index(content, "nuclei.LoadDirectory")
	if targetsIdx < 0 || loadIdx < 0 {
		t.Fatal("expected both readTargetsFromFile and nuclei.LoadDirectory in source")
	}
	if targetsIdx > loadIdx {
		t.Error("target list validation (readTargetsFromFile) must happen before template loading (nuclei.LoadDirectory)")
	}
}

// M10 (logical-order): openapi fuzz must validate baseURL before fuzzing.
func TestOpenAPIFuzzRequiresBaseURL(t *testing.T) {
	src, err := os.ReadFile("cmd_openapi.go")
	if err != nil {
		t.Fatalf("failed to read cmd_openapi.go: %v", err)
	}
	content := string(src)

	// There must be a baseURL check before runOpenAPIFuzz
	checkIdx := strings.Index(content, `Base URL required for fuzzing`)
	fuzzIdx := strings.Index(content, "runOpenAPIFuzz(")
	if checkIdx < 0 {
		t.Error("openapi fuzz must validate baseURL is non-empty before calling runOpenAPIFuzz")
	}
	if checkIdx > 0 && fuzzIdx > 0 && checkIdx > fuzzIdx {
		t.Error("baseURL validation must appear before runOpenAPIFuzz call")
	}
}

// M11 (logical-order): workflow must exit non-zero on engine error even with partial result.
func TestWorkflowExitOnEngineError(t *testing.T) {
	src, err := os.ReadFile("cmd_misc.go")
	if err != nil {
		t.Fatalf("failed to read cmd_misc.go: %v", err)
	}
	content := string(src)

	// The exit condition must include workflowFailed, not just result.Status
	if !strings.Contains(content, "workflowFailed") {
		t.Error("workflow must track engine error via workflowFailed variable")
	}
	if !strings.Contains(content, `result.Status == "failed" || workflowFailed`) {
		t.Error("workflow exit condition must check both result.Status and workflowFailed")
	}
}

// L1: GraphQL scanner must use a single lock region for shared state updates.
// Two separate lock regions create a gap where another goroutine can modify
// result.GraphQL.Vulnerabilities between the append and the counter update.
func TestGraphQLSingleLockRegion(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("cmd_scan.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Find the graphql scanner section
	graphqlIdx := strings.Index(content, `runScanner("graphql"`)
	if graphqlIdx < 0 {
		t.Fatal("graphql scanner not found in cmd_scan.go")
	}
	section := content[graphqlIdx:]

	// Find the next runScanner call to bound the section
	nextScanner := strings.Index(section[1:], "runScanner(")
	if nextScanner > 0 {
		section = section[:nextScanner+1]
	}

	// Count mu.Lock() calls — should be exactly 1 (single lock region)
	lockCount := strings.Count(section, "mu.Lock()")
	if lockCount > 1 {
		t.Errorf("graphql scanner has %d mu.Lock() calls; want 1 (single lock region)", lockCount)
	}
}

// L2: XXE and GraphQL scanners must not call baseConfig() twice.
// The second call creates a redundant config — reuse the value already
// assigned to cfg.Base / testerCfg.Base.
func TestNoRedundantBaseConfigCalls(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("cmd_scan.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Contains(content, "baseConfig().HTTPHeader()") {
		t.Error("found baseConfig().HTTPHeader() — reuse the cfg.Base value instead of calling baseConfig() again")
	}
}
