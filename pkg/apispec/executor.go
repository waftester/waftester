package apispec

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// WAFDetector detects WAF presence and identifies the vendor.
// Implemented by pkg/waf.Detector.
type WAFDetector interface {
	Detect(ctx context.Context, target string) (WAFDetectResult, error)
}

// WAFDetectResult is the subset of waf.DetectionResult that the executor needs.
type WAFDetectResult struct {
	Detected   bool
	Vendor     string
	Confidence float64
}

// RateLimiter controls request pacing to avoid overwhelming the target.
// Implemented by pkg/ratelimit.Limiter.
type RateLimiter interface {
	Wait(ctx context.Context) error
	OnError()
	OnSuccess()
}

// AdaptiveExecutor implements SpecExecutor with 3-phase scanning:
//
//  1. Fingerprint: detect WAF vendor, capture baseline response
//  2. Probe: send 10% of payloads to measure block rate
//  3. Full Scan: execute remaining payloads with escalation based on probe results
//
// If WAF blocks all probes, the executor automatically escalates encoding levels.
// If nothing is blocked, it stays at standard and flags "no WAF detected".
type AdaptiveExecutor struct {
	// BaseURL is the target base URL (spec BaseURL or CLI override).
	BaseURL string

	// ScanFn is called for each plan entry to execute the actual scan.
	ScanFn ScanFunc

	// AuthFn applies authentication to requests.
	AuthFn RequestAuthFunc

	// Concurrency is the max number of concurrent endpoint scans (default: 5).
	Concurrency int

	// Budget caps the total requests the executor may send.
	Budget *RequestBudget

	// WAF detects WAF presence. Optional — skips fingerprinting if nil.
	WAF WAFDetector

	// Limiter controls request pacing. Optional — no throttling if nil.
	Limiter RateLimiter

	// HTTPClient is used for fingerprint and probe requests.
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client

	// ProbePercent is the fraction of plan entries to use as probes (0.0 to 1.0).
	// Default: 0.1 (10%).
	ProbePercent float64

	// OnPhaseStart is called when a scan phase begins.
	OnPhaseStart func(phase string)

	// OnPhaseComplete is called when a scan phase finishes.
	OnPhaseComplete func(phase string, duration time.Duration)

	// OnEndpointStart is called when scanning of an endpoint begins.
	OnEndpointStart func(ep Endpoint, scanType string)

	// OnEndpointComplete is called when scanning of an endpoint finishes.
	OnEndpointComplete func(ep Endpoint, scanType string, findingCount int, err error)

	// OnFinding is called for each finding discovered.
	OnFinding func(f SpecFinding)

	// OnEscalation is called when the executor escalates to a higher evasion level.
	OnEscalation func(from, to EscalationLevel, reason string)
}

// Execute runs the 3-phase scan plan and returns a scan session.
// Phases: fingerprint → probe → full scan.
func (e *AdaptiveExecutor) Execute(ctx context.Context, plan *ScanPlan) (*ScanSession, error) {
	if plan == nil || len(plan.Entries) == 0 {
		return &ScanSession{
			ID:        uuid.New().String(),
			StartedAt: time.Now(),
		}, nil
	}

	session := &ScanSession{
		ID:        uuid.New().String(),
		StartedAt: time.Now(),
	}

	result := &SpecScanResult{
		SpecSource: plan.SpecSource,
		StartedAt:  time.Now(),
	}

	state := NewScanState()

	// Phase 1: Fingerprint.
	fpResult, err := e.phaseFingerprint(ctx, plan)
	if err != nil {
		// Fingerprint failure is non-fatal; proceed with defaults.
		result.AddError(fmt.Sprintf("fingerprint phase: %v", err))
	}

	// Phase 2: Probe.
	probeResult, err := e.phaseProbe(ctx, plan, fpResult, state, result)
	if err != nil {
		result.AddError(fmt.Sprintf("probe phase: %v", err))
	}

	// Phase 3: Full scan.
	err = e.phaseFullScan(ctx, plan, probeResult, state, result)
	if err != nil {
		result.AddError(fmt.Sprintf("full scan phase: %v", err))
	}

	// Finalize.
	result.Finalize()

	session.CompletedAt = result.CompletedAt
	session.Duration = result.Duration
	session.TotalEndpoints = result.TotalEndpoints
	session.TotalTests = result.TotalTests
	session.TotalFindings = result.TotalFindings()
	session.SpecSource = plan.SpecSource
	session.Result = result

	return session, nil
}

// phaseFingerprint detects WAF presence and captures the baseline response.
// Uses 3-5 requests: WAF detection, baseline from spec example, block trigger.
func (e *AdaptiveExecutor) phaseFingerprint(ctx context.Context, plan *ScanPlan) (*FingerprintResult, error) {
	if e.OnPhaseStart != nil {
		e.OnPhaseStart("fingerprint")
	}
	start := time.Now()
	defer func() {
		if e.OnPhaseComplete != nil {
			e.OnPhaseComplete("fingerprint", time.Since(start))
		}
	}()

	fpResult := &FingerprintResult{}

	// WAF detection.
	if e.WAF != nil {
		wafResult, err := e.WAF.Detect(ctx, e.BaseURL)
		if err != nil {
			return fpResult, fmt.Errorf("waf detection: %w", err)
		}
		fpResult.WAFDetected = wafResult.Detected
		fpResult.WAFVendor = wafResult.Vendor
		fpResult.WAFConfidence = wafResult.Confidence
	}

	// Check host error cache before sending requests.
	if parsed, parseErr := url.Parse(e.BaseURL); parseErr == nil {
		if hosterrors.Check(parsed.Hostname()) {
			return fpResult, fmt.Errorf("host %s is in error cache", parsed.Hostname())
		}
	}

	// Capture baseline response by requesting the target.
	client := e.httpClient()
	baselineReq, err := http.NewRequestWithContext(ctx, http.MethodGet, e.BaseURL, nil)
	if err != nil {
		return fpResult, fmt.Errorf("baseline request: %w", err)
	}

	resp, err := client.Do(baselineReq)
	if err != nil {
		return fpResult, fmt.Errorf("baseline request: %w", err)
	}
	body, _ := iohelper.ReadBodyDefault(resp.Body)
	resp.Body.Close()

	fpResult.BaselineStatus = resp.StatusCode
	fpResult.BaselineSize = len(body)

	// Send a known-bad payload to learn the block signature.
	blockReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		e.BaseURL+"?test=<script>alert(1)</script>", nil)
	if err == nil {
		blockResp, blockErr := client.Do(blockReq)
		if blockErr == nil {
			blockBody, _ := iohelper.ReadBodyDefault(blockResp.Body)
			blockResp.Body.Close()

			// If the block response differs from baseline, it's a WAF block signature.
			if blockResp.StatusCode != resp.StatusCode || len(blockBody) != len(body) {
				fpResult.BlockSignature = &BlockSignature{
					StatusCodes: []int{blockResp.StatusCode},
				}
				// Extract body patterns from the block page.
				blockStr := string(blockBody)
				for _, pattern := range knownBlockPatterns {
					if containsCI(blockStr, pattern) {
						fpResult.BlockSignature.BodyPatterns = append(fpResult.BlockSignature.BodyPatterns, pattern)
					}
				}
			}
		}
	}

	return fpResult, nil
}

// phaseProbe sends the first N% of plan entries to measure block rate
// and select the initial escalation level.
func (e *AdaptiveExecutor) phaseProbe(
	ctx context.Context,
	plan *ScanPlan,
	fp *FingerprintResult,
	state *ScanState,
	result *SpecScanResult,
) (*ProbeResult, error) {
	if e.OnPhaseStart != nil {
		e.OnPhaseStart("probe")
	}
	start := time.Now()
	defer func() {
		if e.OnPhaseComplete != nil {
			e.OnPhaseComplete("probe", time.Since(start))
		}
	}()

	probePercent := e.ProbePercent
	if probePercent <= 0 || probePercent > 1.0 {
		probePercent = 0.1
	}

	probeCount := int(float64(len(plan.Entries)) * probePercent)
	if probeCount < 1 {
		probeCount = 1
	}
	if probeCount > len(plan.Entries) {
		probeCount = len(plan.Entries)
	}

	probeEntries := plan.Entries[:probeCount]
	probeResult := &ProbeResult{
		PerCategoryBlockRate: make(map[string]float64),
	}

	// Track per-category block counts.
	type catStats struct {
		total, blocked int
	}
	perCategory := make(map[string]*catStats)

	var totalBlocked int
probeLoop:
	for i, entry := range probeEntries {
		select {
		case <-ctx.Done():
			break probeLoop
		default:
		}

		if e.Limiter != nil {
			if err := e.Limiter.Wait(ctx); err != nil {
				break
			}
		}

		if e.Budget != nil && !e.Budget.Allows(i, time.Since(start)) {
			break
		}

		targetURL, err := resolveEndpointURL(e.BaseURL, entry.Endpoint)
		if err != nil {
			continue
		}

		findings, scanErr := e.ScanFn(ctx, entry.Attack.Category, targetURL, entry.Endpoint)
		if scanErr != nil {
			result.AddError(fmt.Sprintf("probe %s %s [%s]: %v",
				entry.Endpoint.Method, entry.Endpoint.Path, entry.Attack.Category, scanErr))
			if e.Limiter != nil {
				e.Limiter.OnError()
			}
			continue
		}

		if e.Limiter != nil {
			e.Limiter.OnSuccess()
		}

		// Classify: if the scan found nothing and BP knows about block sig, it's blocked.
		blocked := len(findings) == 0 && isRequestBlocked(fp, state)
		if blocked {
			totalBlocked++
		}

		// Track per-category.
		cat := entry.Attack.Category
		if perCategory[cat] == nil {
			perCategory[cat] = &catStats{}
		}
		perCategory[cat].total++
		if blocked {
			perCategory[cat].blocked++
		}

		// Collect findings.
		for _, f := range findings {
			result.AddFinding(f)
			if e.OnFinding != nil {
				e.OnFinding(f)
			}
		}
	}

	probeResult.TotalProbes = len(probeEntries)
	probeResult.BlockedProbes = totalBlocked
	if probeResult.TotalProbes > 0 {
		probeResult.BlockRate = float64(totalBlocked) / float64(probeResult.TotalProbes)
	}

	for cat, stats := range perCategory {
		if stats.total > 0 {
			probeResult.PerCategoryBlockRate[cat] = float64(stats.blocked) / float64(stats.total)
		}
	}

	wafDetected := fp != nil && fp.WAFDetected
	probeResult.EscalationLevel = SelectEscalationLevel(probeResult.BlockRate, wafDetected)

	return probeResult, nil
}

// phaseFullScan executes the remaining plan entries (those not used in probing)
// with the escalation level selected by the probe phase.
func (e *AdaptiveExecutor) phaseFullScan(
	ctx context.Context,
	plan *ScanPlan,
	probe *ProbeResult,
	state *ScanState,
	result *SpecScanResult,
) error {
	if e.OnPhaseStart != nil {
		e.OnPhaseStart("full-scan")
	}
	start := time.Now()
	defer func() {
		if e.OnPhaseComplete != nil {
			e.OnPhaseComplete("full-scan", time.Since(start))
		}
	}()

	// Determine which entries were already probed.
	probePercent := e.ProbePercent
	if probePercent <= 0 || probePercent > 1.0 {
		probePercent = 0.1
	}
	probeCount := int(float64(len(plan.Entries)) * probePercent)
	if probeCount < 1 {
		probeCount = 1
	}
	if probeCount > len(plan.Entries) {
		probeCount = len(plan.Entries)
	}

	remaining := plan.Entries[probeCount:]
	if len(remaining) == 0 {
		return nil
	}

	concurrency := e.Concurrency
	if concurrency < 1 {
		concurrency = 5
	}

	var (
		sem         = make(chan struct{}, concurrency)
		wg          sync.WaitGroup
		sentTotal   atomic.Int64
		endpointMu  sync.Mutex
		endpointSet = make(map[string]bool)
		sentPerEP   = make(map[string]*atomic.Int64)
	)

	escalation := probe.EscalationLevel
	if escalation < EscalationStandard {
		escalation = EscalationStandard
	}

	// Per-category escalation: track block rates and escalate individually.
	catEscalation := make(map[string]EscalationLevel)
	var catMu sync.Mutex

	for _, entry := range remaining {
		select {
		case <-ctx.Done():
			result.AddError(fmt.Sprintf("scan cancelled: %v", ctx.Err()))
			goto done
		default:
		}

		// Budget check.
		elapsed := time.Since(start)
		if e.Budget != nil && !e.Budget.Allows(int(sentTotal.Load()), elapsed) {
			result.AddError("request budget exhausted")
			goto done
		}

		entry := entry // capture
		tag := entry.Endpoint.CorrelationTag
		if tag == "" {
			tag = CorrelationTag(entry.Endpoint.Method, entry.Endpoint.Path)
		}

		endpointMu.Lock()
		endpointSet[tag] = true
		if sentPerEP[tag] == nil {
			sentPerEP[tag] = &atomic.Int64{}
		}
		epCounter := sentPerEP[tag]
		endpointMu.Unlock()

		// Per-endpoint budget check.
		if e.Budget != nil && !e.Budget.AllowsForEndpoint(int(epCounter.Load())) {
			continue
		}

		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			result.AddError(fmt.Sprintf("scan cancelled: %v", ctx.Err()))
			goto done
		}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if e.OnEndpointStart != nil {
				e.OnEndpointStart(entry.Endpoint, entry.Attack.Category)
			}

			// Rate limiting.
			if e.Limiter != nil {
				if err := e.Limiter.Wait(ctx); err != nil {
					return
				}
			}

			targetURL, err := resolveEndpointURL(e.BaseURL, entry.Endpoint)
			if err != nil {
				errMsg := fmt.Sprintf("%s %s: %v", entry.Endpoint.Method, entry.Endpoint.Path, err)
				result.AddError(errMsg)
				if e.OnEndpointComplete != nil {
					e.OnEndpointComplete(entry.Endpoint, entry.Attack.Category, 0, err)
				}
				return
			}

			// Execute scan.
			findings, scanErr := e.ScanFn(ctx, entry.Attack.Category, targetURL, entry.Endpoint)
			sentTotal.Add(1)
			epCounter.Add(1)

			if scanErr != nil {
				errMsg := fmt.Sprintf("%s %s [%s]: %v",
					entry.Endpoint.Method, entry.Endpoint.Path, entry.Attack.Category, scanErr)
				result.AddError(errMsg)
				if e.Limiter != nil {
					e.Limiter.OnError()
				}
			} else if e.Limiter != nil {
				e.Limiter.OnSuccess()
			}

			// Track block rate for per-category escalation.
			cat := entry.Attack.Category
			if len(findings) == 0 && scanErr == nil {
				catMu.Lock()
				currentLevel, ok := catEscalation[cat]
				if !ok {
					currentLevel = escalation
				}
				// Count as blocked (no findings from a valid scan).
				if ShouldEscalate(currentLevel, 1.0) {
					newLevel := currentLevel + 1
					if newLevel > EscalationMultiVector {
						newLevel = EscalationMultiVector
					}
					catEscalation[cat] = newLevel
					if e.OnEscalation != nil {
						e.OnEscalation(currentLevel, newLevel,
							fmt.Sprintf("category %s fully blocked at level %s", cat, currentLevel))
					}
				}
				catMu.Unlock()
			}

			for _, f := range findings {
				result.AddFinding(f)
				if e.OnFinding != nil {
					e.OnFinding(f)
				}
			}

			if e.OnEndpointComplete != nil {
				e.OnEndpointComplete(entry.Endpoint, entry.Attack.Category, len(findings), scanErr)
			}
		}()
	}

	wg.Wait()

done:
	wg.Wait()
	endpointMu.Lock()
	result.TotalEndpoints = len(endpointSet)
	endpointMu.Unlock()
	result.TotalTests = plan.TotalTests

	return nil
}

// httpClient returns the configured HTTP client or the default.
func (e *AdaptiveExecutor) httpClient() *http.Client {
	if e.HTTPClient != nil {
		return e.HTTPClient
	}
	return httpclient.Default()
}

// isRequestBlocked returns true if the probe phase determined that
// requests are being blocked (based on learned block signature).
func isRequestBlocked(fp *FingerprintResult, _ *ScanState) bool {
	return fp != nil && fp.BlockSignature != nil
}

// containsCI checks if s contains substr (case-insensitive).
func containsCI(s, substr string) bool {
	return len(s) >= len(substr) &&
		len(substr) > 0 &&
		// Simple ASCII case-insensitive contains.
		func() bool {
			lower := func(b byte) byte {
				if b >= 'A' && b <= 'Z' {
					return b + 32
				}
				return b
			}
			for i := 0; i <= len(s)-len(substr); i++ {
				match := true
				for j := 0; j < len(substr); j++ {
					if lower(s[i+j]) != lower(substr[j]) {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
			return false
		}()
}

// correlationID generates a unique correlation ID for request tracking.
func correlationID(sessionID, endpointTag, category, injectionPoint string, seq int) string {
	return fmt.Sprintf("waftester-%s-%s-%s-%s-%d",
		sessionID, endpointTag, category, injectionPoint, seq)
}

// payloadHash returns a short hash of a payload for correlation records.
func payloadHash(payload string) string {
	h := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("%x", h[:8])
}

// knownBlockPatterns are common strings found in WAF block pages.
var knownBlockPatterns = []string{
	"access denied",
	"request blocked",
	"forbidden",
	"web application firewall",
	"waf",
	"security",
	"blocked by",
	"cloudflare",
	"akamai",
	"imperva",
	"incapsula",
	"sucuri",
	"mod_security",
	"modsecurity",
	"aws waf",
	"azure front door",
}
