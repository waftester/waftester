package tampers

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// BypassDiscoveryConfig configures the automated bypass discovery loop.
type BypassDiscoveryConfig struct {
	TargetURL    string        // URL to test against (required)
	Payloads     []string      // Reference payloads; if empty, uses built-in SQLi/XSS set
	WAFVendor    string        // Detected WAF vendor (empty = test all)
	Concurrency  int           // Parallel tamper tests (default: 5)
	ConfirmCount int           // Additional payloads to confirm each bypass (default: 2)
	TopN         int           // Number of top tampers to try in combinations (default: 5)
	Timeout      time.Duration // Per-request timeout
	HTTPClient   *http.Client
	OnProgress   func(tamperName string, result string) // "blocked", "bypassed", "error"
}

// BypassResult holds the outcome of testing one tamper against the WAF.
type BypassResult struct {
	TamperName    string   `json:"tamper_name"`
	Category      string   `json:"category"`
	Description   string   `json:"description"`
	SuccessRate   float64  `json:"success_rate"` // 0.0 to 1.0
	Confidence    string   `json:"confidence"`   // "high", "medium", "low"
	Bypassed      int      `json:"bypassed"`
	Blocked       int      `json:"blocked"`
	Errors        int      `json:"errors"`
	SamplePayload string   `json:"sample_payload"`         // First payload that bypassed
	SampleOutput  string   `json:"sample_output"`          // Tampered version of that payload
	TamperNames   []string `json:"tamper_names,omitempty"` // For combinations
}

// BypassDiscoveryResult is the full output of a discovery run.
type BypassDiscoveryResult struct {
	TargetURL       string         `json:"target_url"`
	WAFVendor       string         `json:"waf_vendor"`
	TotalTampers    int            `json:"total_tampers"`
	TotalBypasses   int            `json:"total_bypasses"`
	Duration        time.Duration  `json:"duration"`
	Results         []BypassResult `json:"results"`
	TopBypasses     []BypassResult `json:"top_bypasses"`
	Combinations    []BypassResult `json:"combinations"`
	BaselineBlocked bool           `json:"baseline_blocked"`
}

// responseSignature captures the essential characteristics of an HTTP response
// for comparison purposes.
type responseSignature struct {
	statusCode int
	bodySize   int
	bodyHash   string // hex MD5
}

// resembles returns true if two responses look similar enough to be the same class.
func (s responseSignature) resembles(other responseSignature) bool {
	if s.statusCode/100 != other.statusCode/100 {
		return false
	}
	if other.bodySize == 0 {
		return s.bodySize == 0
	}
	ratio := float64(s.bodySize) / float64(other.bodySize)
	if ratio <= 0.8 || ratio >= 1.2 {
		return false
	}
	// Similar size — check content hash when both are available
	if s.bodyHash != "" && other.bodyHash != "" {
		return s.bodyHash == other.bodyHash
	}
	return true
}

// defaultBypassPayloads is the reference set when the user doesn't supply payloads.
var defaultBypassPayloads = []string{
	"' OR 1=1--",
	"1 UNION SELECT username,password FROM users--",
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"../../etc/passwd",
	"; cat /etc/passwd",
}

func (cfg *BypassDiscoveryConfig) defaults() {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.ConfirmCount <= 0 {
		cfg.ConfirmCount = 2
	}
	if cfg.TopN <= 0 {
		cfg.TopN = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	if len(cfg.Payloads) == 0 {
		cfg.Payloads = defaultBypassPayloads
	}
}

// DiscoverBypasses tests every registered tamper against the target to find WAF bypasses.
//
// Algorithm:
//  1. Capture clean baseline (no payload) and blocked baseline (raw payload)
//  2. If raw payload is not blocked, return early — nothing to bypass
//  3. Test each registered tamper: transform payload, send, classify response
//  4. Confirm potential bypasses with additional payloads
//  5. Test pairwise combinations of top successful tampers
//  6. Return ranked results
func DiscoverBypasses(ctx context.Context, cfg BypassDiscoveryConfig) (*BypassDiscoveryResult, error) {
	if cfg.TargetURL == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	cfg.defaults()

	start := time.Now()
	result := &BypassDiscoveryResult{
		TargetURL: cfg.TargetURL,
		WAFVendor: cfg.WAFVendor,
	}

	referencePayload := cfg.Payloads[0]

	// Step 1: Capture baselines
	cleanSig, err := captureSignature(ctx, cfg.HTTPClient, cfg.TargetURL, "")
	if err != nil {
		return nil, fmt.Errorf("capture clean baseline: %w", err)
	}

	blockedSig, err := captureSignature(ctx, cfg.HTTPClient, cfg.TargetURL, referencePayload)
	if err != nil {
		return nil, fmt.Errorf("capture blocked baseline: %w", err)
	}

	// Step 2: Is the raw payload actually blocked?
	result.BaselineBlocked = !blockedSig.resembles(cleanSig)
	if !result.BaselineBlocked {
		result.Duration = time.Since(start)
		return result, nil
	}

	// Step 3: Test every registered tamper
	tamperNames := List()
	result.TotalTampers = len(tamperNames)

	type tamperResult struct {
		name     string
		bypassed bool
		errored  bool
		output   string
	}

	var mu sync.Mutex
	var tamperResults []tamperResult

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, name := range tamperNames {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(tName string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			t := Get(tName)
			if t == nil {
				return
			}

			transformed := t.Transform(referencePayload)
			// Skip if tamper didn't change anything
			if transformed == referencePayload {
				return
			}

			sig, err := captureSignature(ctx, cfg.HTTPClient, cfg.TargetURL, transformed)

			mu.Lock()

			if err != nil {
				tamperResults = append(tamperResults, tamperResult{name: tName, errored: true})
				mu.Unlock()
				if cfg.OnProgress != nil {
					cfg.OnProgress(tName, "error")
				}
				return
			}

			bypassed := sig.resembles(cleanSig) && !sig.resembles(blockedSig)
			tamperResults = append(tamperResults, tamperResult{
				name:     tName,
				bypassed: bypassed,
				output:   transformed,
			})
			mu.Unlock()

			if cfg.OnProgress != nil {
				if bypassed {
					cfg.OnProgress(tName, "bypassed")
				} else {
					cfg.OnProgress(tName, "blocked")
				}
			}
		}(name)
	}
	wg.Wait()

	// Step 4: Confirm bypasses with additional payloads
	var confirmedBypasses []BypassResult
	for _, tr := range tamperResults {
		if !tr.bypassed {
			continue
		}

		t := Get(tr.name)
		if t == nil {
			continue
		}

		bypassed := 1 // already got one
		blocked := 0
		errors := 0

		// Test with additional payloads for confirmation
		confirmPayloads := cfg.Payloads
		if len(confirmPayloads) > cfg.ConfirmCount+1 {
			confirmPayloads = confirmPayloads[1 : cfg.ConfirmCount+1]
		} else if len(confirmPayloads) > 1 {
			confirmPayloads = confirmPayloads[1:]
		} else {
			confirmPayloads = nil
		}

		for _, payload := range confirmPayloads {
			if ctx.Err() != nil {
				break
			}

			transformed := t.Transform(payload)
			sig, err := captureSignature(ctx, cfg.HTTPClient, cfg.TargetURL, transformed)
			if err != nil {
				errors++
				continue
			}
			if sig.resembles(cleanSig) && !sig.resembles(blockedSig) {
				bypassed++
			} else {
				blocked++
			}
		}

		total := bypassed + blocked
		successRate := 0.0
		if total > 0 {
			successRate = float64(bypassed) / float64(total)
		}

		confidence := "low"
		if bypassed >= 3 {
			confidence = "high"
		} else if bypassed >= 2 {
			confidence = "medium"
		}

		confirmedBypasses = append(confirmedBypasses, BypassResult{
			TamperName:    tr.name,
			Category:      string(t.Category()),
			Description:   t.Description(),
			SuccessRate:   successRate,
			Confidence:    confidence,
			Bypassed:      bypassed,
			Blocked:       blocked,
			Errors:        errors,
			SamplePayload: referencePayload,
			SampleOutput:  tr.output,
			TamperNames:   []string{tr.name},
		})
	}

	// Build results for non-bypass tampers too
	for _, tr := range tamperResults {
		t := Get(tr.name)
		cat := ""
		desc := ""
		if t != nil {
			cat = string(t.Category())
			desc = t.Description()
		}
		bypassed := 0
		blocked := 1
		errors := 0
		if tr.bypassed {
			bypassed = 1
			blocked = 0
		}
		if tr.errored {
			blocked = 0
			errors = 1
		}
		result.Results = append(result.Results, BypassResult{
			TamperName:    tr.name,
			Category:      cat,
			Description:   desc,
			SuccessRate:   float64(bypassed),
			Bypassed:      bypassed,
			Blocked:       blocked,
			Errors:        errors,
			SamplePayload: referencePayload,
			SampleOutput:  tr.output,
			TamperNames:   []string{tr.name},
		})
	}

	// Sort confirmed bypasses by success rate descending
	sort.Slice(confirmedBypasses, func(i, j int) bool {
		return confirmedBypasses[i].SuccessRate > confirmedBypasses[j].SuccessRate
	})

	result.TopBypasses = confirmedBypasses
	result.TotalBypasses = len(confirmedBypasses)

	// Step 5: Test combinations of top tampers
	if len(confirmedBypasses) >= 2 {
		topN := cfg.TopN
		if topN > len(confirmedBypasses) {
			topN = len(confirmedBypasses)
		}
		topNames := make([]string, topN)
		for i := 0; i < topN; i++ {
			topNames[i] = confirmedBypasses[i].TamperName
		}
		result.Combinations = testCombinations(ctx, cfg, topNames, cleanSig, blockedSig)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// testCombinations tries pairwise tamper combinations and returns successful ones.
func testCombinations(ctx context.Context, cfg BypassDiscoveryConfig, topTampers []string,
	cleanSig, blockedSig responseSignature) []BypassResult {

	var results []BypassResult
	referencePayload := cfg.Payloads[0]

	for i := 0; i < len(topTampers); i++ {
		for j := i + 1; j < len(topTampers); j++ {
			select {
			case <-ctx.Done():
				return results
			default:
			}

			chained := Chain(referencePayload, topTampers[i], topTampers[j])
			if chained == referencePayload {
				continue
			}

			sig, err := captureSignature(ctx, cfg.HTTPClient, cfg.TargetURL, chained)
			if err != nil {
				continue
			}

			if sig.resembles(cleanSig) && !sig.resembles(blockedSig) {
				// Confirm with one more payload
				confirmed := 1
				total := 1
				if len(cfg.Payloads) > 1 {
					p2 := Chain(cfg.Payloads[1], topTampers[i], topTampers[j])
					sig2, err := captureSignature(ctx, cfg.HTTPClient, cfg.TargetURL, p2)
					if err == nil {
						total++
						if sig2.resembles(cleanSig) && !sig2.resembles(blockedSig) {
							confirmed++
						}
					}
				}

				tA := Get(topTampers[i])
				tB := Get(topTampers[j])
				comboName := topTampers[i] + " + " + topTampers[j]
				comboDesc := ""
				if tA != nil && tB != nil {
					comboDesc = tA.Description() + " + " + tB.Description()
				}

				results = append(results, BypassResult{
					TamperName:    comboName,
					Category:      "combination",
					Description:   comboDesc,
					SuccessRate:   float64(confirmed) / float64(total),
					Confidence:    confidenceStr(confirmed),
					Bypassed:      confirmed,
					Blocked:       total - confirmed,
					SamplePayload: referencePayload,
					SampleOutput:  chained,
					TamperNames:   []string{topTampers[i], topTampers[j]},
				})
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].SuccessRate > results[j].SuccessRate
	})
	return results
}

// captureSignature sends a request with the given payload and returns the response signature.
// If payload is empty, sends a clean GET request.
func captureSignature(ctx context.Context, client *http.Client, targetURL, payload string) (responseSignature, error) {
	reqURL := targetURL
	if payload != "" {
		u, err := url.Parse(targetURL)
		if err != nil {
			return responseSignature{}, fmt.Errorf("parse url: %w", err)
		}
		q := u.Query()
		q.Set("test", payload)
		u.RawQuery = q.Encode()
		reqURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return responseSignature{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return responseSignature{}, fmt.Errorf("send request: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return responseSignature{}, fmt.Errorf("read response: %w", err)
	}

	hash := md5.Sum(body)
	return responseSignature{
		statusCode: resp.StatusCode,
		bodySize:   len(body),
		bodyHash:   fmt.Sprintf("%x", hash),
	}, nil
}

func confidenceStr(count int) string {
	switch {
	case count >= 3:
		return "high"
	case count >= 2:
		return "medium"
	default:
		return "low"
	}
}
