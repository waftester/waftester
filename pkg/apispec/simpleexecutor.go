package apispec

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ScanFunc is the signature for a scanner function that the executor calls.
// name is the scan category (e.g., "sqli"), targetURL is the fully constructed
// endpoint URL. Returns the number of findings and any error.
type ScanFunc func(ctx context.Context, name string, targetURL string, ep Endpoint) (findings []SpecFinding, err error)

// SimpleExecutor implements SpecExecutor. It iterates ScanPlan entries sequentially,
// calling the registered ScanFunc for each entry. P4 replaces this with
// AdaptiveExecutor that adds fingerprint, probe, and evasion phases.
type SimpleExecutor struct {
	// BaseURL is the target base URL (spec BaseURL or CLI override).
	BaseURL string

	// ScanFn is called for each plan entry to execute the actual scan.
	ScanFn ScanFunc

	// AuthFn applies authentication to requests.
	AuthFn RequestAuthFunc

	// Concurrency is the max number of concurrent endpoint scans (default: 1).
	Concurrency int

	// OnEndpointStart is called when scanning of an endpoint begins.
	OnEndpointStart func(ep Endpoint, scanType string)

	// OnEndpointComplete is called when scanning of an endpoint finishes.
	OnEndpointComplete func(ep Endpoint, scanType string, findingCount int, err error)

	// OnFinding is called for each finding discovered.
	OnFinding func(f SpecFinding)
}

// Execute runs the scan plan and returns aggregated results.
func (e *SimpleExecutor) Execute(ctx context.Context, plan *ScanPlan) (*ScanSession, error) {
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

	// Track unique endpoints.
	endpointsSeen := make(map[string]bool)

	concurrency := e.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, entry := range plan.Entries {
		select {
		case <-ctx.Done():
			result.AddError(fmt.Sprintf("scan cancelled: %v", ctx.Err()))
			goto done
		default:
		}

		entry := entry // capture

		tag := entry.Endpoint.CorrelationTag
		if tag == "" {
			tag = CorrelationTag(entry.Endpoint.Method, entry.Endpoint.Path)
		}
		endpointsSeen[tag] = true

		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if e.OnEndpointStart != nil {
				e.OnEndpointStart(entry.Endpoint, entry.Attack.Category)
			}

			// Build the target URL for this endpoint.
			targetURL, err := resolveEndpointURL(e.BaseURL, entry.Endpoint)
			if err != nil {
				errMsg := fmt.Sprintf("%s %s: %v", entry.Endpoint.Method, entry.Endpoint.Path, err)
				result.AddError(errMsg)
				if e.OnEndpointComplete != nil {
					e.OnEndpointComplete(entry.Endpoint, entry.Attack.Category, 0, err)
				}
				return
			}

			// Execute the scan.
			findings, scanErr := e.ScanFn(ctx, entry.Attack.Category, targetURL, entry.Endpoint)
			if scanErr != nil {
				errMsg := fmt.Sprintf("%s %s [%s]: %v", entry.Endpoint.Method, entry.Endpoint.Path, entry.Attack.Category, scanErr)
				result.AddError(errMsg)
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
	result.Finalize()
	result.TotalEndpoints = len(endpointsSeen)
	result.TotalTests = plan.TotalTests

	session.CompletedAt = result.CompletedAt
	session.Duration = result.Duration
	session.TotalEndpoints = result.TotalEndpoints
	session.TotalTests = result.TotalTests
	session.TotalFindings = result.TotalFindings()
	session.SpecSource = plan.SpecSource

	return session, nil
}

// resolveEndpointURL builds a full URL from the base URL and endpoint path,
// expanding path parameters with example/default values.
func resolveEndpointURL(baseURL string, ep Endpoint) (string, error) {
	path := ep.Path
	for _, p := range ep.Parameters {
		if p.In != LocationPath {
			continue
		}
		placeholder := "{" + p.Name + "}"
		val := exampleOrDefault(p)
		path = replaceAll(path, placeholder, val)
	}

	resolved, err := resolveURL(baseURL, path)
	if err != nil {
		return "", err
	}
	return resolved, nil
}
