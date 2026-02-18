package apispec

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// CrossEndpointTestType identifies the kind of cross-endpoint test.
type CrossEndpointTestType string

const (
	CrossEndpointIDOR    CrossEndpointTestType = "idor"
	CrossEndpointRace    CrossEndpointTestType = "race"
	CrossEndpointPrivesc CrossEndpointTestType = "privesc"
)

// CrossEndpointTest describes a test that coordinates multiple endpoints.
type CrossEndpointTest struct {
	// Type is the kind of cross-endpoint test.
	Type CrossEndpointTestType `json:"type"`

	// Endpoints involved in this test.
	Endpoints []Endpoint `json:"endpoints"`

	// Purpose explains what this test checks.
	Purpose string `json:"purpose"`

	// RequiresDualAuth indicates the test needs two auth tokens.
	RequiresDualAuth bool `json:"requires_dual_auth"`
}

// CrossEndpointResult holds the outcome of a cross-endpoint test.
type CrossEndpointResult struct {
	Test       CrossEndpointTest `json:"test"`
	Passed     bool              `json:"passed"`
	StatusCode int               `json:"status_code,omitempty"`
	Finding    *SpecFinding      `json:"finding,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// CrossEndpointConfig controls cross-endpoint test behavior.
type CrossEndpointConfig struct {
	// AuthTokenA is the primary auth token (e.g., admin).
	AuthTokenA string

	// AuthTokenB is the secondary auth token (e.g., regular user).
	AuthTokenB string

	// RaceConcurrency is how many concurrent requests for race tests.
	RaceConcurrency int

	// DryRun prevents actual requests.
	DryRun bool

	// HTTPClient is the client to use for requests.
	HTTPClient *http.Client

	// BaseURL is the target base URL.
	BaseURL string

	// Timeout per request.
	Timeout time.Duration
}

// GenerateCrossEndpointTests analyzes a spec and generates cross-endpoint
// test plans for IDOR, race conditions, and privilege escalation.
func GenerateCrossEndpointTests(spec *Spec) []CrossEndpointTest {
	if spec == nil || len(spec.Endpoints) == 0 {
		return nil
	}

	var tests []CrossEndpointTest

	tests = append(tests, generateIDORTests(spec)...)
	tests = append(tests, generateRaceTests(spec)...)
	tests = append(tests, generatePrivescTests(spec)...)

	return tests
}

// generateIDORTests finds endpoint pairs where a resource can be created
// by one user and accessed by another.
func generateIDORTests(spec *Spec) []CrossEndpointTest {
	var tests []CrossEndpointTest

	// Group endpoints by normalized path.
	groups := make(map[string][]Endpoint)
	for _, ep := range spec.Endpoints {
		normalized := normalizePath(ep.Path)
		groups[normalized] = append(groups[normalized], ep)
	}

	for path, eps := range groups {
		// Look for write+read pairs with ID parameters.
		if !strings.Contains(path, "{_}") {
			continue
		}

		var writers, readers []Endpoint
		for _, ep := range eps {
			switch strings.ToUpper(ep.Method) {
			case "POST", "PUT", "PATCH":
				writers = append(writers, ep)
			case "GET":
				readers = append(readers, ep)
			}
		}

		// For each writer-reader pair, generate an IDOR test.
		for _, w := range writers {
			for _, r := range readers {
				tests = append(tests, CrossEndpointTest{
					Type:             CrossEndpointIDOR,
					Endpoints:        []Endpoint{w, r},
					Purpose:          fmt.Sprintf("IDOR: create via %s %s, access via %s %s with different auth", w.Method, w.Path, r.Method, r.Path),
					RequiresDualAuth: true,
				})
			}
		}
	}

	return tests
}

// generateRaceTests finds state-changing endpoints that could be vulnerable
// to race conditions.
func generateRaceTests(spec *Spec) []CrossEndpointTest {
	var tests []CrossEndpointTest

	for _, ep := range spec.Endpoints {
		method := strings.ToUpper(ep.Method)
		if method != "POST" && method != "PUT" && method != "PATCH" {
			continue
		}

		// Look for endpoints that affect state (payments, transfers, etc.).
		lower := strings.ToLower(ep.Path)
		isStateful := false
		for _, keyword := range []string{
			"pay", "transfer", "checkout", "order", "redeem",
			"coupon", "credit", "withdraw", "deposit", "vote",
		} {
			if strings.Contains(lower, keyword) {
				isStateful = true
				break
			}
		}
		if !isStateful {
			continue
		}

		tests = append(tests, CrossEndpointTest{
			Type:      CrossEndpointRace,
			Endpoints: []Endpoint{ep},
			Purpose:   fmt.Sprintf("race condition: concurrent %s %s may allow double-spend", method, ep.Path),
		})
	}

	return tests
}

// generatePrivescTests finds admin/privileged endpoints that should be
// tested with low-privilege tokens.
func generatePrivescTests(spec *Spec) []CrossEndpointTest {
	var tests []CrossEndpointTest

	for _, ep := range spec.Endpoints {
		if !isPrivilegedEndpoint(ep) {
			continue
		}

		tests = append(tests, CrossEndpointTest{
			Type:             CrossEndpointPrivesc,
			Endpoints:        []Endpoint{ep},
			Purpose:          fmt.Sprintf("privesc: access %s %s with low-privilege token", ep.Method, ep.Path),
			RequiresDualAuth: true,
		})
	}

	return tests
}

// isPrivilegedEndpoint checks if an endpoint is likely admin/privileged.
func isPrivilegedEndpoint(ep Endpoint) bool {
	lower := strings.ToLower(ep.Path)

	for _, prefix := range []string{"/admin", "/manage", "/internal", "/debug", "/config"} {
		if strings.Contains(lower, prefix) {
			return true
		}
	}

	for _, tag := range ep.Tags {
		t := strings.ToLower(tag)
		if t == "admin" || t == "management" || t == "internal" {
			return true
		}
	}

	return false
}

// ExecuteCrossEndpointTests runs generated cross-endpoint tests.
// Tests that require dual auth are skipped if only one auth token is provided.
func ExecuteCrossEndpointTests(ctx context.Context, tests []CrossEndpointTest, cfg CrossEndpointConfig) []CrossEndpointResult {
	var results []CrossEndpointResult

	hasDualAuth := cfg.AuthTokenA != "" && cfg.AuthTokenB != ""

	for _, test := range tests {
		if test.RequiresDualAuth && !hasDualAuth {
			results = append(results, CrossEndpointResult{
				Test:  test,
				Error: "skipped: requires dual auth (--auth-a and --auth-b)",
			})
			continue
		}

		if cfg.DryRun {
			results = append(results, CrossEndpointResult{
				Test: test,
			})
			continue
		}

		switch test.Type {
		case CrossEndpointIDOR:
			results = append(results, executeIDORTest(ctx, test, cfg))
		case CrossEndpointRace:
			results = append(results, executeRaceTest(ctx, test, cfg))
		case CrossEndpointPrivesc:
			results = append(results, executePrivescTest(ctx, test, cfg))
		}
	}

	return results
}

func executeIDORTest(ctx context.Context, test CrossEndpointTest, cfg CrossEndpointConfig) CrossEndpointResult {
	if len(test.Endpoints) < 2 {
		return CrossEndpointResult{Test: test, Error: "IDOR requires 2 endpoints"}
	}

	reader := test.Endpoints[1]
	url := cfg.BaseURL + substitutePathParams(reader.Path)

	// Try accessing the read endpoint with auth B (should fail if access control works).
	req, err := http.NewRequestWithContext(ctx, reader.Method, url, nil)
	if err != nil {
		return CrossEndpointResult{Test: test, Error: fmt.Sprintf("create request: %v", err)}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AuthTokenB)

	client := cfg.HTTPClient
	if client == nil {
		client = httpclient.Default()
	}

	resp, err := client.Do(req)
	if err != nil {
		return CrossEndpointResult{Test: test, Error: fmt.Sprintf("request failed: %v", err)}
	}
	defer iohelper.DrainAndClose(resp.Body)

	result := CrossEndpointResult{
		Test:       test,
		StatusCode: resp.StatusCode,
	}

	// If we get 200 with the wrong auth, that's an IDOR finding.
	if resp.StatusCode == http.StatusOK {
		result.Finding = &SpecFinding{
			Method:         reader.Method,
			Path:           reader.Path,
			CorrelationTag: CorrelationTag(reader.Method, reader.Path),
			Category:       "idor",
			Title:          "IDOR: resource accessible with different auth",
			Description:    test.Purpose,
			Severity:       string(finding.High),
			CWE:            "CWE-639",
		}
	} else {
		result.Passed = true
	}

	return result
}

func executeRaceTest(ctx context.Context, test CrossEndpointTest, cfg CrossEndpointConfig) CrossEndpointResult {
	if len(test.Endpoints) == 0 {
		return CrossEndpointResult{Test: test, Error: "race requires at least 1 endpoint"}
	}

	ep := test.Endpoints[0]
	url := cfg.BaseURL + substitutePathParams(ep.Path)

	concurrency := cfg.RaceConcurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	client := cfg.HTTPClient
	if client == nil {
		client = httpclient.Default()
	}

	// Build a request body for state-changing methods.
	var bodyBytes []byte
	method := strings.ToUpper(ep.Method)
	if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyBytes = []byte(`{"test": true}`)
	}

	// Fire concurrent requests.
	var wg sync.WaitGroup
	statusCodes := make([]int, concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			var body *bytes.Reader
			if bodyBytes != nil {
				body = bytes.NewReader(bodyBytes)
			}

			var reqBody interface{ Read([]byte) (int, error) }
			if body != nil {
				reqBody = body
			}

			req, err := http.NewRequestWithContext(ctx, ep.Method, url, reqBody)
			if err != nil {
				errs[idx] = err
				return
			}
			if cfg.AuthTokenA != "" {
				req.Header.Set("Authorization", "Bearer "+cfg.AuthTokenA)
			}
			if bodyBytes != nil {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := client.Do(req)
			if err != nil {
				errs[idx] = err
				return
			}
			defer iohelper.DrainAndClose(resp.Body)
			statusCodes[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	// Collect goroutine errors.
	var errMsgs []string
	for _, e := range errs {
		if e != nil {
			errMsgs = append(errMsgs, e.Error())
		}
	}

	// Count successes — if more than 1 succeeded, possible race condition.
	successes := 0
	for _, code := range statusCodes {
		if code == http.StatusOK || code == http.StatusCreated || code == http.StatusAccepted {
			successes++
		}
	}

	result := CrossEndpointResult{
		Test: test,
	}

	if len(errMsgs) > 0 {
		result.Error = fmt.Sprintf("%d/%d requests failed: %s",
			len(errMsgs), concurrency, errMsgs[0])
	}

	if successes > 1 {
		result.Finding = &SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: CorrelationTag(ep.Method, ep.Path),
			Category:       "race",
			Title:          fmt.Sprintf("Race condition: %d/%d concurrent requests succeeded", successes, concurrency),
			Description:    test.Purpose,
			Severity:       string(finding.High),
			CWE:            "CWE-362",
		}
	} else {
		result.Passed = true
	}

	return result
}

func executePrivescTest(ctx context.Context, test CrossEndpointTest, cfg CrossEndpointConfig) CrossEndpointResult {
	if len(test.Endpoints) == 0 {
		return CrossEndpointResult{Test: test, Error: "privesc requires at least 1 endpoint"}
	}

	ep := test.Endpoints[0]
	url := cfg.BaseURL + substitutePathParams(ep.Path)
	req, err := http.NewRequestWithContext(ctx, ep.Method, url, nil)
	if err != nil {
		return CrossEndpointResult{Test: test, Error: fmt.Sprintf("create request: %v", err)}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AuthTokenB)

	client := cfg.HTTPClient
	if client == nil {
		client = httpclient.Default()
	}

	resp, err := client.Do(req)
	if err != nil {
		return CrossEndpointResult{Test: test, Error: fmt.Sprintf("request failed: %v", err)}
	}
	defer iohelper.DrainAndClose(resp.Body)

	result := CrossEndpointResult{
		Test:       test,
		StatusCode: resp.StatusCode,
	}

	// Admin endpoint returning 200 for user token = privesc.
	if resp.StatusCode == http.StatusOK {
		result.Finding = &SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: CorrelationTag(ep.Method, ep.Path),
			Category:       "accesscontrol",
			Title:          "Privilege escalation: admin endpoint accessible with user token",
			Description:    test.Purpose,
			Severity:       string(finding.Critical),
			CWE:            "CWE-269",
		}
	} else {
		result.Passed = true
	}

	return result
}

// pathParamRe matches path template parameters like {id}, {userId}, etc.
var pathParamRe = regexp.MustCompile(`\{([^}]+)\}`)

// substitutePathParams replaces path template parameters with test values.
// E.g., /users/{id}/posts/{postId} → /users/1/posts/1
func substitutePathParams(path string) string {
	return pathParamRe.ReplaceAllString(path, "1")
}
