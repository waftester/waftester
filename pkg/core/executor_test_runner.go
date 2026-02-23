package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/bufpool"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/requestpool"
	"github.com/waftester/waftester/pkg/scoring"
	"github.com/waftester/waftester/pkg/ui"
)

// countWordsAndLines efficiently counts words and lines in a byte slice without allocations
func countWordsAndLines(data []byte) (words, lines int) {
	if len(data) == 0 {
		return 0, 0
	}
	
	inWord := false
	for _, b := range data {
		if b == '\n' {
			lines++
		}
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			inWord = false
		} else if !inWord {
			inWord = true
			words++
		}
	}
	lines++ // Account for last line if no trailing newline
	return words, lines
}

// evidencePatterns contains pre-compiled regexes for detecting vulnerability evidence in responses.
var evidencePatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"sql_error", regexp.MustCompile(`(?i)(mysql|postgresql|oracle|sqlite|sql syntax|query failed|ORA-\d+)`)},
	{"stack_trace", regexp.MustCompile(`(?i)(stack trace|at line \d+|exception|Traceback|panic:)`)},
	{"debug_info", regexp.MustCompile(`(?i)(debug|internal error|undefined variable|Notice:)`)},
	{"path_disclosure", regexp.MustCompile(`[A-Z]:\\|/var/www/|/home/\w+|/usr/local/`)},
	{"version_disclosure", regexp.MustCompile(`(?i)(version|v\d+\.\d+\.\d+|PHP/|Apache/|nginx/)`)},
	{"sensitive_data", regexp.MustCompile(`(?i)(password|secret|api.?key|token|credential)`)},
	{"command_output", regexp.MustCompile(`(?i)(uid=\d+|root:|/bin/bash|command not found)`)},
	{"xml_error", regexp.MustCompile(`(?i)(xml parsing|entity|DTD|<!ENTITY)`)},
	{"template_injection", regexp.MustCompile(`(?i)(\{\{.*\}\}|\$\{.*\}|<%.*%>)`)},
}

// executeTest runs a single payload test
func (e *Executor) executeTest(ctx context.Context, payload payloads.Payload) *output.TestResult {
	// Determine HTTP method (default to GET for standard payloads)
	method := payload.Method
	if method == "" {
		method = "GET"
	}

	result := &output.TestResult{
		ID:              payload.ID,
		Category:        payload.Category,
		Severity:        payload.SeverityHint,
		Payload:         payload.Payload,
		Timestamp:       time.Now().Format("15:04:05"),
		Method:          method,
		TargetPath:      payload.TargetPath,
		ContentType:     payload.ContentType,
		ResponseHeaders: nil, // Lazy init only when headers exist
		// Copy encoding info from payload for effectiveness tracking
		EncodingUsed:    payload.EncodingUsed,
		MutationType:    payload.MutationType,
		OriginalPayload: payload.OriginalPayload,
	}

	var req *http.Request
	var err error

	// Determine target URL (use TargetPath if specified, otherwise use base URL)
	targetURL := e.config.TargetURL
	if payload.TargetPath != "" {
		// Use pre-parsed base URL if available
		if e.parsedBase != nil {
			// Clone the base URL and modify the path
			modifiedURL := *e.parsedBase
			modifiedURL.Path = payload.TargetPath
			targetURL = modifiedURL.String()
		} else {
			// Fallback to runtime parsing if initialization failed
			baseURL, parseErr := url.Parse(e.config.TargetURL)
			if parseErr == nil {
				baseURL.Path = payload.TargetPath
				targetURL = baseURL.String()
			}
		}
	}
	// RequestURL is set below after the full URL (with query params) is built.

	// Build request using realistic mode or legacy mode
	if e.enhancer != nil && e.config.RealisticMode {
		// Use realistic request builder with rotating templates
		template := e.enhancer.RotateTemplate()

		// Override template path if payload specifies target
		if payload.TargetPath != "" {
			template.Path = payload.TargetPath
		}

		// Handle method override
		if method != "" {
			template.Method = method
		}

		req, err = e.enhancer.BuildRequestWithTemplate(payload.Payload, template)
		if err == nil {
			req = req.WithContext(ctx)
			result.RequestURL = req.URL.String()
		}
	} else if method == "POST" && payload.ContentType != "" {
		// Legacy: For POST with body (custom payloads from 'learn' command)
		// The payload IS the body (e.g., JSON like {"message": "' OR '1'='1"})
		body := strings.NewReader(payload.Payload)
		origReq := requestpool.GetWithMethod(method)
		defer requestpool.Put(origReq) // Return original to pool
		req = origReq.WithContext(ctx) // Create context-aware copy
		req.URL, err = url.Parse(targetURL)
		if err == nil {
			req.Body = io.NopCloser(body)
			req.ContentLength = int64(len(payload.Payload))
			req.Header.Set("Content-Type", payload.ContentType)
			result.RequestURL = req.URL.String()
		}
	} else {
		// Legacy: For GET or simple payloads, inject in URL parameter
		targetWithPayload := fmt.Sprintf("%s?test=%s", targetURL, url.QueryEscape(payload.Payload))
		origReq := requestpool.GetWithMethod(method)
		defer requestpool.Put(origReq) // Return original to pool
		req = origReq.WithContext(ctx) // Create context-aware copy
		req.URL, err = url.Parse(targetWithPayload)
		if err == nil {
			result.RequestURL = targetWithPayload
		}
	}

	if err != nil {
		result.Outcome = "Error"
		result.ErrorMessage = err.Error()
		// Calculate risk score for error case
		result.RiskScore = scoring.Calculate(scoring.Input{
			Severity: payload.SeverityHint,
			Outcome:  result.Outcome,
			Category: payload.Category,
		})
		return result
	}

	// Only set static User-Agent if not using realistic mode
	if e.enhancer == nil || !e.config.RealisticMode {
		req.Header.Set("User-Agent", ui.UserAgent())
	}

	// Capture request headers after all modifications (User-Agent, Content-Type,
	// realistic mode headers) so HAR output reflects the actual sent headers.
	if len(req.Header) > 0 {
		result.RequestHeaders = make(map[string]string, len(req.Header))
		for key, values := range req.Header {
			if len(values) > 0 {
				result.RequestHeaders[key] = values[0]
			}
		}
		// Add Host header explicitly — Go's net/http doesn't include it in req.Header.
		if req.URL != nil && req.URL.Host != "" {
			result.RequestHeaders["Host"] = req.URL.Host
		}
	}

	start := time.Now()

	// Execute with retry
	var resp *http.Response
retryLoop:
	for attempt := 0; attempt <= e.config.Retries; attempt++ {
		// Re-create body reader for POST requests on retry (readers are consumed after first use)
		if attempt > 0 && method == "POST" {
			if payload.ContentType != "" {
				req.Body = io.NopCloser(strings.NewReader(payload.Payload))
				req.ContentLength = int64(len(payload.Payload))
			} else if e.config.RealisticMode {
				// Realistic mode may have set a POST body without ContentType
				req.Body = io.NopCloser(strings.NewReader(payload.Payload))
				req.ContentLength = int64(len(payload.Payload))
			}
		}

		start = time.Now() // Measure latency for this attempt only
		resp, err = e.httpClient.Do(req)
		if err == nil {
			break
		}
		if attempt < e.config.Retries {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				break retryLoop
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

	result.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Outcome = "Error"
		// Categorize the error for better analysis
		result.ErrorMessage = categorizeError(err)

		// Track network errors to skip failing hosts after threshold
		if hosterrors.IsNetworkError(err) {
			hosterrors.MarkError(e.config.TargetURL)
		}

		// Record error in detection system
		if e.detector != nil {
			dropResult := e.detector.RecordError(e.config.TargetURL, err)
			if dropResult.Drop != nil && dropResult.Drop.Dropped {
				result.ErrorMessage = fmt.Sprintf("[%s] %s", dropResult.Drop.Type.String(), result.ErrorMessage)
			}
		}

		// Calculate risk score for error case
		result.RiskScore = scoring.Calculate(scoring.Input{
			Severity: payload.SeverityHint,
			Outcome:  result.Outcome,
			Category: payload.Category,
		})
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Capture all response headers for HAR output and analysis.
	// Previously only WAF-specific headers were captured, but HAR output
	// and downstream consumers benefit from the full set.
	if len(resp.Header) > 0 {
		result.ResponseHeaders = make(map[string]string, len(resp.Header))
		for key, values := range resp.Header {
			if len(values) > 0 {
				result.ResponseHeaders[key] = values[0]
			}
		}
	}

	// Extract WAF rule ID from common headers/patterns
	for _, h := range []string{"X-Waf-Rule", "X-Mod-Security-Message", "X-Coraza-Rule", "X-Modsecurity-Rule-Id"} {
		if v := resp.Header.Get(h); v != "" {
			result.WAFRuleID = v
			break
		}
	}

	// Read response body for filtering (limited to 1MB)
	bodyBuf := bufpool.GetSized(defaults.BufferHuge)
	defer bufpool.Put(bodyBuf)
	buf := bufpool.GetSlice(defaults.BufferMedium)
	defer bufpool.PutSlice(buf)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			bodyBuf.Write(buf[:n])
			if bodyBuf.Len() >= 1024*1024 {
				break // Limit to 1MB
			}
		}
		if readErr != nil {
			break
		}
	}
	// Calculate word and line counts for filtering (zero-allocation)
	bodyBytes := bodyBuf.Bytes()
	result.WordCount, result.LineCount = countWordsAndLines(bodyBytes)
	
	// Keep bodyStr only for operations that require a string
	var bodyStr string
	result.ContentLength = bodyBuf.Len()

	// Capture baseline for detection AFTER body is read so ContentLength is accurate
	if e.detector != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		e.detector.CaptureBaseline(e.config.TargetURL, resp, time.Duration(result.LatencyMs)*time.Millisecond, result.ContentLength)
	}

	result.StatusCode = resp.StatusCode

	// Apply filters if configured
	if e.config.Filter != nil {
		if bodyStr == "" {
			bodyStr = bodyBuf.String()
		}
		if !e.shouldShowResult(result, bodyStr) {
			result.Filtered = true
			return result
		}
	}

	// Determine outcome using realistic block detection or legacy method
	var isBlocked bool
	var blockConfidence float64

	if e.enhancer != nil && e.config.RealisticMode {
		// Materialize body string for realistic mode analysis
		if bodyStr == "" {
			bodyStr = bodyBuf.String()
		}
		// Use intelligent block detection
		blockResult, detectErr := e.enhancer.AnalyzeResponse(
			&http.Response{
				StatusCode: resp.StatusCode,
				Body:       io.NopCloser(strings.NewReader(bodyStr)),
				Header:     resp.Header,
			},
			time.Duration(result.LatencyMs)*time.Millisecond,
		)
		if detectErr == nil {
			isBlocked = blockResult.IsBlocked
			blockConfidence = blockResult.Confidence
		} else {
			// Fall back to status code check
			isBlocked = resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 || resp.StatusCode == 503
		}
	} else {
		// Legacy: Simple status code check
		isBlocked = resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 || resp.StatusCode == 503
	}

	// Store block confidence as numeric value
	result.BlockConfidence = blockConfidence

	// Determine outcome based on detection and expectations
	if isBlocked {
		result.Outcome = "Blocked"
		if blockConfidence > 0 {
			result.ErrorMessage = fmt.Sprintf("Block confidence: %.0f%%", blockConfidence*100)
		}
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if payload.ExpectedBlock {
			result.Outcome = "Fail" // Should have been blocked!
			// Generate curl command for bypass reproduction
			result.CurlCommand = generateCurlCommand(req)

			// Capture response evidence for bypass analysis
			if bodyStr == "" {
				bodyStr = bodyBuf.String()
			}
			captureResponseEvidence(result, bodyStr, bodyBytes)
		} else {
			result.Outcome = "Pass"
		}
	} else if resp.StatusCode == 404 {
		result.Outcome = "Pass" // Endpoint doesn't exist
	} else {
		result.Outcome = "Error"
		result.ErrorMessage = fmt.Sprintf("Unexpected status: %d", resp.StatusCode)
	}

	// Check for XSS reflection (payload appears in response)
	reflected := false
	if payload.Category == "xss" || payload.Category == "XSS" {
		// Check if key parts of payload are reflected
		payloadCheck := payload.Payload
		if len(payloadCheck) > 20 {
			payloadCheck = payloadCheck[:20] // Check first 20 chars
		}
		reflected = bytes.Contains(bodyBytes, []byte(payloadCheck))
	}

	// Calculate risk score with full context
	// Scoring only checks ResponseContains for sensitive patterns, so pass
	// the body string. If bodyStr wasn't materialized yet, convert from bytes.
	if bodyStr == "" && len(bodyBytes) > 0 {
		bodyStr = string(bodyBytes)
	}
	result.RiskScore = scoring.Calculate(scoring.Input{
		Severity:         payload.SeverityHint,
		Outcome:          result.Outcome,
		StatusCode:       result.StatusCode,
		LatencyMs:        result.LatencyMs,
		Category:         payload.Category,
		ResponseContains: bodyStr,
		Reflected:        reflected,
	})

	// Record response for silent ban detection
	if e.detector != nil {
		detectionResult := e.detector.RecordResponse(e.config.TargetURL, resp, time.Duration(result.LatencyMs)*time.Millisecond, result.ContentLength)
		if detectionResult.Ban != nil && detectionResult.Ban.Banned {
			// Add warning to result
			result.ErrorMessage = fmt.Sprintf("[SILENT_BAN] confidence=%.0f%% %s", detectionResult.Ban.Confidence*100, result.ErrorMessage)
		}
		if detectionResult.Drop != nil && detectionResult.Drop.Dropped && detectionResult.Drop.Type == detection.DropTypeTarpit {
			result.ErrorMessage = fmt.Sprintf("[TARPIT] slow response detected %s", result.ErrorMessage)
		}
	}

	return result
}

// generateCurlCommand creates a curl command to reproduce the request
func generateCurlCommand(req *http.Request) string {
	if req == nil {
		return ""
	}
	cmd := fmt.Sprintf("curl -X %s '%s'", req.Method, req.URL.String())
	for k, v := range req.Header {
		if len(v) > 0 && k != "User-Agent" {
			cmd += fmt.Sprintf(" -H '%s: %s'", k, v[0])
		}
	}
	return cmd
}

// captureResponseEvidence captures response body evidence for bypass analysis
func captureResponseEvidence(result *output.TestResult, bodyStr string, bodyBytes []byte) {
	// Capture snippet (first 300 chars, sanitized)
	snippet := bodyStr
	if len(snippet) > 300 {
		snippet = snippet[:300] + "..."
	}
	result.ResponseBodySnippet = sanitizeForJSON(snippet)

	// Hash for deduplication (first 16 hex chars of SHA256)
	hash := sha256.Sum256(bodyBytes)
	result.ResponseBodyHash = hex.EncodeToString(hash[:8])

	// Look for evidence markers indicating vulnerability exploitation
	for _, ep := range evidencePatterns {
		if ep.pattern.MatchString(bodyStr) {
			result.EvidenceMarkers = append(result.EvidenceMarkers, ep.name)
		}
	}
}

// sanitizeForJSON removes control characters and null bytes
func sanitizeForJSON(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			sb.WriteRune(r)
		} else if r == '\n' || r == '\t' {
			sb.WriteRune(' ')
		}
	}
	return sb.String()
}

// categorizeError classifies errors for better analysis
func categorizeError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	switch {
	case strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline exceeded"):
		return fmt.Sprintf("[TIMEOUT] %s", errStr)
	case strings.Contains(errLower, "no such host") || strings.Contains(errLower, "dns"):
		return fmt.Sprintf("[DNS] %s", errStr)
	case strings.Contains(errLower, "certificate") || strings.Contains(errLower, "tls") ||
		strings.Contains(errLower, "x509"):
		return fmt.Sprintf("[TLS] %s", errStr)
	case strings.Contains(errLower, "connection refused") || strings.Contains(errLower, "connection reset"):
		return fmt.Sprintf("[CONNECTION] %s", errStr)
	case strings.Contains(errLower, "rate limit") || strings.Contains(errLower, "too many"):
		return fmt.Sprintf("[RATE_LIMIT] %s", errStr)
	case strings.Contains(errLower, "invalid") || strings.Contains(errLower, "malformed"):
		return fmt.Sprintf("[INVALID_REQUEST] %s", errStr)
	default:
		return errStr
	}
}
