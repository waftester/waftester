// Package realistic provides realistic HTTP request generation for WAF testing
// This file provides integration helpers for the core executor

package realistic

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/detection"
)

// ExecutorEnhancer wraps an HTTP client to add realistic request capabilities
type ExecutorEnhancer struct {
	Builder            *Builder
	Detector           *BlockDetector
	Calibrator         *Calibrator
	UnifiedDetector    *detection.Detector // Optional unified detector for connection/ban detection
	IsCalibrated       bool
	UseRealistic       bool
	DetectBlocks       bool
	Templates          []*RequestTemplate
	CurrentTemplateIdx int
}

// NewExecutorEnhancer creates an enhancer for realistic testing
func NewExecutorEnhancer(baseURL string) *ExecutorEnhancer {
	return &ExecutorEnhancer{
		Builder:      NewBuilder(baseURL),
		Detector:     NewBlockDetector(),
		Calibrator:   NewCalibrator(baseURL),
		UseRealistic: true,
		DetectBlocks: true,
		Templates:    defaultTemplates(),
	}
}

// Calibrate performs auto-calibration against the target
func (e *ExecutorEnhancer) Calibrate(ctx context.Context) error {
	if err := e.Calibrator.QuickCalibrate(ctx); err != nil {
		return fmt.Errorf("calibration failed: %w", err)
	}

	// Share the detector's baseline
	e.Detector = e.Calibrator.GetDetector()
	e.IsCalibrated = true

	return nil
}

// FullCalibrate performs comprehensive calibration
func (e *ExecutorEnhancer) FullCalibrate(ctx context.Context) (*CalibrationResult, error) {
	result, err := e.Calibrator.Calibrate(ctx)
	if err != nil {
		return nil, err
	}

	e.Detector = e.Calibrator.GetDetector()
	e.IsCalibrated = true

	return result, nil
}

// BuildRequest creates a realistic request for a payload
func (e *ExecutorEnhancer) BuildRequest(payload string, location InjectionLocation, method string) (*http.Request, error) {
	template := e.selectTemplate(location, method)
	return e.Builder.BuildRequest(payload, template)
}

// BuildRequestWithTemplate creates a request using a specific template
func (e *ExecutorEnhancer) BuildRequestWithTemplate(payload string, template *RequestTemplate) (*http.Request, error) {
	return e.Builder.BuildRequest(payload, template)
}

// UseUnifiedDetection enables the unified detection package for connection
// drop and silent ban detection alongside the block detector.
func (e *ExecutorEnhancer) UseUnifiedDetection() {
	e.UnifiedDetector = detection.Default()
}

// AnalyzeResponse checks if a response indicates blocking
func (e *ExecutorEnhancer) AnalyzeResponse(resp *http.Response, responseTime time.Duration) (*BlockResult, error) {
	result, err := e.Detector.DetectBlock(resp, responseTime)

	// Also record in unified detector if enabled
	if e.UnifiedDetector != nil && resp != nil {
		bodySize := 0
		if resp.ContentLength > 0 {
			bodySize = int(resp.ContentLength)
		}
		e.UnifiedDetector.RecordResponse("", resp, responseTime, bodySize)
	}

	return result, err
}

// IsBlocked is a simple helper to check if response indicates WAF blocking
func (e *ExecutorEnhancer) IsBlocked(statusCode int, body string, headers http.Header) bool {
	// Create a mock response for analysis
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     headers,
	}

	result, err := e.Detector.DetectBlock(resp, 0)
	if err != nil {
		// Fall back to simple status check
		return statusCode == 403 || statusCode == 406 || statusCode == 429
	}

	return result.IsBlocked
}

// ShouldSkipHost checks if the unified detector recommends skipping a host.
func (e *ExecutorEnhancer) ShouldSkipHost(targetURL string) (bool, string) {
	if e.UnifiedDetector == nil {
		return false, ""
	}
	return e.UnifiedDetector.ShouldSkipHost(targetURL)
}

// GetBlockConfidence returns the confidence level that a response is a WAF block
func (e *ExecutorEnhancer) GetBlockConfidence(statusCode int, body string, headers http.Header) float64 {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     headers,
	}

	result, err := e.Detector.DetectBlock(resp, 0)
	if err != nil {
		if statusCode == 403 || statusCode == 406 || statusCode == 429 {
			return 0.5
		}
		return 0.0
	}

	return result.Confidence
}

// selectTemplate chooses an appropriate template based on location and method
func (e *ExecutorEnhancer) selectTemplate(location InjectionLocation, method string) *RequestTemplate {
	// Find matching template
	for _, t := range e.Templates {
		if t.InjectionLoc == location && (method == "" || t.Method == method) {
			return t
		}
	}

	// Return default template
	return &RequestTemplate{
		Method:         method,
		Path:           "/",
		InjectionLoc:   location,
		InjectionParam: "q",
	}
}

// AddTemplate adds a custom template for testing
func (e *ExecutorEnhancer) AddTemplate(template *RequestTemplate) {
	e.Templates = append(e.Templates, template)
}

// RotateTemplate cycles through available templates
func (e *ExecutorEnhancer) RotateTemplate() *RequestTemplate {
	if len(e.Templates) == 0 {
		return DefaultTemplate("")
	}

	template := e.Templates[e.CurrentTemplateIdx]
	e.CurrentTemplateIdx = (e.CurrentTemplateIdx + 1) % len(e.Templates)
	return template
}

// defaultTemplates returns a set of realistic request templates
func defaultTemplates() []*RequestTemplate {
	return []*RequestTemplate{
		// Search functionality
		{
			Method:         "GET",
			Path:           "/search",
			InjectionParam: "q",
			InjectionLoc:   LocationQuery,
			QueryParams: map[string]string{
				"page":  "1",
				"limit": "20",
			},
		},
		// API endpoint
		{
			Method:         "POST",
			Path:           "/api/data",
			InjectionField: "query",
			InjectionLoc:   LocationJSON,
			JSONData: map[string]interface{}{
				"version": "1.0",
				"action":  "search",
			},
		},
		// Form submission
		{
			Method:         "POST",
			Path:           "/submit",
			InjectionParam: "input",
			InjectionLoc:   LocationBody,
			FormData: map[string]string{
				"csrf": "token123",
			},
		},
		// Query parameter on root
		{
			Method:         "GET",
			Path:           "/",
			InjectionParam: "id",
			InjectionLoc:   LocationQuery,
			QueryParams: map[string]string{
				"page": "1",
			},
		},
		// Cookie injection
		{
			Method:         "GET",
			Path:           "/dashboard",
			InjectionParam: "session",
			InjectionLoc:   LocationCookie,
			Cookies: map[string]string{
				"tracking": "abc123",
			},
		},
		// Header injection
		{
			Method:         "GET",
			Path:           "/api/v1/users",
			InjectionParam: "X-Custom-Input",
			InjectionLoc:   LocationHeader,
		},
		// X-Forwarded-For
		{
			Method:       "GET",
			Path:         "/admin",
			InjectionLoc: LocationXForwarded,
		},
	}
}

// Stats returns calibration and detection statistics
func (e *ExecutorEnhancer) Stats() map[string]interface{} {
	stats := map[string]interface{}{
		"is_calibrated":   e.IsCalibrated,
		"use_realistic":   e.UseRealistic,
		"detect_blocks":   e.DetectBlocks,
		"num_templates":   len(e.Templates),
		"num_user_agents": len(e.Builder.UserAgents),
	}

	if e.Detector.Baseline != nil {
		stats["baseline_status"] = e.Detector.Baseline.StatusCode
		stats["baseline_length"] = e.Detector.Baseline.ContentLength
		stats["baseline_latency_ms"] = e.Detector.Baseline.ResponseTime.Milliseconds()
	}

	return stats
}
