package realistic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Calibrator performs automatic baseline calibration for WAF testing
type Calibrator struct {
	Client     *http.Client
	BaseURL    string
	Builder    *Builder
	Detector   *BlockDetector
	Timeout    time.Duration
	NumSamples int // Number of baseline samples to collect
}

// CalibrationResult contains the results of automatic calibration
type CalibrationResult struct {
	Success         bool
	BaselineStatus  int
	BaselineLatency time.Duration
	BaselineLength  int64
	BlockedStatus   int
	BlockedLatency  time.Duration
	NonExistentPath string
	ErrorMessage    string
	Samples         []SampleResult
}

// SampleResult represents a single calibration sample
type SampleResult struct {
	Path       string
	StatusCode int
	Latency    time.Duration
	BodyLength int64
	IsBlocked  bool
}

// NewCalibrator creates a new calibrator
func NewCalibrator(baseURL string) *Calibrator {
	return &Calibrator{
		Client:     httpclient.Default(),
		BaseURL:    baseURL,
		Builder:    NewBuilder(baseURL),
		Detector:   NewBlockDetector(),
		Timeout:    duration.DialTimeout,
		NumSamples: 3,
	}
}

// Calibrate performs automatic baseline and block detection calibration
func (c *Calibrator) Calibrate(ctx context.Context) (*CalibrationResult, error) {
	result := &CalibrationResult{
		Success: false,
		Samples: []SampleResult{},
	}

	// Step 1: Test base URL for baseline
	baselineSample, err := c.samplePath(ctx, "/")
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("baseline request failed: %v", err)
		return result, err
	}
	result.Samples = append(result.Samples, *baselineSample)

	// Step 2: Generate random non-existent paths to find 404 behavior
	for i := 0; i < c.NumSamples; i++ {
		randomPath := "/" + randomHex(16)
		sample, err := c.samplePath(ctx, randomPath)
		if err != nil {
			continue
		}
		result.Samples = append(result.Samples, *sample)
		result.NonExistentPath = randomPath
	}

	// Step 3: Try a known blocked payload to detect block response
	blockedPayloads := []string{
		"<script>alert(1)</script>",
		"' OR 1=1 --",
		"../../../etc/passwd",
	}

	var blockedSample *SampleResult
	for _, payload := range blockedPayloads {
		template := &RequestTemplate{
			Method:         "GET",
			Path:           "/",
			InjectionParam: "test",
			InjectionLoc:   LocationQuery,
		}

		req, err := c.Builder.BuildRequest(payload, template)
		if err != nil {
			continue
		}

		sample, err := c.executeRequest(ctx, req)
		if err != nil {
			continue
		}

		result.Samples = append(result.Samples, *sample)

		// Check if this looks like a block
		if sample.StatusCode == 403 || sample.StatusCode == 406 || sample.StatusCode == 429 {
			blockedSample = sample
			break
		}
	}

	// Step 4: Analyze results and configure detector
	result.BaselineStatus = baselineSample.StatusCode
	result.BaselineLatency = baselineSample.Latency
	result.BaselineLength = baselineSample.BodyLength

	if blockedSample != nil {
		result.BlockedStatus = blockedSample.StatusCode
		result.BlockedLatency = blockedSample.Latency
	}

	// Step 5: Configure detector with baseline
	if len(result.Samples) > 0 {
		// Create a synthetic baseline from samples
		c.Detector.Baseline = &BaselineResponse{
			StatusCode:    result.BaselineStatus,
			ContentLength: result.BaselineLength,
			ResponseTime:  result.BaselineLatency,
		}
	}

	result.Success = true
	return result, nil
}

// samplePath makes a clean request to a path and measures response
func (c *Calibrator) samplePath(ctx context.Context, path string) (*SampleResult, error) {
	template := &RequestTemplate{
		Method:      "GET",
		Path:        path,
		QueryParams: map[string]string{},
	}

	req, err := c.Builder.BuildRequest("", template)
	if err != nil {
		return nil, err
	}

	return c.executeRequest(ctx, req)
}

// executeRequest sends a request and records the response characteristics
func (c *Calibrator) executeRequest(ctx context.Context, req *http.Request) (*SampleResult, error) {
	req = req.WithContext(ctx)

	start := time.Now()
	resp, err := c.Client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return nil, err
	}

	sample := &SampleResult{
		Path:       req.URL.Path,
		StatusCode: resp.StatusCode,
		Latency:    latency,
		BodyLength: int64(len(body)),
		IsBlocked:  resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429,
	}

	return sample, nil
}

// QuickCalibrate performs a fast calibration with minimal requests
func (c *Calibrator) QuickCalibrate(ctx context.Context) error {
	// Make a single baseline request
	sample, err := c.samplePath(ctx, "/")
	if err != nil {
		return fmt.Errorf("calibration failed: %w", err)
	}

	c.Detector.Baseline = &BaselineResponse{
		StatusCode:    sample.StatusCode,
		ContentLength: sample.BodyLength,
		ResponseTime:  sample.Latency,
	}

	return nil
}

// GetDetector returns the configured block detector
func (c *Calibrator) GetDetector() *BlockDetector {
	return c.Detector
}

// GetBuilder returns the request builder
func (c *Calibrator) GetBuilder() *Builder {
	return c.Builder
}

// Helper functions

func randomHex(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// TargetProfile contains discovered information about a target
type TargetProfile struct {
	BaseURL         string
	WAFDetected     bool
	WAFName         string
	BaselineStatus  int
	BaselineLatency time.Duration
	BlockStatus     int
	BlockLatency    time.Duration
	SupportsHTTPS   bool
	SupportsHTTP2   bool
	CDNDetected     bool
	CDNName         string
	CustomHeaders   map[string]string
	Cookies         map[string]string
}

// ProfileTarget discovers characteristics of the target
func (c *Calibrator) ProfileTarget(ctx context.Context) (*TargetProfile, error) {
	profile := &TargetProfile{
		BaseURL:       c.BaseURL,
		CustomHeaders: make(map[string]string),
		Cookies:       make(map[string]string),
	}

	// Make baseline request
	sample, err := c.samplePath(ctx, "/")
	if err != nil {
		return nil, err
	}

	profile.BaselineStatus = sample.StatusCode
	profile.BaselineLatency = sample.Latency

	// Make request to detect blocking
	template := &RequestTemplate{
		Method:         "GET",
		Path:           "/",
		InjectionParam: "test",
		InjectionLoc:   LocationQuery,
	}

	req, err := c.Builder.BuildRequest("<script>alert(1)</script>", template)
	if err != nil {
		return profile, err
	}

	blockSample, err := c.executeRequest(ctx, req)
	if err == nil {
		profile.BlockStatus = blockSample.StatusCode
		profile.BlockLatency = blockSample.Latency
		profile.WAFDetected = blockSample.StatusCode == 403 || blockSample.StatusCode == 406
	}

	return profile, nil
}
