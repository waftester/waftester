package calibration

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Result represents auto-calibration results
type Result struct {
	BaselineStatus int
	BaselineSize   int
	BaselineWords  int
	BaselineLines  int
	Suggestions    FilterSuggestion
	Calibrated     bool
}

// FilterSuggestion contains suggested filters based on calibration
type FilterSuggestion struct {
	FilterStatus []int
	FilterSize   []int
	FilterWords  []int
	FilterLines  []int
}

// Calibrator performs automatic baseline detection
type Calibrator struct {
	targetURL  string
	timeout    time.Duration
	skipVerify bool
	client     *http.Client
}

// NewCalibrator creates a new auto-calibrator
func NewCalibrator(targetURL string, timeout time.Duration, skipVerify bool) *Calibrator {
	return NewCalibratorWithClient(targetURL, timeout, skipVerify, nil)
}

// NewCalibratorWithClient creates a new auto-calibrator with optional custom HTTP client
func NewCalibratorWithClient(targetURL string, timeout time.Duration, skipVerify bool, httpClient *http.Client) *Calibrator {
	var client *http.Client
	if httpClient != nil {
		client = httpClient
	} else {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
		}

		client = &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &Calibrator{
		targetURL:  targetURL,
		timeout:    timeout,
		skipVerify: skipVerify,
		client:     client,
	}
}

// Calibrate performs automatic baseline detection using random strings
// This is similar to ffuf's -ac flag
func (c *Calibrator) Calibrate(ctx context.Context) (*Result, error) {
	result := &Result{}

	// Send requests with random/non-existent paths to find baseline
	calibrationPaths := []string{
		"/waftester_calibration_" + randomString(16),
		"/waftester_random_" + randomString(12),
		"/nonexistent_" + randomString(8) + ".php",
		"/" + randomString(20) + "/admin",
		"/" + randomString(8) + "/../../../etc/passwd",
	}

	var statusCounts = make(map[int]int)
	var sizeCounts = make(map[int]int)
	var wordCounts = make(map[int]int)
	var lineCounts = make(map[int]int)

	for _, path := range calibrationPaths {
		url := strings.TrimSuffix(c.targetURL, "/") + path

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "WAF-Tester/2.1.0 (Calibration)")

		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		status := resp.StatusCode
		size := len(body)
		words := len(strings.Fields(string(body)))
		lines := len(strings.Split(string(body), "\n"))

		statusCounts[status]++
		sizeCounts[size]++
		wordCounts[words]++
		lineCounts[lines]++
	}

	// Find most common responses (these are likely the "not found" baseline)
	if mostCommon := findMostCommon(statusCounts); mostCommon > 0 {
		result.BaselineStatus = mostCommon
		result.Suggestions.FilterStatus = []int{mostCommon}
	}

	if mostCommon := findMostCommon(sizeCounts); mostCommon > 0 {
		result.BaselineSize = mostCommon
		result.Suggestions.FilterSize = []int{mostCommon}
	}

	if mostCommon := findMostCommon(wordCounts); mostCommon > 0 {
		result.BaselineWords = mostCommon
		result.Suggestions.FilterWords = []int{mostCommon}
	}

	if mostCommon := findMostCommon(lineCounts); mostCommon > 0 {
		result.BaselineLines = mostCommon
		result.Suggestions.FilterLines = []int{mostCommon}
	}

	result.Calibrated = len(statusCounts) > 0

	return result, nil
}

// Describe returns a human-readable description of the calibration results
func (r *Result) Describe() string {
	if !r.Calibrated {
		return "Calibration failed - no baseline detected"
	}

	parts := []string{}

	if r.BaselineStatus > 0 {
		parts = append(parts, fmt.Sprintf("Status: %d", r.BaselineStatus))
	}
	if r.BaselineSize > 0 {
		parts = append(parts, fmt.Sprintf("Size: %d", r.BaselineSize))
	}
	if r.BaselineWords > 0 {
		parts = append(parts, fmt.Sprintf("Words: %d", r.BaselineWords))
	}
	if r.BaselineLines > 0 {
		parts = append(parts, fmt.Sprintf("Lines: %d", r.BaselineLines))
	}

	return fmt.Sprintf("Baseline detected: %s", strings.Join(parts, ", "))
}

// GetFilterArgs returns CLI-style filter arguments based on calibration
func (r *Result) GetFilterArgs() string {
	if !r.Calibrated {
		return ""
	}

	args := []string{}

	if len(r.Suggestions.FilterStatus) > 0 {
		codes := []string{}
		for _, code := range r.Suggestions.FilterStatus {
			codes = append(codes, fmt.Sprintf("%d", code))
		}
		args = append(args, fmt.Sprintf("-fc %s", strings.Join(codes, ",")))
	}

	if len(r.Suggestions.FilterSize) > 0 {
		sizes := []string{}
		for _, size := range r.Suggestions.FilterSize {
			sizes = append(sizes, fmt.Sprintf("%d", size))
		}
		args = append(args, fmt.Sprintf("-fs %s", strings.Join(sizes, ",")))
	}

	return strings.Join(args, " ")
}

func findMostCommon(counts map[int]int) int {
	maxCount := 0
	mostCommon := 0

	for value, count := range counts {
		if count > maxCount {
			maxCount = count
			mostCommon = value
		}
	}

	return mostCommon
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := range result {
		// Use crypto/rand for secure random number generation
		n, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			// Fallback to first char if crypto/rand fails (should never happen)
			result[i] = charset[0]
			continue
		}
		result[i] = charset[n.Int64()]
	}
	return string(result)
}
