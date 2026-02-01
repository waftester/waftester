// Fingerprinting provides advanced WAF fingerprinting techniques
package waf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
)

// Fingerprint contains a unique WAF fingerprint
type Fingerprint struct {
	Hash            string          `json:"hash"`
	Components      []string        `json:"components"`
	HeaderOrder     string          `json:"header_order"`
	ErrorPageHash   string          `json:"error_page_hash"`
	BlockPageHash   string          `json:"block_page_hash"`
	TimingProfile   TimingProfile   `json:"timing_profile"`
	ResponseProfile ResponseProfile `json:"response_profile"`
}

// TimingProfile captures response timing characteristics
type TimingProfile struct {
	NormalAvgMs  float64 `json:"normal_avg_ms"`
	BlockedAvgMs float64 `json:"blocked_avg_ms"`
	Variance     float64 `json:"variance"`
}

// ResponseProfile captures response characteristics
type ResponseProfile struct {
	BlockStatusCode    int      `json:"block_status_code"`
	ErrorContentType   string   `json:"error_content_type"`
	HasCustomErrorPage bool     `json:"has_custom_error_page"`
	UniqueHeaders      []string `json:"unique_headers"`
}

// Fingerprinter creates unique WAF fingerprints
type Fingerprinter struct {
	client    *http.Client
	timeout   time.Duration
	userAgent string
}

// NewFingerprinter creates a new fingerprinter
func NewFingerprinter(timeout time.Duration) *Fingerprinter {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	// Use shared httpclient factory for connection pooling
	return &Fingerprinter{
		client: httpclient.New(httpclient.Config{
			Timeout:            timeout,
			InsecureSkipVerify: true,
		}),
		timeout:   timeout,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

// CreateFingerprint generates a unique WAF fingerprint
func (f *Fingerprinter) CreateFingerprint(ctx context.Context, target string) (*Fingerprint, error) {
	fp := &Fingerprint{
		Components: make([]string, 0),
	}

	// Collect header ordering
	headerOrder, uniqueHeaders := f.collectHeaderInfo(ctx, target)
	fp.HeaderOrder = headerOrder
	fp.ResponseProfile.UniqueHeaders = uniqueHeaders

	// Collect error page hash
	fp.ErrorPageHash = f.hashErrorPage(ctx, target)

	// Collect block page hash
	blockHash, blockStatus := f.hashBlockPage(ctx, target)
	fp.BlockPageHash = blockHash
	fp.ResponseProfile.BlockStatusCode = blockStatus

	// Timing profile
	fp.TimingProfile = f.profileTiming(ctx, target)

	// Build composite hash
	components := []string{
		fp.HeaderOrder,
		fp.ErrorPageHash,
		fp.BlockPageHash,
		fmt.Sprintf("%d", fp.ResponseProfile.BlockStatusCode),
	}
	fp.Components = components

	hasher := sha256.New()
	hasher.Write([]byte(strings.Join(components, "|")))
	fp.Hash = hex.EncodeToString(hasher.Sum(nil))[:16]

	return fp, nil
}

func (f *Fingerprinter) collectHeaderInfo(ctx context.Context, target string) (string, []string) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	// Collect header order
	var headerNames []string
	for k := range resp.Header {
		headerNames = append(headerNames, k)
	}
	sort.Strings(headerNames)
	headerOrder := strings.Join(headerNames, ",")

	// Find unique/unusual headers
	commonHeaders := map[string]bool{
		"Content-Type":                true,
		"Content-Length":              true,
		"Date":                        true,
		"Server":                      true,
		"Connection":                  true,
		"Cache-Control":               true,
		"Expires":                     true,
		"Pragma":                      true,
		"Set-Cookie":                  true,
		"Transfer-Encoding":           true,
		"Content-Encoding":            true,
		"Vary":                        true,
		"Accept-Ranges":               true,
		"Last-Modified":               true,
		"Etag":                        true,
		"Location":                    true,
		"Access-Control-Allow-Origin": true,
	}

	var uniqueHeaders []string
	for _, h := range headerNames {
		if !commonHeaders[h] {
			uniqueHeaders = append(uniqueHeaders, h)
		}
	}

	return headerOrder, uniqueHeaders
}

func (f *Fingerprinter) hashErrorPage(ctx context.Context, target string) string {
	// Request non-existent page
	req, err := http.NewRequestWithContext(ctx, "GET", target+"/this-page-does-not-exist-12345", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if len(body) == 0 {
		return ""
	}

	hasher := sha256.New()
	hasher.Write(body)
	return hex.EncodeToString(hasher.Sum(nil))[:16]
}

func (f *Fingerprinter) hashBlockPage(ctx context.Context, target string) (string, int) {
	// Trigger WAF block
	req, err := http.NewRequestWithContext(ctx, "GET", target+"?id=1' OR '1'='1", nil)
	if err != nil {
		return "", 0
	}
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if len(body) == 0 {
		return "", resp.StatusCode
	}

	hasher := sha256.New()
	hasher.Write(body)
	return hex.EncodeToString(hasher.Sum(nil))[:16], resp.StatusCode
}

func (f *Fingerprinter) profileTiming(ctx context.Context, target string) TimingProfile {
	profile := TimingProfile{}

	// Normal requests
	var normalTimes []float64
	for i := 0; i < 5; i++ {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", f.userAgent)
		resp, err := f.client.Do(req)
		if err == nil {
			resp.Body.Close()
			normalTimes = append(normalTimes, float64(time.Since(start).Milliseconds()))
		}
	}

	// Blocked requests
	var blockedTimes []float64
	for i := 0; i < 5; i++ {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, "GET", target+"?id=1' OR '1'='1", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", f.userAgent)
		resp, err := f.client.Do(req)
		if err == nil {
			resp.Body.Close()
			blockedTimes = append(blockedTimes, float64(time.Since(start).Milliseconds()))
		}
	}

	if len(normalTimes) > 0 {
		profile.NormalAvgMs = average(normalTimes)
	}
	if len(blockedTimes) > 0 {
		profile.BlockedAvgMs = average(blockedTimes)
		profile.Variance = profile.BlockedAvgMs - profile.NormalAvgMs
	}

	return profile
}

func average(nums []float64) float64 {
	if len(nums) == 0 {
		return 0
	}
	var sum float64
	for _, n := range nums {
		sum += n
	}
	return sum / float64(len(nums))
}

// KnownFingerprints contains fingerprints of known WAFs
var KnownFingerprints = map[string]string{
	// Format: hash -> WAF name
	// These would be populated from real-world testing
	"example_hash": "ModSecurity/CRS 3.3",
}

// MatchFingerprint tries to match a fingerprint to known WAFs
func MatchFingerprint(fp *Fingerprint) (string, float64) {
	if match, ok := KnownFingerprints[fp.Hash]; ok {
		return match, 1.0
	}

	// Partial matching based on components
	for hash, name := range KnownFingerprints {
		// Simple similarity check
		similarity := calculateSimilarity(fp.Hash, hash)
		if similarity > 0.8 {
			return name, similarity
		}
	}

	return "", 0
}

func calculateSimilarity(a, b string) float64 {
	if len(a) != len(b) {
		return 0
	}
	matches := 0
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			matches++
		}
	}
	return float64(matches) / float64(len(a))
}
