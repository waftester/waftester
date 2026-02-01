package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// DepthScanner implements kiterunner-style depth-based API scanning
// It performs preflight checks at each path depth to detect wildcards
type DepthScanner struct {
	client           *http.Client
	preflightDepth   int
	contentLenIgnore []Range
	wildcardCache    map[string]*WildcardInfo
	mu               sync.RWMutex
}

// Range represents a content-length range to ignore
type Range struct {
	Min int
	Max int
}

// WildcardInfo stores wildcard detection results for a path depth
type WildcardInfo struct {
	IsWildcard     bool
	WildcardType   string // "status", "content", "redirect"
	BaselineSize   int
	BaselineStatus int
}

// DepthScanConfig configures the depth scanner
type DepthScanConfig struct {
	Timeout          time.Duration
	SkipVerify       bool
	PreflightDepth   int     // number of random paths to test at each depth
	ContentLenIgnore []Range // content-length ranges to ignore (likely error pages)
	MaxDepth         int     // maximum depth to scan
}

// DefaultDepthScanConfig returns sensible defaults
func DefaultDepthScanConfig() *DepthScanConfig {
	return &DepthScanConfig{
		Timeout:        10 * time.Second,
		PreflightDepth: 3,
		MaxDepth:       5,
		ContentLenIgnore: []Range{
			{Min: 0, Max: 100},     // Empty/minimal responses
			{Min: 4000, Max: 5000}, // Common error page sizes
		},
	}
}

// NewDepthScanner creates a new depth-based scanner
func NewDepthScanner(config *DepthScanConfig) *DepthScanner {
	if config == nil {
		config = DefaultDepthScanConfig()
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipVerify},
	}

	return &DepthScanner{
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		preflightDepth:   config.PreflightDepth,
		contentLenIgnore: config.ContentLenIgnore,
		wildcardCache:    make(map[string]*WildcardInfo),
	}
}

// ScanResult represents the result of scanning a path
type ScanResult struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	StatusCode  int               `json:"status_code"`
	Size        int               `json:"size"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers,omitempty"`
	IsWildcard  bool              `json:"is_wildcard"`
	Latency     time.Duration     `json:"latency_ms"`
	Error       string            `json:"error,omitempty"`
}

// PreflightCheck performs wildcard detection at a specific depth
func (d *DepthScanner) PreflightCheck(ctx context.Context, baseURL string, depth int) (*WildcardInfo, error) {
	// Build preflight path at this depth
	prefix := buildDepthPrefix(depth)

	cacheKey := fmt.Sprintf("%s:%d", baseURL, depth)

	// Check cache
	d.mu.RLock()
	if info, ok := d.wildcardCache[cacheKey]; ok {
		d.mu.RUnlock()
		return info, nil
	}
	d.mu.RUnlock()

	// Perform preflight requests with random paths
	var responses []ScanResult
	for i := 0; i < d.preflightDepth; i++ {
		randomPath := prefix + "/" + randomString(12)
		url := strings.TrimSuffix(baseURL, "/") + randomPath

		result, err := d.sendRequest(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		responses = append(responses, *result)
	}

	info := d.analyzePreflightResponses(responses)

	// Cache result
	d.mu.Lock()
	d.wildcardCache[cacheKey] = info
	d.mu.Unlock()

	return info, nil
}

func buildDepthPrefix(depth int) string {
	if depth <= 0 {
		return ""
	}
	parts := make([]string, depth)
	for i := 0; i < depth; i++ {
		parts[i] = randomString(8)
	}
	return "/" + strings.Join(parts, "/")
}

func (d *DepthScanner) analyzePreflightResponses(responses []ScanResult) *WildcardInfo {
	info := &WildcardInfo{}

	if len(responses) < 2 {
		return info
	}

	// Check if all responses have same status
	firstStatus := responses[0].StatusCode
	allSameStatus := true
	for _, r := range responses[1:] {
		if r.StatusCode != firstStatus {
			allSameStatus = false
			break
		}
	}

	// Check if all responses have same size
	firstSize := responses[0].Size
	allSameSize := true
	for _, r := range responses[1:] {
		if r.Size != firstSize {
			allSameSize = false
			break
		}
	}

	// Detect wildcard type
	if allSameStatus && firstStatus == 200 {
		if allSameSize {
			info.IsWildcard = true
			info.WildcardType = "content"
			info.BaselineSize = firstSize
			info.BaselineStatus = firstStatus
		} else {
			// Check if sizes fall within ignore range
			allInIgnore := true
			for _, r := range responses {
				if !d.isInIgnoreRange(r.Size) {
					allInIgnore = false
					break
				}
			}
			if allInIgnore {
				info.IsWildcard = true
				info.WildcardType = "content"
			}
		}
	}

	if allSameStatus && (firstStatus == 301 || firstStatus == 302 || firstStatus == 307 || firstStatus == 308) {
		info.IsWildcard = true
		info.WildcardType = "redirect"
		info.BaselineStatus = firstStatus
	}

	return info
}

func (d *DepthScanner) isInIgnoreRange(size int) bool {
	for _, r := range d.contentLenIgnore {
		if size >= r.Min && size <= r.Max {
			return true
		}
	}
	return false
}

// ScanPath scans a specific path with wildcard awareness
func (d *DepthScanner) ScanPath(ctx context.Context, baseURL, path, method string) (*ScanResult, error) {
	// Calculate depth
	depth := strings.Count(strings.Trim(path, "/"), "/") + 1

	// Check for wildcard at this depth
	wildcardInfo, _ := d.PreflightCheck(ctx, baseURL, depth)

	url := strings.TrimSuffix(baseURL, "/") + path
	result, err := d.sendRequest(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	// Mark as wildcard if it matches the baseline
	if wildcardInfo != nil && wildcardInfo.IsWildcard {
		if wildcardInfo.WildcardType == "content" && result.Size == wildcardInfo.BaselineSize {
			result.IsWildcard = true
		}
		if wildcardInfo.WildcardType == "redirect" && result.StatusCode == wildcardInfo.BaselineStatus {
			result.IsWildcard = true
		}
	}

	return result, nil
}

func (d *DepthScanner) sendRequest(ctx context.Context, method, url string, headers map[string]string) (*ScanResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", ui.UserAgentWithContext("DepthScan"))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := d.client.Do(req)
	if err != nil {
		return &ScanResult{
			Path:   url,
			Method: method,
			Error:  err.Error(),
		}, err
	}
	defer iohelper.DrainAndClose(resp.Body)
	latency := time.Since(start)

	body, _ := iohelper.ReadBodyDefault(resp.Body)

	result := &ScanResult{
		Path:        url,
		Method:      method,
		StatusCode:  resp.StatusCode,
		Size:        len(body),
		Words:       len(strings.Fields(string(body))),
		Lines:       len(strings.Split(string(body), "\n")),
		ContentType: resp.Header.Get("Content-Type"),
		Latency:     latency,
	}

	return result, nil
}

// ScanRoutes scans a list of routes with preflight checks
func (d *DepthScanner) ScanRoutes(ctx context.Context, baseURL string, routes []Route) ([]ScanResult, error) {
	var results []ScanResult

	for _, route := range routes {
		result, err := d.ScanPath(ctx, baseURL, route.Path, route.Method)
		if err != nil {
			continue
		}

		// Skip wildcard matches
		if result.IsWildcard {
			continue
		}

		// Skip if in content-length ignore range
		if d.isInIgnoreRange(result.Size) {
			continue
		}

		results = append(results, *result)
	}

	return results, nil
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := range result {
		n, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			result[i] = charset[0]
			continue
		}
		result[i] = charset[n.Int64()]
	}
	return string(result)
}
