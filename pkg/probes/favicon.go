package probes

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/bufpool"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// FaviconResult contains favicon probing results
type FaviconResult struct {
	Found       bool   `json:"found"`
	URL         string `json:"url,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Size        int    `json:"size"`
	MMH3Hash    int32  `json:"mmh3_hash,omitempty"`   // Shodan-compatible hash
	MD5Hash     string `json:"md5_hash,omitempty"`    // MD5 hash for comparison
	ShodanDork  string `json:"shodan_dork,omitempty"` // Ready-to-use Shodan dork
	Error       string `json:"error,omitempty"`
}

// FaviconProber probes for favicon and calculates hash
type FaviconProber struct {
	Timeout     time.Duration
	SkipVerify  bool
	UserAgent   string
	MaxFileSize int64
}

// NewFaviconProber creates a new favicon prober with defaults
func NewFaviconProber() *FaviconProber {
	return &FaviconProber{
		Timeout:     duration.DialTimeout,
		SkipVerify:  true,
		UserAgent:   defaults.UAChrome,
		MaxFileSize: 1024 * 1024, // 1MB max
	}
}

// Probe fetches favicon and calculates its hash
func (p *FaviconProber) Probe(ctx context.Context, baseURL string) *FaviconResult {
	result := &FaviconResult{}

	// Common favicon paths to try
	faviconPaths := []string{
		"/favicon.ico",
		"/favicon.png",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
	}

	client := httpclient.Default()

	baseURL = strings.TrimSuffix(baseURL, "/")

	for _, path := range faviconPaths {
		faviconURL := baseURL + path

		req, err := http.NewRequestWithContext(ctx, "GET", faviconURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", p.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer iohelper.DrainAndClose(resp.Body)

		if resp.StatusCode != 200 {
			continue
		}

		// Check content type
		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "image") && !strings.Contains(contentType, "icon") {
			// Allow empty content type for .ico files
			if path != "/favicon.ico" && contentType != "" {
				continue
			}
		}

		// Read favicon content
		data, err := iohelper.ReadBody(resp.Body, p.MaxFileSize)
		if err != nil {
			continue
		}

		if len(data) == 0 {
			continue
		}

		// Found a valid favicon
		result.Found = true
		result.URL = faviconURL
		result.ContentType = contentType
		result.Size = len(data)

		// Calculate MMH3 hash (Shodan-compatible)
		result.MMH3Hash = mmh3Hash32(faviconBase64(data))
		result.ShodanDork = fmt.Sprintf("http.favicon.hash:%d", result.MMH3Hash)

		return result
	}

	result.Error = "no favicon found"
	return result
}

// faviconBase64 encodes the favicon data for MMH3 hashing
// Shodan uses base64 with specific line formatting
func faviconBase64(data []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(data)

	// Shodan/httpx uses base64 with \n every 76 chars
	result := bufpool.GetString()
	defer bufpool.PutString(result)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		result.WriteString(encoded[i:end])
		result.WriteString("\n")
	}

	return []byte(result.String())
}

// mmh3Hash32 calculates Murmur3 32-bit hash (Shodan-compatible)
// This is a simplified implementation
func mmh3Hash32(data []byte) int32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	const seed uint32 = 0

	h1 := seed
	length := len(data)
	nblocks := length / 4

	// Body
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24

		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	// Tail
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	// Finalization
	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}
