package attackconfig

import (
	"net/http"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
)

// Base contains configuration fields shared across all
// attack and testing packages. Embed it in package-specific
// Config structs to inherit common functionality.
type Base struct {
	Timeout     time.Duration `json:"timeout,omitempty"`
	UserAgent   string        `json:"user_agent,omitempty"`
	Client      *http.Client  `json:"-"`
	MaxPayloads int           `json:"max_payloads,omitempty"`
	MaxParams   int           `json:"max_params,omitempty"`
	Concurrency int           `json:"concurrency,omitempty"`

	// OnVulnerabilityFound is called each time a scanner discovers a
	// vulnerability, enabling real-time progress updates in the CLI.
	// Scanners that support streaming call this per finding; others
	// report in bulk after Scan() returns.
	OnVulnerabilityFound func() `json:"-"`

	// seenVulns tracks dedup keys for NotifyUniqueVuln to prevent
	// overcounting in the progress display. Pointer to sync.Map so
	// Base remains safe to copy by value (no embedded mutex).
	seenVulns *sync.Map `json:"-"`
}

// DefaultBase returns a Base with production defaults.
func DefaultBase() Base {
	return Base{
		Timeout:     httpclient.TimeoutScanning,
		Concurrency: defaults.ConcurrencyMedium,
	}
}

// Validate fills zero-value fields with defaults.
// Call this in NewTester constructors to ensure sane values.
func (b *Base) Validate() {
	if b.Timeout <= 0 {
		b.Timeout = httpclient.TimeoutScanning
	}
	if b.Concurrency <= 0 {
		b.Concurrency = defaults.ConcurrencyMedium
	}
}

// NotifyVulnerabilityFound calls the OnVulnerabilityFound callback if set.
// Call this after recording each vulnerability for real-time progress updates.
func (b *Base) NotifyVulnerabilityFound() {
	if b.OnVulnerabilityFound != nil {
		b.OnVulnerabilityFound()
	}
}

// NotifyUniqueVuln fires the OnVulnerabilityFound callback only once per
// unique dedup key. Use this instead of NotifyVulnerabilityFound in scanners
// where multiple findings share the same dedup key (e.g., same URL+param+type)
// so the real-time progress counter matches the post-dedup final count.
//
// The key should match the dedup key used in dedup.go for that scanner.
func (b *Base) NotifyUniqueVuln(key string) {
	if b.OnVulnerabilityFound == nil {
		return
	}
	if b.seenVulns == nil {
		b.seenVulns = &sync.Map{}
	}
	if _, loaded := b.seenVulns.LoadOrStore(key, struct{}{}); !loaded {
		b.OnVulnerabilityFound()
	}
}
