package apispec

import (
	"sync"
	"time"
)

// SpecScanResult aggregates scan results per endpoint, wrapping scanner-specific
// results with endpoint context (method, path, parameter, attack type).
type SpecScanResult struct {
	// SpecSource identifies the spec file or URL.
	SpecSource string `json:"spec_source"`

	// StartedAt is when the spec scan started.
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the spec scan completed.
	CompletedAt time.Time `json:"completed_at"`

	// Duration is the total wall-clock time.
	Duration time.Duration `json:"duration"`

	// TotalEndpoints is the number of endpoints scanned.
	TotalEndpoints int `json:"total_endpoints"`

	// TotalTests is the number of individual test payloads sent.
	TotalTests int `json:"total_tests"`

	// Findings is the list of all findings across all endpoints.
	Findings []SpecFinding `json:"findings"`

	// EndpointResults groups findings by endpoint.
	EndpointResults []EndpointResult `json:"endpoint_results"`

	// Errors collects non-fatal errors encountered during scanning.
	Errors []string `json:"errors,omitempty"`

	mu sync.Mutex
}

// SpecFinding is a vulnerability finding enriched with endpoint context.
type SpecFinding struct {
	// Endpoint context.
	Method         string `json:"method"`
	Path           string `json:"path"`
	CorrelationTag string `json:"correlation_tag"`

	// Attack context.
	Category  string `json:"category"`
	Parameter string `json:"parameter,omitempty"`
	Location  string `json:"location,omitempty"`
	Payload   string `json:"payload,omitempty"`

	// Finding details.
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	Type        string   `json:"type,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	References  []string `json:"references,omitempty"`
}

// EndpointResult groups findings for a single endpoint.
type EndpointResult struct {
	Method         string        `json:"method"`
	Path           string        `json:"path"`
	CorrelationTag string        `json:"correlation_tag"`
	Findings       []SpecFinding `json:"findings"`
	ScanTypes      []string      `json:"scan_types"`
	Duration       time.Duration `json:"duration"`
	Error          string        `json:"error,omitempty"`
}

// AddFinding adds a finding in a thread-safe manner.
func (r *SpecScanResult) AddFinding(f SpecFinding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)
}

// AddError adds a non-fatal error in a thread-safe manner.
func (r *SpecScanResult) AddError(errMsg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Errors = append(r.Errors, errMsg)
}

// AddEndpointResult adds an endpoint result in a thread-safe manner.
func (r *SpecScanResult) AddEndpointResult(er EndpointResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.EndpointResults = append(r.EndpointResults, er)
}

// TotalFindings returns the total count of findings.
func (r *SpecScanResult) TotalFindings() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Findings)
}

// BySeverity returns a count map of findings grouped by severity.
func (r *SpecScanResult) BySeverity() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[string]int)
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

// ByCategory returns a count map of findings grouped by category.
func (r *SpecScanResult) ByCategory() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[string]int)
	for _, f := range r.Findings {
		m[f.Category]++
	}
	return m
}

// Finalize sets completion time and duration. Safe to call multiple times;
// only the first call takes effect.
func (r *SpecScanResult) Finalize() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.CompletedAt.IsZero() {
		return
	}
	r.CompletedAt = time.Now()
	r.Duration = r.CompletedAt.Sub(r.StartedAt)
}
