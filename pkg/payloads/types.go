package payloads

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Payload represents a single attack payload from JSON.
// This is the SINGLE SOURCE OF TRUTH for payload structure.
// Both the loader (run command) and generator (learn command) use this struct.
type Payload struct {
	ID            string   `json:"id"`
	Payload       string   `json:"payload"`
	Category      string   `json:"category"`               // Attack category (injection, xss, etc.)
	Method        string   `json:"method,omitempty"`       // HTTP method (GET, POST, etc.)
	ContentType   string   `json:"content_type,omitempty"` // Request content type
	TargetPath    string   `json:"target_path,omitempty"`  // Target endpoint path
	ExpectedBlock bool     `json:"expected_block"`
	SeverityHint  string   `json:"severity_hint"`
	Tags          []string `json:"tags"`
	Notes         string   `json:"notes"`
	Vendor        string   `json:"vendor,omitempty"` // Target WAF vendor (modsecurity, cloudflare, etc.)

	// Encoding/mutation tracking
	EncodingUsed    string `json:"encoding_used,omitempty"`    // Encoder name (url, base64, etc.)
	MutationType    string `json:"mutation_type,omitempty"`    // Mutation category (encoder, evasion)
	OriginalPayload string `json:"original_payload,omitempty"` // Pre-mutation payload

	// Effectiveness tracking for ranking and prioritization
	Effectiveness *EffectivenessScore `json:"effectiveness,omitempty"`

	// Deprecated: Use Category instead. Kept for backward compatibility with old payload files.
	AttackCategory string `json:"attack_category,omitempty"`
}

// EffectivenessScore tracks how well a payload performs against WAFs.
// Updated via exponential moving average as scan results come in.
type EffectivenessScore struct {
	// Overall bypass rate across all vendors (0.0 = always blocked, 1.0 = always bypasses).
	Overall float64 `json:"overall"`

	// ByVendor tracks per-vendor bypass rates.
	ByVendor map[string]float64 `json:"by_vendor,omitempty"`

	// LastUpdated is when the score was last recalculated.
	LastUpdated time.Time `json:"last_updated"`

	// SampleCount is total number of test observations.
	SampleCount int `json:"sample_count"`
}

// emaAlpha controls the exponential moving average decay.
// Higher values weight recent results more heavily.
const emaAlpha = 0.1

// UpdateEffectiveness records a single test observation.
// bypassed=true means the payload got through the WAF.
func (p *Payload) UpdateEffectiveness(bypassed bool, vendor string) {
	if p.Effectiveness == nil {
		p.Effectiveness = &EffectivenessScore{
			ByVendor: make(map[string]float64),
		}
	}

	var observed float64
	if bypassed {
		observed = 1.0
	}

	e := p.Effectiveness
	e.SampleCount++
	e.LastUpdated = time.Now()

	// EMA: score = alpha * observed + (1 - alpha) * previous
	e.Overall = emaAlpha*observed + (1-emaAlpha)*e.Overall

	if vendor != "" {
		v := strings.ToLower(vendor)
		prev := e.ByVendor[v]
		e.ByVendor[v] = emaAlpha*observed + (1-emaAlpha)*prev
	}
}

// GetEffectivenessByVendor returns the bypass rate for a specific vendor.
// Returns 0.5 (unknown) if no data exists.
func (p *Payload) GetEffectivenessByVendor(vendor string) float64 {
	if p.Effectiveness == nil {
		return 0.5
	}
	v := strings.ToLower(vendor)
	if score, ok := p.Effectiveness.ByVendor[v]; ok {
		return score
	}
	return 0.5
}

// ValidationError describes a single validation failure.
type ValidationError struct {
	Field   string // e.g. "Payload", "Category"
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// validSeverities is the set of accepted severity values (lowercase).
var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// validMethods is the set of accepted HTTP methods (uppercase).
var validMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// Validate checks a payload for required fields and valid values.
// Returns a joined error with all failures, or nil if valid.
func (p *Payload) Validate() error {
	var errs []error

	if strings.TrimSpace(p.Payload) == "" {
		errs = append(errs, &ValidationError{Field: "Payload", Message: "payload string is required"})
	}
	if strings.TrimSpace(p.Category) == "" {
		errs = append(errs, &ValidationError{Field: "Category", Message: "category is required"})
	}
	if p.SeverityHint != "" && !validSeverities[strings.ToLower(p.SeverityHint)] {
		errs = append(errs, &ValidationError{
			Field:   "SeverityHint",
			Message: fmt.Sprintf("invalid severity %q; want one of: info, low, medium, high, critical", p.SeverityHint),
		})
	}
	if p.Method != "" && !validMethods[strings.ToUpper(p.Method)] {
		errs = append(errs, &ValidationError{
			Field:   "Method",
			Message: fmt.Sprintf("invalid HTTP method %q", p.Method),
		})
	}

	return errors.Join(errs...)
}

// Normalize standardizes a payload's fields in place.
// Should be called before Validate to fix common inconsistencies.
func (p *Payload) Normalize() {
	p.Payload = strings.TrimSpace(p.Payload)
	p.Category = strings.TrimSpace(p.Category)
	p.ID = strings.TrimSpace(p.ID)
	p.Notes = strings.TrimSpace(p.Notes)
	p.Vendor = strings.TrimSpace(strings.ToLower(p.Vendor))
	p.TargetPath = strings.TrimSpace(p.TargetPath)

	// Normalize severity to lowercase
	if p.SeverityHint != "" {
		p.SeverityHint = strings.ToLower(strings.TrimSpace(p.SeverityHint))
	}

	// Normalize method to uppercase, default to GET
	if p.Method != "" {
		p.Method = strings.ToUpper(strings.TrimSpace(p.Method))
	} else {
		p.Method = "GET"
	}

	// Migrate deprecated AttackCategory to Category
	if p.Category == "" && p.AttackCategory != "" {
		p.Category = strings.TrimSpace(p.AttackCategory)
	}

	// Normalize category to lowercase
	p.Category = strings.ToLower(p.Category)

	// Deduplicate and normalize tags
	if len(p.Tags) > 0 {
		seen := make(map[string]bool, len(p.Tags))
		deduped := make([]string, 0, len(p.Tags))
		for _, tag := range p.Tags {
			t := strings.ToLower(strings.TrimSpace(tag))
			if t != "" && !seen[t] {
				seen[t] = true
				deduped = append(deduped, t)
			}
		}
		p.Tags = deduped
	}

	// Generate ID from content hash if missing
	if p.ID == "" && p.Payload != "" {
		h := sha256.Sum256([]byte(p.Category + ":" + p.Payload))
		p.ID = fmt.Sprintf("auto-%x", h[:8])
	}
}

// Category groups payloads by type
type Category struct {
	Name     string
	Payloads []Payload
}

// Statistics for payload loading
type LoadStats struct {
	TotalPayloads  int
	CategoriesUsed int
	ByCategory     map[string]int
}
