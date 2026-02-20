package payloads

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

	// Deprecated: Use Category instead. Kept for backward compatibility with old payload files.
	AttackCategory string `json:"attack_category,omitempty"`
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
