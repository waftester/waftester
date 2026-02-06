package events

// ResultEvent represents a single test result.
// It contains all information about a WAF test execution including
// the test metadata, target details, outcome, and optional evidence.
type ResultEvent struct {
	BaseEvent
	Test     TestInfo     `json:"test"`
	Target   TargetInfo   `json:"target"`
	Result   ResultInfo   `json:"result"`
	Evidence *Evidence    `json:"evidence,omitempty"`
	Context  *ContextInfo `json:"context,omitempty"`
}

// TestInfo contains test metadata including identification,
// categorization, and security classification information.
type TestInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Category    string   `json:"category"`
	Subcategory string   `json:"subcategory,omitempty"`
	Severity    Severity `json:"severity"`
	OWASP       []string `json:"owasp,omitempty"`
	CWE         []int    `json:"cwe,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// TargetInfo contains target endpoint information
// including the URL, HTTP method, and parameter details.
type TargetInfo struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	Endpoint  string `json:"endpoint,omitempty"`
	Parameter string `json:"parameter,omitempty"`
}

// ResultInfo contains the test outcome including
// the result status, HTTP response details, and WAF detection info.
type ResultInfo struct {
	Outcome        Outcome    `json:"outcome"`
	StatusCode     int        `json:"status_code"`
	LatencyMs      float64    `json:"latency_ms"`
	ContentLength  int        `json:"content_length,omitempty"`
	WAFSignature   string     `json:"waf_signature,omitempty"`
	Confidence     Confidence `json:"confidence,omitempty"`
	ConfidenceNote string     `json:"confidence_note,omitempty"`
}

// Evidence contains proof of the test result including
// the payload used, request details, and response preview.
type Evidence struct {
	Payload         string            `json:"payload,omitempty"`
	EncodedPayload  string            `json:"encoded_payload,omitempty"`
	CurlCommand     string            `json:"curl_command,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponsePreview string            `json:"response_preview,omitempty"`
}

// ContextInfo contains execution context including
// the test phase, encoding, and evasion technique details.
type ContextInfo struct {
	Phase            string `json:"phase,omitempty"`
	Tamper           string `json:"tamper,omitempty"`
	Encoding         string `json:"encoding,omitempty"`
	EvasionTechnique string `json:"evasion_technique,omitempty"`
}
