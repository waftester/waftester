// Package ssti provides Server-Side Template Injection (SSTI) detection and testing capabilities.
// It supports detection of template injection vulnerabilities across multiple template engines
// including Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, ERB, Pebble, and more.
package ssti

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"regexp"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
)

// TemplateEngine represents a server-side template engine
type TemplateEngine string

const (
	EngineJinja2     TemplateEngine = "jinja2"
	EngineTwig       TemplateEngine = "twig"
	EngineFreemarker TemplateEngine = "freemarker"
	EngineVelocity   TemplateEngine = "velocity"
	EngineSmarty     TemplateEngine = "smarty"
	EngineMako       TemplateEngine = "mako"
	EngineERB        TemplateEngine = "erb"
	EnginePebble     TemplateEngine = "pebble"
	EngineThymeleaf  TemplateEngine = "thymeleaf"
	EngineNunjucks   TemplateEngine = "nunjucks"
	EngineHandlebars TemplateEngine = "handlebars"
	EngineMustache   TemplateEngine = "mustache"
	EngineTornado    TemplateEngine = "tornado"
	EngineDjango     TemplateEngine = "django"
	EngineRazor      TemplateEngine = "razor"
	EngineUnknown    TemplateEngine = "unknown"
)

// PayloadType represents the type of SSTI payload
type PayloadType string

const (
	PayloadProbe          PayloadType = "probe"          // Detection probes
	PayloadMath           PayloadType = "math"           // Mathematical expressions
	PayloadBlind          PayloadType = "blind"          // Blind SSTI (time-based)
	PayloadRCE            PayloadType = "rce"            // Remote code execution
	PayloadFileRead       PayloadType = "file_read"      // File reading
	PayloadSandboxEscape  PayloadType = "sandbox_escape" // Sandbox escape
	PayloadInfoDisclosure PayloadType = "info_disclosure"
)

// Payload represents an SSTI payload
type Payload struct {
	Template       string           `json:"template"`                  // The template injection payload
	Engine         TemplateEngine   `json:"engine"`                    // Target template engine
	Type           PayloadType      `json:"type"`                      // Payload type
	ExpectedOutput string           `json:"expected_output,omitempty"` // Expected output if vulnerable
	Regex          *regexp.Regexp   `json:"-"`                         // Regex pattern to match in response
	Description    string           `json:"description,omitempty"`     // Description of what this payload does
	Severity       finding.Severity `json:"severity"`                  // Severity if successful
	MathA          int              `json:"math_a,omitempty"`          // First number for math probes
	MathB          int              `json:"math_b,omitempty"`          // Second number for math probes
	MathResult     int              `json:"math_result,omitempty"`     // Expected result for math probes
}

// Vulnerability represents a detected SSTI vulnerability
type Vulnerability struct {
	finding.Vulnerability
	Engine         TemplateEngine `json:"engine"`                // Detected template engine
	Payload        *Payload       `json:"payload,omitempty"`     // Payload that triggered the vuln
	Confidence     string         `json:"confidence"`            // high, medium, low
	CanExecuteCode bool           `json:"can_execute_code"`      // Whether RCE is possible
	RCEPayload     string         `json:"rce_payload,omitempty"` // Example RCE payload
}

// DetectorConfig configures the SSTI detector
type DetectorConfig struct {
	attackconfig.Base
	FollowRedirect bool             // Follow HTTP redirects
	Headers        http.Header      // Additional headers
	Cookies        []*http.Cookie   // Cookies to include
	Proxy          string           // HTTP proxy URL
	SafeMode       bool             // Only use safe detection payloads
	BlindDelay     time.Duration    // Delay for blind SSTI
	Engines        []TemplateEngine // Only test these engines (empty = all)
	PayloadTypes   []PayloadType    // Only use these payload types
	Verbose        bool             // Verbose output
}

// DefaultConfig returns a default detector configuration
func DefaultConfig() *DetectorConfig {
	return &DetectorConfig{
		Base: attackconfig.Base{
			Timeout:     duration.DialTimeout,
			UserAgent:   defaults.UAChrome,
			MaxPayloads: 50,
		},
		FollowRedirect: false,
		SafeMode:       true,
		BlindDelay:     duration.HTTPProbing,
	}
}

// Detector performs SSTI vulnerability detection
type Detector struct {
	config   *DetectorConfig
	client   *http.Client
	payloads []*Payload
}

// NewDetector creates a new SSTI detector
func NewDetector(config *DetectorConfig) *Detector {
	if config == nil {
		config = DefaultConfig()
	}

	d := &Detector{
		config: config,
		client: httpclient.Default(),
	}

	d.payloads = d.generatePayloads()

	return d
}

// generatePayloads creates all SSTI payloads
func (d *Detector) generatePayloads() []*Payload {
	payloads := make([]*Payload, 0, 64)

	// Generate random numbers for math probes (harder to false positive)
	a, b := randomMathValues()
	result := a * b

	// Jinja2/Twig payloads
	payloads = append(payloads, d.jinja2Payloads(a, b, result)...)

	// Freemarker payloads
	payloads = append(payloads, d.freemarkerPayloads(a, b, result)...)

	// Velocity payloads
	payloads = append(payloads, d.velocityPayloads(a, b, result)...)

	// Smarty payloads
	payloads = append(payloads, d.smartyPayloads(a, b, result)...)

	// Mako payloads
	payloads = append(payloads, d.makoPayloads(a, b, result)...)

	// ERB payloads
	payloads = append(payloads, d.erbPayloads(a, b, result)...)

	// Pebble payloads
	payloads = append(payloads, d.pebblePayloads(a, b, result)...)

	// Thymeleaf payloads
	payloads = append(payloads, d.thymeleafPayloads(a, b, result)...)

	// Nunjucks payloads
	payloads = append(payloads, d.nunjucksPayloads(a, b, result)...)

	// Handlebars payloads
	payloads = append(payloads, d.handlebarsPayloads(a, b, result)...)

	// Tornado payloads
	payloads = append(payloads, d.tornadoPayloads(a, b, result)...)

	// Django payloads
	payloads = append(payloads, d.djangoPayloads(a, b, result)...)

	// Razor payloads
	payloads = append(payloads, d.razorPayloads(a, b, result)...)

	// Universal/polyglot payloads
	payloads = append(payloads, d.universalPayloads(a, b, result)...)

	return payloads
}

func randomMathValues() (int, int) {
	// Generate random values between 1000-9999 to avoid false positives
	aVal, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		// Fallback to deterministic but varied values on rand failure
		return 7919, 8731
	}
	bVal, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		return int(aVal.Int64()) + 1000, 8731
	}
	return int(aVal.Int64()) + 1000, int(bVal.Int64()) + 1000
}
