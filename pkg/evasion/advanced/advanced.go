// Package advanced provides advanced evasion techniques for comprehensive WAF bypass testing.
// It includes protocol-level evasion, encoding chains, timing attacks, and chunked encoding.
package advanced

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/waftester/waftester/internal/hexutil"
)

// Category represents the category of evasion technique.
type Category string

const (
	CategoryEncoding   Category = "encoding"
	CategoryProtocol   Category = "protocol"
	CategoryTiming     Category = "timing"
	CategoryChunked    Category = "chunked"
	CategoryMultipart  Category = "multipart"
	CategoryHTTPMethod Category = "http_method"
	CategoryHeader     Category = "header"
	CategoryPath       Category = "path"
	CategoryUnicode    Category = "unicode"
)

// Technique represents an evasion technique.
type Technique struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Category    Category `json:"category" yaml:"category"`
	Description string   `json:"description" yaml:"description"`
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	Tags        []string `json:"tags" yaml:"tags"`
	Transform   func(string) string
	HTTPMod     func(*http.Request) *http.Request
}

// String returns the technique ID.
func (t *Technique) String() string {
	return t.ID
}

// Apply applies the technique to a payload.
func (t *Technique) Apply(payload string) string {
	if t.Transform == nil {
		return payload
	}
	return t.Transform(payload)
}

// ApplyHTTP applies the technique to an HTTP request.
func (t *Technique) ApplyHTTP(req *http.Request) *http.Request {
	if t.HTTPMod == nil {
		return req
	}
	return t.HTTPMod(req)
}

// Config holds configuration for the evasion engine.
type Config struct {
	MaxChainDepth     int           `json:"max_chain_depth" yaml:"max_chain_depth"`
	MaxVariants       int           `json:"max_variants" yaml:"max_variants"`
	TimingDelay       time.Duration `json:"timing_delay" yaml:"timing_delay"`
	ChunkSizes        []int         `json:"chunk_sizes" yaml:"chunk_sizes"`
	EnableUnicode     bool          `json:"enable_unicode" yaml:"enable_unicode"`
	EnableHTTPSmug    bool          `json:"enable_http_smuggling" yaml:"enable_http_smuggling"`
	RandomSeed        int64         `json:"random_seed" yaml:"random_seed"`
	EnabledTechniques []string      `json:"enabled_techniques" yaml:"enabled_techniques"`
}

// DefaultConfig returns default configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxChainDepth:     4,
		MaxVariants:       100,
		TimingDelay:       50 * time.Millisecond,
		ChunkSizes:        []int{1, 2, 4, 8},
		EnableUnicode:     true,
		EnableHTTPSmug:    false,
		RandomSeed:        time.Now().UnixNano(),
		EnabledTechniques: []string{},
	}
}

// Engine provides advanced evasion capabilities.
type Engine struct {
	config     *Config
	techniques map[string]*Technique
	rng        *rand.Rand
}

// NewEngine creates a new evasion engine.
func NewEngine(config *Config) *Engine {
	if config == nil {
		config = DefaultConfig()
	}

	e := &Engine{
		config:     config,
		techniques: make(map[string]*Technique),
		rng:        rand.New(rand.NewSource(config.RandomSeed)),
	}

	e.registerBuiltinTechniques()
	return e
}

// registerBuiltinTechniques registers all built-in techniques.
func (e *Engine) registerBuiltinTechniques() {
	// Encoding techniques
	e.Register(&Technique{
		ID:          "double-url",
		Name:        "Double URL Encoding",
		Category:    CategoryEncoding,
		Description: "Applies URL encoding twice",
		Enabled:     true,
		Transform:   DoubleURLEncode,
	})

	e.Register(&Technique{
		ID:          "triple-url",
		Name:        "Triple URL Encoding",
		Category:    CategoryEncoding,
		Description: "Applies URL encoding three times",
		Enabled:     true,
		Transform:   TripleURLEncode,
	})

	e.Register(&Technique{
		ID:          "mixed-case-url",
		Name:        "Mixed Case URL Encoding",
		Category:    CategoryEncoding,
		Description: "Uses mixed case hex in URL encoding",
		Enabled:     true,
		Transform:   MixedCaseURLEncode,
	})

	e.Register(&Technique{
		ID:          "overlong-utf8",
		Name:        "Overlong UTF-8",
		Category:    CategoryUnicode,
		Description: "Uses overlong UTF-8 sequences",
		Enabled:     true,
		Transform:   OverlongUTF8,
	})

	e.Register(&Technique{
		ID:          "unicode-normalization",
		Name:        "Unicode Normalization Bypass",
		Category:    CategoryUnicode,
		Description: "Uses unicode normalization to bypass",
		Enabled:     true,
		Transform:   UnicodeNormalizationBypass,
	})

	e.Register(&Technique{
		ID:          "null-byte",
		Name:        "Null Byte Injection",
		Category:    CategoryEncoding,
		Description: "Injects null bytes to truncate",
		Enabled:     true,
		Transform:   NullByteInject,
	})

	e.Register(&Technique{
		ID:          "base64-wrap",
		Name:        "Base64 Wrapping",
		Category:    CategoryEncoding,
		Description: "Wraps payload in base64",
		Enabled:     true,
		Transform:   Base64Wrap,
	})

	// Path techniques
	e.Register(&Technique{
		ID:          "path-traversal-dot",
		Name:        "Path Traversal with Dots",
		Category:    CategoryPath,
		Description: "Uses .. sequences with encoding",
		Enabled:     true,
		Transform:   PathTraversalDots,
	})

	e.Register(&Technique{
		ID:          "path-normalization",
		Name:        "Path Normalization Bypass",
		Category:    CategoryPath,
		Description: "Uses path normalization quirks",
		Enabled:     true,
		Transform:   PathNormalization,
	})

	// Header techniques
	e.Register(&Technique{
		ID:          "header-splitting",
		Name:        "Header Splitting",
		Category:    CategoryHeader,
		Description: "Attempts header injection",
		Enabled:     true,
		Transform:   HeaderSplitting,
	})

	e.Register(&Technique{
		ID:          "header-folding",
		Name:        "Header Line Folding",
		Category:    CategoryHeader,
		Description: "Uses HTTP header line folding",
		Enabled:     true,
		Transform:   HeaderFolding,
	})

	// HTTP method techniques
	e.Register(&Technique{
		ID:          "method-override",
		Name:        "HTTP Method Override",
		Category:    CategoryHTTPMethod,
		Description: "Uses X-HTTP-Method-Override",
		Enabled:     true,
		HTTPMod:     MethodOverride,
	})

	// Protocol techniques
	e.Register(&Technique{
		ID:          "http-version",
		Name:        "HTTP Version Manipulation",
		Category:    CategoryProtocol,
		Description: "Manipulates HTTP version string",
		Enabled:     true,
		HTTPMod:     HTTPVersionMod,
	})

	// Chunked encoding
	e.Register(&Technique{
		ID:          "chunked-basic",
		Name:        "Basic Chunked Encoding",
		Category:    CategoryChunked,
		Description: "Splits payload into chunks",
		Enabled:     true,
	})

	e.Register(&Technique{
		ID:          "chunked-varied",
		Name:        "Varied Chunk Sizes",
		Category:    CategoryChunked,
		Description: "Uses varied chunk sizes",
		Enabled:     true,
	})
}

// Register adds a technique to the engine.
func (e *Engine) Register(t *Technique) {
	e.techniques[t.ID] = t
}

// Get returns a technique by ID.
func (e *Engine) Get(id string) (*Technique, bool) {
	t, ok := e.techniques[id]
	return t, ok
}

// List returns all registered techniques.
func (e *Engine) List() []*Technique {
	var result []*Technique
	for _, t := range e.techniques {
		result = append(result, t)
	}
	return result
}

// ListByCategory returns techniques in a category.
func (e *Engine) ListByCategory(cat Category) []*Technique {
	var result []*Technique
	for _, t := range e.techniques {
		if t.Category == cat {
			result = append(result, t)
		}
	}
	return result
}

// Apply applies a single technique to a payload.
func (e *Engine) Apply(techniqueID, payload string) (string, error) {
	t, ok := e.techniques[techniqueID]
	if !ok {
		return "", fmt.Errorf("technique not found: %s", techniqueID)
	}
	return t.Apply(payload), nil
}

// Chain applies multiple techniques in sequence.
func (e *Engine) Chain(payload string, techniqueIDs ...string) (string, error) {
	result := payload
	for _, id := range techniqueIDs {
		var err error
		result, err = e.Apply(id, result)
		if err != nil {
			return "", err
		}
	}
	return result, nil
}

// Variant represents an evasion variant.
type Variant struct {
	Payload     string   `json:"payload"`
	Techniques  []string `json:"techniques"`
	ChainDepth  int      `json:"chain_depth"`
	HTTPMods    []string `json:"http_mods"`
	ChunkedSize int      `json:"chunked_size,omitempty"`
}

// GenerateVariants generates multiple evasion variants.
func (e *Engine) GenerateVariants(payload string, maxVariants int) []*Variant {
	if maxVariants <= 0 {
		maxVariants = e.config.MaxVariants
	}

	var variants []*Variant
	seen := make(map[string]bool)

	// Add original
	variants = append(variants, &Variant{
		Payload:    payload,
		Techniques: []string{"original"},
		ChainDepth: 0,
	})
	seen[payload] = true

	// Single technique variants
	for id, t := range e.techniques {
		if !t.Enabled || t.Transform == nil {
			continue
		}

		evaded := t.Apply(payload)
		if !seen[evaded] {
			variants = append(variants, &Variant{
				Payload:    evaded,
				Techniques: []string{id},
				ChainDepth: 1,
			})
			seen[evaded] = true
		}

		if len(variants) >= maxVariants {
			return variants
		}
	}

	// Chained variants
	for depth := 2; depth <= e.config.MaxChainDepth && len(variants) < maxVariants; depth++ {
		chains := e.generateChains(depth)
		for _, chain := range chains {
			evaded, err := e.Chain(payload, chain...)
			if err != nil {
				continue
			}

			if !seen[evaded] {
				variants = append(variants, &Variant{
					Payload:    evaded,
					Techniques: chain,
					ChainDepth: depth,
				})
				seen[evaded] = true
			}

			if len(variants) >= maxVariants {
				return variants
			}
		}
	}

	// Chunked variants
	for _, size := range e.config.ChunkSizes {
		chunked := ChunkPayload(payload, size)
		if !seen[chunked] {
			variants = append(variants, &Variant{
				Payload:     chunked,
				Techniques:  []string{"chunked"},
				ChainDepth:  1,
				ChunkedSize: size,
			})
			seen[chunked] = true
		}

		if len(variants) >= maxVariants {
			break
		}
	}

	return variants
}

// generateChains generates technique chains of given depth.
func (e *Engine) generateChains(depth int) [][]string {
	var ids []string
	for id, t := range e.techniques {
		if t.Enabled && t.Transform != nil {
			ids = append(ids, id)
		}
	}

	if len(ids) < depth {
		return nil
	}

	var chains [][]string
	for i := 0; i < 20 && len(chains) < 10; i++ {
		chain := make([]string, depth)
		used := make(map[string]bool)
		valid := true

		for j := 0; j < depth; j++ {
			attempts := 0
			for {
				idx := e.rng.Intn(len(ids))
				if !used[ids[idx]] {
					chain[j] = ids[idx]
					used[ids[idx]] = true
					break
				}
				attempts++
				if attempts > 100 {
					valid = false
					break
				}
			}
			if !valid {
				break
			}
		}

		if valid {
			chains = append(chains, chain)
		}
	}

	return chains
}

// ChunkedEncoder creates chunked transfer encoding.
type ChunkedEncoder struct {
	ChunkSize  int
	Extensions map[string]string
	Trailer    http.Header
}

// NewChunkedEncoder creates a new chunked encoder.
func NewChunkedEncoder(chunkSize int) *ChunkedEncoder {
	return &ChunkedEncoder{
		ChunkSize:  chunkSize,
		Extensions: make(map[string]string),
	}
}

// Encode encodes data with chunked transfer encoding.
func (c *ChunkedEncoder) Encode(data []byte) []byte {
	var buf bytes.Buffer

	for i := 0; i < len(data); i += c.ChunkSize {
		end := i + c.ChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Write chunk size
		fmt.Fprintf(&buf, "%x", len(chunk))

		// Write extensions
		for k, v := range c.Extensions {
			fmt.Fprintf(&buf, ";%s=%s", k, v)
		}

		buf.WriteString("\r\n")
		buf.Write(chunk)
		buf.WriteString("\r\n")
	}

	// Final chunk
	buf.WriteString("0\r\n")

	// Trailers
	if c.Trailer != nil {
		for k, vv := range c.Trailer {
			for _, v := range vv {
				fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
			}
		}
	}

	buf.WriteString("\r\n")
	return buf.Bytes()
}

// EncodeReader returns an io.Reader with chunked encoding.
func (c *ChunkedEncoder) EncodeReader(data []byte) io.Reader {
	return bytes.NewReader(c.Encode(data))
}

// TimingAttack implements timing-based evasion.
type TimingAttack struct {
	InitialDelay time.Duration
	BetweenDelay time.Duration
	FinalDelay   time.Duration
	RandomJitter time.Duration
	rng          *rand.Rand
}

// NewTimingAttack creates a new timing attack.
func NewTimingAttack() *TimingAttack {
	return &TimingAttack{
		InitialDelay: 0,
		BetweenDelay: 50 * time.Millisecond,
		FinalDelay:   0,
		RandomJitter: 10 * time.Millisecond,
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Execute executes a timed payload sequence.
func (ta *TimingAttack) Execute(payloads []string, send func(string) error) error {
	if ta.InitialDelay > 0 {
		time.Sleep(ta.InitialDelay + ta.jitter())
	}

	for i, p := range payloads {
		if err := send(p); err != nil {
			return err
		}

		if i < len(payloads)-1 && ta.BetweenDelay > 0 {
			time.Sleep(ta.BetweenDelay + ta.jitter())
		}
	}

	if ta.FinalDelay > 0 {
		time.Sleep(ta.FinalDelay + ta.jitter())
	}

	return nil
}

// jitter returns a random jitter duration.
func (ta *TimingAttack) jitter() time.Duration {
	if ta.RandomJitter <= 0 {
		return 0
	}
	return time.Duration(ta.rng.Int63n(int64(ta.RandomJitter)))
}

// HTTPSmuggling implements HTTP request smuggling techniques.
type HTTPSmuggling struct {
	Technique string
}

// NewHTTPSmuggling creates an HTTP smuggling instance.
func NewHTTPSmuggling(technique string) *HTTPSmuggling {
	return &HTTPSmuggling{Technique: technique}
}

// PrepareRequest prepares a smuggling request.
func (s *HTTPSmuggling) PrepareRequest(payload string) (*http.Request, error) {
	req, err := http.NewRequest("POST", "/", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	switch s.Technique {
	case "cl-te":
		// Content-Length / Transfer-Encoding conflict
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		req.Header.Set("Transfer-Encoding", "chunked")
	case "te-cl":
		// Transfer-Encoding / Content-Length conflict
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Content-Length", "0")
	case "te-te":
		// Obfuscated Transfer-Encoding
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header["Transfer-Encoding"] = []string{"chunked", "identity"}
	}

	return req, nil
}

// MultipartEvasion implements multipart form evasion.
type MultipartEvasion struct {
	Boundary       string
	DoubleQuotes   bool
	ExtraHeaders   bool
	NullInFilename bool
	LongFilename   bool
}

// NewMultipartEvasion creates multipart evasion.
func NewMultipartEvasion() *MultipartEvasion {
	return &MultipartEvasion{
		Boundary: "----WebKitFormBoundary" + randomString(16),
	}
}

// BuildPart builds an evasive multipart part.
func (m *MultipartEvasion) BuildPart(fieldName, filename, content string) []byte {
	var buf bytes.Buffer

	buf.WriteString("--")
	buf.WriteString(m.Boundary)
	buf.WriteString("\r\n")

	// Build Content-Disposition
	cd := fmt.Sprintf(`form-data; name="%s"`, fieldName)
	if filename != "" {
		fn := filename
		if m.NullInFilename {
			fn = filename[:len(filename)/2] + "\x00" + filename[len(filename)/2:]
		}
		if m.LongFilename {
			fn = strings.Repeat("a", 200) + filename
		}
		if m.DoubleQuotes {
			cd += fmt.Sprintf(`; filename=""%s""`, fn)
		} else {
			cd += fmt.Sprintf(`; filename="%s"`, fn)
		}
	}
	buf.WriteString("Content-Disposition: ")
	buf.WriteString(cd)
	buf.WriteString("\r\n")

	if m.ExtraHeaders {
		buf.WriteString("Content-Type: application/octet-stream\r\n")
		buf.WriteString("X-Custom-Header: test\r\n")
	}

	buf.WriteString("\r\n")
	buf.WriteString(content)
	buf.WriteString("\r\n")

	return buf.Bytes()
}

// Finalize finalizes the multipart body.
func (m *MultipartEvasion) Finalize(parts [][]byte) []byte {
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(p)
	}
	buf.WriteString("--")
	buf.WriteString(m.Boundary)
	buf.WriteString("--\r\n")
	return buf.Bytes()
}

// ContentType returns the content type header.
func (m *MultipartEvasion) ContentType() string {
	return "multipart/form-data; boundary=" + m.Boundary
}

// =============================================================================
// Transform Functions
// =============================================================================

// DoubleURLEncode applies URL encoding twice.
func DoubleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}

// TripleURLEncode applies URL encoding three times.
func TripleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(url.QueryEscape(s)))
}

// MixedCaseURLEncode uses mixed case hex in URL encoding.
func MixedCaseURLEncode(s string) string {
	var buf bytes.Buffer
	buf.Grow(len(s) * 3)
	for _, b := range []byte(s) {
		if shouldEncode(b) {
			if rand.Intn(2) == 0 {
				buf.WriteString(hexutil.URLEncoded[b])
			} else {
				buf.WriteString(hexutil.URLEncodedLower[b])
			}
		} else {
			buf.WriteByte(b)
		}
	}
	return buf.String()
}

// OverlongUTF8 creates overlong UTF-8 sequences.
func OverlongUTF8(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		if r < 128 {
			// Convert ASCII to overlong 2-byte sequence
			buf.WriteByte(0xC0 | byte(r>>6))
			buf.WriteByte(0x80 | byte(r&0x3F))
		} else {
			b := make([]byte, 4)
			n := utf8.EncodeRune(b, r)
			buf.Write(b[:n])
		}
	}
	return buf.String()
}

// UnicodeNormalizationBypass uses unicode lookalikes.
func UnicodeNormalizationBypass(s string) string {
	replacements := map[rune]rune{
		'<':  '\uFF1C', // Fullwidth less-than
		'>':  '\uFF1E', // Fullwidth greater-than
		'\'': '\u2019', // Right single quotation
		'"':  '\u201C', // Left double quotation
		'/':  '\uFF0F', // Fullwidth solidus
		'=':  '\uFF1D', // Fullwidth equals
	}

	var buf bytes.Buffer
	for _, r := range s {
		if repl, ok := replacements[r]; ok {
			buf.WriteRune(repl)
		} else {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// NullByteInject injects null bytes.
func NullByteInject(s string) string {
	if len(s) < 2 {
		return s + "\x00"
	}
	mid := len(s) / 2
	return s[:mid] + "\x00" + s[mid:]
}

// Base64Wrap wraps in base64.
func Base64Wrap(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// PathTraversalDots adds encoded dots for traversal.
func PathTraversalDots(s string) string {
	return strings.ReplaceAll(s, "..", "%2e%2e")
}

// PathNormalization uses path normalization quirks.
func PathNormalization(s string) string {
	// Add redundant slashes and dots
	s = strings.ReplaceAll(s, "/", "//./")
	return s
}

// HeaderSplitting attempts header injection.
func HeaderSplitting(s string) string {
	return s + "\r\nX-Injected: true"
}

// HeaderFolding uses header line folding.
func HeaderFolding(s string) string {
	if len(s) < 10 {
		return s
	}
	mid := len(s) / 2
	return s[:mid] + "\r\n " + s[mid:]
}

// ChunkPayload splits payload into chunks.
func ChunkPayload(payload string, size int) string {
	if size <= 0 {
		size = 1
	}

	var buf bytes.Buffer
	for i := 0; i < len(payload); i += size {
		end := i + size
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[i:end]
		fmt.Fprintf(&buf, "%x\r\n%s\r\n", len(chunk), chunk)
	}
	buf.WriteString("0\r\n\r\n")
	return buf.String()
}

// MethodOverride modifies request with method override header.
func MethodOverride(req *http.Request) *http.Request {
	originalMethod := req.Method
	req.Method = "POST"
	req.Header.Set("X-HTTP-Method-Override", originalMethod)
	return req
}

// HTTPVersionMod modifies HTTP version.
func HTTPVersionMod(req *http.Request) *http.Request {
	req.Proto = "HTTP/1.0"
	req.ProtoMajor = 1
	req.ProtoMinor = 0
	return req
}

// =============================================================================
// Helper Functions
// =============================================================================

func shouldEncode(b byte) bool {
	// Check if byte needs URL encoding
	if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
		return false
	}
	switch b {
	case '-', '_', '.', '~':
		return false
	}
	return true
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
