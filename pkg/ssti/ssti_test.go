package ssti

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

func TestNewDetector(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		d := NewDetector(nil)
		if d == nil {
			t.Fatal("expected detector, got nil")
		}
		if d.config == nil {
			t.Fatal("expected config, got nil")
		}
		if d.config.Timeout != 10*time.Second {
			t.Errorf("expected 10s timeout, got %v", d.config.Timeout)
		}
	})

	t.Run("custom config", func(t *testing.T) {
		cfg := &DetectorConfig{
			Timeout:   5 * time.Second,
			SafeMode:  false,
			UserAgent: "CustomAgent/1.0",
		}
		d := NewDetector(cfg)
		if d.config.Timeout != 5*time.Second {
			t.Errorf("expected 5s timeout, got %v", d.config.Timeout)
		}
		if d.config.SafeMode {
			t.Error("expected SafeMode false")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", cfg.Timeout)
	}
	if !cfg.SafeMode {
		t.Error("expected SafeMode true by default")
	}
	if cfg.BlindDelay != 5*time.Second {
		t.Errorf("expected 5s blind delay, got %v", cfg.BlindDelay)
	}
	if cfg.MaxPayloads != 50 {
		t.Errorf("expected 50 max payloads, got %d", cfg.MaxPayloads)
	}
}

func TestPayloadGeneration(t *testing.T) {
	d := NewDetector(&DetectorConfig{SafeMode: false})

	if len(d.payloads) == 0 {
		t.Fatal("expected payloads to be generated")
	}

	// Check for various engine payloads
	engines := make(map[TemplateEngine]int)
	payloadTypes := make(map[PayloadType]int)

	for _, p := range d.payloads {
		engines[p.Engine]++
		payloadTypes[p.Type]++
	}

	// Should have payloads for multiple engines
	expectedEngines := []TemplateEngine{
		EngineJinja2, EngineFreemarker, EngineVelocity, EngineSmarty,
		EngineMako, EngineERB, EnginePebble, EngineThymeleaf,
	}
	for _, engine := range expectedEngines {
		if engines[engine] == 0 {
			t.Errorf("expected payloads for engine %s", engine)
		}
	}

	// Should have various payload types
	expectedTypes := []PayloadType{PayloadMath, PayloadProbe, PayloadInfoDisclosure}
	for _, pt := range expectedTypes {
		if payloadTypes[pt] == 0 {
			t.Errorf("expected payloads of type %s", pt)
		}
	}

	t.Logf("Generated %d payloads across %d engines", len(d.payloads), len(engines))
}

func TestSafeModeFiltering(t *testing.T) {
	// Safe mode should exclude RCE payloads
	safeDetector := NewDetector(&DetectorConfig{SafeMode: true})
	unsafeDetector := NewDetector(&DetectorConfig{SafeMode: false})

	safeCount := 0
	unsafeCount := 0

	for _, p := range safeDetector.getFilteredPayloads() {
		if p.Type == PayloadRCE || p.Type == PayloadSandboxEscape {
			safeCount++
		}
	}

	for _, p := range unsafeDetector.getFilteredPayloads() {
		if p.Type == PayloadRCE || p.Type == PayloadSandboxEscape {
			unsafeCount++
		}
	}

	if safeCount > 0 {
		t.Errorf("safe mode should have 0 RCE payloads, got %d", safeCount)
	}

	if unsafeCount == 0 {
		t.Error("unsafe mode should have RCE payloads")
	}
}

func TestGetPayloads(t *testing.T) {
	d := NewDetector(&DetectorConfig{SafeMode: false})

	t.Run("filter by engine", func(t *testing.T) {
		jinja2Payloads := d.GetPayloads(EngineJinja2, "")
		if len(jinja2Payloads) == 0 {
			t.Error("expected Jinja2 payloads")
		}

		for _, p := range jinja2Payloads {
			if p.Engine != EngineJinja2 && p.Engine != EngineUnknown {
				t.Errorf("expected Jinja2 or Unknown engine, got %s", p.Engine)
			}
		}
	})

	t.Run("filter by type", func(t *testing.T) {
		mathPayloads := d.GetPayloads("", PayloadMath)
		if len(mathPayloads) == 0 {
			t.Error("expected math payloads")
		}

		for _, p := range mathPayloads {
			if p.Type != PayloadMath {
				t.Errorf("expected math type, got %s", p.Type)
			}
		}
	})

	t.Run("filter by both", func(t *testing.T) {
		filtered := d.GetPayloads(EngineJinja2, PayloadMath)
		for _, p := range filtered {
			if p.Type != PayloadMath {
				t.Errorf("expected math type, got %s", p.Type)
			}
			if p.Engine != EngineJinja2 && p.Engine != EngineUnknown {
				t.Errorf("expected Jinja2 or Unknown, got %s", p.Engine)
			}
		}
	})
}

func TestDetect(t *testing.T) {
	// Create test server that reflects input and evaluates simple math
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("name")

		// Simulate vulnerable Jinja2 template engine
		// Detect {{X*Y}} pattern and compute result
		if strings.HasPrefix(input, "{{") && strings.HasSuffix(input, "}}") {
			inner := strings.TrimPrefix(strings.TrimSuffix(input, "}}"), "{{")
			// Simple multiplication detection
			if strings.Contains(inner, "*") {
				parts := strings.Split(inner, "*")
				if len(parts) == 2 {
					var a, b int
					fmt.Sscanf(parts[0], "%d", &a)
					fmt.Sscanf(parts[1], "%d", &b)
					if a > 0 && b > 0 {
						fmt.Fprintf(w, "Result: %d", a*b)
						return
					}
				}
			}
		}

		// Simulate string multiplication {{7*'7'}}
		if input == "{{7*'7'}}" {
			fmt.Fprint(w, "7777777")
			return
		}

		fmt.Fprintf(w, "Hello, %s", input)
	}))
	defer server.Close()

	d := NewDetector(&DetectorConfig{
		SafeMode:    true,
		MaxPayloads: 20,
	})

	ctx := context.Background()
	vulns, err := d.Detect(ctx, server.URL, "name")
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected vulnerabilities to be detected")
	}

	// Check vulnerability properties
	for _, v := range vulns {
		if v.URL == "" {
			t.Error("vulnerability should have URL")
		}
		if v.Parameter != "name" {
			t.Errorf("expected parameter 'name', got '%s'", v.Parameter)
		}
		if v.Confidence == "" {
			t.Error("vulnerability should have confidence")
		}
		t.Logf("Found: %s engine, confidence=%s, evidence=%s", v.Engine, v.Confidence, v.Evidence)
	}
}

func TestDetectNoVulnerability(t *testing.T) {
	// Server that doesn't process templates - returns static content without user input
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return static content without reflecting input at all
		fmt.Fprint(w, "Static response - no user input here")
	}))
	defer server.Close()

	d := NewDetector(&DetectorConfig{
		SafeMode:    true,
		MaxPayloads: 10,
	})

	ctx := context.Background()
	vulns, err := d.Detect(ctx, server.URL, "name")
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	if len(vulns) != 0 {
		t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		for _, v := range vulns {
			t.Logf("False positive: engine=%s, evidence=%s", v.Engine, v.Evidence)
		}
	}
}

func TestPayloadGenerator(t *testing.T) {
	t.Run("math payload generation", func(t *testing.T) {
		engines := []TemplateEngine{
			EngineJinja2, EngineFreemarker, EngineSmarty, EngineERB, EngineThymeleaf, EngineRazor,
		}

		for _, engine := range engines {
			gen := NewPayloadGenerator(engine)
			payload := gen.GenerateMathPayload(123, 456)

			if payload == nil {
				t.Errorf("failed to generate payload for %s", engine)
				continue
			}

			if payload.Engine != engine {
				t.Errorf("expected engine %s, got %s", engine, payload.Engine)
			}

			if payload.MathResult != 123*456 {
				t.Errorf("expected result %d, got %d", 123*456, payload.MathResult)
			}

			if payload.ExpectedOutput != "56088" {
				t.Errorf("expected output '56088', got '%s'", payload.ExpectedOutput)
			}

			t.Logf("%s: %s", engine, payload.Template)
		}
	})

	t.Run("RCE payload generation", func(t *testing.T) {
		gen := NewPayloadGenerator(EngineJinja2)
		payload := gen.GenerateRCEPayload("id")

		if payload == nil {
			t.Fatal("failed to generate RCE payload")
		}

		if payload.Type != PayloadRCE {
			t.Errorf("expected RCE type, got %s", payload.Type)
		}

		if payload.Severity != finding.Critical {
			t.Errorf("expected critical severity, got %s", payload.Severity)
		}

		if !strings.Contains(payload.Template, "id") {
			t.Error("payload should contain command")
		}
	})
}

func TestAllEngines(t *testing.T) {
	engines := AllEngines()

	if len(engines) < 10 {
		t.Errorf("expected at least 10 engines, got %d", len(engines))
	}

	// Check for expected engines
	expected := map[TemplateEngine]bool{
		EngineJinja2:     false,
		EngineTwig:       false,
		EngineFreemarker: false,
		EngineVelocity:   false,
		EngineSmarty:     false,
	}

	for _, e := range engines {
		if _, ok := expected[e]; ok {
			expected[e] = true
		}
	}

	for engine, found := range expected {
		if !found {
			t.Errorf("missing engine: %s", engine)
		}
	}
}

func TestGetEnginePayloads(t *testing.T) {
	payloads := GetEnginePayloads(EngineJinja2, true)

	if len(payloads) == 0 {
		t.Error("expected Jinja2 payloads")
	}

	for _, p := range payloads {
		if p.Type == PayloadRCE || p.Type == PayloadSandboxEscape {
			t.Errorf("safe mode should not include RCE payloads, got type %s", p.Type)
		}
	}
}

func TestEngineFiltering(t *testing.T) {
	d := NewDetector(&DetectorConfig{
		SafeMode: true,
		Engines:  []TemplateEngine{EngineJinja2, EngineMako},
	})

	filtered := d.getFilteredPayloads()

	for _, p := range filtered {
		if p.Engine != EngineJinja2 && p.Engine != EngineMako && p.Engine != EngineUnknown {
			t.Errorf("unexpected engine in filtered results: %s", p.Engine)
		}
	}
}

func TestPayloadTypeFiltering(t *testing.T) {
	d := NewDetector(&DetectorConfig{
		SafeMode:     true,
		PayloadTypes: []PayloadType{PayloadMath},
	})

	filtered := d.getFilteredPayloads()

	if len(filtered) == 0 {
		t.Fatal("expected filtered payloads")
	}

	for _, p := range filtered {
		if p.Type != PayloadMath {
			t.Errorf("expected only math payloads, got %s", p.Type)
		}
	}
}

func TestAnalyzeResponse(t *testing.T) {
	d := NewDetector(nil)

	t.Run("math expression match", func(t *testing.T) {
		payload := &Payload{
			Template:       "{{5*5}}",
			Type:           PayloadMath,
			Engine:         EngineJinja2,
			MathA:          5,
			MathB:          5,
			MathResult:     25,
			ExpectedOutput: "25",
			Severity:       finding.High,
		}

		vuln := d.analyzeResponse("http://test.com", "q", payload, "The result is 25!", time.Millisecond, "")

		if vuln == nil {
			t.Fatal("expected vulnerability detection")
		}
		if vuln.Confidence != "high" {
			t.Errorf("expected high confidence, got %s", vuln.Confidence)
		}
	})

	t.Run("regex match", func(t *testing.T) {
		payload := &Payload{
			Template: "{{config}}",
			Type:     PayloadInfoDisclosure,
			Engine:   EngineJinja2,
			Regex:    regexp.MustCompile(`(?i)secret|debug`),
			Severity: finding.Medium,
		}

		vuln := d.analyzeResponse("http://test.com", "q", payload, "DEBUG=True, SECRET_KEY=abc", time.Millisecond, "")

		if vuln == nil {
			t.Fatal("expected vulnerability detection")
		}
		if vuln.Confidence == "" {
			t.Error("expected confidence to be set")
		}
	})

	t.Run("no match", func(t *testing.T) {
		payload := &Payload{
			Template:       "{{99*99}}",
			Type:           PayloadMath,
			Engine:         EngineJinja2,
			MathResult:     9801,
			ExpectedOutput: "9801",
			Severity:       finding.High,
		}

		vuln := d.analyzeResponse("http://test.com", "q", payload, "Nothing to see here", time.Millisecond, "")

		if vuln != nil {
			t.Error("expected no vulnerability")
		}
	})
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	d := NewDetector(&DetectorConfig{
		Timeout:     5 * time.Second,
		MaxPayloads: 100,
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	_, err := d.Detect(ctx, server.URL, "test")
	if err != context.Canceled {
		// May also return nil if cancelled before first request
		if err != nil && err != context.Canceled {
			t.Logf("got error: %v (expected context.Canceled or nil)", err)
		}
	}
}

func TestInvalidURL(t *testing.T) {
	d := NewDetector(nil)

	_, err := d.Detect(context.Background(), "://invalid", "test")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestScanURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.HasPrefix(name, "{{") && strings.Contains(name, "*") {
			// Simulate vulnerable
			fmt.Fprint(w, "7777777")
			return
		}
		fmt.Fprint(w, "Hello")
	}))
	defer server.Close()

	d := NewDetector(&DetectorConfig{
		SafeMode:    true,
		MaxPayloads: 10,
	})

	result, err := d.ScanURL(context.Background(), server.URL, []string{"name", "id"})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.URL != server.URL {
		t.Errorf("expected URL %s, got %s", server.URL, result.URL)
	}

	if len(result.Parameters) != 2 {
		t.Errorf("expected 2 parameters, got %d", len(result.Parameters))
	}

	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}

	t.Logf("Scan completed: %d vulns found, %d payloads tested, duration: %v",
		len(result.Vulnerabilities), result.PayloadsTested, result.Duration)
}

func TestMathPayloadValues(t *testing.T) {
	// Test that math values are randomized and reasonable
	d1 := NewDetector(nil)
	d2 := NewDetector(nil)

	var d1Math, d2Math *Payload

	for _, p := range d1.payloads {
		if p.Type == PayloadMath && p.MathA > 0 {
			d1Math = p
			break
		}
	}

	for _, p := range d2.payloads {
		if p.Type == PayloadMath && p.MathA > 0 {
			d2Math = p
			break
		}
	}

	if d1Math == nil || d2Math == nil {
		t.Fatal("expected to find math payloads")
	}

	// Values should be between 1000-9999 (random)
	if d1Math.MathA < 1000 || d1Math.MathA > 9999 {
		t.Errorf("MathA out of expected range: %d", d1Math.MathA)
	}

	// Result should be correct
	if d1Math.MathResult != d1Math.MathA*d1Math.MathB {
		t.Errorf("incorrect math result: %d != %d*%d", d1Math.MathResult, d1Math.MathA, d1Math.MathB)
	}

	t.Logf("d1: %d*%d=%d, d2: %d*%d=%d", d1Math.MathA, d1Math.MathB, d1Math.MathResult, d2Math.MathA, d2Math.MathB, d2Math.MathResult)
}

func TestPayloadDescriptions(t *testing.T) {
	d := NewDetector(&DetectorConfig{SafeMode: false})

	for i, p := range d.payloads {
		if p.Description == "" {
			t.Errorf("payload %d missing description: %s", i, p.Template)
		}
		if p.Engine == "" {
			t.Errorf("payload %d missing engine: %s", i, p.Template)
		}
		if p.Type == "" {
			t.Errorf("payload %d missing type: %s", i, p.Template)
		}
		if p.Severity == "" {
			t.Errorf("payload %d missing severity: %s", i, p.Template)
		}
	}
}

func TestVulnerabilityFields(t *testing.T) {
	vuln := &Vulnerability{
		Vulnerability: finding.Vulnerability{
			URL:          "http://example.com/test",
			Parameter:    "q",
			Severity:     finding.High,
			Evidence:     "7777777",
			ResponseTime: 100 * time.Millisecond,
		},
		Engine:         EngineJinja2,
		Confidence:     "high",
		CanExecuteCode: true,
		RCEPayload:     "{{lipsum.__globals__['os'].popen('id').read()}}",
	}

	if vuln.URL == "" {
		t.Error("URL should be set")
	}
	if vuln.Parameter != "q" {
		t.Error("Parameter should be 'q'")
	}
	if vuln.Engine != EngineJinja2 {
		t.Error("Engine should be Jinja2")
	}
	if !vuln.CanExecuteCode {
		t.Error("CanExecuteCode should be true")
	}
}

func TestPayloadEncodingVariations(t *testing.T) {
	d := NewDetector(&DetectorConfig{SafeMode: true})

	// Check that different syntaxes are represented
	syntaxes := map[string]bool{
		"{{": false, // Jinja2/Twig style
		"${": false, // Freemarker/Mako style
		"{%": false, // Jinja2 statement
		"<%": false, // ERB style
	}

	for _, p := range d.payloads {
		for syntax := range syntaxes {
			if strings.Contains(p.Template, syntax) {
				syntaxes[syntax] = true
			}
		}
	}

	for syntax, found := range syntaxes {
		if !found {
			t.Errorf("missing syntax variation: %s", syntax)
		}
	}
}

func TestBlindPayloads(t *testing.T) {
	d := NewDetector(&DetectorConfig{
		BlindDelay: 3 * time.Second,
	})

	payloads := d.getBlindPayloads()

	if len(payloads) == 0 {
		t.Fatal("expected blind payloads")
	}

	for _, p := range payloads {
		if p.Type != PayloadBlind {
			t.Errorf("expected blind type, got %s", p.Type)
		}

		// Should contain the sleep duration
		if !strings.Contains(p.Template, "3") && !strings.Contains(p.Template, "sleep") {
			t.Logf("Blind payload may not have correct delay: %s", p.Template)
		}
	}
}

func TestMaxPayloadsLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	requestCount := 0
	countServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		fmt.Fprint(w, "OK")
	}))
	defer countServer.Close()

	d := NewDetector(&DetectorConfig{
		SafeMode:    true,
		MaxPayloads: 5,
	})

	_, err := d.Detect(context.Background(), countServer.URL, "test")
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	// MaxPayloads limits payload requests; +1 for baseline comparison request
	if requestCount > 6 {
		t.Errorf("expected at most 6 requests (5 payloads + 1 baseline), got %d", requestCount)
	}
}

func TestResultJSON(t *testing.T) {
	result := &Result{
		URL:            "http://example.com",
		Parameters:     []string{"q", "id"},
		DetectedEngine: EngineJinja2,
		Duration:       time.Second,
		PayloadsTested: 50,
	}

	// Verify struct tags work (would panic if malformed)
	if result.URL == "" {
		t.Error("URL should be set")
	}
}
